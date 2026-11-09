"""Explicit HTTPS observations and verified JSON references; no discovery traffic."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import re
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from apkscan.core.attribution import score_edge_provider
from apkscan.core.pinned_transport import PinnedConnection, resolve_public

CHECKS = frozenset({"tls", "tls-no-sni", "tls-random-sni", "host-compare", "resource", "business", "objstore-head", "objstore-get", "follow"})


def safe_url(value: str) -> str:
    """Deliberately accept only explicit credential-free HTTPS paths on port 443."""
    from apkscan.core.probe_target import _host

    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise ValueError("invalid_check_url")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.query or "?" in value or "#" in value or "\\" in value or parsed.port not in (None, 443)):
        raise ValueError("credential_free_https_url_required")
    host = _host(parsed.hostname, domain=True)
    return urlunsplit(("https", host, parsed.path or "/", "", ""))


def follow_order(edges: list[dict], max_objects: int, host: str) -> list[str]:
    if not edges or len(edges) > 5 or type(max_objects) is not int or not 2 <= max_objects <= 6:
        raise ValueError("explicit_follow_object_budget_required")
    for edge in edges:
        if (set(edge) != {"source_url", "target_url", "field_pointer", "source_sha256"}
                or not isinstance(edge["source_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", edge["source_sha256"])
                or not isinstance(edge["field_pointer"], str) or not edge["field_pointer"].startswith("/")
                or len(edge["field_pointer"]) > 1024 or re.search(r"~(?![01])", edge["field_pointer"])):
            raise ValueError("invalid_follow_relation")
        if any(safe_url(edge[k]) != edge[k] for k in ("source_url", "target_url")):
            raise ValueError("noncanonical_follow_url")
    sources, targets = {e["source_url"] for e in edges}, {e["target_url"] for e in edges}
    roots = sources - targets
    if len(roots) != 1 or len(sources | targets) > max_objects:
        raise ValueError("follow_root_or_budget_invalid")
    root = next(iter(roots))
    if urlsplit(root).hostname != host:
        raise ValueError("follow_root_out_of_scope")
    ordered = [root]
    while len(ordered) < len(sources | targets):
        ready = sorted(t for t in (sources | targets) - set(ordered)
                       if all(e["source_url"] in ordered for e in edges if e["target_url"] == t))
        if not ready:
            raise ValueError("follow_cycle")
        ordered.extend(ready)
    return ordered


def http_request(label: str, url: str, *, target: str | None = None, host_header: str | None = None, method: str = "GET") -> dict[str, Any]:
    url = safe_url(url)
    parsed = urlsplit(url)
    return {"label": label, "url": url, "scheme": "https", "host": parsed.hostname,
            "connect_host": target or parsed.hostname, "request_target": parsed.path,
            "sni": parsed.hostname, "host_header": host_header or parsed.hostname, "port": 443, "method": method}


def observe_http(request: dict[str, Any], *, max_bytes: int, timeout: float) -> dict[str, Any]:
    """One pinned request; bound total HTTP reads, certificate, and wall time."""
    row: dict[str, Any] = {**request, "outcome": "failed", "peer_ip": None, "body_complete": False,
                           "observed_at": datetime.now(timezone.utc).isoformat(), "consumed_bytes": 0}
    connection = None
    body, der = bytearray(), b""
    meter = {"remaining": max_bytes, "consumed": 0}
    deadline = time.monotonic() + timeout
    try:
        if request["method"] not in {"GET", "HEAD"} or timeout <= 0 or max_bytes <= 0:
            raise ValueError("invalid_http_check_budget_or_method")
        addresses = resolve_public(request["connect_host"], 443, timeout=deadline - time.monotonic())
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request_deadline")
        connection = PinnedConnection({**request, "_read_budget": meter}, addresses, timeout=remaining)
        connection.request(request["method"], request["request_target"], headers={
            "Host": request["host_header"], "Accept-Encoding": "identity", "Connection": "close", "User-Agent": "fxapk-probe-target/1"})
        row["peer_ip"] = connection.peer_ip
        if connection.sock is not None:
            der = connection.sock.getpeercert(binary_form=True) or b""  # type: ignore[attr-defined]
            if not der or len(der) > meter["remaining"]:
                raise ValueError("certificate_budget_exceeded")
            meter["remaining"] -= len(der)
            row.update(certificate_sha256=hashlib.sha256(der).hexdigest(), certificate_der_base64=base64.b64encode(der).decode(), tls_verified=True)
        response = connection.getresponse()
        headers = sorted([[k.lower(), v] for k, v in response.getheaders()])
        row.update(http_status=response.status, response_headers=headers)
        header_map: dict[str, str] = {}
        for key, value in headers:
            header_map[key] = header_map.get(key, "") + (", " if key in header_map else "") + value
        row["edge_provider_observation"] = score_edge_provider({"response_headers": header_map})
        row["object_metadata"] = {key: value for key, value in sorted(header_map.items())
                                  if key in {"etag", "last-modified", "x-amz-bucket-region", "x-amz-request-id", "x-amz-id-2",
                                             "x-oss-request-id", "x-oss-bucket-region", "x-cos-request-id", "x-cos-bucket-region",
                                             "x-bce-request-id"}}
        # Metadata is an observed server claim, never proof of bucket ownership.
        if request["method"] != "HEAD":
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("request_deadline")
                chunk = response.read1(min(65536, max(1, max_bytes - len(der) - len(body))))
                if not chunk:
                    row["body_complete"] = True
                    break
                body.extend(chunk)
                if len(body) + len(der) >= max_bytes:
                    row["body_complete"] = response.length == 0
                    break
            declared = header_map.get("content-length")
            if declared is not None and (not declared.isdigit() or int(declared) != len(body)):
                row["body_complete"] = False
        row["representation_complete"] = (request["method"] == "GET" and row["body_complete"]
                                            and header_map.get("content-encoding", "identity").lower() == "identity")
        row["outcome"] = "redirect_not_followed" if 300 <= response.status < 400 else "observed"
    except (OSError, ValueError, http.client.HTTPException) as exc:
        row["error_type"] = type(exc).__name__
    finally:
        if connection is not None:
            connection.close()
        row.update(body_sha256=hashlib.sha256(body).hexdigest(), body_base64=base64.b64encode(body).decode(), body_bytes=len(body),
                   consumed_bytes=max(meter["consumed"], len(body)) + len(der))
    return row


def compare_http(check: str, rows: list[dict]) -> dict[str, Any]:
    result: dict[str, Any] = {"check": check, "outcome": "inconclusive", "origin_status": "not_confirmed"}
    if (len(rows) != 2 or any(r.get("outcome") != "observed" or r.get("body_complete") is not True
                              or r.get("representation_complete") is not True for r in rows)):
        return result
    a, b = rows
    keys = ("sni", "port", "request_target", "method") + (("peer_ip",) if check == "host-compare" else ("host_header",))
    if any(not a.get(k) or a.get(k) != b.get(k) for k in keys) or a.get("method") != "GET":
        return result
    if check == "host-compare":
        if a.get("host_header") != b.get("host_header") and (a.get("body_sha256"), a.get("http_status")) != (b.get("body_sha256"), b.get("http_status")):
            result["outcome"] = "content_difference_observed"
        else:
            result["outcome"] = "no_content_difference_observed"
    elif check == "resource" and all(type(r.get("http_status")) is int and 200 <= r["http_status"] < 300 for r in rows):
        result["outcome"] = "resource_bytes_match" if a.get("body_sha256") == b.get("body_sha256") else "resource_bytes_differ"
    return result


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("ambiguous_json_key")
    return dict(pairs)


def relation_matches(edge: dict, row: dict) -> bool:
    if (row.get("outcome") != "observed" or row.get("body_complete") is not True
            or row.get("representation_complete") is not True or row.get("body_sha256") != edge["source_sha256"]):
        return False
    if not 200 <= row.get("http_status", 0) < 300:
        return False
    try:
        raw = base64.b64decode(row["body_base64"], validate=True)
        if hashlib.sha256(raw).hexdigest() != edge["source_sha256"]:
            return False
        value = json.loads(raw, object_pairs_hook=_unique_object)
        for part in edge["field_pointer"].split("/")[1:]:
            part = part.replace("~1", "/").replace("~0", "~")
            value = value[int(part)] if isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part) else value[part]
        return value == edge["target_url"]
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        return False


def run_http_check(check: str, plan: dict, budget: dict[str, Any]) -> dict[str, Any]:
    target, host = plan["target"], plan["business_host"]
    random_host = "probe-" + plan["base_report_canonical_sha256"][:16] + ".example.test"
    requests = []
    if check == "host-compare":
        requests = [http_request("business", plan["url"], target=target),
                    http_request("random", plan["url"], target=target, host_header=random_host)]
    elif check == "resource":
        requests = [http_request("reference", plan["resource_url"]), http_request("candidate", plan["resource_url"], target=target)]
    elif check in {"business", "objstore-head", "objstore-get"}:
        url = plan["url"] if check == "business" else plan["object_url"]
        requests = [http_request(check, url, target=target, method="HEAD" if check == "objstore-head" else "GET")]
    elif check == "follow":
        requests = [http_request(str(i), url, target=target if i == 0 else None)
                    for i, url in enumerate(follow_order(plan["follow_edges"], plan["max_objects"], host))]
    rows: list[dict] = []
    by_url: dict[str, dict] = {}
    for request in requests:
        row: dict[str, Any] = {**request, "outcome": "skipped_not_allowed", "peer_ip": None, "consumed_bytes": 0}
        remaining = budget["deadline"] - time.monotonic()
        parents = [e for e in plan["follow_edges"] if e["target_url"] == request["url"]] if check == "follow" else []
        if parents and not all(relation_matches(e, by_url.get(e["source_url"], {})) for e in parents):
            row["outcome"] = "skipped_reference_unverified"
        elif remaining <= 0 or budget["bytes"] <= 0 or budget["requests"] <= 0:
            row["outcome"] = "skipped_budget_exhausted"
        elif request["connect_host"] in plan["allow"]:
            budget["requests"] -= 1
            row = observe_http(request, max_bytes=budget["bytes"], timeout=min(15, remaining))
            budget["bytes"] -= row["consumed_bytes"]
        rows.append(row)
        by_url[request["url"]] = row
    outcome = compare_http(check, rows) if check in {"host-compare", "resource"} else {"check": check, "outcome": rows[0]["outcome"]}
    if check == "follow":
        outcome["outcome"] = "follow_observed" if all(r["outcome"] == "observed" and r.get("body_complete") for r in rows) else "inconclusive"
    return {**outcome, "observed_at": datetime.now(timezone.utc).isoformat(), "host_header": host,
            "sni": host, "peer_ip": next((r.get("peer_ip") for r in rows if r.get("connect_host") == target), None),
            "requests": sorted(rows, key=lambda r: r["label"]), "origin_status": "not_confirmed"}
