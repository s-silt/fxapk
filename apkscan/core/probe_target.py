"""Explicit bounded active observations. Never App contact or origin proof."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import ssl
import time
from typing import Any
from uuid import uuid4
from urllib.parse import urlsplit

from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.certificate_ownership import verify_certificate_ownership
from apkscan.core.models import Evidence, EvidenceScope
from apkscan.core.pinned_transport import connect_pinned, resolve_public
from apkscan.core.report_schema import ensure_writable_report_version
from apkscan.report.json import _to_jsonable

__all__ = ["build_plan", "probe_tls", "run_plan", "verify_certificate_ownership"]

META_WRITE_OWNER = "core.probe_target"
META_WRITE_CATEGORIES = {"network_attribution": "signal", "closure": "signal"}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)


def _host(value: str, *, domain: bool = False) -> str:
    value = value.encode("idna").decode("ascii").lower().rstrip(".")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) or "." not in value:
            raise ValueError("invalid_host") from None
        if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in value.split(".")):
            raise ValueError("invalid_host")
        return value
    if domain:
        raise ValueError("business_host_must_be_domain")
    return str(address)


def build_plan(report: dict, *, target: str, business_host: str, allow: list[str], checks: list[str] | None = None,
               max_requests: int = 6, max_bytes: int = 2 * 1024 * 1024, window: int = 600,
               url: str = "", resource_url: str = "", object_url: str = "",
               follow_edges: list[dict] | None = None, max_objects: int = 0) -> dict[str, Any]:
    from apkscan.core.probe_checks import CHECKS, follow_order, safe_url

    ensure_writable_report_version(report.get("schema_version"))
    target, host = _host(target), _host(business_host, domain=True)
    checks = sorted(set(checks if checks is not None else ["tls"]))
    if not checks or set(checks) - CHECKS:
        raise ValueError("unsupported_check")
    if (type(max_requests) is not int or not 1 <= max_requests <= 6 or type(max_bytes) is not int
            or not 1 <= max_bytes <= 2 * 1024 * 1024 or type(window) is not int or not 1 <= window <= 600):
        raise ValueError("invalid_budget")
    if not any(isinstance(e, dict) and e.get("value") == target for e in report.get("endpoints", [])):
        raise ValueError("target_not_in_report")
    urls = {"url": url, "resource_url": resource_url, "object_url": object_url}
    required = {"url": {"host-compare", "business"}, "resource_url": {"resource"}, "object_url": {"objstore-head", "objstore-get"}}
    for name, consumers in required.items():
        if set(checks) & consumers:
            urls[name] = safe_url(urls[name])
            if urlsplit(urls[name]).hostname != host:
                raise ValueError("url_out_of_business_scope")
        elif urls[name]:
            raise ValueError("unused_check_url")
    edges = sorted(deepcopy(follow_edges or []), key=lambda e: json.dumps(e, sort_keys=True))
    count = sum(2 if check in {"resource", "host-compare"} else 1 for check in checks if check != "follow")
    if "follow" in checks:
        count += len(follow_order(edges, max_objects, host))
    elif edges or max_objects:
        raise ValueError("follow_not_explicit")
    if count > max_requests:
        raise ValueError("request_budget_exceeded")
    return {"schema": "fxapk-probe-target-1", "status": "planned", "target": target, "business_host": host,
            "base_report_canonical_sha256": hashlib.sha256(json.dumps(report, sort_keys=True, ensure_ascii=True).encode()).hexdigest(),
            "allow": sorted({_host(a) for a in allow}), "checks": checks, "port": 443,
            "max_requests": max_requests, "planned_requests": count, "max_bytes": max_bytes, "window": window,
            **urls, "follow_edges": edges, "max_objects": max_objects,
            "byte_budget_scope": "http_response_and_retained_certificate_der_excluding_tls_overhead", "follow_redirects": False,
            "origin_status": "not_confirmed"}


def probe_tls(plan: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    check = plan.get("tls_check", "tls")
    sni = None if check == "tls-no-sni" else ("probe-" + plan["base_report_canonical_sha256"][:16] + ".example.test"
                                              if check == "tls-random-sni" else plan["business_host"])
    row: dict[str, Any] = {"check": check, "outcome": "failed", "peer_ip": None, "host_header": None,
                           "sni": sni, "port": 443, "method": "TLS",
                           "observed_at": datetime.now(timezone.utc).isoformat(), "tls_verified": False}
    raw, secured, der = None, None, b""
    deadline = time.monotonic() + min(plan["window"], 15)
    try:
        addresses = resolve_public(plan["target"], 443, timeout=deadline - time.monotonic())
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("resolution_budget_exceeded")
        raw = connect_pinned(addresses[0], 443, timeout=remaining)
        row["peer_ip"] = str(raw.getpeername()[0])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("connection_budget_exceeded")
        raw.settimeout(remaining)
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if check != "tls":
            # Chain validation remains mandatory; no host identity claim for comparison SNI.
            context.check_hostname = False
        secured = context.wrap_socket(raw, server_hostname=sni)
        der = secured.getpeercert(binary_form=True) or b""
        if not der or len(der) > plan["max_bytes"]:
            raise ValueError("certificate_missing_or_budget_exceeded")
        certificate: Any = secured.getpeercert() or {}
        sans = sorted({value.lower().rstrip(".") for kind, value in certificate.get("subjectAltName", []) if kind == "DNS" and isinstance(value, str)})
        host = plan["business_host"]
        matches = any(host == san or (san.startswith("*.") and host.endswith(san[1:]) and host.count(".") == san.count(".")) for san in sans)
        row.update(tls_verified=check == "tls", chain_verified=True, hostname_verified=check == "tls",
                   certificate_sha256=hashlib.sha256(der).hexdigest(), san=sans,
                   outcome=("tls_binding_observed" if matches else "san_binding_unverified") if check == "tls" else "certificate_selection_observed")
    except (OSError, ValueError) as exc:
        row["error_type"] = type(exc).__name__
        der = b""
    finally:
        if secured is not None:
            secured.close()
        elif raw is not None:
            raw.close()
    return row, der


def run_plan(plan: dict[str, Any], out: Path, report: dict, *, authorized: bool = False,
             ownership_material: bytes = b"", ownership_key: bytes = b"",
             binding_material: bytes = b"", binding_key: bytes = b"") -> Path:
    from apkscan.core.probe_checks import run_http_check
    from apkscan.core.tls_bindings import verify_tls_bindings

    if authorized is not True:
        raise ValueError("explicit_authorized_active_required")
    expected = build_plan(report, **{k: plan[k] for k in (
        "target", "business_host", "allow", "checks", "max_requests", "max_bytes", "window",
        "url", "resource_url", "object_url", "follow_edges", "max_objects")})
    if plan != expected:
        raise ValueError("plan_changed")
    _retained_active_files(report)  # Validate existing receipts before any new target traffic.
    directory = out / ("origin-check-" + uuid4().hex)
    directory.mkdir(parents=True, exist_ok=False)
    result = deepcopy(report)
    budget = {"bytes": plan["max_bytes"], "requests": plan["max_requests"], "deadline": time.monotonic() + plan["window"]}
    files = {}
    for check in plan["checks"]:
        row: dict[str, Any] = {"check": check, "outcome": "skipped_not_allowed"}
        if check.startswith("tls"):
            der = b""
            remaining = budget["deadline"] - time.monotonic()
            if remaining <= 0 or budget["bytes"] <= 0 or budget["requests"] <= 0:
                row["outcome"] = "skipped_budget_exhausted"
            elif plan["target"] in plan["allow"]:
                budget["requests"] -= 1
                row, der = probe_tls({**plan, "tls_check": check, "window": remaining, "max_bytes": budget["bytes"]})
                budget["bytes"] -= len(der)
            row["certificate_ownership"] = verify_certificate_ownership(
                ownership_material, ownership_key, row.get("certificate_sha256", ""), plan["business_host"]) if check == "tls" else {"status": "unknown"}
            if der:
                row["certificate_der_base64"] = base64.b64encode(der).decode("ascii")
            row["independent_tls_bindings"] = verify_tls_bindings(binding_material, binding_key,
                row.get("peer_ip", ""), row.get("certificate_sha256", ""), row.get("observed_at", ""))
        else:
            row = run_http_check(check, plan, budget)
        files[f"{check}.json"] = _append_observation(result, plan["target"], row)
    _refresh_active_views(result)
    files.update({"plan.json": json.dumps(plan, sort_keys=True).encode(),
                  "report.json": json.dumps(result, ensure_ascii=False, sort_keys=True).encode()})
    files.update(_retained_active_files(result))
    if ownership_material:
        files["certificate-ownership.json"] = ownership_material
    if ownership_key:
        files["ownership-trust-anchor.pem"] = ownership_key
    if binding_material:
        files["tls-bindings.json"] = binding_material
    if binding_key:
        files["bindings-trust-anchor.pem"] = binding_key
    for name, data in sorted(files.items()):
        (directory / name).parent.mkdir(parents=True, exist_ok=True)
        if not atomic_create_bytes(directory / name, data):
            raise OSError("archive_file_exists")
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}
    atomic_create_bytes(directory / "SHA256.json", json.dumps(manifest, sort_keys=True).encode())
    return directory / f"{plan['checks'][0]}.json"


def _append_observation(result: dict, target: str, row: dict) -> bytes:
    encoded = json.dumps(row, sort_keys=True, ensure_ascii=True).encode()
    observation_sha = hashlib.sha256(encoded).hexdigest()
    relative = f"active_observations/{observation_sha}.json"
    # Bind every derived row to the exact archived receipt and retain all earlier checks.
    for endpoint in result.get("endpoints", []):
        if endpoint.get("value") != target:
            continue
        observation = {**row, "observation_sha256": observation_sha, "locator": {"stored_path": relative}}
        prior = endpoint.setdefault("enrichment", {}).get("active_observation", [])
        endpoint["enrichment"]["active_observation"] = sorted(
            [r for r in prior if isinstance(r, dict)] + [observation], key=lambda r: json.dumps(r, sort_keys=True))
        endpoint.setdefault("evidences", []).append(_to_jsonable(Evidence(
            source="active-probe", location=f"probe-target:{observation_sha}", snippet=row["outcome"],
            scope=EvidenceScope.CASE_EVIDENCE,
            observed_at=datetime.fromisoformat(row["observed_at"].replace("Z", "+00:00")).timestamp() if row.get("observed_at") else None,
            provenance={"artifact_sha256": observation_sha, "certificate_sha256": row.get("certificate_sha256")},
            locator={"stored_path": relative})))
    return encoded


def _retained_active_files(report: dict) -> dict[str, bytes]:
    """Keep earlier content-addressed active receipts valid in successive projections."""
    files = {}
    for endpoint in report.get("endpoints", []):
        for row in endpoint.get("enrichment", {}).get("active_observation", []):
            if not isinstance(row, dict):
                continue
            sha = row.get("observation_sha256")
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
                continue
            raw = {k: v for k, v in row.items() if k not in {"observation_sha256", "locator"}}
            data = json.dumps(raw, sort_keys=True, ensure_ascii=True).encode()
            if hashlib.sha256(data).hexdigest() != sha:
                raise ValueError("prior_active_receipt_hash_mismatch")
            files[f"active_observations/{sha}.json"] = data
            for material in [row, *row.get("requests", [])]:
                for field, hash_field, folder, extension in (
                    ("certificate_der_base64", "certificate_sha256", "certificates", "der"),
                    ("body_base64", "body_sha256", "bodies", "body"),
                ):
                    encoded = material.get(field)
                    if not isinstance(encoded, str):
                        continue
                    if len(encoded) > 3 * 1024 * 1024:
                        raise ValueError("prior_material_budget_exceeded")
                    raw = base64.b64decode(encoded, validate=True)
                    digest = hashlib.sha256(raw).hexdigest()
                    if digest != material.get(hash_field):
                        raise ValueError("prior_material_hash_mismatch")
                    files[f"{folder}/{digest}.{extension}"] = raw
    return files


def _refresh_active_views(result: dict) -> None:
    from apkscan.attribution.assemble import build_network_attribution
    from apkscan.core.report_io import report_from_dict

    typed = report_from_dict(result)
    view = build_network_attribution(typed.endpoints, artifact_id=str(typed.meta.get("sample_sha256") or typed.package_name), phase="probe-target")
    meta = result.setdefault("meta", {})
    if view is not None:
        meta["network_attribution"] = view
    closure = meta.get("closure")
    if not isinstance(closure, dict):
        return
    by_value = {endpoint.value: endpoint for endpoint in typed.endpoints}
    for target in closure.get("targets", []):
        value = target.get("value") if isinstance(target, dict) else None
        endpoint = by_value.get(value) if isinstance(value, str) else None
        if endpoint is None:
            continue
        refs = sorted({e.location for e in endpoint.evidences if e.source == "active-probe" and e.scope is EvidenceScope.CASE_EVIDENCE})
        layer = target.get("layers", {}).get("request_target")
        if refs and isinstance(layer, dict):
            layer.setdefault("evidence", {})["active_evidence"] = refs
    meta["closure"] = closure
