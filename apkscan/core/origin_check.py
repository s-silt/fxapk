"""Bounded comparison of an explicit CDN resource and an evidence-derived candidate.

No address discovery, bucket guessing, automatic redirects or origin confirmation.
Cloud VM attribution is deliberately separate from HTTP resource association.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import io
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import uuid4

from apkscan.core.case_identity import normalize_case_id

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 15

# Only documented public endpoint shapes. Custom domains remain unclassified.
# A pattern match identifies an address convention, not ownership or liveness.
_STORAGE = (
    ("aliyun_oss", r"(?:(?P<bucket>[a-z0-9][a-z0-9-]*)\.)?(?P<endpoint>oss-[a-z0-9-]+\.aliyuncs\.com)",
     "https://help.aliyun.com/zh/oss/user-guide/regions-and-endpoints"),  # leak-scan: allow 存储地址模式的公开厂商文档来源，非目标地址：help.aliyun.com
    ("tencent_cos", r"(?:(?P<bucket>[a-z0-9-]+-[0-9]+)\.)?(?P<endpoint>cos\.[a-z0-9-]+\.myqcloud\.com)",
     "https://cloud.tencent.com/document/product/436/6224"),  # leak-scan: allow 存储地址模式的公开厂商文档来源，非目标地址：cloud.tencent.com
    ("huawei_obs", r"(?:(?P<bucket>[a-z0-9][a-z0-9-]*)\.)?(?P<endpoint>obs\.[a-z0-9-]+\.myhuaweicloud\.com)",
     "https://support.huaweicloud.com/obs_faq/obs_faq_0031.html"),  # leak-scan: allow 存储地址模式的公开厂商文档来源，非目标地址：support.huaweicloud.com
    ("volcengine_tos", r"(?:(?P<bucket>[a-z0-9][a-z0-9-]*)\.)?(?P<endpoint>tos-(?:s3-)?[a-z0-9-]+\.volces\.com)",
     "https://www.volcengine.com/docs/6561/107356"),  # leak-scan: allow 存储地址模式的公开厂商文档来源，非目标地址：www.volcengine.com
    ("baidu_bos", r"(?:(?P<bucket>[a-z0-9][a-z0-9-]*)\.)?(?P<endpoint>(?:bj|gz|su)\.bcebos\.com)",
     "https://cloud.baidu.com/doc/BOS/s/ckaqihkra-en"),  # leak-scan: allow 存储地址模式的公开厂商文档来源，非目标地址：cloud.baidu.com
    ("kingsoft_ks3", r"(?:(?P<bucket>[a-z0-9][a-z0-9-]*)\.)?(?P<endpoint>ks3-[a-z0-9-]+\.ksyuncs\.com)",
     "https://docs.ksyun.com/documents/6761"),  # leak-scan: allow 存储地址模式的公开厂商文档来源，非目标地址：docs.ksyun.com
)


def storage_address(host: str) -> dict[str, Any] | None:
    host = host.lower().rstrip(".")
    for product, pattern, source in _STORAGE:
        match = re.fullmatch(pattern, host)
        if match and "internal" not in match["endpoint"]:
            bucket = match["bucket"]
            return {"product": product, "bucket": bucket, "endpoint": match["endpoint"],
                    "scope": "bucket_address" if bucket else "regional_endpoint_only",
                    "basis": "documented_domain_pattern", "source": source}
    return None


def _url(value: str) -> dict[str, Any]:
    if not value or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError("URL must not contain whitespace or control characters")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("An absolute HTTP(S) URL is required")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("URL credentials and fragments are not supported")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.:-]+", host) or "%" in host:
        raise ValueError("Invalid URL host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    path = parsed.path or "/"
    target = path + ("?" + parsed.query if parsed.query else "")
    try:
        target.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("URL path must be percent-encoded") from exc
    authority = f"[{host}]" if ":" in host else host
    if port != (443 if parsed.scheme == "https" else 80):
        authority += f":{port}"
    return {"url": value, "scheme": parsed.scheme, "host": host, "port": port,
            "host_header": authority, "sni": host if parsed.scheme == "https" else None,
            "request_target": target, "storage": storage_address(host)}


def build_plan(reference_url: str, candidate_url: str, *, case_id: str,
               source_note: str, candidate_ip: str = "") -> dict[str, Any]:
    """Pure offline plan. URL authority controls Host/SNI even with a pinned IP."""
    if not case_id.strip() or not source_note.strip():
        raise ValueError("case_id and candidate source note are required")
    case_id = normalize_case_id(case_id)
    reference, candidate = _url(reference_url), _url(candidate_url)
    if candidate_ip:
        candidate["connect_ip"] = str(ipaddress.ip_address(candidate_ip))
    if reference == candidate:
        raise ValueError("Reference and candidate are identical; no independent comparison")
    return {"schema": "fxapk-origin-check-1", "case_id": case_id, "source_note": source_note,
            "reference": reference, "candidate": candidate, "max_requests": 2,
            "max_body_bytes_per_request": MAX_BYTES, "timeout_seconds": TIMEOUT,
            "follow_redirects": False, "method": "GET", "status": "planned",
            "origin_status": "not_confirmed", "scope": "specified_resource_only"}


def _public_ip(value: str) -> str:
    address = ipaddress.ip_address(value)
    mapped = getattr(address, "ipv4_mapped", None)
    if not address.is_global or (mapped is not None and not mapped.is_global):
        raise ValueError("Candidate/request address is not a public Internet address")
    return str(address)


def _resolve(request: dict[str, Any]) -> str:
    if request.get("connect_ip"):
        return _public_ip(request["connect_ip"])
    # Resolve once, validate every answer and pin one address; no hidden reconnect/DNS rebind.
    answers = socket.getaddrinfo(request["host"], request["port"], type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(_public_ip(str(row[4][0])) for row in answers))
    if not addresses:
        raise ValueError("No usable address")
    return addresses[0]


class _DeadlineReader(io.RawIOBase):
    def __init__(self, raw: Any, sock: socket.socket, deadline: float):
        self.raw, self.sock, self.deadline = raw, sock, deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Response time limit")
        self.sock.settimeout(remaining)
        return self.raw.readinto(buffer)

    def close(self) -> None:
        self.raw.close()
        super().close()


class _DeadlineSocket:
    def __init__(self, sock: socket.socket, deadline: float):
        self.sock, self.deadline = sock, deadline

    def makefile(self, mode: str) -> io.BufferedReader:
        if mode != "rb":
            raise ValueError("Only binary response reads are supported")
        raw = self.sock.makefile("rb", buffering=0)
        return io.BufferedReader(_DeadlineReader(raw, self.sock, self.deadline))


class _PinnedConnection(http.client.HTTPConnection):
    def __init__(self, request: dict[str, Any], address: str):
        super().__init__(request["host"], request["port"], timeout=TIMEOUT)
        self.address = address
        self.tls = request["scheme"] == "https"
        deadline = time.monotonic() + TIMEOUT

        class DeadlineResponse(http.client.HTTPResponse):
            def __init__(self, sock: Any, *args: Any, **kwargs: Any):
                super().__init__(cast(Any, _DeadlineSocket(sock, deadline)), *args, **kwargs)

        self.response_class = DeadlineResponse

    def connect(self) -> None:
        sock = socket.create_connection((self.address, self.port), self.timeout)
        try:
            if self.tls:
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                self.sock = context.wrap_socket(sock, server_hostname=self.host)
            else:
                self.sock = sock
        except Exception:
            sock.close()
            raise


def fetch_resource(request: dict[str, Any], directory: Path, label: str) -> dict[str, Any]:
    """One GET, no inherited proxy/auth/cookies, TLS verification enabled, bounded body."""
    result: dict[str, Any] = {"request": request, "observed_at": datetime.now(timezone.utc).isoformat(),
                              "status": "failed", "body_complete": False}
    connection = None
    try:
        address = _resolve(request)
        result["connected_ip"] = address
        connection = _PinnedConnection(request, address)
        started = time.monotonic()
        connection.request("GET", request["request_target"], headers={
            "Host": request["host_header"], "Accept-Encoding": "identity", "Connection": "close",
            "User-Agent": "fxapk-origin-check/1"})
        response = connection.getresponse()
        result["http_status"] = response.status
        result["response_headers"] = response.getheaders()  # preserve duplicate fields
        body = bytearray()
        try:
            while len(body) <= MAX_BYTES:
                if time.monotonic() - started >= TIMEOUT:
                    raise TimeoutError("Response time limit")
                chunk = response.read1(min(65536, MAX_BYTES + 1 - len(body)))
                if not chunk:
                    result["body_complete"] = True
                    break
                body.extend(chunk)
            if len(body) > MAX_BYTES:
                del body[MAX_BYTES:]
                result["body_complete"] = False
            declared = response.getheader("Content-Length")
            if declared is not None and int(declared) != len(body):
                result["body_complete"] = False
            result["status"] = "observed"
        finally:
            path = directory / f"{label}.body"
            path.write_bytes(body)
            result.update(body_file=path.name, body_bytes=len(body),
                          body_sha256=hashlib.sha256(body).hexdigest())
    except (OSError, ValueError, http.client.HTTPException) as exc:
        result["error_type"] = type(exc).__name__  # no credential-bearing URL/error text in console
        result["status"] = "failed"
    finally:
        if connection:
            connection.close()
    return result


def compare_resources(reference: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Matching bytes support resource association, never automatic origin confirmation."""
    result: dict[str, Any] = {"status": "inconclusive", "origin_status": "not_confirmed",
                              "scope": "specified_resource_only", "reasons": []}
    for label, row in (("reference", reference), ("candidate", candidate)):
        if row.get("status") != "observed" or not row.get("body_complete"):
            result["reasons"].append(f"{label}:failed_or_incomplete")
        if row.get("http_status") != 200 or not row.get("body_bytes"):
            result["reasons"].append(f"{label}:requires_nonempty_200_response")
        if not re.fullmatch(r"[0-9a-f]{64}", str(row.get("body_sha256", ""))):
            result["reasons"].append(f"{label}:missing_body_digest")
    ref_request, cand_request = reference.get("request", {}), candidate.get("request", {})
    if (reference.get("connected_ip") == candidate.get("connected_ip")
            and ref_request.get("host_header") == cand_request.get("host_header")
            and ref_request.get("port") == cand_request.get("port")
            and ref_request.get("scheme") == cand_request.get("scheme")):
        result["reasons"].append("same_network_endpoint_not_independent")
    if result["reasons"]:
        return result
    if (reference.get("body_sha256") == candidate.get("body_sha256")
            and reference.get("body_bytes") == candidate.get("body_bytes")):
        result.update(status="resource_match", reasons=["same_complete_body_sha256",
                      "shared_error_page_mirror_backup_or_proxy_not_excluded"])
    else:
        result.update(status="content_differs", reasons=["cache_rewrite_or_dynamic_content_not_excluded"])
    return result


def run_check(plan: dict[str, Any], out: Path) -> Path:
    """Produce a new evidence directory; no existing report or frozen package is changed."""
    directory = out / ("origin-check-" + uuid4().hex)
    directory.mkdir(parents=True, exist_ok=False)
    results = {label: fetch_resource(plan[label], directory, label) for label in ("reference", "candidate")}
    report = {**plan, "status": "executed", "observations": results,
              "assessment": compare_resources(results["reference"], results["candidate"])}
    report_path = directory / "origin-check.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir() if path.is_file()}
    (directory / "SHA256.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return report_path
