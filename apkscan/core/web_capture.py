"""Explicitly authorized HTTP evidence capture. No JS execution or form actions."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import time
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from apkscan.config.fetch import _target_is_safe

_HEADER_ALLOWLIST = {"content-type", "content-length", "location", "server", "cache-control", "content-encoding"}


def _new_session() -> Any:
    """Reuse 1.16's pinned-IP, verified-TLS and absolute-read-deadline transport."""
    from apkscan.core import origin_check

    class Raw:
        def __init__(self, response):
            self.response = response
            self.version = response.version
        def read1(self, size, decode_content=True):
            return self.response.read1(size)

    class Response:
        def __init__(self, response, connection):
            self.raw = Raw(response)
            self.status_code, self.reason = response.status, response.reason
            self.headers, self.connection = response.headers, connection
            self.response = response
        def close(self):
            self.response.close()
            self.connection.close()

    class Session:
        trust_env = False
        def __init__(self):
            self.cookies = self
            self.connections = []
        def clear(self):
            pass  # No cookie jar, authentication or environment proxy is used.
        def get(self, url, *, stream, allow_redirects, timeout, headers):
            if allow_redirects is not False:
                raise ValueError("automatic_redirects_forbidden")
            request = origin_check._url(url)
            address = origin_check._resolve(request)
            connection = origin_check._PinnedConnection(request, address, timeout=min(timeout))
            self.connections.append(connection)
            connection.request("GET", request["request_target"], headers={
                "Host": request["host_header"], "Accept-Encoding": "identity",
                "Connection": "close", "User-Agent": "fxapk-authorized-evidence/1"})
            return Response(connection.getresponse(), connection)
        def close(self):
            for connection in self.connections:
                connection.close()

    return Session()


def capture_http(url: str, *, authorized: bool = False,
                 allowed_hosts: tuple[str, ...] = (), max_hops: int = 5,
                 max_bytes: int = 4 * 1024 * 1024, timeout: float = 30.0) -> dict[str, Any]:
    """Capture a bounded GET/redirect chain into HAR-compatible private material.

    Extra redirect hosts require explicit allow-listing. Initial hostname alone
    is implicitly scoped. Missing bodies, failed requests and redirect stops are
    evidence gaps; no negative lookup or complete browser-capture claim follows.
    """
    result: dict[str, Any] = {"log": {"version": "1.2", "creator": {"name": "fxapk-http-capture", "version": "1"},
                                    "entries": []},
                             "_capture": {"status": "not_authorized", "gaps": [], "network_requests": 0,
                                          "javascript_executed": False, "subresources_captured": False,
                                          "headers_filtered": True, "body_representation": "HTTP entity bytes; identity encoding requested",
                                          "complete_export_verified": False}}
    if authorized is not True:
        return result
    if not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 32 for c in url):
        raise ValueError("invalid_url")
    if isinstance(max_hops, bool) or not isinstance(max_hops, int) or not 1 <= max_hops <= 10:
        raise ValueError("invalid_hop_budget")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 16 * 1024 * 1024:
        raise ValueError("invalid_byte_budget")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 120:
        raise ValueError("invalid_time_budget")
    parsed = urlsplit(url)
    hosts = {(parsed.hostname or "").lower().rstrip("."), *(host.lower().rstrip(".") for host in allowed_hosts)}
    result["_capture"]["requested_url"] = url
    session = _new_session()
    total = 0
    deadline = time.monotonic() + timeout
    seen: set[str] = set()
    result["_capture"]["status"] = "partial"
    try:
        for _ in range(max_hops):
            parsed = urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
                result["_capture"]["gaps"].append("unsupported_or_credentialed_url")
                break
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
            if parsed.hostname.lower().rstrip(".") not in hosts:
                result["_capture"]["gaps"].append("redirect_host_not_authorized")
                break
            if url in seen:
                result["_capture"]["gaps"].append("redirect_cycle")
                break
            seen.add(url)
            safe, _reason = _target_is_safe(url)
            if not safe:
                result["_capture"]["gaps"].append("target_not_verified_public")
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result["_capture"]["gaps"].append("time_budget_exceeded")
                break
            start = datetime.now(timezone.utc).isoformat()
            request_start = time.monotonic()
            response = None
            try:
                session.cookies.clear()
                result["_capture"]["network_requests"] += 1
                response = session.get(url, stream=True, allow_redirects=False,
                                       timeout=(min(10.0, remaining), min(10.0, remaining)),
                                       headers={"User-Agent": "fxapk-authorized-evidence/1"})
                body = bytearray()
                truncated = False
                while True:
                    if time.monotonic() >= deadline:
                        truncated = True
                        result["_capture"]["gaps"].append("time_budget_exceeded")
                        break
                    available = max_bytes - total
                    try:
                        chunk = response.raw.read1(min(8192, available + 1), decode_content=True)
                    except Exception as exc:  # noqa: BLE001 - preserve already received bytes and response headers
                        truncated = True
                        result["_capture"]["gaps"].append("read_failed:" + type(exc).__name__)
                        break
                    if not chunk:
                        break
                    body.extend(chunk[:available])
                    total += min(len(chunk), available)
                    if len(chunk) > available:
                        truncated = True
                        result["_capture"]["gaps"].append("body_budget_exceeded")
                        break
                content_encoding = response.headers.get("Content-Encoding", "").lower()
                if content_encoding not in ("", "identity"):
                    result["_capture"]["gaps"].append("encoded_body_preserved_not_decoded")
                headers = [{"name": key, "value": value} for key, value in response.headers.items()
                           if key.lower() in _HEADER_ALLOWLIST]
                redirect = response.headers.get("Location", "") if 300 <= response.status_code < 400 else ""
                result["log"]["entries"].append({
                    "startedDateTime": start, "time": max(0.0, (time.monotonic() - request_start) * 1000),
                    "cache": {}, "timings": {"send": -1, "wait": -1, "receive": -1},
                    "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1",
                                "cookies": [], "headers": [], "queryString": [], "headersSize": -1, "bodySize": 0},
                    "response": {"status": response.status_code, "statusText": str(getattr(response, "reason", "")),
                                 "httpVersion": {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(getattr(response.raw, "version", 0), "unknown"),
                                 "headers": headers, "cookies": [], "headersSize": -1, "bodySize": -1,
                                 "redirectURL": redirect, "content": {
                                     "size": len(body), "mimeType": response.headers.get("Content-Type", ""),
                                     "encoding": "base64", "text": base64.b64encode(body).decode()}},
                    "_body_truncated": truncated, "_body_content_encoding": content_encoding})
                if truncated:
                    break
                if not redirect:
                    result["_capture"]["status"] = "partial" if result["_capture"]["gaps"] else "captured_http"
                    break
                url = urljoin(url, redirect)
            except Exception as exc:  # noqa: BLE001 - retain a bounded public error code, never exception payload
                result["_capture"]["gaps"].append("request_failed:" + type(exc).__name__)
                break
            finally:
                if response is not None:
                    response.close()
        else:
            result["_capture"]["gaps"].append("redirect_hop_budget_exceeded")
    finally:
        session.close()
    return result
