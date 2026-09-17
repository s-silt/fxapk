"""Bounded service-profile projections shared by passive providers.

These projections are evidence previews, not full API snapshots or an assertion
that all products belong to the same host, tenant, or observation time.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import unicodedata
from typing import Any
from apkscan.core.redact import scrub_urls


def environment_secrets() -> set[str]:
    return {value for name, raw in os.environ.items()
            if any(word in name.upper() for word in ("KEY", "TOKEN", "SECRET", "PASSWORD"))
            for value in (raw, raw.strip()) if value}


SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^[ \t]*(set-cookie|cookie|authorization|proxy-authorization)[ \t]*:[^\r\n]*"
)
_SENSITIVE_KEYS = {
    "password", "secret", "token", "apikey", "authorization", "proxyauthorization",
    "setcookie", "cookie", "cookies",
}


def _normalized_key(value: object) -> str:
    return re.sub(r"[-_]", "", unicodedata.normalize("NFKC", str(value))).casefold().strip()


def bounded_profile(value: object, *, max_chars: int = 16384) -> Any:
    """Hard limits: 256 nodes (including keys), and max_chars across keys/values.

    Metadata and redaction replacements share the budget. At tiny budgets a
    container may be empty because even a truncation marker cannot fit.
    """
    remaining = [max(0, max_chars), 256]
    secrets = sorted(environment_secrets(), key=len, reverse=True)

    def clean(text: str) -> str:
        for secret in secrets:
            text = text.replace(secret, "[credential-redacted]")
        text = SENSITIVE_HEADER_RE.sub(r"\1: [redacted]", text)
        return scrub_urls(text)[0]

    def reserve(chars: int, nodes: int) -> bool:
        if remaining[0] < chars or remaining[1] < nodes:
            return False
        remaining[0] -= chars
        remaining[1] -= nodes
        return True

    def visit(item: object, depth: int) -> Any:
        # Callers reserve the value node, including nulls and replacement values.
        if depth > 6:
            if reserve(9, 2):
                return {"truncated": True}
            return None
        if isinstance(item, str):
            text = clean(item)
            if len(text) <= min(4096, remaining[0]):
                remaining[0] -= len(text)
                return text
            metadata = {"truncated": True, "characters": len(text),
                        "redacted_sha256": hashlib.sha256(text.encode()).hexdigest()}
            overhead = sum(map(len, metadata)) + 64 + len("preview")
            if reserve(overhead, 8):
                limit = min(4096, remaining[0])
                remaining[0] -= limit
                return {"preview": text[:limit], **metadata}
            # No room for a preview envelope: an empty preview is safer than
            # silently presenting a shortened credential replacement as a value.
            if reserve(9, 2):
                return {"truncated": True}
            return ""
        if item is None or isinstance(item, (bool, int)):
            return item
        if isinstance(item, float):
            return item if math.isfinite(item) else None
        if isinstance(item, list):
            marker = reserve(19, 6)  # wrapper, three keys, total and boolean
            values = []
            for child in item[:40]:
                if not reserve(0, 1):
                    break
                values.append(visit(child, depth + 1))
            if len(values) < len(item) and marker:
                return {"items": values, "total": len(item), "truncated": True}
            if marker:
                remaining[0] += 19
                remaining[1] += 6
            return values
        if isinstance(item, dict):
            marker = reserve(10, 2)  # _truncated key and boolean
            result: dict[str, Any] = {}
            sensitive_pair = any(
                _normalized_key(key) == "name" and _normalized_key(child) in _SENSITIVE_KEYS
                for key, child in item.items() if isinstance(child, str)
            )
            consumed = 0
            for key, child in list(item.items())[:40]:
                normalized = _normalized_key(key)  # before cleaning or truncation
                sensitive = normalized in _SENSITIVE_KEYS or (sensitive_pair and normalized == "value")
                replacement_chars = len("[redacted]") if sensitive else 0
                if remaining[1] < 2 or remaining[0] < replacement_chars:
                    break
                name = (str(key) if sensitive else clean(str(key)))[:min(100, remaining[0] - replacement_chars)]
                reserve(len(name), 2)  # key and value nodes
                if sensitive:
                    reserve(replacement_chars, 0)
                    result[name] = "[redacted]"
                else:
                    result[name] = visit(child, depth + 1)
                consumed += 1
            if consumed < len(item) and marker:
                result["_truncated"] = True
            elif marker:
                remaining[0] += 10
                remaining[1] += 2
            return result
        return None

    reserve(0, 1)
    return visit(value, 0)


def coverage(total: object, returned: int, *, limit: int = 20,
             observed: int | None = None, more: bool = False) -> dict[str, object]:
    """Record unknown totals and bounded pages without silently declaring completeness."""
    if isinstance(total, str) and total.isdecimal() and len(total) < 20:
        total = int(total)
    count = total if isinstance(total, int) and not isinstance(total, bool) and total >= 0 else None
    truncated = more or (observed is not None and observed > returned) or (count is not None and count > returned)
    return {"total_reported": count, "returned": returned, "page_limit": limit,
            "coverage_complete": count is not None and count == returned and not truncated,
            "truncated": truncated if count is not None or truncated else None}


PROFILE_FIELDS = (
    "title", "version", "service", "header.server.name", "header.server.version",
    "country.name", "province.name", "city.name", "organization.name", "isp.name",
    "ssl.jarm", "ssl.ja3s", "rdns",
    "product", "product_category", "components", "component", "software", "os", "operating_system",
    "banner", "header", "http", "https", "tls", "ssl", "cert", "certificate", "certificates",
    "device", "device_type", "manufacturer", "tags", "cpe", "cpe23", "transport_protocol",
    "time", "timestamp", "time_stamp", "update_time", "updated_at", "last_updated_at",
    "lastupdatetime", "observed_at", "scan_time", "first_seen", "last_seen", "start_time", "end_time",
)


def service_profile(record: dict[str, Any]) -> dict[str, Any]:
    return bounded_profile({k: record[k] for k in PROFILE_FIELDS if record.get(k) not in (None, "", [], {})})
