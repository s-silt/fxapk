"""网络事实的纯规范化与稳定指纹工具。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import urllib.parse

__all__ = [
    "KNOWN_INTERCEPT_IPS",
    "is_known_intercept_ip",
    "normalize_authority",
    "normalize_domain",
    "normalize_ip",
    "sanitize_absolute_url",
    "sanitize_http_path",
    "stable_digest",
]

_MAX_DOMAIN_LENGTH = 253
_MAX_LABEL_LENGTH = 63
_DEFAULT_PORTS = {"http": 80, "https": 443}

#: Known non-business interception nodes. A domestically-blocked fraud domain resolves
#: to an anti-fraud interception page IP — never a real serving/landing host — so it must
#: be excluded from attribution (never surfaced as "the domain's serving IP"). Shared by
#: the pcap ingest (drop as a runtime endpoint) and the attribution bridge (mint no edge).
KNOWN_INTERCEPT_IPS: frozenset[str] = frozenset({"183.192.65.101"})


def is_known_intercept_ip(value: str) -> bool:
    """Whether ``value`` is a known interception page IP, not a business server."""
    return value in KNOWN_INTERCEPT_IPS


def _require_string(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not value:
        raise ValueError(f"{name} must not be empty")
    return value


def normalize_ip(value: str) -> str:
    """返回 IPv4/IPv6 字面量的压缩规范形式。"""
    raw = _require_string("IP address", value)
    if raw != raw.strip():
        raise ValueError("IP address must not contain surrounding whitespace")
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc


def normalize_domain(value: str) -> str:
    """返回小写 IDNA 域名；去掉尾点并拒绝 IP 字面量。"""
    raw = _require_string("domain", value)
    if any(char.isspace() for char in raw):
        raise ValueError(f"whitespace not allowed in domain: {value!r}")
    stripped = raw.rstrip(".")
    if not stripped:
        raise ValueError("domain must contain at least one label")
    try:
        ipaddress.ip_address(stripped)
    except ValueError:
        pass
    else:
        raise ValueError(f"IP literal is not a domain: {value!r}")

    labels: list[str] = []
    for label in stripped.split("."):
        if not label:
            raise ValueError(f"empty label in domain: {value!r}")
        try:
            encoded = label.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(f"invalid domain label: {label!r}") from exc
        if not encoded or len(encoded) > _MAX_LABEL_LENGTH:
            raise ValueError(f"invalid domain label: {label!r}")
        labels.append(encoded)

    normalized = ".".join(labels)
    if len(normalized) > _MAX_DOMAIN_LENGTH:
        raise ValueError(f"domain too long: {value!r}")
    return normalized


def _parse_port(value: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError(f"invalid port: {value!r}")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return port


def normalize_authority(value: str) -> tuple[str, str, int | None, bool]:
    """返回 ``(authority, host, port, is_ip)``，支持括号 IPv6。"""
    raw = _require_string("authority", value)
    if any(char.isspace() for char in raw):
        raise ValueError(f"whitespace not allowed in authority: {value!r}")
    if "@" in raw:
        raise ValueError("userinfo is not allowed in an authority")
    if any(char in raw for char in "/?#"):
        raise ValueError("path, query, or fragment is not allowed in an authority")

    port_text: str | None
    if raw.startswith("["):
        closing = raw.find("]")
        if closing < 0:
            raise ValueError(f"unterminated IPv6 authority: {value!r}")
        host_raw = raw[1:closing]
        remainder = raw[closing + 1 :]
        if remainder and not remainder.startswith(":"):
            raise ValueError(f"invalid suffix after IPv6 authority: {value!r}")
        port_text = remainder[1:] if remainder else None
        try:
            host = ipaddress.IPv6Address(host_raw).compressed
        except ValueError as exc:
            raise ValueError(f"invalid IPv6 authority: {value!r}") from exc
        rendered_host = f"[{host}]"
        is_ip = True
    else:
        if raw.count(":") > 1:
            raise ValueError("IPv6 authorities must use brackets")
        if ":" in raw:
            host_raw, port_text = raw.split(":", 1)
        else:
            host_raw, port_text = raw, None
        if not host_raw:
            raise ValueError("authority host must not be empty")
        try:
            host = ipaddress.IPv4Address(host_raw).compressed
            is_ip = True
        except ValueError:
            host = normalize_domain(host_raw)
            is_ip = False
        rendered_host = host

    port = _parse_port(port_text) if port_text is not None else None
    authority = rendered_host if port is None else f"{rendered_host}:{port}"
    return authority, host, port, is_ip


def sanitize_http_path(value: str) -> str:
    """返回去掉 query/fragment/authority 的 origin-form 路径。"""
    if not isinstance(value, str):
        raise TypeError("HTTP path must be a string")
    parsed = urllib.parse.urlsplit(value)
    path = parsed.path or "/"
    return path if path.startswith("/") else f"/{path}"


def sanitize_absolute_url(value: str) -> str:
    """规范化 HTTP(S) URL，并移除 query、fragment 与默认端口。"""
    raw = _require_string("URL", value)
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError("URL scheme must be http or https")
    if not parsed.netloc:
        raise ValueError("absolute URL must contain an authority")
    _authority, host, port, is_ip = normalize_authority(parsed.netloc)
    rendered_host = f"[{host}]" if is_ip and ":" in host else host
    netloc = (
        rendered_host
        if port is None or port == _DEFAULT_PORTS[scheme]
        else f"{rendered_host}:{port}"
    )
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return urllib.parse.urlunsplit((scheme, netloc, path, "", ""))


def stable_digest(namespace: str, payload: object) -> str:
    """对命名空间和规范 JSON 计算完整 SHA-256 十六进制摘要。"""
    clean_namespace = _require_string("namespace", namespace).strip()
    if not clean_namespace:
        raise ValueError("namespace must not be blank")
    try:
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("payload is not canonical-JSON serializable") from exc
    digest = hashlib.sha256()
    digest.update(clean_namespace.encode("utf-8"))
    digest.update(b"\0")
    digest.update(canonical.encode("utf-8"))
    return digest.hexdigest()
