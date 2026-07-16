"""PR6 被动情报适配器的共享有界 HTTP 传输层与证据归一化工具。

`_HttpIntelProvider` 是介于 PR5 `IntelProvider` 与各具体适配器之间的**中间抽象基类**：
它**不**实现 `_fetch`（保持抽象，故 PR5 的 `__init_subclass__` 对这一依赖注入层跳过声明
校验），把注入的 `requests.Session` 藏在**名字改写**的私有属性 `self.__session` 后，只暴露
一个传输模板 `_fetch_via_http` 和两个纯钩子 `_request_spec` / `_interpret`。适配器的 `_fetch`
是一行委托 `return self._fetch_via_http(capability, query)`。

不变量（结构性、非约定）：`_fetch_via_http` 是全包**唯一**的 `session.get(...)` 调用点，直线
代码、无循环/重试/翻页/回退，`allow_redirects=False`、`stream=True`、`timeout=(connect, read)`、
流式解压字节上限 + 墙钟截止、`try/finally` 关闭响应。两个钩子都拿不到 session，故 Shodan 域名
查询在物理上无法在 `/dns/resolve` 之后链式 `/shodan/host`。

密钥安全：所有传输失败抛**无消息**（或仅静态串）的、类名即诊断的异常，交给 PR5 基座的
`_safe_exception_name` 脱敏成 FAILURE；适配器零日志、不 `str()` requests 异常；`raw_reference`
只由 {provider, capability} 常量拼成，密钥/URL 无从泄漏。

★残留风险（非本模块可控，与旧 enricher 同）：FOFA/Hunter/Shodan 的 key 按上游要求走 query
string，真实 Session 下若进程开了 `urllib3.connectionpool` 的 DEBUG 日志，请求行（含 query）会
被该第三方 logger 打出。本库刻意不从库内全局改写 logging 级别（那是会误伤调用方的反模式）；
取证运行**不要**为 urllib3 开 DEBUG。Censys 用 Bearer 头（不入 query），无此暴露面。

本模块不接入任何运行时；只在显式 `lookup_*` 调用时执行。
"""

from __future__ import annotations

import json
import os
import time
from abc import abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, final
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter

from apkscan.attribution.models import AttributionEvidence
from apkscan.intel.models import IntelCapability, IntelResult
from apkscan.intel.providers.base import IntelProvider
from apkscan.network import NetworkEntity
from apkscan.network.fingerprints import normalize_authority, normalize_ip, stable_digest

__all__ = [
    "PASSIVE_EVIDENCE_CONFIDENCE",
    "AuthError",
    "CertificateMismatchError",
    "ClientError",
    "CredentialMissingError",
    "MalformedPayloadError",
    "OversizeResponseError",
    "ProviderDeclaredError",
    "RateLimitedError",
    "RedirectResponseError",
    "ServerError",
    "UnexpectedStatusError",
    "UpstreamTimeoutError",
    "_HttpIntelProvider",
    "_RequestSpec",
]

# --------------------------------------------------------------------------- #
# Bound constants (imported by tests so caps never drift between impl & test). #
# --------------------------------------------------------------------------- #
_CONNECT_TIMEOUT = 5.0
_READ_TIMEOUT = 15.0
#: best-effort wall-clock ceiling, checked once per streamed chunk. The HARD
#: per-read bound against a fully stalled socket is _READ_TIMEOUT (requests'
#: per-recv timeout); this ceiling additionally bounds a server that trickles
#: many small chunks. A single large chunk filled by a precisely-tuned
#: sub-timeout drip is not fully bounded here — that requires a compromised
#: pinned provider (fixed HTTPS authority over TLS), out of the practical threat
#: model — but the small chunk size keeps the check frequent for real traffic.
_WALL_DEADLINE = 30.0
#: decompressed body cap (iter_content yields post-decompression bytes, so this
#: is the authoritative guard against a gzip bomb, not Content-Length).
_MAX_RESPONSE_BYTES = 5_242_880  # 5 MiB
#: small enough that the byte cap + wall deadline are re-checked frequently
#: during a streamed read (real HTTP bodies arrive in <= MSS-sized segments).
_CHUNK_SIZE = 8_192
#: max array items considered per JSON array (aligns with FOFA/Hunter page_size).
_MAX_RECORDS = 100
#: descriptive-string truncation length.
_MAX_SCALAR_LEN = 512
#: max evidence records per result, applied AFTER dedup + sort so the kept
#: subset is deterministic.
_MAX_EVIDENCE = 256

#: One flat modest prior: a single passive OSINT observation is corroborating,
#: never confirming, and must sit below the fusion layer's >=2-signal bar. A
#: constant is also deterministic, which id/dedup stability requires.
PASSIVE_EVIDENCE_CONFIDENCE = 0.5

#: closed header-name allowlist for `_RequestSpec.headers`.
_ALLOWED_HEADER_NAMES = frozenset(
    {"Authorization", "Accept", "User-Agent", "X-Organization-ID"}
)


# --------------------------------------------------------------------------- #
# Message-free transport exceptions: the class NAME is the diagnostic. PR5's    #
# _safe_exception_name uses type(exc).__name__ (all identifiers here) as the    #
# FAILURE reason, so these must never carry a URL/header/body fragment.         #
# --------------------------------------------------------------------------- #
class _TransportError(Exception):
    """Base for message-free transport errors; carries no dynamic message."""


class RedirectResponseError(_TransportError):
    """A 3xx response was returned (redirects are never followed)."""


class AuthError(_TransportError):
    """Upstream returned 401/403."""


class RateLimitedError(_TransportError):
    """Upstream returned 429."""


class ClientError(_TransportError):
    """Upstream returned a 4xx not otherwise classified (incl. an un-flagged 404)."""


class ServerError(_TransportError):
    """Upstream returned 5xx."""


class UnexpectedStatusError(_TransportError):
    """Upstream returned a status that is neither 200 nor a classified error."""


class OversizeResponseError(_TransportError):
    """The response body exceeded the decompressed byte cap."""


class UpstreamTimeoutError(_TransportError):
    """The streamed read exceeded the total wall-clock deadline."""


class MalformedPayloadError(_TransportError):
    """The payload was not a JSON object, or had an unusable envelope shape."""


class ProviderDeclaredError(_TransportError):
    """The 200 body declared an application-level error (e.g. FOFA error:true)."""


class CredentialMissingError(_TransportError):
    """The credential vanished between dispatch's presence check and the read."""


class CertificateMismatchError(_TransportError):
    """A certificate asset returned a fingerprint other than the queried one."""


# --------------------------------------------------------------------------- #
# Request spec + status/read helpers                                           #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _RequestSpec:
    """The shape of the single outgoing request; carries no authority/scheme.

    The transport builds the URL as ``https://<_API_AUTHORITY><path>``; the hook
    supplies only path/params/headers, so the looked-up entity can never become
    the URL host.
    """

    path: str
    params: Mapping[str, str] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)
    empty_on_404: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path.startswith("/"):
            raise ValueError("request path must start with '/'")
        if "://" in self.path or any(ch in self.path for ch in "?#"):
            raise ValueError("request path must not contain a scheme, query, or fragment")
        if any(ch.isspace() for ch in self.path):
            raise ValueError("request path must not contain whitespace")
        for name in self.headers:
            if name not in _ALLOWED_HEADER_NAMES:
                raise ValueError(f"header name not allowed: {name!r}")


def _gate_status(status: int) -> None:
    """Raise a typed, message-free error for any non-200 status.

    404 that should mean EMPTY is handled by the caller before this runs; here a
    404 reaching us is an un-flagged endpoint failure -> ClientError.
    """
    if status == 200:
        return
    if 300 <= status < 400:
        raise RedirectResponseError
    if status in (401, 403):
        raise AuthError
    if status == 429:
        raise RateLimitedError
    if 400 <= status < 500:
        raise ClientError
    if 500 <= status < 600:
        raise ServerError
    raise UnexpectedStatusError


def _read_bounded(response: Any) -> bytes:
    """Stream at most ``_MAX_RESPONSE_BYTES`` decompressed bytes, enforcing a
    wall-clock deadline. Content-Length is only a cheap pre-filter."""
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            if int(declared) > _MAX_RESPONSE_BYTES:
                raise OversizeResponseError
        except (TypeError, ValueError):
            pass
    deadline = time.monotonic() + _WALL_DEADLINE
    buffer = bytearray()
    for chunk in response.iter_content(_CHUNK_SIZE):
        if time.monotonic() > deadline:
            raise UpstreamTimeoutError
        if not chunk:
            continue
        buffer.extend(chunk)
        if len(buffer) > _MAX_RESPONSE_BYTES:
            raise OversizeResponseError
    return bytes(buffer)


def _read_credential(names: tuple[str, ...]) -> str:
    """Return the first non-empty stripped env value over ``names`` (any-one
    enables), or raise. Reads only value presence into a local; never logged,
    never stored on the instance."""
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    raise CredentialMissingError


def _validate_authority(authority: object) -> None:
    """Fail-fast check that ``authority`` is a canonical bare host (no scheme,
    port, or userinfo — HTTPS implies port 443)."""
    if not isinstance(authority, str) or not authority:
        raise ValueError("_API_AUTHORITY must be a non-empty host string")
    rendered, _host, port, is_ip = normalize_authority(authority)
    if is_ip or port is not None or rendered != authority:
        raise ValueError(
            f"_API_AUTHORITY must be a canonical host without port: {authority!r}"
        )


# --------------------------------------------------------------------------- #
# Evidence normalization helpers                                               #
# --------------------------------------------------------------------------- #
def _stable_evidence(
    *,
    provider: str,
    capability: IntelCapability,
    evidence_type: str,
    target: NetworkEntity,
    value: str | int | float | bool | None,
) -> AttributionEvidence:
    """Build an atomic evidence record with a deterministic, fact-only id.

    The id payload is exactly the identity-bearing tuple (type, target kind,
    target value, value); it omits confidence/timestamp/raw_reference/sources so
    two identical facts reproduce one id (IntelResult dedup never false-fires)
    while two different facts differ.
    """
    evidence_id = stable_digest(
        f"apkscan.intel/{provider}",
        {"t": evidence_type, "k": target.kind.value, "e": target.value, "v": value},
    )
    return AttributionEvidence(
        id=evidence_id,
        source=provider,
        type=evidence_type,
        target=target,
        value=value,
        confidence=PASSIVE_EVIDENCE_CONFIDENCE,
        timestamp=None,
        raw_reference=f"{provider}:{capability.value}",
    )


def _emit(
    records: list[AttributionEvidence],
    *,
    provider: str,
    capability: IntelCapability,
    target: NetworkEntity,
    evidence_type: str,
    value: str | int | float | bool | None,
) -> None:
    """Append one atomic evidence record iff ``value`` is not None."""
    if value is None:
        return
    records.append(
        _stable_evidence(
            provider=provider,
            capability=capability,
            evidence_type=evidence_type,
            target=target,
            value=value,
        )
    )


def _bounded_text(value: object) -> str | None:
    """A stripped, length-bounded non-empty string, or None. Never a container."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    return text[:_MAX_SCALAR_LEN]


def _coerce_asn(value: object) -> int | None:
    """An ASN as int in 1..4294967294 (strips a leading AS/as), or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if text[:2].upper() == "AS":
            text = text[2:]
        if not text.isdecimal():
            return None
        number = int(text)
    else:
        return None
    return number if 1 <= number <= 4_294_967_294 else None


def _coerce_port(value: object) -> int | None:
    """A port as int in 1..65535, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.strip().isdecimal():
        number = int(value.strip())
    else:
        return None
    return number if 1 <= number <= 65535 else None


def _coerce_ip(value: object) -> str | None:
    """A normalized (compressed) IP literal, or None if not a valid IP string."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return normalize_ip(text)
    except ValueError:
        return None


def _related_hostname(value: object, target: NetworkEntity) -> str | None:
    """A bare lowercase hostname from a possibly scheme/port-bearing host cell.

    FOFA/Hunter 'host' cells carry forms like 'https://h.example.com',
    'h.example.com:8443', or even '1.2.3.4:443'. Emit only the canonical bare
    hostname so one host does not fragment into several stable ids; drop the
    value when it is empty, an IP literal (an IP is not a hostname), or equal to
    the queried entity (a self-reference).
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = urlsplit(text if "://" in text else f"//{text}")
        host = parsed.hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.strip().lower()
    if not host or host == target.value:
        return None
    try:
        normalize_ip(host)
    except ValueError:
        return host[:_MAX_SCALAR_LEN]
    return None


def _as_list(value: object) -> list[Any]:
    """A list view: the list itself, [] for None, else a one-element wrap."""
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _as_dict(value: object) -> dict[str, Any]:
    """A dict view: a shallow copy if ``value`` is a mapping, else {}."""
    return dict(value) if isinstance(value, Mapping) else {}


def _finalize_evidence(
    records: list[AttributionEvidence],
) -> tuple[AttributionEvidence, ...]:
    """Dedup by id, sort by the IntelResult key, and cap deterministically."""
    by_id: dict[str, AttributionEvidence] = {}
    for evidence in records:
        by_id.setdefault(evidence.id, evidence)
    ordered = sorted(
        by_id.values(),
        key=lambda e: (e.id, e.source, e.type, e.target.kind.value, e.target.value),
    )
    return tuple(ordered[:_MAX_EVIDENCE])


# --------------------------------------------------------------------------- #
# Shared transport base                                                        #
# --------------------------------------------------------------------------- #
class _HttpIntelProvider(IntelProvider):
    """Intermediate abstract base: one bounded, fixed-authority GET per lookup.

    Keeps ``_fetch`` abstract so PR5 declaration validation applies only to the
    concrete leaves. Concrete adapters set ``name``/``capabilities``/
    ``required_env``/``active``/``_API_AUTHORITY`` and implement ``_request_spec``
    and ``_interpret``; their ``_fetch`` is the one-line delegation to
    ``_fetch_via_http``.
    """

    #: fixed provider-owned authority (host only; HTTPS implies port 443).
    _API_AUTHORITY: str = ""

    def __init__(self, session: requests.Session | None = None) -> None:
        if session is None:
            session = requests.Session()
            # Pin urllib3 retries off so the one-wire-attempt rule holds even
            # for a self-constructed session; per-call allow_redirects=False
            # additionally overrides any session redirect default.
            session.mount("https://", HTTPAdapter(max_retries=0))
        self.__session = session

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Mirror PR5's concrete-leaf gate: only a concrete provider (one whose
        # _fetch is implemented) must carry a fixed authority, validated fail-fast
        # at class definition. An abstract intermediate is exempt, but if it
        # declares a truthy authority we still validate it early.
        fetch = getattr(cls, "_fetch", None)
        if getattr(fetch, "__isabstractmethod__", False):
            declared = cls.__dict__.get("_API_AUTHORITY")
            if declared:
                _validate_authority(declared)
            return
        _validate_authority(getattr(cls, "_API_AUTHORITY", ""))

    # ---- pure hooks (no session access, so no second request is possible) ----
    @abstractmethod
    def _request_spec(
        self, capability: IntelCapability, query: NetworkEntity
    ) -> _RequestSpec:
        """Return the single request's path/params/headers. No I/O."""

    @abstractmethod
    def _interpret(
        self, capability: IntelCapability, query: NetworkEntity, payload: dict[str, Any]
    ) -> tuple[AttributionEvidence, ...]:
        """Normalize bounded parsed JSON into atomic evidence. Raise on a
        declared error / malformed / all-invalid payload; return () for a valid
        no-record response."""

    # ---- the package's only session.get call-site ----
    @final
    def _fetch_via_http(
        self, capability: IntelCapability, query: NetworkEntity
    ) -> IntelResult:
        spec = self._request_spec(capability, query)
        provider = type(self).name
        url = f"https://{type(self)._API_AUTHORITY}{spec.path}"
        response = self.__session.get(
            url,
            params=dict(spec.params),
            headers=dict(spec.headers),
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
            allow_redirects=False,
            stream=True,
        )
        try:
            status = response.status_code
            if status == 404 and spec.empty_on_404:
                return IntelResult.empty(provider, capability, query)
            _gate_status(status)
            body = _read_bounded(response)
        finally:
            response.close()

        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise MalformedPayloadError
        evidence = self._interpret(capability, query, payload)
        if evidence:
            return IntelResult.success(provider, capability, query, evidence)
        return IntelResult.empty(provider, capability, query)
