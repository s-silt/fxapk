"""PR5 被动情报接口的值对象：能力/状态枚举、证书值校验、IntelResult。

复用既有 apkscan.attribution.models.AttributionEvidence 与
apkscan.network.NetworkEntity/NetworkEntityType，不发明平行类型，不触碰
apkscan/network/*。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from apkscan.attribution.models import AttributionEvidence
from apkscan.network import NetworkEntity, NetworkEntityType

#: provider 名与 env 变量名的文法。用 fullmatch 校验；不带 ^/$ 锚点，
#: 因为 re.match+$ 会接受尾随 \n（$ 匹配最终换行符之前）。
_PROVIDER_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
#: lookup_cert v1 canonical = SHA-256 叶证书 DER 指纹（小写 hex）。
_CERT_VALUE_RE = re.compile(r"sha256:[0-9a-f]{64}")

#: UNSUPPORTED 的封闭 reason 集。
_UNSUPPORTED_REASONS = frozenset({"capability_not_supported", "entity_kind_mismatch"})
_EMPTY_REASON = "no_records"
_UNAVAILABLE_REASON = "credentials_unavailable"


class IntelCapability(str, Enum):
    """三种被动查询能力；值与公开方法名一致。"""

    LOOKUP_IP = "lookup_ip"
    LOOKUP_DOMAIN = "lookup_domain"
    LOOKUP_CERT = "lookup_cert"


class IntelStatus(str, Enum):
    """五个互斥的查询结果状态。"""

    SUCCESS = "success"
    EMPTY = "empty"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    FAILURE = "failure"


#: 每个能力恰好对应一个期望的 NetworkEntityType（只读）。
CAPABILITY_ENTITY_KIND: MappingProxyType[IntelCapability, NetworkEntityType] = MappingProxyType(
    {
        IntelCapability.LOOKUP_IP: NetworkEntityType.IP,
        IntelCapability.LOOKUP_DOMAIN: NetworkEntityType.DOMAIN,
        IntelCapability.LOOKUP_CERT: NetworkEntityType.CERTIFICATE,
    }
)


class ProviderContractError(Exception):
    """_fetch 返回值违反后置契约时内部抛出；被 dispatch 包装为 FAILURE。"""


def validate_certificate_value(value: object) -> str:
    """校验 lookup_cert v1 canonical 值 ``sha256:<64 lowercase hex>``。

    v1 = 叶证书 DER 编码的 SHA-256 指纹。SPKI 哈希、序列号、PEM/DER blob
    显式延后到未来能力/版本。非 str 抛 TypeError，非 canonical 抛 ValueError。
    """
    if not isinstance(value, str):
        raise TypeError(f"certificate value must be a string, got {type(value).__name__}")
    if not _CERT_VALUE_RE.fullmatch(value):
        raise ValueError(f"non-canonical certificate value: {value!r}")
    return value


def _coerce_capability(value: object) -> IntelCapability:
    if isinstance(value, IntelCapability):
        return value
    if isinstance(value, str):
        try:
            return IntelCapability(value)
        except ValueError as exc:
            raise ValueError(f"invalid capability: {value!r}") from exc
    raise TypeError(f"capability must be IntelCapability or str, got {type(value).__name__}")


def _coerce_status(value: object) -> IntelStatus:
    if isinstance(value, IntelStatus):
        return value
    if isinstance(value, str):
        try:
            return IntelStatus(value)
        except ValueError as exc:
            raise ValueError(f"invalid status: {value!r}") from exc
    raise TypeError(f"status must be IntelStatus or str, got {type(value).__name__}")


def _coerce_provider(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"provider must be a string, got {type(value).__name__}")
    if not _PROVIDER_NAME_RE.fullmatch(value):
        raise ValueError(f"invalid provider name: {value!r}")
    return value


def _coerce_missing_env(value: object) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, tuple):
        raise TypeError("missing_env must be a tuple of str")
    cleaned: set[str] = set()
    for name in value:
        if not isinstance(name, str):
            raise TypeError(f"missing_env must contain str, got {type(name).__name__}")
        if not _ENV_NAME_RE.fullmatch(name):
            raise ValueError(f"invalid env name: {name!r}")
        cleaned.add(name)
    return tuple(sorted(cleaned))


def _coerce_evidence(value: object, provider: str) -> tuple[AttributionEvidence, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, tuple):
        raise TypeError("evidence must be a tuple of AttributionEvidence")
    by_id: dict[str, dict[str, Any]] = {}
    keyed: list[tuple[tuple[str, str, str, str, str], AttributionEvidence]] = []
    for item in value:
        if not isinstance(item, AttributionEvidence):
            raise TypeError("evidence must contain AttributionEvidence")
        if item.source != provider:
            raise ValueError(
                f"evidence source {item.source!r} must equal provider {provider!r}"
            )
        payload = item.to_dict()
        existing = by_id.get(item.id)
        if existing is not None:
            if existing != payload:
                raise ValueError(f"conflicting evidence for id {item.id!r}")
            continue
        by_id[item.id] = payload
        key = (
            item.id,
            item.source,
            item.type,
            item.target.kind.value,
            item.target.value,
        )
        keyed.append((key, item))
    keyed.sort(key=lambda pair: pair[0])
    return tuple(item for _key, item in keyed)


@dataclass(frozen=True, kw_only=True)
class IntelResult:
    """一次被动查询的规范化返回：显式状态 + 归一化证据 + 无密钥 reason。"""

    provider: str
    capability: IntelCapability
    query: NetworkEntity
    status: IntelStatus
    evidence: tuple[AttributionEvidence, ...] = ()
    reason: str | None = None
    missing_env: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        provider = _coerce_provider(self.provider)
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "capability", _coerce_capability(self.capability))
        object.__setattr__(self, "status", _coerce_status(self.status))
        if not isinstance(self.query, NetworkEntity):
            raise TypeError("query must be a NetworkEntity")
        object.__setattr__(self, "evidence", _coerce_evidence(self.evidence, provider))
        object.__setattr__(self, "missing_env", _coerce_missing_env(self.missing_env))
        if self.reason is not None and (
            not isinstance(self.reason, str) or not self.reason.strip()
        ):
            raise ValueError("reason must be a non-blank string or None")
        self._check_status_shape()

    def _check_status_shape(self) -> None:
        status = self.status
        reason = self.reason
        has_evidence = bool(self.evidence)
        has_env = bool(self.missing_env)

        if status is IntelStatus.SUCCESS:
            if reason is not None or not has_evidence or has_env:
                raise ValueError("SUCCESS requires reason None, non-empty evidence, no missing_env")
        elif status is IntelStatus.EMPTY:
            if reason != _EMPTY_REASON or has_evidence or has_env:
                raise ValueError("EMPTY requires reason 'no_records', no evidence, no missing_env")
        elif status is IntelStatus.UNSUPPORTED:
            if reason not in _UNSUPPORTED_REASONS or has_evidence or has_env:
                raise ValueError(
                    "UNSUPPORTED requires a closed reason, no evidence, no missing_env"
                )
        elif status is IntelStatus.UNAVAILABLE:
            if reason != _UNAVAILABLE_REASON or has_evidence or not has_env:
                raise ValueError(
                    "UNAVAILABLE requires reason 'credentials_unavailable', "
                    "no evidence, non-empty missing_env"
                )
        else:  # FAILURE
            if reason is None or not reason.isidentifier() or has_evidence or has_env:
                raise ValueError(
                    "FAILURE requires a safe-identifier reason, no evidence, no missing_env"
                )

    def to_dict(self) -> dict[str, Any]:
        """返回确定且可直接 JSON 序列化的公开表示。"""
        return {
            "provider": self.provider,
            "capability": self.capability.value,
            "query": self.query.to_dict(),
            "status": self.status.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "reason": self.reason,
            "missing_env": list(self.missing_env),
        }

    @classmethod
    def success(
        cls,
        provider: str,
        capability: IntelCapability,
        query: NetworkEntity,
        evidence: tuple[AttributionEvidence, ...],
    ) -> IntelResult:
        return cls(
            provider=provider,
            capability=capability,
            query=query,
            status=IntelStatus.SUCCESS,
            evidence=evidence,
            reason=None,
        )

    @classmethod
    def empty(
        cls, provider: str, capability: IntelCapability, query: NetworkEntity
    ) -> IntelResult:
        return cls(
            provider=provider,
            capability=capability,
            query=query,
            status=IntelStatus.EMPTY,
            reason=_EMPTY_REASON,
        )

    @classmethod
    def unsupported(
        cls,
        provider: str,
        capability: IntelCapability,
        query: NetworkEntity,
        reason: str,
    ) -> IntelResult:
        if reason not in _UNSUPPORTED_REASONS:
            raise ValueError(f"unsupported reason must be one of {sorted(_UNSUPPORTED_REASONS)}")
        return cls(
            provider=provider,
            capability=capability,
            query=query,
            status=IntelStatus.UNSUPPORTED,
            reason=reason,
        )

    @classmethod
    def unavailable(
        cls,
        provider: str,
        capability: IntelCapability,
        query: NetworkEntity,
        missing_env: tuple[str, ...],
    ) -> IntelResult:
        return cls(
            provider=provider,
            capability=capability,
            query=query,
            status=IntelStatus.UNAVAILABLE,
            reason=_UNAVAILABLE_REASON,
            missing_env=missing_env,
        )

    @classmethod
    def failure(
        cls,
        provider: str,
        capability: IntelCapability,
        query: NetworkEntity,
        reason: str,
    ) -> IntelResult:
        return cls(
            provider=provider,
            capability=capability,
            query=query,
            status=IntelStatus.FAILURE,
            reason=reason,
        )
