"""Explainable infrastructure role eligibility without numeric scoring."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from apkscan.attribution.models import AttributionEvidence
from apkscan.network import NetworkEntity


class InfrastructureRole(str, Enum):
    DOMESTIC_RELAY_CANDIDATE = "domestic_relay_candidate"
    ORIGIN_CANDIDATE = "origin_candidate"
    EDGE_CANDIDATE = "edge_candidate"
    CLOAKING_EDGE_NODE = "cloaking_edge_node"

    @property
    def parent(self) -> InfrastructureRole | None:
        if self is InfrastructureRole.CLOAKING_EDGE_NODE:
            return InfrastructureRole.EDGE_CANDIDATE
        return None


class RoleSignal(str, Enum):
    DIRECT_CONNECTION = "direct_connection"
    DOMESTIC_NETWORK = "domestic_network"
    REDIRECT = "redirect"
    SUBSEQUENT_OVERSEAS_CONNECTION = "subsequent_overseas_connection"
    NON_PUBLIC_CDN = "non_public_cdn"
    PUBLIC_CDN = "public_cdn"
    BUSINESS_API = "business_api"
    LOGIN_ENDPOINT = "login_endpoint"
    STABLE_IP = "stable_ip"
    HISTORICAL_DNS = "historical_dns"
    BUSINESS_CERTIFICATE = "business_certificate"
    MANY_SHARED_DOMAINS = "many_shared_domains"
    COOKIE_CHALLENGE = "cookie_challenge"
    SHARED_TLS = "shared_tls"
    CONTENT_DIFFERENCE = "content_difference"


def _coerce_signal(value: object) -> RoleSignal:
    if isinstance(value, RoleSignal):
        return value
    if isinstance(value, str):
        try:
            return RoleSignal(value)
        except ValueError as exc:
            raise ValueError(f"invalid role signal: {value!r}") from exc
    raise TypeError(f"signal must be RoleSignal or str, got {type(value).__name__}")


def _coerce_role(value: object) -> InfrastructureRole:
    if isinstance(value, InfrastructureRole):
        return value
    if isinstance(value, str):
        try:
            return InfrastructureRole(value)
        except ValueError as exc:
            raise ValueError(f"invalid infrastructure role: {value!r}") from exc
    raise TypeError(
        f"role must be InfrastructureRole or str, got {type(value).__name__}"
    )


def _normalize_signals(value: object) -> tuple[RoleSignal, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("signals must be a non-string iterable")
    return tuple(sorted({_coerce_signal(item) for item in value}, key=lambda item: item.value))


def _evidence_key(item: AttributionEvidence) -> tuple[str, str, str, str, str]:
    return (
        item.id,
        item.source,
        item.type,
        item.target.kind.value,
        item.target.value,
    )


def _normalize_evidence(
    value: object, *, target: NetworkEntity
) -> tuple[AttributionEvidence, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("evidence must be a non-string iterable")
    unique: dict[tuple[str, str, str, str, str], AttributionEvidence] = {}
    for item in value:
        if not isinstance(item, AttributionEvidence):
            raise TypeError(
                f"evidence must contain AttributionEvidence, got {type(item).__name__}"
            )
        if item.target != target:
            raise ValueError("assessment evidence target must equal assessment target")
        unique[_evidence_key(item)] = item
    return tuple(unique[key] for key in sorted(unique))


@dataclass(frozen=True, kw_only=True)
class RoleFeature:
    signal: RoleSignal
    evidence: AttributionEvidence

    def __post_init__(self) -> None:
        object.__setattr__(self, "signal", _coerce_signal(self.signal))
        if not isinstance(self.evidence, AttributionEvidence):
            raise TypeError("evidence must be AttributionEvidence")


@dataclass(frozen=True, kw_only=True)
class RoleAssessment:
    target: NetworkEntity
    role: InfrastructureRole
    eligible: bool
    matched_signals: tuple[RoleSignal, ...] = ()
    matched_evidence: tuple[AttributionEvidence, ...] = ()
    missing_evidence: tuple[RoleSignal, ...] = ()
    negative_signals: tuple[RoleSignal, ...] = ()
    negative_evidence: tuple[AttributionEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.target, NetworkEntity):
            raise TypeError("target must be NetworkEntity")
        object.__setattr__(self, "role", _coerce_role(self.role))
        if not isinstance(self.eligible, bool):
            raise TypeError("eligible must be bool")
        object.__setattr__(
            self, "matched_signals", _normalize_signals(self.matched_signals)
        )
        object.__setattr__(
            self, "missing_evidence", _normalize_signals(self.missing_evidence)
        )
        object.__setattr__(
            self, "negative_signals", _normalize_signals(self.negative_signals)
        )
        object.__setattr__(
            self,
            "matched_evidence",
            _normalize_evidence(self.matched_evidence, target=self.target),
        )
        object.__setattr__(
            self,
            "negative_evidence",
            _normalize_evidence(self.negative_evidence, target=self.target),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "role": self.role.value,
            "eligible": self.eligible,
            "matched_signals": [item.value for item in self.matched_signals],
            "matched_evidence": [item.to_dict() for item in self.matched_evidence],
            "missing_evidence": [item.value for item in self.missing_evidence],
            "negative_signals": [item.value for item in self.negative_signals],
            "negative_evidence": [item.to_dict() for item in self.negative_evidence],
        }
