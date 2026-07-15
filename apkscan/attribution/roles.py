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


def _normalize_evidence(
    value: object, *, target: NetworkEntity
) -> tuple[AttributionEvidence, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("evidence must be a non-string iterable")
    unique: dict[str, AttributionEvidence] = {}
    for item in value:
        if not isinstance(item, AttributionEvidence):
            raise TypeError(
                f"evidence must contain AttributionEvidence, got {type(item).__name__}"
            )
        if item.target != target:
            raise ValueError("assessment evidence target must equal assessment target")
        existing = unique.get(item.id)
        if existing is None:
            unique[item.id] = item
        elif existing.to_dict() != item.to_dict():
            raise ValueError(
                f"conflicting evidence for id {item.id!r}"
            )
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


@dataclass(frozen=True)
class _Requirement:
    signals: frozenset[RoleSignal]
    minimum: int = 1

    def met_by(self, present: frozenset[RoleSignal]) -> bool:
        return len(self.signals & present) >= self.minimum


@dataclass(frozen=True)
class _RoleDefinition:
    role: InfrastructureRole
    supporting: frozenset[RoleSignal]
    requirements: tuple[_Requirement, ...]
    blockers: frozenset[RoleSignal] = frozenset()


_TRANSITION = frozenset(
    {RoleSignal.REDIRECT, RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION}
)
_ORIGIN_CORRELATION = frozenset(
    {
        RoleSignal.LOGIN_ENDPOINT,
        RoleSignal.STABLE_IP,
        RoleSignal.HISTORICAL_DNS,
        RoleSignal.BUSINESS_CERTIFICATE,
    }
)
_EDGE_SIGNALS = frozenset(
    {
        RoleSignal.MANY_SHARED_DOMAINS,
        RoleSignal.REDIRECT,
        RoleSignal.COOKIE_CHALLENGE,
        RoleSignal.SHARED_TLS,
        RoleSignal.CONTENT_DIFFERENCE,
    }
)

_ROLE_DEFINITIONS = (
    _RoleDefinition(
        role=InfrastructureRole.DOMESTIC_RELAY_CANDIDATE,
        supporting=frozenset(
            {
                RoleSignal.DIRECT_CONNECTION,
                RoleSignal.DOMESTIC_NETWORK,
                RoleSignal.REDIRECT,
                RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION,
                RoleSignal.NON_PUBLIC_CDN,
            }
        ),
        requirements=(
            _Requirement(frozenset({RoleSignal.DIRECT_CONNECTION})),
            _Requirement(frozenset({RoleSignal.DOMESTIC_NETWORK})),
            _Requirement(_TRANSITION),
        ),
        blockers=frozenset({RoleSignal.PUBLIC_CDN}),
    ),
    _RoleDefinition(
        role=InfrastructureRole.ORIGIN_CANDIDATE,
        supporting=frozenset(
            {RoleSignal.BUSINESS_API, RoleSignal.NON_PUBLIC_CDN}
        )
        | _ORIGIN_CORRELATION,
        requirements=(
            _Requirement(frozenset({RoleSignal.BUSINESS_API})),
            _Requirement(_ORIGIN_CORRELATION),
        ),
        blockers=frozenset({RoleSignal.PUBLIC_CDN}),
    ),
    _RoleDefinition(
        role=InfrastructureRole.EDGE_CANDIDATE,
        supporting=_EDGE_SIGNALS,
        requirements=(_Requirement(_EDGE_SIGNALS, minimum=2),),
    ),
)


def _normalize_features(value: object) -> tuple[RoleFeature, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("features must be a non-string iterable of RoleFeature")
    unique: dict[tuple[str, str], RoleFeature] = {}
    for item in value:
        if not isinstance(item, RoleFeature):
            raise TypeError(
                f"features must contain RoleFeature, got {type(item).__name__}"
            )
        key = (item.signal.value, item.evidence.id)
        existing = unique.get(key)
        if existing is None:
            unique[key] = item
        elif existing.evidence.to_dict() != item.evidence.to_dict():
            raise ValueError(
                f"conflicting evidence for feature {key!r}"
            )
    return tuple(unique[key] for key in sorted(unique))


class RoleClassifier:
    """Evaluate explainable role eligibility without scores or confidence."""

    def assess(
        self,
        target: NetworkEntity,
        features: Iterable[RoleFeature],
    ) -> tuple[RoleAssessment, ...]:
        if not isinstance(target, NetworkEntity):
            raise TypeError("target must be NetworkEntity")
        normalized = tuple(
            feature
            for feature in _normalize_features(features)
            if feature.evidence.target == target
        )
        present = frozenset(feature.signal for feature in normalized)
        by_signal: dict[RoleSignal, list[AttributionEvidence]] = {}
        for feature in normalized:
            by_signal.setdefault(feature.signal, []).append(feature.evidence)
        return tuple(
            self._assess_definition(target, definition, present, by_signal)
            for definition in _ROLE_DEFINITIONS
        )

    def classify(
        self,
        target: NetworkEntity,
        features: Iterable[RoleFeature],
    ) -> tuple[RoleAssessment, ...]:
        return tuple(item for item in self.assess(target, features) if item.eligible)

    @staticmethod
    def _assess_definition(
        target: NetworkEntity,
        definition: _RoleDefinition,
        present: frozenset[RoleSignal],
        by_signal: dict[RoleSignal, list[AttributionEvidence]],
    ) -> RoleAssessment:
        matched = definition.supporting & present
        negative = definition.blockers & present
        matched_evidence = tuple(
            evidence
            for signal in matched
            for evidence in by_signal.get(signal, ())
        )
        negative_evidence = tuple(
            evidence
            for signal in negative
            for evidence in by_signal.get(signal, ())
        )
        eligible = not negative and all(
            requirement.met_by(present) for requirement in definition.requirements
        )
        return RoleAssessment(
            target=target,
            role=definition.role,
            eligible=eligible,
            matched_signals=tuple(matched),
            matched_evidence=matched_evidence,
            missing_evidence=tuple(definition.supporting - present),
            negative_signals=tuple(negative),
            negative_evidence=negative_evidence,
        )
