"""Explainable infrastructure role eligibility without numeric scoring."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from itertools import combinations
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


@dataclass(frozen=True, kw_only=True)
class RoleFeature:
    signal: RoleSignal
    evidence: AttributionEvidence

    def __post_init__(self) -> None:
        object.__setattr__(self, "signal", _coerce_signal(self.signal))
        if not isinstance(self.evidence, AttributionEvidence):
            raise TypeError("evidence must be AttributionEvidence")

    def to_dict(self) -> dict[str, Any]:
        return {"signal": self.signal.value, "evidence": self.evidence.to_dict()}


def _normalize_feature_bucket(
    value: object,
    *,
    target: NetworkEntity,
    seen_payloads: dict[str, dict[str, Any]],
) -> tuple[RoleFeature, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("features must be a non-string iterable of RoleFeature")
    unique: dict[tuple[str, str], RoleFeature] = {}
    for item in value:
        if not isinstance(item, RoleFeature):
            raise TypeError(
                f"features must contain RoleFeature, got {type(item).__name__}"
            )
        if item.evidence.target != target:
            raise ValueError("assessment feature target must equal assessment target")
        payload = item.evidence.to_dict()
        existing_payload = seen_payloads.get(item.evidence.id)
        if existing_payload is None:
            seen_payloads[item.evidence.id] = payload
        elif existing_payload != payload:
            raise ValueError(f"conflicting evidence for id {item.evidence.id!r}")
        unique.setdefault((item.signal.value, item.evidence.id), item)
    return tuple(unique[key] for key in sorted(unique))


def _derive_signals(features: tuple[RoleFeature, ...]) -> tuple[RoleSignal, ...]:
    return tuple(
        sorted({feature.signal for feature in features}, key=lambda item: item.value)
    )


def _derive_evidence(
    features: tuple[RoleFeature, ...]
) -> tuple[AttributionEvidence, ...]:
    unique: dict[str, AttributionEvidence] = {}
    for feature in features:
        unique.setdefault(feature.evidence.id, feature.evidence)
    return tuple(unique[key] for key in sorted(unique))


@dataclass(frozen=True, kw_only=True)
class RoleAssessment:
    target: NetworkEntity
    role: InfrastructureRole
    eligible: bool
    matched_features: tuple[RoleFeature, ...] = ()
    context_features: tuple[RoleFeature, ...] = ()
    negative_features: tuple[RoleFeature, ...] = ()
    missing_evidence: tuple[RoleSignal, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.target, NetworkEntity):
            raise TypeError("target must be NetworkEntity")
        object.__setattr__(self, "role", _coerce_role(self.role))
        if not isinstance(self.eligible, bool):
            raise TypeError("eligible must be bool")
        object.__setattr__(
            self, "missing_evidence", _normalize_signals(self.missing_evidence)
        )
        # A single evidence.id must describe one fact across every bucket.
        seen_payloads: dict[str, dict[str, Any]] = {}
        buckets = ("matched_features", "context_features", "negative_features")
        for field in buckets:
            object.__setattr__(
                self,
                field,
                _normalize_feature_bucket(
                    getattr(self, field),
                    target=self.target,
                    seen_payloads=seen_payloads,
                ),
            )
        # Each RoleSignal belongs to exactly one bucket: a signal cannot be
        # simultaneously matched, contextual, and/or negative for one target.
        bucket_signals = {
            field: _derive_signals(getattr(self, field)) for field in buckets
        }
        for first, second in combinations(buckets, 2):
            overlap = set(bucket_signals[first]) & set(bucket_signals[second])
            if overlap:
                shared = ", ".join(signal.value for signal in sorted(overlap, key=lambda item: item.value))
                raise ValueError(
                    f"signal(s) {shared} appear in both {first} and {second}"
                )

    @property
    def matched_signals(self) -> tuple[RoleSignal, ...]:
        return _derive_signals(self.matched_features)

    @property
    def matched_evidence(self) -> tuple[AttributionEvidence, ...]:
        return _derive_evidence(self.matched_features)

    @property
    def context_signals(self) -> tuple[RoleSignal, ...]:
        return _derive_signals(self.context_features)

    @property
    def context_evidence(self) -> tuple[AttributionEvidence, ...]:
        return _derive_evidence(self.context_features)

    @property
    def negative_signals(self) -> tuple[RoleSignal, ...]:
        return _derive_signals(self.negative_features)

    @property
    def negative_evidence(self) -> tuple[AttributionEvidence, ...]:
        return _derive_evidence(self.negative_features)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "role": self.role.value,
            "eligible": self.eligible,
            "matched_features": [item.to_dict() for item in self.matched_features],
            "context_features": [item.to_dict() for item in self.context_features],
            "negative_features": [item.to_dict() for item in self.negative_features],
            "missing_evidence": [item.value for item in self.missing_evidence],
            "matched_signals": [item.value for item in self.matched_signals],
            "matched_evidence": [item.to_dict() for item in self.matched_evidence],
            "context_signals": [item.value for item in self.context_signals],
            "context_evidence": [item.to_dict() for item in self.context_evidence],
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
    # Signals preserved as explanatory context: they neither help a role match
    # nor block it, and are never reported as missing evidence.
    context: frozenset[RoleSignal] = frozenset()


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
# Strong, behavioral cloaking signals (a strict subset of _EDGE_SIGNALS): different
# content per client, a challenge cookie, and a redirect after the challenge. Each
# requires the peer to actively implement it, unlike the merely-shared-hosting edge
# facts (MANY_SHARED_DOMAINS / SHARED_TLS). >=2 of these is the "confirmed cloaking"
# bar; because they are a subset of the edge signals with the same minimum, a
# cloaking-eligible entity is always edge-eligible.
_CLOAKING_STRONG = frozenset(
    {
        RoleSignal.CONTENT_DIFFERENCE,
        RoleSignal.COOKIE_CHALLENGE,
        RoleSignal.REDIRECT,
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
                RoleSignal.HISTORICAL_DNS,
            }
        ),
        requirements=(
            _Requirement(frozenset({RoleSignal.DIRECT_CONNECTION})),
            _Requirement(frozenset({RoleSignal.DOMESTIC_NETWORK})),
            # ★中继过渡须"境内→境外"时序证据（SUBSEQUENT_OVERSEAS）。REDIRECT（跨 host 重定向）单独不证明中继——
            #   一条良性 canonical/支付跳转即会误判"境内中继"，故不放进中继要件（仍在 supporting 作 context 展示）。
            _Requirement(frozenset({RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION})),
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
        context=frozenset({RoleSignal.PUBLIC_CDN}),
    ),
    # cloaking_edge_node: a subtype of edge_candidate requiring >=2 STRONG behavioral
    # signals. Weak edge facts (shared domains/TLS) and PUBLIC_CDN are context, never
    # requirements, so an ordinary shared-hosting / OpenResty edge is not cloaking;
    # a lone server banner is not a RoleSignal at all, so it can never solo-trigger.
    # No blocker (mirrors the parent edge): a subtype only tightens the behavioral
    # requirement, and anti-red fronts routinely ride public CDNs.
    _RoleDefinition(
        role=InfrastructureRole.CLOAKING_EDGE_NODE,
        supporting=_CLOAKING_STRONG,
        requirements=(_Requirement(_CLOAKING_STRONG, minimum=2),),
        context=frozenset(
            {RoleSignal.MANY_SHARED_DOMAINS, RoleSignal.SHARED_TLS, RoleSignal.PUBLIC_CDN}
        ),
    ),
)


def _normalize_features(
    value: object, *, target: NetworkEntity
) -> tuple[RoleFeature, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("features must be a non-string iterable of RoleFeature")
    unique: dict[tuple[str, str], RoleFeature] = {}
    # A single evidence.id must describe one fact for this target, regardless of
    # which signal cites it; identical payload reuse across signals is allowed,
    # but separate (signal, id) features are preserved individually.
    seen_payloads: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, RoleFeature):
            raise TypeError(
                f"features must contain RoleFeature, got {type(item).__name__}"
            )
        if item.evidence.target != target:
            continue
        payload = item.evidence.to_dict()
        existing_payload = seen_payloads.get(item.evidence.id)
        if existing_payload is None:
            seen_payloads[item.evidence.id] = payload
        elif existing_payload != payload:
            raise ValueError(
                f"conflicting evidence for id {item.evidence.id!r}"
            )
        unique.setdefault((item.signal.value, item.evidence.id), item)
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
        normalized = _normalize_features(features, target=target)
        present = frozenset(feature.signal for feature in normalized)
        by_signal: dict[RoleSignal, list[RoleFeature]] = {}
        for feature in normalized:
            by_signal.setdefault(feature.signal, []).append(feature)
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
        by_signal: dict[RoleSignal, list[RoleFeature]],
    ) -> RoleAssessment:
        matched = definition.supporting & present
        context = definition.context & present
        negative = definition.blockers & present
        matched_features = tuple(
            feature
            for signal in matched
            for feature in by_signal.get(signal, ())
        )
        context_features = tuple(
            feature
            for signal in context
            for feature in by_signal.get(signal, ())
        )
        negative_features = tuple(
            feature
            for signal in negative
            for feature in by_signal.get(signal, ())
        )
        eligible = not negative and all(
            requirement.met_by(present) for requirement in definition.requirements
        )
        return RoleAssessment(
            target=target,
            role=definition.role,
            eligible=eligible,
            matched_features=matched_features,
            context_features=context_features,
            negative_features=negative_features,
            missing_evidence=tuple(definition.supporting - present),
        )
