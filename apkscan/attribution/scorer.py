"""Deterministic, fully-traceable evidence scoring value objects and engine.

This module holds the immutable, self-validating value model for PR4 scoring,
the private, immutable per-role weight policy, and ``EvidenceScorer`` — the
engine that reconstructs a canonical assessment, applies the policy once per
signal, and builds a validated :class:`RoleScore`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from apkscan.attribution.models import AttributionEvidence
from apkscan.attribution.roles import (
    InfrastructureRole,
    RoleAssessment,
    RoleClassifier,
    RoleFeature,
    RoleSignal,
)
from apkscan.network import NetworkEntity

# Scores are clamped to this closed integer interval. ``confidence`` is the
# eligible score projected onto [0, 1] by dividing by ``MAX_SCORE``.
MIN_SCORE = 0
MAX_SCORE = 100


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


def _validate_int(name: str, value: object) -> int:
    # bool is an int subclass; a boolean is never a valid point value.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    return value


def _clamp_score(raw: int) -> int:
    return max(MIN_SCORE, min(MAX_SCORE, raw))


def _normalize_contribution_features(
    signal: RoleSignal, value: object
) -> tuple[RoleFeature, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("features must be a non-string iterable of RoleFeature")
    target: NetworkEntity | None = None
    seen_payloads: dict[str, dict[str, Any]] = {}
    unique: dict[str, RoleFeature] = {}
    for item in value:
        if not isinstance(item, RoleFeature):
            raise TypeError(
                f"features must contain RoleFeature, got {type(item).__name__}"
            )
        if item.signal is not signal:
            raise ValueError(
                f"feature signal {item.signal.value!r} does not match "
                f"contribution signal {signal.value!r}"
            )
        if target is None:
            target = item.evidence.target
        elif item.evidence.target != target:
            raise ValueError("contribution features must share one target")
        payload = item.evidence.to_dict()
        existing = seen_payloads.get(item.evidence.id)
        if existing is None:
            seen_payloads[item.evidence.id] = payload
        elif existing != payload:
            raise ValueError(f"conflicting evidence for id {item.evidence.id!r}")
        unique.setdefault(item.evidence.id, item)
    if not unique:
        raise ValueError("contribution requires at least one feature")
    return tuple(unique[key] for key in sorted(unique))


@dataclass(frozen=True, kw_only=True)
class ScoreContribution:
    """One signal's awarded integer weight with its supporting evidence."""

    signal: RoleSignal
    points: int
    features: tuple[RoleFeature, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "signal", _coerce_signal(self.signal))
        object.__setattr__(self, "points", _validate_int("points", self.points))
        object.__setattr__(
            self,
            "features",
            _normalize_contribution_features(self.signal, self.features),
        )

    @property
    def target(self) -> NetworkEntity:
        return self.features[0].evidence.target

    @property
    def evidence(self) -> tuple[AttributionEvidence, ...]:
        return tuple(feature.evidence for feature in self.features)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal.value,
            "points": self.points,
            "features": [feature.to_dict() for feature in self.features],
        }


@dataclass(frozen=True, kw_only=True)
class MissingScoreEvidence:
    """A weighted signal that would have scored had it been present."""

    signal: RoleSignal
    points: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "signal", _coerce_signal(self.signal))
        object.__setattr__(self, "points", _validate_int("points", self.points))
        if self.points <= 0:
            raise ValueError("missing evidence points must be positive")

    def to_dict(self) -> dict[str, Any]:
        return {"signal": self.signal.value, "points": self.points}


def _validate_confidence(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("confidence must be an int or float")
    return float(value)


def _normalize_contributions(
    value: object, *, target: NetworkEntity
) -> tuple[ScoreContribution, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("contributions must be a non-string iterable")
    by_signal: dict[RoleSignal, ScoreContribution] = {}
    # Each evidence.id is globally bound to one complete to_dict payload across
    # every contribution. Distinct signals may reuse the same id only if its
    # payload is byte-for-byte identical; a conflicting payload is rejected
    # regardless of the order contributions are supplied in.
    seen_payloads: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, ScoreContribution):
            raise TypeError(
                "contributions must contain ScoreContribution, "
                f"got {type(item).__name__}"
            )
        if item.target != target:
            raise ValueError("contribution target must equal role-score target")
        if item.signal in by_signal:
            raise ValueError(
                f"duplicate contribution for signal {item.signal.value!r}"
            )
        for evidence in item.evidence:
            payload = evidence.to_dict()
            existing = seen_payloads.get(evidence.id)
            if existing is None:
                seen_payloads[evidence.id] = payload
            elif existing != payload:
                raise ValueError(f"conflicting evidence for id {evidence.id!r}")
        by_signal[item.signal] = item
    return tuple(by_signal[key] for key in sorted(by_signal, key=lambda s: s.value))


def _normalize_missing(value: object) -> tuple[MissingScoreEvidence, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("missing must be a non-string iterable")
    by_signal: dict[RoleSignal, MissingScoreEvidence] = {}
    for item in value:
        if not isinstance(item, MissingScoreEvidence):
            raise TypeError(
                "missing must contain MissingScoreEvidence, "
                f"got {type(item).__name__}"
            )
        if item.signal in by_signal:
            raise ValueError(
                f"duplicate missing evidence for signal {item.signal.value!r}"
            )
        by_signal[item.signal] = item
    return tuple(by_signal[key] for key in sorted(by_signal, key=lambda s: s.value))


@dataclass(frozen=True, kw_only=True)
class RoleScore:
    """A role's deterministic score with full positive/negative/missing trace."""

    target: NetworkEntity
    role: InfrastructureRole
    eligible: bool
    contributions: tuple[ScoreContribution, ...] = ()
    missing: tuple[MissingScoreEvidence, ...] = ()
    raw_score: int
    score: int
    confidence: float

    def __post_init__(self) -> None:
        if not isinstance(self.target, NetworkEntity):
            raise TypeError("target must be a NetworkEntity")
        object.__setattr__(self, "role", _coerce_role(self.role))
        if self.role is InfrastructureRole.CLOAKING_EDGE_NODE:
            raise ValueError("cloaking_edge_node is not scored in PR4")
        if not isinstance(self.eligible, bool):
            raise TypeError("eligible must be bool")
        object.__setattr__(
            self,
            "contributions",
            _normalize_contributions(self.contributions, target=self.target),
        )
        object.__setattr__(self, "missing", _normalize_missing(self.missing))

        present = {item.signal for item in self.contributions}
        overlap = present & {item.signal for item in self.missing}
        if overlap:
            shared = ", ".join(sorted(signal.value for signal in overlap))
            raise ValueError(f"signal(s) {shared} are both scored and missing")

        raw_score = _validate_int("raw_score", self.raw_score)
        expected_raw = sum(item.points for item in self.contributions)
        if raw_score != expected_raw:
            raise ValueError(
                f"raw_score {raw_score} must equal contribution sum {expected_raw}"
            )

        score = _validate_int("score", self.score)
        expected_score = _clamp_score(raw_score)
        if score != expected_score:
            raise ValueError(
                f"score {score} must equal clamped raw score {expected_score}"
            )

        confidence = _validate_confidence(self.confidence)
        expected_confidence = (score / MAX_SCORE) if self.eligible else 0.0
        if confidence != expected_confidence:
            raise ValueError(
                f"confidence {confidence} must equal {expected_confidence} "
                "for this eligibility and score"
            )
        object.__setattr__(self, "confidence", confidence)

        _validate_policy_conformance(self)

    @property
    def positive_contributions(self) -> tuple[ScoreContribution, ...]:
        """Contributions that added points (weight > 0)."""
        return tuple(item for item in self.contributions if item.points > 0)

    @property
    def negative_contributions(self) -> tuple[ScoreContribution, ...]:
        """Contributions that subtracted points (weight < 0)."""
        return tuple(item for item in self.contributions if item.points < 0)

    @property
    def context_contributions(self) -> tuple[ScoreContribution, ...]:
        """Zero-weight explanatory context (weight == 0)."""
        return tuple(item for item in self.contributions if item.points == 0)

    def to_dict(self) -> dict[str, Any]:
        # Contributions are serialized split by sign so positive, negative, and
        # zero-weight (contextual) evidence are each explicitly labelled rather
        # than lumped under one key. Each list preserves the signal-value order
        # established when contributions were normalized.
        return {
            "target": self.target.to_dict(),
            "role": self.role.value,
            "eligible": self.eligible,
            "evidence": [item.to_dict() for item in self.positive_contributions],
            "negative_evidence": [
                item.to_dict() for item in self.negative_contributions
            ],
            "context_evidence": [
                item.to_dict() for item in self.context_contributions
            ],
            "missing_evidence": [item.to_dict() for item in self.missing],
            "raw_score": self.raw_score,
            "score": self.score,
            "confidence": self.confidence,
        }


# --------------------------------------------------------------------------- #
# Private, immutable per-role weight policy
# --------------------------------------------------------------------------- #
def _normalize_weights(value: object) -> Mapping[RoleSignal, int]:
    if not isinstance(value, Mapping):
        raise TypeError("weights must be a mapping of RoleSignal to int")
    normalized: dict[RoleSignal, int] = {}
    for signal, points in value.items():
        role_signal = _coerce_signal(signal)
        if role_signal in normalized:
            raise ValueError(f"duplicate weight for signal {role_signal.value!r}")
        normalized[role_signal] = _validate_int("weight", points)
    return MappingProxyType(
        {key: normalized[key] for key in sorted(normalized, key=lambda s: s.value)}
    )


@dataclass(frozen=True, kw_only=True)
class _RolePolicy:
    """A role's exact, immutable signal-to-weight table.

    The mapping is stored behind a ``MappingProxyType`` so neither the policy
    object nor its weight table can be mutated after construction. Callers
    cannot inject arbitrary weights in PR4.
    """

    role: InfrastructureRole
    weights: Mapping[RoleSignal, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _coerce_role(self.role))
        if self.role is InfrastructureRole.CLOAKING_EDGE_NODE:
            raise ValueError("cloaking_edge_node has no PR4 scoring policy")
        object.__setattr__(self, "weights", _normalize_weights(self.weights))

    @property
    def signals(self) -> tuple[RoleSignal, ...]:
        return tuple(self.weights)

    def weight(self, signal: object) -> int | None:
        """Return the signed weight for ``signal`` or ``None`` if unscored."""
        return self.weights.get(_coerce_signal(signal))

    def to_dict(self) -> dict[str, int]:
        return {signal.value: points for signal, points in self.weights.items()}


# Exact documented weights. Any extra, omitted, or changed signal here is a
# policy change and must be caught by the exact-equality policy tests.
_ROLE_POLICIES: Mapping[InfrastructureRole, _RolePolicy] = MappingProxyType(
    {
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE: _RolePolicy(
            role=InfrastructureRole.DOMESTIC_RELAY_CANDIDATE,
            weights={
                RoleSignal.DIRECT_CONNECTION: 40,
                RoleSignal.DOMESTIC_NETWORK: 15,
                RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION: 20,
                RoleSignal.REDIRECT: 15,
                RoleSignal.HISTORICAL_DNS: 15,
                RoleSignal.NON_PUBLIC_CDN: 10,
                RoleSignal.PUBLIC_CDN: -60,
            },
        ),
        InfrastructureRole.ORIGIN_CANDIDATE: _RolePolicy(
            role=InfrastructureRole.ORIGIN_CANDIDATE,
            weights={
                RoleSignal.BUSINESS_API: 30,
                RoleSignal.LOGIN_ENDPOINT: 15,
                RoleSignal.STABLE_IP: 15,
                RoleSignal.BUSINESS_CERTIFICATE: 15,
                RoleSignal.NON_PUBLIC_CDN: 20,
                RoleSignal.HISTORICAL_DNS: 15,
                RoleSignal.PUBLIC_CDN: -60,
            },
        ),
        InfrastructureRole.EDGE_CANDIDATE: _RolePolicy(
            role=InfrastructureRole.EDGE_CANDIDATE,
            weights={
                RoleSignal.MANY_SHARED_DOMAINS: 15,
                RoleSignal.REDIRECT: 15,
                RoleSignal.COOKIE_CHALLENGE: 20,
                RoleSignal.SHARED_TLS: 15,
                RoleSignal.CONTENT_DIFFERENCE: 25,
                # Zero-point explanatory context: public-CDN evidence may
                # explain an edge but cannot make one eligible on its own.
                RoleSignal.PUBLIC_CDN: 0,
            },
        ),
    }
)


def _validate_policy_conformance(score: RoleScore) -> None:
    """Cross-check a fully arithmetic-consistent ``RoleScore`` against its
    role's immutable weight policy.

    Arithmetic validation in ``__post_init__`` cannot catch a semantically
    inconsistent trace: a contribution weighted off-policy, a signal with no
    policy weight carried at zero points, or a missing list that omits, adds, or
    mis-weights an absent positive signal. Each of those keeps ``raw_score`` /
    ``score`` / ``confidence`` internally consistent yet contradicts the
    documented policy. This helper rejects them.
    """
    policy = _ROLE_POLICIES.get(score.role)
    if policy is None:
        raise ValueError(f"no scoring policy for role {score.role.value!r}")

    # (1)/(2) Every contribution must match policy exactly: a policy-known
    # signal is worth precisely its documented weight; a policy-unknown signal
    # may only appear as zero-point explanatory context (a nonzero off-policy
    # weight is never canonical). Whether a zero-point off-policy signal is
    # actually relevant to this role is a feature-relevance question owned by
    # RoleClassifier and intentionally not decided here.
    for contribution in score.contributions:
        weight = policy.weight(contribution.signal)
        if weight is None:
            if contribution.points != 0:
                raise ValueError(
                    f"signal {contribution.signal.value!r} is not scored under "
                    f"role {score.role.value!r} but contributed "
                    f"{contribution.points} points"
                )
            continue
        if contribution.points != weight:
            raise ValueError(
                f"contribution for signal {contribution.signal.value!r} scored "
                f"{contribution.points} points but policy weight is {weight}"
            )

    # (3)/(4) The missing list must be exactly the policy's positive-weight
    # signals that are not present — no omission, no extra, no wrong points.
    present = {contribution.signal for contribution in score.contributions}
    expected_missing = {
        signal: points
        for signal, points in policy.weights.items()
        if points > 0 and signal not in present
    }
    actual_missing = {item.signal: item.points for item in score.missing}
    if actual_missing != expected_missing:
        expected_repr = {
            signal.value: points for signal, points in expected_missing.items()
        }
        actual_repr = {
            signal.value: points for signal, points in actual_missing.items()
        }
        raise ValueError(
            f"missing evidence {actual_repr} must equal the absent positive "
            f"policy signals {expected_repr} for role {score.role.value!r}"
        )

    _validate_classifier_conformance(score)


def _validate_classifier_conformance(score: RoleScore) -> None:
    """Cross-check the trace's eligibility and feature set against the canonical
    :class:`RoleClassifier` verdict for the same target.

    Policy-weight and missing-list conformance still admit a trace whose feature
    set contradicts what the classifier would derive for this target: an
    eligibility flag the classifier would never grant on this evidence, or
    contribution features that are irrelevant to the role, dropped from the
    canonical partition, or mutated. Every contribution feature is flattened,
    the classifier is asked for this role's assessment, and the reconstructed
    verdict must match exactly — same eligibility, and the same
    matched/context/negative features keyed by ``(signal.value, evidence.id)``
    down to the full :meth:`RoleFeature.to_dict` payload.
    """
    features = tuple(
        feature
        for contribution in score.contributions
        for feature in contribution.features
    )
    candidate: RoleAssessment | None = None
    for assessment in RoleClassifier().assess(score.target, features):
        if assessment.role is score.role:
            candidate = assessment
            break
    if candidate is None:
        raise ValueError(
            f"classifier produced no assessment for role {score.role.value!r}"
        )

    if candidate.eligible != score.eligible:
        raise ValueError(
            f"eligible={score.eligible} contradicts the classifier verdict "
            f"{candidate.eligible} for role {score.role.value!r}"
        )

    input_features = _feature_payload_map(features)
    candidate_features = _feature_payload_map(
        candidate.matched_features
        + candidate.context_features
        + candidate.negative_features
    )
    if input_features != candidate_features:
        raise ValueError(
            f"contribution features for role {score.role.value!r} do not match "
            "the canonical classifier features (irrelevant, dropped, or mutated "
            "evidence)"
        )


def _feature_payload_map(
    features: Iterable[RoleFeature],
) -> dict[tuple[str, str], dict[str, Any]]:
    """Map each feature to its full ``to_dict`` payload, keyed by the
    ``(signal.value, evidence.id)`` pair that uniquely identifies it."""
    return {
        (feature.signal.value, feature.evidence.id): feature.to_dict()
        for feature in features
    }


# --------------------------------------------------------------------------- #
# Scoring engine
# --------------------------------------------------------------------------- #
class EvidenceScorer:
    """Turn a canonical :class:`RoleAssessment` into a validated ``RoleScore``.

    The engine never trusts the assessment's own partition of features. It
    unions every bucket, re-runs :class:`RoleClassifier` over the target, and
    demands the reconstructed assessment equal the input exactly; only then does
    it apply the private per-role weight policy once per present signal.
    """

    def score(self, assessment: object) -> RoleScore:
        if not isinstance(assessment, RoleAssessment):
            raise TypeError(
                f"assessment must be a RoleAssessment, got {type(assessment).__name__}"
            )
        if assessment.role is InfrastructureRole.CLOAKING_EDGE_NODE:
            raise ValueError("cloaking_edge_node is not scored in PR4")
        policy = _ROLE_POLICIES.get(assessment.role)
        if policy is None:
            raise ValueError(
                f"no scoring policy for role {assessment.role.value!r}"
            )

        # Reconstruct the canonical assessment from the full feature union and
        # require an exact match so a tampered partition cannot be scored.
        union = (
            assessment.matched_features
            + assessment.context_features
            + assessment.negative_features
        )
        canonical = self._canonical_assessment(assessment, union)

        features_by_signal: dict[RoleSignal, list[RoleFeature]] = {}
        for feature in (
            canonical.matched_features
            + canonical.context_features
            + canonical.negative_features
        ):
            features_by_signal.setdefault(feature.signal, []).append(feature)

        contributions: list[ScoreContribution] = []
        missing: list[MissingScoreEvidence] = []
        for signal, points in policy.weights.items():
            features = features_by_signal.get(signal)
            if features:
                contributions.append(
                    ScoreContribution(
                        signal=signal, points=points, features=tuple(features)
                    )
                )
            elif points > 0:
                # Absent positive-weight signals are the only ones that would
                # have scored; zero/negative absences are silent.
                missing.append(MissingScoreEvidence(signal=signal, points=points))

        # Preserve every canonical signal group the policy omits as zero-weight
        # context so no matched/context/negative evidence is silently dropped.
        # points=0 leaves the score unchanged and serializes under
        # context_evidence; iteration is sorted by signal value for
        # determinism. Under the exact production policy every canonical signal
        # is already weighted, so this pass adds nothing there.
        scored = set(policy.weights)
        for signal in sorted(
            (s for s in features_by_signal if s not in scored),
            key=lambda s: s.value,
        ):
            contributions.append(
                ScoreContribution(
                    signal=signal,
                    points=0,
                    features=tuple(features_by_signal[signal]),
                )
            )

        raw_score = sum(item.points for item in contributions)
        score = _clamp_score(raw_score)
        confidence = (score / MAX_SCORE) if assessment.eligible else 0.0
        return RoleScore(
            target=assessment.target,
            role=assessment.role,
            eligible=assessment.eligible,
            contributions=tuple(contributions),
            missing=tuple(missing),
            raw_score=raw_score,
            score=score,
            confidence=confidence,
        )

    @staticmethod
    def _canonical_assessment(
        assessment: RoleAssessment, features: tuple[RoleFeature, ...]
    ) -> RoleAssessment:
        for candidate in RoleClassifier().assess(assessment.target, features):
            if candidate.role is assessment.role:
                if candidate != assessment:
                    raise ValueError(
                        "assessment does not equal its canonical reconstruction"
                    )
                return candidate
        raise ValueError(
            f"classifier produced no assessment for role {assessment.role.value!r}"
        )
