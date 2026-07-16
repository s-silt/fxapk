from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping

import pytest

from apkscan.attribution.models import AttributionEvidence
from apkscan.attribution.roles import (
    InfrastructureRole,
    RoleAssessment,
    RoleClassifier,
    RoleFeature,
    RoleSignal,
)
from apkscan.attribution.scorer import (
    MAX_SCORE,
    MIN_SCORE,
    EvidenceScorer,
    MissingScoreEvidence,
    RoleScore,
    ScoreContribution,
    _ROLE_POLICIES,
    _RolePolicy,
)
from apkscan.network import NetworkEntity, NetworkEntityType


def _entity(value: str = "1.2.3.4") -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.IP, value, sources=("pcap",))


def _evidence(
    evidence_id: str,
    *,
    target: NetworkEntity | None = None,
    value: str | int | float | bool | None = True,
) -> AttributionEvidence:
    return AttributionEvidence(
        id=evidence_id,
        source="pcap",
        type="role_signal",
        target=target or _entity(),
        value=value,
        confidence=0.8,
    )


def _feature(
    signal: RoleSignal, evidence_id: str, *, target: NetworkEntity | None = None
) -> RoleFeature:
    return RoleFeature(signal=signal, evidence=_evidence(evidence_id, target=target))


def _contribution(
    signal: RoleSignal,
    points: int,
    *evidence_ids: str,
    target: NetworkEntity | None = None,
) -> ScoreContribution:
    tgt = target or _entity()
    return ScoreContribution(
        signal=signal,
        points=points,
        features=tuple(_feature(signal, eid, target=tgt) for eid in evidence_ids),
    )


def _valid_role_score(
    target: NetworkEntity,
    contributions: tuple[ScoreContribution, ...],
    *,
    eligible: bool = True,
    missing: tuple[MissingScoreEvidence, ...] | None = None,
    role: InfrastructureRole = InfrastructureRole.ORIGIN_CANDIDATE,
) -> dict[str, object]:
    """Build a self-consistent RoleScore kwargs dict callers can perturb.

    When ``missing`` is not supplied it is derived as the exact set of absent
    positive-weight signals for ``role`` drawn straight from ``_ROLE_POLICIES``,
    so a fixture satisfies the policy's missing-list completeness check by
    default. Callers that want to probe an incomplete or tampered missing list
    still pass ``missing`` explicitly.
    """
    raw = sum(item.points for item in contributions)
    score = max(MIN_SCORE, min(MAX_SCORE, raw))
    confidence = (score / MAX_SCORE) if eligible else 0.0
    if missing is None:
        present = {item.signal for item in contributions}
        policy = _ROLE_POLICIES.get(InfrastructureRole(role))
        missing = (
            ()
            if policy is None
            else tuple(
                MissingScoreEvidence(signal=signal, points=points)
                for signal, points in policy.weights.items()
                if points > 0 and signal not in present
            )
        )
    return {
        "target": target,
        "role": role,
        "eligible": eligible,
        "contributions": contributions,
        "missing": missing,
        "raw_score": raw,
        "score": score,
        "confidence": confidence,
    }


def _require_scorer() -> EvidenceScorer:
    """Return a fresh ``EvidenceScorer`` for the scorer tests."""
    return EvidenceScorer()


def _assessment_for(
    role: InfrastructureRole,
    features: tuple[RoleFeature, ...],
    *,
    target: NetworkEntity,
) -> RoleAssessment:
    """Return the canonical PR3 assessment for ``role`` over ``features``.

    Building assessments through ``RoleClassifier`` guarantees each one already
    equals its own canonical reconstruction, so any later perturbation is what
    the scorer must reject.
    """
    for assessment in RoleClassifier().assess(target, features):
        if assessment.role is role:
            return assessment
    raise AssertionError(f"classifier produced no assessment for {role!r}")


def _signal_map(items: list[dict[str, object]]) -> dict[object, dict[str, object]]:
    return {item["signal"]: item for item in items}


# --------------------------------------------------------------------------- #
# ScoreContribution
# --------------------------------------------------------------------------- #
def test_score_contribution_is_frozen_and_keyword_only() -> None:
    contribution = _contribution(RoleSignal.BUSINESS_API, 30, "ev-1")
    assert contribution.signal is RoleSignal.BUSINESS_API
    assert contribution.points == 30
    with pytest.raises(dataclasses.FrozenInstanceError):
        contribution.points = 40  # type: ignore[misc]
    with pytest.raises(TypeError):
        ScoreContribution(RoleSignal.BUSINESS_API, 30, ())  # type: ignore[misc]


def test_score_contribution_coerces_signal_string() -> None:
    target = _entity()
    contribution = ScoreContribution(
        signal="business_api",  # type: ignore[arg-type]
        points=10,
        features=(_feature(RoleSignal.BUSINESS_API, "ev-1", target=target),),
    )
    assert contribution.signal is RoleSignal.BUSINESS_API
    with pytest.raises(ValueError):
        ScoreContribution(
            signal="not-a-signal",  # type: ignore[arg-type]
            points=10,
            features=(_feature(RoleSignal.BUSINESS_API, "ev-1", target=target),),
        )


@pytest.mark.parametrize("bad", [True, 1.5, "30", None])
def test_score_contribution_rejects_non_int_points(bad: object) -> None:
    with pytest.raises(TypeError):
        _contribution(RoleSignal.BUSINESS_API, bad, "ev-1")  # type: ignore[arg-type]


def test_score_contribution_allows_zero_and_negative_points() -> None:
    assert _contribution(RoleSignal.PUBLIC_CDN, 0, "ev-1").points == 0
    assert _contribution(RoleSignal.PUBLIC_CDN, -20, "ev-1").points == -20


def test_score_contribution_requires_at_least_one_feature() -> None:
    with pytest.raises(ValueError):
        ScoreContribution(signal=RoleSignal.BUSINESS_API, points=10, features=())


def test_score_contribution_rejects_signal_mismatch() -> None:
    target = _entity()
    with pytest.raises(ValueError):
        ScoreContribution(
            signal=RoleSignal.BUSINESS_API,
            points=10,
            features=(_feature(RoleSignal.REDIRECT, "ev-1", target=target),),
        )


def test_score_contribution_rejects_non_feature() -> None:
    with pytest.raises(TypeError):
        ScoreContribution(
            signal=RoleSignal.BUSINESS_API,
            points=10,
            features=(object(),),  # type: ignore[arg-type]
        )


def test_score_contribution_rejects_cross_target_features() -> None:
    first = _feature(RoleSignal.REDIRECT, "ev-a", target=_entity("1.1.1.1"))
    second = _feature(RoleSignal.REDIRECT, "ev-b", target=_entity("2.2.2.2"))
    with pytest.raises(ValueError):
        ScoreContribution(signal=RoleSignal.REDIRECT, points=5, features=(first, second))


def test_score_contribution_orders_features_and_is_json_safe() -> None:
    target = _entity()
    first = _feature(RoleSignal.REDIRECT, "ev-b", target=target)
    second = _feature(RoleSignal.REDIRECT, "ev-a", target=target)
    forward = ScoreContribution(signal=RoleSignal.REDIRECT, points=5, features=(first, second))
    reverse = ScoreContribution(signal=RoleSignal.REDIRECT, points=5, features=(second, first))
    assert forward.to_dict() == reverse.to_dict()
    ids = [item["evidence"]["id"] for item in forward.to_dict()["features"]]
    assert ids == ["ev-a", "ev-b"]
    payload = forward.to_dict()
    assert payload["signal"] == "redirect"
    assert payload["points"] == 5
    assert json.loads(json.dumps(payload)) == payload


def test_score_contribution_collapses_identical_evidence() -> None:
    target = _entity()
    first = _feature(RoleSignal.REDIRECT, "ev-dup", target=target)
    second = _feature(RoleSignal.REDIRECT, "ev-dup", target=target)
    contribution = ScoreContribution(signal=RoleSignal.REDIRECT, points=5, features=(first, second))
    assert len(contribution.features) == 1
    assert [item.id for item in contribution.evidence] == ["ev-dup"]


def test_score_contribution_rejects_conflicting_same_id() -> None:
    target = _entity()
    first = RoleFeature(
        signal=RoleSignal.REDIRECT,
        evidence=_evidence("ev", target=target, value=True),
    )
    second = RoleFeature(
        signal=RoleSignal.REDIRECT,
        evidence=_evidence("ev", target=target, value=False),
    )
    with pytest.raises(ValueError):
        ScoreContribution(signal=RoleSignal.REDIRECT, points=5, features=(first, second))


# --------------------------------------------------------------------------- #
# MissingScoreEvidence
# --------------------------------------------------------------------------- #
def test_missing_score_evidence_is_frozen_and_json_safe() -> None:
    missing = MissingScoreEvidence(signal=RoleSignal.STABLE_IP, points=10)
    assert missing.signal is RoleSignal.STABLE_IP
    assert missing.points == 10
    with pytest.raises(dataclasses.FrozenInstanceError):
        missing.points = 5  # type: ignore[misc]
    payload = missing.to_dict()
    assert payload == {"signal": "stable_ip", "points": 10}
    assert json.loads(json.dumps(payload)) == payload


def test_missing_score_evidence_coerces_signal_string() -> None:
    assert (
        MissingScoreEvidence(signal="stable_ip", points=10).signal  # type: ignore[arg-type]
        is RoleSignal.STABLE_IP
    )
    with pytest.raises(ValueError):
        MissingScoreEvidence(signal="not-a-signal", points=10)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [True, 1.5, "10", None])
def test_missing_score_evidence_rejects_non_int_points(bad: object) -> None:
    with pytest.raises(TypeError):
        MissingScoreEvidence(signal=RoleSignal.STABLE_IP, points=bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [0, -1, -10])
def test_missing_score_evidence_requires_positive_points(bad: int) -> None:
    with pytest.raises(ValueError):
        MissingScoreEvidence(signal=RoleSignal.STABLE_IP, points=bad)


# --------------------------------------------------------------------------- #
# RoleScore
# --------------------------------------------------------------------------- #
def test_role_score_is_valid_frozen_and_json_safe() -> None:
    # A canonical eligible origin: business_api(30) + stable_ip(15) at their exact
    # policy weights, with the exact absent positive-weight origin signals listed
    # as missing (derived from the policy by the fixture helper).
    target = _entity()
    api = _contribution(RoleSignal.BUSINESS_API, 30, "ev-api", target=target)
    ip = _contribution(RoleSignal.STABLE_IP, 15, "ev-ip", target=target)
    score = RoleScore(**_valid_role_score(target, (api, ip)))  # type: ignore[arg-type]
    assert score.raw_score == 45
    assert score.score == 45
    assert score.confidence == 45 / MAX_SCORE
    with pytest.raises(dataclasses.FrozenInstanceError):
        score.score = 10  # type: ignore[misc]
    payload = score.to_dict()
    assert payload["role"] == "origin_candidate"
    assert payload["eligible"] is True
    # Final explanation contract: contributions are serialized split by sign so
    # positive, negative, and zero-weight (contextual) evidence are each
    # explicitly labelled rather than lumped under one "contributions" key.
    # Positive contributions are ordered by signal value: business_api < stable_ip.
    assert payload["evidence"] == [api.to_dict(), ip.to_dict()]
    assert payload["negative_evidence"] == []
    assert payload["context_evidence"] == []
    # Exact absent positive-weight origin signals, ordered by signal value.
    assert payload["missing_evidence"] == [
        {"signal": "business_certificate", "points": 15},
        {"signal": "historical_dns", "points": 15},
        {"signal": "login_endpoint", "points": 15},
        {"signal": "non_public_cdn", "points": 20},
    ]
    assert {
        "evidence",
        "negative_evidence",
        "context_evidence",
        "missing_evidence",
    } <= set(payload)
    assert payload["raw_score"] == 45
    assert payload["score"] == 45
    assert payload["confidence"] == 45 / MAX_SCORE
    assert json.loads(json.dumps(payload)) == payload


def test_role_score_coerces_role_string() -> None:
    target = _entity()
    api = _contribution(RoleSignal.BUSINESS_API, 30, "ev-api", target=target)
    ip = _contribution(RoleSignal.STABLE_IP, 15, "ev-ip", target=target)
    base = _valid_role_score(target, (api, ip), role="origin_candidate")  # type: ignore[arg-type]
    assert RoleScore(**base).role is InfrastructureRole.ORIGIN_CANDIDATE  # type: ignore[arg-type]


def test_role_score_rejects_cloaking_role() -> None:
    target = _entity()
    contribution = _contribution(RoleSignal.REDIRECT, 10, "ev-1", target=target)
    base = _valid_role_score(target, (contribution,), role=InfrastructureRole.CLOAKING_EDGE_NODE)
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_rejects_non_bool_eligible() -> None:
    target = _entity()
    contribution = _contribution(RoleSignal.BUSINESS_API, 40, "ev-1", target=target)
    base = _valid_role_score(target, (contribution,))
    base["eligible"] = 1
    with pytest.raises(TypeError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_raw_score_must_equal_contribution_sum() -> None:
    target = _entity()
    contribution = _contribution(RoleSignal.BUSINESS_API, 40, "ev-1", target=target)
    base = _valid_role_score(target, (contribution,))
    with pytest.raises(ValueError):
        RoleScore(**{**base, "raw_score": 41})  # type: ignore[arg-type]


def test_role_score_rejects_non_int_raw_score() -> None:
    target = _entity()
    contribution = _contribution(RoleSignal.BUSINESS_API, 40, "ev-1", target=target)
    base = _valid_role_score(target, (contribution,))
    with pytest.raises(TypeError):
        RoleScore(**{**base, "raw_score": 40.0})  # type: ignore[arg-type]


def test_role_score_score_must_equal_clamped_raw_score() -> None:
    target = _entity()
    contribution = _contribution(RoleSignal.BUSINESS_API, 40, "ev-1", target=target)
    base = _valid_role_score(target, (contribution,))
    with pytest.raises(ValueError):
        RoleScore(**{**base, "score": 41})  # type: ignore[arg-type]


def test_role_score_clamps_negative_raw_to_zero() -> None:
    # public_cdn is an origin blocker weighted -60; on its own it drives the raw
    # score below the floor and pins eligibility (and confidence) to zero.
    target = _entity()
    contribution = _contribution(RoleSignal.PUBLIC_CDN, -60, "ev-cdn", target=target)
    base = _valid_role_score(target, (contribution,), eligible=False)
    score = RoleScore(**base)  # type: ignore[arg-type]
    assert score.raw_score == -60
    assert score.score == MIN_SCORE
    assert score.confidence == 0.0
    with pytest.raises(ValueError):
        RoleScore(**{**base, "score": -60})  # type: ignore[arg-type]


def test_role_score_clamps_excess_raw_to_max() -> None:
    # An eligible domestic relay carrying every positive relay signal at its
    # exact policy weight: direct40 + domestic15 + subsequent_overseas20 +
    # redirect15 + historical_dns15 + non_public_cdn10 = 115 raw, which the floor
    # clamps to MAX_SCORE and (being eligible) yields confidence 1.0. With every
    # positive relay signal present the derived missing list is empty.
    target = _entity()
    contributions = (
        _contribution(RoleSignal.DIRECT_CONNECTION, 40, "ev-direct", target=target),
        _contribution(RoleSignal.DOMESTIC_NETWORK, 15, "ev-domestic", target=target),
        _contribution(RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION, 20, "ev-overseas", target=target),
        _contribution(RoleSignal.REDIRECT, 15, "ev-redirect", target=target),
        _contribution(RoleSignal.HISTORICAL_DNS, 15, "ev-dns", target=target),
        _contribution(RoleSignal.NON_PUBLIC_CDN, 10, "ev-cdn", target=target),
    )
    score = RoleScore(
        **_valid_role_score(
            target,
            contributions,
            role=InfrastructureRole.DOMESTIC_RELAY_CANDIDATE,
        )  # type: ignore[arg-type]
    )
    assert score.raw_score == 115
    assert score.score == MAX_SCORE
    assert score.confidence == 1.0
    assert score.missing == ()


def test_role_score_confidence_zero_when_ineligible() -> None:
    # business_api alone scores its policy weight of 30 but leaves the origin
    # correlation requirement unmet, so the classifier deems the target
    # ineligible and confidence is pinned to zero regardless of the score.
    target = _entity()
    contribution = _contribution(RoleSignal.BUSINESS_API, 30, "ev-1", target=target)
    base = _valid_role_score(target, (contribution,), eligible=False)
    assert base["confidence"] == 0.0
    assert RoleScore(**base).confidence == 0.0  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        RoleScore(**{**base, "confidence": 30 / MAX_SCORE})  # type: ignore[arg-type]


def test_role_score_confidence_tracks_score_when_eligible() -> None:
    target = _entity()
    contribution = _contribution(RoleSignal.BUSINESS_API, 40, "ev-1", target=target)
    base = _valid_role_score(target, (contribution,), eligible=True)
    with pytest.raises(ValueError):
        RoleScore(**{**base, "confidence": 0.0})  # type: ignore[arg-type]


def test_role_score_rejects_non_numeric_confidence() -> None:
    target = _entity()
    contribution = _contribution(RoleSignal.BUSINESS_API, 40, "ev-1", target=target)
    base = _valid_role_score(target, (contribution,))
    with pytest.raises(TypeError):
        RoleScore(**{**base, "confidence": "0.4"})  # type: ignore[arg-type]


def test_role_score_rejects_cross_target_contribution() -> None:
    target = _entity("1.1.1.1")
    other = _entity("2.2.2.2")
    contribution = _contribution(RoleSignal.BUSINESS_API, 40, "ev-1", target=other)
    base = _valid_role_score(target, (contribution,))
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_rejects_duplicate_signal_contribution() -> None:
    target = _entity()
    first = _contribution(RoleSignal.BUSINESS_API, 40, "ev-1", target=target)
    second = _contribution(RoleSignal.BUSINESS_API, 10, "ev-2", target=target)
    base = _valid_role_score(target, (first, second))
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_rejects_signal_present_and_missing() -> None:
    target = _entity()
    contribution = _contribution(RoleSignal.BUSINESS_API, 40, "ev-1", target=target)
    missing = MissingScoreEvidence(signal=RoleSignal.BUSINESS_API, points=10)
    base = _valid_role_score(target, (contribution,), missing=(missing,))
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_allows_same_evidence_id_identical_payload_across_signals() -> None:
    # One evidence.id reused by two distinct signals is legal as long as every
    # occurrence carries the identical AttributionEvidence payload.
    target = _entity()
    shared_a = _evidence("ev-shared", target=target, value=True)
    shared_b = _evidence("ev-shared", target=target, value=True)
    first = ScoreContribution(
        signal=RoleSignal.BUSINESS_API,
        points=30,
        features=(RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=shared_a),),
    )
    second = ScoreContribution(
        signal=RoleSignal.STABLE_IP,
        points=15,
        features=(RoleFeature(signal=RoleSignal.STABLE_IP, evidence=shared_b),),
    )
    score = RoleScore(**_valid_role_score(target, (first, second)))  # type: ignore[arg-type]
    assert {item.signal for item in score.contributions} == {
        RoleSignal.BUSINESS_API,
        RoleSignal.STABLE_IP,
    }
    assert score.raw_score == 45


def test_role_score_rejects_same_evidence_id_conflicting_payload_forward() -> None:
    # Same evidence.id, conflicting payload, across two distinct signals must be
    # rejected in the order the conflicting occurrence appears first.
    target = _entity()
    truthy = _evidence("ev-shared", target=target, value=True)
    falsy = _evidence("ev-shared", target=target, value=False)
    first = ScoreContribution(
        signal=RoleSignal.BUSINESS_API,
        points=30,
        features=(RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=truthy),),
    )
    second = ScoreContribution(
        signal=RoleSignal.STABLE_IP,
        points=15,
        features=(RoleFeature(signal=RoleSignal.STABLE_IP, evidence=falsy),),
    )
    with pytest.raises(ValueError):
        RoleScore(**_valid_role_score(target, (first, second)))  # type: ignore[arg-type]


def test_role_score_rejects_same_evidence_id_conflicting_payload_reverse() -> None:
    # The same conflict must be rejected regardless of contribution order.
    target = _entity()
    truthy = _evidence("ev-shared", target=target, value=True)
    falsy = _evidence("ev-shared", target=target, value=False)
    first = ScoreContribution(
        signal=RoleSignal.BUSINESS_API,
        points=30,
        features=(RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=truthy),),
    )
    second = ScoreContribution(
        signal=RoleSignal.STABLE_IP,
        points=15,
        features=(RoleFeature(signal=RoleSignal.STABLE_IP, evidence=falsy),),
    )
    with pytest.raises(ValueError):
        RoleScore(**_valid_role_score(target, (second, first)))  # type: ignore[arg-type]


def test_role_score_rejects_duplicate_missing_signal() -> None:
    target = _entity()
    contribution = _contribution(RoleSignal.BUSINESS_API, 40, "ev-1", target=target)
    first = MissingScoreEvidence(signal=RoleSignal.STABLE_IP, points=10)
    second = MissingScoreEvidence(signal=RoleSignal.STABLE_IP, points=5)
    base = _valid_role_score(target, (contribution,), missing=(first, second))
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_orders_contributions_and_missing() -> None:
    # An eligible origin carrying business_api(30) + stable_ip(15) at their exact
    # policy weights. Regardless of the order contributions and missing entries
    # are supplied, both serialize in signal-value order. The derived missing
    # list is the exact set of absent positive-weight origin signals.
    target = _entity()
    first = _contribution(RoleSignal.STABLE_IP, 15, "ev-1", target=target)
    second = _contribution(RoleSignal.BUSINESS_API, 30, "ev-2", target=target)
    forward = RoleScore(
        **_valid_role_score(target, (first, second))  # type: ignore[arg-type]
    )
    reverse = RoleScore(
        **_valid_role_score(target, (second, first))  # type: ignore[arg-type]
    )
    assert forward.to_dict() == reverse.to_dict()
    # Final contract: positive contributions serialize under "evidence" ordered
    # by signal value; missing weighted evidence under "missing_evidence".
    assert [item["signal"] for item in forward.to_dict()["evidence"]] == [
        "business_api",
        "stable_ip",
    ]
    assert [item["signal"] for item in forward.to_dict()["missing_evidence"]] == [
        "business_certificate",
        "historical_dns",
        "login_endpoint",
        "non_public_cdn",
    ]


class _DuplicateKeyMapping(Mapping):
    """A Mapping whose ``items()`` yields raw pairs without deduping.

    A dict literal collapses ``RoleSignal.BUSINESS_API`` and its equal str key,
    hiding the duplicate-weight guard. This mapping preserves both pairs so the
    guard can be exercised honestly.
    """

    def __init__(self, *pairs: tuple[object, int]) -> None:
        self._pairs = pairs

    def items(self):  # type: ignore[override]
        return iter(self._pairs)

    def __getitem__(self, key: object) -> int:
        for candidate, value in self._pairs:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self):
        return (key for key, _ in self._pairs)

    def __len__(self) -> int:
        return len(self._pairs)


# --------------------------------------------------------------------------- #
# Private role-weight policy
# --------------------------------------------------------------------------- #
# Documented PR4 weights. Any extra, omitted, or changed signal below is a
# policy change and must fail the exact-equality assertions.
_DOMESTIC_RELAY_WEIGHTS = {
    "direct_connection": 40,
    "domestic_network": 15,
    "subsequent_overseas_connection": 20,
    "redirect": 15,
    "historical_dns": 15,
    "non_public_cdn": 10,
    "public_cdn": -60,
}
_ORIGIN_WEIGHTS = {
    "business_api": 30,
    "login_endpoint": 15,
    "stable_ip": 15,
    "business_certificate": 15,
    "non_public_cdn": 20,
    "historical_dns": 15,
    "public_cdn": -60,
}
_EDGE_WEIGHTS = {
    "many_shared_domains": 15,
    "redirect": 15,
    "cookie_challenge": 20,
    "shared_tls": 15,
    "content_difference": 25,
    "public_cdn": 0,
}


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (InfrastructureRole.DOMESTIC_RELAY_CANDIDATE, _DOMESTIC_RELAY_WEIGHTS),
        (InfrastructureRole.ORIGIN_CANDIDATE, _ORIGIN_WEIGHTS),
        (InfrastructureRole.EDGE_CANDIDATE, _EDGE_WEIGHTS),
    ],
)
def test_role_policy_weights_match_documented_table_exactly(
    role: InfrastructureRole, expected: dict[str, int]
) -> None:
    policy = _ROLE_POLICIES[role]
    # Exact equality catches any extra, omitted, or changed signal/weight.
    assert policy.to_dict() == expected
    assert {signal.value: points for signal, points in policy.weights.items()} == (expected)


def test_edge_policy_carries_explicit_zero_weight_public_cdn_context() -> None:
    policy = _ROLE_POLICIES[InfrastructureRole.EDGE_CANDIDATE]
    # public_cdn must be present as explanatory context, not omitted, and 0.
    assert RoleSignal.PUBLIC_CDN in policy.weights
    assert policy.weight(RoleSignal.PUBLIC_CDN) == 0


def test_negative_public_cdn_weights_only_on_relay_and_origin() -> None:
    relay = _ROLE_POLICIES[InfrastructureRole.DOMESTIC_RELAY_CANDIDATE]
    origin = _ROLE_POLICIES[InfrastructureRole.ORIGIN_CANDIDATE]
    assert relay.weight(RoleSignal.PUBLIC_CDN) == -60
    assert origin.weight(RoleSignal.PUBLIC_CDN) == -60


def test_policy_table_covers_exactly_the_three_scored_roles() -> None:
    assert set(_ROLE_POLICIES) == {
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE,
        InfrastructureRole.ORIGIN_CANDIDATE,
        InfrastructureRole.EDGE_CANDIDATE,
    }
    # cloaking_edge_node is reserved for PR8 and has no PR4 policy.
    assert InfrastructureRole.CLOAKING_EDGE_NODE not in _ROLE_POLICIES


def test_policy_role_matches_its_table_key() -> None:
    for role, policy in _ROLE_POLICIES.items():
        assert policy.role is role


def test_policy_signals_property_matches_weight_keys() -> None:
    for policy in _ROLE_POLICIES.values():
        assert policy.signals == tuple(policy.weights)


def test_policy_weight_returns_none_for_unscored_signal() -> None:
    relay = _ROLE_POLICIES[InfrastructureRole.DOMESTIC_RELAY_CANDIDATE]
    # cookie_challenge is an edge signal, not a domestic-relay signal.
    assert relay.weight(RoleSignal.COOKIE_CHALLENGE) is None


def test_policy_weight_accepts_str_and_rejects_unknown() -> None:
    origin = _ROLE_POLICIES[InfrastructureRole.ORIGIN_CANDIDATE]
    assert origin.weight("business_api") == 30
    with pytest.raises(ValueError):
        origin.weight("not_a_signal")


# --------------------------------------------------------------------------- #
# Policy immutability
# --------------------------------------------------------------------------- #
def test_role_policy_instance_is_frozen() -> None:
    policy = _ROLE_POLICIES[InfrastructureRole.ORIGIN_CANDIDATE]
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.role = InfrastructureRole.EDGE_CANDIDATE  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.weights = {}  # type: ignore[misc]


def test_role_policy_weight_mapping_is_read_only() -> None:
    policy = _ROLE_POLICIES[InfrastructureRole.ORIGIN_CANDIDATE]
    with pytest.raises(TypeError):
        policy.weights[RoleSignal.BUSINESS_API] = 999  # type: ignore[index]
    with pytest.raises(TypeError):
        del policy.weights[RoleSignal.BUSINESS_API]  # type: ignore[attr-defined]


def test_role_policy_table_is_read_only() -> None:
    with pytest.raises(TypeError):
        _ROLE_POLICIES[  # type: ignore[index]
            InfrastructureRole.ORIGIN_CANDIDATE
        ] = _ROLE_POLICIES[InfrastructureRole.EDGE_CANDIDATE]


def test_policy_to_dict_is_a_fresh_copy() -> None:
    policy = _ROLE_POLICIES[InfrastructureRole.EDGE_CANDIDATE]
    dumped = policy.to_dict()
    dumped["public_cdn"] = 12345
    # Mutating the returned dict must not affect the immutable policy.
    assert policy.weight(RoleSignal.PUBLIC_CDN) == 0


def test_role_policy_rejects_cloaking_edge_node() -> None:
    with pytest.raises(ValueError):
        _RolePolicy(
            role=InfrastructureRole.CLOAKING_EDGE_NODE,
            weights={RoleSignal.PUBLIC_CDN: 0},
        )


def test_role_policy_rejects_duplicate_and_non_int_weights() -> None:
    with pytest.raises(TypeError):
        _RolePolicy(
            role=InfrastructureRole.ORIGIN_CANDIDATE,
            weights={RoleSignal.BUSINESS_API: True},  # bool is not a valid int
        )
    with pytest.raises(TypeError):
        _RolePolicy(
            role=InfrastructureRole.ORIGIN_CANDIDATE,
            weights=("business_api", 30),  # not a mapping  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        # A dict literal collapses enum and str keys, so a duplicate can only
        # reach the guard via a mapping that yields two items coercing to the
        # same signal. This proves the duplicate branch is enforced.
        _RolePolicy(
            role=InfrastructureRole.ORIGIN_CANDIDATE,
            weights=_DuplicateKeyMapping((RoleSignal.BUSINESS_API, 30), ("business_api", 40)),
        )


# --------------------------------------------------------------------------- #
# EvidenceScorer
# --------------------------------------------------------------------------- #
def _points_by_signal(score: "RoleScore") -> dict[RoleSignal, int]:
    return {item.signal: item.points for item in score.contributions}


def _missing_points_by_signal(score: "RoleScore") -> dict[RoleSignal, int]:
    return {item.signal: item.points for item in score.missing}


def test_scorer_origin_canonical_exact_score_contributions_and_missing() -> None:
    target = _entity()
    features = (
        _feature(RoleSignal.BUSINESS_API, "ev-api", target=target),
        _feature(RoleSignal.STABLE_IP, "ev-ip", target=target),
    )
    assessment = _assessment_for(InfrastructureRole.ORIGIN_CANDIDATE, features, target=target)
    score = _require_scorer().score(assessment)

    assert score.role is InfrastructureRole.ORIGIN_CANDIDATE
    assert score.eligible is True
    assert score.raw_score == 45
    assert score.score == 45
    assert score.confidence == 45 / MAX_SCORE
    # business_api (30) + stable_ip (15); weight applied once per signal.
    assert _points_by_signal(score) == {
        RoleSignal.BUSINESS_API: 30,
        RoleSignal.STABLE_IP: 15,
    }
    # Only absent positive-weight signals are reported as missing.
    assert _missing_points_by_signal(score) == {
        RoleSignal.LOGIN_ENDPOINT: 15,
        RoleSignal.BUSINESS_CERTIFICATE: 15,
        RoleSignal.NON_PUBLIC_CDN: 20,
        RoleSignal.HISTORICAL_DNS: 15,
    }


def test_scorer_domestic_relay_public_cdn_is_negative_and_blocks_eligibility() -> None:
    target = _entity()
    features = (
        _feature(RoleSignal.DIRECT_CONNECTION, "ev-direct", target=target),
        _feature(RoleSignal.DOMESTIC_NETWORK, "ev-domestic", target=target),
        _feature(RoleSignal.REDIRECT, "ev-redirect", target=target),
        _feature(RoleSignal.PUBLIC_CDN, "ev-cdn", target=target),
    )
    assessment = _assessment_for(
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE, features, target=target
    )
    score = _require_scorer().score(assessment)

    # public_cdn is a blocker for this role: ineligible, confidence pinned to 0.
    assert score.eligible is False
    assert score.confidence == 0.0
    # 40 + 15 + 15 - 60 == 10; the negative public_cdn weight is applied.
    assert score.raw_score == 10
    assert score.score == 10
    assert _points_by_signal(score)[RoleSignal.PUBLIC_CDN] == -60
    assert RoleSignal.PUBLIC_CDN in {item.signal for item in score.negative_contributions}


def test_scorer_domestic_relay_historical_dns_is_retained_and_scores() -> None:
    # historical_dns is a domestic-relay supporting signal: when present it must
    # be retained by the classifier and scored +15 by the policy, never dropped
    # and mistaken for a gap.
    target = _entity()
    features = (
        _feature(RoleSignal.DIRECT_CONNECTION, "ev-direct", target=target),
        _feature(RoleSignal.DOMESTIC_NETWORK, "ev-domestic", target=target),
        _feature(RoleSignal.REDIRECT, "ev-redirect", target=target),
        _feature(RoleSignal.HISTORICAL_DNS, "ev-dns", target=target),
    )
    assessment = _assessment_for(
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE, features, target=target
    )
    score = _require_scorer().score(assessment)

    assert score.eligible is True
    assert _points_by_signal(score)[RoleSignal.HISTORICAL_DNS] == 15
    # direct(40) + domestic(15) + redirect(15) + historical_dns(15) == 85.
    assert score.raw_score == 85
    # Present evidence is never also reported as missing.
    assert RoleSignal.HISTORICAL_DNS not in _missing_points_by_signal(score)


def test_scorer_domestic_relay_historical_dns_missing_when_absent() -> None:
    # Absent historical_dns is a positive-weight gap and must be listed as
    # missing weighted evidence at +15 for the domestic-relay role.
    target = _entity()
    features = (
        _feature(RoleSignal.DIRECT_CONNECTION, "ev-direct", target=target),
        _feature(RoleSignal.DOMESTIC_NETWORK, "ev-domestic", target=target),
        _feature(RoleSignal.REDIRECT, "ev-redirect", target=target),
    )
    assessment = _assessment_for(
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE, features, target=target
    )
    score = _require_scorer().score(assessment)

    assert score.eligible is True
    assert _missing_points_by_signal(score)[RoleSignal.HISTORICAL_DNS] == 15
    assert RoleSignal.HISTORICAL_DNS not in _points_by_signal(score)


def test_scorer_edge_public_cdn_is_zero_weight_context() -> None:
    target = _entity()
    features = (
        _feature(RoleSignal.REDIRECT, "ev-redirect", target=target),
        _feature(RoleSignal.COOKIE_CHALLENGE, "ev-cookie", target=target),
        _feature(RoleSignal.PUBLIC_CDN, "ev-cdn", target=target),
    )
    assessment = _assessment_for(InfrastructureRole.EDGE_CANDIDATE, features, target=target)
    score = _require_scorer().score(assessment)

    assert score.eligible is True
    # public_cdn is explanatory context for an edge: present, weighted zero.
    assert _points_by_signal(score)[RoleSignal.PUBLIC_CDN] == 0
    assert RoleSignal.PUBLIC_CDN in {item.signal for item in score.context_contributions}
    # redirect (15) + cookie_challenge (20) + public_cdn (0).
    assert score.raw_score == 35
    assert score.confidence == 35 / MAX_SCORE


def test_scorer_weights_duplicate_signal_once_preserving_both_confidences() -> None:
    target = _entity()
    first = RoleFeature(
        signal=RoleSignal.BUSINESS_API,
        evidence=AttributionEvidence(
            id="ev-api-a",
            source="pcap",
            type="role_signal",
            target=target,
            value=True,
            confidence=0.7,
        ),
    )
    second = RoleFeature(
        signal=RoleSignal.BUSINESS_API,
        evidence=AttributionEvidence(
            id="ev-api-b",
            source="pcap",
            type="role_signal",
            target=target,
            value=True,
            confidence=0.9,
        ),
    )
    features = (
        first,
        second,
        _feature(RoleSignal.STABLE_IP, "ev-ip", target=target),
    )
    assessment = _assessment_for(InfrastructureRole.ORIGIN_CANDIDATE, features, target=target)
    score = _require_scorer().score(assessment)

    business = next(item for item in score.contributions if item.signal is RoleSignal.BUSINESS_API)
    # Two supporting features, but the signal weight is counted exactly once.
    assert business.points == 30
    assert len(business.features) == 2
    assert sorted(item.confidence for item in business.evidence) == [0.7, 0.9]
    assert score.raw_score == 45


def test_scorer_ineligible_still_scores_but_confidence_is_zero() -> None:
    target = _entity()
    # business_api alone satisfies no correlation requirement -> ineligible.
    features = (_feature(RoleSignal.BUSINESS_API, "ev-api", target=target),)
    assessment = _assessment_for(InfrastructureRole.ORIGIN_CANDIDATE, features, target=target)
    assert assessment.eligible is False
    score = _require_scorer().score(assessment)

    assert score.eligible is False
    assert score.raw_score == 30
    assert score.score == 30
    assert score.confidence == 0.0


def test_scorer_rejects_fabricated_eligibility() -> None:
    target = _entity()
    features = (_feature(RoleSignal.BUSINESS_API, "ev-api", target=target),)
    assessment = _assessment_for(InfrastructureRole.ORIGIN_CANDIDATE, features, target=target)
    tampered = dataclasses.replace(assessment, eligible=True)
    with pytest.raises(ValueError):
        _require_scorer().score(tampered)


def test_scorer_rejects_origin_public_cdn_misplaced_into_context() -> None:
    target = _entity()
    features = (
        _feature(RoleSignal.BUSINESS_API, "ev-api", target=target),
        _feature(RoleSignal.STABLE_IP, "ev-ip", target=target),
        _feature(RoleSignal.PUBLIC_CDN, "ev-cdn", target=target),
    )
    assessment = _assessment_for(InfrastructureRole.ORIGIN_CANDIDATE, features, target=target)
    # Canonically public_cdn is a negative (blocker) for origin, never context.
    public_cdn_feature = assessment.negative_features[0]
    tampered = dataclasses.replace(
        assessment,
        negative_features=(),
        context_features=(public_cdn_feature,),
    )
    with pytest.raises(ValueError):
        _require_scorer().score(tampered)


def test_scorer_rejects_inconsistent_missing_evidence() -> None:
    target = _entity()
    features = (
        _feature(RoleSignal.BUSINESS_API, "ev-api", target=target),
        _feature(RoleSignal.STABLE_IP, "ev-ip", target=target),
    )
    assessment = _assessment_for(InfrastructureRole.ORIGIN_CANDIDATE, features, target=target)
    assert assessment.missing_evidence  # canonical form lists absent supporters
    tampered = dataclasses.replace(assessment, missing_evidence=())
    with pytest.raises(ValueError):
        _require_scorer().score(tampered)


def test_scorer_is_deterministic_regardless_of_input_feature_order() -> None:
    target = _entity()
    a = _feature(RoleSignal.BUSINESS_API, "ev-api", target=target)
    b = _feature(RoleSignal.STABLE_IP, "ev-ip", target=target)
    c = _feature(RoleSignal.LOGIN_ENDPOINT, "ev-login", target=target)
    forward = _assessment_for(InfrastructureRole.ORIGIN_CANDIDATE, (a, b, c), target=target)
    reverse = _assessment_for(InfrastructureRole.ORIGIN_CANDIDATE, (c, b, a), target=target)
    scorer = _require_scorer()
    forward_payload = scorer.score(forward).to_dict()
    reverse_payload = scorer.score(reverse).to_dict()

    assert forward_payload == reverse_payload
    assert json.loads(json.dumps(forward_payload)) == forward_payload


def test_scorer_preserves_canonical_signal_omitted_from_policy_as_zero_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A canonical matched/context/negative signal that the active policy omits
    # must not be silently dropped: it is preserved as zero-weight context with
    # its evidence intact and leaves the score unchanged. We prove this by
    # monkeypatching the edge policy to drop public_cdn entirely; the exact
    # production policy is untouched (it still weights public_cdn at 0).
    import apkscan.attribution.scorer as scorer_mod

    target = _entity()
    features = (
        _feature(RoleSignal.REDIRECT, "ev-redirect", target=target),
        _feature(RoleSignal.COOKIE_CHALLENGE, "ev-cookie", target=target),
        _feature(RoleSignal.PUBLIC_CDN, "ev-cdn", target=target),
    )
    assessment = _assessment_for(InfrastructureRole.EDGE_CANDIDATE, features, target=target)

    # Baseline score under the exact production policy (public_cdn weighted 0).
    baseline = _require_scorer().score(assessment)

    # Build an edge policy that omits public_cdn, then swap it into the table.
    edge = _ROLE_POLICIES[InfrastructureRole.EDGE_CANDIDATE]
    trimmed_weights = {
        signal: points
        for signal, points in edge.weights.items()
        if signal is not RoleSignal.PUBLIC_CDN
    }
    assert RoleSignal.PUBLIC_CDN not in trimmed_weights
    patched_edge = _RolePolicy(role=InfrastructureRole.EDGE_CANDIDATE, weights=trimmed_weights)
    patched_table = dict(_ROLE_POLICIES)
    patched_table[InfrastructureRole.EDGE_CANDIDATE] = patched_edge
    monkeypatch.setattr(scorer_mod, "_ROLE_POLICIES", patched_table)

    score = _require_scorer().score(assessment)

    # public_cdn survives as zero-weight context even though the policy omits it.
    assert _points_by_signal(score)[RoleSignal.PUBLIC_CDN] == 0
    context = next(
        item for item in score.context_contributions if item.signal is RoleSignal.PUBLIC_CDN
    )
    # Its evidence is preserved verbatim, not dropped.
    assert [item.id for item in context.evidence] == ["ev-cdn"]
    # Score is unchanged: preservation adds zero points.
    assert score.raw_score == baseline.raw_score
    assert score.score == baseline.score
    assert score.confidence == baseline.confidence
    # Omitting the signal from the policy still yields the same serialized
    # context_evidence entry as the production zero-weight policy did.
    assert score.to_dict()["context_evidence"] == baseline.to_dict()["context_evidence"]


def test_scorer_rejects_non_assessment_and_cloaking_role() -> None:
    scorer = _require_scorer()
    with pytest.raises(TypeError):
        scorer.score(object())  # type: ignore[arg-type]
    cloaking = RoleAssessment(
        target=_entity(),
        role=InfrastructureRole.CLOAKING_EDGE_NODE,
        eligible=False,
    )
    with pytest.raises(ValueError):
        scorer.score(cloaking)


# --------------------------------------------------------------------------- #
# RoleScore semantic-safety regression tests. RoleScore must cross-check itself
# against the per-role policy and the RoleClassifier.
#
# Every score below is *arithmetically* self-consistent: raw_score equals the
# contribution sum, score equals the clamped raw, and confidence equals the
# eligibility projection. Each case nevertheless violates a semantic invariant
# and therefore must be rejected with ``ValueError``.
# --------------------------------------------------------------------------- #
def _origin_positive_weights() -> dict[RoleSignal, int]:
    """The exact positive-weight origin signals a canonical missing list draws
    from. Mirrors the documented ORIGIN policy (public_cdn is negative, so it is
    never a *missing* positive signal)."""
    return {
        RoleSignal.BUSINESS_API: 30,
        RoleSignal.LOGIN_ENDPOINT: 15,
        RoleSignal.STABLE_IP: 15,
        RoleSignal.BUSINESS_CERTIFICATE: 15,
        RoleSignal.NON_PUBLIC_CDN: 20,
        RoleSignal.HISTORICAL_DNS: 15,
    }


def _origin_missing_for(
    present: set[RoleSignal],
) -> tuple[MissingScoreEvidence, ...]:
    """Canonical complete missing list for an origin score: every positive-weight
    origin signal that is not present, at its documented policy points."""
    return tuple(
        MissingScoreEvidence(signal=signal, points=points)
        for signal, points in _origin_positive_weights().items()
        if signal not in present
    )


def test_role_score_rejects_eligible_origin_with_no_contributions() -> None:
    # (a) An eligible origin with zero contributions and every positive signal
    # listed as missing. raw/score are 0 and confidence is 0/100 == 0.0, so the
    # arithmetic is internally consistent — yet a role cannot be eligible on no
    # positive evidence whatsoever.
    target = _entity()
    base = _valid_role_score(target, (), eligible=True, missing=_origin_missing_for(set()))
    assert base["raw_score"] == 0
    assert base["score"] == 0
    assert base["confidence"] == 0.0
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_rejects_business_api_points_not_matching_policy() -> None:
    # (b) A business_api contribution weighted 999 (the ORIGIN policy weight is
    # 30) with an otherwise complete, consistent origin score. raw==999,
    # score clamps to 100, confidence==1.0 — every arithmetic check agrees with
    # the inflated points, so only a policy cross-check can reject it.
    target = _entity()
    inflated = _contribution(RoleSignal.BUSINESS_API, 999, "ev-api", target=target)
    base = _valid_role_score(
        target,
        (inflated,),
        eligible=True,
        missing=_origin_missing_for({RoleSignal.BUSINESS_API}),
    )
    assert base["raw_score"] == 999
    assert base["score"] == MAX_SCORE
    assert base["confidence"] == 1.0
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_rejects_omitted_missing_positive_signal() -> None:
    # (c) A genuinely absent positive-weight origin signal (historical_dns) is
    # omitted from the missing list. Missing entries never touch raw/score, so
    # the incomplete trace passes every arithmetic check and is only catchable
    # by a completeness check against the policy.
    target = _entity()
    contributions = (
        _contribution(RoleSignal.BUSINESS_API, 30, "ev-api", target=target),
        _contribution(RoleSignal.STABLE_IP, 15, "ev-ip", target=target),
    )
    present = {RoleSignal.BUSINESS_API, RoleSignal.STABLE_IP}
    incomplete = tuple(
        item
        for item in _origin_missing_for(present)
        if item.signal is not RoleSignal.HISTORICAL_DNS
    )
    assert RoleSignal.HISTORICAL_DNS not in {item.signal for item in incomplete}
    base = _valid_role_score(target, contributions, eligible=True, missing=incomplete)
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_rejects_missing_signal_with_wrong_points() -> None:
    # (d) A missing positive signal carried at the wrong weight (historical_dns
    # at 99 instead of the policy's 15). Missing points never enter raw/score,
    # so the tampered weight is arithmetic-invisible.
    target = _entity()
    contributions = (
        _contribution(RoleSignal.BUSINESS_API, 30, "ev-api", target=target),
        _contribution(RoleSignal.STABLE_IP, 15, "ev-ip", target=target),
    )
    present = {RoleSignal.BUSINESS_API, RoleSignal.STABLE_IP}
    wrong_missing = tuple(
        MissingScoreEvidence(signal=item.signal, points=99)
        if item.signal is RoleSignal.HISTORICAL_DNS
        else item
        for item in _origin_missing_for(present)
    )
    assert any(
        item.signal is RoleSignal.HISTORICAL_DNS and item.points == 99 for item in wrong_missing
    )
    base = _valid_role_score(target, contributions, eligible=True, missing=wrong_missing)
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_rejects_irrelevant_cookie_challenge_context_under_origin() -> None:
    # (e) cookie_challenge is an edge signal with no origin policy weight. A
    # zero-point cookie_challenge contribution adds nothing to raw/score, so it
    # is arithmetic-invisible, yet it is semantically irrelevant under origin and
    # would never appear in a canonical origin score.
    target = _entity()
    contributions = (
        _contribution(RoleSignal.BUSINESS_API, 30, "ev-api", target=target),
        _contribution(RoleSignal.COOKIE_CHALLENGE, 0, "ev-cookie", target=target),
        _contribution(RoleSignal.STABLE_IP, 15, "ev-ip", target=target),
    )
    present = {RoleSignal.BUSINESS_API, RoleSignal.STABLE_IP}
    base = _valid_role_score(
        target, contributions, eligible=True, missing=_origin_missing_for(present)
    )
    assert base["raw_score"] == 45  # cookie_challenge@0 leaves arithmetic intact
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_role_score_rejects_eligible_flag_conflicting_with_classifier() -> None:
    # (f) business_api alone never satisfies the origin correlation requirement,
    # so RoleClassifier deems the target ineligible. A score that reconstructs
    # the same single signal yet claims eligible=True contradicts the canonical
    # verdict; confidence==30/100 is a valid eligible projection, so only a
    # classifier cross-check catches the fabricated eligibility.
    target = _entity()
    canonical = _assessment_for(
        InfrastructureRole.ORIGIN_CANDIDATE,
        (_feature(RoleSignal.BUSINESS_API, "ev-api", target=target),),
        target=target,
    )
    assert canonical.eligible is False
    contributions = (_contribution(RoleSignal.BUSINESS_API, 30, "ev-api", target=target),)
    base = _valid_role_score(
        target,
        contributions,
        eligible=True,
        missing=_origin_missing_for({RoleSignal.BUSINESS_API}),
    )
    assert base["confidence"] == 30 / MAX_SCORE
    with pytest.raises(ValueError):
        RoleScore(**base)  # type: ignore[arg-type]


def test_scorer_origin_public_cdn_blocks_eligibility_with_negative_contribution() -> None:
    # Canonical GREEN anchor: an origin target carrying public_cdn is blocked.
    # The scorer applies the -60 public_cdn weight, pins eligibility false and
    # confidence 0, and clamps the negative raw score to the floor.
    target = _entity()
    features = (
        _feature(RoleSignal.BUSINESS_API, "ev-api", target=target),
        _feature(RoleSignal.STABLE_IP, "ev-ip", target=target),
        _feature(RoleSignal.PUBLIC_CDN, "ev-cdn", target=target),
    )
    assessment = _assessment_for(InfrastructureRole.ORIGIN_CANDIDATE, features, target=target)
    score = _require_scorer().score(assessment)

    assert score.eligible is False
    assert score.confidence == 0.0
    assert _points_by_signal(score)[RoleSignal.PUBLIC_CDN] == -60
    assert RoleSignal.PUBLIC_CDN in {item.signal for item in score.negative_contributions}
    # business_api(30) + stable_ip(15) - public_cdn(60) == -15, clamped to 0.
    assert score.raw_score == -15
    assert score.score == MIN_SCORE
