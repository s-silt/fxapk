from __future__ import annotations

import dataclasses
import json

import pytest

from apkscan.attribution.models import AttributionEvidence
from apkscan.attribution.roles import (
    InfrastructureRole,
    RoleAssessment,
    RoleClassifier,
    RoleFeature,
    RoleSignal,
)
from apkscan.network import NetworkEntity, NetworkEntityType


def _entity(value: str = "1.2.3.4") -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.IP, value, sources=["pcap"])


def _evidence(
    evidence_id: str,
    *,
    target: NetworkEntity | None = None,
    evidence_type: str = "role_signal",
) -> AttributionEvidence:
    return AttributionEvidence(
        id=evidence_id,
        source="pcap",
        type=evidence_type,
        target=target or _entity(),
        value=True,
        confidence=0.8,
    )


def _feature(signal: RoleSignal, evidence_id: str) -> RoleFeature:
    return RoleFeature(signal=signal, evidence=_evidence(evidence_id))


def test_role_vocabulary_and_cloaking_parent_are_stable() -> None:
    assert [role.value for role in InfrastructureRole] == [
        "domestic_relay_candidate",
        "origin_candidate",
        "edge_candidate",
        "cloaking_edge_node",
    ]
    assert InfrastructureRole.CLOAKING_EDGE_NODE.parent is InfrastructureRole.EDGE_CANDIDATE
    assert InfrastructureRole.EDGE_CANDIDATE.parent is None


def test_role_feature_is_keyword_only_frozen_and_validated() -> None:
    feature = _feature(RoleSignal.DIRECT_CONNECTION, "ev-1")
    assert feature.signal is RoleSignal.DIRECT_CONNECTION
    with pytest.raises(dataclasses.FrozenInstanceError):
        feature.signal = RoleSignal.REDIRECT  # type: ignore[misc]
    with pytest.raises(TypeError):
        RoleFeature(RoleSignal.DIRECT_CONNECTION, _evidence("ev-2"))  # type: ignore[misc]
    with pytest.raises((TypeError, ValueError)):
        RoleFeature(signal="not-a-signal", evidence=_evidence("ev-3"))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        RoleFeature(signal=RoleSignal.REDIRECT, evidence=object())  # type: ignore[arg-type]


def test_role_assessment_is_json_safe_and_has_no_score_or_confidence() -> None:
    target = _entity()
    supporting = _evidence("ev-support", target=target)
    negative = _evidence("ev-negative", target=target)
    assessment = RoleAssessment(
        target=target,
        role=InfrastructureRole.ORIGIN_CANDIDATE,
        eligible=False,
        matched_signals=(RoleSignal.BUSINESS_API,),
        matched_evidence=(supporting,),
        missing_evidence=(RoleSignal.NON_PUBLIC_CDN,),
        negative_signals=(RoleSignal.PUBLIC_CDN,),
        negative_evidence=(negative,),
    )
    payload = assessment.to_dict()
    assert payload["role"] == "origin_candidate"
    assert payload["missing_evidence"] == ["non_public_cdn"]
    assert json.loads(json.dumps(payload)) == payload
    assert "score" not in payload
    assert "confidence" not in payload
    assert not hasattr(assessment, "score")
    assert not hasattr(assessment, "confidence")


def _features(*signals: RoleSignal) -> list[RoleFeature]:
    return [_feature(signal, f"ev-{index}") for index, signal in enumerate(signals)]


def test_domestic_relay_requires_location_connection_and_transition() -> None:
    classifier = RoleClassifier()
    features = _features(
        RoleSignal.DIRECT_CONNECTION,
        RoleSignal.DOMESTIC_NETWORK,
        RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION,
    )
    result = classifier.classify(_entity(), features)
    assert [item.role for item in result] == [
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE
    ]
    assert result[0].eligible is True
    assert result[0].missing_evidence == (
        RoleSignal.NON_PUBLIC_CDN,
        RoleSignal.REDIRECT,
    )


def test_origin_accepts_business_api_plus_independent_correlation() -> None:
    result = RoleClassifier().classify(
        _entity(),
        _features(
            RoleSignal.BUSINESS_API,
            RoleSignal.LOGIN_ENDPOINT,
            RoleSignal.HISTORICAL_DNS,
            RoleSignal.NON_PUBLIC_CDN,
        ),
    )
    assert [item.role for item in result] == [InfrastructureRole.ORIGIN_CANDIDATE]
    assert result[0].missing_evidence == (
        RoleSignal.BUSINESS_CERTIFICATE,
        RoleSignal.STABLE_IP,
    )


def test_edge_requires_two_distinct_behavior_or_correlation_signals() -> None:
    classifier = RoleClassifier()
    assert classifier.classify(
        _entity(), _features(RoleSignal.REDIRECT)
    ) == ()
    result = classifier.classify(
        _entity(),
        _features(RoleSignal.REDIRECT, RoleSignal.COOKIE_CHALLENGE),
    )
    assert [item.role for item in result] == [InfrastructureRole.EDGE_CANDIDATE]


def test_assess_returns_ineligible_explanations_but_never_cloaking() -> None:
    assessments = RoleClassifier().assess(_entity(), ())
    assert [item.role for item in assessments] == [
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE,
        InfrastructureRole.ORIGIN_CANDIDATE,
        InfrastructureRole.EDGE_CANDIDATE,
    ]
    assert all(not item.eligible for item in assessments)
    assert InfrastructureRole.CLOAKING_EDGE_NODE not in {
        item.role for item in assessments
    }
