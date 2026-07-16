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


def _evidence_variant(
    evidence_id: str,
    *,
    target: NetworkEntity | None = None,
    value: str | int | float | bool | None = True,
    raw_reference: str | None = None,
) -> AttributionEvidence:
    return AttributionEvidence(
        id=evidence_id,
        source="pcap",
        type="role_signal",
        target=target or _entity(),
        value=value,
        confidence=0.8,
        raw_reference=raw_reference,
    )


def test_exact_duplicate_features_collapse_order_independent() -> None:
    target = _entity()
    first = _evidence_variant("ev-dup", target=target, value=True, raw_reference="ref")
    second = _evidence_variant("ev-dup", target=target, value=True, raw_reference="ref")
    assert first == second
    feature_a = RoleFeature(signal=RoleSignal.DIRECT_CONNECTION, evidence=first)
    feature_b = RoleFeature(signal=RoleSignal.DIRECT_CONNECTION, evidence=second)
    classifier = RoleClassifier()
    forward = [item.to_dict() for item in classifier.assess(target, [feature_a, feature_b])]
    reverse = [item.to_dict() for item in classifier.assess(target, [feature_b, feature_a])]
    assert forward == reverse
    matched = [
        evidence
        for assessment in forward
        for evidence in assessment["matched_evidence"]
        if evidence["id"] == "ev-dup"
    ]
    assert matched and all(item == first.to_dict() for item in matched)


@pytest.mark.parametrize(
    ("first_payload", "second_payload"),
    [
        ({"value": True, "raw_reference": None}, {"value": False, "raw_reference": None}),
        (
            {"value": True, "raw_reference": "ref-a"},
            {"value": True, "raw_reference": "ref-b"},
        ),
    ],
)
def test_conflicting_features_same_id_raise_value_error(
    first_payload: dict[str, object], second_payload: dict[str, object]
) -> None:
    target = _entity()
    first = _evidence_variant("ev-conflict", target=target, **first_payload)  # type: ignore[arg-type]
    second = _evidence_variant("ev-conflict", target=target, **second_payload)  # type: ignore[arg-type]
    feature_a = RoleFeature(signal=RoleSignal.DIRECT_CONNECTION, evidence=first)
    feature_b = RoleFeature(signal=RoleSignal.DIRECT_CONNECTION, evidence=second)
    classifier = RoleClassifier()
    with pytest.raises(ValueError):
        classifier.assess(target, [feature_a, feature_b])
    with pytest.raises(ValueError):
        classifier.assess(target, [feature_b, feature_a])


def test_role_assessment_rejects_conflicting_matched_evidence() -> None:
    target = _entity()
    first = _evidence_variant("ev-shared", target=target, value=True)
    second = _evidence_variant("ev-shared", target=target, value=False)
    with pytest.raises(ValueError):
        RoleAssessment(
            target=target,
            role=InfrastructureRole.ORIGIN_CANDIDATE,
            eligible=False,
            matched_signals=(RoleSignal.BUSINESS_API,),
            matched_evidence=(first, second),
        )
    with pytest.raises(ValueError):
        RoleAssessment(
            target=target,
            role=InfrastructureRole.ORIGIN_CANDIDATE,
            eligible=False,
            matched_signals=(RoleSignal.BUSINESS_API,),
            matched_evidence=(second, first),
        )


def test_foreign_target_conflict_is_ignored_and_target_is_classified() -> None:
    target = _entity("1.2.3.4")
    foreign = _entity("9.9.9.9")
    target_redirect = RoleFeature(
        signal=RoleSignal.REDIRECT,
        evidence=_evidence_variant("ev-shared", target=target, value=True),
    )
    target_cookie = RoleFeature(
        signal=RoleSignal.COOKIE_CHALLENGE,
        evidence=_evidence_variant("ev-cookie", target=target, value=True),
    )
    foreign_conflict = RoleFeature(
        signal=RoleSignal.REDIRECT,
        evidence=_evidence_variant("ev-shared", target=foreign, value=False),
    )
    result = RoleClassifier().classify(
        target, [target_redirect, target_cookie, foreign_conflict]
    )
    assert [item.role for item in result] == [InfrastructureRole.EDGE_CANDIDATE]


def test_conflicting_foreign_features_are_ignored_not_raised() -> None:
    target = _entity("1.2.3.4")
    foreign = _entity("9.9.9.9")
    first = RoleFeature(
        signal=RoleSignal.DIRECT_CONNECTION,
        evidence=_evidence_variant("ev-foreign", target=foreign, value=True),
    )
    second = RoleFeature(
        signal=RoleSignal.DIRECT_CONNECTION,
        evidence=_evidence_variant("ev-foreign", target=foreign, value=False),
    )
    classifier = RoleClassifier()
    assert classifier.classify(target, [first, second]) == ()
    assessments = classifier.assess(target, [first, second])
    assert all(not item.eligible for item in assessments)


def test_non_role_feature_still_raises_type_error_with_foreign_features() -> None:
    target = _entity("1.2.3.4")
    foreign = _entity("9.9.9.9")
    foreign_feature = RoleFeature(
        signal=RoleSignal.REDIRECT,
        evidence=_evidence_variant("ev-foreign", target=foreign, value=True),
    )
    with pytest.raises(TypeError):
        RoleClassifier().assess(target, [foreign_feature, object()])  # type: ignore[list-item]


def test_public_cdn_blocks_origin_and_is_reported_as_negative_evidence() -> None:
    result = RoleClassifier().assess(
        _entity(),
        _features(
            RoleSignal.BUSINESS_API,
            RoleSignal.HISTORICAL_DNS,
            RoleSignal.PUBLIC_CDN,
        ),
    )
    origin = next(
        item for item in result if item.role is InfrastructureRole.ORIGIN_CANDIDATE
    )
    assert origin.eligible is False
    assert origin.negative_signals == (RoleSignal.PUBLIC_CDN,)
    assert [item.id for item in origin.negative_evidence] == ["ev-2"]


@pytest.mark.parametrize("weak_signal", ["generic_server_banner", "asn"])
def test_generic_banner_and_shared_asn_alone_have_no_role_signal(
    weak_signal: str,
) -> None:
    assert weak_signal not in {signal.value for signal in RoleSignal}
    target = _entity()
    evidence = _evidence(weak_signal, target=target, evidence_type=weak_signal)
    with pytest.raises(ValueError):
        RoleFeature(signal=weak_signal, evidence=evidence)  # type: ignore[arg-type]


def test_features_for_other_targets_are_ignored() -> None:
    target = _entity()
    other = _entity("5.6.7.8")
    features = [
        RoleFeature(
            signal=RoleSignal.BUSINESS_API,
            evidence=_evidence("other-api", target=other),
        ),
        RoleFeature(
            signal=RoleSignal.HISTORICAL_DNS,
            evidence=_evidence("other-dns", target=other),
        ),
    ]
    assert RoleClassifier().classify(target, features) == ()


def test_duplicate_features_and_input_order_do_not_change_output() -> None:
    first = _feature(RoleSignal.REDIRECT, "redirect")
    second = _feature(RoleSignal.COOKIE_CHALLENGE, "cookie")
    classifier = RoleClassifier()
    left = [item.to_dict() for item in classifier.assess(_entity(), [first, second, first])]
    right = [item.to_dict() for item in classifier.assess(_entity(), [second, first])]
    assert left == right


def test_public_api_exports_role_types() -> None:
    import apkscan.attribution as attribution
    from apkscan.attribution import (
        InfrastructureRole as ExportedRole,
        RoleAssessment as ExportedAssessment,
        RoleClassifier as ExportedClassifier,
        RoleFeature as ExportedFeature,
        RoleSignal as ExportedSignal,
    )

    assert ExportedRole is InfrastructureRole
    assert ExportedAssessment is RoleAssessment
    assert ExportedClassifier is RoleClassifier
    assert ExportedFeature is RoleFeature
    assert ExportedSignal is RoleSignal

    assert attribution.__all__ == [
        "AttributionEvidence",
        "InfrastructureRole",
        "RoleAssessment",
        "RoleClassifier",
        "RoleFeature",
        "RoleSignal",
    ]
