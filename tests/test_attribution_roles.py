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
    context = _evidence("ev-context", target=target)
    negative = _evidence("ev-negative", target=target)
    assessment = RoleAssessment(
        target=target,
        role=InfrastructureRole.ORIGIN_CANDIDATE,
        eligible=False,
        matched_features=(
            RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=supporting),
        ),
        context_features=(
            RoleFeature(signal=RoleSignal.HISTORICAL_DNS, evidence=context),
        ),
        negative_features=(
            RoleFeature(signal=RoleSignal.PUBLIC_CDN, evidence=negative),
        ),
        missing_evidence=(RoleSignal.NON_PUBLIC_CDN,),
    )
    payload = assessment.to_dict()
    assert payload["role"] == "origin_candidate"
    assert payload["missing_evidence"] == ["non_public_cdn"]
    # Structured feature lists pair each signal with its exact evidence.
    assert payload["matched_features"] == [
        {"signal": "business_api", "evidence": supporting.to_dict()},
    ]
    assert payload["context_features"] == [
        {"signal": "historical_dns", "evidence": context.to_dict()},
    ]
    assert payload["negative_features"] == [
        {"signal": "public_cdn", "evidence": negative.to_dict()},
    ]
    # Derived flat accessors project the structured features back to
    # signals/evidence, on both the object and its serialized form.
    assert assessment.matched_signals == (RoleSignal.BUSINESS_API,)
    assert assessment.matched_evidence == (supporting,)
    assert assessment.negative_signals == (RoleSignal.PUBLIC_CDN,)
    assert assessment.negative_evidence == (negative,)
    assert payload["matched_signals"] == ["business_api"]
    assert payload["matched_evidence"] == [supporting.to_dict()]
    assert payload["negative_signals"] == ["public_cdn"]
    assert payload["negative_evidence"] == [negative.to_dict()]
    assert json.loads(json.dumps(payload)) == payload
    assert "score" not in payload
    assert "confidence" not in payload
    assert not hasattr(assessment, "score")
    assert not hasattr(assessment, "confidence")


def test_shared_evidence_supports_two_signals_but_derives_once() -> None:
    target = _entity()
    shared = _evidence("ev-shared", target=target)
    assessment = RoleAssessment(
        target=target,
        role=InfrastructureRole.EDGE_CANDIDATE,
        eligible=True,
        matched_features=(
            RoleFeature(signal=RoleSignal.REDIRECT, evidence=shared),
            RoleFeature(signal=RoleSignal.COOKIE_CHALLENGE, evidence=shared),
        ),
    )
    payload = assessment.to_dict()
    # The exact same evidence id/payload backs two distinct signals; both
    # structured matched_features survive, one entry per signal, sorted
    # deterministically by signal value.
    assert payload["matched_features"] == [
        {"signal": "cookie_challenge", "evidence": shared.to_dict()},
        {"signal": "redirect", "evidence": shared.to_dict()},
    ]
    # Derived flat signals keep both signals.
    assert assessment.matched_signals == (
        RoleSignal.COOKIE_CHALLENGE,
        RoleSignal.REDIRECT,
    )
    # Derived flat evidence collapses the shared evidence to a single entry.
    assert assessment.matched_evidence == (shared,)
    matched_ids = [item["id"] for item in payload["matched_evidence"]]
    assert matched_ids == ["ev-shared"]


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
        RoleSignal.HISTORICAL_DNS,
        RoleSignal.NON_PUBLIC_CDN,
        RoleSignal.REDIRECT,
    )


def test_domestic_relay_retains_historical_dns_supporting_signal() -> None:
    # historical_dns is a domestic-relay supporting signal: when present it is
    # matched and never listed as missing; when absent it surfaces as a gap.
    # Eligibility never depends on it (the three requirements are unchanged).
    classifier = RoleClassifier()
    with_dns = classifier.classify(
        _entity(),
        _features(
            RoleSignal.DIRECT_CONNECTION,
            RoleSignal.DOMESTIC_NETWORK,
            RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION,
            RoleSignal.HISTORICAL_DNS,
        ),
    )
    assert [item.role for item in with_dns] == [
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE
    ]
    assert with_dns[0].eligible is True
    assert RoleSignal.HISTORICAL_DNS in with_dns[0].matched_signals
    assert RoleSignal.HISTORICAL_DNS not in with_dns[0].missing_evidence

    without_dns = classifier.classify(
        _entity(),
        _features(
            RoleSignal.DIRECT_CONNECTION,
            RoleSignal.DOMESTIC_NETWORK,
            RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION,
        ),
    )
    assert without_dns[0].eligible is True
    assert RoleSignal.HISTORICAL_DNS in without_dns[0].missing_evidence
    assert RoleSignal.HISTORICAL_DNS not in without_dns[0].matched_signals


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
    assert [item.role for item in result] == [
        InfrastructureRole.EDGE_CANDIDATE,
        InfrastructureRole.CLOAKING_EDGE_NODE,  # redirect + cookie_challenge = 2 strong signals
    ]


def test_edge_public_cdn_is_context_only_not_matched_or_negative() -> None:
    # An edge made eligible by redirect + cookie_challenge that also carries a
    # public_cdn observation must surface public_cdn as CONTEXT: it neither
    # helps the edge match nor blocks it, yet it is preserved with its exact
    # evidence rather than silently discarded.
    target = _entity()
    redirect = RoleFeature(
        signal=RoleSignal.REDIRECT,
        evidence=_evidence("ev-redirect", target=target),
    )
    cookie = RoleFeature(
        signal=RoleSignal.COOKIE_CHALLENGE,
        evidence=_evidence("ev-cookie", target=target),
    )
    public_cdn = RoleFeature(
        signal=RoleSignal.PUBLIC_CDN,
        evidence=_evidence("ev-public-cdn", target=target),
    )
    result = RoleClassifier().classify(target, [redirect, cookie, public_cdn])
    assert [item.role for item in result] == [
        InfrastructureRole.EDGE_CANDIDATE,
        InfrastructureRole.CLOAKING_EDGE_NODE,  # redirect + cookie_challenge = 2 strong signals
    ]
    edge = result[0]
    assert edge.eligible is True
    # public_cdn lives only in the context lanes, mapped to its exact evidence.
    assert edge.context_signals == (RoleSignal.PUBLIC_CDN,)
    assert edge.context_features == (public_cdn,)
    assert [item.id for item in edge.context_evidence] == ["ev-public-cdn"]
    payload = edge.to_dict()
    assert payload["context_features"] == [
        {"signal": "public_cdn", "evidence": public_cdn.evidence.to_dict()},
    ]
    assert payload["context_signals"] == ["public_cdn"]
    assert payload["context_evidence"] == [public_cdn.evidence.to_dict()]
    # It is absent from the matched and negative lanes entirely.
    assert RoleSignal.PUBLIC_CDN not in edge.matched_signals
    assert RoleSignal.PUBLIC_CDN not in edge.negative_signals
    assert "ev-public-cdn" not in {item.id for item in edge.matched_evidence}
    assert "ev-public-cdn" not in {item.id for item in edge.negative_evidence}
    # A context signal is not a gap the edge is missing.
    assert RoleSignal.PUBLIC_CDN not in edge.missing_evidence


def test_public_cdn_alone_never_classifies_as_edge() -> None:
    # public_cdn is contextual, never a load-bearing edge signal: on its own it
    # cannot make an edge eligible, and even in the ineligible assessment it is
    # reported as context, never as a matched edge signal.
    classifier = RoleClassifier()
    assert classifier.classify(_entity(), _features(RoleSignal.PUBLIC_CDN)) == ()
    assessments = classifier.assess(_entity(), _features(RoleSignal.PUBLIC_CDN))
    edge = next(
        item for item in assessments if item.role is InfrastructureRole.EDGE_CANDIDATE
    )
    assert edge.eligible is False
    assert edge.matched_signals == ()
    assert edge.context_signals == (RoleSignal.PUBLIC_CDN,)


def test_edge_without_public_cdn_does_not_report_it_missing() -> None:
    # Because public_cdn is contextual rather than required, an otherwise
    # eligible edge that simply lacks it must not carry any public_cdn context
    # nor list public_cdn as missing evidence.
    result = RoleClassifier().classify(
        _entity(),
        _features(RoleSignal.REDIRECT, RoleSignal.COOKIE_CHALLENGE),
    )
    assert [item.role for item in result] == [
        InfrastructureRole.EDGE_CANDIDATE,
        InfrastructureRole.CLOAKING_EDGE_NODE,  # redirect + cookie_challenge = 2 strong signals
    ]
    edge = result[0]
    assert edge.context_signals == ()
    assert RoleSignal.PUBLIC_CDN not in edge.missing_evidence


def test_assess_returns_ineligible_explanations_including_cloaking() -> None:
    assessments = RoleClassifier().assess(_entity(), ())
    assert [item.role for item in assessments] == [
        InfrastructureRole.DOMESTIC_RELAY_CANDIDATE,
        InfrastructureRole.ORIGIN_CANDIDATE,
        InfrastructureRole.EDGE_CANDIDATE,
        InfrastructureRole.CLOAKING_EDGE_NODE,
    ]
    # cloaking is now emitted (last) but, like the others, ineligible on empty features
    assert all(not item.eligible for item in assessments)
    assert InfrastructureRole.CLOAKING_EDGE_NODE in {item.role for item in assessments}


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
            matched_features=(
                RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=first),
                RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=second),
            ),
        )
    with pytest.raises(ValueError):
        RoleAssessment(
            target=target,
            role=InfrastructureRole.ORIGIN_CANDIDATE,
            eligible=False,
            matched_features=(
                RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=second),
                RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=first),
            ),
        )


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
def test_assess_same_id_conflicting_payloads_across_signals_raise(
    first_payload: dict[str, object], second_payload: dict[str, object]
) -> None:
    # One target reuses the same evidence.id under two DIFFERENT signals while
    # the full payloads disagree: the classifier must reject this regardless of
    # input order, since a single id cannot describe two different facts.
    # DIRECT_CONNECTION and BUSINESS_API never co-occur in a single role
    # definition's supporting set, so the id collision cannot be caught
    # incidentally by any one assessment's evidence normalization: the
    # classifier must reject it at feature intake, on the id alone.
    target = _entity()
    first = _evidence_variant("ev-cross", target=target, **first_payload)  # type: ignore[arg-type]
    second = _evidence_variant("ev-cross", target=target, **second_payload)  # type: ignore[arg-type]
    feature_a = RoleFeature(signal=RoleSignal.DIRECT_CONNECTION, evidence=first)
    feature_b = RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=second)
    classifier = RoleClassifier()
    with pytest.raises(ValueError):
        classifier.assess(target, [feature_a, feature_b])
    with pytest.raises(ValueError):
        classifier.assess(target, [feature_b, feature_a])


def test_assess_same_id_same_payload_across_signals_is_legal() -> None:
    # The exact same id/payload backing two distinct signals is legitimate
    # shared evidence and must never raise (preservation is covered by
    # test_shared_evidence_supports_two_signals_but_derives_once).
    target = _entity()
    first = _evidence_variant("ev-legal", target=target, value=True, raw_reference="ref")
    second = _evidence_variant("ev-legal", target=target, value=True, raw_reference="ref")
    assert first == second
    feature_a = RoleFeature(signal=RoleSignal.REDIRECT, evidence=first)
    feature_b = RoleFeature(signal=RoleSignal.COOKIE_CHALLENGE, evidence=second)
    classifier = RoleClassifier()
    forward = [item.to_dict() for item in classifier.assess(target, [feature_a, feature_b])]
    reverse = [item.to_dict() for item in classifier.assess(target, [feature_b, feature_a])]
    assert forward == reverse


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
def test_role_assessment_conflicting_payload_across_feature_buckets_raise(
    first_payload: dict[str, object], second_payload: dict[str, object]
) -> None:
    # The same evidence.id appears once in matched_features and once in
    # negative_features with disagreeing payloads. RoleAssessment must reject
    # the cross-bucket conflict no matter which bucket holds which payload.
    target = _entity()
    first = _evidence_variant("ev-bucket", target=target, **first_payload)  # type: ignore[arg-type]
    second = _evidence_variant("ev-bucket", target=target, **second_payload)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        RoleAssessment(
            target=target,
            role=InfrastructureRole.ORIGIN_CANDIDATE,
            eligible=False,
            matched_features=(
                RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=first),
            ),
            negative_features=(
                RoleFeature(signal=RoleSignal.PUBLIC_CDN, evidence=second),
            ),
        )
    with pytest.raises(ValueError):
        RoleAssessment(
            target=target,
            role=InfrastructureRole.ORIGIN_CANDIDATE,
            eligible=False,
            matched_features=(
                RoleFeature(signal=RoleSignal.BUSINESS_API, evidence=second),
            ),
            negative_features=(
                RoleFeature(signal=RoleSignal.PUBLIC_CDN, evidence=first),
            ),
        )


@pytest.mark.parametrize(
    ("bucket_a", "bucket_b"),
    [
        ("matched_features", "context_features"),
        ("matched_features", "negative_features"),
        ("context_features", "negative_features"),
    ],
)
@pytest.mark.parametrize("shared_evidence_id", [True, False])
def test_role_assessment_rejects_same_signal_in_two_buckets(
    bucket_a: str, bucket_b: str, shared_evidence_id: bool
) -> None:
    # A single RoleSignal must belong to exactly one bucket: it cannot be both
    # matched and context (or negative) for the same target/role. This holds
    # whether the two features share the exact same evidence id/payload (the
    # exact same RoleFeature) or cite different evidence ids under that signal.
    target = _entity()
    signal = RoleSignal.REDIRECT
    if shared_evidence_id:
        first = _evidence("ev-overlap", target=target)
        second = _evidence("ev-overlap", target=target)
        assert first == second
    else:
        first = _evidence("ev-overlap-a", target=target)
        second = _evidence("ev-overlap-b", target=target)
    buckets: dict[str, tuple[RoleFeature, ...]] = {
        bucket_a: (RoleFeature(signal=signal, evidence=first),),
        bucket_b: (RoleFeature(signal=signal, evidence=second),),
    }
    with pytest.raises(ValueError):
        RoleAssessment(
            target=target,
            role=InfrastructureRole.EDGE_CANDIDATE,
            eligible=False,
            **buckets,  # type: ignore[arg-type]
        )


def test_role_assessment_allows_shared_evidence_across_distinct_bucket_signals() -> None:
    # Bucket exclusivity constrains signals, not evidence: two DIFFERENT signals
    # living in different buckets may cite the exact same evidence id/payload
    # without raising. This is the legal control for the exclusivity rule.
    target = _entity()
    shared = _evidence("ev-shared-bucket", target=target)
    twin = _evidence("ev-shared-bucket", target=target)
    assert shared == twin
    assessment = RoleAssessment(
        target=target,
        role=InfrastructureRole.EDGE_CANDIDATE,
        eligible=True,
        matched_features=(
            RoleFeature(signal=RoleSignal.REDIRECT, evidence=shared),
        ),
        context_features=(
            RoleFeature(signal=RoleSignal.PUBLIC_CDN, evidence=twin),
        ),
    )
    assert assessment.matched_signals == (RoleSignal.REDIRECT,)
    assert assessment.context_signals == (RoleSignal.PUBLIC_CDN,)
    assert [item.id for item in assessment.matched_evidence] == ["ev-shared-bucket"]
    assert [item.id for item in assessment.context_evidence] == ["ev-shared-bucket"]


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
    assert [item.role for item in result] == [
        InfrastructureRole.EDGE_CANDIDATE,
        InfrastructureRole.CLOAKING_EDGE_NODE,  # redirect + cookie_challenge = 2 strong signals
    ]


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
        EvidenceScorer as ExportedScorer,
        InfrastructureRole as ExportedRole,
        MissingScoreEvidence as ExportedMissing,
        RoleAssessment as ExportedAssessment,
        RoleClassifier as ExportedClassifier,
        RoleFeature as ExportedFeature,
        RoleScore as ExportedRoleScore,
        RoleSignal as ExportedSignal,
        ScoreContribution as ExportedContribution,
    )
    from apkscan.attribution.scorer import (
        EvidenceScorer,
        MissingScoreEvidence,
        RoleScore,
        ScoreContribution,
    )

    assert ExportedRole is InfrastructureRole
    assert ExportedAssessment is RoleAssessment
    assert ExportedClassifier is RoleClassifier
    assert ExportedFeature is RoleFeature
    assert ExportedSignal is RoleSignal
    assert ExportedScorer is EvidenceScorer
    assert ExportedMissing is MissingScoreEvidence
    assert ExportedRoleScore is RoleScore
    assert ExportedContribution is ScoreContribution

    # PR7 additively extends the attribution exports with the graph value model;
    # the sorted-__all__ determinism invariant is preserved, never weakened.
    assert attribution.__all__ == [
        "AttributionEvidence",
        "EvidenceScorer",
        "GraphEdge",
        "GraphIssue",
        "GraphNode",
        "GraphNodeType",
        "GraphRelation",
        "InfrastructureGraph",
        "InfrastructureRole",
        "MissingScoreEvidence",
        "RoleAssessment",
        "RoleClassifier",
        "RoleFeature",
        "RoleScore",
        "RoleSignal",
        "ScoreContribution",
        "build_infrastructure_graph",
    ]
