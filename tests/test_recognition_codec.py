"""Strict canonical JSON primitives for the recognition contract."""

from __future__ import annotations

import random
from dataclasses import dataclass, replace
from typing import cast

import pytest

from apkscan.core import recognition_codec
from apkscan.core.recognition_codec import canonical_json_v1, parse_json_v1
from apkscan.core.recognition_contract import (
    ActionAuthorization,
    AuthorizationLevel,
    CanonicalCodecError,
    CoveragePredicate,
    CoverageSource,
    CoverageStatus,
    EvidenceAnchor,
    EvidenceLocator,
    DomainRecord,
    IdentityMismatchError,
    LocatorKind,
    ObservationValue,
    ObservationValueKind,
    SchemaValidationError,
    Observation,
    ObservationStrength,
    ProducerKind,
    Question,
    SubjectKind,
    SubjectRef,
    validate_contract_value,
    validate_coverage_collection,
)
from apkscan.core.recognition_codec import (
    build_action_outcome,
    build_evidence_gap,
    build_observation,
    build_reasoning_run,
    compute_ledger_id,
    decode_record,
    encode_record,
    semantic_id,
    verify_record_identity,
)
from tests.recognition_fixtures import (
    ACTION_ID,
    SUBJECT,
    make_actor,
    make_anchor,
    make_coverage,
    make_claim_candidate,
    make_action,
    make_locator,
    make_gap,
    make_observation,
    make_outcome,
    make_policy,
    make_producer,
    make_question,
    make_reasoning_run,
    make_review_decision,
)


def test_canonical_json_v1_has_one_exact_utf8_form() -> None:
    assert canonical_json_v1({"z": 1, "a": "中文"}) == (
        b'{"a":"\xe4\xb8\xad\xe6\x96\x87","z":1}'
    )


def test_parse_json_v1_accepts_strict_json_values() -> None:
    assert parse_json_v1('{"items":[true,null,-7],"name":"valid"}') == {
        "items": [True, None, -7],
        "name": "valid",
    }


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ('{"a":1,"a":2}', "duplicate_json_key"),
        ('{"a":NaN}', "non_finite_json"),
        ('{"a":1.5}', "float_forbidden"),
        ('{"a":9223372036854775808}', "integer_out_of_range"),
        ('{"a":"e\\u0301"}', "non_nfc_string"),
        ('{"a":"x\\u0000y"}', "forbidden_unicode_category"),
    ],
)
def test_parse_json_v1_rejects_noncanonical_domain_values(raw: str, code: str) -> None:
    with pytest.raises(CanonicalCodecError) as caught:
        parse_json_v1(raw)

    assert caught.value.code == code
    assert caught.value.field_path.startswith("$")
    assert raw not in str(caught.value)


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ({"a": 2**63}, "integer_out_of_range"),
        ({"a": 1.5}, "float_forbidden"),
        ({"e\u0301": "value"}, "non_nfc_string"),
        ({"a": "x\u200by"}, "forbidden_unicode_category"),
    ],
)
def test_canonical_json_v1_rejects_invalid_python_values(value: object, code: str) -> None:
    with pytest.raises(CanonicalCodecError) as caught:
        canonical_json_v1(value)

    assert caught.value.code == code


def test_codec_error_does_not_echo_rejected_value() -> None:
    secret = "private-backend-credential-fixture"

    with pytest.raises(CanonicalCodecError) as caught:
        canonical_json_v1({"secret": f"{secret}\u0000"})

    assert secret not in str(caught.value)


def test_actor_kind_is_a_business_enum_not_a_record_discriminator() -> None:
    assert cast(dict[str, object], recognition_codec._to_json_value(make_actor())) == {
        "kind": "system",
        "actor_id": "fxapk-test",
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "system", "actor_id": "fxapk-test", "schema_version": "1.0"},
        {"kind": "actor", "actor_id": "fxapk-test"},
        {"kind": "system", "actor_kind": "system", "actor_id": "fxapk-test"},
    ],
)
def test_actor_decoder_rejects_record_discriminator_shape(payload: object) -> None:
    with pytest.raises(SchemaValidationError):
        recognition_codec._decode_actor(payload, "$.actor")


def test_nullable_anchor_fields_encode_as_explicit_null() -> None:
    anchor = make_anchor(logical_id=None, schema_version_ref=None)
    validate_contract_value(anchor)

    data = cast(dict[str, object], recognition_codec._to_json_value(anchor))

    assert data["logical_id"] is None
    assert data["schema_version_ref"] is None
    assert canonical_json_v1(data).startswith(b'{"anchor_id":')


@pytest.mark.parametrize(
    "locator",
    [
        make_locator(kind=LocatorKind.WHOLE, value="unexpected"),
        make_locator(kind=LocatorKind.BYTE_RANGE, value="classes.dex", start=None, end=7),
        make_locator(kind=LocatorKind.LINE_RANGE, value="Main.java", start=9, end=3),
        make_locator(kind=LocatorKind.SYMBOL, value="method", start=1, end=2),
    ],
)
def test_locator_cross_field_rules_fail_closed(locator: EvidenceLocator) -> None:
    with pytest.raises(SchemaValidationError):
        validate_contract_value(locator)


def test_whole_locator_requires_empty_value_and_no_range() -> None:
    locator = make_locator(kind=LocatorKind.WHOLE, value="", start=None, end=None)
    validate_contract_value(locator)


def test_duplicate_coverage_key_is_rejected() -> None:
    coverage = make_coverage()

    with pytest.raises(SchemaValidationError) as caught:
        validate_coverage_collection((coverage, coverage), field_path="$.initial_coverage")

    assert caught.value.code == "duplicate_coverage_key"


def test_coverage_predicate_requires_canonical_unique_statuses() -> None:
    predicate = CoveragePredicate(
        subject=SUBJECT,
        source=CoverageSource.JAVA,
        allowed_statuses=(CoverageStatus.PARTIAL, CoverageStatus.COMPLETE),
    )

    with pytest.raises(SchemaValidationError) as caught:
        validate_contract_value(predicate)

    assert caught.value.code == "non_canonical_tuple"


@pytest.mark.parametrize(
    "value",
    [
        ObservationValue(
            kind=ObservationValueKind.CATEGORICAL,
            categorical="family-a",
            integer=1,
            boolean=None,
            reference=None,
        ),
        ObservationValue(
            kind=ObservationValueKind.REFERENCE,
            categorical=None,
            integer=None,
            boolean=None,
            reference=None,
        ),
    ],
)
def test_observation_value_requires_exactly_its_kind_field(value: ObservationValue) -> None:
    with pytest.raises(SchemaValidationError) as caught:
        validate_contract_value(value)

    assert caught.value.code == "observation_value_shape"


def test_subject_and_producer_validate_exact_tokens() -> None:
    validate_contract_value(SUBJECT)
    validate_contract_value(make_producer())

    invalid = SubjectRef(kind=SubjectKind.ENDPOINT, value="", role=None)
    with pytest.raises(SchemaValidationError) as caught:
        validate_contract_value(invalid)
    assert caught.value.code == "nonempty_string_required"


def test_action_authorization_keeps_its_payload_discriminator() -> None:
    authorization = ActionAuthorization(
        kind="action_authorization",
        schema_version="1.0",
        action_id=ACTION_ID,
        granted_level=AuthorizationLevel.OFFLINE,
        policy=make_policy(),
        reason_codes=("policy_pre_authorized",),
    )

    validate_contract_value(authorization)
    data = cast(dict[str, object], recognition_codec._to_json_value(authorization))
    assert data["kind"] == "action_authorization"


def test_record_ids_are_domain_separated_and_semantic() -> None:
    body = {"kind": "fixture", "schema_version": "1.0", "value": "same"}

    question_id = semantic_id("question", body)
    observation_id = semantic_id("observation", body)

    assert question_id.startswith("question-sha256:")
    assert observation_id.startswith("observation-sha256:")
    assert question_id != observation_id


def test_reuse_run_and_ledger_identity_boundaries() -> None:
    first = make_reasoning_run(execution_nonce="1" * 32)
    second = make_reasoning_run(execution_nonce="2" * 32)

    assert first.reuse_key == second.reuse_key
    assert first.run_id != second.run_id
    assert compute_ledger_id(first.run_id) != compute_ledger_id(second.run_id)


def test_action_attempt_nonce_changes_id_not_dedupe_key() -> None:
    first = make_action(attempt_nonce="2" * 32)
    second = make_action(attempt_nonce="3" * 32)

    assert first.action_id != second.action_id
    assert first.dedupe_key == second.dedupe_key


@pytest.mark.parametrize(
    "record",
    [
        make_reasoning_run(),
        make_question(),
        make_observation(),
        make_claim_candidate(),
        make_gap(),
        make_action(),
        make_outcome(),
        make_review_decision(),
    ],
)
def test_domain_records_round_trip_with_exact_identity(record: DomainRecord) -> None:
    assert decode_record(encode_record(record)) == record


def test_record_tampering_is_rejected() -> None:
    question = make_question()
    tampered = question.__class__(
        kind=question.kind,
        schema_version=question.schema_version,
        question_id=question.question_id,
        question_type=question.question_type,
        subjects=question.subjects,
        allowed_conclusions=(
            question.allowed_conclusions[0].__class__(
                predicate="different-predicate",
                claim_modes=question.allowed_conclusions[0].claim_modes,
                object_kind=question.allowed_conclusions[0].object_kind,
                allowed_categorical_values=question.allowed_conclusions[0].allowed_categorical_values,
            ),
        ),
    )

    with pytest.raises(Exception) as caught:
        verify_record_identity(tampered)

    assert getattr(caught.value, "code", None) == "record_identity_mismatch"


def test_observed_observation_rejects_input_observations() -> None:
    observed = make_observation()
    invalid = Observation(
        kind=observed.kind,
        schema_version=observed.schema_version,
        observation_id=observed.observation_id,
        observation_type=observed.observation_type,
        subjects=observed.subjects,
        value=observed.value,
        source_refs=observed.source_refs,
        scope=observed.scope,
        strength=ObservationStrength.OBSERVED,
        input_observation_ids=(observed.observation_id,),
        origin_outcome_id=observed.origin_outcome_id,
        producer=observed.producer,
        ownership=observed.ownership,
        coverage_assertions=observed.coverage_assertions,
    )

    with pytest.raises(SchemaValidationError) as caught:
        validate_contract_value(invalid)

    assert caught.value.code == "observation_derivation_shape"


def test_observation_rejects_model_producer() -> None:
    observed = make_observation()
    with pytest.raises(SchemaValidationError) as caught:
        build_observation(
            observation_type=observed.observation_type,
            subjects=observed.subjects,
            value=observed.value,
            source_refs=observed.source_refs,
            scope=observed.scope,
            strength=observed.strength,
            input_observation_ids=observed.input_observation_ids,
            origin_outcome_id=observed.origin_outcome_id,
            producer=make_producer(ProducerKind.MODEL),
            ownership=observed.ownership,
            coverage_assertions=observed.coverage_assertions,
        )

    assert caught.value.code == "producer_kind_forbidden"


def test_gap_requires_an_observation_or_coverage_requirement() -> None:
    gap = make_gap()

    with pytest.raises(SchemaValidationError) as caught:
        build_evidence_gap(
            question_id=gap.question_id,
            claim_id=gap.claim_id,
            effect=gap.effect,
            reason_codes=gap.reason_codes,
            required_observation_types=(),
            coverage_requirements=(),
            producer=gap.producer,
        )

    assert caught.value.code == "gap_requirement_required"


def test_decode_record_rejects_action_authorization_payload() -> None:
    authorization = ActionAuthorization(
        kind="action_authorization",
        schema_version="1.0",
        action_id=ACTION_ID,
        granted_level=AuthorizationLevel.OFFLINE,
        policy=make_policy(),
        reason_codes=("policy_pre_authorized",),
    )
    text = canonical_json_v1(recognition_codec._to_json_value(authorization)).decode("utf-8")

    with pytest.raises(SchemaValidationError) as caught:
        decode_record(text)

    assert caught.value.code == "unknown_record_kind"


def test_fixed_seed_canonical_primitive_round_trips_are_stable() -> None:
    rng = random.Random(20260816)
    values: list[object] = [None, True, False, 0, "fixture"]
    for index in range(100):
        values.append(
            {
                "flag": bool(rng.randrange(2)),
                "index": index,
                "items": [rng.randrange(-(2**31), 2**31), f"token-{rng.randrange(1000)}"],
            }
        )

    for value in values:
        encoded = canonical_json_v1(value)
        assert canonical_json_v1(parse_json_v1(encoded.decode("utf-8"))) == encoded


@pytest.mark.parametrize(
    "value",
    [
        r"C:\Users\fixture\report.json",
        "/home/fixture/report.json",
        r"\\server\share\report.json",
    ],
)
def test_locator_rejects_local_absolute_paths(value: str) -> None:
    locator = EvidenceLocator(
        anchor_id=make_anchor().anchor_id,
        kind=LocatorKind.LINE_RANGE,
        value=value,
        start=1,
        end=2,
    )

    with pytest.raises(SchemaValidationError) as caught:
        validate_contract_value(locator)

    assert caught.value.code == "absolute_locator_path_forbidden"


def test_nested_evidence_anchor_identity_is_verified_by_record_codec() -> None:
    anchor = make_anchor()
    forged = replace(anchor, anchor_id="anchor-sha256:" + "f" * 64)
    run = make_reasoning_run()
    forged_run = build_reasoning_run(
        execution_nonce=run.execution_nonce,
        purpose=run.purpose,
        subjects=run.subjects,
        input_anchors=(forged,),
        initial_coverage=run.initial_coverage,
        policies=run.policies,
        producers=run.producers,
    )
    outcome = make_outcome()
    forged_outcome = build_action_outcome(
        action_id=outcome.action_id,
        status=outcome.status,
        output_anchors=(forged,),
        coverage_assertions=outcome.coverage_assertions,
        reason_codes=outcome.reason_codes,
        diagnostics_locator=outcome.diagnostics_locator,
        usage=outcome.usage,
        producer=outcome.producer,
    )

    for record in (forged_run, forged_outcome):
        raw = canonical_json_v1(recognition_codec._to_json_value(record)).decode("utf-8")
        with pytest.raises(IdentityMismatchError):
            encode_record(record)
        with pytest.raises(IdentityMismatchError):
            decode_record(raw)


def test_coverage_predicate_keys_must_be_unique_within_parent() -> None:
    complete = CoveragePredicate(
        subject=SUBJECT,
        source=CoverageSource.JAVA,
        allowed_statuses=(CoverageStatus.COMPLETE,),
    )
    partial = CoveragePredicate(
        subject=SUBJECT,
        source=CoverageSource.JAVA,
        allowed_statuses=(CoverageStatus.PARTIAL,),
    )
    claim = replace(make_claim_candidate(), coverage_requirements=(complete, partial))
    gap = replace(make_gap(), coverage_requirements=(complete, partial))
    action = replace(make_action(), negative_valid_only_if=(complete, partial))

    for value in (claim, gap, action):
        with pytest.raises(SchemaValidationError) as caught:
            validate_contract_value(value)
        assert caught.value.code == "duplicate_coverage_predicate_key"


def test_malformed_tuple_item_uses_stable_contract_error() -> None:
    invalid = replace(make_question(), subjects=(object(),))

    with pytest.raises(SchemaValidationError) as caught:
        validate_contract_value(invalid)  # type: ignore[arg-type]

    assert caught.value.code == "invalid_canonical_tuple_item"


def test_record_codec_rejects_dataclass_subclasses() -> None:
    @dataclass(frozen=True, slots=True)
    class ExtendedQuestion(Question):
        pass

    question = make_question()
    extended = ExtendedQuestion(
        kind=question.kind,
        schema_version=question.schema_version,
        question_id=question.question_id,
        question_type=question.question_type,
        subjects=question.subjects,
        allowed_conclusions=question.allowed_conclusions,
    )

    with pytest.raises(SchemaValidationError) as caught:
        encode_record(extended)

    assert caught.value.code == "unsupported_contract_value"


def test_record_codec_rejects_nested_evidence_anchor_subclasses() -> None:
    @dataclass(frozen=True, slots=True)
    class ExtendedAnchor(EvidenceAnchor):
        pass

    anchor = make_anchor()
    extended = ExtendedAnchor(
        anchor_id=anchor.anchor_id,
        anchor_type=anchor.anchor_type,
        content_digest=anchor.content_digest,
        logical_id=anchor.logical_id,
        schema_version_ref=anchor.schema_version_ref,
    )
    run = replace(make_reasoning_run(), input_anchors=(extended,))

    with pytest.raises(SchemaValidationError) as caught:
        encode_record(run)

    assert caught.value.code == "tuple_item_type_mismatch"
    assert caught.value.field_path == "$.input_anchors[0]"


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (r"C:\Users\fixture\report.json", "absolute_locator_path_forbidden"),
        (r"\\server\share\report.json", "absolute_locator_path_forbidden"),
        ("file:///home/fixture/report.json", "absolute_locator_path_forbidden"),
        ("not/a/pointer", "invalid_json_pointer"),
        ("/invalid~2escape", "invalid_json_pointer"),
        ("/invalid~", "invalid_json_pointer"),
    ],
)
def test_json_pointer_rejects_paths_and_invalid_rfc6901_syntax(
    value: str,
    code: str,
) -> None:
    locator = EvidenceLocator(
        anchor_id=make_anchor().anchor_id,
        kind=LocatorKind.JSON_POINTER,
        value=value,
        start=None,
        end=None,
    )

    with pytest.raises(SchemaValidationError) as caught:
        validate_contract_value(locator)

    assert caught.value.code == code


def test_json_pointer_accepts_rfc6901_escapes() -> None:
    locator = EvidenceLocator(
        anchor_id=make_anchor().anchor_id,
        kind=LocatorKind.JSON_POINTER,
        value="/escaped~1slash/escaped~0tilde",
        start=None,
        end=None,
    )

    validate_contract_value(locator)


def test_malformed_direct_nested_field_uses_stable_contract_error() -> None:
    malformed = replace(make_observation(), producer=object())

    with pytest.raises(SchemaValidationError) as caught:
        encode_record(malformed)  # type: ignore[arg-type]

    assert caught.value.code == "nested_contract_type_mismatch"
    assert caught.value.field_path == "$.producer"
