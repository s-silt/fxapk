"""Strict canonical JSON primitives for recognition records and events."""

from __future__ import annotations

import json
import hashlib
import hmac
import types
import unicodedata
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import StrEnum
from typing import Any, Literal, NoReturn, TypeVar, Union, cast, get_args, get_origin, get_type_hints

from apkscan.core import recognition_contract as rc

from apkscan.core.recognition_contract import (
    Actor,
    CanonicalCodecError,
    DomainRecord,
    IdentityMismatchError,
    SchemaValidationError,
    validate_contract_value,
)

_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_FORBIDDEN_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})


def _fail(code: str, path: str = "$") -> NoReturn:
    raise CanonicalCodecError(code, field_path=path)


def _validate_string(value: str, path: str) -> None:
    if unicodedata.normalize("NFC", value) != value:
        _fail("non_nfc_string", path)
    if any(unicodedata.category(char) in _FORBIDDEN_UNICODE_CATEGORIES for char in value):
        _fail("forbidden_unicode_category", path)


def _validate_json_value(value: object, path: str = "$", *, allow_float: bool = False) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _validate_string(value, path)
        return
    if isinstance(value, int):
        if not _INT64_MIN <= value <= _INT64_MAX:
            _fail("integer_out_of_range", path)
        return
    if isinstance(value, float):
        if allow_float:
            return
        _fail("float_forbidden", path)
    if isinstance(value, list | tuple):
        for item in value:
            _validate_json_value(item, f"{path}[]", allow_float=allow_float)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("non_string_json_key", path)
            _validate_string(key, f"{path}.*")
            _validate_json_value(item, f"{path}.*", allow_float=allow_float)
        return
    _fail("unsupported_json_type", path)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_json_key")
        result[key] = value
    return result


def _reject_float(_value: str) -> NoReturn:
    _fail("float_forbidden")


def _reject_constant(_value: str) -> NoReturn:
    _fail("non_finite_json")


def canonical_json_v1(value: object) -> bytes:
    """Return the one supported UTF-8 JSON representation for a strict value."""
    _validate_json_value(value)
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (RecursionError, TypeError, ValueError, OverflowError) as exc:
        raise CanonicalCodecError("invalid_json_value") from exc
    return rendered.encode("utf-8")


def parse_json_v1(text: str) -> object:
    """Parse strict JSON while rejecting ambiguous or non-canonical domain values."""
    if not isinstance(text, str):
        _fail("json_text_required")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalCodecError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError) as exc:
        raise CanonicalCodecError("invalid_json") from exc
    _validate_json_value(value)
    return value


def _to_json_value(value: object) -> object:
    """Project a dataclass tree onto strict JSON-compatible primitives."""
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _to_json_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple | list):
        return [_to_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {key: _to_json_value(item) for key, item in value.items()}
    return value


def _require_object(value: object, path: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SchemaValidationError("object_required", field_path=path)
    return cast(dict[str, object], value)


def _exact_fields(value: Mapping[str, object], expected: set[str], path: str) -> None:
    if set(value) != expected:
        raise SchemaValidationError("record_fields_mismatch", field_path=path)


def _require_string(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise SchemaValidationError("string_required", field_path=path)
    return value


def _decode_actor(value: object, path: str) -> Actor:
    actor = _decode_dataclass(value, Actor, path)
    validate_contract_value(actor, field_path=path)
    return actor


_T = TypeVar("_T")


def _decode_typed(value: object, expected: object, path: str) -> object:
    origin = get_origin(expected)
    arguments = get_args(expected)
    if origin is Literal:
        if value not in arguments:
            raise SchemaValidationError("literal_value_mismatch", field_path=path)
        return value
    if origin is tuple:
        if not isinstance(value, list) or len(arguments) != 2 or arguments[1] is not Ellipsis:
            raise SchemaValidationError("array_required", field_path=path)
        return tuple(
            _decode_typed(item, arguments[0], f"{path}[{index}]")
            for index, item in enumerate(value)
        )
    if origin in {types.UnionType, Union}:
        if value is None and type(None) in arguments:
            return None
        candidates = tuple(item for item in arguments if item is not type(None))
        if len(candidates) != 1:
            raise SchemaValidationError("unsupported_union_schema", field_path=path)
        return _decode_typed(value, candidates[0], path)
    if expected is str:
        return _require_string(value, path)
    if expected is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SchemaValidationError("integer_required", field_path=path)
        return value
    if expected is bool:
        if not isinstance(value, bool):
            raise SchemaValidationError("boolean_required", field_path=path)
        return value
    if isinstance(expected, type) and issubclass(expected, StrEnum):
        raw = _require_string(value, path)
        try:
            return expected(raw)
        except ValueError as exc:
            raise SchemaValidationError("enum_value_required", field_path=path) from exc
    if isinstance(expected, type) and is_dataclass(expected):
        return _decode_dataclass(value, expected, path)
    raise SchemaValidationError("unsupported_field_schema", field_path=path)


def _decode_dataclass(value: object, expected: type[_T], path: str) -> _T:
    payload = _require_object(value, path)
    dataclass_type = cast(Any, expected)
    expected_fields = {field.name for field in fields(dataclass_type)}
    _exact_fields(payload, expected_fields, path)
    hints = get_type_hints(expected)
    decoded = {
        field.name: _decode_typed(payload[field.name], hints[field.name], f"{path}.{field.name}")
        for field in fields(dataclass_type)
    }
    try:
        return expected(**decoded)
    except TypeError as exc:
        raise SchemaValidationError("record_construction_failed", field_path=path) from exc


def _as_object(value: object) -> dict[str, object]:
    return _require_object(_to_json_value(value), "$")


def domain_hash(domain: str, body: Mapping[str, object]) -> str:
    """Hash a canonical body with an explicit domain separator."""
    payload = domain.encode("utf-8") + b"\0" + canonical_json_v1(body)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


_ID_DOMAINS = {
    "question": ("question-", "fxapk:question:v1"),
    "observation": ("observation-", "fxapk:observation:v1"),
    "claim_candidate": ("claim-", "fxapk:claim-candidate:v1"),
    "evidence_gap": ("gap-", "fxapk:evidence-gap:v1"),
    "next_action": ("action-", "fxapk:next-action:v1"),
    "action_outcome": ("outcome-", "fxapk:action-outcome:v1"),
    "review_decision": ("decision-", "fxapk:review-decision:v1"),
    "candidate_label_feedback": ("feedback-", "fxapk:candidate-label-feedback:v1"),
    "evidence_anchor": ("anchor-", "fxapk:evidence-anchor:v1"),
}


def semantic_id(record_type: str, body: Mapping[str, object]) -> str:
    try:
        prefix, domain = _ID_DOMAINS[record_type]
    except KeyError as exc:
        raise SchemaValidationError("unknown_identity_domain") from exc
    return prefix + domain_hash(domain, body)


def compute_reuse_key(
    *,
    purpose: str,
    subjects: tuple[rc.SubjectRef, ...],
    input_anchors: tuple[rc.EvidenceAnchor, ...],
    initial_coverage: tuple[rc.CoverageAssertion, ...],
    policies: tuple[rc.PolicyRef, ...],
    producers: tuple[rc.ProducerRef, ...],
) -> str:
    body = {
        "purpose": purpose,
        "subjects": _to_json_value(subjects),
        "input_anchors": _to_json_value(input_anchors),
        "initial_coverage": _to_json_value(initial_coverage),
        "policies": _to_json_value(policies),
        "producers": _to_json_value(producers),
    }
    return domain_hash("fxapk:reasoning-reuse:v1", body)


def compute_run_id(reuse_key: str, execution_nonce: str) -> str:
    body = {"reuse_key": reuse_key, "execution_nonce": execution_nonce}
    return "run-" + domain_hash("fxapk:reasoning-run-occurrence:v1", body)


def compute_ledger_id(run_id: str) -> str:
    return "ledger-" + domain_hash("fxapk:judgment-ledger:v1", {"run_id": run_id})


def compute_coverage_context_digest(
    assertions: tuple[rc.CoverageAssertion, ...],
) -> str:
    rc.validate_coverage_collection(assertions, field_path="$.assertions")
    return domain_hash(
        "fxapk:coverage-context:v1",
        {"assertions": _to_json_value(assertions)},
    )


def compute_action_dedupe_key(
    *,
    action_type: str,
    subjects: tuple[rc.SubjectRef, ...],
    input_anchor_ids: tuple[str, ...],
    parameters_digest: str,
    authorization_required: rc.AuthorizationLevel,
    budget: rc.ActionBudget,
    success_criteria: tuple[str, ...],
    negative_valid_only_if: tuple[rc.CoveragePredicate, ...],
    producer: rc.ProducerRef,
) -> str:
    body = {
        "action_type": action_type,
        "subjects": _to_json_value(subjects),
        "input_anchor_ids": _to_json_value(input_anchor_ids),
        "parameters_digest": parameters_digest,
        "authorization_required": authorization_required.value,
        "budget": _to_json_value(budget),
        "success_criteria": _to_json_value(success_criteria),
        "negative_valid_only_if": _to_json_value(negative_valid_only_if),
        "producer": _to_json_value(producer),
    }
    return domain_hash("fxapk:next-action-dedupe:v1", body)


def build_evidence_anchor(
    *,
    anchor_type: rc.EvidenceAnchorType,
    content_digest: str,
    logical_id: str | None,
    schema_version_ref: str | None,
) -> rc.EvidenceAnchor:
    body = {
        "anchor_type": anchor_type.value,
        "content_digest": content_digest,
        "logical_id": logical_id,
        "schema_version_ref": schema_version_ref,
    }
    value = rc.EvidenceAnchor(
        anchor_id=semantic_id("evidence_anchor", body),
        anchor_type=anchor_type,
        content_digest=content_digest,
        logical_id=logical_id,
        schema_version_ref=schema_version_ref,
    )
    rc.validate_contract_value(value)
    return value


def build_reasoning_run(
    *,
    execution_nonce: str,
    purpose: str,
    subjects: tuple[rc.SubjectRef, ...],
    input_anchors: tuple[rc.EvidenceAnchor, ...],
    initial_coverage: tuple[rc.CoverageAssertion, ...],
    policies: tuple[rc.PolicyRef, ...],
    producers: tuple[rc.ProducerRef, ...],
) -> rc.ReasoningRun:
    reuse_key = compute_reuse_key(
        purpose=purpose,
        subjects=subjects,
        input_anchors=input_anchors,
        initial_coverage=initial_coverage,
        policies=policies,
        producers=producers,
    )
    value = rc.ReasoningRun(
        kind="reasoning_run",
        schema_version="1.0",
        run_id=compute_run_id(reuse_key, execution_nonce),
        execution_nonce=execution_nonce,
        reuse_key=reuse_key,
        purpose=purpose,
        subjects=subjects,
        input_anchors=input_anchors,
        initial_coverage=initial_coverage,
        policies=policies,
        producers=producers,
    )
    rc.validate_contract_value(value)
    return value


def _seal_entity(record_type: str, identity_field: str, body: dict[str, object]) -> str:
    if identity_field in body:
        raise SchemaValidationError("identity_field_in_body", field_path=f"$.{identity_field}")
    return semantic_id(record_type, body)


def build_question(
    *,
    question_type: rc.QuestionType,
    subjects: tuple[rc.SubjectRef, ...],
    allowed_conclusions: tuple[rc.AllowedConclusion, ...],
) -> rc.Question:
    body = {
        "kind": "question",
        "schema_version": "1.0",
        "question_type": question_type.value,
        "subjects": _to_json_value(subjects),
        "allowed_conclusions": _to_json_value(allowed_conclusions),
    }
    value = rc.Question(
        kind="question",
        schema_version="1.0",
        question_id=_seal_entity("question", "question_id", body),
        question_type=question_type,
        subjects=subjects,
        allowed_conclusions=allowed_conclusions,
    )
    rc.validate_contract_value(value)
    return value


def build_observation(
    *,
    observation_type: str,
    subjects: tuple[rc.SubjectRef, ...],
    value: rc.ObservationValue,
    source_refs: tuple[rc.EvidenceLocator, ...],
    scope: rc.EvidenceScope,
    strength: rc.ObservationStrength,
    input_observation_ids: tuple[str, ...],
    origin_outcome_id: str | None,
    producer: rc.ProducerRef,
    ownership: rc.OwnershipValue,
    coverage_assertions: tuple[rc.CoverageAssertion, ...],
) -> rc.Observation:
    body = {
        "kind": "observation",
        "schema_version": "1.0",
        "observation_type": observation_type,
        "subjects": _to_json_value(subjects),
        "value": _to_json_value(value),
        "source_refs": _to_json_value(source_refs),
        "scope": scope.value,
        "strength": strength.value,
        "input_observation_ids": _to_json_value(input_observation_ids),
        "origin_outcome_id": origin_outcome_id,
        "producer": _to_json_value(producer),
        "ownership": ownership.value,
        "coverage_assertions": _to_json_value(coverage_assertions),
    }
    record = rc.Observation(
        kind="observation",
        schema_version="1.0",
        observation_id=_seal_entity("observation", "observation_id", body),
        observation_type=observation_type,
        subjects=subjects,
        value=value,
        source_refs=source_refs,
        scope=scope,
        strength=strength,
        input_observation_ids=input_observation_ids,
        origin_outcome_id=origin_outcome_id,
        producer=producer,
        ownership=ownership,
        coverage_assertions=coverage_assertions,
    )
    rc.validate_contract_value(record)
    return record


def build_claim_candidate(
    *,
    question_id: str,
    task: rc.ClaimTask,
    claim_mode: rc.ClaimMode,
    subjects: tuple[rc.SubjectRef, ...],
    predicate: str,
    object_value: rc.ObservationValue | None,
    supporting_observation_ids: tuple[str, ...],
    contradicting_observation_ids: tuple[str, ...],
    excluded_observations: tuple[rc.ExcludedObservation, ...],
    coverage_requirements: tuple[rc.CoveragePredicate, ...],
    coverage_context_digest: str,
    ownership: tuple[rc.SubjectOwnership, ...],
    caps: tuple[str, ...],
    unknowns: tuple[str, ...],
    resolves_gap_ids: tuple[str, ...],
    producer: rc.ProducerRef,
    supersedes: str | None,
    score: rc.RankingScore | None,
) -> rc.ClaimCandidate:
    kwargs: dict[str, object] = {
        "kind": "claim_candidate",
        "schema_version": "1.0",
        "question_id": question_id,
        "task": task,
        "claim_mode": claim_mode,
        "subjects": subjects,
        "predicate": predicate,
        "object_value": object_value,
        "supporting_observation_ids": supporting_observation_ids,
        "contradicting_observation_ids": contradicting_observation_ids,
        "excluded_observations": excluded_observations,
        "coverage_requirements": coverage_requirements,
        "coverage_context_digest": coverage_context_digest,
        "ownership": ownership,
        "caps": caps,
        "unknowns": unknowns,
        "resolves_gap_ids": resolves_gap_ids,
        "producer": producer,
        "supersedes": supersedes,
        "score": score,
    }
    body = cast(dict[str, object], _to_json_value(kwargs))
    record = rc.ClaimCandidate(
        claim_id=_seal_entity("claim_candidate", "claim_id", body),
        **kwargs,  # type: ignore[arg-type]
    )
    rc.validate_contract_value(record)
    return record


def build_evidence_gap(
    *,
    question_id: str,
    claim_id: str | None,
    effect: rc.GapEffect,
    reason_codes: tuple[str, ...],
    required_observation_types: tuple[str, ...],
    coverage_requirements: tuple[rc.CoveragePredicate, ...],
    producer: rc.ProducerRef,
) -> rc.EvidenceGap:
    body = {
        "kind": "evidence_gap",
        "schema_version": "1.0",
        "question_id": question_id,
        "claim_id": claim_id,
        "effect": effect.value,
        "reason_codes": _to_json_value(reason_codes),
        "required_observation_types": _to_json_value(required_observation_types),
        "coverage_requirements": _to_json_value(coverage_requirements),
        "producer": _to_json_value(producer),
    }
    record = rc.EvidenceGap(
        kind="evidence_gap",
        schema_version="1.0",
        gap_id=_seal_entity("evidence_gap", "gap_id", body),
        question_id=question_id,
        claim_id=claim_id,
        effect=effect,
        reason_codes=reason_codes,
        required_observation_types=required_observation_types,
        coverage_requirements=coverage_requirements,
        producer=producer,
    )
    rc.validate_contract_value(record)
    return record


def build_next_action(
    *,
    question_id: str,
    gap_ids: tuple[str, ...],
    attempt_nonce: str,
    action_type: str,
    subjects: tuple[rc.SubjectRef, ...],
    input_anchor_ids: tuple[str, ...],
    parameters_digest: str,
    authorization_required: rc.AuthorizationLevel,
    budget: rc.ActionBudget,
    success_criteria: tuple[str, ...],
    negative_valid_only_if: tuple[rc.CoveragePredicate, ...],
    producer: rc.ProducerRef,
) -> rc.NextAction:
    dedupe_key = compute_action_dedupe_key(
        action_type=action_type,
        subjects=subjects,
        input_anchor_ids=input_anchor_ids,
        parameters_digest=parameters_digest,
        authorization_required=authorization_required,
        budget=budget,
        success_criteria=success_criteria,
        negative_valid_only_if=negative_valid_only_if,
        producer=producer,
    )
    body = {
        "kind": "next_action",
        "schema_version": "1.0",
        "question_id": question_id,
        "gap_ids": _to_json_value(gap_ids),
        "attempt_nonce": attempt_nonce,
        "action_type": action_type,
        "subjects": _to_json_value(subjects),
        "input_anchor_ids": _to_json_value(input_anchor_ids),
        "parameters_digest": parameters_digest,
        "authorization_required": authorization_required.value,
        "budget": _to_json_value(budget),
        "success_criteria": _to_json_value(success_criteria),
        "negative_valid_only_if": _to_json_value(negative_valid_only_if),
        "dedupe_key": dedupe_key,
        "producer": _to_json_value(producer),
    }
    record = rc.NextAction(
        kind="next_action",
        schema_version="1.0",
        action_id=_seal_entity("next_action", "action_id", body),
        question_id=question_id,
        gap_ids=gap_ids,
        attempt_nonce=attempt_nonce,
        action_type=action_type,
        subjects=subjects,
        input_anchor_ids=input_anchor_ids,
        parameters_digest=parameters_digest,
        authorization_required=authorization_required,
        budget=budget,
        success_criteria=success_criteria,
        negative_valid_only_if=negative_valid_only_if,
        dedupe_key=dedupe_key,
        producer=producer,
    )
    rc.validate_contract_value(record)
    return record


def build_candidate_label_feedback(
    *,
    label_kind: rc.LabelKind,
    proposed_label_digest: str,
    subject_refs: tuple[rc.SubjectRef, ...],
    evidence_ref: str | None,
    reason_codes: tuple[str, ...],
    policy: rc.PolicyRef,
    producer: rc.ProducerRef,
) -> rc.CandidateLabelFeedback:
    body = {
        "kind": "candidate_label_feedback",
        "schema_version": "1.0",
        "label_kind": label_kind.value,
        "proposed_label_digest": proposed_label_digest,
        "subject_refs": _to_json_value(subject_refs),
        "evidence_ref": evidence_ref,
        "reason_codes": _to_json_value(reason_codes),
        "policy": _to_json_value(policy),
        "producer": _to_json_value(producer),
    }
    record = rc.CandidateLabelFeedback(
        kind="candidate_label_feedback",
        schema_version="1.0",
        feedback_id=_seal_entity("candidate_label_feedback", "feedback_id", body),
        label_kind=label_kind,
        proposed_label_digest=proposed_label_digest,
        subject_refs=subject_refs,
        evidence_ref=evidence_ref,
        reason_codes=reason_codes,
        policy=policy,
        producer=producer,
    )
    rc.validate_contract_value(record)
    return record


def build_action_outcome(
    *,
    action_id: str,
    status: rc.OutcomeStatus,
    output_anchors: tuple[rc.EvidenceAnchor, ...],
    coverage_assertions: tuple[rc.CoverageAssertion, ...],
    reason_codes: tuple[str, ...],
    diagnostics_locator: rc.EvidenceLocator | None,
    usage: rc.ActionUsage,
    producer: rc.ProducerRef,
) -> rc.ActionOutcome:
    body = {
        "kind": "action_outcome",
        "schema_version": "1.0",
        "action_id": action_id,
        "status": status.value,
        "output_anchors": _to_json_value(output_anchors),
        "coverage_assertions": _to_json_value(coverage_assertions),
        "reason_codes": _to_json_value(reason_codes),
        "diagnostics_locator": _to_json_value(diagnostics_locator),
        "usage": _to_json_value(usage),
        "producer": _to_json_value(producer),
    }
    record = rc.ActionOutcome(
        kind="action_outcome",
        schema_version="1.0",
        outcome_id=_seal_entity("action_outcome", "outcome_id", body),
        action_id=action_id,
        status=status,
        output_anchors=output_anchors,
        coverage_assertions=coverage_assertions,
        reason_codes=reason_codes,
        diagnostics_locator=diagnostics_locator,
        usage=usage,
        producer=producer,
    )
    rc.validate_contract_value(record)
    return record


def build_review_decision(
    *,
    question_id: str,
    claim_id: str,
    decision: rc.ReviewDecisionValue,
    reviewer: rc.Actor,
    basis_head_digest: str,
    basis_observation_ids: tuple[str, ...],
    gap_ids: tuple[str, ...],
    reason_codes: tuple[str, ...],
) -> rc.ReviewDecision:
    body = {
        "kind": "review_decision",
        "schema_version": "1.0",
        "question_id": question_id,
        "claim_id": claim_id,
        "decision": decision.value,
        "reviewer": _to_json_value(reviewer),
        "basis_head_digest": basis_head_digest,
        "basis_observation_ids": _to_json_value(basis_observation_ids),
        "gap_ids": _to_json_value(gap_ids),
        "reason_codes": _to_json_value(reason_codes),
    }
    record = rc.ReviewDecision(
        kind="review_decision",
        schema_version="1.0",
        decision_id=_seal_entity("review_decision", "decision_id", body),
        question_id=question_id,
        claim_id=claim_id,
        decision=decision,
        reviewer=reviewer,
        basis_head_digest=basis_head_digest,
        basis_observation_ids=basis_observation_ids,
        gap_ids=gap_ids,
        reason_codes=reason_codes,
    )
    rc.validate_contract_value(record)
    return record


_RECORD_CLASSES: dict[str, type[DomainRecord]] = {
    "reasoning_run": rc.ReasoningRun,
    "question": rc.Question,
    "observation": rc.Observation,
    "claim_candidate": rc.ClaimCandidate,
    "evidence_gap": rc.EvidenceGap,
    "next_action": rc.NextAction,
    "action_outcome": rc.ActionOutcome,
    "review_decision": rc.ReviewDecision,
    "candidate_label_feedback": rc.CandidateLabelFeedback,
}

_IDENTITY_FIELDS = {
    "question": ("question_id", "question"),
    "observation": ("observation_id", "observation"),
    "claim_candidate": ("claim_id", "claim_candidate"),
    "evidence_gap": ("gap_id", "evidence_gap"),
    "next_action": ("action_id", "next_action"),
    "action_outcome": ("outcome_id", "action_outcome"),
    "review_decision": ("decision_id", "review_decision"),
    "candidate_label_feedback": ("feedback_id", "candidate_label_feedback"),
}


def verify_evidence_anchor_identity(anchor: rc.EvidenceAnchor) -> None:
    rc.validate_contract_value(anchor)
    body = {
        "anchor_type": anchor.anchor_type.value,
        "content_digest": anchor.content_digest,
        "logical_id": anchor.logical_id,
        "schema_version_ref": anchor.schema_version_ref,
    }
    expected = semantic_id("evidence_anchor", body)
    if not hmac.compare_digest(anchor.anchor_id, expected):
        raise IdentityMismatchError("record_identity_mismatch", field_path="$.anchor_id")


def verify_record_identity(record: DomainRecord) -> None:
    rc.validate_contract_value(record)
    if type(record) is rc.ReasoningRun:
        record = cast(rc.ReasoningRun, record)
        for anchor in record.input_anchors:
            verify_evidence_anchor_identity(anchor)
        expected_reuse = compute_reuse_key(
            purpose=record.purpose,
            subjects=record.subjects,
            input_anchors=record.input_anchors,
            initial_coverage=record.initial_coverage,
            policies=record.policies,
            producers=record.producers,
        )
        expected_run = compute_run_id(expected_reuse, record.execution_nonce)
        if not hmac.compare_digest(record.reuse_key, expected_reuse) or not hmac.compare_digest(
            record.run_id, expected_run
        ):
            raise IdentityMismatchError("record_identity_mismatch")
        return
    data = _as_object(record)
    identity_field, record_type = _IDENTITY_FIELDS[record.kind]
    actual = cast(str, data.pop(identity_field))
    expected = semantic_id(record_type, data)
    if not hmac.compare_digest(actual, expected):
        raise IdentityMismatchError("record_identity_mismatch", field_path=f"$.{identity_field}")
    if isinstance(record, rc.ActionOutcome):
        for anchor in record.output_anchors:
            verify_evidence_anchor_identity(anchor)
    if isinstance(record, rc.NextAction):
        expected_dedupe = compute_action_dedupe_key(
            action_type=record.action_type,
            subjects=record.subjects,
            input_anchor_ids=record.input_anchor_ids,
            parameters_digest=record.parameters_digest,
            authorization_required=record.authorization_required,
            budget=record.budget,
            success_criteria=record.success_criteria,
            negative_valid_only_if=record.negative_valid_only_if,
            producer=record.producer,
        )
        if not hmac.compare_digest(record.dedupe_key, expected_dedupe):
            raise IdentityMismatchError("action_dedupe_mismatch", field_path="$.dedupe_key")


def encode_record(record: DomainRecord) -> str:
    verify_record_identity(record)
    return canonical_json_v1(_to_json_value(record)).decode("utf-8")


def decode_record(text: str) -> DomainRecord:
    payload = _require_object(parse_json_v1(text), "$")
    kind = payload.get("kind")
    if not isinstance(kind, str) or kind not in _RECORD_CLASSES:
        raise SchemaValidationError("unknown_record_kind", field_path="$.kind")
    record = _decode_dataclass(payload, _RECORD_CLASSES[kind], "$")
    verify_record_identity(record)
    return record


__all__ = [
    "build_action_outcome",
    "build_candidate_label_feedback",
    "build_claim_candidate",
    "build_evidence_anchor",
    "build_evidence_gap",
    "build_next_action",
    "build_observation",
    "build_question",
    "build_reasoning_run",
    "build_review_decision",
    "canonical_json_v1",
    "compute_action_dedupe_key",
    "compute_coverage_context_digest",
    "compute_ledger_id",
    "compute_reuse_key",
    "compute_run_id",
    "decode_record",
    "domain_hash",
    "encode_record",
    "parse_json_v1",
    "semantic_id",
    "verify_record_identity",
    "verify_evidence_anchor_identity",
]
