"""Append-only judgment ledger event and hash-chain contracts."""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Literal, NoReturn, TypeAlias, TypeVar, cast

from apkscan.core import recognition_codec as codec
from apkscan.core import recognition_contract as rc
from apkscan.core.recognition_contract import (
    LedgerIntegrityError,
    ReferenceIntegrityError,
    ReplayTransitionError,
)


class EventType(StrEnum):
    RUN_OPENED = "run_opened"
    QUESTION_OPENED = "question_opened"
    OBSERVATION_ADDED = "observation_added"
    CLAIM_PROPOSED = "claim_proposed"
    GAP_IDENTIFIED = "gap_identified"
    ACTION_PROPOSED = "action_proposed"
    ACTION_AUTHORIZED = "action_authorized"
    ACTION_OUTCOME_RECORDED = "action_outcome_recorded"
    CLAIM_REVISED = "claim_revised"
    REVIEW_DECIDED = "review_decided"
    FEEDBACK_QUEUED = "feedback_queued"


class QuestionStatus(StrEnum):
    OPEN = "open"
    AWAITING_REVIEW = "awaiting_review"
    CHANGES_REQUESTED = "changes_requested"
    ACCEPTED = "accepted"
    UNKNOWN = "unknown"


class ClaimStatus(StrEnum):
    PROPOSED = "proposed"
    SUPERSEDED = "superseded"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    CHANGES_REQUESTED = "changes_requested"


class GapStatus(StrEnum):
    OPEN = "open"
    ADDRESSED = "addressed"
    RESOLVED = "resolved"


class ActionStatus(StrEnum):
    PROPOSED = "proposed"
    AUTHORIZED = "authorized"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


LedgerPayload: TypeAlias = rc.DomainRecord | rc.ActionAuthorization


@dataclass(frozen=True, slots=True)
class LedgerEvent:
    kind: Literal["judgment_ledger_event"]
    schema_version: Literal["1.0"]
    ledger_id: str
    sequence: int
    event_type: EventType
    actor: rc.Actor
    occurred_at: str
    previous_event_digest: str | None
    payload: LedgerPayload
    event_digest: str


@dataclass(frozen=True, slots=True)
class JudgmentProjection:
    ledger_id: str
    run: rc.ReasoningRun
    questions: tuple[rc.Question, ...]
    observations: tuple[rc.Observation, ...]
    claims: tuple[rc.ClaimCandidate, ...]
    gaps: tuple[rc.EvidenceGap, ...]
    actions: tuple[rc.NextAction, ...]
    authorizations: tuple[rc.ActionAuthorization, ...]
    outcomes: tuple[rc.ActionOutcome, ...]
    decisions: tuple[rc.ReviewDecision, ...]
    anchors: tuple[rc.EvidenceAnchor, ...]
    feedbacks: tuple[rc.CandidateLabelFeedback, ...]
    current_coverage: tuple[rc.CoverageAssertion, ...]
    coverage_context_digest: str
    question_statuses: tuple[tuple[str, QuestionStatus], ...]
    claim_statuses: tuple[tuple[str, ClaimStatus], ...]
    gap_statuses: tuple[tuple[str, GapStatus], ...]
    action_statuses: tuple[tuple[str, ActionStatus], ...]
    effective_claim_ids_by_question: tuple[tuple[str, tuple[str, ...]], ...]
    head_digest: str
    event_count: int


_EVENT_PAYLOAD_TYPES: dict[EventType, type[LedgerPayload]] = {
    EventType.RUN_OPENED: rc.ReasoningRun,
    EventType.QUESTION_OPENED: rc.Question,
    EventType.OBSERVATION_ADDED: rc.Observation,
    EventType.CLAIM_PROPOSED: rc.ClaimCandidate,
    EventType.GAP_IDENTIFIED: rc.EvidenceGap,
    EventType.ACTION_PROPOSED: rc.NextAction,
    EventType.ACTION_AUTHORIZED: rc.ActionAuthorization,
    EventType.ACTION_OUTCOME_RECORDED: rc.ActionOutcome,
    EventType.CLAIM_REVISED: rc.ClaimCandidate,
    EventType.REVIEW_DECIDED: rc.ReviewDecision,
    EventType.FEEDBACK_QUEUED: rc.CandidateLabelFeedback,
}

_RECORD_ID_FIELDS: dict[type[rc.DomainRecord], str] = {
    rc.ReasoningRun: "run_id",
    rc.Question: "question_id",
    rc.Observation: "observation_id",
    rc.ClaimCandidate: "claim_id",
    rc.EvidenceGap: "gap_id",
    rc.NextAction: "action_id",
    rc.ActionOutcome: "outcome_id",
    rc.ReviewDecision: "decision_id",
    rc.CandidateLabelFeedback: "feedback_id",
}

_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
_LEDGER_ID_RE = re.compile(r"ledger-sha256:[0-9a-f]{64}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_INT64_MAX = 2**63 - 1


def _event_body(event: LedgerEvent) -> dict[str, object]:
    value = cast(dict[str, object], codec._to_json_value(event))
    value.pop("event_digest")
    return value


def compute_event_digest(event: LedgerEvent) -> str:
    """Compute the domain-separated digest for an event envelope."""
    return codec.domain_hash("fxapk:judgment-ledger-event:v1", _event_body(event))


def _fail(code: str, event: LedgerEvent | None = None, *, path: str = "$") -> None:
    raise LedgerIntegrityError(
        code,
        field_path=path,
        event_sequence=None if event is None else event.sequence,
    )


def _validate_timestamp(value: str, event: LedgerEvent | None = None) -> None:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        _fail("invalid_event_timestamp", event, path="$.occurred_at")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        _fail("invalid_event_timestamp", event, path="$.occurred_at")


def _validate_payload(event: LedgerEvent) -> None:
    expected = _EVENT_PAYLOAD_TYPES.get(event.event_type)
    if expected is None or type(event.payload) is not expected:
        _fail("event_payload_type_mismatch", event, path="$.payload")

    rc.validate_contract_value(event.payload, field_path="$.payload")
    if isinstance(event.payload, rc.ActionAuthorization):
        authorization = event.payload
        if event.actor.kind is rc.ActorKind.SYSTEM:
            if authorization.granted_level is not rc.AuthorizationLevel.OFFLINE:
                _fail("authorization_actor_forbidden", event, path="$.actor")
            if "policy_pre_authorized" not in authorization.reason_codes:
                _fail("authorization_reason_required", event, path="$.payload.reason_codes")
        elif event.actor.kind is not rc.ActorKind.HUMAN:
            _fail("authorization_actor_forbidden", event, path="$.actor")
    else:
        codec.verify_record_identity(event.payload)
        anchors = (
            event.payload.input_anchors
            if isinstance(event.payload, rc.ReasoningRun)
            else event.payload.output_anchors
            if isinstance(event.payload, rc.ActionOutcome)
            else ()
        )
        for anchor in anchors:
            codec.verify_evidence_anchor_identity(anchor)

    if event.event_type is EventType.CLAIM_PROPOSED:
        claim = cast(rc.ClaimCandidate, event.payload)
        if claim.supersedes is not None:
            _fail("claim_proposed_supersedes_forbidden", event, path="$.payload.supersedes")
    elif event.event_type is EventType.CLAIM_REVISED:
        claim = cast(rc.ClaimCandidate, event.payload)
        if claim.supersedes is None:
            _fail("claim_revised_supersedes_required", event, path="$.payload.supersedes")
    elif event.event_type is EventType.REVIEW_DECIDED:
        decision = cast(rc.ReviewDecision, event.payload)
        if event.actor != decision.reviewer:
            _fail("review_actor_mismatch", event, path="$.actor")

    if event.event_type in {
        EventType.OBSERVATION_ADDED,
        EventType.ACTION_OUTCOME_RECORDED,
    } and event.actor.kind is rc.ActorKind.MODEL:
        _fail("model_evidence_actor_forbidden", event, path="$.actor.kind")

    # 模型无权自行入队候选标签（母设计 §7）；HUMAN（XLSX 纠正）与 SYSTEM（规则队列）可以。
    if (
        event.event_type is EventType.FEEDBACK_QUEUED
        and event.actor.kind is rc.ActorKind.MODEL
    ):
        _fail("feedback_actor_forbidden", event, path="$.actor.kind")


def _validate_event_local(event: LedgerEvent, *, verify_digest: bool) -> None:
    if type(event) is not LedgerEvent:
        _fail("event_required")
    if event.kind != "judgment_ledger_event":
        _fail("event_kind_mismatch", event, path="$.kind")
    if event.schema_version != "1.0":
        _fail("event_schema_version_mismatch", event, path="$.schema_version")
    if _LEDGER_ID_RE.fullmatch(event.ledger_id) is None:
        _fail("invalid_ledger_id", event, path="$.ledger_id")
    if isinstance(event.sequence, bool) or not isinstance(event.sequence, int):
        _fail("invalid_event_sequence", event, path="$.sequence")
    if not 0 <= event.sequence <= _INT64_MAX:
        _fail("invalid_event_sequence", event, path="$.sequence")
    if not isinstance(event.event_type, EventType):
        _fail("invalid_event_type", event, path="$.event_type")
    rc.validate_contract_value(event.actor, field_path="$.actor")
    _validate_timestamp(event.occurred_at, event)
    if event.previous_event_digest is not None and (
        not isinstance(event.previous_event_digest, str)
        or _DIGEST_RE.fullmatch(event.previous_event_digest) is None
    ):
        _fail("invalid_previous_event_digest", event, path="$.previous_event_digest")
    if not isinstance(event.event_digest, str) or _DIGEST_RE.fullmatch(event.event_digest) is None:
        _fail("invalid_event_digest", event, path="$.event_digest")
    _validate_payload(event)
    if verify_digest and not hmac.compare_digest(event.event_digest, compute_event_digest(event)):
        _fail("event_digest_mismatch", event, path="$.event_digest")


def make_event(
    events: tuple[LedgerEvent, ...],
    event_type: EventType,
    actor: rc.Actor,
    occurred_at: str,
    payload: LedgerPayload,
) -> LedgerEvent:
    """Seal the next event using only caller-supplied nondeterministic inputs."""
    if not isinstance(events, tuple):
        raise LedgerIntegrityError("event_tuple_required")
    if events:
        validate_event_chain(events)
        ledger_id = events[0].ledger_id
        previous_event_digest = events[-1].event_digest
    else:
        if event_type is not EventType.RUN_OPENED or type(payload) is not rc.ReasoningRun:
            raise LedgerIntegrityError("run_opened_required", event_sequence=0)
        ledger_id = codec.compute_ledger_id(payload.run_id)
        previous_event_digest = None

    unsealed = LedgerEvent(
        kind="judgment_ledger_event",
        schema_version="1.0",
        ledger_id=ledger_id,
        sequence=len(events),
        event_type=event_type,
        actor=actor,
        occurred_at=occurred_at,
        previous_event_digest=previous_event_digest,
        payload=payload,
        event_digest="sha256:" + "0" * 64,
    )
    _validate_event_local(unsealed, verify_digest=False)
    event = replace(unsealed, event_digest=compute_event_digest(unsealed))
    _validate_event_local(event, verify_digest=True)
    return event


def encode_event(event: LedgerEvent) -> str:
    _validate_event_local(event, verify_digest=True)
    return codec.canonical_json_v1(codec._to_json_value(event)).decode("utf-8")


def decode_event(text: str) -> LedgerEvent:
    value = codec._require_object(codec.parse_json_v1(text), "$")
    codec._exact_fields(
        value,
        {
            "kind",
            "schema_version",
            "ledger_id",
            "sequence",
            "event_type",
            "actor",
            "occurred_at",
            "previous_event_digest",
            "payload",
            "event_digest",
        },
        "$",
    )
    kind = codec._decode_typed(value["kind"], Literal["judgment_ledger_event"], "$.kind")
    schema_version = codec._decode_typed(
        value["schema_version"], Literal["1.0"], "$.schema_version"
    )
    event_type = cast(EventType, codec._decode_typed(value["event_type"], EventType, "$.event_type"))
    payload_type = _EVENT_PAYLOAD_TYPES[event_type]
    event = LedgerEvent(
        kind=cast(Literal["judgment_ledger_event"], kind),
        schema_version=cast(Literal["1.0"], schema_version),
        ledger_id=cast(str, codec._decode_typed(value["ledger_id"], str, "$.ledger_id")),
        sequence=cast(int, codec._decode_typed(value["sequence"], int, "$.sequence")),
        event_type=event_type,
        actor=codec._decode_actor(value["actor"], "$.actor"),
        occurred_at=cast(str, codec._decode_typed(value["occurred_at"], str, "$.occurred_at")),
        previous_event_digest=cast(
            str | None,
            codec._decode_typed(
                value["previous_event_digest"], str | None, "$.previous_event_digest"
            ),
        ),
        payload=cast(
            LedgerPayload,
            codec._decode_dataclass(value["payload"], payload_type, "$.payload"),
        ),
        event_digest=cast(
            str, codec._decode_typed(value["event_digest"], str, "$.event_digest")
        ),
    )
    _validate_event_local(event, verify_digest=True)
    return event


def _record_id(payload: LedgerPayload) -> str | None:
    if isinstance(payload, rc.ActionAuthorization):
        return None
    return cast(str, getattr(payload, _RECORD_ID_FIELDS[type(payload)]))


def validate_event_chain(events: tuple[LedgerEvent, ...]) -> None:
    """Validate event-local contracts and all cross-event chain structure."""
    if not isinstance(events, tuple):
        raise LedgerIntegrityError("event_tuple_required")
    if not events or type(events[0]) is not LedgerEvent:
        raise LedgerIntegrityError("run_opened_required", event_sequence=0)
    if events[0].event_type is not EventType.RUN_OPENED:
        raise LedgerIntegrityError("run_opened_required", event_sequence=0)

    first_payload = events[0].payload
    if type(first_payload) is not rc.ReasoningRun:
        raise LedgerIntegrityError("event_payload_type_mismatch", event_sequence=0)
    expected_ledger_id = codec.compute_ledger_id(first_payload.run_id)
    seen_record_ids: set[str] = set()

    for expected_sequence, event in enumerate(events):
        if type(event) is not LedgerEvent:
            raise LedgerIntegrityError("event_required", event_sequence=expected_sequence)
        if event.sequence != expected_sequence:
            raise LedgerIntegrityError("event_sequence_gap", event_sequence=expected_sequence)
        expected_previous = None if expected_sequence == 0 else events[expected_sequence - 1].event_digest
        if event.previous_event_digest != expected_previous:
            raise LedgerIntegrityError(
                "previous_event_digest_mismatch",
                event_sequence=expected_sequence,
            )
        if event.ledger_id != expected_ledger_id:
            raise LedgerIntegrityError("ledger_id_mismatch", event_sequence=expected_sequence)
        if expected_sequence > 0 and event.event_type is EventType.RUN_OPENED:
            raise LedgerIntegrityError("duplicate_run", event_sequence=expected_sequence)

        _validate_event_local(event, verify_digest=True)
        record_id = _record_id(event.payload)
        if record_id is not None:
            if record_id in seen_record_ids:
                raise LedgerIntegrityError("duplicate_record_id", event_sequence=expected_sequence)
            seen_record_ids.add(record_id)


_QUESTION_TASKS = {
    rc.QuestionType.RESOLVE_FAMILY: rc.ClaimTask.FAMILY,
    rc.QuestionType.RESOLVE_CLUE: rc.ClaimTask.CLUE,
    rc.QuestionType.RESOLVE_RELATION: rc.ClaimTask.RELATION,
    rc.QuestionType.RESOLVE_OWNERSHIP: rc.ClaimTask.OWNERSHIP,
    rc.QuestionType.PLAN_REANALYSIS: rc.ClaimTask.REANALYSIS,
}


def _coverage_key(assertion: rc.CoverageAssertion) -> tuple[bytes, rc.CoverageSource]:
    subject = codec.canonical_json_v1(codec._to_json_value(assertion.subject))
    return (subject, assertion.source)


def _coverage_predicate_key(
    predicate: rc.CoveragePredicate,
) -> tuple[bytes, rc.CoverageSource]:
    subject = codec.canonical_json_v1(codec._to_json_value(predicate.subject))
    return (subject, predicate.source)


_RecordT = TypeVar("_RecordT")


def _canonical_records(values: dict[str, _RecordT]) -> tuple[_RecordT, ...]:
    return tuple(value for _, value in sorted(values.items()))


@dataclass(slots=True)
class _ReplayState:
    ledger_id: str
    run: rc.ReasoningRun
    questions: dict[str, rc.Question] = field(default_factory=dict)
    observations: dict[str, rc.Observation] = field(default_factory=dict)
    claims: dict[str, rc.ClaimCandidate] = field(default_factory=dict)
    gaps: dict[str, rc.EvidenceGap] = field(default_factory=dict)
    feedbacks: dict[str, rc.CandidateLabelFeedback] = field(default_factory=dict)
    actions: dict[str, rc.NextAction] = field(default_factory=dict)
    authorizations: dict[str, rc.ActionAuthorization] = field(default_factory=dict)
    outcomes: dict[str, rc.ActionOutcome] = field(default_factory=dict)
    decisions: dict[str, rc.ReviewDecision] = field(default_factory=dict)
    anchors: dict[str, rc.EvidenceAnchor] = field(default_factory=dict)
    coverage: dict[tuple[bytes, rc.CoverageSource], rc.CoverageAssertion] = field(
        default_factory=dict
    )
    question_statuses: dict[str, QuestionStatus] = field(default_factory=dict)
    claim_statuses: dict[str, ClaimStatus] = field(default_factory=dict)
    gap_statuses: dict[str, GapStatus] = field(default_factory=dict)
    action_statuses: dict[str, ActionStatus] = field(default_factory=dict)
    event_sequence: int = 0

    @classmethod
    def from_run(cls, event: LedgerEvent) -> _ReplayState:
        run = cast(rc.ReasoningRun, event.payload)
        state = cls(ledger_id=event.ledger_id, run=run, event_sequence=event.sequence)
        for anchor in run.input_anchors:
            _register_anchor(state, anchor)
        for assertion in run.initial_coverage:
            _require_locator(state, assertion.receipt_locator)
            state.coverage[_coverage_key(assertion)] = assertion
        return state

    def freeze(self, head_digest: str, event_count: int) -> JudgmentProjection:
        current_coverage = _current_coverage(self)
        effective: list[tuple[str, tuple[str, ...]]] = []
        for question_id in sorted(self.questions):
            claim_ids = tuple(
                sorted(
                    claim_id
                    for claim_id, claim in self.claims.items()
                    if claim.question_id == question_id
                    and self.claim_statuses[claim_id] is not ClaimStatus.SUPERSEDED
                )
            )
            if claim_ids:
                effective.append((question_id, claim_ids))
        return JudgmentProjection(
            ledger_id=self.ledger_id,
            run=self.run,
            questions=_canonical_records(self.questions),
            observations=_canonical_records(self.observations),
            claims=_canonical_records(self.claims),
            gaps=_canonical_records(self.gaps),
            actions=_canonical_records(self.actions),
            authorizations=tuple(value for _, value in sorted(self.authorizations.items())),
            outcomes=_canonical_records(self.outcomes),
            decisions=_canonical_records(self.decisions),
            anchors=_canonical_records(self.anchors),
            feedbacks=_canonical_records(self.feedbacks),
            current_coverage=current_coverage,
            coverage_context_digest=codec.compute_coverage_context_digest(current_coverage),
            question_statuses=tuple(sorted(self.question_statuses.items())),
            claim_statuses=tuple(sorted(self.claim_statuses.items())),
            gap_statuses=tuple(sorted(self.gap_statuses.items())),
            action_statuses=tuple(sorted(self.action_statuses.items())),
            effective_claim_ids_by_question=tuple(effective),
            head_digest=head_digest,
            event_count=event_count,
        )


def _reference_error(code: str, state: _ReplayState, path: str) -> NoReturn:
    raise rc.ReferenceIntegrityError(
        code,
        field_path=path,
        event_sequence=state.event_sequence,
    )


def _transition_error(
    code: str, state: _ReplayState, path: str = "$.payload"
) -> NoReturn:
    raise rc.ReplayTransitionError(
        code,
        field_path=path,
        event_sequence=state.event_sequence,
    )


def _register_anchor(state: _ReplayState, anchor: rc.EvidenceAnchor) -> None:
    codec.verify_evidence_anchor_identity(anchor)
    if anchor.anchor_id in state.anchors:
        _reference_error("duplicate_anchor", state, "$.payload.output_anchors")
    state.anchors[anchor.anchor_id] = anchor


def _require_locator(state: _ReplayState, locator: rc.EvidenceLocator | None) -> None:
    if locator is not None and locator.anchor_id not in state.anchors:
        _reference_error("unknown_anchor", state, "$.payload")


def _current_coverage(state: _ReplayState) -> tuple[rc.CoverageAssertion, ...]:
    return tuple(
        sorted(
            state.coverage.values(),
            key=lambda item: codec.canonical_json_v1(codec._to_json_value(item)),
        )
    )


def _apply_coverage(
    state: _ReplayState, assertions: tuple[rc.CoverageAssertion, ...]
) -> None:
    for assertion in assertions:
        _require_locator(state, assertion.receipt_locator)
    for assertion in assertions:
        state.coverage[_coverage_key(assertion)] = assertion


def _apply_question(state: _ReplayState, question: rc.Question) -> None:
    state.questions[question.question_id] = question
    state.question_statuses[question.question_id] = QuestionStatus.OPEN


def _apply_observation(state: _ReplayState, observation: rc.Observation) -> None:
    for locator in observation.source_refs:
        _require_locator(state, locator)
    if observation.value.reference is not None:
        _require_locator(state, observation.value.reference)
    for observation_id in observation.input_observation_ids:
        if observation_id not in state.observations:
            _reference_error("unknown_observation", state, "$.payload.input_observation_ids")
    if (
        observation.origin_outcome_id is not None
        and observation.origin_outcome_id not in state.outcomes
    ):
        _reference_error("unknown_outcome", state, "$.payload.origin_outcome_id")
    _apply_coverage(state, observation.coverage_assertions)
    state.observations[observation.observation_id] = observation


def _claim_object_kind(claim: rc.ClaimCandidate) -> rc.ObjectKind:
    if claim.object_value is None:
        return rc.ObjectKind.NONE
    return rc.ObjectKind(claim.object_value.kind.value)


def _require_allowed_conclusion(
    state: _ReplayState,
    question: rc.Question,
    claim: rc.ClaimCandidate,
) -> None:
    object_kind = _claim_object_kind(claim)
    for conclusion in question.allowed_conclusions:
        if (
            conclusion.predicate != claim.predicate
            or claim.claim_mode not in conclusion.claim_modes
            or conclusion.object_kind is not object_kind
        ):
            continue
        if object_kind is rc.ObjectKind.CATEGORICAL:
            categorical = cast(rc.ObservationValue, claim.object_value).categorical
            if (
                conclusion.allowed_categorical_values
                and categorical not in conclusion.allowed_categorical_values
            ):
                continue
        return
    _transition_error("claim_conclusion_not_allowed", state)


def _require_claim_observations(state: _ReplayState, claim: rc.ClaimCandidate) -> None:
    observation_ids = (
        *claim.supporting_observation_ids,
        *claim.contradicting_observation_ids,
        *(item.observation_id for item in claim.excluded_observations),
    )
    for observation_id in observation_ids:
        if observation_id not in state.observations:
            _reference_error("unknown_observation", state, "$.payload")


def _predicate_satisfied(state: _ReplayState, predicate: rc.CoveragePredicate) -> bool:
    assertion = state.coverage.get(_coverage_predicate_key(predicate))
    return assertion is not None and assertion.status in predicate.allowed_statuses


def _require_negative_coverage(state: _ReplayState, claim: rc.ClaimCandidate) -> None:
    if claim.claim_mode not in {rc.ClaimMode.NEGATIVE, rc.ClaimMode.EXHAUSTIVE}:
        return
    for predicate in claim.coverage_requirements:
        assertion = state.coverage.get(_coverage_predicate_key(predicate))
        if assertion is None or assertion.status is not rc.CoverageStatus.COMPLETE:
            _transition_error("negative_coverage_not_complete", state)
        if assertion.scope is not rc.EvidenceScope.CASE_EVIDENCE:
            _transition_error("negative_coverage_not_case_evidence", state)


def _require_ownership(state: _ReplayState, claim: rc.ClaimCandidate) -> None:
    claim_subjects = set(claim.subjects)
    claim_support = set(claim.supporting_observation_ids)
    for ownership in claim.ownership:
        if ownership.subject not in claim_subjects:
            _transition_error("ownership_subject_mismatch", state)
        if ownership.value is rc.OwnershipValue.UNKNOWN:
            continue
        ownership_support = set(ownership.supporting_observation_ids)
        if not ownership_support or not ownership_support <= claim_support:
            _transition_error("ownership_support_mismatch", state)
        if not any(
            state.observations[observation_id].scope is rc.EvidenceScope.CASE_EVIDENCE
            for observation_id in ownership_support
        ):
            _transition_error("ownership_evidence_not_authoritative", state)


def _require_gap_resolution(
    state: _ReplayState,
    claim: rc.ClaimCandidate,
) -> tuple[str, ...]:
    supporting = tuple(
        state.observations[observation_id]
        for observation_id in claim.supporting_observation_ids
    )
    resolved: list[str] = []
    for gap_id in claim.resolves_gap_ids:
        gap = state.gaps.get(gap_id)
        if gap is None:
            _reference_error("unknown_gap", state, "$.payload.resolves_gap_ids")
        if gap.question_id != claim.question_id:
            _transition_error("gap_question_mismatch", state)
        if state.gap_statuses[gap_id] is GapStatus.RESOLVED:
            _transition_error("gap_already_resolved", state)
        observation_types = {item.observation_type for item in supporting}
        if not set(gap.required_observation_types) <= observation_types or not all(
            _predicate_satisfied(state, predicate) for predicate in gap.coverage_requirements
        ):
            _transition_error("gap_resolution_not_satisfied", state)
        resolved.append(gap_id)
    return tuple(resolved)


def _apply_claim(
    state: _ReplayState,
    claim: rc.ClaimCandidate,
    *,
    revised: bool,
) -> None:
    question = state.questions.get(claim.question_id)
    if question is None:
        _reference_error("unknown_question", state, "$.payload.question_id")
    if state.question_statuses[claim.question_id] is QuestionStatus.ACCEPTED:
        _transition_error("question_already_accepted", state)
    if claim.task is not _QUESTION_TASKS[question.question_type]:
        _transition_error("claim_task_mismatch", state, "$.payload.task")
    if claim.subjects != question.subjects:
        _transition_error("claim_subject_mismatch", state, "$.payload.subjects")
    if claim.object_value is not None:
        _require_locator(state, claim.object_value.reference)
    _require_allowed_conclusion(state, question, claim)
    _require_claim_observations(state, claim)
    current_digest = codec.compute_coverage_context_digest(_current_coverage(state))
    if not hmac.compare_digest(claim.coverage_context_digest, current_digest):
        _transition_error("coverage_context_stale", state, "$.payload.coverage_context_digest")
    _require_negative_coverage(state, claim)
    _require_ownership(state, claim)

    superseded: rc.ClaimCandidate | None = None
    if revised:
        if claim.supersedes is None:
            _transition_error("supersedes_required", state, "$.payload.supersedes")
        superseded = state.claims.get(claim.supersedes)
        if superseded is None:
            _reference_error("unknown_superseded_claim", state, "$.payload.supersedes")
        if superseded.question_id != claim.question_id:
            _transition_error("supersedes_question_mismatch", state)
        if state.claim_statuses[superseded.claim_id] is ClaimStatus.SUPERSEDED:
            _transition_error("claim_already_superseded", state)
    elif claim.supersedes is not None:
        _transition_error("supersedes_forbidden", state, "$.payload.supersedes")

    resolved_gap_ids = _require_gap_resolution(state, claim)
    if superseded is not None:
        state.claim_statuses[superseded.claim_id] = ClaimStatus.SUPERSEDED
    state.claims[claim.claim_id] = claim
    state.claim_statuses[claim.claim_id] = ClaimStatus.PROPOSED
    state.question_statuses[claim.question_id] = QuestionStatus.AWAITING_REVIEW
    for gap_id in resolved_gap_ids:
        state.gap_statuses[gap_id] = GapStatus.RESOLVED


def _apply_gap(state: _ReplayState, gap: rc.EvidenceGap) -> None:
    if gap.question_id not in state.questions:
        _reference_error("unknown_question", state, "$.payload.question_id")
    if state.question_statuses[gap.question_id] is QuestionStatus.ACCEPTED:
        _transition_error("question_already_accepted", state)
    if gap.claim_id is not None:
        claim = state.claims.get(gap.claim_id)
        if claim is None:
            _reference_error("unknown_claim", state, "$.payload.claim_id")
        if claim.question_id != gap.question_id:
            _transition_error("gap_claim_question_mismatch", state)
        if state.claim_statuses[claim.claim_id] is ClaimStatus.SUPERSEDED:
            _transition_error("gap_claim_superseded", state)
    state.gaps[gap.gap_id] = gap
    state.gap_statuses[gap.gap_id] = GapStatus.OPEN


_NONTERMINAL_ACTION_STATUSES = frozenset(
    {ActionStatus.PROPOSED, ActionStatus.AUTHORIZED}
)


def _apply_action(state: _ReplayState, action: rc.NextAction) -> None:
    if action.question_id not in state.questions:
        _reference_error("unknown_question", state, "$.payload.question_id")
    if state.question_statuses[action.question_id] is QuestionStatus.ACCEPTED:
        _transition_error("question_already_accepted", state)
    for gap_id in action.gap_ids:
        gap = state.gaps.get(gap_id)
        if gap is None:
            _reference_error("unknown_gap", state, "$.payload.gap_ids")
        if gap.question_id != action.question_id:
            _transition_error("action_gap_question_mismatch", state)
        if state.gap_statuses[gap_id] not in {GapStatus.OPEN, GapStatus.ADDRESSED}:
            _transition_error("action_gap_state_invalid", state)
    for anchor_id in action.input_anchor_ids:
        if anchor_id not in state.anchors:
            _reference_error("unknown_anchor", state, "$.payload.input_anchor_ids")

    matching = tuple(
        prior for prior in state.actions.values() if prior.dedupe_key == action.dedupe_key
    )
    if any(
        state.action_statuses[prior.action_id] in _NONTERMINAL_ACTION_STATUSES
        for prior in matching
    ):
        _transition_error("action_dedupe_nonterminal", state)
    if any(prior.attempt_nonce == action.attempt_nonce for prior in matching):
        _transition_error("action_retry_nonce_reused", state)

    state.actions[action.action_id] = action
    state.action_statuses[action.action_id] = ActionStatus.PROPOSED


def _apply_authorization(
    state: _ReplayState,
    authorization: rc.ActionAuthorization,
) -> None:
    action = state.actions.get(authorization.action_id)
    if action is None:
        _reference_error("unknown_action", state, "$.payload.action_id")
    if authorization.action_id in state.authorizations:
        _transition_error("action_already_authorized", state)
    if authorization.granted_level is not action.authorization_required:
        _transition_error("authorization_level_mismatch", state)
    if authorization.policy not in state.run.policies:
        _transition_error("authorization_policy_unknown", state)
    if state.action_statuses[action.action_id] is not ActionStatus.PROPOSED:
        _transition_error("action_state_not_proposed", state)
    state.authorizations[action.action_id] = authorization
    state.action_statuses[action.action_id] = ActionStatus.AUTHORIZED


def _apply_outcome(state: _ReplayState, outcome: rc.ActionOutcome) -> None:
    action = state.actions.get(outcome.action_id)
    if action is None:
        _reference_error("unknown_action", state, "$.payload.action_id")
    if outcome.action_id not in state.authorizations:
        _transition_error("action_not_authorized", state)
    if any(prior.action_id == outcome.action_id for prior in state.outcomes.values()):
        _transition_error("action_outcome_exists", state)

    output_ids: set[str] = set()
    for anchor in outcome.output_anchors:
        codec.verify_evidence_anchor_identity(anchor)
        if anchor.anchor_id in state.anchors or anchor.anchor_id in output_ids:
            _reference_error("duplicate_anchor", state, "$.payload.output_anchors")
        output_ids.add(anchor.anchor_id)
    known_anchor_ids = set(state.anchors) | output_ids
    if (
        outcome.diagnostics_locator is not None
        and outcome.diagnostics_locator.anchor_id not in known_anchor_ids
    ):
        _reference_error("unknown_anchor", state, "$.payload.diagnostics_locator")
    for assertion in outcome.coverage_assertions:
        if (
            assertion.receipt_locator is not None
            and assertion.receipt_locator.anchor_id not in known_anchor_ids
        ):
            _reference_error("unknown_anchor", state, "$.payload.coverage_assertions")

    for anchor in outcome.output_anchors:
        state.anchors[anchor.anchor_id] = anchor
    _apply_coverage(state, outcome.coverage_assertions)
    state.outcomes[outcome.outcome_id] = outcome
    state.action_statuses[action.action_id] = ActionStatus(outcome.status.value)
    for gap_id in action.gap_ids:
        if state.gap_statuses[gap_id] is GapStatus.OPEN:
            state.gap_statuses[gap_id] = GapStatus.ADDRESSED


def _question_status_from_claims(state: _ReplayState, question_id: str) -> QuestionStatus:
    statuses = {
        state.claim_statuses[claim_id]
        for claim_id, claim in state.claims.items()
        if claim.question_id == question_id
        and state.claim_statuses[claim_id] is not ClaimStatus.SUPERSEDED
    }
    for claim_status, question_status in (
        (ClaimStatus.ACCEPTED, QuestionStatus.ACCEPTED),
        (ClaimStatus.PROPOSED, QuestionStatus.AWAITING_REVIEW),
        (ClaimStatus.CHANGES_REQUESTED, QuestionStatus.CHANGES_REQUESTED),
        (ClaimStatus.UNKNOWN, QuestionStatus.UNKNOWN),
    ):
        if claim_status in statuses:
            return question_status
    return QuestionStatus.OPEN


def _require_review_gaps(
    state: _ReplayState,
    decision: rc.ReviewDecision,
    claim: rc.ClaimCandidate,
) -> None:
    for gap_id in decision.gap_ids:
        gap = state.gaps.get(gap_id)
        if gap is None:
            _reference_error("unknown_gap", state, "$.payload.gap_ids")
        if gap.question_id != claim.question_id:
            _transition_error("review_gap_question_mismatch", state)
        if decision.decision in {
            rc.ReviewDecisionValue.UNKNOWN,
            rc.ReviewDecisionValue.CHANGES_REQUESTED,
        } and state.gap_statuses[gap_id] is GapStatus.RESOLVED:
            _transition_error("review_gap_resolved", state)


def _require_authoritative_positive(
    state: _ReplayState,
    claim: rc.ClaimCandidate,
) -> None:
    if claim.claim_mode is not rc.ClaimMode.POSITIVE or claim.task is rc.ClaimTask.REANALYSIS:
        return
    if not any(
        state.observations[observation_id].scope is rc.EvidenceScope.CASE_EVIDENCE
        for observation_id in claim.supporting_observation_ids
    ):
        _transition_error("evidence_scope_not_authoritative", state)


def _apply_review(
    state: _ReplayState,
    event: LedgerEvent,
    decision: rc.ReviewDecision,
) -> None:
    claim = state.claims.get(decision.claim_id)
    if claim is None:
        _reference_error("unknown_claim", state, "$.payload.claim_id")
    if decision.question_id != claim.question_id:
        _transition_error("review_question_mismatch", state)
    if state.question_statuses[claim.question_id] is QuestionStatus.ACCEPTED:
        _transition_error("question_already_accepted", state)
    if state.claim_statuses[claim.claim_id] is ClaimStatus.SUPERSEDED:
        _transition_error("review_claim_not_current", state)
    if any(prior.claim_id == claim.claim_id for prior in state.decisions.values()):
        _transition_error("claim_decision_exists", state)
    if decision.basis_head_digest != event.previous_event_digest:
        _transition_error("review_basis_head_mismatch", state, "$.payload.basis_head_digest")

    evidence_ids = {
        *claim.supporting_observation_ids,
        *claim.contradicting_observation_ids,
        *(item.observation_id for item in claim.excluded_observations),
    }
    if not set(decision.basis_observation_ids) <= evidence_ids:
        _transition_error("review_basis_not_in_claim", state)
    _require_review_gaps(state, decision, claim)

    if decision.decision is rc.ReviewDecisionValue.ACCEPTED:
        current_digest = codec.compute_coverage_context_digest(_current_coverage(state))
        if not hmac.compare_digest(claim.coverage_context_digest, current_digest):
            _transition_error("coverage_context_stale", state)

    if decision.decision in {
        rc.ReviewDecisionValue.ACCEPTED,
        rc.ReviewDecisionValue.REJECTED,
    }:
        if not all(
            _predicate_satisfied(state, predicate)
            for predicate in claim.coverage_requirements
        ):
            _transition_error("claim_coverage_unsatisfied", state)
        _require_negative_coverage(state, claim)

    if decision.decision is rc.ReviewDecisionValue.ACCEPTED:
        if "blocks_acceptance" in claim.caps:
            _transition_error("claim_acceptance_blocked", state)
        if any(
            gap.question_id == claim.question_id
            and gap.effect is rc.GapEffect.BLOCKS_REVIEW
            and state.gap_statuses[gap.gap_id] is GapStatus.OPEN
            for gap in state.gaps.values()
        ):
            _transition_error("blocking_gap_open", state)
        _require_authoritative_positive(state, claim)
        if claim.claim_mode is rc.ClaimMode.POSITIVE and not (
            set(decision.basis_observation_ids) & set(claim.supporting_observation_ids)
        ):
            _transition_error("accepted_basis_required", state)
        state.claim_statuses[claim.claim_id] = ClaimStatus.ACCEPTED
    elif decision.decision is rc.ReviewDecisionValue.REJECTED:
        state.claim_statuses[claim.claim_id] = ClaimStatus.REJECTED
    elif decision.decision is rc.ReviewDecisionValue.UNKNOWN:
        state.claim_statuses[claim.claim_id] = ClaimStatus.UNKNOWN
    else:
        state.claim_statuses[claim.claim_id] = ClaimStatus.CHANGES_REQUESTED

    state.decisions[decision.decision_id] = decision
    state.question_statuses[claim.question_id] = _question_status_from_claims(
        state, claim.question_id
    )


def _apply_feedback(state: _ReplayState, feedback: rc.CandidateLabelFeedback) -> None:
    if feedback.feedback_id in state.feedbacks:
        _transition_error("feedback_duplicate", state)
    state.feedbacks[feedback.feedback_id] = feedback


def _apply_event(state: _ReplayState, event: LedgerEvent) -> None:
    state.event_sequence = event.sequence
    if event.event_type is EventType.QUESTION_OPENED:
        _apply_question(state, cast(rc.Question, event.payload))
    elif event.event_type is EventType.OBSERVATION_ADDED:
        _apply_observation(state, cast(rc.Observation, event.payload))
    elif event.event_type is EventType.CLAIM_PROPOSED:
        _apply_claim(state, cast(rc.ClaimCandidate, event.payload), revised=False)
    elif event.event_type is EventType.CLAIM_REVISED:
        _apply_claim(state, cast(rc.ClaimCandidate, event.payload), revised=True)
    elif event.event_type is EventType.GAP_IDENTIFIED:
        _apply_gap(state, cast(rc.EvidenceGap, event.payload))
    elif event.event_type is EventType.ACTION_PROPOSED:
        _apply_action(state, cast(rc.NextAction, event.payload))
    elif event.event_type is EventType.ACTION_AUTHORIZED:
        _apply_authorization(state, cast(rc.ActionAuthorization, event.payload))
    elif event.event_type is EventType.ACTION_OUTCOME_RECORDED:
        _apply_outcome(state, cast(rc.ActionOutcome, event.payload))
    elif event.event_type is EventType.FEEDBACK_QUEUED:
        _apply_feedback(state, cast(rc.CandidateLabelFeedback, event.payload))
    elif event.event_type is EventType.REVIEW_DECIDED:
        _apply_review(state, event, cast(rc.ReviewDecision, event.payload))
    else:
        _transition_error("event_transition_not_implemented", state)


def replay(events: tuple[LedgerEvent, ...]) -> JudgmentProjection:
    """Replay a complete ledger into a frozen projection without side effects."""
    validate_event_chain(events)
    state = _ReplayState.from_run(events[0])
    for event in events[1:]:
        _apply_event(state, event)
    return state.freeze(events[-1].event_digest, len(events))


def append_event(
    events: tuple[LedgerEvent, ...], event: LedgerEvent
) -> tuple[LedgerEvent, ...]:
    candidate = (*events, event)
    replay(candidate)
    return candidate


__all__ = [
    "ActionStatus",
    "ClaimStatus",
    "EventType",
    "GapStatus",
    "JudgmentProjection",
    "LedgerEvent",
    "LedgerPayload",
    "QuestionStatus",
    "ReferenceIntegrityError",
    "ReplayTransitionError",
    "append_event",
    "compute_event_digest",
    "decode_event",
    "encode_event",
    "make_event",
    "replay",
    "validate_event_chain",
]
