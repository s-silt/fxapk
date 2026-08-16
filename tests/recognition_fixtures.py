"""Deterministic, documentation-only fixtures for recognition contracts."""

from __future__ import annotations

from apkscan.core.recognition_contract import (
    Actor,
    ActorKind,
    AllowedConclusion,
    ClaimCandidate,
    ClaimMode,
    ClaimTask,
    CoverageAssertion,
    CoveragePredicate,
    CoverageSource,
    CoverageStatus,
    EvidenceAnchor,
    EvidenceAnchorType,
    EvidenceGap,
    EvidenceLocator,
    EvidenceScope,
    GapEffect,
    LocatorKind,
    NextAction,
    ObjectKind,
    Observation,
    ObservationStrength,
    ObservationValue,
    ObservationValueKind,
    OutcomeStatus,
    PolicyRef,
    ProducerKind,
    ProducerRef,
    Question,
    QuestionType,
    ReasoningRun,
    ReviewDecision,
    ReviewDecisionValue,
    ActionOutcome,
    ActionBudget,
    ActionAuthorization,
    ActionUsage,
    AuthorizationLevel,
    OwnershipValue,
    SubjectKind,
    SubjectRef,
)
from apkscan.core.recognition_codec import (
    build_action_outcome,
    build_claim_candidate,
    build_evidence_anchor,
    build_evidence_gap,
    build_next_action,
    build_observation,
    build_question,
    build_reasoning_run,
    build_review_decision,
    compute_coverage_context_digest,
)
from apkscan.core.judgment_ledger import EventType, LedgerEvent, make_event

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
ANCHOR_ID = "anchor-sha256:" + "c" * 64
ACTION_ID = "action-sha256:" + "d" * 64
OBSERVATION_ID = "observation-sha256:" + "e" * 64
FIXED_TIME = "2026-08-16T00:00:00.000000Z"
SUBJECT = SubjectRef(kind=SubjectKind.SAMPLE, value="sample-a", role=None)


def make_actor(actor_kind: ActorKind = ActorKind.SYSTEM) -> Actor:
    return Actor(kind=actor_kind, actor_id="fxapk-test")


def make_anchor(
    *,
    logical_id: str | None = "package-a",
    schema_version_ref: str | None = "1.0",
) -> EvidenceAnchor:
    return build_evidence_anchor(
        anchor_type=EvidenceAnchorType.CASE_PACKAGE,
        content_digest=DIGEST_A,
        logical_id=logical_id,
        schema_version_ref=schema_version_ref,
    )


def make_locator(
    *,
    kind: LocatorKind = LocatorKind.JSON_POINTER,
    value: str = "/meta/visibility/java",
    start: int | None = None,
    end: int | None = None,
) -> EvidenceLocator:
    return EvidenceLocator(
        anchor_id=make_anchor().anchor_id,
        kind=kind,
        value=value,
        start=start,
        end=end,
    )


def make_coverage(
    *,
    source: CoverageSource = CoverageSource.JAVA,
    status: CoverageStatus = CoverageStatus.COMPLETE,
    scope: EvidenceScope = EvidenceScope.CASE_EVIDENCE,
) -> CoverageAssertion:
    return CoverageAssertion(
        subject=SUBJECT,
        source=source,
        status=status,
        scope=scope,
        assessment_digest=DIGEST_B,
        receipt_locator=make_locator(),
        reason_codes=(),
    )


def make_policy() -> PolicyRef:
    return PolicyRef(policy_id="default-policy", version="1.0", digest=DIGEST_A)


def make_producer(kind: ProducerKind = ProducerKind.ANALYZER) -> ProducerRef:
    return ProducerRef(
        kind=kind,
        producer_id="fxapk-test-producer",
        version="1.0",
        artifact_digest=DIGEST_A,
        configuration_digest=DIGEST_B,
    )


def make_reasoning_run(*, execution_nonce: str = "1" * 32) -> ReasoningRun:
    return build_reasoning_run(
        execution_nonce=execution_nonce,
        purpose="resolve-family",
        subjects=(SUBJECT,),
        input_anchors=(make_anchor(),),
        initial_coverage=(make_coverage(),),
        policies=(make_policy(),),
        producers=(make_producer(),),
    )


def make_question() -> Question:
    conclusion = AllowedConclusion(
        predicate="family-membership",
        claim_modes=(ClaimMode.POSITIVE,),
        object_kind=ObjectKind.CATEGORICAL,
        allowed_categorical_values=("family-a",),
    )
    return build_question(
        question_type=QuestionType.RESOLVE_FAMILY,
        subjects=(SUBJECT,),
        allowed_conclusions=(conclusion,),
    )


def make_observation() -> Observation:
    return build_observation(
        observation_type="family-anchor",
        subjects=(SUBJECT,),
        value=ObservationValue(
            kind=ObservationValueKind.CATEGORICAL,
            categorical="family-a",
            integer=None,
            boolean=None,
            reference=None,
        ),
        source_refs=(make_locator(),),
        scope=EvidenceScope.CASE_EVIDENCE,
        strength=ObservationStrength.OBSERVED,
        input_observation_ids=(),
        origin_outcome_id=None,
        producer=make_producer(),
        ownership=OwnershipValue.UNKNOWN,
        coverage_assertions=(make_coverage(),),
    )


def make_claim_candidate() -> ClaimCandidate:
    observation = make_observation()
    coverage = (make_coverage(),)
    return build_claim_candidate(
        question_id=make_question().question_id,
        task=ClaimTask.FAMILY,
        claim_mode=ClaimMode.POSITIVE,
        subjects=(SUBJECT,),
        predicate="family-membership",
        object_value=ObservationValue(
            kind=ObservationValueKind.CATEGORICAL,
            categorical="family-a",
            integer=None,
            boolean=None,
            reference=None,
        ),
        supporting_observation_ids=(observation.observation_id,),
        contradicting_observation_ids=(),
        excluded_observations=(),
        coverage_requirements=(),
        coverage_context_digest=compute_coverage_context_digest(coverage),
        ownership=(),
        caps=(),
        unknowns=(),
        resolves_gap_ids=(),
        producer=make_producer(ProducerKind.RULE_ENGINE),
        supersedes=None,
        score=None,
    )


def make_gap() -> EvidenceGap:
    return build_evidence_gap(
        question_id=make_question().question_id,
        claim_id=make_claim_candidate().claim_id,
        effect=GapEffect.BLOCKS_REVIEW,
        reason_codes=("java-coverage-partial",),
        required_observation_types=(),
        coverage_requirements=(
            CoveragePredicate(
                subject=SUBJECT,
                source=CoverageSource.JAVA,
                allowed_statuses=(CoverageStatus.COMPLETE,),
            ),
        ),
        producer=make_producer(ProducerKind.SYSTEM),
    )


def make_action(
    *, attempt_nonce: str = "2" * 32, action_type: str = "jadx-usage-query"
) -> NextAction:
    return build_next_action(
        question_id=make_question().question_id,
        gap_ids=(make_gap().gap_id,),
        attempt_nonce=attempt_nonce,
        action_type=action_type,
        subjects=(SUBJECT,),
        input_anchor_ids=(make_anchor().anchor_id,),
        parameters_digest=DIGEST_B,
        authorization_required=AuthorizationLevel.OFFLINE,
        budget=ActionBudget(max_seconds=60, max_memory_mb=512),
        success_criteria=("coverage-receipt",),
        negative_valid_only_if=(),
        producer=make_producer(ProducerKind.SYSTEM),
    )


def make_outcome() -> ActionOutcome:
    return build_action_outcome(
        action_id=make_action().action_id,
        status=OutcomeStatus.COMPLETE,
        output_anchors=(),
        coverage_assertions=(make_coverage(),),
        reason_codes=(),
        diagnostics_locator=None,
        usage=ActionUsage(elapsed_ms=10, peak_memory_mb=128, output_bytes=256),
        producer=make_producer(ProducerKind.QUERY),
    )


def make_review_decision() -> ReviewDecision:
    claim = make_claim_candidate()
    return build_review_decision(
        question_id=make_question().question_id,
        claim_id=claim.claim_id,
        decision=ReviewDecisionValue.ACCEPTED,
        reviewer=make_actor(ActorKind.HUMAN),
        basis_head_digest=DIGEST_A,
        basis_observation_ids=claim.supporting_observation_ids,
        gap_ids=(),
        reason_codes=("manual-review",),
    )


def make_run_event() -> LedgerEvent:
    return make_event(
        (),
        EventType.RUN_OPENED,
        make_actor(),
        FIXED_TIME,
        make_reasoning_run(),
    )


def make_question_ledger() -> tuple[LedgerEvent, ...]:
    first = make_run_event()
    second = make_event(
        (first,),
        EventType.QUESTION_OPENED,
        make_actor(),
        FIXED_TIME,
        make_question(),
    )
    return (first, second)


def append_record(
    events: tuple[LedgerEvent, ...],
    event_type: EventType,
    payload: object,
    *,
    actor_kind: ActorKind = ActorKind.SYSTEM,
) -> tuple[LedgerEvent, ...]:
    event = make_event(
        events,
        event_type,
        make_actor(actor_kind),
        FIXED_TIME,
        payload,  # type: ignore[arg-type]
    )
    return (*events, event)


def make_claim_ledger(
    *,
    mode: ClaimMode = ClaimMode.POSITIVE,
    source: CoverageSource = CoverageSource.JAVA,
    status: CoverageStatus = CoverageStatus.COMPLETE,
    scope: EvidenceScope = EvidenceScope.CASE_EVIDENCE,
) -> tuple[LedgerEvent, ...]:
    coverage = make_coverage(source=source, status=status, scope=scope)
    run = build_reasoning_run(
        execution_nonce="1" * 32,
        purpose="resolve-family",
        subjects=(SUBJECT,),
        input_anchors=(make_anchor(),),
        initial_coverage=(coverage,),
        policies=(make_policy(),),
        producers=(make_producer(),),
    )
    object_kind = ObjectKind.CATEGORICAL if mode is ClaimMode.POSITIVE else ObjectKind.NONE
    conclusion = AllowedConclusion(
        predicate="family-membership",
        claim_modes=(mode,),
        object_kind=object_kind,
        allowed_categorical_values=("family-a",) if mode is ClaimMode.POSITIVE else (),
    )
    question = build_question(
        question_type=QuestionType.RESOLVE_FAMILY,
        subjects=(SUBJECT,),
        allowed_conclusions=(conclusion,),
    )
    events = (
        make_event((), EventType.RUN_OPENED, make_actor(), FIXED_TIME, run),
    )
    events = append_record(events, EventType.QUESTION_OPENED, question)
    supporting_ids: tuple[str, ...] = ()
    if mode is ClaimMode.POSITIVE:
        observation = build_observation(
            observation_type="family-anchor",
            subjects=(SUBJECT,),
            value=ObservationValue(
                kind=ObservationValueKind.CATEGORICAL,
                categorical="family-a",
                integer=None,
                boolean=None,
                reference=None,
            ),
            source_refs=(make_locator(),),
            scope=scope,
            strength=ObservationStrength.OBSERVED,
            input_observation_ids=(),
            origin_outcome_id=None,
            producer=make_producer(),
            ownership=OwnershipValue.UNKNOWN,
            coverage_assertions=(coverage,),
        )
        events = append_record(events, EventType.OBSERVATION_ADDED, observation)
        supporting_ids = (observation.observation_id,)
    claim = build_claim_candidate(
        question_id=question.question_id,
        task=ClaimTask.FAMILY,
        claim_mode=mode,
        subjects=(SUBJECT,),
        predicate="family-membership",
        object_value=(
            ObservationValue(
                kind=ObservationValueKind.CATEGORICAL,
                categorical="family-a",
                integer=None,
                boolean=None,
                reference=None,
            )
            if mode is ClaimMode.POSITIVE
            else None
        ),
        supporting_observation_ids=supporting_ids,
        contradicting_observation_ids=(),
        excluded_observations=(),
        coverage_requirements=(
            (
                CoveragePredicate(
                    subject=SUBJECT,
                    source=source,
                    allowed_statuses=(CoverageStatus.COMPLETE,),
                ),
            )
            if mode in {ClaimMode.NEGATIVE, ClaimMode.EXHAUSTIVE}
            else ()
        ),
        coverage_context_digest=compute_coverage_context_digest((coverage,)),
        ownership=(),
        caps=(),
        unknowns=(),
        resolves_gap_ids=(),
        producer=make_producer(ProducerKind.RULE_ENGINE),
        supersedes=None,
        score=None,
    )
    return append_record(events, EventType.CLAIM_PROPOSED, claim)


def make_gap_ledger() -> tuple[LedgerEvent, ...]:
    return append_record(make_claim_ledger(), EventType.GAP_IDENTIFIED, make_gap())


def make_action_ledger(
    *, attempt_nonce: str = "2" * 32, action_type: str = "jadx-usage-query"
) -> tuple[LedgerEvent, ...]:
    return append_record(
        make_gap_ledger(),
        EventType.ACTION_PROPOSED,
        make_action(attempt_nonce=attempt_nonce, action_type=action_type),
    )


def make_authorization(
    *,
    action_id: str | None = None,
    level: AuthorizationLevel = AuthorizationLevel.OFFLINE,
    policy: PolicyRef | None = None,
    reason_codes: tuple[str, ...] = ("policy_pre_authorized",),
) -> ActionAuthorization:
    return ActionAuthorization(
        kind="action_authorization",
        schema_version="1.0",
        action_id=action_id or make_action().action_id,
        granted_level=level,
        policy=policy or make_policy(),
        reason_codes=reason_codes,
    )


def make_completed_action_ledger(
    *, attempt_nonce: str = "2" * 32
) -> tuple[LedgerEvent, ...]:
    events = make_action_ledger(attempt_nonce=attempt_nonce)
    action = events[-1].payload
    assert isinstance(action, NextAction)
    events = append_record(
        events,
        EventType.ACTION_AUTHORIZED,
        make_authorization(action_id=action.action_id),
    )
    outcome = build_action_outcome(
        action_id=action.action_id,
        status=OutcomeStatus.COMPLETE,
        output_anchors=(),
        coverage_assertions=(),
        reason_codes=(),
        diagnostics_locator=None,
        usage=ActionUsage(elapsed_ms=10, peak_memory_mb=128, output_bytes=256),
        producer=make_producer(ProducerKind.QUERY),
    )
    return append_record(events, EventType.ACTION_OUTCOME_RECORDED, outcome)


def make_candidate_label_feedback() -> object:
    from apkscan.core.recognition_codec import build_candidate_label_feedback
    from apkscan.core.recognition_contract import LabelKind

    return build_candidate_label_feedback(
        label_kind=LabelKind.FAMILY_ASSIGNMENT,
        proposed_label_digest=DIGEST_A,
        subject_refs=(SUBJECT,),
        evidence_ref="bundle:2026/fixture-feedback",
        reason_codes=("fixture-feedback",),
        policy=make_policy(),
        producer=make_producer(ProducerKind.SYSTEM),
    )


def make_full_ten_event_ledger() -> tuple[LedgerEvent, ...]:
    """覆盖全部事件类型的金样账本（P4-B 起含第 11 类 FEEDBACK_QUEUED）。"""
    events = make_claim_ledger()
    original = events[-1].payload
    assert isinstance(original, ClaimCandidate)
    events = append_record(events, EventType.GAP_IDENTIFIED, make_gap())
    events = append_record(events, EventType.ACTION_PROPOSED, make_action())
    events = append_record(events, EventType.ACTION_AUTHORIZED, make_authorization())
    events = append_record(events, EventType.ACTION_OUTCOME_RECORDED, make_outcome())
    revised = build_claim_candidate(
        question_id=original.question_id,
        task=original.task,
        claim_mode=original.claim_mode,
        subjects=original.subjects,
        predicate=original.predicate,
        object_value=original.object_value,
        supporting_observation_ids=original.supporting_observation_ids,
        contradicting_observation_ids=original.contradicting_observation_ids,
        excluded_observations=original.excluded_observations,
        coverage_requirements=original.coverage_requirements,
        coverage_context_digest=original.coverage_context_digest,
        ownership=original.ownership,
        caps=original.caps,
        unknowns=("post-action-confirmed",),
        resolves_gap_ids=(make_gap().gap_id,),
        producer=original.producer,
        supersedes=original.claim_id,
        score=original.score,
    )
    events = append_record(events, EventType.CLAIM_REVISED, revised)
    decision = build_review_decision(
        question_id=revised.question_id,
        claim_id=revised.claim_id,
        decision=ReviewDecisionValue.ACCEPTED,
        reviewer=make_actor(ActorKind.HUMAN),
        basis_head_digest=events[-1].event_digest,
        basis_observation_ids=revised.supporting_observation_ids,
        gap_ids=(),
        reason_codes=("manual-review",),
    )
    events = append_record(
        events,
        EventType.REVIEW_DECIDED,
        decision,
        actor_kind=ActorKind.HUMAN,
    )
    return append_record(
        events,
        EventType.FEEDBACK_QUEUED,
        make_candidate_label_feedback(),
        actor_kind=ActorKind.HUMAN,
    )
