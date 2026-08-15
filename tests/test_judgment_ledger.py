"""Append-only judgment ledger integrity and replay contracts."""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from apkscan.core import recognition_codec
from apkscan.core.judgment_ledger import (
    ActionStatus,
    ClaimStatus,
    EventType,
    GapStatus,
    LedgerEvent,
    LedgerIntegrityError,
    QuestionStatus,
    ReferenceIntegrityError,
    ReplayTransitionError,
    decode_event,
    encode_event,
    make_event,
    replay,
    validate_event_chain,
)
from apkscan.core.recognition_contract import (
    ActionAuthorization,
    ActorKind,
    AllowedConclusion,
    AuthorizationLevel,
    CanonicalCodecError,
    ClaimCandidate,
    IdentityMismatchError,
    ClaimMode,
    ClaimTask,
    CoveragePredicate,
    CoverageSource,
    CoverageStatus,
    EvidenceLocator,
    EvidenceScope,
    LocatorKind,
    NextAction,
    ObjectKind,
    ObservationStrength,
    ObservationValue,
    ObservationValueKind,
    OwnershipValue,
    OutcomeStatus,
    PolicyRef,
    ProducerKind,
    Question,
    QuestionType,
    ReviewDecisionValue,
    SchemaValidationError,
    SubjectKind,
    SubjectOwnership,
    SubjectRef,
)
from apkscan.core.recognition_codec import (
    build_action_outcome,
    build_claim_candidate,
    build_evidence_gap,
    build_observation,
    build_question,
    build_reasoning_run,
    build_review_decision,
    compute_coverage_context_digest,
    encode_record,
)
from tests.recognition_fixtures import (
    ANCHOR_ID,
    DIGEST_B,
    FIXED_TIME,
    SUBJECT,
    append_record,
    make_actor,
    make_action,
    make_action_ledger,
    make_authorization,
    make_anchor,
    make_claim_ledger,
    make_completed_action_ledger,
    make_coverage,
    make_full_ten_event_ledger,
    make_gap,
    make_gap_ledger,
    make_locator,
    make_observation,
    make_outcome,
    make_policy,
    make_producer,
    make_question,
    make_question_ledger,
    make_reasoning_run,
    make_run_event,
)


def test_first_event_is_run_opened_and_chains_by_digest() -> None:
    first, second = make_question_ledger()

    assert first.sequence == 0
    assert first.previous_event_digest is None
    assert second.sequence == 1
    assert second.previous_event_digest == first.event_digest
    validate_event_chain((first, second))


def test_tampered_event_chain_fails_closed() -> None:
    events = make_question_ledger()
    tampered = replace(events[-1], previous_event_digest=DIGEST_B)

    with pytest.raises(LedgerIntegrityError) as caught:
        validate_event_chain((*events[:-1], tampered))

    assert caught.value.code == "previous_event_digest_mismatch"
    assert caught.value.event_sequence == 1


@pytest.mark.parametrize(
    "events, code",
    [
        ((), "run_opened_required"),
        ((make_question_ledger()[1],), "run_opened_required"),
        (
            (
                make_run_event(),
                replace(make_question_ledger()[1], sequence=3),
            ),
            "event_sequence_gap",
        ),
        (
            (
                make_run_event(),
                replace(make_question_ledger()[1], ledger_id="ledger-sha256:" + "f" * 64),
            ),
            "ledger_id_mismatch",
        ),
    ],
)
def test_event_chain_rejects_invalid_structure(events: tuple[object, ...], code: str) -> None:
    with pytest.raises(LedgerIntegrityError) as caught:
        validate_event_chain(events)  # type: ignore[arg-type]

    assert caught.value.code == code


def test_event_codec_round_trips_question_and_nested_actor_kind() -> None:
    event = make_question_ledger()[1]

    decoded = decode_event(encode_event(event))

    assert decoded == event
    assert decoded.actor.kind is ActorKind.SYSTEM


def test_event_codec_accepts_action_authorization_payload() -> None:
    first = make_run_event()
    authorization = ActionAuthorization(
        kind="action_authorization",
        schema_version="1.0",
        action_id="action-sha256:" + "d" * 64,
        granted_level=AuthorizationLevel.OFFLINE,
        policy=make_policy(),
        reason_codes=("policy_pre_authorized",),
    )
    event = make_event(
        (first,),
        EventType.ACTION_AUTHORIZED,
        make_actor(ActorKind.SYSTEM),
        FIXED_TIME,
        authorization,
    )

    assert decode_event(encode_event(event)) == event


def test_system_offline_authorization_requires_fixed_reason() -> None:
    first = make_run_event()
    authorization = ActionAuthorization(
        kind="action_authorization",
        schema_version="1.0",
        action_id="action-sha256:" + "d" * 64,
        granted_level=AuthorizationLevel.OFFLINE,
        policy=make_policy(),
        reason_codes=("different-reason",),
    )

    with pytest.raises(LedgerIntegrityError) as caught:
        make_event(
            (first,),
            EventType.ACTION_AUTHORIZED,
            make_actor(ActorKind.SYSTEM),
            FIXED_TIME,
            authorization,
        )

    assert caught.value.code == "authorization_reason_required"


def test_stored_event_digest_is_verified_on_decode() -> None:
    event = make_question_ledger()[1]
    tampered = replace(event, event_digest=DIGEST_B)
    raw = recognition_codec.canonical_json_v1(
        recognition_codec._to_json_value(tampered)
    ).decode("utf-8")

    with pytest.raises(LedgerIntegrityError) as caught:
        decode_event(raw)

    assert caught.value.code == "event_digest_mismatch"


def test_event_encoder_has_no_unverified_escape_hatch() -> None:
    with pytest.raises(TypeError):
        encode_event(make_run_event(), verify=False)  # type: ignore[call-arg]


def test_duplicate_record_id_is_rejected_across_events() -> None:
    first, second = make_question_ledger()
    duplicate = make_event(
        (first, second),
        EventType.QUESTION_OPENED,
        make_actor(),
        FIXED_TIME,
        make_question(),
    )

    with pytest.raises(LedgerIntegrityError) as caught:
        validate_event_chain((first, second, duplicate))

    assert caught.value.code == "duplicate_record_id"


def test_noncanonical_timestamp_is_rejected() -> None:
    with pytest.raises(LedgerIntegrityError) as caught:
        make_event(
            (),
            EventType.RUN_OPENED,
            make_actor(),
            "2026-08-16T00:00:00Z",
            make_reasoning_run(),
        )

    assert caught.value.code == "invalid_event_timestamp"


def test_replay_projects_question_observation_and_claim() -> None:
    projection = replay(make_claim_ledger())

    question_id = projection.questions[0].question_id
    claim_id = projection.claims[0].claim_id
    assert projection.question_statuses == ((question_id, QuestionStatus.AWAITING_REVIEW),)
    assert projection.claim_statuses == ((claim_id, ClaimStatus.PROPOSED),)
    assert projection.effective_claim_ids_by_question == ((question_id, (claim_id,)),)
    assert projection.event_count == 4


def test_java_partial_keeps_positive_but_blocks_negative() -> None:
    positive = replay(make_claim_ledger(mode=ClaimMode.POSITIVE, status=CoverageStatus.PARTIAL))
    assert positive.effective_claim_ids_by_question

    with pytest.raises(ReplayTransitionError) as caught:
        replay(make_claim_ledger(mode=ClaimMode.NEGATIVE, status=CoverageStatus.PARTIAL))

    assert caught.value.code == "negative_coverage_not_complete"


def test_stale_positive_coverage_digest_is_rejected() -> None:
    events = make_claim_ledger()
    original = events[-1].payload
    assert isinstance(original, ClaimCandidate)
    stale = build_claim_candidate(
        **{
            **{
                field: getattr(original, field)
                for field in (
                    "question_id",
                    "task",
                    "claim_mode",
                    "subjects",
                    "predicate",
                    "object_value",
                    "supporting_observation_ids",
                    "contradicting_observation_ids",
                    "excluded_observations",
                    "coverage_requirements",
                    "ownership",
                    "caps",
                    "unknowns",
                    "resolves_gap_ids",
                    "producer",
                    "supersedes",
                    "score",
                )
            },
            "coverage_context_digest": DIGEST_B,
        }
    )
    prefix = events[:-1]

    with pytest.raises(ReplayTransitionError) as caught:
        replay(append_record(prefix, EventType.CLAIM_PROPOSED, stale))

    assert caught.value.code == "coverage_context_stale"


def test_observation_cannot_reference_unknown_anchor() -> None:
    events = make_question_ledger()
    unknown_locator = EvidenceLocator(
        anchor_id=ANCHOR_ID,
        kind=LocatorKind.JSON_POINTER,
        value="/unknown",
        start=None,
        end=None,
    )
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
        source_refs=(unknown_locator,),
        scope=EvidenceScope.CASE_EVIDENCE,
        strength=ObservationStrength.OBSERVED,
        input_observation_ids=(),
        origin_outcome_id=None,
        producer=make_producer(),
        ownership=OwnershipValue.UNKNOWN,
        coverage_assertions=(),
    )

    with pytest.raises(ReferenceIntegrityError) as caught:
        replay(append_record(events, EventType.OBSERVATION_ADDED, observation))

    assert caught.value.code == "unknown_anchor"


def test_claim_task_and_subjects_must_match_question() -> None:
    events = make_claim_ledger()
    original = events[-1].payload
    assert isinstance(original, ClaimCandidate)
    other_subject = SubjectRef(kind=SubjectKind.SAMPLE, value="sample-b", role=None)
    mismatches = (
        ("claim_task_mismatch", {"task": ClaimTask.CLUE}),
        ("claim_subject_mismatch", {"subjects": (other_subject,)}),
    )
    for code, changes in mismatches:
        body = {
            field: getattr(original, field)
            for field in (
                "question_id",
                "task",
                "claim_mode",
                "subjects",
                "predicate",
                "object_value",
                "supporting_observation_ids",
                "contradicting_observation_ids",
                "excluded_observations",
                "coverage_requirements",
                "coverage_context_digest",
                "ownership",
                "caps",
                "unknowns",
                "resolves_gap_ids",
                "producer",
                "supersedes",
                "score",
            )
        }
        body.update(changes)
        claim = build_claim_candidate(**body)  # type: ignore[arg-type]
        with pytest.raises(ReplayTransitionError) as caught:
            replay(append_record(events[:-1], EventType.CLAIM_PROPOSED, claim))
        assert caught.value.code == code


def test_non_unknown_ownership_requires_case_support() -> None:
    events = make_claim_ledger(scope=EvidenceScope.BATCH_REFERENCE)
    original = events[-1].payload
    assert isinstance(original, ClaimCandidate)
    ownership = SubjectOwnership(
        subject=SUBJECT,
        value=OwnershipValue.SUSPECT_FIRST_PARTY,
        supporting_observation_ids=original.supporting_observation_ids,
    )
    claim = build_claim_candidate(
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
        ownership=(ownership,),
        caps=original.caps,
        unknowns=original.unknowns,
        resolves_gap_ids=original.resolves_gap_ids,
        producer=original.producer,
        supersedes=None,
        score=None,
    )

    with pytest.raises(ReplayTransitionError) as caught:
        replay(append_record(events[:-1], EventType.CLAIM_PROPOSED, claim))

    assert caught.value.code == "ownership_evidence_not_authoritative"


def test_claim_revision_preserves_and_supersedes_old_claim() -> None:
    events = make_claim_ledger()
    old_claim = events[-1].payload
    assert isinstance(old_claim, ClaimCandidate)
    revised = build_claim_candidate(
        question_id=old_claim.question_id,
        task=old_claim.task,
        claim_mode=old_claim.claim_mode,
        subjects=old_claim.subjects,
        predicate=old_claim.predicate,
        object_value=old_claim.object_value,
        supporting_observation_ids=old_claim.supporting_observation_ids,
        contradicting_observation_ids=old_claim.contradicting_observation_ids,
        excluded_observations=old_claim.excluded_observations,
        coverage_requirements=old_claim.coverage_requirements,
        coverage_context_digest=old_claim.coverage_context_digest,
        ownership=old_claim.ownership,
        caps=old_claim.caps,
        unknowns=("needs-second-anchor",),
        resolves_gap_ids=old_claim.resolves_gap_ids,
        producer=old_claim.producer,
        supersedes=old_claim.claim_id,
        score=old_claim.score,
    )
    projection = replay(append_record(events, EventType.CLAIM_REVISED, revised))

    assert old_claim in projection.claims
    assert projection.claim_statuses == tuple(
        sorted(
            (
                (old_claim.claim_id, ClaimStatus.SUPERSEDED),
                (revised.claim_id, ClaimStatus.PROPOSED),
            )
        )
    )


def test_gap_resolution_requires_supporting_observation_type() -> None:
    events = make_claim_ledger()
    question = events[1].payload
    old_claim = events[-1].payload
    assert isinstance(question, Question)
    assert isinstance(old_claim, ClaimCandidate)
    gap = build_evidence_gap(
        question_id=question.question_id,
        claim_id=old_claim.claim_id,
        effect=make_gap().effect,
        reason_codes=("missing-runtime-anchor",),
        required_observation_types=("runtime-anchor",),
        coverage_requirements=(),
        producer=make_producer(ProducerKind.SYSTEM),
    )
    events = append_record(events, EventType.GAP_IDENTIFIED, gap)
    revised = build_claim_candidate(
        question_id=old_claim.question_id,
        task=old_claim.task,
        claim_mode=old_claim.claim_mode,
        subjects=old_claim.subjects,
        predicate=old_claim.predicate,
        object_value=old_claim.object_value,
        supporting_observation_ids=old_claim.supporting_observation_ids,
        contradicting_observation_ids=old_claim.contradicting_observation_ids,
        excluded_observations=old_claim.excluded_observations,
        coverage_requirements=old_claim.coverage_requirements,
        coverage_context_digest=old_claim.coverage_context_digest,
        ownership=old_claim.ownership,
        caps=old_claim.caps,
        unknowns=(),
        resolves_gap_ids=(gap.gap_id,),
        producer=old_claim.producer,
        supersedes=old_claim.claim_id,
        score=old_claim.score,
    )

    with pytest.raises(ReplayTransitionError) as caught:
        replay(append_record(events, EventType.CLAIM_REVISED, revised))

    assert caught.value.code == "gap_resolution_not_satisfied"


def test_action_moves_from_proposed_to_authorized_to_complete() -> None:
    events = make_action_ledger()
    action = events[-1].payload
    assert isinstance(action, NextAction)
    proposed = replay(events)
    assert proposed.action_statuses == ((action.action_id, ActionStatus.PROPOSED),)

    events = append_record(
        events,
        EventType.ACTION_AUTHORIZED,
        make_authorization(action_id=action.action_id),
    )
    authorized = replay(events)
    assert authorized.action_statuses == ((action.action_id, ActionStatus.AUTHORIZED),)

    outcome = build_action_outcome(
        action_id=action.action_id,
        status=OutcomeStatus.COMPLETE,
        output_anchors=(),
        coverage_assertions=(),
        reason_codes=(),
        diagnostics_locator=None,
        usage=make_outcome().usage,
        producer=make_producer(ProducerKind.QUERY),
    )
    completed = replay(append_record(events, EventType.ACTION_OUTCOME_RECORDED, outcome))
    assert completed.action_statuses == ((action.action_id, ActionStatus.COMPLETE),)
    assert completed.gap_statuses == ((make_gap().gap_id, GapStatus.ADDRESSED),)


def test_action_authorization_requires_exact_level_and_known_policy() -> None:
    events = make_action_ledger()
    action = events[-1].payload
    assert isinstance(action, NextAction)
    cases = (
        (
            "authorization_level_mismatch",
            make_authorization(
                action_id=action.action_id,
                level=AuthorizationLevel.PASSIVE_ONLINE,
            ),
            ActorKind.HUMAN,
        ),
        (
            "authorization_policy_unknown",
            make_authorization(
                action_id=action.action_id,
                policy=PolicyRef(policy_id="other-policy", version="1.0", digest=DIGEST_B),
            ),
            ActorKind.SYSTEM,
        ),
    )
    for code, authorization, actor_kind in cases:
        with pytest.raises(ReplayTransitionError) as caught:
            replay(
                append_record(
                    events,
                    EventType.ACTION_AUTHORIZED,
                    authorization,
                    actor_kind=actor_kind,
                )
            )
        assert caught.value.code == code


def test_nonterminal_action_dedupe_is_rejected() -> None:
    events = make_action_ledger(attempt_nonce="1" * 32)
    retry = make_action(attempt_nonce="2" * 32)

    with pytest.raises(ReplayTransitionError) as caught:
        replay(append_record(events, EventType.ACTION_PROPOSED, retry))

    assert caught.value.code == "action_dedupe_nonterminal"


def test_terminal_action_can_retry_with_new_attempt_nonce() -> None:
    events = make_completed_action_ledger(attempt_nonce="1" * 32)
    retry = make_action(attempt_nonce="2" * 32)

    projection = replay(append_record(events, EventType.ACTION_PROPOSED, retry))

    assert len(projection.actions) == 2
    assert dict(projection.action_statuses)[retry.action_id] is ActionStatus.PROPOSED


def test_outcome_requires_authorization_and_is_unique() -> None:
    proposed = make_action_ledger()
    action = proposed[-1].payload
    assert isinstance(action, NextAction)
    outcome = build_action_outcome(
        action_id=action.action_id,
        status=OutcomeStatus.COMPLETE,
        output_anchors=(),
        coverage_assertions=(),
        reason_codes=(),
        diagnostics_locator=None,
        usage=make_outcome().usage,
        producer=make_producer(ProducerKind.QUERY),
    )
    with pytest.raises(ReplayTransitionError) as caught:
        replay(append_record(proposed, EventType.ACTION_OUTCOME_RECORDED, outcome))
    assert caught.value.code == "action_not_authorized"

    completed = make_completed_action_ledger()
    second = build_action_outcome(
        action_id=action.action_id,
        status=OutcomeStatus.PARTIAL,
        output_anchors=(),
        coverage_assertions=(),
        reason_codes=("more-evidence-needed",),
        diagnostics_locator=None,
        usage=make_outcome().usage,
        producer=make_producer(ProducerKind.QUERY),
    )
    with pytest.raises(ReplayTransitionError) as caught:
        replay(append_record(completed, EventType.ACTION_OUTCOME_RECORDED, second))
    assert caught.value.code == "action_outcome_exists"


def _accepted_review_events(
    *, scope: EvidenceScope = EvidenceScope.CASE_EVIDENCE,
) -> tuple[LedgerEvent, ...]:
    events = make_claim_ledger(scope=scope)
    claim = events[-1].payload
    assert isinstance(claim, ClaimCandidate)
    decision = build_review_decision(
        question_id=claim.question_id,
        claim_id=claim.claim_id,
        decision=ReviewDecisionValue.ACCEPTED,
        reviewer=make_actor(ActorKind.HUMAN),
        basis_head_digest=events[-1].event_digest,
        basis_observation_ids=claim.supporting_observation_ids,
        gap_ids=(),
        reason_codes=("manual-review",),
    )
    return append_record(
        events,
        EventType.REVIEW_DECIDED,
        decision,
        actor_kind=ActorKind.HUMAN,
    )


def test_accepted_review_closes_claim_and_question() -> None:
    projection = replay(_accepted_review_events())

    claim = projection.claims[0]
    question = projection.questions[0]
    assert projection.claim_statuses == ((claim.claim_id, ClaimStatus.ACCEPTED),)
    assert projection.question_statuses == ((question.question_id, QuestionStatus.ACCEPTED),)


def test_batch_only_positive_cannot_be_accepted() -> None:
    with pytest.raises(ReplayTransitionError) as caught:
        replay(_accepted_review_events(scope=EvidenceScope.BATCH_REFERENCE))

    assert caught.value.code == "evidence_scope_not_authoritative"


def test_review_requires_exact_pre_event_head() -> None:
    events = make_claim_ledger()
    claim = events[-1].payload
    assert isinstance(claim, ClaimCandidate)
    decision = build_review_decision(
        question_id=claim.question_id,
        claim_id=claim.claim_id,
        decision=ReviewDecisionValue.ACCEPTED,
        reviewer=make_actor(ActorKind.HUMAN),
        basis_head_digest=DIGEST_B,
        basis_observation_ids=claim.supporting_observation_ids,
        gap_ids=(),
        reason_codes=("manual-review",),
    )

    with pytest.raises(ReplayTransitionError) as caught:
        replay(
            append_record(
                events,
                EventType.REVIEW_DECIDED,
                decision,
                actor_kind=ActorKind.HUMAN,
            )
        )

    assert caught.value.code == "review_basis_head_mismatch"


def test_open_blocks_review_gap_prevents_acceptance() -> None:
    events = make_gap_ledger()
    claim = events[3].payload
    assert isinstance(claim, ClaimCandidate)
    decision = build_review_decision(
        question_id=claim.question_id,
        claim_id=claim.claim_id,
        decision=ReviewDecisionValue.ACCEPTED,
        reviewer=make_actor(ActorKind.HUMAN),
        basis_head_digest=events[-1].event_digest,
        basis_observation_ids=claim.supporting_observation_ids,
        gap_ids=(),
        reason_codes=("manual-review",),
    )

    with pytest.raises(ReplayTransitionError) as caught:
        replay(
            append_record(
                events,
                EventType.REVIEW_DECIDED,
                decision,
                actor_kind=ActorKind.HUMAN,
            )
        )

    assert caught.value.code == "blocking_gap_open"


def test_full_ten_event_golden_replay_is_stable() -> None:
    events = make_full_ten_event_ledger()
    first = replay(events)
    decoded = tuple(decode_event(encode_event(event)) for event in events)
    second = replay(decoded)

    assert tuple(event.event_type for event in events) == tuple(EventType)
    assert second == first
    assert second.event_count == 10
    assert second.head_digest == (
        "sha256:98ced47c733b74f68cdb56597a0f58e00feb10dc6bc3d589655e88ac3ca0fbef"
    )


def test_superseded_claim_bytes_are_preserved_in_golden_replay() -> None:
    events = make_full_ten_event_ledger()
    original = events[3].payload
    assert isinstance(original, ClaimCandidate)

    projection = replay(events)
    projected = next(claim for claim in projection.claims if claim.claim_id == original.claim_id)

    assert encode_record(projected) == encode_record(original)
    assert dict(projection.claim_statuses)[original.claim_id] is ClaimStatus.SUPERSEDED


def test_nested_anchor_identity_tamper_is_rejected_at_event_boundary() -> None:
    run = make_reasoning_run()
    forged_anchor = replace(run.input_anchors[0], anchor_id="anchor-sha256:" + "f" * 64)
    forged_run = build_reasoning_run(
        execution_nonce=run.execution_nonce,
        purpose=run.purpose,
        subjects=run.subjects,
        input_anchors=(forged_anchor,),
        initial_coverage=run.initial_coverage,
        policies=run.policies,
        producers=run.producers,
    )

    with pytest.raises(IdentityMismatchError) as caught:
        make_event((), EventType.RUN_OPENED, make_actor(), FIXED_TIME, forged_run)

    assert caught.value.code == "record_identity_mismatch"


def test_accepted_review_rejects_coverage_drift() -> None:
    events = make_claim_ledger()
    claim = events[-1].payload
    assert isinstance(claim, ClaimCandidate)
    drifted_coverage = make_coverage(status=CoverageStatus.PARTIAL)
    observation = build_observation(
        observation_type="coverage-refresh",
        subjects=(SUBJECT,),
        value=ObservationValue(
            kind=ObservationValueKind.BOOLEAN,
            categorical=None,
            integer=None,
            boolean=True,
            reference=None,
        ),
        source_refs=(make_locator(),),
        scope=EvidenceScope.CASE_EVIDENCE,
        strength=ObservationStrength.OBSERVED,
        input_observation_ids=(),
        origin_outcome_id=None,
        producer=make_producer(),
        ownership=OwnershipValue.UNKNOWN,
        coverage_assertions=(drifted_coverage,),
    )
    events = append_record(events, EventType.OBSERVATION_ADDED, observation)
    decision = build_review_decision(
        question_id=claim.question_id,
        claim_id=claim.claim_id,
        decision=ReviewDecisionValue.ACCEPTED,
        reviewer=make_actor(ActorKind.HUMAN),
        basis_head_digest=events[-1].event_digest,
        basis_observation_ids=claim.supporting_observation_ids,
        gap_ids=(),
        reason_codes=("manual-review",),
    )

    with pytest.raises(ReplayTransitionError) as caught:
        replay(
            append_record(
                events,
                EventType.REVIEW_DECIDED,
                decision,
                actor_kind=ActorKind.HUMAN,
            )
        )

    assert caught.value.code == "coverage_context_stale"


def test_resolved_gap_cannot_support_unknown_review() -> None:
    events = make_full_ten_event_ledger()[:-1]
    revised = events[-1].payload
    assert isinstance(revised, ClaimCandidate)
    decision = build_review_decision(
        question_id=revised.question_id,
        claim_id=revised.claim_id,
        decision=ReviewDecisionValue.UNKNOWN,
        reviewer=make_actor(ActorKind.HUMAN),
        basis_head_digest=events[-1].event_digest,
        basis_observation_ids=(),
        gap_ids=(make_gap().gap_id,),
        reason_codes=("needs-review",),
    )

    with pytest.raises(ReplayTransitionError) as caught:
        replay(
            append_record(
                events,
                EventType.REVIEW_DECIDED,
                decision,
                actor_kind=ActorKind.HUMAN,
            )
        )

    assert caught.value.code == "review_gap_resolved"


def test_full_ten_event_every_prefix_replays_deterministically() -> None:
    events = make_full_ten_event_ledger()

    for length in range(1, len(events) + 1):
        projection = replay(events[:length])
        assert projection.event_count == length
        assert projection.head_digest == events[length - 1].event_digest


def test_negative_coverage_dex_complete_is_independent_from_java_timeout() -> None:
    dex = make_coverage(source=CoverageSource.DEX, status=CoverageStatus.COMPLETE)
    java = make_coverage(source=CoverageSource.JAVA, status=CoverageStatus.TIMEOUT)
    coverage = (dex, java)
    run = build_reasoning_run(
        execution_nonce="1" * 32,
        purpose="resolve-family",
        subjects=(SUBJECT,),
        input_anchors=(make_anchor(),),
        initial_coverage=coverage,
        policies=(make_policy(),),
        producers=(make_producer(),),
    )
    question = build_question(
        question_type=QuestionType.RESOLVE_FAMILY,
        subjects=(SUBJECT,),
        allowed_conclusions=(
            AllowedConclusion(
                predicate="family-membership",
                claim_modes=(ClaimMode.NEGATIVE,),
                object_kind=ObjectKind.NONE,
                allowed_categorical_values=(),
            ),
        ),
    )
    claim = build_claim_candidate(
        question_id=question.question_id,
        task=ClaimTask.FAMILY,
        claim_mode=ClaimMode.NEGATIVE,
        subjects=(SUBJECT,),
        predicate="family-membership",
        object_value=None,
        supporting_observation_ids=(),
        contradicting_observation_ids=(),
        excluded_observations=(),
        coverage_requirements=(
            CoveragePredicate(
                subject=SUBJECT,
                source=CoverageSource.DEX,
                allowed_statuses=(CoverageStatus.COMPLETE,),
            ),
        ),
        coverage_context_digest=compute_coverage_context_digest(coverage),
        ownership=(),
        caps=(),
        unknowns=(),
        resolves_gap_ids=(),
        producer=make_producer(ProducerKind.RULE_ENGINE),
        supersedes=None,
        score=None,
    )
    events = (make_event((), EventType.RUN_OPENED, make_actor(), FIXED_TIME, run),)
    events = append_record(events, EventType.QUESTION_OPENED, question)
    events = append_record(events, EventType.CLAIM_PROPOSED, claim)

    assert replay(events).effective_claim_ids_by_question


@pytest.mark.parametrize(
    "event_type,payload",
    [
        (EventType.OBSERVATION_ADDED, make_observation()),
        (EventType.ACTION_OUTCOME_RECORDED, make_outcome()),
    ],
)
def test_model_observation_or_outcome_actor_is_rejected(
    event_type: EventType,
    payload: object,
) -> None:
    with pytest.raises(LedgerIntegrityError) as caught:
        make_event(
            (make_run_event(),),
            event_type,
            make_actor(ActorKind.MODEL),
            FIXED_TIME,
            payload,  # type: ignore[arg-type]
        )

    assert caught.value.code == "model_evidence_actor_forbidden"


def test_accepted_question_is_terminal_for_new_gap() -> None:
    events = _accepted_review_events()

    with pytest.raises(ReplayTransitionError) as caught:
        replay(append_record(events, EventType.GAP_IDENTIFIED, make_gap()))

    assert caught.value.code == "question_already_accepted"


def test_truncated_event_json_fails_closed() -> None:
    encoded = encode_event(make_run_event())

    with pytest.raises(CanonicalCodecError):
        decode_event(encoded[:-1])


def test_reference_error_does_not_echo_raw_locator_value() -> None:
    events = make_question_ledger()
    raw_value = "/private/raw/value"
    locator = EvidenceLocator(
        anchor_id="anchor-sha256:" + "f" * 64,
        kind=LocatorKind.JSON_POINTER,
        value=raw_value,
        start=None,
        end=None,
    )
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
        source_refs=(locator,),
        scope=EvidenceScope.CASE_EVIDENCE,
        strength=ObservationStrength.OBSERVED,
        input_observation_ids=(),
        origin_outcome_id=None,
        producer=make_producer(),
        ownership=OwnershipValue.UNKNOWN,
        coverage_assertions=(),
    )

    with pytest.raises(ReferenceIntegrityError) as caught:
        replay(append_record(events, EventType.OBSERVATION_ADDED, observation))

    assert raw_value not in str(caught.value)


def test_claim_reference_value_requires_registered_anchor() -> None:
    events = (make_run_event(),)
    question = build_question(
        question_type=QuestionType.RESOLVE_FAMILY,
        subjects=(SUBJECT,),
        allowed_conclusions=(
            AllowedConclusion(
                predicate="family-reference",
                claim_modes=(ClaimMode.POSITIVE,),
                object_kind=ObjectKind.REFERENCE,
                allowed_categorical_values=(),
            ),
        ),
    )
    events = append_record(events, EventType.QUESTION_OPENED, question)
    observation = make_observation()
    events = append_record(events, EventType.OBSERVATION_ADDED, observation)
    locator = EvidenceLocator(
        anchor_id="anchor-sha256:" + "f" * 64,
        kind=LocatorKind.OPAQUE,
        value="unregistered-anchor-ref",
        start=None,
        end=None,
    )
    claim = build_claim_candidate(
        question_id=question.question_id,
        task=ClaimTask.FAMILY,
        claim_mode=ClaimMode.POSITIVE,
        subjects=(SUBJECT,),
        predicate="family-reference",
        object_value=ObservationValue(
            kind=ObservationValueKind.REFERENCE,
            categorical=None,
            integer=None,
            boolean=None,
            reference=locator,
        ),
        supporting_observation_ids=(observation.observation_id,),
        contradicting_observation_ids=(),
        excluded_observations=(),
        coverage_requirements=(),
        coverage_context_digest=compute_coverage_context_digest((make_coverage(),)),
        ownership=(),
        caps=(),
        unknowns=(),
        resolves_gap_ids=(),
        producer=make_producer(ProducerKind.RULE_ENGINE),
        supersedes=None,
        score=None,
    )

    with pytest.raises(ReferenceIntegrityError) as caught:
        replay(append_record(events, EventType.CLAIM_PROPOSED, claim))

    assert caught.value.code == "unknown_anchor"


def test_rejected_review_cannot_bypass_unsatisfied_coverage_requirement() -> None:
    events = make_claim_ledger()
    original = events[-1].payload
    assert isinstance(original, ClaimCandidate)
    claim = build_claim_candidate(
        question_id=original.question_id,
        task=original.task,
        claim_mode=original.claim_mode,
        subjects=original.subjects,
        predicate=original.predicate,
        object_value=original.object_value,
        supporting_observation_ids=original.supporting_observation_ids,
        contradicting_observation_ids=original.contradicting_observation_ids,
        excluded_observations=original.excluded_observations,
        coverage_requirements=(
            CoveragePredicate(
                subject=SUBJECT,
                source=CoverageSource.DEX,
                allowed_statuses=(CoverageStatus.COMPLETE,),
            ),
        ),
        coverage_context_digest=original.coverage_context_digest,
        ownership=original.ownership,
        caps=original.caps,
        unknowns=original.unknowns,
        resolves_gap_ids=original.resolves_gap_ids,
        producer=original.producer,
        supersedes=None,
        score=original.score,
    )
    events = append_record(events[:-1], EventType.CLAIM_PROPOSED, claim)
    decision = build_review_decision(
        question_id=claim.question_id,
        claim_id=claim.claim_id,
        decision=ReviewDecisionValue.REJECTED,
        reviewer=make_actor(ActorKind.HUMAN),
        basis_head_digest=events[-1].event_digest,
        basis_observation_ids=claim.supporting_observation_ids,
        gap_ids=(),
        reason_codes=("manual-review",),
    )

    with pytest.raises(ReplayTransitionError) as caught:
        replay(
            append_record(
                events,
                EventType.REVIEW_DECIDED,
                decision,
                actor_kind=ActorKind.HUMAN,
            )
        )

    assert caught.value.code == "claim_coverage_unsatisfied"


def test_rejected_review_allows_unrelated_coverage_drift() -> None:
    events = make_claim_ledger()
    claim = events[-1].payload
    assert isinstance(claim, ClaimCandidate)
    unrelated = build_observation(
        observation_type="unrelated-coverage-refresh",
        subjects=(SUBJECT,),
        value=ObservationValue(
            kind=ObservationValueKind.BOOLEAN,
            categorical=None,
            integer=None,
            boolean=True,
            reference=None,
        ),
        source_refs=(make_locator(),),
        scope=EvidenceScope.CASE_EVIDENCE,
        strength=ObservationStrength.OBSERVED,
        input_observation_ids=(),
        origin_outcome_id=None,
        producer=make_producer(),
        ownership=OwnershipValue.UNKNOWN,
        coverage_assertions=(
            make_coverage(source=CoverageSource.JAVA, status=CoverageStatus.PARTIAL),
        ),
    )
    events = append_record(events, EventType.OBSERVATION_ADDED, unrelated)
    decision = build_review_decision(
        question_id=claim.question_id,
        claim_id=claim.claim_id,
        decision=ReviewDecisionValue.REJECTED,
        reviewer=make_actor(ActorKind.HUMAN),
        basis_head_digest=events[-1].event_digest,
        basis_observation_ids=claim.supporting_observation_ids,
        gap_ids=(),
        reason_codes=("manual-review",),
    )

    projection = replay(
        append_record(
            events,
            EventType.REVIEW_DECIDED,
            decision,
            actor_kind=ActorKind.HUMAN,
        )
    )

    assert dict(projection.claim_statuses)[claim.claim_id] is ClaimStatus.REJECTED


def test_event_codec_rejects_dataclass_subclasses() -> None:
    @dataclass(frozen=True, slots=True)
    class ExtendedLedgerEvent(LedgerEvent):
        pass

    event = make_run_event()
    extended = ExtendedLedgerEvent(
        kind=event.kind,
        schema_version=event.schema_version,
        ledger_id=event.ledger_id,
        sequence=event.sequence,
        event_type=event.event_type,
        actor=event.actor,
        occurred_at=event.occurred_at,
        previous_event_digest=event.previous_event_digest,
        payload=event.payload,
        event_digest=event.event_digest,
    )

    with pytest.raises(LedgerIntegrityError) as caught:
        encode_event(extended)

    assert caught.value.code == "event_required"


def test_make_event_rejects_malformed_nested_payload_before_hashing() -> None:
    malformed = replace(make_observation(), producer=object())

    with pytest.raises(SchemaValidationError) as caught:
        make_event(
            make_question_ledger(),
            EventType.OBSERVATION_ADDED,
            make_actor(),
            FIXED_TIME,
            malformed,  # type: ignore[arg-type]
        )

    assert caught.value.code == "nested_contract_type_mismatch"
    assert caught.value.field_path == "$.payload.producer"


def test_replay_rejects_malformed_nested_payload_without_attribute_error() -> None:
    events = make_question_ledger()
    valid = append_record(events, EventType.OBSERVATION_ADDED, make_observation())[-1]
    malformed = replace(make_observation(), producer=object())
    tampered = replace(valid, payload=malformed)

    with pytest.raises(SchemaValidationError) as caught:
        replay((*events, tampered))

    assert caught.value.code == "nested_contract_type_mismatch"
    assert caught.value.field_path == "$.payload.producer"
