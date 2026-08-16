"""P4-B 红态契约：FEEDBACK_QUEUED 账本事件（第 11 类）。

核心不变量（设计见本地 P4 v2 spec §2/§6.4）：
- 新实体 CandidateLabelFeedback（内容寻址 seal；label_kind 五值 closed-world；
  proposed_label_digest 只锁形态——账本不内嵌标签内容）；
- actor 规则：MODEL 禁止入队（HUMAN=XLSX 纠正、SYSTEM=规则队列自动入队可以）；
- 事件 envelope schema_version 保持 "1.0"（additive）：旧十类账本在新 reader 全有效；
  unknown event_type 在 decode 层 fail-closed（不静默跳过）；
- replay 落 feedbacks 投影；同一 feedback 重复入队被链级 record 身份拒绝。
"""

from __future__ import annotations

import pytest

from apkscan.core import judgment_ledger as jl
from apkscan.core import recognition_codec as codec
from apkscan.core import recognition_contract as rc
from tests.recognition_fixtures import (
    DIGEST_A,
    FIXED_TIME,
    SUBJECT,
    make_actor,
    make_full_ten_event_ledger,
    make_policy,
    make_producer,
    make_question_ledger,
)


def _feedback(**over: object):
    from typing import Any

    fields: dict[str, Any] = dict(
        label_kind=rc.LabelKind.FAMILY_ASSIGNMENT,
        proposed_label_digest=DIGEST_A,
        subject_refs=(SUBJECT,),
        evidence_ref="bundle:2026/feedback-0001",
        reason_codes=("xlsx-correction",),
        policy=make_policy(),
        producer=make_producer(rc.ProducerKind.SYSTEM),
    )
    fields.update(over)
    return codec.build_candidate_label_feedback(**fields)


def _queued(actor_kind: rc.ActorKind = rc.ActorKind.HUMAN):
    events = make_question_ledger()
    event = jl.make_event(
        events,
        jl.EventType.FEEDBACK_QUEUED,
        make_actor(actor_kind),
        FIXED_TIME,
        _feedback(),
    )
    return jl.append_event(events, event)


# ---------------------------------------------------------------- 实体契约


def test_label_kind_covers_exactly_the_five_label_record_kinds():
    assert {member.value for member in rc.LabelKind} == {
        "family_assignment",
        "clue_judgment",
        "relation_judgment",
        "ownership_judgment",
        "reanalysis_outcome",
    }


def test_feedback_entity_is_content_addressed_and_deterministic():
    assert _feedback().feedback_id == _feedback().feedback_id


@pytest.mark.parametrize(
    "override",
    [
        {"label_kind": rc.LabelKind.CLUE_JUDGMENT},
        {"proposed_label_digest": "sha256:" + "d" * 64},
        {"subject_refs": (rc.SubjectRef(kind=rc.SubjectKind.SAMPLE, value="sample-b", role=None),)},
        {"evidence_ref": None},
        {"reason_codes": ("another-reason",)},
        {"policy": rc.PolicyRef(policy_id="other-policy", version="2.0", digest=DIGEST_A)},
        {"producer": make_producer(rc.ProducerKind.MODEL)},
    ],
    ids=["label_kind", "digest", "subjects", "evidence", "reasons", "policy", "producer"],
)
def test_every_semantic_field_enters_the_seal(override):
    # codex 复审 P2：逐字段变异都必须改变 feedback_id，防 seal 漏字段。
    assert _feedback(**override).feedback_id != _feedback().feedback_id


def test_feedback_digest_form_is_validated():
    with pytest.raises(rc.SchemaValidationError):
        _feedback(proposed_label_digest="a" * 64)  # 缺 sha256: 前缀
    with pytest.raises(rc.SchemaValidationError):
        _feedback(proposed_label_digest="sha256:" + "g" * 64)


def test_feedback_empty_evidence_ref_rejected_none_allowed():
    assert _feedback(evidence_ref=None).evidence_ref is None
    with pytest.raises(rc.SchemaValidationError):
        _feedback(evidence_ref="")


# ---------------------------------------------------------------- 事件与 actor 规则


def test_feedback_event_replays_into_projection():
    events = _queued()
    projection = jl.replay(events)
    feedbacks = projection.feedbacks
    assert len(feedbacks) == 1
    assert feedbacks[0].label_kind is rc.LabelKind.FAMILY_ASSIGNMENT


def test_model_actor_cannot_queue_feedback():
    events = make_question_ledger()
    # 密封（make_event）即校验 actor 规则——拦截发生在事件进链之前。
    with pytest.raises(jl.LedgerIntegrityError) as exc:
        jl.append_event(
            events,
            jl.make_event(
                events,
                jl.EventType.FEEDBACK_QUEUED,
                make_actor(rc.ActorKind.MODEL),
                FIXED_TIME,
                _feedback(),
            ),
        )
    assert exc.value.code == "feedback_actor_forbidden"


@pytest.mark.parametrize("actor_kind", [rc.ActorKind.HUMAN, rc.ActorKind.SYSTEM])
def test_human_and_system_actors_can_queue_feedback(actor_kind):
    events = _queued(actor_kind)
    assert events[-1].event_type is jl.EventType.FEEDBACK_QUEUED


def test_wrong_payload_type_rejected():
    events = make_question_ledger()
    with pytest.raises(jl.LedgerIntegrityError) as exc:
        jl.append_event(
            events,
            jl.make_event(
                events,
                jl.EventType.FEEDBACK_QUEUED,
                make_actor(),
                FIXED_TIME,
                make_policy(),  # type: ignore[arg-type]
            ),
        )
    assert exc.value.code == "event_payload_type_mismatch"


def test_duplicate_feedback_queue_rejected_by_record_identity():
    events = _queued()
    rival = jl.make_event(
        events,
        jl.EventType.FEEDBACK_QUEUED,
        make_actor(rc.ActorKind.HUMAN),
        FIXED_TIME,
        _feedback(),
    )
    with pytest.raises(jl.LedgerIntegrityError) as exc:
        jl.append_event(events, rival)
    assert exc.value.code == "duplicate_record_id"


# ---------------------------------------------------------------- 兼容面（P4 spec §6.4）


def test_legacy_ledger_without_feedback_still_valid_under_new_reader():
    # 旧十类事件链（不含 feedback）在新 reader 下全部有效、feedbacks 投影为空。
    from tests.recognition_fixtures import make_completed_action_ledger

    events = make_completed_action_ledger()
    jl.validate_event_chain(events)
    projection = jl.replay(events)
    assert projection.feedbacks == ()


def test_full_ledger_covers_all_eleven_event_types():
    events = make_full_ten_event_ledger()
    assert {event.event_type for event in events} == set(jl.EventType)
    projection = jl.replay(events)
    assert len(projection.feedbacks) == 1


def test_feedback_event_wire_roundtrip():
    events = _queued()
    encoded = jl.encode_event(events[-1])
    decoded = jl.decode_event(encoded)
    assert decoded == events[-1]
    assert '"schema_version": "1.0"' in encoded or '"schema_version":"1.0"' in encoded


def test_unknown_event_type_decode_fails_closed():
    events = _queued()
    encoded = jl.encode_event(events[-1])
    tampered = encoded.replace("feedback_queued", "feedback_promoted")
    with pytest.raises(rc.SchemaValidationError) as exc:
        jl.decode_event(tampered)
    assert exc.value.code == "enum_value_required"
    assert exc.value.field_path == "$.event_type"
