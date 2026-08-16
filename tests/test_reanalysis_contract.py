"""P3-A 红态契约：apkscan/core/reanalysis_contract.py 的行为规范。

这份测试是契约本身（设计见本地 P3 v4 spec §1/§2/§4）。核心不变量：
- AnalysisType closed-world（8 值）；授权矩阵固定、声明不可降；
- request_id := NextAction.action_id、dedupe_key 恒等（单一去重宇宙）；
- wire 拼写下划线 canonical，连字符 fail-closed（不归一化）；
- 投影 emitter 恒产 status=proposed；通用 validator 认 §8 全部状态；
- priority / current_coverage 是展示层，不进身份。
"""

from __future__ import annotations

import dataclasses

import pytest

from apkscan.core import reanalysis_contract as rx
from apkscan.core.judgment_ledger import GapStatus
from apkscan.core.recognition_codec import build_evidence_gap, build_next_action
from apkscan.core.recognition_contract import (
    ActionBudget,
    AuthorizationLevel,
    GapEffect,
    ProducerKind,
    QuestionType,
    SchemaValidationError,
)
from tests.recognition_fixtures import (
    DIGEST_A,
    DIGEST_B,
    SUBJECT,
    make_anchor,
    make_gap,
    make_producer,
    make_question,
)

SAMPLE_DIGEST = "sha256:" + "f" * 64


# ---------------------------------------------------------------- 构造辅助


def _gap(reason_codes: tuple[str, ...], required: tuple[str, ...]):
    return build_evidence_gap(
        question_id=make_question().question_id,
        claim_id=None,
        effect=GapEffect.BLOCKS_REVIEW,
        reason_codes=reason_codes,
        required_observation_types=required,
        coverage_requirements=(),
        producer=make_producer(ProducerKind.SYSTEM),
    )


def _action(
    *,
    gap_ids: tuple[str, ...],
    action_type: str = "jadx_callpath",
    authorization: AuthorizationLevel = AuthorizationLevel.OFFLINE,
):
    return build_next_action(
        question_id=make_question().question_id,
        gap_ids=gap_ids,
        attempt_nonce="3" * 32,
        action_type=action_type,
        subjects=(SUBJECT,),
        input_anchor_ids=(make_anchor().anchor_id,),
        parameters_digest=DIGEST_B,
        authorization_required=authorization,
        budget=ActionBudget(max_seconds=600, max_memory_mb=4096),
        success_criteria=("observation-recorded",),
        negative_valid_only_if=(),
        producer=make_producer(ProducerKind.SYSTEM),
    )


def _context(gaps, *, ceiling: AuthorizationLevel = AuthorizationLevel.AUTHORIZED_DEVICE):
    return rx.PlanningContext(
        question=make_question(),
        gaps=tuple(gaps),
        gap_statuses={gap.gap_id: GapStatus.OPEN for gap in gaps},
        anchors=(make_anchor(),),
        supporting_observation_ids=(),
        contradicting_observation_ids=(),
        authorization_ceiling=ceiling,
        sample_digest=SAMPLE_DIGEST,
    )


def _meta(
    *,
    priority: "rx.PriorityClass | None" = None,
    eig: float = 0.5,
    coverage: tuple[tuple[str, str], ...] = (),
):
    return rx.PlanningMeta(
        priority_class=priority or rx.PriorityClass.REVIEW,
        expected_information_gain=eig,
        current_coverage=coverage,
    )


def _projected(action_type: str = "jadx_callpath"):
    gap = _gap(("ownership-undetermined",), ("jadx_callpath_trace",))
    action = _action(gap_ids=(gap.gap_id,), action_type=action_type)
    return rx.project_reanalysis_request(action, _context([gap]), _meta()), action


# ---------------------------------------------------------------- 枚举与矩阵


def test_analysis_type_enum_is_exactly_the_eight_controlled_values():
    assert {member.value for member in rx.AnalysisType} == {
        "jadx_callpath",
        "jadx_structural_diff",
        "native_buildinfo",
        "native_function_diff",
        "web_evidence",
        "official_baseline_diff",
        "passive_enrichment",
        "pcap_runtime",
    }


def test_authorization_matrix_covers_every_type_with_fixed_levels():
    assert set(rx.ANALYSIS_AUTHORIZATION) == set(rx.AnalysisType)
    assert (
        rx.ANALYSIS_AUTHORIZATION[rx.AnalysisType.PCAP_RUNTIME]
        is AuthorizationLevel.AUTHORIZED_DEVICE
    )
    assert (
        rx.ANALYSIS_AUTHORIZATION[rx.AnalysisType.PASSIVE_ENRICHMENT]
        is AuthorizationLevel.PASSIVE_ONLINE
    )
    offline_types = set(rx.AnalysisType) - {
        rx.AnalysisType.PCAP_RUNTIME,
        rx.AnalysisType.PASSIVE_ENRICHMENT,
    }
    for analysis_type in offline_types:
        assert rx.ANALYSIS_AUTHORIZATION[analysis_type] is AuthorizationLevel.OFFLINE


def test_executor_availability_marks_only_official_baseline_diff_unavailable():
    assert set(rx.EXECUTOR_AVAILABLE) == set(rx.AnalysisType)
    for analysis_type, available in rx.EXECUTOR_AVAILABLE.items():
        expected = analysis_type is not rx.AnalysisType.OFFICIAL_BASELINE_DIFF
        assert available is expected


def test_authorization_order_is_a_total_order_over_all_levels():
    assert set(rx.AUTHORIZATION_ORDER) == set(AuthorizationLevel)
    assert (
        rx.AUTHORIZATION_ORDER[AuthorizationLevel.OFFLINE]
        < rx.AUTHORIZATION_ORDER[AuthorizationLevel.PASSIVE_ONLINE]
        < rx.AUTHORIZATION_ORDER[AuthorizationLevel.AUTHORIZED_DEVICE]
    )


def test_matrix_version_is_a_nonempty_token():
    assert isinstance(rx.MATRIX_VERSION, str) and rx.MATRIX_VERSION


# ---------------------------------------------------------------- PlanningContext


def test_planning_context_validates_a_wellformed_context():
    gap = make_gap()
    rx.validate_planning_context(_context([gap]))


def test_planning_context_rejects_empty_gaps():
    context = dataclasses.replace(_context([make_gap()]), gaps=(), gap_statuses={})
    with pytest.raises(SchemaValidationError):
        rx.validate_planning_context(context)


def test_planning_context_rejects_gap_from_another_question():
    gap = make_gap()
    foreign = dataclasses.replace(gap, question_id="question-sha256:" + "9" * 64)
    context = dataclasses.replace(
        _context([gap]),
        gaps=(foreign,),
        gap_statuses={foreign.gap_id: GapStatus.OPEN},
    )
    with pytest.raises(SchemaValidationError):
        rx.validate_planning_context(context)


def test_planning_context_rejects_missing_gap_status():
    gap = make_gap()
    context = dataclasses.replace(_context([gap]), gap_statuses={})
    with pytest.raises(SchemaValidationError):
        rx.validate_planning_context(context)


@pytest.mark.parametrize(
    "bad_digest",
    ["f" * 64, "sha256:" + "f" * 63, "sha256:" + "g" * 64, "", "sha256:"],
)
def test_planning_context_rejects_malformed_sample_digest(bad_digest):
    context = dataclasses.replace(_context([make_gap()]), sample_digest=bad_digest)
    with pytest.raises(SchemaValidationError):
        rx.validate_planning_context(context)


# ---------------------------------------------------------------- 投影：身份


def test_projection_reuses_action_identity_verbatim():
    request, action = _projected()
    assert request.request_id == action.action_id
    assert request.dedupe_key == action.dedupe_key
    assert request.status is rx.RequestStatus.PROPOSED
    assert request.subject_refs == action.subjects
    assert request.authorization is AuthorizationLevel.OFFLINE
    assert request.question_type is QuestionType.RESOLVE_FAMILY


def test_projection_display_meta_does_not_change_identity():
    gap = _gap(("ownership-undetermined",), ("jadx_callpath_trace",))
    action = _action(gap_ids=(gap.gap_id,))
    context = _context([gap])
    low = rx.project_reanalysis_request(
        action, context, _meta(priority=rx.PriorityClass.LOW, eig=0.1)
    )
    high = rx.project_reanalysis_request(
        action,
        context,
        _meta(priority=rx.PriorityClass.HIGH, eig=0.9, coverage=(("java", "partial"),)),
    )
    assert low.request_id == high.request_id == action.action_id
    assert low.dedupe_key == high.dedupe_key == action.dedupe_key


def test_projection_is_deterministic():
    first, _ = _projected()
    second, _ = _projected()
    assert first == second


# ---------------------------------------------------------------- 投影：closed-world 与矩阵


def test_projection_rejects_legacy_hyphen_action_type():
    with pytest.raises(SchemaValidationError) as exc:
        _projected(action_type="jadx-usage-query")
    assert exc.value.code == "analysis_type_unknown"


def test_projection_rejects_action_type_outside_enum():
    with pytest.raises(SchemaValidationError):
        _projected(action_type="active_probe")


def test_projection_rejects_authorization_below_matrix():
    gap = make_gap()
    action = _action(
        gap_ids=(gap.gap_id,),
        action_type="pcap_runtime",
        authorization=AuthorizationLevel.OFFLINE,
    )
    with pytest.raises(SchemaValidationError):
        rx.project_reanalysis_request(action, _context([gap]), _meta())


def test_projection_accepts_matrix_consistent_device_action():
    gap = make_gap()
    action = _action(
        gap_ids=(gap.gap_id,),
        action_type="pcap_runtime",
        authorization=AuthorizationLevel.AUTHORIZED_DEVICE,
    )
    request = rx.project_reanalysis_request(action, _context([gap]), _meta())
    assert request.analysis_type is rx.AnalysisType.PCAP_RUNTIME
    assert request.authorization is AuthorizationLevel.AUTHORIZED_DEVICE


def test_projection_rejects_action_exceeding_context_ceiling():
    # 纵深防御（codex 复审 P1）：ceiling 过滤在 planner，但绕开 planner 直调投影
    # 也必须被拦下，否则授权上限只是君子协定。
    gap = make_gap()
    action = _action(
        gap_ids=(gap.gap_id,),
        action_type="pcap_runtime",
        authorization=AuthorizationLevel.AUTHORIZED_DEVICE,
    )
    context = _context([gap], ceiling=AuthorizationLevel.OFFLINE)
    with pytest.raises(SchemaValidationError) as exc:
        rx.project_reanalysis_request(action, context, _meta())
    assert exc.value.code == "authorization_exceeds_ceiling"


# ---------------------------------------------------------------- 投影：gap 聚合与 origin


def test_projection_unions_reason_codes_and_required_observations_sorted():
    gap_one = _gap(("alpha-reason", "zeta-reason"), ("obs-b",))
    gap_two = _gap(("alpha-reason", "mid-reason"), ("obs-a", "obs-b"))
    action = _action(gap_ids=tuple(sorted((gap_one.gap_id, gap_two.gap_id))))
    request = rx.project_reanalysis_request(
        action, _context([gap_one, gap_two]), _meta()
    )
    assert request.reason_codes == ("alpha-reason", "mid-reason", "zeta-reason")
    assert request.required_observations == ("obs-a", "obs-b")


def test_projection_origin_is_gap_scoped_and_never_forges_candidate():
    request, action = _projected()
    assert request.origin.gap_ids == action.gap_ids
    assert request.origin.question_id == action.question_id
    assert request.origin.candidate_id is None
    assert request.origin.input_digest == SAMPLE_DIGEST


def test_projection_rejects_action_referencing_unknown_gap():
    gap = make_gap()
    stranger = _gap(("other-reason",), ("obs-stranger",))
    action = _action(gap_ids=(stranger.gap_id,))
    with pytest.raises(SchemaValidationError):
        rx.project_reanalysis_request(action, _context([gap]), _meta())


# ---------------------------------------------------------------- validator：全态与边界


def test_validator_accepts_every_section8_status():
    request, _ = _projected()
    for status in rx.RequestStatus:
        rx.validate_reanalysis_request(dataclasses.replace(request, status=status))


def test_validator_rejects_out_of_range_information_gain():
    request, _ = _projected()
    for bad in (-0.1, 1.1):
        with pytest.raises(SchemaValidationError):
            rx.validate_reanalysis_request(
                dataclasses.replace(request, expected_information_gain=bad)
            )


def test_validator_rejects_empty_origin_gap_ids():
    request, _ = _projected()
    origin = dataclasses.replace(request.origin, gap_ids=())
    with pytest.raises(SchemaValidationError):
        rx.validate_reanalysis_request(dataclasses.replace(request, origin=origin))


def test_validator_rejects_boolean_information_gain():
    # bool 是 int 子类（codex 复审 P2）：True 会冒充 1.0 混过数值范围检查。
    request, _ = _projected()
    with pytest.raises(SchemaValidationError):
        rx.validate_reanalysis_request(
            dataclasses.replace(request, expected_information_gain=True)
        )


def test_validator_rejects_non_dataclass_origin_with_contract_error():
    request, _ = _projected()
    with pytest.raises(SchemaValidationError) as exc:
        rx.validate_reanalysis_request(
            dataclasses.replace(request, origin=None)  # type: ignore[arg-type]
        )
    assert exc.value.code == "origin_invalid"


# ---------------------------------------------------------------- wire：编码与解码


_WIRE_KEYS = {
    "kind",
    "schema_version",
    "request_id",
    "subject_refs",
    "question_type",
    "analysis_type",
    "reason_codes",
    "current_coverage",
    "supporting_evidence_refs",
    "contradicting_evidence_refs",
    "required_observations",
    "success_criteria",
    "negative_valid_only_if",
    "priority",
    "authorization",
    "budget",
    "dedupe_key",
    "origin",
    "status",
}


def test_wire_encoding_has_exactly_the_section8_key_set():
    request, _ = _projected()
    wire = rx.encode_reanalysis_request(request)
    assert set(wire) == _WIRE_KEYS
    assert wire["kind"] == "reanalysis_request"
    assert wire["schema_version"] == "1.0"
    assert wire["status"] == "proposed"
    assert wire["authorization"] == "offline"
    assert wire["priority"] == {"class": "review", "expected_information_gain": 0.5}
    assert wire["budget"] == {"max_seconds": 600, "max_memory_mb": 4096}
    origin = wire["origin"]
    assert isinstance(origin, dict) and origin["candidate_id"] is None
    assert wire["current_coverage"] == {}


def test_wire_roundtrip_preserves_the_request():
    request, _ = _projected()
    assert rx.decode_reanalysis_request(rx.encode_reanalysis_request(request)) == request


@pytest.mark.parametrize(
    ("action_type", "level", "hyphen"),
    [
        ("passive_enrichment", AuthorizationLevel.PASSIVE_ONLINE, "passive-online"),
        ("pcap_runtime", AuthorizationLevel.AUTHORIZED_DEVICE, "authorized-device"),
    ],
)
def test_wire_decode_rejects_hyphen_authorization_without_normalizing(
    action_type, level, hyphen
):
    # ★关键：连字符归一化后的值必须与矩阵值一致，才能证明拒收出自拼写锁本身，
    # 而不是被矩阵一致性校验捎带拦下（突变验证曾揭出这个掩护洞）。
    gap = make_gap()
    action = _action(gap_ids=(gap.gap_id,), action_type=action_type, authorization=level)
    request = rx.project_reanalysis_request(action, _context([gap]), _meta())
    wire = rx.encode_reanalysis_request(request)
    assert wire["authorization"] == hyphen.replace("-", "_")
    wire["authorization"] = hyphen
    with pytest.raises(SchemaValidationError) as exc:
        rx.decode_reanalysis_request(wire)
    # 锁定拒收出自拼写锁本身（codex 复审：弱断言会被别的校验掩护）。
    assert exc.value.code == "enum_value_invalid"
    assert exc.value.field_path == "$.authorization"


def test_wire_decode_rejects_unknown_enum_values_and_keys():
    request, _ = _projected()

    wire = rx.encode_reanalysis_request(request)
    wire["analysis_type"] = "active_probe"
    with pytest.raises(SchemaValidationError):
        rx.decode_reanalysis_request(wire)

    wire = rx.encode_reanalysis_request(request)
    wire["status"] = "authorized"
    with pytest.raises(SchemaValidationError):
        rx.decode_reanalysis_request(wire)

    wire = rx.encode_reanalysis_request(request)
    wire["priority"] = {"class": "urgent", "expected_information_gain": 0.5}
    with pytest.raises(SchemaValidationError):
        rx.decode_reanalysis_request(wire)

    wire = rx.encode_reanalysis_request(request)
    wire["extra_field"] = True
    with pytest.raises(SchemaValidationError):
        rx.decode_reanalysis_request(wire)


def test_wire_decode_rejects_non_string_identity_fields():
    # cast() 不做运行时检查（codex 复审 P2）：身份字段类型混入会污染去重宇宙。
    request, _ = _projected()

    wire = rx.encode_reanalysis_request(request)
    wire["request_id"] = 123
    with pytest.raises(SchemaValidationError) as exc:
        rx.decode_reanalysis_request(wire)
    assert exc.value.code == "request_id_invalid"

    wire = rx.encode_reanalysis_request(request)
    wire["dedupe_key"] = False
    with pytest.raises(SchemaValidationError) as exc:
        rx.decode_reanalysis_request(wire)
    assert exc.value.code == "dedupe_key_invalid"


def test_wire_decode_rejects_boolean_information_gain():
    request, _ = _projected()
    wire = rx.encode_reanalysis_request(request)
    wire["priority"] = {"class": "review", "expected_information_gain": True}
    with pytest.raises(SchemaValidationError):
        rx.decode_reanalysis_request(wire)


def test_wire_encodes_nonempty_current_coverage_as_object():
    gap = _gap(("ownership-undetermined",), ("obs-x",))
    action = _action(gap_ids=(gap.gap_id,))
    request = rx.project_reanalysis_request(
        action, _context([gap]), _meta(coverage=(("java", "partial"), ("native", "complete")))
    )
    wire = rx.encode_reanalysis_request(request)
    assert wire["current_coverage"] == {"java": "partial", "native": "complete"}


# ---------------------------------------------------------------- 常量卫兵


def test_digest_fixture_shapes_still_hold():
    # 上游契约若改 digest 形态，这里先红，避免本模块的正则悄悄失配。
    assert DIGEST_A.startswith("sha256:") and len(DIGEST_A) == 71
    assert SAMPLE_DIGEST.startswith("sha256:") and len(SAMPLE_DIGEST) == 71
