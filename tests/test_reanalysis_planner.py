"""P3-B 红态契约：apkscan/core/reanalysis.py（planner 纯函数）的行为规范。

核心不变量（设计见本地 P3 v4 spec §3/§4/§6）：
- 准入谓词 v1：只吃 OPEN gap；BLOCKS_* 才可能高价值；REDUCES_CONFIDENCE 走白名单；
  未知 reason 只 suppress 并计数，绝不静默映射；
- 同 dedupe 合并：同一 analysis_type 的多 gap 并成恰一个 NextAction（gap_ids 并集排序），
  nonce 救不了底座的 dedupe 先检，必须在生成层合并；
- ceiling 只过滤不改声明：authorization_required 恒等于矩阵值；
- 抑制永不静默：四类 suppress всё进 receipt 计数；
- 版本 token fail-closed；同输入恒同输出。
"""

from __future__ import annotations

import dataclasses
import re

import pytest

from apkscan.core import reanalysis as rp
from apkscan.core import reanalysis_contract as rxc
from apkscan.core.judgment_ledger import GapStatus
from apkscan.core.recognition_codec import build_evidence_gap
from apkscan.core.recognition_contract import (
    AuthorizationLevel,
    GapEffect,
    ProducerKind,
    SchemaValidationError,
)
from tests.recognition_fixtures import (
    make_anchor,
    make_producer,
    make_question,
)

SAMPLE_DIGEST = "sha256:" + "f" * 64
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")


def _gap(
    *,
    effect: GapEffect = GapEffect.BLOCKS_REVIEW,
    reasons: tuple[str, ...] = ("fixture-callpath-gap",),
    required: tuple[str, ...] = ("jadx_value_usage",),
):
    return build_evidence_gap(
        question_id=make_question().question_id,
        claim_id=None,
        effect=effect,
        reason_codes=reasons,
        required_observation_types=required,
        producer=make_producer(ProducerKind.SYSTEM),
        coverage_requirements=(),
    )


def _context(
    gaps,
    *,
    ceiling: AuthorizationLevel = AuthorizationLevel.AUTHORIZED_DEVICE,
    statuses: dict[str, GapStatus] | None = None,
):
    return rxc.PlanningContext(
        question=make_question(),
        gaps=tuple(gaps),
        gap_statuses=statuses
        if statuses is not None
        else {gap.gap_id: GapStatus.OPEN for gap in gaps},
        anchors=(make_anchor(),),
        supporting_observation_ids=(),
        contradicting_observation_ids=(),
        authorization_ceiling=ceiling,
        sample_digest=SAMPLE_DIGEST,
    )


def _policy(
    mapping: dict[str, tuple[rxc.AnalysisType, ...]] | None = None,
    *,
    whitelist: frozenset[str] = frozenset(),
):
    return rp.AdmissionPolicy(
        predicate_version="p3-admit-v1",  # 谓词语义由代码实现，只认支持集内的版本
        mapping_version="test-mapping-v1",
        reason_mapping=mapping or {},
        reduces_confidence_whitelist=whitelist,
    )


_PRODUCER = make_producer(ProducerKind.SYSTEM)


def _plan(context, policy):
    return rp.plan_reanalysis(context, producer=_PRODUCER, policy=policy)


_CALLPATH = rxc.AnalysisType.JADX_CALLPATH
_PCAP = rxc.AnalysisType.PCAP_RUNTIME


# ---------------------------------------------------------------- 默认策略与版本


def test_default_policy_is_versioned_and_production_populated():
    """P3-E3 语义演进：生产映射从「刻意空表」翻转为 v2 实表（21 键，见
    test_production_mapping_v2_shape 的逐键锁）；whitelist 仍空。"""
    policy = rp.DEFAULT_ADMISSION_POLICY
    assert policy.predicate_version and policy.mapping_version
    assert policy.reason_mapping  # 空表时代结束（P3-E3）
    assert not policy.reduces_confidence_whitelist


def test_blank_version_tokens_fail_closed():
    for field in ("predicate_version", "mapping_version"):
        bad = dataclasses.replace(_policy(), **{field: ""})
        with pytest.raises(SchemaValidationError):
            _plan(_context([_gap()]), bad)


def test_unknown_predicate_version_fails_closed():
    # codex 复审 P1：非空但未支持的版本 = 宣称本模块没有的谓词语义，必须拒。
    bad = dataclasses.replace(_policy(), predicate_version="totally-unknown-v9")
    with pytest.raises(SchemaValidationError) as exc:
        _plan(_context([_gap()]), bad)
    assert exc.value.code == "predicate_version_unsupported"


def test_empty_mapping_entry_fails_closed():
    # codex 复审 P1：已知 reason 映射到空集会造成静默零授予面，策略层直接拒。
    with pytest.raises(SchemaValidationError) as exc:
        _plan(_context([_gap()]), _policy({"fixture-callpath-gap": ()}))
    assert exc.value.code == "reason_mapping_empty_entry"


def test_duplicate_gap_in_context_fails_closed():
    # codex 复审 P2：重复 gap 会让 receipt 授予计数与 gap_ids 去重结果失配。
    gap = _gap()
    context = dataclasses.replace(_context([gap]), gaps=(gap, gap))
    with pytest.raises(SchemaValidationError) as exc:
        _plan(context, _policy({"fixture-callpath-gap": (_CALLPATH,)}))
    assert exc.value.code == "gap_duplicate"


def test_coverage_only_gap_gets_fallback_success_criteria():
    # 合法 gap 可以只带 coverage_requirements；planner 必须给非空 success_criteria。
    from apkscan.core.recognition_contract import (
        CoveragePredicate,
        CoverageSource,
        CoverageStatus,
    )
    from tests.recognition_fixtures import SUBJECT

    coverage_only = build_evidence_gap(
        question_id=make_question().question_id,
        claim_id=None,
        effect=GapEffect.BLOCKS_REVIEW,
        reason_codes=("fixture-coverage-gap",),
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
    result = _plan(
        _context([coverage_only]),
        _policy({"fixture-coverage-gap": (_CALLPATH,)}),
    )
    assert len(result.planned) == 1
    assert result.planned[0].action.success_criteria == ("coverage_requirements_satisfied",)


# ---------------------------------------------------------------- 准入谓词


def test_open_blocks_gap_with_mapped_reason_is_admitted():
    gap = _gap()
    result = _plan(_context([gap]), _policy({"fixture-callpath-gap": (_CALLPATH,)}))
    assert len(result.planned) == 1
    planned = result.planned[0]
    assert planned.action.action_type == "jadx_callpath"
    assert planned.action.gap_ids == (gap.gap_id,)
    assert planned.action.authorization_required is AuthorizationLevel.OFFLINE
    assert result.receipt.emitted == (("jadx_callpath", 1),)


def test_non_open_gap_is_suppressed_and_counted():
    gap = _gap()
    context = _context([gap], statuses={gap.gap_id: GapStatus.ADDRESSED})
    result = _plan(context, _policy({"fixture-callpath-gap": (_CALLPATH,)}))
    assert result.planned == ()
    assert result.receipt.suppressed_not_open == 1
    assert result.receipt.emitted == ()


def test_unknown_reason_suppresses_without_silent_mapping():
    gap = _gap(reasons=("nobody-knows-this-reason",))
    result = _plan(_context([gap]), _policy({"fixture-callpath-gap": (_CALLPATH,)}))
    assert result.planned == ()
    assert result.receipt.suppressed_unknown_reason == 1


def test_reduces_confidence_outside_whitelist_is_low_value():
    gap = _gap(effect=GapEffect.REDUCES_CONFIDENCE)
    result = _plan(_context([gap]), _policy({"fixture-callpath-gap": (_CALLPATH,)}))
    assert result.planned == ()
    assert result.receipt.suppressed_low_value == 1


def test_reduces_confidence_whitelisted_reason_is_admitted():
    gap = _gap(effect=GapEffect.REDUCES_CONFIDENCE)
    policy = _policy(
        {"fixture-callpath-gap": (_CALLPATH,)},
        whitelist=frozenset({"fixture-callpath-gap"}),
    )
    result = _plan(_context([gap]), policy)
    assert len(result.planned) == 1
    assert result.receipt.suppressed_low_value == 0


def test_unmapped_fixture_reason_stays_suppressed():
    # P3-E3 改名改注：v2 实表下未映射 reason（夹具值）仍诚实抑制、receipt 记因。
    result = _plan(_context([_gap()]), rp.DEFAULT_ADMISSION_POLICY)
    assert result.planned == ()
    assert result.receipt.suppressed_unknown_reason == 1


# ---------------------------------------------------------------- 同 dedupe 合并


def test_two_gaps_same_type_merge_into_exactly_one_action():
    gap_one = _gap(reasons=("fixture-callpath-gap",), required=("obs-a",))
    gap_two = _gap(reasons=("fixture-callpath-two",), required=("obs-b",))
    policy = _policy(
        {
            "fixture-callpath-gap": (_CALLPATH,),
            "fixture-callpath-two": (_CALLPATH,),
        }
    )
    result = _plan(_context([gap_one, gap_two]), policy)
    assert len(result.planned) == 1
    action = result.planned[0].action
    assert action.gap_ids == tuple(sorted((gap_one.gap_id, gap_two.gap_id)))
    assert action.success_criteria == ("obs-a", "obs-b")
    assert result.receipt.emitted == (("jadx_callpath", 2),)


def test_one_gap_two_types_produces_two_actions_not_deduped():
    gap = _gap(reasons=("fixture-dual-gap",))
    policy = _policy({"fixture-dual-gap": (_CALLPATH, rxc.AnalysisType.JADX_STRUCTURAL_DIFF)})
    result = _plan(_context([gap]), policy)
    assert len(result.planned) == 2
    types = {planned.action.action_type for planned in result.planned}
    assert types == {"jadx_callpath", "jadx_structural_diff"}
    dedupe_keys = {planned.action.dedupe_key for planned in result.planned}
    assert len(dedupe_keys) == 2


def test_planned_actions_are_sorted_by_analysis_type():
    gap = _gap(reasons=("fixture-dual-gap",))
    policy = _policy({"fixture-dual-gap": (rxc.AnalysisType.JADX_STRUCTURAL_DIFF, _CALLPATH)})
    result = _plan(_context([gap]), policy)
    listed = [planned.action.action_type for planned in result.planned]
    assert listed == sorted(listed)


# ---------------------------------------------------------------- ceiling 三不变量


def test_full_ceiling_matrix_filters_without_mutating_declaration():
    # 3 ceiling × 8 类型全组合（R1 锁 8/9）：产出当且仅当矩阵值 ≤ ceiling，
    # 且 authorization_required 恒等于矩阵值——ceiling 只过滤，绝不改声明。
    for ceiling in AuthorizationLevel:
        for analysis_type in rxc.AnalysisType:
            reason = f"fixture-{analysis_type.value.replace('_', '-')}"
            gap = _gap(reasons=(reason,))
            result = _plan(
                _context([gap], ceiling=ceiling),
                _policy({reason: (analysis_type,)}),
            )
            required = rxc.ANALYSIS_AUTHORIZATION[analysis_type]
            expected_emit = rxc.AUTHORIZATION_ORDER[required] <= rxc.AUTHORIZATION_ORDER[ceiling]
            if expected_emit:
                assert len(result.planned) == 1, (ceiling, analysis_type)
                assert result.planned[0].action.authorization_required is required
            else:
                assert result.planned == (), (ceiling, analysis_type)
                assert result.receipt.suppressed_by_ceiling == ((analysis_type.value, 1),)


def test_ceiling_suppression_is_counted_by_type():
    gap = _gap(reasons=("fixture-pcap-gap",))
    result = _plan(
        _context([gap], ceiling=AuthorizationLevel.OFFLINE),
        _policy({"fixture-pcap-gap": (_PCAP,)}),
    )
    assert result.planned == ()
    assert result.receipt.suppressed_by_ceiling == (("pcap_runtime", 1),)


# ---------------------------------------------------------------- nonce 三类黄金测试


def test_attempt_nonce_is_deterministic_32_hex():
    nonce = rp.derive_attempt_nonce(
        dedupe_key="sha256:" + "a" * 64,
        question_id="question-1",
        gap_ids=("gap-b", "gap-a"),
    )
    again = rp.derive_attempt_nonce(
        dedupe_key="sha256:" + "a" * 64,
        question_id="question-1",
        gap_ids=("gap-a", "gap-b"),  # 顺序无关：内部排序
    )
    assert nonce == again
    assert _HEX32.fullmatch(nonce)


def test_attempt_nonce_changes_with_question_but_not_dedupe():
    dedupe = "sha256:" + "a" * 64
    one = rp.derive_attempt_nonce(dedupe_key=dedupe, question_id="question-1", gap_ids=("gap-a",))
    two = rp.derive_attempt_nonce(dedupe_key=dedupe, question_id="question-2", gap_ids=("gap-a",))
    assert one != two


def test_attempt_nonce_changes_with_gap_ids():
    dedupe = "sha256:" + "a" * 64
    one = rp.derive_attempt_nonce(dedupe_key=dedupe, question_id="question-1", gap_ids=("gap-a",))
    two = rp.derive_attempt_nonce(
        dedupe_key=dedupe, question_id="question-1", gap_ids=("gap-a", "gap-b")
    )
    assert one != two


def test_attempt_nonce_changes_when_dedupe_fields_change():
    one = rp.derive_attempt_nonce(dedupe_key="sha256:" + "a" * 64, question_id="q", gap_ids=("g",))
    two = rp.derive_attempt_nonce(dedupe_key="sha256:" + "b" * 64, question_id="q", gap_ids=("g",))
    assert one != two


# ---------------------------------------------------------------- 产物完整性


def test_planned_action_fields_are_wired_from_context():
    gap = _gap()
    context = _context([gap])
    result = _plan(context, _policy({"fixture-callpath-gap": (_CALLPATH,)}))
    action = result.planned[0].action
    assert action.question_id == context.question.question_id
    assert action.subjects == context.question.subjects
    assert action.input_anchor_ids == tuple(sorted(anchor.anchor_id for anchor in context.anchors))
    assert action.attempt_nonce == rp.derive_attempt_nonce(
        dedupe_key=action.dedupe_key,
        question_id=action.question_id,
        gap_ids=action.gap_ids,
    )
    # planner 产物必须能直接过 P3-A 投影（同一契约宇宙）。
    request = rxc.project_reanalysis_request(action, context, result.planned[0].meta)
    assert request.request_id == action.action_id


def test_priority_class_follows_effect_ladder():
    blocks_claim = _gap(effect=GapEffect.BLOCKS_CLAIM, reasons=("fixture-a",))
    blocks_review = _gap(effect=GapEffect.BLOCKS_REVIEW, reasons=("fixture-b",))
    policy = _policy({"fixture-a": (_CALLPATH,), "fixture-b": (_CALLPATH,)})

    high = _plan(_context([blocks_claim]), policy)
    assert high.planned[0].meta.priority_class is rxc.PriorityClass.HIGH

    review = _plan(_context([blocks_review]), policy)
    assert review.planned[0].meta.priority_class is rxc.PriorityClass.REVIEW

    low_gap = _gap(effect=GapEffect.REDUCES_CONFIDENCE, reasons=("fixture-c",))
    low = _plan(
        _context([low_gap]),
        _policy({"fixture-c": (_CALLPATH,)}, whitelist=frozenset({"fixture-c"})),
    )
    assert low.planned[0].meta.priority_class is rxc.PriorityClass.LOW


def test_receipt_carries_versions_and_totals():
    gap = _gap()
    result = _plan(_context([gap]), _policy({"fixture-callpath-gap": (_CALLPATH,)}))
    receipt = result.receipt
    assert receipt.predicate_version == "p3-admit-v1"
    assert receipt.mapping_version == "test-mapping-v1"
    assert receipt.matrix_version == rxc.MATRIX_VERSION
    assert receipt.gaps_seen == 1


def test_planner_is_deterministic():
    gap = _gap()
    policy = _policy({"fixture-callpath-gap": (_CALLPATH,)})
    assert _plan(_context([gap]), policy) == _plan(_context([gap]), policy)


def test_planner_validates_context_fail_closed():
    gap = _gap()
    broken = dataclasses.replace(_context([gap]), gaps=(), gap_statuses={})
    with pytest.raises(SchemaValidationError):
        _plan(broken, _policy())


# --------------------------------------------- P3-E3：生产映射 v2（空表→实表）

_V2_SOURCES = {
    "java": _CALLPATH,
    "native": rxc.AnalysisType.NATIVE_BUILDINFO,
    "runtime": _PCAP,
}
_V2_LEVELS = ("partial", "stub_only", "opaque", "unavailable", "unknown", "timeout", "failed")


def test_production_mapping_v2_shape():
    """T1 表形状锁：21 键全展开、值合法、版本号 v2、whitelist 仍空。"""
    policy = rp.DEFAULT_ADMISSION_POLICY
    assert policy.mapping_version == "p3-mapping-v2"
    assert policy.predicate_version == "p3-admit-v1"  # 谓词没动
    assert not policy.reduces_confidence_whitelist
    expected = {
        f"{source}_visibility_{level}": (analysis,)
        for source, analysis in _V2_SOURCES.items()
        for level in _V2_LEVELS
    }
    assert dict(policy.reason_mapping) == expected


def test_java_gap_yields_callpath_proposal():
    """T2 java 缺口 → 恰 1 条 JADX_CALLPATH（BLOCKS_CLAIM → HIGH、OFFLINE）。"""
    gap = _gap(
        effect=GapEffect.BLOCKS_CLAIM,
        reasons=("claim.static_endpoint_exhaustive", "java_visibility_timeout"),
        required=("jadx_java_surface",),
    )
    planning = _plan(_context([gap]), rp.DEFAULT_ADMISSION_POLICY)
    assert len(planning.planned) == 1
    action = planning.planned[0].action
    assert action.action_type == _CALLPATH.value
    request = rxc.project_reanalysis_request(action, _context([gap]), planning.planned[0].meta)
    assert request.priority_class is rxc.PriorityClass.HIGH
    assert request.authorization is AuthorizationLevel.OFFLINE


def test_runtime_gap_respects_ceiling():
    """T3 runtime 缺口：OFFLINE ceiling 抑制入账；AUTHORIZED_DEVICE 放行 PCAP。"""
    gap = _gap(
        effect=GapEffect.BLOCKS_CLAIM,
        reasons=("claim.runtime_contact_observed", "runtime_visibility_unavailable"),
        required=("runtime_capture",),
    )
    low = _plan(_context([gap], ceiling=AuthorizationLevel.OFFLINE), rp.DEFAULT_ADMISSION_POLICY)
    assert not low.planned
    assert dict(low.receipt.suppressed_by_ceiling).get(_PCAP.value) == 1
    high = _plan(_context([gap]), rp.DEFAULT_ADMISSION_POLICY)
    assert [p.action.action_type for p in high.planned] == [_PCAP.value]


def test_claim_tokens_alone_stay_unknown():
    """T4 仅 claim.* 令牌 → unknown 抑制（身份令牌不驱动动作）。"""
    gap = _gap(effect=GapEffect.BLOCKS_CLAIM, reasons=("claim.no_sms_interception",))
    planning = _plan(_context([gap]), rp.DEFAULT_ADMISSION_POLICY)
    assert not planning.planned
    assert planning.receipt.suppressed_unknown_reason == 1


def test_bookkeeping_gap_still_low_value():
    """T5 簿记 gap（REDUCES_CONFIDENCE）→ 仍 low_value（whitelist 空锁）。"""
    gap = _gap(
        effect=GapEffect.REDUCES_CONFIDENCE, reasons=("index_observation_surface_unrecorded",)
    )
    planning = _plan(_context([gap]), rp.DEFAULT_ADMISSION_POLICY)
    assert not planning.planned
    assert planning.receipt.suppressed_low_value == 1


def test_dex_resource_gaps_stay_unknown():
    """T7 无执行器可补的面不虚授。"""
    for reason in ("dex_visibility_partial", "resource_visibility_unknown"):
        gap = _gap(effect=GapEffect.BLOCKS_CLAIM, reasons=(reason,))
        planning = _plan(_context([gap]), rp.DEFAULT_ADMISSION_POLICY)
        assert not planning.planned, reason
        assert planning.receipt.suppressed_unknown_reason == 1, reason


def test_real_producer_multisource_leaves_residual_trace():
    """E3 复审 P1 锁：真 gap 生产器多源输出——已授予源出动作且 criteria 恰可兑现、
    未授予源（dex）独立成 gap 计入 unknown 留痕。"""
    from apkscan.core.gap_production import build_visibility_gaps

    sources = {
        name: {"visibility": "complete", "why": [], "inputs_seen": []}
        for name in ("manifest", "dex", "java", "native", "resource", "runtime")
    }
    sources["dex"]["visibility"] = "partial"
    sources["java"]["visibility"] = "failed"
    doc = {
        "schema_version": "1.1",
        "sources": sources,
        "claims": {},
        "blocked_claims": ["static_endpoint_exhaustive"],
        "remediation": "not_attempted",
        "notes": [],
        "next_actions": [],
        "degraded": True,
    }
    question = make_question()
    gaps = build_visibility_gaps(doc, question_id=question.question_id, producer=_PRODUCER)
    assert len(gaps) == 2
    context = rxc.PlanningContext(
        question=question,
        gaps=gaps,
        gap_statuses={gap.gap_id: GapStatus.OPEN for gap in gaps},
        anchors=(make_anchor(),),
        supporting_observation_ids=(),
        contradicting_observation_ids=(),
        authorization_ceiling=AuthorizationLevel.AUTHORIZED_DEVICE,
        sample_digest=SAMPLE_DIGEST,
    )
    planning = _plan(context, rp.DEFAULT_ADMISSION_POLICY)
    assert [p.action.action_type for p in planning.planned] == [_CALLPATH.value]
    (planned,) = planning.planned
    assert all("dex" not in c for c in planned.action.success_criteria)
    assert planning.receipt.suppressed_unknown_reason == 1
