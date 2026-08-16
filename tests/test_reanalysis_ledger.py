"""P3-C 红态契约：apkscan/core/reanalysis_ledger.py（账本投影 + sidecar 发布）。

核心不变量（设计见本地 P3 v4 spec §6 P3-C）：
- 单次投影调用只追加 ACTION_PROPOSED——绝无 ACTION_AUTHORIZED / OUTCOME（R1 锁 14/15）；
- 禁止复用 P2-D2 的自动授权路径（静态依赖锁点名三个函数与其模块）；
- 幂等：同 dedupe 非终态已在链上 → 跳过并记 receipt，不撞底座 dedupe 拒绝（R1 锁 17）；
- 发布走 create-only + 回读 replay，失败不落文件、不声称闭合（R1 锁 18）。
"""

from __future__ import annotations

from pathlib import Path

from apkscan.core import judgment_ledger as jl
from apkscan.core import reanalysis as rp
from apkscan.core import reanalysis_contract as rxc
from apkscan.core import reanalysis_ledger as rl
from apkscan.core.judgment_ledger import EventType
from apkscan.core.recognition_contract import (
    ActorKind,
    AuthorizationLevel,
    ProducerKind,
)
from tests.recognition_fixtures import (
    FIXED_TIME,
    make_actor,
    make_anchor,
    make_gap,
    make_gap_ledger,
    make_producer,
    make_question,
)

SAMPLE_SHA = "f" * 64


def _context():
    gap = make_gap()
    return rxc.PlanningContext(
        question=make_question(),
        gaps=(gap,),
        gap_statuses={gap.gap_id: jl.GapStatus.OPEN},
        anchors=(make_anchor(),),
        supporting_observation_ids=(),
        contradicting_observation_ids=(),
        authorization_ceiling=AuthorizationLevel.AUTHORIZED_DEVICE,
        sample_digest="sha256:" + SAMPLE_SHA,
    )


def _planned():
    # 夹具 gap 的 reason 是 "java-coverage-partial"（BLOCKS_REVIEW）。
    policy = rp.AdmissionPolicy(
        predicate_version="p3-admit-v1",
        mapping_version="test-mapping-v1",
        reason_mapping={
            "java-coverage-partial": (rxc.AnalysisType.JADX_CALLPATH,)
        },
        reduces_confidence_whitelist=frozenset(),
    )
    result = rp.plan_reanalysis(
        _context(), producer=make_producer(ProducerKind.SYSTEM), policy=policy
    )
    assert result.planned, "夹具规划必须产出动作，否则本文件全部测试失去对象"
    return result.planned


def _event_types(events):
    return [event.event_type for event in events]


# ---------------------------------------------------------------- 投影：白名单与幂等


def test_projection_appends_exactly_one_action_proposed():
    base = make_gap_ledger()
    extended, receipt = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    new_events = extended[len(base) :]
    assert [event.event_type for event in new_events] == [EventType.ACTION_PROPOSED]
    assert receipt.appended == 1
    assert receipt.skipped_nonterminal_dedupe == 0
    assert receipt.skipped_already_recorded == 0
    jl.replay(extended)  # 链必须闭合


def test_projection_never_emits_authorization_or_outcome():
    base = make_gap_ledger()
    before = _event_types(base)
    extended, _ = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    added = _event_types(extended)[len(before) :]
    assert EventType.ACTION_AUTHORIZED not in added
    assert EventType.ACTION_OUTCOME_RECORDED not in added
    assert EventType.OBSERVATION_ADDED not in added
    # 投影后动作停在 PROPOSED 状态，未被任何隐式授权推进。
    projection = jl.replay(extended)
    action = _planned()[0].action
    statuses = dict(projection.action_statuses)
    assert statuses[action.action_id] is jl.ActionStatus.PROPOSED
    assert not any(
        authorization.action_id == action.action_id
        for authorization in projection.authorizations
    )


def test_projection_is_idempotent_for_identical_replan():
    # 确定性规划：同输入恒同 action_id → 已在链上（PROPOSED 态）即同一提议的重放。
    base = make_gap_ledger()
    once, first = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    twice, second = rl.append_reanalysis_proposals(
        once, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    assert first.appended == 1
    assert second.appended == 0
    assert second.skipped_already_recorded == 1
    assert twice == once  # 不追加、不报错——幂等跳过，而不是撞底座拒绝


def test_projection_skips_after_terminal_outcome_without_crashing():
    # codex 复审 P1：终态（已授权+已出结果）后同输入重规划，不得撞底座
    # duplicate record_id——须走 already_recorded 幂等跳过。
    from apkscan.core.recognition_codec import build_action_outcome
    from apkscan.core.recognition_contract import (
        ActionUsage,
        OutcomeStatus,
    )
    from tests.recognition_fixtures import make_authorization

    base = make_gap_ledger()
    extended, _ = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    action = _planned()[0].action
    extended = jl.append_event(
        extended,
        jl.make_event(
            extended,
            EventType.ACTION_AUTHORIZED,
            make_actor(),
            FIXED_TIME,
            make_authorization(action_id=action.action_id),
        ),
    )
    outcome = build_action_outcome(
        action_id=action.action_id,
        status=OutcomeStatus.COMPLETE,
        output_anchors=(),
        coverage_assertions=(),
        reason_codes=(),
        diagnostics_locator=None,
        usage=ActionUsage(elapsed_ms=1, peak_memory_mb=1, output_bytes=1),
        producer=make_producer(ProducerKind.QUERY),
    )
    extended = jl.append_event(
        extended,
        jl.make_event(
            extended,
            EventType.ACTION_OUTCOME_RECORDED,
            make_actor(),
            FIXED_TIME,
            outcome,
        ),
    )
    final, receipt = rl.append_reanalysis_proposals(
        extended, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    assert receipt.appended == 0
    assert receipt.skipped_already_recorded == 1
    assert final == extended


def test_projection_dedupe_skip_within_one_batch():
    # 同批两个不同 action_id、同 dedupe_key（gap_ids 不进 dedupe）：第二个必须
    # 在生成层被非终态 dedupe 跳过，而不是撞底座。
    import dataclasses as _dc

    from apkscan.core.recognition_codec import build_next_action

    base = make_gap_ledger()
    planned = _planned()
    first_action = planned[0].action
    second_gap = make_gap()
    rival_action = build_next_action(
        question_id=first_action.question_id,
        gap_ids=first_action.gap_ids,
        attempt_nonce="9" * 32,  # 不同 nonce → 不同 action_id，同语义字段 → 同 dedupe
        action_type=first_action.action_type,
        subjects=first_action.subjects,
        input_anchor_ids=first_action.input_anchor_ids,
        parameters_digest=first_action.parameters_digest,
        authorization_required=first_action.authorization_required,
        budget=first_action.budget,
        success_criteria=first_action.success_criteria,
        negative_valid_only_if=first_action.negative_valid_only_if,
        producer=first_action.producer,
    )
    assert rival_action.dedupe_key == first_action.dedupe_key
    assert rival_action.action_id != first_action.action_id
    del second_gap, _dc

    batch = (planned[0], rp.PlannedAction(action=rival_action, meta=planned[0].meta))
    extended, receipt = rl.append_reanalysis_proposals(
        base, planned=batch, actor=make_actor(), occurred_at=FIXED_TIME
    )
    assert receipt.appended == 1
    assert receipt.skipped_nonterminal_dedupe == 1
    jl.replay(extended)


def test_projection_leaves_input_events_untouched():
    base = make_gap_ledger()
    extended, _ = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    assert extended[: len(base)] == base


def test_projection_actor_is_recorded_verbatim():
    base = make_gap_ledger()
    actor = make_actor(ActorKind.SYSTEM)
    extended, _ = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=actor, occurred_at=FIXED_TIME
    )
    assert extended[-1].actor == actor
    assert extended[-1].occurred_at == FIXED_TIME


# ---------------------------------------------------------------- 静态依赖锁


def test_module_never_touches_auto_authorization_paths():
    # R2/R3 安全核查落点：P2-D2 的 PROPOSED→AUTHORIZED→OUTCOME 一条龙绝不复用。
    source = Path(rl.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "jadx_run_ledger",
        "_append_usage_action",
        "_authorization",
        "append_jadx_query_projection",
        "ActionAuthorization",
        "ACTION_AUTHORIZED",
    ):
        assert forbidden not in source, forbidden


# ---------------------------------------------------------------- 发布：create-only + 回读 replay


def test_publish_writes_verifiable_sidecar(tmp_path: Path):
    base = make_gap_ledger()
    extended, _ = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    receipt = rl.publish_reanalysis_ledger(
        extended, out_dir=str(tmp_path), sample_sha256=SAMPLE_SHA
    )
    assert receipt["ok"] is True  # 唯一成功判据（codex 复审 P2）
    assert receipt["published"] is True
    assert receipt["replay_ok"] is True
    locator = str(receipt["locator"])
    assert SAMPLE_SHA in locator
    target = tmp_path / locator
    assert target.is_file()
    lines = target.read_text(encoding="utf-8").splitlines()
    events = tuple(jl.decode_event(line) for line in lines)
    jl.validate_event_chain(events)
    jl.replay(events)
    assert len(events) == len(extended)
    assert int(str(receipt["event_count"])) == len(extended)


def test_publish_is_create_only(tmp_path: Path):
    base = make_gap_ledger()
    extended, _ = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    first = rl.publish_reanalysis_ledger(
        extended, out_dir=str(tmp_path), sample_sha256=SAMPLE_SHA
    )
    target = tmp_path / str(first["locator"])
    original_bytes = target.read_bytes()

    second = rl.publish_reanalysis_ledger(
        extended, out_dir=str(tmp_path), sample_sha256=SAMPLE_SHA
    )
    assert second["ok"] is False
    assert second["published"] is False
    assert target.read_bytes() == original_bytes  # 绝不覆盖已发布内容


def test_publish_failure_does_not_claim_closure(tmp_path: Path):
    base = make_gap_ledger()
    extended, _ = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    blocked = tmp_path / "not-a-dir"
    blocked.write_text("occupied", encoding="utf-8")
    receipt = rl.publish_reanalysis_ledger(
        extended, out_dir=str(blocked), sample_sha256=SAMPLE_SHA
    )
    assert receipt["ok"] is False
    assert receipt["published"] is False
    assert receipt["replay_ok"] is False


def test_publish_creates_missing_out_dir_deliberately(tmp_path: Path):
    # 有意语义（codex 复审 P2 要求冻结）：目录不存在 → 创建并发布成功。
    base = make_gap_ledger()
    extended, _ = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    nested = tmp_path / "brand" / "new"
    receipt = rl.publish_reanalysis_ledger(
        extended, out_dir=str(nested), sample_sha256=SAMPLE_SHA
    )
    assert receipt["ok"] is True
    assert (nested / str(receipt["locator"])).is_file()


def test_tampered_read_back_never_claims_closure(tmp_path: Path, monkeypatch):
    base = make_gap_ledger()
    extended, _ = rl.append_reanalysis_proposals(
        base, planned=_planned(), actor=make_actor(), occurred_at=FIXED_TIME
    )
    real_read = Path.read_bytes

    def _corrupted(self: Path) -> bytes:
        data = real_read(self)
        return data[:-2] + b"x\n" if data else data

    monkeypatch.setattr(Path, "read_bytes", _corrupted)
    receipt = rl.publish_reanalysis_ledger(
        extended, out_dir=str(tmp_path), sample_sha256=SAMPLE_SHA
    )
    assert receipt["ok"] is False
    assert receipt["replay_ok"] is False
    assert receipt["reason"] == "replay_failed"


def test_static_lock_holds_at_ast_level():
    # 字符串扫描之外的结构性断言（codex 复审：文本断言脆弱）：
    # 模块的 import 图里不得出现 P2-D2 自动授权路径所在模块。
    import ast

    tree = ast.parse(Path(rl.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imported.add(module)
            imported.update(f"{module}.{alias.name}" for alias in node.names)
    assert not any("jadx_run_ledger" in name for name in imported)
    assert not any("index_ledger" in name for name in imported)
