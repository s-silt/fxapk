"""P1-A S3 ledger 投影适配器：状态矩阵、事件链合法性、阴性绝不产观察。

链构造复用 P0-A 的 recognition_fixtures（make_action_ledger 止于 ACTION_PROPOSED，
再补 ACTION_AUTHORIZED）；适配器只允许消费已授权动作。
"""

from __future__ import annotations

import hashlib

import pytest

from apkscan.core import judgment_ledger as jl
from apkscan.core import recognition_contract as rc
from apkscan.core.jadx_index import DexLineage, DexRole, JadxIndexError, UsageHit
from apkscan.core.jadx_index_ledger import (
    IndexQueryResult,
    IndexQueryState,
    append_jadx_query_projection,
)
from tests.recognition_fixtures import (
    FIXED_TIME,
    append_record,
    make_action_ledger,
    make_actor,
    make_authorization,
)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _authorized_ledger() -> tuple[tuple[jl.LedgerEvent, ...], str]:
    events = make_action_ledger()
    action = events[-1].payload
    assert isinstance(action, rc.NextAction)
    events = append_record(
        events,
        jl.EventType.ACTION_AUTHORIZED,
        make_authorization(action_id=action.action_id),
    )
    return events, action.action_id


def _hit() -> UsageHit:
    return UsageHit(
        relative_path="com/example/App.java",
        line=42,
        column=7,
        value_digest=_digest(b"needle"),
        lineage=DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"dex")),
    )


def _result(
    state: IndexQueryState,
    *,
    coverage: str | None = "complete",
    hits: tuple[UsageHit, ...] = (),
) -> IndexQueryResult:
    return IndexQueryResult(
        state=state,
        coverage=coverage,
        hits=hits,
        # anchor 走 recognition contract 的 digest 形态（sha256: 前缀）。
        manifest_digest="sha256:" + "a" * 64,
        shard_digests=("sha256:" + "b" * 64,),
        reason_codes=("test",),
    )


def _last_outcome(events: tuple[jl.LedgerEvent, ...]) -> rc.ActionOutcome:
    projection = jl.replay(events)
    assert projection.outcomes
    return projection.outcomes[-1]


def _observation_count(events: tuple[jl.LedgerEvent, ...]) -> int:
    return sum(1 for e in events if e.event_type is jl.EventType.OBSERVATION_ADDED)


# ---------------------------------------------------------------------------
# 状态矩阵
# ---------------------------------------------------------------------------


def test_hit_complete_projection_with_observations() -> None:
    events, action_id = _authorized_ledger()
    before_obs = _observation_count(events)
    out = append_jadx_query_projection(
        events,
        action_id=action_id,
        result=_result(IndexQueryState.HIT, hits=(_hit(),)),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    jl.replay(out)  # 整链必须可重放
    outcome = _last_outcome(out)
    assert outcome.status is rc.OutcomeStatus.COMPLETE
    (cov,) = outcome.coverage_assertions
    assert cov.source is rc.CoverageSource.JADX_INDEX
    assert cov.status is rc.CoverageStatus.COMPLETE
    assert _observation_count(out) == before_obs + 1
    # ★不用 observations[-1]：投影按 observation_id 排序，位置随 digest 漂移——
    #   按 observation_type 选取本次追加的那条。
    (obs,) = [
        o for o in jl.replay(out).observations
        if o.observation_type == "jadx_value_usage"
    ]
    assert obs.ownership is rc.OwnershipValue.UNKNOWN
    assert obs.origin_outcome_id == outcome.outcome_id
    # 观察值是 digest（token 化形态），不是原值。
    assert obs.value.categorical == _hit().value_digest.replace(":", ".", 1)


def test_hit_on_partial_manifest_keeps_partial_coverage() -> None:
    """★映射修正回归锁：命中 partial 索引，coverage 沿用 partial 不升格。"""
    events, action_id = _authorized_ledger()
    out = append_jadx_query_projection(
        events,
        action_id=action_id,
        result=_result(IndexQueryState.HIT, coverage="partial", hits=(_hit(),)),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    outcome = _last_outcome(out)
    assert outcome.status is rc.OutcomeStatus.COMPLETE
    assert outcome.coverage_assertions[0].status is rc.CoverageStatus.PARTIAL


def test_rebuilt_truncated_is_partial_partial() -> None:
    """★REBUILT+截断 → PARTIAL/PARTIAL——绝不升格为完整成功。"""
    events, action_id = _authorized_ledger()
    out = append_jadx_query_projection(
        events,
        action_id=action_id,
        result=_result(IndexQueryState.REBUILT, coverage="partial", hits=(_hit(),)),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    outcome = _last_outcome(out)
    assert outcome.status is rc.OutcomeStatus.PARTIAL
    assert outcome.coverage_assertions[0].status is rc.CoverageStatus.PARTIAL


@pytest.mark.parametrize(
    ("state", "expect_cov"),
    [
        (IndexQueryState.MISS, rc.CoverageStatus.UNKNOWN),
        (IndexQueryState.CORRUPT, rc.CoverageStatus.UNKNOWN),
        (IndexQueryState.DRIFT, rc.CoverageStatus.UNKNOWN),
        (IndexQueryState.TIMEOUT_EMPTY, rc.CoverageStatus.TIMEOUT),
        (IndexQueryState.FAILED, rc.CoverageStatus.FAILED),
        (IndexQueryState.UNAVAILABLE, rc.CoverageStatus.UNAVAILABLE),
    ],
)
def test_negative_states_failed_outcome_zero_observations(
    state: IndexQueryState, expect_cov: rc.CoverageStatus
) -> None:
    events, action_id = _authorized_ledger()
    before_obs = _observation_count(events)
    out = append_jadx_query_projection(
        events,
        action_id=action_id,
        result=_result(state, coverage=None),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    outcome = _last_outcome(out)
    assert outcome.status is rc.OutcomeStatus.FAILED
    assert outcome.coverage_assertions[0].status is expect_cov
    assert _observation_count(out) == before_obs  # ★阴性绝不产观察


def test_negative_state_with_hits_still_produces_no_observation() -> None:
    """★带 hits 的失败态（防御性）：状态不在阳性集合，hits 一律不投影。"""
    events, action_id = _authorized_ledger()
    before_obs = _observation_count(events)
    out = append_jadx_query_projection(
        events,
        action_id=action_id,
        result=_result(IndexQueryState.MISS, coverage=None, hits=(_hit(),)),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    assert _observation_count(out) == before_obs


# ---------------------------------------------------------------------------
# 事件链合法性
# ---------------------------------------------------------------------------


def test_detached_action_rejected() -> None:
    events, _ = _authorized_ledger()
    with pytest.raises(JadxIndexError) as exc:
        append_jadx_query_projection(
            events,
            action_id="action-sha256:" + "9" * 64,
            result=_result(IndexQueryState.HIT, hits=(_hit(),)),
            actor=make_actor(),
            occurred_at=FIXED_TIME,
        )
    assert exc.value.code == "detached_action"


def test_unauthorized_action_rejected() -> None:
    """只 PROPOSED 未 AUTHORIZED 的动作不得记录结局——授权门是硬的。"""
    events = make_action_ledger()
    action = events[-1].payload
    assert isinstance(action, rc.NextAction)
    with pytest.raises(JadxIndexError) as exc:
        append_jadx_query_projection(
            events,
            action_id=action.action_id,
            result=_result(IndexQueryState.HIT, hits=(_hit(),)),
            actor=make_actor(),
            occurred_at=FIXED_TIME,
        )
    assert exc.value.code == "action_not_authorized"


def test_appended_chain_replays_and_is_append_only() -> None:
    events, action_id = _authorized_ledger()
    out = append_jadx_query_projection(
        events,
        action_id=action_id,
        result=_result(IndexQueryState.HIT, hits=(_hit(),)),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    # 追加式：原链前缀逐事件不变。
    assert out[: len(events)] == events
    projection = jl.replay(out)
    assert dict(projection.action_statuses)[action_id] is jl.ActionStatus.COMPLETE
