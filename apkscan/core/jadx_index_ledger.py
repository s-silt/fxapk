"""JADX 索引查询的 ledger 投影适配器（P1-A S3）。

索引查询本身不是判断：本模块把一次查询的结局投影进既有判断账本——
消费一个已 PROPOSED 且已 AUTHORIZED 的动作，追加恰好一条 ACTION_OUTCOME_RECORDED，
并仅对真实阳性命中逐条追加 OBSERVATION_ADDED。一切追加走 ``append_event``
（内部 replay 验证），绝不构造游离事件；空结果 / miss / 损坏 / 漂移 / 超时无产出 /
环境不可用**绝不**产生 Observation，也绝不被解释为「不存在」。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import StrEnum

from apkscan.core import judgment_ledger as jl
from apkscan.core import recognition_codec as codec
from apkscan.core import recognition_contract as rc
from apkscan.core.jadx_index import JadxIndexError, UsageHit


class IndexQueryState(StrEnum):
    HIT = "hit"
    REBUILT = "rebuilt"
    MISS = "miss"
    CORRUPT = "corrupt"
    DRIFT = "drift"
    TIMEOUT_PARTIAL = "timeout_partial"
    TIMEOUT_EMPTY = "timeout_empty"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


#: 允许产生 Observation 的状态：存在可用阳性产出的那三种，仅此而已。
_POSITIVE_STATES = frozenset(
    {IndexQueryState.HIT, IndexQueryState.REBUILT, IndexQueryState.TIMEOUT_PARTIAL}
)


@dataclass(frozen=True, slots=True)
class IndexQueryResult:
    """一次索引查询的完整结局（适配器的唯一输入载体）。"""

    state: IndexQueryState
    coverage: str | None
    hits: tuple[UsageHit, ...]
    manifest_digest: str | None = None
    shard_digests: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    query_receipt_locator: rc.EvidenceLocator | None = None


def _coverage_status(state: IndexQueryState, coverage: str | None) -> rc.CoverageStatus:
    """固定映射（见 spec 表）。★HIT/REBUILT 都沿用实际 coverage——
    命中或重建出一个 partial 索引绝不升格为 complete 覆盖。"""
    if state in (IndexQueryState.HIT, IndexQueryState.REBUILT):
        return rc.CoverageStatus.PARTIAL if coverage == "partial" else rc.CoverageStatus.COMPLETE
    if state in (IndexQueryState.TIMEOUT_PARTIAL, IndexQueryState.TIMEOUT_EMPTY):
        return rc.CoverageStatus.TIMEOUT
    if state is IndexQueryState.FAILED:
        return rc.CoverageStatus.FAILED
    if state is IndexQueryState.UNAVAILABLE:
        return rc.CoverageStatus.UNAVAILABLE
    # MISS / CORRUPT / DRIFT：对内容一无所知。
    return rc.CoverageStatus.UNKNOWN


def _outcome_status(state: IndexQueryState, coverage: str | None) -> rc.OutcomeStatus:
    if state is IndexQueryState.HIT:
        return rc.OutcomeStatus.COMPLETE
    if state is IndexQueryState.REBUILT:
        # 截断重建是 PARTIAL 结局，不是完整成功。
        return rc.OutcomeStatus.PARTIAL if coverage == "partial" else rc.OutcomeStatus.COMPLETE
    if state is IndexQueryState.TIMEOUT_PARTIAL:
        return rc.OutcomeStatus.PARTIAL
    return rc.OutcomeStatus.FAILED


def _digest_anchor(digest: str, *, logical_id: str) -> rc.EvidenceAnchor:
    return codec.build_evidence_anchor(
        anchor_type=rc.EvidenceAnchorType.JADX_INDEX,
        content_digest=digest,
        logical_id=logical_id,
        schema_version_ref="1.0",
    )


def append_jadx_query_projection(
    events: tuple[jl.LedgerEvent, ...],
    *,
    action_id: str,
    result: IndexQueryResult,
    actor: rc.Actor,
    occurred_at: str,
) -> tuple[jl.LedgerEvent, ...]:
    """把查询结局合法地追加进账本；前置校验失败抛 JadxIndexError，不产生半截链。"""
    projection = jl.replay(events)

    action = next(
        (candidate for candidate in projection.actions if candidate.action_id == action_id),
        None,
    )
    if action is None:
        raise JadxIndexError("detached_action", "$.action_id")
    # 动作类型跟随 P0-A 既有先例（tests/recognition_fixtures.py 的 make_action）。
    if action.action_type != "jadx-usage-query":
        raise JadxIndexError("wrong_action_type", "$.action_id")
    action_status = dict(projection.action_statuses).get(action_id)
    if action_status is not jl.ActionStatus.AUTHORIZED:
        raise JadxIndexError("action_not_authorized", "$.action_id")

    subjects = action.subjects or projection.run.subjects
    if not subjects:
        raise JadxIndexError("malformed", "$.action.subjects")
    subject = subjects[0]

    anchors: list[rc.EvidenceAnchor] = []
    if result.manifest_digest is not None:
        anchors.append(
            _digest_anchor(result.manifest_digest, logical_id=f"action:{action_id}:manifest")
        )
    for index, digest in enumerate(result.shard_digests):
        anchors.append(_digest_anchor(digest, logical_id=f"action:{action_id}:shard:{index}"))
    # contract 要求 canonical tuple（JSON 规范序 + 无重复）——与其
    # _validate_canonical_tuple 的排序键同构。
    anchors.sort(
        key=lambda a: json.dumps(
            {k: (v.value if isinstance(v, StrEnum) else v) for k, v in asdict(a).items()},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )

    coverage = rc.CoverageAssertion(
        subject=subject,
        source=rc.CoverageSource.JADX_INDEX,
        status=_coverage_status(result.state, result.coverage),
        scope=rc.EvidenceScope.DERIVED_REFERENCE,
        # 无 manifest 的失败态用显式全零占位——可辨识、不可与真实 digest 混淆。
        assessment_digest=(
            result.manifest_digest if result.manifest_digest is not None else "sha256:" + "0" * 64
        ),
        receipt_locator=result.query_receipt_locator,
        reason_codes=result.reason_codes,
    )

    producer = (
        projection.run.producers[0]
        if projection.run.producers
        else rc.ProducerRef(
            kind=rc.ProducerKind.QUERY,
            producer_id="fxapk.jadx.index",
            version="1",
            artifact_digest=None,
            configuration_digest=None,
        )
    )

    outcome = codec.build_action_outcome(
        action_id=action_id,
        status=_outcome_status(result.state, result.coverage),
        output_anchors=tuple(anchors),
        coverage_assertions=(coverage,),
        reason_codes=result.reason_codes,
        diagnostics_locator=result.query_receipt_locator,
        usage=rc.ActionUsage(elapsed_ms=None, peak_memory_mb=None, output_bytes=None),
        producer=producer,
    )
    outcome_event = jl.make_event(
        events, jl.EventType.ACTION_OUTCOME_RECORDED, actor, occurred_at, outcome
    )
    result_events = jl.append_event(events, outcome_event)

    if result.hits and result.state in _POSITIVE_STATES:
        for hit in result.hits:
            locator = rc.EvidenceLocator(
                anchor_id=anchors[0].anchor_id if anchors else coverage.assessment_digest,
                kind=rc.LocatorKind.LINE_RANGE,
                value=hit.relative_path,
                start=hit.line,
                end=hit.line,
            )
            observation = codec.build_observation(
                observation_type="jadx_value_usage",
                subjects=(subject,),
                value=rc.ObservationValue(
                    kind=rc.ObservationValueKind.CATEGORICAL,
                    # contract 的 categorical 是小写 token（不含冒号）——digest 前缀
                    # 以点号形态编码（sha256.<hex>），仍是不透明标识、绝非原值。
                    categorical=hit.value_digest.replace(":", ".", 1),
                    integer=None,
                    boolean=None,
                    reference=None,
                ),
                source_refs=(locator,),
                scope=rc.EvidenceScope.DERIVED_REFERENCE,
                strength=rc.ObservationStrength.OBSERVED,
                input_observation_ids=(),
                origin_outcome_id=outcome.outcome_id,
                producer=producer,
                ownership=rc.OwnershipValue.UNKNOWN,
                coverage_assertions=(coverage,),
            )
            observation_event = jl.make_event(
                result_events, jl.EventType.OBSERVATION_ADDED, actor, occurred_at, observation
            )
            result_events = jl.append_event(result_events, observation_event)

    return result_events


__all__ = [
    "IndexQueryResult",
    "IndexQueryState",
    "append_jadx_query_projection",
]
