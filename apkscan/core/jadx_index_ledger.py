"""JADX 索引查询的 ledger 投影适配器（P1-A S3 + P1-B callpath）。

索引查询本身不是判断：本模块把一次查询的结局投影进既有判断账本——
消费一个已 PROPOSED 且已 AUTHORIZED 的动作，追加恰好一条 ACTION_OUTCOME_RECORDED，
并仅对真实阳性产出逐条追加 OBSERVATION_ADDED。一切追加走 ``append_event``
（内部 replay 验证），绝不构造游离事件；空结果 / miss / 损坏 / 漂移 / 超时无产出 /
环境不可用**绝不**产生 Observation，也绝不被解释为「不存在」。

P1-B：callpath 查询走独立动作类型 ``jadx-callpath-query``；路径观察每条边一个
LINE_RANGE 定位符。强度用 OBSERVED：契约规定 DERIVED 必须携带非空
input_observation_ids（推导可追溯），而 P1-B 不为单条边落独立观察——链上每个
调用表达式都是被直接观察到的事实，整条观察以逐边 source_refs 锚定。
「没找到静态路径」不是「不可达」——空 paths 在任何状态下都不产观察。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum

from apkscan.core import judgment_ledger as jl
from apkscan.core import recognition_codec as codec
from apkscan.core import recognition_contract as rc
from apkscan.core.jadx_callpath import CallPath
from apkscan.core.jadx_index import INDEX_SCHEMA_VERSION, JadxIndexError, UsageHit
from apkscan.core.jadx_ownership import OwnershipProjection


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
    """一次索引查询的完整结局（usage 适配器的唯一输入载体）。

    外部调用者的输入面：构造期即校验，坏输入在这里被结构化拒绝，
    不留到投影中途炸成非契约异常。
    """

    state: IndexQueryState
    coverage: str | None
    hits: tuple[UsageHit, ...]
    manifest_digest: str | None = None
    shard_digests: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    query_receipt_locator: rc.EvidenceLocator | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, IndexQueryState):
            raise JadxIndexError("invalid_query_state", "$.state")
        if self.coverage is not None and self.coverage not in ("complete", "partial"):
            raise JadxIndexError("invalid_query_coverage", "$.coverage")
        if not isinstance(self.hits, tuple) or any(
            not isinstance(hit, UsageHit) for hit in self.hits
        ):
            raise JadxIndexError("invalid_query_hits", "$.hits")
        if not isinstance(self.shard_digests, tuple) or not isinstance(self.reason_codes, tuple):
            raise JadxIndexError("invalid_query_tuples", "$")


@dataclass(frozen=True, slots=True)
class CallPathQueryResult:
    """一次调用路径查询的完整结局（callpath 适配器的唯一输入载体）。"""

    state: IndexQueryState
    coverage: str | None
    paths: tuple[CallPath, ...]
    manifest_digest: str | None = None
    shard_digests: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    query_receipt_locator: rc.EvidenceLocator | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, IndexQueryState):
            raise JadxIndexError("invalid_query_state", "$.state")
        if self.coverage is not None and self.coverage not in ("complete", "partial"):
            raise JadxIndexError("invalid_query_coverage", "$.coverage")
        if not isinstance(self.paths, tuple) or any(
            not isinstance(path, CallPath) for path in self.paths
        ):
            raise JadxIndexError("invalid_query_paths", "$.paths")
        if not isinstance(self.shard_digests, tuple) or not isinstance(self.reason_codes, tuple):
            raise JadxIndexError("invalid_query_tuples", "$")


@dataclass(frozen=True, slots=True)
class OwnershipQueryResult:
    """一次 ownership projection 查询的完整结局（ownership 适配器的唯一输入载体）。"""

    state: IndexQueryState
    coverage: str | None
    projection: OwnershipProjection
    manifest_digest: str | None = None
    baseline_manifest_digest: str | None = None
    shard_digests: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    query_receipt_locator: rc.EvidenceLocator | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, IndexQueryState):
            raise JadxIndexError("invalid_query_state", "$.state")
        if self.coverage is not None and self.coverage not in ("complete", "partial"):
            raise JadxIndexError("invalid_query_coverage", "$.coverage")
        if not isinstance(self.projection, OwnershipProjection):
            raise JadxIndexError("invalid_query_projection", "$.projection")
        if not isinstance(self.shard_digests, tuple) or not isinstance(self.reason_codes, tuple):
            raise JadxIndexError("invalid_query_tuples", "$")


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
        # anchor 的 schema 引用跟随常量：索引 schema 演进时锚随之走，不留死字面量。
        schema_version_ref=INDEX_SCHEMA_VERSION,
    )


def _canonical_sort_key(record: object) -> str:
    """contract 的 canonical tuple 排序键（JSON 规范序）——anchors 与 locators 共用。"""
    return json.dumps(
        {k: (v.value if isinstance(v, StrEnum) else v) for k, v in asdict(record).items()},  # type: ignore[call-overload]
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _project_outcome(
    events: tuple[jl.LedgerEvent, ...],
    *,
    action_id: str,
    action_type: str,
    result: IndexQueryResult | CallPathQueryResult | OwnershipQueryResult,
    actor: rc.Actor,
    occurred_at: str,
    baseline_digest: str | None = None,
) -> tuple[
    tuple[jl.LedgerEvent, ...],
    rc.SubjectRef,
    rc.CoverageAssertion,
    rc.ProducerRef,
    rc.ActionOutcome,
]:
    """共享投影核：校验动作链、落恰好一条 outcome；前置校验失败抛 JadxIndexError。"""
    projection = jl.replay(events)

    action = next(
        (candidate for candidate in projection.actions if candidate.action_id == action_id),
        None,
    )
    if action is None:
        raise JadxIndexError("detached_action", "$.action_id")
    # 动作类型是硬边界：usage 动作不能投 callpath，反之亦然。
    if action.action_type != action_type:
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
    # baseline 锚在构造期加入（账本是 append-only 哈希链，事后替换 outcome
    # 事件是禁手）；让「baseline 选择」本身可追溯可复核。
    if baseline_digest is not None:
        anchors.append(_digest_anchor(baseline_digest, logical_id=f"action:{action_id}:baseline"))
    # contract 要求 canonical tuple（JSON 规范序 + 无重复）——与其
    # _validate_canonical_tuple 的排序键同构。
    anchors.sort(key=_canonical_sort_key)

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
    return jl.append_event(events, outcome_event), subject, coverage, producer, outcome


def append_jadx_query_projection(
    events: tuple[jl.LedgerEvent, ...],
    *,
    action_id: str,
    result: IndexQueryResult,
    actor: rc.Actor,
    occurred_at: str,
) -> tuple[jl.LedgerEvent, ...]:
    """把 usage 查询结局合法地追加进账本；仅真实阳性命中逐条产观察。"""
    result_events, subject, coverage, producer, outcome = _project_outcome(
        events,
        action_id=action_id,
        action_type="jadx-usage-query",
        result=result,
        actor=actor,
        occurred_at=occurred_at,
    )

    if result.hits and result.state in _POSITIVE_STATES:
        anchors = outcome.output_anchors
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


def append_jadx_callpath_projection(
    events: tuple[jl.LedgerEvent, ...],
    *,
    action_id: str,
    result: CallPathQueryResult,
    actor: rc.Actor,
    occurred_at: str,
) -> tuple[jl.LedgerEvent, ...]:
    """把 callpath 查询结局合法地追加进账本；仅真实找到的路径逐条产观察。"""
    result_events, subject, coverage, producer, outcome = _project_outcome(
        events,
        action_id=action_id,
        action_type="jadx-callpath-query",
        result=result,
        actor=actor,
        occurred_at=occurred_at,
    )

    if result.paths and result.state in _POSITIVE_STATES:
        anchors = outcome.output_anchors
        anchor_id = anchors[0].anchor_id if anchors else coverage.assessment_digest
        for path in result.paths:
            # 观察值 = 路径 canonical 编码的 digest token——bounded、确定、绝不携带
            # 原始标识符序列（方法名链不落账本值域）。
            payload = {
                "nodes": list(path.nodes),
                "edges": [
                    {
                        "caller_path": edge.caller_path,
                        "line": edge.line,
                        "resolution": edge.resolution,
                        "scope": edge.scope,
                    }
                    for edge in path.edges
                ],
            }
            categorical = "sha256." + hashlib.sha256(codec.canonical_json_v1(payload)).hexdigest()
            source_refs = tuple(
                sorted(
                    (
                        rc.EvidenceLocator(
                            anchor_id=anchor_id,
                            kind=rc.LocatorKind.LINE_RANGE,
                            value=edge.caller_path,
                            start=edge.line,
                            end=edge.line,
                        )
                        for edge in path.edges
                    ),
                    key=_canonical_sort_key,
                )
            )
            observation = codec.build_observation(
                observation_type="jadx_callpath",
                subjects=(subject,),
                value=rc.ObservationValue(
                    kind=rc.ObservationValueKind.CATEGORICAL,
                    categorical=categorical,
                    integer=None,
                    boolean=None,
                    reference=None,
                ),
                source_refs=source_refs,
                scope=rc.EvidenceScope.DERIVED_REFERENCE,
                # OBSERVED 而非 DERIVED：契约要求 DERIVED 携带非空 input_observation_ids，
                # 而 P1-B 不为单条边落独立观察；载荷如实携带链上调用表达式及其名字
                # 判据状态，并由逐边 source_refs 锚定。未来若为边落独立观察，再升 DERIVED。
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


def append_jadx_ownership_projection(
    events: tuple[jl.LedgerEvent, ...],
    *,
    action_id: str,
    result: OwnershipQueryResult,
    actor: rc.Actor,
    occurred_at: str,
) -> tuple[jl.LedgerEvent, ...]:
    """把 ownership projection 结局合法地追加进账本；仅 INHERITED_OFFICIAL 匹配产观察。

    UNKNOWN 区域一律零观察——unknown 不是发现；digest 相等的官方匹配才是
    可定位的阳性事实。baseline manifest 锚随 outcome 落链，baseline 选择可复核。
    """
    result_events, subject, coverage, producer, outcome = _project_outcome(
        events,
        action_id=action_id,
        action_type="jadx-ownership-projection",
        result=result,
        actor=actor,
        occurred_at=occurred_at,
        baseline_digest=result.baseline_manifest_digest,
    )

    if result.state in _POSITIVE_STATES:
        anchors = outcome.output_anchors
        anchor_id = anchors[0].anchor_id if anchors else coverage.assessment_digest
        for item in result.projection.regions:
            if item.ownership is not rc.OwnershipValue.INHERITED_OFFICIAL:
                continue
            region = item.region
            locator = rc.EvidenceLocator(
                anchor_id=anchor_id,
                kind=rc.LocatorKind.LINE_RANGE,
                value=region.path,
                start=region.start_line,
                end=region.end_line,
            )
            observation = codec.build_observation(
                observation_type="jadx_ownership_match",
                subjects=(subject,),
                value=rc.ObservationValue(
                    kind=rc.ObservationValueKind.CATEGORICAL,
                    categorical=region.body_digest.replace(":", ".", 1),
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
                # ★契约字段直接承载结论：官方匹配即 INHERITED_OFFICIAL；
                #   本适配器绝不产出 suspect/third-party/shared 任一值。
                ownership=rc.OwnershipValue.INHERITED_OFFICIAL,
                coverage_assertions=(coverage,),
            )
            observation_event = jl.make_event(
                result_events, jl.EventType.OBSERVATION_ADDED, actor, occurred_at, observation
            )
            result_events = jl.append_event(result_events, observation_event)

    return result_events


__all__ = [
    "CallPathQueryResult",
    "IndexQueryResult",
    "IndexQueryState",
    "OwnershipQueryResult",
    "append_jadx_callpath_projection",
    "append_jadx_ownership_projection",
    "append_jadx_query_projection",
]
