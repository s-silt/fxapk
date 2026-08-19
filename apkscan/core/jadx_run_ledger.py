"""Pipeline 级 JADX 查询账本 sidecar。

启用持久 JADX 索引且样本可计算 SHA-256 时，本模块为本次 pipeline 运行构造最小
judgment ledger：

RUN_OPENED
→ QUESTION_OPENED
→ JADX usage/index-acquisition ACTION_PROPOSED
→ ACTION_AUTHORIZED
→ ACTION_OUTCOME_RECORDED
→ 可选 ownership projection action/outcome/observations

本模块不执行 callpath 查询，因此不生成 callpath 动作。

sidecar 使用 canonical JSONL、create-only 原子发布，并在发布后从实际文件回读、
解码和 replay。所有异常均在模块内收敛为稳定失败锚，不向 pipeline 抛出。
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from apkscan.core import jadx_index_ledger as index_ledger
from apkscan.core import judgment_ledger as jl
from apkscan.core import recognition_codec as codec
from apkscan.core import recognition_contract as rc
from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.jadx_index import INDEX_SCHEMA_VERSION, JadxIndexStore, LoadedIndex
from apkscan.core.jadx_ownership import project_ownership

logger = logging.getLogger(__name__)


def _sidecar_name(sample_sha256: str) -> str:
    """样本寻址的 sidecar 名：同一 out 目录多样本各得其账本，绝不互相顶掉。"""
    return f"judgment-ledger-{sample_sha256}.jsonl"


_AUTO_POLICY_ID = "fxapk.pipeline.auto_policy"
_PRODUCER_ID = "fxapk.jadx.index"

_REASON_ALREADY_EXISTS = "sidecar_already_exists"
_REASON_PUBLISH_FAILED = "sidecar_publish_failed"
_REASON_REPLAY_FAILED = "sidecar_replay_failed"
_REASON_LEDGER_BUILD_FAILED = "ledger_build_failed"
_REASON_INDEX_INFORMATION_UNAVAILABLE = "index_information_unavailable"

_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def _sample_sha256(path: str) -> str | None:
    """流式计算样本 SHA-256；任何读取失败均返回 None。"""

    if not isinstance(path, str) or not path:
        return None

    digest = hashlib.sha256()
    try:
        with open(path, "rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except (OSError, ValueError, TypeError):
        return None

    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_digest(value: object) -> str:
    return _sha256_bytes(codec.canonical_json_v1(value))


def _deterministic_nonce(*parts: str) -> str:
    """确定性派生 nonce（同输入同 nonce，账本可重放；绝不用随机/时间源）。

    contract 的 execution_nonce/attempt_nonce 都要求恰 32 位 hex——取 sha256 前半。
    """
    material = ":".join(parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


def _occurred_at() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _valid_hex_key(value: object) -> str | None:
    if isinstance(value, str) and _HEX64_RE.fullmatch(value):
        return value
    return None


def _valid_digest(value: object) -> str | None:
    if isinstance(value, str) and _DIGEST_RE.fullmatch(value):
        return value
    return None


def _manifest_digest(cache_root: str, index_key: str | None) -> str | None:
    """读取 ``<cache_root>/<index_key>/manifest.json`` 的实际文件字节摘要。"""

    if index_key is None:
        return None

    try:
        data = (Path(cache_root) / index_key / "manifest.json").read_bytes()
    except (OSError, ValueError, TypeError):
        return None

    return _sha256_bytes(data)


def _receipt_index(meta: Mapping[str, object]) -> Mapping[str, object] | None:
    """严格取得 jadx receipt 的 index 块；形态漂移返回 None。"""

    receipt = meta.get("jadx_receipt")
    if not isinstance(receipt, dict):
        return None

    index = receipt.get("index")
    if not isinstance(index, dict):
        return None

    return index


def _receipt_reason_codes(index: Mapping[str, object] | None) -> tuple[str, ...]:
    """取得有效 reason_codes；形态异常显式降级为信息不可得。"""

    if index is None:
        return (_REASON_INDEX_INFORMATION_UNAVAILABLE,)

    raw = index.get("reason_codes")
    if not isinstance(raw, list) or any(not isinstance(item, str) or not item for item in raw):
        return (_REASON_INDEX_INFORMATION_UNAVAILABLE,)

    # recognition contract 的 tuple 要求稳定、无重复；不得依赖分析器插入顺序。
    return tuple(sorted(set(raw)))


def _index_state_and_coverage(
    index: Mapping[str, object] | None,
) -> tuple[index_ledger.IndexQueryState, str | None]:
    """将 receipt.index.status 映射为查询适配器状态。"""

    if index is None:
        return index_ledger.IndexQueryState.UNAVAILABLE, None

    status = index.get("status")
    if status == "built":
        return index_ledger.IndexQueryState.REBUILT, "complete"
    if status == "reused":
        return index_ledger.IndexQueryState.HIT, "complete"
    if status == "partial":
        return index_ledger.IndexQueryState.REBUILT, "partial"
    if status == "failed":
        return index_ledger.IndexQueryState.FAILED, None
    if status in ("unavailable", "disabled"):
        return index_ledger.IndexQueryState.UNAVAILABLE, None

    return index_ledger.IndexQueryState.UNAVAILABLE, None


def _append(
    events: tuple[jl.LedgerEvent, ...],
    event_type: jl.EventType,
    actor: rc.Actor,
    occurred_at: str,
    payload: jl.LedgerPayload,
) -> tuple[jl.LedgerEvent, ...]:
    event = jl.make_event(events, event_type, actor, occurred_at, payload)
    return jl.append_event(events, event)


def _policy() -> rc.PolicyRef:
    policy_digest = _canonical_digest(
        {
            "policy_id": _AUTO_POLICY_ID,
            "version": "1",
            "authorization_level": rc.AuthorizationLevel.OFFLINE.value,
        }
    )
    policy = rc.PolicyRef(
        policy_id=_AUTO_POLICY_ID,
        version="1",
        digest=policy_digest,
    )
    rc.validate_contract_value(policy)
    return policy


def _system_producer() -> rc.ProducerRef:
    """gap/NextAction 的提案主体（契约限定 MODEL/SYSTEM）。"""
    producer = rc.ProducerRef(
        kind=rc.ProducerKind.SYSTEM,
        producer_id="fxapk.pipeline",
        version=INDEX_SCHEMA_VERSION,
        artifact_digest=None,
        configuration_digest=None,
    )
    rc.validate_contract_value(producer)
    return producer


def _producer(meta: Mapping[str, object]) -> rc.ProducerRef:
    configuration_digest: str | None = None

    receipt = meta.get("jadx_receipt")
    if isinstance(receipt, dict):
        configuration_digest = _valid_digest(receipt.get("options_digest"))

    producer = rc.ProducerRef(
        kind=rc.ProducerKind.QUERY,
        producer_id=_PRODUCER_ID,
        version=INDEX_SCHEMA_VERSION,
        artifact_digest=None,
        configuration_digest=configuration_digest,
    )
    rc.validate_contract_value(producer)
    return producer


def _run_anchors(
    *,
    sample_digest: str,
    cache_root: str,
    subject_index_key: str | None,
    ownership_summary: Mapping[str, object] | None,
) -> tuple[rc.EvidenceAnchor, ...]:
    anchors: list[rc.EvidenceAnchor] = [
        codec.build_evidence_anchor(
            anchor_type=rc.EvidenceAnchorType.ARTIFACT,
            content_digest=sample_digest,
            logical_id="apk:sample",
            schema_version_ref=None,
        )
    ]

    subject_manifest_digest = _manifest_digest(cache_root, subject_index_key)
    if subject_index_key is not None and subject_manifest_digest is not None:
        anchors.append(
            codec.build_evidence_anchor(
                anchor_type=rc.EvidenceAnchorType.JADX_INDEX,
                content_digest=subject_manifest_digest,
                logical_id=f"jadx-index:{subject_index_key}",
                schema_version_ref=INDEX_SCHEMA_VERSION,
            )
        )

    if ownership_summary is not None and ownership_summary.get("status") == "compared":
        baseline_key = _valid_hex_key(ownership_summary.get("baseline_index_key"))
        declared_digest = _valid_digest(ownership_summary.get("baseline_manifest_digest"))
        actual_digest = _manifest_digest(cache_root, baseline_key)

        # baseline 双锚只在 index key、摘要和实际 manifest 字节三者一致时进入 run。
        if (
            baseline_key is not None
            and declared_digest is not None
            and actual_digest == declared_digest
        ):
            anchors.append(
                codec.build_evidence_anchor(
                    anchor_type=rc.EvidenceAnchorType.JADX_INDEX,
                    content_digest=declared_digest,
                    logical_id=f"jadx-baseline:{baseline_key}",
                    schema_version_ref=INDEX_SCHEMA_VERSION,
                )
            )

    # EvidenceAnchor canonical JSON 的首个稳定字段是 anchor_id；按 ID 排序可确保 tuple 稳定。
    return tuple(sorted(anchors, key=lambda item: item.anchor_id))


def _authorization(
    *,
    action_id: str,
    policy: rc.PolicyRef,
) -> rc.ActionAuthorization:
    authorization = rc.ActionAuthorization(
        kind="action_authorization",
        schema_version="1.0",
        action_id=action_id,
        granted_level=rc.AuthorizationLevel.OFFLINE,
        policy=policy,
        reason_codes=("policy_pre_authorized",),
    )
    rc.validate_contract_value(authorization)
    return authorization


def _build_action(
    *,
    question_id: str,
    gap_id: str,
    action_type: str,
    nonce_material: str,
    parameters: object,
    subjects: tuple[rc.SubjectRef, ...],
    input_anchor_ids: tuple[str, ...],
    producer: rc.ProducerRef,
) -> rc.NextAction:
    return codec.build_next_action(
        question_id=question_id,
        gap_ids=(gap_id,),
        attempt_nonce=_deterministic_nonce(action_type, nonce_material),
        action_type=action_type,
        subjects=subjects,
        input_anchor_ids=tuple(sorted(input_anchor_ids)),
        parameters_digest=_canonical_digest(parameters),
        authorization_required=rc.AuthorizationLevel.OFFLINE,
        budget=rc.ActionBudget(
            max_seconds=1,
            max_memory_mb=1,
        ),
        success_criteria=("query_outcome_recorded",),
        negative_valid_only_if=(),
        producer=producer,
    )


def _append_usage_action(
    events: tuple[jl.LedgerEvent, ...],
    *,
    question: rc.Question,
    gap_id: str,
    subjects: tuple[rc.SubjectRef, ...],
    input_anchor_ids: tuple[str, ...],
    sample_digest: str,
    index_key: str | None,
    index_block: Mapping[str, object] | None,
    cache_root: str,
    producer: rc.ProducerRef,
    policy: rc.PolicyRef,
    actor: rc.Actor,
    occurred_at: str,
) -> tuple[jl.LedgerEvent, ...]:
    parameters: dict[str, object]
    if index_key is not None:
        parameters = {"index_key": index_key}
    else:
        parameters = {"input_digest": sample_digest}

    action = _build_action(
        question_id=question.question_id,
        gap_id=gap_id,
        action_type="jadx-usage-query",
        nonce_material=_canonical_digest(parameters),
        parameters=parameters,
        subjects=subjects,
        input_anchor_ids=input_anchor_ids,
        producer=producer,
    )
    events = _append(
        events,
        jl.EventType.ACTION_PROPOSED,
        actor,
        occurred_at,
        action,
    )

    authorization = _authorization(action_id=action.action_id, policy=policy)
    events = _append(
        events,
        jl.EventType.ACTION_AUTHORIZED,
        actor,
        occurred_at,
        authorization,
    )

    query_state, coverage = _index_state_and_coverage(index_block)
    result = index_ledger.IndexQueryResult(
        state=query_state,
        coverage=coverage,
        hits=(),
        manifest_digest=_manifest_digest(cache_root, index_key),
        shard_digests=(),
        reason_codes=_receipt_reason_codes(index_block),
        query_receipt_locator=None,
    )
    return index_ledger.append_jadx_query_projection(
        events,
        action_id=action.action_id,
        result=result,
        actor=actor,
        occurred_at=occurred_at,
    )


def _append_ownership_action_if_available(
    events: tuple[jl.LedgerEvent, ...],
    *,
    question: rc.Question,
    gap_id: str,
    subjects: tuple[rc.SubjectRef, ...],
    input_anchor_ids: tuple[str, ...],
    summary: Mapping[str, object] | None,
    cache_root: str,
    producer: rc.ProducerRef,
    policy: rc.PolicyRef,
    actor: rc.Actor,
    occurred_at: str,
    current_index_key: str | None,
) -> tuple[jl.LedgerEvent, ...]:
    """重放 ownership 查询；任何前置条件不满足时不创建该动作。

    ownership 摘要只能为**当前样本的索引**追加动作：摘要 subject_index_key 必须
    等于本次 run 解析出的 index key，否则无法证明摘要属于当前样本，fail-closed
    放弃。cache 内容是 P1 声明的信任边界——load 后不再复读 manifest 字节做
    TOCTOU 比对（能写 cache 的攻击者本就能伪造本阶段读取的一切工件）。
    """

    if summary is None or summary.get("status") != "compared":
        return events

    subject_key = _valid_hex_key(summary.get("subject_index_key"))
    if current_index_key is None or subject_key != current_index_key:
        return events
    baseline_key = _valid_hex_key(summary.get("baseline_index_key"))
    declared_baseline_digest = _valid_digest(summary.get("baseline_manifest_digest"))

    if subject_key is None or baseline_key is None or declared_baseline_digest is None:
        return events

    actual_baseline_digest = _manifest_digest(cache_root, baseline_key)
    if actual_baseline_digest != declared_baseline_digest:
        return events

    try:
        store = JadxIndexStore(cache_root)
        subject_loaded = store.load_index(subject_key)
        baseline_loaded = store.load_index(baseline_key)
    except Exception:  # noqa: BLE001 — 可选动作不可污染主 ledger 流
        logger.exception("JADX ownership ledger 重放加载失败")
        return events

    if not isinstance(subject_loaded, LoadedIndex):
        return events
    if not isinstance(baseline_loaded, LoadedIndex):
        return events
    if subject_loaded.manifest.index_key != subject_key:
        return events
    if baseline_loaded.manifest.index_key != baseline_key:
        return events

    try:
        projection = project_ownership(subject_loaded, baseline_loaded)
    except Exception:  # noqa: BLE001 — 可选动作失败时不留下悬空 proposed action
        logger.exception("JADX ownership ledger 投影失败")
        return events

    parameters = {
        "subject_index_key": subject_key,
        "baseline_index_key": baseline_key,
        "baseline_manifest_digest": declared_baseline_digest,
    }
    action = _build_action(
        question_id=question.question_id,
        gap_id=gap_id,
        action_type="jadx-ownership-projection",
        nonce_material=_canonical_digest(parameters),
        parameters=parameters,
        subjects=subjects,
        input_anchor_ids=input_anchor_ids,
        producer=producer,
    )

    # 所有可能失败的 load/project 均已完成；此后才追加动作，避免悬空 action。
    result_events = _append(
        events,
        jl.EventType.ACTION_PROPOSED,
        actor,
        occurred_at,
        action,
    )
    authorization = _authorization(action_id=action.action_id, policy=policy)
    result_events = _append(
        result_events,
        jl.EventType.ACTION_AUTHORIZED,
        actor,
        occurred_at,
        authorization,
    )

    subject_manifest_digest = _manifest_digest(cache_root, subject_key)
    coverage = projection.subject_coverage
    if coverage not in ("complete", "partial"):
        coverage = None

    result = index_ledger.OwnershipQueryResult(
        state=index_ledger.IndexQueryState.HIT,
        coverage=coverage,
        projection=projection,
        manifest_digest=subject_manifest_digest,
        baseline_manifest_digest=declared_baseline_digest,
        shard_digests=(),
        reason_codes=(),
        query_receipt_locator=None,
    )
    return index_ledger.append_jadx_ownership_projection(
        result_events,
        action_id=action.action_id,
        result=result,
        actor=actor,
        occurred_at=occurred_at,
    )


def _append_visibility_section(
    events: tuple[jl.LedgerEvent, ...],
    *,
    meta: Mapping[str, object],
    subjects: tuple[rc.SubjectRef, ...],
    actor: rc.Actor,
    occurred_at: str,
    system_producer: rc.ProducerRef,
) -> tuple[tuple[jl.LedgerEvent, ...], dict[str, object]]:
    from apkscan.core import gap_production

    visibility = meta.get("visibility")
    if visibility is None:
        return events, {
            "appended": False,
            "reason": "visibility_missing",
        }

    # 非 Mapping 值不得进 gap 生产层：裸 AttributeError 会逃过本节的显式簿记口径。
    if not isinstance(visibility, Mapping):
        return events, {
            "appended": False,
            "reason": "visibility_invalid",
        }

    visibility_question = codec.build_question(
        question_type=rc.QuestionType.PLAN_REANALYSIS,
        subjects=subjects,
        allowed_conclusions=(
            rc.AllowedConclusion(
                predicate="analysis-visibility-recoverable",
                claim_modes=(rc.ClaimMode.POSITIVE,),
                object_kind=rc.ObjectKind.NONE,
                allowed_categorical_values=(),
            ),
        ),
    )

    try:
        gaps = gap_production.build_visibility_gaps(
            visibility,
            question_id=visibility_question.question_id,
            producer=system_producer,
        )
    except gap_production.GapProductionError as exc:
        return events, {
            "appended": False,
            "reason": exc.reason_code,
        }

    # 无 gap 时不得把空 question 入账。
    if not gaps:
        return events, {
            "appended": False,
            "reason": "no_blocked_claims",
        }

    events = _append(
        events,
        jl.EventType.QUESTION_OPENED,
        actor,
        occurred_at,
        visibility_question,
    )
    for gap in gaps:
        events = _append(
            events,
            jl.EventType.GAP_IDENTIFIED,
            actor,
            occurred_at,
            gap,
        )

    return events, {
        "appended": True,
        "gap_count": len(gaps),
        "question_id": visibility_question.question_id,
    }


def _build_events(
    *,
    meta: Mapping[str, object],
    cache_root: str,
    sample_sha256: str,
) -> tuple[tuple[jl.LedgerEvent, ...], dict[str, object]]:
    sample_digest = "sha256:" + sample_sha256
    index_block = _receipt_index(meta)

    receipt_key = _valid_hex_key(index_block.get("key")) if index_block is not None else None
    flattened_key = _valid_hex_key(meta.get("jadx_index_key"))

    # receipt key 与兼容扁平 key 冲突时不选择任一 manifest，避免锚错索引。
    if receipt_key is not None and flattened_key is not None and receipt_key != flattened_key:
        index_key = None
    else:
        index_key = receipt_key or flattened_key

    raw_summary = meta.get("jadx_ownership_summary")
    ownership_summary = raw_summary if isinstance(raw_summary, dict) else None

    subjects = (
        rc.SubjectRef(
            kind=rc.SubjectKind.SAMPLE,
            value=sample_sha256,
            role=None,
        ),
    )
    rc.validate_contract_value(subjects[0])

    policy = _policy()
    producer = _producer(meta)
    anchors = _run_anchors(
        sample_digest=sample_digest,
        cache_root=cache_root,
        subject_index_key=index_key,
        ownership_summary=ownership_summary,
    )

    nonce_material = _canonical_digest(
        {
            "sample_digest": sample_digest,
            "index_key": index_key,
            "configuration_digest": producer.configuration_digest,
        }
    )
    run = codec.build_reasoning_run(
        execution_nonce=_deterministic_nonce(
            "jadx-ledger-run",
            sample_sha256,
            nonce_material,
        ),
        purpose="jadx_index_query_ledger",
        subjects=subjects,
        input_anchors=anchors,
        initial_coverage=(),
        policies=(policy,),
        producers=(producer,),
    )

    # contract 要求 allowed_conclusions 非空。NONE 是无宾语的一元谓词，表示
    # JADX 索引观测面可用性；本账本只记录该观测面状态，不由此产生任何 claim。
    question = codec.build_question(
        question_type=rc.QuestionType.PLAN_REANALYSIS,
        subjects=subjects,
        allowed_conclusions=(
            rc.AllowedConclusion(
                predicate="jadx-index-observation-surface-available",
                claim_modes=(rc.ClaimMode.POSITIVE,),
                object_kind=rc.ObjectKind.NONE,
                allowed_categorical_values=(),
            ),
        ),
    )

    # 账本契约：ACTION_AUTHORIZED 的 actor 只许 SYSTEM（自动策略、granted=OFFLINE、
    # reason 带 policy_pre_authorized）或 HUMAN——具名自动策略即 SYSTEM，绝不伪装人签。
    actor = rc.Actor(
        kind=rc.ActorKind.SYSTEM,
        actor_id=_AUTO_POLICY_ID,
    )
    rc.validate_contract_value(actor)

    occurred_at = _occurred_at()

    first = jl.make_event(
        (),
        jl.EventType.RUN_OPENED,
        actor,
        occurred_at,
        run,
    )
    events = jl.append_event((), first)
    events = _append(
        events,
        jl.EventType.QUESTION_OPENED,
        actor,
        occurred_at,
        question,
    )

    # P0 契约：动作由 gap 驱动（gap_ids 非空）。本账本的 gap =「索引观察面尚未入账」。
    # gap/NextAction 的 producer 契约只允许 MODEL/SYSTEM（提案主体是系统，不是查询本身；
    # QUERY producer 留在 run.producers 供 outcome 锚定执行者）。
    system_producer = _system_producer()
    gap = codec.build_evidence_gap(
        question_id=question.question_id,
        claim_id=None,
        effect=rc.GapEffect.REDUCES_CONFIDENCE,
        reason_codes=("index_observation_surface_unrecorded",),
        required_observation_types=("jadx_value_usage",),
        coverage_requirements=(),
        producer=system_producer,
    )
    events = _append(
        events,
        jl.EventType.GAP_IDENTIFIED,
        actor,
        occurred_at,
        gap,
    )

    events, visibility_note = _append_visibility_section(
        events,
        meta=meta,
        subjects=subjects,
        actor=actor,
        occurred_at=occurred_at,
        system_producer=system_producer,
    )

    input_anchor_ids = tuple(sorted(anchor.anchor_id for anchor in anchors))
    events = _append_usage_action(
        events,
        question=question,
        gap_id=gap.gap_id,
        subjects=subjects,
        input_anchor_ids=input_anchor_ids,
        sample_digest=sample_digest,
        index_key=index_key,
        index_block=index_block,
        cache_root=cache_root,
        producer=system_producer,
        policy=policy,
        actor=actor,
        occurred_at=occurred_at,
    )
    events = _append_ownership_action_if_available(
        events,
        question=question,
        gap_id=gap.gap_id,
        subjects=subjects,
        input_anchor_ids=input_anchor_ids,
        summary=ownership_summary,
        cache_root=cache_root,
        current_index_key=index_key,
        producer=system_producer,
        policy=policy,
        actor=actor,
        occurred_at=occurred_at,
    )

    jl.validate_event_chain(events)
    jl.replay(events)
    return events, visibility_note


def _anchor(
    *,
    locator: str,
    replay_ok: bool,
    digest: str | None = None,
    event_count: int | None = None,
    attempted_digest: str | None = None,
    attempted_event_count: int | None = None,
    reason: str | None = None,
    published: bool | None = None,
    visibility_gaps: dict[str, object] | None = None,
) -> dict[str, object]:
    """锚只写实际存在且语义匹配的字段：digest/event_count 只描述已验证的磁盘文件；
    attempted_* 描述本次拟发布字节——冲突/失败时绝不冒充磁盘摘要。"""
    value: dict[str, object] = {"locator": locator, "replay_ok": replay_ok}
    if visibility_gaps is not None:
        value["visibility_gaps"] = visibility_gaps
    if digest is not None:
        value["digest"] = digest
    if event_count is not None:
        value["event_count"] = event_count
    if attempted_digest is not None:
        value["attempted_digest"] = attempted_digest
    if attempted_event_count is not None:
        value["attempted_event_count"] = attempted_event_count
    if reason is not None:
        value["reason"] = reason
    if published is not None:
        value["published"] = published
    return value


def _verify_published(path: Path, expected: bytes) -> tuple[jl.LedgerEvent, ...]:
    actual = path.read_bytes()
    if actual != expected:
        raise ValueError("published_sidecar_bytes_mismatch")

    text = actual.decode("utf-8")
    lines = text.splitlines()
    if not lines or any(not line for line in lines):
        raise ValueError("invalid_sidecar_jsonl")

    events = tuple(jl.decode_event(line) for line in lines)
    jl.validate_event_chain(events)
    jl.replay(events)
    return events


def build_and_publish(
    *,
    ctx: object,
    meta: Mapping[str, object],
    cache_root: str,
    out_dir: str,
) -> dict[str, object] | None:
    """构造并发布 ledger sidecar。

    返回：
    - 未启用、无输出目录或样本哈希失败：None；
    - 已尝试构造/发布：ledger meta 锚，包括失败状态；
    - 所有异常均在本函数内部处理，不向 pipeline 抛出。
    """

    if not isinstance(cache_root, str) or not cache_root:
        return None
    if not isinstance(out_dir, str) or not out_dir:
        return None

    apk_path = getattr(ctx, "apk_path", None)
    if not isinstance(apk_path, str) or not apk_path:
        return None

    sample_sha256 = _sample_sha256(apk_path)
    if sample_sha256 is None:
        return None

    locator = _sidecar_name(sample_sha256)
    visibility_note: dict[str, object] | None = None
    try:
        events, visibility_note = _build_events(
            meta=meta,
            cache_root=cache_root,
            sample_sha256=sample_sha256,
        )
        data = ("\n".join(jl.encode_event(event) for event in events) + "\n").encode("utf-8")
    except Exception:  # noqa: BLE001 — ledger 是附加消费面，构造失败不得打断主分析
        logger.exception("JADX judgment ledger 构造失败")
        return _anchor(
            locator=locator,
            replay_ok=False,
            reason=_REASON_LEDGER_BUILD_FAILED,
            visibility_gaps=visibility_note,
        )

    attempted_digest = _sha256_bytes(data)
    attempted_event_count = len(events)
    target = Path(out_dir) / locator
    try:
        published = atomic_create_bytes(target, data)
    except Exception:  # noqa: BLE001 — 原子发布失败必须留痕但不得传播
        logger.exception("JADX judgment ledger sidecar 发布失败")
        return _anchor(
            locator=locator,
            replay_ok=False,
            attempted_digest=attempted_digest,
            attempted_event_count=attempted_event_count,
            reason=_REASON_PUBLISH_FAILED,
            published=False,
            visibility_gaps=visibility_note,
        )

    if not published:
        return _anchor(
            locator=locator,
            replay_ok=False,
            attempted_digest=attempted_digest,
            attempted_event_count=attempted_event_count,
            reason=_REASON_ALREADY_EXISTS,
            published=False,
            visibility_gaps=visibility_note,
        )

    try:
        replayed = _verify_published(target, data)
    except Exception:  # noqa: BLE001 — 文件已发布但未通过回读/replay，不能声称闭合
        logger.exception("JADX judgment ledger sidecar replay 失败")
        return _anchor(
            locator=locator,
            replay_ok=False,
            attempted_digest=attempted_digest,
            attempted_event_count=attempted_event_count,
            reason=_REASON_REPLAY_FAILED,
            published=True,
            visibility_gaps=visibility_note,
        )

    return _anchor(
        locator=locator,
        digest=attempted_digest,
        event_count=len(replayed),
        replay_ok=True,
        visibility_gaps=visibility_note,
    )


__all__ = [
    "build_and_publish",
]
