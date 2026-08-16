"""提供确定性的重新分析准入、授权过滤与动作规划纯函数。"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import NoReturn

from apkscan.core import reanalysis_contract as rxc
from apkscan.core import recognition_codec as codec
from apkscan.core import recognition_contract as rc
from apkscan.core.judgment_ledger import GapStatus


@dataclass(frozen=True, slots=True)
class AdmissionPolicy:
    """重新分析准入谓词及 reason 到分析类型的版本化映射。"""

    predicate_version: str
    mapping_version: str
    reason_mapping: Mapping[str, tuple[rxc.AnalysisType, ...]]
    reduces_confidence_whitelist: frozenset[str]


# 谓词语义由本模块代码实现：声明未支持的 predicate_version 即宣称本模块没有的语义，
# 必须 fail-closed（codex 复审 P1）。mapping_version 是调用方对表内容的出处声明，
# 表内容本身随策略注入，形态另行校验。
SUPPORTED_PREDICATE_VERSIONS = frozenset({"p3-admit-v1"})

DEFAULT_ADMISSION_POLICY = AdmissionPolicy(
    "p3-admit-v1",
    "p3-mapping-v1",
    {},
    frozenset(),
)


@dataclass(frozen=True, slots=True)
class PlannedAction:
    """规划生成的动作及其投影元数据。"""

    action: rc.NextAction
    meta: rxc.PlanningMeta


@dataclass(frozen=True, slots=True)
class PlanningReceipt:
    """规划过程中的版本信息、准入统计和授权过滤统计。"""

    predicate_version: str
    mapping_version: str
    matrix_version: str
    gaps_seen: int
    suppressed_not_open: int
    suppressed_low_value: int
    suppressed_unknown_reason: int
    suppressed_by_ceiling: tuple[tuple[str, int], ...]
    emitted: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class PlanningResult:
    """确定性的重新分析规划结果。"""

    planned: tuple[PlannedAction, ...]
    receipt: PlanningReceipt


def _fail(code: str, field_path: str) -> NoReturn:
    raise rc.SchemaValidationError(code, field_path=field_path)


def derive_attempt_nonce(
    *,
    dedupe_key: str,
    question_id: str,
    gap_ids: tuple[str, ...],
) -> str:
    """由动作去重键、问题和 gap 集合确定性派生 32 位十六进制 nonce。"""

    payload = {
        "attempt_of": dedupe_key,
        "question_id": question_id,
        "gap_ids": sorted(gap_ids),
    }
    return hashlib.sha256(codec.canonical_json_v1(payload)).hexdigest()[:32]


def _priority_for_gaps(
    gaps: tuple[rc.EvidenceGap, ...],
) -> rxc.PriorityClass:
    if any(gap.effect is rc.GapEffect.BLOCKS_CLAIM for gap in gaps):
        return rxc.PriorityClass.HIGH
    if any(gap.effect is rc.GapEffect.BLOCKS_REVIEW for gap in gaps):
        return rxc.PriorityClass.REVIEW
    return rxc.PriorityClass.LOW


def _count_tuple(
    counts: Mapping[rxc.AnalysisType, int],
) -> tuple[tuple[str, int], ...]:
    return tuple(
        (analysis_type.value, counts[analysis_type])
        for analysis_type in sorted(counts, key=lambda item: item.value)
    )


def plan_reanalysis(
    context: rxc.PlanningContext,
    *,
    producer: rc.ProducerRef,
    policy: AdmissionPolicy,
) -> PlanningResult:
    """根据准入策略和授权上限确定性生成重新分析动作。"""

    if policy.predicate_version not in SUPPORTED_PREDICATE_VERSIONS:
        _fail("predicate_version_unsupported", "$.policy.predicate_version")
    if not isinstance(policy.mapping_version, str) or not policy.mapping_version:
        _fail("mapping_version_invalid", "$.policy.mapping_version")
    for reason, mapped in policy.reason_mapping.items():
        # 空元组映射项会造成「已知 reason 但零授予」的静默抑制面（codex 复审 P1）。
        if not mapped:
            _fail("reason_mapping_empty_entry", f"$.policy.reason_mapping[{reason!r}]")

    rxc.validate_planning_context(context)

    suppressed_not_open = 0
    suppressed_low_value = 0
    suppressed_unknown_reason = 0
    suppressed_by_ceiling: dict[rxc.AnalysisType, int] = {}
    emitted: dict[rxc.AnalysisType, int] = {}

    admitted_by_type: dict[
        rxc.AnalysisType,
        dict[str, rc.EvidenceGap],
    ] = {}

    for gap in context.gaps:
        if context.gap_statuses[gap.gap_id] is not GapStatus.OPEN:
            suppressed_not_open += 1
            continue

        if gap.effect is rc.GapEffect.REDUCES_CONFIDENCE and not any(
            reason in policy.reduces_confidence_whitelist
            for reason in gap.reason_codes
        ):
            suppressed_low_value += 1
            continue

        mapped_types: set[rxc.AnalysisType] = set()
        has_unknown_reason = False
        for reason in gap.reason_codes:
            mapped = policy.reason_mapping.get(reason)
            if mapped is None:
                has_unknown_reason = True
            else:
                mapped_types.update(mapped)

        if not mapped_types:
            if has_unknown_reason:
                suppressed_unknown_reason += 1
            continue

        for analysis_type in mapped_types:
            required_authorization = rxc.ANALYSIS_AUTHORIZATION[analysis_type]
            if (
                rxc.AUTHORIZATION_ORDER[required_authorization]
                > rxc.AUTHORIZATION_ORDER[context.authorization_ceiling]
            ):
                suppressed_by_ceiling[analysis_type] = (
                    suppressed_by_ceiling.get(analysis_type, 0) + 1
                )
                continue

            emitted[analysis_type] = emitted.get(analysis_type, 0) + 1
            admitted_by_type.setdefault(analysis_type, {})[gap.gap_id] = gap

    planned: list[PlannedAction] = []
    subjects = context.question.subjects
    input_anchor_ids = tuple(
        sorted(anchor.anchor_id for anchor in context.anchors)
    )
    parameters_digest = "sha256:" + hashlib.sha256(
        codec.canonical_json_v1({"input_digest": context.sample_digest})
    ).hexdigest()

    for analysis_type in sorted(
        admitted_by_type,
        key=lambda item: item.value,
    ):
        gaps = tuple(
            admitted_by_type[analysis_type][gap_id]
            for gap_id in sorted(admitted_by_type[analysis_type])
        )
        gap_ids = tuple(gap.gap_id for gap in gaps)
        success_criteria = tuple(
            sorted(
                {
                    observation_type
                    for gap in gaps
                    for observation_type in gap.required_observation_types
                }
            )
        )
        if not success_criteria:
            # 合法 gap 可以只带 coverage_requirements（契约二选一）；NextAction 的
            # success_criteria 必须非空，此处用固定 fallback token 表达该语义。
            success_criteria = ("coverage_requirements_satisfied",)
        negative_valid_only_if: tuple[rc.CoveragePredicate, ...] = ()
        authorization_required = rxc.ANALYSIS_AUTHORIZATION[analysis_type]
        budget = rc.ActionBudget(max_seconds=600, max_memory_mb=4096)

        dedupe_key = codec.compute_action_dedupe_key(
            action_type=analysis_type.value,
            subjects=subjects,
            input_anchor_ids=input_anchor_ids,
            parameters_digest=parameters_digest,
            authorization_required=authorization_required,
            budget=budget,
            success_criteria=success_criteria,
            negative_valid_only_if=negative_valid_only_if,
            producer=producer,
        )
        attempt_nonce = derive_attempt_nonce(
            dedupe_key=dedupe_key,
            question_id=context.question.question_id,
            gap_ids=gap_ids,
        )
        action = codec.build_next_action(
            question_id=context.question.question_id,
            gap_ids=gap_ids,
            attempt_nonce=attempt_nonce,
            action_type=analysis_type.value,
            subjects=subjects,
            input_anchor_ids=input_anchor_ids,
            parameters_digest=parameters_digest,
            authorization_required=authorization_required,
            budget=budget,
            success_criteria=success_criteria,
            negative_valid_only_if=negative_valid_only_if,
            producer=producer,
        )
        meta = rxc.PlanningMeta(
            priority_class=_priority_for_gaps(gaps),
            expected_information_gain=0.5,
            current_coverage=(),
        )
        planned.append(PlannedAction(action=action, meta=meta))

    receipt = PlanningReceipt(
        predicate_version=policy.predicate_version,
        mapping_version=policy.mapping_version,
        matrix_version=rxc.MATRIX_VERSION,
        gaps_seen=len(context.gaps),
        suppressed_not_open=suppressed_not_open,
        suppressed_low_value=suppressed_low_value,
        suppressed_unknown_reason=suppressed_unknown_reason,
        suppressed_by_ceiling=_count_tuple(suppressed_by_ceiling),
        emitted=_count_tuple(emitted),
    )
    return PlanningResult(planned=tuple(planned), receipt=receipt)
