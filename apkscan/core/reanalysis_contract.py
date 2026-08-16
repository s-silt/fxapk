"""定义重新分析规划、投影、校验及线协议编解码契约。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, NoReturn, cast

from apkscan.core import recognition_codec as codec
from apkscan.core import recognition_contract as rc
from apkscan.core.judgment_ledger import GapStatus


class AnalysisType(StrEnum):
    JADX_CALLPATH = "jadx_callpath"
    JADX_STRUCTURAL_DIFF = "jadx_structural_diff"
    NATIVE_BUILDINFO = "native_buildinfo"
    NATIVE_FUNCTION_DIFF = "native_function_diff"
    WEB_EVIDENCE = "web_evidence"
    OFFICIAL_BASELINE_DIFF = "official_baseline_diff"
    PASSIVE_ENRICHMENT = "passive_enrichment"
    PCAP_RUNTIME = "pcap_runtime"


class PriorityClass(StrEnum):
    HIGH = "high"
    REVIEW = "review"
    LOW = "low"


class RequestStatus(StrEnum):
    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    RUNNING = "running"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


ANALYSIS_AUTHORIZATION: dict[AnalysisType, rc.AuthorizationLevel] = {
    AnalysisType.JADX_CALLPATH: rc.AuthorizationLevel.OFFLINE,
    AnalysisType.JADX_STRUCTURAL_DIFF: rc.AuthorizationLevel.OFFLINE,
    AnalysisType.NATIVE_BUILDINFO: rc.AuthorizationLevel.OFFLINE,
    AnalysisType.NATIVE_FUNCTION_DIFF: rc.AuthorizationLevel.OFFLINE,
    AnalysisType.WEB_EVIDENCE: rc.AuthorizationLevel.OFFLINE,
    AnalysisType.OFFICIAL_BASELINE_DIFF: rc.AuthorizationLevel.OFFLINE,
    AnalysisType.PASSIVE_ENRICHMENT: rc.AuthorizationLevel.PASSIVE_ONLINE,
    AnalysisType.PCAP_RUNTIME: rc.AuthorizationLevel.AUTHORIZED_DEVICE,
}

EXECUTOR_AVAILABLE: dict[AnalysisType, bool] = {
    analysis_type: analysis_type is not AnalysisType.OFFICIAL_BASELINE_DIFF
    for analysis_type in AnalysisType
}

AUTHORIZATION_ORDER: dict[rc.AuthorizationLevel, int] = {
    rc.AuthorizationLevel.OFFLINE: 0,
    rc.AuthorizationLevel.PASSIVE_ONLINE: 1,
    rc.AuthorizationLevel.AUTHORIZED_DEVICE: 2,
}

MATRIX_VERSION = "p3-matrix-v1"


@dataclass(frozen=True, slots=True)
class PlanningMeta:
    priority_class: PriorityClass
    expected_information_gain: float
    current_coverage: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class RequestOrigin:
    gap_ids: tuple[str, ...]
    question_id: str
    candidate_id: str | None
    input_digest: str


@dataclass(frozen=True, slots=True)
class PlanningContext:
    question: rc.Question
    gaps: tuple[rc.EvidenceGap, ...]
    gap_statuses: Mapping[str, GapStatus]
    anchors: tuple[rc.EvidenceAnchor, ...]
    supporting_observation_ids: tuple[str, ...]
    contradicting_observation_ids: tuple[str, ...]
    authorization_ceiling: rc.AuthorizationLevel
    sample_digest: str


@dataclass(frozen=True, slots=True)
class ReanalysisRequest:
    kind: Literal["reanalysis_request"]
    schema_version: Literal["1.0"]
    request_id: str
    subject_refs: tuple[rc.SubjectRef, ...]
    question_type: rc.QuestionType
    analysis_type: AnalysisType
    reason_codes: tuple[str, ...]
    current_coverage: tuple[tuple[str, str], ...]
    supporting_evidence_refs: tuple[str, ...]
    contradicting_evidence_refs: tuple[str, ...]
    required_observations: tuple[str, ...]
    success_criteria: tuple[str, ...]
    negative_valid_only_if: tuple[rc.CoveragePredicate, ...]
    priority_class: PriorityClass
    expected_information_gain: float
    authorization: rc.AuthorizationLevel
    budget: rc.ActionBudget
    dedupe_key: str
    origin: RequestOrigin
    status: RequestStatus


def _fail(code: str, field_path: str) -> NoReturn:
    raise rc.SchemaValidationError(code, field_path=field_path)


def _enum(value: object, enum_type: type[StrEnum], path: str) -> StrEnum:
    if not isinstance(value, str):
        _fail("enum_type_invalid", path)
    try:
        return enum_type(value)
    except ValueError:
        _fail("enum_value_invalid", path)


def _strings(value: object, path: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        _fail("sequence_invalid", path)
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            _fail("string_invalid", f"{path}[{index}]")
        result.append(item)
    return tuple(result)


def validate_planning_context(context: PlanningContext) -> None:
    if not context.gaps:
        _fail("gaps_empty", "$.gaps")
    if len({gap.gap_id for gap in context.gaps}) != len(context.gaps):
        # 重复 gap 会让 receipt 授予计数与实际 gap_ids 去重结果失配（codex 复审 P2）。
        _fail("gap_duplicate", "$.gaps")
    if not isinstance(context.question.question_id, str):
        _fail("question_id_invalid", "$.question.question_id")
    for index, gap in enumerate(context.gaps):
        path = f"$.gaps[{index}]"
        if gap.question_id != context.question.question_id:
            _fail("gap_question_mismatch", f"{path}.question_id")
        if gap.gap_id not in context.gap_statuses:
            _fail("gap_status_missing", f"$.gap_statuses[{gap.gap_id!r}]")
        if not isinstance(context.gap_statuses[gap.gap_id], GapStatus):
            _fail("gap_status_invalid", f"$.gap_statuses[{gap.gap_id!r}]")
    if (
        not isinstance(context.sample_digest, str)
        or len(context.sample_digest) != 71
        or not context.sample_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in context.sample_digest[7:])
    ):
        _fail("sample_digest_invalid", "$.sample_digest")
    if context.authorization_ceiling not in AUTHORIZATION_ORDER:
        _fail("authorization_ceiling_invalid", "$.authorization_ceiling")


def validate_reanalysis_request(request: ReanalysisRequest) -> None:
    if request.kind != "reanalysis_request":
        _fail("kind_invalid", "$.kind")
    if request.schema_version != "1.0":
        _fail("schema_version_invalid", "$.schema_version")
    if not isinstance(request.request_id, str) or not request.request_id:
        _fail("request_id_invalid", "$.request_id")
    if not isinstance(request.dedupe_key, str) or not request.dedupe_key:
        _fail("dedupe_key_invalid", "$.dedupe_key")
    if not isinstance(request.origin, RequestOrigin):
        _fail("origin_invalid", "$.origin")
    if not isinstance(request.question_type, rc.QuestionType):
        _fail("question_type_invalid", "$.question_type")
    if not isinstance(request.analysis_type, AnalysisType):
        _fail("analysis_type_invalid", "$.analysis_type")
    if not isinstance(request.priority_class, PriorityClass):
        _fail("priority_class_invalid", "$.priority_class")
    if not isinstance(request.authorization, rc.AuthorizationLevel):
        _fail("authorization_invalid", "$.authorization")
    if not isinstance(request.status, RequestStatus):
        _fail("status_invalid", "$.status")
    # bool 是 int 子类：True/False 会冒充数值混进增益字段，必须显式排除。
    if (
        isinstance(request.expected_information_gain, bool)
        or not isinstance(request.expected_information_gain, float | int)
        or not (0.0 <= request.expected_information_gain <= 1.0)
    ):
        _fail("information_gain_out_of_range", "$.expected_information_gain")
    if not request.origin.gap_ids:
        _fail("origin_gap_ids_empty", "$.origin.gap_ids")
    if request.origin.candidate_id is not None and not isinstance(
        request.origin.candidate_id, str
    ):
        _fail("candidate_id_invalid", "$.origin.candidate_id")
    if not isinstance(request.budget, rc.ActionBudget):
        _fail("budget_invalid", "$.budget")
    if request.authorization is not ANALYSIS_AUTHORIZATION[request.analysis_type]:
        _fail("authorization_matrix_mismatch", "$.authorization")


def project_reanalysis_request(
    action: rc.NextAction,
    context: PlanningContext,
    meta: PlanningMeta,
) -> ReanalysisRequest:
    validate_planning_context(context)

    try:
        analysis_type = AnalysisType(action.action_type)
    except ValueError:
        _fail("analysis_type_unknown", "$.action.action_type")

    expected_authorization = ANALYSIS_AUTHORIZATION[analysis_type]
    if action.authorization_required is not expected_authorization:
        _fail("authorization_matrix_mismatch", "$.action.authorization_required")
    # 纵深防御：ceiling 过滤本该发生在 planner（含抑制计数），投影作为公共接缝
    # 仍须拒绝越限动作——否则绕开 planner 直调投影即可越过授权上限。
    if (
        AUTHORIZATION_ORDER[action.authorization_required]
        > AUTHORIZATION_ORDER[context.authorization_ceiling]
    ):
        _fail("authorization_exceeds_ceiling", "$.action.authorization_required")
    if action.question_id != context.question.question_id:
        _fail("question_id_mismatch", "$.action.question_id")

    gaps_by_id = {gap.gap_id: gap for gap in context.gaps}
    selected: list[rc.EvidenceGap] = []
    for index, gap_id in enumerate(action.gap_ids):
        if gap_id not in gaps_by_id:
            _fail("gap_unknown", f"$.action.gap_ids[{index}]")
        selected.append(gaps_by_id[gap_id])

    reason_codes = tuple(
        sorted({code for gap in selected for code in gap.reason_codes})
    )
    required_observations = tuple(
        sorted({item for gap in selected for item in gap.required_observation_types})
    )
    request = ReanalysisRequest(
        kind="reanalysis_request",
        schema_version="1.0",
        request_id=action.action_id,
        subject_refs=action.subjects,
        question_type=context.question.question_type,
        analysis_type=analysis_type,
        reason_codes=reason_codes,
        current_coverage=meta.current_coverage,
        supporting_evidence_refs=context.supporting_observation_ids,
        contradicting_evidence_refs=context.contradicting_observation_ids,
        required_observations=required_observations,
        success_criteria=action.success_criteria,
        negative_valid_only_if=action.negative_valid_only_if,
        priority_class=meta.priority_class,
        expected_information_gain=meta.expected_information_gain,
        authorization=action.authorization_required,
        budget=action.budget,
        dedupe_key=action.dedupe_key,
        origin=RequestOrigin(
            gap_ids=action.gap_ids,
            question_id=action.question_id,
            candidate_id=None,
            input_digest=context.sample_digest,
        ),
        status=RequestStatus.PROPOSED,
    )
    validate_reanalysis_request(request)
    return request


def encode_reanalysis_request(request: ReanalysisRequest) -> dict[str, object]:
    validate_reanalysis_request(request)
    coverage = {key: value for key, value in request.current_coverage}
    return {
        "kind": request.kind,
        "schema_version": request.schema_version,
        "request_id": request.request_id,
        "subject_refs": cast(list[object], codec._to_json_value(request.subject_refs)),
        "question_type": request.question_type.value,
        "analysis_type": request.analysis_type.value,
        "reason_codes": list(request.reason_codes),
        "current_coverage": coverage,
        "supporting_evidence_refs": list(request.supporting_evidence_refs),
        "contradicting_evidence_refs": list(request.contradicting_evidence_refs),
        "required_observations": list(request.required_observations),
        "success_criteria": list(request.success_criteria),
        "negative_valid_only_if": cast(
            list[object], codec._to_json_value(request.negative_valid_only_if)
        ),
        "priority": {
            "class": request.priority_class.value,
            "expected_information_gain": request.expected_information_gain,
        },
        "authorization": request.authorization.value,
        "budget": {
            "max_seconds": request.budget.max_seconds,
            "max_memory_mb": request.budget.max_memory_mb,
        },
        "dedupe_key": request.dedupe_key,
        "origin": {
            "gap_ids": list(request.origin.gap_ids),
            "question_id": request.origin.question_id,
            "candidate_id": request.origin.candidate_id,
            "input_digest": request.origin.input_digest,
        },
        "status": request.status.value,
    }


def _decode_dataclass(value: object, expected: type[object], path: str) -> object:
    try:
        return codec._decode_dataclass(value, expected, path)
    except rc.SchemaValidationError:
        raise
    except (TypeError, ValueError, KeyError):
        _fail("dataclass_invalid", path)


def decode_reanalysis_request(wire: Mapping[str, object]) -> ReanalysisRequest:
    expected_keys = {
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
    codec._exact_fields(wire, expected_keys, "$")

    if wire["kind"] != "reanalysis_request":
        _fail("kind_invalid", "$.kind")
    if wire["schema_version"] != "1.0":
        _fail("schema_version_invalid", "$.schema_version")

    subject_value = wire["subject_refs"]
    if not isinstance(subject_value, list):
        _fail("sequence_invalid", "$.subject_refs")
    subjects = tuple(
        cast(
            rc.SubjectRef,
            _decode_dataclass(item, rc.SubjectRef, f"$.subject_refs[{index}]"),
        )
        for index, item in enumerate(subject_value)
    )

    priority = codec._require_object(wire["priority"], "$.priority")
    codec._exact_fields(
        priority,
        {"class", "expected_information_gain"},
        "$.priority",
    )
    priority_class = cast(
        PriorityClass,
        _enum(priority["class"], PriorityClass, "$.priority.class"),
    )
    eig = priority["expected_information_gain"]
    if isinstance(eig, bool) or not isinstance(eig, float | int):
        _fail("information_gain_invalid", "$.priority.expected_information_gain")

    budget = cast(
        rc.ActionBudget,
        _decode_dataclass(wire["budget"], rc.ActionBudget, "$.budget"),
    )
    origin = cast(
        RequestOrigin,
        _decode_dataclass(wire["origin"], RequestOrigin, "$.origin"),
    )

    coverage_object = codec._require_object(
        wire["current_coverage"], "$.current_coverage"
    )
    coverage: list[tuple[str, str]] = []
    for key, value in coverage_object.items():
        if not isinstance(value, str):
            _fail("coverage_value_invalid", f"$.current_coverage[{key!r}]")
        coverage.append((key, value))

    negative_value = wire["negative_valid_only_if"]
    if not isinstance(negative_value, list):
        _fail("sequence_invalid", "$.negative_valid_only_if")
    negative = tuple(
        cast(
            rc.CoveragePredicate,
            _decode_dataclass(
                item,
                rc.CoveragePredicate,
                f"$.negative_valid_only_if[{index}]",
            ),
        )
        for index, item in enumerate(negative_value)
    )

    request = ReanalysisRequest(
        kind=cast(Literal["reanalysis_request"], wire["kind"]),
        schema_version=cast(Literal["1.0"], wire["schema_version"]),
        request_id=cast(str, wire["request_id"]),
        subject_refs=subjects,
        question_type=cast(
            rc.QuestionType,
            _enum(wire["question_type"], rc.QuestionType, "$.question_type"),
        ),
        analysis_type=cast(
            AnalysisType,
            _enum(wire["analysis_type"], AnalysisType, "$.analysis_type"),
        ),
        reason_codes=_strings(wire["reason_codes"], "$.reason_codes"),
        current_coverage=tuple(coverage),
        supporting_evidence_refs=_strings(
            wire["supporting_evidence_refs"], "$.supporting_evidence_refs"
        ),
        contradicting_evidence_refs=_strings(
            wire["contradicting_evidence_refs"],
            "$.contradicting_evidence_refs",
        ),
        required_observations=_strings(
            wire["required_observations"], "$.required_observations"
        ),
        success_criteria=_strings(wire["success_criteria"], "$.success_criteria"),
        negative_valid_only_if=negative,
        priority_class=priority_class,
        expected_information_gain=float(eig),
        authorization=cast(
            rc.AuthorizationLevel,
            _enum(wire["authorization"], rc.AuthorizationLevel, "$.authorization"),
        ),
        budget=budget,
        dedupe_key=cast(str, wire["dedupe_key"]),
        origin=origin,
        status=cast(
            RequestStatus, _enum(wire["status"], RequestStatus, "$.status")
        ),
    )
    validate_reanalysis_request(request)
    return request
