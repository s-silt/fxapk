"""Strict JSONL contract for multi-task recognition labels.

This module validates recognition-label records without resolving or parsing
``evidence_ref`` values. Validation is fail-closed and deterministic: per-record
rules are checked during the first pass, followed by cross-record rules in
source-line order.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, NoReturn, cast

__all__ = [
    "RecognitionLabelRecord",
    "RecognitionLabelSet",
    "RecognitionLabelValidationError",
    "load_recognition_labels",
]


_COMMON_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "kind",
        "schema_version",
        "record_id",
        "status",
        "layer",
        "author_kind",
        "label_basis",
        "evidence_ref",
        "label_lineage",
        "confidence",
        "supersedes",
        "reason_codes",
    }
)

_KIND_FIELDS: Final[Mapping[str, frozenset[str]]] = {
    "family_assignment": frozenset(
        {"sample_sha256", "level", "family_id"}
    ),
    "relation_judgment": frozenset(
        {
            "left_sha256",
            "right_sha256",
            "relation",
            "relation_subtype",
        }
    ),
    "clue_judgment": frozenset(
        {"clue_ref", "verdict", "ownership"}
    ),
    "ownership_judgment": frozenset(
        {"sample_sha256", "observation_ref", "ownership"}
    ),
    "reanalysis_outcome": frozenset(
        {
            "request_id",
            "outcome",
            "obtained_observation_types",
            "coverage_reason_codes",
        }
    ),
}

_STATUSES: Final[frozenset[str]] = frozenset(
    {"confirmed", "proposed", "rejected", "superseded"}
)
_LAYERS: Final[frozenset[str]] = frozenset(
    {"silver", "gold_internal", "gold_external", "adversarial"}
)
_AUTHOR_KINDS: Final[frozenset[str]] = frozenset(
    {"human", "model", "system"}
)
_LABEL_LINEAGES: Final[frozenset[str]] = frozenset(
    {"queue-internal", "queue-external", "unspecified"}
)
_LEVELS: Final[frozenset[str]] = frozenset(
    {
        "platform_family",
        "product_line",
        "customer_cluster",
        "operator_cluster",
    }
)
_RELATIONS: Final[frozenset[str]] = frozenset(
    {"positive", "negative", "unknown"}
)
_RELATION_SUBTYPES: Final[frozenset[str]] = frozenset(
    {
        "exact_artifact_identity",
        "binary_lineage",
        "packaging_pipeline",
        "product_line_reuse",
        "control_plane",
        "infrastructure_reuse",
        "technical_link_relevant",
        "same_operator",
    }
)
_VERDICTS: Final[frozenset[str]] = frozenset(
    {"valid", "invalid", "unknown"}
)
_OWNERSHIPS: Final[frozenset[str]] = frozenset(
    {
        "suspect_first_party",
        "inherited_official",
        "inherited_third_party",
        "shared_infrastructure",
        "unknown",
    }
)
_OUTCOMES: Final[frozenset[str]] = frozenset(
    {"obtained", "partial", "not_obtained"}
)
_RESERVED_FAMILY_IDS: Final[frozenset[str]] = frozenset(
    {"unknown", "abstain"}
)
_INACTIVE_STATUSES: Final[frozenset[str]] = frozenset(
    {"superseded", "rejected"}
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
# 受控 label_basis 词表（与 linkage_labels.LABEL_BASIS_FEATURE_FAMILIES 的键同源，
# 不跨模块 import——linkage 侧按母文档保持不动）。
_LABEL_BASIS_VOCABULARY: Final[frozenset[str]] = frozenset(
    {
        "independent-review",
        "remote-config-review",
        "native-binary-review",
        "signing-certificate-review",
        "build-root-review",
        "ioc-review",
        "rule-candidate-review",
    }
)

_EVIDENCE_REF_PLACEHOLDERS: Final[frozenset[str]] = frozenset(
    {
        "evidence",
        "evidenceref",
        "fixme",
        "missing",
        "nil",
        "none",
        "null",
        "pending",
        "placeholder",
        "tbd",
        "todo",
        "unknown",
    }
)

_TOKEN_ITEM_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z"
)

_OPAQUE_REF_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z"
)
_EVIDENCE_REF_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}\Z"
)
_FAMILY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z"
)


class RecognitionLabelValidationError(ValueError):
    """Raised when a recognition-label JSONL contract is violated."""

    code: str
    line: int

    def __init__(self, code: str, line: int) -> None:
        self.code = code
        self.line = line
        super().__init__(f"{code} at line {line}")


@dataclass(frozen=True, slots=True)
class RecognitionLabelRecord:
    """Immutable validated recognition-label record."""

    kind: str
    schema_version: str
    record_id: str
    status: str
    layer: str
    author_kind: str
    label_basis: tuple[str, ...]
    evidence_ref: str | None
    label_lineage: str
    confidence: float | None
    supersedes: str | None
    reason_codes: tuple[str, ...]

    sample_sha256: str | None = None
    level: str | None = None
    family_id: str | None = None

    left_sha256: str | None = None
    right_sha256: str | None = None
    relation: str | None = None
    relation_subtype: str | None = None

    clue_ref: str | None = None
    verdict: str | None = None
    ownership: str | None = None

    observation_ref: str | None = None

    request_id: str | None = None
    outcome: str | None = None
    obtained_observation_types: tuple[str, ...] | None = None
    coverage_reason_codes: tuple[str, ...] | None = None

    _line: int = field(repr=False, compare=False, hash=False, default=0)


@dataclass(frozen=True, slots=True)
class RecognitionLabelSet:
    """Immutable projections and counts for a validated label file."""

    records: tuple[RecognitionLabelRecord, ...]
    active: tuple[RecognitionLabelRecord, ...]
    effective: tuple[RecognitionLabelRecord, ...]
    kind_counts: tuple[tuple[str, int], ...]
    status_counts: tuple[tuple[str, int], ...]
    layer_counts: tuple[tuple[str, int], ...]

    @property
    def record_count(self) -> int:
        """Return the number of validated source records."""

        return len(self.records)


def _fail(code: str, line: int) -> NoReturn:
    raise RecognitionLabelValidationError(code, line)


def _require_string(value: object, code: str, line: int) -> str:
    if not isinstance(value, str):
        _fail(code, line)
    return value


def _require_optional_string(
    value: object,
    code: str,
    line: int,
) -> str | None:
    if value is None:
        return None
    return _require_string(value, code, line)


def _require_string_list(
    value: object,
    code: str,
    line: int,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(code, line)
    if not all(isinstance(item, str) for item in value):
        _fail(code, line)
    return tuple(cast(list[str], value))


def _require_token_list(
    value: object,
    code: str,
    line: int,
) -> tuple[str, ...]:
    items = _require_string_list(value, code, line)
    if len(set(items)) != len(items):
        _fail(code, line)
    for item in items:
        if _TOKEN_ITEM_RE.fullmatch(item) is None:
            _fail(code, line)
    return items


def _require_enum(
    value: object,
    allowed: frozenset[str],
    code: str,
    line: int,
) -> str:
    result = _require_string(value, code, line)
    if result not in allowed:
        _fail(code, line)
    return result


def _require_opaque_ref(
    value: object,
    code: str,
    line: int,
) -> str:
    result = _require_string(value, code, line)
    if _OPAQUE_REF_RE.fullmatch(result) is None:
        _fail(code, line)
    return result


def _require_optional_opaque_ref(
    value: object,
    code: str,
    line: int,
) -> str | None:
    if value is None:
        return None
    return _require_opaque_ref(value, code, line)


def _require_sha256(value: object, line: int) -> str:
    result = _require_string(value, "sha256_invalid", line)
    if _SHA256_RE.fullmatch(result) is None:
        _fail("sha256_invalid", line)
    return result


def _require_confidence(value: object, line: int) -> float | None:
    if value is None:
        return None
    if type(value) is not float:
        _fail("confidence_invalid", line)
    result = cast(float, value)
    if not 0.0 <= result <= 1.0:
        _fail("confidence_invalid", line)
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError("non-finite JSON number")


def _object_from_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _parse_json_object(text: str, line: int) -> dict[str, object]:
    if text.strip() == "":
        _fail("jsonl_invalid", line)

    try:
        parsed = json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_object_from_pairs,
        )
    except (json.JSONDecodeError, TypeError, ValueError):
        _fail("jsonl_invalid", line)

    if not isinstance(parsed, dict):
        _fail("jsonl_invalid", line)

    return cast(dict[str, object], parsed)


def _validate_common(
    raw: Mapping[str, object],
    kind: str,
    line: int,
) -> dict[str, object]:
    schema_version = _require_string(
        raw["schema_version"], "schema_version_invalid", line
    )
    if schema_version != "1.0":
        _fail("schema_version_invalid", line)

    record_id = _require_opaque_ref(
        raw["record_id"], "record_id_invalid", line
    )
    status = _require_enum(
        raw["status"], _STATUSES, "status_invalid", line
    )
    layer = _require_enum(
        raw["layer"], _LAYERS, "layer_invalid", line
    )
    author_kind = _require_enum(
        raw["author_kind"], _AUTHOR_KINDS, "author_kind_invalid", line
    )
    label_basis = _require_string_list(
        raw["label_basis"], "label_basis_invalid", line
    )
    # 受控 basis 词表（沿用 linkage_labels 语义门，不只封字段名——codex 复审 P1）：
    # 空列表、表外 token、重复项都拒。
    if (
        not label_basis
        or len(set(label_basis)) != len(label_basis)
        or any(item not in _LABEL_BASIS_VOCABULARY for item in label_basis)
    ):
        _fail("label_basis_invalid", line)

    evidence_value = raw["evidence_ref"]
    if evidence_value is None:
        evidence_ref: str | None = None
    else:
        evidence_ref = _require_string(
            evidence_value, "evidence_ref_invalid", line
        )
        if _EVIDENCE_REF_RE.fullmatch(evidence_ref) is None:
            _fail("evidence_ref_invalid", line)
        # 占位值不许充当证据引用（沿用 linkage_labels 的 placeholder 黑名单）。
        if evidence_ref.strip().lower() in _EVIDENCE_REF_PLACEHOLDERS:
            _fail("evidence_ref_invalid", line)

    label_lineage = _require_enum(
        raw["label_lineage"],
        _LABEL_LINEAGES,
        "label_lineage_invalid",
        line,
    )
    confidence = _require_confidence(raw["confidence"], line)
    supersedes = _require_optional_opaque_ref(
        raw["supersedes"], "supersedes_invalid", line
    )
    reason_codes = _require_token_list(
        raw["reason_codes"], "reason_codes_invalid", line
    )

    if author_kind == "model":
        if status != "proposed":
            _fail("model_status_forbidden", line)
        if layer != "silver":
            _fail("model_layer_forbidden", line)

    if layer == "gold_internal" and label_lineage != "queue-internal":
        _fail("layer_lineage_mismatch", line)
    if layer == "gold_external" and label_lineage != "queue-external":
        _fail("layer_lineage_mismatch", line)

    return {
        "kind": kind,
        "schema_version": schema_version,
        "record_id": record_id,
        "status": status,
        "layer": layer,
        "author_kind": author_kind,
        "label_basis": label_basis,
        "evidence_ref": evidence_ref,
        "label_lineage": label_lineage,
        "confidence": confidence,
        "supersedes": supersedes,
        "reason_codes": reason_codes,
    }


def _validate_family(
    raw: Mapping[str, object],
    common: Mapping[str, object],
    line: int,
) -> RecognitionLabelRecord:
    sample_sha256 = _require_sha256(raw["sample_sha256"], line)
    level = _require_enum(raw["level"], _LEVELS, "level_invalid", line)
    family_id = _require_string(
        raw["family_id"], "family_id_invalid", line
    )

    if family_id in _RESERVED_FAMILY_IDS:
        _fail("family_id_reserved", line)
    if _FAMILY_ID_RE.fullmatch(family_id) is None:
        _fail("family_id_invalid", line)

    return _make_record(
        common,
        line,
        sample_sha256=sample_sha256,
        level=level,
        family_id=family_id,
    )


def _validate_relation(
    raw: Mapping[str, object],
    common: Mapping[str, object],
    line: int,
) -> RecognitionLabelRecord:
    left_sha256 = _require_sha256(raw["left_sha256"], line)
    right_sha256 = _require_sha256(raw["right_sha256"], line)
    relation = _require_enum(
        raw["relation"], _RELATIONS, "relation_invalid", line
    )
    relation_subtype = _require_enum(
        raw["relation_subtype"],
        _RELATION_SUBTYPES,
        "relation_subtype_unknown",
        line,
    )

    if left_sha256 >= right_sha256:
        _fail("pair_order_invalid", line)

    status = cast(str, common["status"])
    author_kind = cast(str, common["author_kind"])
    label_basis = cast(tuple[str, ...], common["label_basis"])
    evidence_ref = cast(str | None, common["evidence_ref"])

    if relation_subtype == "same_operator" and status == "confirmed":
        # This is only the machine-enforceable minimum floor.
        if (
            author_kind != "human"
            or "independent-review" not in label_basis
            or evidence_ref is None
        ):
            _fail("same_operator_confirmation_floor", line)

    return _make_record(
        common,
        line,
        left_sha256=left_sha256,
        right_sha256=right_sha256,
        relation=relation,
        relation_subtype=relation_subtype,
    )


def _validate_clue(
    raw: Mapping[str, object],
    common: Mapping[str, object],
    line: int,
) -> RecognitionLabelRecord:
    clue_ref = _require_opaque_ref(
        raw["clue_ref"], "clue_ref_invalid", line
    )
    verdict = _require_enum(
        raw["verdict"], _VERDICTS, "verdict_invalid", line
    )
    ownership = _require_enum(
        raw["ownership"], _OWNERSHIPS, "ownership_invalid", line
    )
    return _make_record(
        common,
        line,
        clue_ref=clue_ref,
        verdict=verdict,
        ownership=ownership,
    )


def _validate_ownership(
    raw: Mapping[str, object],
    common: Mapping[str, object],
    line: int,
) -> RecognitionLabelRecord:
    sample_sha256 = _require_sha256(raw["sample_sha256"], line)
    observation_ref = _require_opaque_ref(
        raw["observation_ref"], "observation_ref_invalid", line
    )
    ownership = _require_enum(
        raw["ownership"], _OWNERSHIPS, "ownership_invalid", line
    )
    return _make_record(
        common,
        line,
        sample_sha256=sample_sha256,
        observation_ref=observation_ref,
        ownership=ownership,
    )


def _validate_outcome(
    raw: Mapping[str, object],
    common: Mapping[str, object],
    line: int,
) -> RecognitionLabelRecord:
    request_id = _require_opaque_ref(
        raw["request_id"], "request_id_invalid", line
    )
    outcome = _require_enum(
        raw["outcome"], _OUTCOMES, "outcome_invalid", line
    )
    obtained_observation_types = _require_token_list(
        raw["obtained_observation_types"],
        "obtained_observation_types_invalid",
        line,
    )
    coverage_reason_codes = _require_token_list(
        raw["coverage_reason_codes"],
        "coverage_reason_codes_invalid",
        line,
    )
    return _make_record(
        common,
        line,
        request_id=request_id,
        outcome=outcome,
        obtained_observation_types=obtained_observation_types,
        coverage_reason_codes=coverage_reason_codes,
    )


def _make_record(
    common: Mapping[str, object],
    line: int,
    *,
    sample_sha256: str | None = None,
    level: str | None = None,
    family_id: str | None = None,
    left_sha256: str | None = None,
    right_sha256: str | None = None,
    relation: str | None = None,
    relation_subtype: str | None = None,
    clue_ref: str | None = None,
    verdict: str | None = None,
    ownership: str | None = None,
    observation_ref: str | None = None,
    request_id: str | None = None,
    outcome: str | None = None,
    obtained_observation_types: tuple[str, ...] | None = None,
    coverage_reason_codes: tuple[str, ...] | None = None,
) -> RecognitionLabelRecord:
    return RecognitionLabelRecord(
        kind=cast(str, common["kind"]),
        schema_version=cast(str, common["schema_version"]),
        record_id=cast(str, common["record_id"]),
        status=cast(str, common["status"]),
        layer=cast(str, common["layer"]),
        author_kind=cast(str, common["author_kind"]),
        label_basis=cast(tuple[str, ...], common["label_basis"]),
        evidence_ref=cast(str | None, common["evidence_ref"]),
        label_lineage=cast(str, common["label_lineage"]),
        confidence=cast(float | None, common["confidence"]),
        supersedes=cast(str | None, common["supersedes"]),
        reason_codes=cast(tuple[str, ...], common["reason_codes"]),
        sample_sha256=sample_sha256,
        level=level,
        family_id=family_id,
        left_sha256=left_sha256,
        right_sha256=right_sha256,
        relation=relation,
        relation_subtype=relation_subtype,
        clue_ref=clue_ref,
        verdict=verdict,
        ownership=ownership,
        observation_ref=observation_ref,
        request_id=request_id,
        outcome=outcome,
        obtained_observation_types=obtained_observation_types,
        coverage_reason_codes=coverage_reason_codes,
        _line=line,
    )


def _validate_record(
    raw: Mapping[str, object],
    line: int,
) -> RecognitionLabelRecord:
    kind_value = raw.get("kind")
    if not isinstance(kind_value, str) or kind_value not in _KIND_FIELDS:
        _fail("kind_unknown", line)
    kind = kind_value

    expected_fields = _COMMON_FIELDS | _KIND_FIELDS[kind]
    if frozenset(raw.keys()) != expected_fields:
        _fail("field_set_mismatch", line)

    common = _validate_common(raw, kind, line)

    if kind == "family_assignment":
        return _validate_family(raw, common, line)
    if kind == "relation_judgment":
        return _validate_relation(raw, common, line)
    if kind == "clue_judgment":
        return _validate_clue(raw, common, line)
    if kind == "ownership_judgment":
        return _validate_ownership(raw, common, line)
    if kind == "reanalysis_outcome":
        return _validate_outcome(raw, common, line)

    _fail("kind_unknown", line)


def _natural_key(record: RecognitionLabelRecord) -> tuple[object, ...]:
    if record.kind == "family_assignment":
        return (
            record.kind,
            record.sample_sha256,
            record.level,
            record.family_id,
        )
    if record.kind == "relation_judgment":
        return (
            record.kind,
            record.left_sha256,
            record.right_sha256,
            record.relation_subtype,
        )
    if record.kind == "clue_judgment":
        return (record.kind, record.clue_ref)
    if record.kind == "ownership_judgment":
        return (
            record.kind,
            record.sample_sha256,
            record.observation_ref,
        )
    return (record.kind, record.request_id)


def _validate_cross_record(
    records: tuple[RecognitionLabelRecord, ...],
) -> None:
    first_by_id: dict[str, RecognitionLabelRecord] = {}
    for record in records:
        first_by_id.setdefault(record.record_id, record)

    seen_ids: set[str] = set()
    successor_by_target: dict[str, RecognitionLabelRecord] = {}
    active_by_natural_key: dict[
        tuple[object, ...], RecognitionLabelRecord
    ] = {}

    for record in records:
        line = record._line

        if record.record_id in seen_ids:
            _fail("record_id_duplicate", line)
        seen_ids.add(record.record_id)

        target_id = record.supersedes
        if target_id is not None:
            if target_id == record.record_id:
                _fail("supersedes_self_reference", line)

            target = first_by_id.get(target_id)
            if target is None:
                _fail("supersedes_unknown_target", line)
            if target.kind != record.kind:
                _fail("supersedes_kind_mismatch", line)
            if target.status != "superseded":
                _fail("supersedes_target_not_superseded", line)
            if target_id in successor_by_target:
                _fail("supersedes_multiple_successors", line)
            successor_by_target[target_id] = record

        if record.status not in _INACTIVE_STATUSES:
            natural_key = _natural_key(record)
            if natural_key in active_by_natural_key:
                _fail("natural_key_conflict", line)
            active_by_natural_key[natural_key] = record

    # supersedes 链必须无环（两节点互指也非法——codex 复审 P1）。
    # 报错行 = 环内行号最大者（“完成闭环”的那条记录）。
    chain = {
        record.record_id: record.supersedes
        for record in records
        if record.supersedes is not None
    }
    line_by_id = {record.record_id: record._line for record in records}
    finished: set[str] = set()
    for record in records:
        start = record.record_id
        if start in finished:
            continue
        trail: list[str] = []
        on_trail: set[str] = set()
        current: str | None = start
        while current is not None and current not in finished:
            if current in on_trail:
                cycle = trail[trail.index(current) :]
                _fail(
                    "supersedes_cycle",
                    max(line_by_id[node] for node in cycle),
                )
            trail.append(current)
            on_trail.add(current)
            current = chain.get(current)
        finished.update(trail)


def _counts(
    values: Iterable[str],
) -> tuple[tuple[str, int], ...]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return tuple(sorted(counts.items()))


def validate_recognition_label(record: Mapping[str, object]) -> None:
    """Validate a single in-memory label record (line reported as 1)."""

    _validate_record(dict(record), 1)


def load_recognition_labels(path: str | Path) -> RecognitionLabelSet:
    """Load and strictly validate a recognition-label JSONL file."""

    source = Path(path)
    text = source.read_text(encoding="utf-8")

    # 「首个违规行」= 全文件行号最小者：逐行错误与跨记录错误都收集后取最小行
    # （codex 复审 P1：早行的跨记录违规不能被晚行的行内违规抢报）。
    errors: list[RecognitionLabelValidationError] = []
    records_list: list[RecognitionLabelRecord] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        try:
            raw = _parse_json_object(raw_line, line_number)
            records_list.append(_validate_record(raw, line_number))
        except RecognitionLabelValidationError as exc:
            errors.append(exc)

    records = tuple(records_list)
    try:
        _validate_cross_record(records)
    except RecognitionLabelValidationError as exc:
        errors.append(exc)
    if errors:
        raise min(errors, key=lambda error: error.line)

    active = tuple(
        record
        for record in records
        if record.status not in _INACTIVE_STATUSES
    )
    effective = tuple(
        record for record in active if record.status == "confirmed"
    )

    return RecognitionLabelSet(
        records=records,
        active=active,
        effective=effective,
        kind_counts=_counts(record.kind for record in records),
        status_counts=_counts(record.status for record in records),
        layer_counts=_counts(record.layer for record in records),
    )
