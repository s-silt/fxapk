"""Strict, local-only label contracts for offline linkage evaluation.

The loader intentionally knows nothing about corpus paths or case metadata.
It accepts only opaque label identifiers and real APK SHA-256 identities, and
never performs network or filesystem writes.  Evaluation-facing truth is
derived solely from active, confirmed records; an unresolved judgment is not
a negative example.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, TypeAlias


LABEL_SCHEMA_VERSION = "1.0"

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_GROUND_TRUTH_PAIR_MATERIALIZATIONS = 250_000
_OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_RELATION_SUBTYPES = frozenset(
    {
        "binary_lineage",
        "packaging_pipeline",
        "control_plane",
        "infrastructure_reuse",
        "technical_link_relevant",
    }
)
_STATUSES = frozenset({"confirmed", "proposed", "rejected", "superseded"})
_RELATIONS = frozenset({"positive", "negative", "unknown"})
_SAMPLING_CLASSES = frozenset({"hard", "semi_hard", "easy", "unspecified"})

# Label lineage records whether the judged subject came out of the rule-recall
# review queue ("queue-internal") or was sampled outside it ("queue-external").
# Queue-derived labels are conditioned on "the rules already recalled this":
# the right distribution for reranker training and cap regression, but they can
# never measure what the rules missed.  Open-set recall evaluation needs
# queue-external labels, and without this field they are indistinguishable.
_LABEL_LINEAGES = frozenset({"queue-internal", "queue-external", "unspecified"})

# evidence_ref is an opaque token pointing at a private-side evidence bundle.
# This validator checks shape only: it never resolves the token, never treats
# it as a path, and never learns the private layout behind it.  The shape gate
# exists to stop writers from satisfying the obligation with blanks or
# throwaway placeholders; it cannot prove the evidence exists or is relevant.
_EVIDENCE_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}\Z")
_EVIDENCE_REF_PLACEHOLDERS = frozenset(
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

LINKAGE_FEATURE_FAMILIES = frozenset({"remote_config", "native", "signing", "build", "ioc"})
LABEL_BASIS_FEATURE_FAMILIES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        # The reviewer asserts that the judgment came from evidence outside
        # every feature consumed by the linkage ranker/trainer.  This is and
        # remains a self-assertion: an offline validator cannot machine-verify
        # what a reviewer actually looked at.  The evidence_ref obligation
        # (enforced in _validated_label_set) only upgrades the bare assertion
        # to an auditable one -- every active independent-review label must
        # point at a private-side evidence bundle that a later audit can
        # replay.  It does not make independence trustworthy by itself.
        "independent-review": frozenset(),
        "remote-config-review": frozenset({"remote_config"}),
        "native-binary-review": frozenset({"native"}),
        "signing-certificate-review": frozenset({"signing"}),
        "build-root-review": frozenset({"build"}),
        "ioc-review": frozenset({"ioc"}),
        # Reviewing the current rule queue is circular for every model feature.
        "rule-candidate-review": LINKAGE_FEATURE_FAMILIES,
    }
)

_COMMON_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "record_id",
        "status",
        "confidence",
        "supersedes",
        "label_basis",
        "evidence_ref",
        "label_lineage",
    }
)
_FAMILY_FIELDS = _COMMON_FIELDS | {
    "sample_sha256",
    "family_id",
    "relation_subtype",
    "reason_codes",
}
_PAIR_FIELDS = _COMMON_FIELDS | {
    "left_sha256",
    "right_sha256",
    "relation",
    "relation_subtype",
    "reason_codes",
    "sampling_class",
}


class LabelValidationError(ValueError):
    """A label file is unsafe or ambiguous and must not be evaluated."""


@dataclass(frozen=True, slots=True)
class FamilyMembership:
    record_id: str | None
    sample_sha256: str
    family_id: str
    relation_subtype: str
    status: str
    label_basis: tuple[str, ...]
    reason_codes: tuple[str, ...]
    evidence_ref: str | None
    label_lineage: str
    confidence: float | None
    supersedes: str | None
    source_line: int

    def natural_key(self) -> tuple[str, str, str]:
        return ("family_membership", self.sample_sha256, self.relation_subtype)


@dataclass(frozen=True, slots=True)
class PairJudgment:
    record_id: str | None
    left_sha256: str
    right_sha256: str
    relation: str
    relation_subtype: str
    status: str
    reason_codes: tuple[str, ...]
    sampling_class: str
    label_basis: tuple[str, ...]
    evidence_ref: str | None
    label_lineage: str
    confidence: float | None
    supersedes: str | None
    source_line: int

    def pair(self) -> tuple[str, str]:
        return (self.left_sha256, self.right_sha256)

    def natural_key(self) -> tuple[str, str, str, str]:
        return (
            "pair_judgment",
            self.left_sha256,
            self.right_sha256,
            self.relation_subtype,
        )


LabelRecord: TypeAlias = FamilyMembership | PairJudgment


@dataclass(frozen=True, slots=True)
class LinkageLabelSet:
    """Validated records plus the deterministic active-record projection."""

    records: tuple[LabelRecord, ...]
    effective_records: tuple[LabelRecord, ...]
    status_counts: tuple[tuple[str, int], ...]

    @property
    def record_count(self) -> int:
        return len(self.records)


@dataclass(frozen=True, slots=True)
class FamilyGroup:
    family_id: str
    relation_subtype: str
    members: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LabelFeatureLeakage:
    """Aggregate-safe pair projection for label/feature independence gates."""

    pair_feature_families: tuple[tuple[tuple[str, str], frozenset[str]], ...]
    independent_positive_pairs: frozenset[tuple[str, str]]
    independent_negative_pairs: frozenset[tuple[str, str]]
    independent_unknown_pairs: frozenset[tuple[str, str]]
    independent_hard_negative_pairs: frozenset[tuple[str, str]]
    independent_positive_by_subtype: tuple[tuple[str, frozenset[tuple[str, str]]], ...]
    independent_family_groups: tuple[FamilyGroup, ...]

    def feature_families_by_pair(self) -> dict[tuple[str, str], frozenset[str]]:
        return dict(self.pair_feature_families)


@dataclass(frozen=True, slots=True)
class LinkageGroundTruth:
    positive_pairs: frozenset[tuple[str, str]]
    negative_pairs: frozenset[tuple[str, str]]
    unknown_pairs: frozenset[tuple[str, str]]
    hard_negative_pairs: frozenset[tuple[str, str]]
    positive_by_subtype: tuple[tuple[str, frozenset[tuple[str, str]]], ...]
    family_groups: tuple[FamilyGroup, ...]
    leakage: LabelFeatureLeakage


def _error(line: int, field: str, problem: str) -> LabelValidationError:
    return LabelValidationError(f"line {line}: {field}: {problem}")


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite numeric value")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonfinite(value: object, *, line: int, field: str = "record") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise _error(line, field, "non-finite numeric value")
    if isinstance(value, Mapping):
        for key, item in value.items():
            # Top-level keys have already passed the strict schema check. Nested
            # mapping keys are untrusted values and must never enter diagnostics.
            child = str(key) if field == "record" else field
            _reject_nonfinite(item, line=line, field=child)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_nonfinite(item, line=line, field=field)


def _reject_excessive_nesting(value: object, *, line: int) -> None:
    """Bound hostile decoded structures without putting their keys in errors."""
    stack: list[tuple[object, int]] = [(value, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if depth > 256 or visited > 100_000:
            raise _error(line, "record", "nesting exceeds the supported limit")
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend((item, depth + 1) for item in current)


def _required_text(record: Mapping[str, object], field: str, line: int) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value or value != value.strip():
        raise _error(line, field, "must be a non-empty trimmed string")
    if any(ord(char) < 32 for char in value):
        raise _error(line, field, "contains control characters")
    return value


def _optional_token(record: Mapping[str, object], field: str, line: int) -> str | None:
    value = record.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or _OPAQUE_ID_RE.fullmatch(value) is None:
        raise _error(line, field, "must be an opaque identifier")
    return value


def _sha256(record: Mapping[str, object], field: str, line: int) -> str:
    value = _required_text(record, field, line).lower()
    if _SHA256_RE.fullmatch(value) is None:
        raise _error(line, field, "must be a real 64-hex SHA-256")
    return value


def _choice(record: Mapping[str, object], field: str, choices: frozenset[str], line: int) -> str:
    value = _required_text(record, field, line)
    if value not in choices:
        raise _error(line, field, "unsupported value")
    return value


def _code_list(record: Mapping[str, object], field: str, line: int) -> tuple[str, ...]:
    value = record.get(field, [])
    if not isinstance(value, list):
        raise _error(line, field, "must be a list")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or _CODE_RE.fullmatch(item) is None:
            raise _error(line, field, "contains an invalid code")
        if item in seen:
            raise _error(line, field, "contains a duplicate code")
        seen.add(item)
        result.append(item)
    return tuple(sorted(result))


def _evidence_ref(record: Mapping[str, object], line: int) -> str | None:
    """Shape-check the opaque evidence token without ever resolving it.

    The gate rejects blanks, short throwaway strings, well-known placeholder
    words and single-repeated-character filler.  It is a formal gate only: a
    token that passes may still point at nothing, and this module has no way
    to find out.
    """
    value = record.get("evidence_ref")
    if value is None:
        return None
    if not isinstance(value, str) or _EVIDENCE_REF_RE.fullmatch(value) is None:
        raise _error(line, "evidence_ref", "must be an opaque token of 8 to 128 allowed characters")
    core = "".join(char for char in value.lower() if char.isalnum())
    if core in _EVIDENCE_REF_PLACEHOLDERS or len(set(core)) <= 1:
        raise _error(line, "evidence_ref", "placeholder tokens are not evidence")
    return value


def _label_lineage(record: Mapping[str, object], line: int) -> str:
    value = record.get("label_lineage", "unspecified")
    if not isinstance(value, str) or value not in _LABEL_LINEAGES:
        raise _error(line, "label_lineage", "unsupported value")
    return value


def _label_basis(record: Mapping[str, object], line: int) -> tuple[str, ...]:
    result = _code_list(record, "label_basis", line)
    if not result:
        raise _error(line, "label_basis", "must contain at least one controlled basis")
    unsupported = sorted(set(result) - set(LABEL_BASIS_FEATURE_FAMILIES))
    if unsupported:
        raise _error(line, "label_basis", "contains an unsupported basis")
    return result


def label_basis_feature_families(basis_codes: Iterable[str]) -> frozenset[str]:
    """Map validated basis codes to the ranker feature families they overlap."""
    families: set[str] = set()
    for code in basis_codes:
        mapped = LABEL_BASIS_FEATURE_FAMILIES.get(code)
        if mapped is None:
            raise ValueError("unsupported label basis")
        families.update(mapped)
    return frozenset(families)


def _confidence(record: Mapping[str, object], line: int) -> float | None:
    value = record.get("confidence")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _error(line, "confidence", "must be a finite number")
    try:
        result = float(value)
    except OverflowError as exc:
        raise _error(line, "confidence", "must be finite and between 0 and 1") from exc
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise _error(line, "confidence", "must be finite and between 0 and 1")
    return result


def _reject_unknown_fields(
    record: Mapping[str, object], allowed: frozenset[str], line: int
) -> None:
    if any(not isinstance(key, str) for key in record):
        raise _error(line, "record", "field names must be strings")
    unknown = sorted(set(record) - allowed)
    if unknown:
        raise _error(line, "record", "contains unknown field")


def _parse_record(record: Mapping[str, object], line: int) -> LabelRecord:
    _reject_excessive_nesting(record, line=line)
    schema = _required_text(record, "schema_version", line)
    if schema != LABEL_SCHEMA_VERSION:
        raise _error(line, "schema_version", "unsupported schema")
    kind = _required_text(record, "kind", line)
    if kind == "family_membership":
        _reject_unknown_fields(record, _FAMILY_FIELDS, line)
    elif kind == "pair_judgment":
        _reject_unknown_fields(record, _PAIR_FIELDS, line)
    else:
        raise _error(line, "kind", "unsupported label kind")
    _reject_nonfinite(record, line=line)

    status = _choice(record, "status", _STATUSES, line)
    record_id = _optional_token(record, "record_id", line)
    supersedes = _optional_token(record, "supersedes", line)
    label_basis = _label_basis(record, line)
    confidence = _confidence(record, line)
    evidence_ref = _evidence_ref(record, line)
    label_lineage = _label_lineage(record, line)

    if kind == "family_membership":
        family_id = _required_text(record, "family_id", line)
        if _OPAQUE_ID_RE.fullmatch(family_id) is None:
            raise _error(line, "family_id", "must be an opaque identifier")
        return FamilyMembership(
            record_id=record_id,
            sample_sha256=_sha256(record, "sample_sha256", line),
            family_id=family_id,
            relation_subtype=_choice(
                record, "relation_subtype", _RELATION_SUBTYPES - {"technical_link_relevant"}, line
            ),
            status=status,
            label_basis=label_basis,
            reason_codes=_code_list(record, "reason_codes", line),
            evidence_ref=evidence_ref,
            label_lineage=label_lineage,
            confidence=confidence,
            supersedes=supersedes,
            source_line=line,
        )

    if kind == "pair_judgment":
        left = _sha256(record, "left_sha256", line)
        right = _sha256(record, "right_sha256", line)
        if left == right:
            raise _error(line, "right_sha256", "self-pairs are not valid labels")
        left, right = sorted((left, right))
        relation = _choice(record, "relation", _RELATIONS, line)
        sampling_class = record.get("sampling_class", "unspecified")
        if not isinstance(sampling_class, str) or sampling_class not in _SAMPLING_CLASSES:
            raise _error(line, "sampling_class", "unsupported value")
        if relation != "negative" and sampling_class != "unspecified":
            raise _error(line, "sampling_class", "only negative labels may set a class")
        return PairJudgment(
            record_id=record_id,
            left_sha256=left,
            right_sha256=right,
            relation=relation,
            relation_subtype=_choice(record, "relation_subtype", _RELATION_SUBTYPES, line),
            status=status,
            reason_codes=_code_list(record, "reason_codes", line),
            sampling_class=sampling_class,
            label_basis=label_basis,
            evidence_ref=evidence_ref,
            label_lineage=label_lineage,
            confidence=confidence,
            supersedes=supersedes,
            source_line=line,
        )

    raise AssertionError("validated label kind was not handled")


def _record_sort_key(record: LabelRecord) -> tuple[object, ...]:
    if isinstance(record, FamilyMembership):
        subject: tuple[object, ...] = (
            record.sample_sha256,
            record.relation_subtype,
            record.family_id,
        )
    else:
        subject = (
            record.left_sha256,
            record.right_sha256,
            record.relation_subtype,
            record.relation,
        )
    return (record.natural_key()[0], *subject, record.status, record.record_id or "")


def _validated_label_set(parsed: list[LabelRecord]) -> LinkageLabelSet:
    by_id: dict[str, LabelRecord] = {}
    for record in parsed:
        if record.record_id is None:
            continue
        if record.record_id in by_id:
            raise _error(record.source_line, "record_id", "duplicate identifier")
        by_id[record.record_id] = record

    superseded_ids: set[str] = set()
    superseded_by: dict[str, str] = {}
    for record in parsed:
        if record.supersedes is None:
            continue
        if record.record_id is None:
            raise _error(
                record.source_line,
                "record_id",
                "a replacement must have a new identifier",
            )
        target = by_id.get(record.supersedes)
        if target is None:
            raise _error(record.source_line, "supersedes", "target does not exist")
        if target.source_line >= record.source_line:
            raise _error(
                record.source_line,
                "supersedes",
                "target must precede its replacement",
            )
        if target.natural_key() != record.natural_key():
            raise _error(record.source_line, "supersedes", "target has a different natural key")
        if record.record_id == record.supersedes:
            raise _error(record.source_line, "supersedes", "self-reference is not allowed")
        if record.supersedes in superseded_by:
            raise _error(record.source_line, "supersedes", "target already has a replacement")
        superseded_ids.add(record.supersedes)
        superseded_by[record.supersedes] = record.record_id

    for record in parsed:
        if record.status != "superseded":
            continue
        if record.record_id is None or record.record_id not in superseded_ids:
            raise _error(
                record.source_line,
                "status",
                "superseded record has no replacement",
            )

    for record_id in sorted(by_id):
        seen: set[str] = set()
        current = record_id
        while current in superseded_by:
            if current in seen:
                raise _error(by_id[record_id].source_line, "supersedes", "cycle detected")
            seen.add(current)
            current = superseded_by[current]

    active_heads = [
        record
        for record in parsed
        if (record.record_id is None or record.record_id not in superseded_ids)
        and record.status not in {"rejected", "superseded"}
    ]

    # Evidence obligation for self-asserted independence.  Every label whose
    # basis claims independent-review must carry an opaque evidence_ref and at
    # least one reason code.  The obligation binds only records that still
    # speak (active heads): superseded and rejected history stays loadable so
    # that the append-only supersede chain remains the one repair path for
    # legacy records that predate this rule.  Honest limitation: this check
    # cannot verify that the evidence exists, matches the judgment, or was
    # actually consulted -- independence stays a reviewer assertion, now with
    # an audit pointer attached.
    for record in active_heads:
        if "independent-review" not in record.label_basis:
            continue
        if record.evidence_ref is None:
            raise _error(
                record.source_line,
                "evidence_ref",
                "independent-review requires an evidence reference",
            )
        if not record.reason_codes:
            raise _error(
                record.source_line,
                "reason_codes",
                "independent-review requires at least one reason code",
            )

    by_natural_key: dict[tuple[str, ...], LabelRecord] = {}
    for record in active_heads:
        key = record.natural_key()
        previous = by_natural_key.get(key)
        if previous is not None:
            if previous == record:
                problem = "duplicate active label"
            else:
                problem = "conflicting active labels"
            raise _error(record.source_line, "record", problem)
        by_natural_key[key] = record

    # Resolve authority along each append-only chain. A proposal does not
    # replace the last accepted judgment until a confirmed successor appears.
    # Rejecting an accepted judgment tombstones it, while rejecting a proposal
    # leaves the preceding accepted judgment in force.
    accepted_after: dict[str, LabelRecord | None] = {}
    for record in parsed:
        accepted: LabelRecord | None = None
        if record.supersedes is not None:
            accepted = accepted_after[record.supersedes]
        if record.status in {"confirmed", "superseded"}:
            accepted = record
        elif record.status == "rejected" and record.supersedes is not None:
            target = by_id[record.supersedes]
            if target.status in {"confirmed", "superseded"}:
                accepted = None
        if record.record_id is not None:
            accepted_after[record.record_id] = accepted

    effective_candidates: list[LabelRecord] = [
        record
        for record in parsed
        if record.record_id is None and record.status == "confirmed"
    ]
    for record_id, record in by_id.items():
        if record_id in superseded_ids:
            continue
        accepted = accepted_after[record_id]
        if accepted is not None and accepted.status == "confirmed":
            effective_candidates.append(accepted)

    by_natural_key = {}
    for record in effective_candidates:
        key = record.natural_key()
        previous = by_natural_key.get(key)
        if previous is not None:
            if previous == record:
                problem = "duplicate effective label"
            else:
                problem = "conflicting effective labels"
            raise _error(record.source_line, "record", problem)
        by_natural_key[key] = record

    records = tuple(sorted(parsed, key=_record_sort_key))
    effective = tuple(sorted(effective_candidates, key=_record_sort_key))
    counts = Counter(record.status for record in parsed)
    return LinkageLabelSet(
        records=records,
        effective_records=effective,
        status_counts=tuple((status, counts.get(status, 0)) for status in sorted(_STATUSES)),
    )


def validate_linkage_label_records(
    records: Iterable[Mapping[str, object]],
) -> LinkageLabelSet:
    """Validate already-decoded label objects without accepting loose aliases."""
    parsed: list[LabelRecord] = []
    for line, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            raise _error(line, "record", "must be an object")
        try:
            parsed.append(_parse_record(record, line))
        except RecursionError as exc:
            raise _error(line, "record", "nesting exceeds the supported limit") from exc
    return _validated_label_set(parsed)


def load_linkage_labels(path: str | Path) -> LinkageLabelSet:
    """Load a strict UTF-8 JSONL label file without exposing its path or values."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise LabelValidationError("unable to read label file as UTF-8") from exc

    decoded: list[Mapping[str, object]] = []
    source_lines: list[int] = []
    for source_line, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            value = json.loads(
                raw,
                parse_constant=_reject_json_constant,
                object_pairs_hook=_unique_object,
            )
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise _error(source_line, "record", "invalid strict JSON") from exc
        if not isinstance(value, Mapping):
            raise _error(source_line, "record", "must be an object")
        decoded.append(value)
        source_lines.append(source_line)

    parsed: list[LabelRecord] = []
    for record, line in zip(decoded, source_lines):
        try:
            parsed.append(_parse_record(record, line))
        except RecursionError as exc:
            raise _error(line, "record", "nesting exceeds the supported limit") from exc
    return _validated_label_set(parsed)


def _canonical_pair(left: str, right: str) -> tuple[str, str]:
    return (left, right) if left < right else (right, left)


def build_linkage_ground_truth(labels: LinkageLabelSet) -> LinkageGroundTruth:
    """Resolve confirmed labels into positive, negative and unknown pair sets."""
    memberships: dict[tuple[str, str], dict[str, frozenset[str]]] = {}
    direct_by_subtype: dict[str, dict[str, set[tuple[str, str]]]] = {}
    basis_by_judgment: dict[
        tuple[str, str, tuple[str, str]], set[str]
    ] = {}
    hard_negative_judgments: set[tuple[str, tuple[str, str]]] = set()

    for record in labels.effective_records:
        if record.status != "confirmed":
            continue
        basis_families = label_basis_feature_families(record.label_basis)
        if isinstance(record, FamilyMembership):
            memberships.setdefault((record.relation_subtype, record.family_id), {})[
                record.sample_sha256
            ] = basis_families
            continue
        bucket = direct_by_subtype.setdefault(
            record.relation_subtype,
            {"positive": set(), "negative": set(), "unknown": set()},
        )
        bucket[record.relation].add(record.pair())
        basis_by_judgment.setdefault(
            (record.relation_subtype, record.relation, record.pair()), set()
        ).update(basis_families)
        if record.relation == "negative" and record.sampling_class == "hard":
            hard_negative_judgments.add((record.relation_subtype, record.pair()))

    positive_by_subtype: dict[str, set[tuple[str, str]]] = {
        subtype: set(groups["positive"]) for subtype, groups in direct_by_subtype.items()
    }
    pair_materializations = sum(
        len(pairs)
        for groups in direct_by_subtype.values()
        for pairs in groups.values()
    )
    if pair_materializations > _MAX_GROUND_TRUTH_PAIR_MATERIALIZATIONS:
        raise LabelValidationError("ground truth pair materialization exceeds the supported limit")
    family_groups: list[FamilyGroup] = []
    independent_family_groups: list[FamilyGroup] = []
    for (subtype, family_id), member_basis in sorted(memberships.items()):
        ordered = tuple(sorted(member_basis))
        family_groups.append(FamilyGroup(family_id, subtype, ordered))
        independent_members = tuple(member for member in ordered if not member_basis[member])
        if independent_members:
            independent_family_groups.append(FamilyGroup(family_id, subtype, independent_members))
        positives = positive_by_subtype.setdefault(subtype, set())
        pair_count = len(ordered) * (len(ordered) - 1) // 2
        pair_materializations += pair_count
        if pair_materializations > _MAX_GROUND_TRUTH_PAIR_MATERIALIZATIONS:
            raise LabelValidationError(
                "ground truth pair materialization exceeds the supported limit"
            )
        for left_index, left in enumerate(ordered):
            for right in ordered[left_index + 1 :]:
                pair = _canonical_pair(left, right)
                positives.add(pair)
                basis_by_judgment.setdefault((subtype, "positive", pair), set()).update(
                    member_basis[left] | member_basis[right]
                )

    for subtype in sorted(set(positive_by_subtype) | set(direct_by_subtype)):
        positives_for_subtype = positive_by_subtype.get(subtype, set())
        groups = direct_by_subtype.get(
            subtype, {"positive": set(), "negative": set(), "unknown": set()}
        )
        if positives_for_subtype & groups["negative"]:
            raise LabelValidationError("ground truth conflict: pair is both positive and negative")
        if groups["unknown"] & (positives_for_subtype | groups["negative"]):
            raise LabelValidationError("ground truth conflict: unknown overlaps a confirmed relation")

    positives = set().union(*positive_by_subtype.values()) if positive_by_subtype else set()
    target_relations = direct_by_subtype.get("technical_link_relevant")
    negatives = set(target_relations["negative"]) if target_relations is not None else set()
    unknown = set(target_relations["unknown"]) if target_relations is not None else set()
    if negatives & positives:
        raise LabelValidationError("ground truth conflict: pair is both positive and negative")
    if unknown & (positives | negatives):
        raise LabelValidationError("ground truth conflict: unknown overlaps a confirmed relation")

    # Subtype-specific negative/unknown labels describe only that relation
    # dimension. They are not global negatives for the technical-link target.
    hard_negatives = {
        pair
        for subtype, pair in hard_negative_judgments
        if subtype == "technical_link_relevant" and pair in negatives
    }

    pair_features: dict[tuple[str, str], frozenset[str]] = {}
    independent_positive_by_subtype_map: dict[str, frozenset[tuple[str, str]]] = {}
    for subtype, pairs in sorted(positive_by_subtype.items()):
        independent_positive_by_subtype_map[subtype] = frozenset(
            pair
            for pair in pairs
            if not basis_by_judgment.get((subtype, "positive", pair), set())
        )
    independent_positive = frozenset().union(*independent_positive_by_subtype_map.values())
    for pair in positives:
        if pair in independent_positive:
            pair_features[pair] = frozenset()
            continue
        pair_features[pair] = frozenset().union(
            *(
                basis_by_judgment.get((subtype, "positive", pair), set())
                for subtype, pairs in positive_by_subtype.items()
                if pair in pairs
            )
        )

    for relation, pairs in (("negative", negatives), ("unknown", unknown)):
        for pair in pairs:
            pair_features[pair] = frozenset(
                basis_by_judgment.get(
                    ("technical_link_relevant", relation, pair), set()
                )
            )

    independent_negative = frozenset(pair for pair in negatives if not pair_features[pair])
    independent_unknown = frozenset(pair for pair in unknown if not pair_features[pair])
    independent_positive_by_subtype = tuple(
        sorted(independent_positive_by_subtype_map.items())
    )

    return LinkageGroundTruth(
        positive_pairs=frozenset(positives),
        negative_pairs=frozenset(negatives),
        unknown_pairs=frozenset(unknown),
        hard_negative_pairs=frozenset(hard_negatives),
        positive_by_subtype=tuple(
            (subtype, frozenset(pairs)) for subtype, pairs in sorted(positive_by_subtype.items())
        ),
        family_groups=tuple(family_groups),
        leakage=LabelFeatureLeakage(
            pair_feature_families=tuple(sorted(pair_features.items())),
            independent_positive_pairs=independent_positive,
            independent_negative_pairs=independent_negative,
            independent_unknown_pairs=independent_unknown,
            independent_hard_negative_pairs=frozenset(hard_negatives) & independent_negative,
            independent_positive_by_subtype=independent_positive_by_subtype,
            independent_family_groups=tuple(independent_family_groups),
        ),
    )


def project_independent_ground_truth(truth: LinkageGroundTruth) -> LinkageGroundTruth:
    """Return only truth whose declared basis does not overlap ranker features."""
    if not isinstance(truth, LinkageGroundTruth):
        raise TypeError("truth must be LinkageGroundTruth")
    leakage = truth.leakage
    return LinkageGroundTruth(
        positive_pairs=leakage.independent_positive_pairs,
        negative_pairs=leakage.independent_negative_pairs,
        unknown_pairs=leakage.independent_unknown_pairs,
        hard_negative_pairs=leakage.independent_hard_negative_pairs,
        positive_by_subtype=leakage.independent_positive_by_subtype,
        family_groups=leakage.independent_family_groups,
        leakage=leakage,
    )


__all__ = [
    "LABEL_BASIS_FEATURE_FAMILIES",
    "LABEL_SCHEMA_VERSION",
    "LINKAGE_FEATURE_FAMILIES",
    "FamilyGroup",
    "FamilyMembership",
    "LabelFeatureLeakage",
    "LabelValidationError",
    "LinkageGroundTruth",
    "LinkageLabelSet",
    "PairJudgment",
    "build_linkage_ground_truth",
    "label_basis_feature_families",
    "load_linkage_labels",
    "project_independent_ground_truth",
    "validate_linkage_label_records",
]
