"""Immutable values and stable errors for the structured recognition contract."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, fields, is_dataclass
from enum import StrEnum
from typing import Literal, NoReturn, TypeAlias, TypeVar, cast


class JudgmentContractError(ValueError):
    """Base error with stable, value-free machine-readable context."""

    def __init__(
        self,
        code: str,
        *,
        field_path: str = "$",
        event_sequence: int | None = None,
    ) -> None:
        self.code = code
        self.field_path = field_path
        self.event_sequence = event_sequence
        super().__init__(f"{code} at {field_path}")


class CanonicalCodecError(JudgmentContractError):
    """A value cannot be represented by canonical_json_v1."""


class SchemaValidationError(JudgmentContractError):
    """A structured record does not match its exact schema."""


class IdentityMismatchError(JudgmentContractError):
    """A stored semantic identity does not match the record body."""


class LedgerIntegrityError(JudgmentContractError):
    """An event stream fails sequence or hash-chain integrity."""


class ReferenceIntegrityError(JudgmentContractError):
    """A record reference is missing, premature, or the wrong type."""


class ReplayTransitionError(JudgmentContractError):
    """An event requests an illegal judgment-state transition."""


class ActorKind(StrEnum):
    HUMAN = "human"
    SYSTEM = "system"
    TOOL = "tool"
    MODEL = "model"


class ProducerKind(StrEnum):
    ANALYZER = "analyzer"
    QUERY = "query"
    RULE_ENGINE = "rule_engine"
    KNOWLEDGE_PACK = "knowledge_pack"
    MODEL = "model"
    SYSTEM = "system"


class LabelKind(StrEnum):
    FAMILY_ASSIGNMENT = "family_assignment"
    CLUE_JUDGMENT = "clue_judgment"
    RELATION_JUDGMENT = "relation_judgment"
    OWNERSHIP_JUDGMENT = "ownership_judgment"
    REANALYSIS_OUTCOME = "reanalysis_outcome"


class SubjectKind(StrEnum):
    CASE = "case"
    SAMPLE = "sample"
    PACKAGE = "package"
    ARTIFACT = "artifact"
    ENDPOINT = "endpoint"
    FAMILY = "family"
    PRODUCT_LINE = "product_line"
    PAIR = "pair"


class EvidenceAnchorType(StrEnum):
    CASE_PACKAGE = "case_package"
    REPORT = "report"
    ARTIFACT = "artifact"
    CORPUS_REVISION = "corpus_revision"
    EVIDENCE_SNAPSHOT = "evidence_snapshot"
    JADX_INDEX = "jadx_index"


class LocatorKind(StrEnum):
    WHOLE = "whole"
    JSON_POINTER = "json_pointer"
    ARCHIVE_ENTRY = "archive_entry"
    SYMBOL = "symbol"
    BYTE_RANGE = "byte_range"
    LINE_RANGE = "line_range"
    FLOW = "flow"
    OPAQUE = "opaque"


class CoverageSource(StrEnum):
    DEX = "dex"
    JAVA = "java"
    NATIVE = "native"
    RESOURCE = "resource"
    RUNTIME = "runtime"
    WEB = "web"
    ENRICHMENT = "enrichment"
    JADX_INDEX = "jadx_index"


class CoverageStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    STUB_ONLY = "stub_only"
    OPAQUE = "opaque"
    TIMEOUT = "timeout"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


class EvidenceScope(StrEnum):
    CASE_EVIDENCE = "case_evidence"
    BATCH_REFERENCE = "batch_reference"
    DERIVED_REFERENCE = "derived_reference"


class ObservationValueKind(StrEnum):
    CATEGORICAL = "categorical"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    REFERENCE = "reference"


class OwnershipValue(StrEnum):
    SUSPECT_FIRST_PARTY = "suspect_first_party"
    INHERITED_OFFICIAL = "inherited_official"
    INHERITED_THIRD_PARTY = "inherited_third_party"
    SHARED_INFRASTRUCTURE = "shared_infrastructure"
    UNKNOWN = "unknown"


class ClaimMode(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    EXHAUSTIVE = "exhaustive"


class ObjectKind(StrEnum):
    NONE = "none"
    CATEGORICAL = "categorical"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    REFERENCE = "reference"


class AuthorizationLevel(StrEnum):
    OFFLINE = "offline"
    PASSIVE_ONLINE = "passive_online"
    AUTHORIZED_DEVICE = "authorized_device"


class QuestionType(StrEnum):
    RESOLVE_FAMILY = "resolve_family"
    RESOLVE_CLUE = "resolve_clue"
    RESOLVE_RELATION = "resolve_relation"
    RESOLVE_OWNERSHIP = "resolve_ownership"
    PLAN_REANALYSIS = "plan_reanalysis"


class ClaimTask(StrEnum):
    FAMILY = "family"
    CLUE = "clue"
    RELATION = "relation"
    OWNERSHIP = "ownership"
    REANALYSIS = "reanalysis"


class ObservationStrength(StrEnum):
    OBSERVED = "observed"
    DERIVED = "derived"


class GapEffect(StrEnum):
    BLOCKS_CLAIM = "blocks_claim"
    BLOCKS_REVIEW = "blocks_review"
    REDUCES_CONFIDENCE = "reduces_confidence"


class OutcomeStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReviewDecisionValue(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    CHANGES_REQUESTED = "changes_requested"


@dataclass(frozen=True, slots=True)
class Actor:
    kind: ActorKind
    actor_id: str


@dataclass(frozen=True, slots=True)
class ProducerRef:
    kind: ProducerKind
    producer_id: str
    version: str
    artifact_digest: str | None
    configuration_digest: str | None


@dataclass(frozen=True, slots=True)
class PolicyRef:
    policy_id: str
    version: str
    digest: str


@dataclass(frozen=True, slots=True)
class SubjectRef:
    kind: SubjectKind
    value: str
    role: str | None


@dataclass(frozen=True, slots=True)
class EvidenceAnchor:
    anchor_id: str
    anchor_type: EvidenceAnchorType
    content_digest: str
    logical_id: str | None
    schema_version_ref: str | None


@dataclass(frozen=True, slots=True)
class EvidenceLocator:
    anchor_id: str
    kind: LocatorKind
    value: str
    start: int | None
    end: int | None


@dataclass(frozen=True, slots=True)
class CoverageAssertion:
    subject: SubjectRef
    source: CoverageSource
    status: CoverageStatus
    scope: EvidenceScope
    assessment_digest: str
    receipt_locator: EvidenceLocator | None
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CoveragePredicate:
    subject: SubjectRef
    source: CoverageSource
    allowed_statuses: tuple[CoverageStatus, ...]


@dataclass(frozen=True, slots=True)
class ObservationValue:
    kind: ObservationValueKind
    categorical: str | None
    integer: int | None
    boolean: bool | None
    reference: EvidenceLocator | None


@dataclass(frozen=True, slots=True)
class SubjectOwnership:
    subject: SubjectRef
    value: OwnershipValue
    supporting_observation_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExcludedObservation:
    observation_id: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class RankingScore:
    value: int
    semantics: str


@dataclass(frozen=True, slots=True)
class ActionBudget:
    max_seconds: int
    max_memory_mb: int


@dataclass(frozen=True, slots=True)
class ActionUsage:
    elapsed_ms: int | None
    peak_memory_mb: int | None
    output_bytes: int | None


@dataclass(frozen=True, slots=True)
class AllowedConclusion:
    predicate: str
    claim_modes: tuple[ClaimMode, ...]
    object_kind: ObjectKind
    allowed_categorical_values: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ActionAuthorization:
    kind: Literal["action_authorization"]
    schema_version: Literal["1.0"]
    action_id: str
    granted_level: AuthorizationLevel
    policy: PolicyRef
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReasoningRun:
    kind: Literal["reasoning_run"]
    schema_version: Literal["1.0"]
    run_id: str
    execution_nonce: str
    reuse_key: str
    purpose: str
    subjects: tuple[SubjectRef, ...]
    input_anchors: tuple[EvidenceAnchor, ...]
    initial_coverage: tuple[CoverageAssertion, ...]
    policies: tuple[PolicyRef, ...]
    producers: tuple[ProducerRef, ...]


@dataclass(frozen=True, slots=True)
class Question:
    kind: Literal["question"]
    schema_version: Literal["1.0"]
    question_id: str
    question_type: QuestionType
    subjects: tuple[SubjectRef, ...]
    allowed_conclusions: tuple[AllowedConclusion, ...]


@dataclass(frozen=True, slots=True)
class Observation:
    kind: Literal["observation"]
    schema_version: Literal["1.0"]
    observation_id: str
    observation_type: str
    subjects: tuple[SubjectRef, ...]
    value: ObservationValue
    source_refs: tuple[EvidenceLocator, ...]
    scope: EvidenceScope
    strength: ObservationStrength
    input_observation_ids: tuple[str, ...]
    origin_outcome_id: str | None
    producer: ProducerRef
    ownership: OwnershipValue
    coverage_assertions: tuple[CoverageAssertion, ...]


@dataclass(frozen=True, slots=True)
class ClaimCandidate:
    kind: Literal["claim_candidate"]
    schema_version: Literal["1.0"]
    claim_id: str
    question_id: str
    task: ClaimTask
    claim_mode: ClaimMode
    subjects: tuple[SubjectRef, ...]
    predicate: str
    object_value: ObservationValue | None
    supporting_observation_ids: tuple[str, ...]
    contradicting_observation_ids: tuple[str, ...]
    excluded_observations: tuple[ExcludedObservation, ...]
    coverage_requirements: tuple[CoveragePredicate, ...]
    coverage_context_digest: str
    ownership: tuple[SubjectOwnership, ...]
    caps: tuple[str, ...]
    unknowns: tuple[str, ...]
    resolves_gap_ids: tuple[str, ...]
    producer: ProducerRef
    supersedes: str | None
    score: RankingScore | None


@dataclass(frozen=True, slots=True)
class EvidenceGap:
    kind: Literal["evidence_gap"]
    schema_version: Literal["1.0"]
    gap_id: str
    question_id: str
    claim_id: str | None
    effect: GapEffect
    reason_codes: tuple[str, ...]
    required_observation_types: tuple[str, ...]
    coverage_requirements: tuple[CoveragePredicate, ...]
    producer: ProducerRef


@dataclass(frozen=True, slots=True)
class NextAction:
    kind: Literal["next_action"]
    schema_version: Literal["1.0"]
    action_id: str
    question_id: str
    gap_ids: tuple[str, ...]
    attempt_nonce: str
    action_type: str
    subjects: tuple[SubjectRef, ...]
    input_anchor_ids: tuple[str, ...]
    parameters_digest: str
    authorization_required: AuthorizationLevel
    budget: ActionBudget
    success_criteria: tuple[str, ...]
    negative_valid_only_if: tuple[CoveragePredicate, ...]
    dedupe_key: str
    producer: ProducerRef


@dataclass(frozen=True, slots=True)
class ActionOutcome:
    kind: Literal["action_outcome"]
    schema_version: Literal["1.0"]
    outcome_id: str
    action_id: str
    status: OutcomeStatus
    output_anchors: tuple[EvidenceAnchor, ...]
    coverage_assertions: tuple[CoverageAssertion, ...]
    reason_codes: tuple[str, ...]
    diagnostics_locator: EvidenceLocator | None
    usage: ActionUsage
    producer: ProducerRef


@dataclass(frozen=True, slots=True)
class ReviewDecision:
    kind: Literal["review_decision"]
    schema_version: Literal["1.0"]
    decision_id: str
    question_id: str
    claim_id: str
    decision: ReviewDecisionValue
    reviewer: Actor
    basis_head_digest: str
    basis_observation_ids: tuple[str, ...]
    gap_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]


SharedValue: TypeAlias = (
    Actor
    | ProducerRef
    | PolicyRef
    | SubjectRef
    | EvidenceAnchor
    | EvidenceLocator
    | CoverageAssertion
    | CoveragePredicate
    | ObservationValue
    | SubjectOwnership
    | ExcludedObservation
    | RankingScore
    | ActionBudget
    | ActionUsage
    | AllowedConclusion
    | ActionAuthorization
)
@dataclass(frozen=True, slots=True)
class CandidateLabelFeedback:
    kind: Literal["candidate_label_feedback"]
    schema_version: Literal["1.0"]
    feedback_id: str
    label_kind: LabelKind
    proposed_label_digest: str
    subject_refs: tuple[SubjectRef, ...]
    evidence_ref: str | None
    reason_codes: tuple[str, ...]
    policy: PolicyRef
    producer: ProducerRef


DomainRecord: TypeAlias = (
    ReasoningRun
    | Question
    | Observation
    | ClaimCandidate
    | EvidenceGap
    | NextAction
    | ActionOutcome
    | ReviewDecision
    | CandidateLabelFeedback
)
ContractValue: TypeAlias = SharedValue | DomainRecord

_TOKEN_RE = re.compile(r"[a-z][a-z0-9._-]{0,127}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_RECORD_ID_RE = re.compile(r"[a-z][a-z0-9_-]*-sha256:[0-9a-f]{64}")
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_FORBIDDEN_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})
_WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"[A-Za-z]:[\\/]")
_INVALID_JSON_POINTER_ESCAPE_RE = re.compile(r"~(?:[^01]|$)")
_T = TypeVar("_T")


def _invalid(code: str, path: str) -> NoReturn:
    raise SchemaValidationError(code, field_path=path)


def _require_exact_type(value: object, expected_type: type[_T], path: str) -> _T:
    if type(value) is not expected_type:
        _invalid("nested_contract_type_mismatch", path)
    return cast(_T, value)


def _validate_text(
    value: object,
    path: str,
    *,
    allow_empty: bool = False,
    max_length: int | None = None,
) -> str:
    if not isinstance(value, str):
        _invalid("string_required", path)
    if not allow_empty and not value:
        _invalid("nonempty_string_required", path)
    if max_length is not None and len(value) > max_length:
        _invalid("string_too_long", path)
    if unicodedata.normalize("NFC", value) != value:
        _invalid("non_nfc_string", path)
    if any(unicodedata.category(char) in _FORBIDDEN_UNICODE_CATEGORIES for char in value):
        _invalid("forbidden_unicode_category", path)
    return value


def _validate_optional_text(value: object, path: str, *, max_length: int) -> None:
    if value is not None:
        _validate_text(value, path, max_length=max_length)


def _validate_token(value: object, path: str) -> None:
    text = _validate_text(value, path)
    if _TOKEN_RE.fullmatch(text) is None:
        _invalid("invalid_token", path)


def _validate_digest(value: object, path: str) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        _invalid("invalid_digest", path)


def _validate_optional_digest(value: object, path: str) -> None:
    if value is not None:
        _validate_digest(value, path)


def _validate_record_id(value: object, path: str, *, prefix: str | None = None) -> None:
    if not isinstance(value, str) or _RECORD_ID_RE.fullmatch(value) is None:
        _invalid("invalid_record_id", path)
    if prefix is not None and not value.startswith(f"{prefix}-sha256:"):
        _invalid("record_id_type_mismatch", path)


def _validate_enum(value: object, enum_type: type[StrEnum], path: str) -> None:
    if not isinstance(value, enum_type):
        _invalid("enum_value_required", path)


def _validate_int64(value: object, path: str, *, minimum: int = _INT64_MIN) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _invalid("integer_required", path)
    if not minimum <= value <= _INT64_MAX:
        _invalid("integer_out_of_range", path)
    return value


def _sort_data(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _sort_data(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_sort_data(item) for item in value]
    return value


def _sort_key(value: object, path: str) -> bytes:
    try:
        return json.dumps(
            _sort_data(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, OverflowError) as exc:
        raise SchemaValidationError("invalid_canonical_tuple_item", field_path=path) from exc


def _validate_canonical_tuple(
    value: object,
    path: str,
    *,
    nonempty: bool = False,
) -> tuple[object, ...]:
    if not isinstance(value, tuple):
        _invalid("tuple_required", path)
    if nonempty and not value:
        _invalid("nonempty_tuple_required", path)
    keys = tuple(_sort_key(item, f"{path}[{index}]") for index, item in enumerate(value))
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        _invalid("non_canonical_tuple", path)
    return value


def _validate_reason_codes(value: object, path: str, *, nonempty: bool = False) -> None:
    values = _validate_canonical_tuple(value, path, nonempty=nonempty)
    for index, item in enumerate(values):
        _validate_token(item, f"{path}[{index}]")


def _validate_actor(value: Actor, path: str) -> None:
    _validate_enum(value.kind, ActorKind, f"{path}.kind")
    _validate_token(value.actor_id, f"{path}.actor_id")


def _validate_producer(value: ProducerRef, path: str) -> None:
    _validate_enum(value.kind, ProducerKind, f"{path}.kind")
    _validate_token(value.producer_id, f"{path}.producer_id")
    _validate_text(value.version, f"{path}.version", max_length=120)
    _validate_optional_digest(value.artifact_digest, f"{path}.artifact_digest")
    _validate_optional_digest(value.configuration_digest, f"{path}.configuration_digest")


def _validate_policy(value: PolicyRef, path: str) -> None:
    _validate_token(value.policy_id, f"{path}.policy_id")
    _validate_text(value.version, f"{path}.version", max_length=120)
    _validate_digest(value.digest, f"{path}.digest")


def _validate_subject(value: SubjectRef, path: str) -> None:
    _validate_enum(value.kind, SubjectKind, f"{path}.kind")
    _validate_text(value.value, f"{path}.value", max_length=512)
    if value.role is not None:
        _validate_token(value.role, f"{path}.role")


def _validate_anchor(value: EvidenceAnchor, path: str) -> None:
    _validate_record_id(value.anchor_id, f"{path}.anchor_id", prefix="anchor")
    _validate_enum(value.anchor_type, EvidenceAnchorType, f"{path}.anchor_type")
    _validate_digest(value.content_digest, f"{path}.content_digest")
    _validate_optional_text(value.logical_id, f"{path}.logical_id", max_length=512)
    _validate_optional_text(value.schema_version_ref, f"{path}.schema_version_ref", max_length=120)


def _validate_locator(value: EvidenceLocator, path: str) -> None:
    _validate_record_id(value.anchor_id, f"{path}.anchor_id", prefix="anchor")
    _validate_enum(value.kind, LocatorKind, f"{path}.kind")
    _validate_text(value.value, f"{path}.value", allow_empty=True, max_length=2048)
    if value.kind is LocatorKind.WHOLE:
        if value.value or value.start is not None or value.end is not None:
            _invalid("locator_shape", path)
        return
    if (
        value.value.startswith("\\")
        or _WINDOWS_ABSOLUTE_PATH_RE.match(value.value) is not None
        or value.value.casefold().startswith("file:")
    ):
        _invalid("absolute_locator_path_forbidden", f"{path}.value")
    if value.kind is LocatorKind.JSON_POINTER:
        if (
            not value.value.startswith("/")
            or _INVALID_JSON_POINTER_ESCAPE_RE.search(value.value) is not None
            or value.start is not None
            or value.end is not None
        ):
            _invalid("invalid_json_pointer", f"{path}.value")
        return
    if value.value.startswith("/"):
        _invalid("absolute_locator_path_forbidden", f"{path}.value")
    if value.kind in {LocatorKind.BYTE_RANGE, LocatorKind.LINE_RANGE}:
        if not value.value or value.start is None or value.end is None:
            _invalid("locator_shape", path)
        start = _validate_int64(value.start, f"{path}.start", minimum=0)
        end = _validate_int64(value.end, f"{path}.end", minimum=0)
        if start > end:
            _invalid("locator_range_order", path)
        return
    if not value.value or value.start is not None or value.end is not None:
        _invalid("locator_shape", path)


def _validate_coverage(value: CoverageAssertion, path: str) -> None:
    subject_path = f"{path}.subject"
    _validate_subject(_require_exact_type(value.subject, SubjectRef, subject_path), subject_path)
    _validate_enum(value.source, CoverageSource, f"{path}.source")
    _validate_enum(value.status, CoverageStatus, f"{path}.status")
    _validate_enum(value.scope, EvidenceScope, f"{path}.scope")
    _validate_digest(value.assessment_digest, f"{path}.assessment_digest")
    if value.receipt_locator is not None:
        locator_path = f"{path}.receipt_locator"
        _validate_locator(
            _require_exact_type(value.receipt_locator, EvidenceLocator, locator_path),
            locator_path,
        )
    _validate_reason_codes(value.reason_codes, f"{path}.reason_codes")


def _validate_coverage_predicate(value: CoveragePredicate, path: str) -> None:
    subject_path = f"{path}.subject"
    _validate_subject(_require_exact_type(value.subject, SubjectRef, subject_path), subject_path)
    _validate_enum(value.source, CoverageSource, f"{path}.source")
    statuses = _validate_canonical_tuple(
        value.allowed_statuses,
        f"{path}.allowed_statuses",
        nonempty=True,
    )
    for index, status in enumerate(statuses):
        _validate_enum(status, CoverageStatus, f"{path}.allowed_statuses[{index}]")


def _validate_coverage_predicate_collection(
    value: object,
    path: str,
    *,
    nonempty: bool = False,
) -> tuple[CoveragePredicate, ...]:
    predicates = cast(
        tuple[CoveragePredicate, ...],
        _validate_typed_tuple(
            value,
            path,
            CoveragePredicate,
            nonempty=nonempty,
        ),
    )
    seen: set[tuple[bytes, CoverageSource]] = set()
    for index, predicate in enumerate(predicates):
        key = (_sort_key(predicate.subject, f"{path}[{index}].subject"), predicate.source)
        if key in seen:
            _invalid("duplicate_coverage_predicate_key", path)
        seen.add(key)
    return predicates


def _validate_observation_value(value: ObservationValue, path: str) -> None:
    _validate_enum(value.kind, ObservationValueKind, f"{path}.kind")
    present = {
        ObservationValueKind.CATEGORICAL: value.categorical is not None,
        ObservationValueKind.INTEGER: value.integer is not None,
        ObservationValueKind.BOOLEAN: value.boolean is not None,
        ObservationValueKind.REFERENCE: value.reference is not None,
    }
    if sum(present.values()) != 1 or not present[value.kind]:
        _invalid("observation_value_shape", path)
    if value.categorical is not None:
        _validate_token(value.categorical, f"{path}.categorical")
    if value.integer is not None:
        _validate_int64(value.integer, f"{path}.integer")
    if value.boolean is not None and not isinstance(value.boolean, bool):
        _invalid("boolean_required", f"{path}.boolean")
    if value.reference is not None:
        reference_path = f"{path}.reference"
        _validate_locator(
            _require_exact_type(value.reference, EvidenceLocator, reference_path),
            reference_path,
        )


def _validate_subject_ownership(value: SubjectOwnership, path: str) -> None:
    subject_path = f"{path}.subject"
    _validate_subject(_require_exact_type(value.subject, SubjectRef, subject_path), subject_path)
    _validate_enum(value.value, OwnershipValue, f"{path}.value")
    ids = _validate_canonical_tuple(
        value.supporting_observation_ids,
        f"{path}.supporting_observation_ids",
    )
    for index, observation_id in enumerate(ids):
        _validate_record_id(
            observation_id,
            f"{path}.supporting_observation_ids[{index}]",
            prefix="observation",
        )


def _validate_excluded(value: ExcludedObservation, path: str) -> None:
    _validate_record_id(value.observation_id, f"{path}.observation_id", prefix="observation")
    _validate_token(value.reason_code, f"{path}.reason_code")


def _validate_ranking(value: RankingScore, path: str) -> None:
    score = _validate_int64(value.value, f"{path}.value", minimum=0)
    if score > 1_000_000:
        _invalid("ranking_score_out_of_range", f"{path}.value")
    _validate_token(value.semantics, f"{path}.semantics")


def _validate_budget(value: ActionBudget, path: str) -> None:
    seconds = _validate_int64(value.max_seconds, f"{path}.max_seconds", minimum=1)
    memory = _validate_int64(value.max_memory_mb, f"{path}.max_memory_mb", minimum=1)
    if seconds > 86_400:
        _invalid("budget_seconds_out_of_range", f"{path}.max_seconds")
    if memory > 1_048_576:
        _invalid("budget_memory_out_of_range", f"{path}.max_memory_mb")


def _validate_usage(value: ActionUsage, path: str) -> None:
    for field_name in ("elapsed_ms", "peak_memory_mb", "output_bytes"):
        item = getattr(value, field_name)
        if item is not None:
            _validate_int64(item, f"{path}.{field_name}", minimum=0)


def _validate_allowed_conclusion(value: AllowedConclusion, path: str) -> None:
    _validate_token(value.predicate, f"{path}.predicate")
    modes = _validate_canonical_tuple(value.claim_modes, f"{path}.claim_modes", nonempty=True)
    for index, mode in enumerate(modes):
        _validate_enum(mode, ClaimMode, f"{path}.claim_modes[{index}]")
    _validate_enum(value.object_kind, ObjectKind, f"{path}.object_kind")
    categories = _validate_canonical_tuple(
        value.allowed_categorical_values,
        f"{path}.allowed_categorical_values",
    )
    for index, category in enumerate(categories):
        _validate_token(category, f"{path}.allowed_categorical_values[{index}]")
    if value.object_kind is not ObjectKind.CATEGORICAL and categories:
        _invalid("categorical_values_not_allowed", f"{path}.allowed_categorical_values")


def _validate_authorization(value: ActionAuthorization, path: str) -> None:
    if value.kind != "action_authorization":
        _invalid("record_kind_mismatch", f"{path}.kind")
    if value.schema_version != "1.0":
        _invalid("unsupported_schema_version", f"{path}.schema_version")
    _validate_record_id(value.action_id, f"{path}.action_id", prefix="action")
    _validate_enum(value.granted_level, AuthorizationLevel, f"{path}.granted_level")
    policy_path = f"{path}.policy"
    _validate_policy(_require_exact_type(value.policy, PolicyRef, policy_path), policy_path)
    _validate_reason_codes(value.reason_codes, f"{path}.reason_codes", nonempty=True)


def _validate_literal(value: object, expected: str, path: str, code: str) -> None:
    if value != expected:
        _invalid(code, path)


def _validate_typed_tuple(
    value: object,
    path: str,
    expected_type: type[object],
    *,
    nonempty: bool = False,
) -> tuple[object, ...]:
    items = _validate_canonical_tuple(value, path, nonempty=nonempty)
    for index, item in enumerate(items):
        if type(item) is not expected_type:
            _invalid("tuple_item_type_mismatch", f"{path}[{index}]")
        validate_contract_value(cast(ContractValue, item), field_path=f"{path}[{index}]")
    return items


def _validate_id_tuple(
    value: object,
    path: str,
    *,
    prefix: str,
    nonempty: bool = False,
) -> tuple[object, ...]:
    items = _validate_canonical_tuple(value, path, nonempty=nonempty)
    for index, item in enumerate(items):
        _validate_record_id(item, f"{path}[{index}]", prefix=prefix)
    return items


def _validate_record_header(
    kind: object,
    schema_version: object,
    record_id: object,
    path: str,
    *,
    expected_kind: str,
    id_prefix: str,
) -> None:
    _validate_literal(kind, expected_kind, f"{path}.kind", "record_kind_mismatch")
    _validate_literal(
        schema_version,
        "1.0",
        f"{path}.schema_version",
        "unsupported_schema_version",
    )
    _validate_record_id(record_id, f"{path}.{id_prefix}_id", prefix=id_prefix)


def _validate_reasoning_run(value: ReasoningRun, path: str) -> None:
    _validate_literal(value.kind, "reasoning_run", f"{path}.kind", "record_kind_mismatch")
    _validate_literal(
        value.schema_version,
        "1.0",
        f"{path}.schema_version",
        "unsupported_schema_version",
    )
    _validate_record_id(value.run_id, f"{path}.run_id", prefix="run")
    if re.fullmatch(r"[0-9a-f]{32}", value.execution_nonce) is None:
        _invalid("invalid_execution_nonce", f"{path}.execution_nonce")
    _validate_digest(value.reuse_key, f"{path}.reuse_key")
    _validate_token(value.purpose, f"{path}.purpose")
    _validate_typed_tuple(value.subjects, f"{path}.subjects", SubjectRef, nonempty=True)
    _validate_typed_tuple(
        value.input_anchors,
        f"{path}.input_anchors",
        EvidenceAnchor,
        nonempty=True,
    )
    validate_coverage_collection(value.initial_coverage, field_path=f"{path}.initial_coverage")
    _validate_typed_tuple(value.policies, f"{path}.policies", PolicyRef, nonempty=True)
    _validate_typed_tuple(value.producers, f"{path}.producers", ProducerRef, nonempty=True)


def _validate_question(value: Question, path: str) -> None:
    _validate_record_header(
        value.kind,
        value.schema_version,
        value.question_id,
        path,
        expected_kind="question",
        id_prefix="question",
    )
    _validate_enum(value.question_type, QuestionType, f"{path}.question_type")
    _validate_typed_tuple(value.subjects, f"{path}.subjects", SubjectRef, nonempty=True)
    conclusions = _validate_typed_tuple(
        value.allowed_conclusions,
        f"{path}.allowed_conclusions",
        AllowedConclusion,
        nonempty=True,
    )
    predicates = [item.predicate for item in conclusions if isinstance(item, AllowedConclusion)]
    if len(predicates) != len(set(predicates)):
        _invalid("duplicate_allowed_predicate", f"{path}.allowed_conclusions")


def _validate_observation(value: Observation, path: str) -> None:
    _validate_record_header(
        value.kind,
        value.schema_version,
        value.observation_id,
        path,
        expected_kind="observation",
        id_prefix="observation",
    )
    _validate_token(value.observation_type, f"{path}.observation_type")
    _validate_typed_tuple(value.subjects, f"{path}.subjects", SubjectRef, nonempty=True)
    validate_contract_value(value.value, field_path=f"{path}.value")
    _validate_typed_tuple(
        value.source_refs,
        f"{path}.source_refs",
        EvidenceLocator,
        nonempty=True,
    )
    _validate_enum(value.scope, EvidenceScope, f"{path}.scope")
    _validate_enum(value.strength, ObservationStrength, f"{path}.strength")
    _validate_id_tuple(
        value.input_observation_ids,
        f"{path}.input_observation_ids",
        prefix="observation",
    )
    if value.strength is ObservationStrength.OBSERVED and value.input_observation_ids:
        _invalid("observation_derivation_shape", path)
    if value.strength is ObservationStrength.DERIVED and not value.input_observation_ids:
        _invalid("observation_derivation_shape", path)
    if value.origin_outcome_id is not None:
        _validate_record_id(value.origin_outcome_id, f"{path}.origin_outcome_id", prefix="outcome")
    producer_path = f"{path}.producer"
    _validate_producer(
        _require_exact_type(value.producer, ProducerRef, producer_path),
        producer_path,
    )
    if value.producer.kind not in {
        ProducerKind.ANALYZER,
        ProducerKind.QUERY,
        ProducerKind.SYSTEM,
    }:
        _invalid("producer_kind_forbidden", f"{path}.producer.kind")
    _validate_enum(value.ownership, OwnershipValue, f"{path}.ownership")
    validate_coverage_collection(
        value.coverage_assertions,
        field_path=f"{path}.coverage_assertions",
    )


def _validate_claim(value: ClaimCandidate, path: str) -> None:
    _validate_record_header(
        value.kind,
        value.schema_version,
        value.claim_id,
        path,
        expected_kind="claim_candidate",
        id_prefix="claim",
    )
    _validate_record_id(value.question_id, f"{path}.question_id", prefix="question")
    _validate_enum(value.task, ClaimTask, f"{path}.task")
    _validate_enum(value.claim_mode, ClaimMode, f"{path}.claim_mode")
    _validate_typed_tuple(value.subjects, f"{path}.subjects", SubjectRef, nonempty=True)
    _validate_token(value.predicate, f"{path}.predicate")
    if value.object_value is not None:
        validate_contract_value(value.object_value, field_path=f"{path}.object_value")
    support = _validate_id_tuple(
        value.supporting_observation_ids,
        f"{path}.supporting_observation_ids",
        prefix="observation",
        nonempty=value.claim_mode is ClaimMode.POSITIVE,
    )
    contradict = _validate_id_tuple(
        value.contradicting_observation_ids,
        f"{path}.contradicting_observation_ids",
        prefix="observation",
    )
    excluded = _validate_typed_tuple(
        value.excluded_observations,
        f"{path}.excluded_observations",
        ExcludedObservation,
    )
    excluded_ids = {
        item.observation_id for item in excluded if isinstance(item, ExcludedObservation)
    }
    if set(support) & set(contradict) or set(support) & excluded_ids or set(contradict) & excluded_ids:
        _invalid("claim_evidence_overlap", path)
    requirements = _validate_coverage_predicate_collection(
        value.coverage_requirements,
        f"{path}.coverage_requirements",
        nonempty=value.claim_mode in {ClaimMode.NEGATIVE, ClaimMode.EXHAUSTIVE},
    )
    if value.claim_mode in {ClaimMode.NEGATIVE, ClaimMode.EXHAUSTIVE}:
        for requirement in requirements:
            if not isinstance(requirement, CoveragePredicate) or requirement.allowed_statuses != (
                CoverageStatus.COMPLETE,
            ):
                _invalid("negative_coverage_must_require_complete", f"{path}.coverage_requirements")
    _validate_digest(value.coverage_context_digest, f"{path}.coverage_context_digest")
    _validate_typed_tuple(value.ownership, f"{path}.ownership", SubjectOwnership)
    _validate_reason_codes(value.caps, f"{path}.caps")
    _validate_reason_codes(value.unknowns, f"{path}.unknowns")
    _validate_id_tuple(value.resolves_gap_ids, f"{path}.resolves_gap_ids", prefix="gap")
    producer_path = f"{path}.producer"
    _validate_producer(
        _require_exact_type(value.producer, ProducerRef, producer_path),
        producer_path,
    )
    if value.producer.kind not in {
        ProducerKind.RULE_ENGINE,
        ProducerKind.KNOWLEDGE_PACK,
        ProducerKind.MODEL,
        ProducerKind.SYSTEM,
    }:
        _invalid("producer_kind_forbidden", f"{path}.producer.kind")
    if value.supersedes is not None:
        _validate_record_id(value.supersedes, f"{path}.supersedes", prefix="claim")
    if value.score is not None:
        score_path = f"{path}.score"
        _validate_ranking(
            _require_exact_type(value.score, RankingScore, score_path),
            score_path,
        )


def _validate_gap(value: EvidenceGap, path: str) -> None:
    _validate_record_header(
        value.kind,
        value.schema_version,
        value.gap_id,
        path,
        expected_kind="evidence_gap",
        id_prefix="gap",
    )
    _validate_record_id(value.question_id, f"{path}.question_id", prefix="question")
    if value.claim_id is not None:
        _validate_record_id(value.claim_id, f"{path}.claim_id", prefix="claim")
    _validate_enum(value.effect, GapEffect, f"{path}.effect")
    _validate_reason_codes(value.reason_codes, f"{path}.reason_codes", nonempty=True)
    observation_types = _validate_canonical_tuple(
        value.required_observation_types,
        f"{path}.required_observation_types",
    )
    for index, observation_type in enumerate(observation_types):
        _validate_token(observation_type, f"{path}.required_observation_types[{index}]")
    _validate_coverage_predicate_collection(
        value.coverage_requirements,
        f"{path}.coverage_requirements",
    )
    if not value.required_observation_types and not value.coverage_requirements:
        _invalid("gap_requirement_required", path)
    producer_path = f"{path}.producer"
    _validate_producer(
        _require_exact_type(value.producer, ProducerRef, producer_path),
        producer_path,
    )
    if value.producer.kind not in {ProducerKind.MODEL, ProducerKind.SYSTEM}:
        _invalid("producer_kind_forbidden", f"{path}.producer.kind")


def _validate_next_action(value: NextAction, path: str) -> None:
    _validate_record_header(
        value.kind,
        value.schema_version,
        value.action_id,
        path,
        expected_kind="next_action",
        id_prefix="action",
    )
    _validate_record_id(value.question_id, f"{path}.question_id", prefix="question")
    _validate_id_tuple(value.gap_ids, f"{path}.gap_ids", prefix="gap", nonempty=True)
    if re.fullmatch(r"[0-9a-f]{32}", value.attempt_nonce) is None:
        _invalid("invalid_attempt_nonce", f"{path}.attempt_nonce")
    _validate_token(value.action_type, f"{path}.action_type")
    _validate_typed_tuple(value.subjects, f"{path}.subjects", SubjectRef, nonempty=True)
    _validate_id_tuple(value.input_anchor_ids, f"{path}.input_anchor_ids", prefix="anchor")
    _validate_digest(value.parameters_digest, f"{path}.parameters_digest")
    _validate_enum(
        value.authorization_required,
        AuthorizationLevel,
        f"{path}.authorization_required",
    )
    budget_path = f"{path}.budget"
    _validate_budget(_require_exact_type(value.budget, ActionBudget, budget_path), budget_path)
    criteria = _validate_canonical_tuple(
        value.success_criteria,
        f"{path}.success_criteria",
        nonempty=True,
    )
    for index, criterion in enumerate(criteria):
        _validate_token(criterion, f"{path}.success_criteria[{index}]")
    _validate_coverage_predicate_collection(
        value.negative_valid_only_if,
        f"{path}.negative_valid_only_if",
    )
    _validate_digest(value.dedupe_key, f"{path}.dedupe_key")
    producer_path = f"{path}.producer"
    _validate_producer(
        _require_exact_type(value.producer, ProducerRef, producer_path),
        producer_path,
    )
    if value.producer.kind not in {ProducerKind.MODEL, ProducerKind.SYSTEM}:
        _invalid("producer_kind_forbidden", f"{path}.producer.kind")


def _validate_outcome(value: ActionOutcome, path: str) -> None:
    _validate_record_header(
        value.kind,
        value.schema_version,
        value.outcome_id,
        path,
        expected_kind="action_outcome",
        id_prefix="outcome",
    )
    _validate_record_id(value.action_id, f"{path}.action_id", prefix="action")
    _validate_enum(value.status, OutcomeStatus, f"{path}.status")
    _validate_typed_tuple(value.output_anchors, f"{path}.output_anchors", EvidenceAnchor)
    validate_coverage_collection(
        value.coverage_assertions,
        field_path=f"{path}.coverage_assertions",
    )
    _validate_reason_codes(value.reason_codes, f"{path}.reason_codes")
    if value.diagnostics_locator is not None:
        locator_path = f"{path}.diagnostics_locator"
        _validate_locator(
            _require_exact_type(value.diagnostics_locator, EvidenceLocator, locator_path),
            locator_path,
        )
    usage_path = f"{path}.usage"
    _validate_usage(_require_exact_type(value.usage, ActionUsage, usage_path), usage_path)
    producer_path = f"{path}.producer"
    _validate_producer(
        _require_exact_type(value.producer, ProducerRef, producer_path),
        producer_path,
    )
    if value.producer.kind not in {
        ProducerKind.ANALYZER,
        ProducerKind.QUERY,
        ProducerKind.SYSTEM,
    }:
        _invalid("producer_kind_forbidden", f"{path}.producer.kind")


def _validate_review(value: ReviewDecision, path: str) -> None:
    _validate_record_header(
        value.kind,
        value.schema_version,
        value.decision_id,
        path,
        expected_kind="review_decision",
        id_prefix="decision",
    )
    _validate_record_id(value.question_id, f"{path}.question_id", prefix="question")
    _validate_record_id(value.claim_id, f"{path}.claim_id", prefix="claim")
    _validate_enum(value.decision, ReviewDecisionValue, f"{path}.decision")
    reviewer_path = f"{path}.reviewer"
    _validate_actor(_require_exact_type(value.reviewer, Actor, reviewer_path), reviewer_path)
    if value.reviewer.kind not in {ActorKind.HUMAN, ActorKind.MODEL}:
        _invalid("review_actor_forbidden", f"{path}.reviewer.kind")
    _validate_digest(value.basis_head_digest, f"{path}.basis_head_digest")
    _validate_id_tuple(
        value.basis_observation_ids,
        f"{path}.basis_observation_ids",
        prefix="observation",
        nonempty=value.decision is ReviewDecisionValue.REJECTED,
    )
    _validate_id_tuple(value.gap_ids, f"{path}.gap_ids", prefix="gap")
    if value.decision in {
        ReviewDecisionValue.UNKNOWN,
        ReviewDecisionValue.CHANGES_REQUESTED,
    } and not value.gap_ids:
        _invalid("review_gap_required", f"{path}.gap_ids")
    _validate_reason_codes(value.reason_codes, f"{path}.reason_codes", nonempty=True)


def validate_coverage_collection(
    value: tuple[CoverageAssertion, ...],
    *,
    field_path: str,
) -> None:
    if not isinstance(value, tuple):
        _invalid("tuple_required", field_path)
    values = value
    keys = tuple(
        _sort_key(item, f"{field_path}[{index}]") for index, item in enumerate(values)
    )
    if keys != tuple(sorted(keys)):
        _invalid("non_canonical_tuple", field_path)
    seen: set[tuple[bytes, CoverageSource]] = set()
    for index, item in enumerate(values):
        if type(item) is not CoverageAssertion:
            _invalid("coverage_assertion_required", f"{field_path}[{index}]")
        _validate_coverage(item, f"{field_path}[{index}]")
        key = (_sort_key(item.subject, f"{field_path}[{index}].subject"), item.source)
        if key in seen:
            _invalid("duplicate_coverage_key", field_path)
        seen.add(key)


def _validate_candidate_label_feedback(value: CandidateLabelFeedback, path: str) -> None:
    _validate_record_header(
        value.kind,
        value.schema_version,
        value.feedback_id,
        path,
        expected_kind="candidate_label_feedback",
        id_prefix="feedback",
    )
    _validate_enum(value.label_kind, LabelKind, f"{path}.label_kind")
    _validate_digest(value.proposed_label_digest, f"{path}.proposed_label_digest")
    _validate_typed_tuple(value.subject_refs, f"{path}.subject_refs", SubjectRef, nonempty=True)
    if value.evidence_ref is not None:
        if not value.evidence_ref:
            _invalid("empty_evidence_ref", f"{path}.evidence_ref")
        _validate_text(value.evidence_ref, f"{path}.evidence_ref", max_length=256)
    _validate_reason_codes(value.reason_codes, f"{path}.reason_codes")
    _validate_policy(value.policy, f"{path}.policy")
    _validate_producer(value.producer, f"{path}.producer")


def validate_contract_value(value: ContractValue, *, field_path: str = "$") -> None:
    """Validate one shared contract value without coercion or normalization."""
    value_type = type(value)
    if value_type is Actor:
        _validate_actor(cast(Actor, value), field_path)
    elif value_type is ProducerRef:
        _validate_producer(cast(ProducerRef, value), field_path)
    elif value_type is PolicyRef:
        _validate_policy(cast(PolicyRef, value), field_path)
    elif value_type is SubjectRef:
        _validate_subject(cast(SubjectRef, value), field_path)
    elif value_type is EvidenceAnchor:
        _validate_anchor(cast(EvidenceAnchor, value), field_path)
    elif value_type is EvidenceLocator:
        _validate_locator(cast(EvidenceLocator, value), field_path)
    elif value_type is CoverageAssertion:
        _validate_coverage(cast(CoverageAssertion, value), field_path)
    elif value_type is CoveragePredicate:
        _validate_coverage_predicate(cast(CoveragePredicate, value), field_path)
    elif value_type is ObservationValue:
        _validate_observation_value(cast(ObservationValue, value), field_path)
    elif value_type is SubjectOwnership:
        _validate_subject_ownership(cast(SubjectOwnership, value), field_path)
    elif value_type is ExcludedObservation:
        _validate_excluded(cast(ExcludedObservation, value), field_path)
    elif value_type is RankingScore:
        _validate_ranking(cast(RankingScore, value), field_path)
    elif value_type is ActionBudget:
        _validate_budget(cast(ActionBudget, value), field_path)
    elif value_type is ActionUsage:
        _validate_usage(cast(ActionUsage, value), field_path)
    elif value_type is AllowedConclusion:
        _validate_allowed_conclusion(cast(AllowedConclusion, value), field_path)
    elif value_type is ActionAuthorization:
        _validate_authorization(cast(ActionAuthorization, value), field_path)
    elif value_type is ReasoningRun:
        _validate_reasoning_run(cast(ReasoningRun, value), field_path)
    elif value_type is Question:
        _validate_question(cast(Question, value), field_path)
    elif value_type is Observation:
        _validate_observation(cast(Observation, value), field_path)
    elif value_type is ClaimCandidate:
        _validate_claim(cast(ClaimCandidate, value), field_path)
    elif value_type is EvidenceGap:
        _validate_gap(cast(EvidenceGap, value), field_path)
    elif value_type is NextAction:
        _validate_next_action(cast(NextAction, value), field_path)
    elif value_type is ActionOutcome:
        _validate_outcome(cast(ActionOutcome, value), field_path)
    elif value_type is ReviewDecision:
        _validate_review(cast(ReviewDecision, value), field_path)
    elif value_type is CandidateLabelFeedback:
        _validate_candidate_label_feedback(cast(CandidateLabelFeedback, value), field_path)
    else:
        _invalid("unsupported_contract_value", field_path)


__all__ = [
    "ActionAuthorization",
    "ActionBudget",
    "ActionOutcome",
    "ActionUsage",
    "Actor",
    "ActorKind",
    "AllowedConclusion",
    "AuthorizationLevel",
    "CanonicalCodecError",
    "CandidateLabelFeedback",
    "ClaimMode",
    "ClaimCandidate",
    "ClaimTask",
    "ContractValue",
    "CoverageAssertion",
    "CoveragePredicate",
    "CoverageSource",
    "CoverageStatus",
    "EvidenceAnchor",
    "EvidenceAnchorType",
    "EvidenceGap",
    "EvidenceLocator",
    "EvidenceScope",
    "ExcludedObservation",
    "DomainRecord",
    "GapEffect",
    "IdentityMismatchError",
    "LabelKind",
    "JudgmentContractError",
    "LedgerIntegrityError",
    "LocatorKind",
    "ObjectKind",
    "NextAction",
    "Observation",
    "ObservationStrength",
    "ObservationValue",
    "ObservationValueKind",
    "OwnershipValue",
    "OutcomeStatus",
    "PolicyRef",
    "ProducerKind",
    "ProducerRef",
    "Question",
    "QuestionType",
    "RankingScore",
    "ReferenceIntegrityError",
    "ReasoningRun",
    "ReplayTransitionError",
    "ReviewDecision",
    "ReviewDecisionValue",
    "SchemaValidationError",
    "SharedValue",
    "SubjectKind",
    "SubjectOwnership",
    "SubjectRef",
    "validate_contract_value",
    "validate_coverage_collection",
]
