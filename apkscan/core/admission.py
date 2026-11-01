"""Purpose-specific admission of observations, never a business-truth score.

An allowed candidate still has to pass the existing tier, scope, network-mode,
and closure gates. Independent evidence is evaluated separately: a same-value
decoy neither contaminates a real observation nor borrows its qualification.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

from apkscan.core.models import EvidenceScope, OBSERVED_CONTACT_SOURCES, evidence_source_is_direct
from apkscan.core.observations import occurrence_id

POLICY_VERSION = "evidence-admission/1"
PURPOSES = frozenset({
    "passive_enrichment", "lead_priority", "closure_candidate", "dex_query",
    "model_summary", "corpus_relation",
})
DOWNGRADE_ADMISSION = "evidence_admission"
ADMISSION_NOTE = "该用途仅有存疑、未核或非当前案件观察支撑；材料保留待核，不能借同值弱来源升级"
_WEAK_STRUCTURE = frozenset({"invalid", "malformed", "failed", "unsupported", "name-only"})
_WEAK_REFERENCE = frozenset({"name-only", "name_only", "comment-only", "comment_only"})
_T = TypeVar("_T")


def _field(evidence: object, name: str, default: Any = None) -> Any:
    return evidence.get(name, default) if isinstance(evidence, Mapping) else getattr(evidence, name, default)


def _has_field(evidence: object, name: str) -> bool:
    return name in evidence if isinstance(evidence, Mapping) else hasattr(evidence, name)


@dataclass(frozen=True)
class Verdict:
    state: str
    reason_codes: tuple[str, ...]


def evaluate_evidence(evidence: object, purpose: str) -> Verdict:
    if purpose not in PURPOSES:
        raise ValueError("unknown evidence purpose")
    scope = _field(evidence, "scope")
    scope = scope.value if isinstance(scope, EvidenceScope) else scope
    if scope != EvidenceScope.CASE_EVIDENCE.value:
        return Verdict("blocked", ("not_current_case",))
    source = _field(evidence, "source", "")
    if not evidence_source_is_direct(source):
        return Verdict("review", ("unverified_reconstruction",))
    reasons: set[str] = set()
    if not isinstance(source, str) or not source.strip():
        reasons.add("unknown_source")
    for name in ("provenance", "locator"):
        if _has_field(evidence, name) and not isinstance(_field(evidence, name), Mapping):
            reasons.add("malformed_evidence_facts")
    statuses = {}
    for name in ("structure_status", "reference_status", "reachability"):
        value = _field(evidence, name, "unknown")
        if not isinstance(value, str):
            reasons.add("malformed_evidence_facts")
            value = "unknown"
        statuses[name] = value
    if _has_field(evidence, "suspicions"):
        suspicions = _field(evidence, "suspicions")
        if suspicions is None or suspicions == "":
            pass
        elif isinstance(suspicions, list):
            if suspicions:
                if any(
                    isinstance(item, Mapping)
                    and item.get("kind") in ("malformed_suspicion", "malformed_evidence_fact")
                    for item in suspicions
                ):
                    reasons.add("malformed_evidence_facts")
                if any(
                    not isinstance(item, Mapping)
                    or item.get("kind") not in ("malformed_suspicion", "malformed_evidence_fact")
                    for item in suspicions
                ):
                    reasons.add("suspicious_occurrence")
        else:
            reasons.add("malformed_evidence_facts")
    if statuses["structure_status"] in _WEAK_STRUCTURE:
        reasons.add("invalid_or_unsupported_structure")
    if statuses["reference_status"] in _WEAK_REFERENCE:
        reasons.add("name_or_comment_only")
    if statuses["reachability"] in {"unreachable", "non-executable"}:
        reasons.add("not_reachable")
    if source == "static-dex-xref" and purpose not in {"dex_query", "model_summary"}:
        reasons.add("static_xref_not_runtime")
    if reasons:
        return Verdict("review", tuple(sorted(reasons)))
    runtime = isinstance(source, str) and source in OBSERVED_CONTACT_SOURCES
    if purpose == "corpus_relation" and not runtime:
        if (
            statuses["structure_status"] not in {"parsed", "verified"}
            or statuses["reference_status"] not in {"referenced", "resolved"}
            or not isinstance(_field(evidence, "provenance"), Mapping)
            or not isinstance(_field(evidence, "locator"), Mapping)
            or not _field(evidence, "provenance") or not _field(evidence, "locator")
        ):
            return Verdict("review", ("relation_support_unknown",))
    return Verdict("allowed", (
        "observed_contact_not_ownership" if runtime else "static_candidate_not_runtime",
    ))


def admitted_refs(evidences: Iterable[_T], purpose: str) -> list[_T]:
    return [evidence for evidence in evidences if evaluate_evidence(evidence, purpose).state == "allowed"]


def evaluate_usage(evidences: Iterable[object], purpose: str) -> dict:
    if purpose not in PURPOSES:
        raise ValueError("unknown evidence purpose")
    items = list(evidences)
    verdicts = [evaluate_evidence(evidence, purpose) for evidence in items]
    counts = {state: sum(verdict.state == state for verdict in verdicts)
              for state in ("allowed", "review", "blocked")}
    located: list[str] = []
    unlocated_allowed_count = 0
    for evidence, verdict in zip(items, verdicts, strict=True):
        if verdict.state != "allowed":
            continue
        try:
            occurrence = occurrence_id(evidence)
        except (TypeError, ValueError):
            occurrence = None
        if occurrence is None:
            unlocated_allowed_count += 1
        else:
            located.append(occurrence)
    state = "allowed" if counts["allowed"] else "review" if counts["review"] else "blocked"
    return {
        "policy_version": POLICY_VERSION, "purpose": purpose, "state": state,
        "reason_codes": sorted({reason for verdict in verdicts for reason in verdict.reason_codes})
        if verdicts else ["no_evidence"],
        "occurrence_counts": counts,
        "supporting_occurrence_ids": sorted(set(located)),
        "unlocated_allowed_count": unlocated_allowed_count,
        "establishes_business_ownership": False,
    }
