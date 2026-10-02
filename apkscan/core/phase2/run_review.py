"""Pure declared-run history and conflict review, without collection or file I/O."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from apkscan.core.provider_review import SOURCE_FAMILIES
from apkscan.core.source_status import normalize_source_status


_RUN_TYPES = frozenset({"static", "dynamic", "enrichment", "case_close", "decrypt",
                        "comparison", "manual", "web", "build", "family"})
_RUN_STATES = frozenset({"complete", "partial", "failed", "skipped", "done", "blocked"})
_CONFLICT_FIELDS = ("origin_ip", "hosting_provider", "service_operator", "app_type")


class PreparationError(ValueError):
    """Safe preparation failure without reflecting private case values."""


def build_run_review(runs: Sequence[Mapping[str, Any]], *, case_id: str,
                     evidence_values: str = "omit") -> dict[str, Any]:
    """Retain per-run outcomes; never use last-write-wins to erase failures."""
    if evidence_values not in {"omit", "raw"}:
        raise PreparationError("invalid_evidence_mode")
    if len(runs) > 1000:
        raise PreparationError("run_record_limit")
    seen: dict[str, str] = {}
    parents: dict[str, str | None] = {}
    records = []
    history: dict[str, list[dict[str, str]]] = {}
    claims: dict[str, dict[str, list[str]]] = {key: {} for key in _CONFLICT_FIELDS}
    for number, run in enumerate(runs, 1):
        if not isinstance(run, Mapping) or run.get("case_id") != case_id:
            raise PreparationError("run_case_mismatch")
        run_id = run.get("run_id")
        if not isinstance(run_id, str) or not run_id or len(run_id) > 256 or run_id in seen:
            raise PreparationError("invalid_or_duplicate_run_id")
        parent = run.get("parent_run_id")
        if parent is not None and (not isinstance(parent, str) or not parent or len(parent) > 256):
            raise PreparationError("invalid_parent_run_id")
        run_type = run.get("run_type")
        if not isinstance(run_type, str) or run_type not in _RUN_TYPES:
            raise PreparationError("unsupported_run_type")
        run_ref = f"run-{number:04d}"
        seen[run_id] = run_ref
        parents[run_id] = parent
        state = run.get("status")
        state = state if isinstance(state, str) and state in _RUN_STATES else "unknown"
        records.append({"run_ref": run_ref, "run_type": run_type, "status": state,
                        "artifact_provenance": "declared_not_verified"})
        statuses = run.get("source_statuses", {})
        if not isinstance(statuses, Mapping) or len(statuses) > 100:
            raise PreparationError("invalid_source_statuses")
        for provider, value in statuses.items():
            if not isinstance(provider, str) or not provider or len(provider) > 128:
                raise PreparationError("invalid_source_name")
            normalized = normalize_source_status(value)
            history.setdefault(provider, []).append(
                {"run_ref": run_ref, "status": str(normalized["status"])})
        closure = run.get("closure", {})
        if not isinstance(closure, Mapping):
            raise PreparationError("invalid_run_closure")
        for field in _CONFLICT_FIELDS:
            value = closure.get(field)
            if isinstance(value, str) and value.strip():
                if len(value) > 2048:
                    raise PreparationError("run_claim_limit")
                claims[field].setdefault(value.strip(), []).append(run_ref)
    # Check the graph without recursion; a long valid chain must not overflow.
    finished: set[str] = set()
    for run_id in parents:
        path: set[str] = set()
        cursor: str | None = run_id
        while cursor is not None and cursor not in finished:
            if cursor not in parents:
                raise PreparationError("missing_parent_run")
            if cursor in path:
                raise PreparationError("run_parent_cycle")
            path.add(cursor)
            cursor = parents[cursor]
        finished.update(path)
    sources = []
    for number, (provider, observations) in enumerate(sorted(history.items()), 1):
        public_name = provider if provider in SOURCE_FAMILIES or evidence_values == "raw" else f"source-{number:04d}"
        sources.append({"source_ref": public_name, "observations": observations,
                        "has_failed_observation": any(row["status"] == "failed" for row in observations)})
    conflicts = []
    for field, values in claims.items():
        if len(values) > 1:
            conflicts.append({"field": field, "candidate_value_count": len(values),
                              "run_refs": sorted({ref for refs in values.values() for ref in refs}),
                              "status": "potential_conflict_requires_resource_and_time_scope_review",
                              **({"values": sorted(values)} if evidence_values == "raw" else {})})
    return {"runs": records, "source_history": sources, "conflicts": conflicts,
            "run_count": len(records), "artifact_provenance_verified": False}
