"""Index package-bound network evidence for report-before-review joins.

Shared-host matching is a navigation aid, not proof of the same connection,
service, observation time, or operator. Exact Phase1 candidate IDs remain the
authority for coverage; no source field can mark a provider identity verified.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from apkscan.core.models import Endpoint
from apkscan.core.phase2.inventory import ReviewCandidate, _stable_parent_id
from apkscan.core.phase2.triage import normalize_host

_KINDS = {"DOMAIN": "domain", "IP": "ip", "URL": "url"}
_STATIC_SOURCES = frozenset({"dex", "resource", "native", "manifest", "cert"})
_SCOPES = frozenset({"case_evidence", "batch_reference", "legacy_unspecified", "parent"})


class PackageEvidenceIndex:
    """Build once per package, then resolve targets without repeated scans."""

    def __init__(self, payload: Mapping[str, Any], candidates: Sequence[ReviewCandidate]):
        candidate_map = {(c.collection, c.parent_id, c.evidence_id, c.scope): c for c in candidates}
        parents: dict[tuple[str, str], list[ReviewCandidate]] = defaultdict(list)
        for candidate in candidates:
            parents[(candidate.collection, candidate.parent_id)].append(candidate)
        self.by_host: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        self.network_candidates: set[str] = set()
        self.matched_candidates: set[str] = set()
        meta = payload.get("meta")
        web = isinstance(meta, Mapping) and meta.get("platform") == "web"
        for collection, evidence_field in (("leads", "source_refs"), ("endpoints", "evidences")):
            values = payload.get(collection, [])
            if not isinstance(values, list):
                continue
            for parent in values:
                if not isinstance(parent, Mapping):
                    continue
                kind = parent.get("kind") if collection == "endpoints" else _KINDS.get(str(parent.get("category")))
                value = parent.get("value")
                if kind not in ("ip", "domain", "url") or not isinstance(value, str):
                    continue
                host = normalize_host(str(kind), value)
                identity = _stable_parent_id(collection, parent)
                if not host or identity is None:
                    continue
                parent_id = identity[0]
                for candidate in parents.get((collection, parent_id), ()):
                    self.network_candidates.add(candidate.candidate_id)
                    self.by_host[host].setdefault(candidate.candidate_id, {
                        "candidate_id": candidate.candidate_id, "collection": collection,
                        "scope": candidate.scope if candidate.scope in _SCOPES else "unknown",
                        "has_evidence": candidate.has_evidence, "stages": set(), "times": set(),
                    })
                evidences = parent.get(evidence_field, [])
                if not isinstance(evidences, list):
                    continue
                for evidence in evidences:
                    if not isinstance(evidence, Mapping):
                        continue
                    eid, scope = evidence.get("evidence_id"), evidence.get("scope", "legacy_unspecified")
                    if not isinstance(eid, str) or not isinstance(scope, str):
                        continue
                    candidate = candidate_map.get((collection, parent_id, eid, scope))
                    if candidate is None:
                        continue
                    row = self.by_host[host][candidate.candidate_id]
                    source = evidence.get("source")
                    stage = ("dynamic" if isinstance(source, str) and source.startswith("runtime") else
                             "web" if web or source in ("web", "http", "browser") else
                             "static" if isinstance(source, str) and source in _STATIC_SOURCES else "unknown")
                    row["stages"].add(stage)
                    observed = evidence.get("observed_at")
                    if isinstance(observed, (int, float)) and not isinstance(observed, bool) and math.isfinite(observed):
                        row["times"].add(float(observed))

    def resolve(self, endpoint: Endpoint, *, evidence_values: str = "omit", max_refs: int = 64) -> dict[str, Any]:
        if evidence_values not in {"omit", "raw"}:
            raise ValueError("invalid_evidence_mode")
        if isinstance(max_refs, bool) or not isinstance(max_refs, int) or not 1 <= max_refs <= 256:
            raise ValueError("invalid_reference_budget")
        host = normalize_host(endpoint.kind, endpoint.value)
        rows = self.by_host.get(host, {})
        self.matched_candidates.update(rows)
        selected = sorted(rows)[:max_refs]
        scopes = Counter(row["scope"] for row in rows.values())
        refs = []
        for candidate_id in selected:
            row = rows[candidate_id]
            refs.append({"candidate_id": candidate_id, "collection": row["collection"],
                         "scope": row["scope"], "has_evidence": row["has_evidence"],
                         "stages": sorted(row["stages"]) or ["unknown"],
                         "observed_time_present": bool(row["times"]),
                         **({"observed_at": sorted(row["times"])} if evidence_values == "raw" else {})})
        return {"match_basis": "shared_normalized_host_not_connection_identity",
                "candidate_count": len(rows), "scope_counts": dict(sorted(scopes.items())),
                "candidate_refs": refs, "references_truncated": len(rows) > len(selected),
                "source_independence_verified": False, "provider_identity_verified": False,
                "status": "linked_for_review" if rows else "no_matching_phase1_candidate",
                "next_action": "review_original_coordinates_resource_scope_and_observation_time"}

    def summary(self) -> dict[str, int]:
        return {"network_candidate_count": len(self.network_candidates),
                "linked_network_candidate_count": len(self.matched_candidates),
                "unlinked_network_candidate_count": len(self.network_candidates - self.matched_candidates)}
