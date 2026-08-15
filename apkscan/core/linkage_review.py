"""Pure review projections over the deterministic corpus linkage engine.

This module never scores evidence itself and never writes to the corpus.  It
turns the complete result from :func:`rank_link_candidates` into either a
single-pair explanation or explicitly edge-based review groups.
"""

from __future__ import annotations

from copy import deepcopy
from itertools import combinations
import math
import re
from typing import Any, Iterable, Mapping

from apkscan.core.linkage import rank_link_candidates


REVIEW_SCHEMA_VERSION = "1.0"
_TRANSITIVE_PAIR_PREVIEW_LIMIT = 100
_TRANSITIVE_PAIR_SCAN_LIMIT = 10_000

_EVIDENCE_VALUE_MODES = frozenset({"raw", "omit"})
_REAL_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class LinkageReviewError(ValueError):
    """A review query or upstream linkage result violates its contract."""


def _evidence_mode(value: str) -> str:
    if value not in _EVIDENCE_VALUE_MODES:
        raise LinkageReviewError("evidence_values must be 'raw' or 'omit'")
    return value


def _query_sha(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise LinkageReviewError(f"{field} must be a SHA-256 string")
    normalized = value.strip().lower()
    if _REAL_SHA256_RE.fullmatch(normalized) is None:
        raise LinkageReviewError(f"{field} must be a 64-character hexadecimal SHA-256")
    return normalized


def _candidate_pair(candidate: Mapping[str, object]) -> tuple[str, str]:
    left = candidate.get("left")
    right = candidate.get("right")
    if not isinstance(left, Mapping) or not isinstance(right, Mapping):
        raise LinkageReviewError("candidate sides must be objects")
    left_id = left.get("sample_sha256")
    right_id = right.get("sample_sha256")
    if not isinstance(left_id, str) or not isinstance(right_id, str):
        raise LinkageReviewError("candidate sides must contain sample identities")
    left_normalized = left_id.lower()
    right_normalized = right_id.lower()
    if left_normalized == right_normalized:
        raise LinkageReviewError("candidate must not be a self-pair")
    if left_normalized < right_normalized:
        return left_normalized, right_normalized
    return right_normalized, left_normalized


def _candidate_score(candidate: Mapping[str, object]) -> float:
    value = candidate.get("review_priority_score")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LinkageReviewError("candidate review_priority_score must be numeric")
    try:
        score = float(value)
    except (OverflowError, ValueError) as exc:
        raise LinkageReviewError(
            "candidate review_priority_score must be finite and within 0..100"
        ) from exc
    if not math.isfinite(score) or not 0 <= score <= 100:
        raise LinkageReviewError("candidate review_priority_score must be finite and within 0..100")
    return score


def _engine_result(entries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    result = rank_link_candidates(list(entries), limit=None)
    if not isinstance(result, dict):
        raise LinkageReviewError("rank_link_candidates returned a non-object")
    status = result.get("status")
    generation = result.get("candidate_generation")
    candidates = result.get("candidates")
    truncated = result.get("truncated_anchors")
    if status not in {"complete", "partial"}:
        raise LinkageReviewError("linkage result status is invalid")
    if not isinstance(generation, dict) or generation.get("status") != status:
        raise LinkageReviewError("linkage candidate-generation status is invalid")
    if not isinstance(candidates, list) or not isinstance(truncated, list):
        raise LinkageReviewError("linkage result collections are invalid")
    total = result.get("total_before_limit")
    if isinstance(total, bool) or not isinstance(total, int) or total != len(candidates):
        raise LinkageReviewError("review requires an untruncated linkage result")
    return result


def _aliases(sample_ids: Iterable[str]) -> dict[str, str]:
    return {
        sample_id: f"sample-{number:04d}"
        for number, sample_id in enumerate(sorted(set(sample_ids)), start=1)
    }


def _reason_category(value: object) -> str:
    reason = value if isinstance(value, str) else ""
    if reason.startswith("packer:"):
        return "packer"
    if reason in {
        "third-party-sdk",
        "shared_component",
        "renamed-shared-component",
        "debug-certificate",
        "remote-config-echo",
    }:
        return reason
    return "other"


def _omit_candidate(
    candidate: Mapping[str, object], aliases: Mapping[str, str]
) -> dict[str, Any]:
    left_id, right_id = _candidate_pair(candidate)
    supports = candidate.get("supporting_evidence")
    excluded = candidate.get("excluded_evidence")
    caps = candidate.get("score_caps")
    gaps = candidate.get("coverage_gaps")
    if not isinstance(supports, list):
        raise LinkageReviewError("candidate supporting_evidence must be a list")
    if not isinstance(excluded, list):
        raise LinkageReviewError("candidate excluded_evidence must be a list")
    if not isinstance(caps, list):
        raise LinkageReviewError("candidate score_caps must be a list")
    if not isinstance(gaps, list):
        raise LinkageReviewError("candidate coverage_gaps must be a list")

    safe_supports: list[dict[str, object]] = []
    for support in supports:
        if not isinstance(support, Mapping):
            raise LinkageReviewError("supporting evidence must be an object")
        safe_supports.append(
            {
                "family": support.get("family"),
                "strength": support.get("strength"),
                "weight": support.get("weight"),
                "match_count": support.get("match_count"),
                "values_omitted": True,
            }
        )

    safe_excluded: list[dict[str, object]] = []
    for item in excluded:
        if not isinstance(item, Mapping):
            raise LinkageReviewError("excluded evidence must be an object")
        safe_excluded.append(
            {
                "family": item.get("family"),
                "kind": item.get("kind"),
                "weight": item.get("weight"),
                "reason_category": _reason_category(item.get("reason")),
                "value_omitted": True,
            }
        )

    safe_caps: list[dict[str, object]] = []
    for cap in caps:
        if not isinstance(cap, Mapping):
            raise LinkageReviewError("score cap must be an object")
        safe_caps.append({"code": cap.get("code"), "cap": cap.get("cap")})

    safe_gaps: list[dict[str, object]] = []
    for gap in gaps:
        if not isinstance(gap, Mapping):
            raise LinkageReviewError("coverage gap must be an object")
        sample_id = gap.get("sample_sha256")
        if not isinstance(sample_id, str) or sample_id.lower() not in aliases:
            raise LinkageReviewError("coverage gap has an unknown sample identity")
        safe_gaps.append(
            {
                "sample_id": aliases[sample_id.lower()],
                "field": gap.get("field"),
                "status": gap.get("status"),
            }
        )

    return {
        "left": {"sample_id": aliases[left_id]},
        "right": {"sample_id": aliases[right_id]},
        "rank": candidate.get("rank"),
        "review_priority_score": candidate.get("review_priority_score"),
        "uncapped_score": candidate.get("uncapped_score"),
        "level": candidate.get("level"),
        "strong_family_count": candidate.get("strong_family_count"),
        "support_family_count": candidate.get("support_family_count"),
        "supporting_evidence": safe_supports,
        "score_caps": safe_caps,
        "excluded_evidence": safe_excluded,
        "coverage_gaps": safe_gaps,
    }


def _project_candidate(
    candidate: Mapping[str, object], mode: str, aliases: Mapping[str, str]
) -> dict[str, Any]:
    return deepcopy(dict(candidate)) if mode == "raw" else _omit_candidate(candidate, aliases)


def _truncated_anchors(result: Mapping[str, object], mode: str) -> list[dict[str, Any]]:
    value = result.get("truncated_anchors")
    if not isinstance(value, list):
        raise LinkageReviewError("truncated_anchors must be a list")
    if mode == "raw":
        return deepcopy(value)
    projected: list[dict[str, Any]] = []
    for anchor in value:
        if not isinstance(anchor, Mapping):
            raise LinkageReviewError("truncated anchor must be an object")
        projected.append(
            {
                "kind": anchor.get("kind"),
                "sample_count": anchor.get("sample_count"),
                "value_omitted": True,
            }
        )
    return projected


def _common_output(result: Mapping[str, object], *, kind: str, mode: str) -> dict[str, Any]:
    model = result.get("model")
    generation = result.get("candidate_generation")
    engine_input = result.get("input")
    migration = result.get("migration")
    if not isinstance(model, Mapping) or not isinstance(generation, Mapping):
        raise LinkageReviewError("linkage metadata is invalid")
    if not isinstance(engine_input, Mapping):
        raise LinkageReviewError("linkage input summary is invalid")
    if not isinstance(migration, Mapping):
        raise LinkageReviewError("linkage migration summary is invalid")

    if mode == "raw":
        safe_model = deepcopy(dict(model))
    else:
        safe_model = {
            key: model.get(key)
            for key in (
                "id",
                "kind",
                "score_semantics",
                "feature_schema_version",
                "normalization_version",
                "policy_status",
            )
        }
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "kind": kind,
        "status": result.get("status"),
        "evidence_values": mode,
        "model": safe_model,
        "input": {
            key: engine_input.get(key)
            for key in (
                "record_count",
                "sample_count",
                "invalid_sample_identity_record_count",
                "legacy_repack_identity_record_count",
                "anchor_cluster_limit",
            )
        },
        "candidate_generation": deepcopy(dict(generation)),
        "migration": deepcopy(dict(migration)),
        "truncated_anchors": _truncated_anchors(result, mode),
    }


def explain_link_candidate(
    entries: Iterable[dict[str, Any]],
    left_sha: str,
    right_sha: str,
    evidence_values: str = "omit",
) -> dict[str, Any]:
    """Explain one generated candidate pair without changing its score."""
    mode = _evidence_mode(evidence_values)
    left = _query_sha(left_sha, "left_sha")
    right = _query_sha(right_sha, "right_sha")
    if left == right:
        raise LinkageReviewError("left_sha and right_sha must be different")
    wanted = tuple(sorted((left, right)))
    result = _engine_result(entries)

    found: Mapping[str, object] | None = None
    for candidate in result["candidates"]:
        if not isinstance(candidate, Mapping):
            raise LinkageReviewError("candidate must be an object")
        if _candidate_pair(candidate) == wanted:
            found = candidate
            break

    aliases = _aliases(wanted)
    output = _common_output(
        result, kind="link_candidate_explanation", mode=mode
    )
    output["lookup_status"] = "found" if found is not None else "not_found"
    output["query"] = (
        {"left_sample_sha256": left, "right_sample_sha256": right}
        if mode == "raw"
        else {"left_sample_id": aliases[left], "right_sample_id": aliases[right]}
    )
    output["candidate"] = (
        _project_candidate(found, mode, aliases) if found is not None else None
    )
    output["disclaimer"] = (
        "仅解释规则引擎实际生成的技术关联候选；未生成不等于无关联，结果不代表同一运营主体。"
    )
    return output


def _minimum_score(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LinkageReviewError("min_score must be numeric")
    try:
        score = float(value)
    except (OverflowError, ValueError) as exc:
        raise LinkageReviewError("min_score must be finite and within 0..100") from exc
    if not math.isfinite(score) or not 0 <= score <= 100:
        raise LinkageReviewError("min_score must be finite and within 0..100")
    return score


def _components(
    edge_candidates: list[Mapping[str, object]],
) -> list[tuple[tuple[str, ...], list[Mapping[str, object]]]]:
    adjacency: dict[str, set[str]] = {}
    edge_by_pair: dict[tuple[str, str], Mapping[str, object]] = {}
    for candidate in edge_candidates:
        pair = _candidate_pair(candidate)
        if pair in edge_by_pair:
            raise LinkageReviewError("duplicate candidate edge")
        edge_by_pair[pair] = candidate
        adjacency.setdefault(pair[0], set()).add(pair[1])
        adjacency.setdefault(pair[1], set()).add(pair[0])

    remaining = set(adjacency)
    components: list[tuple[tuple[str, ...], list[Mapping[str, object]]]] = []
    for start in sorted(adjacency):
        if start not in remaining:
            continue
        pending = [start]
        members: set[str] = set()
        while pending:
            current = pending.pop()
            if current in members:
                continue
            members.add(current)
            pending.extend(sorted(adjacency[current] - members, reverse=True))
        remaining.difference_update(members)
        member_tuple = tuple(sorted(members))
        component_pairs = {
            (member, neighbor) if member < neighbor else (neighbor, member)
            for member in members
            for neighbor in adjacency[member]
        }
        edges = [edge_by_pair[pair] for pair in component_pairs]
        edges.sort(
            key=lambda candidate: (
                -_candidate_score(candidate),
                *_candidate_pair(candidate),
            )
        )
        components.append((member_tuple, edges))
    components.sort(
        key=lambda item: (
            -max(_candidate_score(edge) for edge in item[1]),
            -len(item[0]),
            item[0],
        )
    )
    return components


def _edge_summary(
    candidate: Mapping[str, object], mode: str, aliases: Mapping[str, str]
) -> dict[str, object]:
    left, right = _candidate_pair(candidate)
    endpoints = (
        {"left_sample_sha256": left, "right_sample_sha256": right}
        if mode == "raw"
        else {"left_sample_id": aliases[left], "right_sample_id": aliases[right]}
    )
    return {
        **endpoints,
        "rank": candidate.get("rank"),
        "review_priority_score": candidate.get("review_priority_score"),
    }


def _transitive_pair_preview(
    members: tuple[str, ...],
    direct_pairs: set[tuple[str, str]],
    total: int,
) -> list[tuple[str, str]]:
    """Return a stable bounded preview without materializing the component closure."""
    if total <= 0:
        return []
    target = min(total, _TRANSITIVE_PAIR_PREVIEW_LIMIT)
    preview: list[tuple[str, str]] = []
    for scanned, pair in enumerate(combinations(members, 2), start=1):
        if pair not in direct_pairs:
            preview.append(pair)
            if len(preview) >= target:
                break
        if scanned >= _TRANSITIVE_PAIR_SCAN_LIMIT:
            break
    return preview


def build_review_groups(
    entries: Iterable[dict[str, Any]],
    min_score: int | float = 50,
    evidence_values: str = "omit",
) -> dict[str, Any]:
    """Build connected review groups while preserving direct-edge semantics."""
    mode = _evidence_mode(evidence_values)
    threshold = _minimum_score(min_score)
    result = _engine_result(entries)
    selected: list[Mapping[str, object]] = []
    for candidate in result["candidates"]:
        if not isinstance(candidate, Mapping):
            raise LinkageReviewError("candidate must be an object")
        if _candidate_score(candidate) >= threshold:
            selected.append(candidate)

    components = _components(selected)
    all_members = sorted({sample for members, _edges in components for sample in members})
    aliases = _aliases(all_members)
    review_groups: list[dict[str, Any]] = []
    for number, (members, edges) in enumerate(components, start=1):
        direct_pairs = {_candidate_pair(edge) for edge in edges}
        transitive_pair_count = len(members) * (len(members) - 1) // 2 - len(
            direct_pairs
        )
        transitive_pairs = _transitive_pair_preview(
            members,
            direct_pairs,
            transitive_pair_count,
        )
        weakest = min(
            edges,
            key=lambda candidate: (
                _candidate_score(candidate),
                *_candidate_pair(candidate),
            ),
        )
        review_groups.append(
            {
                "review_group_id": f"review-group-{number:04d}",
                "members": (
                    list(members)
                    if mode == "raw"
                    else [aliases[sample] for sample in members]
                ),
                "edge_count": len(edges),
                "edges": [
                    _project_candidate(edge, mode, aliases) for edge in edges
                ],
                "weakest_edge": _edge_summary(weakest, mode, aliases),
                "transitive_only_pair_count": transitive_pair_count,
                "transitive_only_pairs_truncated": (
                    len(transitive_pairs) < transitive_pair_count
                ),
                "transitive_only_pairs": [
                    {
                        **(
                            {"left_sample_sha256": pair[0], "right_sample_sha256": pair[1]}
                            if mode == "raw"
                            else {
                                "left_sample_id": aliases[pair[0]],
                                "right_sample_id": aliases[pair[1]],
                            }
                        ),
                        "relation": "connected_without_direct_candidate_edge",
                    }
                    for pair in transitive_pairs
                ],
            }
        )

    output = _common_output(result, kind="linkage_review_groups", mode=mode)
    output.update(
        {
            "min_score": min_score,
            "review_group_count": len(review_groups),
            "edge_count": len(selected),
            "review_groups": review_groups,
            "disclaimer": (
                "review_groups 仅按真实候选边连通；传递相连不等于存在直接证据边，"
                "也不代表同一运营主体。"
            ),
        }
    )
    return output


__all__ = [
    "LinkageReviewError",
    "REVIEW_SCHEMA_VERSION",
    "build_review_groups",
    "explain_link_candidate",
]
