"""Label-guided discovery of technical anchors for analyst review.

This module mines only already-extracted, versioned corpus features. It does
not promote an anchor to a rule, infer an operator, or write to the corpus.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
import math
from typing import Any

from apkscan.core.linkage import SampleFeatures, collapse_manifest_entries
from apkscan.core.linkage_labels import (
    FamilyMembership,
    LinkageLabelSet,
    build_linkage_ground_truth,
    label_basis_feature_families,
)


DISCOVERY_SCHEMA_VERSION = "1.0"
_VALUE_MODES = frozenset({"raw", "omit"})
_ANCHOR_ORDER = {
    "remote_config_content": 0,
    "remote_config_url": 1,
    "native": 2,
    "signing": 3,
    "build": 4,
    "ioc_url": 5,
    "ioc_domain": 6,
    "ioc_public_ip": 7,
    "ioc_other": 8,
}


def _sample_anchors(sample: SampleFeatures) -> tuple[tuple[str, str], ...]:
    anchors = [
        *(("remote_config_content", value) for value in sample.config_sha256),
        *(("remote_config_url", value) for value in sample.config_urls),
        *(("native", value) for value in sample.native_sha256),
        *(("signing", value) for value in sample.sign_sha256),
        *(("build", value) for value in sample.build_environments),
        *((f"ioc_{kind}", value) for kind, value in sample.key_iocs),
    ]
    return tuple(sorted(anchors, key=lambda item: (_ANCHOR_ORDER[item[0]], item[1])))


def _basis_overlaps(anchor_family: str, basis_codes: set[str]) -> bool:
    feature_family = {
        "remote_config_content": "remote_config",
        "remote_config_url": "remote_config",
        "native": "native",
        "signing": "signing",
        "build": "build",
    }.get(anchor_family, "ioc")
    return feature_family in label_basis_feature_families(basis_codes)


def discover_linkage_anchors(
    entries: Iterable[dict[str, Any]],
    labels: LinkageLabelSet,
    *,
    min_member_count: int = 2,
    min_member_fraction: float = 0.25,
    evidence_values: str = "omit",
    limit: int = 200,
) -> dict[str, object]:
    """Find within-group recurring anchors and report cross-corpus prevalence."""
    if not isinstance(labels, LinkageLabelSet):
        raise TypeError("labels must be a LinkageLabelSet")
    if isinstance(min_member_count, bool) or not isinstance(min_member_count, int):
        raise ValueError("min_member_count must be an integer")
    if min_member_count < 2:
        raise ValueError("min_member_count must be at least 2")
    if isinstance(min_member_fraction, bool) or not isinstance(
        min_member_fraction, (int, float)
    ):
        raise ValueError("min_member_fraction must be in (0, 1]")
    try:
        normalized_fraction = float(min_member_fraction)
    except (OverflowError, ValueError) as exc:
        raise ValueError("min_member_fraction must be in (0, 1]") from exc
    if not math.isfinite(normalized_fraction) or not 0.0 < normalized_fraction <= 1.0:
        raise ValueError("min_member_fraction must be in (0, 1]")
    if evidence_values not in _VALUE_MODES:
        raise ValueError("evidence_values must be raw or omit")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be at least 1")

    entry_list = list(entries)
    samples = tuple(
        sample for sample in collapse_manifest_entries(entry_list) if not sample.synthetic_identity
    )
    by_sample = {sample.sample_sha256: sample for sample in samples}
    global_index: dict[tuple[str, str], set[str]] = defaultdict(set)
    for sample in samples:
        for anchor in _sample_anchors(sample):
            global_index[anchor].add(sample.sample_sha256)

    truth = build_linkage_ground_truth(labels)
    groups = sorted(
        truth.family_groups,
        key=lambda group: (group.relation_subtype, group.family_id, group.members),
    )
    group_refs = {
        (group.relation_subtype, group.family_id): f"group-{index:04d}"
        for index, group in enumerate(groups, start=1)
    }
    basis_by_group: dict[tuple[str, str], set[str]] = defaultdict(set)
    for record in labels.effective_records:
        if isinstance(record, FamilyMembership) and record.status == "confirmed":
            basis_by_group[(record.relation_subtype, record.family_id)].update(record.label_basis)

    group_summaries: list[dict[str, object]] = []
    candidates: list[dict[str, object]] = []
    evaluable_groups = 0
    for group in groups:
        key = (group.relation_subtype, group.family_id)
        group_ref = group_refs[key]
        members = sorted(set(group.members) & set(by_sample))
        if len(members) >= min_member_count:
            evaluable_groups += 1
        counts: dict[tuple[str, str], int] = defaultdict(int)
        for sample_id in members:
            for anchor in _sample_anchors(by_sample[sample_id]):
                counts[anchor] += 1
        group_candidate_count = 0
        for (anchor_family, value), member_count in sorted(
            counts.items(),
            key=lambda item: (
                -item[1],
                _ANCHOR_ORDER[item[0][0]],
                item[0][1],
            ),
        ):
            fraction = member_count / len(members) if members else 0.0
            if member_count < min_member_count or fraction < normalized_fraction:
                continue
            global_samples = global_index[(anchor_family, value)]
            outside_count = len(global_samples - set(members))
            overlap = _basis_overlaps(anchor_family, basis_by_group[key])
            row: dict[str, object] = {
                "group": group_ref if evidence_values == "omit" else group.family_id,
                "relation_subtype": group.relation_subtype,
                "anchor_family": anchor_family,
                "within_group_sample_count": member_count,
                "within_group_fraction": fraction,
                "corpus_sample_count": len(global_samples),
                "outside_group_sample_count": outside_count,
                "group_specificity": member_count / len(global_samples),
                "label_basis_overlap": overlap,
                "independent_confirmation_required": True,
            }
            if evidence_values == "raw":
                row["value"] = value
            candidates.append(row)
            group_candidate_count += 1
        group_summaries.append(
            {
                "group": group_ref if evidence_values == "omit" else group.family_id,
                "relation_subtype": group.relation_subtype,
                "labeled_member_count": len(group.members),
                "members_present_in_corpus": len(members),
                "candidate_anchor_count": group_candidate_count,
            }
        )

    def candidate_sort_key(row: dict[str, object]) -> tuple[object, ...]:
        specificity = row["group_specificity"]
        fraction = row["within_group_fraction"]
        count = row["within_group_sample_count"]
        if not isinstance(specificity, float) or not isinstance(fraction, float):
            raise RuntimeError("internal discovery ratio is not numeric")
        if isinstance(count, bool) or not isinstance(count, int):
            raise RuntimeError("internal discovery count is not an integer")
        return (
            bool(row["label_basis_overlap"]),
            -specificity,
            -fraction,
            -count,
            str(row["relation_subtype"]),
            _ANCHOR_ORDER[str(row["anchor_family"])],
            str(row.get("value") or row["group"]),
        )

    candidates.sort(key=candidate_sort_key)
    for rank, candidate in enumerate(candidates, start=1):
        candidate["discovery_rank"] = rank

    status = "complete" if evaluable_groups else "insufficient_labels"
    return {
        "schema_version": DISCOVERY_SCHEMA_VERSION,
        "status": status,
        "experimental": True,
        "input": {
            "record_count": len(entry_list),
            "real_sample_count": len(samples),
            "confirmed_family_group_count": len(groups),
            "evaluable_family_group_count": evaluable_groups,
            "min_member_count": min_member_count,
            "min_member_fraction": normalized_fraction,
        },
        "groups": group_summaries,
        "candidate_anchor_count": len(candidates),
        "returned_candidate_anchor_count": min(len(candidates), limit),
        "candidates": candidates[:limit],
        "warnings": {
            "label_basis_overlap_candidate_count": sum(
                bool(candidate["label_basis_overlap"]) for candidate in candidates
            ),
            "meaning": ("候选锚只用于人工复核；与标签依据重合的锚不能作为独立效果证据"),
        },
        "privacy": {
            "evidence_values": evidence_values,
            "contains_raw_identifiers": evidence_values == "raw",
            "contains_raw_evidence_values": evidence_values == "raw",
        },
        "disclaimer": "重复技术锚不等于同一运营主体，也不会自动写入规则或 corpus。",
    }


__all__ = ["DISCOVERY_SCHEMA_VERSION", "discover_linkage_anchors"]
