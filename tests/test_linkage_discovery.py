"""Label-guided anchor discovery remains aggregate and analyst-reviewed."""

from __future__ import annotations

import json

import pytest

from apkscan.core.linkage_discovery import discover_linkage_anchors
from apkscan.core.linkage_labels import validate_linkage_label_records


def _sha(char: str) -> str:
    return char * 64


def _entry(
    sample: str,
    *,
    native: str | None = None,
    build: str | None = None,
) -> dict:
    return {
        "sample_sha256": sample,
        "sample_sha256_synthetic": False,
        "tool_version": "1.0",
        "ruleset_digest": "rules",
        "evidence_surface": "static",
        "case_ids": [],
        "native_lib_hashes": ([{"name": "libfamilycore.so", "sha256": native}] if native else []),
        "build_environments": (
            [{"identifier": build, "root": "/workspace/project"}] if build else []
        ),
        "remote_config_objects": [],
        "key_iocs": [],
        "case_ioc_scope_indexed": True,
        "repack_identity_verdict": "unknown",
        "visibility": {},
    }


def _family(
    sample: str,
    *,
    status: str = "confirmed",
    basis: str = "build-root-review",
) -> dict:
    return {
        "kind": "family_membership",
        "schema_version": "1.0",
        "sample_sha256": sample,
        "family_id": "private-family",
        "relation_subtype": "packaging_pipeline",
        "status": status,
        "label_basis": [basis],
    }


def test_discovery_ranks_specific_anchors_and_marks_circular_label_basis() -> None:
    a, b, c, outside = (_sha(char) for char in "abcd")
    native = _sha("f")
    build = "private-build-root"
    entries = [
        _entry(a, native=native, build=build),
        _entry(b, native=native, build=build),
        _entry(c, build=build),
        _entry(outside, native=native),
    ]
    labels = validate_linkage_label_records([_family(a), _family(b), _family(c)])

    result = discover_linkage_anchors(entries, labels, evidence_values="raw")

    assert result["status"] == "complete"
    by_family = {row["anchor_family"]: row for row in result["candidates"]}
    assert by_family["native"] == {
        "group": "private-family",
        "relation_subtype": "packaging_pipeline",
        "anchor_family": "native",
        "within_group_sample_count": 2,
        "within_group_fraction": pytest.approx(2 / 3),
        "corpus_sample_count": 3,
        "outside_group_sample_count": 1,
        "group_specificity": pytest.approx(2 / 3),
        "label_basis_overlap": False,
        "independent_confirmation_required": True,
        "value": native,
        "discovery_rank": 1,
    }
    assert by_family["build"]["within_group_sample_count"] == 3
    assert by_family["build"]["label_basis_overlap"] is True
    assert result["warnings"]["label_basis_overlap_candidate_count"] == 1


def test_omit_mode_is_deterministic_and_contains_no_private_values() -> None:
    a, b = _sha("a"), _sha("b")
    native = _sha("f")
    entries = [_entry(a, native=native), _entry(b, native=native)]
    labels = validate_linkage_label_records([_family(a), _family(b)])

    forward = discover_linkage_anchors(entries, labels)
    backward = discover_linkage_anchors(list(reversed(entries)), labels)

    assert forward == backward
    assert forward["privacy"] == {
        "evidence_values": "omit",
        "contains_raw_identifiers": False,
        "contains_raw_evidence_values": False,
    }
    rendered = json.dumps(forward, sort_keys=True)
    for private_value in (a, b, native, "private-family"):
        assert private_value not in rendered
    assert forward["candidates"][0]["group"] == "group-0001"
    assert "value" not in forward["candidates"][0]


def test_unconfirmed_or_too_small_groups_are_insufficient() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records([_family(a), _family(b, status="proposed")])

    result = discover_linkage_anchors(
        [_entry(a, native=_sha("f")), _entry(b, native=_sha("f"))], labels
    )

    assert result["status"] == "insufficient_labels"
    assert result["candidate_anchor_count"] == 0


def test_rule_candidate_review_overlaps_every_discovery_feature() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [
            _family(a, basis="rule-candidate-review"),
            _family(b, basis="rule-candidate-review"),
        ]
    )
    result = discover_linkage_anchors(
        [
            _entry(a, native=_sha("f"), build="build-family"),
            _entry(b, native=_sha("f"), build="build-family"),
        ],
        labels,
    )

    assert result["candidate_anchor_count"] == 2
    assert all(row["label_basis_overlap"] for row in result["candidates"])


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"min_member_count": 1}, "min_member_count"),
        ({"min_member_fraction": 0.0}, "min_member_fraction"),
        ({"min_member_fraction": 10**400}, "min_member_fraction"),
        ({"evidence_values": "masked"}, "evidence_values"),
        ({"limit": 0}, "limit"),
    ],
)
def test_discovery_rejects_ambiguous_options(kwargs: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        discover_linkage_anchors([], validate_linkage_label_records([]), **kwargs)
