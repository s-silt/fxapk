"""Pure explanations and explicitly edge-based linkage review groups."""

from __future__ import annotations

import json
from time import perf_counter

import pytest

from apkscan.core import linkage_review
from apkscan.core.linkage_review import (
    LinkageReviewError,
    build_review_groups,
    explain_link_candidate,
)


_SAMPLE_A = "1" * 64
_SAMPLE_B = "2" * 64
_SAMPLE_C = "3" * 64
_NATIVE_AB = "a" * 64
_NATIVE_BC = "b" * 64
_SIGN = "c" * 64


def _entry(
    sample: str,
    *,
    native: tuple[str, ...] = (),
    sign: str | None = None,
    cases: tuple[str, ...] = (),
) -> dict:
    return {
        "sample_sha256": sample,
        "sample_sha256_synthetic": False,
        "tool_version": "1.0.0",
        "ruleset_digest": "d" * 16,
        "evidence_surface": "static",
        "case_ids": list(cases),
        "record_state": "active",
        "sign_sha256": sign,
        "native_lib_hashes": [
            {"name": f"libbusiness-{index}.so", "sha256": sha, "size": 123}
            for index, sha in enumerate(native)
        ],
        "build_environments": [],
        "remote_config_objects": [],
        "key_iocs": [],
        "finding_ids": [],
        "case_ioc_scope_indexed": True,
        "repack_identity_verdict": "unknown",
        "visibility": {},
    }


def test_explain_raw_preserves_evidence_and_omit_removes_identifiers() -> None:
    case = "case-canary-secret"
    entries = [
        _entry(_SAMPLE_A, native=(_NATIVE_AB,), cases=(case,)),
        _entry(_SAMPLE_B, native=(_NATIVE_AB,), cases=(case,)),
    ]

    raw = explain_link_candidate(entries, _SAMPLE_B.upper(), _SAMPLE_A, "raw")
    assert raw["lookup_status"] == "found"
    assert raw["candidate"]["supporting_evidence"][0]["matches"][0]["value"] == _NATIVE_AB
    assert raw["candidate"]["candidate_id"].startswith("pair-")

    omitted = explain_link_candidate(entries, _SAMPLE_B, _SAMPLE_A, "omit")
    blob = json.dumps(omitted, ensure_ascii=False)
    assert omitted["query"] == {
        "left_sample_id": "sample-0002",
        "right_sample_id": "sample-0001",
    }
    assert omitted["candidate"]["left"] == {"sample_id": "sample-0001"}
    assert omitted["candidate"]["right"] == {"sample_id": "sample-0002"}
    assert omitted["candidate"]["supporting_evidence"][0]["values_omitted"] is True
    for secret in (_SAMPLE_A, _SAMPLE_B, _NATIVE_AB, case):
        assert secret not in blob
    assert "candidate_id" not in blob
    assert "policy_digest" not in blob


def test_public_api_defaults_to_omit_raw_identifiers() -> None:
    case = "case-default-canary"
    entries = [
        _entry(_SAMPLE_A, native=(_NATIVE_AB,), cases=(case,)),
        _entry(_SAMPLE_B, native=(_NATIVE_AB,), cases=(case,)),
    ]

    explanation = explain_link_candidate(entries, _SAMPLE_A, _SAMPLE_B)
    groups = build_review_groups(entries)

    assert explanation["evidence_values"] == "omit"
    assert groups["evidence_values"] == "omit"
    for output in (explanation, groups):
        blob = json.dumps(output, ensure_ascii=False)
        for secret in (_SAMPLE_A, _SAMPLE_B, _NATIVE_AB, case):
            assert secret not in blob


def test_review_layer_always_requests_the_complete_ranked_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = linkage_review.rank_link_candidates
    observed_limits: list[int | None] = []

    def spy(entries: object, *, limit: int | None = 20) -> dict:
        observed_limits.append(limit)
        return original(entries, limit=limit)  # type: ignore[arg-type]

    monkeypatch.setattr(linkage_review, "rank_link_candidates", spy)
    explain_link_candidate(
        [
            _entry(_SAMPLE_A, native=(_NATIVE_AB,)),
            _entry(_SAMPLE_B, native=(_NATIVE_AB,)),
        ],
        _SAMPLE_A,
        _SAMPLE_B,
    )

    assert observed_limits == [None]


def test_chain_lists_transitive_pair_without_inventing_an_edge() -> None:
    entries = [
        _entry(_SAMPLE_A, native=(_NATIVE_AB,)),
        _entry(_SAMPLE_B, native=(_NATIVE_AB, _NATIVE_BC)),
        _entry(_SAMPLE_C, native=(_NATIVE_BC,)),
    ]

    result = build_review_groups(entries, min_score=50, evidence_values="raw")

    assert result["review_group_count"] == 1
    group = result["review_groups"][0]
    edge_pairs = {
        tuple(sorted((edge["left"]["sample_sha256"], edge["right"]["sample_sha256"])))
        for edge in group["edges"]
    }
    assert edge_pairs == {(_SAMPLE_A, _SAMPLE_B), (_SAMPLE_B, _SAMPLE_C)}
    assert group["transitive_only_pair_count"] == 1
    assert group["transitive_only_pairs_truncated"] is False
    assert group["transitive_only_pairs"] == [
        {
            "left_sample_sha256": _SAMPLE_A,
            "right_sample_sha256": _SAMPLE_C,
            "relation": "connected_without_direct_candidate_edge",
        }
    ]
    assert (_SAMPLE_A, _SAMPLE_C) not in edge_pairs


def test_omit_groups_are_stable_and_have_no_raw_values() -> None:
    entries = [
        _entry(_SAMPLE_A, native=(_NATIVE_AB,), cases=("case-alpha",)),
        _entry(_SAMPLE_B, native=(_NATIVE_AB, _NATIVE_BC), cases=("case-beta",)),
        _entry(_SAMPLE_C, native=(_NATIVE_BC,), cases=("case-gamma",)),
    ]

    forward = build_review_groups(entries, evidence_values="omit")
    backward = build_review_groups(list(reversed(entries)), evidence_values="omit")

    assert forward == backward
    group = forward["review_groups"][0]
    assert group["members"] == ["sample-0001", "sample-0002", "sample-0003"]
    assert group["transitive_only_pair_count"] == 1
    assert group["transitive_only_pairs_truncated"] is False
    assert group["transitive_only_pairs"] == [
        {
            "left_sample_id": "sample-0001",
            "right_sample_id": "sample-0003",
            "relation": "connected_without_direct_candidate_edge",
        }
    ]
    blob = json.dumps(forward, ensure_ascii=False)
    for secret in (
        _SAMPLE_A,
        _SAMPLE_B,
        _SAMPLE_C,
        _NATIVE_AB,
        _NATIVE_BC,
        "case-alpha",
        "case-beta",
        "case-gamma",
    ):
        assert secret not in blob
    assert "candidate_id" not in blob


def test_transitive_pair_preview_is_bounded_for_a_ten_thousand_member_chain() -> None:
    members = tuple(f"{index:064x}" for index in range(10_000))
    direct_pairs = set(zip(members, members[1:]))
    total = len(members) * (len(members) - 1) // 2 - len(direct_pairs)

    preview = linkage_review._transitive_pair_preview(members, direct_pairs, total)

    assert total == 49_985_001
    assert len(preview) == linkage_review._TRANSITIVE_PAIR_PREVIEW_LIMIT
    assert preview[0] == (members[0], members[2])


def test_component_partition_is_linear_for_many_disjoint_edges() -> None:
    edges = [
        {
            "left": {"sample_sha256": f"{index * 2 + 1:064x}"},
            "right": {"sample_sha256": f"{index * 2 + 2:064x}"},
            "review_priority_score": 50,
        }
        for index in range(5_000)
    ]

    started = perf_counter()
    components = linkage_review._components(edges)
    elapsed = perf_counter() - started

    assert len(components) == 5_000
    assert all(len(members) == 2 and len(component_edges) == 1 for members, component_edges in components)
    assert elapsed < 1.5


def test_omit_review_preserves_renamed_component_reason_category() -> None:
    entries = [
        _entry(_SAMPLE_A, native=(_NATIVE_AB,), sign=_SIGN),
        _entry(_SAMPLE_B, native=(_NATIVE_AB,), sign=_SIGN),
        _entry(_SAMPLE_C, native=(_NATIVE_AB,)),
    ]
    for entry, name in zip(entries, ("libalpha.so", "libbravo.so", "libcharlie.so")):
        entry["native_lib_hashes"][0]["name"] = name

    group = build_review_groups(entries, min_score=45, evidence_values="omit")[
        "review_groups"
    ][0]

    assert group["edges"][0]["excluded_evidence"] == [
        {
            "family": "native",
            "kind": "sha256",
            "weight": 0,
            "reason_category": "renamed-shared-component",
            "value_omitted": True,
        }
    ]


def test_threshold_filters_edges_without_changing_engine_scores() -> None:
    entries = [
        _entry(_SAMPLE_A, native=(_NATIVE_AB,)),
        _entry(_SAMPLE_B, native=(_NATIVE_AB,)),
    ]

    included = build_review_groups(entries, min_score=50)
    excluded = build_review_groups(entries, min_score=51)

    assert included["edge_count"] == 1
    assert included["review_groups"][0]["edges"][0]["review_priority_score"] == 50
    assert excluded["edge_count"] == 0
    assert excluded["review_groups"] == []


def test_partial_generation_and_overbroad_anchor_are_propagated_safely() -> None:
    entries = [_entry(f"{number:064x}", sign=_SIGN) for number in range(1, 52)]

    raw = build_review_groups(entries, evidence_values="raw")
    omitted = build_review_groups(entries, evidence_values="omit")
    explanation = explain_link_candidate(
        entries, f"{1:064x}", f"{2:064x}", evidence_values="omit"
    )

    assert raw["status"] == raw["candidate_generation"]["status"] == "partial"
    assert raw["truncated_anchors"][0]["value"] == _SIGN
    assert omitted["status"] == omitted["candidate_generation"]["status"] == "partial"
    assert omitted["truncated_anchors"] == [
        {"kind": "sign_sha256", "sample_count": 51, "value_omitted": True}
    ]
    assert _SIGN not in json.dumps(omitted)
    assert explanation["status"] == "partial"
    assert explanation["lookup_status"] == "not_found"


@pytest.mark.parametrize("mode", ["", "redacted", "RAW"])
def test_invalid_evidence_mode_is_rejected(mode: str) -> None:
    with pytest.raises(LinkageReviewError, match="evidence_values"):
        build_review_groups([], evidence_values=mode)


@pytest.mark.parametrize("score", [-1, 101, float("nan"), True, "50"])
def test_invalid_min_score_is_rejected(score: object) -> None:
    with pytest.raises(LinkageReviewError, match="min_score"):
        build_review_groups([], min_score=score)  # type: ignore[arg-type]


def test_extreme_integer_min_score_is_a_review_contract_error() -> None:
    with pytest.raises(LinkageReviewError, match="min_score"):
        build_review_groups([], min_score=10**400)


def test_extreme_integer_candidate_score_is_a_review_contract_error(monkeypatch) -> None:
    entries = [
        _entry(_SAMPLE_A, native=(_NATIVE_AB,)),
        _entry(_SAMPLE_B, native=(_NATIVE_AB,)),
    ]
    original = linkage_review.rank_link_candidates

    def _overflowing(rows, *, limit=None):  # noqa: ANN001
        result = original(rows, limit=limit)
        result["candidates"][0]["review_priority_score"] = 10**400
        return result

    monkeypatch.setattr(linkage_review, "rank_link_candidates", _overflowing)

    with pytest.raises(LinkageReviewError, match="review_priority_score"):
        build_review_groups(entries)


def test_explain_rejects_bad_or_identical_query_sha() -> None:
    with pytest.raises(LinkageReviewError, match="left_sha"):
        explain_link_candidate([], "bad", _SAMPLE_B)
    with pytest.raises(LinkageReviewError, match="different"):
        explain_link_candidate([], _SAMPLE_A, _SAMPLE_A)
