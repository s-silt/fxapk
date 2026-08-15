"""Strict private-label contracts and aggregate-only linkage evaluation."""

from __future__ import annotations

import inspect
import json
import math
from pathlib import Path

import pytest

from apkscan.core import linkage, linkage_evaluation
from apkscan.core.linkage_evaluation import evaluate_linkage_rules
from apkscan.core.linkage_labels import (
    LabelValidationError,
    build_linkage_ground_truth,
    load_linkage_labels,
    validate_linkage_label_records,
)


def _sha(char: str) -> str:
    return char * 64


def _entry(
    sample: str,
    *,
    native_sha: str | None = None,
    build_id: str | None = None,
    case_id: str = "",
) -> dict:
    native = []
    if native_sha is not None:
        native = [{"name": "libfamilycore.so", "sha256": native_sha}]
    return {
        "sample_sha256": sample,
        "sample_sha256_synthetic": False,
        "tool_version": "1.0",
        "ruleset_digest": "rules-v1",
        "evidence_surface": "static",
        "case_ids": [case_id] if case_id else [],
        "native_lib_hashes": native,
        "build_environments": ([{"identifier": build_id}] if build_id else []),
        "remote_config_objects": [],
        "key_iocs": [],
        "case_ioc_scope_indexed": True,
        "repack_identity_verdict": "unknown",
        "visibility": {},
    }


def _family(
    sample: str,
    family_id: str = "family-1",
    *,
    subtype: str = "binary_lineage",
    status: str = "confirmed",
    basis: str = "independent-review",
    **extra: object,
) -> dict:
    return {
        "kind": "family_membership",
        "schema_version": "1.0",
        "sample_sha256": sample,
        "family_id": family_id,
        "relation_subtype": subtype,
        "status": status,
        "label_basis": [basis],
        "reason_codes": ["manual-diff"],
        "evidence_ref": "fixture-evidence-bundle-001",
        **extra,
    }


def _pair(
    left: str,
    right: str,
    relation: str,
    *,
    subtype: str = "technical_link_relevant",
    status: str = "confirmed",
    sampling_class: str = "unspecified",
    **extra: object,
) -> dict:
    return {
        "kind": "pair_judgment",
        "schema_version": "1.0",
        "left_sha256": left,
        "right_sha256": right,
        "relation": relation,
        "relation_subtype": subtype,
        "status": status,
        "reason_codes": ["manual-diff"],
        "sampling_class": sampling_class,
        "label_basis": ["independent-review"],
        "evidence_ref": "fixture-evidence-bundle-001",
        **extra,
    }


def _walk_numbers(value: object) -> list[float]:
    found: list[float] = []
    if isinstance(value, dict):
        for item in value.values():
            found.extend(_walk_numbers(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_walk_numbers(item))
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        found.append(float(value))
    return found


def test_minimal_document_examples_validate_and_unknown_is_not_negative() -> None:
    a, b, c = _sha("a"), _sha("b"), _sha("c")
    labels = validate_linkage_label_records(
        [
            _family(a),
            _family(b),
            _pair(a, c, "negative", sampling_class="hard"),
            _pair(b, c, "unknown"),
        ]
    )
    truth = build_linkage_ground_truth(labels)

    assert truth.positive_pairs == {(a, b)}
    assert truth.negative_pairs == {(a, c)}
    assert truth.unknown_pairs == {(b, c)}
    assert truth.hard_negative_pairs == {(a, c)}


def test_same_sample_may_have_memberships_in_different_subtypes() -> None:
    sample = _sha("a")
    labels = validate_linkage_label_records(
        [
            _family(sample, "family-code", subtype="binary_lineage"),
            _family(sample, "family-control", subtype="control_plane"),
        ]
    )
    assert len(labels.effective_records) == 2


@pytest.mark.parametrize(
    "records",
    [
        [_family(_sha("a")), _family(_sha("a"))],
        [_family(_sha("a"), "family-1"), _family(_sha("a"), "family-2")],
        [_pair(_sha("a"), _sha("b"), "positive"), _pair(_sha("b"), _sha("a"), "positive")],
    ],
)
def test_duplicate_or_conflicting_natural_keys_fail_closed(records: list[dict]) -> None:
    with pytest.raises(LabelValidationError, match="line 2"):
        validate_linkage_label_records(records)


def test_explicit_supersession_replaces_the_same_natural_key() -> None:
    sample = _sha("a")
    labels = validate_linkage_label_records(
        [
            _family(sample, "family-old", record_id="record-old"),
            _family(
                sample,
                "family-new",
                record_id="record-new",
                supersedes="record-old",
            ),
        ]
    )
    assert len(labels.records) == 2
    assert len(labels.effective_records) == 1
    assert labels.effective_records[0].record_id == "record-new"


def test_confirmed_replacement_becomes_authoritative() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [
            _pair(a, b, "positive", record_id="old"),
            _pair(a, b, "negative", record_id="new", supersedes="old"),
        ]
    )
    truth = build_linkage_ground_truth(labels)

    assert [record.record_id for record in labels.effective_records] == ["new"]
    assert truth.positive_pairs == set()
    assert truth.negative_pairs == {(a, b)}


def test_rejected_direct_replacement_tombstones_confirmed_truth() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [
            _pair(a, b, "positive", record_id="old"),
            _pair(
                a,
                b,
                "positive",
                status="rejected",
                record_id="tombstone",
                supersedes="old",
            ),
        ]
    )
    truth = build_linkage_ground_truth(labels)

    assert labels.effective_records == ()
    assert truth.positive_pairs == set()
    assert truth.negative_pairs == set()


def test_proposed_replacement_keeps_confirmed_truth_authoritative() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [
            _pair(a, b, "positive", record_id="old"),
            _pair(
                a,
                b,
                "negative",
                status="proposed",
                record_id="proposal",
                supersedes="old",
            ),
        ]
    )
    truth = build_linkage_ground_truth(labels)

    assert [record.record_id for record in labels.effective_records] == ["old"]
    assert truth.positive_pairs == {(a, b)}
    assert truth.negative_pairs == set()


def test_confirmed_successor_to_proposal_becomes_authoritative() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [
            _pair(a, b, "positive", record_id="old"),
            _pair(
                a,
                b,
                "negative",
                status="proposed",
                record_id="proposal",
                supersedes="old",
            ),
            _pair(
                a,
                b,
                "negative",
                record_id="accepted-proposal",
                supersedes="proposal",
            ),
        ]
    )
    truth = build_linkage_ground_truth(labels)

    assert [record.record_id for record in labels.effective_records] == ["accepted-proposal"]
    assert truth.positive_pairs == set()
    assert truth.negative_pairs == {(a, b)}


def test_rejected_successor_to_proposal_falls_back_to_confirmed_truth() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [
            _pair(a, b, "positive", record_id="old"),
            _pair(
                a,
                b,
                "negative",
                status="proposed",
                record_id="proposal",
                supersedes="old",
            ),
            _pair(
                a,
                b,
                "negative",
                status="rejected",
                record_id="rejected-proposal",
                supersedes="proposal",
            ),
        ]
    )
    truth = build_linkage_ground_truth(labels)

    assert [record.record_id for record in labels.effective_records] == ["old"]
    assert truth.positive_pairs == {(a, b)}
    assert truth.negative_pairs == set()


@pytest.mark.parametrize("status", ["proposed", "rejected"])
def test_standalone_nonconfirmed_record_has_no_authoritative_truth(status: str) -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [_pair(a, b, "positive", status=status, record_id="workflow-only")]
    )
    truth = build_linkage_ground_truth(labels)

    assert labels.effective_records == ()
    assert truth.positive_pairs == set()
    assert truth.negative_pairs == set()


def test_inactive_workflow_states_do_not_enter_ground_truth() -> None:
    a, b, c, d = _sha("a"), _sha("b"), _sha("c"), _sha("d")
    labels = validate_linkage_label_records(
        [
            _pair(a, b, "positive", status="proposed"),
            _pair(a, c, "negative", status="rejected"),
            _pair(
                a,
                d,
                "positive",
                status="superseded",
                record_id="old-label",
            ),
            _pair(
                a,
                d,
                "unknown",
                status="rejected",
                record_id="replacement-label",
                supersedes="old-label",
            ),
        ]
    )
    truth = build_linkage_ground_truth(labels)
    assert not truth.positive_pairs
    assert not truth.negative_pairs
    assert not truth.unknown_pairs
    assert dict(labels.status_counts) == {
        "confirmed": 0,
        "proposed": 1,
        "rejected": 2,
        "superseded": 1,
    }


def test_supersession_must_target_existing_same_subject_without_cycles() -> None:
    sample = _sha("a")
    with pytest.raises(LabelValidationError, match="target does not exist"):
        validate_linkage_label_records([_family(sample, record_id="new", supersedes="missing")])
    with pytest.raises(LabelValidationError, match="different natural key"):
        validate_linkage_label_records(
            [
                _family(sample, record_id="old"),
                _family(_sha("b"), record_id="new", supersedes="old"),
            ]
        )


def test_supersession_requires_append_only_unbranched_identified_chain() -> None:
    sample = _sha("a")
    old = _family(sample, record_id="old")

    with pytest.raises(LabelValidationError, match="new identifier"):
        validate_linkage_label_records([old, _family(sample, supersedes="old")])

    with pytest.raises(LabelValidationError, match="must precede"):
        validate_linkage_label_records(
            [
                _family(sample, record_id="new", supersedes="old"),
                old,
            ]
        )

    with pytest.raises(LabelValidationError, match="already has a replacement"):
        validate_linkage_label_records(
            [
                old,
                _family(sample, record_id="new-1", supersedes="old"),
                _family(sample, record_id="new-2", supersedes="old"),
            ]
        )

    with pytest.raises(LabelValidationError, match="has no replacement"):
        validate_linkage_label_records([_family(sample, status="superseded", record_id="orphan")])


@pytest.mark.parametrize("basis", [None, [], ["invented-basis"]])
def test_label_basis_is_required_and_controlled(basis: object) -> None:
    row = _family(_sha("a"))
    if basis is None:
        row.pop("label_basis")
    else:
        row["label_basis"] = basis
    with pytest.raises(LabelValidationError, match="label_basis"):
        validate_linkage_label_records([row])


def test_active_independent_review_requires_evidence_ref_and_reason_codes() -> None:
    family = _family(_sha("a"))
    family.pop("evidence_ref")
    with pytest.raises(LabelValidationError, match="evidence_ref"):
        validate_linkage_label_records([family])

    family = _family(_sha("a"))
    family["reason_codes"] = []
    with pytest.raises(LabelValidationError, match="reason_codes"):
        validate_linkage_label_records([family])

    pair = _pair(_sha("a"), _sha("b"), "positive")
    pair.pop("evidence_ref")
    with pytest.raises(LabelValidationError, match="evidence_ref"):
        validate_linkage_label_records([pair])


@pytest.mark.parametrize(
    "bogus",
    ["", "   ", "N/A", "TODO", "short", "xxxxxxxxxx", "aaaaaaaa", "........", "TODO-....", 42],
)
def test_evidence_ref_rejects_blank_and_placeholder_tokens(bogus: object) -> None:
    row = _pair(_sha("a"), _sha("b"), "positive")
    row["evidence_ref"] = bogus
    with pytest.raises(LabelValidationError, match="evidence_ref"):
        validate_linkage_label_records([row])


def test_evidence_ref_is_optional_for_non_independent_bases() -> None:
    row = _family(_sha("a"), basis="build-root-review")
    row.pop("evidence_ref")
    row.pop("reason_codes")
    labels = validate_linkage_label_records([row])
    assert labels.record_count == 1
    assert labels.records[0].evidence_ref is None


def test_supersede_chain_repairs_legacy_independent_record_without_evidence() -> None:
    """补发路径（真实迁移场景）：缺 evidence_ref 的历史 independent-review 记录

    单独存在时必须被拒；追加带证据指针的 supersede 替代后，整个文件重新可加载，
    历史行保持原样（append-only），义务由活跃的替代记录满足。
    """
    a, b = _sha("a"), _sha("b")
    legacy = _pair(a, b, "negative", sampling_class="hard", record_id="legacy")
    legacy.pop("evidence_ref")

    with pytest.raises(LabelValidationError, match="evidence_ref"):
        validate_linkage_label_records([legacy])

    replacement = _pair(
        a,
        b,
        "negative",
        sampling_class="hard",
        record_id="legacy-r2",
        supersedes="legacy",
        label_lineage="queue-internal",
    )
    labels = validate_linkage_label_records([legacy, replacement])
    assert [record.record_id for record in labels.effective_records] == ["legacy-r2"]
    assert labels.effective_records[0].evidence_ref == "fixture-evidence-bundle-001"
    assert labels.effective_records[0].label_lineage == "queue-internal"


def test_label_lineage_vocabulary_is_controlled() -> None:
    default = validate_linkage_label_records([_family(_sha("a"))]).records[0]
    assert default.label_lineage == "unspecified"

    for lineage in ("queue-internal", "queue-external"):
        row = _family(_sha("a"), label_lineage=lineage)
        assert validate_linkage_label_records([row]).records[0].label_lineage == lineage

    with pytest.raises(LabelValidationError, match="label_lineage"):
        validate_linkage_label_records([_family(_sha("a"), label_lineage="pipeline")])
    with pytest.raises(LabelValidationError, match="label_lineage"):
        validate_linkage_label_records([_family(_sha("a"), label_lineage=3)])


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda row: row.update(schema_version="2.0"), "unsupported schema"),
        (lambda row: row.update(sample_sha256="not-a-sha"), "real 64-hex SHA-256"),
        (lambda row: row.update(extra_private_value="x"), "unknown field"),
        (lambda row: row.update(confidence=float("nan")), "non-finite"),
        (lambda row: row.update(confidence=float("inf")), "non-finite"),
        (lambda row: row.update(confidence=10**400), "finite and between"),
    ],
)
def test_schema_sha_unknown_fields_and_nonfinite_values_fail_closed(mutate, message: str) -> None:
    row = _family(_sha("a"))
    mutate(row)
    with pytest.raises(LabelValidationError, match=message):
        validate_linkage_label_records([row])


@pytest.mark.parametrize("unknown_value", [float("nan"), float("inf"), float("-inf")])
def test_unknown_field_and_nonfinite_value_are_not_exposed_by_direct_api(
    unknown_value: float,
) -> None:
    private_field = "case-2026-private-field"
    row = _family(_sha("a")) | {private_field: unknown_value}

    with pytest.raises(LabelValidationError, match="contains unknown field") as error:
        validate_linkage_label_records([row])

    rendered = str(error.value).lower()
    assert private_field not in rendered
    assert "nan" not in rendered
    assert "inf" not in rendered


def test_old_relation_aliases_are_rejected() -> None:
    row = _pair(_sha("a"), _sha("b"), "same-family")
    with pytest.raises(LabelValidationError, match="unsupported value"):
        validate_linkage_label_records([row])


def test_ground_truth_cross_source_conflicts_fail_closed() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records([_family(a), _family(b), _pair(a, b, "negative")])
    with pytest.raises(LabelValidationError, match="both positive and negative"):
        build_linkage_ground_truth(labels)


def test_subtype_negative_does_not_become_global_negative_or_override_positive() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [
            _pair(a, b, "negative", subtype="packaging_pipeline", sampling_class="hard"),
            _pair(a, b, "positive", subtype="binary_lineage"),
        ]
    )

    truth = build_linkage_ground_truth(labels)

    assert truth.positive_pairs == {(a, b)}
    assert truth.negative_pairs == set()
    assert truth.hard_negative_pairs == set()


def test_subtype_negative_alone_is_not_a_global_training_negative() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [_pair(a, b, "negative", subtype="packaging_pipeline", sampling_class="hard")]
    )

    truth = build_linkage_ground_truth(labels)

    assert truth.positive_pairs == set()
    assert truth.negative_pairs == set()
    assert truth.hard_negative_pairs == set()


def test_other_subtype_negative_basis_does_not_taint_global_negative() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [
            _pair(a, b, "negative", sampling_class="hard"),
            _pair(
                a,
                b,
                "negative",
                subtype="packaging_pipeline",
                label_basis=["build-root-review"],
            ),
        ]
    )

    truth = build_linkage_ground_truth(labels)

    assert truth.negative_pairs == {(a, b)}
    assert truth.hard_negative_pairs == {(a, b)}
    assert truth.leakage.independent_negative_pairs == {(a, b)}
    assert truth.leakage.independent_hard_negative_pairs == {(a, b)}
    assert truth.leakage.feature_families_by_pair()[(a, b)] == frozenset()


def test_other_subtype_hard_sampling_does_not_promote_global_negative() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [
            _pair(a, b, "negative"),
            _pair(
                a,
                b,
                "negative",
                subtype="packaging_pipeline",
                sampling_class="hard",
            ),
        ]
    )

    truth = build_linkage_ground_truth(labels)

    assert truth.negative_pairs == {(a, b)}
    assert truth.hard_negative_pairs == set()


def test_family_positive_conflicts_with_direct_negative_in_the_same_subtype() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records(
        [
            _family(a),
            _family(b),
            _pair(a, b, "negative", subtype="binary_lineage"),
        ]
    )

    with pytest.raises(LabelValidationError, match="both positive and negative"):
        build_linkage_ground_truth(labels)


def test_ground_truth_pair_budget_fails_before_large_family_expansion(monkeypatch) -> None:
    monkeypatch.setattr(
        "apkscan.core.linkage_labels._MAX_GROUND_TRUTH_PAIR_MATERIALIZATIONS", 3
    )
    labels = validate_linkage_label_records(
        [_family(_sha(char), "large-family") for char in "abcd"]
    )

    with pytest.raises(LabelValidationError, match="materialization exceeds"):
        build_linkage_ground_truth(labels)


def test_jsonl_loader_rejects_nan_duplicate_keys_and_hides_path(tmp_path: Path) -> None:
    nan_path = tmp_path / "private-case-labels.jsonl"
    nan_path.write_text(
        json.dumps(_family(_sha("a"))).replace(
            '"status": "confirmed"', '"confidence": NaN, "status": "confirmed"'
        ),
        encoding="utf-8",
    )
    with pytest.raises(LabelValidationError, match="invalid strict JSON") as error:
        load_linkage_labels(nan_path)
    assert "private-case-labels" not in str(error.value)

    duplicate_key_path = tmp_path / "duplicate.jsonl"
    duplicate_key_path.write_text(
        '{"kind":"family_membership","kind":"pair_judgment"}\n', encoding="utf-8"
    )
    with pytest.raises(LabelValidationError, match="invalid strict JSON"):
        load_linkage_labels(duplicate_key_path)


def test_jsonl_loader_preserves_source_line_for_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "labels.jsonl"
    path.write_text("\n" + json.dumps(_family("bad")) + "\n", encoding="utf-8")
    with pytest.raises(LabelValidationError, match="line 2"):
        load_linkage_labels(path)


def test_jsonl_loader_rejects_deep_nesting_with_a_stable_private_error(tmp_path: Path) -> None:
    path = tmp_path / "secret-deep-labels.jsonl"
    nested = "[" * 2_000 + "0" + "]" * 2_000
    path.write_text('{"unexpected":' + nested + "}\n", encoding="utf-8")

    with pytest.raises(LabelValidationError, match="invalid strict JSON|nesting exceeds") as error:
        load_linkage_labels(path)

    assert str(path) not in str(error.value)


def test_evaluation_uses_existing_ranker_and_reports_only_aggregates(monkeypatch) -> None:
    a, b, c = _sha("a"), _sha("b"), _sha("c")
    native = _sha("f")
    entries = [
        _entry(a, native_sha=native, case_id="private-case-a"),
        _entry(b, native_sha=native, case_id="private-case-b"),
        _entry(c, native_sha=native, case_id="private-case-c"),
    ]
    labels = validate_linkage_label_records(
        [
            _family(a, "private-family"),
            _family(b, "private-family"),
            _pair(a, c, "negative", sampling_class="hard"),
            _pair(b, c, "unknown"),
        ]
    )

    original = linkage_evaluation.rank_link_candidates
    calls = 0

    def _spy(rows, *, case_id: str = "", limit: int = 20):  # noqa: ANN001
        nonlocal calls
        calls += 1
        return original(rows, case_id=case_id, limit=limit)

    monkeypatch.setattr(linkage_evaluation, "rank_link_candidates", _spy)
    result = evaluate_linkage_rules(entries, labels, ks=(1, 5, 20))

    assert calls == 1
    assert result["status"] == "complete"
    assert result["experimental"] is True
    assert result["candidate_generation"]["status"] == "complete"
    assert result["engine"]["id"]
    assert result["engine"]["feature_schema_version"]
    assert result["engine"]["normalization_version"]
    assert len(result["engine"]["policy_digest"]) == 64
    assert result["retrieval"]["indexable_positive_pair_recall"] == 1.0
    assert result["ranking"]["pool_conditioned_judged_only"]["average_precision"] == 1.0
    assert result["ranking"]["pool_conditioned_judged_only"]["at_k"]["5"]["precision"] == 0.5
    assert result["ranking"]["raw_candidate_queue"]["first_positive_rank"] == 1
    assert result["coverage"]["unknown_candidate_count"] == 1
    assert result["errors"]["retrieved_hard_negative_count"] == 1
    assert result["errors"]["hard_negative_high_priority_count"] == 0
    assert result["slices"]["native_only"]["judged_precision"] == 0.5
    assert result["privacy"] == {
        "aggregate_only": True,
        "contains_raw_identifiers": False,
        "contains_raw_evidence_values": False,
    }

    rendered = json.dumps(result, ensure_ascii=False, sort_keys=True)
    for private_value in (
        a,
        b,
        c,
        native,
        "private-family",
        "private-case-a",
        "private-case-b",
        "private-case-c",
    ):
        assert private_value not in rendered
    assert all(math.isfinite(value) for value in _walk_numbers(result))


def test_evaluation_rejects_engine_number_that_overflows_float(monkeypatch) -> None:
    a, b = _sha("a"), _sha("b")
    native = _sha("f")
    entries = [_entry(a, native_sha=native), _entry(b, native_sha=native)]
    labels = validate_linkage_label_records([_family(a), _family(b)])
    original = linkage_evaluation.rank_link_candidates

    def _overflowing(rows, *, case_id: str = "", limit: int = 20):  # noqa: ANN001
        result = original(rows, case_id=case_id, limit=limit)
        result["candidates"][0]["review_priority_score"] = 10**400
        return result

    monkeypatch.setattr(linkage_evaluation, "rank_link_candidates", _overflowing)

    with pytest.raises(linkage_evaluation.LinkageEvaluationError, match="non-finite"):
        evaluate_linkage_rules(entries, labels)


def test_evaluation_is_input_order_independent() -> None:
    a, b, c = _sha("a"), _sha("b"), _sha("c")
    native = _sha("f")
    entries = [
        _entry(a, native_sha=native),
        _entry(b, native_sha=native),
        _entry(c, native_sha=native),
    ]
    raw_labels = [
        _family(a),
        _family(b),
        _pair(a, c, "negative", sampling_class="hard"),
        _pair(b, c, "unknown"),
    ]
    forward = evaluate_linkage_rules(entries, validate_linkage_label_records(raw_labels))
    backward = evaluate_linkage_rules(
        list(reversed(entries)), validate_linkage_label_records(list(reversed(raw_labels)))
    )
    assert forward == backward


def test_feature_overlapping_labels_are_excluded_from_promotion_metrics() -> None:
    a, b, c = _sha("a"), _sha("b"), _sha("c")
    labels = validate_linkage_label_records(
        [
            _family(a, basis="build-root-review"),
            _family(b, basis="build-root-review"),
            _pair(a, c, "negative"),
        ]
    )
    result = evaluate_linkage_rules(
        [
            _entry(a, build_id="build-family"),
            _entry(b, build_id="build-family"),
            _entry(c, build_id="build-family"),
        ],
        labels,
    )

    assert result["status"] == "insufficient_independent_labels"
    assert result["labels"]["positive_pair_count"] == 1
    assert result["labels"]["independent_positive_pair_count"] == 0
    assert result["labels"]["feature_overlap_excluded_positive_pair_count"] == 1
    assert result["retrieval"]["positive_pair_count"] == 0
    assert result["label_feature_independence"]["leakage_matrix"]["build"] == {
        "positive_pair_count": 1,
        "negative_pair_count": 0,
        "unknown_pair_count": 0,
    }


def test_raw_queue_metrics_do_not_delete_unlabelled_candidates() -> None:
    a, b, c, d = (_sha(char) for char in "abcd")
    native = _sha("f")
    labels = validate_linkage_label_records(
        [
            _pair(a, b, "negative"),
            _pair(c, d, "positive"),
        ]
    )
    result = evaluate_linkage_rules(
        [_entry(sample, native_sha=native) for sample in (a, b, c, d)],
        labels,
        ks=(1, 6),
    )

    raw = result["ranking"]["raw_candidate_queue"]
    conditioned = result["ranking"]["pool_conditioned_judged_only"]
    assert raw["first_positive_rank"] == 6
    assert raw["average_precision_at_raw_positions"] == pytest.approx(1 / 6)
    assert raw["at_k"]["1"]["observed_positive_count"] == 0
    assert raw["at_k"]["6"]["unlabelled_count"] == 4
    assert conditioned["average_precision"] == pytest.approx(1 / 2)


def test_missing_positive_is_separate_from_indexable_recall() -> None:
    a, b, missing = _sha("a"), _sha("b"), _sha("c")
    native = _sha("f")
    labels = validate_linkage_label_records([_family(a), _family(b), _family(missing)])
    result = evaluate_linkage_rules(
        [_entry(a, native_sha=native), _entry(b, native_sha=native)], labels
    )
    retrieval = result["retrieval"]
    assert retrieval["positive_pair_count"] == 3
    assert retrieval["indexable_positive_pair_count"] == 1
    assert retrieval["retrieved_positive_pair_count"] == 1
    assert retrieval["positive_pair_candidate_recall"] == pytest.approx(1 / 3)
    assert retrieval["indexable_positive_pair_recall"] == 1.0
    assert retrieval["missing_from_corpus_positive_pair_count"] == 2


# ---------------------------------------------------------------------------
# rules-v2 封顶回归档（closed set，不 gate 训练）
# ---------------------------------------------------------------------------


def test_rules_cap_regression_tier_is_a_closed_internal_set() -> None:
    """回归档没有可传参的门槛入口：档位常量固定，公开函数不接受任何门槛参数。"""
    parameters = inspect.signature(
        linkage_evaluation.assess_rules_regression_readiness
    ).parameters
    assert list(parameters) == ["entries", "labels"]
    assert linkage_evaluation._RULES_REGRESSION_MIN_HARD_NEGATIVE_PAIRS == 30
    assert linkage_evaluation._RULES_REGRESSION_MIN_FAMILY_GROUPS == 3


def test_rules_cap_regression_block_branches_are_self_identifying() -> None:
    block = linkage_evaluation._rules_cap_regression_block

    ready = block(
        labeled_independent_hard_negative_pair_count=31,
        recalled_independent_hard_negative_pair_count=30,
        confirmed_family_group_count=3,
        hard_negative_high_priority_count=0,
        candidate_generation_complete=True,
    )
    assert ready["status"] == "ready_for_cap_regression"
    assert ready["reason"] is None
    assert ready["claim_supported"] is True
    assert ready["tier"] == "rules-v2-cap-regression-v1"
    assert ready["gated_claim"] == "rules_v2_hard_negative_cap_correctness"
    assert ready["model_training"] == {
        "gated_by_this_tier": False,
        "unlocked_by_this_tier": False,
        "authority": "production_readiness_thresholds_only",
    }
    assert ready["produces_model_artifact"] is False

    # ready 但发现未封顶的 hard negative：声明被否定，而不是被沉默。
    failed = block(
        labeled_independent_hard_negative_pair_count=31,
        recalled_independent_hard_negative_pair_count=30,
        confirmed_family_group_count=3,
        hard_negative_high_priority_count=1,
        candidate_generation_complete=True,
    )
    assert failed["status"] == "ready_for_cap_regression"
    assert failed["claim_supported"] is False

    # 标签不足：不给声明结论（None），unmet 指出缺口。
    short = block(
        labeled_independent_hard_negative_pair_count=2,
        recalled_independent_hard_negative_pair_count=1,
        confirmed_family_group_count=2,
        hard_negative_high_priority_count=0,
        candidate_generation_complete=True,
    )
    assert short["status"] == "blocked"
    assert short["reason"] == "insufficient_regression_labels"
    assert short["claim_supported"] is None
    assert {item["metric"] for item in short["unmet"]} == {
        "recalled_independent_hard_negative_pair_count",
        "confirmed_family_group_count",
    }

    # partial 队列上的"0 误报"不可信：fail closed。
    partial = block(
        labeled_independent_hard_negative_pair_count=31,
        recalled_independent_hard_negative_pair_count=30,
        confirmed_family_group_count=3,
        hard_negative_high_priority_count=0,
        candidate_generation_complete=False,
    )
    assert partial["status"] == "blocked"
    assert partial["reason"] == "candidate_generation_incomplete"
    assert partial["claim_supported"] is None


def test_evaluation_embeds_the_regression_tier_with_source_consistent_counts() -> None:
    """link-evaluate 输出内嵌回归档，计数与 errors 节同源（同一 ranked/truth）。"""
    a, b, c = _sha("a"), _sha("b"), _sha("c")
    native = _sha("f")
    labels = validate_linkage_label_records(
        [
            _family(a),
            _family(b),
            _pair(a, c, "negative", sampling_class="hard"),
        ]
    )
    result = evaluate_linkage_rules(
        [_entry(sample, native_sha=native) for sample in (a, b, c)], labels
    )

    tier = result["rules_cap_regression"]
    assert tier["status"] == "blocked"
    assert tier["reason"] == "insufficient_regression_labels"
    assert tier["claim_supported"] is None
    assert (
        tier["counts"]["recalled_independent_hard_negative_pair_count"]
        == result["errors"]["retrieved_hard_negative_count"]
        == 1
    )
    assert (
        tier["counts"]["hard_negative_high_priority_count"]
        == result["errors"]["hard_negative_high_priority_count"]
    )
    assert tier["counts"]["confirmed_family_group_count"] == 1

    standalone = linkage_evaluation.assess_rules_regression_readiness(
        [_entry(sample, native_sha=native) for sample in (a, b, c)], labels
    )
    assert standalone == tier


@pytest.mark.parametrize(
    ("present_samples", "present_positive_count", "present_negative_count"),
    [
        (("c", "d"), 0, 1),
        (("a", "b"), 1, 0),
        (("e",), 0, 0),
    ],
)
def test_evaluation_requires_independent_positive_and_negative_pairs_in_current_corpus(
    present_samples: tuple[str, ...],
    present_positive_count: int,
    present_negative_count: int,
) -> None:
    samples = {char: _sha(char) for char in "abcde"}
    labels = validate_linkage_label_records(
        [
            _pair(samples["a"], samples["b"], "positive"),
            _pair(samples["c"], samples["d"], "negative"),
        ]
    )

    result = evaluate_linkage_rules(
        [_entry(samples[char]) for char in present_samples],
        labels,
    )

    assert result["status"] == "insufficient_independent_labels"
    independence = result["label_feature_independence"]
    assert independence["status"] == "insufficient_independent_labels"
    assert (
        independence["present_independent_positive_pair_count"]
        == present_positive_count
    )
    assert (
        independence["present_independent_negative_pair_count"]
        == present_negative_count
    )


def test_partial_engine_status_includes_invalid_identity_diagnostics() -> None:
    a, b = _sha("a"), _sha("b")
    native = _sha("f")
    labels = validate_linkage_label_records([_family(a), _family(b)])
    result = evaluate_linkage_rules(
        [
            _entry(a, native_sha=native),
            _entry(b, native_sha=native),
            {"sample_sha256": "invalid-untrusted-identity"},
        ],
        labels,
    )
    assert result["status"] == "insufficient_independent_labels"
    assert result["candidate_generation"] == {
        "status": "partial",
        "generated_pair_count": 1,
        "overbroad_anchor_count": 0,
        "pair_budget_exhausted": False,
        "invalid_sample_identity_record_count": 1,
        "missing_repack_identity_record_count": 0,
        "invalid_repack_identity_record_count": 0,
        "legacy_repack_identity_record_count": 0,
    }
    assert result["coverage"]["candidate_generation_partial"] is True


def test_partial_engine_status_separates_invalid_repack_projection() -> None:
    a, b = _sha("a"), _sha("b")
    native = _sha("f")
    labels = validate_linkage_label_records([_family(a), _family(b)])
    invalid = _entry(a, native_sha=native)
    invalid["repack_identity_verdict"] = "future-verdict"

    result = evaluate_linkage_rules([invalid, _entry(b, native_sha=native)], labels)

    assert result["candidate_generation"]["status"] == "partial"
    assert result["candidate_generation"]["missing_repack_identity_record_count"] == 0
    assert result["candidate_generation"]["invalid_repack_identity_record_count"] == 1


def test_partial_engine_status_reports_global_pair_budget(monkeypatch) -> None:
    a, b, c = _sha("a"), _sha("b"), _sha("c")
    native = _sha("f")
    labels = validate_linkage_label_records([_family(a), _family(b), _family(c)])
    monkeypatch.setattr(linkage, "_MAX_CANDIDATE_PAIRS", 2)

    result = evaluate_linkage_rules(
        [
            _entry(a, native_sha=native),
            _entry(b, native_sha=native),
            _entry(c, native_sha=native),
        ],
        labels,
    )

    assert result["candidate_generation"]["status"] == "partial"
    assert result["candidate_generation"]["generated_pair_count"] == 2
    assert result["candidate_generation"]["pair_budget_exhausted"] is True


def test_high_priority_hard_negative_requires_score_and_multiple_support_families() -> None:
    a, b = _sha("a"), _sha("b")
    labels = validate_linkage_label_records([_pair(a, b, "negative", sampling_class="hard")])
    result = evaluate_linkage_rules(
        [
            _entry(a, native_sha=_sha("f"), build_id="build-family"),
            _entry(b, native_sha=_sha("f"), build_id="build-family"),
        ],
        labels,
    )
    assert result["errors"]["retrieved_hard_negative_count"] == 1
    assert result["errors"]["hard_negative_high_priority_count"] == 1


def test_empty_truth_and_empty_candidates_use_none_not_nan() -> None:
    labels = validate_linkage_label_records([])
    result = evaluate_linkage_rules([_entry(_sha("a"))], labels)
    assert result["retrieval"]["positive_pair_candidate_recall"] is None
    assert result["status"] == "insufficient_independent_labels"
    assert result["experimental"] is True
    assert result["ranking"]["pool_conditioned_judged_only"]["average_precision"] is None
    assert result["coverage"]["pair_reduction_fraction"] is None
    assert all(math.isfinite(value) for value in _walk_numbers(result))
