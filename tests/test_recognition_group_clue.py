"""P5-C Group+Clue 指标红态测试（契约见 docs/superpowers/specs/2026-08-17-p5c-group-clue-metrics-design.md）。

夹具值全部合成；期望值全部手算写死。
"""

from __future__ import annotations

import pytest

from apkscan.core.recognition_evaluation import (
    ClueCandidate,
    RecognitionEvaluationError,
    evaluate_clues,
    evaluate_groups,
)
from apkscan.core.recognition_labels import (
    RecognitionLabelRecord,
    RecognitionLabelSet,
)
from apkscan.core.recognition_training import SplitConfig, build_split_manifest

SHA_A = "aa" * 32
SHA_B = "bb" * 32
SHA_C = "cc" * 32
SHA_D = "dd" * 32
SHA_E = "ee" * 32
SHA_T = "77" * 32  # train 侧样本

_seq = iter(range(1, 10_000))


def _record(
    kind: str,
    layer: str = "gold_external",
    **fields: object,
) -> RecognitionLabelRecord:
    return RecognitionLabelRecord(
        kind=kind,
        schema_version="1.0",
        record_id=f"rec-{next(_seq):04d}",
        status="confirmed",
        layer=layer,
        author_kind="human",
        label_basis=(),
        evidence_ref=None,
        label_lineage="queue-external",
        confidence=None,
        supersedes=None,
        reason_codes=(),
        **fields,  # type: ignore[arg-type]
    )


def _relation(
    left: str, right: str, relation: str, subtype: str, **over: str
) -> RecognitionLabelRecord:
    return _record(
        "relation_judgment",
        left_sha256=left,
        right_sha256=right,
        relation=relation,
        relation_subtype=subtype,
        **over,
    )


def _clue(ref: str, verdict: str, ownership: str, **over: str) -> RecognitionLabelRecord:
    return _record(
        "clue_judgment",
        clue_ref=ref,
        verdict=verdict,
        ownership=ownership,
        **over,
    )


def _label_set(*records: RecognitionLabelRecord) -> RecognitionLabelSet:
    active = tuple(r for r in records if r.status not in {"superseded", "rejected"})
    effective = tuple(r for r in active if r.status == "confirmed")
    return RecognitionLabelSet(
        records=tuple(records),
        active=active,
        effective=effective,
        kind_counts=(),
        status_counts=(),
        layer_counts=(),
    )


def _row(sha: str, case_id: str) -> dict:
    return {
        "sample_sha256": sha,
        "tool_version": "1.6.1",
        "ruleset_digest": "rules-v2",
        "evidence_surface": "static",
        "case_ids": [case_id],
        "record_state": "active",
        "record_state_reason": None,
        "ingest_sequence": None,
    }


_LATE = (SHA_A, SHA_B, SHA_C, SHA_D, SHA_E)
_MANIFEST = build_split_manifest(
    [_row(sha, f"case-{sha[:2]}") for sha in _LATE] + [_row(SHA_T, "case-77")],
    _label_set(),
    {f"case-{sha[:2]}": "2026-03-01" for sha in _LATE} | {"case-77": "2025-11-01"},
    SplitConfig(
        cutoff_date="2026-01-01",
        unseen_families=(),
        adversarial_samples=(),
        calibration_samples=(),
        derivations=(),
        policy_version="split-v1",
        labels_digest="ab" * 32,
        catalog_revision="rev-1",
    ),
)


def _eval_groups(labels, groups, **over):
    kwargs: dict = {
        "layers": ("gold_external",),
        "positive_subtypes": ("same_operator",),
        "cannot_link_subtypes": ("same_operator",),
        "repack_subtypes": ("binary_lineage",),
    }
    kwargs.update(over)
    split = kwargs.pop("split_name", "test_temporal_seen")
    return evaluate_groups(labels, _MANIFEST, split, groups, **kwargs)


def _eval_clues(labels, candidates, *, top_n=2, **over):
    kwargs: dict = {"layers": ("gold_external",)}
    kwargs.update(over)
    split = kwargs.pop("split_name", "test_temporal_seen")
    return evaluate_clues(labels, _MANIFEST, split, candidates, top_n=top_n, **kwargs)


# --------------------------------------------------------------- Group（G1-G6）


def test_bcubed_hand_case_two_gold_clusters_merged() -> None:
    labels = _label_set(
        _relation(SHA_A, SHA_B, "positive", "same_operator"),
        _relation(SHA_C, SHA_D, "positive", "same_operator"),
    )
    result = _eval_groups(labels, ((SHA_A, SHA_B, SHA_C, SHA_D),))
    assert result.evaluated_item_count == 4
    assert result.bcubed_precision == pytest.approx(0.5)
    assert result.bcubed_recall == pytest.approx(1.0)


def test_unpredicted_gold_item_counts_as_singleton() -> None:
    labels = _label_set(_relation(SHA_A, SHA_B, "positive", "same_operator"))
    result = _eval_groups(labels, ((SHA_A,),))
    assert result.unpredicted_item_count == 1
    assert result.bcubed_precision == pytest.approx(1.0)
    assert result.bcubed_recall == pytest.approx(0.5)


def test_negative_only_sample_is_not_gold_singleton() -> None:
    labels = _label_set(
        _relation(SHA_A, SHA_B, "positive", "same_operator"),
        _relation(SHA_E, SHA_A, "negative", "same_operator"),
    )
    result = _eval_groups(labels, ((SHA_A, SHA_B, SHA_E),))
    # E 只出现在负例：不进 B-cubed（否则 P 会被拉成 5/9）
    assert result.evaluated_item_count == 2
    assert result.gold_unclustered_count == 1
    assert result.bcubed_precision == pytest.approx(2 / 3)
    # 同时 E-A 同组构成 cannot-link 违规
    assert result.cannot_link_violation_count == 1


def test_cannot_link_counts_only_confirmed_negatives() -> None:
    labels = _label_set(
        _relation(SHA_A, SHA_B, "positive", "same_operator"),
        _relation(SHA_A, SHA_C, "negative", "same_operator"),
    )
    together = _eval_groups(labels, ((SHA_A, SHA_B, SHA_C),))
    assert together.cannot_link_violation_count == 1
    apart = _eval_groups(labels, ((SHA_A, SHA_B), (SHA_C,)))
    assert apart.cannot_link_violation_count == 0


def test_official_repack_mismerge_requires_no_group_support() -> None:
    repack_only = _label_set(_relation(SHA_A, SHA_D, "positive", "binary_lineage"))
    result = _eval_groups(repack_only, ((SHA_A, SHA_D),))
    assert result.official_repack_mismerge_count == 1
    supported = _label_set(
        _relation(SHA_A, SHA_D, "positive", "binary_lineage"),
        _relation(SHA_A, SHA_D, "positive", "same_operator"),
    )
    ok = _eval_groups(supported, ((SHA_A, SHA_D),))
    assert ok.official_repack_mismerge_count == 0


def test_group_input_validation_rejects() -> None:
    labels = _label_set(_relation(SHA_A, SHA_B, "positive", "same_operator"))
    for groups, over, code in (
        (((SHA_A,), (SHA_A,)), {}, "predictions_invalid"),  # 跨组重复
        (((SHA_A, SHA_T),), {}, "predictions_invalid"),  # 切分外成员
        (((SHA_A,),), {"positive_subtypes": ("nope",)}, "predictions_invalid"),
        (((SHA_A,),), {"positive_subtypes": ()}, "predictions_invalid"),
    ):
        with pytest.raises(RecognitionEvaluationError) as exc:
            _eval_groups(labels, groups, **over)
        assert exc.value.reason_code == code


# ---------------------------------------------------------------- Clue（C1-C4）

_CLUE_GOLD = _label_set(
    _clue("clue-001", "valid", "suspect_first_party"),
    _clue("clue-002", "invalid", "unknown"),
)
_CANDS = (
    ClueCandidate("clue-001", SHA_A, "valid", "suspect_first_party", "ev:1"),
    ClueCandidate("clue-002", SHA_B, "valid", "inherited_official", None),
    ClueCandidate("clue-003", SHA_C, "unknown", "unknown", "  "),
)


def test_clue_precision_hand_case() -> None:
    result = _eval_clues(_CLUE_GOLD, _CANDS, top_n=2)
    assert result.labeled_top_count == 2
    # 金标 valid 的只有 clue-001 → 1/2
    assert result.validity_precision == pytest.approx(0.5)
    # ownership 分母剔除金标 unknown 的 clue-002 → 1/1
    assert result.ownership_precision == pytest.approx(1.0)
    assert result.ownership_unknown_gold_count == 1
    assert result.valid_and_ownership_precision == pytest.approx(0.5)


def test_clue_unlabeled_top_candidates_stay_out_of_denominators() -> None:
    result = _eval_clues(_CLUE_GOLD, _CANDS, top_n=3)
    assert result.top_count == 3
    assert result.unlabeled_top_count == 1
    assert result.validity_precision == pytest.approx(0.5)  # 分母仍是 2


def test_clue_evidence_ref_completeness() -> None:
    result = _eval_clues(_CLUE_GOLD, _CANDS, top_n=3)
    # "ev:1" 有效；None 与全空白都算缺 → 1/3
    assert result.evidence_ref_completeness == pytest.approx(1 / 3)


def test_clue_input_validation_rejects() -> None:
    dup = (_CANDS[0], ClueCandidate("clue-001", SHA_B, "valid", "unknown", None))
    for cands, over, code in (
        (_CANDS, {"top_n": 0}, "predictions_invalid"),
        (dup, {}, "predictions_invalid"),
        ((ClueCandidate("c", SHA_T, "valid", "unknown", None),), {}, "predictions_invalid"),
        ((ClueCandidate("c", SHA_A, "nope", "unknown", None),), {}, "predictions_invalid"),
        ((ClueCandidate("c", SHA_A, "valid", "nope", None),), {}, "predictions_invalid"),
    ):
        with pytest.raises(RecognitionEvaluationError) as exc:
            _eval_clues(_CLUE_GOLD, cands, **over)
        assert exc.value.reason_code == code


# ------------------------------------------------------------- 公共（E3-E4）


def test_honest_empty_group_and_clue() -> None:
    groups = _eval_groups(_label_set(), ())
    assert groups.bcubed_precision is None
    assert groups.cannot_link_violation_count == 0
    assert groups.provenance.promotion_eligible is False
    clues = _eval_clues(_label_set(), ())
    assert clues.validity_precision is None
    assert clues.provenance.promotion_eligible is False


def test_promotion_matrix_for_group_and_clue() -> None:
    gold = _label_set(_relation(SHA_A, SHA_B, "positive", "same_operator"))
    assert _eval_groups(gold, ((SHA_A, SHA_B),)).provenance.promotion_eligible is True
    silver = _label_set(_relation(SHA_A, SHA_B, "positive", "same_operator", layer="silver"))
    assert (
        _eval_groups(silver, ((SHA_A, SHA_B),), layers=("silver",)).provenance.promotion_eligible
        is False
    )
    assert _eval_clues(_CLUE_GOLD, _CANDS[:1]).provenance.promotion_eligible is True
    silver_clue = _label_set(_clue("clue-001", "valid", "suspect_first_party", layer="silver"))
    assert (
        _eval_clues(silver_clue, _CANDS[:1], layers=("silver",)).provenance.promotion_eligible
        is False
    )
