"""P5-B Family+Pair 指标层红态测试（契约见 docs/superpowers/specs/2026-08-17-p5b-family-pair-metrics-design.md）。

夹具值全部合成；指标期望值全部手算写死（不用被测模块的常量复算——防同源假绿）。
"""

from __future__ import annotations

import math

import pytest

from apkscan.core.recognition_evaluation import (
    FamilyPrediction,
    PairRanking,
    RecognitionEvaluationError,
    evaluate_family,
    evaluate_pairs,
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
SHA_Q = "11" * 32
SHA_W = "66" * 32
SHA_R1 = "22" * 32
SHA_R2 = "33" * 32
SHA_N1 = "44" * 32
SHA_X = "55" * 32
SHA_T = "77" * 32  # train 侧样本

_seq = iter(range(1, 10_000))


def _record(
    kind: str,
    status: str = "confirmed",
    layer: str = "gold_external",
    lineage: str = "queue-external",
    **fields: object,
) -> RecognitionLabelRecord:
    return RecognitionLabelRecord(
        kind=kind,
        schema_version="1.0",
        record_id=f"rec-{next(_seq):04d}",
        status=status,
        layer=layer,
        author_kind="human",
        label_basis=(),
        evidence_ref=None,
        label_lineage=lineage,
        confidence=None,
        supersedes=None,
        reason_codes=(),
        **fields,  # type: ignore[arg-type]
    )


def _family(sha: str, family_id: str, **over: str) -> RecognitionLabelRecord:
    return _record(
        "family_assignment",
        sample_sha256=sha,
        level="product_line",
        family_id=family_id,
        **over,
    )


def _relation(left: str, right: str, relation: str, **over: str) -> RecognitionLabelRecord:
    return _record(
        "relation_judgment",
        left_sha256=left,
        right_sha256=right,
        relation=relation,
        relation_subtype="binary_lineage",
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


# 每个样本独立 case：test 侧 late、train 侧 early，单位不合并
_LATE_SHAS = (SHA_A, SHA_B, SHA_C, SHA_D, SHA_E, SHA_Q, SHA_W)
_ROWS = [_row(sha, f"case-{sha[:2]}") for sha in _LATE_SHAS] + [_row(SHA_T, "case-77")]
_TIME = {f"case-{sha[:2]}": "2026-03-01" for sha in _LATE_SHAS} | {"case-77": "2025-11-01"}

_MANIFEST = build_split_manifest(
    _ROWS,
    _label_set(),
    _TIME,
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

_GOLD3 = _label_set(
    _family(SHA_A, "fam-x"),
    _family(SHA_B, "fam-x"),
    _family(SHA_C, "fam-y"),
)


def _eval_family(labels, predictions, *, layers=("gold_external",), **over):
    kwargs: dict = {
        "split_name": "test_temporal_seen",
        "level": "product_line",
        "layers": layers,
    }
    kwargs.update(over)
    return evaluate_family(
        labels, _MANIFEST, kwargs.pop("split_name"), kwargs.pop("level"), predictions, **kwargs
    )


def _eval_pairs(
    labels, rankings, *, k=2, layers=("gold_external",), lineages=("queue-external",), **over
):
    kwargs: dict = {"split_name": "test_temporal_seen"}
    kwargs.update(over)
    return evaluate_pairs(
        labels, _MANIFEST, kwargs.pop("split_name"), rankings, k=k, layers=layers, lineages=lineages
    )


# ------------------------------------------------------------- Family（F1-F6）


def test_family_eval_sample_selection_excludes_visibly() -> None:
    # SHA_T 在 train、SHA_D 无金标、silver 层金标不入选——三类都不进分母
    labels = _label_set(
        _family(SHA_A, "fam-x"),
        _family(SHA_T, "fam-x"),
        _family(SHA_B, "fam-x", layer="silver"),
    )
    result = _eval_family(labels, (FamilyPrediction(SHA_A, "fam-x"),))
    assert result.gold_sample_count == 1
    assert result.covered_count == 1
    assert result.macro_f1 == pytest.approx(1.0)


def test_family_input_validation_rejects() -> None:
    preds = (FamilyPrediction(SHA_A, "fam-x"), FamilyPrediction(SHA_A, "fam-y"))
    with pytest.raises(RecognitionEvaluationError) as exc:
        _eval_family(_GOLD3, preds)
    assert exc.value.reason_code == "predictions_invalid"
    for over, code in (
        ({"split_name": "nope"}, "split_unknown"),
        ({"level": "nope"}, "level_invalid"),
        ({"layers": ()}, "layer_invalid"),
        ({"layers": ("gold", "nope")}, "layer_invalid"),
    ):
        with pytest.raises(RecognitionEvaluationError) as exc:
            _eval_family(_GOLD3, (), **over)
        assert exc.value.reason_code == code


def test_family_macro_f1_and_recall_hand_case() -> None:
    # A→x(TP) B→y(x 的 FN、y 的 FP) C→y(TP)；D 无金标预测被忽略
    preds = (
        FamilyPrediction(SHA_A, "fam-x"),
        FamilyPrediction(SHA_B, "fam-y"),
        FamilyPrediction(SHA_C, "fam-y"),
        FamilyPrediction(SHA_D, "fam-x"),
    )
    result = _eval_family(_GOLD3, preds)
    assert result.gold_sample_count == 3
    assert result.covered_count == 3
    # fam-x: F1=2/3；fam-y: P=0.5 R=1 F1=2/3
    assert result.macro_f1 == pytest.approx(2 / 3)
    assert dict(result.per_family_recall) == {
        "fam-x": pytest.approx(0.5),
        "fam-y": pytest.approx(1.0),
    }


def test_family_known_unknown_metrics_and_conflict() -> None:
    preds = (
        FamilyPrediction(SHA_A, "fam-x"),
        FamilyPrediction(SHA_D, "unknown"),
        FamilyPrediction(SHA_E, "fam-x"),
    )
    labels = _label_set(_family(SHA_A, "fam-x"))
    result = _eval_family(labels, preds, known_unknown_samples=(SHA_D, SHA_E))
    assert result.known_unknown_count == 2
    assert result.unknown_recall == pytest.approx(0.5)
    assert result.forced_assignment_error_rate == pytest.approx(0.5)
    with pytest.raises(RecognitionEvaluationError) as exc:
        _eval_family(labels, preds, known_unknown_samples=(SHA_A,))
    assert exc.value.reason_code == "input_conflict"


def test_family_missing_prediction_visible_and_excluded() -> None:
    preds = (FamilyPrediction(SHA_A, "fam-x"), FamilyPrediction(SHA_B, "fam-y"))
    result = _eval_family(_GOLD3, preds)  # C 缺预测
    assert result.missing_prediction_count == 1
    assert result.covered_count == 2
    # 覆盖集只剩 fam-x（gold A,B）：TP=1 FN=1 FP=0 → macro=2/3
    assert result.macro_f1 == pytest.approx(2 / 3)
    assert dict(result.per_family_recall) == {"fam-x": pytest.approx(0.5)}


def test_family_promotion_eligibility_matrix() -> None:
    pred = (FamilyPrediction(SHA_A, "fam-x"),)
    gold = _label_set(_family(SHA_A, "fam-x"))
    assert _eval_family(gold, pred).provenance.promotion_eligible is True
    silver = _label_set(_family(SHA_A, "fam-x", layer="silver"))
    assert _eval_family(silver, pred, layers=("silver",)).provenance.promotion_eligible is False
    train_gold = _label_set(_family(SHA_T, "fam-x"))
    train_result = _eval_family(train_gold, (FamilyPrediction(SHA_T, "fam-x"),), split_name="train")
    assert train_result.provenance.promotion_eligible is False
    empty = _eval_family(_label_set(), ())
    assert empty.provenance.label_count == 0
    assert empty.provenance.promotion_eligible is False


# --------------------------------------------------------------- Pair（P1-P7）

_PAIR_GOLD = _label_set(
    _relation(SHA_Q, SHA_R1, "positive"),
    _relation(SHA_R2, SHA_Q, "positive"),
    _relation(SHA_Q, SHA_N1, "negative"),
)
_RANKING_Q = PairRanking(
    SHA_Q,
    ((SHA_R1, 0.9), (SHA_N1, 0.8), (SHA_R2, 0.7), (SHA_X, 0.6)),
)


def test_pair_ranking_validation_rejects() -> None:
    bad_order = PairRanking(SHA_Q, ((SHA_R1, 0.5), (SHA_N1, 0.9)))
    with pytest.raises(RecognitionEvaluationError) as exc:
        _eval_pairs(_PAIR_GOLD, (bad_order,))
    assert exc.value.reason_code == "ranking_not_sorted"
    # 同分处 candidate 必须 sha 升序（N1="44..">R1="22.."，降序违规）
    bad_tie = PairRanking(SHA_Q, ((SHA_N1, 0.5), (SHA_R1, 0.5)))
    with pytest.raises(RecognitionEvaluationError) as exc:
        _eval_pairs(_PAIR_GOLD, (bad_tie,))
    assert exc.value.reason_code == "ranking_not_sorted"
    for ranked in (
        ((SHA_R1, 0.9), (SHA_R1, 0.8)),  # candidate 重复
        ((SHA_Q, 0.9),),  # 含 query 自身
        ((SHA_R1, float("nan")),),  # 非有限 score
    ):
        with pytest.raises(RecognitionEvaluationError) as exc:
            _eval_pairs(_PAIR_GOLD, (PairRanking(SHA_Q, ranked),))
        assert exc.value.reason_code == "predictions_invalid"
    with pytest.raises(RecognitionEvaluationError) as exc:
        _eval_pairs(_PAIR_GOLD, (PairRanking(SHA_T, ((SHA_R1, 0.9),)),))
    assert exc.value.reason_code == "predictions_invalid"  # query 不在切分


def test_pair_recall_at_k_hand_case() -> None:
    result = _eval_pairs(_PAIR_GOLD, (_RANKING_Q,))
    # 相关={R1,R2}，top-2={R1,N1} → 1/2
    assert result.recall_at_k == pytest.approx(0.5)
    assert result.positive_pair_count == 2
    assert result.negative_pair_count == 1


def test_pair_ndcg_at_k_hand_case() -> None:
    result = _eval_pairs(_PAIR_GOLD, (_RANKING_Q,))
    idcg = 1 / math.log2(2) + 1 / math.log2(3)
    assert result.ndcg_at_k == pytest.approx((1 / math.log2(2)) / idcg)


def test_pair_average_precision_full_list_hand_case() -> None:
    result = _eval_pairs(_PAIR_GOLD, (_RANKING_Q,))
    # 命中位 1（P=1）与 3（P=2/3），|相关|=2 → AP=5/6
    assert result.mean_average_precision == pytest.approx(5 / 6)


def test_pair_false_edges_count_only_confirmed_negatives() -> None:
    result = _eval_pairs(_PAIR_GOLD, (_RANKING_Q,))
    # top-2 里 N1 是确认负例；X 未标注不算负——纪律
    assert result.confirmed_false_edge_count == 1


def test_pair_query_without_positives_stays_out_of_means() -> None:
    rankings = (_RANKING_Q, PairRanking(SHA_W, ((SHA_X, 0.9),)))
    result = _eval_pairs(_PAIR_GOLD, rankings)
    assert result.query_count == 2
    assert result.evaluated_query_count == 1
    assert result.unevaluable_query_count == 1
    assert result.recall_at_k == pytest.approx(0.5)  # W 不得按 0 拉低


def test_pair_lineage_filter_excludes_queue_internal() -> None:
    internal = _label_set(_relation(SHA_Q, SHA_R1, "positive", lineage="queue-internal"))
    result = _eval_pairs(internal, (_RANKING_Q,))
    assert result.evaluated_query_count == 0
    assert result.positive_pair_count == 0
    internal_used = _eval_pairs(internal, (_RANKING_Q,), lineages=("queue-internal",))
    assert internal_used.evaluated_query_count == 1
    assert internal_used.provenance.promotion_eligible is False  # lineage 门


def test_pair_k_must_be_positive() -> None:
    with pytest.raises(RecognitionEvaluationError) as exc:
        _eval_pairs(_PAIR_GOLD, (_RANKING_Q,), k=0)
    assert exc.value.reason_code == "predictions_invalid"


# ------------------------------------------------------------- 公共（E1-E2）


def test_honest_empty_evaluations() -> None:
    family = _eval_family(_label_set(), ())
    assert family.macro_f1 is None
    assert family.unknown_recall is None
    pair = _eval_pairs(_label_set(), ())
    assert pair.recall_at_k is None
    assert pair.confirmed_false_edge_count == 0
    assert pair.provenance.promotion_eligible is False


def test_determinism_under_input_reordering() -> None:
    preds = (
        FamilyPrediction(SHA_A, "fam-x"),
        FamilyPrediction(SHA_B, "fam-y"),
        FamilyPrediction(SHA_C, "fam-y"),
    )
    one = _eval_family(_GOLD3, preds)
    other = _eval_family(
        _label_set(_family(SHA_C, "fam-y"), _family(SHA_A, "fam-x"), _family(SHA_B, "fam-x")),
        tuple(reversed(preds)),
    )
    # record_id 不同不影响指标——比逐字段指标而非整对象
    assert one.macro_f1 == other.macro_f1
    assert one.per_family_recall == other.per_family_recall
    rankings = (_RANKING_Q, PairRanking(SHA_W, ((SHA_X, 0.9),)))
    p_one = _eval_pairs(_PAIR_GOLD, rankings)
    p_other = _eval_pairs(_PAIR_GOLD, tuple(reversed(rankings)))
    assert p_one.recall_at_k == p_other.recall_at_k
    assert p_one.mean_average_precision == p_other.mean_average_precision
