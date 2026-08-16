"""提供 APK 识别评估的 Family 与 Pair 指标层纯函数实现，指标定义与晋升资格规则源自 §11.2。"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Final

from apkscan.core.recognition_labels import (
    RecognitionLabelRecord,
    RecognitionLabelSet,
)
from apkscan.core.recognition_training import SplitManifest


_SPLIT_NAMES: Final[frozenset[str]] = frozenset(
    {
        "train",
        "calibration",
        "test_temporal_seen",
        "test_unseen_family",
        "test_adversarial",
    }
)
_PROMOTION_SPLITS: Final[frozenset[str]] = frozenset(
    {
        "test_temporal_seen",
        "test_unseen_family",
        "test_adversarial",
    }
)
_LEVELS: Final[frozenset[str]] = frozenset(
    {
        "platform_family",
        "product_line",
        "customer_cluster",
        "operator_cluster",
    }
)
_LAYERS: Final[frozenset[str]] = frozenset(
    {
        "silver",
        "gold_internal",
        "gold_external",
        "adversarial",
    }
)
_PROMOTION_LAYERS: Final[frozenset[str]] = frozenset(
    {
        "gold_external",
        "adversarial",
    }
)
_LINEAGES: Final[frozenset[str]] = frozenset(
    {
        "queue-internal",
        "queue-external",
        "unspecified",
    }
)
_PROMOTION_PAIR_LINEAGES: Final[frozenset[str]] = frozenset({"queue-external"})
_RESERVED_FAMILY_IDS: Final[frozenset[str]] = frozenset({"unknown", "abstain"})
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")

# 与 recognition_labels / recognition_training 同源的本模块词表副本。


class RecognitionEvaluationError(Exception):
    """识别评估输入或约束错误。"""

    reason_code: str
    detail: str

    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def _fail(reason_code: str, detail: str) -> None:
    raise RecognitionEvaluationError(reason_code, detail)


@dataclass(frozen=True, slots=True)
class EvaluationProvenance:
    split_name: str
    level: str | None
    layers_used: tuple[str, ...]
    lineages_used: tuple[str, ...]
    label_count: int
    evaluated_count: int
    promotion_eligible: bool


@dataclass(frozen=True, slots=True)
class FamilyPrediction:
    sample_sha256: str
    family_id: str


@dataclass(frozen=True, slots=True)
class FamilyEvaluation:
    provenance: EvaluationProvenance
    per_family_recall: tuple[tuple[str, float], ...]
    macro_f1: float | None
    unknown_recall: float | None
    forced_assignment_error_rate: float | None
    gold_sample_count: int
    covered_count: int
    missing_prediction_count: int
    known_unknown_count: int


@dataclass(frozen=True, slots=True)
class PairRanking:
    query_sha256: str
    ranked: tuple[tuple[str, float], ...]


@dataclass(frozen=True, slots=True)
class PairEvaluation:
    provenance: EvaluationProvenance
    recall_at_k: float | None
    ndcg_at_k: float | None
    mean_average_precision: float | None
    confirmed_false_edge_count: int
    query_count: int
    evaluated_query_count: int
    unevaluable_query_count: int
    positive_pair_count: int
    negative_pair_count: int


def derive_promotion_eligible(
    *,
    split_name: str,
    label_count: int,
    layers_used: tuple[str, ...],
    lineages_used: tuple[str, ...],
    pair_task: bool,
) -> bool:
    """按实际消费标签推导晋升资格。"""
    if split_name not in _PROMOTION_SPLITS or label_count <= 0:
        return False
    # 空消费集合不得晋级——空集是任意集合的子集，必须先拒（codex 复审 P1）。
    if not layers_used:
        return False
    if not set(layers_used).issubset(_PROMOTION_LAYERS):
        return False
    if pair_task and (
        not lineages_used or not set(lineages_used).issubset(_PROMOTION_PAIR_LINEAGES)
    ):
        return False
    return True


def _is_valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_PATTERN.fullmatch(value) is not None


def _validate_split_name(split_name: str) -> None:
    if split_name not in _SPLIT_NAMES:
        _fail("split_unknown", f"未知切分名: {split_name!r}")


def _validate_level(level: str) -> None:
    if level not in _LEVELS:
        _fail("level_invalid", f"未知标签层级: {level!r}")


def _validate_layers(layers: tuple[str, ...]) -> frozenset[str]:
    if not layers:
        _fail("layer_invalid", "layers 不得为空")
    if any(not isinstance(layer, str) or layer not in _LAYERS for layer in layers):
        _fail("layer_invalid", "layers 含未知值")
    return frozenset(layers)


def _validate_lineages(lineages: tuple[str, ...]) -> frozenset[str]:
    if not lineages:
        _fail("lineage_invalid", "lineages 不得为空")
    if any(not isinstance(lineage, str) or lineage not in _LINEAGES for lineage in lineages):
        _fail("lineage_invalid", "lineages 含未知值")
    return frozenset(lineages)


def _split_members(
    manifest: SplitManifest,
    split_name: str,
) -> frozenset[str]:
    members: set[str] = set()
    for unit in manifest.splits[split_name]:
        members.update(unit.members)
    return frozenset(members)


def _family_record_sort_key(
    record: RecognitionLabelRecord,
) -> tuple[str, str, str, str]:
    return (
        record.layer,
        record.label_lineage,
        record.record_id,
        record.family_id or "",
    )


def evaluate_family(
    label_set: RecognitionLabelSet,
    manifest: SplitManifest,
    split_name: str,
    level: str,
    predictions: tuple[FamilyPrediction, ...],
    *,
    layers: tuple[str, ...],
    known_unknown_samples: tuple[str, ...] = (),
) -> FamilyEvaluation:
    """评估指定切分与层级上的族分类结果。"""
    _validate_split_name(split_name)
    _validate_level(level)
    selected_layers = _validate_layers(layers)
    split_members = _split_members(manifest, split_name)

    predictions_by_sha: dict[str, FamilyPrediction] = {}
    for prediction in predictions:
        if not isinstance(prediction, FamilyPrediction):
            _fail("predictions_invalid", "predictions 含非 FamilyPrediction 项")
        if not _is_valid_sha256(prediction.sample_sha256):
            _fail(
                "sha_invalid",
                f"预测样本 SHA-256 非法: {prediction.sample_sha256!r}",
            )
        if prediction.sample_sha256 in predictions_by_sha:
            _fail(
                "predictions_invalid",
                f"预测样本重复: {prediction.sample_sha256}",
            )
        predictions_by_sha[prediction.sample_sha256] = prediction

    known_unknown_set: set[str] = set()
    for sample_sha256 in known_unknown_samples:
        if not _is_valid_sha256(sample_sha256):
            _fail(
                "sha_invalid",
                f"known_unknown_samples 中 SHA-256 非法: {sample_sha256!r}",
            )
        if sample_sha256 not in split_members:
            _fail(
                "input_conflict",
                f"known_unknown_samples 含切分外样本: {sample_sha256}",
            )
        known_unknown_set.add(sample_sha256)

    candidates_by_sha: dict[str, list[RecognitionLabelRecord]] = {}
    for record in label_set.effective:
        if (
            record.kind == "family_assignment"
            and record.level == level
            and record.layer in selected_layers
            and record.sample_sha256 is not None
            and record.family_id is not None
            and record.sample_sha256 in split_members
        ):
            candidates_by_sha.setdefault(record.sample_sha256, []).append(record)

    gold_by_sha: dict[str, RecognitionLabelRecord] = {}
    for sample_sha256 in sorted(candidates_by_sha):
        records = candidates_by_sha[sample_sha256]
        gold_by_sha[sample_sha256] = min(
            records,
            key=_family_record_sort_key,
        )

    overlap = known_unknown_set.intersection(gold_by_sha)
    if overlap:
        conflicting_sha = min(overlap)
        _fail(
            "input_conflict",
            f"known_unknown_samples 与可评金标重叠: {conflicting_sha}",
        )

    consumed_records = tuple(gold_by_sha[sample_sha256] for sample_sha256 in sorted(gold_by_sha))
    layers_used = tuple(sorted({record.layer for record in consumed_records}))
    lineages_used = tuple(sorted({record.label_lineage for record in consumed_records}))

    covered_gold_shas = tuple(
        sample_sha256
        for sample_sha256 in sorted(gold_by_sha)
        if sample_sha256 in predictions_by_sha
    )
    covered_unknown_shas = tuple(
        sample_sha256
        for sample_sha256 in sorted(known_unknown_set)
        if sample_sha256 in predictions_by_sha
    )

    gold_sample_count = len(gold_by_sha)
    covered_count = len(covered_gold_shas)
    missing_prediction_count = gold_sample_count - covered_count
    known_unknown_count = len(covered_unknown_shas)

    gold_counts: dict[str, int] = {}
    true_positive_counts: dict[str, int] = {}
    false_positive_counts: dict[str, int] = {}

    for sample_sha256 in covered_gold_shas:
        record = gold_by_sha[sample_sha256]
        gold_family = record.family_id
        if gold_family is None:
            continue

        predicted_family = predictions_by_sha[sample_sha256].family_id
        gold_counts[gold_family] = gold_counts.get(gold_family, 0) + 1

        if predicted_family == gold_family:
            true_positive_counts[gold_family] = true_positive_counts.get(gold_family, 0) + 1
        elif predicted_family in gold_counts:
            false_positive_counts[predicted_family] = (
                false_positive_counts.get(predicted_family, 0) + 1
            )

    # FP 必须依据覆盖集中出现的全部金标族计算，不能依赖遍历时点。
    covered_gold_families = frozenset(gold_counts)
    false_positive_counts = {}
    for sample_sha256 in covered_gold_shas:
        record = gold_by_sha[sample_sha256]
        gold_family = record.family_id
        if gold_family is None:
            continue
        predicted_family = predictions_by_sha[sample_sha256].family_id
        if predicted_family != gold_family and predicted_family in covered_gold_families:
            false_positive_counts[predicted_family] = (
                false_positive_counts.get(predicted_family, 0) + 1
            )

    per_family_recall = tuple(
        (
            family_id,
            true_positive_counts.get(family_id, 0) / gold_counts[family_id],
        )
        for family_id in sorted(gold_counts)
    )

    if gold_counts:
        f1_values: list[float] = []
        for family_id in sorted(gold_counts):
            true_positive = true_positive_counts.get(family_id, 0)
            false_positive = false_positive_counts.get(family_id, 0)
            false_negative = gold_counts[family_id] - true_positive
            denominator = (2 * true_positive) + false_positive + false_negative
            f1_values.append(0.0 if denominator == 0 else (2.0 * true_positive) / denominator)
        macro_f1: float | None = sum(f1_values) / len(f1_values)
    else:
        macro_f1 = None

    if known_unknown_count:
        abstained_count = sum(
            1
            for sample_sha256 in covered_unknown_shas
            if predictions_by_sha[sample_sha256].family_id in _RESERVED_FAMILY_IDS
        )
        forced_count = known_unknown_count - abstained_count
        unknown_recall: float | None = abstained_count / known_unknown_count
        forced_assignment_error_rate: float | None = forced_count / known_unknown_count
    else:
        unknown_recall = None
        forced_assignment_error_rate = None

    label_count = len(consumed_records)
    promotion_eligible = derive_promotion_eligible(
        split_name=split_name,
        label_count=label_count,
        layers_used=layers_used,
        lineages_used=lineages_used,
        pair_task=False,
    )

    provenance = EvaluationProvenance(
        split_name=split_name,
        level=level,
        layers_used=layers_used,
        lineages_used=lineages_used,
        label_count=label_count,
        evaluated_count=covered_count,
        promotion_eligible=promotion_eligible,
    )
    return FamilyEvaluation(
        provenance=provenance,
        per_family_recall=per_family_recall,
        macro_f1=macro_f1,
        unknown_recall=unknown_recall,
        forced_assignment_error_rate=forced_assignment_error_rate,
        gold_sample_count=gold_sample_count,
        covered_count=covered_count,
        missing_prediction_count=missing_prediction_count,
        known_unknown_count=known_unknown_count,
    )


def _validate_pair_ranking(
    ranking: PairRanking,
    split_members: frozenset[str],
) -> None:
    query_sha256 = ranking.query_sha256
    if not _is_valid_sha256(query_sha256):
        _fail(
            "sha_invalid",
            f"查询 SHA-256 非法: {query_sha256!r}",
        )
    if query_sha256 not in split_members:
        _fail(
            "predictions_invalid",
            f"查询不属于目标切分: {query_sha256}",
        )

    seen_candidates: set[str] = set()
    previous_score: float | None = None
    previous_candidate: str | None = None

    for item in ranking.ranked:
        if not isinstance(item, tuple) or len(item) != 2:
            _fail("predictions_invalid", "ranked 项必须为二元组")

        candidate_sha256, score = item
        if not _is_valid_sha256(candidate_sha256):
            _fail(
                "sha_invalid",
                f"候选 SHA-256 非法: {candidate_sha256!r}",
            )
        if candidate_sha256 == query_sha256:
            _fail(
                "predictions_invalid",
                f"候选不得等于查询: {query_sha256}",
            )
        if candidate_sha256 in seen_candidates:
            _fail(
                "predictions_invalid",
                f"候选重复: {candidate_sha256}",
            )
        if not isinstance(score, float) or not math.isfinite(score):
            _fail(
                "predictions_invalid",
                f"候选分数必须为有限 float: {score!r}",
            )

        if previous_score is not None:
            if score > previous_score:
                _fail(
                    "ranking_not_sorted",
                    f"查询排名分数非递减顺序: {query_sha256}",
                )
            if (
                score == previous_score
                and previous_candidate is not None
                and candidate_sha256 < previous_candidate
            ):
                _fail(
                    "ranking_not_sorted",
                    f"查询排名同分候选未按 SHA 升序: {query_sha256}",
                )

        seen_candidates.add(candidate_sha256)
        previous_score = score
        previous_candidate = candidate_sha256


def evaluate_pairs(
    label_set: RecognitionLabelSet,
    manifest: SplitManifest,
    split_name: str,
    rankings: tuple[PairRanking, ...],
    *,
    k: int,
    layers: tuple[str, ...],
    lineages: tuple[str, ...],
) -> PairEvaluation:
    """评估指定切分上的相似样本检索排名。"""
    _validate_split_name(split_name)
    selected_layers = _validate_layers(layers)
    selected_lineages = _validate_lineages(lineages)

    if not isinstance(k, int) or isinstance(k, bool) or k < 1:
        _fail("predictions_invalid", "k 必须为不小于 1 的整数")

    split_members = _split_members(manifest, split_name)
    rankings_by_query: dict[str, PairRanking] = {}

    for ranking in rankings:
        if not isinstance(ranking, PairRanking):
            _fail("predictions_invalid", "rankings 含非 PairRanking 项")
        _validate_pair_ranking(ranking, split_members)
        if ranking.query_sha256 in rankings_by_query:
            _fail(
                "predictions_invalid",
                f"查询重复: {ranking.query_sha256}",
            )
        rankings_by_query[ranking.query_sha256] = ranking

    query_shas = frozenset(rankings_by_query)
    positives_by_query: dict[str, set[str]] = {query_sha256: set() for query_sha256 in query_shas}
    negatives_by_query: dict[str, set[str]] = {query_sha256: set() for query_sha256 in query_shas}
    consumed_layers: set[str] = set()
    consumed_lineages: set[str] = set()

    for record in label_set.effective:
        if (
            record.kind != "relation_judgment"
            or record.layer not in selected_layers
            or record.label_lineage not in selected_lineages
            or record.relation not in {"positive", "negative"}
            or record.left_sha256 is None
            or record.right_sha256 is None
        ):
            continue

        consumed_for_record = False

        if record.left_sha256 in query_shas:
            target = positives_by_query if record.relation == "positive" else negatives_by_query
            target[record.left_sha256].add(record.right_sha256)
            consumed_for_record = True

        if record.right_sha256 in query_shas:
            target = positives_by_query if record.relation == "positive" else negatives_by_query
            target[record.right_sha256].add(record.left_sha256)
            consumed_for_record = True

        if consumed_for_record:
            consumed_layers.add(record.layer)
            consumed_lineages.add(record.label_lineage)

    positive_pair_count = sum(
        len(positives_by_query[query_sha256]) for query_sha256 in sorted(query_shas)
    )
    negative_pair_count = sum(
        len(negatives_by_query[query_sha256]) for query_sha256 in sorted(query_shas)
    )

    recall_values: list[float] = []
    ndcg_values: list[float] = []
    average_precision_values: list[float] = []
    confirmed_false_edge_count = 0
    evaluated_query_count = 0

    for query_sha256 in sorted(query_shas):
        ranking = rankings_by_query[query_sha256]
        relevant = positives_by_query[query_sha256]
        confirmed_negative = negatives_by_query[query_sha256]
        top_k = ranking.ranked[:k]

        confirmed_false_edge_count += sum(
            1 for candidate_sha256, _score in top_k if candidate_sha256 in confirmed_negative
        )

        if not relevant:
            continue

        evaluated_query_count += 1

        top_k_hit_count = sum(
            1 for candidate_sha256, _score in top_k if candidate_sha256 in relevant
        )
        recall_values.append(top_k_hit_count / len(relevant))

        dcg = 0.0
        for rank, (candidate_sha256, _score) in enumerate(top_k, start=1):
            if candidate_sha256 in relevant:
                dcg += 1.0 / math.log2(rank + 1)

        ideal_length = min(k, len(relevant))
        idcg = 0.0
        for rank in range(1, ideal_length + 1):
            idcg += 1.0 / math.log2(rank + 1)
        ndcg_values.append(dcg / idcg)

        hit_count = 0
        precision_sum = 0.0
        for rank, (candidate_sha256, _score) in enumerate(
            ranking.ranked,
            start=1,
        ):
            if candidate_sha256 in relevant:
                hit_count += 1
                precision_sum += hit_count / rank
        average_precision_values.append(precision_sum / len(relevant))

    query_count = len(rankings_by_query)
    unevaluable_query_count = query_count - evaluated_query_count

    if evaluated_query_count:
        recall_at_k: float | None = sum(recall_values) / evaluated_query_count
        ndcg_at_k: float | None = sum(ndcg_values) / evaluated_query_count
        mean_average_precision: float | None = sum(average_precision_values) / evaluated_query_count
    else:
        recall_at_k = None
        ndcg_at_k = None
        mean_average_precision = None

    layers_used = tuple(sorted(consumed_layers))
    lineages_used = tuple(sorted(consumed_lineages))
    label_count = positive_pair_count + negative_pair_count
    promotion_eligible = derive_promotion_eligible(
        split_name=split_name,
        label_count=label_count,
        layers_used=layers_used,
        lineages_used=lineages_used,
        pair_task=True,
    )

    provenance = EvaluationProvenance(
        split_name=split_name,
        level=None,
        layers_used=layers_used,
        lineages_used=lineages_used,
        label_count=label_count,
        evaluated_count=evaluated_query_count,
        promotion_eligible=promotion_eligible,
    )
    return PairEvaluation(
        provenance=provenance,
        recall_at_k=recall_at_k,
        ndcg_at_k=ndcg_at_k,
        mean_average_precision=mean_average_precision,
        confirmed_false_edge_count=confirmed_false_edge_count,
        query_count=query_count,
        evaluated_query_count=evaluated_query_count,
        unevaluable_query_count=unevaluable_query_count,
        positive_pair_count=positive_pair_count,
        negative_pair_count=negative_pair_count,
    )


# 与 recognition_labels 同源的本模块词表副本。
_RELATION_SUBTYPES: Final[frozenset[str]] = frozenset(
    {
        "exact_artifact_identity",
        "binary_lineage",
        "packaging_pipeline",
        "product_line_reuse",
        "control_plane",
        "infrastructure_reuse",
        "technical_link_relevant",
        "same_operator",
    }
)
_VERDICTS: Final[frozenset[str]] = frozenset({"valid", "invalid", "unknown"})
_OWNERSHIPS: Final[frozenset[str]] = frozenset(
    {
        "suspect_first_party",
        "inherited_official",
        "inherited_third_party",
        "shared_infrastructure",
        "unknown",
    }
)


@dataclass(frozen=True, slots=True)
class GroupEvaluation:
    provenance: EvaluationProvenance
    bcubed_precision: float | None
    bcubed_recall: float | None
    cannot_link_violation_count: int
    official_repack_mismerge_count: int
    evaluated_item_count: int
    gold_unclustered_count: int
    unpredicted_item_count: int


@dataclass(frozen=True, slots=True)
class ClueCandidate:
    clue_ref: str
    subject_sha256: str
    predicted_verdict: str
    predicted_ownership: str
    evidence_ref: str | None


@dataclass(frozen=True, slots=True)
class ClueEvaluation:
    provenance: EvaluationProvenance
    validity_precision: float | None
    ownership_precision: float | None
    valid_and_ownership_precision: float | None
    evidence_ref_completeness: float | None
    candidate_count: int
    top_count: int
    labeled_top_count: int
    unlabeled_top_count: int
    ownership_unknown_gold_count: int


def _validate_relation_subtypes(
    subtypes: tuple[str, ...],
    *,
    name: str,
    allow_empty: bool,
) -> frozenset[str]:
    if not isinstance(subtypes, tuple):
        _fail("predictions_invalid", f"{name} 必须为 tuple")
    if not allow_empty and not subtypes:
        _fail("predictions_invalid", f"{name} 不得为空")
    if any(
        not isinstance(subtype, str) or subtype not in _RELATION_SUBTYPES for subtype in subtypes
    ):
        _fail("predictions_invalid", f"{name} 含未知 relation_subtype")
    return frozenset(subtypes)


def _canonical_relation_pair(
    left_sha256: str,
    right_sha256: str,
) -> tuple[str, str]:
    if left_sha256 <= right_sha256:
        return left_sha256, right_sha256
    return right_sha256, left_sha256


def evaluate_groups(
    label_set: RecognitionLabelSet,
    manifest: SplitManifest,
    split_name: str,
    predicted_groups: tuple[tuple[str, ...], ...],
    *,
    layers: tuple[str, ...],
    positive_subtypes: tuple[str, ...],
    cannot_link_subtypes: tuple[str, ...],
    repack_subtypes: tuple[str, ...],
) -> GroupEvaluation:
    """评估指定切分上的分组结果与显式关系约束。"""
    _validate_split_name(split_name)
    selected_layers = _validate_layers(layers)
    selected_positive_subtypes = _validate_relation_subtypes(
        positive_subtypes,
        name="positive_subtypes",
        allow_empty=False,
    )
    selected_cannot_link_subtypes = _validate_relation_subtypes(
        cannot_link_subtypes,
        name="cannot_link_subtypes",
        allow_empty=True,
    )
    selected_repack_subtypes = _validate_relation_subtypes(
        repack_subtypes,
        name="repack_subtypes",
        allow_empty=True,
    )
    split_members = _split_members(manifest, split_name)

    if not isinstance(predicted_groups, tuple):
        _fail("predictions_invalid", "predicted_groups 必须为 tuple")

    predicted_group_by_sha: dict[str, frozenset[str]] = {}
    seen_predicted_members: set[str] = set()

    for group in predicted_groups:
        if not isinstance(group, tuple) or not group:
            _fail("predictions_invalid", "预测组必须为非空 tuple")

        group_members: set[str] = set()
        for sample_sha256 in group:
            if not _is_valid_sha256(sample_sha256):
                _fail(
                    "predictions_invalid",
                    f"预测组含非法 SHA-256: {sample_sha256!r}",
                )
            if sample_sha256 not in split_members:
                _fail(
                    "predictions_invalid",
                    f"预测组含切分外样本: {sample_sha256}",
                )
            if sample_sha256 in seen_predicted_members:
                _fail(
                    "predictions_invalid",
                    f"预测组成员重复: {sample_sha256}",
                )
            seen_predicted_members.add(sample_sha256)
            group_members.add(sample_sha256)

        frozen_group = frozenset(group_members)
        for sample_sha256 in frozen_group:
            predicted_group_by_sha[sample_sha256] = frozen_group

    parent: dict[str, str] = {}

    def find(sample_sha256: str) -> str:
        root = sample_sha256
        while parent[root] != root:
            root = parent[root]
        while parent[sample_sha256] != sample_sha256:
            next_sha256 = parent[sample_sha256]
            parent[sample_sha256] = root
            sample_sha256 = next_sha256
        return root

    def add_vertex(sample_sha256: str) -> None:
        if sample_sha256 not in parent:
            parent[sample_sha256] = sample_sha256

    def union(left_sha256: str, right_sha256: str) -> None:
        add_vertex(left_sha256)
        add_vertex(right_sha256)
        left_root = find(left_sha256)
        right_root = find(right_sha256)
        if left_root == right_root:
            return
        if left_root < right_root:
            parent[right_root] = left_root
        else:
            parent[left_root] = right_root

    consumed_records: list[RecognitionLabelRecord] = []
    cannot_link_pairs: set[tuple[str, str]] = set()
    repack_pairs: set[tuple[str, str]] = set()
    supported_positive_pairs: set[tuple[str, str]] = set()
    negative_endpoints: set[str] = set()

    for record in label_set.effective:
        if (
            record.kind != "relation_judgment"
            or record.layer not in selected_layers
            or record.left_sha256 is None
            or record.right_sha256 is None
            or record.left_sha256 not in split_members
            or record.right_sha256 not in split_members
        ):
            continue

        pair = _canonical_relation_pair(
            record.left_sha256,
            record.right_sha256,
        )
        consumed = False

        if record.relation == "positive" and record.relation_subtype in selected_positive_subtypes:
            union(record.left_sha256, record.right_sha256)
            supported_positive_pairs.add(pair)
            consumed = True

        if (
            record.relation == "negative"
            and record.relation_subtype in selected_cannot_link_subtypes
        ):
            cannot_link_pairs.add(pair)
            negative_endpoints.add(record.left_sha256)
            negative_endpoints.add(record.right_sha256)
            consumed = True

        if record.relation == "positive" and record.relation_subtype in selected_repack_subtypes:
            repack_pairs.add(pair)
            consumed = True

        if consumed:
            consumed_records.append(record)

    gold_members_by_root: dict[str, set[str]] = {}
    for sample_sha256 in sorted(parent):
        root = find(sample_sha256)
        gold_members_by_root.setdefault(root, set()).add(sample_sha256)

    gold_group_by_sha: dict[str, frozenset[str]] = {}
    for members in gold_members_by_root.values():
        frozen_members = frozenset(members)
        for sample_sha256 in frozen_members:
            gold_group_by_sha[sample_sha256] = frozen_members

    gold_items = tuple(sorted(gold_group_by_sha))
    gold_unclustered_count = len(negative_endpoints.difference(gold_group_by_sha))
    unpredicted_item_count = sum(
        1 for sample_sha256 in gold_items if sample_sha256 not in predicted_group_by_sha
    )

    precision_values: list[float] = []
    recall_values: list[float] = []

    for sample_sha256 in gold_items:
        gold_group = gold_group_by_sha[sample_sha256]
        predicted_group = predicted_group_by_sha.get(
            sample_sha256,
            frozenset({sample_sha256}),
        )
        intersection_count = len(gold_group.intersection(predicted_group))
        precision_values.append(intersection_count / len(predicted_group))
        recall_values.append(intersection_count / len(gold_group))

    evaluated_item_count = len(gold_items)
    if evaluated_item_count:
        bcubed_precision: float | None = sum(precision_values) / evaluated_item_count
        bcubed_recall: float | None = sum(recall_values) / evaluated_item_count
    else:
        bcubed_precision = None
        bcubed_recall = None

    def pair_is_in_same_predicted_group(pair: tuple[str, str]) -> bool:
        left_sha256, right_sha256 = pair
        left_group = predicted_group_by_sha.get(left_sha256)
        return left_group is not None and right_sha256 in left_group

    cannot_link_violation_count = sum(
        1 for pair in cannot_link_pairs if pair_is_in_same_predicted_group(pair)
    )
    official_repack_mismerge_count = sum(
        1
        for pair in repack_pairs
        if pair not in supported_positive_pairs and pair_is_in_same_predicted_group(pair)
    )

    layers_used = tuple(sorted({record.layer for record in consumed_records}))
    lineages_used = tuple(sorted({record.label_lineage for record in consumed_records}))
    label_count = len(consumed_records)
    promotion_eligible = derive_promotion_eligible(
        split_name=split_name,
        label_count=label_count,
        layers_used=layers_used,
        lineages_used=lineages_used,
        pair_task=False,
    )

    provenance = EvaluationProvenance(
        split_name=split_name,
        level=None,
        layers_used=layers_used,
        lineages_used=lineages_used,
        label_count=label_count,
        evaluated_count=evaluated_item_count,
        promotion_eligible=promotion_eligible,
    )
    return GroupEvaluation(
        provenance=provenance,
        bcubed_precision=bcubed_precision,
        bcubed_recall=bcubed_recall,
        cannot_link_violation_count=cannot_link_violation_count,
        official_repack_mismerge_count=official_repack_mismerge_count,
        evaluated_item_count=evaluated_item_count,
        gold_unclustered_count=gold_unclustered_count,
        unpredicted_item_count=unpredicted_item_count,
    )


def _clue_record_sort_key(
    record: RecognitionLabelRecord,
) -> tuple[str, str, str]:
    return (
        record.layer,
        record.label_lineage,
        record.record_id,
    )


def evaluate_clues(
    label_set: RecognitionLabelSet,
    manifest: SplitManifest,
    split_name: str,
    candidates: tuple[ClueCandidate, ...],
    *,
    top_n: int,
    layers: tuple[str, ...],
) -> ClueEvaluation:
    """评估指定切分上的线索候选优先级与标注一致性。"""
    _validate_split_name(split_name)
    selected_layers = _validate_layers(layers)

    if not isinstance(top_n, int) or isinstance(top_n, bool) or top_n < 1:
        _fail("predictions_invalid", "top_n 必须为不小于 1 的整数")
    if not isinstance(candidates, tuple):
        _fail("predictions_invalid", "candidates 必须为 tuple")

    split_members = _split_members(manifest, split_name)
    seen_clue_refs: set[str] = set()

    for candidate in candidates:
        if not isinstance(candidate, ClueCandidate):
            _fail("predictions_invalid", "candidates 含非 ClueCandidate 项")
        if not isinstance(candidate.clue_ref, str) or not candidate.clue_ref:
            _fail("predictions_invalid", "clue_ref 必须为非空字符串")
        if candidate.clue_ref in seen_clue_refs:
            _fail(
                "predictions_invalid",
                f"clue_ref 重复: {candidate.clue_ref!r}",
            )
        seen_clue_refs.add(candidate.clue_ref)

        if not _is_valid_sha256(candidate.subject_sha256):
            _fail(
                "predictions_invalid",
                f"线索载体 SHA-256 非法: {candidate.subject_sha256!r}",
            )
        if candidate.subject_sha256 not in split_members:
            _fail(
                "predictions_invalid",
                f"线索载体不属于目标切分: {candidate.subject_sha256}",
            )
        if candidate.predicted_verdict not in _VERDICTS:
            _fail(
                "predictions_invalid",
                f"非法 predicted_verdict: {candidate.predicted_verdict!r}",
            )
        if candidate.predicted_ownership not in _OWNERSHIPS:
            _fail(
                "predictions_invalid",
                f"非法 predicted_ownership: {candidate.predicted_ownership!r}",
            )
        if candidate.evidence_ref is not None and not isinstance(candidate.evidence_ref, str):
            _fail(
                "predictions_invalid",
                "evidence_ref 必须为字符串或 None",
            )

    top_candidates = candidates[:top_n]
    top_clue_refs = frozenset(candidate.clue_ref for candidate in top_candidates)

    records_by_clue_ref: dict[str, list[RecognitionLabelRecord]] = {}
    for record in label_set.effective:
        if (
            record.kind == "clue_judgment"
            and record.layer in selected_layers
            and record.clue_ref is not None
            and record.clue_ref in top_clue_refs
        ):
            records_by_clue_ref.setdefault(record.clue_ref, []).append(record)

    gold_by_clue_ref: dict[str, RecognitionLabelRecord] = {}
    for clue_ref in sorted(records_by_clue_ref):
        gold_by_clue_ref[clue_ref] = min(
            records_by_clue_ref[clue_ref],
            key=_clue_record_sort_key,
        )

    consumed_records = tuple(gold_by_clue_ref[clue_ref] for clue_ref in sorted(gold_by_clue_ref))

    labeled_candidates = tuple(
        candidate for candidate in top_candidates if candidate.clue_ref in gold_by_clue_ref
    )
    labeled_top_count = len(labeled_candidates)
    top_count = len(top_candidates)
    unlabeled_top_count = top_count - labeled_top_count

    valid_gold_count = 0
    ownership_correct_count = 0
    valid_and_ownership_correct_count = 0
    ownership_evaluable_count = 0
    ownership_unknown_gold_count = 0

    for candidate in labeled_candidates:
        gold = gold_by_clue_ref[candidate.clue_ref]
        ownership_correct = candidate.predicted_ownership == gold.ownership

        if gold.verdict == "valid":
            valid_gold_count += 1
            if ownership_correct:
                valid_and_ownership_correct_count += 1

        if gold.ownership == "unknown":
            ownership_unknown_gold_count += 1
        else:
            ownership_evaluable_count += 1
            if ownership_correct:
                ownership_correct_count += 1

    if labeled_top_count:
        validity_precision: float | None = valid_gold_count / labeled_top_count
        valid_and_ownership_precision: float | None = (
            valid_and_ownership_correct_count / labeled_top_count
        )
    else:
        validity_precision = None
        valid_and_ownership_precision = None

    if ownership_evaluable_count:
        ownership_precision: float | None = ownership_correct_count / ownership_evaluable_count
    else:
        ownership_precision = None

    if top_count:
        evidence_present_count = sum(
            1
            for candidate in top_candidates
            if (isinstance(candidate.evidence_ref, str) and bool(candidate.evidence_ref.strip()))
        )
        evidence_ref_completeness: float | None = evidence_present_count / top_count
    else:
        evidence_ref_completeness = None

    layers_used = tuple(sorted({record.layer for record in consumed_records}))
    lineages_used = tuple(sorted({record.label_lineage for record in consumed_records}))
    label_count = len(consumed_records)
    promotion_eligible = derive_promotion_eligible(
        split_name=split_name,
        label_count=label_count,
        layers_used=layers_used,
        lineages_used=lineages_used,
        pair_task=False,
    )

    provenance = EvaluationProvenance(
        split_name=split_name,
        level=None,
        layers_used=layers_used,
        lineages_used=lineages_used,
        label_count=label_count,
        evaluated_count=labeled_top_count,
        promotion_eligible=promotion_eligible,
    )
    return ClueEvaluation(
        provenance=provenance,
        validity_precision=validity_precision,
        ownership_precision=ownership_precision,
        valid_and_ownership_precision=valid_and_ownership_precision,
        evidence_ref_completeness=evidence_ref_completeness,
        candidate_count=len(candidates),
        top_count=top_count,
        labeled_top_count=labeled_top_count,
        unlabeled_top_count=unlabeled_top_count,
        ownership_unknown_gold_count=ownership_unknown_gold_count,
    )
