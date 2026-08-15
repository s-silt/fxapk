"""Aggregate-only offline evaluation for the deterministic linkage engine.

This module deliberately consumes :func:`rank_link_candidates` instead of
reimplementing candidate generation or scoring.  Returned data contains only
counts, ratios, fixed evidence-family names and fixed relation subtype names;
sample identities, case identifiers, IOC values and label paths never leave
the evaluator.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Set as AbstractSet
from dataclasses import dataclass
from itertools import combinations
import math
import re
from typing import Any

from apkscan.core.linkage import collapse_manifest_entries, rank_link_candidates
from apkscan.core.linkage_labels import (
    LINKAGE_FEATURE_FAMILIES,
    LinkageGroundTruth,
    LinkageLabelSet,
    build_linkage_ground_truth,
    project_independent_ground_truth,
)


EVALUATION_SCHEMA_VERSION = "1.1"

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_ENGINE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SAFE_SUPPORT_FAMILIES = frozenset({"remote_config", "native", "signing", "build", "ioc"})

#: rules-v2 回归档：与生产训练门槛**平行、永不相通**的一档。它只 gate「规则封顶正确性」
#: （独立确认的 hard negative 不得进入高优先复核档）这一条声明；ready 不解锁模型训练、
#: 不产出模型 artifact、不代表任何生产门槛达标。
#: ★档位是**枚举出来的内部常量**（closed set），不是可传参的门槛集——绝不提供
#: "调用方随便传一组小数字"的入口；训练侧另有政策下限强制（linkage_training），
#: 两边都改不动对方。
RULES_REGRESSION_TIER_ID = "rules-v2-cap-regression-v1"
RULES_REGRESSION_GATED_CLAIM = "rules_v2_hard_negative_cap_correctness"
_RULES_REGRESSION_MIN_HARD_NEGATIVE_PAIRS = 30
_RULES_REGRESSION_MIN_FAMILY_GROUPS = 3
_RULES_REGRESSION_DISCLAIMER = (
    "回归档只回归「规则封顶正确性」这一条声明；ready 不代表任何训练门槛达标，"
    "本档永不解锁模型训练、不产出模型 artifact。训练/发布仍由生产门槛独立 fail-closed。"
)


class LinkageEvaluationError(ValueError):
    """The evaluator received an invalid engine result or evaluation contract."""


@dataclass(frozen=True, slots=True)
class _CandidateView:
    pair: tuple[str, str]
    support_families: frozenset[str]
    high_priority: bool


@dataclass(frozen=True, slots=True)
class _EngineSummary:
    model_id: str
    feature_schema_version: str
    normalization_version: str
    policy_digest: str
    policy_status: str
    generation_status: str
    generated_pair_count: int
    overbroad_anchor_count: int
    pair_budget_exhausted: bool
    invalid_identity_record_count: int
    missing_repack_identity_record_count: int
    invalid_repack_identity_record_count: int


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _validate_ks(ks: Iterable[int]) -> tuple[int, ...]:
    values: set[int] = set()
    for value in ks:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise LinkageEvaluationError("ks must contain only positive integers")
        values.add(value)
    if not values:
        raise LinkageEvaluationError("ks must not be empty")
    return tuple(sorted(values))


def _candidate_sha(value: object, *, synthetic: bool) -> str | None:
    if synthetic:
        return None
    if not isinstance(value, str):
        raise LinkageEvaluationError("candidate identity has an invalid type")
    normalized = value.lower()
    if _SHA256_RE.fullmatch(normalized) is None:
        raise LinkageEvaluationError("candidate identity is not a real SHA-256")
    return normalized


def _finite_engine_number(value: object, field: str) -> float:
    if value is None:
        raise LinkageEvaluationError(f"candidate {field} is missing")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LinkageEvaluationError(f"candidate {field} is not numeric")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise LinkageEvaluationError(f"candidate {field} is non-finite") from exc
    if not math.isfinite(result):
        raise LinkageEvaluationError(f"candidate {field} is non-finite")
    return result


def _nonnegative_engine_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LinkageEvaluationError(f"engine {field} is invalid")
    return value


def _engine_token(value: object, field: str) -> str:
    if not isinstance(value, str) or _ENGINE_TOKEN_RE.fullmatch(value) is None:
        raise LinkageEvaluationError(f"engine {field} is invalid")
    return value


def _candidate_view(value: object) -> _CandidateView | None:
    if not isinstance(value, Mapping):
        raise LinkageEvaluationError("candidate must be an object")
    left = value.get("left")
    right = value.get("right")
    if not isinstance(left, Mapping) or not isinstance(right, Mapping):
        raise LinkageEvaluationError("candidate sides must be objects")
    left_synthetic = left.get("synthetic_identity", False)
    right_synthetic = right.get("synthetic_identity", False)
    if not isinstance(left_synthetic, bool) or not isinstance(right_synthetic, bool):
        raise LinkageEvaluationError("candidate synthetic flags must be boolean")
    left_sha = _candidate_sha(left.get("sample_sha256"), synthetic=left_synthetic)
    right_sha = _candidate_sha(right.get("sample_sha256"), synthetic=right_synthetic)
    if left_sha is None or right_sha is None:
        return None
    if left_sha == right_sha:
        raise LinkageEvaluationError("candidate contains a self-pair")
    pair = (left_sha, right_sha) if left_sha < right_sha else (right_sha, left_sha)

    supports = value.get("supporting_evidence")
    if not isinstance(supports, list):
        raise LinkageEvaluationError("candidate supporting_evidence must be a list")
    families: set[str] = set()
    for support in supports:
        if not isinstance(support, Mapping):
            raise LinkageEvaluationError("candidate evidence must be an object")
        family = support.get("family")
        if not isinstance(family, str) or family not in _SAFE_SUPPORT_FAMILIES:
            raise LinkageEvaluationError("candidate has an unsupported evidence family")
        families.add(family)

    review_score = _finite_engine_number(
        value.get("review_priority_score"), "review_priority_score"
    )
    if not 0.0 <= review_score <= 100.0:
        raise LinkageEvaluationError("candidate review_priority_score is outside 0..100")
    if "score" in value:
        _finite_engine_number(value.get("score"), "score")
    if "uncapped_score" in value:
        _finite_engine_number(value.get("uncapped_score"), "uncapped_score")
    strong_count = value.get("strong_family_count")
    if isinstance(strong_count, bool) or not isinstance(strong_count, int) or strong_count < 0:
        raise LinkageEvaluationError("candidate strong_family_count is invalid")
    # Use the numeric policy output plus independent support-family count, not
    # presentation-level names.  This includes corroborated native+build pairs
    # while ensuring a single high-weight anchor cannot enter the high slice.
    high_priority = review_score >= 75.0 and len(families) >= 2
    return _CandidateView(pair, frozenset(families), high_priority)


def _sample_inventory(entries: list[dict[str, Any]]) -> tuple[set[str], int, int]:
    real: set[str] = set()
    synthetic_count = 0
    samples = collapse_manifest_entries(entries)
    for sample in samples:
        normalized = sample.sample_sha256.lower()
        if sample.synthetic_identity:
            synthetic_count += 1
            continue
        if _SHA256_RE.fullmatch(normalized) is None:
            raise LinkageEvaluationError("manifest contains a non-SHA sample identity")
        real.add(normalized)
    return real, len(samples), synthetic_count


def _parse_engine_candidates(
    result: object,
) -> tuple[list[_CandidateView], int, int, _EngineSummary]:
    if not isinstance(result, Mapping):
        raise LinkageEvaluationError("rank_link_candidates returned a non-object")
    raw_candidates = result.get("candidates")
    if not isinstance(raw_candidates, list):
        raise LinkageEvaluationError("engine candidates must be a list")
    candidates: list[_CandidateView] = []
    synthetic_count = 0
    seen: set[tuple[str, str]] = set()
    for raw in raw_candidates:
        candidate = _candidate_view(raw)
        if candidate is None:
            synthetic_count += 1
            continue
        if candidate.pair in seen:
            raise LinkageEvaluationError("engine returned a duplicate candidate pair")
        seen.add(candidate.pair)
        candidates.append(candidate)

    total = result.get("total_before_limit")
    if isinstance(total, bool) or not isinstance(total, int) or total < len(raw_candidates):
        raise LinkageEvaluationError("engine total_before_limit is invalid")
    if total != len(raw_candidates):
        raise LinkageEvaluationError("evaluation requires an untruncated candidate result")
    truncated = result.get("truncated_anchors", [])
    if not isinstance(truncated, list):
        raise LinkageEvaluationError("engine truncated_anchors must be a list")

    model = result.get("model")
    generation = result.get("candidate_generation")
    engine_input = result.get("input")
    if not isinstance(model, Mapping):
        raise LinkageEvaluationError("engine model contract is missing")
    if not isinstance(generation, Mapping):
        raise LinkageEvaluationError("engine candidate_generation contract is missing")
    if not isinstance(engine_input, Mapping):
        raise LinkageEvaluationError("engine input contract is missing")
    status = result.get("status")
    generation_status = generation.get("status")
    if status not in {"complete", "partial"} or generation_status != status:
        raise LinkageEvaluationError("engine generation status is invalid")
    generated_pair_count = _nonnegative_engine_int(
        generation.get("generated_pair_count"), "generated_pair_count"
    )
    overbroad_anchor_count = _nonnegative_engine_int(
        generation.get("overbroad_anchor_count"), "overbroad_anchor_count"
    )
    pair_budget_exhausted = generation.get("pair_budget_exhausted")
    if not isinstance(pair_budget_exhausted, bool):
        raise LinkageEvaluationError("engine pair_budget_exhausted is invalid")
    invalid_identity_count = _nonnegative_engine_int(
        engine_input.get("invalid_sample_identity_record_count"),
        "invalid_sample_identity_record_count",
    )
    missing_repack_identity_count = _nonnegative_engine_int(
        engine_input.get("missing_repack_identity_record_count"),
        "missing_repack_identity_record_count",
    )
    invalid_repack_identity_count = _nonnegative_engine_int(
        engine_input.get("invalid_repack_identity_record_count"),
        "invalid_repack_identity_record_count",
    )
    if generated_pair_count != total or overbroad_anchor_count != len(truncated):
        raise LinkageEvaluationError("engine generation counts are inconsistent")
    if (
        overbroad_anchor_count
        or pair_budget_exhausted
        or invalid_identity_count
        or missing_repack_identity_count
        or invalid_repack_identity_count
    ) and status != "partial":
        raise LinkageEvaluationError("engine suppressed input must be marked partial")

    policy_digest = model.get("policy_digest")
    if not isinstance(policy_digest, str) or _SHA256_RE.fullmatch(policy_digest) is None:
        raise LinkageEvaluationError("engine policy_digest is invalid")
    policy_status = model.get("policy_status")
    if policy_status not in {"complete", "partial"}:
        raise LinkageEvaluationError("engine policy_status is invalid")
    if policy_status == "partial" and status != "partial":
        raise LinkageEvaluationError("partial engine policy must mark generation partial")
    summary = _EngineSummary(
        model_id=_engine_token(model.get("id"), "model id"),
        feature_schema_version=_engine_token(
            model.get("feature_schema_version"), "feature_schema_version"
        ),
        normalization_version=_engine_token(
            model.get("normalization_version"), "normalization_version"
        ),
        policy_digest=policy_digest,
        policy_status=policy_status,
        generation_status=status,
        generated_pair_count=generated_pair_count,
        overbroad_anchor_count=overbroad_anchor_count,
        pair_budget_exhausted=pair_budget_exhausted,
        invalid_identity_record_count=invalid_identity_count,
        missing_repack_identity_record_count=missing_repack_identity_count,
        invalid_repack_identity_record_count=invalid_repack_identity_count,
    )
    return candidates, synthetic_count, len(truncated), summary


def _queue_counts(
    ranked: list[_CandidateView], truth: LinkageGroundTruth, limit: int
) -> dict[str, int | float | None]:
    top = ranked[:limit]
    positive = sum(candidate.pair in truth.positive_pairs for candidate in top)
    negative = sum(candidate.pair in truth.negative_pairs for candidate in top)
    unknown = sum(candidate.pair in truth.unknown_pairs for candidate in top)
    unlabelled = len(top) - positive - negative - unknown
    return {
        "candidate_count": len(top),
        "positive_count": positive,
        "negative_count": negative,
        "unknown_count": unknown,
        "unlabelled_count": unlabelled,
        "judged_precision": _ratio(positive, positive + negative),
    }


def _judged_ranking_metrics(
    ranked: list[_CandidateView],
    truth: LinkageGroundTruth,
    present_positives: set[tuple[str, str]],
    ks: tuple[int, ...],
) -> dict[str, object]:
    judged = [
        candidate
        for candidate in ranked
        if candidate.pair in truth.positive_pairs or candidate.pair in truth.negative_pairs
    ]
    at_k: dict[str, dict[str, int | float | None]] = {}
    for k in ks:
        top = judged[:k]
        positives = sum(candidate.pair in truth.positive_pairs for candidate in top)
        negatives = len(top) - positives
        dcg = sum(
            1.0 / math.log2(rank + 1)
            for rank, candidate in enumerate(top, start=1)
            if candidate.pair in truth.positive_pairs
        )
        ideal_hits = min(k, len(present_positives))
        idcg = sum(1.0 / math.log2(rank + 1) for rank in range(1, ideal_hits + 1))
        at_k[str(k)] = {
            "judged_candidate_count": len(top),
            "positive_count": positives,
            "negative_count": negatives,
            "precision": _ratio(positives, positives + negatives),
            "recall": _ratio(positives, len(present_positives)),
            "ndcg": (dcg / idcg) if idcg else None,
        }

    hits = 0
    precision_sum = 0.0
    dcg = 0.0
    for rank, candidate in enumerate(judged, start=1):
        if candidate.pair not in truth.positive_pairs:
            continue
        hits += 1
        precision_sum += hits / rank
        dcg += 1.0 / math.log2(rank + 1)
    idcg = sum(1.0 / math.log2(rank + 1) for rank in range(1, len(present_positives) + 1))
    return {
        "candidate_count": len(judged),
        "average_precision": (
            precision_sum / len(present_positives) if present_positives else None
        ),
        "ndcg": (dcg / idcg) if idcg else None,
        "at_k": at_k,
    }


def _raw_queue_position_metrics(
    ranked: list[_CandidateView],
    truth: LinkageGroundTruth,
    present_positives: set[tuple[str, str]],
    ks: tuple[int, ...],
) -> dict[str, object]:
    """Measure positive positions without deleting unlabelled queue entries."""
    at_k: dict[str, dict[str, int | float | None]] = {}
    for k in ks:
        top = ranked[:k]
        positive = sum(candidate.pair in truth.positive_pairs for candidate in top)
        negative = sum(candidate.pair in truth.negative_pairs for candidate in top)
        unknown = sum(candidate.pair in truth.unknown_pairs for candidate in top)
        at_k[str(k)] = {
            "reviewed_candidate_count": len(top),
            "observed_positive_count": positive,
            "observed_negative_count": negative,
            "unknown_label_count": unknown,
            "unlabelled_count": len(top) - positive - negative - unknown,
            "observed_positive_yield": _ratio(positive, len(top)),
            "positive_recall": _ratio(positive, len(present_positives)),
        }

    hits = 0
    precision_sum = 0.0
    dcg = 0.0
    first_positive_rank: int | None = None
    for rank, candidate in enumerate(ranked, start=1):
        if candidate.pair not in truth.positive_pairs:
            continue
        if first_positive_rank is None:
            first_positive_rank = rank
        hits += 1
        precision_sum += hits / rank
        dcg += 1.0 / math.log2(rank + 1)
    idcg = sum(1.0 / math.log2(rank + 1) for rank in range(1, len(present_positives) + 1))
    return {
        "candidate_count": len(ranked),
        "average_precision_at_raw_positions": (
            precision_sum / len(present_positives) if present_positives else None
        ),
        "ndcg_at_raw_positions": (dcg / idcg) if idcg else None,
        "first_positive_rank": first_positive_rank,
        "at_k": at_k,
        "unlabelled_candidates_retained": True,
    }


def _label_feature_leakage_matrix(
    truth: LinkageGroundTruth,
) -> dict[str, dict[str, int]]:
    features_by_pair = truth.leakage.feature_families_by_pair()
    result: dict[str, dict[str, int]] = {}
    for family in sorted(LINKAGE_FEATURE_FAMILIES):
        result[family] = {
            "positive_pair_count": sum(
                family in features_by_pair[pair] for pair in truth.positive_pairs
            ),
            "negative_pair_count": sum(
                family in features_by_pair[pair] for pair in truth.negative_pairs
            ),
            "unknown_pair_count": sum(
                family in features_by_pair[pair] for pair in truth.unknown_pairs
            ),
        }
    return result


def _sample_neighbor_recall(
    ranked: list[_CandidateView],
    present_positives: set[tuple[str, str]],
    ks: tuple[int, ...],
) -> dict[str, dict[str, int | float | None]]:
    positive_neighbors: dict[str, set[str]] = defaultdict(set)
    for left, right in present_positives:
        positive_neighbors[left].add(right)
        positive_neighbors[right].add(left)
    incident: dict[str, list[str]] = defaultdict(list)
    for candidate in ranked:
        left, right = candidate.pair
        incident[left].append(right)
        incident[right].append(left)

    result: dict[str, dict[str, int | float | None]] = {}
    denominator = len(positive_neighbors)
    for k in ks:
        found = sum(
            bool(set(incident.get(sample, [])[:k]) & neighbors)
            for sample, neighbors in positive_neighbors.items()
        )
        result[str(k)] = {
            "eligible_sample_count": denominator,
            "sample_count_with_positive_neighbor": found,
            "recall": _ratio(found, denominator),
        }
    return result


def _family_macro_recall(
    truth: LinkageGroundTruth,
    present_samples: set[str],
    retrieved: set[tuple[str, str]],
) -> dict[str, int | float | None]:
    recalls: list[float] = []
    for group in truth.family_groups:
        members = sorted(set(group.members) & present_samples)
        if len(members) < 2:
            continue
        pairs = {
            tuple(pair) for pair in combinations(members, 2) if tuple(pair) in truth.positive_pairs
        }
        if not pairs:
            continue
        recalls.append(len(pairs & retrieved) / len(pairs))
    return {
        "family_group_count": len(truth.family_groups),
        "evaluable_family_group_count": len(recalls),
        "positive_pair_recall": (sum(recalls) / len(recalls)) if recalls else None,
    }


def _subtype_metrics(
    truth: LinkageGroundTruth,
    present_samples: set[str],
    retrieved: set[tuple[str, str]],
) -> dict[str, dict[str, int | float | None]]:
    result: dict[str, dict[str, int | float | None]] = {}
    for subtype, positives in truth.positive_by_subtype:
        present = {
            pair for pair in positives if pair[0] in present_samples and pair[1] in present_samples
        }
        result[subtype] = {
            "positive_pair_count": len(positives),
            "indexable_positive_pair_count": len(present),
            "retrieved_positive_pair_count": len(present & retrieved),
            "positive_pair_recall": _ratio(len(present & retrieved), len(present)),
        }
    return result


def _slice_metrics(
    candidates: list[_CandidateView], truth: LinkageGroundTruth
) -> dict[str, int | float | None]:
    positive = sum(candidate.pair in truth.positive_pairs for candidate in candidates)
    negative = sum(candidate.pair in truth.negative_pairs for candidate in candidates)
    unknown = sum(candidate.pair in truth.unknown_pairs for candidate in candidates)
    return {
        "candidate_count": len(candidates),
        "positive_count": positive,
        "negative_count": negative,
        "unknown_count": unknown,
        "unlabelled_count": len(candidates) - positive - negative - unknown,
        "judged_precision": _ratio(positive, positive + negative),
    }


def _bridge_error_count(
    retrieved_negatives: AbstractSet[tuple[str, str]], truth: LinkageGroundTruth
) -> int:
    memberships: dict[str, dict[str, str]] = defaultdict(dict)
    for group in truth.family_groups:
        for sample in group.members:
            memberships[group.relation_subtype][sample] = group.family_id
    count = 0
    for left, right in retrieved_negatives:
        if any(
            left in by_sample and right in by_sample and by_sample[left] != by_sample[right]
            for by_sample in memberships.values()
        ):
            count += 1
    return count


def _present_family_group_count(
    all_truth: LinkageGroundTruth, present_samples: set[str]
) -> int:
    """Count confirmed family groups with at least two members in the corpus.

    回归档的"家族多样性"语境不要求家族标签独立于特征（那是训练/晋级指标的要求）：
    现有种子族多以 native/build 为定义依据，属 feature-overlapping，但对「hard negative
    的封顶回归是否横跨多个族群语境」而言仍是有效的多样性证据。按 family_id 去重，
    同一族在多个 relation_subtype 下不重复计数。
    """
    return len(
        {
            group.family_id
            for group in all_truth.family_groups
            if sum(member in present_samples for member in group.members) >= 2
        }
    )


def _rules_cap_regression_block(
    *,
    labeled_independent_hard_negative_pair_count: int,
    recalled_independent_hard_negative_pair_count: int,
    confirmed_family_group_count: int,
    hard_negative_high_priority_count: int,
    candidate_generation_complete: bool,
) -> dict[str, object]:
    """Build the self-identifying rules-v2 cap-regression tier decision."""
    thresholds = {
        "min_hard_negative_pairs": _RULES_REGRESSION_MIN_HARD_NEGATIVE_PAIRS,
        "min_family_groups": _RULES_REGRESSION_MIN_FAMILY_GROUPS,
    }
    # 门槛压在**被规则召回**的独立 hard negative 上：未被召回的 pair 不会出现在复核队列里，
    # 封顶正确与否对它是空命题；只有被召回的那部分才真正检验了封顶。
    unmet: list[dict[str, int | str]] = []
    if (
        recalled_independent_hard_negative_pair_count
        < _RULES_REGRESSION_MIN_HARD_NEGATIVE_PAIRS
    ):
        unmet.append(
            {
                "metric": "recalled_independent_hard_negative_pair_count",
                "actual": recalled_independent_hard_negative_pair_count,
                "required": _RULES_REGRESSION_MIN_HARD_NEGATIVE_PAIRS,
            }
        )
    if confirmed_family_group_count < _RULES_REGRESSION_MIN_FAMILY_GROUPS:
        unmet.append(
            {
                "metric": "confirmed_family_group_count",
                "actual": confirmed_family_group_count,
                "required": _RULES_REGRESSION_MIN_FAMILY_GROUPS,
            }
        )
    generation_unmet = not candidate_generation_complete
    if generation_unmet:
        # partial 队列上的"0 误报"不可信：被预算/超宽锚抑制的候选里可能正藏着未封顶的
        # hard negative——fail closed，不在不完整队列上支持声明。
        unmet.append({"metric": "candidate_generation_complete", "actual": 0, "required": 1})
    ready = not unmet
    if ready:
        reason = None
    elif generation_unmet and len(unmet) == 1:
        reason = "candidate_generation_incomplete"
    else:
        reason = "insufficient_regression_labels"
    return {
        "tier": RULES_REGRESSION_TIER_ID,
        "experimental": True,
        "status": "ready_for_cap_regression" if ready else "blocked",
        "reason": reason,
        "gated_claim": RULES_REGRESSION_GATED_CLAIM,
        # ready 前不给出声明结论（None），ready 后由"召回的独立 hard negative 高优先误报
        # 是否为 0"直接判定——这就是本档 gate 的那一条声明，别的什么都不背书。
        "claim_supported": (
            (hard_negative_high_priority_count == 0) if ready else None
        ),
        "thresholds": thresholds,
        "counts": {
            "labeled_independent_hard_negative_pair_count": (
                labeled_independent_hard_negative_pair_count
            ),
            "recalled_independent_hard_negative_pair_count": (
                recalled_independent_hard_negative_pair_count
            ),
            "confirmed_family_group_count": confirmed_family_group_count,
            "hard_negative_high_priority_count": hard_negative_high_priority_count,
        },
        "unmet": unmet,
        "model_training": {
            "gated_by_this_tier": False,
            "unlocked_by_this_tier": False,
            "authority": "production_readiness_thresholds_only",
        },
        "produces_model_artifact": False,
        "privacy": {"aggregate_only": True, "contains_raw_identifiers": False},
        "disclaimer": _RULES_REGRESSION_DISCLAIMER,
    }


def assess_rules_regression_readiness(
    entries: Iterable[dict[str, Any]],
    labels: LinkageLabelSet,
) -> dict[str, object]:
    """Gate only the rules-v2 hard-negative cap-regression claim.

    刻意**不接受**门槛参数：回归档是枚举的内部档位（closed set），没有任何参数 / 环境变量 /
    配置项可以调整它或让它冒充生产档。本函数零写入、零 artifact，输出只有聚合计数。
    """
    if not isinstance(labels, LinkageLabelSet):
        raise TypeError("labels must be a LinkageLabelSet")
    entry_list = list(entries)
    present_samples, _sample_count, _synthetic_count = _sample_inventory(entry_list)
    all_truth = build_linkage_ground_truth(labels)
    truth = project_independent_ground_truth(all_truth)
    ranked, _synthetic_candidates, _truncated, engine_summary = _parse_engine_candidates(
        rank_link_candidates(entry_list, limit=None)
    )
    retrieved = {candidate.pair for candidate in ranked}
    return _rules_cap_regression_block(
        labeled_independent_hard_negative_pair_count=len(truth.hard_negative_pairs),
        recalled_independent_hard_negative_pair_count=len(
            retrieved & truth.hard_negative_pairs
        ),
        confirmed_family_group_count=_present_family_group_count(
            all_truth, present_samples
        ),
        hard_negative_high_priority_count=sum(
            candidate.pair in truth.hard_negative_pairs and candidate.high_priority
            for candidate in ranked
        ),
        candidate_generation_complete=engine_summary.generation_status == "complete",
    )


def evaluate_linkage_rules(
    entries: Iterable[dict[str, Any]],
    labels: LinkageLabelSet,
    *,
    ks: Iterable[int] = (1, 5, 20),
) -> dict[str, object]:
    """Evaluate the current deterministic ranker without returning private values."""
    if not isinstance(labels, LinkageLabelSet):
        raise TypeError("labels must be a LinkageLabelSet")
    cutoffs = _validate_ks(ks)
    entry_list = list(entries)
    present_samples, sample_count, synthetic_sample_count = _sample_inventory(entry_list)
    all_truth = build_linkage_ground_truth(labels)
    truth = project_independent_ground_truth(all_truth)

    engine_result = rank_link_candidates(entry_list, limit=None)
    (
        ranked,
        synthetic_candidate_count,
        truncated_anchor_count,
        engine_summary,
    ) = _parse_engine_candidates(engine_result)
    retrieved = {candidate.pair for candidate in ranked}
    possible_pairs = len(present_samples) * (len(present_samples) - 1) // 2
    if len(ranked) > possible_pairs:
        raise LinkageEvaluationError("engine returned more candidates than possible pairs")

    present_positives = {
        pair
        for pair in truth.positive_pairs
        if pair[0] in present_samples and pair[1] in present_samples
    }
    present_negatives = {
        pair
        for pair in truth.negative_pairs
        if pair[0] in present_samples and pair[1] in present_samples
    }
    retrieved_positives = present_positives & retrieved
    retrieved_negatives = present_negatives & retrieved
    hard_negative_high_priority = sum(
        candidate.pair in truth.hard_negative_pairs and candidate.high_priority
        for candidate in ranked
    )

    slices = {
        "native_only": _slice_metrics(
            [candidate for candidate in ranked if candidate.support_families == {"native"}],
            truth,
        ),
        "single_anchor_family": _slice_metrics(
            [candidate for candidate in ranked if len(candidate.support_families) == 1],
            truth,
        ),
        "multi_anchor_family": _slice_metrics(
            [candidate for candidate in ranked if len(candidate.support_families) >= 2],
            truth,
        ),
    }

    queue_at_k = {str(k): _queue_counts(ranked, truth, k) for k in cutoffs}
    status_counts = dict(labels.status_counts)
    effective_confirmed = sum(record.status == "confirmed" for record in labels.effective_records)
    has_evaluable_independent_binary_truth = bool(present_positives) and bool(
        present_negatives
    )
    evaluation_status = (
        "insufficient_independent_labels"
        if not has_evaluable_independent_binary_truth
        else engine_summary.generation_status
    )
    overlap_positive = all_truth.positive_pairs - truth.positive_pairs
    overlap_negative = all_truth.negative_pairs - truth.negative_pairs
    overlap_unknown = all_truth.unknown_pairs - truth.unknown_pairs
    return {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "status": evaluation_status,
        "experimental": True,
        "engine": {
            "kind": "deterministic_rule_baseline",
            "entrypoint": "rank_link_candidates",
            "id": engine_summary.model_id,
            "feature_schema_version": engine_summary.feature_schema_version,
            "normalization_version": engine_summary.normalization_version,
            "policy_digest": engine_summary.policy_digest,
            "policy_status": engine_summary.policy_status,
        },
        "candidate_generation": {
            "status": engine_summary.generation_status,
            "generated_pair_count": engine_summary.generated_pair_count,
            "overbroad_anchor_count": engine_summary.overbroad_anchor_count,
            "pair_budget_exhausted": engine_summary.pair_budget_exhausted,
            "invalid_sample_identity_record_count": (engine_summary.invalid_identity_record_count),
            "missing_repack_identity_record_count": (
                engine_summary.missing_repack_identity_record_count
            ),
            "invalid_repack_identity_record_count": (
                engine_summary.invalid_repack_identity_record_count
            ),
            # Compatibility alias for aggregate consumers of evaluation schema 1.0.
            "legacy_repack_identity_record_count": (
                engine_summary.missing_repack_identity_record_count
            ),
        },
        "labels": {
            "record_count": labels.record_count,
            "effective_record_count": len(labels.effective_records),
            "effective_confirmed_record_count": effective_confirmed,
            "status_counts": status_counts,
            "positive_pair_count": len(all_truth.positive_pairs),
            "negative_pair_count": len(all_truth.negative_pairs),
            "unknown_pair_count": len(all_truth.unknown_pairs),
            "hard_negative_pair_count": len(all_truth.hard_negative_pairs),
            "independent_positive_pair_count": len(truth.positive_pairs),
            "independent_negative_pair_count": len(truth.negative_pairs),
            "independent_unknown_pair_count": len(truth.unknown_pairs),
            "independent_hard_negative_pair_count": len(truth.hard_negative_pairs),
            "feature_overlap_excluded_positive_pair_count": len(overlap_positive),
            "feature_overlap_excluded_negative_pair_count": len(overlap_negative),
            "feature_overlap_excluded_unknown_pair_count": len(overlap_unknown),
            "missing_basis_pair_count": 0,
        },
        "label_feature_independence": {
            "status": (
                "sufficient"
                if has_evaluable_independent_binary_truth
                else "insufficient_independent_labels"
            ),
            "promotion_metrics_use_independent_pairs_only": True,
            "present_independent_positive_pair_count": len(present_positives),
            "present_independent_negative_pair_count": len(present_negatives),
            "feature_overlap_excluded_pair_count": len(
                overlap_positive | overlap_negative | overlap_unknown
            ),
            "missing_basis_pair_count": 0,
            "leakage_matrix": _label_feature_leakage_matrix(all_truth),
        },
        "corpus": {
            "record_count": len(entry_list),
            "sample_count": sample_count,
            "real_sample_count": len(present_samples),
            "synthetic_sample_count": synthetic_sample_count,
        },
        "retrieval": {
            "positive_pair_count": len(truth.positive_pairs),
            "indexable_positive_pair_count": len(present_positives),
            "retrieved_positive_pair_count": len(retrieved_positives),
            "positive_pair_candidate_recall": _ratio(
                len(retrieved_positives), len(truth.positive_pairs)
            ),
            "indexable_positive_pair_recall": _ratio(
                len(retrieved_positives), len(present_positives)
            ),
            "missing_from_corpus_positive_pair_count": (
                len(truth.positive_pairs) - len(present_positives)
            ),
            "sample_neighbor_recall_at_k": _sample_neighbor_recall(
                ranked, present_positives, cutoffs
            ),
            "family_macro": _family_macro_recall(truth, present_samples, retrieved),
            "relation_subtypes": _subtype_metrics(truth, present_samples, retrieved),
        },
        "ranking": {
            "raw_queue_at_k": queue_at_k,
            "raw_candidate_queue": _raw_queue_position_metrics(
                ranked, truth, present_positives, cutoffs
            ),
            "pool_conditioned_judged_only": _judged_ranking_metrics(
                ranked, truth, present_positives, cutoffs
            ),
        },
        "coverage": {
            "candidate_count": len(ranked),
            "synthetic_candidate_count_excluded": synthetic_candidate_count,
            "possible_real_sample_pair_count": possible_pairs,
            "candidate_pair_fraction": _ratio(len(ranked), possible_pairs),
            "pair_reduction_fraction": (
                1.0 - (len(ranked) / possible_pairs) if possible_pairs else None
            ),
            "candidates_per_real_sample": _ratio(len(ranked), len(present_samples)),
            "judged_candidate_count": len(
                retrieved & (truth.positive_pairs | truth.negative_pairs)
            ),
            "unknown_candidate_count": len(retrieved & truth.unknown_pairs),
            "unlabelled_candidate_count": len(
                retrieved - truth.positive_pairs - truth.negative_pairs - truth.unknown_pairs
            ),
            "truncated_anchor_count": truncated_anchor_count,
            "candidate_generation_partial": engine_summary.generation_status == "partial",
        },
        "errors": {
            "confirmed_negative_candidate_count": len(retrieved_negatives),
            "bridge_error_count": _bridge_error_count(retrieved_negatives, truth),
            "retrieved_hard_negative_count": len(retrieved & truth.hard_negative_pairs),
            "hard_negative_high_priority_count": hard_negative_high_priority,
        },
        # rules-v2 回归档：只 gate「规则封顶正确性」声明（见块内 disclaimer），与上面的
        # 晋级/训练指标互不背书。计数与 errors 节同源（同一 ranked/truth），不另算一遍。
        "rules_cap_regression": _rules_cap_regression_block(
            labeled_independent_hard_negative_pair_count=len(truth.hard_negative_pairs),
            recalled_independent_hard_negative_pair_count=len(
                retrieved & truth.hard_negative_pairs
            ),
            confirmed_family_group_count=_present_family_group_count(
                all_truth, present_samples
            ),
            hard_negative_high_priority_count=hard_negative_high_priority,
            candidate_generation_complete=engine_summary.generation_status == "complete",
        ),
        "slices": slices,
        "privacy": {
            "aggregate_only": True,
            "contains_raw_identifiers": False,
            "contains_raw_evidence_values": False,
        },
        "disclaimer": (
            "聚合结果只评估技术关联候选排序，不代表同一运营主体；仅独立标签进入晋级指标，"
            "pool-conditioned 指标会删除未标候选，raw queue 指标保留其真实位置。"
        ),
    }
