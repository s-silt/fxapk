"""Threshold-gated, group-disjoint training for the optional linkage challenger.

The module never reads private paths and never writes artifacts.  Callers pass
already-authoritative manifest rows and a validated label set.  Scikit-learn is
imported only after every readiness and split gate succeeds.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import json
import math
import re
from typing import Any

from apkscan import __version__ as FXAPK_VERSION
from apkscan.core.linkage import (
    LinkagePreprocessingContext,
    _entry_sample_identity,
    fit_linkage_preprocessing_context,
    rank_link_candidates,
)
from apkscan.core.linkage_labels import (
    LinkageLabelSet,
    LinkageGroundTruth,
    build_linkage_ground_truth,
    project_independent_ground_truth,
)
from apkscan.core.linkage_ml import (
    LINKAGE_ML_MODEL_ID,
    ML_SCORE_SEMANTICS,
    MODEL_ARTIFACT_SCHEMA_VERSION,
    PAIR_FEATURE_NAMES,
    PAIR_FEATURE_SCHEMA_VERSION,
    READINESS_POLICY_FLOOR,
    current_rule_engine_contract,
    extract_pair_features,
    feature_vector,
    seal_linkage_model_artifact,
)


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SKLEARN_SEED = 2**32 - 1

TRAINING_WEIGHTING_VERSION = "component-balanced-v1"
TRAINING_PREPROCESSING_SCOPE = "train-partition-frozen-v1"


class TrainingDataError(ValueError):
    """The labelled candidate dataset violates the training contract."""


class TrainingDependencyError(RuntimeError):
    """The optional local training dependency is unavailable."""


@dataclass(frozen=True, slots=True)
class ReadinessThresholds:
    min_real_samples: int = 200
    min_family_groups: int = 10
    min_positive_pairs: int = 300
    min_negative_pairs: int = 600
    min_hard_negative_pairs: int = 500

    def __post_init__(self) -> None:
        for value in self.as_dict().values():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("readiness thresholds must be non-negative integers")

    def as_dict(self) -> dict[str, int]:
        return {
            "min_real_samples": self.min_real_samples,
            "min_family_groups": self.min_family_groups,
            "min_positive_pairs": self.min_positive_pairs,
            "min_negative_pairs": self.min_negative_pairs,
            "min_hard_negative_pairs": self.min_hard_negative_pairs,
        }


DEFAULT_READINESS_THRESHOLDS = ReadinessThresholds()


def _require_policy_floor(thresholds: ReadinessThresholds) -> None:
    """生产门禁不信任调用方传入的门槛：逐字段强制政策下限。

    ★`ReadinessThresholds.__post_init__` 只保证"非负整数"，挡不住
    `ReadinessThresholds(0, 0, 0, 0, 0)` 这类把门槛压到 0 的调用——一旦独立正负样本各有
    极少量，门禁就会放行并产出 artifact。政策下限（:data:`READINESS_POLICY_FLOOR`，
    与 artifact 校验侧共用同一真源）在三个门禁入口内部强制：调用方可以**抬高**门槛，
    不能**降低**。测试需要小门槛时在测试内 monkeypatch 本模块常量，不提供任何
    生产参数 / 环境变量 / 配置开关。
    """
    supplied = thresholds.as_dict()
    lowered = sorted(
        name
        for name, minimum in READINESS_POLICY_FLOOR.items()
        if supplied.get(name, 0) < minimum
    )
    if lowered:
        raise ValueError(
            "readiness thresholds below the policy floor: " + ", ".join(lowered)
        )


@dataclass(frozen=True, slots=True)
class TrainingRow:
    pair: tuple[str, str]
    features: tuple[float, ...]
    target: int
    hard_negative: bool


@dataclass(frozen=True, slots=True)
class TrainingDataset:
    rows: tuple[TrainingRow, ...]
    component_by_sample: tuple[tuple[str, str], ...]
    candidate_generation_complete: bool
    real_sample_count: int
    family_group_count: int
    positive_pair_count: int
    negative_pair_count: int
    hard_negative_pair_count: int
    independent_label_positive_pair_count: int
    independent_label_negative_pair_count: int
    #: 声明侧对照列：双侧样本都在当前 manifest、且 sampling_class 声明为 hard 的独立确认负例。
    #: 与门禁输入 :attr:`hard_negative_pair_count`（声明 ∧ 被 ranker 召回）的差值 =
    #: 「声明了 hard 但当前规则并不召回」的对数——标注而非删除，供人工比对声明与结构的漂移。
    independent_label_hard_negative_pair_count: int
    feature_overlap_excluded_positive_pair_count: int
    feature_overlap_excluded_negative_pair_count: int
    missing_basis_pair_count: int
    dataset_digest: str

    def components(self) -> dict[str, str]:
        return dict(self.component_by_sample)


@dataclass(frozen=True, slots=True)
class GroupDisjointSplit:
    train_rows: tuple[TrainingRow, ...]
    test_rows: tuple[TrainingRow, ...]
    dropped_cross_split_pair_count: int
    train_components: tuple[str, ...]
    test_components: tuple[str, ...]
    split_digest: str


@dataclass(frozen=True, slots=True)
class ManifestEntrySplit:
    train_entries: tuple[dict[str, Any], ...]
    test_entries: tuple[dict[str, Any], ...]
    component_by_sample: tuple[tuple[str, str], ...]
    train_components: tuple[str, ...]
    test_components: tuple[str, ...]
    dropped_cross_split_pair_count: int
    split_digest: str


class _UnionFind:
    def __init__(self, values: Iterable[str]) -> None:
        self._parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self._parent[value]
        while parent != self._parent[parent]:
            parent = self._parent[parent]
        while value != parent:
            previous = self._parent[value]
            self._parent[value] = parent
            value = previous
        return parent

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            self._parent[right_root] = left_root
        else:
            self._parent[left_root] = right_root


def _canonical_json(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise TrainingDataError("training aggregate is not JSON-safe") from exc
    return rendered.encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _candidate_pair(candidate: Mapping[str, object]) -> tuple[str, str] | None:
    sides: list[str] = []
    for field in ("left", "right"):
        side = candidate.get(field)
        if not isinstance(side, Mapping):
            raise TrainingDataError("candidate side must be an object")
        synthetic = side.get("synthetic_identity", False)
        if not isinstance(synthetic, bool):
            raise TrainingDataError("candidate synthetic flag must be boolean")
        if synthetic:
            return None
        value = side.get("sample_sha256")
        if not isinstance(value, str) or _SHA256_RE.fullmatch(value.lower()) is None:
            raise TrainingDataError("candidate identity must be a real SHA-256")
        sides.append(value.lower())
    if sides[0] == sides[1]:
        raise TrainingDataError("candidate self-pair is invalid")
    return tuple(sorted(sides))  # type: ignore[return-value]


def _dataset_digest(rows: list[TrainingRow]) -> str:
    # Pair identities are intentionally absent.  Multiplicity is retained so
    # the digest still changes when the effective training population changes.
    signatures = sorted(([*row.features], row.target, row.hard_negative) for row in rows)
    return _digest(signatures)


def _split_parameters(test_fraction: object, seed: object) -> tuple[float, int]:
    if isinstance(test_fraction, bool) or not isinstance(test_fraction, (int, float)):
        raise ValueError("test_fraction must be finite and between 0 and 1")
    try:
        normalized_fraction = float(test_fraction)
    except (OverflowError, ValueError) as exc:
        raise ValueError("test_fraction must be finite and between 0 and 1") from exc
    if not math.isfinite(normalized_fraction) or not 0.0 < normalized_fraction < 1.0:
        raise ValueError("test_fraction must be finite and between 0 and 1")
    if (
        isinstance(seed, bool)
        or not isinstance(seed, int)
        or not 0 <= seed <= _MAX_SKLEARN_SEED
    ):
        raise ValueError("seed must be an integer between 0 and 2**32 - 1")
    return normalized_fraction, seed


def _positive_components(
    samples: set[str], truth: LinkageGroundTruth
) -> dict[str, str]:
    component_samples = samples | {
        sample for pair in truth.positive_pairs for sample in pair
    }
    union_find = _UnionFind(component_samples)
    for left, right in truth.positive_pairs:
        union_find.union(left, right)
    members_by_root: dict[str, list[str]] = {}
    for sample in sorted(component_samples):
        members_by_root.setdefault(union_find.find(sample), []).append(sample)
    return {
        sample: min(members_by_root[union_find.find(sample)])
        for sample in samples
    }


def _split_manifest_entries(
    entries: Iterable[dict[str, Any]],
    truth: LinkageGroundTruth,
    *,
    test_fraction: float = 0.2,
    seed: int = 0,
) -> ManifestEntrySplit:
    """Split complete sample revisions before fitting any corpus-level context."""
    if not isinstance(truth, LinkageGroundTruth):
        raise TypeError("truth must be a LinkageGroundTruth")
    normalized_fraction, normalized_seed = _split_parameters(test_fraction, seed)
    entry_list = list(entries)
    identities: list[str] = []
    for entry in entry_list:
        identity = _entry_sample_identity(entry)
        if identity is None:
            raise TrainingDataError("training entries contain an invalid sample identity")
        identities.append(identity)
    component_by_sample = _positive_components(set(identities), truth)
    components = sorted(set(component_by_sample.values()))
    if len(components) < 2:
        raise TrainingDataError("at least two positive components are required for a split")

    ordered = sorted(
        components,
        key=lambda component: hashlib.sha256(
            f"{normalized_seed}:{component}".encode("ascii")
        ).digest(),
    )
    test_count = max(
        1,
        min(len(ordered) - 1, math.ceil(len(ordered) * normalized_fraction)),
    )
    test_components = frozenset(ordered[:test_count])
    train_components = frozenset(ordered[test_count:])
    train_entries: list[dict[str, Any]] = []
    test_entries: list[dict[str, Any]] = []
    for entry, identity in zip(entry_list, identities):
        target = (
            test_entries
            if component_by_sample[identity] in test_components
            else train_entries
        )
        target.append(entry)

    present = set(identities)
    independent_truth = project_independent_ground_truth(truth)
    dropped = sum(
        component_by_sample[left] in train_components
        and component_by_sample[right] in test_components
        or component_by_sample[left] in test_components
        and component_by_sample[right] in train_components
        for left, right in (
            independent_truth.positive_pairs | independent_truth.negative_pairs
        )
        if left in present and right in present
    )
    assignment_digest = _digest(
        {
            "seed": normalized_seed,
            "test_fraction": normalized_fraction,
            "train": sorted(
                hashlib.sha256(value.encode("ascii")).hexdigest()
                for value in train_components
            ),
            "test": sorted(
                hashlib.sha256(value.encode("ascii")).hexdigest()
                for value in test_components
            ),
        }
    )
    return ManifestEntrySplit(
        train_entries=tuple(train_entries),
        test_entries=tuple(test_entries),
        component_by_sample=tuple(sorted(component_by_sample.items())),
        train_components=tuple(sorted(train_components)),
        test_components=tuple(sorted(test_components)),
        dropped_cross_split_pair_count=dropped,
        split_digest=assignment_digest,
    )


def build_training_dataset(
    entries: Iterable[dict[str, Any]],
    labels: LinkageLabelSet,
    *,
    preprocessing_context: LinkagePreprocessingContext | None = None,
) -> TrainingDataset:
    """Build rows only from rule-recalled, independent confirmed labels."""
    if not isinstance(labels, LinkageLabelSet):
        raise TypeError("labels must be a LinkageLabelSet")
    if preprocessing_context is not None and not isinstance(
        preprocessing_context, LinkagePreprocessingContext
    ):
        raise TypeError("preprocessing_context must be a LinkagePreprocessingContext")
    entry_list = list(entries)
    all_truth = build_linkage_ground_truth(labels)
    truth = project_independent_ground_truth(all_truth)
    rule_result = rank_link_candidates(
        entry_list,
        limit=None,
        preprocessing_context=preprocessing_context,
    )
    if not isinstance(rule_result, Mapping):
        raise TrainingDataError("rule engine returned a non-object")
    status = rule_result.get("status")
    if status not in {"complete", "partial"}:
        raise TrainingDataError("rule engine returned an invalid status")
    raw_candidates = rule_result.get("candidates")
    if not isinstance(raw_candidates, list):
        raise TrainingDataError("rule engine candidates must be a list")

    rows: list[TrainingRow] = []
    seen: set[tuple[str, str]] = set()
    retrieved_positive: set[tuple[str, str]] = set()
    for raw_candidate in raw_candidates:
        if not isinstance(raw_candidate, Mapping):
            raise TrainingDataError("candidate must be an object")
        pair = _candidate_pair(raw_candidate)
        if pair is None:
            continue
        if pair in seen:
            raise TrainingDataError("rule engine returned a duplicate candidate")
        seen.add(pair)
        if pair in truth.positive_pairs:
            target = 1
            retrieved_positive.add(pair)
        elif pair in truth.negative_pairs:
            target = 0
        else:
            # Unknown and unlabelled candidates are not implicit negatives.
            continue
        features = feature_vector(extract_pair_features(raw_candidate))
        # ★hard 的门禁判据 = sampling_class 声明 ∧ 本行存在（即被 rank_link_candidates 召回）。
        #   sampling_class 与 label_basis 独立性同构，都是标注者的自声明；区别是 hard 有机器可推导
        #   的结构侧（候选生成纯靠共享非弱锚倒排，被召回 ⇔ 与对侧共享 ≥1 个锚），所以这里能真收紧：
        #   声明无法把未召回的 pair 塞进 min_hard_negative_pairs 计数——结构上限就是召回集。
        #   召回口径与 rules-v2 封顶回归档同源（同一 rank_link_candidates 候选集成员资格，
        #   见 linkage_evaluation 的 retrieved & truth.hard_negative_pairs），不另造第二套判据；
        #   反方向也不放松：被召回但未声明 hard 的负例不会被推导「升格」，声明仍是必要条件。
        rows.append(
            TrainingRow(
                pair=pair,
                features=features,
                target=target,
                hard_negative=(target == 0 and pair in truth.hard_negative_pairs),
            )
        )
    rows.sort(key=lambda row: row.pair)

    samples = {sample for row in rows for sample in row.pair}
    # Rows use only feature-independent truth, but split isolation must honor
    # every confirmed positive relation. Otherwise a family label excluded for
    # circularity could still put known relatives on opposite sides.
    canonical_root = _positive_components(samples, all_truth)
    represented_positive_components = {
        canonical_root[left] for left, _right in retrieved_positive
    }
    present_real_samples = {
        identity
        for entry in entry_list
        if (identity := _entry_sample_identity(entry)) is not None
        and _SHA256_RE.fullmatch(identity) is not None
    }

    def _present_pair(pair: tuple[str, str]) -> bool:
        return pair[0] in present_real_samples and pair[1] in present_real_samples

    return TrainingDataset(
        rows=tuple(rows),
        component_by_sample=tuple(sorted(canonical_root.items())),
        candidate_generation_complete=status == "complete",
        real_sample_count=len(samples),
        family_group_count=len(represented_positive_components),
        positive_pair_count=sum(row.target == 1 for row in rows),
        negative_pair_count=sum(row.target == 0 for row in rows),
        hard_negative_pair_count=sum(row.hard_negative for row in rows),
        independent_label_positive_pair_count=sum(
            _present_pair(pair) for pair in truth.positive_pairs
        ),
        independent_label_negative_pair_count=sum(
            _present_pair(pair) for pair in truth.negative_pairs
        ),
        independent_label_hard_negative_pair_count=sum(
            _present_pair(pair) for pair in truth.hard_negative_pairs
        ),
        feature_overlap_excluded_positive_pair_count=len(
            {
                pair
                for pair in all_truth.positive_pairs - truth.positive_pairs
                if _present_pair(pair)
            }
        ),
        feature_overlap_excluded_negative_pair_count=len(
            {
                pair
                for pair in all_truth.negative_pairs - truth.negative_pairs
                if _present_pair(pair)
            }
        ),
        missing_basis_pair_count=0,
        dataset_digest=_dataset_digest(rows),
    )


def training_readiness(
    dataset: TrainingDataset,
    thresholds: ReadinessThresholds = DEFAULT_READINESS_THRESHOLDS,
) -> dict[str, object]:
    """Return a structured gate decision without exposing any pair identity."""
    if not isinstance(dataset, TrainingDataset):
        raise TypeError("dataset must be a TrainingDataset")
    if not isinstance(thresholds, ReadinessThresholds):
        raise TypeError("thresholds must be ReadinessThresholds")
    _require_policy_floor(thresholds)
    counts = {
        "real_sample_count": dataset.real_sample_count,
        "family_group_count": dataset.family_group_count,
        "positive_pair_count": dataset.positive_pair_count,
        "negative_pair_count": dataset.negative_pair_count,
        "hard_negative_pair_count": dataset.hard_negative_pair_count,
        "independent_label_positive_pair_count": (dataset.independent_label_positive_pair_count),
        "independent_label_negative_pair_count": (dataset.independent_label_negative_pair_count),
        "independent_label_hard_negative_pair_count": (
            dataset.independent_label_hard_negative_pair_count
        ),
        "feature_overlap_excluded_positive_pair_count": (
            dataset.feature_overlap_excluded_positive_pair_count
        ),
        "feature_overlap_excluded_negative_pair_count": (
            dataset.feature_overlap_excluded_negative_pair_count
        ),
        "missing_basis_pair_count": dataset.missing_basis_pair_count,
    }
    comparisons = (
        ("real_sample_count", "min_real_samples"),
        ("family_group_count", "min_family_groups"),
        ("positive_pair_count", "min_positive_pairs"),
        ("negative_pair_count", "min_negative_pairs"),
        ("hard_negative_pair_count", "min_hard_negative_pairs"),
    )
    required = thresholds.as_dict()
    unmet = [
        {"metric": count_name, "actual": counts[count_name], "required": required[threshold_name]}
        for count_name, threshold_name in comparisons
        if counts[count_name] < required[threshold_name]
    ]
    if not dataset.candidate_generation_complete:
        unmet.append({"metric": "candidate_generation_complete", "actual": 0, "required": 1})
    independent_classes_present = bool(dataset.positive_pair_count) and bool(
        dataset.negative_pair_count
    )
    if not dataset.positive_pair_count:
        unmet.append(
            {
                "metric": "independent_recalled_positive_pair_count",
                "actual": 0,
                "required": 1,
            }
        )
    if not dataset.negative_pair_count:
        unmet.append(
            {
                "metric": "independent_recalled_negative_pair_count",
                "actual": 0,
                "required": 1,
            }
        )
    reason = (
        "readiness_thresholds" if independent_classes_present else "insufficient_independent_labels"
    )
    return {
        "status": "ready" if not unmet else "blocked",
        "ready": not unmet,
        "reason": None if not unmet else reason,
        "counts": counts,
        "thresholds": required,
        "unmet": unmet,
        "scope": "rule_recalled_confirmed_independent_pairs_only",
        "label_feature_independence": {
            "training_rows_use_independent_pairs_only": True,
            "feature_overlap_excluded_pair_count": (
                dataset.feature_overlap_excluded_positive_pair_count
                + dataset.feature_overlap_excluded_negative_pair_count
            ),
            "missing_basis_pair_count": dataset.missing_basis_pair_count,
        },
    }


def assess_training_readiness(
    entries: Iterable[dict[str, Any]],
    labels: LinkageLabelSet,
    thresholds: ReadinessThresholds = DEFAULT_READINESS_THRESHOLDS,
    *,
    test_fraction: float = 0.2,
    seed: int = 0,
) -> dict[str, object]:
    """Report the actual train-partition gate without fitting a model."""
    if not isinstance(labels, LinkageLabelSet):
        raise TypeError("labels must be a LinkageLabelSet")
    if not isinstance(thresholds, ReadinessThresholds):
        raise TypeError("thresholds must be ReadinessThresholds")
    # 在任何早退分支（如 split 不可用）之前强制政策下限：低门槛调用必须一律被拒，
    # 不能借早退路径拿到一个"看起来合法"的 blocked 结果。
    _require_policy_floor(thresholds)
    entry_list = list(entries)
    truth = build_linkage_ground_truth(labels)
    try:
        partition = _split_manifest_entries(
            entry_list,
            truth,
            test_fraction=test_fraction,
            seed=seed,
        )
    except TrainingDataError:
        return {
            "status": "blocked",
            "ready": False,
            "reason": "group_disjoint_split_unavailable",
            "counts": {
                "real_sample_count": 0,
                "family_group_count": 0,
                "positive_pair_count": 0,
                "negative_pair_count": 0,
                "hard_negative_pair_count": 0,
                "independent_label_positive_pair_count": 0,
                "independent_label_negative_pair_count": 0,
                "independent_label_hard_negative_pair_count": 0,
                "feature_overlap_excluded_positive_pair_count": 0,
                "feature_overlap_excluded_negative_pair_count": 0,
                "missing_basis_pair_count": 0,
            },
            "thresholds": thresholds.as_dict(),
            "unmet": [
                {
                    "metric": "group_disjoint_component_count",
                    "actual": 0,
                    "required": 2,
                }
            ],
            "scope": "rule_recalled_confirmed_independent_pairs_only",
            "partition": "train",
            "preprocessing_scope": TRAINING_PREPROCESSING_SCOPE,
        }
    preprocessing_context = fit_linkage_preprocessing_context(partition.train_entries)
    dataset = build_training_dataset(
        partition.train_entries,
        labels,
        preprocessing_context=preprocessing_context,
    )
    result = training_readiness(dataset, thresholds)
    result["partition"] = "train"
    result["preprocessing_scope"] = TRAINING_PREPROCESSING_SCOPE
    split_summary = {
        "train_record_count": len(partition.train_entries),
        "test_record_count": len(partition.test_entries),
        "train_component_count": len(partition.train_components),
        "test_component_count": len(partition.test_components),
        "dropped_cross_split_pair_count": partition.dropped_cross_split_pair_count,
    }
    result["split"] = split_summary
    if result["ready"] is not True:
        return result

    holdout = build_training_dataset(
        partition.test_entries,
        labels,
        preprocessing_context=preprocessing_context,
    )
    holdout_positive, holdout_negative = _class_counts(holdout.rows)
    split_summary.update(
        {
            "test_pair_count": len(holdout.rows),
            "test_positive_count": holdout_positive,
            "test_negative_count": holdout_negative,
        }
    )
    unmet = result.get("unmet")
    if not isinstance(unmet, list):
        raise TrainingDataError("readiness result has an invalid unmet list")
    if not holdout.candidate_generation_complete:
        result["status"] = "blocked"
        result["ready"] = False
        result["reason"] = "holdout_candidate_generation_incomplete"
        unmet.append(
            {"metric": "holdout_candidate_generation_complete", "actual": 0, "required": 1}
        )
    elif not holdout_positive or not holdout_negative:
        result["status"] = "blocked"
        result["ready"] = False
        result["reason"] = "group_disjoint_split_missing_class"
        unmet.append(
            {
                "metric": "holdout_class_count",
                "actual": int(bool(holdout_positive)) + int(bool(holdout_negative)),
                "required": 2,
            }
        )
    return result


def split_group_disjoint(
    dataset: TrainingDataset, *, test_fraction: float = 0.2, seed: int = 0
) -> GroupDisjointSplit:
    """Assign whole positive components, then discard cross-partition pairs."""
    if not isinstance(dataset, TrainingDataset):
        raise TypeError("dataset must be a TrainingDataset")
    normalized_fraction, normalized_seed = _split_parameters(test_fraction, seed)
    component_by_sample = dataset.components()
    components = sorted(set(component_by_sample.values()))
    if len(components) < 2:
        raise TrainingDataError("at least two positive components are required for a split")

    ordered = sorted(
        components,
        key=lambda component: hashlib.sha256(
            f"{normalized_seed}:{component}".encode("ascii")
        ).digest(),
    )
    test_count = max(1, min(len(ordered) - 1, math.ceil(len(ordered) * normalized_fraction)))
    test_components = frozenset(ordered[:test_count])
    train_components = frozenset(ordered[test_count:])
    train_rows: list[TrainingRow] = []
    test_rows: list[TrainingRow] = []
    dropped = 0
    for row in dataset.rows:
        left_component = component_by_sample[row.pair[0]]
        right_component = component_by_sample[row.pair[1]]
        if left_component in train_components and right_component in train_components:
            train_rows.append(row)
        elif left_component in test_components and right_component in test_components:
            test_rows.append(row)
        else:
            dropped += 1

    assignment_digest = _digest(
        {
            "seed": normalized_seed,
            "test_fraction": normalized_fraction,
            "train": sorted(
                hashlib.sha256(value.encode("ascii")).hexdigest() for value in train_components
            ),
            "test": sorted(
                hashlib.sha256(value.encode("ascii")).hexdigest() for value in test_components
            ),
        }
    )
    return GroupDisjointSplit(
        train_rows=tuple(train_rows),
        test_rows=tuple(test_rows),
        dropped_cross_split_pair_count=dropped,
        train_components=tuple(sorted(train_components)),
        test_components=tuple(sorted(test_components)),
        split_digest=assignment_digest,
    )


def _component_balanced_weights(
    rows: tuple[TrainingRow, ...], component_by_sample: Mapping[str, str]
) -> tuple[float, ...]:
    """Give each positive component and negative component-pair equal class mass."""
    if not rows:
        raise TrainingDataError("training split is empty")
    groups: dict[tuple[object, ...], list[int]] = {}
    for index, row in enumerate(rows):
        try:
            left_component = component_by_sample[row.pair[0]]
            right_component = component_by_sample[row.pair[1]]
        except KeyError as exc:
            raise TrainingDataError("training row lacks a component assignment") from exc
        if row.target == 1:
            if left_component != right_component:
                raise TrainingDataError("positive training row crosses confirmed components")
            key: tuple[object, ...] = (1, left_component)
        elif row.target == 0:
            key = (0, *sorted((left_component, right_component)))
        else:
            raise TrainingDataError("training target must be binary")
        groups.setdefault(key, []).append(index)

    groups_by_class = {
        target: [key for key in groups if key[0] == target]
        for target in (0, 1)
    }
    if not groups_by_class[0] or not groups_by_class[1]:
        raise TrainingDataError("component-balanced weighting requires both classes")
    weights = [0.0] * len(rows)
    for target in (0, 1):
        group_mass = len(rows) / (2.0 * len(groups_by_class[target]))
        for key in groups_by_class[target]:
            per_row = group_mass / len(groups[key])
            for index in groups[key]:
                weights[index] = per_row
    if not all(math.isfinite(value) and value > 0.0 for value in weights):
        raise TrainingDataError("component-balanced weighting produced invalid values")
    return tuple(weights)


def _fit_scaler(
    rows: tuple[TrainingRow, ...], sample_weight: tuple[float, ...]
) -> tuple[tuple[float, ...], tuple[float, ...]]:
    if not rows:
        raise TrainingDataError("training split is empty")
    if len(sample_weight) != len(rows):
        raise TrainingDataError("scaler weights do not match training rows")
    total_weight = sum(sample_weight)
    if not math.isfinite(total_weight) or total_weight <= 0.0:
        raise TrainingDataError("scaler weights must have positive finite mass")
    width = len(rows[0].features)
    if width == 0 or any(len(row.features) != width for row in rows):
        raise TrainingDataError("training feature rows have inconsistent widths")
    means: list[float] = []
    scales: list[float] = []
    for index in range(width):
        values = [row.features[index] for row in rows]
        mean = sum(
            weight * value for weight, value in zip(sample_weight, values)
        ) / total_weight
        variance = sum(
            weight * (value - mean) ** 2
            for weight, value in zip(sample_weight, values)
        ) / total_weight
        scale = math.sqrt(variance)
        means.append(mean)
        scales.append(scale if scale > 0.0 else 1.0)
    return tuple(means), tuple(scales)


def _standardize(
    rows: tuple[TrainingRow, ...], mean: tuple[float, ...], scale: tuple[float, ...]
) -> list[list[float]]:
    return [
        [(value - mean[index]) / scale[index] for index, value in enumerate(row.features)]
        for row in rows
    ]


def _fit_logistic_regression(
    features: list[list[float]],
    targets: list[int],
    sample_weight: tuple[float, ...],
    *,
    seed: int,
) -> tuple[tuple[float, ...], float, str]:
    try:
        # scikit-learn 是可选 extra（pyproject `ml`），CI 的 lint 环境只装基础依赖，
        # 因此这两行对 pyright 恒为 unresolved——运行期由下面的 except 兜底并抛
        # TrainingDependencyError。忽略只施加在这两行，不放宽全局 reportMissingImports。
        import sklearn  # pyright: ignore[reportMissingImports]
        from sklearn.linear_model import LogisticRegression  # pyright: ignore[reportMissingImports]
    except ImportError as exc:
        raise TrainingDependencyError(
            "scikit-learn is required only for local challenger training"
        ) from exc
    model = LogisticRegression(
        max_iter=1000,
        random_state=seed,
        solver="liblinear",
    )
    model.fit(features, targets, sample_weight=sample_weight)
    try:
        raw_coefficients: Any = model.coef_
        raw_intercept: Any = model.intercept_
        coefficients = tuple(float(value) for value in raw_coefficients[0])
        intercept = float(raw_intercept[0])
    except (AttributeError, IndexError, TypeError, ValueError) as exc:
        raise TrainingDataError("logistic regression returned an invalid model shape") from exc
    dependency_version = str(getattr(sklearn, "__version__", "")).strip()
    if not dependency_version or len(dependency_version) > 128:
        raise TrainingDataError("training dependency returned an invalid version")
    return coefficients, intercept, dependency_version


def _class_counts(rows: tuple[TrainingRow, ...]) -> tuple[int, int]:
    positive = sum(row.target == 1 for row in rows)
    return positive, len(rows) - positive


def _rank_scores(
    rows: tuple[TrainingRow, ...],
    mean: tuple[float, ...],
    scale: tuple[float, ...],
    coefficients: tuple[float, ...],
    intercept: float,
) -> tuple[float, ...]:
    scores: list[float] = []
    for row in rows:
        logit = intercept + sum(
            coefficient * ((value - mean[index]) / scale[index])
            for index, (coefficient, value) in enumerate(
                zip(coefficients, row.features)
            )
        )
        if logit >= 0.0:
            probability = 1.0 / (1.0 + math.exp(-logit))
        else:
            exp_logit = math.exp(logit)
            probability = exp_logit / (1.0 + exp_logit)
        scores.append(probability * 100.0)
    return tuple(scores)


def _weighted_holdout_metrics(
    rows: tuple[TrainingRow, ...],
    scores: tuple[float, ...],
    sample_weight: tuple[float, ...],
) -> dict[str, float]:
    if not (len(rows) == len(scores) == len(sample_weight)) or not rows:
        raise TrainingDataError("holdout metric inputs are inconsistent")
    positive_weight = sum(
        weight for row, weight in zip(rows, sample_weight) if row.target == 1
    )
    negative_weight = sum(
        weight for row, weight in zip(rows, sample_weight) if row.target == 0
    )
    if positive_weight <= 0.0 or negative_weight <= 0.0:
        raise TrainingDataError("holdout metrics require both classes")

    grouped: dict[float, list[float]] = {}
    for row, score, weight in zip(rows, scores, sample_weight):
        if not math.isfinite(score):
            raise TrainingDataError("holdout score is non-finite")
        bucket = grouped.setdefault(score, [0.0, 0.0])
        bucket[row.target] += weight

    cumulative_negative = 0.0
    concordant = 0.0
    for score in sorted(grouped):
        negative_at_score, positive_at_score = grouped[score]
        concordant += positive_at_score * (
            cumulative_negative + 0.5 * negative_at_score
        )
        cumulative_negative += negative_at_score
    roc_auc = concordant / (positive_weight * negative_weight)

    cumulative_positive = 0.0
    cumulative_total = 0.0
    average_precision = 0.0
    for score in sorted(grouped, reverse=True):
        negative_at_score, positive_at_score = grouped[score]
        cumulative_positive += positive_at_score
        cumulative_total += positive_at_score + negative_at_score
        average_precision += (
            positive_at_score / positive_weight
        ) * (cumulative_positive / cumulative_total)

    positive_mean = sum(
        score * weight
        for row, score, weight in zip(rows, scores, sample_weight)
        if row.target == 1
    ) / positive_weight
    negative_mean = sum(
        score * weight
        for row, score, weight in zip(rows, scores, sample_weight)
        if row.target == 0
    ) / negative_weight
    return {
        "roc_auc": roc_auc,
        "average_precision": average_precision,
        "positive_mean_rank_score": positive_mean,
        "negative_mean_rank_score": negative_mean,
    }


def train_linkage_challenger(
    entries: Iterable[dict[str, Any]],
    labels: LinkageLabelSet,
    *,
    thresholds: ReadinessThresholds = DEFAULT_READINESS_THRESHOLDS,
    test_fraction: float = 0.2,
    seed: int = 0,
) -> dict[str, object]:
    """Split first, freeze train-only preprocessing, then gate and fit."""
    if not isinstance(labels, LinkageLabelSet):
        raise TypeError("labels must be a LinkageLabelSet")
    if not isinstance(thresholds, ReadinessThresholds):
        raise TypeError("thresholds must be ReadinessThresholds")
    _require_policy_floor(thresholds)
    entry_list = list(entries)
    all_truth = build_linkage_ground_truth(labels)
    try:
        partition = _split_manifest_entries(
            entry_list,
            all_truth,
            test_fraction=test_fraction,
            seed=seed,
        )
    except TrainingDataError:
        return {
            "status": "blocked",
            "experimental": True,
            "reason": "group_disjoint_split_unavailable",
        }

    preprocessing_context = fit_linkage_preprocessing_context(partition.train_entries)
    train_dataset = build_training_dataset(
        partition.train_entries,
        labels,
        preprocessing_context=preprocessing_context,
    )
    readiness = training_readiness(train_dataset, thresholds)
    readiness["partition"] = "train"
    readiness["preprocessing_scope"] = TRAINING_PREPROCESSING_SCOPE
    if readiness["ready"] is not True:
        return {
            "status": "blocked",
            "experimental": True,
            "reason": readiness.get("reason") or "readiness_thresholds",
            "readiness": readiness,
        }

    test_dataset = build_training_dataset(
        partition.test_entries,
        labels,
        preprocessing_context=preprocessing_context,
    )
    train_positive, train_negative = _class_counts(train_dataset.rows)
    test_positive, test_negative = _class_counts(test_dataset.rows)
    split_summary = {
        "train_pair_count": len(train_dataset.rows),
        "test_pair_count": len(test_dataset.rows),
        "dropped_cross_split_pair_count": partition.dropped_cross_split_pair_count,
        "train_positive_count": train_positive,
        "train_negative_count": train_negative,
        "test_positive_count": test_positive,
        "test_negative_count": test_negative,
    }
    if not test_dataset.candidate_generation_complete:
        return {
            "status": "blocked",
            "experimental": True,
            "reason": "holdout_candidate_generation_incomplete",
            "readiness": readiness,
            "split": split_summary,
        }
    if min(train_positive, train_negative, test_positive, test_negative) == 0:
        return {
            "status": "blocked",
            "experimental": True,
            "reason": "group_disjoint_split_missing_class",
            "readiness": readiness,
            "split": split_summary,
        }

    train_weights = _component_balanced_weights(
        train_dataset.rows, train_dataset.components()
    )
    test_weights = _component_balanced_weights(
        test_dataset.rows, test_dataset.components()
    )
    mean, scale = _fit_scaler(train_dataset.rows, train_weights)
    standardized = _standardize(train_dataset.rows, mean, scale)
    targets = [row.target for row in train_dataset.rows]
    try:
        coefficients, intercept, dependency_version = _fit_logistic_regression(
            standardized,
            targets,
            train_weights,
            seed=seed,
        )
    except TrainingDependencyError:
        return {
            "status": "blocked",
            "experimental": True,
            "reason": "missing_training_dependency",
            "readiness": readiness,
        }
    if len(coefficients) != len(PAIR_FEATURE_NAMES) or not all(
        math.isfinite(value) for value in (*coefficients, intercept)
    ):
        raise TrainingDataError("fitted model contains invalid coefficients")
    holdout_scores = _rank_scores(
        test_dataset.rows,
        mean,
        scale,
        coefficients,
        intercept,
    )
    holdout_metrics = _weighted_holdout_metrics(
        test_dataset.rows,
        holdout_scores,
        test_weights,
    )

    training_summary = {
        "real_sample_count": train_dataset.real_sample_count,
        "family_group_count": train_dataset.family_group_count,
        "positive_pair_count": train_dataset.positive_pair_count,
        "negative_pair_count": train_dataset.negative_pair_count,
        "hard_negative_pair_count": train_dataset.hard_negative_pair_count,
        "train_pair_count": len(train_dataset.rows),
        "test_pair_count": len(test_dataset.rows),
        "dropped_cross_split_pair_count": partition.dropped_cross_split_pair_count,
        "train_positive_count": train_positive,
        "train_negative_count": train_negative,
        "test_positive_count": test_positive,
        "test_negative_count": test_negative,
        "train_component_count": len(partition.train_components),
        "test_component_count": len(partition.test_components),
        "dataset_digest": train_dataset.dataset_digest,
        "holdout_dataset_digest": test_dataset.dataset_digest,
        "split_digest": partition.split_digest,
        "weighting_version": TRAINING_WEIGHTING_VERSION,
        "preprocessing_scope": TRAINING_PREPROCESSING_SCOPE,
        "seed": seed,
        "test_fraction": float(test_fraction),
        "holdout_metrics": holdout_metrics,
    }
    artifact = seal_linkage_model_artifact(
        {
            "artifact_schema_version": MODEL_ARTIFACT_SCHEMA_VERSION,
            "model_id": LINKAGE_ML_MODEL_ID,
            "model_kind": "logistic_regression",
            "feature_schema_version": PAIR_FEATURE_SCHEMA_VERSION,
            "feature_names": list(PAIR_FEATURE_NAMES),
            "score_semantics": ML_SCORE_SEMANTICS,
            "experimental": True,
            "calibration": {
                "status": "not_calibrated",
                "score_semantics": ML_SCORE_SEMANTICS,
            },
            "rule_engine": current_rule_engine_contract(),
            "training_runtime": {
                "fxapk_version": FXAPK_VERSION,
                "dependency_name": "scikit-learn",
                "dependency_version": dependency_version,
            },
            "scaler": {"mean": list(mean), "scale": list(scale)},
            "coefficients": list(coefficients),
            "intercept": intercept,
            "readiness_thresholds": thresholds.as_dict(),
            "training_summary": training_summary,
        }
    )
    return {
        "status": "trained",
        "experimental": True,
        "readiness": readiness,
        "split": split_summary,
        "holdout_metrics": holdout_metrics,
        "artifact": artifact,
    }
