"""Fixed pair features and standard-library inference for linkage ranking.

No raw anchor value, sample identity, case identifier, path or free text is a
model feature.  The optional model can only reorder candidates already emitted
by the deterministic linkage engine, and its score remains bounded by every
deterministic score cap on the candidate.
"""

from __future__ import annotations

from collections.abc import Mapping
import copy
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import re
from types import MappingProxyType
from typing import Any

from apkscan.core.linkage import (
    FEATURE_SCHEMA_VERSION as RULE_FEATURE_SCHEMA_VERSION,
    NORMALIZATION_VERSION as RULE_NORMALIZATION_VERSION,
    POLICY_DIGEST as RULE_POLICY_DIGEST,
    POLICY_ID as RULE_POLICY_ID,
    RESULT_SCHEMA_VERSION as RULE_RESULT_SCHEMA_VERSION,
)


MODEL_ARTIFACT_SCHEMA_VERSION = "1.2"
PAIR_FEATURE_SCHEMA_VERSION = "1.2"
LINKAGE_ML_MODEL_ID = "fxapk-linkage-logreg-v1"
ML_SCORE_SEMANTICS = "ml_rank_score_not_probability"

_SUPPORT_FAMILIES = ("remote_config", "native", "signing", "build", "ioc")
_CAP_CODES = (
    "no_strong_anchor",
    "single_strong_family",
    "broad_shared_anchor_only",
    "invalid_feature_fields",
    "synthetic_sample_identity",
    "repack_suspected",
    "non_authoritative_input",
)

PAIR_FEATURE_NAMES = (
    "rule_review_priority_score",
    "rule_uncapped_score",
    "strong_family_count",
    "support_family_count",
    "synthetic_side_count",
    *(name for family in _SUPPORT_FAMILIES for name in (
        f"support_{family}",
        f"match_count_{family}",
        f"weight_{family}",
    )),
    *(f"excluded_{family}_count" for family in _SUPPORT_FAMILIES),
    *(f"cap_{code}" for code in _CAP_CODES),
    "coverage_unknown_count",
    "coverage_observed_with_invalid_siblings_count",
    "coverage_invalid_only_count",
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT_FIELDS = frozenset(
    {
        "artifact_schema_version",
        "model_id",
        "model_kind",
        "feature_schema_version",
        "feature_names",
        "score_semantics",
        "experimental",
        "calibration",
        "rule_engine",
        "training_runtime",
        "scaler",
        "coefficients",
        "intercept",
        "readiness_thresholds",
        "training_summary",
        "artifact_digest",
    }
)
_RULE_ENGINE_FIELDS = frozenset(
    {
        "policy_id",
        "policy_digest",
        "result_schema_version",
        "feature_schema_version",
        "normalization_version",
    }
)
_THRESHOLD_FIELDS = frozenset(
    {
        "min_real_samples",
        "min_family_groups",
        "min_positive_pairs",
        "min_negative_pairs",
        "min_hard_negative_pairs",
    }
)
#: ★生产训练门槛的**政策下限**（fail-closed 契约的一部分，非"默认值"）。默认值只决定没传参时
#:   取什么；政策下限是门禁**内部**逐字段强制的最小值：`training_readiness` /
#:   `assess_training_readiness` / `train_linkage_challenger` 对任何低于此线的调用方 thresholds
#:   一律拒绝，artifact 校验侧同样拒绝记录了低于此线门槛的 artifact——两侧同时关死，
#:   既挡"传小数字进门禁"，也挡"先造出低门槛 artifact 再洗进加载路径"。
#:   放本模块（artifact 契约层）是因为两侧都要引用；数值变更即政策变更，须随 policy 评审走。
READINESS_POLICY_FLOOR: Mapping[str, int] = MappingProxyType(
    {
        "min_real_samples": 200,
        "min_family_groups": 10,
        "min_positive_pairs": 300,
        "min_negative_pairs": 600,
        "min_hard_negative_pairs": 500,
    }
)
_SUMMARY_COUNT_FIELDS = frozenset(
    {
        "real_sample_count",
        "family_group_count",
        "positive_pair_count",
        "negative_pair_count",
        "hard_negative_pair_count",
        "train_pair_count",
        "test_pair_count",
        "dropped_cross_split_pair_count",
        "train_positive_count",
        "train_negative_count",
        "test_positive_count",
        "test_negative_count",
        "train_component_count",
        "test_component_count",
    }
)
_SUMMARY_FIELDS = _SUMMARY_COUNT_FIELDS | {
    "dataset_digest",
    "holdout_dataset_digest",
    "split_digest",
    "weighting_version",
    "preprocessing_scope",
    "seed",
    "test_fraction",
    "holdout_metrics",
}
_HOLDOUT_METRIC_FIELDS = frozenset(
    {
        "roc_auc",
        "average_precision",
        "positive_mean_rank_score",
        "negative_mean_rank_score",
    }
)
_TRAINING_RUNTIME_FIELDS = frozenset(
    {"fxapk_version", "dependency_name", "dependency_version"}
)
_SAFE_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}\Z")


class PairFeatureError(ValueError):
    """A deterministic candidate cannot be represented by the fixed schema."""


class ArtifactValidationError(ValueError):
    """A model artifact is malformed, incompatible or has been modified."""


@dataclass(frozen=True, slots=True)
class LinkageModelArtifact:
    model_id: str
    feature_schema_version: str
    feature_names: tuple[str, ...]
    rule_policy_id: str
    rule_policy_digest: str
    rule_result_schema_version: str
    rule_feature_schema_version: str
    rule_normalization_version: str
    scaler_mean: tuple[float, ...]
    scaler_scale: tuple[float, ...]
    coefficients: tuple[float, ...]
    intercept: float
    artifact_digest: str

    def __post_init__(self) -> None:
        _validate_model_instance(self)


def _finite_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PairFeatureError(f"{field} must be numeric")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise PairFeatureError(f"{field} must be finite") from exc
    if not math.isfinite(result):
        raise PairFeatureError(f"{field} must be finite")
    return result


def current_rule_engine_contract() -> dict[str, str]:
    """Return the exact deterministic rule contract used to train a challenger."""
    return {
        "policy_id": RULE_POLICY_ID,
        "policy_digest": RULE_POLICY_DIGEST,
        "result_schema_version": RULE_RESULT_SCHEMA_VERSION,
        "feature_schema_version": RULE_FEATURE_SCHEMA_VERSION,
        "normalization_version": RULE_NORMALIZATION_VERSION,
    }


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PairFeatureError(f"{field} must be a non-negative integer")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PairFeatureError(f"{field} must be an object")
    return value


def _list(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise PairFeatureError(f"{field} must be a list")
    return value


def extract_pair_features(candidate: Mapping[str, object]) -> dict[str, float]:
    """Project one rule candidate onto the fixed, raw-value-free feature schema."""
    review_score = _finite_number(
        candidate.get("review_priority_score"), "review_priority_score"
    )
    uncapped_score = _finite_number(candidate.get("uncapped_score"), "uncapped_score")
    if not 0.0 <= review_score <= 100.0 or uncapped_score < 0.0:
        raise PairFeatureError("rule scores are outside their supported range")
    strong_count = _nonnegative_int(candidate.get("strong_family_count"), "strong_family_count")
    support_count = _nonnegative_int(
        candidate.get("support_family_count"), "support_family_count"
    )

    left = _mapping(candidate.get("left"), "left")
    right = _mapping(candidate.get("right"), "right")
    synthetic_side_count = 0
    for side in (left, right):
        synthetic = side.get("synthetic_identity", False)
        if not isinstance(synthetic, bool):
            raise PairFeatureError("synthetic_identity must be boolean")
        synthetic_side_count += int(synthetic)

    support_values: dict[str, tuple[int, float]] = {}
    for raw_support in _list(candidate.get("supporting_evidence"), "supporting_evidence"):
        support = _mapping(raw_support, "supporting_evidence item")
        family = support.get("family")
        if not isinstance(family, str) or family not in _SUPPORT_FAMILIES:
            raise PairFeatureError("unsupported support family")
        if family in support_values:
            raise PairFeatureError("duplicate support family")
        match_count = _nonnegative_int(support.get("match_count"), "match_count")
        weight = _finite_number(support.get("weight"), "support weight")
        if weight < 0.0:
            raise PairFeatureError("support weight must be non-negative")
        support_values[family] = (match_count, weight)
    if support_count != len(support_values) or strong_count > support_count:
        raise PairFeatureError("support family counts are inconsistent")

    excluded_counts = {family: 0 for family in _SUPPORT_FAMILIES}
    for raw_excluded in _list(candidate.get("excluded_evidence"), "excluded_evidence"):
        excluded = _mapping(raw_excluded, "excluded_evidence item")
        family = excluded.get("family")
        if not isinstance(family, str) or family not in excluded_counts:
            raise PairFeatureError("unsupported excluded evidence family")
        excluded_counts[family] += 1

    cap_flags = {code: 0 for code in _CAP_CODES}
    seen_caps: set[str] = set()
    for raw_cap in _list(candidate.get("score_caps"), "score_caps"):
        cap = _mapping(raw_cap, "score_caps item")
        code = cap.get("code")
        if not isinstance(code, str) or code not in cap_flags:
            raise PairFeatureError("unsupported score cap")
        if code in seen_caps:
            raise PairFeatureError("duplicate score cap")
        seen_caps.add(code)
        cap_value = _finite_number(cap.get("cap"), "score cap")
        if not 0.0 <= cap_value <= 100.0:
            raise PairFeatureError("score cap is outside 0..100")
        cap_flags[code] = 1

    gap_counts = {
        "unknown": 0,
        "observed_with_invalid_siblings": 0,
        "invalid_only": 0,
    }
    for raw_gap in _list(candidate.get("coverage_gaps"), "coverage_gaps"):
        gap = _mapping(raw_gap, "coverage_gaps item")
        status = gap.get("status")
        if not isinstance(status, str) or status not in gap_counts:
            raise PairFeatureError("unsupported coverage gap status")
        gap_counts[status] += 1

    features: dict[str, float] = {
        "rule_review_priority_score": review_score,
        "rule_uncapped_score": uncapped_score,
        "strong_family_count": float(strong_count),
        "support_family_count": float(support_count),
        "synthetic_side_count": float(synthetic_side_count),
    }
    for family in _SUPPORT_FAMILIES:
        match_count, weight = support_values.get(family, (0, 0.0))
        features[f"support_{family}"] = float(family in support_values)
        features[f"match_count_{family}"] = float(match_count)
        features[f"weight_{family}"] = weight
    for family in _SUPPORT_FAMILIES:
        features[f"excluded_{family}_count"] = float(excluded_counts[family])
    for code in _CAP_CODES:
        features[f"cap_{code}"] = float(cap_flags[code])
    features["coverage_unknown_count"] = float(gap_counts["unknown"])
    features["coverage_observed_with_invalid_siblings_count"] = float(
        gap_counts["observed_with_invalid_siblings"]
    )
    features["coverage_invalid_only_count"] = float(gap_counts["invalid_only"])
    if tuple(features) != PAIR_FEATURE_NAMES:
        raise AssertionError("pair feature implementation drifted from its allowlist")
    return features


def feature_vector(features: Mapping[str, object]) -> tuple[float, ...]:
    """Validate an exact feature mapping and return allowlist-ordered values."""
    if set(features) != set(PAIR_FEATURE_NAMES):
        raise PairFeatureError("feature names do not exactly match the allowlist")
    return tuple(_finite_number(features[name], name) for name in PAIR_FEATURE_NAMES)


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
        raise ArtifactValidationError("artifact is not strict JSON-safe data") from exc
    return rendered.encode("ascii")


def _artifact_digest(payload: Mapping[str, object]) -> str:
    unsigned = dict(payload)
    unsigned.pop("artifact_digest", None)
    return hashlib.sha256(_canonical_json(unsigned)).hexdigest()


def seal_linkage_model_artifact(payload: Mapping[str, object]) -> dict[str, object]:
    """Attach a deterministic digest and validate a JSON-safe artifact payload."""
    if "artifact_digest" in payload:
        raise ArtifactValidationError("unsigned artifact payload already has a digest")
    sealed = copy.deepcopy(dict(payload))
    sealed["artifact_digest"] = _artifact_digest(sealed)
    validate_linkage_model_artifact(sealed)
    return sealed


def _exact_keys(value: Mapping[str, object], expected: frozenset[str], field: str) -> None:
    if set(value) != expected:
        raise ArtifactValidationError(f"{field} fields do not match the artifact schema")


def _artifact_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ArtifactValidationError(f"{field} must be numeric")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise ArtifactValidationError(f"{field} must be finite") from exc
    if not math.isfinite(result):
        raise ArtifactValidationError(f"{field} must be finite")
    return result


def _artifact_count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ArtifactValidationError(f"{field} must be a non-negative integer")
    return value


def _float_array(value: object, field: str, *, positive: bool = False) -> tuple[float, ...]:
    if not isinstance(value, list) or len(value) != len(PAIR_FEATURE_NAMES):
        raise ArtifactValidationError(f"{field} length does not match the feature schema")
    result = tuple(_artifact_number(item, field) for item in value)
    if positive and any(item <= 0.0 for item in result):
        raise ArtifactValidationError(f"{field} values must be positive")
    return result


def _validate_model_instance(model: LinkageModelArtifact) -> LinkageModelArtifact:
    """Enforce the artifact projection invariants for every API entry path."""
    if model.model_id != LINKAGE_ML_MODEL_ID:
        raise ArtifactValidationError("unsupported model id")
    if model.feature_schema_version != PAIR_FEATURE_SCHEMA_VERSION:
        raise ArtifactValidationError("unsupported pair feature schema")
    if model.feature_names != PAIR_FEATURE_NAMES:
        raise ArtifactValidationError("artifact feature allowlist or order is invalid")

    expected = current_rule_engine_contract()
    actual = {
        "policy_id": model.rule_policy_id,
        "policy_digest": model.rule_policy_digest,
        "result_schema_version": model.rule_result_schema_version,
        "feature_schema_version": model.rule_feature_schema_version,
        "normalization_version": model.rule_normalization_version,
    }
    if actual != expected:
        raise ArtifactValidationError("artifact rule engine contract is incompatible")

    arrays = {
        "scaler.mean": model.scaler_mean,
        "scaler.scale": model.scaler_scale,
        "coefficients": model.coefficients,
    }
    for field, values in arrays.items():
        if not isinstance(values, tuple) or len(values) != len(PAIR_FEATURE_NAMES):
            raise ArtifactValidationError(f"{field} length does not match the feature schema")
        for value in values:
            _artifact_number(value, field)
    if any(value <= 0.0 for value in model.scaler_scale):
        raise ArtifactValidationError("scaler.scale values must be positive")
    _artifact_number(model.intercept, "intercept")
    if _SHA256_RE.fullmatch(model.artifact_digest) is None:
        raise ArtifactValidationError("artifact_digest must be a SHA-256 digest")
    return model


def validate_linkage_model_artifact(
    artifact: Mapping[str, object],
) -> LinkageModelArtifact:
    """Validate schema, feature order, finite values and the content digest."""
    if not isinstance(artifact, Mapping):
        raise ArtifactValidationError("artifact must be an object")
    _exact_keys(artifact, _ARTIFACT_FIELDS, "artifact")
    _canonical_json(artifact)
    if artifact.get("artifact_schema_version") != MODEL_ARTIFACT_SCHEMA_VERSION:
        raise ArtifactValidationError("unsupported artifact schema version")
    if artifact.get("model_id") != LINKAGE_ML_MODEL_ID:
        raise ArtifactValidationError("unsupported model id")
    if artifact.get("model_kind") != "logistic_regression":
        raise ArtifactValidationError("unsupported model kind")
    if artifact.get("feature_schema_version") != PAIR_FEATURE_SCHEMA_VERSION:
        raise ArtifactValidationError("unsupported pair feature schema")
    if artifact.get("feature_names") != list(PAIR_FEATURE_NAMES):
        raise ArtifactValidationError("artifact feature allowlist or order is invalid")
    if artifact.get("score_semantics") != ML_SCORE_SEMANTICS:
        raise ArtifactValidationError("artifact score semantics are invalid")
    if artifact.get("experimental") is not True:
        raise ArtifactValidationError("challenger artifact must remain experimental")

    calibration = artifact.get("calibration")
    if not isinstance(calibration, Mapping):
        raise ArtifactValidationError("calibration must be an object")
    _exact_keys(
        calibration,
        frozenset({"status", "score_semantics"}),
        "calibration",
    )
    if calibration.get("status") != "not_calibrated":
        raise ArtifactValidationError("unsupported calibration status")
    if calibration.get("score_semantics") != ML_SCORE_SEMANTICS:
        raise ArtifactValidationError("calibration score semantics are invalid")

    rule_engine = artifact.get("rule_engine")
    if not isinstance(rule_engine, Mapping):
        raise ArtifactValidationError("rule_engine must be an object")
    _exact_keys(rule_engine, _RULE_ENGINE_FIELDS, "rule_engine")
    expected_rule_engine = current_rule_engine_contract()
    for field, expected in expected_rule_engine.items():
        if rule_engine.get(field) != expected:
            raise ArtifactValidationError(
                f"rule_engine.{field} is incompatible with the current rule engine"
            )

    runtime = artifact.get("training_runtime")
    if not isinstance(runtime, Mapping):
        raise ArtifactValidationError("training_runtime must be an object")
    _exact_keys(runtime, _TRAINING_RUNTIME_FIELDS, "training_runtime")
    if runtime.get("dependency_name") != "scikit-learn":
        raise ArtifactValidationError("training dependency name is invalid")
    for field in ("fxapk_version", "dependency_version"):
        value = runtime.get(field)
        if not isinstance(value, str) or _SAFE_VERSION_RE.fullmatch(value) is None:
            raise ArtifactValidationError(f"training_runtime.{field} is invalid")

    scaler = artifact.get("scaler")
    if not isinstance(scaler, Mapping):
        raise ArtifactValidationError("scaler must be an object")
    _exact_keys(scaler, frozenset({"mean", "scale"}), "scaler")
    scaler_mean = _float_array(scaler.get("mean"), "scaler.mean")
    scaler_scale = _float_array(scaler.get("scale"), "scaler.scale", positive=True)
    coefficients = _float_array(artifact.get("coefficients"), "coefficients")
    intercept = _artifact_number(artifact.get("intercept"), "intercept")

    thresholds = artifact.get("readiness_thresholds")
    if not isinstance(thresholds, Mapping):
        raise ArtifactValidationError("readiness_thresholds must be an object")
    _exact_keys(thresholds, _THRESHOLD_FIELDS, "readiness_thresholds")
    for field in sorted(_THRESHOLD_FIELDS):
        value = _artifact_count(thresholds.get(field), field)
        # ★非负整数不够：门禁侧强制政策下限后，这里必须同样强制，否则"绕过门禁另行拼装
        #   低门槛 artifact"仍能通过校验进入加载/shadow 路径。
        if value < READINESS_POLICY_FLOOR.get(field, 0):
            raise ArtifactValidationError(
                f"readiness_thresholds.{field} is below the policy floor"
            )

    summary = artifact.get("training_summary")
    if not isinstance(summary, Mapping):
        raise ArtifactValidationError("training_summary must be an object")
    _exact_keys(summary, _SUMMARY_FIELDS, "training_summary")
    for field in sorted(_SUMMARY_COUNT_FIELDS):
        _artifact_count(summary.get(field), field)
    for field in ("dataset_digest", "holdout_dataset_digest", "split_digest"):
        value = summary.get(field)
        if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
            raise ArtifactValidationError(f"{field} must be a SHA-256 digest")
    if summary.get("weighting_version") != "component-balanced-v1":
        raise ArtifactValidationError("training weighting version is unsupported")
    if summary.get("preprocessing_scope") != "train-partition-frozen-v1":
        raise ArtifactValidationError("training preprocessing scope is unsupported")
    seed = _artifact_count(summary.get("seed"), "seed")
    if seed > 2**32 - 1:
        raise ArtifactValidationError("seed exceeds the supported range")
    test_fraction = _artifact_number(summary.get("test_fraction"), "test_fraction")
    if not 0.0 < test_fraction < 1.0:
        raise ArtifactValidationError("test_fraction must be between 0 and 1")
    holdout_metrics = summary.get("holdout_metrics")
    if not isinstance(holdout_metrics, Mapping):
        raise ArtifactValidationError("holdout_metrics must be an object")
    _exact_keys(holdout_metrics, _HOLDOUT_METRIC_FIELDS, "holdout_metrics")
    for field in ("roc_auc", "average_precision"):
        value = _artifact_number(holdout_metrics.get(field), field)
        if not 0.0 <= value <= 1.0:
            raise ArtifactValidationError(f"{field} must be within 0..1")
    for field in ("positive_mean_rank_score", "negative_mean_rank_score"):
        value = _artifact_number(holdout_metrics.get(field), field)
        if not 0.0 <= value <= 100.0:
            raise ArtifactValidationError(f"{field} must be within 0..100")

    digest = artifact.get("artifact_digest")
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise ArtifactValidationError("artifact_digest must be a SHA-256 digest")
    if not hmac.compare_digest(digest, _artifact_digest(artifact)):
        raise ArtifactValidationError("artifact digest mismatch")
    return LinkageModelArtifact(
        model_id=LINKAGE_ML_MODEL_ID,
        feature_schema_version=PAIR_FEATURE_SCHEMA_VERSION,
        feature_names=PAIR_FEATURE_NAMES,
        rule_policy_id=expected_rule_engine["policy_id"],
        rule_policy_digest=expected_rule_engine["policy_digest"],
        rule_result_schema_version=expected_rule_engine["result_schema_version"],
        rule_feature_schema_version=expected_rule_engine["feature_schema_version"],
        rule_normalization_version=expected_rule_engine["normalization_version"],
        scaler_mean=scaler_mean,
        scaler_scale=scaler_scale,
        coefficients=coefficients,
        intercept=intercept,
        artifact_digest=digest,
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_linkage_model_artifact_json(text: str) -> LinkageModelArtifact:
    """Parse a strict JSON artifact without accepting NaN, Infinity or duplicate keys."""
    if not isinstance(text, str):
        raise ArtifactValidationError("artifact JSON must be text")

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON constant")

    try:
        value = json.loads(
            text,
            parse_constant=reject_constant,
            object_pairs_hook=_unique_json_object,
        )
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ArtifactValidationError("artifact is not strict JSON") from exc
    if not isinstance(value, Mapping):
        raise ArtifactValidationError("artifact must be a JSON object")
    return validate_linkage_model_artifact(value)


def score_pair_features(
    features: Mapping[str, object], artifact: Mapping[str, object] | LinkageModelArtifact
) -> float:
    """Return a bounded ranking score; it is intentionally not a probability."""
    model = _validate_model_instance(
        artifact
        if isinstance(artifact, LinkageModelArtifact)
        else validate_linkage_model_artifact(artifact)
    )
    vector = feature_vector(features)
    logit = model.intercept
    for value, mean, scale, coefficient in zip(
        vector, model.scaler_mean, model.scaler_scale, model.coefficients
    ):
        logit += ((value - mean) / scale) * coefficient
    if not math.isfinite(logit):
        raise ArtifactValidationError("model produced a non-finite logit")
    if logit >= 0.0:
        rank_fraction = 1.0 / (1.0 + math.exp(-logit))
    else:
        exp_logit = math.exp(logit)
        rank_fraction = exp_logit / (1.0 + exp_logit)
    return round(rank_fraction * 100.0, 6)


def _candidate_rule_cap(candidate: Mapping[str, object]) -> float:
    caps = candidate.get("score_caps")
    if not isinstance(caps, list):
        raise PairFeatureError("score_caps must be a list")
    result = 100.0
    for raw_cap in caps:
        cap = _mapping(raw_cap, "score_caps item")
        value = _finite_number(cap.get("cap"), "score cap")
        if not 0.0 <= value <= 100.0:
            raise PairFeatureError("score cap is outside 0..100")
        result = min(result, value)
    return result


def rerank_rule_candidates(
    rule_result: dict[str, Any],
    artifact: Mapping[str, object] | LinkageModelArtifact | None = None,
) -> dict[str, Any]:
    """Optionally rerank only existing candidates while enforcing every rule cap."""
    if artifact is None:
        return rule_result
    if not isinstance(rule_result, dict):
        raise TypeError("rule_result must be a dict")
    model = _validate_model_instance(
        artifact
        if isinstance(artifact, LinkageModelArtifact)
        else validate_linkage_model_artifact(artifact)
    )
    rule_model = rule_result.get("model")
    if not isinstance(rule_model, Mapping):
        raise ArtifactValidationError("rule result model contract is missing")
    actual_rule_contract = {
        "policy_id": rule_model.get("id"),
        "policy_digest": rule_model.get("policy_digest"),
        "result_schema_version": rule_model.get("result_schema_version"),
        "feature_schema_version": rule_model.get("feature_schema_version"),
        "normalization_version": rule_model.get("normalization_version"),
    }
    expected_rule_contract = {
        "policy_id": model.rule_policy_id,
        "policy_digest": model.rule_policy_digest,
        "result_schema_version": model.rule_result_schema_version,
        "feature_schema_version": model.rule_feature_schema_version,
        "normalization_version": model.rule_normalization_version,
    }
    if rule_result.get("schema_version") != model.rule_result_schema_version:
        raise ArtifactValidationError("rule result schema is incompatible with the model")
    for field, expected in expected_rule_contract.items():
        if actual_rule_contract[field] != expected:
            raise ArtifactValidationError(
                f"rule result {field} is incompatible with the model artifact"
            )
    raw_candidates = rule_result.get("candidates")
    if not isinstance(raw_candidates, list):
        raise PairFeatureError("rule_result candidates must be a list")

    reranked: list[tuple[float, int, dict[str, Any]]] = []
    for fallback_rank, raw_candidate in enumerate(raw_candidates, start=1):
        if not isinstance(raw_candidate, Mapping):
            raise PairFeatureError("candidate must be an object")
        features = extract_pair_features(raw_candidate)
        raw_score = score_pair_features(features, model)
        applied_score = min(raw_score, _candidate_rule_cap(raw_candidate))
        original_rank = raw_candidate.get("rank", fallback_rank)
        if isinstance(original_rank, bool) or not isinstance(original_rank, int) or original_rank < 1:
            raise PairFeatureError("candidate rank must be a positive integer")
        candidate_copy = copy.deepcopy(dict(raw_candidate))
        candidate_copy["ml_raw_rank_score"] = raw_score
        candidate_copy["ml_rank_score"] = applied_score
        candidate_copy["ml_score_semantics"] = ML_SCORE_SEMANTICS
        reranked.append((applied_score, original_rank, candidate_copy))
    reranked.sort(key=lambda row: (-row[0], row[1]))
    for ml_rank, (_score, _rule_rank, candidate) in enumerate(reranked, start=1):
        candidate["ml_rank"] = ml_rank

    result = copy.deepcopy(rule_result)
    result["candidates"] = [candidate for _score, _rank, candidate in reranked]
    result["ml"] = {
        "status": "applied",
        "experimental": True,
        "model_id": model.model_id,
        "feature_schema_version": model.feature_schema_version,
        "rule_engine": expected_rule_contract,
        "artifact_digest": model.artifact_digest,
        "score_semantics": ML_SCORE_SEMANTICS,
        "candidate_space": "deterministic_rule_candidates_only",
        "deterministic_caps_enforced": True,
    }
    return result
