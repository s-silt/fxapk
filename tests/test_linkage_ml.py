"""Gated local challenger training and standard-library inference contracts."""

from __future__ import annotations

import copy
import json
import math

import pytest

from apkscan.core import linkage_ml, linkage_training
from apkscan.core.linkage import rank_link_candidates
from apkscan.core.linkage_labels import validate_linkage_label_records
from apkscan.core.linkage_labels import build_linkage_ground_truth
from apkscan.core.linkage_ml import (
    ArtifactValidationError,
    ML_SCORE_SEMANTICS,
    PAIR_FEATURE_NAMES,
    PairFeatureError,
    extract_pair_features,
    load_linkage_model_artifact_json,
    rerank_rule_candidates,
    score_pair_features,
    validate_linkage_model_artifact,
)
from apkscan.core.linkage_training import (
    DEFAULT_READINESS_THRESHOLDS,
    ReadinessThresholds,
    assess_training_readiness,
    build_training_dataset,
    split_group_disjoint,
    train_linkage_challenger,
)


def _sha(char: str) -> str:
    return char * 64


def _entry(sample: str, native_sha: str) -> dict:
    return {
        "sample_sha256": sample,
        "sample_sha256_synthetic": False,
        "tool_version": "1.0",
        "ruleset_digest": "rules-v1",
        "evidence_surface": "static",
        "case_ids": ["private-case-fixture"],
        "native_lib_hashes": [{"name": "libfamilycore.so", "sha256": native_sha}],
        "build_environments": [],
        "remote_config_objects": [],
        "key_iocs": [],
        "case_ioc_scope_indexed": True,
        "repack_identity_verdict": "unknown",
        "visibility": {},
    }


def _family(
    sample: str,
    family_id: str,
    *,
    subtype: str = "binary_lineage",
    basis: str = "independent-review",
) -> dict:
    return {
        "kind": "family_membership",
        "schema_version": "1.0",
        "sample_sha256": sample,
        "family_id": family_id,
        "relation_subtype": subtype,
        "status": "confirmed",
        "label_basis": [basis],
        "reason_codes": ["manual-diff"],
        "evidence_ref": "fixture-evidence-bundle-001",
    }


def _negative(
    left: str,
    right: str,
    *,
    relation: str = "negative",
    basis: str = "independent-review",
    sampling_class: str | None = None,
) -> dict:
    if sampling_class is None:
        sampling_class = "hard" if relation == "negative" else "unspecified"
    return {
        "kind": "pair_judgment",
        "schema_version": "1.0",
        "left_sha256": left,
        "right_sha256": right,
        "relation": relation,
        "relation_subtype": "technical_link_relevant",
        "status": "confirmed",
        "reason_codes": ["manual-diff"],
        "sampling_class": sampling_class,
        "label_basis": [basis],
        "evidence_ref": "fixture-evidence-bundle-001",
    }


def _training_fixture() -> tuple[list[dict], object, list[str], str]:
    samples = [_sha(char) for char in "12345678"]
    native_sha = _sha("f")
    entries = [_entry(sample, native_sha) for sample in samples]
    family_index: dict[str, int] = {}
    records: list[dict] = []
    for family_number, offset in enumerate(range(0, len(samples), 2), start=1):
        for sample in samples[offset : offset + 2]:
            family_index[sample] = family_number
            records.append(_family(sample, f"opaque-family-{family_number}"))
    for left_index, left in enumerate(samples):
        for right in samples[left_index + 1 :]:
            if family_index[left] != family_index[right]:
                records.append(_negative(left, right))
    labels = validate_linkage_label_records(records)
    return entries, labels, samples, native_sha


LOW_THRESHOLDS = ReadinessThresholds(
    min_real_samples=8,
    min_family_groups=4,
    min_positive_pairs=4,
    min_negative_pairs=24,
    min_hard_negative_pairs=24,
)

SPLIT_THRESHOLDS = ReadinessThresholds(
    min_real_samples=4,
    min_family_groups=2,
    min_positive_pairs=2,
    min_negative_pairs=4,
    min_hard_negative_pairs=4,
)

#: 测试用"无下限"政策线。生产侧没有任何参数 / 环境变量 / 配置能达到同样效果——
#: 只有测试进程内 monkeypatch 模块常量这一条路（见 sub_floor_gate fixture）。
_NO_FLOOR = {name: 0 for name in DEFAULT_READINESS_THRESHOLDS.as_dict()}


@pytest.fixture
def sub_floor_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """让本测试可用小门槛驱动训练管线机制（split/权重/artifact 形状），不弱化政策锁。

    政策下限本身另有不打补丁的专测（test_policy_floor_*）锁着；本 fixture 只对
    "机制类"测试开小门槛，两个模块常量都要补——门禁侧与 artifact 校验侧各持一份绑定。
    """
    monkeypatch.setattr(linkage_training, "READINESS_POLICY_FLOOR", _NO_FLOOR)
    monkeypatch.setattr(linkage_ml, "READINESS_POLICY_FLOOR", _NO_FLOOR)


def test_default_readiness_thresholds_are_the_approved_gate() -> None:
    assert DEFAULT_READINESS_THRESHOLDS.as_dict() == {
        "min_real_samples": 200,
        "min_family_groups": 10,
        "min_positive_pairs": 300,
        "min_negative_pairs": 600,
        "min_hard_negative_pairs": 500,
    }


def test_policy_floor_matches_the_approved_default_gate() -> None:
    """政策下限与默认门槛同源同值：改任何一边都必须显式过 policy 评审。"""
    assert dict(linkage_ml.READINESS_POLICY_FLOOR) == DEFAULT_READINESS_THRESHOLDS.as_dict()


def test_policy_floor_rejects_lowered_thresholds_at_every_gate() -> None:
    """★P0 锁：调用方传入低于政策下限的门槛，三个门禁入口一律 fail-closed 拒绝。

    没有这道锁时 `ReadinessThresholds(0,0,0,0,0)` 可把门槛压到 0——一旦出现极少量
    独立正负样本，门禁就会放行并产出 artifact。删除 `_require_policy_floor` 调用
    （突变验证目标）必须让本测试变红。
    """
    entries, labels, _samples, _native_sha = _training_fixture()
    dataset = build_training_dataset(entries, labels)
    with pytest.raises(ValueError, match="policy floor"):
        linkage_training.training_readiness(dataset, LOW_THRESHOLDS)
    with pytest.raises(ValueError, match="policy floor"):
        assess_training_readiness(entries, labels, ReadinessThresholds(0, 0, 0, 0, 0))
    with pytest.raises(ValueError, match="policy floor"):
        train_linkage_challenger(entries, labels, thresholds=SPLIT_THRESHOLDS)


def test_policy_floor_allows_raising_thresholds_above_the_default() -> None:
    """门槛只许抬高不许降低：高于政策线的自定义门槛正常进入门禁逻辑。"""
    entries, labels, _samples, _native_sha = _training_fixture()
    raised = ReadinessThresholds(
        min_real_samples=400,
        min_family_groups=20,
        min_positive_pairs=600,
        min_negative_pairs=1200,
        min_hard_negative_pairs=1000,
    )
    readiness = assess_training_readiness(entries, labels, raised)
    assert readiness["status"] == "blocked"
    assert readiness["thresholds"] == raised.as_dict()


def test_artifact_recording_sub_floor_thresholds_is_rejected(monkeypatch) -> None:
    """★P0 锁（artifact 侧）：绕开门禁拼出的低门槛 artifact 不得通过校验进入加载路径。"""

    def _fake_fit(features, targets, sample_weight, *, seed):  # noqa: ANN001, ARG001
        return (tuple(0.0 for _ in PAIR_FEATURE_NAMES), 0.0, "test-sklearn")

    entries, labels, _samples, _native_sha = _training_fixture()
    monkeypatch.setattr(linkage_training, "_fit_logistic_regression", _fake_fit)
    with monkeypatch.context() as patched:
        patched.setattr(linkage_training, "READINESS_POLICY_FLOOR", _NO_FLOOR)
        patched.setattr(linkage_ml, "READINESS_POLICY_FLOOR", _NO_FLOOR)
        artifact = train_linkage_challenger(
            entries, labels, thresholds=SPLIT_THRESHOLDS, test_fraction=0.5, seed=17
        )["artifact"]

    with pytest.raises(ArtifactValidationError, match="policy floor"):
        validate_linkage_model_artifact(artifact)


def test_pair_features_have_a_fixed_allowlist_and_no_raw_values() -> None:
    entries, _labels, samples, native_sha = _training_fixture()
    candidate = rank_link_candidates(entries, limit=None)["candidates"][0]
    features = extract_pair_features(candidate)

    assert tuple(features) == PAIR_FEATURE_NAMES
    assert all(math.isfinite(value) for value in features.values())
    rendered = json.dumps(features, sort_keys=True)
    for private_value in (*samples, native_sha, "private-case-fixture"):
        assert private_value not in rendered


def test_pair_features_parse_five_state_gaps_and_deterministic_caps() -> None:
    left = _entry(_sha("1"), _sha("f"))
    left["native_lib_hashes"].append({"sha256": "invalid"})
    left["record_state"] = "quarantined"
    left["repack_identity_verdict"] = "repack_suspected"
    right = _entry(_sha("2"), _sha("f"))

    candidate = rank_link_candidates([left, right], limit=None)["candidates"][0]
    features = extract_pair_features(candidate)

    assert features["coverage_observed_with_invalid_siblings_count"] == 1.0
    assert features["coverage_invalid_only_count"] == 0.0
    assert features["cap_repack_suspected"] == 1.0
    assert features["cap_non_authoritative_input"] == 1.0


def test_nonfinite_or_unknown_feature_contract_fails_closed() -> None:
    entries, _labels, _samples, _native_sha = _training_fixture()
    candidate = copy.deepcopy(rank_link_candidates(entries, limit=None)["candidates"][0])
    candidate["review_priority_score"] = float("nan")
    with pytest.raises(PairFeatureError, match="finite"):
        extract_pair_features(candidate)


def test_readiness_counts_only_rule_recalled_confirmed_pairs(sub_floor_gate) -> None:
    entries, labels, _samples, _native_sha = _training_fixture()
    readiness = linkage_training.training_readiness(
        build_training_dataset(entries, labels), LOW_THRESHOLDS
    )
    assert readiness == {
        "status": "ready",
        "ready": True,
        "reason": None,
        "counts": {
            "real_sample_count": 8,
            "family_group_count": 4,
            "positive_pair_count": 4,
            "negative_pair_count": 24,
            "hard_negative_pair_count": 24,
            "independent_label_positive_pair_count": 4,
            "independent_label_negative_pair_count": 24,
            "independent_label_hard_negative_pair_count": 24,
            "feature_overlap_excluded_positive_pair_count": 0,
            "feature_overlap_excluded_negative_pair_count": 0,
            "missing_basis_pair_count": 0,
        },
        "thresholds": LOW_THRESHOLDS.as_dict(),
        "unmet": [],
        "scope": "rule_recalled_confirmed_independent_pairs_only",
        "label_feature_independence": {
            "training_rows_use_independent_pairs_only": True,
            "feature_overlap_excluded_pair_count": 0,
            "missing_basis_pair_count": 0,
        },
    }


def test_hard_negative_gate_count_requires_declaration_and_rule_recall(sub_floor_gate) -> None:
    """★锁死 min_hard_negative_pairs 的门禁判据 = sampling_class 声明 ∧ 被 ranker 召回。

    sampling_class 是纯声明字段（与 label_basis 独立性自声明同构），但 hard 有机器可推导的
    结构侧：候选生成纯靠共享锚倒排，被召回 ⇔ 共享 ≥1 个非弱锚。两个方向都要锁：
    ① 声明 hard 但未被召回（a/c 无共享锚）→ 不得进入门禁计数——把计数改成「声明侧 present」
      的突变必须在这里变红；
    ② 被召回但声明 easy（a/x 共锚）→ 不得被推导「升格」为 hard——把判据改成「召回即 hard」
      的突变（会让门禁变松）也必须在这里变红。
    声明侧只进对照列 independent_label_hard_negative_pair_count，标注而非删除。
    """
    a, b, x, c = (_sha(char) for char in "1234")
    entries = [
        _entry(a, _sha("e")),
        _entry(b, _sha("e")),
        _entry(x, _sha("e")),
        _entry(c, _sha("d")),
    ]
    labels = validate_linkage_label_records(
        [
            _negative(a, b),  # 召回 ∧ 声明 hard → 唯一进门禁计数的一条
            _negative(a, x, sampling_class="easy"),  # 召回但声明 easy → 不升格
            _negative(a, c),  # 声明 hard 但无共享锚、不被召回 → 只进声明侧对照列
        ]
    )
    dataset = build_training_dataset(entries, labels)

    assert dataset.negative_pair_count == 2
    assert dataset.hard_negative_pair_count == 1
    assert dataset.independent_label_negative_pair_count == 3
    assert dataset.independent_label_hard_negative_pair_count == 2
    readiness = linkage_training.training_readiness(
        dataset, ReadinessThresholds(0, 0, 0, 0, 0)
    )
    assert readiness["counts"]["hard_negative_pair_count"] == 1
    assert readiness["counts"]["independent_label_hard_negative_pair_count"] == 2


def test_unknown_pair_is_not_counted_as_positive_or_negative(sub_floor_gate) -> None:
    left, right, native = _sha("1"), _sha("2"), _sha("f")
    labels = validate_linkage_label_records([_negative(left, right, relation="unknown")])
    readiness = assess_training_readiness(
        [_entry(left, native), _entry(right, native)],
        labels,
        ReadinessThresholds(0, 0, 0, 0, 0),
    )
    assert readiness["counts"] == {
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
    }
    assert readiness["status"] == "blocked"
    assert readiness["reason"] == "insufficient_independent_labels"


def test_feature_overlapping_truth_is_excluded_from_training_rows(sub_floor_gate) -> None:
    a, b, c = _sha("1"), _sha("2"), _sha("3")
    native = _sha("f")
    labels = validate_linkage_label_records(
        [
            _family(a, "family-native", basis="native-binary-review"),
            _family(b, "family-native", basis="native-binary-review"),
            _negative(a, c),
        ]
    )
    dataset = build_training_dataset([_entry(sample, native) for sample in (a, b, c)], labels)
    readiness = linkage_training.training_readiness(dataset, ReadinessThresholds(0, 0, 0, 0, 0))

    assert dataset.positive_pair_count == 0
    assert dataset.negative_pair_count == 1
    assert dataset.feature_overlap_excluded_positive_pair_count == 1
    assert readiness["status"] == "blocked"
    assert readiness["reason"] == "insufficient_independent_labels"


def test_family_group_count_is_unique_positive_component_not_subtype_count() -> None:
    a, b, c, d = (_sha(char) for char in "1234")
    native = _sha("f")
    labels = validate_linkage_label_records(
        [
            _family(a, "binary-family"),
            _family(b, "binary-family"),
            _family(a, "control-family", subtype="control_plane"),
            _family(b, "control-family", subtype="control_plane"),
            _family(c, "other-family"),
            _family(d, "other-family"),
            _negative(a, c),
        ]
    )
    dataset = build_training_dataset([_entry(sample, native) for sample in (a, b, c, d)], labels)

    assert dataset.positive_pair_count == 2
    assert dataset.family_group_count == 2


def test_split_components_include_unrecalled_transitive_positive_links() -> None:
    a, b, c, d = (_sha(char) for char in "1234")
    shared = _sha("f")
    labels = validate_linkage_label_records(
        [
            _negative(a, b, relation="positive"),
            _negative(b, c, relation="positive"),
            _negative(a, d),
            _negative(c, d),
        ]
    )
    dataset = build_training_dataset(
        [
            _entry(a, shared),
            _entry(b, _sha("e")),
            _entry(c, shared),
            _entry(d, shared),
        ],
        labels,
    )

    components = dataset.components()
    assert components[a] == components[c]
    assert components[a] != components[d]


def test_split_components_include_feature_overlapping_confirmed_family_links() -> None:
    a, b, c, d = (_sha(char) for char in "1234")
    shared = _sha("f")
    labels = validate_linkage_label_records(
        [
            _family(a, "overlap-family", basis="native-binary-review"),
            _family(b, "overlap-family", basis="native-binary-review"),
            _negative(a, c, relation="positive"),
            _negative(b, d, relation="positive"),
        ]
    )

    dataset = build_training_dataset(
        [_entry(sample, shared) for sample in (a, b, c, d)], labels
    )
    components = dataset.components()

    assert dataset.feature_overlap_excluded_positive_pair_count == 1
    assert dataset.positive_pair_count == 2
    assert components[a] == components[b] == components[c] == components[d]
    assert dataset.family_group_count == 1


def test_default_gate_blocks_before_training_dependency_is_called(monkeypatch) -> None:
    entries, labels, _samples, _native_sha = _training_fixture()
    called = False

    def _must_not_fit(features, targets, *, seed):  # noqa: ANN001, ARG001
        nonlocal called
        called = True
        raise AssertionError("fitter must not run below readiness thresholds")

    monkeypatch.setattr(linkage_training, "_fit_logistic_regression", _must_not_fit)
    result = train_linkage_challenger(entries, labels)
    assert result["status"] == "blocked"
    assert result["reason"] == "readiness_thresholds"
    assert result["readiness"]["ready"] is False
    assert "artifact" not in result
    assert called is False


def test_training_rechecks_readiness_after_group_split(monkeypatch, sub_floor_gate) -> None:
    entries, labels, _samples, _native_sha = _training_fixture()
    called = False

    def _must_not_fit(features, targets, sample_weight, *, seed):  # noqa: ANN001, ARG001
        nonlocal called
        called = True
        raise AssertionError("fitter must not run when the train partition is below thresholds")

    monkeypatch.setattr(linkage_training, "_fit_logistic_regression", _must_not_fit)
    result = train_linkage_challenger(
        entries,
        labels,
        thresholds=LOW_THRESHOLDS,
        test_fraction=0.5,
        seed=17,
    )

    assert result["status"] == "blocked"
    assert result["reason"] == "readiness_thresholds"
    assert result["readiness"]["counts"]["real_sample_count"] == 4
    assert result["readiness"]["counts"]["family_group_count"] == 2
    assert "artifact" not in result
    assert called is False


def test_holdout_basenames_cannot_change_training_features(monkeypatch, sub_floor_gate) -> None:
    entries, labels, _samples, _native_sha = _training_fixture()
    truth = build_linkage_ground_truth(labels)
    partition = linkage_training._split_manifest_entries(
        entries,
        truth,
        test_fraction=0.5,
        seed=17,
    )
    held_out = {
        row["sample_sha256"]
        for row in partition.test_entries
    }
    assert len(held_out) >= 3

    baseline = copy.deepcopy(entries)
    adversarial_holdout = copy.deepcopy(entries)
    suffixes = iter(("alpha", "bravo", "charlie", "delta"))
    for entry in adversarial_holdout:
        if entry["sample_sha256"] in held_out:
            entry["native_lib_hashes"][0]["name"] = f"lib{next(suffixes)}.so"

    fitted_features: list[list[list[float]]] = []

    def _capture_fit(features, targets, sample_weight, *, seed):  # noqa: ANN001, ARG001
        fitted_features.append(copy.deepcopy(features))
        return (tuple(0.0 for _ in PAIR_FEATURE_NAMES), 0.0, "test-sklearn")

    monkeypatch.setattr(linkage_training, "_fit_logistic_regression", _capture_fit)
    first = train_linkage_challenger(
        baseline,
        labels,
        thresholds=SPLIT_THRESHOLDS,
        test_fraction=0.5,
        seed=17,
    )
    second = train_linkage_challenger(
        adversarial_holdout,
        labels,
        thresholds=SPLIT_THRESHOLDS,
        test_fraction=0.5,
        seed=17,
    )

    assert first["status"] == second["status"] == "trained"
    assert fitted_features[0] == fitted_features[1]
    assert first["artifact"] == second["artifact"]


def test_positive_component_split_has_no_group_or_sample_leakage() -> None:
    entries, labels, _samples, _native_sha = _training_fixture()
    dataset = build_training_dataset(entries, labels)
    split = split_group_disjoint(dataset, test_fraction=0.5, seed=17)
    component_by_sample = dataset.components()

    assert set(split.train_components).isdisjoint(split.test_components)
    train_samples = {sample for row in split.train_rows for sample in row.pair}
    test_samples = {sample for row in split.test_rows for sample in row.pair}
    assert train_samples.isdisjoint(test_samples)
    for row in (*split.train_rows, *split.test_rows):
        assert (
            component_by_sample[row.pair[0]] == component_by_sample[row.pair[1]] or row.target == 0
        )
    assert split == split_group_disjoint(dataset, test_fraction=0.5, seed=17)


def test_split_rejects_fraction_that_overflows_float() -> None:
    entries, labels, _samples, _native_sha = _training_fixture()
    dataset = build_training_dataset(entries, labels)

    with pytest.raises(ValueError, match="test_fraction"):
        split_group_disjoint(dataset, test_fraction=10**400)


@pytest.mark.parametrize("seed", [-1, 2**32])
def test_split_rejects_seed_outside_sklearn_uint32_contract(seed: int) -> None:
    entries, labels, _samples, _native_sha = _training_fixture()
    dataset = build_training_dataset(entries, labels)

    with pytest.raises(ValueError, match="seed"):
        split_group_disjoint(dataset, test_fraction=0.5, seed=seed)


def test_component_balanced_weights_equalize_families_component_pairs_and_classes() -> None:
    a, b, c, d, e, f, g = (_sha(char) for char in "1234567")
    rows = (
        linkage_training.TrainingRow((a, b), (0.0,), 1, False),
        linkage_training.TrainingRow((a, c), (0.0,), 1, False),
        linkage_training.TrainingRow((b, c), (0.0,), 1, False),
        linkage_training.TrainingRow((d, e), (0.0,), 1, False),
        linkage_training.TrainingRow((f, g), (0.0,), 1, False),
        linkage_training.TrainingRow((a, d), (0.0,), 0, True),
        linkage_training.TrainingRow((b, d), (0.0,), 0, True),
        linkage_training.TrainingRow((a, e), (0.0,), 0, True),
        linkage_training.TrainingRow((b, e), (0.0,), 0, True),
        linkage_training.TrainingRow((c, e), (0.0,), 0, True),
        linkage_training.TrainingRow((a, f), (0.0,), 0, True),
        linkage_training.TrainingRow((d, f), (0.0,), 0, True),
    )
    components = {a: a, b: a, c: a, d: d, e: d, f: f, g: f}

    weights = linkage_training._component_balanced_weights(rows, components)

    assert sum(weight for row, weight in zip(rows, weights) if row.target == 1) == pytest.approx(
        len(rows) / 2
    )
    assert sum(weight for row, weight in zip(rows, weights) if row.target == 0) == pytest.approx(
        len(rows) / 2
    )
    assert sum(weights[:3]) == pytest.approx(weights[3]) == pytest.approx(weights[4])
    assert sum(weights[5:10]) == pytest.approx(weights[10]) == pytest.approx(weights[11])


def test_weighted_scaler_uses_the_same_component_balancing_weights() -> None:
    rows = (
        linkage_training.TrainingRow((_sha("1"), _sha("2")), (0.0,), 1, False),
        linkage_training.TrainingRow((_sha("1"), _sha("3")), (0.0,), 1, False),
        linkage_training.TrainingRow((_sha("4"), _sha("5")), (10.0,), 0, True),
    )

    mean, scale = linkage_training._fit_scaler(rows, (0.5, 0.5, 1.0))

    assert mean == pytest.approx((5.0,))
    assert scale == pytest.approx((5.0,))


def test_low_gate_training_exports_strict_raw_free_artifact(monkeypatch, sub_floor_gate) -> None:
    entries, labels, samples, native_sha = _training_fixture()

    def _fake_fit(features, targets, sample_weight, *, seed):  # noqa: ANN001, ARG001
        assert {0, 1} == set(targets)
        assert all(len(row) == len(PAIR_FEATURE_NAMES) for row in features)
        assert sum(sample_weight) == pytest.approx(len(targets))
        return (tuple(0.0 for _ in PAIR_FEATURE_NAMES), 10.0, "test-sklearn")

    monkeypatch.setattr(linkage_training, "_fit_logistic_regression", _fake_fit)
    result = train_linkage_challenger(
        entries,
        labels,
        thresholds=SPLIT_THRESHOLDS,
        test_fraction=0.5,
        seed=17,
    )
    assert result["status"] == "trained"
    artifact = result["artifact"]
    model = validate_linkage_model_artifact(artifact)
    assert model.feature_names == PAIR_FEATURE_NAMES
    assert len(model.artifact_digest) == 64
    assert artifact["score_semantics"] == ML_SCORE_SEMANTICS
    assert artifact["rule_engine"] == linkage_ml.current_rule_engine_contract()
    assert artifact["training_summary"]["weighting_version"] == "component-balanced-v1"
    assert artifact["training_summary"]["preprocessing_scope"] == "train-partition-frozen-v1"
    assert artifact["training_summary"]["seed"] == 17
    assert artifact["training_summary"]["test_fraction"] == 0.5
    assert set(artifact["training_summary"]["holdout_metrics"]) == {
        "average_precision",
        "negative_mean_rank_score",
        "positive_mean_rank_score",
        "roc_auc",
    }
    assert artifact["calibration"]["status"] == "not_calibrated"
    assert artifact["training_runtime"] == {
        "dependency_name": "scikit-learn",
        "dependency_version": "test-sklearn",
        "fxapk_version": linkage_training.FXAPK_VERSION,
    }

    rendered = json.dumps(artifact, allow_nan=False, sort_keys=True)
    loaded = load_linkage_model_artifact_json(rendered)
    assert loaded == model
    for private_value in (
        *samples,
        native_sha,
        "private-case-fixture",
        "opaque-family-1",
    ):
        assert private_value not in rendered


def test_artifact_tampering_and_nonfinite_values_fail_closed(monkeypatch, sub_floor_gate) -> None:
    entries, labels, _samples, _native_sha = _training_fixture()

    def _fake_fit(features, targets, sample_weight, *, seed):  # noqa: ANN001, ARG001
        return (tuple(0.0 for _ in PAIR_FEATURE_NAMES), 0.0, "test-sklearn")

    monkeypatch.setattr(linkage_training, "_fit_logistic_regression", _fake_fit)
    artifact = train_linkage_challenger(
        entries, labels, thresholds=SPLIT_THRESHOLDS, test_fraction=0.5, seed=17
    )["artifact"]

    tampered = copy.deepcopy(artifact)
    tampered["coefficients"][0] = 1.0
    with pytest.raises(ArtifactValidationError, match="digest mismatch"):
        validate_linkage_model_artifact(tampered)

    nonfinite = copy.deepcopy(artifact)
    nonfinite["coefficients"][0] = float("inf")
    with pytest.raises(ArtifactValidationError, match="JSON-safe|finite"):
        validate_linkage_model_artifact(nonfinite)

    oversized = copy.deepcopy(artifact)
    oversized["coefficients"][0] = 10**400
    oversized["artifact_digest"] = linkage_ml._artifact_digest(oversized)
    with pytest.raises(ArtifactValidationError, match="finite"):
        validate_linkage_model_artifact(oversized)

    stale = copy.deepcopy(artifact)
    stale["rule_engine"]["normalization_version"] = "stale-normalization"
    stale["artifact_digest"] = linkage_ml._artifact_digest(stale)
    with pytest.raises(ArtifactValidationError, match="incompatible"):
        validate_linkage_model_artifact(stale)


def test_direct_model_instances_enforce_and_recheck_runtime_invariants() -> None:
    rule = linkage_ml.current_rule_engine_contract()
    kwargs = {
        "model_id": linkage_ml.LINKAGE_ML_MODEL_ID,
        "feature_schema_version": linkage_ml.PAIR_FEATURE_SCHEMA_VERSION,
        "feature_names": PAIR_FEATURE_NAMES,
        "rule_policy_id": rule["policy_id"],
        "rule_policy_digest": rule["policy_digest"],
        "rule_result_schema_version": rule["result_schema_version"],
        "rule_feature_schema_version": rule["feature_schema_version"],
        "rule_normalization_version": rule["normalization_version"],
        "scaler_mean": tuple(0.0 for _ in PAIR_FEATURE_NAMES),
        "scaler_scale": tuple(1.0 for _ in PAIR_FEATURE_NAMES),
        "coefficients": tuple(0.0 for _ in PAIR_FEATURE_NAMES),
        "intercept": 0.0,
        "artifact_digest": _sha("d"),
    }

    with pytest.raises(ArtifactValidationError, match="length"):
        linkage_ml.LinkageModelArtifact(**(kwargs | {"coefficients": ()}))
    with pytest.raises(ArtifactValidationError, match="positive"):
        linkage_ml.LinkageModelArtifact(
            **(
                kwargs
                | {"scaler_scale": (0.0, *tuple(1.0 for _ in PAIR_FEATURE_NAMES[1:]))}
            )
        )

    model = linkage_ml.LinkageModelArtifact(**kwargs)
    object.__setattr__(model, "scaler_scale", tuple(0.0 for _ in PAIR_FEATURE_NAMES))
    with pytest.raises(ArtifactValidationError, match="positive"):
        score_pair_features({name: 0.0 for name in PAIR_FEATURE_NAMES}, model)


def test_no_model_is_exact_noop_and_model_cannot_bypass_candidates_or_caps(
    monkeypatch, sub_floor_gate
) -> None:
    entries, labels, _samples, _native_sha = _training_fixture()

    def _high_fit(features, targets, sample_weight, *, seed):  # noqa: ANN001, ARG001
        return (tuple(0.0 for _ in PAIR_FEATURE_NAMES), 10.0, "test-sklearn")

    monkeypatch.setattr(linkage_training, "_fit_logistic_regression", _high_fit)
    artifact = train_linkage_challenger(
        entries, labels, thresholds=SPLIT_THRESHOLDS, test_fraction=0.5, seed=17
    )["artifact"]
    rule_result = rank_link_candidates(entries, limit=None)
    assert rerank_rule_candidates(rule_result, None) is rule_result

    reranked = rerank_rule_candidates(rule_result, artifact)
    assert reranked is not rule_result
    original_ids = {candidate["candidate_id"] for candidate in rule_result["candidates"]}
    reranked_ids = {candidate["candidate_id"] for candidate in reranked["candidates"]}
    assert reranked_ids == original_ids
    assert len(reranked["candidates"]) == len(rule_result["candidates"])
    assert all("ml_rank_score" not in candidate for candidate in rule_result["candidates"])
    for candidate in reranked["candidates"]:
        cap = min([100.0, *(item["cap"] for item in candidate["score_caps"])])
        assert candidate["ml_rank_score"] <= cap
        assert candidate["ml_score_semantics"] == ML_SCORE_SEMANTICS
    assert reranked["ml"]["candidate_space"] == "deterministic_rule_candidates_only"
    assert reranked["ml"]["deterministic_caps_enforced"] is True
    assert reranked["ml"]["rule_engine"] == linkage_ml.current_rule_engine_contract()

    drifted_result = copy.deepcopy(rule_result)
    drifted_result["model"]["policy_digest"] = "0" * 64
    with pytest.raises(ArtifactValidationError, match="incompatible"):
        rerank_rule_candidates(drifted_result, artifact)


def test_runtime_score_rejects_feature_name_or_nonfinite_drift(
    monkeypatch, sub_floor_gate
) -> None:
    entries, labels, _samples, _native_sha = _training_fixture()

    def _fake_fit(features, targets, sample_weight, *, seed):  # noqa: ANN001, ARG001
        return (tuple(0.0 for _ in PAIR_FEATURE_NAMES), 0.0, "test-sklearn")

    monkeypatch.setattr(linkage_training, "_fit_logistic_regression", _fake_fit)
    artifact = train_linkage_challenger(
        entries, labels, thresholds=SPLIT_THRESHOLDS, test_fraction=0.5, seed=17
    )["artifact"]
    candidate = rank_link_candidates(entries, limit=None)["candidates"][0]
    features = extract_pair_features(candidate)
    assert score_pair_features(features, artifact) == 50.0

    missing = dict(features)
    missing.pop(PAIR_FEATURE_NAMES[0])
    with pytest.raises(PairFeatureError, match="allowlist"):
        score_pair_features(missing, artifact)
    nonfinite = dict(features)
    nonfinite[PAIR_FEATURE_NAMES[0]] = float("nan")
    with pytest.raises(PairFeatureError, match="finite"):
        score_pair_features(nonfinite, artifact)
