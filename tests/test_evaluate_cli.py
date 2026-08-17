"""P5-E 红态契约：``fxapk recognize evaluate``（评测 CLI + 显式阈值晋级门）。

契约见 docs/superpowers/specs/2026-08-17-p5e-evaluate-cli-design.md：四任务 e2e、
params/predictions 严格校验、create-only、promotion 硬规则（not_eligible 不评门、
null 指标门必 fail）、exit 4 = 评测成功但门未过。走主 app 真入口。
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.recognition_labels import load_recognition_labels
from apkscan.core.recognition_training import (
    SplitConfig,
    build_split_manifest,
    encode_split_manifest,
)

runner = CliRunner()

SHA_A = "aa" * 32
SHA_B = "bb" * 32
SHA_Q = "11" * 32
SHA_R = "22" * 32

_seq = iter(range(1, 10_000))


def _label_line(kind: str, **fields: object) -> str:
    record = {
        "kind": kind,
        "schema_version": "1.0",
        "record_id": f"rec-{next(_seq):04d}",
        "status": "confirmed",
        "layer": "gold_external",
        "author_kind": "human",
        "label_basis": ["independent-review"],
        "evidence_ref": "bundle:2026/fixture-0001",
        "label_lineage": "queue-external",
        "confidence": 0.9,
        "supersedes": None,
        "reason_codes": ["fixture-reason"],
    }
    record.update(fields)
    return json.dumps(record, ensure_ascii=False)


def _family_line(sha: str, family_id: str, **over: object) -> str:
    return _label_line(
        "family_assignment", sample_sha256=sha, level="product_line", family_id=family_id, **over
    )


def _relation_line(left: str, right: str, **over: object) -> str:
    return _label_line(
        "relation_judgment",
        left_sha256=left,
        right_sha256=right,
        relation="positive",
        relation_subtype="same_operator",
        **over,
    )


def _clue_line(ref: str, **over: object) -> str:
    return _label_line(
        "clue_judgment", clue_ref=ref, verdict="valid", ownership="suspect_first_party", **over
    )


def _manifest_text() -> str:
    rows = [
        {
            "sample_sha256": sha,
            "tool_version": "1.7.0",
            "ruleset_digest": "rules-v2",
            "evidence_surface": "static",
            "case_ids": [f"case-{sha[:2]}"],
            "record_state": "active",
            "record_state_reason": None,
            "ingest_sequence": None,
        }
        for sha in (SHA_A, SHA_B, SHA_Q, SHA_R)
    ]
    time_table = {f"case-{sha[:2]}": "2026-03-01" for sha in (SHA_A, SHA_B, SHA_Q, SHA_R)}
    manifest = build_split_manifest(
        rows,
        _empty_label_set(),
        time_table,
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
    return encode_split_manifest(manifest)


def _empty_label_set():
    from apkscan.core.recognition_labels import RecognitionLabelSet

    return RecognitionLabelSet(
        records=(), active=(), effective=(), kind_counts=(), status_counts=(), layer_counts=()
    )


_FAMILY_PARAMS = {
    "level": "product_line",
    "layers": ["gold_external"],
    "known_unknown_samples": [],
}
_FAMILY_PREDICTIONS = {"predictions": [{"sample_sha256": SHA_A, "family_id": "fam-x"}]}


def _write_case(
    tmp_path: Path,
    *,
    labels_lines: list[str],
    params: dict,
    predictions: dict,
    gates: dict | None = None,
) -> dict[str, Path]:
    paths = {
        "manifest": tmp_path / "split.json",
        "labels": tmp_path / "labels.jsonl",
        "params": tmp_path / "params.json",
        "predictions": tmp_path / "predictions.json",
        "out": tmp_path / "metrics.json",
    }
    # 字节写入：write_text 在 Windows 会把 \n 翻成 \r\n，破坏 manifest 的 canonical 字节
    paths["manifest"].write_bytes(_manifest_text().encode("utf-8"))
    paths["labels"].write_text("".join(line + "\n" for line in labels_lines), encoding="utf-8")
    paths["params"].write_text(json.dumps(params), encoding="utf-8")
    paths["predictions"].write_text(json.dumps(predictions), encoding="utf-8")
    if gates is not None:
        paths["gates"] = tmp_path / "gates.json"
        paths["gates"].write_text(json.dumps(gates), encoding="utf-8")
    return paths


def _run(paths: dict[str, Path], task: str, split: str = "test_temporal_seen"):
    args = [
        "recognize",
        "evaluate",
        "--manifest",
        str(paths["manifest"]),
        "--labels",
        str(paths["labels"]),
        "--task",
        task,
        "--split",
        split,
        "--params",
        str(paths["params"]),
        "--predictions",
        str(paths["predictions"]),
        "--out",
        str(paths["out"]),
    ]
    if "gates" in paths:
        args += ["--gates", str(paths["gates"])]
    return runner.invoke(cli.app, args)


def _output(result) -> str:
    return result.output + (result.stderr or "")


def _metrics(paths: dict[str, Path]) -> dict:
    return json.loads(paths["out"].read_text(encoding="utf-8"))


# ------------------------------------------------------- 四任务 e2e（E1-E4）


def test_family_end_to_end(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions=_FAMILY_PREDICTIONS,
    )
    result = _run(paths, "family")
    assert result.exit_code == 0, _output(result)
    doc = _metrics(paths)
    assert doc["task"] == "family"
    assert doc["metrics"]["macro_f1"] == 1.0
    assert doc["provenance"]["promotion_eligible"] is True
    # labels_digest = 标签文件字节 sha256（独立重算核对）
    import hashlib

    assert doc["labels_digest"] == hashlib.sha256(paths["labels"].read_bytes()).hexdigest()
    manifest_doc = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    assert doc["manifest_digest"] == manifest_doc["manifest_digest"]
    assert "promotion_eligible=True" in _output(result)


def test_pair_end_to_end(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_relation_line(SHA_Q, SHA_R)],
        params={"k": 1, "layers": ["gold_external"], "lineages": ["queue-external"]},
        predictions={"rankings": [{"query_sha256": SHA_Q, "ranked": [[SHA_R, 0.9]]}]},
    )
    result = _run(paths, "pair")
    assert result.exit_code == 0, _output(result)
    assert _metrics(paths)["metrics"]["recall_at_k"] == 1.0


def test_group_end_to_end(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_relation_line(SHA_A, SHA_B)],
        params={
            "layers": ["gold_external"],
            "positive_subtypes": ["same_operator"],
            "cannot_link_subtypes": ["same_operator"],
            "repack_subtypes": ["binary_lineage"],
        },
        predictions={"groups": [[SHA_A, SHA_B]]},
    )
    result = _run(paths, "group")
    assert result.exit_code == 0, _output(result)
    doc = _metrics(paths)
    assert doc["metrics"]["bcubed_precision"] == 1.0
    assert doc["metrics"]["cannot_link_violation_count"] == 0


def test_clue_end_to_end(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_clue_line("clue-001")],
        params={"top_n": 1, "layers": ["gold_external"]},
        predictions={
            "candidates": [
                {
                    "clue_ref": "clue-001",
                    "subject_sha256": SHA_A,
                    "predicted_verdict": "valid",
                    "predicted_ownership": "suspect_first_party",
                    "evidence_ref": "ev:1",
                }
            ]
        },
    )
    result = _run(paths, "clue")
    assert result.exit_code == 0, _output(result)
    assert _metrics(paths)["metrics"]["validity_precision"] == 1.0


# ------------------------------------------------------- 校验与写入（E5-E7）


def test_params_strict_keyset(tmp_path: Path) -> None:
    for bad in (
        {**_FAMILY_PARAMS, "surprise": 1},
        {"level": "product_line", "layers": ["gold_external"]},  # 缺键
        {**_FAMILY_PARAMS, "layers": "gold_external"},  # 类型错
    ):
        paths = _write_case(
            tmp_path,
            labels_lines=[_family_line(SHA_A, "fam-x")],
            params=bad,
            predictions=_FAMILY_PREDICTIONS,
        )
        paths["out"].unlink(missing_ok=True)
        result = _run(paths, "family")
        assert result.exit_code == 2
        assert "params_invalid" in _output(result)


def test_predictions_shape_and_semantic_errors(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions={"wrong_key": []},
    )
    result = _run(paths, "family")
    assert result.exit_code == 2
    assert "predictions_unreadable" in _output(result)
    # 语义错：pair 乱序 → 评测层 reason_code，且不回显分数值
    sub = tmp_path / "sub"
    sub.mkdir()
    paths2 = _write_case(
        sub,
        labels_lines=[_relation_line(SHA_Q, SHA_R)],
        params={"k": 1, "layers": ["gold_external"], "lineages": ["queue-external"]},
        predictions={"rankings": [{"query_sha256": SHA_Q, "ranked": [[SHA_R, 0.5], [SHA_A, 0.9]]}]},
    )
    result2 = _run(paths2, "pair")
    assert result2.exit_code == 2
    out = _output(result2)
    assert "ranking_not_sorted" in out
    assert "0.9" not in out  # 稳定错误行：不回显动态输入


def test_out_is_create_only(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions=_FAMILY_PREDICTIONS,
    )
    paths["out"].write_text("sentinel", encoding="utf-8")
    result = _run(paths, "family")
    assert result.exit_code == 2
    assert "out_exists" in _output(result)
    assert paths["out"].read_text(encoding="utf-8") == "sentinel"


# ------------------------------------------------------------ 晋级门（E8-E12）


def test_gates_pass(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions=_FAMILY_PREDICTIONS,
        gates={"macro_f1": {"min": 0.5}},
    )
    result = _run(paths, "family")
    assert result.exit_code == 0, _output(result)
    doc = _metrics(paths)
    assert doc["gates"]["status"] == "pass"
    assert "gates=pass" in _output(result)


def test_gates_fail_exit_4(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions={"predictions": [{"sample_sha256": SHA_A, "family_id": "fam-wrong"}]},
        gates={"macro_f1": {"min": 0.9}},
    )
    result = _run(paths, "family")
    assert result.exit_code == 4, _output(result)
    assert _metrics(paths)["gates"]["status"] == "fail"


def test_gates_not_eligible_on_silver(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x", layer="silver")],
        params={**_FAMILY_PARAMS, "layers": ["silver"]},
        predictions=_FAMILY_PREDICTIONS,
        gates={"macro_f1": {"min": 0.1}},
    )
    result = _run(paths, "family")
    assert result.exit_code == 4, _output(result)
    doc = _metrics(paths)
    assert doc["gates"]["status"] == "not_eligible"
    assert doc["metrics"]["macro_f1"] == 1.0  # 数字照算，只是永远过不了门


def test_gates_invalid_metric_name(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions=_FAMILY_PREDICTIONS,
        gates={"nope_metric": {"min": 0.5}},
    )
    result = _run(paths, "family")
    assert result.exit_code == 2
    assert "gates_invalid" in _output(result)
    assert not paths["out"].exists()


def test_null_metric_fails_gate(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions={"predictions": []},  # 零预测 → macro_f1 null
        gates={"macro_f1": {"min": 0.1}},
    )
    result = _run(paths, "family")
    assert result.exit_code == 4, _output(result)
    doc = _metrics(paths)
    assert doc["metrics"]["macro_f1"] is None
    assert doc["gates"]["status"] == "fail"


# ------------------------------------------------------------- 其它（E13-E14）


def test_tampered_manifest_rejected(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions=_FAMILY_PREDICTIONS,
    )
    text = paths["manifest"].read_bytes().decode("utf-8")
    paths["manifest"].write_bytes(text.replace("2026-01-01", "2026-01-02", 1).encode("utf-8"))
    result = _run(paths, "family")
    assert result.exit_code == 2
    assert "digest_mismatch" in _output(result)


def test_evaluate_reachable_from_main_app() -> None:
    result = runner.invoke(cli.app, ["recognize", "evaluate", "--help"])
    assert result.exit_code == 0
    assert "--gates" in result.output


def test_labels_fixture_lines_are_actually_valid(tmp_path: Path) -> None:
    """夹具自检：本文件生成的标签行必须真的能过 load_recognition_labels。"""
    labels = tmp_path / "check.jsonl"
    labels.write_text(
        _family_line(SHA_A, "fam-x")
        + "\n"
        + _relation_line(SHA_Q, SHA_R)
        + "\n"
        + _clue_line("clue-001")
        + "\n",
        encoding="utf-8",
    )
    label_set = load_recognition_labels(labels)
    assert len(label_set.effective) == 3


# --------------------------------------------------- codex 复审补锁（P1/P2）


def test_huge_integer_score_is_stable_error(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_relation_line(SHA_Q, SHA_R)],
        params={"k": 1, "layers": ["gold_external"], "lineages": ["queue-external"]},
        predictions={"rankings": [{"query_sha256": SHA_Q, "ranked": [[SHA_R, 10**400]]}]},
    )
    result = _run(paths, "pair")
    assert result.exit_code == 2, _output(result)
    assert "predictions_unreadable" in _output(result)
    assert not paths["out"].exists()


def test_huge_integer_gate_threshold_is_stable_error(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions=_FAMILY_PREDICTIONS,
        gates={"macro_f1": {"min": 10**400}},
    )
    result = _run(paths, "family")
    assert result.exit_code == 2, _output(result)
    assert "gates_invalid" in _output(result)


def test_uppercase_sha_rejected_at_parse_layer(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions={"predictions": [{"sample_sha256": "AA" * 32, "family_id": "fam-x"}]},
    )
    result = _run(paths, "family")
    assert result.exit_code == 2
    assert "predictions_unreadable" in _output(result)


def test_gates_max_path_and_null_with_max(tmp_path: Path) -> None:
    # max 通过：missing_prediction_count=0 ≤ 0
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions=_FAMILY_PREDICTIONS,
        gates={"missing_prediction_count": {"max": 0}},
    )
    assert _run(paths, "family").exit_code == 0
    # max 失败：B 缺预测 → missing=1 > 0
    sub = tmp_path / "maxfail"
    sub.mkdir()
    paths2 = _write_case(
        sub,
        labels_lines=[_family_line(SHA_A, "fam-x"), _family_line(SHA_B, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions=_FAMILY_PREDICTIONS,
        gates={"missing_prediction_count": {"max": 0}},
    )
    result = _run(paths2, "family")
    assert result.exit_code == 4, _output(result)
    # null + max 同样 fail（无数据不得视为达标）
    sub2 = tmp_path / "nullmax"
    sub2.mkdir()
    paths3 = _write_case(
        sub2,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions={"predictions": []},
        gates={"macro_f1": {"max": 0.5}},
    )
    result3 = _run(paths3, "family")
    assert result3.exit_code == 4, _output(result3)
    assert _metrics(paths3)["gates"]["status"] == "fail"


def test_gates_invalid_shapes_rejected(tmp_path: Path) -> None:
    for bad in (
        {"macro_f1": {"min": 0.5, "max": 0.9}},  # min/max 并存
        {"macro_f1": {"min": True}},  # bool 阈值
        {"macro_f1": {"min": "0.5"}},  # 字符串阈值
        {"macro_f1": {}},  # 空规则
    ):
        paths = _write_case(
            tmp_path,
            labels_lines=[_family_line(SHA_A, "fam-x")],
            params=_FAMILY_PARAMS,
            predictions=_FAMILY_PREDICTIONS,
            gates=bad,
        )
        paths["out"].unlink(missing_ok=True)
        result = _run(paths, "family")
        assert result.exit_code == 2, _output(result)
        assert "gates_invalid" in _output(result)


def test_metrics_output_is_canonical_bytes(tmp_path: Path) -> None:
    paths = _write_case(
        tmp_path,
        labels_lines=[_family_line(SHA_A, "fam-x")],
        params=_FAMILY_PARAMS,
        predictions=_FAMILY_PREDICTIONS,
    )
    assert _run(paths, "family").exit_code == 0
    raw = paths["out"].read_bytes()
    doc = json.loads(raw.decode("utf-8"))
    expected = (
        json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"
    ).encode("utf-8")
    assert raw == expected
