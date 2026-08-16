"""P5-D 红态契约：``fxapk recognize split build/validate``（split-manifest 命令面）。

契约见 docs/superpowers/specs/2026-08-17-p5d-split-cli-design.md：build 端到端
create-only、fail-closed 不产文件、稳定错误行；validate 只读复验。走主 app 真入口。
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.recognition_training import load_split_manifest

runner = CliRunner()

SHA_A = "aa" * 32
SHA_B = "bb" * 32


def _catalog_row(sha: str, case_id: str) -> dict:
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


def _write_corpus(tmp_path: Path, rows: list[dict] | None, raw_extra: str = "") -> Path:
    corpus = tmp_path / "corpus"
    corpus.mkdir(exist_ok=True)
    if rows is not None:
        payload = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
        (corpus / "catalog.jsonl").write_text(payload + raw_extra, encoding="utf-8")
    return corpus


def _write_inputs(
    tmp_path: Path,
    *,
    rows: list[dict] | None,
    time_table: dict | None = None,
    config: dict | None = None,
    labels_text: str = "",
    raw_extra: str = "",
) -> dict[str, Path]:
    corpus = _write_corpus(tmp_path, rows, raw_extra)
    labels = tmp_path / "labels.jsonl"
    labels.write_text(labels_text, encoding="utf-8")
    time_path = tmp_path / "time.json"
    time_path.write_text(
        json.dumps(time_table if time_table is not None else {"case-01": "2025-11-15"}),
        encoding="utf-8",
    )
    config_path = tmp_path / "config.json"
    base_config = {
        "cutoff_date": "2026-01-01",
        "unseen_families": [],
        "adversarial_samples": [],
        "calibration_samples": [],
        "derivations": [],
        "policy_version": "split-v1",
    }
    config_path.write_text(
        json.dumps(config if config is not None else base_config), encoding="utf-8"
    )
    return {
        "corpus": corpus,
        "labels": labels,
        "time": time_path,
        "config": config_path,
        "out": tmp_path / "manifest.json",
    }


def _build(paths: dict[str, Path]):
    return runner.invoke(
        cli.app,
        [
            "recognize",
            "split",
            "build",
            "--corpus",
            str(paths["corpus"]),
            "--labels",
            str(paths["labels"]),
            "--time-table",
            str(paths["time"]),
            "--config",
            str(paths["config"]),
            "--out",
            str(paths["out"]),
        ],
    )


def _output(result) -> str:
    return result.output + (result.stderr or "")


def test_build_end_to_end_roundtrip(tmp_path: Path) -> None:
    paths = _write_inputs(tmp_path, rows=[_catalog_row(SHA_A, "case-01")])
    result = _build(paths)
    assert result.exit_code == 0, _output(result)
    manifest = load_split_manifest(paths["out"].read_text(encoding="utf-8"))
    assert sum(len(units) for units in manifest.splits.values()) == 1
    out = _output(result)
    for name in (
        "train",
        "calibration",
        "test_temporal_seen",
        "test_unseen_family",
        "test_adversarial",
    ):
        assert f"split {name} " in out
    assert "digest=" in out


def test_build_is_create_only(tmp_path: Path) -> None:
    paths = _write_inputs(tmp_path, rows=[_catalog_row(SHA_A, "case-01")])
    paths["out"].write_text("sentinel", encoding="utf-8")
    result = _build(paths)
    assert result.exit_code == 2
    assert "out_exists" in _output(result)
    assert paths["out"].read_text(encoding="utf-8") == "sentinel"


def test_build_rejects_corrupt_catalog(tmp_path: Path) -> None:
    paths = _write_inputs(tmp_path, rows=[_catalog_row(SHA_A, "case-01")], raw_extra="not-json\n")
    result = _build(paths)
    assert result.exit_code == 2
    assert "catalog_corrupt" in _output(result)
    assert not paths["out"].exists()


def test_build_rejects_invalid_labels_with_stable_line(tmp_path: Path) -> None:
    paths = _write_inputs(
        tmp_path,
        rows=[_catalog_row(SHA_A, "case-01")],
        labels_text='{"kind": "nope"}\n',
    )
    result = _build(paths)
    assert result.exit_code == 2
    out = _output(result)
    assert "at line 1" in out
    assert str(paths["labels"]) not in out  # 不回显路径


def test_build_missing_case_time_fails_without_output(tmp_path: Path) -> None:
    paths = _write_inputs(tmp_path, rows=[_catalog_row(SHA_A, "case-01")], time_table={})
    result = _build(paths)
    assert result.exit_code == 2
    assert "time_missing" in _output(result)
    assert not paths["out"].exists()


def test_build_rejects_config_with_extra_or_missing_keys(tmp_path: Path) -> None:
    extra = {
        "cutoff_date": "2026-01-01",
        "unseen_families": [],
        "adversarial_samples": [],
        "calibration_samples": [],
        "derivations": [],
        "policy_version": "split-v1",
        "surprise": True,
    }
    paths = _write_inputs(tmp_path, rows=[_catalog_row(SHA_A, "case-01")], config=extra)
    assert _build(paths).exit_code == 2
    missing = {"cutoff_date": "2026-01-01"}
    paths2 = _write_inputs(tmp_path, rows=[_catalog_row(SHA_A, "case-01")], config=missing)
    result = _build(paths2)
    assert result.exit_code == 2
    assert "config_invalid" in _output(result)


def test_build_rejects_unknown_policy_version(tmp_path: Path) -> None:
    config = {
        "cutoff_date": "2026-01-01",
        "unseen_families": [],
        "adversarial_samples": [],
        "calibration_samples": [],
        "derivations": [],
        "policy_version": "split-v0",
    }
    paths = _write_inputs(tmp_path, rows=[_catalog_row(SHA_A, "case-01")], config=config)
    result = _build(paths)
    assert result.exit_code == 2
    assert "policy_unknown" in _output(result)


def test_build_missing_catalog_yields_honest_empty_manifest(tmp_path: Path) -> None:
    paths = _write_inputs(tmp_path, rows=None, time_table={})
    result = _build(paths)
    assert result.exit_code == 0, _output(result)
    manifest = load_split_manifest(paths["out"].read_text(encoding="utf-8"))
    assert all(units == () for units in manifest.splits.values())


def test_build_missing_labels_file_stable_error(tmp_path: Path) -> None:
    paths = _write_inputs(tmp_path, rows=[_catalog_row(SHA_A, "case-01")])
    paths["labels"].unlink()
    result = _build(paths)
    assert result.exit_code == 2
    assert "labels_unreadable" in _output(result)


def test_validate_ok_and_tamper_rejected(tmp_path: Path) -> None:
    paths = _write_inputs(tmp_path, rows=[_catalog_row(SHA_A, "case-01")])
    assert _build(paths).exit_code == 0
    ok = runner.invoke(cli.app, ["recognize", "split", "validate", "--manifest", str(paths["out"])])
    assert ok.exit_code == 0
    assert "digest=" in _output(ok)
    text = paths["out"].read_text(encoding="utf-8")
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(text.replace("2026-01-01", "2026-01-02", 1), encoding="utf-8")
    bad = runner.invoke(
        cli.app, ["recognize", "split", "validate", "--manifest", str(tampered_path)]
    )
    assert bad.exit_code == 2
    assert "digest_mismatch" in _output(bad)


def test_split_group_reachable_from_main_app() -> None:
    result = runner.invoke(cli.app, ["recognize", "split", "--help"])
    assert result.exit_code == 0
    assert "build" in result.output
    assert "validate" in result.output
