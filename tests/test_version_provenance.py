"""Synthetic provenance contracts, including real pipeline JSON round trips."""
from __future__ import annotations

import importlib.metadata as metadata
import json
import logging
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest

import fxapk
from fxapk._version import resolve_version
from fxapk.core import pipeline
from fxapk.core.models import AnalysisConfig
from fxapk.core.report_io import load_report
from fxapk.report.json import dump
from fxapk.selfcheck import build_version_component


def pin_distribution(monkeypatch, version):
    original = metadata.distribution

    def distribution(name):
        if name != "fxapk":
            return original(name)
        if version is None:
            raise metadata.PackageNotFoundError(name)
        if version == "error":
            raise OSError("synthetic unreadable metadata")
        return SimpleNamespace(version=version, locate_file=lambda _: "synthetic-location")

    monkeypatch.setattr(metadata, "distribution", distribution)


@pytest.mark.parametrize("dist", ["2.0.0", "1.0.0", None, "error"])
def test_package_initialization_preserves_distribution_priority(monkeypatch, dist):
    pin_distribution(monkeypatch, dist)
    initialized = runpy.run_path(str(Path(fxapk.__file__)))
    assert initialized["__version__"] == (
        dist if dist not in (None, "error") else initialized["_FALLBACK_VERSION"]
    )


@pytest.mark.parametrize(
    "dist,effective,status,consistency,origin",
    [
        ("2.0.0", "2.0.0", "available", "consistent", "distribution"),
        (None, "2.0.0", "missing", "unverifiable", "source"),
        ("1.0.0", "1.0.0", "available", "conflict", "distribution"),
        ("error", "2.0.0", "error", "unverifiable", "source"),
        ("2.0.0", "1.0.0", "available", "conflict", "unknown"),
    ],
)
def test_new_report_records_provenance(
    monkeypatch, fake_ctx, tmp_path, caplog, dist, effective, status, consistency, origin,
):
    pin_distribution(monkeypatch, dist)
    monkeypatch.setattr(fxapk, "_FALLBACK_VERSION", "2.0.0")
    monkeypatch.setattr(fxapk, "__version__", effective)
    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda **_: set())
    with caplog.at_level(logging.WARNING, logger=pipeline.__name__):
        report = pipeline.run(fake_ctx, AnalysisConfig(online=False))
    path = tmp_path / "report.json"
    dump(report, str(path))
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["meta"]["tool_version"] == effective
    expected = {
        "effective_version": effective,
        "source_version": "2.0.0",
        "distribution_version": dist if status == "available" else None,
        "distribution_status": status,
        "selected_source": origin,
        "consistency": consistency,
    }
    assert payload["meta"]["tool_version_provenance"] == expected
    assert load_report(path).meta["tool_version_provenance"] == expected
    warnings = [r for r in caplog.records if "fxapk version conflict" in r.message]
    assert len(warnings) == int(consistency == "conflict")
    if consistency == "conflict":
        assert build_version_component()["status"] == "unreachable"

    # Serialization and loading must never stamp today's environment on old evidence.
    del report.meta["tool_version_provenance"]
    dump(report, str(path))
    assert "tool_version_provenance" not in load_report(path).meta
    assert load_report(path).meta["tool_version"] == effective


def test_missing_source_is_not_consistent(monkeypatch):
    pin_distribution(monkeypatch, "2.0.0")
    result = resolve_version(None)
    assert result.source_version is None
    assert result.consistency == "unverifiable"


@pytest.mark.parametrize(
    "dist,effective,status,consistency,exit_code",
    [
        ("2.0.0", "2.0.0", "available", "consistent", 0),
        ("1.0.0", "1.0.0", "available", "conflict", 1),
        (None, "2.0.0", "missing", "unverifiable", 0),
        ("error", "2.0.0", "error", "unverifiable", 0),
        ("", "2.0.0", "invalid", "unverifiable", 0),
    ],
)
def test_version_detail_distinguishes_metadata_states_without_changing_exit(
    monkeypatch, dist, effective, status, consistency, exit_code,
):
    from typer.testing import CliRunner
    from fxapk.cli import app

    pin_distribution(monkeypatch, dist)
    monkeypatch.setattr(fxapk, "_FALLBACK_VERSION", "2.0.0")
    monkeypatch.setattr(fxapk, "__version__", effective)
    before = resolve_version("2.0.0", effective_version=effective).report_record()
    component = build_version_component()
    assert f"distribution_status={status}" in component["detail"]
    assert f"consistency={consistency}" in component["detail"]
    display = {"missing": "未安装", "error": "读取失败", "invalid": "版本无效"}.get(status, dist)
    assert f"distribution={display} " in component["detail"]
    if status in ("error", "invalid"):
        assert "未安装" not in component["detail"]
    assert component["status"] == ("unreachable" if exit_code else "ok")
    result = CliRunner().invoke(app, ["--version-verbose"])
    assert result.exit_code == exit_code
    assert f"distribution_status={status}" in result.output
    assert f"consistency={consistency}" in result.output
    assert f"distribution={display}\n" in result.output
    if status in ("error", "invalid"):
        assert "未安装" not in result.output
    assert resolve_version("2.0.0", effective_version=effective).report_record() == before
    assert fxapk.__version__ == effective
