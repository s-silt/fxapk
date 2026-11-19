"""Characterize the offline runtime-report identity gate before merging evidence."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from fxapk.core import integrity
from fxapk.dynamic.auto import _verified_merge_namespace


def test_verified_namespace_binds_exact_runtime_bytes(tmp_path: Path) -> None:
    path = tmp_path / "runtime.json"
    data = b'{"synthetic": true}'
    path.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    records = [
        {"runtime_report_path": "unrelated.json", "runtime_report_sha256": "0" * 64},
        {"runtime_report_path": str(path), "runtime_report_sha256": expected},
    ]
    assert _verified_merge_namespace(str(path), records) == f"capture:{expected}"
    path.write_bytes(data + b" ")
    assert _verified_merge_namespace(str(path), records) is None
    path.unlink()
    assert _verified_merge_namespace(str(path), records) is None


def test_missing_first_recorded_digest_does_not_read_or_choose_later_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def should_not_read(_path: str) -> str:
        pytest.fail("should not read unbound material")

    monkeypatch.setattr(integrity, "sha256_file", should_not_read)
    records = [
        {"runtime_report_path": "synthetic.json", "runtime_report_sha256": None},
        {"runtime_report_path": "synthetic.json", "runtime_report_sha256": "a" * 64},
    ]
    assert _verified_merge_namespace("synthetic.json", records) is None
    assert _verified_merge_namespace("missing.json", records) is None


def test_merge_stage_refuses_changed_artifact_and_continues_in_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fxapk.core.models import Report
    from fxapk.dynamic import auto

    content = b'{"package_name":"com.example.fixture","runtime_variant":"original-runtime"}'
    digest = hashlib.sha256(content).hexdigest()
    paths = [tmp_path / f"synthetic-{i}.json" for i in range(3)]
    for path in paths:
        path.write_bytes(content)
    paths[1].write_bytes(content + b" ")
    rows = [{"runtime_report_path": str(path), "runtime_report_sha256": digest} for path in paths]
    report = Report("com.example.fixture", {"capture_rounds": [dict(row) for row in rows]}, [], [], [], [])
    calls = []
    receipt = object()

    def render(report_arg, path, *, evidence_namespace, delivery_sink, **kwargs):
        assert report_arg is report
        assert evidence_namespace == f"capture:{digest}"
        calls.append(path)
        delivery_sink.append(receipt)
        return auto._step(auto._STEP_MERGE, "done", "synthetic"), ["same.json", f"{len(calls)}.json"]

    monkeypatch.setattr(auto, "_run_merge", render)
    steps: list[auto.StepResult] = []
    outputs: list[str] = ["same.json"]
    delivery: list[object] = []
    auto._merge_capture_stage(
        report, capture_step=auto._step(auto._STEP_CAPTURE, "done", "synthetic"),
        capture_round_paths=[str(path) for path in paths], round_records=rows,
        apk_identity={"which": "original", "original": {"sha256": "synthetic"}},
        out_dir=str(tmp_path), base="fixture", formats=["json"], on_progress=None,
        steps=steps, report_paths=outputs, delivery_sink=delivery,
    )
    assert [step["status"] for step in steps] == ["done", "error", "done"]
    assert calls == [str(paths[0]), str(paths[2])]
    assert outputs == ["same.json", "1.json", "2.json"]
    assert delivery == [receipt, receipt]
    first, rejected, last = report.meta["capture_rounds"]
    assert first["artifact_verified"] is last["artifact_verified"] is True
    assert first["package_matches"] is last["package_matches"] is True
    assert first["original_sample_sha256"] == "synthetic"
    assert rejected == rows[1]
    assert all("merge_status" not in row for row in rows)
