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


def test_later_round_merge_keeps_earlier_runtime_input_and_step_gaps(tmp_path: Path) -> None:
    from fxapk.core.models import Report
    from fxapk.dynamic import merge

    report = Report("com.example.fixture", {}, [], [], [], [])
    broken = tmp_path / "round-1.json"
    accepted = tmp_path / "round-2.json"
    broken.write_bytes(b"{")
    accepted.write_bytes(b'{"package_name":"com.example.fixture"}')
    for path in (broken, accepted):
        merge.merge_and_rerender(
            report, None, str(tmp_path), "fixture", formats=["json"], runtime_report_path=str(path),
        )

    assert report.meta["runtime_report_input"]["status"] == "unavailable"
    assert report.meta["runtime_report_input"]["reason"] == "runtime_report_invalid_json"
    assert {step["status"] for step in report.meta["runtime_merge_steps"].values()} == {"skipped"}
    assert report.meta["visibility"]["sources"]["runtime"]["visibility"] == "partial"


def test_merge_step_error_survives_later_ok_and_accepted_input_does_not_erase_gap() -> None:
    from fxapk.dynamic import merge

    steps = merge._retain_merge_steps(
        {"first": {"status": "error", "error_type": "RuntimeError"}, "earlier_only": {"status": "ok", "error_type": ""}},
        {"first": {"status": "ok", "error_type": ""}, "second": {"status": "ok", "error_type": ""}},
    )
    assert steps == {
        "first": {"status": "error", "error_type": "RuntimeError"},
        "earlier_only": {"status": "ok", "error_type": ""},
        "second": {"status": "ok", "error_type": ""},
    }
    partial = {"status": "partial", "gaps": {"messages": {"reason": "invalid_array"}}}
    accepted = {"status": "accepted", "artifact_sha256": "a" * 64}
    unavailable = {"status": "unavailable", "reason": "runtime_report_missing"}
    assert merge._retain_input_receipt(partial, accepted) == partial
    assert merge._retain_input_receipt(partial, unavailable) == unavailable
    assert merge._retain_input_receipt(accepted, partial) == partial
    assert merge._retain_input_receipt(None, accepted) == accepted


@pytest.mark.parametrize(("status", "merged"), [("degraded", True), ("error", False), ("skipped", False)])
def test_single_round_merges_degraded_capture_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, merged: bool,
) -> None:
    from fxapk.core.models import Report
    from fxapk.dynamic import auto

    report = Report("com.example.fixture", {}, [], [], [], [])
    calls: list[str] = []

    def render(report_arg, path, **kwargs):
        assert "evidence_namespace" not in kwargs
        calls.append(path)
        return auto._step(auto._STEP_MERGE, "done", "synthetic"), []

    monkeypatch.setattr(auto, "_run_merge", render)
    steps: list[auto.StepResult] = []
    auto._merge_capture_stage(
        report, capture_step=auto._step(auto._STEP_CAPTURE, status, "synthetic"),
        capture_round_paths=["synthetic-runtime.json"], round_records=None,
        apk_identity={"which": "original"}, out_dir=str(tmp_path), base="fixture", formats=["json"],
        on_progress=None, steps=steps, report_paths=[], delivery_sink=[],
    )
    assert calls == (["synthetic-runtime.json"] if merged else [])
    assert [step["status"] for step in steps] == (["done"] if merged else ["skipped"])
