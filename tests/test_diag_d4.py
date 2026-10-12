"""D4：PID 复用要跨窗口一致，并且带上 run / APK / 可用设备身份。"""

from __future__ import annotations

import json
from pathlib import Path

from apkscan.core.models import Report
from apkscan.core.runtime_diagnostics import explain_coverage
from apkscan.dynamic import merge

_SAMPLE = "ab" * 32


def _report() -> Report:
    return Report(
        package_name="example.invalid",
        meta={
            "sample_sha256": _SAMPLE,
            "closure": {"status": "partial", "gaps": ["keep"]},
            "runtime_diagnostics": {
                "schema": "runtime-diagnostics/1",
                "frida_detection": "not_inferred",
                "endpoints_added": 0,
                "closure_evaluated": False,
                "items": [{
                    "class": "static-potential",
                    "event": "isolated_process",
                    "window_id": "manifest",
                    "run_id": "unknown",
                    "apk_sha256": "unknown",
                    "start_token": "unknown",
                    "pid": "unknown",
                }],
            },
        },
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def _row(start: str, window: str, *, run_id: str = "run1", device: str | None = None) -> dict[str, object]:
    row: dict[str, object] = {
        "event": "capture_window",
        "pid": 123,
        "start_token": start,
        "window_id": window,
        "run_id": run_id,
        "apk_sha256": _SAMPLE,
        "runtime_variant": "original-runtime",
        "observer_attached": True,
    }
    if device is not None:
        row["device_id"] = device
    return row


def test_same_batch_reuse_requires_same_run_not_just_pid() -> None:
    same = explain_coverage([
        _row("s1", "w1", run_id="run-same"),
        _row("s2", "w2", run_id="run-same"),
    ])["items"]
    assert [item["event"] for item in same] == ["pid_reuse", "pid_reuse"]
    other = explain_coverage([
        _row("s1", "w1", run_id="run-a"),
        _row("s2", "w2", run_id="run-b"),
    ])["items"]
    assert [item["event"] for item in other] == ["capture_window", "capture_window"]
    split_device = explain_coverage([
        _row("s1", "w1", device="device-a"),
        _row("s2", "w2", device="device-b"),
    ])["items"]
    assert [item["event"] for item in split_device] == ["capture_window", "capture_window"]
    assert [item["device_id"] for item in split_device] == ["device-a", "device-b"]


def test_separate_merges_mark_pid_reuse_without_overwriting_identity(tmp_path: Path) -> None:
    report = _report()
    for start, window in (("s1", "w1"), ("s2", "w2")):
        runtime = tmp_path / f"{window}.json"
        runtime.write_text(json.dumps({
            "package_name": "example.invalid",
            "source": "runtime",
            "endpoints": [],
            "process_observations": [_row(start, window)],
        }), encoding="utf-8")
        merge.merge_and_rerender(
            report, [], str(tmp_path), formats=["json"], runtime_report_path=str(runtime),
        )
    items = report.meta["runtime_diagnostics"]["items"]
    assert items[0]["event"] == "isolated_process"
    assert items[0]["class"] == "static-potential"
    dynamic = items[1:]
    assert [item["event"] for item in dynamic] == ["pid_reuse", "pid_reuse"]
    assert [item["window_id"] for item in dynamic] == ["w1", "w2"]
    assert [item["start_token"] for item in dynamic] == ["s1", "s2"]
    assert [item["run_id"] for item in dynamic] == ["run1", "run1"]
    assert [item["apk_sha256"] for item in dynamic] == [_SAMPLE, _SAMPLE]
    assert all(item["window_coverage_shared"] is False for item in dynamic)
    assert all(item["run_coverage_shared"] is False for item in dynamic)
    assert report.endpoints == []
    assert report.meta["closure"]["status"] == "partial"


def test_other_run_merge_does_not_reuse_this_window(tmp_path: Path) -> None:
    report = _report()
    for start, window, run_id in (("s1", "w1", "run-a"), ("s2", "w2", "run-b")):
        runtime = tmp_path / f"{window}.json"
        runtime.write_text(json.dumps({
            "package_name": "example.invalid",
            "endpoints": [],
            "process_observations": [_row(start, window, run_id=run_id)],
        }), encoding="utf-8")
        merge.merge_and_rerender(
            report, [], str(tmp_path), formats=["json"], runtime_report_path=str(runtime),
        )
    dynamic = report.meta["runtime_diagnostics"]["items"][1:]
    assert [item["event"] for item in dynamic] == ["capture_window", "capture_window"]
    assert [item["run_id"] for item in dynamic] == ["run-a", "run-b"]
    assert [item["window_id"] for item in dynamic] == ["w1", "w2"]
