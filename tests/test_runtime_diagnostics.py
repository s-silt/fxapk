"""反分析诊断只解释覆盖。早退不是 Frida 检测，诊断不新增端点或闭环分。"""

from __future__ import annotations

import json
from pathlib import Path

from apkscan.core.models import Report
from apkscan.core.runtime_diagnostics import (
    explain_coverage,
    merge_process_observations,
    observation_from_capture,
)
from apkscan.dynamic import merge
from apkscan.report.digest import build_digest
from tests.conftest import FakeContext


def _window(event: str, window_id: str, **extra: object) -> dict[str, object]:
    row: dict[str, object] = {
        "event": event,
        "window_id": window_id,
        "run_id": extra.pop("run_id", window_id),
        "apk_sha256": "ab" * 32,
    }
    row.update(extra)
    return row


def test_explain_coverage_keeps_each_counterexample() -> None:
    records = [
        _window("capture_window", "wrong-pid", pid=10, expected_pid=11, start_token="a"),
        _window("capture_window", "isolated-uid", pid=20, uid=99001, start_token="b"),
        _window("capture_window", "reuse-1", pid=30, start_token="s1", run_id="run-a"),
        _window("capture_window", "reuse-2", pid=30, start_token="s2", run_id="run-a"),
        _window("capture_window", "window-a", pid=70, start_token="same", run_id="run-a"),
        _window("capture_window", "window-b", pid=70, start_token="same", run_id="run-b"),
        _window("early_exit", "early", pid=40, runtime_variant="original-runtime"),
        _window("process_exit", "no-log", logs=False),
        _window("selinux_query", "selinux", observer_attached=True),
        _window("java_hook", "java-only", observer_attached=True),
        _window("observer_late", "late", observer_attached=False),
        _window(
            "capture_window", "late-timed",
            observer_attached=False,
            observer_requested=True,
            observer_late_evidence=True,
            pid=80,
            start_token="timed",
        ),
        _window(
            "capture_window", "original",
            runtime_variant="original-runtime", status="failed", pid=50, start_token="o",
        ),
        _window(
            "capture_window", "bypass",
            runtime_variant="modified-runtime", status="ok", pid=51, start_token="m",
        ),
        _window("early_exit", "early-wrong-pid", pid=True, expected_pid=9),
    ]
    explained = explain_coverage(records)
    assert explained["schema"] == "runtime-diagnostics/1"
    assert explained["frida_detection"] == "not_inferred"
    assert explained["endpoints_added"] == 0
    assert explained["closure_evaluated"] is False
    by_window = {item["window_id"]: item for item in explained["items"]}
    assert by_window["wrong-pid"]["class"] == "coverage-gap"
    assert by_window["wrong-pid"]["event"] == "pid_mismatch"
    assert by_window["isolated-uid"]["class"] == "observed-event"
    assert by_window["isolated-uid"]["event"] == "uid_isolated"
    assert by_window["reuse-1"]["event"] == "pid_reuse"
    assert by_window["reuse-2"]["event"] == "pid_reuse"
    assert by_window["reuse-1"]["run_coverage_shared"] is False
    assert by_window["window-a"]["event"] == "capture_window"
    assert by_window["window-b"]["event"] == "capture_window"
    assert by_window["window-a"]["window_coverage_shared"] is False
    assert by_window["window-b"]["window_coverage_shared"] is False
    assert by_window["early"]["class"] == "coverage-gap"
    assert by_window["early"]["event"] == "early_exit_unattributed"
    assert by_window["no-log"]["event"] == "no_log_exit"
    assert by_window["selinux"]["class"] == "observed-event"
    assert by_window["selinux"]["event"] == "selinux_query"
    assert by_window["java-only"]["event"] == "java_only"
    assert by_window["late"]["event"] == "observer_unknown"
    assert by_window["late-timed"]["event"] == "observer_late"
    assert by_window["original"]["runtime_variant"] == "original-runtime"
    assert by_window["original"]["event"] == "original_uncovered"
    assert by_window["bypass"]["runtime_variant"] == "modified-runtime"
    assert by_window["bypass"]["event"] == "capture_window"
    assert by_window["original"]["window_id"] != by_window["bypass"]["window_id"]
    assert by_window["early-wrong-pid"]["pid"] == "unknown"
    assert by_window["no-log"]["module_sha256"] == "unknown"
    assert by_window["no-log"]["abi"] == "unknown"
    assert "frida_detected" not in {item["event"] for item in explained["items"]}


def test_merge_appends_diagnostics_without_new_endpoints(tmp_path: Path) -> None:
    report = Report(
        package_name="example.invalid",
        meta={
            "sample_sha256": "cd" * 32,
            "closure": {"status": "partial", "gaps": ["keep"]},
            "runtime_diagnostics": {
                "schema": "runtime-diagnostics/1",
                "frida_detection": "not_inferred",
                "endpoints_added": 0,
                "closure_evaluated": False,
                "items": [{"class": "static-potential", "event": "isolated_process", "window_id": "manifest"}],
            },
        },
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    runtime = tmp_path / "runtime_report.json"
    runtime.write_text(json.dumps({
        "package_name": "example.invalid",
        "source": "runtime",
        "endpoints": [],
        "runtime_variant": "original-runtime",
        "process_observations": [
            observation_from_capture(
                pid=10,
                uid=None,
                hook_status="java-unavailable",
                retreated=False,
                runtime_variant="original-runtime",
                pass_tag="round-1",
            ),
            observation_from_capture(
                pid=11,
                uid=None,
                hook_status="none",
                retreated=True,
                runtime_variant="modified-runtime",
                pass_tag="round-2",
            ),
        ],
    }), encoding="utf-8")
    before_endpoints = list(report.endpoints)
    merge.merge_and_rerender(
        report, [], str(tmp_path), formats=["json"], runtime_report_path=str(runtime),
    )
    assert report.endpoints == before_endpoints
    assert report.findings == []
    assert report.meta["closure"]["status"] == "partial"
    items = report.meta["runtime_diagnostics"]["items"]
    assert items[0]["event"] == "isolated_process"
    assert items[0]["class"] == "static-potential"
    events = {item["event"] for item in items}
    assert "java_only" in events
    assert "early_exit_unattributed" in events
    assert report.meta["runtime_diagnostics"]["frida_detection"] == "not_inferred"
    assert report.meta["runtime_diagnostics"]["endpoints_added"] == 0
    digest = build_digest({
        "package_name": report.package_name,
        "meta": report.meta,
        "leads": [],
        "findings": [],
        "endpoints": [],
    })
    assert digest["runtime_diagnostics"]["frida_detection"] == "not_inferred"
    assert "isolated_process" in json.dumps(digest["runtime_diagnostics"])
    rendered = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert rendered["meta"]["runtime_diagnostics"]["items"][0]["event"] == "isolated_process"


def test_static_manifest_emits_only_explicit_attributes() -> None:
    from apkscan.analyzers.runtime_diagnostics import RuntimeDiagnosticsAnalyzer

    analyzer = RuntimeDiagnosticsAnalyzer()
    plain = analyzer.analyze(FakeContext(manifest_xml="<manifest package='example.invalid'/>"))
    assert "runtime_diagnostics" not in plain.meta
    assert plain.endpoints == []
    assert plain.findings == []
    declared = analyzer.analyze(FakeContext(manifest_xml=(
        "<manifest package='example.invalid' xmlns:android="
        "'http://schemas.android.com/apk/res/android'>"
        "<application><service android:name='.Worker' "
        "android:isolatedProcess='true' android:useAppZygote='false'/>"
        "</application></manifest>"
    )))
    items = declared.meta["runtime_diagnostics"]["items"]
    by_event = {item["event"]: item for item in items}
    assert by_event["isolated_process"]["class"] == "static-potential"
    assert by_event["isolated_process"]["declared_value"] is True
    assert by_event["isolated_process"]["component_name"] == ".Worker"
    assert by_event["app_zygote"]["class"] == "static-recorded"
    assert by_event["app_zygote"]["declared_value"] is False
    assert declared.meta["runtime_diagnostics"]["frida_detection"] == "not_inferred"
    assert declared.endpoints == []


def test_new_failure_does_not_drop_old_success() -> None:
    report = Report(
        package_name="example.invalid",
        meta={"runtime_diagnostics": explain_coverage([
            _window("selinux_query", "kept", observer_attached=True),
        ])},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    merge_process_observations(report, [
        _window("early_exit", "later", runtime_variant="original-runtime"),
    ])
    events = [item["event"] for item in report.meta["runtime_diagnostics"]["items"]]
    assert events == ["selinux_query", "early_exit_unattributed"]
    assert report.endpoints == []
