"""Synthetic CLI cancellation during report merge; no device or APK operations."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fxapk import cli
from fxapk.core.models import Report
from fxapk.core.report_delivery import ReportDelivery
from fxapk.dynamic import auto, capture_sequence
from fxapk.dynamic.cancel import AutoCancelled


@pytest.mark.parametrize(
    ("interrupt", "reason"),
    [(KeyboardInterrupt(), "merge_interrupted"), (AutoCancelled("existing_cancel"), "existing_cancel")],
)
def test_cli_merge_cancel_keeps_completed_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interrupt: BaseException, reason: str,
) -> None:
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"Not an APK")
    source = b'{"package_name":"com.example.fixture","runtime_variant":"original-runtime"}'
    paths = [tmp_path / f"capture-{i}.json" for i in range(1, 4)]
    for path in paths:
        path.write_bytes(source)
    rows = [
        {
            "round": i, "kind": kind, "status": "done", "reason": "synthetic",
            "runtime_report_path": str(path), "runtime_report_sha256": hashlib.sha256(source).hexdigest(),
        }
        for i, (kind, path) in enumerate(zip(("pcap", "generic", "targeted"), paths, strict=True), 1)
    ]
    static_path = tmp_path / "static.json"
    merged_path = tmp_path / "merged.json"
    report = Report("com.example.fixture", {}, [], [], [], [])

    def step(name):
        return auto._step(name, "done", "synthetic")

    def fake_static(*args, **kwargs):
        static_path.write_bytes(b"static")
        return step(auto._STEP_STATIC), report, report.package_name, [str(static_path)], "fixture"

    calls: list[str] = []

    def fake_merge(report_arg, path, **kwargs):
        assert report_arg is report
        calls.append(path)
        if len(calls) == 2:
            raise interrupt
        assert len(calls) == 1
        merged_path.write_bytes(b"merged")
        kwargs["delivery_sink"].append(ReportDelivery(("json",), ("json",), (), ()))
        return step(auto._STEP_MERGE), [str(merged_path)]

    def unexpected(*args, **kwargs):
        pytest.fail("unexpected later or unstubbed operation")

    monkeypatch.setattr(cli, "_adb_owned_at_start", lambda: False)
    monkeypatch.setattr(cli, "_cleanup_adb_quiet", lambda _: None)
    monkeypatch.setattr(auto.device, "select_target_serial", lambda: "synthetic-device")
    monkeypatch.setattr(auto, "_run_doctor", lambda **_: step(auto._STEP_DOCTOR))
    monkeypatch.setattr(auto, "_ensure_root_frida_server", lambda **_: None)
    monkeypatch.setattr(auto, "_run_install_app", lambda *_, **__: step(auto._STEP_INSTALL))
    monkeypatch.setattr(auto, "_run_unpack", lambda *_, **__: (step(auto._STEP_UNPACK), [], None))
    monkeypatch.setattr(auto, "_run_static", fake_static)
    monkeypatch.setattr(capture_sequence, "run_rounds", lambda *_, **__: rows)
    monkeypatch.setattr(auto, "_run_capture", unexpected)
    monkeypatch.setattr(auto, "_run_repackage", unexpected)
    monkeypatch.setattr(auto, "_run_merge", fake_merge)
    monkeypatch.setattr(auto, "_run_closure", unexpected)

    real_run = auto.run
    observed: list[auto.RunResult] = []

    def observe(*args, **kwargs):
        value = real_run(*args, **kwargs)
        observed.append(value)
        return value

    monkeypatch.setattr(auto, "run", observe)
    cli_result = CliRunner().invoke(
        cli.app, ["auto", str(apk), "--out", str(tmp_path / "out"), "--offline",
                  "--no-fix", "--no-repackage", "--fmt", "json", "--strict-case"],
    )
    assert cli_result.exit_code == 130, cli_result.output
    [result] = observed
    assert result["status"] == "cancelled" and result["closure"]["status"] == "not_run"
    assert result["cancel_reason"] == reason
    assert result["report_paths"] == [str(static_path), str(merged_path)]
    assert result["report_delivery"] == ReportDelivery(("json",), ("json",), (), ())
    assert [s["status"] for s in result["steps"] if s["name"] == auto._STEP_MERGE] == ["done"]
    assert calls == [str(paths[0]), str(paths[1])]
    assert static_path.read_bytes() == b"static" and merged_path.read_bytes() == b"merged"
    assert str(merged_path) in cli_result.output
    assert "后续步骤：未执行（已取消）" in cli_result.output
    assert "案件闭环：not_run" in cli_result.output
