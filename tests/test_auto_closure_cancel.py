"""Cancellation at the case-closure boundary with synthetic reports and no device."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fxapk import cli
from fxapk.core import closure
from fxapk.core.models import Report
from fxapk.core.report_delivery import ReportDelivery
from fxapk.dynamic import auto


@pytest.mark.parametrize(("scenario", "verdict", "expected_exit"), [
    ("calculate", "partial", 130),
    ("before_write", "partial", 130),
    ("json_failure", "complete", 1),
    ("json_failure", "partial", 1),
    ("html_failure", "complete", 1),
    ("html_failure", "partial", 1),
    ("delivered", "complete", 0),
    ("delivered", "partial", 5),
])
def test_closure_interrupt_preserves_existing_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str, verdict: str, expected_exit: int,
) -> None:
    fixture = tmp_path / "fixture.apk"
    fixture.write_bytes(b"synthetic report-only input; never open as an APK")
    report = Report("com.example.fixture", {}, [], [], [], [])
    saved: list[bytes] = []
    closed: list[bool] = []
    observed: list[auto.RunResult] = []

    def static(*_, out_dir, formats, delivery_sink, **__):
        paths = auto._write_reports(report, out_dir=out_dir, formats=formats, base="fixture",
                                    delivery_sink=delivery_sink)
        saved.append(Path(paths[0]).read_bytes())
        if scenario == "html_failure":
            Path(paths[0]).with_suffix(".html").write_text("old inert HTML", encoding="utf-8")
        return auto._step(auto._STEP_STATIC, "done", "synthetic"), report, report.package_name, paths, "fixture"

    def close(input_report, _config):
        assert input_report is report
        closed.append(True)
        if scenario == "calculate":
            raise KeyboardInterrupt
        result = {"status": verdict, "targets": [], "gaps": []}
        input_report.meta["closure"] = result
        return result

    def unexpected(*_, **__):
        pytest.fail("unexpected device or later write step")

    monkeypatch.setattr(cli, "_adb_owned_at_start", lambda: False)
    monkeypatch.setattr(cli, "_cleanup_adb_quiet", lambda _: None)
    monkeypatch.setattr(auto.device, "select_target_serial", lambda: None)
    monkeypatch.setattr(auto, "_run_doctor", lambda **_: auto._step(auto._STEP_DOCTOR, "done", "synthetic"))
    monkeypatch.setattr(auto, "_run_static", static)
    monkeypatch.setattr(auto, "_run_unpack", lambda *_, **__: (auto._step(auto._STEP_UNPACK, "skipped", ""), [], None))
    monkeypatch.setattr(auto, "_run_capture", lambda *_, **__: (auto._step(auto._STEP_CAPTURE, "skipped", ""), ""))
    monkeypatch.setattr(auto, "_run_install_app", unexpected)
    monkeypatch.setattr(auto, "_run_repackage", unexpected)
    monkeypatch.setattr(auto, "_ensure_root_frida_server", unexpected)
    monkeypatch.setattr(closure, "close_report", close)
    if scenario in ("calculate", "before_write"):
        from fxapk.core import report_io

        def cancel_write(*_, **__):
            assert scenario == "before_write"
            raise KeyboardInterrupt

        monkeypatch.setattr(report_io, "write_report", cancel_write)

    if scenario == "html_failure":
        from fxapk.report import html as report_html

        def reject_html(*_, **__):
            raise OSError("synthetic HTML write failure before replacement")

        monkeypatch.setattr(report_html, "render", reject_html)
    if scenario == "json_failure":
        from fxapk.core import report_io

        def reject_json(*_, **__):
            raise OSError("synthetic JSON write failure before replacement")

        monkeypatch.setattr(report_io, "atomic_write_text", reject_json)

    real_run = auto.run

    def observe(*args, **kwargs):
        value = real_run(*args, **kwargs)
        observed.append(value)
        return value

    monkeypatch.setattr(auto, "run", observe)
    out = tmp_path / "out"
    invocation = CliRunner().invoke(cli.app, ["auto", str(fixture), "--out", str(out),
        "--offline", "--no-fix", "--no-repackage", "--fmt", "json", "--strict-case"])
    assert closed == [True]
    assert invocation.exit_code == expected_exit, invocation.output
    [result] = observed
    path = out / "fixture.json"
    assert result["report_paths"] == [str(path)]
    assert str(path) in invocation.output
    if scenario in ("json_failure", "html_failure"):
        fmt = scenario.split("_")[0]
        requested = ("json", "html") if fmt == "html" else ("json",)
        assert result["report_delivery"] == ReportDelivery(requested, ("json",), (fmt,), ())
        assert result["status"] == result["closure"]["status"] == verdict
        assert f"必需报告写出失败：{fmt}" in invocation.output
        if fmt == "html":
            assert json.loads(path.read_text())["meta"]["closure"]["status"] == verdict
            assert path.with_suffix(".html").read_text() == "old inert HTML"
            assert "JSON 已写出" in invocation.output
        else:
            assert path.read_bytes() == saved[0]
        return
    assert result["report_delivery"] == ReportDelivery(("json",), ("json",), (), ())
    if scenario in ("calculate", "before_write"):
        assert result["status"] == "cancelled"
        assert result["cancel_reason"] == "closure_interrupted"
        assert result["closure"]["status"] == "interrupted"
        assert result["closure"]["gaps"] == ["closure_interrupted"]
        assert "案件闭环：interrupted" in invocation.output
        assert "案件闭环已开始，但未完成" in invocation.output
        assert "停止后续抓包" not in invocation.output
        assert path.read_bytes() == saved[0]
    else:
        assert result["status"] == result["closure"]["status"] == verdict
        assert f"案件闭环：{verdict}" in invocation.output
        assert json.loads(path.read_text())["meta"]["closure"]["status"] == verdict
