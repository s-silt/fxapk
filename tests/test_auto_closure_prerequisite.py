"""Isolated CLI coverage for missing and recovered report inputs to closure."""
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fxapk import cli
from fxapk.core.models import Report
from fxapk.core.report_delivery import ReportDelivery
from fxapk.dynamic import auto


@pytest.mark.parametrize(
    ("recover", "strict", "exit_code", "exception_stage"),
    [
        (False, False, 0, None), (False, True, 6, None),
        (True, True, 0, None), (True, True, 6, None),
        (False, True, 6, "before"), (True, True, 6, "during"),
    ],
    ids=["missing-default", "missing-strict", "recovered-complete", "recovered-failed",
         "unexpected-before-closure", "unexpected-during-closure"],
)
def test_closure_requires_a_report_but_can_use_recovered_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recover: bool, strict: bool, exit_code: int,
    exception_stage: str | None,
) -> None:
    apk = tmp_path / "inert.apk"
    apk.write_bytes(b"not an APK; simulated inputs only")
    report_path = tmp_path / "recovered.json"
    report = Report("com.example.fixture", {}, [], [], [], [])
    observed = []
    closure_calls = []

    def try_recover(*_, **__):
        if exception_stage == "before":
            raise RuntimeError("synthetic error")
        if not recover:
            return auto._step(auto._STEP_UNPACK, "skipped", "synthetic"), [], None
        return auto._step(auto._STEP_UNPACK, "done", "synthetic"), [], report

    def run_closure(value, *, delivery_sink, **_):
        closure_calls.append(value)
        if exception_stage == "during":
            raise RuntimeError("synthetic error")
        verdict = "complete" if exit_code == 0 else "failed"
        if verdict == "complete":
            report_path.write_text("synthetic", encoding="utf-8")
            delivery_sink.append(ReportDelivery(("json",), ("json",), (), ()))
        return (
            auto._step(auto._STEP_CLOSE, "done" if verdict == "complete" else "error", verdict),
            {"status": verdict, "gaps": []},
            [str(report_path)] if verdict == "complete" else [],
        )

    def unexpected(*_, **__):
        pytest.fail("unexpected device or unsupported stage")

    real_run = auto.run

    def observe(*args, **kwargs):
        result = real_run(*args, **kwargs)
        observed.append(result)
        return result

    monkeypatch.setattr(cli, "_adb_owned_at_start", lambda: False)
    monkeypatch.setattr(cli, "_cleanup_adb_quiet", lambda _: None)
    monkeypatch.setattr(auto.device, "select_target_serial", lambda: None)
    monkeypatch.setattr(auto, "_run_doctor", lambda **_: auto._step(auto._STEP_DOCTOR, "done", "synthetic"))
    monkeypatch.setattr(auto, "_run_static", lambda *_, **__: (
        auto._step(auto._STEP_STATIC, "error", "synthetic"), None, "", [], "inert",
    ))
    monkeypatch.setattr(auto, "_run_unpack", try_recover)
    monkeypatch.setattr(auto, "_run_capture", lambda *_, **__: (
        auto._step(auto._STEP_CAPTURE, "skipped", "synthetic"), "",
    ))
    monkeypatch.setattr(auto, "_run_install_app", unexpected)
    monkeypatch.setattr(auto, "_run_repackage", unexpected)
    monkeypatch.setattr(auto, "_ensure_root_frida_server", unexpected)
    monkeypatch.setattr(auto, "_run_closure", run_closure)
    monkeypatch.setattr(auto, "run", observe)

    args = ["auto", str(apk), "--out", str(tmp_path / "out"),
            "--offline", "--no-fix", "--no-repackage", "--fmt", "json"]
    if strict:
        args.append("--strict-case")
    invocation = CliRunner().invoke(cli.app, args)
    assert invocation.exit_code == exit_code, invocation.output
    [result] = observed
    if exception_stage:
        assert result["status"] == "failed"
        assert not result["report_paths"] and not report_path.exists()
        assert "synthetic error" not in invocation.output
        if exception_stage == "before":
            assert closure_calls == []
            assert result["closure"]["status"] == "not_run"
            assert result["closure"]["gaps"] == ["pipeline_stopped_before_closure"]
            assert "案件闭环：not_run" in invocation.output
        else:
            assert closure_calls == [report]
            assert result["closure"]["status"] == "failed"
            assert result["closure"]["gaps"] == ["closure_execution_error"]
            assert "案件闭环：failed" in invocation.output
        return
    [close] = [step for step in result["steps"] if step["name"] == auto._STEP_CLOSE]
    if recover:
        assert closure_calls == [report]
        assert result["closure"]["status"] == ("complete" if exit_code == 0 else "failed")
        assert close["status"] == ("done" if exit_code == 0 else "error")
        assert report_path.is_file() is (exit_code == 0)
    else:
        assert closure_calls == []
        assert result["status"] == "failed"
        assert result["closure"]["status"] == "not_run"
        assert result["closure"]["gaps"] == ["no_report_for_closure"]
        assert close["status"] == "skipped"
        assert "案件闭环：not_run" in invocation.output
        assert "无可用于闭环的报告" in invocation.output
        assert not result["report_paths"] and not report_path.exists()
