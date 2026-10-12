"""E1/E3/E5 退出反例。设备、联网和真实 APK 都不碰。"""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import click
import pytest
import typer
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.models import Report
from apkscan.core.report_delivery import ReportDelivery
from apkscan.dynamic.cancel import AutoCancelled, CANCEL_EXIT_CODE
from apkscan.dynamic import auto

runner = CliRunner()


def _report() -> Report:
    return Report("invalid.example.synthetic", {}, [], [], [], [])


def _apk(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic.apk"
    path.write_bytes(b"synthetic-loader-input; not an APK")
    return path


def _stub_analyze(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_adb_owned_at_start", lambda: False)
    monkeypatch.setattr(cli, "_cleanup_adb_quiet", lambda *_a, **_k: None)
    monkeypatch.setattr(cli.device, "has_device", lambda: False)
    monkeypatch.setattr(
        cli,
        "load_apk",
        lambda *_a, **_k: SimpleNamespace(
            package_name="invalid.example.synthetic", extra_dex_report=None
        ),
    )
    monkeypatch.setattr("apkscan.core.pipeline.run", lambda *_a, **_k: _report())


def _stub_auto_pipeline(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """静态报告可写出；设备动作与闭环都换成计数桩。"""
    import apkscan.core.apk as apk_mod
    import apkscan.core.pipeline as pipeline_mod
    import apkscan.dynamic.capture as capture_mod
    import apkscan.dynamic.doctor as doctor_mod
    import apkscan.dynamic.provision as provision_mod
    import apkscan.dynamic.repackage as repackage_mod
    import apkscan.dynamic.unpack as unpack_mod
    from apkscan.core import closure

    counts = {"capture": 0, "closure": 0, "repackage": 0, "merge": 0}

    monkeypatch.setattr(auto.device, "select_target_serial", lambda: "synthetic-device")
    monkeypatch.setattr(doctor_mod, "run", lambda **_k: {"ok": True, "items": []})
    monkeypatch.setattr(
        provision_mod, "ensure_frida_server", lambda **_k: {"ok": True, "action": "already_running"}
    )
    monkeypatch.setattr(provision_mod, "install_apk", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(
        unpack_mod, "run", lambda *_a, **_k: {"status": "skipped", "reason": "synthetic"}
    )
    monkeypatch.setattr(apk_mod, "load_apk", lambda *_a, **_k: SimpleNamespace(
        package_name="invalid.example.synthetic", extra_dex_report=None
    ))
    monkeypatch.setattr(pipeline_mod, "run", lambda *_a, **_k: _report())

    def _capture(*_a, **_k):
        counts["capture"] += 1
        return {"status": "done", "report_paths": [], "artifacts": []}

    def _close(*_a, **_k):
        counts["closure"] += 1
        return {"status": "complete", "targets": [], "gaps": [], "next_actions": []}

    def _repackage(*_a, **_k):
        counts["repackage"] += 1
        return {"status": "skipped"}

    monkeypatch.setattr(capture_mod, "run", _capture)
    monkeypatch.setattr(closure, "close_report", _close)
    monkeypatch.setattr(repackage_mod, "run", _repackage)
    return counts


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (None, 1),
        ({}, 1),
        ({"status": "unexpected"}, 1),
        ({"status": None}, 1),
        ({"status": ""}, 1),
        ({"status": 0}, 1),
        ({"status": []}, 1),
        ([], 1),
        ("done", 1),
        ({"status": "done"}, 0),
        ({"status": "error"}, 1),
        ({"status": "skipped"}, 2),
        ({"status": "degraded"}, 3),
    ],
)
@pytest.mark.parametrize("command", ["capture", "unpack", "repackage"])
def test_dynamic_cli_rejects_non_contract_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command: str, payload: object, expected: int
) -> None:
    module = __import__(f"apkscan.dynamic.{command}", fromlist=["run"])
    monkeypatch.setattr(module, "run", lambda *_a, **_k: payload)
    monkeypatch.setattr(cli, "_adb_owned_at_start", lambda: False)
    cleaned = {"n": 0}
    monkeypatch.setattr(
        cli, "_cleanup_adb_quiet", lambda *_a, **_k: cleaned.__setitem__("n", cleaned["n"] + 1)
    )
    target = "invalid.example.synthetic" if command == "capture" else str(_apk(tmp_path))
    result = runner.invoke(cli.app, [command, target, "--out", str(tmp_path / command)])
    assert result.exit_code == expected
    if command == "capture":
        assert cleaned["n"] == 1


def test_analyze_json_oserror_is_not_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_analyze(monkeypatch)

    def _boom(*_a, **_k):
        raise OSError("synthetic-write-error")

    monkeypatch.setattr("apkscan.report.json.dump", _boom)
    out = tmp_path / "out"
    result = runner.invoke(
        cli.app, ["analyze", str(_apk(tmp_path)), "--offline", "--fmt", "json", "--out", str(out)]
    )
    assert result.exit_code == 1
    assert not (out / "synthetic.json").exists()
    assert "synthetic-write-error" not in (result.output or "")


def test_analyze_html_success_does_not_cover_json_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_analyze(monkeypatch)

    def _boom(*_a, **_k):
        raise OSError("synthetic-write-error")

    def _html(report, path, *_a, **_k):
        Path(path).write_text("<html>synthetic</html>", encoding="utf-8")

    monkeypatch.setattr("apkscan.report.json.dump", _boom)
    monkeypatch.setattr("apkscan.report.html.render", _html)
    out = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        ["analyze", str(_apk(tmp_path)), "--offline", "--fmt", "html,json", "--out", str(out), "--strict"],
    )
    assert result.exit_code == 1
    assert (out / "synthetic.html").is_file()
    assert not (out / "synthetic.json").exists()


def test_analyze_partial_temp_keeps_old_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_analyze(monkeypatch)
    out = tmp_path / "out"
    out.mkdir()
    target = out / "synthetic.json"
    old = b'{"old":"valid-synthetic-report"}\n'
    target.write_bytes(old)

    def _partial(stream, data):
        stream.write(data[:3])
        raise OSError("synthetic-temp-write-error")

    monkeypatch.setattr("apkscan.core.atomic._write_text_to_stream", _partial)
    result = runner.invoke(
        cli.app, ["analyze", str(_apk(tmp_path)), "--offline", "--fmt", "json", "--out", str(out)]
    )
    assert result.exit_code == 1
    assert target.read_bytes() == old
    assert not list(out.glob(".synthetic.json.*.tmp"))


def test_analyze_success_control_exits_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_analyze(monkeypatch)
    out = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        ["analyze", str(_apk(tmp_path)), "--offline", "--fmt", "json", "--out", str(out), "--strict"],
    )
    assert result.exit_code == 0
    assert (out / "synthetic.json").is_file()


def test_merge_failure_receipt_blocks_without_dropping_written_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from apkscan.dynamic import merge
    from apkscan.report import html as report_html

    def _boom(*_a, **_k):
        raise OSError("synthetic-html-error")

    monkeypatch.setattr(report_html, "render", _boom)
    stats = merge.merge_and_rerender(_report(), [], str(tmp_path), "synthetic", formats=["html", "json"])
    delivery = stats["report_delivery"]
    assert isinstance(delivery, ReportDelivery)
    assert delivery.blocks_success()
    assert "json" in delivery.written
    assert "html" in delivery.failed
    assert (tmp_path / "synthetic.json").is_file()
    assert not (tmp_path / "synthetic.html").exists()


def test_auto_merge_delivery_failure_is_not_done(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from apkscan.report import html as report_html

    def _boom(*_a, **_k):
        raise OSError("synthetic-html-error")

    monkeypatch.setattr(report_html, "render", _boom)
    step, paths = auto._run_merge(
        _report(),
        str(tmp_path / "missing-runtime.json"),
        out_dir=str(tmp_path),
        base="synthetic",
        formats=["html", "json"],
        on_progress=None,
    )
    assert step["status"] == "error"
    assert any(path.endswith("synthetic.json") for path in paths)
    assert not any(path.endswith("synthetic.html") for path in paths)


@pytest.mark.parametrize("case", ["False", "Abort", "KeyboardInterrupt"])
def test_confirm_stop_signal_does_not_continue(case: str) -> None:
    def _callback(_message: str):
        if case == "Abort":
            raise click.Abort()
        if case == "KeyboardInterrupt":
            raise KeyboardInterrupt()
        return False

    try:
        returned = auto._confirm(_callback, "synthetic confirmation")
    except AutoCancelled:
        return
    except KeyboardInterrupt:
        pytest.fail("KeyboardInterrupt was not converted to AutoCancelled")
    assert returned is False


@pytest.mark.parametrize("case", ["True", "None"])
def test_confirm_continue_controls(case: str) -> None:
    def _callback(_message: str) -> bool:
        return True

    returned = auto._confirm(None if case == "None" else _callback, "synthetic confirmation")
    assert returned is not False


def test_auto_run_cancel_stops_capture_and_closure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    counts = _stub_auto_pipeline(monkeypatch)

    def _refuse(_message: str) -> bool:
        return False

    try:
        result = auto.run(
            str(_apk(tmp_path)),
            out_dir=str(tmp_path / "out"),
            online=False,
            auto_fix=False,
            confirm=_refuse,
            repackage=False,
        )
    except KeyboardInterrupt:
        pytest.fail("KeyboardInterrupt escaped auto.run")
    assert result["status"] == "cancelled"
    assert result["closure"]["status"] != "complete"
    assert counts["capture"] == 0
    assert counts["closure"] == 0
    assert counts["repackage"] == 0


def test_second_round_cancel_keeps_first_round_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from apkscan.dynamic.capture_sequence import run_rounds

    calls: list[int] = []

    def _runner(package: str, **kwargs):
        del package
        number = len(calls) + 1
        calls.append(number)
        out = Path(kwargs["out"])
        out.mkdir(parents=True, exist_ok=True)
        artifact = out / "runtime_report.json"
        artifact.write_text(
            json.dumps({"package_name": "invalid.example.synthetic", "round": number}),
            encoding="utf-8",
        )
        return {"status": "done", "report_paths": [str(artifact)]}

    def _before(message: str) -> None:
        if "2/3" in message:
            raise AutoCancelled("confirm_refused")

    with pytest.raises(AutoCancelled):
        run_rounds(
            "invalid.example.synthetic",
            report=_report(),
            unpacked=False,
            out_dir=str(tmp_path),
            duration=1,
            runner=_runner,
            before_round=_before,
        )
    assert calls == [1]
    assert (tmp_path / "round1-pcap" / "runtime_report.json").is_file()
    assert not (tmp_path / "round2-probe").exists()


def test_cli_auto_tty_refusal_exits_130(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    counts = _stub_auto_pipeline(monkeypatch)
    monkeypatch.setattr(cli, "_adb_owned_at_start", lambda: False)
    cleaned = {"n": 0}
    monkeypatch.setattr(
        cli, "_cleanup_adb_quiet", lambda *_a, **_k: cleaned.__setitem__("n", cleaned["n"] + 1)
    )
    monkeypatch.setattr(typer, "confirm", lambda *_a, **_k: False)
    original = runner.isolation

    @contextmanager
    def _isolation(*args, **kwargs):
        with original(*args, **kwargs) as streams:
            with patch.object(sys.stdin, "isatty", return_value=True):
                yield streams

    try:
        with patch.object(runner, "isolation", side_effect=_isolation):
            result = runner.invoke(
                cli.app,
                [
                    "auto",
                    str(_apk(tmp_path)),
                    "--offline",
                    "--no-fix",
                    "--fmt",
                    "json",
                    "--duration",
                    "1",
                    "--single-round",
                    "--out",
                    str(tmp_path / "out"),
                ],
            )
    except KeyboardInterrupt:
        pytest.fail("KeyboardInterrupt escaped CLI")
    assert result.exit_code == CANCEL_EXIT_CODE
    assert counts["capture"] == 0
    assert counts["closure"] == 0
    assert cleaned["n"] == 1


def test_cli_auto_delivery_failure_precedes_complete_closure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "_adb_owned_at_start", lambda: False)
    monkeypatch.setattr(cli, "_cleanup_adb_quiet", lambda *_a, **_k: None)
    monkeypatch.setattr(
        auto,
        "run",
        lambda *_a, **_k: {
            "status": "complete",
            "closure": {"status": "complete", "gaps": []},
            "steps": [],
            "report_paths": [],
            "package_name": "invalid.example.synthetic",
            "out_dir": "out",
            "report_delivery": ReportDelivery(("json",), (), ("json",), ()),
        },
    )
    result = runner.invoke(
        cli.app,
        ["auto", str(_apk(tmp_path)), "--offline", "--strict-case", "--no-fix"],
    )
    assert result.exit_code == 1
