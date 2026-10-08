from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan.dynamic.actions import ActionResult, AndroidActions
from apkscan.plugins.contracts import CaptureRoundContext


@pytest.fixture
def plugin(monkeypatch):
    source = Path(__file__).parents[1] / "plugins/fxapk-android-ui/src"
    monkeypatch.syspath_prepend(str(source))
    return importlib.import_module("fxapk_android_ui.plugin")


def plan(*steps, max_steps=32, duration=30):
    return {"schema_version": "ui-plan/1", "serial": "device-1", "package": "com.example.synthetic",
            "actions": list(steps), "max_steps": max_steps, "max_duration_sec": duration}


def test_plan_prevalidates_later_actions_before_any_device_mutation(plugin, monkeypatch, tmp_path):
    monkeypatch.setattr(AndroidActions, "launch_package", lambda self: pytest.fail("invalid plan launched app"))
    result = plugin._run_plan(plan({"kind": "launch"}, {"kind": "input_text", "value": "literal%svalue"}), out=tmp_path / "out")
    assert result["status"] == "failed"
    assert result["actions"][0]["index"] == 2
    assert result["actions"][0]["reason"] == "invalid_action"


def test_plan_refuses_wait_that_exceeds_remaining_budget(plugin, monkeypatch, tmp_path):
    monkeypatch.setattr(plugin.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(AndroidActions, "wait", lambda *_a: pytest.fail("wait exceeded budget"))
    result = plugin._run_plan(plan({"kind": "wait", "seconds": 30}, duration=1), out=tmp_path / "out")
    assert result["status"] == "partial"
    assert result["actions"][0]["status"] == "stopped"


def test_plan_failed_action_is_failed_and_partial_after_success(plugin, monkeypatch, tmp_path):
    monkeypatch.setattr(AndroidActions, "launch_package", lambda self: ActionResult("launch", True))
    monkeypatch.setattr(AndroidActions, "back", lambda self: ActionResult("keyevent", False))
    assert plugin._run_plan(plan({"kind": "back"}), out=tmp_path / "failed")["status"] == "failed"
    result = plugin._run_plan(plan({"kind": "launch"}, {"kind": "back"}), out=tmp_path / "out")
    assert result["status"] == "partial"


def test_run_plan_budget_stop_has_nonzero_exit_and_structured_receipt(plugin, monkeypatch, tmp_path):
    monkeypatch.setattr(AndroidActions, "launch_package", lambda self: ActionResult("launch", True))
    payload = plan({"kind": "launch"}, {"kind": "back"}, max_steps=1)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(plugin.ui_app, ["run-plan", "--serial", "device-1", "--package", "com.example.synthetic",
                                                "--plan", str(path), "--out", str(out)])
    assert result.exit_code != 0
    receipt = json.loads((out / "operations.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "partial"


def test_failed_plan_snapshot_stops_and_uses_relative_receipt(plugin, monkeypatch, tmp_path):
    monkeypatch.setattr(plugin, "_snapshot_result", lambda *_a, **_k: {"status": "failed"})
    monkeypatch.setattr(AndroidActions, "launch_package", lambda self: pytest.fail("plan continued after failed snapshot"))
    result = plugin._run_plan(plan({"kind": "snapshot"}, {"kind": "launch"}), out=tmp_path / "out")
    assert result["status"] == "failed"
    assert result["actions"][0]["receipt"] == "snapshot-1/observation.json"


@pytest.fixture
def fake_cli(plugin, monkeypatch):
    from fxapk_android_ui.android_cli import CommandResult

    class FakeCli:
        def __init__(self, *_a, **_k):
            pass

        def capture(self, *, output, **kwargs):
            output.write_bytes(b"synthetic-screen")
            return CommandResult((), 0, b"", b"")

        def layout(self, *, output, **kwargs):
            output.write_bytes(b"{}")
            return CommandResult((), 0, b"", b"")

    monkeypatch.setattr(plugin, "AndroidCli", FakeCli)
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    return FakeCli


def test_snapshot_does_not_credit_old_files_when_tool_produces_nothing(plugin, fake_cli, monkeypatch, tmp_path):
    from fxapk_android_ui.android_cli import CommandResult
    (tmp_path / "screen.png").write_bytes(b"old")
    (tmp_path / "layout.json").write_bytes(b"old")
    monkeypatch.setattr(fake_cli, "capture", lambda *_a, **_k: CommandResult((), 0, b"", b""))
    monkeypatch.setattr(fake_cli, "layout", lambda *_a, **_k: CommandResult((), 0, b"", b""))
    with pytest.raises(FileExistsError, match="ui_output_exists_refuse_overwrite"):
        plugin._snapshot_result("device-1", "com.example.synthetic", tmp_path, False, False)
    assert (tmp_path / "screen.png").read_bytes() == b"old"
    assert (tmp_path / "layout.json").read_bytes() == b"old"
    assert not (tmp_path / "observation.json").exists()


def test_round_disk_receipt_is_bound_and_artifact_hashes_match_bytes(plugin, fake_cli, tmp_path):
    context = CaptureRoundContext(serial="device-1", package_name="com.example.synthetic", round_id="round1",
                                  round_kind="pcap", out_dir=tmp_path, sample_sha256="a" * 64,
                                  capture_mode="floor-only", runtime_variant="original-runtime")
    receipt = plugin.plugin_factory().run_round(context)
    disk = json.loads((tmp_path / "ui/observation.json").read_text(encoding="utf-8"))
    assert disk == receipt
    assert disk["scope"] == "case_evidence"
    assert disk["round_id"] == "round1"
    assert disk["sample_sha256"] == "a" * 64
    assert disk["capture_mode"] == "floor-only"
    assert disk["runtime_variant"] == "original-runtime"
    assert disk["receipt_path"] == "ui/observation.json"
    for artifact in disk["artifacts"]:
        path = tmp_path / artifact["relative_path"]
        assert artifact["size"] == len(path.read_bytes())
        assert artifact["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert artifact["round_id"] == "round1"
        assert artifact["sample_sha256"] == "a" * 64


def test_android_cli_each_subprocess_timeout_uses_remaining_deadline(plugin, monkeypatch, tmp_path):
    from fxapk_android_ui.android_cli import AndroidCli
    import fxapk_android_ui.android_cli as adapter
    from apkscan.core.proctree import OwnedRun

    clock = [10.0]
    timeouts = []
    monkeypatch.setattr(plugin.time, "monotonic", lambda: clock[0])

    def run(argv, **kwargs):
        timeouts.append(kwargs["timeout"])
        clock[0] += 0.75
        return OwnedRun(0, "", "", False, True, True, False, ())

    monkeypatch.setattr(adapter, "run_owned", run)
    cli = AndroidCli("synthetic-android", deadline=11.0)
    cli.capture(serial="device-1", output=tmp_path / "screen.png")
    cli.layout(serial="device-1", output=tmp_path / "layout.json")
    assert timeouts == [1.0, 0.25]



def test_plan_keeps_structured_receipts_when_artifact_publish_fails(plugin, fake_cli, monkeypatch, tmp_path):
    monkeypatch.setattr(AndroidActions, "launch_package", lambda self: ActionResult("launch", True))
    monkeypatch.setattr(AndroidActions, "back", lambda self: pytest.fail("continued after partial snapshot"))
    out = tmp_path / "out"
    original_create = plugin.atomic_create_bytes
    monkeypatch.setattr(plugin, "atomic_create_bytes",
                        lambda path, data: False if path.name == "screen.png" else original_create(path, data))
    payload = plan({"kind": "launch"}, {"kind": "snapshot"}, {"kind": "back"})
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = CliRunner().invoke(plugin.ui_app, ["run-plan", "--serial", "device-1", "--package", "com.example.synthetic",
                                                "--plan", str(path), "--out", str(out)])
    assert result.exit_code != 0
    receipt = json.loads((out / "operations.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "partial"
    assert len(receipt["actions"]) == 2
    snapshot = json.loads((out / "snapshot-2/observation.json").read_text(encoding="utf-8"))
    assert snapshot["status"] == "partial"
    assert snapshot["operations"][0]["ok"] is False
    assert snapshot["operations"][0]["reason"] == "artifact_io_failed"


def test_plan_records_snapshot_io_failure_without_sensitive_exception_text(plugin, monkeypatch, tmp_path):
    monkeypatch.setattr(AndroidActions, "launch_package", lambda self: ActionResult("launch", True))

    def fail(*args, **kwargs):
        raise OSError("synthetic-sensitive-value")

    monkeypatch.setattr(plugin, "_snapshot_result", fail)
    result = plugin._run_plan(plan({"kind": "launch"}, {"kind": "snapshot"}), out=tmp_path / "out")
    assert result["status"] == "partial"
    assert result["actions"][1]["reason"] == "snapshot_io_failed"
    assert "synthetic-sensitive-value" not in json.dumps(result)



@pytest.mark.parametrize("foreground", [None, "com.example.other"])
def test_snapshot_refuses_capture_before_target_foreground_is_confirmed(plugin, fake_cli, monkeypatch, tmp_path, foreground):
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: foreground)
    monkeypatch.setattr(fake_cli, "capture", lambda *_a, **_k: pytest.fail("captured unselected app"))
    monkeypatch.setattr(fake_cli, "layout", lambda *_a, **_k: pytest.fail("read unselected app layout"))

    out = tmp_path / "out"
    receipt = plugin._snapshot_result("device-1", "com.example.synthetic", out, False, False)

    assert receipt["status"] == "failed"
    assert receipt["reason"] == "target_foreground_unconfirmed"
    assert receipt["artifacts"] == []
    assert receipt["target_foreground_confirmed"] is False
    assert not (out / "screen.png").exists()
    assert not (out / "layout.json").exists()
    assert json.loads((out / "observation.json").read_text(encoding="utf-8")) == receipt


def test_snapshot_keeps_partial_evidence_when_target_changes_during_capture(plugin, fake_cli, monkeypatch, tmp_path):
    foregrounds = iter(["com.example.synthetic", "com.example.other"])
    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: next(foregrounds))

    out = tmp_path / "out"
    receipt = plugin._snapshot_result("device-1", "com.example.synthetic", out, False, False)

    assert receipt["status"] == "partial"
    assert receipt["reason"] == "target_foreground_changed"
    assert receipt["foreground_package_before"] == "com.example.synthetic"
    assert receipt["foreground_package"] == "com.example.other"
    assert receipt["target_foreground_confirmed"] is False
    assert len(receipt["artifacts"]) == 2


@pytest.mark.parametrize("command", ["snapshot", "run-plan"])
@pytest.mark.parametrize("existing", ["empty_directory", "evidence_directory", "file"])
def test_existing_output_is_rejected_before_any_device_call(plugin, monkeypatch, tmp_path, command, existing):
    def forbidden(*args, **kwargs):
        pytest.fail("existing output reached a device operation")

    monkeypatch.setattr(AndroidActions, "foreground_package", forbidden)
    monkeypatch.setattr(AndroidActions, "launch_package", forbidden)
    out = tmp_path / "out"
    if existing == "file":
        out.write_bytes(b"original-output")
    else:
        out.mkdir()
        if existing == "evidence_directory":
            (out / "operations.json").write_bytes(b"original-receipt")
            (out / "screen.png").write_bytes(b"original-screen")
    before = {str(p): p.read_bytes() for p in out.rglob("*") if p.is_file()} if out.is_dir() else {str(out): out.read_bytes()}
    args = [command, "--serial", "device-1", "--package", "com.example.synthetic", "--out", str(out)]
    if command == "run-plan":
        source = tmp_path / "plan.json"
        source.write_text(json.dumps(plan({"kind": "launch"})), encoding="utf-8")
        args += ["--plan", str(source)]
    result = CliRunner().invoke(plugin.ui_app, args)
    assert result.exit_code != 0
    assert isinstance(result.exception, FileExistsError)
    after = {str(p): p.read_bytes() for p in out.rglob("*") if p.is_file()} if out.is_dir() else {str(out): out.read_bytes()}
    assert after == before


def test_snapshot_fresh_output_requires_fresh_artifacts(plugin, fake_cli, monkeypatch, tmp_path):
    from fxapk_android_ui.android_cli import CommandResult

    monkeypatch.setattr(fake_cli, "capture", lambda *_a, **_k: CommandResult((), 0, b"", b""))
    monkeypatch.setattr(fake_cli, "layout", lambda *_a, **_k: CommandResult((), 0, b"", b""))
    receipt = plugin._snapshot_result("device-1", "com.example.synthetic", tmp_path / "out", False, False)
    assert receipt["status"] == "failed"
    assert receipt["artifacts"] == []


def test_snapshot_publication_race_preserves_other_writers_bytes(plugin, fake_cli, monkeypatch, tmp_path):
    from fxapk_android_ui.android_cli import CommandResult

    out = tmp_path / "out"

    def capture(self, *, output, **kwargs):
        output.write_bytes(b"new-screen")
        (out / "screen.png").write_bytes(b"concurrent-screen")
        return CommandResult((), 0, b"", b"")

    monkeypatch.setattr(fake_cli, "capture", capture)
    receipt = plugin._snapshot_result("device-1", "com.example.synthetic", out, False, False)
    assert receipt["status"] == "partial"
    assert (out / "screen.png").read_bytes() == b"concurrent-screen"
    assert [item["kind"] for item in receipt["artifacts"]] == ["layout"]


def test_receipt_publication_never_replaces_an_existing_file(plugin, tmp_path):
    path = tmp_path / "operations.json"
    path.write_bytes(b"original-receipt")
    with pytest.raises(FileExistsError, match="ui_receipt_exists_refuse_overwrite"):
        plugin._write_result(path, {"status": "complete"})
    assert path.read_bytes() == b"original-receipt"


@pytest.mark.parametrize("outcome", ["complete", "failed", "partial"])
def test_plan_receipt_binds_executed_bytes_identity_and_utc_without_text(plugin, monkeypatch, tmp_path, outcome):
    from datetime import datetime, timedelta

    secret = "synthetic-secret-text"
    source = tmp_path / "plan.json"
    payload = plan({"kind": "input_text", "value": secret})
    if outcome == "partial":
        payload["actions"].append({"kind": "wait", "seconds": 0})
        payload["max_steps"] = 1
    original = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    source.write_bytes(original)

    def input_text(self, value):
        assert value == secret
        # Changing the plan after it was loaded must not change its receipt hash.
        source.write_bytes(b"changed-after-plan-read")
        return ActionResult("input_text", outcome != "failed", value_length=len(value))

    monkeypatch.setattr(AndroidActions, "input_text", input_text)
    out = tmp_path / "out"
    result = CliRunner().invoke(plugin.ui_app, [
        "run-plan", "--serial", "device-1", "--package", "com.example.synthetic",
        "--plan", str(source), "--out", str(out),
    ])
    assert result.exit_code == (0 if outcome == "complete" else 1)
    raw_receipt = (out / "operations.json").read_text(encoding="utf-8")
    receipt = json.loads(raw_receipt)
    assert receipt["status"] == outcome
    assert receipt["serial"] == "device-1"
    assert receipt["package"] == "com.example.synthetic"
    assert receipt["plan_sha256"] == hashlib.sha256(original).hexdigest()
    assert receipt["plan_hash_source"] == "file_bytes"
    start, end = (datetime.fromisoformat(receipt[key]) for key in ("started_at_utc", "finished_at_utc"))
    assert start.utcoffset() == end.utcoffset() == timedelta(0)
    assert start <= end
    assert secret not in raw_receipt
    assert secret not in result.output


def test_snapshot_receipt_has_utc_observation_window(plugin, fake_cli, tmp_path):
    from datetime import datetime, timedelta

    receipt = plugin._snapshot_result("device-1", "com.example.synthetic", tmp_path / "out", False, False)
    start, end = (datetime.fromisoformat(receipt[key]) for key in ("started_at_utc", "finished_at_utc"))
    assert start.utcoffset() == end.utcoffset() == timedelta(0)
    assert start <= end


@pytest.mark.parametrize("root_actions", [False, True])
def test_plan_root_actions_requires_cli_opt_in_and_is_bound_in_receipt(plugin, monkeypatch, tmp_path, root_actions):
    seen = []
    monkeypatch.setattr(AndroidActions, "tap", lambda self, x, y: seen.append(self.root_actions) or ActionResult("tap", True))
    payload = plan({"kind": "tap", "x": 1, "y": 2})
    payload["root_actions"] = True  # Plan data alone must never elevate privileges.
    source = tmp_path / "plan.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    args = ["run-plan", "--serial", "device-1", "--package", "com.example.synthetic",
            "--plan", str(source), "--out", str(tmp_path / "out")]
    if root_actions:
        args.append("--root-actions")
    result = CliRunner().invoke(plugin.ui_app, args)
    assert result.exit_code == 0
    receipt = json.loads((tmp_path / "out/operations.json").read_text(encoding="utf-8"))
    assert seen == [root_actions]
    assert receipt["root_actions"] is root_actions


def test_plan_stops_when_input_reports_security_exception_at_exit_zero(plugin, monkeypatch, tmp_path):
    from types import SimpleNamespace

    monkeypatch.setattr(AndroidActions, "foreground_package", lambda self: self.package)
    monkeypatch.setattr("apkscan.dynamic.actions.device._run", lambda *_a, **_k: SimpleNamespace(
        returncode=0, stdout="", stderr="java.lang.SecurityException: INJECT_EVENTS denied"))
    monkeypatch.setattr(AndroidActions, "back", lambda *_a: pytest.fail("continued after denied input"))
    result = plugin._run_plan(plan({"kind": "tap", "x": 1, "y": 2}, {"kind": "back"}), out=tmp_path / "out")
    assert result["status"] == "failed"
    assert len(result["actions"]) == 1
    assert result["actions"][0]["result"]["detail"] == "injection_permission_denied"


@pytest.mark.parametrize("no_idle", [False, True])
def test_snapshot_idle_policy_is_explicit_and_recorded(plugin, fake_cli, monkeypatch, tmp_path, no_idle):
    original_layout = fake_cli.layout
    observed = []

    def layout(self, **kwargs):
        observed.append(kwargs["no_idle"])
        return original_layout(self, **kwargs)

    monkeypatch.setattr(fake_cli, "layout", layout)
    args = ["snapshot", "--serial", "device-1", "--package", "com.example.synthetic", "--out", str(tmp_path / "out")]
    if no_idle:
        args.append("--no-idle")
    result = CliRunner().invoke(plugin.ui_app, args)
    assert result.exit_code == 0
    receipt = json.loads((tmp_path / "out/observation.json").read_text(encoding="utf-8"))
    assert observed == [no_idle]
    assert receipt["layout_wait_for_idle"] is not no_idle


def test_plan_snapshot_passes_no_idle_and_rejects_nonboolean_before_actions(plugin, monkeypatch, tmp_path):
    observed = []
    monkeypatch.setattr(plugin, "_snapshot_result", lambda *_a, **kw: observed.append(kw["no_idle"]) or {"status": "complete"})
    result = plugin._run_plan(plan({"kind": "snapshot", "no_idle": True}), out=tmp_path / "good")
    assert result["status"] == "complete"
    assert observed == [True]
    monkeypatch.setattr(AndroidActions, "launch_package", lambda *_a: pytest.fail("invalid plan reached device"))
    result = plugin._run_plan(plan({"kind": "launch"}, {"kind": "snapshot", "no_idle": "yes"}), out=tmp_path / "bad")
    assert result["status"] == "failed"
    assert len(observed) == 1


def test_android_cli_no_idle_is_opt_in(plugin, monkeypatch, tmp_path):
    from fxapk_android_ui.android_cli import AndroidCli, CommandResult

    calls = []
    monkeypatch.setattr(AndroidCli, "_run", lambda self, *args: calls.append(args) or CommandResult(args, 0, b"", b""))
    cli = AndroidCli("synthetic-android")
    cli.layout(serial="device-exact", output=tmp_path / "layout.json")
    cli.layout(serial="device-exact", output=tmp_path / "layout.json", no_idle=True)
    assert "--no-idle" not in calls[0]
    assert calls[1] == (*calls[0], "--no-idle")


def test_layout_failure_preserves_bounded_controlled_diagnostics_without_echo(plugin, fake_cli, monkeypatch, tmp_path):
    from fxapk_android_ui.android_cli import CommandResult

    private_text = b"synthetic-private-ui-text"
    raw = b"Could not obtain idle state: " + private_text + b"x" * 70000
    monkeypatch.setattr(fake_cli, "layout", lambda *_a, **_k: CommandResult((), 1, b"", raw))
    out = tmp_path / "out"
    result = CliRunner().invoke(plugin.ui_app, ["snapshot", "--serial", "device-1", "--package", "com.example.synthetic", "--out", str(out)])
    assert result.exit_code == 1
    receipt_text = (out / "observation.json").read_text(encoding="utf-8")
    receipt = json.loads(receipt_text)
    operation = receipt["operations"][1]
    assert operation["reason"] == "command_exit_nonzero"
    assert receipt["status"] == "partial"
    assert private_text.decode() not in result.output
    assert private_text.decode() not in receipt_text
    diagnostic = operation["diagnostics"][0]
    assert diagnostic["scope"] == "controlled_diagnostic"
    assert diagnostic["size"] == 65536
    assert diagnostic["truncated"] is True
    assert diagnostic["original_size"] == len(raw)
    assert diagnostic["original_sha256"] == hashlib.sha256(raw).hexdigest()
    retained = (out / diagnostic["relative_path"]).read_bytes()
    assert retained == raw[:65536]
    assert hashlib.sha256(retained).hexdigest() == diagnostic["sha256"]


@pytest.mark.parametrize("owned,terminated,forced", [(False, True, False), (True, False, False), (True, True, True)])
def test_android_cli_refuses_success_when_process_tree_is_not_clean(plugin, monkeypatch, owned, terminated, forced):
    from apkscan.core.proctree import OwnedRun
    import fxapk_android_ui.android_cli as adapter

    monkeypatch.setattr(adapter, "run_owned", lambda *_a, **_k: OwnedRun(
        0, "synthetic-output", "", False, owned, terminated, forced, ("synthetic_reason",),
    ))
    result = adapter.AndroidCli("synthetic-android").version()
    assert result.ok is False
    assert result.ownership_complete is owned
    assert result.termination_complete is terminated
    assert result.forced_tree_kill is forced
    assert result.reason_codes == ("synthetic_reason",)
    assert result.output_format == "utf8_text_normalized"


def test_snapshot_does_not_credit_output_after_unverified_tree_cleanup(plugin, fake_cli, monkeypatch, tmp_path):
    from fxapk_android_ui.android_cli import CommandResult

    def bad_capture(*_args, output, **_kwargs):
        output.write_bytes(b"synthetic-screen")
        return CommandResult((), 0, b"", b"", termination_complete=False, reason_codes=("survivors_after_kill",))

    monkeypatch.setattr(fake_cli, "capture", bad_capture)
    out = tmp_path / "out"
    receipt = plugin._snapshot_result("device-1", "com.example.synthetic", out, False, False)
    operation = receipt["operations"][0]
    assert receipt["status"] == "partial"
    assert operation["reason"] == "process_tree_unverified"
    assert operation["process_tree"]["termination_complete"] is False
    assert operation["process_tree"]["reason_codes"] == ["survivors_after_kill"]
    assert not (out / "screen.png").exists()


def test_android_cli_timeout_stops_windows_wrapper_descendant(plugin, tmp_path):
    import sys
    import time

    import psutil
    from fxapk_android_ui.android_cli import AndroidCli

    if sys.platform != "win32":
        pytest.skip("Windows command wrapper timeout regression")
    child = tmp_path / "synthetic_child.py"
    child.write_text("import os, time\nprint(os.getpid(), flush=True)\ntime.sleep(30)\n", encoding="utf-8")
    wrapper = tmp_path / "synthetic_android.cmd"
    executable = getattr(sys, "_base_executable", None) or sys.executable
    wrapper.write_text(f'@echo off\n"{executable}" "{child}"\n', encoding="utf-8")
    started = time.monotonic()
    result = AndroidCli(str(wrapper), timeout_sec=1.0).version()
    elapsed = time.monotonic() - started
    pid = int(result.stdout.strip()) if result.stdout.strip() else None
    try:
        assert result.timed_out is True
        assert result.ok is False
        assert result.ownership_complete and result.termination_complete
        assert "timeout" in result.reason_codes
        assert elapsed < 10, "wrapper timeout waited on its surviving child's pipe"
        if pid is not None:
            assert not psutil.pid_exists(pid), "child survived the wrapper timeout"
    finally:
        if pid is not None:
            try:
                process = psutil.Process(pid)
                if str(child) in process.cmdline():
                    process.kill()
            except psutil.NoSuchProcess:
                pass
