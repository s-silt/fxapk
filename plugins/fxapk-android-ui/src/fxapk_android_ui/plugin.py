"""Plugin CLI and factory."""
from __future__ import annotations

import hashlib
import json
import math
import tempfile
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer

from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.integrity import sha256_file
from apkscan.dynamic.actions import AndroidActions, validate_action
from apkscan.plugins.contracts import PLUGIN_API_VERSION, CaptureRoundContext, ExternalEvidenceAttachment

from .android_cli import AndroidCli, CommandResult

ui_app = typer.Typer(add_completion=False, help="Android CLI UI observation and controlled actions.")


def _write_result(path: Path, result: dict[str, Any]) -> None:
    raw = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if not atomic_create_bytes(path, raw):
        raise FileExistsError("ui_receipt_exists_refuse_overwrite")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _claim_output(out: Path) -> None:
    # The leaf directory is the exclusive claim: reject even an empty existing
    # directory, file, or symlink before making the first device call.
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise FileExistsError("ui_output_exists_refuse_overwrite") from None


def _load_plan(path: Path, *, package: str, serial: str) -> tuple[dict[str, Any], str]:
    # Parse and hash the same read, so a later input-file edit cannot rebind the
    # receipt to a different plan from the one actually executed.
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != "ui-plan/1":
        raise typer.BadParameter("plan schema_version 必须为 ui-plan/1")
    if payload.get("package") != package or payload.get("serial") != serial:
        raise typer.BadParameter("plan package 或 serial 与命令不匹配")
    actions = payload.get("actions")
    if not isinstance(actions, list) or not actions:
        raise typer.BadParameter("plan actions 必须为非空数组")
    if isinstance(payload.get("max_steps"), bool) or not isinstance(payload.get("max_steps"), int) or not 1 <= payload["max_steps"] <= 32:
        raise typer.BadParameter("plan max_steps 必须在 1..32")
    if not isinstance(payload.get("max_duration_sec"), (int, float)) or isinstance(payload.get("max_duration_sec"), bool) or not math.isfinite(payload["max_duration_sec"]) or not 1 <= payload["max_duration_sec"] <= 300:
        raise typer.BadParameter("plan max_duration_sec 必须在 1..300")
    return payload, hashlib.sha256(raw).hexdigest()


def _run_plan(
    plan: dict[str, Any], *, out: Path, plan_sha256: str | None = None,
    root_actions: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    binding = {
        "schema_version": "ui-plan-result/1",
        "serial": plan["serial"],
        "package": plan["package"],
        "root_actions": root_actions,
        "plan_sha256": plan_sha256 or hashlib.sha256(
            json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "plan_hash_source": "file_bytes" if plan_sha256 is not None else "canonical_json",
        "started_at_utc": _utc_now(),
    }
    _claim_output(out)

    def finish(status: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
        return {**binding, "status": status, "actions": rows,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "finished_at_utc": _utc_now()}

    rows: list[dict[str, Any]] = []
    status = "complete"
    # Validate every step before the first device operation, including later steps.
    for index, step in enumerate(plan["actions"], 1):
        try:
            validate_action(step)
        except ValueError:
            return finish("failed", [
                {"index": index, "status": "failed", "reason": "invalid_action"}])
    deadline = started + plan["max_duration_sec"]
    actions = AndroidActions(
        serial=str(plan["serial"]), package=str(plan["package"]), deadline=deadline,
        root_actions=root_actions,
    )
    for index, step in enumerate(plan["actions"], 1):
        remaining = deadline - time.monotonic()
        kind = step["kind"]
        if index > plan["max_steps"] or remaining <= 0 or (kind == "wait" and min(step["seconds"], 30) > remaining):
            rows.append({"index": index, "status": "stopped", "reason": "step_or_duration_budget_exceeded"})
            status = "partial"
            break
        if kind == "launch":
            result = actions.launch_package()
        elif kind == "tap":
            result = actions.tap(step["x"], step["y"])
        elif kind == "input_text":
            result = actions.input_text(step["value"])
        elif kind == "back":
            result = actions.back()
        elif kind == "wait":
            result = actions.wait(step["seconds"])
        elif kind == "wait_for_foreground":
            result = actions.wait_foreground(timeout_sec=step.get("timeout_sec", 5))
        elif kind == "snapshot":
            try:
                receipt = _snapshot_result(
                    str(plan["serial"]), str(plan["package"]), out / f"snapshot-{index}",
                    False, False, deadline=deadline, no_idle=step.get("no_idle", False),
                )
            except OSError:
                rows.append({"index": index, "kind": kind, "status": "failed", "reason": "snapshot_io_failed"})
                status = "partial" if len(rows) > 1 else "failed"
                break
            rows.append({"index": index, "kind": kind, "status": receipt["status"], "receipt": f"snapshot-{index}/observation.json"})
            if receipt["status"] != "complete":
                status = "partial" if len(rows) > 1 or receipt["status"] == "partial" else "failed"
                break
            continue
        else:
            raise ValueError("invalid_action")
        rows.append({"index": index, "kind": kind, "result": result.to_dict()})
        if not result.ok:
            status = "partial" if len(rows) > 1 else "failed"
            break
    if status == "complete" and time.monotonic() > deadline:
        status = "partial"
    return finish(status, rows)


def _command_diagnostics(
    command: CommandResult, *, kind: str, out: Path, root: Path,
) -> list[dict[str, Any]]:
    """Keep bounded tool errors inside controlled evidence, never echo text.

    Layout errors can quote visible UI content. The receipt exposes only hashes
    and paths; input-action output is never passed to this diagnostic writer.
    output_format identifies normalized text versus exact original pipe bytes.
    """
    diagnostics = []
    for stream, raw in (("stdout", command.stdout), ("stderr", command.stderr)):
        if not raw or (stream == "stdout" and command.ok):
            continue
        retained = raw[:65536]
        path = out / ".diagnostics" / f"{kind}.{stream}.bin"
        if not atomic_create_bytes(path, retained):
            raise FileExistsError("ui_diagnostic_exists_refuse_overwrite")
        diagnostics.append({
            "relative_path": path.relative_to(root).as_posix(),
            "scope": "controlled_diagnostic", "stream": stream,
            "output_format": command.output_format,
            "size": len(retained), "sha256": hashlib.sha256(retained).hexdigest(),
            "original_size": len(raw), "original_sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": len(retained) != len(raw),
        })
    return diagnostics


def _snapshot_result(
    serial: str, package: str, out: Path, annotate: bool, full: bool,
    executable: str | None = None, *, deadline: float | None = None,
    context: CaptureRoundContext | None = None,
    no_idle: bool = False,
) -> dict[str, Any]:
    started_at = _utc_now()
    actions = AndroidActions(serial=serial, package=package, deadline=deadline)
    _claim_output(out)
    foreground_before = actions.foreground_package()
    root = context.out_dir if context is not None else out
    artifacts = []
    operations = []
    if foreground_before == package:
        cli = AndroidCli(executable, deadline=deadline)
        # Stage fresh outputs so successful exit codes cannot credit pre-existing files.
        with tempfile.TemporaryDirectory(prefix=".ui-", dir=out) as temporary:
            staging = Path(temporary)
            screen = staging / ("screen.annotated.png" if annotate else "screen.png")
            layout = staging / "layout.json"
            capture = cli.capture(serial=serial, output=screen, annotate=annotate)
            layout_result = cli.layout(serial=serial, output=layout, full=full, no_idle=no_idle)
            for kind, command, path in (("screen_capture", capture, screen), ("layout", layout_result, layout)):
                operation = {
                    "kind": kind, "ok": False, "exit_code": command.exit_code,
                    "process_tree": {
                        "ownership_complete": command.ownership_complete,
                        "termination_complete": command.termination_complete,
                        "forced_tree_kill": command.forced_tree_kill,
                        "reason_codes": list(command.reason_codes),
                    },
                }
                if not command.ok:
                    operation["reason"] = (
                        "command_timed_out" if command.timed_out else
                        "process_tree_unverified" if not (command.ownership_complete and command.termination_complete) else
                        "descendants_after_root_exit" if command.forced_tree_kill else
                        "command_unavailable" if command.exit_code is None else "command_exit_nonzero"
                    )
                try:
                    diagnostics = _command_diagnostics(command, kind=kind, out=out, root=root)
                    if diagnostics:
                        operation["diagnostics"] = diagnostics
                except OSError:
                    operation["diagnostic_status"] = "write_failed"
                try:
                    valid = command.ok and path.is_file() and not path.is_symlink() and path.stat().st_size > 0
                    if valid:
                        destination = out / path.name
                        if not atomic_create_bytes(destination, path.read_bytes()):
                            raise FileExistsError("ui_artifact_exists_refuse_overwrite")
                        artifact = ExternalEvidenceAttachment(
                            producer="android_ui", schema_version="ui-observation/1",
                            relative_path=destination.relative_to(root).as_posix(), kind=kind,
                            size=destination.stat().st_size, sha256=sha256_file(destination),
                            round_id=context.round_id if context else None,
                            sample_sha256=context.sample_sha256 if context else None,
                        )
                        artifacts.append(asdict(artifact))
                        operation["ok"] = True
                except OSError:
                    operation["reason"] = "artifact_io_failed"
                operations.append(operation)
        foreground_after = actions.foreground_package()
    else:
        foreground_after = foreground_before
    target_confirmed = foreground_before == package and foreground_after == package
    success_count = sum(operation["ok"] for operation in operations)
    status = "complete" if success_count == 2 and target_confirmed else "partial" if success_count else "failed"
    if deadline is not None and time.monotonic() > deadline and status == "complete":
        status = "partial"
    receipt = {
        "schema_version": "ui-observation/1",
        "producer": "android_ui",
        "scope": "case_evidence",
        "status": status,
        "started_at_utc": started_at,
        "finished_at_utc": _utc_now(),
        "serial": serial,
        "requested_package": package,
        "foreground_package": foreground_after,
        "foreground_package_before": foreground_before,
        "target_foreground_confirmed": target_confirmed,
        "metrics": "disabled",
        "layout_wait_for_idle": not no_idle,
        "operations": operations,
        "artifacts": artifacts,
        "receipt_path": (out / "observation.json").relative_to(root).as_posix(),
    }
    if foreground_before != package:
        receipt["reason"] = "target_foreground_unconfirmed"
    elif foreground_after != package:
        receipt["reason"] = "target_foreground_changed"
    if context is not None:
        receipt.update(round_id=context.round_id, round_kind=context.round_kind,
                       sample_sha256=context.sample_sha256, capture_mode=context.capture_mode,
                       runtime_variant=context.runtime_variant)
    _write_result(out / "observation.json", receipt)
    return receipt


@ui_app.command("capabilities")
def capabilities(
    serial: str = typer.Option(..., "--serial"),
    executable: str | None = typer.Option(None, "--android"),
) -> None:
    cli = AndroidCli(executable)
    version = cli.version()
    typer.echo(json.dumps({
        "status": "ok" if cli.available and version.ok else "unavailable",
        "serial": serial,
        "android_cli": cli.executable,
        "version": version.stdout.decode("utf-8", "replace").strip(),
        "metrics": "disabled",
        "capabilities": {
            "screen_capture": "available" if cli.available else "missing",
            "layout": "available" if cli.available else "missing",
            "screen_resolve": "available" if cli.available else "missing",
        },
    }, ensure_ascii=False, indent=2))


@ui_app.command("snapshot")
def snapshot(
    serial: str = typer.Option(..., "--serial"),
    package: str = typer.Option(..., "--package"),
    out: Path = typer.Option(..., "--out"),
    executable: str | None = typer.Option(None, "--android"),
    annotate: bool = typer.Option(False, "--annotate"),
    full: bool = typer.Option(False, "--full"),
    no_idle: bool = typer.Option(False, "--no-idle", help="Capture layout without waiting for UI idle."),
) -> None:
    receipt = _snapshot_result(serial, package, out, annotate, full, executable, no_idle=no_idle)
    typer.echo(json.dumps(receipt, ensure_ascii=False, indent=2))
    if receipt["status"] != "complete":
        raise typer.Exit(code=1)


@ui_app.command("run-plan")
def run_plan(
    serial: str = typer.Option(..., "--serial"),
    package: str = typer.Option(..., "--package"),
    plan: Path = typer.Option(..., "--plan", exists=True, readable=True),
    out: Path = typer.Option(..., "--out"),
    root_actions: bool = typer.Option(
        False, "--root-actions", help="Explicitly use root for fixed tap/text/back actions on the selected device.",
    ),
) -> None:
    payload, plan_sha256 = _load_plan(plan, package=package, serial=serial)
    result = _run_plan(payload, out=out, plan_sha256=plan_sha256, root_actions=root_actions)
    _write_result(out / "operations.json", result)
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
    if result["status"] != "complete":
        raise typer.Exit(code=1)


class AndroidUiPlugin:
    name = "android_ui"
    api_version = PLUGIN_API_VERSION

    def register_cli(self, app: Any) -> None:
        app.add_typer(ui_app, name="ui")

    def capabilities(self) -> dict[str, Any]:
        return {"snapshot": True, "layout": True, "screen_resolve": True}

    def run_round(self, context: CaptureRoundContext) -> dict[str, Any]:
        receipt = _snapshot_result(
            context.serial,
            context.package_name,
            context.out_dir / "ui",
            False,
            False,
            deadline=context.deadline_monotonic,
            context=context,
        )
        return receipt


def plugin_factory() -> AndroidUiPlugin:
    return AndroidUiPlugin()
