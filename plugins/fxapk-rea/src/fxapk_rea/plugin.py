"""Optional CLI entry points. No automatic round or closure hooks."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
from pathlib import Path
from typing import Any

import typer

from apkscan.core.atomic import atomic_create_bytes
from apkscan.plugins.contracts import PLUGIN_API_VERSION

from .evidence import (
    EvidenceError,
    claim_output,
    import_observation,
    parse_json,
    project,
    publish,
    read_bounded,
)
from .runtime import ReaRuntime, validate_scope

rea_app = typer.Typer(
    add_completion=False,
    rich_markup_mode=None,
    help="Optional REA browser observation and offline evidence import.",
)
_WEBSOCKETS_FLOOR = (13, 1)
_WEBSOCKETS_CEILING = (14, 0)
_ATTACH_REGISTERED = False
_NATIVE_REGISTERED = False


def ensure_attach_command() -> None:
    """Register offline attach once. Missing REA does not block this command."""
    global _ATTACH_REGISTERED
    if _ATTACH_REGISTERED:
        return
    from .attachment import register_attach

    register_attach(rea_app)
    _ATTACH_REGISTERED = True


def ensure_native_command() -> None:
    """Register native recovery once. Missing REA does not block --help."""
    global _NATIVE_REGISTERED
    if _NATIVE_REGISTERED:
        return
    from .native_cli import register_native

    register_native(rea_app)
    _NATIVE_REGISTERED = True


def _websockets_supported(version: str) -> bool:
    parts = version.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return False
    return _WEBSOCKETS_FLOOR <= (major, minor) < _WEBSOCKETS_CEILING


def trace_local_capabilities() -> dict[str, Any]:
    """Local import check only. Does not open a browser or the network."""
    info: dict[str, Any] = {
        "status": "unavailable",
        "provider": "trace",
        "reason": "trace_dependency_missing",
        "browser": "not_probed",
        "websockets_version": None,
        "supported_websockets": ">=13.1,<14",
        "capabilities": {"trace": "unavailable"},
    }
    if importlib.util.find_spec("websockets") is None:
        return info
    try:
        version = importlib.metadata.version("websockets")
    except importlib.metadata.PackageNotFoundError:
        return info
    info["websockets_version"] = version
    if not _websockets_supported(version):
        info["reason"] = "unsupported_websockets_version"
        return info
    info["status"] = "ok"
    info["reason"] = ""
    info["capabilities"]["trace"] = "available"
    return info


def attach_local_capabilities() -> dict[str, Any]:
    """Offline attach has no REA or browser prerequisite."""
    return {
        "status": "ok",
        "provider": "attach",
        "reason": "",
        "browser": "not_probed",
        "capabilities": {"attach": "offline_available"},
    }


def _error(exc: Exception) -> None:
    reason = str(exc) if isinstance(exc, EvidenceError) else "evidence_io_failed"
    typer.echo(json.dumps({"status": "failed", "reason": reason}))
    raise typer.Exit(1)


def _summary(receipt: dict[str, Any]) -> None:
    typer.echo(
        json.dumps(
            {
                "status": receipt["status"],
                "schema_version": receipt["schema_version"],
                "source_sha256": receipt["source"]["sha256"],
                "requests": len(receipt["requests"]),
                "scripts": len(receipt["scripts"]),
                "coverage": receipt["coverage"]["status"],
                "gaps": receipt["coverage"]["gaps"],
                "closure_evaluated": False,
            },
            ensure_ascii=False,
        )
    )


@rea_app.command("capabilities")
def capabilities(
    executable: str | None = typer.Option(
        None, "--rea", help="REA executable or JavaScript launcher; no npx downloads."
    ),
    node: str | None = typer.Option(None, "--node"),
    provider: str | None = typer.Option(
        None,
        "--provider",
        help="trace or attach: local prerequisites only. Omit to probe the REA runtime.",
    ),
) -> None:
    """Report local prerequisites. status=ok is not a live browser measurement."""
    if provider is None:
        info = ReaRuntime(executable, node).capabilities()
    elif provider == "trace":
        info = trace_local_capabilities()
    elif provider == "attach":
        info = attach_local_capabilities()
    else:
        typer.echo(json.dumps({"status": "failed", "reason": "invalid_provider"}))
        raise typer.Exit(1)
    typer.echo(json.dumps(info))
    if info["status"] != "ok":
        raise typer.Exit(1)


@rea_app.command("import")
def import_command(
    source: Path = typer.Argument(...),
    out: Path = typer.Option(..., "--out"),
    expected_sha256: str | None = typer.Option(None, "--expected-sha256"),
) -> None:
    """Offline import; status=ok means valid import, never complete case evidence."""
    try:
        receipt = import_observation(source, out, expected_sha256)
    except (EvidenceError, OSError) as exc:
        _error(exc)
        return
    typer.echo(
        "REA files may contain sensitive original values; terminal output is a summary only.",
        err=True,
    )
    _summary(receipt)


@rea_app.command("inspect")
def inspect_command(
    endpoint: str = typer.Option(..., "--endpoint"),
    target: str = typer.Option(..., "--target"),
    origin: str = typer.Option(..., "--origin"),
    out: Path = typer.Option(..., "--out"),
    executable: str | None = typer.Option(None, "--rea"),
    node: str | None = typer.Option(None, "--node"),
    observation_ms: int = typer.Option(10000, "--observation-ms", min=0, max=60000),
    console_text: bool = typer.Option(False, "--console-text"),
) -> None:
    """Observe an explicitly selected page; no navigation, clicks or browser launch."""
    claimed = False
    try:
        endpoint = validate_scope(endpoint, target, origin)
        claim_output(out)
        claimed = True
        runtime = ReaRuntime(executable, node)
        capability = runtime.capabilities()
        if capability["status"] != "ok":
            raise EvidenceError(capability["reason"])
        execution = runtime.inspect(
            endpoint,
            target,
            origin,
            out / "execution",
            observation_ms=observation_ms,
            console_text=console_text,
        )
        if not atomic_create_bytes(
            out / "execution.json", (json.dumps(execution, indent=2) + "\n").encode()
        ):
            raise EvidenceError("execution_receipt_exists")
        if not execution["ok"]:
            raise EvidenceError("rea_execution_failed")
        raw_ref = (
            "execution/after-navigation/stdout.bin"
            if execution.get("navigation_retry")
            else "execution/stdout.bin"
        )
        raw = read_bounded(out / raw_ref)
        receipt, files = project(raw)
        parameters = parse_json(raw)["data"]["parameters"]
        if (
            receipt["target"]["target_id"] != target
            or receipt["allowed_origins"] != [origin]
            or parameters.get("cdp_endpoint") != endpoint
            or parameters.get("observation_ms") != observation_ms
        ):
            raise EvidenceError("requested_observation_binding_mismatch")
        receipt["tool_version"] = capability["rea_version"]
        receipt["acquisition"] = {
            "kind": "local_cdp_observation",
            "execution_ref": "execution.json",
            "console_text_requested": console_text,
            "stdout_ref": raw_ref,
            "navigation_retry": bool(execution.get("navigation_retry")),
            "window_scope": (
                "new_observation_window_after_navigation"
                if execution.get("navigation_retry")
                else "requested_observation_window"
            ),
        }
        publish(out, receipt, files)
    except (EvidenceError, OSError) as exc:
        if claimed:
            reason = str(exc) if isinstance(exc, EvidenceError) else "evidence_io_failed"
            try:
                atomic_create_bytes(
                    out / "failure.json",
                    json.dumps({"status": "failed", "reason": reason}).encode(),
                )
            except OSError:
                pass  # Original failure is still reported, never replaced by success.
        _error(exc)
        return
    typer.echo(
        "REA files may contain sensitive original values; terminal output is a summary only.",
        err=True,
    )
    _summary(receipt)


@rea_app.command("trace")
def trace_command(
    endpoint: str = typer.Option(..., "--endpoint"),
    target: str = typer.Option(..., "--target"),
    origin: str = typer.Option(..., "--origin"),
    out: Path = typer.Option(..., "--out"),
    observation_ms: int = typer.Option(10000, "--observation-ms", min=0, max=60000),
    related_targets: bool = typer.Option(False, "--related-targets"),
    navigate: str | None = typer.Option(None, "--navigate"),
    click_selector: str | None = typer.Option(None, "--click-selector"),
    related_origin: list[str] | None = typer.Option(None, "--related-origin"),
    pause_related_start: bool = typer.Option(False, "--pause-related-start"),
) -> None:
    """Attach one page session. Navigation and clicks run only when those options are set."""
    claimed: list[bool] = []
    try:
        from .trace import run_trace

        run_trace(
            endpoint,
            target,
            origin,
            observation_ms,
            out,
            claimed,
            related_targets=related_targets,
            navigate=navigate,
            click_selector=click_selector,
            related_origin=related_origin,
            pause_related_start=pause_related_start,
        )
    except (EvidenceError, OSError) as exc:
        if claimed:
            reason = str(exc) if isinstance(exc, EvidenceError) else "evidence_io_failed"
            try:
                atomic_create_bytes(
                    out / "failure.json",
                    json.dumps({"status": "failed", "reason": reason}).encode(),
                )
            except OSError:
                pass
        _error(exc)
        return
    typer.echo(
        "CDP trace files may contain sensitive original values; terminal output is a summary only.",
        err=True,
    )
    typer.echo(
        json.dumps(
            {
                "status": "ok",
                "schema_version": "fxapk-cdp-trace-observation/1",
                "coverage": "partial",
                "closure_evaluated": False,
            }
        )
    )


class ReaPlugin:
    name = "rea"
    api_version = PLUGIN_API_VERSION

    def register_cli(self, app: Any) -> None:
        ensure_attach_command()
        ensure_native_command()
        app.add_typer(rea_app, name="rea")

    def run_supplement(self, request: dict[str, Any]) -> dict[str, Any]:
        from .supplement import run_supplement

        return run_supplement(request)

    def capabilities(self) -> dict[str, Any]:
        return {
            "import": True,
            "inspect": "requires_external_runtime",
            "attach": "offline",
            "native": "optional_local_rea_not_a_live_provider",
            "trace": "optional_cdp_provider",
            "trace_scope": {
                "related_targets": "explicit_page_session_oopif_and_dedicated_worker",
                "related_origin": "explicit_repeatable_exact_origin_max_8",
                "pause_related_start": "explicit_opt_in_related_debugger_pause",
                "navigate": "explicit_same_origin",
                "click_selector": "explicit_top_document",
            },
        }


def plugin_factory() -> ReaPlugin:
    return ReaPlugin()


ensure_attach_command()
ensure_native_command()
