"""Nested `fxapk rea native` commands. Registration happens once from plugin.py."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .native import NativeError, attach, capabilities, extract_native, inspect, recover

native_app = typer.Typer(
    add_completion=False,
    rich_markup_mode=None,
    help="Read-only native REA inspect and declarative address recovery.",
)


def _fail(exc: Exception) -> None:
    reason = str(exc) if isinstance(exc, NativeError) else "evidence_io_failed"
    typer.echo(json.dumps({"status": "failed", "reason": reason}))
    raise typer.Exit(1)


@native_app.command("capabilities")
def capabilities_command(
    provider: str | None = typer.Option(None, "--provider"),
    executable: str | None = typer.Option(None, "--rea"),
    node: str | None = typer.Option(None, "--node"),
    binary: Path | None = typer.Option(None, "--binary"),
    toolchain: Path | None = typer.Option(None, "--toolchain"),
) -> None:
    """Report host limits and local provider readiness. Not a live-target proof."""
    try:
        info = capabilities(
            provider=provider, executable=executable, node=node, binary=binary, toolchain=toolchain
        )
    except (NativeError, OSError) as exc:
        _fail(exc)
        return
    typer.echo(json.dumps(info))
    if info["status"] != "ok":
        raise typer.Exit(1)


@native_app.command("inspect")
def inspect_command(
    binary: Path = typer.Argument(...),
    out: Path = typer.Option(..., "--out"),
    provider: str = typer.Option(..., "--provider"),
    operation: str = typer.Option("overview", "--operation"),
    query: str | None = typer.Option(None, "--query"),
    length: int | None = typer.Option(None, "--length"),
    executable: str | None = typer.Option(None, "--rea"),
    node: str | None = typer.Option(None, "--node"),
    toolchain: Path | None = typer.Option(None, "--toolchain"),
) -> None:
    """Capture one read-only REA dossier. Stdout is a summary, not recovered endpoints."""
    try:
        manifest = inspect(
            binary,
            out,
            provider=provider,
            operation=operation,
            query=query,
            length=length,
            executable=executable,
            node=node,
            toolchain=toolchain,
        )
    except (NativeError, OSError) as exc:
        _fail(exc)
        return
    typer.echo(
        json.dumps(
            {
                "status": "captured",
                "schema_version": manifest["schema_version"],
                "binary_sha256": manifest["binary_sha256"],
                "operation": manifest["operation"],
                "provider": manifest["provider"],
                "endpoints_derived": False,
            }
        )
    )


@native_app.command("recover")
def recover_command(
    bundle: Path = typer.Argument(...),
    recipe: Path = typer.Option(..., "--recipe"),
    out: Path = typer.Option(..., "--out"),
) -> None:
    """Apply a finite recipe. The summary does not echo the candidate value."""
    try:
        summary = recover(bundle, recipe, out)
    except (NativeError, OSError) as exc:
        _fail(exc)
        return
    typer.echo(json.dumps(summary))


@native_app.command("attach")
def attach_command(
    bundle: Path = typer.Argument(...),
    report: Path = typer.Option(..., "--report"),
    out: Path = typer.Option(..., "--out"),
) -> None:
    """Append a candidate onto a new report directory. No closure or enrichment."""
    try:
        summary = attach(bundle, report, out)
    except (NativeError, OSError) as exc:
        _fail(exc)
        return
    typer.echo(json.dumps(summary))


@native_app.command("extract")
def extract_command(
    apk: Path = typer.Argument(...),
    member: str = typer.Option(..., "--member"),
    out: Path = typer.Option(..., "--out"),
    report: Path | None = typer.Option(None, "--report"),
) -> None:
    """Copy one lib/<abi>/<name>.so to a new directory. No engine and no bulk unzip."""
    try:
        summary = extract_native(apk, member, out, report)
    except (NativeError, OSError) as exc:
        _fail(exc)
        return
    typer.echo(
        json.dumps(
            {
                "status": "ok",
                "apk_sha256": summary["apk_sha256"],
                "member": summary["member"],
                "member_sha256": summary["member_sha256"],
                "abi": summary["abi"],
                "engine_required": False,
            }
        )
    )


def register_native(app: typer.Typer) -> None:
    app.add_typer(native_app, name="native")
