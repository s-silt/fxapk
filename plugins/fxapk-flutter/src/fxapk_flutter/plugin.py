"""Optional CLI and static analysis hook. Registration performs no tool probing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import uuid

import typer

from apkscan.plugins.contracts import PLUGIN_API_VERSION

from .evidence import FlutterError, validate_bundle
from .index import query
from .projection import attach, project
from .runtime import analyze, capabilities

app = typer.Typer(help="Offline Flutter AOT analysis with a prepared local Blutter toolchain.")


def output(value: dict) -> None:
    typer.echo(json.dumps(value, ensure_ascii=False))


def fail(exc: Exception) -> None:
    output({"status": "failed", "reason": str(exc) if isinstance(exc, FlutterError) else "io_failed"})
    raise typer.Exit(1)


@app.command("capabilities")
def capabilities_command(apk: Path | None = typer.Option(None, "--apk"), toolchain: Path | None = typer.Option(None, "--toolchain")):
    result = capabilities(apk, toolchain)
    output(result)
    if result["status"] == "unavailable":
        raise typer.Exit(1)


@app.command("analyze")
def analyze_command(apk: Path, out: Path = typer.Option(..., "--out"), toolchain: Path | None = typer.Option(None, "--toolchain"),
                    timeout: int = typer.Option(300, "--timeout", min=1, max=1800), no_cache: bool = typer.Option(False, "--no-cache")):
    try:
        result = analyze(apk, out, toolchain, timeout=timeout, use_cache=not no_cache)
        output({"status": result["status"], "cache_hit": result["cache_hit"],
                "functions": result["coverage"]["functions"], "runtime_observed": False})
    except (FlutterError, OSError) as exc:
        fail(exc)


@app.command("query")
def query_command(bundle: Path, symbol: str | None = typer.Option(None, "--symbol"), text: str | None = typer.Option(None, "--text"),
                  limit: int = typer.Option(30, "--limit", min=1, max=200)):
    try:
        validate_bundle(bundle)
        typer.echo("Query output contains original local evidence values; it is not redacted.", err=True)
        output(query(bundle, symbol, text, limit))
    except (FlutterError, OSError) as exc:
        fail(exc)


@app.command("attach")
def attach_command(bundle: Path, report: Path = typer.Option(..., "--report"), out: Path = typer.Option(..., "--out")):
    try:
        output(attach(bundle, report, out))
    except (FlutterError, OSError) as exc:
        fail(exc)


class FlutterPlugin:
    name = "flutter"
    api_version = PLUGIN_API_VERSION

    def register_cli(self, parent: Any) -> None:
        parent.add_typer(app, name="flutter")

    def capabilities(self) -> dict[str, Any]:
        return {"analyze": "prepared_docker_toolchain", "query": "offline", "attach": "offline"}

    def run_static(self, request: dict[str, Any]) -> dict[str, Any]:
        relative = "flutter/" + uuid.uuid4().hex
        root = Path(request["out_dir"]) / relative
        try:
            path = Path(request["toolchain"]) if request.get("toolchain") else None
            analyze(Path(request["apk"]), root, path, timeout=request.get("timeout", 300),
                    expected_apk_sha256=request["expected_apk_sha256"])
            return project(root, relative)
        except (FlutterError, OSError) as exc:
            return {"metadata": {"schema_version": "fxapk-flutter/1", "status": "failed",
                                 "reason": str(exc) if isinstance(exc, FlutterError) else "io_failed",
                                 "bundle": relative, "runtime_observed": False}, "endpoints": []}


def plugin_factory() -> FlutterPlugin:
    return FlutterPlugin()
