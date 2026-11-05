"""Public entry points for bounded offline review and fxfetch ingestion."""
from __future__ import annotations

import json
import re
from pathlib import Path

import typer


def failure_code(error: Exception, fallback: str) -> str:
    return str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else fallback


def evidence_review(
    manifest: Path = typer.Argument(..., help="Offline review manifest with explicit hashes and tasks"),
    out: Path = typer.Option(..., "--out", help="New output directory; never overwrites a revision"),
    report: Path | None = typer.Option(None, "--report", help="Existing report to copy and supplement"),
) -> None:
    from apkscan.core.offline_review.runner import run

    try:
        receipt = run(manifest, out, report, lambda event: typer.echo(json.dumps(event), err=True))
    except Exception as error:
        # Parser exception text can contain input bytes. Print only metadata.
        typer.echo(json.dumps({"state": "failed", "reason_code": failure_code(error, "evidence_review_failed"),
                               "exception_type": type(error).__name__}), err=True)
        raise typer.Exit(2) from error
    typer.echo(json.dumps({"state": receipt["state"], "receipt": str(out / "review.json"),
                           "tasks": [{"id": row["id"], "state": row["state"], "reason_codes": row["reason_codes"]}
                                     for row in receipt["tasks"]]}, ensure_ascii=False))
    if receipt["state"] != "ok":
        raise typer.Exit(5 if receipt["state"] == "partial" else 6)


def intake_fetch(
    archive: Path = typer.Argument(..., help="Saved fxfetch task-evidence ZIP; never visits the source URL"),
    out: Path = typer.Option(..., "--out", help="New intake directory"),
    fxfetch: str = typer.Option("fxfetch", "--fxfetch", help="Trusted local fxfetch CLI executable"),
    fxapk: str | None = typer.Option(None, "--fxapk", help="Trusted local fxapk CLI executable"),
    timeout: int = typer.Option(600, "--timeout", min=1, max=3600),
    review_manifest: Path | None = typer.Option(None, "--review-manifest", help="Run targeted reviews against the matching analyzed APK"),
) -> None:
    from apkscan.core.fetch_intake import run

    try:
        receipt = run(archive, out, fxfetch=fxfetch, fxapk=fxapk, timeout=timeout,
                      review_manifest=review_manifest,
                      progress=lambda event: typer.echo(json.dumps(event, ensure_ascii=False), err=True))
    except Exception as error:
        typer.echo(json.dumps({"state": "failed", "reason_code": failure_code(error, "fetch_intake_failed"),
                               "exception_type": type(error).__name__}), err=True)
        raise typer.Exit(2) from error
    typer.echo(json.dumps({"state": receipt["state"], "receipt": str(out / "intake.json"),
                           "index": str(out / "index.html")}, ensure_ascii=False))
    if receipt["state"] != "ok":
        raise typer.Exit(5 if receipt["state"] == "partial" else 6)


def recover_runtime(
    plan: Path = typer.Argument(..., help="Explicit serial/PID/ranges, original APK hash and target methods"),
    out: Path = typer.Option(..., "--out", help="New capture, reanalysis and review revision"),
) -> None:
    from apkscan.dynamic.recovery import run

    try:
        receipt = run(plan, out, lambda event: typer.echo(json.dumps(event), err=True))
    except Exception as error:
        typer.echo(json.dumps({"state": "failed", "reason_code": failure_code(error, "runtime_recovery_failed"),
                               "exception_type": type(error).__name__}), err=True)
        raise typer.Exit(2) from error
    typer.echo(json.dumps({"state": receipt["state"], "receipt": str(out / "recovery.json")}, ensure_ascii=False))
    if receipt["state"] != "ok":
        raise typer.Exit(5 if receipt["state"] == "partial" else 6)
