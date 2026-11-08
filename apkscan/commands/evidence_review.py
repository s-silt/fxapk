"""Public entry points for bounded offline review and fxfetch ingestion."""
from __future__ import annotations

import json
import re
from pathlib import Path

import typer

from apkscan.core.evidence_archive import Compression


def failure_code(error: Exception, fallback: str) -> str:
    return str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else fallback


def _progress(event):
    typer.echo(json.dumps(event, ensure_ascii=False), err=True)


def evidence_review(
    manifest: Path = typer.Argument(..., help="Offline review manifest with explicit hashes and tasks"),
    out: Path | None = typer.Option(None, "--out", help="New output directory; never overwrites a revision"),
    report: Path | None = typer.Option(None, "--report", help="Existing report to copy and supplement"),
    archive_member: str | None = typer.Option(None, "--archive-member", help="Manifest inside an evidence archive"),
    archive_out: Path | None = typer.Option(None, "--archive-out", help="Verified ZIP64 output instead of an uncompressed directory"),
    archive_compression: Compression = typer.Option(Compression.zstd, "--archive-compression", help="Compression for --archive-out; level 6"),
) -> None:
    from apkscan.core.offline_review.runner import run
    from apkscan.core.evidence_output import EvidenceOutput

    destination = None
    try:
        with EvidenceOutput(out, archive_out, _progress, compression=archive_compression.value) as destination:
            source = Path(f"{manifest}::{archive_member}") if archive_member else manifest
            receipt = run(source, destination.path, report, _progress, retain_inputs=archive_out is not None)
    except Exception as error:
        # Parser exception text can contain input bytes. Print only metadata.
        typer.echo(json.dumps({"state": "failed", "reason_code": failure_code(error, "evidence_review_failed"),
                               "exception_type": type(error).__name__}), err=True)
        storage_failed = destination is not None and destination.storage and destination.storage.get("phase") == "storage"
        raise typer.Exit(6 if storage_failed else 2) from error
    typer.echo(json.dumps({"state": receipt["state"], "receipt": destination.reference("review.json"),
                           "storage": destination.storage,
                           "tasks": [{"id": row["id"], "state": row["state"], "reason_codes": row["reason_codes"]}
                                     for row in receipt["tasks"]]}, ensure_ascii=False))
    if receipt["state"] != "ok":
        raise typer.Exit(5 if receipt["state"] == "partial" else 6)
    if destination.storage and destination.storage["state"] != "verified":
        raise typer.Exit(5)


def intake_fetch(
    archive: Path = typer.Argument(..., help="Saved fxfetch task-evidence ZIP; never visits the source URL"),
    out: Path | None = typer.Option(None, "--out", help="New intake directory"),
    fxfetch: str = typer.Option("fxfetch", "--fxfetch", help="Trusted local fxfetch CLI executable"),
    fxapk: str | None = typer.Option(None, "--fxapk", help="Trusted local fxapk CLI executable"),
    timeout: int = typer.Option(600, "--timeout", min=1, max=3600),
    review_manifest: Path | None = typer.Option(None, "--review-manifest", help="Run targeted reviews against the matching analyzed APK"),
    archive_out: Path | None = typer.Option(None, "--archive-out", help="Verified ZIP64 output instead of an uncompressed directory"),
    archive_member: str | None = typer.Option(None, "--archive-member", help="fxfetch ZIP member inside an evidence archive"),
    archive_compression: Compression = typer.Option(Compression.zstd, "--archive-compression", help="Compression for --archive-out; level 6"),
) -> None:
    from apkscan.core.fetch_intake import run
    from apkscan.core.evidence_archive import materialize
    from apkscan.core.evidence_output import EvidenceOutput

    destination = None
    try:
        with EvidenceOutput(out, archive_out, _progress, compression=archive_compression.value) as destination:
            source = f"{archive}::{archive_member}" if archive_member else archive
            with materialize(source, limit=2 * 1024**3) as local_archive:
                receipt = run(local_archive, destination.path, fxfetch=fxfetch, fxapk=fxapk, timeout=timeout,
                              review_manifest=review_manifest, progress=_progress,
                              retain_review_inputs=archive_out is not None)
    except Exception as error:
        typer.echo(json.dumps({"state": "failed", "reason_code": failure_code(error, "fetch_intake_failed"),
                               "exception_type": type(error).__name__}), err=True)
        storage_failed = destination is not None and destination.storage and destination.storage.get("phase") == "storage"
        raise typer.Exit(6 if storage_failed else 2) from error
    typer.echo(json.dumps({"state": receipt["state"], "receipt": destination.reference("intake.json"),
                           "index": destination.reference("index.html"), "storage": destination.storage}, ensure_ascii=False))
    if receipt["state"] != "ok":
        raise typer.Exit(5 if receipt["state"] == "partial" else 6)
    if destination.storage and destination.storage["state"] != "verified":
        raise typer.Exit(5)


def recover_runtime(
    plan: Path = typer.Argument(..., help="Explicit serial/PID/ranges, original APK hash and target methods"),
    out: Path | None = typer.Option(None, "--out", help="New capture, reanalysis and review revision"),
    archive_out: Path | None = typer.Option(None, "--archive-out", help="Verified ZIP64 output; retain staging on storage failure"),
    archive_compression: Compression = typer.Option(Compression.zstd, "--archive-compression", help="Compression for --archive-out; level 6"),
) -> None:
    from apkscan.dynamic.recovery import run
    from apkscan.core.evidence_output import EvidenceOutput

    destination = None
    try:
        with EvidenceOutput(out, archive_out, _progress, compression=archive_compression.value) as destination:
            receipt = run(plan, destination.path, _progress, retain_review_inputs=archive_out is not None)
    except Exception as error:
        typer.echo(json.dumps({"state": "failed", "reason_code": failure_code(error, "runtime_recovery_failed"),
                               "exception_type": type(error).__name__}), err=True)
        storage_failed = destination is not None and destination.storage and destination.storage.get("phase") == "storage"
        raise typer.Exit(6 if storage_failed else 2) from error
    typer.echo(json.dumps({"state": receipt["state"], "receipt": destination.reference("recovery.json"),
                           "storage": destination.storage}, ensure_ascii=False))
    if receipt["state"] != "ok":
        raise typer.Exit(5 if receipt["state"] == "partial" else 6)
    if destination.storage and destination.storage["state"] != "verified":
        raise typer.Exit(5)
