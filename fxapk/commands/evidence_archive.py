"""Storage commands, offline APK analysis and the existing case verification gate."""
from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Literal, NoReturn, TypedDict

import typer

from fxapk.core.atomic import atomic_write_text
from fxapk.core.evidence_archive import ArchiveError, Compression, EvidenceArchive, _name, materialize, pack

app = typer.Typer(help="Lossless evidence archive storage and verified offline reading.")
META_WRITE_OWNER = "commands.evidence_archive"
META_WRITE_CATEGORIES = {"evidence_manifest": "record"}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)


VerificationStage = Literal["archive_open", "member_verification", "archive_close"]
VerificationReason = Literal["access_denied", "not_found", "io_error", "archive_contract_failed", "unknown"]


class VerificationFailure(TypedDict):
    """First failure observed at a command boundary, not an inferred internal cause."""

    stage: VerificationStage
    reason: VerificationReason
    index_observed: bool
    all_members_verified: bool


class VerificationDiagnostic(TypedDict):
    first_failure: VerificationFailure


def _verification_failure(
    error: Exception, stage: VerificationStage, index_observed: bool, members_verified: bool,
) -> VerificationFailure:
    reason: VerificationReason = "unknown"
    if isinstance(error, PermissionError):
        reason = "access_denied"
    elif isinstance(error, FileNotFoundError):
        reason = "not_found"
    elif isinstance(error, OSError):
        reason = "io_error"
    elif isinstance(error, ArchiveError):
        reason = "archive_contract_failed"
    return {"stage": stage, "reason": reason, "index_observed": index_observed,
            "all_members_verified": members_verified}


def _failure(error: Exception, output: Path | None = None, prior: dict | None = None, *, diagnostic: VerificationDiagnostic | None = None) -> NoReturn:
    code = str(error) if isinstance(error, ValueError) and re.fullmatch("[a-z_]{1,80}", str(error)) else "archive_operation_failed"
    value = {**(prior or {}), "state": "failed", "reason_codes": sorted(set([*(prior or {}).get("reason_codes", []), code])),
             "exception_type": type(error).__name__}
    if diagnostic is not None:
        value["diagnostic"] = diagnostic
    if output is not None:
        atomic_write_text(output, json.dumps(value, indent=2))
    typer.echo(json.dumps(value), err=True)
    raise typer.Exit(6) from error


def _progress(event: dict) -> None:
    typer.echo(json.dumps(event), err=True)


@app.command("pack")
def pack_command(
    source: Path = typer.Argument(..., exists=True, file_okay=False),
    out: Path = typer.Option(..., "--out", help="New ZIP64 archive outside the evidence directory"),
    level: int = typer.Option(6, "--level", min=0, max=9),
    compression: Compression = typer.Option(Compression.zstd, "--compression", help="zstd: balanced size/read speed; deflate: older ZIP tools"),
) -> None:
    """Archive original bytes, then verify every member; never delete the source."""
    try:
        receipt = pack(source, out, level=level, compression=compression.value, progress=_progress)
    except Exception as error:
        _failure(error)
    typer.echo(json.dumps(receipt))


@app.command("verify")
def verify_command(archive: Path = typer.Argument(..., exists=True, dir_okay=False)) -> None:
    """Stream and hash every original file without extracting the archive."""
    stage: VerificationStage = "archive_open"
    index_observed = False
    members_verified = False
    first_failure: VerificationFailure | None = None
    try:
        with EvidenceArchive(archive) as source:
            index_observed = True
            stage = "member_verification"
            try:
                receipt = source.verify()
            except Exception as error:
                # Snapshot before __exit__: a later close failure must not relabel it.
                first_failure = _verification_failure(error, stage, index_observed, members_verified)
                raise
            members_verified = True
            stage = "archive_close"
    except Exception as error:
        if first_failure is None:
            first_failure = _verification_failure(error, stage, index_observed, members_verified)
        # The legacy envelope still describes the exception that actually escaped.
        # Do not infer another failure's stage from arbitrary exception chains.
        _failure(error, diagnostic={"first_failure": first_failure})
    typer.echo(json.dumps(receipt))


@app.command("extract")
def extract_command(
    archive: Path = typer.Argument(..., exists=True, dir_okay=False),
    out: Path = typer.Option(..., "--out", help="New directory"),
    member: list[str] | None = typer.Option(None, "--member", help="Repeat for selected members; omitted extracts all"),
) -> None:
    try:
        with EvidenceArchive(archive) as source:
            receipt = source.extract(out, member)
    except Exception as error:
        _failure(error)
    typer.echo(json.dumps(receipt))


@app.command("analyze")
def analyze_command(
    archive: Path = typer.Argument(..., exists=True, dir_okay=False),
    member: str = typer.Option(..., "--member", help="APK member; only this member is materialized"),
    out: Path = typer.Option(..., "--out", help="New analysis directory"),
    timeout: int = typer.Option(600, "--timeout", min=1, max=3600),
) -> None:
    """Read a verified APK into temporary storage and run the offline pipeline."""
    from fxapk.core.fetch_intake import _process
    from fxapk.core.offline_review.common import json_value, read_bytes
    from fxapk.core.report_io import load_report

    if out.exists():
        _failure(ValueError("archive_analysis_output_exists"))
    out.mkdir(parents=True)
    receipt_path = out / "archive-analysis.json"
    receipt: dict = {"state": "running", "reason_codes": []}
    try:
        _name(member)
        with EvidenceArchive(archive) as source:
            row = source.files.get(member)
            if row is None:
                raise ValueError("archive_member_missing")
            identity = {"index_sha256": source.index_sha256, "input_sha256": row["sha256"], "input_size": row["size"]}
        with materialize(f"{archive}::{member}", limit=1024**3) as sample:
            report_dir = out / "report"
            receipt = _process([sys.executable, "-m", "fxapk.cli", "analyze", str(sample),
                                "--offline", "--fmt", "json,html", "--out", str(report_dir.resolve())],
                               out / "analysis-process", time.monotonic() + timeout)
            receipt.update(identity, source_binding_verified=False, storage_integrity="verified")
            reports = list(report_dir.glob("*.json"))
            if len(reports) != 1:
                raise ValueError("archive_analysis_report_missing")
            report = load_report(reports[0])
            if report.meta.get("sample_sha256") != identity["input_sha256"] or report.meta.get("online") is not False:
                raise ValueError("archive_analysis_identity_mismatch")
            # Read actual terminal report health; a successful process is insufficient.
            raw = json_value(read_bytes(reports[0], 128 * 1024**2))
            health = raw.get("analysis_status")
            if health != "complete":
                receipt["state"] = "partial" if health == "partial" and receipt["state"] == "ok" else "failed"
                receipt["reason_codes"] = sorted(set([*receipt["reason_codes"], "archive_analysis_incomplete"]))
            receipt["report"] = reports[0].relative_to(out).as_posix()
            from fxapk.core.evidence_archive import storage_projection
            from fxapk.report import html, json as report_json
            from fxapk.report.digest import build_digest

            manifest = report.meta.get("evidence_manifest")
            manifest = dict(manifest) if isinstance(manifest, dict) else {}
            manifest["archive_storage"] = storage_projection({**identity, "state": "verified"})
            report.meta["evidence_manifest"] = manifest
            report_json.dump(report, str(reports[0]))
            html.render(report, str(reports[0].with_suffix(".html")))
            # The analysis subprocess wrote <stem>.sha256 for its own bytes;
            # the rewritten report/HTML invalidate it, so recompute in place.
            products = [reports[0]]
            html_report = reports[0].with_suffix(".html")
            if html_report.is_file():
                products.append(html_report)
            lines = []
            for product in products:
                digest = hashlib.sha256()
                with product.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                lines.append(f"{digest.hexdigest()}  {product.name}")
            atomic_write_text(report_dir / f"{reports[0].stem}.sha256", "\n".join(lines) + "\n")
            atomic_write_text(out / "digest.json", json.dumps(build_digest(report_json.to_dict(report)), ensure_ascii=False, indent=2))
        atomic_write_text(receipt_path, json.dumps(receipt, indent=2))
    except Exception as error:
        _failure(error, receipt_path, receipt)
    typer.echo(json.dumps(receipt))
    if receipt["state"] != "ok":
        raise typer.Exit(5 if receipt["state"] == "partial" else 6)


@app.command("case-verify")
def case_verify_command(
    archive: Path = typer.Argument(..., exists=True, dir_okay=False),
    member: str = typer.Option(..., "--member", help="Unmodified Phase1 case manifest member"),
) -> None:
    """Run the existing full case gate, including REA guards, in bounded staging."""
    from fxapk.core.case_package import verify_case_package

    try:
        _name(member)
        with EvidenceArchive(archive) as source, tempfile.TemporaryDirectory(prefix="fxapk-evidence-case-") as folder:
            target = Path(folder) / "evidence"
            source.extract(target)
            receipt = verify_case_package(target / member)
            receipt["storage_integrity"] = "verified"
    except Exception as error:
        _failure(error)
    typer.echo(json.dumps(receipt, ensure_ascii=False))
    if receipt["status"] != "verified":
        raise typer.Exit(6)


@app.command("corpus-add")
def corpus_add_command(
    archive: Path = typer.Argument(..., exists=True, dir_okay=False),
    manifest_member: str = typer.Option("case-package.json", "--manifest-member", help="Frozen Phase1 manifest member"),
    corpus: Path = typer.Option(..., "--corpus", help="Explicit corpus root outside a Git worktree"),
) -> None:
    """Verify the whole case, then ingest its original report with case/package binding."""
    from fxapk.commands.corpus import corpus_add, resolve_corpus
    from fxapk.core.case_package import verify_case_package
    from fxapk.core.offline_review.common import json_value, read_bytes

    # Validate the destination before potentially expanding a large package.
    root = resolve_corpus(str(corpus))
    try:
        _name(manifest_member)
        with EvidenceArchive(archive) as source, tempfile.TemporaryDirectory(prefix="fxapk-evidence-corpus-") as folder:
            target = Path(folder) / "evidence"
            source.extract(target)
            manifest = target / manifest_member
            gate = verify_case_package(manifest)
            if gate["status"] != "verified":
                typer.echo(json.dumps({"state": "failed", "stage": "case_verification",
                                       "storage_integrity": "verified", "case_verification": gate}), err=True)
                raise typer.Exit(6)
            payload = json_value(read_bytes(manifest))
            reports = [row for row in payload["artifacts"] if row["kind"] == "report"]
            report_path = manifest.parent / _name(reports[0]["path"])
            # Reuse the existing conflict, exact-byte, identity and corpus guards.
            corpus_add([report_path], case="", package=manifest, corpus=str(root))
    except typer.Exit:
        raise
    except Exception as error:
        _failure(error)
    typer.echo(json.dumps({"state": "ok", "storage_integrity": "verified", "coverage": "all_members",
                           "case_verification": "verified", "package_id": gate["package_id"]}))
