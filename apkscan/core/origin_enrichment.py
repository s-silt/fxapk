"""Use the existing bounded batch interface for origin-check targets."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
from typing import Any

import click


def enrich_origin_candidates(check: dict[str, Any], directory: Path, providers: str) -> dict[str, Any]:
    from apkscan.commands.enrich import batch

    targets = list(dict.fromkeys(str(value) for value in (
        check["reference"]["host"], check["candidate"]["host"], check["candidate"].get("connect_ip"),
        *(row.get("connected_ip") for row in check["observations"].values()),
    ) if value))
    target_file = directory / "enrichment-targets.txt"
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    result: dict[str, Any] = {"status": "not_requested", "targets": targets, "records": [], "coverage": None}
    if not providers.strip():
        return result
    destination = directory / "enrichment"
    for dry_run in (True, False):
        captured = io.StringIO()
        try:
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                batch(targets_file=str(target_file), out_dir=str(destination), dry_run=dry_run,
                      max_targets=6, resume=False, stage="all", providers=providers,
                      credential_slot=0, case_id=check["case_id"], retain_responses=True)
            summary = json.loads(captured.getvalue())
            if not isinstance(summary, dict):
                raise ValueError("Invalid batch summary")
        except (click.exceptions.Exit, OSError, ValueError) as exc:
            result.update(status="failed", error_type=type(exc).__name__)
            return result
        filename = "enrichment-plan.json" if dry_run else "enrichment-summary.json"
        (directory / filename).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        if dry_run:
            if not summary.get("safe_to_execute") or summary.get("over_max_targets"):
                result.update(status="blocked_by_existing_budget_or_configuration", plan=summary)
                return result
            continue
        coverage_path = Path(summary["coverage"]).resolve()
        if not coverage_path.is_relative_to(destination.resolve()):
            raise ValueError("Coverage receipt escaped output")
        coverage = json.loads(coverage_path.read_bytes())
        if coverage["case_id"] != check["case_id"]:
            raise ValueError("Coverage case mismatch")
        records_path = (destination / coverage["ledger_relpath"]).resolve()
        if not records_path.is_relative_to(destination.resolve()):
            raise ValueError("Enrichment records escaped output")
        raw = records_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != coverage["ledger_sha256"]:
            raise ValueError("Enrichment records hash mismatch")
        complete = (coverage["coverage_complete"]
                    and coverage.get("response_archive_complete") is True
                    and not summary.get("completed_with_gaps"))
        result.update(status="complete" if complete else "partial",
                      coverage=coverage, coverage_relpath=coverage_path.relative_to(directory).as_posix(),
                      records=[json.loads(line) for line in raw.splitlines() if line.strip()])
    return result
