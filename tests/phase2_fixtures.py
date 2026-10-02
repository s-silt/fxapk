"""Synthetic, publicly verifiable Phase1 packages for Phase2 tests.

Every package goes through ``create_case_package`` so Phase2 tests exercise the
same integrity path as real cases; nothing here uses real case values.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from apkscan.core.case_package import create_case_package


def write_verified_package(
    case_dir: Path,
    name: str,
    *,
    leads: list[dict[str, Any]] | None = None,
    endpoints: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    case_id: str | None = None,
    report_name: str = "report.json",
) -> Path:
    """Write ``case_dir/name`` as a signed Phase1 package; return the package dir."""
    package = case_dir / name
    package.mkdir(parents=True)
    report = {
        "package_name": "com.example.synthetic",
        "meta": {
            "sample_sha256": hashlib.sha256(name.encode("utf-8")).hexdigest(),
            "tool_version": "1.15.0",
            "ruleset_digest": "b" * 16,
        },
        "leads": leads or [],
        "endpoints": endpoints or [],
        "findings": findings or [],
        "analyzer_status": [],
        "analysis_status": "complete",
    }
    report_path = package / report_name
    report_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    create_case_package(
        report_path,
        package / "case-package.json",
        case_id=case_id or case_dir.name,
        producer="synthetic-test",
    )
    return package


__all__ = ["write_verified_package"]
