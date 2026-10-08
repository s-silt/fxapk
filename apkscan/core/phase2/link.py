# -*- coding: utf-8 -*-
"""Phase2 gate receipt: the single artefact that binds a Phase2 verdict to Phase1 packages.

The receipt records exactly which immutable packages (``package_id`` +
``manifest_sha256``), which inventory, and which coverage/decision bytes the
gate judged.  ``case review`` may only bind an accepted review to a PASS
receipt that names the reviewed package; any later change to the package,
coverage, decisions or a supplied survey yields a different receipt and the old review cannot be
re-bound to it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from apkscan.core.atomic import atomic_write_text
from apkscan.core.integrity import sha256_hex
from apkscan.core.json_io import read_json_bounded
from apkscan.core.phase2.survey import SurveyLimits
from apkscan.core.phase2.chain import chain_link, file_sha256, is_sha256

GATE_RECEIPT_SCHEMA_VERSION = "phase2-gate-receipt/1.0"


class GateReceiptError(ValueError):
    """The receipt is missing, malformed, not PASS, or does not cover the package."""


def _file_sha256(path: Path) -> str:
    """文件当前字节。缺文件抛 ``OSError``，不用空哈希冒充上一环。"""
    return file_sha256(path)


def build_gate_receipt(
    inventory: Any,
    report: Any,
    *,
    coverage_path: Path,
    decisions_path: Path,
    decisions_ledger: str,
    survey_sha256: str | None = None,
    survey_assessment: str | None = None,
) -> dict[str, object]:
    packages = sorted(
        (
            {
                "package_id": str(p.package_id),
                "manifest_sha256": str(p.manifest_sha256),
                "directory_name": str(p.directory_name),
            }
            for p in inventory.packages
        ),
        key=lambda item: (item["package_id"], item["directory_name"]),
    )
    body = {
        "schema_version": GATE_RECEIPT_SCHEMA_VERSION,
        "case_id": str(inventory.case_id),
        "result": "PASS" if report.ok else "BLOCKED",
        "inventory_fingerprint": str(inventory.fingerprint),
        "packages": packages,
        "coverage_sha256": _file_sha256(coverage_path),
        "decisions_sha256": file_sha256(decisions_path),
        "decisions_ledger": decisions_ledger,
        "blocker_count": len(report.blockers),
        "warning_count": len(report.warnings),
    }
    if survey_sha256 is not None or survey_assessment is not None:
        if (not is_sha256(survey_sha256) or not isinstance(survey_assessment, str)
                or survey_assessment not in {"complete", "partial", "unassessed"}):
            raise GateReceiptError("survey receipt binding is malformed")
        body["survey_sha256"] = survey_sha256
        body["survey_assessment"] = survey_assessment
    # 回执的上一环只钉 coverage。判决账本必须已是文件：自动结案由 gate 先补一份
    # 显式空账本，再把那份文件的字节哈希写进来。缺文件抛 OSError，不记空哈希。
    return chain_link("gate-receipt", body, previous_sha256=str(body["coverage_sha256"]))


def write_gate_receipt(path: Path, receipt: Mapping[str, object]) -> None:
    # Reuse the common exclusive, private-at-creation, fsynced temporary
    # writer. A fixed ".tmp" name lets concurrent writers corrupt one another.
    atomic_write_text(
        path, json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def receipt_sibling(receipt_path: Path, name: str) -> Path:
    """回执旁边的 Phase2 产物。review 绑定时必须还能对上这些当前字节。"""
    return receipt_path.parent / name


def load_receipt_for_package(
    receipt_path: Path,
    *,
    package_id: str,
    manifest_sha256: str,
    case_id: object,
    coverage_path: Path | None = None,
    decisions_path: Path | None = None,
) -> dict[str, str]:
    """Return the binding block for a review, or raise if the receipt does not cover it.

    When ``coverage_path`` / ``decisions_path`` are given, their current bytes must
    still match what the gate judged; an edited coverage or decision ledger after a
    PASS makes the receipt stale. A receipt with survey metadata also requires
    its unchanged, bounded ``survey.json`` sibling, even without explicit paths.
    """
    try:
        raw = receipt_path.read_bytes()
        receipt = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise GateReceiptError("phase2 gate receipt is unreadable") from exc
    if not isinstance(receipt, dict) or receipt.get("schema_version") != GATE_RECEIPT_SCHEMA_VERSION:
        raise GateReceiptError("phase2 gate receipt has an unsupported schema")
    if receipt.get("result") != "PASS":
        raise GateReceiptError("phase2 gate did not pass")
    if receipt.get("case_id") != case_id:
        raise GateReceiptError("phase2 gate receipt belongs to a different case")
    fingerprint = receipt.get("inventory_fingerprint")
    if not is_sha256(fingerprint):
        raise GateReceiptError("phase2 gate receipt has no inventory fingerprint")
    packages = receipt.get("packages")
    covered = isinstance(packages, list) and any(
        isinstance(item, Mapping)
        and item.get("package_id") == package_id
        and item.get("manifest_sha256") == manifest_sha256
        for item in packages
    )
    if not covered:
        raise GateReceiptError("phase2 gate receipt does not cover this exact package")
    if coverage_path is not None and receipt.get("coverage_sha256") != _file_sha256(coverage_path):
        raise GateReceiptError("coverage changed after the phase2 gate; rerun gate")
    if decisions_path is not None and receipt.get("decisions_sha256") != _file_sha256(decisions_path):
        raise GateReceiptError("decisions changed after the phase2 gate; rerun gate")
    if "survey_sha256" in receipt or "survey_assessment" in receipt:
        digest = receipt.get("survey_sha256")
        assessment = receipt.get("survey_assessment")
        if (not is_sha256(digest) or not isinstance(assessment, str)
                or assessment not in {"complete", "partial", "unassessed"}):
            raise GateReceiptError("survey receipt binding is malformed")
        bounds = SurveyLimits()
        try:
            _, survey_raw = read_json_bounded(
                receipt_sibling(receipt_path, "survey.json"), bounds.max_bytes, bounds.max_json_depth,
            )
        except (OSError, UnicodeError, ValueError, OverflowError, RecursionError) as exc:
            raise GateReceiptError("survey snapshot is unreadable; rerun gate") from exc
        if sha256_hex(survey_raw) != digest:
            raise GateReceiptError("survey changed after the phase2 gate; rerun gate")
    return {
        "receipt_sha256": sha256_hex(raw),
        "inventory_fingerprint": str(fingerprint),
    }


def is_valid_review_binding(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and is_sha256(value.get("receipt_sha256"))
        and is_sha256(value.get("inventory_fingerprint"))
    )


__all__ = [
    "GATE_RECEIPT_SCHEMA_VERSION",
    "GateReceiptError",
    "build_gate_receipt",
    "is_valid_review_binding",
    "load_receipt_for_package",
    "receipt_sibling",
    "write_gate_receipt",
]
