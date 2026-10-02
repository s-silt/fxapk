"""Join verified packages and review coverage into pre-report materials only.

No network, report rendering, report mutation or automatic evidence acceptance.
The optional run history follows the sanitized handoff's declaration contract;
its provenance is explicitly unverified until original run artifacts are checked.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from apkscan.core.closure.layers import assemble_target_closure
from apkscan.core.closure.gates import _capture_meta, evaluate_capture_quality
from apkscan.core.models import Report
from apkscan.core.closure.targets import _select_targets_with_stats
from apkscan.core.integrity import sha256_hex
from apkscan.core.corpus import manifest_entry
from apkscan.core.linkage_review import build_review_groups
from apkscan.core.provider_review import project_provider_review, build_source_worklist
from apkscan.core.report_io import report_from_dict
from apkscan.core.phase2.run_review import (
    PreparationError as PreparationError,
    build_run_review as build_run_review,
)
from apkscan.core.phase2.evidence_map import PackageEvidenceIndex
from apkscan.core.phase2.inventory import (
    InventoryLimits, _read_json_bounded, _registered_report_path, audit_coverage,
    build_inventory,
)

SCHEMA_VERSION = "pre-report-materials/1.0"
def _stage_observations(payload: Mapping[str, Any], report: Report) -> dict[str, Any]:
    meta = payload.get("meta")
    meta = meta if isinstance(meta, Mapping) else {}
    analyzer_status = payload.get("analyzer_status")
    analyzer_status = analyzer_status if isinstance(analyzer_status, list) else []
    names = {row.get("name") for row in analyzer_status if isinstance(row, Mapping)
             and isinstance(row.get("name"), str)}
    quality_input = _capture_meta(report)
    dynamic: dict[str, Any] = {"material_present": bool(quality_input), "status": "not_supplied"}
    if quality_input:
        quality = evaluate_capture_quality(quality_input)
        dynamic.update(status=quality["dynamic_status"],
                       target_attributed_count=quality["target_attributed_count"],
                       bidirectional_target_count=quality["bidirectional_target_count"],
                       modified_runtime=quality["runtime_variant"] == "modified-runtime",
                       apk_identity_unconfirmed=quality["capture_apk_identity_which"] == "unknown",
                       artifact_provenance_verified=False)
    analysis_status = payload.get("analysis_status")
    return {
        "static": {"analysis_status": analysis_status if isinstance(analysis_status, str) and analysis_status
                   in {"complete", "partial", "failed"} else "unknown"},
        "dynamic": dynamic,
        "web": {"material_present": "web_evidence" in names or meta.get("platform") == "web"
                or isinstance(meta.get("web_har_summary"), Mapping)},
        "build": {"material_present": isinstance(meta.get("build_provenance"), Mapping)},
        "family": {"status": "see_case_level_family_review"},
        "note": "Material presence is not evidence completeness or provider verification.",
    }


def prepare_case_materials(case_dir: Path, *, coverage: object = None,
                           clue_records: object = None,
                           runs: Sequence[Mapping[str, Any]] = (),
                           evidence_values: str = "omit", max_targets: int = 200) -> dict[str, Any]:
    """Prepare immutable-input-bound material without issuing a report or PASS."""
    if evidence_values not in {"omit", "raw"}:
        raise PreparationError("invalid_evidence_mode")
    if isinstance(max_targets, bool) or not isinstance(max_targets, int) or not 1 <= max_targets <= 200:
        raise PreparationError("invalid_target_budget")
    if (coverage is None) != (clue_records is None):
        raise PreparationError("coverage_and_clues_must_be_paired")
    inventory = build_inventory(case_dir)
    output: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "state": "blocked" if inventory.issues else "review_required",
        "formal_report_generated": False, "provider_identity_verified": False,
        "evidence_values": evidence_values, "inventory_fingerprint": inventory.fingerprint,
        "package_count": len(inventory.packages), "candidate_count": len(inventory.candidates),
        "inventory_issue_codes": sorted({issue.code for issue in inventory.issues}),
        "packages": [], "network_requests": 0,
    }
    if inventory.issues:
        return output
    if not inventory.packages:
        output["state"] = "blocked"
        output["inventory_issue_codes"] = ["no_verified_packages"]
        return output
    limits = InventoryLimits()
    remaining_targets = max_targets
    linkage_entries: list[dict[str, Any]] = []
    candidates_by_package = defaultdict(list)
    for candidate in inventory.candidates:
        candidates_by_package[candidate.package_id].append(candidate)
    for number, package in enumerate(inventory.packages, 1):
        package_dir = case_dir / package.directory_name
        manifest, manifest_raw = _read_json_bounded(package_dir / "case-package.json", limits.max_manifest_bytes, 64)
        if not isinstance(manifest, Mapping) or sha256_hex(manifest_raw) != package.manifest_sha256:
            raise PreparationError("manifest_changed_during_preparation")
        report_path = _registered_report_path(package_dir, manifest)
        if report_path is None:
            raise PreparationError("registered_report_missing")
        payload, report_raw = _read_json_bounded(report_path, limits.max_report_bytes, 64)
        if not isinstance(payload, Mapping) or sha256_hex(report_raw) != package.report_sha256:
            raise PreparationError("report_changed_during_preparation")
        entry = manifest_entry(dict(payload), case_id=inventory.case_id)
        entry.update(case_ids=[inventory.case_id], package_ids=[package.package_id],
                     report_bytes_sha256=package.report_sha256, record_state="active")
        linkage_entries.append(entry)
        report = report_from_dict(payload)
        targets, selection = _select_targets_with_stats(report, max(1, remaining_targets))
        if remaining_targets == 0:
            targets = []
        else:
            remaining_targets -= len(targets)
        evidence_index = PackageEvidenceIndex(payload, candidates_by_package[package.package_id])
        plan = project_provider_review([assemble_target_closure(ep) for ep in targets], evidence_values=evidence_values)
        for target, row in zip(targets, plan["targets"], strict=True):
            row["phase1_evidence"] = evidence_index.resolve(target, evidence_values=evidence_values)
        plan["evidence_linkage"] = evidence_index.summary()
        total = selection.get("candidate_total", 0)
        if not isinstance(total, int) or isinstance(total, bool):
            raise PreparationError("invalid_target_selection_count")
        plan["truncated"] = total > len(targets)
        plan["input_target_count"] = total
        output["packages"].append({
            "package_ref": f"package-{number:04d}", "package_id": package.package_id,
            "manifest_sha256": package.manifest_sha256, "report_sha256": package.report_sha256,
            "stage_observations": _stage_observations(payload, report), "provider_review": plan,
        })
    global_targets = [
        {**target, "target_ref": package["package_ref"] + "/" + target["target_ref"]}
        for package in output["packages"] for target in package["provider_review"]["targets"]
    ]
    output["source_worklist"] = build_source_worklist({"targets": global_targets})
    # Reuse the public rule engine, including its weak-anchor exclusions and
    # ownership caps. Large cases need a separately budgeted linkage run;
    # never silently sample them and call the smaller graph complete.
    if 2 <= len(linkage_entries) <= 100:
        output["family_review"] = build_review_groups(linkage_entries, evidence_values=evidence_values)
    else:
        output["family_review"] = {
            "status": "insufficient_samples" if len(linkage_entries) < 2 else "deferred_resource_budget",
            "record_count": len(linkage_entries), "automatic_record_limit": 100,
            "next_action": "use_explicitly_budgeted_corpus_linkage_review",
        }
    if coverage is None or clue_records is None:
        output["coverage"] = {"status": "not_supplied", "next_action": "supply_coverage_and_clue_records"}
    else:
        audit = audit_coverage(inventory, coverage, clue_records)
        output["coverage"] = {
            "status": "structurally_consistent" if audit.ok else "blocked",
            "candidate_count": audit.candidate_count, "covered_count": audit.covered_count,
            "accepted_clue_count": audit.accepted_clue_count, "disposition_counts": audit.disposition_counts,
            "blocker_codes": sorted({issue.code for issue in audit.blockers}),
        }
        if not audit.ok:
            output["state"] = "blocked"
    output["run_review"] = build_run_review(runs, case_id=inventory.case_id, evidence_values=evidence_values)
    output["next_actions"] = ["review_role_specific_provider_evidence", "resolve_coverage_and_run_provenance_gaps",
                              "keep_unresolved_roles_explicit", "stop_before_formal_report"]
    return output
