"""Conservative paired-round diagnostics, not a proof of probe non-interference."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path
import re
from typing import Any

_CONDITIONS = ("action_plan_sha256", "initial_state_sha256", "environment_sha256")
_OUTCOMES = ("onboarding", "network")


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _evidence_matches(root: Path, refs: object) -> bool:
    if not isinstance(refs, list) or not 1 <= len(refs) <= 8:
        return False
    for ref in refs:
        if not isinstance(ref, Mapping) or not isinstance(ref.get("path"), str) or not _digest(ref.get("sha256")):
            return False
        relative = Path(ref["path"])
        path = root / relative
        try:
            if relative.is_absolute() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                return False
            if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
                return False
            with path.open("rb") as stream:
                raw = stream.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
                return False
        except (OSError, ValueError):
            return False
    return True


def round_safety(record: Mapping[str, Any], result: Mapping[str, Any], package: str) -> dict[str, Any]:
    signals = result.get("capture_signals")
    signals = signals if isinstance(signals, Mapping) else {}
    summary: dict[str, Any] = {
        "schema_version": "capture-safety/1",
        "capture_status": record.get("status", "unknown"),
        "target_foreground_confirmed": None,
        "onboarding": "not_checked", "network": "not_checked",
        "tls_policy": signals.get("tls_policy", "unknown"),
        "proxy_set": signals.get("proxy_set"),
        "capture_done_means_business_success": False,
        "zero_traffic_means_network_failure": False,
        "causal_attribution": "not_established",
        "conditions": {}, "assessment_evidence": [],
    }
    observations = result.get("ui_observations")
    for observation in observations if isinstance(observations, list) else []:
        if not isinstance(observation, Mapping) or observation.get("requested_package") != package:
            continue
        foreground = observation.get("target_foreground_confirmed")
        summary["target_foreground_confirmed"] = foreground if type(foreground) is bool else None
        summary.update(onboarding="not_checked", network="not_checked", conditions={}, assessment_evidence=[])
        summary.pop("assessment_source", None)
        summary.pop("assessment_gap", None)
        check = observation.get("safety_check")
        if not isinstance(check, Mapping) or check.get("schema_version") != "capture-safety-check/1":
            continue
        refs = check.get("evidence_refs")
        if not _evidence_matches(Path(str(record["output_dir"])), refs):
            summary["assessment_gap"] = "assessment_evidence_missing_or_changed"
            continue
        summary["assessment_source"] = "producer_assertion_with_hash_bound_artifacts"
        summary["assessment_evidence"] = refs
        summary["conditions"] = {key: check[key] for key in _CONDITIONS if _digest(check.get(key))}
        for key in _OUTCOMES:
            value = check.get(key)
            summary[key] = value if value in ("passed", "failed") else "not_checked"
    return summary


def compare_rounds(records: list[dict[str, Any]]) -> dict[str, Any]:
    baseline = next((row for row in records if row.get("kind") == "pcap"), None)
    comparisons = []
    for row in records:
        if row.get("kind") == "pcap":
            continue
        gaps: list[str] = []
        base = baseline or {}
        left, right = base.get("capture_safety", {}), row.get("capture_safety", {})
        left = left if isinstance(left, Mapping) else {}
        right = right if isinstance(right, Mapping) else {}
        if not base or base.get("status") != "done" or row.get("status") != "done":
            gaps.append("complete_baseline_and_instrumented_capture_required")
        sha = base.get("original_sample_sha256")
        if (not _digest(sha) or sha != row.get("original_sample_sha256")
                or any(item.get("artifact_verified") is not True or item.get("package_matches") is not True
                       or item.get("identity_which") != "original" for item in (base, row))):
            gaps.append("same_original_sample_not_verified")
        for name, health in (("baseline", left), ("instrumented", right)):
            if health.get("target_foreground_confirmed") is not True:
                gaps.append(name + "_foreground_not_confirmed")
            if any(health.get(key) not in ("passed", "failed") for key in _OUTCOMES):
                gaps.append(name + "_business_outcome_not_checked")
        lc, rc = left.get("conditions", {}), right.get("conditions", {})
        if (not isinstance(lc, Mapping) or not isinstance(rc, Mapping)
                or any(not _digest(lc.get(key)) or lc.get(key) != rc.get(key) for key in _CONDITIONS)):
            gaps.append("actions_initial_state_or_environment_not_matched")
        for item, health in ((base, left), (row, right)):
            if not _evidence_matches(Path(str(item.get("output_dir", ""))), health.get("assessment_evidence")):
                gaps.append("assessment_evidence_missing_or_changed")
        regressions = [key for key in _OUTCOMES if left.get(key) == "passed" and right.get(key) == "failed"]
        status = ("inconclusive" if gaps else "reported_regression" if regressions
                  else "baseline_failed" if any(left.get(key) == "failed" for key in _OUTCOMES)
                  else "no_reported_regression")
        comparisons.append({
            "round": row.get("round"), "baseline_round": base.get("round"), "status": status,
            "regressions": regressions if not gaps else [], "gaps": sorted(set(gaps)),
            "condition_verification": "producer_declared_not_independently_verified",
            "causal_attribution": "not_established",
        })
    return {"schema_version": "capture-safety-comparison/1", "comparisons": comparisons,
            "non_interference_proven": False,
            "next_action": "Compare the same original APK, actions, initial state and environment; inspect the recorded business outcomes, not capture completion or traffic counts."}
