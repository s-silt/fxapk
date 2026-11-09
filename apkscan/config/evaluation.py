"""Offline synthetic evaluation across independent addressing dimensions.

This exercises production projectors; synthetic examples cannot authorize any
ranking/advice change or estimate real-case precision/recall.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from apkscan.attribution.assemble import _ip_entity, _ip_signal_features
from apkscan.attribution.roles import RoleSignal
from apkscan.config.runtime_chain import review_runtime
from apkscan.core.closure.layers import assemble_target_closure
from apkscan.core.report_io import report_from_dict

_NEGATIVE_CATEGORIES = ("cdn_contact", "expired_resolution", "modified_runtime", "random_iv", "sdk_config_domain", "shared_ip")


def evaluate_synthetic_suite(cases: list[dict]) -> dict[str, Any]:
    rows = []
    for case in cases:
        bindings = review_runtime(case["artifacts"], case["events"], sample_sha256=case["sample_sha256"],
                                  body_records=case["body_records"], rounds=case["rounds"])
        endpoint = report_from_dict({"package_name": "test.example.app", "endpoints": [case["endpoint"]]}).endpoints[0]
        ip = _ip_entity(endpoint.value)
        if ip is None:
            raise ValueError("evaluation_requires_ip_endpoint")
        entries = endpoint.enrichment.get("attribution", {}).get("ips", [])
        signals = {feature.signal for entry in entries for feature in _ip_signal_features(ip, entry, endpoint=endpoint)}
        closure_origin = assemble_target_closure(endpoint)["origin"]
        actual = {
            "original_consumption_verified": any(c["consumption"] == "verified" and c["runtime_variant"] == "original-runtime"
                                                 for b in bindings for c in b["correlations"]),
            "business_certificate_usable": RoleSignal.BUSINESS_CERTIFICATE in signals,
            "origin_confirmed": isinstance(closure_origin, dict) and closure_origin.get("status") == "complete",
        }
        rows.append({"case_id": case["case_id"], "actual": actual, "expected": case["expected"],
                     "matches_expected": actual == case["expected"],
                     "input_sha256": hashlib.sha256(json.dumps(case, sort_keys=True).encode()).hexdigest()})
    return {"suite_kind": "synthetic", "cases": sorted(rows, key=lambda r: r["case_id"]),
            "synthetic_case_count": len(rows), "real_case_count": 0,
            "mismatch_count": sum(not r["matches_expected"] for r in rows),
            "ranking_or_advice_change_eligible": False,
            "gaps": ["independent_real_case_evaluation_missing"]}


def _read_evaluation_ref(ref: dict, *, binary: bool = False) -> tuple[dict, str]:
    """Rehash every selected source; never trust a receipt's claimed file hash."""
    from apkscan.dynamic.config_artifacts import _linked

    path = Path(ref["path"])
    if not path.is_absolute() or any(_linked(p) for p in (path, *path.parents)):
        raise ValueError("invalid_evaluation_path")
    limit = 1024 * 1024 * 1024 if binary else 64 * 1024 * 1024
    digest, total, chunks = hashlib.sha256(), 0, []
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > limit:
                raise ValueError("evaluation_file_budget_exceeded")
            digest.update(chunk)
            if not binary:
                chunks.append(chunk)
    if digest.hexdigest() != ref["sha256"]:
        raise ValueError("evaluation_file_hash_mismatch")
    data = {} if binary else json.loads(b"".join(chunks))
    if not isinstance(data, dict):
        raise ValueError("invalid_evaluation_object")
    return data, digest.hexdigest()


def evaluate_real_suite(cases: list[dict]) -> dict[str, Any]:
    """Reproject selected local evidence and compare separately supplied labels.

    Labels are externally reviewed ground truth, not conclusions generated here.
    Missing labels stay unknown and never enter the accuracy denominator. Hash
    checks establish integrity, not the truth of a reviewer-supplied label.
    """
    from apkscan.dynamic.addressing import project_addressing
    from apkscan.dynamic.event_origin import RuntimePayload
    from apkscan.dynamic.merge import _endpoint_from_jsonable, runtime_scope_verified
    from apkscan.dynamic.capture_provenance import capture_scope, retain_observations, project_observations

    if not 1 <= len(cases) <= 100 or len({c["case_id"] for c in cases}) != len(cases):
        raise ValueError("invalid_evaluation_cases")
    rows = []
    for case in cases:
        _, sample = _read_evaluation_ref(case["apk"], binary=True)
        raw_report, report_sha = _read_evaluation_ref(case["report"])
        report = report_from_dict(raw_report)
        if report.meta.get("sample_sha256") != sample:
            raise ValueError("evaluation_report_sample_mismatch")
        # Recompute runtime consumption; stale derived flags are never labels.
        for endpoint in report.endpoints:
            endpoint.enrichment.pop("config_runtime_bindings", None)
        report.meta.pop("control_chains", None)
        for key in ("runtime_observations", "runtime_observation_overflow", "runtime_observations_truncated"):
            report.meta.pop(key, None)
        gaps, captures, input_hashes = set(), [], {sample, report_sha}
        runtime_refs = case.get("runtime_reports", [])
        if len(runtime_refs) > 20:
            raise ValueError("evaluation_capture_budget_exceeded")
        for ref in sorted(runtime_refs, key=lambda r: r["sha256"]):
            runtime, sha = _read_evaluation_ref(ref)
            input_hashes.add(sha)
            if runtime.get("package_name") != report.package_name:
                raise ValueError("evaluation_runtime_package_mismatch")
            capture = {"sha256": sha, "runtime_variant": runtime.get("runtime_variant"),
                       "body_record_count": len(runtime.get("config_body_artifacts") or []),
                       "addressing_event_count": len(runtime.get("addressing_events") or []),
                       "capture_complete": runtime.get("capture_complete", "unknown")}
            captures.append(capture)
            context = runtime.get("capture_context") or {}
            if context.get("sample_sha256") != sample:
                gaps.add("runtime_sample_binding_missing")
                continue
            raw = Path(ref["path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != sha:
                raise ValueError("evaluation_file_hash_mismatch")
            payload = RuntimePayload(runtime, raw, ref["path"])
            namespace = "capture:" + sha
            identity = report.meta.get("capture_apk_identity")
            original = identity.get("original") if isinstance(identity, dict) else None
            verified = (isinstance(original, dict) and original.get("sha256") == sample
                        and runtime_scope_verified(report, payload, namespace))
            if not verified:
                gaps.add("runtime_capture_binding_unverified")
            with capture_scope(namespace, verified=verified):
                raw_endpoints = payload.get("endpoints")
                endpoints = [e for row in raw_endpoints if (e := _endpoint_from_jsonable(row)) is not None] if isinstance(raw_endpoints, list) else []
                retain_observations(report, endpoints)
                project_observations(report)
            project_addressing(report, payload)
        correlations = [c for chain in report.meta.get("control_chains", []) for backend in chain.get("backends", [])
                        for c in backend.get("runtime_correlations", [])]
        certificate_usable, origin_confirmed = False, False
        for endpoint in report.endpoints:
            ip = _ip_entity(endpoint.value)
            if ip is not None:
                entries = endpoint.enrichment.get("attribution", {}).get("ips", []) or [{}]
                certificate_usable |= any(f.signal == RoleSignal.BUSINESS_CERTIFICATE for entry in entries
                                          for f in _ip_signal_features(ip, entry, endpoint=endpoint))
            origin = assemble_target_closure(endpoint)["origin"]
            origin_confirmed |= isinstance(origin, dict) and origin.get("status") == "complete"
        actual = {"original_consumption_verified": any(c.get("consumption") == "verified" and c.get("runtime_variant") == "original-runtime" for c in correlations),
                  "business_certificate_usable": certificate_usable, "origin_confirmed": origin_confirmed}
        expected, label_sha = None, None
        categories: list[str] = []
        if case.get("independent_label"):
            label, label_sha = _read_evaluation_ref(case["independent_label"])
            expected = label.get("expected")
            categories = label.get("negative_categories", [])
            if (label.get("schema") != "fxapk-addressing-label-1" or label.get("basis") != "independent_review"
                    or not isinstance(label.get("reviewer"), str) or not label["reviewer"]
                    or label.get("case_id") != case["case_id"] or label.get("sample_sha256") != sample
                    or not isinstance(expected, dict) or set(expected) != set(actual) or any(type(v) is not bool for v in expected.values())
                    or not isinstance(categories, list) or any(not isinstance(c, str) or c not in _NEGATIVE_CATEGORIES for c in categories)
                    or len(categories) != len(set(categories))
                    or not isinstance(label.get("evidence_sha256"), list) or not label["evidence_sha256"]
                    or any(not isinstance(sha, str) for sha in label["evidence_sha256"])
                    or not set(label["evidence_sha256"]) <= input_hashes):
                raise ValueError("invalid_independent_label")
        else:
            gaps.add("independent_real_case_labels_missing")
        rows.append({"case_id": case["case_id"], "sample_sha256": sample, "report_sha256": report_sha,
                     "runtime_captures": sorted(captures, key=lambda r: r["sha256"]), "actual": actual, "expected": expected,
                     "label_status": "independently_supplied" if expected is not None else "unknown", "label_sha256": label_sha,
                     "negative_categories": sorted(categories),
                     "matches_expected": actual == expected if expected is not None else None, "gaps": sorted(gaps)})
    labeled = [r for r in rows if r["expected"] is not None]
    gaps = {g for r in rows for g in r["gaps"]}
    if not any(r["expected"]["original_consumption_verified"] and r["expected"]["business_certificate_usable"] for r in labeled):
        gaps.add("independent_positive_case_missing")
    if not any(not r["expected"]["original_consumption_verified"] or not r["expected"]["business_certificate_usable"] for r in labeled):
        gaps.add("independent_negative_case_missing")
    coverage = [{"category": category, "labeled_case_count": sum(category in r["negative_categories"] for r in labeled)}
                for category in _NEGATIVE_CATEGORIES]
    gaps.update("independent_negative_category_missing:" + row["category"] for row in coverage if not row["labeled_case_count"])
    return {"suite_kind": "real_evidence_review", "real_case_count": len(rows), "synthetic_case_count": 0,
            "cases": sorted(rows, key=lambda r: r["case_id"]), "independently_labeled_case_count": len(labeled),
            "accuracy": sum(r["matches_expected"] for r in labeled) / len(labeled) if labeled else None,
            "negative_category_coverage": coverage, "ranking_or_advice_change_eligible": False, "gaps": sorted(gaps)}
