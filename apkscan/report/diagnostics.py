"""Bounded diagnostics for digest; never promote reported checks to verified facts."""
from __future__ import annotations

from itertools import islice
from typing import Any

from apkscan.core.redact import scrub_pii


def compact_capture_safety(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    rows = value.get("comparisons")
    if not isinstance(rows, list):
        return {}
    projected = []
    statuses = {"inconclusive", "reported_regression", "baseline_failed", "no_reported_regression"}
    for row in rows[:12]:
        if not isinstance(row, dict):
            continue
        status = row.get("status")
        regressions = row.get("regressions")
        gaps = row.get("gaps")
        projected.append({
            "round": row.get("round") if type(row.get("round")) is int else None,
            "baseline_round": row.get("baseline_round") if type(row.get("baseline_round")) is int else None,
            "status": status if isinstance(status, str) and status in statuses else "inconclusive",
            "regressions": [key for key in ("onboarding", "network") if isinstance(regressions, list) and key in regressions],
            "gap_count": len(gaps) if isinstance(gaps, list) else None,
            "condition_verification": "producer_declared_not_independently_verified",
            "causal_attribution": "not_established",
        })
    return {
        "comparisons": projected,
        "omitted_comparisons": len(rows) - len(projected),
        "non_interference_proven": False,
        "capture_done_means_business_success": False,
    }


def _text(value: object, redact: bool) -> str | None:
    if not isinstance(value, str):
        return None
    return (scrub_pii(value)[0] if redact else value)[:256]


def _texts(value: object, redact: bool) -> list[str | None]:
    return [_text(item, redact) for item in value[:8] if isinstance(item, str)] if isinstance(value, list) else []


def _target(row: dict[str, Any], redact: bool) -> dict[str, Any]:
    layers = row.get("layers")
    layer = layers.get("request_target") if isinstance(layers, dict) else None
    evidence = layer.get("evidence") if isinstance(layer, dict) else None
    evidence = evidence if isinstance(evidence, dict) else {}
    sources = row.get("source_context")
    sources = sources if isinstance(sources, dict) else {}
    contexts = []
    for provider, context in islice(sources.items(), 8):
        if not isinstance(context, dict):
            continue
        query = context.get("query_time")
        contexts.append({
            "provider": _text(provider, redact),
            "source_family": _text(context.get("source_family"), redact),
            "query_time_status": query.get("status") if isinstance(query, dict) and query.get("status") in ("recorded", "unavailable") else "unavailable",
            "incident_time_correlation": "not_established",
            "same_family_counts_as_independent": False,
        })
    return {
        "value": _text(row.get("value"), redact),
        "status": _text(row.get("status"), redact),
        "provider_candidate": _text(evidence.get("provider"), redact),
        "provider_role": _text(evidence.get("provider_role"), redact) or "unknown",
        "required_identifiers": _texts(evidence.get("required_identifiers"), redact),
        "evidence_to_obtain": _texts(evidence.get("evidence_fields"), redact),
        "verification_questions": _texts(evidence.get("verification_questions"), redact),
        "legal_request_channel_status": "not_verified",
        "incident_time_correlation": "not_established",
        "service_operator": "unknown",
        "sources": contexts,
        "omitted_sources": len(sources) - len(contexts),
        "establishes_business_ownership": False,
    }


def compact_request_targets(closure: dict[str, Any], *, redact: bool) -> dict[str, Any]:
    targets = closure.get("targets")
    if not isinstance(targets, list) or not targets:
        return {}
    rows = []
    for target in targets[:6]:
        if not isinstance(target, dict):
            continue
        row = _target(target, redact)
        resolved = target.get("resolved_ip_targets")
        if isinstance(resolved, list):
            children = [_target(child, redact) for child in resolved[:4] if isinstance(child, dict)]
            row["resolved_ip_candidates"] = children
            row["omitted_resolved_ips"] = len(resolved) - len(children)
        rows.append(row)
    return {"request_targets": rows, "omitted_request_targets": len(targets) - len(rows)}
