"""Full input denominator for bounded enrichment, including unqueried cells."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from apkscan.core.batch_enrich import Target, _is_configured, _provider_name
from apkscan.core.enrichment_profiles import CONTRACTS
from apkscan.core.source_status import normalize_source_status_map


def _object(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def payload_has_gaps(value: object) -> bool:
    if isinstance(value, dict):
        if "coverage_complete" in value and value["coverage_complete"] is not True:
            return True
        if any((key.endswith("_status") and isinstance(item, str) and item.startswith("failed"))
               or ((key.endswith("_truncated") or key == "truncated") and bool(item))
               for key, item in value.items()):
            return True
        return any(payload_has_gaps(item) for item in value.values())
    return isinstance(value, list) and any(payload_has_gaps(item) for item in value)


def build_coverage(
    targets: Sequence[Target], enrichers: Sequence[Any], records: Sequence[Mapping[str, Any]],
    env: Mapping[str, str], *, case_id: str = "",
) -> dict[str, Any]:
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        for provider, status in normalize_source_status_map(record.get("source_status")).items():
            contracts = _object(record.get("source_contracts"))
            if provider in CONTRACTS and contracts.get(provider) != CONTRACTS[provider]:
                status = {"status": "skipped", "reason": "source_contract_changed"}
            latest[str(record.get("target", "")), provider] = {
                **status, "started_at": record.get("started_at"), "finished_at": record.get("finished_at"),
                "receipt": _object(record.get("receipts")).get(provider, {}),
                "raw_response_evidence": _object(_object(record.get("enrichment")).get("raw_response_evidence")).get(provider, {}),
                "query_coverage": "partial" if payload_has_gaps(_object(record.get("enrichment")).get(provider)) else "unspecified",
            }
    rows = []
    counts: Counter[str] = Counter()
    gaps = 0
    for target in targets:
        statuses = {}
        for enricher in enrichers:
            provider = _provider_name(enricher)
            if target.kind not in (getattr(enricher, "applies_to", []) or []):
                status = {"status": "skipped", "reason": "not_applicable"}
            elif (target.value, provider) in latest:
                status = latest[target.value, provider]
            elif not _is_configured(enricher, env):
                status = {"status": "disabled", "reason": "credential_or_product_not_configured"}
            else:
                status = {"status": "skipped", "reason": "not_executed_in_bounded_run"}
            statuses[provider] = status
            counts[str(status["status"])] += 1
            if (status["status"] not in {"hit", "no_record"} and status.get("reason") != "not_applicable") or status.get("query_coverage") == "partial":
                gaps += 1
        rows.append({"target": target.value, "kind": target.kind, "source_status": statuses})
    return {"schema": "enrichment-coverage-1", "case_id": case_id,
            "observed_at": datetime.now(timezone.utc).isoformat(), "targets": rows,
            "providers": sorted(_provider_name(e) for e in enrichers),
            "target_count": len(rows), "source_outcomes": dict(counts),
            "unresolved_cells": gaps, "coverage_complete": gaps == 0,
            "note": "Coverage describes this explicit input and selected providers; it does not establish attribution."}
