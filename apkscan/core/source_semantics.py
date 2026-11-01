"""Read-only source and time context; never infer ownership or historical validity."""
from __future__ import annotations

from collections.abc import Mapping
from itertools import islice
import math
from typing import Any

from apkscan.core.source_catalog import source_lineage_summary
from apkscan.core.source_status import normalize_source_status_map

_TIME_FIELDS = frozenset({
    "observed_at", "timestamp", "time", "time_stamp", "scan_time",
    "update_time", "last_updated_at", "lastupdatetime", "first_seen", "last_seen",
    "first_resolved", "last_resolved", "date", "starttime", "endtime",
})
_MAX_VISITED = 256
_MAX_TIMES = 32


def _time_fields(payload: object) -> dict[str, Any]:
    pending: list[tuple[str, object, int]] = [("", payload, 0)]
    fields: list[dict[str, object]] = []
    visited = 0
    limited = False
    while pending and visited < _MAX_VISITED and len(fields) < _MAX_TIMES:
        pointer, value, depth = pending.pop()
        visited += 1
        if isinstance(value, Mapping):
            keys = list(islice(value, _MAX_VISITED))
            limited |= len(value) > len(keys)
            for key in reversed(keys):
                if not isinstance(key, str):
                    continue
                item = value[key]
                path = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
                if key in _TIME_FIELDS and isinstance(item, (str, int, float)) and not isinstance(item, bool):
                    if isinstance(item, float) and not math.isfinite(item):
                        limited = True
                        continue
                    if len(fields) < _MAX_TIMES:
                        field: dict[str, object] = {"json_pointer": path, "value": item}
                        if isinstance(item, str) and len(item) > 256:
                            field.update(value=item[:256], value_truncated=True)
                        fields.append(field)
                    else:
                        limited = True
                elif isinstance(item, (Mapping, list)):
                    if depth < 4 and len(pending) < _MAX_VISITED:
                        pending.append((path, item, depth + 1))
                    else:
                        limited = True
        elif isinstance(value, list):
            available = max(0, _MAX_VISITED - len(pending))
            limited |= len(value) > available
            pending.extend((f"{pointer}/{i}", item, depth + 1)
                           for i, item in reversed(list(enumerate(value[:available]))))
    return {
        "fields": sorted(fields, key=lambda item: str(item["json_pointer"])),
        "projection_truncated": bool(pending) or limited,
        "semantics": "provider_field_values_uninterpreted",
        "historical_validity": "not_established",
    }


def source_contexts(enrichment: Mapping[str, Any], receipts: object = None) -> dict[str, Any]:
    """Separate query execution, provider time claims and incident-time correlation."""
    outcomes = normalize_source_status_map(enrichment.get("source_status"))
    receipt_map = receipts if isinstance(receipts, Mapping) else {}
    contexts = {}
    for provider, outcome in outcomes.items():
        receipt = receipt_map.get(provider)
        receipt = receipt if isinstance(receipt, Mapping) else {}
        started, finished = receipt.get("started_at"), receipt.get("finished_at")
        contexts[provider] = {
            **source_lineage_summary(provider),
            "outcome": outcome,
            "query_time": {
                "status": "recorded" if isinstance(started, str) or isinstance(finished, str) else "unavailable",
                "started_at": started if isinstance(started, str) else None,
                "finished_at": finished if isinstance(finished, str) else None,
                "semantics": "local_query_execution_not_remote_observation",
            },
            "provider_time": _time_fields(enrichment.get(provider)),
            "incident_time_correlation": "not_established",
            "establishes_business_ownership": False,
        }
    return contexts
