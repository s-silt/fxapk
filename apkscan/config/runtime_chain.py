"""Pure, round-scoped addressing evidence projections. No decision feedback."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import ipaddress
import re
from typing import Any

_SCOPE = ("sample_sha256", "capture_ref", "runtime_variant", "pid", "process_start")
_MAX_EVENTS = 20000


def _time(value: object) -> datetime | None:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def _scope_ok(row: dict, sample: str) -> bool:
    return (isinstance(sample, str) and bool(re.fullmatch(r"[0-9a-f]{64}", sample)) and row.get("sample_sha256") == sample
            and isinstance(row.get("capture_ref"), str) and bool(row["capture_ref"])
            and row.get("runtime_variant") in ("original-runtime", "modified-runtime")
            and type(row.get("pid")) is int and row["pid"] > 0
            and isinstance(row.get("process_start"), str) and bool(row["process_start"])
            and row.get("target_attributed") is True)


def _identity(event: dict, key: str = "event_id") -> tuple[str, str]:
    ref, value = event.get("capture_ref"), event.get(key)
    return (ref, value) if isinstance(ref, str) and isinstance(value, str) else ("", "")


def _coordinates_ok(event: dict) -> bool:
    if (not isinstance(event.get("host"), str) or not event["host"]
            or type(event.get("port")) is not int or not 1 <= event["port"] <= 65535
            or _time(event.get("observed_at")) is None):
        return False
    protocol = event.get("protocol")
    if protocol == "tcp":
        try:
            ipaddress.ip_address(str(event.get("peer_ip")))
        except ValueError:
            return False
        return (event.get("host_status") == "socket_argument" and event["host"] == event.get("value")
                and event.get("sni") is None and event.get("sni_status") == "not_applicable"
                and event.get("socket_connected") is True
                and event.get("network_api") == "java.net.Socket.<init>(java.lang.String,int)")
    if event.get("host_status") != "observed":
        return False
    if protocol == "http":
        return event.get("sni") is None and event.get("sni_status") == "not_applicable"
    return (protocol == "https" and isinstance(event.get("sni"), str) and bool(event["sni"])
            and event.get("sni_status") == "observed")


def compare_material(static: dict, runtime: dict) -> dict[str, Any]:
    comparable = (static.get("material", {}).get("complete") is True
                  and runtime.get("hash_scope") == "full" and runtime.get("verified") is True
                  and bool(static.get("sha256")) and bool(runtime.get("sha256")))
    status = "not_comparable"
    if comparable:
        status = "content_matches" if static["sha256"] == runtime["sha256"] else "content_differs"
    return {"status": status, "static_sha256": static.get("sha256"), "runtime_sha256": runtime.get("sha256")}


def review_runtime(
    artifacts: list[dict], events: list[dict], *, sample_sha256: str,
    body_records: list[dict], rounds: list[dict],
) -> list[dict[str, Any]]:
    """Only explicit object-origin links can verify a specified field's consumption.

    Callers must supply original, integrity-checked observer records. Values/timing
    are useful correlation clues but never synthesize the missing origin link.
    Modified rounds remain independently labeled, including their positive links.
    """
    items = [e for e in events[:_MAX_EVENTS] if isinstance(e, dict)]
    counts = Counter(_identity(e) for e in items)
    indexed = {_identity(e): e for e in items}
    out = []
    for art in artifacts:
        if not isinstance(art, dict) or not art.get("decoded"):
            continue
        for field in art.get("fields") or []:
            if not isinstance(field, dict) or not isinstance(field.get("value"), str):
                continue
            value, path, sha = field["value"], field.get("path"), art.get("sha256")
            correlations = []
            for event in items:
                if event.get("kind") != "network_argument" or event.get("value") != value:
                    continue
                gaps = set()
                if len(events) > _MAX_EVENTS:
                    gaps.add("runtime_event_budget_exceeded")
                if not _scope_ok(event, sample_sha256):
                    gaps.add("runtime_scope_incomplete")
                if not _coordinates_ok(event):
                    gaps.add("network_coordinates_incomplete")
                origin_key = _identity(event, "origin_event_id")
                origin = indexed.get(origin_key, {})
                if event.get("capture_gaps") or origin.get("capture_gaps"):
                    gaps.add("observer_record_unverified")
                if (not all(_identity(event)) or not all(origin_key) or counts[_identity(event)] != 1
                        or counts[origin_key] != 1):
                    gaps.add("event_identity_missing_or_ambiguous")
                if (origin.get("kind") != "config_field_read" or origin.get("artifact_sha256") != sha
                        or origin.get("field_path") != path or origin.get("value") != value):
                    gaps.add("field_origin_unbound")
                if (not _scope_ok(origin, sample_sha256)
                        or any(origin.get(k) != event.get(k) for k in _SCOPE)):
                    gaps.add("cross_scope_or_unbound_origin")
                if (origin.get("source_binding") != "direct_object_origin"
                        or event.get("source_binding") != "direct_object_origin"
                        or not origin.get("object_id") or origin.get("object_id") != event.get("origin_object_id")):
                    gaps.add("direct_origin_link_missing")
                earlier, later = _time(origin.get("observed_at")), _time(event.get("observed_at"))
                if (type(origin.get("sequence")) is not int or type(event.get("sequence")) is not int
                        or not 0 <= origin["sequence"] < event["sequence"]
                        or earlier is None or later is None or earlier > later):
                    gaps.add("event_order_unverified")
                if not any(_scope_ok(b, sample_sha256) and b.get("sha256") == sha and b.get("hash_scope") == "full"
                           and b.get("verified") is True and all(b.get(k) == event.get(k) for k in _SCOPE)
                           for b in body_records if isinstance(b, dict)):
                    gaps.add("complete_runtime_material_unbound")
                correlations.append({
                    **{k: event.get(k) for k in (*_SCOPE, "target_attributed", "protocol", "port", "host", "sni", "observed_at",
                                               "host_status", "sni_status", "peer_ip", "network_api", "socket_connected")},
                    "status": "correlation_candidate", "consumption": "candidate" if gaps else "verified",
                    "evidence_event_ids": sorted({str(e) for e in (event.get("event_id"), event.get("origin_event_id")) if e}),
                    "gaps": sorted(gaps),
                })
            suspicions = []
            for round_record in rounds:
                if (isinstance(round_record, dict) and round_record.get("sample_sha256") == sample_sha256
                        and round_record.get("runtime_variant") == "original-runtime"
                        and round_record.get("target_attributed") is True
                        and round_record.get("business_traffic_observed") is True
                        and round_record.get("capture_ref") and isinstance(round_record.get("observed_values"), list)
                        and value not in round_record["observed_values"]):
                    suspicions.append({"kind": "not_contacted_in_round", "capture_ref": round_record["capture_ref"]})
            out.append({"artifact_sha256": sha, "field_path": path, "value": value,
                        "correlations": sorted(correlations, key=lambda c: (str(c["capture_ref"]), str(c["runtime_variant"]), str(c["observed_at"]), c["evidence_event_ids"])),
                        "suspicions": sorted(suspicions, key=lambda s: s["capture_ref"])})
    return sorted(out, key=lambda r: (str(r["artifact_sha256"]), str(r["field_path"]), r["value"]))
