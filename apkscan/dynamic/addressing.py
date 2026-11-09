"""Offline addressing projection from the exact runtime report and body bytes."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from apkscan.config.chain import build_control_chains
from apkscan.config.runtime_chain import compare_material, review_runtime
from apkscan.core.jadx_sources import contained
from apkscan.core.models import Report
from apkscan.dynamic.config_artifacts import MAX_BODY_BYTES, MAX_RECORDS, _linked
from apkscan.dynamic.event_origin import RuntimePayload
from apkscan.dynamic.addressing_events import MAX_EVENTS, verify_event_record

META_WRITE_OWNER = "dynamic.addressing"
META_WRITE_CATEGORIES = {"control_chains": "signal"}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)


def project_addressing(report: Report, payload: RuntimePayload) -> int:
    artifacts = report.meta.get("remote_config_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return 0
    sample = report.meta.get("sample_sha256", "")
    namespace = "capture:" + payload.sha256
    variant = payload.get("runtime_variant")
    ledger = report.meta.get("runtime_observations", [])
    observations = [r for r in ledger if isinstance(r, dict) and r.get("capture_ref") == namespace
                    and isinstance(r.get("runtime"), dict)] if isinstance(ledger, list) else []
    attributed = {r.get("value") for r in observations if isinstance(r.get("value"), str)
                  and r["runtime"].get("target_attributed") is True
                  and r["runtime"].get("variant", "original-runtime") == variant
                  and r.get("eligible") is True}
    events = []
    raw_events = payload.get("addressing_events", [])
    common_scope = _common_scope(raw_events) if isinstance(raw_events, list) else None
    for row in raw_events[:MAX_EVENTS] if isinstance(raw_events, list) else []:
        if not isinstance(row, dict):
            continue
        event = deepcopy(row)
        raw_verified = len(raw_events) <= MAX_EVENTS and verify_event_record(row, Path(payload.path).parent)
        if not raw_verified:
            event["capture_gaps"] = sorted(set(event.get("capture_gaps") or []) | {"observer_record_unverified"})
        # Bind one file to one capture; preserve caller scope differences as gaps.
        if event.get("runtime_variant") != variant or payload.get("package_name") != report.package_name:
            event["target_attributed"] = False
        else:
            event["target_attributed"] = raw_verified and event.get("target_attributed") is True and event.get("value") in attributed
        event["capture_ref"] = namespace if common_scope and row.get("capture_ref") == common_scope else ""
        events.append(event)
    # Legacy observations are correlations only. They carry no fabricated origin event.
    for row in observations:
        if any(e.get("kind") == "network_argument" and e.get("value") == row.get("value") for e in events):
            continue
        runtime = row["runtime"]
        events.append({"kind": "network_argument", "value": row.get("value"), "sample_sha256": sample,
                       "capture_ref": namespace, "runtime_variant": runtime.get("variant", "original-runtime"),
                       "target_attributed": row.get("value") in attributed,
                       **{k: runtime.get(k) for k in ("protocol", "port", "host", "sni", "observed_at", "pid", "process_start")}})
    bodies = []
    raw_bodies = payload.get("config_body_artifacts", [])
    for row in raw_bodies[:MAX_RECORDS] if isinstance(raw_bodies, list) else []:
        if not isinstance(row, dict):
            continue
        body = deepcopy(row)
        body["verified"] = False
        try:
            path = contained(Path(payload.path).parent, body.get("stored_path", ""))
            if any(_linked(p) for p in (path, *path.parents)):
                raise ValueError("linked_body_path")
            with path.open("rb") as stream:
                data = stream.read(MAX_BODY_BYTES + 1)
            body["verified"] = (len(data) <= MAX_BODY_BYTES and len(data) == body.get("received_bytes")
                                and hashlib.sha256(data).hexdigest() == body.get("sha256"))
        except (OSError, ValueError, TypeError):
            pass
        if body.get("runtime_variant") != variant or body.get("sample_sha256") != sample:
            body["verified"] = False
        if common_scope and body.get("capture_ref") != common_scope:
            body["verified"] = False
        if type(body.get("declared_length")) is not int or body.get("declared_length") != body.get("received_bytes"):
            body["hash_scope"] = "prefix"
        body["capture_ref"] = namespace
        bodies.append(body)
    rounds = []
    if variant == "original-runtime" and any(r.get("value") in attributed and r["runtime"].get("business_api_paths") for r in observations):
        rounds.append({"capture_ref": namespace, "sample_sha256": sample, "runtime_variant": variant,
                       "target_attributed": True, "business_traffic_observed": True,
                       "observed_values": sorted({r["value"] for r in observations if isinstance(r.get("value"), str)})})
    bindings = review_runtime(artifacts, events, sample_sha256=sample, body_records=bodies, rounds=rounds)
    by_sha = {a.get("sha256"): a for a in artifacts if isinstance(a, dict) and isinstance(a.get("sha256"), str)}
    for binding in bindings:
        art = by_sha.get(binding["artifact_sha256"], {})
        binding["capture_ref"] = namespace
        binding["material_comparisons"] = sorted([
            {**compare_material(art, b), "capture_ref": namespace, "runtime_variant": b.get("runtime_variant")}
            for b in bodies if b.get("source_url") == art.get("source_url")
        ], key=lambda b: (str(b["runtime_sha256"]), str(b["runtime_variant"])))
    for endpoint in report.endpoints:
        own = [b for b in bindings if b["value"] == endpoint.value]
        if not own:
            continue
        old = endpoint.enrichment.get("config_runtime_bindings", [])
        rows = [b for b in old if isinstance(b, dict) and b.get("capture_ref") != namespace] if isinstance(old, list) else []
        endpoint.enrichment["config_runtime_bindings"] = sorted(rows + own, key=lambda b: json.dumps(b, sort_keys=True))
    report.meta["control_chains"] = build_control_chains(artifacts, report.meta.get("crypto_recipe"), report.endpoints)
    return len(bindings)


def _common_scope(rows: list) -> Any:
    """The first source scope names this file; differing scopes are never joined."""
    return next((r.get("capture_ref") for r in rows if isinstance(r, dict)), None)
