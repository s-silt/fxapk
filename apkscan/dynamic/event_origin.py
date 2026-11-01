"""Bind parsed runtime events to the exact bytes read, before normalization."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import hashlib
import re
from typing import Any

from apkscan.core.models import Evidence


class RuntimePayload(dict[str, Any]):
    def __init__(self, value: dict[str, Any], raw: bytes, path: str) -> None:
        super().__init__(value)
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.path = path


@dataclass(frozen=True)
class EventOrigin:
    sha256: str
    path: str
    pointer: str
    capture: dict[str, Any]
    gaps: tuple[str, ...] = ()


class RuntimeEvent(dict[str, Any]):
    def __init__(self, value: dict[str, Any], origin: EventOrigin) -> None:
        super().__init__(value)
        self.origin = origin


def bind_event(payload: object, field: str, index: int, value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, RuntimePayload):
        return dict(value)
    raw_capture = value.get("capture_context")
    capture = {}
    if isinstance(raw_capture, dict):
        for key in ("package", "pid", "uid", "round", "pass_tag", "sample_sha256", "script_sha256"):
            item = raw_capture.get(key)
            if type(item) is int or isinstance(item, str) and len(item) <= 512:
                capture[key] = item
    pointer = "/" + field.replace("~", "~0").replace("/", "~1") + f"/{index}"
    gaps = []
    if value.get("body_capture_status") == "not_read_non_interference":
        gaps.append("request_body_not_read_non_interference")
    if value.get("export_status") == "not_attempted_non_interference":
        gaps.append("database_export_not_attempted_non_interference")
    return RuntimeEvent(value, EventOrigin(payload.sha256, payload.path, pointer, capture, tuple(gaps)))


def preserve_origin(raw: dict[str, Any], normalized: dict[str, Any]) -> dict[str, Any]:
    return RuntimeEvent(normalized, raw.origin) if isinstance(raw, RuntimeEvent) else normalized


def evidence_coordinates(event: object) -> dict[str, Any]:
    if not isinstance(event, RuntimeEvent):
        return {}
    origin = event.origin
    script = origin.capture.get("script_sha256")
    timestamp = event.get("ts")
    observed_at = (
        timestamp / 1000
        if isinstance(timestamp, (int, float))
        and not isinstance(timestamp, bool)
        and 0 <= timestamp <= 253402300799999
        else None
    )
    return {
        "observed_at": observed_at,
        "provenance": {
            "artifact_sha256": origin.sha256,
            "artifact_path": origin.path,
            "artifact_kind": "runtime_report",
            "capture_context": dict(origin.capture),
            "completeness": "not_attested",
            "capture_gaps": list(origin.gaps),
            "event_time_semantics": "producer_reported_unix_milliseconds" if observed_at is not None else "unavailable",
            "capture_identity_status": "producer_declared" if origin.capture else "not_provided",
            "script_identity_status": "producer_declared" if isinstance(script, str) and re.fullmatch(r"[0-9a-f]{64}", script) else "not_provided",
            "authenticity_claimed": False,
            "target_app_attribution_verified": False,
        },
        "locator": {"json_pointer": origin.pointer, "coordinate_system": "json_pointer"},
    }


def index_events(events: list[dict[str, Any]], keys: Callable[[dict[str, Any]], Iterable[str]]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        for key in dict.fromkeys(keys(event)):
            index.setdefault(key, []).append(event)
    return index


def bind_evidence(evidence: Evidence, event: dict[str, Any]) -> None:
    coordinates = evidence_coordinates(event)
    if coordinates:
        evidence.provenance = coordinates["provenance"]
        evidence.locator = coordinates["locator"]
        evidence.observed_at = coordinates["observed_at"]
