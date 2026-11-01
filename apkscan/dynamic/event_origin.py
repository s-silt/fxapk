"""Bind parsed runtime events to the exact bytes read, before normalization."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import hashlib
import math
import re
from typing import Any

from apkscan.core.models import Evidence


_TIMESTAMP_UNITS = {
    "messages": "seconds",
    "crypto_events": "milliseconds",
    "jsbridge_events": "milliseconds",
    "sensitive_api_events": "milliseconds",
    "antidetect_events": "milliseconds",
    "credential_events": "milliseconds",
    "sqlcipher_events": "milliseconds",
    "clipboard_events": "milliseconds",
    "remote_control_events": "milliseconds",
}


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
    timestamp_unit: str | None = None
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
    raw_gaps = value.get("capture_gaps")
    gaps = (
        [gap for gap in raw_gaps[:32] if isinstance(gap, str) and len(gap) <= 256]
        if isinstance(raw_gaps, list)
        else []
    )
    pid = capture.get("pid")
    script = capture.get("script_sha256")
    if (
        type(pid) is not int
        or pid <= 0
        or not isinstance(script, str)
        or not re.fullmatch(r"[0-9a-f]{64}", script)
    ) and "process_binding_missing" not in gaps:
        gaps.append("process_binding_missing")
    if value.get("body_capture_status") == "not_read_non_interference":
        if "request_body_not_read_non_interference" not in gaps:
            gaps.append("request_body_not_read_non_interference")
    if value.get("export_status") == "not_attempted_non_interference":
        if "database_export_not_attempted_non_interference" not in gaps:
            gaps.append("database_export_not_attempted_non_interference")
    return RuntimeEvent(
        value,
        EventOrigin(
            payload.sha256,
            payload.path,
            pointer,
            capture,
            _TIMESTAMP_UNITS.get(field),
            tuple(gaps),
        ),
    )


def preserve_origin(raw: dict[str, Any], normalized: dict[str, Any]) -> dict[str, Any]:
    return RuntimeEvent(normalized, raw.origin) if isinstance(raw, RuntimeEvent) else normalized


def evidence_coordinates(event: object) -> dict[str, Any]:
    if not isinstance(event, RuntimeEvent):
        return {}
    origin = event.origin
    script = origin.capture.get("script_sha256")
    timestamp = event.get("ts")
    timestamp_limit = (
        {
            "seconds": 253402300799,
            "milliseconds": 253402300799999,
        }.get(origin.timestamp_unit)
        if origin.timestamp_unit is not None
        else None
    )
    timestamp_valid = False
    observed_at = None
    if (
        timestamp_limit is not None
        and isinstance(timestamp, (int, float))
        and not isinstance(timestamp, bool)
    ):
        if isinstance(timestamp, int):
            timestamp_valid = 0 <= timestamp <= timestamp_limit
        else:
            timestamp_valid = math.isfinite(timestamp) and 0 <= timestamp <= timestamp_limit
        if timestamp_valid:
            observed_at = timestamp if origin.timestamp_unit == "seconds" else timestamp / 1000
    timestamp_semantics = (
        f"producer_reported_unix_{origin.timestamp_unit}"
        if timestamp_valid
        else "unavailable"
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
            "event_time_semantics": timestamp_semantics,
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
