"""Bounded ingestion of explicit observer-origin links, without synthesizing them.

Specialized observers supply object/event IDs. This collector is not a general
taint engine: unsupported code paths retain missing-link gaps.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import threading
from typing import Any

from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.jadx_sources import contained
from apkscan.dynamic.config_artifacts import _linked

MAX_EVENTS = 20000
MAX_EVENT_BYTES = 16384
MAX_TOTAL_BYTES = 5 * 1024 * 1024
_EVENT_KEYS = ("event_id", "kind", "observed_at", "sequence", "artifact_sha256", "field_path", "value",
               "source_binding", "object_id", "origin_event_id", "origin_object_id", "protocol", "port", "host", "sni",
               "host_status", "sni_status", "peer_ip", "network_api", "socket_connected")


class AddressingEventCollector:
    def __init__(self, directory: Path, context: dict[str, Any]):
        self.directory, self.context = directory, deepcopy(context)
        self._rows: list[dict] = []
        self._total, self.dropped = 0, 0
        self._lock = threading.Lock()

    def on_message(self, message: object, data: object) -> None:
        if not isinstance(message, dict) or message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "fxapk-addressing-event-v1":
            return
        with self._lock:
            try:
                raw = json.dumps({"payload": payload, "context": self.context}, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
                if len(self._rows) >= MAX_EVENTS or len(raw) > MAX_EVENT_BYTES or self._total + len(raw) > MAX_TOTAL_BYTES:
                    raise ValueError("observer_event_budget_exceeded")
                sha = hashlib.sha256(raw).hexdigest()
                relative = f"addressing_events/{sha}.json"
                path = self.directory / relative
                if any(_linked(p) for p in (path, *path.parents)):
                    raise ValueError("linked_event_path")
                path.parent.mkdir(parents=True, exist_ok=True)
                if not atomic_create_bytes(path, raw) and path.read_bytes() != raw:
                    raise ValueError("observer_event_archive_conflict")
                self._rows.append({**{k: deepcopy(payload[k]) for k in _EVENT_KEYS if k in payload}, **deepcopy(self.context),
                                   "raw_record": {"stored_path": relative, "sha256": sha}, "capture_gaps": []})
                self._total += len(raw)
            except (OSError, ValueError, TypeError, RecursionError):
                self.dropped += 1

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = deepcopy(self._rows)
            if self.dropped:
                for row in rows:
                    row["capture_gaps"] = ["observer_event_budget_exceeded"]
            return sorted(rows, key=lambda r: json.dumps(r, sort_keys=True))


def verify_event_record(row: dict, directory: Path) -> bool:
    try:
        if row.get("capture_gaps"):
            return False
        ref = row["raw_record"]
        path = contained(directory, ref["stored_path"])
        if Path(ref["stored_path"]).is_absolute() or any(_linked(p) for p in (path, *path.parents)):
            return False
        with path.open("rb") as stream:
            raw = stream.read(MAX_EVENT_BYTES + 1)
        if len(raw) > MAX_EVENT_BYTES or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
            return False
        envelope = json.loads(raw)
        payload, context = envelope["payload"], envelope["context"]
        expected = {**{k: payload[k] for k in _EVENT_KEYS if k in payload}, **context,
                    "raw_record": ref, "capture_gaps": []}
        return payload.get("type") == "fxapk-addressing-event-v1" and row == expected
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return False
