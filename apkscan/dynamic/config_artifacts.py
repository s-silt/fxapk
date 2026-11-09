"""Bounded host-side retention of observer body messages, without replaying requests."""
from __future__ import annotations

import hashlib
import json
import logging
import stat
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any

from apkscan.core.atomic import atomic_create_bytes

logger = logging.getLogger(__name__)
MAX_BODY_BYTES = 512 * 1024
MAX_RECORDS = 40
MAX_TOTAL_BYTES = 5 * 1024 * 1024


def _linked(path: Path) -> bool:
    try:
        info = path.lstat()
        return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except FileNotFoundError:
        return False


class ConfigBodyCollector:
    def __init__(self, directory: Path, context: dict[str, Any]):
        self.directory = directory
        self.context = deepcopy(context)
        self._rows: dict[str, dict] = {}
        self._total = 0
        self.dropped = 0
        self._lock = threading.Lock()

    def on_message(self, message: object, data: object) -> None:
        if not isinstance(message, dict) or message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "fxapk-config-body-v1":
            return
        with self._lock:
            if len(self._rows) >= MAX_RECORDS or self._total >= MAX_TOTAL_BYTES:
                self.dropped += 1
                return
            raw = data if isinstance(data, bytes) else b""
            kept = raw[:min(MAX_BODY_BYTES, MAX_TOTAL_BYTES - self._total)]
            declared = payload.get("declared_length")
            full = (isinstance(data, bytes) and len(kept) == len(raw)
                    and payload.get("body_complete") is True and type(declared) is int
                    and declared >= 0 and len(raw) == declared)
            sha = hashlib.sha256(kept).hexdigest()
            row: dict[str, Any] = {k: deepcopy(payload.get(k)) for k in ("source_url", "method", "observed_at", "response_headers", "declared_length")}
            row.update(deepcopy(self.context))  # Host binding always overrides payload declarations.
            row.update(sha256=sha, received_bytes=len(kept), hash_scope="full" if full else "prefix",
                       comparability="comparable" if full else "not_comparable", verified=False,
                       stored_path=None, gaps=[] if full else ["runtime_body_incomplete"])
            try:
                relative = f"config_artifacts/{sha}.bin"
                dest = self.directory / relative
                if any(_linked(p) for p in (dest, *dest.parents)):
                    raise ValueError("linked_output_path")
                self.directory.mkdir(parents=True, exist_ok=True)
                dest.parent.mkdir(exist_ok=True)
                if not atomic_create_bytes(dest, kept) and dest.read_bytes() != kept:
                    raise ValueError("body_archive_conflict")
                row.update(stored_path=relative, verified=True)
            except (OSError, ValueError):
                logger.warning("runtime configuration body archival failed", exc_info=True)
                row["comparability"] = "not_comparable"
                row["gaps"].append("runtime_body_not_archived")
            identity = hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
            if identity not in self._rows:
                row["event_id"] = identity
                self._rows[identity] = row
                self._total += len(kept)

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return [deepcopy(row) for _, row in sorted(self._rows.items())]
