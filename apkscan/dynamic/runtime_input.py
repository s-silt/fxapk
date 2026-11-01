"""Bounded runtime-report ingestion; acceptance is not event authentication."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Any

from apkscan.core.bounded_io import read_limited
from apkscan.core.json_contract import parse_finite_json_float, reject_nonfinite_json_constant
from apkscan.core.json_io import BoundedJsonError, REPORT_JSON_MAX_BYTES, loads_bounded
from apkscan.dynamic.event_origin import RuntimePayload

EVENT_FIELDS = ("messages", "endpoints", "crypto_events", "jsbridge_events", "sensitive_api_events",
                "antidetect_events", "credential_events", "sqlcipher_events", "clipboard_events",
                "remote_control_events", "ui_observations", "process_observations")


@dataclass(frozen=True)
class RuntimeReadFailure:
    reason: str


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def read_runtime_input(path: Path) -> RuntimePayload | RuntimeReadFailure:
    try:
        if path.is_symlink():
            return RuntimeReadFailure("runtime_report_unsafe_file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                return RuntimeReadFailure("runtime_report_unsafe_file")
            if info.st_size > REPORT_JSON_MAX_BYTES:
                return RuntimeReadFailure("runtime_report_size_limit")
            raw = read_limited(stream, REPORT_JSON_MAX_BYTES)
        if len(raw) > REPORT_JSON_MAX_BYTES:
            return RuntimeReadFailure("runtime_report_size_limit")
        value = loads_bounded(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_float=parse_finite_json_float,
                              parse_constant=reject_nonfinite_json_constant)
        if not isinstance(value, dict):
            return RuntimeReadFailure("runtime_report_invalid_root")
        return RuntimePayload(value, raw, str(path))
    except FileNotFoundError:
        return RuntimeReadFailure("runtime_report_missing")
    except BoundedJsonError:
        return RuntimeReadFailure("runtime_report_depth_limit")
    except (ValueError, RecursionError):
        return RuntimeReadFailure("runtime_report_invalid_json")
    except OSError:
        return RuntimeReadFailure("runtime_report_read_failed")


def input_receipt(payload: object) -> dict[str, Any]:
    if isinstance(payload, RuntimeReadFailure):
        return {"status": "unavailable", "reason": payload.reason, "scope": "json_ingestion_only"}
    if not isinstance(payload, RuntimePayload):
        return {"status": "unknown", "scope": "json_ingestion_only"}
    gaps = {}
    for field in EVENT_FIELDS:
        if field not in payload:
            continue
        rows = payload[field]
        if not isinstance(rows, list):
            gaps[field] = {"reason": "invalid_array"}
        elif invalid := sum(not isinstance(row, dict) for row in rows):
            gaps[field] = {"reason": "invalid_rows", "count": invalid}
    return {"status": "partial" if gaps else "accepted", "scope": "json_ingestion_only",
            "artifact_sha256": payload.sha256, "gaps": gaps,
            "event_semantics_validated": False, "target_app_attribution_verified": False}
