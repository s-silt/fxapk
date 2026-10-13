"""Project explicit navigate/click records. Attribution flags stay false."""

from __future__ import annotations

from typing import Any

from .evidence import EvidenceError

_KINDS = frozenset({"navigate", "click"})


def project_actions(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("actions")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise EvidenceError("invalid_trace_envelope")
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or item.get("kind") not in _KINDS:
            continue
        timestamp = item.get("timestamp")
        if not isinstance(timestamp, str) or not timestamp:
            continue
        row: dict[str, Any] = {
            "kind": item["kind"],
            "ack": item.get("ack") is True,
            "timestamp": timestamp,
            "round": item.get("round") if type(item.get("round")) is int else None,
            "original_ref": f"cdp-trace-original.json#/actions/{index}",
        }
        if item["kind"] == "navigate" and isinstance(item.get("url"), str):
            row["url"] = item["url"]
        if item["kind"] == "click" and isinstance(item.get("selector"), str):
            row["selector"] = item["selector"]
        rows.append(row)
    return rows
