"""Related-target admission. Exact allowlisted origins, no service-worker inheritance."""

from __future__ import annotations

from typing import Any

from .evidence import EvidenceError, origin_of

_ACCEPT = frozenset({"iframe", "worker"})
_MAX_RELATED = 8


def split_targets(
    payload: dict[str, Any], allow: set[str], base: str
) -> tuple[dict[str, dict[str, Any]], set[str], list[str]]:
    raw = payload.get("targets")
    if raw is None:
        return {}, set(), []
    if not isinstance(raw, list):
        raise EvidenceError("invalid_trace_envelope")
    selected = payload.get("session_id")
    selected_id = selected if isinstance(selected, str) else ""
    grouped: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        session_id = item.get("sessionId")
        if not isinstance(session_id, str) or not session_id or session_id == selected_id:
            continue
        record = {
            "session_id": session_id,
            "target_id": item.get("targetId") if isinstance(item.get("targetId"), str) else "",
            "type": item.get("type") if isinstance(item.get("type"), str) else "",
            "subtype": item.get("subtype") if isinstance(item.get("subtype"), str) else "",
            "url": item.get("url") if isinstance(item.get("url"), str) else "",
            "parent_session_id": item.get("parentSessionId") if isinstance(item.get("parentSessionId"), str) else "",
            "attached": item.get("attached") is True,
            "original_ref": f"cdp-trace-original.json#/targets/{index}",
        }
        if session_id not in grouped:
            order.append(session_id)
            grouped[session_id] = []
        grouped[session_id].append(record)
    accepted: dict[str, dict[str, Any]] = {}
    rejected: set[str] = set()
    gaps: list[str] = []
    pending: list[dict[str, Any]] = []
    for session_id in order:
        rows = grouped[session_id]
        identity = {
            (row["target_id"], row["type"], row["subtype"], row["url"], row["parent_session_id"])
            for row in rows
        }
        if len(identity) != 1:
            rejected.add(session_id)
            if "related_target_conflict" not in gaps:
                gaps.append("related_target_conflict")
            continue
        chosen = dict(rows[0])
        chosen["attached"] = any(row["attached"] for row in rows)
        pending.append(chosen)
    for _ in range(_MAX_RELATED):
        progressed = False
        for record in pending:
            session_id = record["session_id"]
            if session_id in accepted or session_id in rejected:
                continue
            parent = record["parent_session_id"]
            if parent != selected_id and parent not in accepted:
                continue
            progressed = True
            if len(accepted) >= _MAX_RELATED or not _admitted(record, allow, base):
                rejected.add(session_id)
                _reject_gap(record, gaps)
                continue
            accepted[session_id] = record
        if not progressed:
            break
    for record in pending:
        session_id = record["session_id"]
        if session_id in accepted or session_id in rejected:
            continue
        rejected.add(session_id)
        if "related_target_unknown" not in gaps:
            gaps.append("related_target_unknown")
    return accepted, rejected, gaps


def _reject_gap(record: dict[str, Any], gaps: list[str]) -> None:
    if record["type"] == "service_worker" or record["subtype"] in {"service_worker", "shared", "shared_worker"}:
        name = "service_worker_unattributed"
    elif record["type"] == "iframe":
        name = "oopif_origin_rejected"
    elif record["type"] not in _ACCEPT:
        name = "related_target_unknown"
    else:
        name = "related_target_rejected"
    if name not in gaps:
        gaps.append(name)


def _admitted(record: dict[str, Any], allow: set[str], base: str) -> bool:
    del base
    if not record["attached"]:
        return False
    if record["type"] not in _ACCEPT:
        return False
    if record["subtype"] in {"shared", "service_worker", "shared_worker"}:
        return False
    try:
        return origin_of(record["url"]) in allow
    except EvidenceError:
        return False
