"""Bounded parent-stack resolution. Never guesses a debugger session."""

from __future__ import annotations

import json
from typing import Any

_MAX_PARENT_DEPTH = 32


def debugger_sessions(capture: dict[str, Any]) -> dict[str, str]:
    """Map debuggerId to the session that reported it. Duplicate ids are unusable."""
    rows = capture.get("debugger_sessions")
    if not isinstance(rows, list):
        return {}
    found: dict[str, str] = {}
    blocked: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        debugger_id = row.get("debuggerId")
        session_id = row.get("sessionId")
        if not isinstance(debugger_id, str) or not debugger_id or not isinstance(session_id, str):
            continue
        previous = found.get(debugger_id)
        if previous is not None and previous != session_id:
            blocked.add(debugger_id)
            continue
        found[debugger_id] = session_id
    for debugger_id in blocked:
        found.pop(debugger_id, None)
    return found


def _request_consistent(row: dict[str, Any], debugger_id: str, stack_id: str) -> bool:
    """A stored getStackTrace must name the same session and stack id. Absence stays usable."""
    request = row.get("request")
    if request is None:
        return True
    if not isinstance(request, dict) or request.get("method") != "Debugger.getStackTrace":
        return False
    if request.get("sessionId") != row.get("sessionId"):
        return False
    params = request.get("params")
    ident = params.get("stackTraceId") if isinstance(params, dict) else None
    return (
        isinstance(ident, dict)
        and ident.get("id") == stack_id
        and ident.get("debuggerId") == debugger_id
    )


def parent_stacks(payload: dict[str, Any]) -> dict[tuple[str, str], tuple[int, dict[str, Any], bool]]:
    """Index fetched stacks. Session/request mismatch or conflicting rows drop the key."""
    rows = payload.get("parent_stacks")
    if not isinstance(rows, list):
        return {}
    capture = payload.get("capture")
    owners = debugger_sessions(capture if isinstance(capture, dict) else {})
    grouped: dict[tuple[str, str], list[tuple[int, dict[str, Any], bool, str]]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        debugger_id = row.get("debuggerId")
        stack_id = row.get("stackTraceId")
        session_id = row.get("sessionId")
        result = row.get("result")
        if (
            not isinstance(debugger_id, str)
            or not isinstance(stack_id, str)
            or not isinstance(session_id, str)
            or not isinstance(result, dict)
        ):
            continue
        stack = result.get("stackTrace")
        owner = owners.get(debugger_id)
        if not isinstance(stack, dict) or owner is None or session_id != owner:
            continue
        if not _request_consistent(row, debugger_id, stack_id):
            continue
        request = row.get("request")
        signature = json.dumps(
            {"stack": stack, "request": request if isinstance(request, dict) else None},
            sort_keys=True,
            ensure_ascii=False,
        )
        grouped.setdefault((debugger_id, stack_id), []).append(
            (index, stack, isinstance(request, dict), signature)
        )
    found: dict[tuple[str, str], tuple[int, dict[str, Any], bool]] = {}
    for key, items in grouped.items():
        if any(item[3] != items[0][3] for item in items[1:]):
            continue
        index, stack, has_request, _signature = items[0]
        found[key] = (index, stack, has_request)
    return found


def walk_groups(
    stack: Any,
    prefix: str,
    session_id: str,
    *,
    debuggers: dict[str, str],
    fetched: dict[tuple[str, str], tuple[int, dict[str, Any], bool]],
) -> tuple[list[tuple[str, list[tuple[Any, str]], str, str | None]], bool, bool]:
    """Return (kind, frames, session, request_ref) groups. Inline parent wins over parentId."""
    unresolved = False
    seen: set[tuple[str, str]] = set()

    def frames_of(node: dict[str, Any], path: str) -> list[tuple[Any, str]]:
        raw = node.get("callFrames")
        if not isinstance(raw, list):
            return []
        return [(frame, f"{path}/callFrames/{index}") for index, frame in enumerate(raw)]

    def walk(
        node: Any, path: str, session: str, depth: int, kind: str
    ) -> tuple[list[tuple[str, list[tuple[Any, str]], str, str | None]], bool]:
        if not isinstance(node, dict):
            return [], False
        cut = node.get("truncated") is True
        groups: list[tuple[str, list[tuple[Any, str]], str, str | None]] = [
            (kind, frames_of(node, path), session, None)
        ]
        if depth >= _MAX_PARENT_DEPTH:
            return groups, cut or isinstance(node.get("parent"), dict) or isinstance(node.get("parentId"), dict)
        parent = node.get("parent")
        if isinstance(parent, dict):
            nested, truncated = walk(parent, path + "/parent", session, depth + 1, "async")
            return groups + nested, truncated or cut
        parent_id = node.get("parentId")
        if not isinstance(parent_id, dict):
            return groups, cut
        stack_id = parent_id.get("id")
        debugger_id = parent_id.get("debuggerId")
        if not isinstance(stack_id, str) or not isinstance(debugger_id, str):
            return groups, True
        owner = debuggers.get(debugger_id)
        key = (debugger_id, stack_id)
        located = fetched.get(key)
        if owner is None or located is None or key in seen:
            return groups, cut
        seen.add(key)
        index, parent_stack, has_request = located
        pointer = f"cdp-trace-original.json#/parent_stacks/{index}/result/stackTrace"
        request_ref = (
            f"cdp-trace-original.json#/parent_stacks/{index}/request" if has_request else None
        )
        nested, truncated = walk(parent_stack, pointer, owner, depth + 1, "async")
        if request_ref and nested:
            kind_n, frames_n, session_n, _prior = nested[0]
            nested[0] = (kind_n, frames_n, session_n, request_ref)
        return groups + nested, truncated or cut

    if not isinstance(stack, dict):
        return [], False, False
    groups, truncated = walk(stack, prefix, session_id, 0, "sync")
    unresolved = _unresolved(stack, debuggers, fetched, seen)
    return groups, unresolved, truncated


def _unresolved(
    stack: dict[str, Any],
    debuggers: dict[str, str],
    fetched: dict[tuple[str, str], tuple[int, dict[str, Any], bool]],
    used: set[tuple[str, str]],
) -> bool:
    del used

    def scan(node: Any, depth: int, trail: set[tuple[str, str]]) -> bool:
        if not isinstance(node, dict):
            return False
        parent = node.get("parent")
        parent_id = node.get("parentId")
        if isinstance(parent, dict) and isinstance(parent_id, dict):
            return True
        if depth >= _MAX_PARENT_DEPTH:
            return isinstance(parent, dict) or isinstance(parent_id, dict)
        if isinstance(parent, dict):
            return scan(parent, depth + 1, trail)
        if not isinstance(parent_id, dict):
            return False
        stack_id = parent_id.get("id")
        debugger_id = parent_id.get("debuggerId")
        if not isinstance(stack_id, str) or not isinstance(debugger_id, str):
            return True
        key = (debugger_id, stack_id)
        if debuggers.get(debugger_id) is None or key not in fetched or key in trail:
            return True
        trail.add(key)
        _index, parent_stack, _has_request = fetched[key]
        return scan(parent_stack, depth + 1, trail)

    return scan(stack, 0, set())
