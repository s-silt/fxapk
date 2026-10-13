"""Pure CDP-trace projection and publication. No websocket import."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from apkscan.core.atomic import atomic_create_bytes

from .evidence import (
    EvidenceError,
    _javascript_lines,
    _utf16_units,
    claim_output,
    digest,
    origin_of,
)
from .runtime import validate_scope
from .trace_actions import project_actions
from .trace_limits import MAX_RAW_BYTES
from .trace_parents import debugger_sessions, parent_stacks, walk_groups
from .trace_targets import split_targets

_SCHEMA = "fxapk-cdp-trace/1"
_OBSERVATION_SCHEMA = "fxapk-cdp-trace-observation/1"
_PRODUCER = "fxapk-cdp-trace"
_BLOCKING = frozenset(
    {
        "missing_context",
        "frame_mismatch",
        "wrong_session",
        "source_tamper",
        "coordinate_unproven",
        "loader_conflict",
        "source_ambiguous",
        "cross_frame_async_unverified",
        "hop_identity_conflict",
    }
)
_ALWAYS_GAPS = (
    "click_attribution_unavailable",
    "target_app_attribution_unavailable",
    "provenance_unauthenticated",
    "closure_unavailable",
    "oopif_worker_unsupported",
    "attach_before_history_unobserved",
)
_MAX_EVENTS = 1024
_MAX_SOURCES = 64
_MAX_COMMANDS = 128
_MAX_DEPTH = 48
_MAX_SOURCE_CHARS = 48 * 1024


def normalize_related_origins(base: str, values: list[str] | None, related: bool) -> list[str]:
    """Exact origins only. Related origins require related targets and never replace the base."""
    items = list(values or [])
    if items and not related:
        raise EvidenceError("related_origin_requires_related_targets")
    if len(items) > 8:
        raise EvidenceError("related_origin_limit")
    allow = [base]
    for item in items:
        try:
            norm = origin_of(item)
        except EvidenceError:
            raise EvidenceError("related_origin_rejected") from None
        if norm not in allow:
            allow.append(norm)
    if len(allow) - 1 > 8:
        raise EvidenceError("related_origin_limit")
    return allow


def project_trace(raw: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Project one filtered trace envelope. Does not touch the network or disk."""
    if len(raw) > MAX_RAW_BYTES:
        raise EvidenceError("trace_oversize")
    payload = _envelope(raw)
    selected = payload["session_id"]
    origin = payload["origin"]
    allow = _allowlist(payload, origin)
    accepted, rejected, target_gaps = split_targets(payload, allow, origin)
    events = _ordered_events(payload["events"])
    sources, files, tamper, ambiguous = _sources(payload["sources"])
    raw_gaps = _raw_gaps(payload["completeness"])
    state = _State()
    state.target_ids[selected] = payload["target_id"] if isinstance(payload.get("target_id"), str) else ""
    for record in accepted.values():
        state.target_ids[record["session_id"]] = record["target_id"]
    requests: dict[tuple[str, str, int], dict[str, Any]] = {}
    order: list[tuple[str, str, int]] = []
    debuggers = debugger_sessions(payload["capture"] if isinstance(payload.get("capture"), dict) else {})
    fetched = parent_stacks(payload)
    allowed = set(accepted) | rejected | {selected}
    for index, event in enumerate(events):
        method = event["method"]
        session = event["sessionId"]
        seq = event["seq"]
        params = event["params"]
        if session not in allowed:
            if method == "Debugger.scriptParsed":
                foreign_script = params.get("scriptId")
                if isinstance(foreign_script, str):
                    state.seen.append((session, foreign_script, seq))
            continue
        if session in rejected and method != "Network.requestWillBeSent":
            if method == "Debugger.scriptParsed":
                foreign_script = params.get("scriptId")
                if isinstance(foreign_script, str):
                    state.seen.append((session, foreign_script, seq))
            continue
        if method == "Runtime.executionContextCreated":
            worker = accepted.get(session)
            state.context_created(
                session,
                params,
                origin,
                allow,
                worker_target=worker["target_id"] if worker and worker["type"] == "worker" else "",
            )
        elif method == "Runtime.executionContextDestroyed":
            state.context_destroyed(session, params)
        elif method == "Runtime.executionContextsCleared":
            state.contexts_cleared(session)
        elif method == "Page.frameNavigated":
            state.navigated(session, params)
        elif method == "Page.frameDetached":
            state.detached(session, params)
        elif method == "Target.detachedFromTarget":
            child = params.get("sessionId")
            state.target_detached(child if isinstance(child, str) and child else session)
        elif method == "Debugger.scriptParsed":
            state.script_parsed(session, seq, params)
        elif method == "Network.requestWillBeSent":
            _request(
                state,
                requests,
                order,
                sources,
                tamper,
                ambiguous,
                session,
                seq,
                index,
                params,
                debuggers,
                fetched,
            )
    gaps = _coverage_gaps(requests, raw_gaps)
    related = payload.get("capture", {}).get("related_targets") is True
    if related:
        gaps = [gap for gap in gaps if gap != "oopif_worker_unsupported"]
        for name in target_gaps:
            if name not in gaps:
                gaps.append(name)
        uncovered = [
            record["session_id"]
            for record in accepted.values()
            if not _session_covered(events, record["session_id"])
        ]
        if not accepted or uncovered:
            if "related_target_uncovered" not in gaps:
                gaps.append("related_target_uncovered")
        for record in accepted.values():
            record["covered"] = record["session_id"] not in uncovered
    receipt = {
        "schema_version": _OBSERVATION_SCHEMA,
        "producer": _PRODUCER,
        "coverage": {"status": "partial", "gaps": gaps},
        "click_attribution_verified": False,
        "target_app_attribution_verified": False,
        "provenance_authenticated": False,
        "closure_evaluated": False,
        "source": {
            "sha256": digest(raw),
            "relative_path": "cdp-trace-original.json",
        },
        "capture": _capture_identity(payload),
        "requests": [_public_request(requests[key]) for key in order],
    }
    actions = project_actions(payload)
    if actions:
        receipt["actions"] = actions
    interventions = payload.get("capture", {}).get("startup_interventions") if isinstance(payload.get("capture"), dict) else None
    if isinstance(interventions, list) and interventions:
        receipt["startup_interventions"] = [item for item in interventions if isinstance(item, dict)]
    if accepted or payload.get("targets"):
        receipt["related_targets"] = list(accepted.values())
    return receipt, files


def _allowlist(payload: dict[str, Any], origin: str) -> set[str]:
    allow = {origin}
    capture = payload.get("capture")
    raw = capture.get("origin_allowlist") if isinstance(capture, dict) else None
    if not isinstance(raw, list):
        return allow
    for item in raw:
        if not isinstance(item, str):
            continue
        try:
            allow.add(origin_of(item))
        except EvidenceError:
            continue
    return allow


def _session_covered(events: list[dict[str, Any]], session: str) -> bool:
    return any(
        event.get("sessionId") == session
        and event.get("method") in {"Debugger.scriptParsed", "Network.requestWillBeSent"}
        for event in events
    )


def run_trace(
    endpoint: str,
    target: str,
    origin: str,
    observation_ms: int,
    out: Path,
    claimed: list[bool] | None = None,
    *,
    related_targets: bool = False,
    navigate: str | None = None,
    click_selector: str | None = None,
    related_origin: list[str] | None = None,
    pause_related_start: bool = False,
) -> dict[str, Any]:
    """Claim the directory, capture, then publish raw, scripts, and the receipt."""
    endpoint = validate_scope(endpoint, target, origin)
    if type(observation_ms) is not int or isinstance(observation_ms, bool):
        raise EvidenceError("invalid_observation_budget")
    if not 0 <= observation_ms <= 60000:
        raise EvidenceError("invalid_observation_budget")
    if pause_related_start and not related_targets:
        raise EvidenceError("pause_related_start_requires_related_targets")
    allow = normalize_related_origins(origin, related_origin, related_targets)
    if navigate is not None and origin_of(navigate) != origin:
        raise EvidenceError("navigate_origin_rejected")
    if click_selector is not None and (
        not isinstance(click_selector, str) or not click_selector.strip() or len(click_selector) > 256
    ):
        raise EvidenceError("invalid_click_selector")
    claim_output(out)
    if claimed is not None:
        claimed.append(True)
    from .trace_runtime import capture

    raw = capture(
        endpoint=endpoint,
        target=target,
        origin=origin,
        observation_ms=observation_ms,
        out=out,
        related_targets=related_targets,
        navigate=navigate,
        click_selector=click_selector,
        related_origins=allow[1:],
        pause_related_start=pause_related_start,
    )
    receipt, files = project_trace(raw)
    return _publish(out, raw, receipt, files)


def _envelope(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_nonfinite,
        )
    except EvidenceError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise EvidenceError("invalid_trace_envelope") from None
    if not isinstance(value, dict):
        raise EvidenceError("invalid_trace_envelope")
    _bounded(value, 0)
    if value.get("schema_version") != _SCHEMA or value.get("producer") != _PRODUCER:
        raise EvidenceError("invalid_trace_envelope")
    for key in (
        "target_id",
        "session_id",
        "origin",
        "capture",
        "events",
        "sources",
        "commands",
        "completeness",
    ):
        if key not in value:
            raise EvidenceError("invalid_trace_envelope")
    for key in ("target_id", "session_id", "origin"):
        _short_text(value.get(key))
    capture = value.get("capture")
    if not isinstance(capture, dict):
        raise EvidenceError("invalid_trace_envelope")
    for key in ("id", "tool_version", "started_at"):
        _short_text(capture.get(key))
    if not isinstance(value.get("events"), list) or len(value["events"]) > _MAX_EVENTS:
        raise EvidenceError("invalid_trace_envelope")
    if not isinstance(value.get("sources"), list) or len(value["sources"]) > _MAX_SOURCES:
        raise EvidenceError("invalid_trace_envelope")
    if not isinstance(value.get("commands"), list) or len(value["commands"]) > _MAX_COMMANDS:
        raise EvidenceError("invalid_trace_envelope")
    for optional, limit in (("parent_stacks", 32), ("targets", 16), ("actions", 8)):
        if optional in value and (
            not isinstance(value[optional], list) or len(value[optional]) > limit
        ):
            raise EvidenceError("invalid_trace_envelope")
    completeness = value.get("completeness")
    if not isinstance(completeness, dict) or not isinstance(completeness.get("gaps"), list):
        raise EvidenceError("invalid_trace_envelope")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise EvidenceError("invalid_trace_envelope")
        result[key] = item
    return result


def _nonfinite(_: str) -> Any:
    raise EvidenceError("invalid_trace_envelope")


def _bounded(value: Any, depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise EvidenceError("invalid_trace_envelope")
    if isinstance(value, dict):
        if len(value) > 4096:
            raise EvidenceError("invalid_trace_envelope")
        for item in value.values():
            _bounded(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 4096:
            raise EvidenceError("invalid_trace_envelope")
        for item in value:
            _bounded(item, depth + 1)


def _short_text(value: Any) -> None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise EvidenceError("invalid_trace_envelope")


def _ordered_events(value: list[Any]) -> list[dict[str, Any]]:
    """Keep wire order. Duplicate or decreasing seq is malformed evidence."""
    ordered: list[dict[str, Any]] = []
    previous: int | None = None
    seen: set[int] = set()
    for item in value:
        if not isinstance(item, dict):
            raise EvidenceError("invalid_trace_envelope")
        method = item.get("method")
        session = item.get("sessionId")
        seq = item.get("seq")
        params = item.get("params")
        if not isinstance(method, str) or not isinstance(session, str) or type(seq) is not int:
            raise EvidenceError("invalid_trace_envelope")
        if seq < 0 or seq in seen or (previous is not None and seq <= previous):
            raise EvidenceError("invalid_trace_envelope")
        if not isinstance(params, dict):
            raise EvidenceError("invalid_trace_envelope")
        seen.add(seq)
        previous = seq
        ordered.append(item)
    return ordered


def _raw_gaps(completeness: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    for item in completeness.get("gaps", []):
        if not isinstance(item, str):
            raise EvidenceError("invalid_trace_envelope")
        if item not in gaps:
            gaps.append(item)
    return gaps


def _sources(
    value: list[Any],
) -> tuple[
    dict[tuple[str, int, int, str], dict[str, Any]],
    dict[str, bytes],
    set[tuple[str, int, int, str]],
    set[tuple[str, int, int, str]],
]:
    good: dict[tuple[str, int, int, str], dict[str, Any]] = {}
    files: dict[str, bytes] = {}
    tamper: set[tuple[str, int, int, str]] = set()
    ambiguous: set[tuple[str, int, int, str]] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            continue
        session = item.get("sessionId")
        seq = item.get("seq")
        context_id = item.get("contextId")
        script_id = item.get("scriptId")
        text = item.get("sourceText")
        claimed = item.get("sha256")
        if (
            not isinstance(session, str)
            or type(seq) is not int
            or isinstance(seq, bool)
            or type(context_id) is not int
            or isinstance(context_id, bool)
            or not isinstance(script_id, str)
        ):
            continue
        if not isinstance(text, str) or not isinstance(claimed, str):
            continue
        if len(text) > _MAX_SOURCE_CHARS:
            raise EvidenceError("invalid_trace_envelope")
        key = (session, seq, context_id, script_id)
        if key in ambiguous or key in good or key in tamper:
            good.pop(key, None)
            tamper.discard(key)
            ambiguous.add(key)
            continue
        digest_hex = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if claimed != digest_hex:
            tamper.add(key)
            continue
        stored = dict(item)
        stored["_origin_index"] = index
        good[key] = stored
        files[f"scripts/{digest_hex}.js"] = text.encode("utf-8")
    return good, files, tamper, ambiguous


class _Life:
    def __init__(self, unique: str, frame_id: str, origin: str, worker_target: str = "") -> None:
        self.unique = unique
        self.frame_id = frame_id
        self.origin = origin
        self.worker_target = worker_target


class _Script:
    def __init__(
        self,
        seq: int,
        context_id: int,
        unique: str,
        frame_id: str,
        epoch: int,
        start_line: int,
        start_column: int,
    ) -> None:
        self.seq = seq
        self.context_id = context_id
        self.unique = unique
        self.frame_id = frame_id
        self.epoch = epoch
        self.start_line = start_line
        self.start_column = start_column


class _State:
    def __init__(self) -> None:
        self.contexts: dict[tuple[str, int], _Life] = {}
        self.scripts: dict[tuple[str, str], _Script] = {}
        self.ambiguous: set[tuple[str, str]] = set()
        self.seen: list[tuple[str, str, int]] = []
        self.epochs: dict[tuple[str, str], int] = {}
        self.loaders: dict[tuple[str, str], str] = {}
        self.dead: set[str] = set()
        self.gen: dict[str, int] = {}
        self.child_frames: set[str] = set()
        self.target_ids: dict[str, str] = {}

    def context_created(
        self,
        session: str,
        params: dict[str, Any],
        origin: str,
        allow: set[str] | None = None,
        worker_target: str = "",
    ) -> None:
        if session in self.dead:
            return
        context = params.get("context")
        if not isinstance(context, dict) or type(context.get("id")) is not int:
            return
        if isinstance(context.get("id"), bool):
            return
        unique = context.get("uniqueId")
        context_origin = context.get("origin")
        aux = context.get("auxData")
        frame = aux.get("frameId") if isinstance(aux, dict) else None
        if not isinstance(unique, str) or not isinstance(context_origin, str):
            return
        try:
            normalized = origin_of(context_origin)
        except EvidenceError:
            return
        permitted = allow if allow is not None else {origin}
        if normalized not in permitted:
            return
        if normalized != origin and not worker_target and frame not in self.child_frames:
            return
        if worker_target:
            if isinstance(frame, str):
                return
            frame = ""
        elif not isinstance(frame, str):
            return
        self.contexts[(session, context["id"])] = _Life(unique, frame, context_origin, worker_target)

    def context_destroyed(self, session: str, params: dict[str, Any]) -> None:
        context_id = params.get("executionContextId")
        if type(context_id) is not int:
            return
        life = self.contexts.get((session, context_id))
        unique = params.get("executionContextUniqueId")
        if life is None:
            return
        if isinstance(unique, str) and unique != life.unique:
            return
        self.contexts.pop((session, context_id), None)
        self._drop_scripts(session, unique=life.unique)

    def contexts_cleared(self, session: str) -> None:
        for key in [key for key in self.contexts if key[0] == session]:
            self.contexts.pop(key, None)
        self._drop_scripts(session)

    def navigated(self, session: str, params: dict[str, Any]) -> None:
        if session in self.dead:
            return
        frame = params.get("frame")
        if not isinstance(frame, dict) or not isinstance(frame.get("id"), str):
            return
        frame_id = frame["id"]
        loader = frame.get("loaderId")
        if isinstance(loader, str):
            self.loaders[(session, frame_id)] = loader
        parent = frame.get("parentId")
        if isinstance(parent, str) and parent:
            self.child_frames.add(frame_id)
        key = (session, frame_id)
        self.epochs[key] = self.epochs.get(key, 0) + 1
        self._drop_scripts(session, frame_id=frame_id)

    def detached(self, session: str, params: dict[str, Any]) -> None:
        frame_id = params.get("frameId")
        if not isinstance(frame_id, str):
            return
        self._drop_scripts(session, frame_id=frame_id)
        for key, life in list(self.contexts.items()):
            if key[0] == session and life.frame_id == frame_id:
                self.contexts.pop(key, None)
        self.loaders.pop((session, frame_id), None)

    def target_detached(self, session: str) -> None:
        if not session:
            return
        self.dead.add(session)
        self.gen[session] = self.gen.get(session, 0) + 1
        for key in [key for key in self.contexts if key[0] == session]:
            self.contexts.pop(key, None)
        self._drop_scripts(session)
        for key in [key for key in self.loaders if key[0] == session]:
            self.loaders.pop(key, None)
        for key in [key for key in self.epochs if key[0] == session]:
            self.epochs.pop(key, None)

    def script_parsed(self, session: str, seq: int, params: dict[str, Any]) -> None:
        if session in self.dead:
            return
        script_id = params.get("scriptId")
        context_id = params.get("executionContextId")
        if not isinstance(script_id, str) or type(context_id) is not int or isinstance(context_id, bool):
            return
        ident = (session, script_id)
        self.seen.append((session, script_id, seq))
        if ident in self.ambiguous:
            return
        previous = self.scripts.get(ident)
        if previous is not None and self._script_live(session, previous):
            self.scripts.pop(ident, None)
            self.ambiguous.add(ident)
            return
        life = self.contexts.get((session, context_id))
        if life is None:
            return
        start_line = params.get("startLine")
        start_column = params.get("startColumn")
        if type(start_line) is not int or type(start_column) is not int:
            start_line, start_column = -1, -1
        elif isinstance(start_line, bool) or isinstance(start_column, bool):
            start_line, start_column = -1, -1
        epoch = self.epochs.get((session, life.frame_id), 0)
        self.scripts[ident] = _Script(
            seq, context_id, life.unique, life.frame_id, epoch, start_line, start_column
        )

    def _script_live(self, session: str, script: _Script) -> bool:
        current = self.contexts.get((session, script.context_id))
        if current is None or current.unique != script.unique:
            return False
        return script.epoch == self.epochs.get((session, script.frame_id), 0)

    def _drop_scripts(
        self, session: str, *, unique: str | None = None, frame_id: str | None = None
    ) -> None:
        for key, script in list(self.scripts.items()):
            if key[0] != session:
                continue
            if unique is not None and script.unique != unique:
                continue
            if frame_id is not None and script.frame_id != frame_id:
                continue
            self.scripts.pop(key, None)


def _request(
    state: _State,
    requests: dict[tuple[str, str, int], dict[str, Any]],
    order: list[tuple[str, str, int]],
    sources: dict[tuple[str, int, int, str], dict[str, Any]],
    tamper: set[tuple[str, int, int, str]],
    ambiguous: set[tuple[str, int, int, str]],
    session: str,
    seq: int,
    index: int,
    params: dict[str, Any],
    debuggers: dict[str, str],
    fetched: dict[tuple[str, str], tuple[int, dict[str, Any], bool]],
) -> None:
    request_id = params.get("requestId")
    if not isinstance(request_id, str):
        return
    request_info = params.get("request")
    url = request_info.get("url") if isinstance(request_info, dict) else None
    if not isinstance(url, str):
        url = ""
    slot_key = (session, request_id, state.gen.get(session, 0))
    slot = requests.get(slot_key)
    if slot is None:
        slot = {
            "request_id": request_id,
            "session_id": session,
            "target_id": state.target_ids.get(session, ""),
            "original_ref": f"cdp-trace-original.json#/events/{index}",
            "hops": [],
            "stack_groups": [],
            "gaps": [],
            "observed_identity_bridge": False,
            "async_parent_present": False,
            "_bound": False,
        }
        requests[slot_key] = slot
        order.append(slot_key)
    frame_id = _as_text(params.get("frameId"))
    loader = _as_text(params.get("loaderId"))
    epoch = state.epochs.get((session, frame_id), 0)
    initiator = params.get("initiator")
    stack = initiator.get("stack") if isinstance(initiator, dict) else None
    groups, unresolved, truncated = walk_groups(
        stack,
        f"cdp-trace-original.json#/events/{index}/params/initiator/stack",
        session,
        debuggers=debuggers,
        fetched=fetched,
    )
    gaps: list[str] = []
    if unresolved:
        gaps.append("unresolved_parent_id")
    if truncated:
        gaps.append("async_parent_truncated")
    observed = state.loaders.get((session, frame_id))
    if observed is not None and loader != observed:
        gaps.append("loader_conflict")
    bound_groups = []
    bridged = any(frames for _kind, frames, _group_session, _ref in groups)
    context_unique = ""
    for kind, frames, group_session, request_ref in groups:
        bound_frames = []
        for frame, pointer in frames:
            record, frame_gaps, proven = _bind_frame(
                state,
                sources,
                tamper,
                ambiguous,
                group_session,
                frame,
                frame_id,
                loader,
                epoch,
                pointer,
                kind,
            )
            bound_frames.append(record)
            if not context_unique and isinstance(record.get("context_unique_id"), str):
                context_unique = record["context_unique_id"]
            for gap in frame_gaps:
                if gap not in gaps:
                    gaps.append(gap)
            if not proven:
                bridged = False
        group_row: dict[str, Any] = {"kind": kind, "frames": bound_frames}
        if request_ref:
            group_row["request_ref"] = request_ref
        bound_groups.append(group_row)
    if unresolved or truncated or any(gap in _BLOCKING for gap in gaps):
        bridged = False
    if "loader_conflict" in gaps or "hop_identity_conflict" in gaps:
        for group in bound_groups:
            for record in group["frames"]:
                record["source_ref"] = None
    async_present = any(kind == "async" for kind, _frames, _group_session, _ref in groups)
    hop = {
        "seq": seq,
        "session_id": session,
        "url": url,
        "original_ref": f"cdp-trace-original.json#/events/{index}",
        "frame_id": frame_id,
        "loader_id": loader,
        "epoch": epoch,
        "context_unique_id": context_unique or None,
        "observed_identity_bridge": bridged,
        "async_parent_present": async_present,
        "stack_groups": bound_groups,
        "gaps": gaps,
    }
    slot["hops"].append(hop)
    if not slot["_bound"]:
        slot["stack_groups"] = bound_groups
        slot["gaps"] = list(gaps)
        slot["_bound"] = True
    else:
        for gap in gaps:
            if gap not in slot["gaps"]:
                slot["gaps"].append(gap)
    signatures = {
        (hop_item["frame_id"], hop_item["loader_id"], hop_item["context_unique_id"])
        for hop_item in slot["hops"]
    }
    conflict = len(signatures) > 1
    if conflict and "hop_identity_conflict" not in slot["gaps"]:
        slot["gaps"].append("hop_identity_conflict")
    slot["observed_identity_bridge"] = all(
        hop_item["observed_identity_bridge"] for hop_item in slot["hops"]
    ) and not conflict
    slot["async_parent_present"] = any(hop_item["async_parent_present"] for hop_item in slot["hops"])


def _bind_frame(
    state: _State,
    sources: dict[tuple[str, int, int, str], dict[str, Any]],
    tamper: set[tuple[str, int, int, str]],
    ambiguous: set[tuple[str, int, int, str]],
    session: str,
    frame: Any,
    frame_id: str,
    loader: str,
    epoch: int,
    pointer: str,
    kind: str,
) -> tuple[dict[str, Any], list[str], bool]:
    script_id = frame.get("scriptId") if isinstance(frame, dict) else None
    function_name = frame.get("functionName") if isinstance(frame, dict) else ""
    if not isinstance(script_id, str):
        script_id = ""
    if not isinstance(function_name, str):
        function_name = ""
    record: dict[str, Any] = {
        "script_id": script_id,
        "context_id": "unknown",
        "context_unique_id": None,
        "frame_id": frame_id,
        "loader_id": loader,
        "epoch": epoch,
        "original_ref": pointer,
        "source_ref": None,
        "function_name": function_name,
    }
    if (session, script_id) in state.ambiguous:
        return record, ["source_ambiguous"], False
    life = state.scripts.get((session, script_id))
    if life is None:
        if any(seen_session != session and seen_script == script_id for seen_session, seen_script, _seen_seq in state.seen):
            return record, ["wrong_session"], False
        return record, ["missing_context"], False
    current = state.contexts.get((session, life.context_id))
    if current is None or current.unique != life.unique or life.epoch != state.epochs.get((session, life.frame_id), 0):
        return record, ["missing_context"], False
    record["context_id"] = life.context_id
    record["context_unique_id"] = life.unique
    record["epoch"] = life.epoch
    identity_gaps: list[str] = []
    if current.worker_target:
        if frame_id:
            return record, ["worker_frame_mismatch"], False
        record["frame_id"] = ""
        record["worker_target_id"] = current.worker_target
        record["loader_id"] = None
        identity_gaps.append("loader_unknown")
    elif life.frame_id != frame_id:
        if kind != "async":
            return record, ["frame_mismatch"], False
        record["frame_id"] = frame_id
        record["script_frame_id"] = life.frame_id
        observed = state.loaders.get((session, life.frame_id))
        if observed is None:
            record["loader_id"] = None
            identity_gaps.append("loader_unknown")
        else:
            record["loader_id"] = observed
    key = (session, life.seq, life.context_id, script_id)
    if key in ambiguous:
        return record, ["source_ambiguous"], False
    if key in tamper:
        return record, ["source_tamper"], False
    source = sources.get(key)
    if source is None or source.get("scriptId") != script_id:
        return record, ["missing_context"], False
    if not _column_proven(source.get("sourceText"), frame, life.start_line, life.start_column):
        return record, ["coordinate_unproven"], False
    sha = source["sha256"]
    record["source_ref"] = {
        "script_id": script_id,
        "sha256": sha,
        "seq": life.seq,
        "context_id": life.context_id,
        "relative_path": f"scripts/{sha}.js",
        "original_ref": f"cdp-trace-original.json#/sources/{source['_origin_index']}",
        "network_source": False,
    }
    return record, identity_gaps, not identity_gaps


def _column_proven(text: Any, frame: Any, start_line: int, start_column: int) -> bool:
    if not isinstance(text, str) or not isinstance(frame, dict):
        return False
    if start_line < 0 or start_column < 0:
        return False
    line = frame.get("lineNumber")
    column = frame.get("columnNumber")
    if type(line) is not int or type(column) is not int or isinstance(line, bool) or isinstance(column, bool):
        return False
    if line < start_line or column < 0:
        return False
    line -= start_line
    if line == 0:
        if column < start_column:
            return False
        column -= start_column
    rows = _javascript_lines(text)
    if line >= len(rows) or column > _utf16_units(rows[line]):
        return False
    row = rows[line]
    if column >= _utf16_units(row):
        return True
    encoded = row.encode("utf-16-le")
    unit = int.from_bytes(encoded[column * 2 : column * 2 + 2], "little")
    return not 0xDC00 <= unit <= 0xDFFF


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return ""


def _coverage_gaps(
    requests: dict[tuple[str, str, int], dict[str, Any]], raw_gaps: list[str]
) -> list[str]:
    found: list[str] = list(_ALWAYS_GAPS)
    for gap in raw_gaps:
        if gap not in found:
            found.append(gap)
    for request in requests.values():
        for gap in request["gaps"]:
            if gap not in found:
                found.append(gap)
    return found


def _capture_identity(payload: dict[str, Any]) -> dict[str, Any]:
    capture = payload["capture"]
    identity: dict[str, Any] = {
        "target_id": payload["target_id"],
        "session_id": payload["session_id"],
        "origin": payload["origin"],
        "id": capture["id"],
        "tool_version": capture["tool_version"],
        "started_at": capture["started_at"],
    }
    window = {
        key: capture[key]
        for key in ("debugger_enabled", "async_call_stack_depth")
        if key in capture
    }
    if window:
        identity["window"] = window
    return identity


def _publish(
    out: Path, raw: bytes, receipt: dict[str, Any], files: dict[str, bytes]
) -> dict[str, Any]:
    if not atomic_create_bytes(out / "cdp-trace-original.json", raw):
        raise EvidenceError("artifact_exists_refuse_overwrite")
    attachments: list[dict[str, Any]] = [
        {
            "producer": _PRODUCER,
            "schema_version": _SCHEMA,
            "relative_path": "cdp-trace-original.json",
            "kind": "cdp_trace_original",
            "size": len(raw),
            "sha256": digest(raw),
            "scope": "unverified_external_observation",
        }
    ]
    for name in sorted(files):
        target = out / name
        target.parent.mkdir(parents=True, exist_ok=True)
        blob = files[name]
        if not atomic_create_bytes(target, blob):
            raise EvidenceError("artifact_exists_refuse_overwrite")
        attachments.append(
            {
                "producer": _PRODUCER,
                "schema_version": _SCHEMA,
                "relative_path": name,
                "kind": "script_source",
                "representation": "cdp_source_text_utf8",
                "size": len(blob),
                "sha256": digest(blob),
                "scope": "unverified_external_observation",
            }
        )
    body = dict(receipt)
    body["artifacts"] = attachments
    body["requests"] = [_public_request(item) for item in receipt["requests"]]
    encoded = (json.dumps(body, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    if not atomic_create_bytes(out / "observation.json", encoded):
        raise EvidenceError("receipt_exists_refuse_overwrite")
    return body


def _public_request(item: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if not key.startswith("_")}
