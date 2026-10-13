"""Optional synchronous CDP collector. Imports websockets only when capture runs."""

from __future__ import annotations

import hashlib
import importlib
import json
import socket
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from apkscan.core.atomic import atomic_create_bytes

from .evidence import EvidenceError, origin_of
from .trace_limits import MAX_COMMANDS, MAX_RAW_BYTES

_MAX_MESSAGE = 256 * 1024
_MAX_ENVELOPE = MAX_RAW_BYTES
# Room for the detach ack and capture.stopped_reason without another full dump per event.
_TAIL_RESERVE = 512
_MAX_HTTP = 64 * 1024
_MAX_EVENTS = 1024
_MAX_SOURCES = 64
_MAX_SOURCE_CHARS = 48 * 1024
# Keep room in the envelope for request/response and identity records.
_MAX_SOURCE_BYTES = 128 * 1024
_MAX_STACK = 32
_MAX_PARENT_FETCHES = 32
_MAX_CHILD_TARGETS = 8
_MAX_CHILD_DEPTH = 4
_OPTIONAL_JSON_KEY = {
    "targets": "targets",
    "actions": "actions",
    "parent_stacks": "parent_stacks",
    "debugger_sessions": "debugger_sessions",
    "interventions": "startup_interventions",
}
_BOOTSTRAP_S = 15.0
_BUDGET_FATAL = frozenset({"trace_oversize", "trace_deadline", "trace_limit"})
_SCHEMA = "fxapk-cdp-trace/1"
_PRODUCER = "fxapk-cdp-trace"
_LIMIT_GAPS = (
    "click_attribution_unavailable",
    "target_app_attribution_unavailable",
    "provenance_unauthenticated",
    "closure_unavailable",
    "oopif_worker_unsupported",
    "attach_before_history_unobserved",
)
_KEEP = frozenset(
    {
        "Page.frameNavigated",
        "Page.frameDetached",
        "Runtime.executionContextCreated",
        "Runtime.executionContextDestroyed",
        "Runtime.executionContextsCleared",
        "Debugger.scriptParsed",
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Network.loadingFailed",
        "Network.loadingFinished",
        "Target.detachedFromTarget",
    }
)


def capture(
    *,
    endpoint: str,
    target: str,
    origin: str,
    observation_ms: int,
    out: Path,
    related_targets: bool = False,
    navigate: str | None = None,
    click_selector: str | None = None,
    related_origins: list[str] | None = None,
    pause_related_start: bool = False,
) -> bytes:
    """Attach one target session, observe, and return the filtered raw envelope."""
    try:
        __import__("websockets.sync.client")
        connect = importlib.import_module("websockets.sync.client").connect
    except ImportError:
        raise EvidenceError("trace_dependency_missing") from None
    deadline = time.monotonic() + (observation_ms / 1000) + _BOOTSTRAP_S
    version, listed = _discover(endpoint, deadline)
    page = _select_target(listed, target, origin)
    ws_url = _browser_socket(version, endpoint)
    host, port = _endpoint_host_port(endpoint)
    sock = socket.create_connection((host, port), timeout=_remaining(deadline))
    try:
        websocket = connect(
            ws_url,
            sock=sock,
            max_size=_MAX_MESSAGE,
            compression=None,
            open_timeout=_remaining(deadline),
            close_timeout=1,
        )
    except Exception:
        sock.close()
        raise EvidenceError("cdp_setup_failed") from None
    client = _Client(websocket, deadline)
    client.origin = origin
    client.related_targets = related_targets
    client.pause_related_start = pause_related_start
    client.allow_origins = [origin, *(related_origins or [])]
    client.navigate_url = navigate
    client.click_selector = click_selector
    client.target_id = page["id"] if isinstance(page.get("id"), str) else target
    session_id = ""
    failed: EvidenceError | None = None
    partial: bytes | None = None
    try:
        try:
            info = client.call("Target.getTargetInfo", {"targetId": page["id"]})
            _recheck_target(info, target, origin)
            attached = client.call(
                "Target.attachToTarget", {"targetId": page["id"], "flatten": True}
            )
            attached_session = attached.get("sessionId") if isinstance(attached, dict) else None
            if not isinstance(attached_session, str) or not attached_session:
                raise EvidenceError("cdp_setup_failed")
            session_id = attached_session
            client.session_id = session_id
            for method in ("Page.enable", "Runtime.enable", "Debugger.enable", "Network.enable"):
                client.call(method, session=session_id)
            client.call(
                "Debugger.setAsyncCallStackDepth",
                {"maxDepth": _MAX_STACK},
                session=session_id,
            )
            if related_targets:
                _auto_attach(client, session_id)
            tree = client.call("Page.getFrameTree", session=session_id)
            top_id = _require_frame_tree(tree, origin)
            client.top_frame = top_id
            if not _same_origin_context(client.contexts, origin):
                _wait_for_context(client, origin)
            _write_ready(out, client.capture_id)
            if navigate is not None:
                _perform_navigate(client, session_id, navigate, origin)
            if click_selector is not None:
                _perform_click(client, session_id, click_selector)
            client.observe_until(observation_ms, top_id)
            client.drain_sources()
        except EvidenceError as exc:
            failed = exc
            client.stop_fetching = True
        except Exception:
            failed = EvidenceError("cdp_setup_failed")
            client.stop_fetching = True
    finally:
        # Children cleanup can raise. Detach and socket close still run, and a
        # later budget error while recording the gap cannot skip the close.
        client.stop_fetching = True
        cleanup_ok = False
        cleanup_error: Exception | None = None
        try:
            cleanup_ok = _cleanup_children(client, failed)
        except Exception as exc:
            cleanup_ok = False
            cleanup_error = exc
        detach_ok = False
        try:
            detach_ok = _detach(client, session_id) if session_id else True
        except Exception:
            detach_ok = False
        socket_ok = False
        try:
            socket_ok = _close_socket(websocket)
        except Exception:
            socket_ok = False
        client.detach_acked = bool(session_id) and detach_ok and cleanup_ok
        client.socket_closed = socket_ok
        cleanup_failed = (
            cleanup_error is not None
            or not cleanup_ok
            or (bool(session_id) and not detach_ok)
            or not socket_ok
        )
        if cleanup_failed:
            try:
                client._gap("trace_cleanup_failed")
            except Exception:
                if "trace_cleanup_failed" not in client.gaps and len(client.gaps) < 64:
                    client.gaps.append("trace_cleanup_failed")
        if failed is None and cleanup_error is not None:
            failed = (
                cleanup_error
                if isinstance(cleanup_error, EvidenceError)
                else EvidenceError("trace_cleanup_failed")
            )
        elif failed is None and cleanup_failed:
            failed = EvidenceError("trace_cleanup_failed")
        if failed is not None:
            client.stop_fetching = True
            try:
                _preserve_partial(out, client, target, session_id or client.session_id, origin, failed)
            except Exception:
                pass
        else:
            try:
                partial = client.envelope(target, session_id, origin)
            except EvidenceError as exc:
                failed = exc
                client.stop_fetching = True
                try:
                    _preserve_partial(out, client, target, session_id, origin, exc)
                except Exception:
                    pass
    if failed is not None:
        raise failed
    if partial is None:
        raise EvidenceError("cdp_setup_failed")
    return partial


def _auto_attach(client: _Client, session_id: str) -> None:
    client.call(
        "Target.setAutoAttach",
        {
            "autoAttach": True,
            "waitForDebuggerOnStart": client.pause_related_start,
            "flatten": True,
            "filter": [{"type": "iframe"}, {"type": "worker"}],
        },
        session=session_id,
    )


def _cleanup_children(client: _Client, pending: BaseException | None) -> bool:
    ok = True
    for child in list(client.provisional):
        try:
            client._abandon_unresolved(child)
        except EvidenceError as exc:
            ok = False
            if str(exc) in _BUDGET_FATAL or str(exc) == "related_start_resume_failed" or client._transport_broken:
                client._gap("trace_cleanup_failed")
                if pending is None:
                    raise
    for child in list(client.paused_children):
        try:
            client._resume(child)
        except EvidenceError as exc:
            ok = False
            if str(exc) in _BUDGET_FATAL or str(exc) == "related_start_resume_failed" or client._transport_broken:
                client._gap("trace_cleanup_failed")
                if pending is None:
                    raise
    ranked = sorted(
        (
            child
            for child in client.attached_children
            if child not in client.naturally_detached
        ),
        key=lambda child: client.target_depth.get(child, 0),
        reverse=True,
    )
    for child in ranked:
        if child not in client.attached_children or child in client.naturally_detached:
            continue
        parent = client.parent_of.get(child)
        if not isinstance(parent, str) or not parent or not _detach(client, child, parent):
            ok = False
    return ok


def _perform_navigate(client: _Client, session_id: str, url: str, origin: str) -> None:
    if origin_of(url) != origin:
        raise EvidenceError("navigate_origin_rejected")
    result = client.call("Page.navigate", {"url": url}, session=session_id)
    error_text = result.get("errorText") if isinstance(result, dict) else None
    failed = not isinstance(result, dict) or (isinstance(error_text, str) and error_text != "")
    loader = result.get("loaderId") if isinstance(result, dict) else None
    client._remember(
        "actions",
        {
            "kind": "navigate",
            "url": url,
            "ack": not failed,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "round": 1,
        },
    )
    if failed:
        raise EvidenceError("navigate_failed")
    if not isinstance(loader, str) or not loader:
        raise EvidenceError("navigate_not_ready")
    while loader not in client.seen_top_loaders or client.load_gen <= client.loader_load_gen.get(loader, client.load_gen):
        if not client.pump_one():
            raise EvidenceError("navigate_not_ready")


def _perform_click(client: _Client, session_id: str, selector: str) -> None:
    client.call("DOM.enable", session=session_id)
    document = client.call("DOM.getDocument", {"depth": 0, "pierce": False}, session=session_id)
    root = document.get("root", {}).get("nodeId") if isinstance(document, dict) else None
    if type(root) is not int or isinstance(root, bool) or root <= 0:
        raise EvidenceError("click_selector_failed")
    found = client.call("DOM.querySelector", {"nodeId": root, "selector": selector}, session=session_id)
    node_id = found.get("nodeId") if isinstance(found, dict) else None
    if type(node_id) is not int or isinstance(node_id, bool) or node_id <= 0:
        raise EvidenceError("click_selector_failed")
    box = client.call("DOM.getBoxModel", {"nodeId": node_id}, session=session_id)
    model = box.get("model") if isinstance(box, dict) else None
    quad = model.get("content") if isinstance(model, dict) else None
    if not isinstance(quad, list) or len(quad) < 8:
        raise EvidenceError("click_selector_failed")
    xs = [quad[index] for index in range(0, 8, 2)]
    ys = [quad[index] for index in range(1, 8, 2)]
    if not all(isinstance(item, (int, float)) and not isinstance(item, bool) for item in xs + ys):
        raise EvidenceError("click_selector_failed")
    x = sum(xs) / 4
    y = sum(ys) / 4
    for name in ("mousePressed", "mouseReleased"):
        client.call(
            "Input.dispatchMouseEvent",
            {"type": name, "x": x, "y": y, "button": "left", "clickCount": 1},
            session=session_id,
        )
    client._remember(
        "actions",
        {
            "kind": "click",
            "selector": selector,
            "ack": True,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "round": 1,
        },
    )


def _discover(endpoint: str, deadline: float) -> tuple[dict[str, Any], list[Any]]:
    version = _http_json(endpoint, "/json/version", deadline)
    listed = _http_json(endpoint, "/json/list", deadline)
    if not isinstance(version, dict) or not isinstance(listed, list):
        raise EvidenceError("cdp_http_failed")
    return version, listed


def _http_json(endpoint: str, path: str, deadline: float) -> Any:
    import http.client

    host, port = _endpoint_host_port(endpoint)
    connection = http.client.HTTPConnection(host, port, timeout=_remaining(deadline))
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        if response.status in (301, 302, 303, 307, 308):
            raise EvidenceError("redirect_refused")
        if response.status != 200:
            raise EvidenceError("cdp_http_failed")
        body = response.read(_MAX_HTTP + 1)
        if len(body) > _MAX_HTTP:
            raise EvidenceError("trace_oversize")
    except EvidenceError:
        raise
    except Exception:
        raise EvidenceError("cdp_http_failed") from None
    finally:
        connection.close()
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        raise EvidenceError("cdp_http_failed") from None


def _select_target(listed: list[Any], target: str, origin: str) -> dict[str, Any]:
    for item in listed:
        if isinstance(item, dict) and item.get("id") == target:
            if item.get("type") != "page":
                raise EvidenceError("target_type_rejected")
            if _url_kind(item.get("url"), origin) != "same":
                raise EvidenceError("target_origin_rejected")
            return item
    raise EvidenceError("target_not_found")


def _recheck_target(result: Any, target: str, origin: str) -> None:
    info = result.get("targetInfo") if isinstance(result, dict) else None
    if not isinstance(info, dict) or info.get("targetId") != target:
        raise EvidenceError("cdp_setup_failed")
    if info.get("type") != "page" or _url_kind(info.get("url"), origin) != "same":
        raise EvidenceError("target_origin_rejected")


def _browser_socket(version: dict[str, Any], endpoint: str) -> str:
    raw = version.get("webSocketDebuggerUrl")
    if not isinstance(raw, str):
        raise EvidenceError("websocket_url_rejected")
    parsed = urlsplit(raw)
    host, port = _endpoint_host_port(endpoint)
    try:
        same_port = parsed.port == port
    except ValueError:
        same_port = False
    if (
        parsed.scheme != "ws"
        or parsed.hostname != host
        or not same_port
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith("/devtools/browser/")
        or parsed.query
        or parsed.fragment
    ):
        raise EvidenceError("websocket_url_rejected")
    return raw


def _endpoint_host_port(endpoint: str) -> tuple[str, int]:
    parsed = urlsplit(endpoint)
    if parsed.hostname is None or parsed.port is None:
        raise EvidenceError("cdp_endpoint_requires_numeric_loopback_http")
    return parsed.hostname, parsed.port


def _require_frame_tree(result: Any, origin: str) -> str:
    tree = result.get("frameTree") if isinstance(result, dict) else None
    frame = tree.get("frame") if isinstance(tree, dict) else None
    if not isinstance(frame, dict) or not isinstance(frame.get("id"), str):
        raise EvidenceError("cdp_setup_failed")
    if _url_kind(frame.get("url"), origin) != "same":
        raise EvidenceError("top_frame_origin_rejected")
    return frame["id"]


def _same_origin_context(contexts: dict[int, dict[str, Any]], origin: str) -> bool:
    return any(item.get("origin") == origin for item in contexts.values())


def _wait_for_context(client: _Client, origin: str) -> None:
    while not _same_origin_context(client.contexts, origin):
        if not client.pump_one():
            raise EvidenceError("no_initial_context")


def _write_ready(out: Path, capture_id: str) -> None:
    payload = {
        "status": "ready",
        "debugger_enabled": True,
        "async_call_stack_depth": _MAX_STACK,
        "capture_id": capture_id,
    }
    raw = (json.dumps(payload, sort_keys=True) + "\n").encode("ascii")
    if not atomic_create_bytes(out / "ready.json", raw):
        raise EvidenceError("artifact_exists_refuse_overwrite")


def _detach(client: _Client, session_id: str, via: str | None = None) -> bool:
    """Detach one session. Child sessions are addressed through their attach parent."""
    if not session_id:
        return False
    try:
        client.call("Target.detachFromTarget", {"sessionId": session_id}, session=via)
    except Exception:
        return False
    return True


def _close_socket(websocket: Any) -> bool:
    try:
        websocket.close()
    except Exception:
        return False
    return True


def _preserve_partial(
    out: Path,
    client: _Client,
    target: str,
    session_id: str,
    origin: str,
    reason: EvidenceError,
) -> None:
    """Write one valid envelope that still names the stop. Never slice broken JSON."""
    reason_code = str(reason)
    while True:
        try:
            raw = client.envelope(target, session_id, origin, stopped_reason=reason_code)
        except EvidenceError as exc:
            if str(exc) != "trace_oversize":
                return
            if client.sources:
                client.sources.pop()
                continue
            if client.events:
                client.events.pop()
                continue
            raw = _minimal_failure(client, target, session_id, origin, reason_code)
        atomic_create_bytes(out / "cdp-trace-original.json", raw)
        return


def _minimal_failure(
    client: _Client,
    target: str,
    session_id: str,
    origin: str,
    reason_code: str,
) -> bytes:
    """Auditable stop record with no oversized metadata and no success claim."""
    gaps = [reason_code]
    for name in client.gaps:
        if name not in gaps and len(name) <= 64 and len(gaps) < 16:
            gaps.append(name)
    observed = client.debugger_enable_observed
    if observed is True:
        debugger_enabled: bool | str = True
    elif observed is False:
        debugger_enabled = False
    else:
        debugger_enabled = "unknown"
        if "metadata_omitted" not in gaps and len(gaps) < 16:
            gaps.append("metadata_omitted")
    body = {
        "schema_version": _SCHEMA,
        "producer": _PRODUCER,
        "target_id": target[:2048],
        "session_id": session_id[:2048] or "unknown",
        "origin": origin[:2048],
        "capture": {
            "id": client.capture_id,
            "tool_version": "0.1.0",
            "started_at": client.started_at,
            "debugger_enabled": debugger_enabled,
            "commands_summary": {
                "metadata": "omitted",
                "acked_methods": list(client.command_acks)[:16],
            },
            "async_call_stack_depth": _MAX_STACK,
            "max_envelope_bytes": _MAX_ENVELOPE,
            "max_source_bytes": _MAX_SOURCE_BYTES,
            "detach_acked": client.detach_acked,
            "socket_closed": client.socket_closed,
            "stopped_reason": reason_code,
        },
        "events": [],
        "sources": [],
        "commands": [],
        "completeness": {
            "gaps": gaps,
            "filtered": {"headers": 0, "cookies": 0, "post_data": 0, "off_origin": 0},
        },
    }
    raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
    if len(raw) > _MAX_ENVELOPE:
        body["completeness"]["gaps"] = [reason_code]
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
    if len(raw) > _MAX_ENVELOPE:
        raise EvidenceError("trace_oversize")
    return raw


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise EvidenceError("trace_deadline")
    return left


def _url_kind(url: Any, origin: str) -> str:
    if not isinstance(url, str) or not url or any(ord(char) < 32 for char in url):
        return "opaque"
    parsed = urlsplit(url)
    if parsed.scheme in ("http", "https"):
        try:
            return "same" if origin_of(url) == origin else "off"
        except EvidenceError:
            return "off"
    return "virtual"


class _Client:
    def __init__(self, websocket: Any, deadline: float) -> None:
        self.websocket = websocket
        self.deadline = deadline
        self.next_id = 0
        self.events: list[dict[str, Any]] = []
        self.commands: list[dict[str, Any]] = []
        self.sent_commands = 0
        self.sources: list[dict[str, Any]] = []
        self.contexts: dict[int, dict[str, Any]] = {}
        self.context_gen: dict[int, int] = {}
        self.filtered = {"headers": 0, "cookies": 0, "post_data": 0, "off_origin": 0}
        self.gaps: list[str] = []
        self.capture_id = str(uuid.uuid4())
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.seq = 0
        self.top_frame = ""
        self.origin = ""
        self.session_id = ""
        self.depth = 0
        self.detach_acked = False
        self.socket_closed = False
        self.fetch_queue: list[dict[str, Any]] = []
        self.source_keys: set[tuple[str, int, int, str]] = set()
        self.source_bytes = 0
        self.target_id = ""
        self._draining = False
        self.stop_fetching = False
        self._metered = False
        self._spent = 0
        self.related_targets = False
        self.pause_related_start = False
        self.allow_origins: list[str] = []
        self.paused_children: list[str] = []
        self.provisional: dict[str, dict[str, Any]] = {}
        self.owned_frames: dict[str, str] = {}
        self.parent_of: dict[str, str] = {}
        self.naturally_detached: set[str] = set()
        self.admitted_children = 0
        self.target_depth: dict[str, int] = {}
        self.seen_top_loaders: set[str] = set()
        self.loader_load_gen: dict[str, int] = {}
        self.load_gen = 0
        self.child_frames: set[str] = set()
        self.interventions: list[dict[str, str]] = []
        self._transport_broken = False
        self.navigate_url: str | None = None
        self.click_selector: str | None = None
        self.actions: list[dict[str, Any]] = []
        self.targets: list[dict[str, Any]] = []
        self.accepted: set[str] = set()
        self.attached_children: list[str] = []
        self.child_contexts: dict[tuple[str, int], dict[str, Any]] = {}
        self.child_gen: dict[tuple[str, int], int] = {}
        self.debugger_by_id: dict[str, str] = {}
        self.debugger_sessions: list[dict[str, str]] = []
        self.debugger_enable_observed: bool | None = None
        self.command_acks: list[str] = []
        self.parent_stacks: list[dict[str, Any]] = []
        self.parent_queue: list[dict[str, str]] = []
        self.parent_seen: set[tuple[str, str]] = set()
        self._pending: list[dict[str, Any]] = []

    def call(self, method: str, params: dict[str, Any] | None = None, session: str | None = None) -> Any:
        cleanup = method in {"Target.detachFromTarget", "Runtime.runIfWaitingForDebugger"}
        limit = MAX_COMMANDS if cleanup else MAX_COMMANDS - (2 * _MAX_CHILD_TARGETS + 1)
        if self.sent_commands >= limit:
            raise EvidenceError("trace_limit")
        self.next_id += 1
        command_id = self.next_id
        message: dict[str, Any] = {"id": command_id, "method": method}
        if params:
            message["params"] = params
        if session:
            message["sessionId"] = session
        self.sent_commands += 1
        self.websocket.send(json.dumps(message))
        self.depth += 1
        succeeded = False
        deferred: list[dict[str, Any]] = []
        try:
            while True:
                incoming = self._recv()
                if incoming.get("id") == command_id:
                    if "error" in incoming:
                        if method == "Debugger.getScriptSource":
                            raise EvidenceError("source_unavailable")
                        raise EvidenceError("cdp_setup_failed")
                    ack = {"method": method, "ack": True}
                    if method == "Debugger.setAsyncCallStackDepth":
                        ack["maxDepth"] = _MAX_STACK
                    self._charge("commands", ack)
                    self.commands.append(ack)
                    if method not in self.command_acks and len(self.command_acks) < 32:
                        self.command_acks.append(method)
                    succeeded = True
                    result = incoming.get("result", {})
                    if method == "Debugger.enable":
                        self.debugger_enable_observed = True
                        if isinstance(session, str):
                            self._note_debugger(session, result)
                    return result
                if "id" in incoming:
                    deferred.append(incoming)
                    continue
                self._on_event(incoming)
        finally:
            if deferred:
                self._pending[0:0] = deferred
            self.depth -= 1
            if succeeded and self.depth == 0 and not self._draining and not self.stop_fetching:
                self._drain_fetches()

    def observe_until(self, observation_ms: int, top_id: str) -> None:
        self.top_frame = top_id
        end = min(self.deadline, time.monotonic() + observation_ms / 1000)
        while time.monotonic() < end:
            if not self.pump_one(end=end):
                break
        self._drain_fetches()

    def drain_sources(self) -> None:
        self._drain_fetches()

    def pump_one(self, end: float | None = None) -> bool:
        try:
            incoming = self._recv(end)
        except EvidenceError as exc:
            if str(exc) == "trace_deadline":
                return False
            raise
        if "method" in incoming and "id" not in incoming:
            self._on_event(incoming)
        return True

    def envelope(
        self,
        target: str,
        session_id: str,
        origin: str,
        stopped_reason: str | None = None,
    ) -> bytes:
        payload = self._body(target, session_id, origin, stopped_reason)
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if len(raw) > _MAX_ENVELOPE:
            raise EvidenceError("trace_oversize")
        return raw

    def _body(
        self,
        target: str,
        session_id: str,
        origin: str,
        stopped_reason: str | None = None,
    ) -> dict[str, Any]:
        capture: dict[str, Any] = {
            "id": self.capture_id,
            "tool_version": "0.1.0",
            "started_at": self.started_at,
            "debugger_enabled": True,
            "async_call_stack_depth": _MAX_STACK,
            "detach_acked": self.detach_acked,
            "socket_closed": self.socket_closed,
        }
        if stopped_reason is not None:
            capture["stopped_reason"] = stopped_reason
        if self.related_targets:
            capture["related_targets"] = True
            capture["origin_allowlist"] = list(self.allow_origins)
        if self.interventions:
            capture["startup_interventions"] = list(self.interventions)
        if self.debugger_sessions:
            capture["debugger_sessions"] = list(self.debugger_sessions)
        body: dict[str, Any] = {
            "schema_version": _SCHEMA,
            "producer": _PRODUCER,
            "target_id": target,
            "session_id": session_id,
            "origin": origin,
            "capture": capture,
            "events": self.events,
            "sources": self.sources,
            "commands": self.commands,
            "completeness": {"gaps": self._complete_gaps(), "filtered": self.filtered},
        }
        if self.parent_stacks:
            body["parent_stacks"] = self.parent_stacks
        if self.targets:
            body["targets"] = self.targets
        if self.actions:
            body["actions"] = self.actions
        return body

    def _charge(self, bucket_name: str, item: dict[str, Any]) -> None:
        """Account one JSON value. Serializes that value only, not the whole envelope."""
        bucket: list[dict[str, Any]] = getattr(self, bucket_name)
        if not self._metered:
            self._spent = len(
                json.dumps(
                    self._body(self.target_id, self.session_id, self.origin),
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            self._metered = True
        extra = self._json_extra(bucket_name, bucket, item)
        if self._spent + extra > _MAX_ENVELOPE - _TAIL_RESERVE:
            raise EvidenceError("trace_oversize")
        self._spent += extra

    def _json_extra(self, bucket_name: str, bucket: list[dict[str, Any]], item: dict[str, Any]) -> int:
        """Byte cost of appending one value. json.dumps joins arrays with ', ' (2 bytes)."""
        encoded = json.dumps(item, ensure_ascii=False).encode("utf-8")
        key = _OPTIONAL_JSON_KEY.get(bucket_name)
        if key is None:
            return len(encoded) + (2 if bucket else 0)
        if bucket:
            return len(encoded) + 2
        wrapped = json.dumps({key: [item]}, ensure_ascii=False).encode("utf-8")
        return 2 + len(wrapped[1:-1])

    def _remember(self, bucket_name: str, item: dict[str, Any]) -> None:
        self._charge(bucket_name, item)
        bucket: list[dict[str, Any]] = getattr(self, bucket_name)
        bucket.append(item)

    def _over_budget(self) -> bool:
        return self._metered and self._spent > _MAX_ENVELOPE - _TAIL_RESERVE

    def _recv(self, end: float | None = None) -> dict[str, Any]:
        if self._pending:
            return self._pending.pop(0)
        limit = self.deadline if end is None else min(self.deadline, end)
        timeout = limit - time.monotonic()
        if timeout <= 0:
            raise EvidenceError("trace_deadline")
        try:
            data = self.websocket.recv(timeout=timeout)
        except TimeoutError:
            raise EvidenceError("trace_deadline") from None
        except Exception:
            self._transport_broken = True
            raise EvidenceError("cdp_setup_failed") from None
        if isinstance(data, bytes):
            raise EvidenceError("cdp_setup_failed")
        try:
            value = json.loads(data)
        except ValueError:
            raise EvidenceError("cdp_setup_failed") from None
        if not isinstance(value, dict):
            raise EvidenceError("cdp_setup_failed")
        return value

    def _on_event(self, incoming: dict[str, Any]) -> None:
        if not self.session_id or not self.origin:
            return
        method = incoming.get("method")
        event_session = incoming.get("sessionId")
        if not isinstance(method, str):
            return
        params = incoming.get("params")
        if not isinstance(params, dict):
            params = {}
        if method == "Target.targetInfoChanged":
            self._on_target_info(params)
            return
        if not isinstance(event_session, str):
            if method != "Target.detachedFromTarget":
                return
            detached_child = params.get("sessionId")
            derived = self.parent_of.get(detached_child) if isinstance(detached_child, str) else None
            if not isinstance(derived, str) or not derived:
                return
            event_session = derived
        if event_session != self.session_id and event_session not in self.accepted:
            return
        if method == "Target.attachedToTarget" and (
            event_session == self.session_id or event_session in self.accepted
        ):
            self._on_attached(params, event_session)
            return
        if method == "Target.detachedFromTarget":
            child = params.get("sessionId")
            if (
                not isinstance(child, str)
                or (
                    child not in self.accepted
                    and child not in self.attached_children
                    and child not in self.provisional
                )
            ):
                return
            self._on_detached(params)
        if method == "Page.frameNavigated" and event_session == self.session_id:
            raw_frame = params.get("frame")
            frame = raw_frame if isinstance(raw_frame, dict) else {}
            frame_id = frame.get("id")
            loader_id = frame.get("loaderId")
            parent_id = frame.get("parentId")
            if isinstance(parent_id, str) and parent_id and isinstance(frame_id, str):
                self.child_frames.add(frame_id)
            self._bind_frame_target(frame)
            if frame_id == self.top_frame and isinstance(loader_id, str):
                self.seen_top_loaders.add(loader_id)
                self.loader_load_gen[loader_id] = self.load_gen
        if method == "Page.loadEventFired" and event_session == self.session_id:
            self.load_gen += 1
        if method == "Runtime.executionContextCreated":
            self._remember_context(event_session, params)
        elif method == "Runtime.executionContextDestroyed":
            self._forget_context(event_session, params)
        elif method == "Runtime.executionContextsCleared":
            self._clear_contexts(event_session)
        elif method == "Page.frameDetached":
            self._drop_frame(event_session, params.get("frameId"))
        if method not in _KEEP:
            return
        if len(self.events) >= _MAX_EVENTS:
            raise EvidenceError("trace_limit")
        self.seq += 1
        stored = self._filter(method, event_session, params, self.origin)
        if stored is None:
            self.seq -= 1
            return
        record = {
            "method": method,
            "sessionId": event_session,
            "seq": self.seq,
            "params": stored,
        }
        self._charge("events", record)
        self.events.append(record)
        if method == "Debugger.scriptParsed":
            self._queue_source(record)
        if method == "Network.requestWillBeSent":
            initiator = stored.get("initiator")
            stack = initiator.get("stack") if isinstance(initiator, dict) else None
            self._collect_parent_ids(event_session, stack)

    def _remember_context(self, session: str, params: dict[str, Any]) -> None:
        context = params.get("context")
        if not isinstance(context, dict) or type(context.get("id")) is not int:
            return
        if not self._origin_allowed(context.get("origin")):
            return
        aux = context.get("auxData") if isinstance(context.get("auxData"), dict) else {}
        frame_id = aux.get("frameId") if isinstance(aux, dict) else None
        if session in self.accepted and self._target_type(session) == "worker":
            if isinstance(frame_id, str):
                self._gap("worker_top_frame_rejected")
                return
        elif session == self.session_id and not self._origin_allowed(context.get("origin"), top=True):
            if not (isinstance(frame_id, str) and frame_id in self.child_frames):
                return
        context_id = context["id"]
        if session == self.session_id:
            generation = self.context_gen.get(context_id, 0) + 1
            self.context_gen[context_id] = generation
            stored = dict(context)
            stored["_gen"] = generation
            self.contexts[context_id] = stored
            return
        key = (session, context_id)
        generation = self.child_gen.get(key, 0) + 1
        self.child_gen[key] = generation
        stored = dict(context)
        stored["_gen"] = generation
        self.child_contexts[key] = stored

    def _forget_context(self, session: str, params: dict[str, Any]) -> None:
        context_id = params.get("executionContextId")
        if type(context_id) is not int:
            return
        if session != self.session_id:
            life = self.child_contexts.get((session, context_id))
            if life is None:
                return
            unique = params.get("executionContextUniqueId")
            if isinstance(unique, str) and unique != life.get("uniqueId"):
                return
            self.child_contexts.pop((session, context_id), None)
            return
        life = self.contexts.get(context_id)
        if life is None:
            return
        unique = params.get("executionContextUniqueId")
        if isinstance(unique, str) and unique != life.get("uniqueId"):
            return
        self.contexts.pop(context_id, None)

    def _clear_contexts(self, session: str) -> None:
        if session != self.session_id:
            for key in [key for key in self.child_contexts if key[0] == session]:
                self.child_gen[key] = self.child_gen.get(key, 0) + 1
                self.child_contexts.pop(key, None)
            return
        for context_id in list(self.contexts):
            self.context_gen[context_id] = self.context_gen.get(context_id, 0) + 1
        self.contexts.clear()

    def _drop_frame(self, session: str, frame_id: Any) -> None:
        if session != self.session_id:
            return
        if not isinstance(frame_id, str):
            return
        for context_id, life in list(self.contexts.items()):
            aux = life.get("auxData")
            if isinstance(aux, dict) and aux.get("frameId") == frame_id:
                self.contexts.pop(context_id, None)

    def _complete_gaps(self) -> list[str]:
        gaps = list(self.gaps)
        for name in _LIMIT_GAPS:
            if name == "oopif_worker_unsupported" and self.related_targets:
                continue
            if name not in gaps:
                gaps.append(name)
        if self.related_targets:
            accepted = [item for item in self.targets if item.get("attached") is True]
            missing = False
            if not accepted:
                missing = True
            for item in accepted:
                session = item.get("sessionId")
                if not any(
                    event.get("sessionId") == session
                    and event.get("method") in {"Debugger.scriptParsed", "Network.requestWillBeSent"}
                    for event in self.events
                ):
                    missing = True
            if missing and "related_target_uncovered" not in gaps:
                gaps.append("related_target_uncovered")
        return gaps

    def _filter(
        self, method: str, session: str, params: dict[str, Any], origin: str | None
    ) -> dict[str, Any] | None:
        if method == "Target.detachedFromTarget":
            return {key: params[key] for key in ("sessionId", "targetId") if isinstance(params.get(key), str)}
        if method == "Runtime.executionContextCreated":
            return self._context_params(params, origin, session)
        if method == "Debugger.scriptParsed":
            return self._script_params(session, params, origin)
        if method == "Network.requestWillBeSent":
            return self._request_params(params, origin)
        if method == "Network.responseReceived":
            return self._response_params(params, origin)
        if method == "Page.frameNavigated":
            return self._frame_params(params, origin)
        if method in (
            "Runtime.executionContextDestroyed",
            "Runtime.executionContextsCleared",
            "Page.frameDetached",
            "Network.loadingFailed",
            "Network.loadingFinished",
        ):
            return _plain(params)
        return None

    def _context_params(
        self, params: dict[str, Any], origin: str | None, session: str
    ) -> dict[str, Any] | None:
        context = params.get("context")
        if not isinstance(context, dict):
            return None
        if origin is not None and not self._origin_allowed(context.get("origin")):
            self.filtered["off_origin"] += 1
            return None
        if (
            origin is not None
            and session == self.session_id
            and not self._origin_allowed(context.get("origin"), top=True)
        ):
            aux_check = _as_dict(context.get("auxData"))
            frame_id = aux_check.get("frameId")
            if not (isinstance(frame_id, str) and frame_id in self.child_frames):
                self.filtered["off_origin"] += 1
                return None
        aux = _as_dict(context.get("auxData"))
        return {
            "context": {
                "id": context.get("id"),
                "uniqueId": context.get("uniqueId"),
                "origin": context.get("origin"),
                "auxData": {"frameId": aux.get("frameId"), "isDefault": aux.get("isDefault")},
            }
        }

    def _script_params(self, session: str, params: dict[str, Any], origin: str | None) -> dict[str, Any] | None:
        context_id = params.get("executionContextId")
        if type(context_id) is not int:
            return None
        life = self._context_for(session, context_id)
        if life is None or (origin is not None and not self._origin_allowed(life.get("origin"))):
            self.filtered["off_origin"] += 1
            return None
        stored = {
            "scriptId": params.get("scriptId"),
            "url": _kept_url(params.get("url"), origin, self.filtered, self.allow_origins),
            "executionContextId": context_id,
            "startLine": params.get("startLine"),
            "startColumn": params.get("startColumn"),
            "hash": params.get("hash"),
        }
        length = params.get("length")
        if type(length) is int and length >= 0:
            stored["length"] = length
        return stored

    def _request_params(self, params: dict[str, Any], origin: str | None) -> dict[str, Any] | None:
        request = _as_dict(params.get("request"))
        self._count_sensitive(request)
        if origin is not None and self._scope_kind(request.get("url")) == "off":
            self.filtered["off_origin"] += 1
            return None
        if origin is not None and self._scope_kind(params.get("documentURL")) == "off":
            self.filtered["off_origin"] += 1
            return None
        initiator = _as_dict(params.get("initiator"))
        stack = initiator.get("stack")
        return {
            "requestId": params.get("requestId"),
            "frameId": params.get("frameId"),
            "loaderId": params.get("loaderId"),
            "timestamp": params.get("timestamp"),
            "documentURL": _kept_url(params.get("documentURL"), origin, self.filtered, self.allow_origins),
            "request": {
                "url": _kept_url(request.get("url"), origin, self.filtered, self.allow_origins),
                "method": request.get("method"),
            },
            "initiator": {
                "type": initiator.get("type"),
                "stack": _sanitize_stack(stack, origin, self.filtered, 0, self.allow_origins),
            },
        }

    def _response_params(self, params: dict[str, Any], origin: str | None) -> dict[str, Any] | None:
        response = _as_dict(params.get("response"))
        self._count_sensitive(response)
        if origin is not None and self._scope_kind(response.get("url")) == "off":
            self.filtered["off_origin"] += 1
            return None
        return {
            "requestId": params.get("requestId"),
            "loaderId": params.get("loaderId"),
            "timestamp": params.get("timestamp"),
            "status": response.get("status"),
        }

    def _frame_params(self, params: dict[str, Any], origin: str | None) -> dict[str, Any] | None:
        frame = _as_dict(params.get("frame"))
        frame_id = frame.get("id")
        kind = self._scope_kind(frame.get("url")) if origin is not None else _url_kind(frame.get("url"), origin or "")
        top = frame.get("parentId") in (None, "") or frame_id == self.top_frame
        if origin is not None and top and not self._origin_allowed(frame.get("url"), top=True) and kind != "opaque":
            if kind == "off" or kind == "same":
                raise EvidenceError("top_frame_origin_rejected")
        if origin is not None and kind == "off":
            self.filtered["off_origin"] += 1
            return None
        return {
            "frame": {
                "id": frame_id,
                "loaderId": frame.get("loaderId"),
                "parentId": frame.get("parentId"),
                "url": _kept_url(frame.get("url"), origin, self.filtered, self.allow_origins),
            }
        }

    def _count_sensitive(self, payload: dict[str, Any]) -> None:
        if "headers" in payload:
            self.filtered["headers"] += 1
        if "cookies" in payload or "cookie" in payload:
            self.filtered["cookies"] += 1
        if "postData" in payload or "postDataEntries" in payload:
            self.filtered["post_data"] += 1

    def _queue_source(self, record: dict[str, Any]) -> None:
        params = record["params"]
        script_id = params.get("scriptId")
        context_id = params.get("executionContextId")
        if not isinstance(script_id, str) or type(context_id) is not int:
            return
        # Chrome reports the script length before source retrieval. Do not ask
        # for a known oversized vendor bundle: the reply can close the bounded
        # WebSocket before any requests are observed. Retain its metadata and
        # an explicit coverage gap, never a truncated or invented source body.
        length = params.get("length")
        if type(length) is int and length > _MAX_SOURCE_CHARS:
            self._gap("source_unavailable")
            return
        life = self._context_for(str(record["sessionId"]), context_id)
        if life is None or not self._origin_allowed(life.get("origin")):
            self._gap("source_unavailable")
            return
        self.fetch_queue.append(
            {
                "scriptId": script_id,
                "sessionId": record["sessionId"],
                "seq": record["seq"],
                "contextId": context_id,
                "length": length,
                "gen": life.get("_gen"),
                "unique": life.get("uniqueId"),
            }
        )
        if self.depth == 0:
            self._drain_fetches()

    def _drain_fetches(self) -> None:
        if self._draining or self.depth != 0 or self.stop_fetching:
            return
        self._draining = True
        try:
            while self.fetch_queue and self.depth == 0 and not self.stop_fetching:
                self._fetch_now(self.fetch_queue.pop(0))
            while (
                self.parent_queue
                and len(self.parent_stacks) < _MAX_PARENT_FETCHES
                and self.depth == 0
                and not self.stop_fetching
            ):
                self._fetch_parent(self.parent_queue.pop(0))
        finally:
            self._draining = False

    def _fetch_now(self, record: dict[str, Any]) -> None:
        script_id = record.get("scriptId")
        context_id = record.get("contextId")
        session = record.get("sessionId")
        if not isinstance(script_id, str) or type(context_id) is not int or not isinstance(session, str):
            return
        if self._over_budget():
            raise EvidenceError("trace_oversize")
        if session != self.session_id and session not in self.accepted:
            self._gap("source_unavailable")
            return
        if not self._lifetime_matches(session, context_id, record.get("gen"), record.get("unique")):
            self._gap("source_unavailable")
            return
        key = (session, record["seq"], context_id, script_id)
        if key in self.source_keys:
            self._gap("source_ambiguous")
            return
        if len(self.sources) >= _MAX_SOURCES:
            raise EvidenceError("trace_limit")
        length = record.get("length")
        if self.source_bytes >= _MAX_SOURCE_BYTES or (
            type(length) is int and length > _MAX_SOURCE_BYTES - self.source_bytes
        ):
            self._gap("source_unavailable")
            return
        try:
            result = self.call("Debugger.getScriptSource", {"scriptId": script_id}, session=session)
        except EvidenceError as exc:
            if str(exc) == "source_unavailable":
                self._gap("source_unavailable")
                return
            raise
        if not self._lifetime_matches(session, context_id, record.get("gen"), record.get("unique")):
            self._gap("source_unavailable")
            return
        text = result.get("scriptSource") if isinstance(result, dict) else None
        if not isinstance(text, str):
            self._gap("source_unavailable")
            return
        if len(text) > _MAX_SOURCE_CHARS:
            raise EvidenceError("trace_oversize")
        encoded = text.encode("utf-8")
        item = {
            "scriptId": script_id,
            "sessionId": session,
            "seq": record["seq"],
            "contextId": context_id,
            "sourceText": text,
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
        source_size = len(json.dumps(item, ensure_ascii=False).encode("utf-8")) + 2
        if self.source_bytes + source_size > _MAX_SOURCE_BYTES:
            self._gap("source_unavailable")
            return
        self._charge("sources", item)
        self.source_bytes += source_size
        self.source_keys.add(key)
        self.sources.append(item)

    def _lifetime_matches(self, session: str, context_id: int, generation: Any, unique: Any) -> bool:
        life = self._context_for(session, context_id)
        if life is None:
            return False
        return life.get("_gen") == generation and life.get("uniqueId") == unique

    def _context_for(self, session: str, context_id: int) -> dict[str, Any] | None:
        if session == self.session_id:
            return self.contexts.get(context_id)
        return self.child_contexts.get((session, context_id))

    def _note_debugger(self, session: str, result: Any) -> None:
        debugger_id = result.get("debuggerId") if isinstance(result, dict) else None
        if not isinstance(debugger_id, str) or not debugger_id:
            return
        previous = self.debugger_by_id.get(debugger_id)
        if previous is not None and previous != session:
            self._gap("debugger_id_ambiguous")
            return
        self.debugger_by_id[debugger_id] = session
        row = {"sessionId": session, "debuggerId": debugger_id}
        if row not in self.debugger_sessions:
            self._remember("debugger_sessions", row)

    def _origin_allowed(self, value: Any, *, top: bool = False) -> bool:
        if not isinstance(value, str) or not value:
            return False
        try:
            norm = origin_of(value)
        except EvidenceError:
            return False
        if top:
            return norm == self.origin
        return norm in self.allow_origins

    def _scope_kind(self, url: Any) -> str:
        return _scope_kind(url, self.allow_origins or [self.origin])

    def _resume(self, child: str) -> None:
        ack = True
        try:
            self.call("Runtime.runIfWaitingForDebugger", session=child)
        except EvidenceError as exc:
            ack = False
            self._gap("related_start_resume_failed")
            self._note_resume(child, ack=False)
            if str(exc) in _BUDGET_FATAL or self._transport_broken:
                raise
            raise EvidenceError("related_start_resume_failed") from None
        if child in self.paused_children:
            self.paused_children.remove(child)
        self._note_resume(child, ack=ack)

    def _note_resume(self, child: str, *, ack: bool) -> None:
        self._remember(
            "interventions",
            {
                "sessionId": child,
                "action": "runIfWaitingForDebugger",
                "ack": ack,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        )

    def _target_type(self, session: str) -> str:
        for item in self.targets:
            if item.get("sessionId") == session and item.get("attached") is True:
                kind = item.get("type")
                return kind if isinstance(kind, str) else ""
        return ""

    def _on_attached(self, params: dict[str, Any], parent: str) -> None:
        if not self.related_targets:
            return
        info = params.get("targetInfo")
        child = params.get("sessionId")
        if not isinstance(info, dict) or not isinstance(child, str) or not child or child == self.session_id:
            return
        if parent != self.session_id and parent not in self.accepted:
            self._gap("related_target_unknown")
            return
        waiting = params.get("waitingForDebugger") is True
        paused = self.pause_related_start and waiting
        record = {
            "sessionId": child,
            "targetId": info.get("targetId") if isinstance(info.get("targetId"), str) else "",
            "type": info.get("type") if isinstance(info.get("type"), str) else "",
            "subtype": info.get("subtype") if isinstance(info.get("subtype"), str) else "",
            "url": info.get("url") if isinstance(info.get("url"), str) else "",
            "parentSessionId": parent,
            "attached": False,
        }
        prior = [
            item
            for item in self.targets
            if item.get("sessionId") == child and item.get("attached") is True
        ]
        if prior:
            previous = prior[0]
            same = (
                previous.get("targetId") == record["targetId"]
                and previous.get("url") == record["url"]
                and previous.get("type") == record["type"]
            )
            if not same:
                self._gap("related_target_conflict")
                self.parent_of[child] = parent
                self._reject_child(child, record["type"], paused=paused)
            elif paused:
                self._resume(child)
            return
        if self._child_budget_blocks(child):
            self._refuse_extra_child(child, parent, paused)
        self.parent_of[child] = parent
        if paused and child not in self.paused_children:
            self.paused_children.append(child)
        if self._identity_pending(record["url"]) and record["type"] in {"iframe", "worker"}:
            if record["subtype"] not in {"shared", "service_worker", "shared_worker"}:
                self.provisional[child] = record
                self._probe_identity(child, paused)
                return
        self._finish_admission(record, parent, paused)

    def _child_budget_blocks(self, child: str) -> bool:
        """Pending and admitted children share one slot budget. Count before insert."""
        if child in self.provisional or child in self.accepted:
            return False
        if len(self.provisional) + self.admitted_children >= _MAX_CHILD_TARGETS:
            return True
        if child not in self.parent_of and len(self.parent_of) >= _MAX_CHILD_TARGETS:
            return True
        return len(self.paused_children) >= _MAX_CHILD_TARGETS

    def _refuse_extra_child(self, child: str, parent: str, paused: bool) -> None:
        """Resume our own pause, detach, then stop. Never keep the extra child paused."""
        self.parent_of[child] = parent
        failure: EvidenceError | None = None
        try:
            if paused:
                try:
                    self._resume(child)
                except EvidenceError as exc:
                    failure = exc
            try:
                self.call("Target.detachFromTarget", {"sessionId": child}, session=parent)
            except EvidenceError as exc:
                if failure is None:
                    if str(exc) in _BUDGET_FATAL or self._transport_broken:
                        failure = exc
                    else:
                        self._gap("related_target_detach_failed")
                        failure = EvidenceError("trace_cleanup_failed")
        finally:
            self._drop_unbilled_child(child)
        if failure is not None:
            raise failure
        self._gap("child_target_limit")
        raise EvidenceError("trace_limit")

    def _drop_unbilled_child(self, child: str) -> None:
        """Drop per-child maps once the child is no longer live. Admitted sessions stay addressable."""
        if child in self.accepted or child in self.attached_children:
            self.naturally_detached.discard(child)
            return
        self.parent_of.pop(child, None)
        self.target_depth.pop(child, None)
        self.provisional.pop(child, None)
        self.naturally_detached.discard(child)
        if child in self.paused_children:
            self.paused_children.remove(child)
        for frame_id, owner in list(self.owned_frames.items()):
            if owner == child:
                self.owned_frames.pop(frame_id, None)
                self.child_frames.discard(frame_id)
        for key in [key for key in self.child_contexts if key[0] == child]:
            self.child_contexts.pop(key, None)
            self.child_gen.pop(key, None)

    def _identity_pending(self, url: str) -> bool:
        if url == "":
            return True
        try:
            origin_of(url)
        except EvidenceError:
            try:
                return urlsplit(url).scheme == "about"
            except ValueError:
                return False
        return False

    def _probe_identity(self, child: str, paused: bool) -> None:
        """One getTargetInfo, then a later targetInfoChanged or frame targetId. No evidence domains."""
        record = self.provisional.get(child)
        if record is None:
            return
        target_id = record.get("targetId")
        if isinstance(target_id, str) and target_id:
            try:
                info = self.call("Target.getTargetInfo", {"targetId": target_id})
            except EvidenceError as exc:
                if str(exc) in _BUDGET_FATAL or self._transport_broken:
                    raise
                info = None
            if child not in self.provisional:
                return
            url = _target_info_url(info)
            if url and not self._identity_pending(url):
                self._apply_resolved_url(child, url)
                return
        if child not in self.provisional:
            return
        if paused and child in self.paused_children and not record.get("identity_resumed"):
            self._gap("related_target_startup_unobserved")
            record["identity_resumed"] = True
            self._resume(child)
            return
        if not paused:
            self._abandon_unresolved(child)

    def _on_target_info(self, params: dict[str, Any]) -> None:
        info = params.get("targetInfo")
        if not isinstance(info, dict):
            return
        target_id = info.get("targetId")
        url = info.get("url")
        if not isinstance(target_id, str) or not target_id:
            return
        if not isinstance(url, str) or self._identity_pending(url):
            return
        for child, record in list(self.provisional.items()):
            if record.get("targetId") == target_id:
                self._apply_resolved_url(child, url)
                return

    def _bind_frame_target(self, frame: dict[str, Any]) -> None:
        """Bind only when the frame payload names the target. Same URL is not identity."""
        target_id = frame.get("targetId")
        url = frame.get("url")
        if not isinstance(target_id, str) or not target_id:
            return
        if not isinstance(url, str) or self._identity_pending(url):
            return
        for child, record in list(self.provisional.items()):
            if record.get("targetId") == target_id:
                self._apply_resolved_url(child, url)
                return

    def _apply_resolved_url(self, child: str, url: str) -> None:
        record = self.provisional.pop(child, None)
        if record is None:
            return
        record["url"] = url
        parent = record.get("parentSessionId")
        paused = child in self.paused_children
        if not isinstance(parent, str) or not parent:
            kind = record.get("type")
            self._reject_child(child, kind if isinstance(kind, str) else "", paused=paused)
            return
        self._finish_admission(record, parent, paused)

    def _finish_admission(self, record: dict[str, Any], parent: str, paused: bool) -> None:
        child = record["sessionId"]
        admitted = self._admit_target(record)
        depth = 1 if parent == self.session_id else self.target_depth.get(parent, 1) + 1
        still_paused = paused and not record.get("identity_resumed")
        over_count = (
            self.admitted_children >= _MAX_CHILD_TARGETS
            or len(self.provisional) + self.admitted_children >= _MAX_CHILD_TARGETS
        )
        if not admitted or over_count or depth > _MAX_CHILD_DEPTH:
            if admitted and (over_count or depth > _MAX_CHILD_DEPTH):
                self._gap("child_target_limit")
            try:
                self._remember("targets", record)
            except EvidenceError:
                self._reject_child(child, record["type"], paused=still_paused)
                raise
            self._reject_child(child, record["type"], paused=still_paused)
            if over_count:
                raise EvidenceError("trace_limit")
            return
        record["attached"] = True
        self.admitted_children += 1
        self.accepted.add(child)
        self.target_depth[child] = depth
        if child not in self.attached_children:
            self.attached_children.append(child)
        self._remember("targets", record)
        self._enable_child(child, depth, str(record.get("type") or ""))
        if still_paused and child in self.paused_children:
            self._resume(child)

    def _enable_child(self, child: str, depth: int, kind: str) -> None:
        methods = ["Network.enable", "Runtime.enable", "Debugger.enable"]
        if kind == "iframe":
            methods.insert(0, "Page.enable")
        for method in methods:
            self.call(method, session=child)
        if kind == "iframe":
            try:
                tree = self.call("Page.getFrameTree", session=child)
            except EvidenceError as exc:
                if str(exc) in _BUDGET_FATAL or self._transport_broken:
                    raise
                self._gap("related_target_frame_unattributed")
            else:
                self._own_frames(child, tree)
        if depth < _MAX_CHILD_DEPTH:
            _auto_attach(self, child)

    def _own_frames(self, session: str, result: Any) -> None:
        tree = result.get("frameTree") if isinstance(result, dict) else None
        found: list[str] = []
        self._walk_frames(tree, found)
        if not found:
            self._gap("related_target_frame_unattributed")
            return
        for frame_id in found:
            owner = self.owned_frames.get(frame_id)
            if owner is not None and owner != session:
                self._gap("related_target_conflict")
                continue
            self.owned_frames[frame_id] = session
            self.child_frames.add(frame_id)

    def _walk_frames(self, node: Any, found: list[str]) -> None:
        if not isinstance(node, dict) or len(found) >= 32:
            return
        frame = node.get("frame")
        if isinstance(frame, dict) and isinstance(frame.get("id"), str) and frame["id"]:
            found.append(frame["id"])
        children = node.get("childFrames")
        if isinstance(children, list):
            for child in children:
                self._walk_frames(child, found)

    def _abandon_unresolved(self, child: str) -> None:
        record = self.provisional.pop(child, None)
        if record is None or child in self.naturally_detached:
            if record is not None:
                self._gap("related_target_identity_unresolved")
            self._drop_unbilled_child(child)
            return
        self._gap("related_target_identity_unresolved")
        try:
            self._remember("targets", record)
        except EvidenceError:
            self._reject_child(child, str(record.get("type") or ""), paused=child in self.paused_children)
            raise
        if child in self.paused_children:
            self._resume(child)
        parent = self.parent_of.get(child)
        try:
            self.call(
                "Target.detachFromTarget",
                {"sessionId": child},
                session=parent if isinstance(parent, str) and parent else None,
            )
        except EvidenceError as exc:
            if str(exc) in _BUDGET_FATAL or self._transport_broken:
                raise
            self._gap("related_target_detach_failed")
            raise EvidenceError("trace_cleanup_failed") from None
        self._drop_unbilled_child(child)

    def _admit_target(self, record: dict[str, Any]) -> bool:
        if record["type"] not in {"iframe", "worker"}:
            return False
        if record["subtype"] in {"shared", "service_worker", "shared_worker"}:
            return False
        try:
            return origin_of(record["url"]) in (self.allow_origins or [self.origin])
        except EvidenceError:
            return False

    def _reject_child(self, child: str, kind: str, paused: bool = False) -> None:
        if kind == "service_worker":
            self._gap("service_worker_unattributed")
        elif kind == "iframe":
            self._gap("oopif_origin_rejected")
        elif kind not in {"iframe", "worker"}:
            self._gap("related_target_unknown")
        else:
            self._gap("related_target_rejected")
        if paused:
            self._resume(child)
        parent = self.parent_of.get(child)
        try:
            self.call(
                "Target.detachFromTarget",
                {"sessionId": child},
                session=parent if isinstance(parent, str) and parent else None,
            )
        except EvidenceError as exc:
            if str(exc) in _BUDGET_FATAL or self._transport_broken:
                raise
            self._gap("related_target_detach_failed")
            raise EvidenceError("trace_cleanup_failed") from None
        self._drop_unbilled_child(child)

    def _on_detached(self, params: dict[str, Any]) -> None:
        child = params.get("sessionId")
        if not isinstance(child, str):
            return
        self.accepted.discard(child)
        self.naturally_detached.add(child)
        if child in self.paused_children:
            self.paused_children.remove(child)
        if child in self.provisional:
            self.provisional.pop(child, None)
            self._gap("related_target_identity_unresolved")
        if child in self.attached_children:
            self.attached_children.remove(child)
        prior = [item for item in self.targets if item.get("sessionId") == child and item.get("attached") is True]
        if not prior:
            self._drop_unbilled_child(child)
            return
        released = dict(prior[0])
        released["attached"] = False
        self._remember("targets", released)
        self._drop_unbilled_child(child)

    def _collect_parent_ids(self, session: str, stack: Any, depth: int = 0) -> None:
        if not isinstance(stack, dict) or depth >= _MAX_STACK:
            return
        parent = stack.get("parent")
        if isinstance(parent, dict):
            self._collect_parent_ids(session, parent, depth + 1)
            return
        parent_id = stack.get("parentId")
        if not isinstance(parent_id, dict):
            return
        stack_id = parent_id.get("id")
        debugger_id = parent_id.get("debuggerId")
        if not isinstance(stack_id, str) or not isinstance(debugger_id, str):
            self._gap("unresolved_parent_id")
            return
        if debugger_id not in self.debugger_by_id:
            self._gap("unresolved_parent_id")
            return
        key = (debugger_id, stack_id)
        if key in self.parent_seen:
            return
        self.parent_queue.append({"id": stack_id, "debuggerId": debugger_id})

    def _fetch_parent(self, item: dict[str, str]) -> None:
        debugger_id = item["debuggerId"]
        stack_id = item["id"]
        owner = self.debugger_by_id.get(debugger_id)
        key = (debugger_id, stack_id)
        if owner is None or key in self.parent_seen:
            self._gap("unresolved_parent_id")
            return
        if len(self.parent_stacks) >= _MAX_PARENT_FETCHES:
            self._gap("parent_fetch_limit")
            return
        if self._over_budget():
            raise EvidenceError("trace_oversize")
        self.parent_seen.add(key)
        try:
            result = self.call(
                "Debugger.getStackTrace",
                {"stackTraceId": {"id": stack_id, "debuggerId": debugger_id}},
                session=owner,
            )
        except EvidenceError:
            self._gap("unresolved_parent_id")
            return
        if not isinstance(result, dict):
            self._gap("unresolved_parent_id")
            return
        self._remember(
            "parent_stacks",
            {
                "sessionId": owner,
                "debuggerId": debugger_id,
                "stackTraceId": stack_id,
                "request": {
                    "method": "Debugger.getStackTrace",
                    "sessionId": owner,
                    "params": {"stackTraceId": {"id": stack_id, "debuggerId": debugger_id}},
                },
                "result": result,
            },
        )
        stack = result.get("stackTrace")
        self._collect_parent_ids(owner, stack, 0)

    def _gap(self, name: str) -> None:
        if name in self.gaps:
            return
        if self._metered:
            extra = len(json.dumps(name, ensure_ascii=False).encode("utf-8")) + (2 if self.gaps else 0)
            if self._spent + extra > _MAX_ENVELOPE - _TAIL_RESERVE:
                raise EvidenceError("trace_oversize")
            self._spent += extra
        self.gaps.append(name)


def _target_info_url(result: Any) -> str:
    info = result.get("targetInfo") if isinstance(result, dict) else None
    if not isinstance(info, dict):
        return ""
    url = info.get("url")
    return url if isinstance(url, str) else ""


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _plain(params: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "executionContextId",
        "executionContextUniqueId",
        "frameId",
        "requestId",
        "timestamp",
        "errorText",
        "encodedDataLength",
    )
    return {key: params.get(key) for key in allowed if key in params}


def _kept_url(
    url: Any, origin: str | None, filtered: dict[str, int], allow: list[str] | None = None
) -> Any:
    if origin is None:
        return url if isinstance(url, str) else None
    kind = _scope_kind(url, allow or [origin])
    if kind == "off":
        filtered["off_origin"] += 1
        return None
    return url if isinstance(url, str) else None


def _scope_kind(url: Any, allow: list[str]) -> str:
    if not isinstance(url, str) or not url or any(ord(char) < 32 for char in url):
        return "opaque"
    parsed = urlsplit(url)
    if parsed.scheme in ("http", "https"):
        try:
            return "same" if origin_of(url) in allow else "off"
        except EvidenceError:
            return "off"
    return "virtual"


def _sanitize_stack(
    stack: Any,
    origin: str | None,
    filtered: dict[str, int],
    depth: int,
    allow: list[str] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(stack, dict):
        return None
    if depth >= _MAX_STACK:
        return {"callFrames": [], "truncated": True}
    frames = []
    raw_frames = stack.get("callFrames")
    if isinstance(raw_frames, list):
        for frame in raw_frames[:_MAX_STACK]:
            if not isinstance(frame, dict):
                frames.append({})
                continue
            frames.append(
                {
                    "functionName": frame.get("functionName"),
                    "scriptId": frame.get("scriptId"),
                    "url": _kept_url(frame.get("url"), origin, filtered, allow),
                    "lineNumber": frame.get("lineNumber"),
                    "columnNumber": frame.get("columnNumber"),
                }
            )
    stored: dict[str, Any] = {"callFrames": frames}
    if stack.get("truncated") is True or (isinstance(raw_frames, list) and len(raw_frames) > _MAX_STACK):
        stored["truncated"] = True
    if isinstance(stack.get("parent"), dict):
        stored["parent"] = _sanitize_stack(stack["parent"], origin, filtered, depth + 1, allow)
    parent_id = stack.get("parentId")
    if isinstance(parent_id, dict):
        stored["parentId"] = {
            "id": parent_id.get("id") if isinstance(parent_id.get("id"), str) else None,
            "debuggerId": parent_id.get("debuggerId")
            if isinstance(parent_id.get("debuggerId"), str)
            else None,
        }
    return stored
