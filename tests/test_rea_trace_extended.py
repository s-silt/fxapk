"""Extended CDP-trace contracts: offsets, parents, related targets, explicit actions."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

_ORIGIN = "http://127.0.0.1:8765"
_OTHER = "https://outside.test"
_SESSION = "SESSION-A"
_CHILD = "SESSION-W"


@pytest.fixture
def plugin_src(monkeypatch: pytest.MonkeyPatch) -> Path:
    src = Path(__file__).parents[1] / "plugins" / "fxapk-rea" / "src"
    monkeypatch.syspath_prepend(str(src))
    return src


def _trace(plugin_src: Path):
    del plugin_src
    return importlib.import_module("fxapk_rea.trace")


def _runtime(plugin_src: Path):
    del plugin_src
    return importlib.import_module("fxapk_rea.trace_runtime")


def _plugin(plugin_src: Path):
    del plugin_src
    return importlib.import_module("fxapk_rea.plugin")


def _sha(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _envelope(events: list, sources: list, **extra: object) -> bytes:
    body = {
        "schema_version": "fxapk-cdp-trace/1",
        "producer": "fxapk-cdp-trace",
        "target_id": "TARGET-1",
        "session_id": _SESSION,
        "origin": _ORIGIN,
        "capture": {
            "id": "00000000-0000-4000-8000-000000000001",
            "tool_version": "synthetic",
            "started_at": "2026-10-12T00:00:00Z",
        },
        "events": events,
        "sources": sources,
        "commands": [],
        "completeness": {"gaps": []},
    }
    body.update(extra)
    return json.dumps(body).encode("utf-8")


def _source(script_id: str, seq: int, context_id: int, text: str, session: str = _SESSION) -> dict:
    return {
        "scriptId": script_id,
        "sessionId": session,
        "seq": seq,
        "contextId": context_id,
        "sourceText": text,
        "sha256": _sha(text),
    }


def _ctx(context_id: int, unique: str, frame: str | None, seq: int, session: str = _SESSION) -> dict:
    aux: dict = {"isDefault": True}
    if frame is not None:
        aux["frameId"] = frame
    else:
        aux["type"] = "worker"
    return {
        "method": "Runtime.executionContextCreated",
        "sessionId": session,
        "seq": seq,
        "params": {
            "context": {
                "id": context_id,
                "uniqueId": unique,
                "origin": _ORIGIN,
                "auxData": aux,
            }
        },
    }


def _parsed(
    script_id: str,
    context_id: int,
    seq: int,
    *,
    session: str = _SESSION,
    start_line: int = 0,
    start_column: int = 0,
) -> dict:
    return {
        "method": "Debugger.scriptParsed",
        "sessionId": session,
        "seq": seq,
        "params": {
            "scriptId": script_id,
            "url": "",
            "executionContextId": context_id,
            "startLine": start_line,
            "startColumn": start_column,
        },
    }


def _request(
    request_id: str,
    frame: str,
    seq: int,
    stack: dict,
    *,
    session: str = _SESSION,
    loader: str = "LOAD-1",
) -> dict:
    return {
        "method": "Network.requestWillBeSent",
        "sessionId": session,
        "seq": seq,
        "params": {
            "requestId": request_id,
            "frameId": frame,
            "loaderId": loader,
            "timestamp": 1.5,
            "documentURL": f"{_ORIGIN}/",
            "request": {"url": f"{_ORIGIN}/api", "method": "GET"},
            "initiator": {"type": "script", "stack": stack},
        },
    }


def _call(script_id: str, line: int, column: int, name: str = "send") -> dict:
    return {
        "functionName": name,
        "scriptId": script_id,
        "url": "",
        "lineNumber": line,
        "columnNumber": column,
    }


def _project(plugin_src: Path, raw: bytes) -> dict:
    receipt, _files = _trace(plugin_src).project_trace(raw)
    assert receipt["coverage"]["status"] == "partial"
    for flag in (
        "click_attribution_verified",
        "target_app_attribution_verified",
        "provenance_authenticated",
        "closure_evaluated",
    ):
        assert receipt[flag] is False
    return receipt


def test_nonzero_inline_offset_uses_relative_line_and_first_column_only(plugin_src: Path) -> None:
    text = "😀XY\r\nb\nc\rd\u2028e\u2029f"
    stack = {"callFrames": [_call("7", 0, 4)]}
    raw = _envelope(
        [_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2, start_line=0, start_column=2), _request("req", "FRAME-1", 5, stack)],
        [_source("7", 2, 1, text)],
    )
    receipt = _project(plugin_src, raw)
    assert receipt["requests"][0]["observed_identity_bridge"] is True
    assert receipt["requests"][0]["stack_groups"][0]["frames"][0]["source_ref"]["relative_path"].endswith(".js")

    low = {"callFrames": [_call("7", 0, 3)]}
    surrogate = _project(
        plugin_src,
        _envelope(
            [_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2, start_line=0, start_column=2), _request("req", "FRAME-1", 5, low)],
            [_source("7", 2, 1, text)],
        ),
    )
    assert "coordinate_unproven" in surrogate["requests"][0]["gaps"]

    later = {"callFrames": [_call("7", 5, 0)]}
    tail = _project(
        plugin_src,
        _envelope(
            [_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2, start_line=0, start_column=2), _request("req", "FRAME-1", 5, later)],
            [_source("7", 2, 1, text)],
        ),
    )
    assert tail["requests"][0]["observed_identity_bridge"] is True

    missing = _parsed("7", 1, 2)
    del missing["params"]["startLine"]
    del missing["params"]["startColumn"]
    refused = _project(
        plugin_src,
        _envelope(
            [_ctx(1, "u1", "FRAME-1", 1), missing, _request("req", "FRAME-1", 5, {"callFrames": [_call("7", 0, 0)]})],
            [_source("7", 2, 1, "f()\n")],
        ),
    )
    assert refused["requests"][0]["observed_identity_bridge"] is False
    assert "coordinate_unproven" in refused["requests"][0]["gaps"]


def test_same_session_cross_frame_async_uses_ancestor_identity(plugin_src: Path) -> None:
    text = "function parent(){return 1}\n"
    child = "function child(){fetch('/api')}\n"
    parent_frame = {
        "callFrames": [_call("9", 0, 0, "parent")],
    }
    stack = {"callFrames": [_call("7", 0, 0, "child")], "parent": parent_frame}
    events = [
        _ctx(1, "u1", "FRAME-A", 1),
        _ctx(2, "u2", "FRAME-B", 2),
        {
            "method": "Page.frameNavigated",
            "sessionId": _SESSION,
            "seq": 3,
            "params": {"frame": {"id": "FRAME-B", "loaderId": "LOAD-B", "url": f"{_ORIGIN}/child"}},
        },
        _parsed("7", 1, 4),
        _parsed("9", 2, 5),
        _request("req", "FRAME-A", 6, stack, loader="LOAD-A"),
    ]
    receipt = _project(
        plugin_src,
        _envelope(events, [_source("7", 4, 1, child), _source("9", 5, 2, text)]),
    )
    groups = receipt["requests"][0]["stack_groups"]
    assert groups[1]["kind"] == "async"
    assert groups[1]["frames"][0]["frame_id"] == "FRAME-A"
    assert groups[1]["frames"][0]["script_frame_id"] == "FRAME-B"
    assert groups[1]["frames"][0]["loader_id"] == "LOAD-B"
    assert receipt["requests"][0]["hops"][0]["frame_id"] == "FRAME-A"
    assert receipt["requests"][0]["observed_identity_bridge"] is True

    unknown = [item for item in events if item["method"] != "Page.frameNavigated"]
    loose = _project(
        plugin_src,
        _envelope(unknown, [_source("7", 4, 1, child), _source("9", 5, 2, text)]),
    )
    ancestor = loose["requests"][0]["stack_groups"][1]["frames"][0]
    assert ancestor["frame_id"] == "FRAME-A"
    assert ancestor["script_frame_id"] == "FRAME-B"
    assert ancestor["loader_id"] is None
    assert "loader_unknown" in loose["requests"][0]["gaps"]
    assert ancestor["context_unique_id"] == "u2"


def test_parent_fetch_keeps_raw_and_refuses_cross_session_guess(plugin_src: Path) -> None:
    text = "function parent(){return 1}\n"
    child = "function child(){fetch('/api')}\n"
    stack = {
        "callFrames": [_call("7", 0, 0, "child")],
        "parentId": {"id": "stack-9", "debuggerId": "dbg-A"},
    }
    fetched = {
        "callFrames": [_call("9", 0, 0, "parent")],
    }
    body_events = [
        _ctx(1, "u1", "FRAME-A", 1),
        _ctx(2, "u2", "FRAME-B", 2),
        {
            "method": "Page.frameNavigated",
            "sessionId": _SESSION,
            "seq": 3,
            "params": {"frame": {"id": "FRAME-B", "loaderId": "LOAD-B", "url": f"{_ORIGIN}/b"}},
        },
        _parsed("7", 1, 4),
        _parsed("9", 2, 5),
        _request("req", "FRAME-A", 6, stack),
    ]
    raw = json.loads(
        _envelope(
            body_events,
            [_source("7", 4, 1, child), _source("9", 5, 2, text)],
        )
    )
    raw["capture"]["debugger_sessions"] = [{"sessionId": _SESSION, "debuggerId": "dbg-A"}]
    raw["parent_stacks"] = [
        {
            "sessionId": _SESSION,
            "debuggerId": "dbg-A",
            "stackTraceId": "stack-9",
            "result": {"stackTrace": fetched},
        }
    ]
    receipt = _project(plugin_src, json.dumps(raw).encode())
    parent = receipt["requests"][0]["stack_groups"][1]
    assert parent["frames"][0]["function_name"] == "parent"
    assert parent["frames"][0]["original_ref"].startswith("cdp-trace-original.json#/parent_stacks/0")
    assert "unresolved_parent_id" not in receipt["requests"][0]["gaps"]

    raw["capture"]["debugger_sessions"] = [{"sessionId": "SESSION-Z", "debuggerId": "dbg-Z"}]
    guessed = _project(plugin_src, json.dumps(raw).encode())
    assert "unresolved_parent_id" in guessed["requests"][0]["gaps"]
    assert len(guessed["requests"][0]["stack_groups"]) == 1

    del raw["parent_stacks"]
    raw["capture"].pop("debugger_sessions")
    legacy = _project(plugin_src, json.dumps(raw).encode())
    assert legacy["schema_version"] == "fxapk-cdp-trace-observation/1"
    assert "unresolved_parent_id" in legacy["requests"][0]["gaps"]


def test_related_worker_is_not_top_frame_and_sessions_do_not_collide(plugin_src: Path) -> None:
    page = "function page(){fetch('/api')}\n"
    worker = "function worker(){fetch('/api')}\n"
    events = [
        _ctx(1, "page-u", "FRAME-TOP", 1),
        _parsed("7", 1, 2),
        _ctx(1, "worker-u", None, 3, session=_CHILD),
        _parsed("7", 1, 4, session=_CHILD),
        _request("w", "", 5, {"callFrames": [_call("7", 0, 0, "worker")]}, session=_CHILD, loader=""),
    ]
    raw = json.loads(_envelope(events, [_source("7", 2, 1, page), _source("7", 4, 1, worker, _CHILD)]))
    raw["targets"] = [
        {
            "sessionId": _CHILD,
            "targetId": "WORKER-1",
            "type": "worker",
            "subtype": "",
            "url": f"{_ORIGIN}/worker.js",
            "parentSessionId": _SESSION,
            "attached": True,
        }
    ]
    receipt = _project(plugin_src, json.dumps(raw).encode())
    frame = receipt["requests"][0]["stack_groups"][0]["frames"][0]
    assert frame["frame_id"] != "FRAME-TOP"
    assert frame["worker_target_id"] == "WORKER-1"
    assert frame["source_ref"]["sha256"] == _sha(worker)
    assert frame["loader_id"] is None
    assert "loader_unknown" in receipt["requests"][0]["gaps"]

    impersonated = json.loads(json.dumps(raw))
    impersonated["events"][2]["params"]["context"]["auxData"] = {"frameId": "FRAME-TOP", "isDefault": True, "type": "worker"}
    blocked = _project(plugin_src, json.dumps(impersonated).encode())
    assert blocked["requests"][0]["observed_identity_bridge"] is False

    foreign = json.loads(json.dumps(raw))
    foreign["targets"][0]["url"] = f"{_OTHER}/worker.js"
    rejected = _project(plugin_src, json.dumps(foreign).encode())
    assert rejected["requests"][0]["observed_identity_bridge"] is False


def test_explicit_actions_stay_unverified(plugin_src: Path) -> None:
    text = "function click(){fetch('/api')}\n"
    raw = json.loads(
        _envelope(
            [
                _ctx(1, "u1", "FRAME-1", 1),
                _parsed("7", 1, 2),
                _request("req", "FRAME-1", 3, {"callFrames": [_call("7", 0, 0, "click")]}),
            ],
            [_source("7", 2, 1, text)],
        )
    )
    raw["actions"] = [
        {"kind": "navigate", "url": f"{_ORIGIN}/next", "ack": True, "timestamp": "2026-10-12T00:00:01Z", "round": 1},
        {"kind": "click", "selector": "#go", "ack": True, "timestamp": "2026-10-12T00:00:02Z", "round": 1},
    ]
    receipt = _project(plugin_src, json.dumps(raw).encode())
    assert [item["kind"] for item in receipt["actions"]] == ["navigate", "click"]
    assert receipt["actions"][0]["original_ref"] == "cdp-trace-original.json#/actions/0"
    assert receipt["actions"][0]["ack"] is True
    assert receipt["click_attribution_verified"] is False


def test_runtime_related_targets_and_actions_use_page_session(plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime(plugin_src)
    origin = _ORIGIN
    peer_box: dict[str, object] = {}

    class _Peer:
        def __init__(self) -> None:
            self.q: list[dict] = []
            self.sent: list[dict] = []

        def send(self, raw: str) -> None:
            message = json.loads(raw)
            self.sent.append(message)
            method = message["method"]
            result: dict = {}
            session = message.get("sessionId")
            if method == "Target.getTargetInfo":
                result = {"targetInfo": {"targetId": "T", "type": "page", "url": origin + "/"}}
            elif method == "Target.attachToTarget":
                result = {"sessionId": "S"}
            elif method == "Runtime.enable" and session == "S":
                self.q.append(
                    {
                        "sessionId": "S",
                        "method": "Runtime.executionContextCreated",
                        "params": {
                            "context": {
                                "id": 1,
                                "uniqueId": "page",
                                "origin": origin,
                                "auxData": {"frameId": "F", "isDefault": True},
                            }
                        },
                    }
                )
            elif method == "Debugger.enable" and session == "S":
                result = {"debuggerId": "dbg-S"}
            elif method == "Target.setAutoAttach":
                if session != "S":
                    result = {}
                else:
                    assert session == "S"
                    self.q.append(
                        {
                            "sessionId": "S",
                            "method": "Target.attachedToTarget",
                            "params": {
                                "sessionId": "SW",
                                "waitingForDebugger": False,
                                "targetInfo": {
                                    "targetId": "WORKER-1",
                                    "type": "worker",
                                    "url": origin + "/worker.js",
                                    "attached": True,
                                },
                            },
                        }
                    )
                    self.q.append(
                        {
                            "sessionId": "S",
                            "method": "Target.attachedToTarget",
                            "params": {
                                "sessionId": "SO",
                                "targetInfo": {
                                    "targetId": "IFRAME-1",
                                    "type": "iframe",
                                    "url": _OTHER + "/frame",
                                },
                            },
                        }
                    )
                    self.q.append(
                        {
                            "sessionId": "S",
                            "method": "Target.attachedToTarget",
                            "params": {
                                "sessionId": "SS",
                                "targetInfo": {
                                    "targetId": "SW-SHARED",
                                    "type": "service_worker",
                                    "url": origin + "/sw.js",
                                },
                            },
                        }
                    )
            elif method == "Debugger.enable" and session == "SW":
                result = {"debuggerId": "dbg-W"}
                self.q.append(
                    {
                        "sessionId": "SW",
                        "method": "Runtime.executionContextCreated",
                        "params": {
                            "context": {
                                "id": 1,
                                "uniqueId": "wu",
                                "origin": origin,
                                "auxData": {"isDefault": True, "type": "worker"},
                            }
                        },
                    }
                )
            elif method == "Page.getFrameTree":
                result = {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": origin + "/"}}}
            elif method == "Page.navigate":
                assert session == "S"
                assert message["params"]["url"] == origin + "/next"
                self.q.append(
                    {
                        "sessionId": "S",
                        "method": "Page.frameNavigated",
                        "params": {"frame": {"id": "F", "loaderId": "L2", "url": origin + "/next"}},
                    }
                )
                self.q.append({"sessionId": "S", "method": "Page.loadEventFired", "params": {}})
                result = {"frameId": "F", "loaderId": "L2"}
            elif method == "DOM.getDocument":
                result = {"root": {"nodeId": 1}}
            elif method == "DOM.querySelector":
                result = {"nodeId": 4}
            elif method == "DOM.getBoxModel":
                result = {"model": {"content": [0, 0, 10, 0, 10, 10, 0, 10]}}
            elif method == "Debugger.getStackTrace":
                result = {"stackTrace": {"callFrames": []}}
            self.q.append({"id": message["id"], "result": result})

        def recv(self, timeout: float | None = None) -> str:
            del timeout
            if not self.q:
                raise TimeoutError()
            return json.dumps(self.q.pop(0))

        def close(self) -> None:
            return None

    peer = _Peer()
    peer_box["peer"] = peer

    def _import(name: str):
        if name == "websockets.sync.client":
            return type("Client", (), {"connect": staticmethod(lambda *a, **k: peer)})()
        return importlib.import_module(name)

    monkeypatch.setattr(runtime.importlib, "import_module", _import)
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *a, **k: type("Sock", (), {"close": lambda self: None})())
    monkeypatch.setattr(
        runtime,
        "_discover",
        lambda *a: ({"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"}, [{"id": "T", "type": "page", "url": origin + "/"}]),
    )
    raw = runtime.capture(
        endpoint="http://127.0.0.1:9999",
        target="T",
        origin=origin,
        observation_ms=0,
        out=tmp_path,
        related_targets=True,
        navigate=origin + "/next",
        click_selector="#go",
    )
    value = json.loads(raw)
    methods = [(item.get("sessionId"), item["method"]) for item in peer.sent]
    assert ("S", "Target.setAutoAttach") in methods
    assert any(item["method"] == "Target.setAutoAttach" and "sessionId" not in item for item in peer.sent) is False
    assert ("SW", "Runtime.enable") in methods
    assert ("SO", "Runtime.enable") not in methods
    assert ("SS", "Runtime.enable") not in methods
    assert any(item["method"] == "Target.detachFromTarget" and item.get("params", {}).get("sessionId") == "SS" for item in peer.sent)
    assert value["actions"][0]["kind"] == "navigate"
    assert value["actions"][0]["ack"] is True
    assert value["actions"][1]["kind"] == "click"
    assert any(item["type"] == "worker" and item["attached"] is True for item in value["targets"])
    assert any(item["type"] == "service_worker" and item["attached"] is False for item in value["targets"])
    enabled = [item for item in value["capture"]["debugger_sessions"] if item["sessionId"] == "S"]
    assert enabled[0]["debuggerId"] == "dbg-S"


def test_off_origin_navigate_and_missing_selector_fail(plugin_src: Path, tmp_path: Path) -> None:
    trace = _trace(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    with pytest.raises(EvidenceError, match="navigate_origin_rejected"):
        trace.run_trace(
            "http://127.0.0.1:9",
            "T",
            _ORIGIN,
            0,
            tmp_path / "nav",
            navigate=f"{_OTHER}/x",
        )
    with pytest.raises(EvidenceError, match="invalid_click_selector"):
        trace.run_trace(
            "http://127.0.0.1:9",
            "T",
            _ORIGIN,
            0,
            tmp_path / "click",
            click_selector="",
        )
    with pytest.raises(EvidenceError, match="related_origin_requires_related_targets"):
        trace.run_trace(
            "http://127.0.0.1:9",
            "T",
            _ORIGIN,
            0,
            tmp_path / "origin",
            related_origin=["https://example.test/path"],
        )
    with pytest.raises(EvidenceError, match="pause_related_start_requires_related_targets"):
        trace.run_trace(
            "http://127.0.0.1:9",
            "T",
            _ORIGIN,
            0,
            tmp_path / "pause",
            pause_related_start=True,
        )
    assert trace.normalize_related_origins(_ORIGIN, ["HTTPS://Example.TEST/a"], True) == [
        _ORIGIN,
        "https://example.test",
    ]


def test_trace_cli_exposes_new_flags(plugin_src: Path) -> None:
    import inspect

    plugin = _plugin(plugin_src)
    info = plugin.ReaPlugin().capabilities()
    assert info["trace"] == "optional_cdp_provider"
    assert info["attach"] == "offline"
    assert "related_targets" in info["trace_scope"]
    names = set(inspect.signature(plugin.trace_command).parameters)
    assert {"related_targets", "navigate", "click_selector", "related_origin", "pause_related_start"} <= names
    assert "related_origin" in info["trace_scope"]
    assert "pause_related_start" in info["trace_scope"]


def test_request_namespace_and_detach_keep_earlier_evidence(plugin_src: Path) -> None:
    page = "function page(){fetch('/api')}\n"
    worker = "function worker(){fetch('/api')}\n"
    events = [
        _ctx(1, "page-u", "FRAME-TOP", 1),
        _parsed("7", 1, 2),
        _request("same", "FRAME-TOP", 3, {"callFrames": [_call("7", 0, 0, "page")]}),
        _ctx(1, "worker-u", None, 4, session=_CHILD),
        _parsed("7", 1, 5, session=_CHILD),
        _request("same", "", 6, {"callFrames": [_call("7", 0, 0, "worker")]}, session=_CHILD, loader=""),
        {
            "method": "Target.detachedFromTarget",
            "sessionId": _SESSION,
            "seq": 7,
            "params": {"sessionId": _CHILD, "targetId": "WORKER-1"},
        },
        _ctx(1, "worker-u", None, 8, session=_CHILD),
        _parsed("7", 1, 9, session=_CHILD),
        _request("same", "", 10, {"callFrames": [_call("7", 0, 0, "worker")]}, session=_CHILD, loader=""),
    ]
    raw = json.loads(
        _envelope(events, [_source("7", 2, 1, page), _source("7", 5, 1, worker, _CHILD), _source("7", 9, 1, worker, _CHILD)])
    )
    raw["capture"]["related_targets"] = True
    raw["targets"] = [
        {
            "sessionId": _CHILD,
            "targetId": "WORKER-1",
            "type": "worker",
            "url": f"{_ORIGIN}/worker.js",
            "parentSessionId": _SESSION,
            "attached": True,
        },
        {
            "sessionId": _CHILD,
            "targetId": "WORKER-1",
            "type": "worker",
            "url": f"{_ORIGIN}/worker.js",
            "parentSessionId": _SESSION,
            "attached": False,
        },
    ]
    receipt = _project(plugin_src, json.dumps(raw).encode())
    assert len(receipt["requests"]) == 3
    by_session = {item["session_id"]: item for item in receipt["requests"] if item["request_id"] == "same" and item["hops"][0]["seq"] != 10}
    assert set(by_session) == {_SESSION, _CHILD}
    assert by_session[_CHILD]["target_id"] == "WORKER-1"
    assert by_session[_CHILD]["hops"][0]["stack_groups"][0]["frames"][0]["source_ref"] is not None
    assert by_session[_SESSION]["observed_identity_bridge"] is True
    late = [item for item in receipt["requests"] if item["hops"][0]["seq"] == 10][0]
    assert late["session_id"] == _CHILD
    assert late["hops"][0]["stack_groups"][0]["frames"][0]["source_ref"] is None

    clash = json.loads(json.dumps(raw))
    clash["targets"][1]["url"] = f"{_OTHER}/worker.js"
    clash["targets"][1]["targetId"] = "WORKER-X"
    blocked = _project(plugin_src, json.dumps(clash).encode())
    assert "related_target_conflict" in blocked["coverage"]["gaps"]
    assert all(item["observed_identity_bridge"] is False or item["session_id"] == _SESSION for item in blocked["requests"])


def test_related_origin_allowlist_and_parent_stack_pointers(plugin_src: Path) -> None:
    text = "function worker(){fetch('/api')}\n"
    parent = "function parent(){return 1}\n"
    events = [
        _ctx(1, "page-u", "FRAME-TOP", 1),
        _parsed("9", 1, 2),
        {
            "method": "Page.frameNavigated",
            "sessionId": _SESSION,
            "seq": 3,
            "params": {"frame": {"id": "F2", "parentId": "FRAME-TOP", "url": f"{_OTHER}/frame", "loaderId": "L2"}},
        },
        _ctx(2, "frame-u", "F2", 4),
        _ctx(1, "worker-u", None, 5, session=_CHILD),
        _parsed("7", 1, 6, session=_CHILD),
        _request(
            "w",
            "",
            7,
            {
                "callFrames": [_call("7", 0, 0, "worker")],
                "parentId": {"id": "stack-1", "debuggerId": "dbg-page"},
            },
            session=_CHILD,
            loader="",
        ),
    ]
    events[3]["params"]["context"]["origin"] = _OTHER
    events[4]["params"]["context"]["origin"] = _OTHER
    events[6]["params"]["documentURL"] = f"{_OTHER}/worker.js"
    events[6]["params"]["request"]["url"] = f"{_OTHER}/api?branch=worker"
    raw = json.loads(_envelope(events, [_source("9", 2, 1, parent), _source("7", 6, 1, text, _CHILD)]))
    raw["capture"]["related_targets"] = True
    raw["capture"]["origin_allowlist"] = [_ORIGIN, _OTHER]
    raw["capture"]["debugger_sessions"] = [
        {"sessionId": _SESSION, "debuggerId": "dbg-page"},
        {"sessionId": _CHILD, "debuggerId": "dbg-worker"},
    ]
    raw["targets"] = [
        {
            "sessionId": _CHILD,
            "targetId": "WORKER-1",
            "type": "worker",
            "url": f"{_OTHER}/worker.js",
            "parentSessionId": _SESSION,
            "attached": True,
        }
    ]
    fetched = {"callFrames": [_call("9", 0, 0, "parent")]}
    raw["parent_stacks"] = [
        {
            "sessionId": _SESSION,
            "debuggerId": "dbg-page",
            "stackTraceId": "stack-1",
            "request": {
                "method": "Debugger.getStackTrace",
                "sessionId": _SESSION,
                "params": {"stackTraceId": {"id": "stack-1", "debuggerId": "dbg-page"}},
            },
            "result": {"stackTrace": fetched},
        }
    ]
    receipt = _project(plugin_src, json.dumps(raw).encode())
    worker_req = receipt["requests"][0]
    assert worker_req["session_id"] == _CHILD
    assert worker_req["stack_groups"][0]["frames"][0]["source_ref"]["sha256"] == _sha(text)
    assert worker_req["stack_groups"][1]["frames"][0]["script_id"] == "9"
    assert worker_req["stack_groups"][1]["frames"][0]["source_ref"]["sha256"] == _sha(parent)
    assert worker_req["stack_groups"][1]["request_ref"].endswith("/parent_stacks/0/request")
    assert "oopif_worker_unsupported" not in receipt["coverage"]["gaps"]

    unknown = json.loads(json.dumps(raw))
    unknown["capture"]["debugger_sessions"] = [{"sessionId": _CHILD, "debuggerId": "dbg-worker"}]
    missed = _project(plugin_src, json.dumps(unknown).encode())
    assert "unresolved_parent_id" in missed["requests"][0]["gaps"]
    assert len(missed["requests"][0]["stack_groups"]) == 1
    assert missed["requests"][0]["stack_groups"][0]["frames"][0]["source_ref"]["sha256"] == _sha(text)

    bare = json.loads(json.dumps(raw))
    del bare["capture"]["origin_allowlist"]
    denied = _project(plugin_src, json.dumps(bare).encode())
    assert denied["requests"][0]["observed_identity_bridge"] is False


def test_uncovered_related_target_is_a_gap(plugin_src: Path) -> None:
    text = "function page(){fetch('/api')}\n"
    raw = json.loads(
        _envelope(
            [
                _ctx(1, "u", "FRAME-TOP", 1),
                _parsed("7", 1, 2),
                _request("p", "FRAME-TOP", 3, {"callFrames": [_call("7", 0, 0, "page")]}),
            ],
            [_source("7", 2, 1, text)],
        )
    )
    raw["capture"]["related_targets"] = True
    raw["targets"] = [
        {
            "sessionId": _CHILD,
            "targetId": "WORKER-1",
            "type": "worker",
            "url": f"{_ORIGIN}/worker.js",
            "parentSessionId": _SESSION,
            "attached": True,
        }
    ]
    receipt = _project(plugin_src, json.dumps(raw).encode())
    assert "related_target_uncovered" in receipt["coverage"]["gaps"]
    assert receipt["requests"][0]["session_id"] == _SESSION


def _peer_capture(runtime, peer, tmp_path: Path, **kwargs):
    import importlib as _importlib

    def _import(name: str):
        if name == "websockets.sync.client":
            return type("Client", (), {"connect": staticmethod(lambda *a, **k: peer)})()
        return original(name)

    original = _importlib.import_module
    previous = (
        runtime.importlib.import_module,
        runtime.socket.create_connection,
        runtime._discover,
    )
    runtime.importlib.import_module = _import
    runtime.socket.create_connection = lambda *a, **k: type("Sock", (), {"close": lambda self: None})()
    runtime._discover = lambda *a: (
        {"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"},
        [{"id": "T", "type": "page", "url": _ORIGIN + "/"}],
    )
    try:
        return runtime.capture(
            endpoint="http://127.0.0.1:9999",
            target="T",
            origin=_ORIGIN,
            observation_ms=0,
            out=tmp_path,
            **kwargs,
        )
    finally:
        (
            runtime.importlib.import_module,
            runtime.socket.create_connection,
            runtime._discover,
        ) = previous


class _ScriptedPeer:
    def __init__(self, handler) -> None:
        self.q: list[dict] = []
        self.sent: list[dict] = []
        self.handler = handler

    def send(self, raw: str) -> None:
        message = json.loads(raw)
        self.sent.append(message)
        result = self.handler(self, message)
        self.q.append({"id": message["id"], "result": result if isinstance(result, dict) else {}})

    def recv(self, timeout: float | None = None) -> str:
        del timeout
        if not self.q:
            raise TimeoutError()
        return json.dumps(self.q.pop(0))

    def close(self) -> None:
        return None


def test_fake_peer_pause_captures_worker_and_rejects_foreign_session(plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime(plugin_src)
    origin = _ORIGIN

    def handler(peer: _ScriptedPeer, message: dict) -> dict:
        method = message["method"]
        session = message.get("sessionId")
        if method == "Target.getTargetInfo":
            return {"targetInfo": {"targetId": "T", "type": "page", "url": origin + "/"}}
        if method == "Target.attachToTarget":
            return {"sessionId": "S"}
        if method == "Debugger.enable" and session == "S":
            return {"debuggerId": "dbg-S"}
        if method == "Target.setAutoAttach" and session == "S":
            assert message["params"]["waitForDebuggerOnStart"] is True
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "SW",
                        "waitingForDebugger": True,
                        "targetInfo": {"targetId": "WORKER-1", "type": "worker", "url": origin + "/worker.js"},
                    },
                }
            )
            peer.q.append(
                {
                    "sessionId": "FAKE",
                    "method": "Network.requestWillBeSent",
                    "params": {
                        "requestId": "nope",
                        "documentURL": origin + "/",
                        "request": {"url": origin + "/api?branch=worker", "method": "GET"},
                    },
                }
            )
        if method == "Network.enable" and session == "SW":
            peer.q.append(
                {
                    "sessionId": "SW",
                    "method": "Network.requestWillBeSent",
                    "params": {
                        "requestId": "w1",
                        "documentURL": origin + "/worker.js",
                        "request": {"url": origin + "/api?branch=worker", "method": "GET"},
                        "initiator": {"type": "script", "stack": {"callFrames": []}},
                    },
                }
            )
        if method == "Debugger.enable" and session == "SW":
            return {"debuggerId": "dbg-W"}
        if method == "Runtime.runIfWaitingForDebugger":
            assert session == "SW"
            return {}
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": origin + "/"}}}
        if method == "Runtime.enable" and session == "S":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Runtime.executionContextCreated",
                    "params": {
                        "context": {
                            "id": 1,
                            "uniqueId": "page",
                            "origin": origin,
                            "auxData": {"frameId": "F", "isDefault": True},
                        }
                    },
                }
            )
        return {}

    peer = _ScriptedPeer(handler)
    monkeypatch.setattr(runtime.importlib, "import_module", lambda name: type("M", (), {"connect": staticmethod(lambda *a, **k: peer)})() if name == "websockets.sync.client" else importlib.import_module(name))
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *a, **k: type("Sock", (), {"close": lambda self: None})())
    monkeypatch.setattr(
        runtime,
        "_discover",
        lambda *a: ({"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"}, [{"id": "T", "type": "page", "url": origin + "/"}]),
    )
    raw = runtime.capture(
        endpoint="http://127.0.0.1:9999",
        target="T",
        origin=origin,
        observation_ms=0,
        out=tmp_path,
        related_targets=True,
        pause_related_start=True,
    )
    value = json.loads(raw)
    worker_events = [item for item in value["events"] if item.get("sessionId") == "SW"]
    assert any(item["method"] == "Network.requestWillBeSent" for item in worker_events)
    assert not any(item.get("sessionId") == "FAKE" for item in value["events"])
    assert value["capture"]["origin_allowlist"] == [origin]
    assert any(item["action"] == "runIfWaitingForDebugger" and item["sessionId"] == "SW" for item in value["capture"]["startup_interventions"])
    resumed = [item for item in peer.sent if item["method"] == "Runtime.runIfWaitingForDebugger"]
    assert resumed and all(item.get("sessionId") == "SW" for item in resumed)


def test_child_cleanup_and_reject_do_not_hide_fatals(plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    def handler(peer: _ScriptedPeer, message: dict) -> dict:
        method = message["method"]
        session = message.get("sessionId")
        if method == "Target.getTargetInfo":
            return {"targetInfo": {"targetId": "T", "type": "page", "url": _ORIGIN + "/"}}
        if method == "Target.attachToTarget":
            return {"sessionId": "S"}
        if method == "Runtime.enable" and session == "S":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Runtime.executionContextCreated",
                    "params": {
                        "context": {"id": 1, "uniqueId": "page", "origin": _ORIGIN, "auxData": {"frameId": "F", "isDefault": True}}
                    },
                }
            )
        if method == "Target.setAutoAttach":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "SW",
                        "waitingForDebugger": False,
                        "targetInfo": {"targetId": "W", "type": "worker", "url": _ORIGIN + "/worker.js"},
                    },
                }
            )
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": _ORIGIN + "/"}}}
        if method == "Target.detachFromTarget" and message.get("params", {}).get("sessionId") == "SW":
            raise TimeoutError("child detach transport")
        return {}

    peer = _ScriptedPeer(handler)
    monkeypatch.setattr(runtime.importlib, "import_module", lambda name: type("M", (), {"connect": staticmethod(lambda *a, **k: peer)})() if name == "websockets.sync.client" else importlib.import_module(name))
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *a, **k: type("Sock", (), {"close": lambda self: None})())
    monkeypatch.setattr(
        runtime,
        "_discover",
        lambda *a: ({"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"}, [{"id": "T", "type": "page", "url": _ORIGIN + "/"}]),
    )
    with pytest.raises(EvidenceError, match="trace_cleanup_failed"):
        runtime.capture(
            endpoint="http://127.0.0.1:9999",
            target="T",
            origin=_ORIGIN,
            observation_ms=0,
            out=tmp_path / "clean",
            related_targets=True,
        )

    client = runtime._Client(object(), __import__("time").monotonic() + 5)
    client.origin = _ORIGIN

    def explode(*_a, **_k):
        raise EvidenceError("trace_oversize")

    client.call = explode
    with pytest.raises(EvidenceError, match="trace_oversize"):
        client._reject_child("SW", "worker")


def test_navigate_error_text_blocks_click_on_old_page(plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    def handler(peer: _ScriptedPeer, message: dict) -> dict:
        method = message["method"]
        session = message.get("sessionId")
        if method == "Target.getTargetInfo":
            return {"targetInfo": {"targetId": "T", "type": "page", "url": _ORIGIN + "/"}}
        if method == "Target.attachToTarget":
            return {"sessionId": "S"}
        if method == "Runtime.enable" and session == "S":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Runtime.executionContextCreated",
                    "params": {
                        "context": {"id": 1, "uniqueId": "page", "origin": _ORIGIN, "auxData": {"frameId": "F", "isDefault": True}}
                    },
                }
            )
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": _ORIGIN + "/"}}}
        if method == "Page.navigate":
            return {"frameId": "F", "loaderId": "L2", "errorText": "net::ERR_FAILED"}
        if method == "DOM.getDocument":
            raise AssertionError("clicked old page")
        return {}

    peer = _ScriptedPeer(handler)
    monkeypatch.setattr(runtime.importlib, "import_module", lambda name: type("M", (), {"connect": staticmethod(lambda *a, **k: peer)})() if name == "websockets.sync.client" else importlib.import_module(name))
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *a, **k: type("Sock", (), {"close": lambda self: None})())
    monkeypatch.setattr(
        runtime,
        "_discover",
        lambda *a: ({"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"}, [{"id": "T", "type": "page", "url": _ORIGIN + "/"}]),
    )
    with pytest.raises(EvidenceError, match="navigate_failed"):
        runtime.capture(
            endpoint="http://127.0.0.1:9999",
            target="T",
            origin=_ORIGIN,
            observation_ms=0,
            out=tmp_path,
            navigate=_ORIGIN + "/next",
            click_selector="#go",
        )


def test_parent_row_must_match_owner_and_nested_gaps_block_bridge(plugin_src: Path) -> None:
    frame = _call("7", 0, 0, "child")
    parent = _call("9", 0, 0, "parent")
    raw = json.loads(
        _envelope(
            [
                _ctx(1, "u1", "FRAME-A", 1),
                _parsed("7", 1, 2),
                _parsed("9", 1, 3),
                _request("req", "FRAME-A", 4, {"callFrames": [frame], "parentId": {"id": "p1", "debuggerId": "d1"}}),
            ],
            [_source("7", 2, 1, "function child(){fetch('/api')}\n"), _source("9", 3, 1, "function parent(){return 1}\n")],
        )
    )
    raw["capture"]["debugger_sessions"] = [{"debuggerId": "d1", "sessionId": _SESSION}]

    def project(row: dict) -> dict:
        cloned = json.loads(json.dumps(raw))
        cloned["parent_stacks"] = [row]
        return _project(plugin_src, json.dumps(cloned).encode())["requests"][0]

    good = {
        "sessionId": _SESSION,
        "debuggerId": "d1",
        "stackTraceId": "p1",
        "request": {
            "method": "Debugger.getStackTrace",
            "sessionId": _SESSION,
            "params": {"stackTraceId": {"id": "p1", "debuggerId": "d1"}},
        },
        "result": {"stackTrace": {"callFrames": [parent]}},
    }
    assert project(good)["observed_identity_bridge"] is True
    foreign = json.loads(json.dumps(good))
    foreign["sessionId"] = "foreign"
    foreign["request"]["sessionId"] = "foreign"
    mismatched = project(foreign)
    assert mismatched["observed_identity_bridge"] is False
    assert mismatched["async_parent_present"] is False
    other = json.loads(json.dumps(good))
    other["result"]["stackTrace"]["callFrames"][0]["scriptId"] = "foreign"
    both = json.loads(json.dumps(raw))
    both["parent_stacks"] = [good, other]
    conflicted = _project(plugin_src, json.dumps(both).encode())["requests"][0]
    assert conflicted["observed_identity_bridge"] is False
    assert conflicted["async_parent_present"] is False
    nested = json.loads(json.dumps(good))
    nested["result"]["stackTrace"]["parentId"] = {"id": "missing", "debuggerId": "d1"}
    missing = project(nested)
    assert missing["observed_identity_bridge"] is False
    assert "unresolved_parent_id" in missing["gaps"]
    cycled = json.loads(json.dumps(good))
    cycled["result"]["stackTrace"]["parentId"] = {"id": "p1", "debuggerId": "d1"}
    cycle = project(cycled)
    assert cycle["observed_identity_bridge"] is False
    assert "unresolved_parent_id" in cycle["gaps"]


def test_child_detach_uses_parent_session_and_natural_detach_is_distinct(
    plugin_src: Path, tmp_path: Path
) -> None:
    runtime = _runtime(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    def base(peer: _ScriptedPeer, message: dict) -> dict:
        method = message["method"]
        session = message.get("sessionId")
        if method == "Target.getTargetInfo":
            return {"targetInfo": {"targetId": "T", "type": "page", "url": _ORIGIN + "/"}}
        if method == "Target.attachToTarget":
            return {"sessionId": "S"}
        if method == "Runtime.enable" and session == "S":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Runtime.executionContextCreated",
                    "params": {
                        "context": {
                            "id": 1,
                            "uniqueId": "page",
                            "origin": _ORIGIN,
                            "auxData": {"frameId": "F", "isDefault": True},
                        }
                    },
                }
            )
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": _ORIGIN + "/"}}}
        return {}

    def alive(peer: _ScriptedPeer, message: dict) -> dict:
        method = message["method"]
        session = message.get("sessionId")
        if method == "Target.setAutoAttach" and session == "S":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "C1",
                        "waitingForDebugger": True,
                        "targetInfo": {"targetId": "W1", "type": "worker", "url": _ORIGIN + "/a.js"},
                    },
                }
            )
        if method == "Target.setAutoAttach" and session == "C1":
            peer.q.append(
                {
                    "sessionId": "C1",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "C2",
                        "waitingForDebugger": False,
                        "targetInfo": {"targetId": "W2", "type": "worker", "url": _ORIGIN + "/b.js"},
                    },
                }
            )
        if method == "Target.detachFromTarget":
            child = message.get("params", {}).get("sessionId")
            if child == "C2":
                assert message.get("sessionId") == "C1"
            elif child == "C1":
                assert message.get("sessionId") == "S"
            elif child == "S":
                assert "sessionId" not in message
        return base(peer, message)

    alive_peer = _ScriptedPeer(alive)
    raw = _peer_capture(
        runtime, alive_peer, tmp_path / "alive", related_targets=True, pause_related_start=True
    )
    value = json.loads(raw)
    assert any(
        item["sessionId"] == "C1" and item["ack"] is True
        for item in value["capture"]["startup_interventions"]
    )
    assert [item.get("params", {}).get("sessionId") for item in alive_peer.sent if item["method"] == "Target.detachFromTarget"][:2] == ["C2", "C1"]

    def failed(peer: _ScriptedPeer, message: dict) -> dict:
        answered = base(peer, message)
        if message["method"] == "Target.setAutoAttach":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "SW",
                        "waitingForDebugger": False,
                        "targetInfo": {"targetId": "W", "type": "worker", "url": _ORIGIN + "/worker.js"},
                    },
                }
            )
        if message["method"] == "Target.detachFromTarget" and message.get("params", {}).get("sessionId") == "SW":
            assert message.get("sessionId") == "S"
            peer.q.append({"id": message["id"], "error": {"message": "No session with given id"}})
        return answered

    peer = _ScriptedPeer(failed)
    with pytest.raises(EvidenceError, match="trace_cleanup_failed"):
        _peer_capture(runtime, peer, tmp_path / "fail", related_targets=True)
    assert any(
        item["method"] == "Target.detachFromTarget"
        and item.get("sessionId") == "S"
        and item.get("params", {}).get("sessionId") == "SW"
        for item in peer.sent
    )

    def natural(peer: _ScriptedPeer, message: dict) -> dict:
        answered = base(peer, message)
        if message["method"] == "Target.setAutoAttach":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "SW",
                        "waitingForDebugger": False,
                        "targetInfo": {"targetId": "W", "type": "worker", "url": _ORIGIN + "/worker.js"},
                    },
                }
            )
            peer.q.append({"sessionId": "S", "method": "Target.detachedFromTarget", "params": {"sessionId": "SW"}})
        if message["method"] == "Target.detachFromTarget" and message.get("params", {}).get("sessionId") == "SW":
            raise AssertionError("natural detach was issued again")
        return answered

    natural_peer = _ScriptedPeer(natural)
    produced = _peer_capture(runtime, natural_peer, tmp_path / "natural", related_targets=True)
    assert json.loads(produced)["capture"]["detach_acked"] is True


def test_array_separator_and_optional_keys_are_precharged(plugin_src: Path) -> None:
    runtime = _runtime(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    client = runtime._Client(object(), __import__("time").monotonic() + 5)
    client.origin = _ORIGIN
    client.session_id = _SESSION
    client.target_id = "T"
    item = {"method": "Page.frameDetached", "sessionId": _SESSION, "seq": 1, "params": {"frameId": "F"}}
    client._charge("events", item)
    client.events.append(item)
    second = {"method": "Page.frameDetached", "sessionId": _SESSION, "seq": 2, "params": {"frameId": "G"}}
    client._charge("events", second)
    client.events.append(second)
    target = {
        "sessionId": "C",
        "targetId": "W",
        "type": "worker",
        "subtype": "",
        "url": _ORIGIN + "/w.js",
        "parentSessionId": _SESSION,
        "attached": True,
    }
    client._charge("targets", target)
    client.targets.append(target)
    body = json.dumps(client._body("T", _SESSION, _ORIGIN), ensure_ascii=False).encode("utf-8")
    assert client._spent == len(body)
    client._spent = runtime._MAX_ENVELOPE - runtime._TAIL_RESERVE + 1
    client._metered = True
    with pytest.raises(EvidenceError, match="trace_oversize"):
        client._fetch_now(
            {"scriptId": "1", "sessionId": _SESSION, "seq": 1, "contextId": 1, "gen": 1, "unique": "u"}
        )


def _page_base(peer: _ScriptedPeer, message: dict) -> dict:
    method = message["method"]
    session = message.get("sessionId")
    if method == "Target.getTargetInfo" and message.get("params", {}).get("targetId", "T") == "T":
        return {"targetInfo": {"targetId": "T", "type": "page", "url": _ORIGIN + "/"}}
    if method == "Target.attachToTarget":
        return {"sessionId": "S"}
    if method == "Runtime.enable" and session == "S":
        peer.q.append(
            {
                "sessionId": "S",
                "method": "Runtime.executionContextCreated",
                "params": {
                    "context": {
                        "id": 1,
                        "uniqueId": "page",
                        "origin": _ORIGIN,
                        "auxData": {"frameId": "F", "isDefault": True},
                    }
                },
            }
        )
    if method == "Page.getFrameTree" and session == "S":
        return {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": _ORIGIN + "/"}}}
    return {}


def test_empty_oopif_url_waits_for_target_id_before_evidence_domains(
    plugin_src: Path, tmp_path: Path
) -> None:
    runtime = _runtime(plugin_src)
    child_url = _ORIGIN + "/oopif-child.html"

    def handler(peer: _ScriptedPeer, message: dict) -> dict:
        method = message["method"]
        session = message.get("sessionId")
        params = message.get("params") or {}
        if method == "Target.getTargetInfo" and params.get("targetId") in {"IF", "DECOY"}:
            return {"targetInfo": {"targetId": params["targetId"], "type": "iframe", "url": ""}}
        if method == "Target.setAutoAttach" and session == "S":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "SI",
                        "waitingForDebugger": True,
                        "targetInfo": {"targetId": "IF", "type": "iframe", "url": ""},
                    },
                }
            )
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "SD",
                        "waitingForDebugger": True,
                        "targetInfo": {"targetId": "DECOY", "type": "iframe", "url": ""},
                    },
                }
            )
        if method == "Runtime.runIfWaitingForDebugger" and session == "SI":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Page.frameNavigated",
                    "params": {"frame": {"id": "LOOKALIKE", "parentId": "F", "url": child_url}},
                }
            )
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.targetInfoChanged",
                    "params": {"targetInfo": {"targetId": "IF", "type": "iframe", "url": child_url}},
                }
            )
        if method == "Page.getFrameTree" and session == "SI":
            return {"frameTree": {"frame": {"id": "OOPIF-F", "loaderId": "OL", "url": child_url}}}
        if method == "Network.enable" and session == "SI":
            peer.q.append(
                {
                    "sessionId": "SI",
                    "method": "Network.requestWillBeSent",
                    "params": {
                        "requestId": "oopif-1",
                        "frameId": "OOPIF-F",
                        "loaderId": "OL",
                        "documentURL": child_url,
                        "request": {"url": _ORIGIN + "/api?branch=oopif", "method": "GET"},
                        "initiator": {"type": "script", "stack": {"callFrames": []}},
                    },
                }
            )
        if method == "Network.enable" and session == "SD":
            raise AssertionError("decoy evidence domain enabled")
        return _page_base(peer, message)

    peer = _ScriptedPeer(handler)
    raw = _peer_capture(
        runtime, peer, tmp_path / "oopif", related_targets=True, pause_related_start=True
    )
    value = json.loads(raw)
    assert any(
        item["method"] == "Network.requestWillBeSent" and item["sessionId"] == "SI"
        for item in value["events"]
    )
    assert not any(item.get("sessionId") == "SD" for item in value["events"])
    assert "related_target_startup_unobserved" in value["completeness"]["gaps"]
    assert "related_target_identity_unresolved" in value["completeness"]["gaps"]
    assert any(
        item["method"] == "Page.enable" and item.get("sessionId") == "SI" for item in peer.sent
    )
    assert any(
        item["method"] == "Page.getFrameTree" and item.get("sessionId") == "SI" for item in peer.sent
    )
    assert any(
        item["method"] == "Target.detachFromTarget" and item.get("params", {}).get("sessionId") == "SD"
        for item in peer.sent
    )
    network_at = next(
        index for index, item in enumerate(peer.sent) if item["method"] == "Network.enable" and item.get("sessionId") == "SI"
    )
    resolved_at = next(
        index
        for index, item in enumerate(peer.sent)
        if item["method"] == "Runtime.runIfWaitingForDebugger" and item.get("sessionId") == "SI"
    )
    assert resolved_at < network_at


def test_empty_url_does_not_admit_without_allowlisted_target_info(
    plugin_src: Path, tmp_path: Path
) -> None:
    runtime = _runtime(plugin_src)

    def foreign(peer: _ScriptedPeer, message: dict) -> dict:
        method = message["method"]
        session = message.get("sessionId")
        params = message.get("params") or {}
        if method == "Target.getTargetInfo" and params.get("targetId") == "IF":
            return {"targetInfo": {"targetId": "IF", "type": "iframe", "url": ""}}
        if method == "Target.setAutoAttach" and session == "S":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "SI",
                        "waitingForDebugger": True,
                        "targetInfo": {"targetId": "IF", "type": "iframe", "url": ""},
                    },
                }
            )
        if method == "Runtime.runIfWaitingForDebugger" and session == "SI":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.targetInfoChanged",
                    "params": {"targetInfo": {"targetId": "IF", "type": "iframe", "url": _OTHER + "/frame"}},
                }
            )
        if method == "Network.enable" and session == "SI":
            raise AssertionError("foreign iframe evidence domain enabled")
        return _page_base(peer, message)

    peer = _ScriptedPeer(foreign)
    raw = _peer_capture(
        runtime, peer, tmp_path / "foreign", related_targets=True, pause_related_start=True
    )
    value = json.loads(raw)
    assert "oopif_origin_rejected" in value["completeness"]["gaps"]
    assert "related_target_startup_unobserved" in value["completeness"]["gaps"]
    assert any(
        item["method"] == "Target.detachFromTarget" and item.get("params", {}).get("sessionId") == "SI"
        for item in peer.sent
    )

    def quiet(peer: _ScriptedPeer, message: dict) -> dict:
        method = message["method"]
        session = message.get("sessionId")
        params = message.get("params") or {}
        if method == "Target.getTargetInfo" and params.get("targetId") == "IF":
            return {"targetInfo": {"targetId": "IF", "type": "iframe", "url": ""}}
        if method == "Target.setAutoAttach" and session == "S":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "SI",
                        "waitingForDebugger": False,
                        "targetInfo": {"targetId": "IF", "type": "iframe", "url": ""},
                    },
                }
            )
        if method == "Runtime.runIfWaitingForDebugger":
            raise AssertionError("resumed an unpaused empty target")
        if method == "Network.enable" and session == "SI":
            raise AssertionError("empty iframe evidence domain enabled")
        return _page_base(peer, message)

    quiet_peer = _ScriptedPeer(quiet)
    quiet_raw = _peer_capture(
        runtime, quiet_peer, tmp_path / "quiet", related_targets=True, pause_related_start=True
    )
    assert "related_target_identity_unresolved" in json.loads(quiet_raw)["completeness"]["gaps"]
    assert not any(item["method"] == "Runtime.runIfWaitingForDebugger" for item in quiet_peer.sent)


def test_natural_detach_drops_paused_child_but_resume_failure_still_raises(
    plugin_src: Path, tmp_path: Path
) -> None:
    runtime = _runtime(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    def natural(peer: _ScriptedPeer, message: dict) -> dict:
        method = message["method"]
        session = message.get("sessionId")
        if method == "Target.setAutoAttach" and session == "S":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "SI",
                        "waitingForDebugger": True,
                        "targetInfo": {"targetId": "IF", "type": "iframe", "url": ""},
                    },
                }
            )
            peer.q.append({"sessionId": "S", "method": "Target.detachedFromTarget", "params": {"sessionId": "SI"}})
        if method == "Target.getTargetInfo" and (message.get("params") or {}).get("targetId") == "IF":
            return {"targetInfo": {"targetId": "IF", "type": "iframe", "url": ""}}
        if method == "Runtime.runIfWaitingForDebugger":
            raise AssertionError("resume after natural detach")
        if method == "Target.detachFromTarget" and (message.get("params") or {}).get("sessionId") == "SI":
            raise AssertionError("detach after natural detach")
        return _page_base(peer, message)

    peer = _ScriptedPeer(natural)
    produced = _peer_capture(
        runtime, peer, tmp_path / "natural-paused", related_targets=True, pause_related_start=True
    )
    assert json.loads(produced)["capture"]["detach_acked"] is True
    assert "related_target_identity_unresolved" in json.loads(produced)["completeness"]["gaps"]

    def broken(peer: _ScriptedPeer, message: dict) -> dict:
        method = message["method"]
        session = message.get("sessionId")
        answered = _page_base(peer, message)
        if method == "Target.setAutoAttach" and session == "S":
            peer.q.append(
                {
                    "sessionId": "S",
                    "method": "Target.attachedToTarget",
                    "params": {
                        "sessionId": "SW",
                        "waitingForDebugger": True,
                        "targetInfo": {"targetId": "W", "type": "worker", "url": _ORIGIN + "/worker.js"},
                    },
                }
            )
        if method == "Runtime.runIfWaitingForDebugger" and session == "SW":
            peer.q.append({"id": message["id"], "error": {"message": "No session with given id"}})
        return answered

    broken_peer = _ScriptedPeer(broken)
    with pytest.raises(EvidenceError, match="related_start_resume_failed"):
        _peer_capture(
            runtime, broken_peer, tmp_path / "resume-fail", related_targets=True, pause_related_start=True
        )


def test_metadata_only_oversize_keeps_minimal_failure_envelope(plugin_src: Path, tmp_path: Path) -> None:
    runtime = _runtime(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    client = runtime._Client(object(), __import__("time").monotonic() + 5)
    client.origin = _ORIGIN
    client.session_id = _SESSION
    client.target_id = "T"
    client._metered = True
    client._spent = runtime._MAX_ENVELOPE - runtime._TAIL_RESERVE - 8
    with pytest.raises(EvidenceError, match="trace_oversize"):
        client._gap("metadata-budget-exceeded")
    assert client.gaps == []

    huge = runtime._Client(object(), __import__("time").monotonic() + 5)
    huge.origin = _ORIGIN
    huge.session_id = _SESSION
    huge.target_id = "T"
    huge.gaps.append("m" * (300 * 1024))
    assert huge.events == [] and huge.sources == []
    runtime._preserve_partial(tmp_path, huge, "T", _SESSION, _ORIGIN, EvidenceError("trace_oversize"))
    raw = (tmp_path / "cdp-trace-original.json").read_bytes()
    assert 0 < len(raw) <= 256 * 1024
    saved = json.loads(raw)
    assert saved["capture"]["stopped_reason"] == "trace_oversize"
    assert saved["events"] == []
    assert saved["sources"] == []
    assert saved["commands"] == []
    assert "trace_oversize" in saved["completeness"]["gaps"]
    assert "m" * 100 not in raw.decode("utf-8")
    assert "complete" not in saved["capture"]
    assert saved["capture"]["debugger_enabled"] == "unknown"
    assert saved["capture"]["commands_summary"]["metadata"] == "omitted"
    assert "metadata_omitted" in saved["completeness"]["gaps"]

    enabled = runtime._Client(object(), __import__("time").monotonic() + 5)
    enabled.origin = _ORIGIN
    enabled.session_id = _SESSION
    enabled.target_id = "T"
    enabled.debugger_enable_observed = True
    enabled.command_acks = ["Debugger.enable", "Runtime.enable"]
    enabled.gaps.append("m" * (300 * 1024))
    runtime._preserve_partial(tmp_path / "enabled", enabled, "T", _SESSION, _ORIGIN, EvidenceError("trace_oversize"))
    enabled_saved = json.loads((tmp_path / "enabled" / "cdp-trace-original.json").read_text(encoding="utf-8"))
    assert enabled_saved["capture"]["debugger_enabled"] is True
    assert enabled_saved["capture"]["commands_summary"]["acked_methods"] == ["Debugger.enable", "Runtime.enable"]
    assert enabled_saved["commands"] == []

    from fxapk_rea.attachment import AttachError, attach

    with pytest.raises(AttachError):
        attach(tmp_path, tmp_path / "missing-report.json", tmp_path / "attached")


def test_malformed_child_url_and_parent_are_not_admitted(plugin_src: Path) -> None:
    runtime = _runtime(plugin_src)
    client = runtime._Client(object(), __import__("time").monotonic() + 5)
    client.origin = _ORIGIN
    client.related_targets = True
    client.session_id = _SESSION
    client.allow_origins = [_ORIGIN]
    client.provisional["C"] = {
        "sessionId": "C",
        "targetId": "IF",
        "type": "iframe",
        "subtype": "",
        "url": "",
        "parentSessionId": _SESSION,
        "attached": False,
    }
    finished: list[object] = []
    client._finish_admission = lambda *args, **kwargs: finished.append(args)
    client._on_target_info({"targetInfo": {"targetId": "IF", "url": None}})
    client._bind_frame_target({"targetId": "IF", "url": 1})
    client._bind_frame_target({"targetId": None, "url": _ORIGIN + "/frame"})
    assert finished == []
    assert "C" in client.provisional
    client.provisional["C"]["parentSessionId"] = None
    rejected: list[object] = []
    client._reject_child = lambda *args, **kwargs: rejected.append(args)
    client._apply_resolved_url("C", _ORIGIN + "/frame")
    assert finished == []
    assert rejected and rejected[0][0] == "C"


def test_transport_failure_survives_cleanup_exception(
    plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """First transport failure stays primary; child-cleanup errors still close the socket."""
    runtime = _runtime(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    class _Peer:
        def __init__(self) -> None:
            self.closed = False
            self.q: list[str] = []
            self.sent: list[dict] = []

        def send(self, raw: str) -> None:
            message = json.loads(raw)
            self.sent.append(message)
            if message["method"] == "Network.enable":
                self.q.append("transport")
                return
            result: dict = {}
            if message["method"] == "Target.attachToTarget":
                result = {"sessionId": "S"}
            elif message["method"] == "Target.getTargetInfo":
                result = {"targetInfo": {"targetId": "T", "type": "page", "url": _ORIGIN + "/"}}
            elif message["method"] == "Page.getFrameTree":
                result = {"frameTree": {"frame": {"id": "F", "url": _ORIGIN + "/"}}}
            self.q.append(json.dumps({"id": message["id"], "result": result}))

        def recv(self, timeout: float | None = None) -> str:
            del timeout
            if not self.q:
                raise TimeoutError()
            item = self.q.pop(0)
            if item == "transport":
                raise ConnectionError("reset")
            return item

        def close(self) -> None:
            self.closed = True

    peer = _Peer()

    def _import(name: str):
        if name == "websockets.sync.client":
            return type("Client", (), {"connect": staticmethod(lambda *a, **k: peer)})()
        return importlib.import_module(name)

    monkeypatch.setattr(runtime.importlib, "import_module", _import)
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *a, **k: type("Sock", (), {"close": lambda self: None})())
    monkeypatch.setattr(
        runtime,
        "_discover",
        lambda *a: (
            {"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"},
            [{"id": "T", "type": "page", "url": _ORIGIN + "/"}],
        ),
    )

    def _boom(*_a, **_k):
        raise EvidenceError("trace_deadline")

    monkeypatch.setattr(runtime, "_cleanup_children", _boom)
    with pytest.raises(EvidenceError, match="cdp_setup_failed"):
        runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=0, out=tmp_path)
    assert peer.closed
    assert any(item.get("method") == "Target.detachFromTarget" for item in peer.sent)
    saved = json.loads((tmp_path / "cdp-trace-original.json").read_text(encoding="utf-8"))
    assert saved["capture"]["stopped_reason"] == "cdp_setup_failed"
    assert "trace_cleanup_failed" in saved["completeness"]["gaps"]
    assert saved["capture"]["socket_closed"] is True


def test_budget_failure_survives_cleanup_exception(plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    class _Peer:
        def __init__(self) -> None:
            self.closed = False
            self.q: list[dict] = []
            self.sent: list[dict] = []

        def send(self, raw: str) -> None:
            message = json.loads(raw)
            self.sent.append(message)
            method = message["method"]
            result: dict = {}
            if method == "Target.getTargetInfo":
                result = {"targetInfo": {"targetId": "T", "type": "page", "url": _ORIGIN + "/"}}
            elif method == "Target.attachToTarget":
                result = {"sessionId": "S"}
            elif method == "Runtime.enable":
                self.q.append(
                    {
                        "sessionId": "S",
                        "method": "Runtime.executionContextCreated",
                        "params": {
                            "context": {
                                "id": 1,
                                "uniqueId": "u1",
                                "origin": _ORIGIN,
                                "auxData": {"frameId": "F", "isDefault": True},
                            }
                        },
                    }
                )
            elif method == "Debugger.enable":
                result = {"debuggerId": "dbg-1"}
                for number in range(6):
                    self.q.append(
                        {
                            "sessionId": "S",
                            "method": "Debugger.scriptParsed",
                            "params": {
                                "scriptId": str(10 + number),
                                "executionContextId": 1,
                                "url": _ORIGIN + "/synthetic.js",
                                "startLine": 0,
                                "startColumn": 0,
                            },
                        }
                    )
            elif method == "Page.getFrameTree":
                result = {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": _ORIGIN + "/"}}}
            elif method == "Debugger.getScriptSource":
                result = {"scriptSource": "a" * 48000}
            self.q.append({"id": message["id"], "result": result})

        def recv(self, timeout: float | None = None) -> str:
            del timeout
            if not self.q:
                raise TimeoutError()
            return json.dumps(self.q.pop(0))

        def close(self) -> None:
            self.closed = True

    peer = _Peer()

    def _import(name: str):
        if name == "websockets.sync.client":
            return type("Client", (), {"connect": staticmethod(lambda *a, **k: peer)})()
        return importlib.import_module(name)

    monkeypatch.setattr(runtime.importlib, "import_module", _import)
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *a, **k: type("Sock", (), {"close": lambda self: None})())
    monkeypatch.setattr(
        runtime,
        "_discover",
        lambda *a: (
            {"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"},
            [{"id": "T", "type": "page", "url": _ORIGIN + "/"}],
        ),
    )
    monkeypatch.setattr(runtime, "_cleanup_children", lambda *_a, **_k: (_ for _ in ()).throw(EvidenceError("cdp_setup_failed")))
    with pytest.raises(EvidenceError, match="trace_oversize"):
        runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=0, out=tmp_path)
    assert peer.closed
    saved = json.loads((tmp_path / "cdp-trace-original.json").read_text(encoding="utf-8"))
    assert saved["capture"]["stopped_reason"] == "trace_oversize"
    assert "trace_cleanup_failed" in saved["completeness"]["gaps"]


def test_gap_budget_during_cleanup_still_closes(plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    class _Peer:
        def __init__(self) -> None:
            self.closed = False
            self.q: list[str] = []

        def send(self, raw: str) -> None:
            message = json.loads(raw)
            result: dict = {}
            if message["method"] == "Target.attachToTarget":
                result = {"sessionId": "S"}
            elif message["method"] == "Target.getTargetInfo":
                result = {"targetInfo": {"targetId": "T", "type": "page", "url": _ORIGIN + "/"}}
            elif message["method"] == "Runtime.enable":
                self.q.append(
                    json.dumps(
                        {
                            "sessionId": "S",
                            "method": "Runtime.executionContextCreated",
                            "params": {
                                "context": {
                                    "id": 1,
                                    "uniqueId": "u1",
                                    "origin": _ORIGIN,
                                    "auxData": {"frameId": "F", "isDefault": True},
                                }
                            },
                        }
                    )
                )
            elif message["method"] == "Page.getFrameTree":
                result = {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": _ORIGIN + "/"}}}
            self.q.append(json.dumps({"id": message["id"], "result": result}))

        def recv(self, timeout: float | None = None) -> str:
            del timeout
            if not self.q:
                raise TimeoutError()
            return self.q.pop(0)

        def close(self) -> None:
            self.closed = True

    peer = _Peer()

    def _import(name: str):
        if name == "websockets.sync.client":
            return type("Client", (), {"connect": staticmethod(lambda *a, **k: peer)})()
        return importlib.import_module(name)

    monkeypatch.setattr(runtime.importlib, "import_module", _import)
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *a, **k: type("Sock", (), {"close": lambda self: None})())
    monkeypatch.setattr(
        runtime,
        "_discover",
        lambda *a: (
            {"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"},
            [{"id": "T", "type": "page", "url": _ORIGIN + "/"}],
        ),
    )
    monkeypatch.setattr(
        runtime,
        "_cleanup_children",
        lambda *_a, **_k: (_ for _ in ()).throw(EvidenceError("trace_deadline")),
    )
    real_gap = runtime._Client._gap

    def _gap(self, name: str) -> None:
        if name == "trace_cleanup_failed":
            raise EvidenceError("trace_oversize")
        real_gap(self, name)

    monkeypatch.setattr(runtime._Client, "_gap", _gap)
    with pytest.raises(EvidenceError, match="trace_deadline"):
        runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=0, out=tmp_path)
    assert peer.closed
    saved = json.loads((tmp_path / "cdp-trace-original.json").read_text(encoding="utf-8"))
    assert saved["capture"]["stopped_reason"] == "trace_deadline"
    assert "trace_cleanup_failed" in saved["completeness"]["gaps"]
    assert saved["capture"]["socket_closed"] is True


def test_blank_iframe_budget_rejects_ninth_and_churn_stays_bounded(
    plugin_src: Path, tmp_path: Path
) -> None:
    runtime = _runtime(plugin_src)
    from fxapk_rea.evidence import EvidenceError

    def handler(count: int):
        def _handler(peer: _ScriptedPeer, message: dict) -> dict:
            method = message["method"]
            session = message.get("sessionId")
            params = message.get("params") or {}
            target_id = params.get("targetId")
            if method == "Target.getTargetInfo" and target_id not in {None, "T"}:
                return {"targetInfo": {"targetId": target_id, "type": "iframe", "url": ""}}
            if method == "Target.setAutoAttach" and session == "S":
                for number in range(count):
                    peer.q.append(
                        {
                            "sessionId": "S",
                            "method": "Target.attachedToTarget",
                            "params": {
                                "sessionId": f"C{number}",
                                "waitingForDebugger": True,
                                "targetInfo": {"targetId": f"T{number}", "type": "iframe", "url": ""},
                            },
                        }
                    )
            return _page_base(peer, message)

        return _handler

    class _ClosingPeer(_ScriptedPeer):
        def __init__(self, on_message) -> None:
            super().__init__(on_message)
            self.closed = False

        def close(self) -> None:
            self.closed = True

    limit = runtime._MAX_CHILD_TARGETS
    within = _ClosingPeer(handler(limit))
    raw = _peer_capture(
        runtime, within, tmp_path / "boundary", related_targets=True, pause_related_start=True
    )
    bounded = json.loads(raw)
    assert bounded["capture"]["socket_closed"] is True
    assert "stopped_reason" not in bounded["capture"]
    assert within.closed
    child_detaches = [
        item
        for item in within.sent
        if item["method"] == "Target.detachFromTarget"
        and (item.get("params") or {}).get("sessionId") != "S"
    ]
    assert len(child_detaches) == limit

    over = _ClosingPeer(handler(limit + 1))
    with pytest.raises(EvidenceError, match="trace_limit"):
        _peer_capture(runtime, over, tmp_path / "over", related_targets=True, pause_related_start=True)
    assert over.closed
    saved = json.loads((tmp_path / "over" / "cdp-trace-original.json").read_text(encoding="utf-8"))
    assert saved["capture"]["stopped_reason"] == "trace_limit"
    assert saved["capture"]["socket_closed"] is True
    assert "child_target_limit" in saved["completeness"]["gaps"]
    ninth = f"C{limit}"
    assert any(
        item["method"] == "Runtime.runIfWaitingForDebugger" and item.get("sessionId") == ninth
        for item in over.sent
    )
    assert any(
        item["method"] == "Target.detachFromTarget"
        and (item.get("params") or {}).get("sessionId") == ninth
        for item in over.sent
    )
    assert any(
        item["method"] == "Target.detachFromTarget" and (item.get("params") or {}).get("sessionId") == "S"
        for item in over.sent
    )

    client = runtime._Client(object(), __import__("time").monotonic() + 30)
    client.session_id = "ROOT"
    client.origin = _ORIGIN
    client.related_targets = True
    client.pause_related_start = True
    client.call = lambda *_args, **_kwargs: {"targetInfo": {"url": ""}}
    for number in range(20):
        client._on_attached(
            {
                "sessionId": f"S{number}",
                "waitingForDebugger": True,
                "targetInfo": {"targetId": f"T{number}", "type": "iframe", "url": ""},
            },
            "ROOT",
        )
        client._on_detached({"sessionId": f"S{number}"})
    assert client.provisional == {}
    assert client.paused_children == []
    assert client.parent_of == {}
    assert len(client.naturally_detached) <= limit
