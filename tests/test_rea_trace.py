"""RED contracts for pure fxapk_rea.trace.project_trace and CDP-trace intake refusal."""

from __future__ import annotations

import gzip
import hashlib
import importlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan.core.models import AnalysisConfig
from apkscan.core.redact import safe_exception_text
from apkscan.core.webctx import load_web_evidence

_DIAGNOSTIC = "unverified REA observation cannot be admitted as direct case evidence"
_ORIGIN = "http://127.0.0.1:8765"
_SESSION = "SESSION-A"
_OTHER = "SESSION-B"
_MAX_RAW = 256 * 1024


@pytest.fixture
def plugin_src(monkeypatch: pytest.MonkeyPatch) -> Path:
    src = Path(__file__).parents[1] / "plugins" / "fxapk-rea" / "src"
    monkeypatch.syspath_prepend(str(src))
    return src


def _trace(plugin_src: Path):
    del plugin_src
    spec = importlib.util.find_spec("fxapk_rea.trace")
    assert spec is not None and spec.origin
    return importlib.import_module("fxapk_rea.trace")


def _plugin(plugin_src: Path):
    del plugin_src
    spec = importlib.util.find_spec("fxapk_rea.plugin")
    assert spec is not None
    return importlib.import_module("fxapk_rea.plugin")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ctx(context_id: int, unique: str, frame: str, seq: int) -> dict:
    return {
        "method": "Runtime.executionContextCreated",
        "sessionId": _SESSION,
        "seq": seq,
        "params": {
            "context": {
                "id": context_id,
                "uniqueId": unique,
                "origin": _ORIGIN,
                "auxData": {"frameId": frame, "isDefault": True},
            }
        },
    }


def _parsed(script_id: str, context_id: int, seq: int, session: str = _SESSION) -> dict:
    return {
        "method": "Debugger.scriptParsed",
        "sessionId": session,
        "seq": seq,
        "params": {
            "scriptId": script_id,
            "url": f"{_ORIGIN}/app.js",
            "executionContextId": context_id,
            "startLine": 0,
            "startColumn": 0,
            "hash": "cdp-hash-not-bytes",
        },
    }


def _request(
    request_id: str,
    frame: str,
    seq: int,
    *,
    url: str = f"{_ORIGIN}/api",
    script_id: str = "7",
    column: int = 0,
    parent: dict | None = None,
    loader: str = "LOAD-1",
) -> dict:
    stack: dict = {
        "callFrames": [
            {
                "functionName": "click",
                "scriptId": script_id,
                "url": f"{_ORIGIN}/app.js",
                "lineNumber": 0,
                "columnNumber": column,
            }
        ]
    }
    if parent is not None:
        stack["parent"] = parent
    return {
        "method": "Network.requestWillBeSent",
        "sessionId": _SESSION,
        "seq": seq,
        "params": {
            "requestId": request_id,
            "frameId": frame,
            "loaderId": loader,
            "timestamp": seq / 1000,
            "documentURL": f"{_ORIGIN}/",
            "request": {"url": url, "method": "GET"},
            "initiator": {"type": "script", "stack": stack},
        },
    }


def _raw(events: list, sources: list | None = None) -> bytes:
    text = "function click(){fetch('/api')}\n"
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
        "sources": sources
        if sources is not None
        else [
            {
                "scriptId": "7",
                "sessionId": _SESSION,
                "seq": 2,
                "contextId": 1,
                "sourceText": text,
                "sha256": _sha(text),
            }
        ],
        "commands": [],
        "completeness": {"gaps": []},
    }
    return json.dumps(body).encode("utf-8")


def _project(plugin_src: Path, raw: bytes):
    receipt, files = _trace(plugin_src).project_trace(raw)
    assert receipt["schema_version"] == "fxapk-cdp-trace-observation/1"
    assert receipt["producer"] == "fxapk-cdp-trace"
    assert receipt["coverage"]["status"] == "partial"
    for flag in (
        "click_attribution_verified",
        "target_app_attribution_verified",
        "provenance_authenticated",
        "closure_evaluated",
    ):
        assert receipt[flag] is False
    assert isinstance(files, dict)
    return receipt


def _frame(receipt: dict, request_id: str, index: int = 0) -> dict:
    request = next(item for item in receipt["requests"] if item["request_id"] == request_id)
    return request["stack_groups"][0]["frames"][index]


def test_same_url_two_frames_keep_distinct_identity(plugin_src: Path) -> None:
    raw = _raw(
        [
            _ctx(1, "u1", "FRAME-1", 1),
            _parsed("7", 1, 2),
            _ctx(2, "u2", "FRAME-2", 3),
            _parsed("8", 2, 4),
            _request("req-1", "FRAME-1", 5),
            _request("req-2", "FRAME-2", 6, script_id="8"),
        ],
        sources=[
            {
                "scriptId": "7",
                "sessionId": _SESSION,
                "seq": 2,
                "contextId": 1,
                "sourceText": "function click(){fetch('/api')}\n",
                "sha256": _sha("function click(){fetch('/api')}\n"),
            },
            {
                "scriptId": "8",
                "sessionId": _SESSION,
                "seq": 4,
                "contextId": 2,
                "sourceText": "function click(){fetch('/api')}\n",
                "sha256": _sha("function click(){fetch('/api')}\n"),
            },
        ],
    )
    receipt = _project(plugin_src, raw)
    left, right = _frame(receipt, "req-1"), _frame(receipt, "req-2")
    assert (left["frame_id"], left["context_unique_id"]) == ("FRAME-1", "u1")
    assert (right["frame_id"], right["context_unique_id"]) == ("FRAME-2", "u2")
    assert left["source_ref"]["script_id"] == "7"
    assert right["source_ref"]["script_id"] == "8"
    assert receipt["requests"][0]["observed_identity_bridge"] is True


def test_missing_context_is_gap_not_bridge(plugin_src: Path) -> None:
    receipt = _project(plugin_src, _raw([_request("req-1", "FRAME-1", 5)], sources=[]))
    frame = _frame(receipt, "req-1")
    assert frame["context_id"] == "unknown"
    assert frame["source_ref"] is None
    assert "missing_context" in receipt["requests"][0]["gaps"]
    assert receipt["requests"][0]["observed_identity_bridge"] is False


def test_context_frame_mismatch_is_unresolved(plugin_src: Path) -> None:
    raw = _raw([_ctx(1, "u1", "FRAME-2", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5)])
    receipt = _project(plugin_src, raw)
    assert _frame(receipt, "req-1")["source_ref"] is None
    assert "frame_mismatch" in receipt["requests"][0]["gaps"]
    assert receipt["requests"][0]["observed_identity_bridge"] is False


def test_other_session_script_does_not_bind(plugin_src: Path) -> None:
    raw = _raw(
        [_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2, session=_OTHER), _request("req-1", "FRAME-1", 5)]
    )
    receipt = _project(plugin_src, raw)
    assert _frame(receipt, "req-1")["source_ref"] is None
    assert "wrong_session" in receipt["requests"][0]["gaps"]


def test_context_reuse_keeps_request_snapshot(plugin_src: Path) -> None:
    raw = _raw(
        [
            _ctx(1, "u1", "FRAME-1", 1),
            _parsed("7", 1, 2),
            _request("req-old", "FRAME-1", 3),
            {
                "method": "Runtime.executionContextDestroyed",
                "sessionId": _SESSION,
                "seq": 4,
                "params": {"executionContextId": 1, "executionContextUniqueId": "u1"},
            },
            _ctx(1, "u2", "FRAME-1", 5),
            _parsed("7", 1, 6),
            _request("req-new", "FRAME-1", 7),
        ]
    )
    receipt = _project(plugin_src, raw)
    assert _frame(receipt, "req-old")["context_unique_id"] == "u1"
    assert _frame(receipt, "req-new")["context_unique_id"] == "u2"


def test_navigation_bumps_epoch_without_rebinding(plugin_src: Path) -> None:
    raw = _raw(
        [
            _ctx(1, "u1", "FRAME-1", 1),
            _parsed("7", 1, 2),
            _request("req-old", "FRAME-1", 3, loader="LOAD-1"),
            {
                "method": "Page.frameNavigated",
                "sessionId": _SESSION,
                "seq": 4,
                "params": {"frame": {"id": "FRAME-1", "loaderId": "LOAD-2", "url": f"{_ORIGIN}/next"}},
            },
            _ctx(1, "u1", "FRAME-1", 5),
            _request("req-new", "FRAME-1", 6, loader="LOAD-2"),
        ]
    )
    receipt = _project(plugin_src, raw)
    assert _frame(receipt, "req-old")["epoch"] == 0
    assert _frame(receipt, "req-new")["epoch"] == 1
    assert _frame(receipt, "req-old")["loader_id"] == "LOAD-1"


def test_source_hash_mismatch_is_tamper_gap(plugin_src: Path) -> None:
    text = "function click(){fetch('/api')}\n"
    raw = _raw(
        [_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5)],
        sources=[
            {
                "scriptId": "7",
                "sessionId": _SESSION,
                "seq": 2,
                "contextId": 1,
                "sourceText": text,
                "sha256": "0" * 64,
            }
        ],
    )
    receipt = _project(plugin_src, raw)
    assert _frame(receipt, "req-1")["source_ref"] is None
    assert "source_tamper" in receipt["requests"][0]["gaps"]


def test_utf16_column_inside_surrogate_is_not_forced(plugin_src: Path) -> None:
    text = "😀x\n"
    raw = _raw(
        [_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5, column=1)],
        sources=[
            {
                "scriptId": "7",
                "sessionId": _SESSION,
                "seq": 2,
                "contextId": 1,
                "sourceText": text,
                "sha256": _sha(text),
            }
        ],
    )
    receipt = _project(plugin_src, raw)
    assert "coordinate_unproven" in receipt["requests"][0]["gaps"]
    assert _frame(receipt, "req-1")["source_ref"] is None


def test_two_async_parents_preserve_order_and_unresolved_parent_id(plugin_src: Path) -> None:
    parent = {
        "callFrames": [
            {
                "functionName": "outer",
                "scriptId": "7",
                "url": f"{_ORIGIN}/app.js",
                "lineNumber": 0,
                "columnNumber": 0,
            }
        ],
        "parentId": {"id": "missing-parent", "debuggerId": "dbg-1"},
    }
    raw = _raw([_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5, parent=parent)])
    receipt = _project(plugin_src, raw)
    request = receipt["requests"][0]
    assert request["async_parent_present"] is True
    assert [group["kind"] for group in request["stack_groups"]] == ["sync", "async"]
    assert request["stack_groups"][1]["frames"][0]["function_name"] == "outer"
    assert "unresolved_parent_id" in request["gaps"]
    assert receipt["coverage"]["status"] != "complete"


def test_repeated_request_id_keeps_hops_by_seq(plugin_src: Path) -> None:
    raw = _raw(
        [
            _ctx(1, "u1", "FRAME-1", 1),
            _parsed("7", 1, 2),
            _request("req-1", "FRAME-1", 10, url=f"{_ORIGIN}/first"),
            _request("req-1", "FRAME-1", 12, url=f"{_ORIGIN}/second"),
        ]
    )
    receipt = _project(plugin_src, raw)
    assert [hop["url"] for hop in receipt["requests"][0]["hops"]] == [
        f"{_ORIGIN}/first",
        f"{_ORIGIN}/second",
    ]
    assert [hop["seq"] for hop in receipt["requests"][0]["hops"]] == [10, 12]


def test_malformed_and_oversize_raw_are_refused(plugin_src: Path) -> None:
    from fxapk_rea.evidence import EvidenceError

    assert importlib.util.find_spec("fxapk_rea.trace") is not None
    project = _trace(plugin_src).project_trace
    with pytest.raises(EvidenceError, match="invalid_trace_envelope"):
        project(b"{")
    with pytest.raises(EvidenceError, match="trace_oversize"):
        project(b"{" + b" " * _MAX_RAW)


def test_trace_command_is_registered(plugin_src: Path) -> None:
    rea = _plugin(plugin_src)
    names = {command.name for command in rea.rea_app.registered_commands}
    assert "trace" in names
    result = CliRunner().invoke(rea.rea_app, ["trace", "--help"])
    assert result.exit_code == 0
    for flag in ("--endpoint", "--target", "--origin", "--observation-ms", "--out"):
        assert flag in result.stdout


def test_trace_import_does_not_import_websockets(plugin_src: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert importlib.util.find_spec("fxapk_rea.trace") is not None
    real_import = __import__

    def _guard(name: str, *args, **kwargs):
        if name == "websockets" or name.startswith("websockets."):
            raise ImportError("websockets blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _guard)
    module = _trace(plugin_src)
    importlib.reload(module)
    assert callable(module.project_trace)


def test_copied_raw_and_receipt_envelopes_are_refused(tmp_path: Path) -> None:
    raw = _raw([])
    receipt = json.dumps(
        {"schema_version": "fxapk-cdp-trace-observation/1", "producer": "fxapk-cdp-trace"}
    ).encode()
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "notes.body").write_bytes(raw)
    (tmp_path / "gzip").mkdir()
    (tmp_path / "gzip" / "renamed.json").write_bytes(gzip.compress(receipt))
    for name in ("raw", "gzip"):
        with pytest.raises(ValueError) as excinfo:
            load_web_evidence(tmp_path / name, AnalysisConfig(online=False))
        assert safe_exception_text(excinfo.value) == _DIAGNOSTIC


def test_invalid_endpoint_does_not_claim(plugin_src: Path, tmp_path: Path) -> None:
    rea = _plugin(plugin_src)
    out = tmp_path / "trace-out"
    result = CliRunner().invoke(
        rea.rea_app,
        [
            "trace",
            "--endpoint",
            "http://example.test",
            "--target",
            "TARGET",
            "--origin",
            _ORIGIN,
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 1
    assert not out.exists()


def test_missing_dependency_preserves_marker_without_receipt(
    plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    real_import = __import__

    def _guard(name: str, *args, **kwargs):
        if name == "websockets" or name.startswith("websockets."):
            raise ImportError("websockets blocked")
        return real_import(name, *args, **kwargs)

    for key in list(sys.modules):
        if key == "websockets" or key.startswith("websockets."):
            monkeypatch.delitem(sys.modules, key, raising=False)
    monkeypatch.setattr("builtins.__import__", _guard)
    rea = _plugin(plugin_src)
    out = tmp_path / "trace-out"
    result = CliRunner().invoke(
        rea.rea_app,
        [
            "trace",
            "--endpoint",
            "http://127.0.0.1:9",
            "--target",
            "TARGET",
            "--origin",
            _ORIGIN,
            "--observation-ms",
            "0",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 1
    assert (out / "fxapk-rea-bundle.json").is_file()
    assert not (out / "observation.json").exists()
    failure = json.loads((out / "failure.json").read_text(encoding="utf-8"))
    assert failure["reason"] == "trace_dependency_missing"


def _serve(mode: str):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    holder: dict[str, int] = {}

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if mode == "redirect" and self.path == "/json/version":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1/refused")
                self.end_headers()
                return
            if self.path == "/json/version":
                port = holder["port"]
                body = json.dumps(
                    {"webSocketDebuggerUrl": f"ws://127.0.0.1:{port}/devtools/browser/abc"}
                ).encode()
            elif self.path == "/json/list":
                page = "http://127.0.0.1:9/" if mode == "scope" else _ORIGIN + "/"
                body = json.dumps([{"id": "TARGET", "type": "page", "url": page}]).encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    holder["port"] = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _invoke_trace(plugin_src: Path, out: Path, port: int):
    rea = _plugin(plugin_src)
    return CliRunner().invoke(
        rea.rea_app,
        [
            "trace",
            "--endpoint",
            f"http://127.0.0.1:{port}",
            "--target",
            "TARGET",
            "--origin",
            _ORIGIN,
            "--observation-ms",
            "0",
            "--out",
            str(out),
        ],
    )


def test_scope_mismatch_is_refused(plugin_src: Path, tmp_path: Path) -> None:
    server = _serve("scope")
    try:
        out = tmp_path / "trace-out"
        result = _invoke_trace(plugin_src, out, server.server_address[1])
        assert result.exit_code == 1
        failure = json.loads((out / "failure.json").read_text(encoding="utf-8"))
        assert failure["reason"] == "target_origin_rejected"
        assert (out / "fxapk-rea-bundle.json").is_file()
        assert not (out / "observation.json").exists()
    finally:
        server.shutdown()


def test_redirect_is_refused(plugin_src: Path, tmp_path: Path) -> None:
    server = _serve("redirect")
    try:
        out = tmp_path / "trace-out"
        result = _invoke_trace(plugin_src, out, server.server_address[1])
        assert result.exit_code == 1
        failure = json.loads((out / "failure.json").read_text(encoding="utf-8"))
        assert failure["reason"] == "redirect_refused"
        assert not (out / "observation.json").exists()
    finally:
        server.shutdown()


def test_failed_setup_preserves_marker_without_receipt(plugin_src: Path, tmp_path: Path) -> None:
    server = _serve("setup")
    try:
        out = tmp_path / "trace-out"
        result = _invoke_trace(plugin_src, out, server.server_address[1])
        assert result.exit_code == 1
        failure = json.loads((out / "failure.json").read_text(encoding="utf-8"))
        assert failure["reason"] == "cdp_setup_failed"
        assert (out / "fxapk-rea-bundle.json").is_file()
        assert not (out / "observation.json").exists()
        assert not (out / "ready.json").exists()
    finally:
        server.shutdown()


def test_frame_detach_foreign_origin_and_root_parent_id(plugin_src: Path) -> None:
    detached = _raw(
        [
            _ctx(1, "u1", "FRAME-1", 1),
            _parsed("7", 1, 2),
            {
                "method": "Page.frameDetached",
                "sessionId": _SESSION,
                "seq": 3,
                "params": {"frameId": "FRAME-1", "reason": "remove"},
            },
            _request("req-1", "FRAME-1", 5),
        ]
    )
    receipt = _project(plugin_src, detached)
    assert receipt["requests"][0]["observed_identity_bridge"] is False
    assert _frame(receipt, "req-1")["source_ref"] is None
    foreign = json.loads(_raw([_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5)]))
    foreign["events"][0]["params"]["context"]["origin"] = "https://outside.test"
    refused = _project(plugin_src, json.dumps(foreign).encode())
    assert refused["requests"][0]["observed_identity_bridge"] is False
    parent = json.loads(_raw([_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5)]))
    parent["events"][-1]["params"]["initiator"]["stack"]["parentId"] = {"id": "not-fetched"}
    rooted = _project(plugin_src, json.dumps(parent).encode())
    assert rooted["requests"][0]["async_parent_present"] is False
    assert "unresolved_parent_id" in rooted["requests"][0]["gaps"]
    assert len(rooted["requests"][0]["stack_groups"]) == 1
    assert rooted["coverage"]["gaps"]


def test_source_identity_loader_and_scope_are_conservative(plugin_src: Path) -> None:
    mismatched = json.loads(_raw([_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5)]))
    mismatched["sources"][0]["scriptId"] = "different-script"
    receipt = _project(plugin_src, json.dumps(mismatched).encode())
    assert receipt["requests"][0]["observed_identity_bridge"] is False
    assert _frame(receipt, "req-1")["source_ref"] is None
    foreign = json.loads(_raw([_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5)]))
    for event in foreign["events"]:
        event["sessionId"] = "foreign"
    for source in foreign["sources"]:
        source["sessionId"] = "foreign"
    foreign["session_id"] = _SESSION
    scoped = _project(plugin_src, json.dumps(foreign).encode())
    assert not scoped["requests"] or not any(item["observed_identity_bridge"] for item in scoped["requests"])
    shifted = json.loads(_raw([_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5)]))
    shifted["events"][1]["params"]["startLine"] = 10
    shifted_receipt = _project(plugin_src, json.dumps(shifted).encode())
    assert shifted_receipt["requests"][0]["observed_identity_bridge"] is False
    duplicate = json.loads(_raw([_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5)]))
    other = dict(duplicate["sources"][0])
    other["sourceText"] = "function unrelated(){}\n"
    other["sha256"] = _sha(other["sourceText"])
    duplicate["sources"].append(other)
    try:
        duplicated = _project(plugin_src, json.dumps(duplicate).encode())
    except ValueError:
        duplicated = None
    if duplicated is not None:
        assert duplicated["requests"][0]["observed_identity_bridge"] is False
    conflict = json.loads(_raw([_ctx(1, "u1", "FRAME-1", 1), _parsed("7", 1, 2), _request("req-1", "FRAME-1", 5)]))
    conflict["events"].insert(
        0,
        {
            "seq": 0,
            "sessionId": _SESSION,
            "method": "Page.frameNavigated",
            "params": {"frame": {"id": "FRAME-1", "loaderId": "OTHER-LOAD", "url": f"{_ORIGIN}/"}},
        },
    )
    conflicted = _project(plugin_src, json.dumps(conflict).encode())
    assert conflicted["requests"][0]["observed_identity_bridge"] is False
    assert _frame(conflicted, "req-1")["source_ref"] is None


def test_malformed_envelope_is_not_reordered(plugin_src: Path) -> None:
    from fxapk_rea.evidence import EvidenceError

    project = _trace(plugin_src).project_trace
    body = json.loads(_raw([]))
    body["events"] = [
        {"method": "Runtime.executionContextsCleared", "sessionId": _SESSION, "seq": 2, "params": {}},
        {"method": "Runtime.executionContextsCleared", "sessionId": _SESSION, "seq": 1, "params": {}},
    ]
    with pytest.raises(EvidenceError, match="invalid_trace_envelope"):
        project(json.dumps(body).encode())
    body["events"][1]["seq"] = 2
    with pytest.raises(EvidenceError, match="invalid_trace_envelope"):
        project(json.dumps(body).encode())
    with pytest.raises(EvidenceError, match="invalid_trace_envelope"):
        project(b'{"schema_version":"fxapk-cdp-trace/1","schema_version":"fxapk-cdp-trace/1"}')
    with pytest.raises(EvidenceError, match="invalid_trace_envelope"):
        project(b'{"schema_version": NaN}')


def test_bootstrap_scope_and_cleanup_use_the_real_collector(plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    del plugin_src
    runtime = importlib.import_module("fxapk_rea.trace_runtime")
    origin = _ORIGIN
    peer_box: dict[str, object] = {}

    class _Peer:
        def __init__(self) -> None:
            self.q: list[dict[str, object]] = []
            self.sent: list[dict[str, object]] = []
            self.closed = False

        def send(self, raw: str) -> None:
            message = json.loads(raw)
            self.sent.append(message)
            method = message["method"]
            result: dict[str, object] = {}
            if method == "Target.getTargetInfo":
                result = {"targetInfo": {"targetId": "T", "type": "page", "url": origin + "/"}}
            if method == "Target.attachToTarget":
                result = {"sessionId": "S"}
            if method == "Runtime.enable":
                for sid, number, item_origin in (("S", 1, origin), ("S", 2, "https://outside.test"), ("FOREIGN", 3, origin)):
                    self.q.append(
                        {
                            "sessionId": sid,
                            "method": "Runtime.executionContextCreated",
                            "params": {
                                "context": {
                                    "id": number,
                                    "uniqueId": "u" + str(number),
                                    "origin": item_origin,
                                    "auxData": {"frameId": "F", "isDefault": True},
                                }
                            },
                        }
                    )
            if method == "Debugger.enable":
                for sid, number, url in (("S", 1, origin + "/app.js"), ("S", 2, "https://outside.test/private.js"), ("FOREIGN", 3, origin + "/foreign.js")):
                    self.q.append(
                        {
                            "sessionId": sid,
                            "method": "Debugger.scriptParsed",
                            "params": {
                                "scriptId": str(number),
                                "executionContextId": number,
                                "url": url,
                                "startLine": 0,
                                "startColumn": 0,
                            },
                        }
                    )
            if method == "Network.enable":
                self.q.append(
                    {
                        "sessionId": "S",
                        "method": "Network.requestWillBeSent",
                        "params": {
                            "requestId": "outside",
                            "frameId": "F",
                            "loaderId": "L",
                            "documentURL": origin + "/",
                            "request": {
                                "url": "https://outside.test/private",
                                "method": "GET",
                                "headers": {"Cookie": "synthetic-cookie"},
                            },
                            "initiator": {"type": "other"},
                        },
                    }
                )
            if method == "Page.getFrameTree":
                result = {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": origin + "/"}}}
            if method == "Debugger.getScriptSource":
                result = {"scriptSource": "function synthetic(){}\n"}
            self.q.append({"id": message["id"], "result": result})

        def recv(self, timeout: float | None = None) -> str:
            del timeout
            if not self.q:
                raise TimeoutError()
            return json.dumps(self.q.pop(0))

        def close(self) -> None:
            self.closed = True

    peer = _Peer()
    peer_box["peer"] = peer
    real_import = importlib.import_module

    def _import(name: str) -> object:
        if name == "websockets.sync.client":
            return type("Client", (), {"connect": staticmethod(lambda *args, **kwargs: peer)})()
        return real_import(name)

    monkeypatch.setattr(runtime.importlib, "import_module", _import)
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *args, **kwargs: type("Sock", (), {"close": lambda self: None})())
    monkeypatch.setattr(
        runtime,
        "_discover",
        lambda *args: ({"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"}, [{"id": "T", "type": "page", "url": origin + "/"}]),
    )
    raw = runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=origin, observation_ms=0, out=tmp_path)
    value = json.loads(raw)
    assert b"outside.test" not in raw
    assert b"synthetic-cookie" not in raw
    assert all(event["sessionId"] == "S" for event in value["events"])
    assert all(source["sessionId"] == "S" and source["contextId"] == 1 for source in value["sources"])
    assert not any(
        item["method"] == "Debugger.getScriptSource" and item.get("params", {}).get("scriptId") in ["2", "3"]
        for item in peer.sent
    )
    assert peer.closed
    assert value["capture"]["detach_acked"] is True
    assert value["capture"]["socket_closed"] is True
    assert value["completeness"]["gaps"]


def test_destroyed_context_is_not_rebound_and_cleanup_failure_keeps_bytes(
    plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del plugin_src
    from fxapk_rea.evidence import EvidenceError

    runtime = importlib.import_module("fxapk_rea.trace_runtime")
    client = runtime._Client(websocket=None, deadline=runtime.time.monotonic() + 5)
    client.origin = _ORIGIN
    client.session_id = _SESSION
    client.contexts[1] = {"id": 1, "uniqueId": "u1", "origin": _ORIGIN, "_gen": 1, "auxData": {"frameId": "F"}}
    client.context_gen[1] = 1
    client.depth = 1
    client._queue_source(
        {
            "sessionId": _SESSION,
            "seq": 2,
            "params": {"scriptId": "7", "executionContextId": 1},
        }
    )
    client.depth = 0
    client.contexts.pop(1)
    client.contexts[1] = {"id": 1, "uniqueId": "u2", "origin": _ORIGIN, "_gen": 2, "auxData": {"frameId": "F"}}
    client.context_gen[1] = 2
    calls: list[str] = []

    def _refuse(*args: object, **kwargs: object) -> dict[str, str]:
        del args, kwargs
        calls.append("fetch")
        return {"scriptSource": "function no(){}\n"}

    monkeypatch.setattr(client, "call", _refuse)
    client._drain_fetches()
    assert calls == []
    assert client.sources == []
    assert "source_unavailable" in client.gaps

    class _Closing:
        def __init__(self) -> None:
            self.q: list[str] = []
            self.sent: list[dict[str, object]] = []

        def send(self, raw: str) -> None:
            message = json.loads(raw)
            self.sent.append(message)
            if message["method"] == "Target.attachToTarget":
                self.q.append(json.dumps({"id": message["id"], "result": {"sessionId": "S"}}))
                return
            if message["method"] == "Target.getTargetInfo":
                self.q.append(json.dumps({"id": message["id"], "result": {"targetInfo": {"targetId": "T", "type": "page", "url": _ORIGIN + "/"}}}))
                return
            if message["method"] == "Runtime.enable":
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
            self.q.append(json.dumps({"id": message["id"], "result": {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": _ORIGIN + "/"}}}} if message["method"] == "Page.getFrameTree" else {"id": message["id"], "result": {}}))

        def recv(self, timeout: float | None = None) -> str:
            del timeout
            if not self.q:
                raise TimeoutError()
            return self.q.pop(0)

        def close(self) -> None:
            raise OSError("close failed")

    peer = _Closing()
    monkeypatch.setattr(
        runtime.importlib,
        "import_module",
        lambda name: type("M", (), {"connect": staticmethod(lambda *a, **k: peer)})() if name == "websockets.sync.client" else importlib.import_module(name),
    )
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *a, **k: type("Sock", (), {"close": lambda self: None})())
    monkeypatch.setattr(
        runtime,
        "_discover",
        lambda *a: ({"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"}, [{"id": "T", "type": "page", "url": _ORIGIN + "/"}]),
    )
    with pytest.raises(EvidenceError, match="trace_cleanup_failed"):
        runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=0, out=tmp_path)
    saved = (tmp_path / "cdp-trace-original.json").read_bytes()
    assert b"outside.test" not in saved
    assert json.loads(saved)["capture"]["socket_closed"] is False


def _install_runtime(monkeypatch: pytest.MonkeyPatch, peer: object):
    runtime = importlib.import_module("fxapk_rea.trace_runtime")
    real = importlib.import_module

    def _import(name: str) -> object:
        if name == "websockets.sync.client":
            return type("M", (), {"connect": staticmethod(lambda *args, **kwargs: peer)})()
        return real(name)

    monkeypatch.setattr(runtime.importlib, "import_module", _import)
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *args, **kwargs: type("Sock", (), {"close": lambda self: None})())
    monkeypatch.setattr(
        runtime,
        "_discover",
        lambda *args: (
            {"webSocketDebuggerUrl": "ws://127.0.0.1:9999/devtools/browser/B"},
            [{"id": "T", "type": "page", "url": _ORIGIN + "/"}],
        ),
    )
    return runtime


class _ScriptPeer:
    def __init__(self, count: int, length: int, *, fault: str = "") -> None:
        self.count = count
        self.length = length
        self.fault = fault
        self.q: list[dict[str, object]] = []
        self.sent: list[dict[str, object]] = []
        self.closed = False
        self.fetches = 0

    def send(self, raw: str) -> None:
        message = json.loads(raw)
        self.sent.append(message)
        method = message["method"]
        if method == "Target.getTargetInfo":
            result = {"targetInfo": {"targetId": "T", "type": "page", "url": _ORIGIN + "/"}}
        elif method == "Target.attachToTarget":
            result = {"sessionId": "S"}
        elif method == "Runtime.enable":
            result = {}
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
            result = {}
            for number in range(self.count):
                self.q.append(
                    {
                        "sessionId": "S",
                        "method": "Debugger.scriptParsed",
                        "params": {
                            "scriptId": str(number + 10),
                            "executionContextId": 1,
                            "url": _ORIGIN + "/synthetic.js",
                            "startLine": 0,
                            "startColumn": 0,
                        },
                    }
                )
        elif method == "Page.getFrameTree":
            result = {"frameTree": {"frame": {"id": "F", "loaderId": "L", "url": _ORIGIN + "/"}}}
            if self.fault == "navigate":
                self.q.append(
                    {
                        "sessionId": "S",
                        "method": "Page.frameNavigated",
                        "params": {"frame": {"id": "F", "loaderId": "L2", "url": "https://outside.test/moved"}},
                    }
                )
        elif method == "Debugger.getScriptSource":
            self.fetches += 1
            if self.fault == "transport":
                self.q.append({"_transport": True})
                return
            if self.fault == "deadline":
                self.q.append({"_deadline": True})
                return
            if self.fault == "cdp_error":
                self.q.append({"id": message["id"], "error": {"code": -32000, "message": "No script"}})
                return
            result = {"scriptSource": "a" * self.length}
        else:
            result = {}
        self.q.append({"id": message["id"], "result": result})

    def recv(self, timeout: float | None = None) -> str:
        del timeout
        if not self.q:
            if self.fault == "deadline":
                raise TimeoutError()
            raise TimeoutError()
        item = self.q.pop(0)
        if isinstance(item, dict) and item.get("_transport"):
            raise ConnectionError("socket reset")
        if isinstance(item, dict) and item.get("_deadline"):
            raise TimeoutError()
        return json.dumps(item)

    def close(self) -> None:
        self.closed = True


def test_source_budget_counts_before_the_next_fetch(plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    del plugin_src
    from fxapk_rea.evidence import EvidenceError

    peer = _ScriptPeer(65, 10)
    runtime = _install_runtime(monkeypatch, peer)
    with pytest.raises(EvidenceError, match="trace_limit"):
        runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=0, out=tmp_path)
    assert peer.closed
    assert peer.fetches == 64
    saved = json.loads((tmp_path / "cdp-trace-original.json").read_text(encoding="utf-8"))
    assert saved["capture"]["stopped_reason"] == "trace_limit"
    assert len(saved["sources"]) == 64
    assert saved["events"]
    assert saved["capture"]["socket_closed"] is True


def test_total_envelope_keeps_valid_partial_without_byte_slice(
    plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del plugin_src
    from fxapk_rea.evidence import EvidenceError

    peer = _ScriptPeer(6, 48000)
    runtime = _install_runtime(monkeypatch, peer)
    with pytest.raises(EvidenceError, match="trace_oversize"):
        runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=0, out=tmp_path)
    assert peer.closed
    raw = (tmp_path / "cdp-trace-original.json").read_bytes()
    assert 0 < len(raw) <= 256 * 1024
    saved = json.loads(raw)
    assert saved["events"]
    assert 0 < len(saved["sources"]) <= 64
    assert saved["capture"]["stopped_reason"] == "trace_oversize"
    assert saved["capture"]["socket_closed"] is True
    assert "complete" not in saved["capture"]


def test_source_command_error_is_unavailable_but_transport_and_deadline_propagate(
    plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del plugin_src
    from fxapk_rea.evidence import EvidenceError

    unavailable = _ScriptPeer(1, 8, fault="cdp_error")
    runtime = _install_runtime(monkeypatch, unavailable)
    raw = runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=0, out=tmp_path)
    assert b"source_unavailable" in raw
    assert unavailable.closed

    transport = _ScriptPeer(2, 8, fault="transport")
    runtime = _install_runtime(monkeypatch, transport)
    with pytest.raises(EvidenceError, match="cdp_setup_failed"):
        runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=0, out=tmp_path / "transport")
    assert transport.closed
    assert transport.fetches == 1

    deadline = _ScriptPeer(2, 8, fault="deadline")
    runtime = _install_runtime(monkeypatch, deadline)
    with pytest.raises(EvidenceError, match="trace_deadline"):
        runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=0, out=tmp_path / "deadline")
    assert deadline.closed
    assert deadline.fetches == 1


def test_off_origin_navigation_fails_and_closes_socket(
    plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del plugin_src
    from fxapk_rea.evidence import EvidenceError

    peer = _ScriptPeer(0, 1, fault="navigate")
    runtime = _install_runtime(monkeypatch, peer)
    with pytest.raises(EvidenceError, match="top_frame_origin_rejected"):
        runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=1000, out=tmp_path)
    assert peer.closed
    assert not (tmp_path / "observation.json").exists()


def test_system_exit_closes_socket_and_is_not_swallowed(
    plugin_src: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del plugin_src
    peer = _ScriptPeer(0, 1)
    runtime = _install_runtime(monkeypatch, peer)

    def _boom(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise SystemExit(3)

    monkeypatch.setattr(runtime, "_write_ready", _boom)
    with pytest.raises(SystemExit):
        runtime.capture(endpoint="http://127.0.0.1:9999", target="T", origin=_ORIGIN, observation_ms=0, out=tmp_path)
    assert peer.closed
    assert not (tmp_path / "observation.json").exists()
