"""可携带 REA trace 合成夹具的契约测试。只打本地回环 HTTP，不启动浏览器。"""

from __future__ import annotations

import ast
import hashlib
import json
import signal
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import psutil

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "rea_trace_fixture.py"
FIXTURES = ROOT / "tests" / "fixtures" / "rea_trace"
MODES = ("direct", "crossframe", "worker", "oopif", "inline", "decoy")
STDLIB = set(sys.stdlib_module_names) | {"__future__"}
HEADER_MARKER = "SYNTHETIC-HEADER-MARKER"
BODY_MARKER = b"SYNTHETIC-BODY-MARKER"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".", 1)[0])
    return found


def _fetch(url: str, *, host: str | None = None, data: bytes | None = None, method: str | None = None):
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Cookie", HEADER_MARKER)
    req.add_header("X-Marker", HEADER_MARKER)
    if host is not None:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


@pytest.fixture
def server(tmp_path: Path):
    out = tmp_path / "fresh-out"
    proc = subprocess.Popen(
        [sys.executable, str(TOOL), "--out", str(out), "--port", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ROOT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )
    assert proc.stdout is not None
    line = proc.stdout.readline()
    if not line:
        err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        proc.kill()
        pytest.fail(f"fixture produced no stdout line: {err}")
    meta = json.loads(line.decode("utf-8"))
    try:
        yield proc, out, meta
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def test_tool_and_fixtures_import_only_stdlib() -> None:
    assert TOOL.is_file()
    assert _imports(TOOL) <= STDLIB
    assert _imports(TOOL).isdisjoint({"webbrowser", "playwright", "selenium", "requests"})
    text = TOOL.read_text(encoding="utf-8").lower()
    for name in ("playwright", "selenium", "webbrowser", "node ", "npm "):
        assert name not in text


def test_stdout_identity_and_both_loopback_hosts(server) -> None:
    _proc, out, meta = server
    assert set(meta) == {"origin", "secondary_origin", "pid"}
    assert meta["origin"].startswith("http://127.0.0.1:")
    assert meta["secondary_origin"].startswith("http://localhost:")
    assert meta["origin"].rsplit(":", 1)[-1] == meta["secondary_origin"].rsplit(":", 1)[-1]
    # Windows venv python.exe can be a redirector spawning the interpreter.
    assert meta["pid"] in {
        _proc.pid, *(child.pid for child in psutil.Process(_proc.pid).children(recursive=True))
    }
    status, body, _headers = _fetch(meta["origin"] + "/?mode=direct")
    assert status == 200 and b'id="load"' in body
    status, body, _headers = _fetch(meta["secondary_origin"] + "/api?branch=direct")
    payload = json.loads(body)
    assert status == 200
    assert payload["branch"] == "direct"
    assert payload["path"] == "/api?branch=direct"
    assert payload["method"] == "GET"
    assert isinstance(payload["run_id"], str) and payload["run_id"]
    assert "pass" not in payload and "verified" not in payload


def test_modes_expose_stable_load_button_and_ground_truth_calls(server) -> None:
    _proc, _out, meta = server
    for mode in MODES:
        status, body, _headers = _fetch(meta["origin"] + "/?mode=" + mode)
        assert status == 200, mode
        text = body.decode("utf-8")
        assert text.count('id="load"') == 1
        assert "left:24px;top:24px" in text.replace(" ", "")
        assert "position:fixed" in text.replace(" ", "")

    direct = _fetch(meta["origin"] + "/direct.js")[1].decode("utf-8")
    assert "function loadConfig(" in direct and 'requestConfig("direct")' in direct
    assert 'fetch("/api?branch=" + branch)' in direct

    parent = _fetch(meta["origin"] + "/?mode=crossframe")[1].decode("utf-8")
    child = _fetch(meta["origin"] + "/cross-child.js")[1].decode("utf-8")
    assert "fetch(" not in parent
    assert "contentWindow" in parent and "scheduleFromParent()" in parent
    assert "function scheduleFromParent(" in child
    assert "Promise.resolve()" in child and ".then(" in child and "setTimeout(" in child
    assert "function childSend(" in child and 'requestConfig("crossframe")' in child
    assert 'fetch("/api?branch=" + branch)' in child

    worker_page = _fetch(meta["origin"] + "/?mode=worker")[1].decode("utf-8")
    worker = _fetch(meta["origin"] + "/worker.js")[1].decode("utf-8")
    assert "fetch(" not in worker_page
    assert 'new Worker("/worker.js")' in worker_page
    assert "self.onmessage" in worker and "function workerSend(" in worker
    assert 'requestConfig("worker")' in worker

    oopif = _fetch(meta["origin"] + "/?mode=oopif&wait=ready")[1].decode("utf-8")
    child_page = _fetch(meta["secondary_origin"] + "/oopif-child.js")[1].decode("utf-8")
    assert "fetch(" not in oopif
    assert "http://localhost:" in oopif and "postMessage" in oopif
    assert "data-fixture-ready" in oopif
    assert "ev.origin" in child_page
    assert 'fetch(location.origin + "/api?branch=oopif")' in child_page

    inline = _fetch(meta["origin"] + "/?mode=inline")[1]
    text = inline.decode("utf-8")
    assert "合成" in text and "🙂" in text
    assert b"\r\n" in inline and b"\n" in inline
    start = text.index("/*配置🙂*/")
    assert text.count("\n", 0, start) > 0
    column = start - text.rfind("\n", 0, start) - 1
    assert column > 0
    assert "<script src=" not in text
    assert "function inlineSend(" in text and 'fetch("/api?branch=inline")' in text

    decoy = _fetch(meta["origin"] + "/decoy.js")[1].decode("utf-8")
    assert "Math.random" not in decoy
    assert "function initProbe(" in decoy and "independentDecoy" in decoy
    assert 'requestConfig("decoy")' in decoy and 'requestConfig("clicked")' in decoy
    assert "function loadConfig(" in decoy and "setTimeout(clickSend" in decoy
    assert decoy.strip().splitlines()[-2].strip() == "initProbe();" or "\ninitProbe();\n" in decoy


def test_path_traversal_is_rejected(server) -> None:
    _proc, _out, meta = server
    probes = (
        "/../pyproject.toml",
        "/..%2fpyproject.toml",
        "/fixtures/%2e%2e/%2e%2e/pyproject.toml",
        "/cross-child.js%5C..%5C..%5Cpyproject.toml",
        "/inline.html/../../tools/rea_trace_fixture.py",
        "/%2e%2e/%2e%2e/pyproject.toml",
    )
    for path in probes:
        status, body, _headers = _fetch(meta["origin"] + path)
        assert status == 400, path
        assert b"pyproject" not in body.lower()
        assert b"[project]" not in body


def test_log_hashes_and_refuse_overwrite(server, tmp_path: Path) -> None:
    proc, out, meta = server
    status, body, _headers = _fetch(
        meta["origin"] + "/api?branch=direct",
        data=BODY_MARKER,
        method="POST",
    )
    assert status == 405
    assert BODY_MARKER not in body
    _fetch(meta["origin"] + "/?mode=decoy")
    lines = [json.loads(line) for line in (out / "server.jsonl").read_text(encoding="utf-8").splitlines()]
    assert lines
    blob = (out / "server.jsonl").read_bytes()
    assert HEADER_MARKER.encode() not in blob
    assert BODY_MARKER not in blob
    assert b"Cookie" not in blob
    for rec in lines:
        assert set(rec) == {"time", "method", "path", "branch", "run_id"}
        assert rec["run_id"]
        assert "\n" not in rec["path"]
    posted = [rec for rec in lines if rec["method"] == "POST"]
    assert posted and posted[0]["path"] == "/api?branch=direct"
    assert posted[0]["branch"] == "direct"
    sources = json.loads((out / "fixture_sources.json").read_text(encoding="utf-8"))
    expected = []
    for path in sorted(p for p in FIXTURES.rglob("*") if p.is_file()):
        data = path.read_bytes()
        expected.append({
            "path": path.relative_to(FIXTURES).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })
    assert sources["files"] == expected
    assert {p.name for p in out.iterdir()} == {"server.jsonl", "fixture_sources.json"}
    before = (out / "fixture_sources.json").read_bytes()
    again = subprocess.run(
        [sys.executable, str(TOOL), "--out", str(out), "--port", "0"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert again.returncode != 0
    assert again.stdout.strip() == ""
    assert (out / "fixture_sources.json").read_bytes() == before
    assert proc.poll() is None


def test_stop_signal_exits_zero(server) -> None:
    proc, _out, _meta = server
    proc.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
    assert proc.wait(timeout=5) == 0
