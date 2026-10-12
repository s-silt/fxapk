"""本地回环合成 HTTP 夹具。只绑定 127.0.0.1，不启动浏览器、不联网、不装依赖。

页面与脚本的字节是采集方必须自己观察到的 ground truth。本进程只记录合成请求，
不写采集结果、不写 pass 文件。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "rea_trace"
HOSTS = frozenset({"127.0.0.1", "localhost"})
MODES = {
    "direct": "direct.html",
    "crossframe": "crossframe.html",
    "worker": "worker.html",
    "oopif": "oopif.html",
    "inline": "inline.html",
    "decoy": "decoy.html",
}
FILES = {
    "/direct.js": "direct.js",
    "/cross-child.html": "cross-child.html",
    "/cross-child.js": "cross-child.js",
    "/worker.js": "worker.js",
    "/decoy.js": "decoy.js",
    "/oopif-child.html": "oopif-child.html",
    "/oopif-child.js": "oopif-child.js",
}
LOG_KEYS = ("time", "method", "path", "branch", "run_id")


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, port: int, log_path: Path, run_id: str) -> None:
        super().__init__(("127.0.0.1", port), Handler)
        self.log_path = log_path
        self.run_id = run_id
        self.log_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server: FixtureServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def log_error(self, fmt: str, *args: object) -> None:
        return

    def handle_error(self, request: object, client_address: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        self._handle(write_body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle(write_body=False)

    def do_POST(self) -> None:  # noqa: N802
        self._handle(write_body=True)

    def _handle(self, *, write_body: bool) -> None:
        self._discard_body()
        if _bad_target(self.path):
            self._audit()
            self._send(400, b"rejected", "text/plain; charset=utf-8", write_body)
            return
        if not self._host_ok():
            self._audit()
            self._send(403, b"rejected", "text/plain; charset=utf-8", write_body)
            return
        self._audit()
        if self.command not in {"GET", "HEAD"}:
            self._send(405, b"", "text/plain; charset=utf-8", write_body)
            return
        status, body, content_type = self._route()
        self._send(status, body, content_type, write_body)

    def _discard_body(self) -> None:
        raw = self.headers.get("Content-Length", "0")
        try:
            length = int(raw)
        except ValueError:
            length = 0
        if length > 0:
            remaining = length
            while remaining:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)

    def _host_ok(self) -> bool:
        host = self.headers.get("Host", "")
        name, sep, port = host.partition(":")
        if sep != ":" or name.lower() not in HOSTS:
            return False
        return port == str(self.server.server_address[1])

    def _route(self) -> tuple[int, bytes, str]:
        parsed = urlsplit(self.path)
        if parsed.path == "/api":
            return 200, _api_body(self), "application/json; charset=utf-8"
        if parsed.path == "/":
            mode = parse_qs(parsed.query, keep_blank_values=True).get("mode", [""])[0]
            name = MODES.get(mode)
            if name is None:
                return 404, b"not found", "text/plain; charset=utf-8"
            kind = "text/html; charset=utf-8"
            return 200, _read_fixture(name), kind
        name = FILES.get(parsed.path)
        if name is None:
            return 404, b"not found", "text/plain; charset=utf-8"
        if name.endswith(".js"):
            return 200, _read_fixture(name), "text/javascript; charset=utf-8"
        return 200, _read_fixture(name), "text/html; charset=utf-8"

    def _audit(self) -> None:
        parsed = urlsplit(self.path)
        branch: str | None = None
        if parsed.path == "/api":
            values = parse_qs(parsed.query, keep_blank_values=True).get("branch")
            if values:
                branch = values[0]
        record = {
            "time": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "path": self.path,
            "branch": branch,
            "run_id": self.server.run_id,
        }
        if tuple(record) != LOG_KEYS:
            raise RuntimeError("request log keys drifted")
        line = json.dumps(record, ensure_ascii=True) + "\n"
        with self.server.log_lock:
            with self.server.log_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line)
                handle.flush()

    def _send(self, status: int, body: bytes, content_type: str, write_body: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if write_body and self.command != "HEAD":
            self.wfile.write(body)


def _api_body(handler: Handler) -> bytes:
    parsed = urlsplit(handler.path)
    values = parse_qs(parsed.query, keep_blank_values=True).get("branch", [None])
    payload = {
        "ok": True,
        "synthetic": True,
        "branch": values[0],
        "method": handler.command,
        "path": handler.path,
        "run_id": handler.server.run_id,
        "time": datetime.now(timezone.utc).isoformat(),
    }
    return json.dumps(payload, ensure_ascii=True).encode("ascii")


def _bad_target(target: str) -> bool:
    if not target.startswith("/") or target.startswith("//"):
        return True
    path = target.split("?", 1)[0]
    decoded = unquote(path)
    twice = unquote(decoded)
    for item in (path, decoded, twice):
        if "\\" in item or "\x00" in item:
            return True
        if any(part == ".." for part in item.split("/")):
            return True
    return False


def _read_fixture(name: str) -> bytes:
    path = (FIXTURES / name).resolve()
    path.relative_to(FIXTURES.resolve())
    return path.read_bytes()


def _source_manifest() -> dict[str, object]:
    files: list[dict[str, object]] = []
    for path in sorted(item for item in FIXTURES.rglob("*") if item.is_file()):
        data = path.read_bytes()
        files.append({
            "path": path.relative_to(FIXTURES).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })
    return {"files": files}


def _install_stop(httpd: FixtureServer) -> None:
    def stop(signum: int, frame: object) -> None:
        del signum, frame
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, stop)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="loopback synthetic trace fixture")
    parser.add_argument("--out", required=True)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    if args.port < 0 or args.port > 65535:
        print("port out of range", file=sys.stderr)
        return 2
    out = Path(args.out)
    if out.exists():
        print("refusing to overwrite existing output", file=sys.stderr)
        return 2
    missing = [name for name in (*MODES.values(), *FILES.values()) if not (FIXTURES / name).is_file()]
    if missing:
        print("fixture source missing", file=sys.stderr)
        return 2
    out.mkdir(parents=False)
    manifest = _source_manifest()
    (out / "fixture_sources.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    run_id = uuid.uuid4().hex
    log_path = out / "server.jsonl"
    log_path.write_text("", encoding="utf-8")
    httpd = FixtureServer(args.port, log_path, run_id)
    bound_host, bound_port = httpd.server_address[:2]
    if bound_host != "127.0.0.1":
        httpd.server_close()
        print("refusing non-loopback bind", file=sys.stderr)
        return 2
    identity = {
        "origin": f"http://127.0.0.1:{bound_port}",
        "secondary_origin": f"http://localhost:{bound_port}",
        "pid": os.getpid(),
    }
    sys.stdout.buffer.write(json.dumps(identity, separators=(",", ":")).encode("ascii") + b"\n")
    sys.stdout.buffer.flush()
    _install_stop(httpd)
    try:
        httpd.serve_forever(poll_interval=0.2)
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
