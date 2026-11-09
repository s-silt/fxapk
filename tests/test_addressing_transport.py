"""All networking is replaced; reserved addresses exercise the pinned boundary."""
import socket

import pytest


def test_resolution_checks_every_answer_before_connect(monkeypatch):
    from apkscan.core import pinned_transport as pt
    from apkscan.config import fetch
    monkeypatch.setattr(fetch, "_ip_is_blocked", lambda ip: str(ip) == "192.0.2.2")
    monkeypatch.setattr(pt.socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ("192.0.2.1", "192.0.2.2")])
    monkeypatch.setattr(pt.socket, "socket", lambda *a, **k: pytest.fail("connected before all answers checked"))
    with pytest.raises(ValueError):
        pt.resolve_public("api.example.test", 443)


def test_numeric_connect_never_resolves_again_and_checks_peer(monkeypatch):
    from apkscan.core import pinned_transport as pt
    from apkscan.config import fetch
    monkeypatch.setattr(fetch, "_ip_is_blocked", lambda ip: False)
    monkeypatch.setattr(pt.socket, "getaddrinfo", lambda *a, **k: pytest.fail("numeric pin must not resolve again"))
    class Sock:
        closed = False
        peer = "192.0.2.1"
        def settimeout(self, value): pass
        def connect(self, target): self.target = target
        def getpeername(self): return self.peer, 443
        def close(self): self.closed = True
    sock = Sock()
    monkeypatch.setattr(pt.socket, "socket", lambda *a: sock)
    assert pt.connect_pinned("192.0.2.1", 443, timeout=2) is sock
    assert sock.target == ("192.0.2.1", 443)
    sock.peer = "192.0.2.2"
    with pytest.raises(ValueError):
        pt.connect_pinned("192.0.2.1", 443, timeout=2)
    assert sock.closed


def test_config_guard_unavailable_is_closed(monkeypatch):
    from apkscan.config import fetch
    monkeypatch.setattr(fetch, "_GUARDED_ADAPTER_CLS", None)
    assert fetch._build_guarded_session() is None


def test_config_guard_calls_shared_pin_not_original_connection(monkeypatch):
    from apkscan.core import pinned_transport as pt
    from apkscan.config import fetch
    monkeypatch.setattr(pt, "resolve_public", lambda host, port: ["192.0.2.1"])
    class Sock:
        def getpeername(self): return "192.0.2.1", 443
    sock = Sock()
    calls = []
    monkeypatch.setattr(pt, "connect_pinned", lambda ip, port, **kw: calls.append((ip, port)) or sock)
    class Base:
        host, port, timeout = "api.example.test", 443, 2
        source_address, socket_options = None, None
        def _new_conn(self): pytest.fail("unvalidated second DNS/connection")
    conn = type("Guard", (fetch._PeerGuardMixin, Base), {})()
    assert conn._new_conn() is sock
    assert calls == [("192.0.2.1", 443)]
    assert conn.peer_ip == "192.0.2.1"


def test_resolution_deadline_returns_without_connecting(monkeypatch):
    from apkscan.core import pinned_transport as pt
    import threading
    release, completed = threading.Event(), threading.Event()
    def blocked(*args, **kwargs):
        try:
            release.wait(2)
            return []
        finally:
            completed.set()
    monkeypatch.setattr(pt.socket, "getaddrinfo", blocked)
    try:
        with pytest.raises(TimeoutError):
            pt.resolve_public("api.example.test", 443, timeout=0.01)
    finally:
        release.set()
        completed.wait(1)


def test_response_reader_caps_headers_and_body_together():
    from io import BytesIO
    import time
    from apkscan.core.pinned_transport import _DeadlineReader
    class Sock:
        def settimeout(self, value): pass
    meter = {"remaining": 5, "consumed": 0}
    reader = _DeadlineReader(BytesIO(b"HTTP/1.1 200 OK\r\n"), Sock(), time.monotonic() + 2, meter)
    output = bytearray(100)
    assert reader.readinto(output) == 5
    assert meter == {"remaining": 0, "consumed": 5}
    with pytest.raises(OSError, match="byte_budget"):
        reader.readinto(output)
