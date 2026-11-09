"""Shared fail-closed transport: validate every DNS answer, then connect numerically."""
from __future__ import annotations

from collections.abc import Sequence
import http.client
import io
import ssl
import time
import ipaddress
import socket
import threading
from typing import Any, cast


def public_ip(value: str) -> str:
    from apkscan.config.fetch import _ip_is_blocked

    address = ipaddress.ip_address(value)
    if _ip_is_blocked(address):
        raise ValueError("non_public_address")
    return str(address)


_DNS_SLOTS = threading.BoundedSemaphore(4)


def _resolve_public(host: str, port: int) -> list[str]:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(public_ip(str(row[4][0])) for row in answers))
    else:
        addresses = [public_ip(host)]
    if not addresses:
        raise ValueError("no_public_address")
    return addresses


def resolve_public(host: str, port: int, *, timeout: float | None = None) -> list[str]:
    if timeout is None:
        return _resolve_public(host, port)
    if timeout <= 0 or not _DNS_SLOTS.acquire(blocking=False):
        raise TimeoutError("resolver_budget_unavailable")
    done = threading.Event()
    results: list[list[str] | Exception] = []

    def resolve() -> None:
        try:
            results.append(_resolve_public(host, port))
        except Exception as exc:
            results.append(exc)
        finally:
            _DNS_SLOTS.release()
            done.set()

    # A timed-out OS resolver cannot be cancelled, but can never initiate TCP;
    # at most four daemon resolvers can remain outstanding in this process.
    threading.Thread(target=resolve, daemon=True, name="fxapk-bounded-dns").start()
    if not done.wait(timeout):
        raise TimeoutError("resolution_budget_exceeded")
    result = results[0]
    if isinstance(result, Exception):
        raise result
    return result


def connect_pinned(address: str, port: int, *, timeout: float | None, source_address: Any = None,
                   socket_options: Any = None) -> socket.socket:
    address = public_ip(address)
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        for option in socket_options or []:
            sock.setsockopt(*option)
        if source_address:
            sock.bind(source_address)
        # socket.connect with a numeric address does not perform a second DNS lookup.
        sock.connect((address, port, 0, 0) if family == socket.AF_INET6 else (address, port))
        peer = public_ip(str(sock.getpeername()[0]))
        if peer != address:
            raise ValueError("connected_peer_mismatch")
        return sock
    except BaseException:
        sock.close()
        raise


def connect_first(addresses: Sequence[str], port: int, *, timeout: float | None,
                  deadline: float | None = None, source_address: Any = None,
                  socket_options: Any = None) -> socket.socket:
    if not addresses:
        raise ValueError("no_public_address")
    last_error: OSError | None = None
    for address in addresses:
        attempt_timeout = timeout
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("connection_budget_exceeded")
            attempt_timeout = remaining if timeout is None else min(timeout, remaining)
        try:
            return connect_pinned(address, port, timeout=attempt_timeout,
                                  source_address=source_address, socket_options=socket_options)
        except OSError as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


class _DeadlineReader(io.RawIOBase):
    def __init__(self, raw: Any, sock: socket.socket, deadline: float, budget: dict[str, int] | None = None):
        self.raw, self.sock, self.deadline = raw, sock, deadline
        self.budget = budget

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Response time limit")
        self.sock.settimeout(remaining)
        if self.budget is not None:
            if self.budget["remaining"] <= 0:
                raise OSError("response_byte_budget_exceeded")
            buffer = memoryview(buffer)[:self.budget["remaining"]]
        count = self.raw.readinto(buffer)
        if self.budget is not None and count:
            self.budget["remaining"] -= count
            self.budget["consumed"] += count
        return count

    def close(self) -> None:
        self.raw.close()
        super().close()


class _DeadlineSocket:
    def __init__(self, sock: socket.socket, deadline: float, budget: dict[str, int] | None = None):
        self.sock, self.deadline = sock, deadline
        self.budget = budget

    def makefile(self, mode: str) -> io.BufferedReader:
        if mode != "rb":
            raise ValueError("Only binary response reads are supported")
        raw = self.sock.makefile("rb", buffering=0)
        return io.BufferedReader(_DeadlineReader(raw, self.sock, self.deadline, self.budget))


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, request: dict[str, Any], address: str | Sequence[str], *, timeout: float | None = None):
        timeout = 15 if timeout is None else timeout
        super().__init__(request["host"], request["port"], timeout=timeout)
        self.addresses = [address] if isinstance(address, str) else list(address)
        self.address = self.addresses[0] if self.addresses else ""
        self.tls = request["scheme"] == "https"
        self._deadline = time.monotonic() + timeout
        deadline = self._deadline

        class DeadlineResponse(http.client.HTTPResponse):
            def __init__(self, sock: Any, *args: Any, **kwargs: Any):
                super().__init__(cast(Any, _DeadlineSocket(sock, deadline, request.get("_read_budget"))), *args, **kwargs)

        self.response_class = DeadlineResponse

    def connect(self) -> None:
        sock = connect_first(self.addresses, self.port, timeout=self.timeout, deadline=self._deadline)
        self.peer_ip = str(sock.getpeername()[0])
        try:
            if self.tls:
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                self.sock = context.wrap_socket(sock, server_hostname=self.host)
            else:
                self.sock = sock
        except Exception:
            sock.close()
            raise
