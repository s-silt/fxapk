"""Safety regression: accidental external requests fail before leaving Python."""
import socket

import pytest


def test_external_dns_is_blocked_before_resolution():
    with pytest.raises(OSError, match="external network disabled"):
        socket.getaddrinfo("example.invalid", 443)
    with pytest.raises(OSError, match="external network disabled"):
        socket.gethostbyname("example.invalid")


def test_external_tcp_and_udp_are_blocked():
    with socket.socket() as connection:
        with pytest.raises(OSError, match="external network disabled"):
            connection.connect(("192.0.2.1", 443))
        with pytest.raises(OSError, match="external network disabled"):
            connection.connect_ex(("192.0.2.1", 443))
    with socket.socket(type=socket.SOCK_DGRAM) as connection:
        with pytest.raises(OSError, match="external network disabled"):
            connection.sendto(b"CANARY", ("192.0.2.1", 53))


def test_loopback_fixture_remains_available():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=1) as client:
            peer, _ = server.accept()
            with peer:
                client.sendall(b"CANARY")
                assert peer.recv(6) == b"CANARY"
