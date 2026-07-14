"""tshark 可选深度后端（明文 HTTP 抽取）：解析纯逻辑离线测 + 子进程 mock。"""

from __future__ import annotations

import types

from apkscan.dynamic import tshark_backend

# tshark -T fields 的 TSV（列序：host method uri user_agent ip.dst tcp.dstport；TAB 分隔）。
_TSV = "\n".join([
    "c2.evil.com\tPOST\t/api/report\tokhttp/4.9\t1.2.3.4\t80",
    "c2.evil.com\tGET\t/api/config\tokhttp/4.9\t1.2.3.4\t80",
    "\tGET\t/no-host\t\t5.6.7.8\t80",          # host 为空 → 跳过
    "tracker.x.com\tGET\t/t\t\t9.9.9.9\t8080",  # UA 缺（列少）也解
    "",                                          # 空行跳过
])


def test_parse_http_fields() -> None:
    reqs = tshark_backend.parse_http_fields(_TSV)
    assert len(reqs) == 3  # 空 host 与空行不计
    assert reqs[0].host == "c2.evil.com" and reqs[0].method == "POST" and reqs[0].uri == "/api/report"
    assert reqs[0].user_agent == "okhttp/4.9" and reqs[0].dst_ip == "1.2.3.4" and reqs[0].dst_port == "80"
    assert reqs[2].host == "tracker.x.com" and reqs[2].uri == "/t"


def test_parse_robust() -> None:
    assert tshark_backend.parse_http_fields("") == []
    assert tshark_backend.parse_http_fields(None) == []  # type: ignore[arg-type]
    # 列不足 → 补空、不抛
    r = tshark_backend.parse_http_fields("onlyhost\tGET")
    assert r and r[0].host == "onlyhost" and r[0].method == "GET" and r[0].uri == ""


def test_to_endpoints_dedup_by_host() -> None:
    reqs = tshark_backend.parse_http_fields(_TSV)
    eps = tshark_backend.to_endpoints(reqs, observed_at=123.0)
    hosts = {e.value for e in eps}
    assert hosts == {"c2.evil.com", "tracker.x.com"}  # 一 Host 一端点（dedup）
    assert all(e.kind == "domain" for e in eps)
    c2 = next(e for e in eps if e.value == "c2.evil.com")
    assert c2.evidences[0].source == "runtime-tshark"
    assert "明文 HTTP POST" in c2.evidences[0].snippet and "1.2.3.4:80" in c2.evidences[0].snippet
    assert c2.evidences[0].observed_at == 123.0


def test_run_tshark_absent_returns_none(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: None)
    assert tshark_backend.run_tshark_http("x.pcap") is None
    assert tshark_backend.extract_http("x.pcap") == []  # tshark 缺 → 空、不抛
    assert tshark_backend.has_tshark() is False


def test_run_tshark_mocked_subprocess(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: "/usr/bin/tshark")
    monkeypatch.setattr(
        tshark_backend.subprocess, "run",
        lambda *a, **k: types.SimpleNamespace(stdout=_TSV, returncode=0),
    )
    reqs = tshark_backend.extract_http("x.pcap")
    assert len(reqs) == 3 and reqs[0].host == "c2.evil.com"


def test_run_tshark_timeout_returns_none(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import subprocess as _sp

    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: "/usr/bin/tshark")

    def _boom(*a, **k):
        raise _sp.TimeoutExpired(cmd="tshark", timeout=60)

    monkeypatch.setattr(tshark_backend.subprocess, "run", _boom)
    assert tshark_backend.run_tshark_http("x.pcap") is None  # 超时 → None、不抛
