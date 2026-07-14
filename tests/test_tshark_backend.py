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
    assert all(e.is_cleartext for e in eps)  # ★复审 #6：明文 HTTP 端点定义上就是 cleartext
    c2 = next(e for e in eps if e.value == "c2.evil.com")
    assert c2.evidences[0].source == "runtime-tshark"
    assert "明文 HTTP POST" in c2.evidences[0].snippet and "1.2.3.4:80" in c2.evidences[0].snippet
    assert c2.evidences[0].observed_at == 123.0


def test_host_normalization() -> None:
    """★复审 #4/#9：Host 归一化——剥 :port、小写、去尾点、IP 字面量→kind=ip；归一后同 Host 才 dedup。"""
    reqs = [
        tshark_backend.HttpRequest(host="API.Evil.COM:8443", method="GET", uri="/a"),
        tshark_backend.HttpRequest(host="api.evil.com.", method="POST", uri="/b"),  # 尾点 → 同一 Host
        tshark_backend.HttpRequest(host="43.155.1.2", method="GET", uri="/c"),       # IP 字面量
    ]
    eps = tshark_backend.to_endpoints(reqs)
    vals = {e.value: e.kind for e in eps}
    assert vals == {"api.evil.com": "domain", "43.155.1.2": "ip"}  # 大小写/端口/尾点归一后 dedup 为一


def test_tab_in_field_defense() -> None:
    """★复审 #7：字段值内嵌 tab 致列溢出 → uri/ua/ip/port 不可信置空，host/method 仍保留、不产错域名。"""
    line = "evil.com\tGET\t/path\twith\ttab\tinUA\t1.2.3.4\t80"  # URI/UA 里的 tab 撑出 8 列
    r = tshark_backend.parse_http_fields(line)
    assert len(r) == 1 and r[0].host == "evil.com" and r[0].method == "GET"
    assert r[0].uri == "" and r[0].dst_ip == ""  # 列溢出 → 后续列一律置空
    # 正常行里坏 IP/端口也置空
    r2 = tshark_backend.parse_http_fields("x.com\tGET\t/\t\tnot-an-ip\tNaN")
    assert r2[0].dst_ip == "" and r2[0].dst_port == ""


def test_run_tshark_absent_returns_none(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: None)
    assert tshark_backend.run_tshark_http("x.pcap") is None
    assert tshark_backend.extract_http("x.pcap") == []  # tshark 缺 → 空、不抛
    assert tshark_backend.has_tshark() is False


def test_run_tshark_mocked_subprocess(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: "/usr/bin/tshark")

    def _fake_run(cmd, **kw):  # 新实现把 stdout 落临时文件（内存有界）→ mock 写进去
        kw["stdout"].write(_TSV.encode("utf-8"))
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(tshark_backend.subprocess, "run", _fake_run)
    reqs = tshark_backend.extract_http("x.pcap")
    assert len(reqs) == 3 and reqs[0].host == "c2.evil.com"


def test_run_tshark_timeout_returns_none(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import subprocess as _sp

    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: "/usr/bin/tshark")

    def _boom(*a, **k):
        raise _sp.TimeoutExpired(cmd="tshark", timeout=60)

    monkeypatch.setattr(tshark_backend.subprocess, "run", _boom)
    assert tshark_backend.run_tshark_http("x.pcap") is None  # 超时 → None、不抛
