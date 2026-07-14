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


# ---------------------------------------------------------------------------
# P2：NSS TLS Key Log 解密路径（HTTP/1.1-over-TLS + HTTP/2 成对合并）
# ---------------------------------------------------------------------------
# 解密 TSV 列序（10 列）：http.host, http2.authority, http.method, http2.method,
#   http.uri, http2.path, http.ua, http2.ua, ip.dst, tcp.dstport。
_DEC_TSV = "\n".join([
    # HTTP/2 行（host 在 :authority）
    "\t".join(["", "api.evil.com", "", "POST", "", "/zj/api/user_login", "", "okhttp/4.9", "1.2.3.4", "443"]),
    # HTTP/1.1-over-TLS 行（host 在 http.host）
    "\t".join(["secure.evil.com", "", "GET", "", "/config", "", "Dalvik/2.1", "", "5.6.7.8", "443"]),
    # 无 host/authority → 跳过
    "\t".join(["", "", "GET", "", "", "/x", "", "", "9.9.9.9", "443"]),
    "",  # 空行跳过
])


def test_looks_like_keylog(tmp_path) -> None:
    good = tmp_path / "tls.keys"
    good.write_text("# SSL/TLS secrets log\nCLIENT_RANDOM 5a2f def456\n", encoding="utf-8")  # 注释后即标签
    assert tshark_backend._looks_like_keylog(good) is True
    bad = tmp_path / "notkeys.txt"
    bad.write_text("hello world\nnothing to see\n", encoding="utf-8")
    assert tshark_backend._looks_like_keylog(bad) is False
    assert tshark_backend._looks_like_keylog(tmp_path / "missing") is False  # 缺文件 → False、不抛


def test_looks_like_keylog_scan_bounded(tmp_path) -> None:
    """★标签在 200 行扫描窗之外 → 不认（扫描上限有界，防对大文件全量逐行）。"""
    late = tmp_path / "late.keys"
    late.write_text("# comment\n" * 300 + "CLIENT_RANDOM aa bb\n", encoding="utf-8")
    assert tshark_backend._looks_like_keylog(late) is False  # 第 301 行的标签落在 200 行窗外


def test_parse_decrypted_fields() -> None:
    reqs = tshark_backend.parse_decrypted_fields(_DEC_TSV)
    assert len(reqs) == 2  # 无 host 行 + 空行不计
    assert reqs[0].host == "api.evil.com" and reqs[0].method == "POST"  # h2 :authority/:method 合并
    assert reqs[0].uri == "/zj/api/user_login" and reqs[0].user_agent == "okhttp/4.9"
    assert reqs[0].dst_ip == "1.2.3.4" and reqs[0].dst_port == "443"
    assert reqs[1].host == "secure.evil.com" and reqs[1].method == "GET" and reqs[1].uri == "/config"


def test_parse_decrypted_robust() -> None:
    assert tshark_backend.parse_decrypted_fields("") == []
    assert tshark_backend.parse_decrypted_fields(None) == []  # type: ignore[arg-type]
    # 列不足 → host/method 仍取、其余置空、不抛
    r = tshark_backend.parse_decrypted_fields("\tonlyauthority.com")
    assert r and r[0].host == "onlyauthority.com" and r[0].uri == ""


def test_run_tshark_decrypt_rejects_bad_keylog(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: "/usr/bin/tshark")
    assert tshark_backend.run_tshark_decrypt("x.pcap", str(tmp_path / "missing")) is None  # 缺
    empty = tmp_path / "empty.keys"
    empty.write_text("", encoding="utf-8")
    assert tshark_backend.run_tshark_decrypt("x.pcap", str(empty)) is None  # 空
    junk = tmp_path / "junk"
    junk.write_text("not a keylog at all\n", encoding="utf-8")
    assert tshark_backend.run_tshark_decrypt("x.pcap", str(junk)) is None  # 非 NSS
    assert tshark_backend.extract_decrypted_http("x.pcap", str(junk)) == []


def test_run_tshark_decrypt_absent_tshark(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: None)
    kl = tmp_path / "tls.keys"
    kl.write_text("CLIENT_RANDOM aa bb\n", encoding="utf-8")
    assert tshark_backend.run_tshark_decrypt("x.pcap", str(kl)) is None  # tshark 缺 → None、不抛


def test_run_tshark_decrypt_mocked(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: "/usr/bin/tshark")
    kl = tmp_path / "tls.keys"
    kl.write_text("CLIENT_RANDOM aa bb\n", encoding="utf-8")
    captured: dict = {}

    def _fake_run(cmd, **kw):  # noqa: ANN001, ANN202
        captured["cmd"] = cmd
        kw["stdout"].write(_DEC_TSV.encode("utf-8"))
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(tshark_backend.subprocess, "run", _fake_run)
    reqs = tshark_backend.extract_decrypted_http("x.pcap", str(kl))
    assert len(reqs) == 2 and reqs[0].host == "api.evil.com"
    kl_arg = next(str(c) for c in captured["cmd"] if str(c).startswith("tls.keylog_file:"))
    assert "\\" not in kl_arg  # ★正斜杠化：pref 值无反斜杠（Windows 下 tshark 才不误解析）


def test_decrypted_to_endpoints() -> None:
    reqs = tshark_backend.parse_decrypted_fields(_DEC_TSV)
    eps = tshark_backend.decrypted_to_endpoints(reqs, observed_at=99.0)
    assert {e.value for e in eps} == {"api.evil.com", "secure.evil.com"}
    for e in eps:
        assert e.is_cleartext is False  # ★解密还原 ≠ 明文
        assert e.kind == "domain"
        assert e.evidences[0].source == "runtime-tls-decrypted"
        assert e.evidences[0].observed_at == 99.0
    api = next(e for e in eps if e.value == "api.evil.com")
    assert "TLS 解密" in api.evidences[0].snippet
    assert "https://api.evil.com/zj/api/user_login" in api.evidences[0].snippet  # https + 解密 URL


def test_cleartext_to_endpoints_unchanged() -> None:
    """★回归：重构 to_endpoints 后明文路径行为不变（is_cleartext=True、http scheme、明文 HTTP 标签）。"""
    reqs = tshark_backend.parse_http_fields(_TSV)
    eps = tshark_backend.to_endpoints(reqs)
    assert all(e.is_cleartext for e in eps)
    c2 = next(e for e in eps if e.value == "c2.evil.com")
    assert c2.evidences[0].source == "runtime-tshark"
    assert "明文 HTTP" in c2.evidences[0].snippet and "http://c2.evil.com" in c2.evidences[0].snippet


def test_run_tshark_decrypt_ssl_fallback_old_wireshark(monkeypatch, tmp_path) -> None:
    """★复审 Finding2：旧 Wireshark(<3.0) 的 tls.keylog_file 是未知 pref → 非零+空产出 → 回退 ssl.keylog_file。"""
    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: "/usr/bin/tshark")
    kl = tmp_path / "tls.keys"
    kl.write_text("CLIENT_RANDOM aa bb\n", encoding="utf-8")
    calls: list[str] = []

    def _fake_run(cmd, **kw):  # noqa: ANN001, ANN202
        joined = " ".join(str(c) for c in cmd)
        calls.append(joined)
        if "ssl.keylog_file:" in joined:  # 回退路径：ssl 成功、有产出
            kw["stdout"].write(_DEC_TSV.encode("utf-8"))
            return types.SimpleNamespace(returncode=0)
        return types.SimpleNamespace(returncode=1)  # tls 首跑：未知 pref → 非零、空产出

    monkeypatch.setattr(tshark_backend.subprocess, "run", _fake_run)
    reqs = tshark_backend.extract_decrypted_http("x.pcap", str(kl))
    assert len(reqs) == 2  # 回退 ssl 成功解出
    assert any("tls.keylog_file:" in c for c in calls) and any("ssl.keylog_file:" in c for c in calls)


def test_run_tshark_decrypt_no_fallback_when_tls_ok(monkeypatch, tmp_path) -> None:
    """tls.keylog_file 有产出 → 不回退、只跑一次（现代 Wireshark 不因未知 ssl 别名多跑/破功）。"""
    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: "/usr/bin/tshark")
    kl = tmp_path / "tls.keys"
    kl.write_text("CLIENT_RANDOM aa bb\n", encoding="utf-8")
    calls: list[str] = []

    def _fake_run(cmd, **kw):  # noqa: ANN001, ANN202
        calls.append(" ".join(str(c) for c in cmd))
        kw["stdout"].write(_DEC_TSV.encode("utf-8"))
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(tshark_backend.subprocess, "run", _fake_run)
    tshark_backend.extract_decrypted_http("x.pcap", str(kl))
    assert len(calls) == 1 and "tls.keylog_file:" in calls[0]  # 只跑一次、tls 路径


# ---------------------------------------------------------------------------
# P2 续：解密后凭据头（Authorization/Cookie=登录态/token）抽取（未脱敏，脱敏由 caller 做）
# ---------------------------------------------------------------------------
# 凭据 TSV 列序（10）：host, authority, method, h2method, uri, h2path, http.authz, h2.authz, http.cookie, h2.cookie。
_CRED_TSV = "\n".join([
    # HTTP/2 登录请求：Authorization 在 http2.headers.authorization（col7）
    "\t".join(["", "api.evil.com", "", "POST", "", "/zj/api/user_login", "", "Bearer secrettoken1234567890", "", ""]),
    # HTTP/1.1 请求：Cookie 在 http.cookie（col8）
    "\t".join(["secure.evil.com", "", "GET", "", "/config", "", "", "", "sid=abc; token=xyz", ""]),
    # 无凭据头（filter 理论不产出，防御性）→ 丢弃
    "\t".join(["nohdr.evil.com", "", "GET", "", "/x", "", "", "", "", ""]),
    "",
])


def test_parse_decrypted_credentials() -> None:
    creds = tshark_backend.parse_decrypted_credentials(_CRED_TSV)
    assert len(creds) == 2  # 无凭据头行不计
    assert creds[0]["source"] == "tls-decrypted"
    assert creds[0]["url"] == "https://api.evil.com/zj/api/user_login" and creds[0]["method"] == "POST"
    assert creds[0]["headers"]["Authorization"] == "Bearer secrettoken1234567890"  # 未脱敏（脱敏在 caller）
    assert "Cookie" not in creds[0]["headers"]
    assert creds[1]["headers"]["Cookie"] == "sid=abc; token=xyz" and "Authorization" not in creds[1]["headers"]


def test_parse_decrypted_credentials_robust() -> None:
    assert tshark_backend.parse_decrypted_credentials("") == []
    assert tshark_backend.parse_decrypted_credentials(None) == []  # type: ignore[arg-type]
    assert tshark_backend.parse_decrypted_credentials("a\tb\tc") == []  # 列数≠10（tab 溢出）→ 丢弃、不产错


def test_extract_decrypted_credentials_mocked(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(tshark_backend.shutil, "which", lambda _n: "/usr/bin/tshark")
    kl = tmp_path / "tls.keys"
    kl.write_text("CLIENT_RANDOM aa bb\n", encoding="utf-8")

    def _fake_run(cmd, **kw):  # noqa: ANN001, ANN202
        assert "http.authorization" in " ".join(str(c) for c in cmd)  # 用了凭据 filter/字段
        kw["stdout"].write(_CRED_TSV.encode("utf-8"))
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(tshark_backend.subprocess, "run", _fake_run)
    creds = tshark_backend.extract_decrypted_credentials("x.pcap", str(kl))
    assert len(creds) == 2 and creds[0]["headers"]["Authorization"].startswith("Bearer")
