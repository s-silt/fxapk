"""ReconEnricher 单测：**重点测门控**（无 opt-in 不探、私网/CDN/非公网不探），mock 网络不发真请求。

合规最敏感的 enricher，测试以"绝不在不该探的时候触网"为第一优先级：
- 未设 FXAPK_ACTIVE_RECON → 立即 ok=False，零网络调用（最硬的闸）。
- 内网/回环（is_private / 私网字面）→ 跳过，零网络。
- 已知 CDN/基础设施域名 → 跳过，零网络。
- 解析到非公网 IP（CGNAT/保留）→ 跳过，零网络。
- 全门控通过才探测；探测全程 mock（socket/ssl），断言归一 dict 与授权声明日志。
另测纯函数：证书归一、HTTP 响应解析、<title> 抽取、端口→服务、forensic 渲染。
"""

from __future__ import annotations

import logging

import pytest

import apkscan.enrichers.recon as recon_mod
from apkscan.core import forensic
from apkscan.core.models import Endpoint
from apkscan.enrichers.recon import ReconEnricher


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    # 默认 opt-in 关闭；需要的测试各自 setenv。每个测试重置授权声明 once 标志与并发闸。
    monkeypatch.delenv("FXAPK_ACTIVE_RECON", raising=False)
    monkeypatch.delenv("FXAPK_ACTIVE_RECON_CONCURRENCY", raising=False)
    monkeypatch.setattr(recon_mod, "_auth_notice_emitted", False, raising=False)
    monkeypatch.setattr(recon_mod, "_SEMAPHORE", None, raising=False)


def _ep(value: str, kind: str, *, is_private: bool = False) -> Endpoint:
    return Endpoint(value=value, kind=kind, evidences=[], is_private=is_private)


class _NetGuard:
    """把 socket.create_connection / getaddrinfo / ssl 全替成爆炸版，证明"绝不触网"。"""

    def __init__(self) -> None:
        self.touched = False

    def boom(self, *a: object, **k: object) -> None:
        self.touched = True
        raise AssertionError("门控失败：不该触网却发起了连接")


# --------------------------------------------------------------------------- 门控（核心）


def test_disabled_without_optin(monkeypatch: pytest.MonkeyPatch) -> None:
    # 未设 FXAPK_ACTIVE_RECON → ok=False，且**绝不触网**（socket 一旦被调用即 AssertionError）。
    guard = _NetGuard()
    monkeypatch.setattr(recon_mod.socket, "create_connection", guard.boom)
    monkeypatch.setattr(recon_mod.socket, "getaddrinfo", guard.boom)
    res = ReconEnricher().enrich(_ep("45.33.32.156", "ip"))
    assert res.ok is False
    assert "opt-in" in (res.error or "")
    assert guard.touched is False


def test_private_endpoint_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    # opt-in 开，但端点标了 is_private → 跳过，零网络。
    monkeypatch.setenv("FXAPK_ACTIVE_RECON", "1")
    guard = _NetGuard()
    monkeypatch.setattr(recon_mod.socket, "create_connection", guard.boom)
    monkeypatch.setattr(recon_mod.socket, "getaddrinfo", guard.boom)
    res = ReconEnricher().enrich(_ep("10.0.0.5", "ip", is_private=True))
    assert res.ok is False
    assert "内网" in (res.error or "")
    assert guard.touched is False


def test_private_ip_literal_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    # opt-in 开，IP 字面是私网（未标 is_private）→ 仍被 _is_public_ip 二次自检拦下，零网络。
    monkeypatch.setenv("FXAPK_ACTIVE_RECON", "1")
    guard = _NetGuard()
    monkeypatch.setattr(recon_mod.socket, "create_connection", guard.boom)
    res = ReconEnricher().enrich(_ep("192.168.1.1", "ip"))
    assert res.ok is False
    assert "非公网" in (res.error or "")
    assert guard.touched is False


def test_loopback_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_ACTIVE_RECON", "1")
    guard = _NetGuard()
    monkeypatch.setattr(recon_mod.socket, "create_connection", guard.boom)
    res = ReconEnricher().enrich(_ep("127.0.0.1", "ip"))
    assert res.ok is False
    assert guard.touched is False


def test_cgnat_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    # 100.64/10 CGNAT 非全局 → 跳过。
    monkeypatch.setenv("FXAPK_ACTIVE_RECON", "1")
    guard = _NetGuard()
    monkeypatch.setattr(recon_mod.socket, "create_connection", guard.boom)
    res = ReconEnricher().enrich(_ep("100.64.1.1", "ip"))
    assert res.ok is False
    assert "非公网" in (res.error or "")
    assert guard.touched is False


def test_known_infra_domain_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    # 已知 CDN/基础设施域名 → 跳过（不打到第三方头上），零网络（连解析都不做）。
    monkeypatch.setenv("FXAPK_ACTIVE_RECON", "1")
    guard = _NetGuard()
    monkeypatch.setattr(recon_mod.socket, "create_connection", guard.boom)
    monkeypatch.setattr(recon_mod.socket, "getaddrinfo", guard.boom)
    res = ReconEnricher().enrich(_ep("foo.myqcloud.com", "domain"))
    assert res.ok is False
    assert "基础设施" in (res.error or "") or "CDN" in (res.error or "")
    assert guard.touched is False


def test_domain_resolving_to_private_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    # 域名解析到内网 IP（DNS 把目标指内网）→ _is_public_ip 拦下，不做端口探测。
    monkeypatch.setenv("FXAPK_ACTIVE_RECON", "1")

    def fake_getaddrinfo(host, *a, **k):  # type: ignore[no-untyped-def]
        return [(2, 1, 6, "", ("10.1.2.3", 0))]

    monkeypatch.setattr(recon_mod.socket, "getaddrinfo", fake_getaddrinfo)
    guard = _NetGuard()
    monkeypatch.setattr(recon_mod.socket, "create_connection", guard.boom)
    res = ReconEnricher().enrich(_ep("evil.example", "domain"))
    assert res.ok is False
    assert "非公网" in (res.error or "")
    assert guard.touched is False  # 解析了，但没发起任何 connect


# --------------------------------------------------------------------------- 探测（门控通过后）


def test_optin_public_ip_probes_and_emits_notice(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # 全门控通过：opt-in 开 + 公网 IP。mock 端口探测：只有 80 开放，其它拒绝。
    monkeypatch.setenv("FXAPK_ACTIVE_RECON", "1")

    opened: list[int] = []

    class _Sock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def close(self): pass

    def fake_create_connection(addr, timeout=None, **k):  # type: ignore[no-untyped-def]
        _ip, port = addr
        if port == 80:
            opened.append(port)
            return _Sock()
        raise OSError("connection refused")

    monkeypatch.setattr(recon_mod.socket, "create_connection", fake_create_connection)
    # http 探测：让 _http_exchange 直接返回成功（避免触真 socket recv）。
    monkeypatch.setattr(
        recon_mod,
        "_http_exchange",
        lambda ip, port, use_tls, host, path, timeout: (
            (200, {"server": "nginx", "x-powered-by": "PHP/7.4"}, "<title>XX管理后台</title>")
            if path == "/"
            else (200, {}, "<title>admin</title>")
            if path == "/admin"
            else None
        ),
    )

    with caplog.at_level(logging.WARNING, logger="apkscan.enrichers.recon"):
        res = ReconEnricher().enrich(_ep("45.33.32.156", "ip"))

    assert res.ok is True
    d = res.data
    assert d["open_ports"] == [80]
    assert d["active"] is True and d["source"] == "recon"
    assert d["target_ip"] == "45.33.32.156"
    http = d["http"]
    assert any(h["server"] == "nginx" and h["status"] == 200 for h in http)
    assert any(h.get("title") == "XX管理后台" for h in http)
    # 暴露后台路径命中 /admin。
    assert any(p["path"] == "/admin" and p["status"] == 200 for p in d["exposed_paths"])
    # 授权声明日志已打。
    assert any("主动探测已启用" in r.message for r in caplog.records)


def test_optin_values_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    # opt-in 接受 1/true/yes/on（大小写不敏感），其它值视为关。
    for on in ("1", "true", "TRUE", "Yes", "on"):
        monkeypatch.setenv("FXAPK_ACTIVE_RECON", on)
        assert recon_mod._enabled() is True
    for off in ("0", "false", "no", "", "off", "x"):
        monkeypatch.setenv("FXAPK_ACTIVE_RECON", off)
        assert recon_mod._enabled() is False


def test_empty_value_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_ACTIVE_RECON", "1")
    res = ReconEnricher().enrich(_ep("   ", "ip"))
    assert res.ok is False


# --------------------------------------------------------------------------- 纯函数


def test_is_public_ip() -> None:
    assert recon_mod._is_public_ip("45.33.32.156") is True
    assert recon_mod._is_public_ip("8.8.8.8") is True
    assert recon_mod._is_public_ip("10.0.0.1") is False
    assert recon_mod._is_public_ip("192.168.0.1") is False
    assert recon_mod._is_public_ip("127.0.0.1") is False
    assert recon_mod._is_public_ip("169.254.1.1") is False  # 链路本地
    assert recon_mod._is_public_ip("100.64.0.1") is False   # CGNAT
    assert recon_mod._is_public_ip("not-an-ip") is False


def test_parse_http_response() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Powered-By: PHP/7.4\r\n\r\n"
        b"<html><head><title>  Admin  Panel </title></head></html>"
    )
    parsed = recon_mod._parse_http_response(raw)
    assert parsed is not None
    status, headers, body = parsed
    assert status == 200
    assert headers["server"] == "nginx"
    assert headers["x-powered-by"] == "PHP/7.4"
    assert "Admin" in body
    assert recon_mod._parse_http_response(b"") is None


def test_extract_title() -> None:
    assert recon_mod._extract_title("<title>X 后台</title>") == "X 后台"
    assert recon_mod._extract_title("<TITLE>\n a \n b </TITLE>") == "a b"
    assert recon_mod._extract_title("<html>no title</html>") == ""
    assert recon_mod._extract_title("") == ""


def _make_self_signed_der(
    cn: str = "evil.example", sans: tuple[str, ...] = ("evil.example", "www.evil.example")
) -> bytes:
    """现造一张自签证书并返回 DER 字节（_parse_cert 现走 DER 解析，必须喂真实 DER）。"""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"),
            x509.NameAttribute(NameOID.COMMON_NAME, "R3"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2024, 4, 1, tzinfo=datetime.timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_cert_from_der() -> None:
    # ★ 回归（review high）：CERT_NONE 下 getpeercert() 非 binary 恒空，必须用 DER 解析。
    der = _make_self_signed_der()
    out = recon_mod._parse_cert(der, ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), 443)
    assert out["port"] == 443
    assert "evil.example" in out["subject"]  # rfc4514: CN=evil.example
    assert "Let's Encrypt" in out["issuer"]
    assert set(out["san"]) == {"evil.example", "www.evil.example"}
    assert out["not_after"].startswith("2024-04-01")  # ISO 格式有效期
    assert out["not_before"].startswith("2024-01-01")
    assert out["cipher"] == "TLS_AES_256_GCM_SHA384"


def test_parse_cert_empty_or_bad_der_safe() -> None:
    # der 为空/None/非字节（如非 TLS 端口）→ 安全返回 port + cipher，不抛、不静默丢错。
    for bad in (b"", None, "notbytes", b"\x00\x01garbage"):
        out = recon_mod._parse_cert(bad, ("c",), 8443)
        assert out["port"] == 8443 and out["cipher"] == "c"
        assert "subject" not in out  # 坏证书不臆造字段


def test_ports_to_services() -> None:
    svcs = recon_mod._ports_to_services([6379, 22, 80])
    by_port = {s["port"]: s["service"] for s in svcs}
    assert by_port[22] == "SSH" and by_port[6379] == "Redis" and by_port[80] == "HTTP"
    # 已排序去重。
    assert [s["port"] for s in svcs] == [22, 80, 6379]


# --------------------------------------------------------------------------- forensic 渲染


def test_render_active_recon() -> None:
    lines = forensic.render_active_recon({
        "open_ports": [22, 80, 6379],
        "services": [
            {"port": 22, "service": "SSH"},
            {"port": 80, "service": "HTTP"},
            {"port": 6379, "service": "Redis"},
        ],
        "http": [{"port": 80, "status": 200, "server": "nginx", "title": "XX管理后台"}],
        "tls": {"443": {"subject": "CN=evil.com", "issuer": "Let's Encrypt", "not_after": "2024"}},
        "exposed_paths": [
            {"path": "/admin", "status": 200},
            {"path": "/druid", "status": 401, "title": "Druid"},
        ],
        "active": True,
        "source": "recon",
    })
    blob = "\n".join(lines)
    assert "主动探测·已授权" in blob
    assert "22(SSH)" in blob and "6379(Redis)" in blob
    assert "Server=nginx" in blob and "XX管理后台" in blob
    assert "/admin(200)" in blob and "/druid(401)" in blob
    # 每一行都带"主动探测·已授权"前缀（合规审计可区分主动 vs 被动）。
    assert all(line.startswith("主动探测·已授权") for line in lines)


def test_render_active_recon_empty() -> None:
    assert forensic.render_active_recon(None) == []
    assert forensic.render_active_recon({}) == []
    assert forensic.render_active_recon("notdict") == []


def test_render_active_recon_skips_noise_status0() -> None:
    # ★ 回归（review low）：非 HTTP 服务回 status=0 且无指纹 → 不渲染无信息量的"…HTTP 指纹：80 0"。
    lines = forensic.render_active_recon({"http": [{"port": 80, "status": 0}]})
    assert not any("HTTP 指纹" in ln for ln in lines)
    # 但 status=0 却有有效指纹（server/标题）→ 仍保留弱指纹（有取证价值），且不渲染无意义的 0。
    lines2 = forensic.render_active_recon({"http": [{"port": 80, "status": 0, "server": "nginx"}]})
    blob = "\n".join(lines2)
    assert "HTTP 指纹" in blob and "Server=nginx" in blob and " 0" not in blob


def test_host_for_header_ipv6_bracketed() -> None:
    # ★ 回归（review low）：IPv6 字面量 Host 头须加方括号（RFC 7230），否则对端返 400。
    assert recon_mod._host_for_header("2606:4700::1") == "[2606:4700::1]"
    assert recon_mod._host_for_header("1.2.3.4") == "1.2.3.4"
    assert recon_mod._host_for_header("evil.example") == "evil.example"


def test_classify_jurisdiction_accepts_recon_kwarg() -> None:
    # recon 透传进 classify_jurisdiction 不得 TypeError（pipeline **enr 统一透传）。
    assert (
        forensic.classify_jurisdiction("evil.example", recon={"open_ports": [80]})
        == forensic.JURIS_UNKNOWN
    )
