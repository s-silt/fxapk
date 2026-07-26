"""自带 DoH / HTTPDNS 解析检测：取证可见性信号。零真实样本，合成标记。"""
from __future__ import annotations

from apkscan.analyzers.dns_bypass import DnsBypassAnalyzer, assess_markers
from tests.conftest import FakeContext

_FID = "APP-MANAGED-DNS-RESOLUTION"


def _analyze(dex_strings=None, files=None):
    return DnsBypassAnalyzer().analyze(FakeContext(dex_strings=dex_strings, files=files))


def _ids(result) -> list[str]:
    return [f.id for f in result.findings]


def test_doh_wire_format_detected():
    """★RFC 8484 线格式 MIME 是最硬的一条：命中即说明 App 内含 DoH 客户端。"""
    result = _analyze(dex_strings=["Content-Type: application/dns-message", "other"])
    assert _FID in _ids(result)
    assert result.meta["dns_bypass"]["protocol"] == ["application/dns-message"]


def test_doh_query_path_detected():
    result = _analyze(dex_strings=["https://example-resolver.test/dns-query"])
    assert _FID in _ids(result)


def test_httpdns_sdk_detected():
    """商用 HTTPDNS SDK 同样绕开系统 DNS，对取证可见性影响一致。"""
    result = _analyze(dex_strings=["https://resolvers-cn.httpdns.aliyuncs.com/resolve"])
    assert _FID in _ids(result)
    f = next(f for f in result.findings if f.id == _FID)
    assert "HTTPDNS" in f.title


def test_resolver_hostname_alone_does_not_fire():
    """★无修复即失败：只出现公共解析器主机名 → **不**触发。

    这类串可能只是配置默认值，单独命中不足以说明 App 自带解析；把它当判据会让大量正常
    App 中招（实测语料里裸解析器主机名极常见）。
    """
    result = _analyze(dex_strings=["dns.alidns.com", "doh.pub", "dns.google", "1.1.1.1"])
    assert _FID not in _ids(result)
    hits = result.meta["dns_bypass"]
    assert hits["resolver"], "解析器主机名仍应被记录（作佐证），只是不单独触发"
    assert not hits["protocol"] and not hits["sdk"]


def test_clean_app_not_flagged():
    result = _analyze(dex_strings=["com.example.MainActivity", "https://api.example.test/v1"])
    assert _FID not in _ids(result)


def test_finding_is_low_severity_visibility_signal():
    """★这是能力/可见性信号不是罪状：语料里约三分之一样本具备，严重度不得拔高。"""
    from apkscan.core.models import Severity
    result = _analyze(dex_strings=["application/dns-message"])
    f = next(f for f in result.findings if f.id == _FID)
    assert f.severity == Severity.LOW
    assert "不能" in f.description and "推出" in f.description   # 明确否定「DNS 无记录=没访问」
    assert "SNI" in f.recommendation                            # 给出替代取证路径


def test_markers_found_in_native_so():
    """标记在 .so 里同样能命中（实测语料中多数出现在 native 侧）。"""
    so = b"\x7fELF" + b"POST /dns-query HTTP/1.1 application/dns-message " * 4
    result = _analyze(files={"lib/arm64-v8a/libnet.so": so})
    assert _FID in _ids(result)


def test_assess_markers_pure_function():
    hits = assess_markers("X application/dns-message Y httpdns.aliyuncs.com Z doh.pub")
    assert hits["protocol"] == ["application/dns-message"]
    assert hits["sdk"] == ["httpdns.aliyuncs.com"]
    assert hits["resolver"] == ["doh.pub"]
    assert assess_markers("") == {"protocol": [], "sdk": [], "resolver": []}
