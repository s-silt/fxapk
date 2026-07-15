"""ShodanEnricher 单测：mock 网络（requests），不发真实请求。

覆盖 opt-in 门控（未配 key → 跳过）、IP host 解析、domain→resolve→host、404 查无记录（缓存避免复查）、
网络异常 ok=False、缓存命中跳过触网、Shodan 归属国喂 forensic 辖区判定、境外源站被动定位渲染。
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

import apkscan.enrichers.shodan as sh_mod
from apkscan.core import forensic
from apkscan.core.models import Endpoint
from apkscan.enrichers.shodan import ShodanEnricher

# 取自真实 scanme.nmap.org 响应的精简样例（字段形态一致）。
_HOST_PAYLOAD = {
    "ip_str": "45.33.32.156",
    "ports": [80, 22, 31337],
    "hostnames": ["scanme.nmap.org"],
    "org": "Linode",
    "isp": "Linode",
    "asn": "AS63949",
    "country_name": "United States",
    "os": None,
    "tags": ["cloud"],
    "vulns": ["CVE-2021-44790", "CVE-2021-40438"],
    "data": [
        {
            "port": 22,
            "transport": "tcp",
            "_shodan": {"module": "ssh"},
            "product": "OpenSSH",
            "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
            "cpe": ["cpe:/a:openbsd:openssh:6.6.1p1"],
        },
        {
            "port": 80,
            "transport": "tcp",
            "_shodan": {"module": "http"},
            "product": "Apache httpd",
            "version": "2.4.7",
            "cpe": ["cpe:/a:apache:http_server:2.4.7"],
            "http": {"server": "Apache/2.4.7 (Ubuntu)", "title": "Go ahead and ScanMe!"},
        },
    ],
}


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sh_mod, "CACHE_DIR", tmp_path / ".apkscan_cache")
    monkeypatch.setattr(sh_mod, "CACHE_FILE", tmp_path / ".apkscan_cache" / "shodan.json")
    # 默认无 key（opt-in 关）；需要的测试各自 setenv。
    monkeypatch.delenv("FXAPK_SHODAN_KEY", raising=False)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)


class _Resp:
    def __init__(self, status: int, payload: object) -> None:
        self.status_code = status
        self._p = payload

    def json(self) -> object:
        return self._p

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeRequests:
    """按 URL 片段分发；记录调用便于断言触网次数/解析路径。"""

    def __init__(self, mapping: dict[str, tuple[int, object]]) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    def get(self, url: str, params: dict | None = None, timeout: float | None = None) -> _Resp:
        self.calls.append(url)
        for frag, (status, payload) in self.mapping.items():
            if frag in url:
                return _Resp(status, payload)
        return _Resp(404, {})


def _ep(value: str, kind: str) -> Endpoint:
    return Endpoint(value=value, kind=kind, evidences=[])


def test_disabled_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeRequests({})
    monkeypatch.setattr(sh_mod, "requests", fake)
    res = ShodanEnricher().enrich(_ep("45.33.32.156", "ip"))
    assert res.ok is False
    assert not fake.calls  # opt-in 未开，绝不触网


def test_ip_host_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_SHODAN_KEY", "testkey")
    fake = _FakeRequests({"/shodan/host/45.33.32.156": (200, _HOST_PAYLOAD)})
    monkeypatch.setattr(sh_mod, "requests", fake)
    res = ShodanEnricher().enrich(_ep("45.33.32.156", "ip"))
    assert res.ok is True
    d = res.data
    assert d["ports"] == [22, 80, 31337]  # 归一去重数值排序
    assert d["country"] == "United States"
    assert d["asn"] == "AS63949"
    assert "vulns" not in d and "vuln_total" not in d  # 被动归属：只识别真源站/归属，不采集漏洞字段
    assert d["hostnames"] == ["scanme.nmap.org"]
    svc80 = next(s for s in d["services"] if s["port"] == 80)
    assert svc80["product"] == "Apache httpd" and svc80["version"] == "2.4.7"
    assert svc80["http_server"] == "Apache/2.4.7 (Ubuntu)"


def test_domain_resolves_then_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "testkey")  # 兼容官方变量名
    fake = _FakeRequests({
        "/dns/resolve": (200, {"evil.example": "45.33.32.156"}),
        "/shodan/host/45.33.32.156": (200, _HOST_PAYLOAD),
    })
    monkeypatch.setattr(sh_mod, "requests", fake)
    res = ShodanEnricher().enrich(_ep("evil.example", "domain"))
    assert res.ok is True
    assert res.data["country"] == "United States"
    assert any("/dns/resolve" in c for c in fake.calls)  # 走了解析
    assert any("/shodan/host/45.33.32.156" in c for c in fake.calls)


def test_host_404_miss_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_SHODAN_KEY", "testkey")
    fake = _FakeRequests({})  # 全 404 → 库中无记录
    monkeypatch.setattr(sh_mod, "requests", fake)
    e = ShodanEnricher()
    res = e.enrich(_ep("1.2.3.4", "ip"))
    assert res.ok is True  # 查无记录是 ok=True 空结果（非错误）
    assert "note" in res.data and not res.data.get("ports")
    n = len(fake.calls)
    e.enrich(_ep("1.2.3.4", "ip"))  # 二次：命中缓存空标记
    assert len(fake.calls) == n  # 未再触网（省额度）


def test_network_error_ok_false_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_SHODAN_KEY", "testkey")
    fake = _FakeRequests({"/shodan/host/45.33.32.156": (500, {})})  # 500 → raise_for_status 抛
    monkeypatch.setattr(sh_mod, "requests", fake)
    e = ShodanEnricher()
    res = e.enrich(_ep("45.33.32.156", "ip"))
    assert res.ok is False
    n = len(fake.calls)
    e.enrich(_ep("45.33.32.156", "ip"))  # 失败不缓存 → 再次触网
    assert len(fake.calls) > n


def test_network_error_never_exposes_api_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "synthetic-shodan-secret"
    monkeypatch.setenv("FXAPK_SHODAN_KEY", secret)

    class _LeakyRequests:
        @staticmethod
        def get(*args: object, **kwargs: object) -> _Resp:
            raise RuntimeError(f"request failed: https://api.example.test/?key={secret}")

    monkeypatch.setattr(sh_mod, "requests", _LeakyRequests())
    with caplog.at_level(logging.DEBUG):
        result = ShodanEnricher().enrich(_ep("198.51.100.10", "ip"))

    assert result.ok is False
    assert secret not in str(result.error)
    assert secret not in caplog.text


def test_cache_hit_skips_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_SHODAN_KEY", "testkey")
    fake = _FakeRequests({"/shodan/host/45.33.32.156": (200, _HOST_PAYLOAD)})
    monkeypatch.setattr(sh_mod, "requests", fake)
    e = ShodanEnricher()
    e.enrich(_ep("45.33.32.156", "ip"))
    n = len(fake.calls)
    e.enrich(_ep("45.33.32.156", "ip"))
    assert len(fake.calls) == n


def test_forensic_uses_shodan_country() -> None:
    assert (
        forensic.classify_jurisdiction("1.2.3.4", shodan={"country": "United States"})
        == forensic.JURIS_FOREIGN
    )
    assert (
        forensic.classify_jurisdiction("1.2.3.4", shodan={"country": "China"})
        == forensic.JURIS_DOMESTIC
    )


def test_render_overseas_targets() -> None:
    # 境外源站被动定位：源站归属(IP/ASN/org/geo) + 开放端口/服务指纹 + 关联主机名(串案)；零漏洞/利用。
    lines = forensic.render_overseas_targets({
        "ip": "45.33.32.156",
        "asn": "AS63949",
        "org": "Linode",
        "country": "United States",
        "ports": [22, 80],
        "services": [
            {"port": 80, "product": "Apache httpd", "version": "2.4.7"},
            {"port": 22, "product": "OpenSSH", "version": "6.6.1p1"},
        ],
        "hostnames": ["a.example", "b.example"],
    })
    blob = "\n".join(lines)
    assert "源站被动归属" in blob and "45.33.32.156" in blob and "Linode" in blob
    assert "80(Apache httpd 2.4.7)" in blob
    assert "22(OpenSSH 6.6.1p1)" in blob
    # 纯被动定位：绝不含漏洞方向 / CVE / 利用。
    assert "CVE" not in blob and "漏洞" not in blob and "利用" not in blob
    assert "a.example" in blob and "串案" in blob


def test_render_overseas_targets_empty_on_miss() -> None:
    # "查无记录"标记 / 非 dict → 不产证据行。
    assert forensic.render_overseas_targets({"note": "Shodan 库中无该主机记录", "source": "shodan"}) == []
    assert forensic.render_overseas_targets(None) == []
