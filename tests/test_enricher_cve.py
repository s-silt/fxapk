"""CveEnricher 单测：mock NVD（requests），不发真实请求。

覆盖：无指纹优雅跳过、从 shodan CPE 查 NVD 并归一(CVSS 降序/top-N)、复用 Shodan 已覆盖 CVE 标记、
recon keyword 兜底（无 CPE 时）、按 CPE 缓存命中不复触网、限速器窗口阻塞、NVD 全失败 ok=False、
可选 key 仅提速不门控、攻击面渲染并入证据行。
"""

from __future__ import annotations

from pathlib import Path

import pytest

import apkscan.enrichers.cve as cve_mod
from apkscan.core import forensic
from apkscan.core.models import Endpoint
from apkscan.enrichers.cve import CveEnricher, _RateLimiter

# 取自真实 NVD 2.0 /cves 响应形态的精简样例（cpeName=cpe:2.3:a:apache:http_server:2.4.7）。
_NVD_PAYLOAD = {
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2017-15715",
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}
                    ]
                },
            }
        },
        {
            "cve": {
                "id": "CVE-2021-44790",
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ]
                },
            }
        },
    ],
}


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cve_mod, "CACHE_DIR", tmp_path / ".apkscan_cache")
    monkeypatch.setattr(cve_mod, "CACHE_FILE", tmp_path / ".apkscan_cache" / "cve.json")
    # 默认无 NVD key（慢档限速，但不门控）。
    monkeypatch.delenv("FXAPK_NVD_KEY", raising=False)
    # 每个测试重置进程级限速器，避免跨测试污染（且测试里限速窗口不应真 sleep）。
    monkeypatch.setattr(cve_mod, "_LIMITER", None)
    monkeypatch.setattr(cve_mod, "_LIMITER_KEYED", None)


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
    """记录每次调用的 params/headers，便于断言触网次数 / key 透传 / 复用跳过。"""

    def __init__(self, status: int, payload: object) -> None:
        self.status = status
        self.payload = payload
        self.calls: list[dict] = []

    def get(self, url, params=None, headers=None, timeout=None):  # type: ignore[no-untyped-def]
        self.calls.append({"url": url, "params": params or {}, "headers": headers or {}})
        return _Resp(self.status, self.payload)


def _ep_with(**enrichment) -> Endpoint:  # type: ignore[no-untyped-def]
    return Endpoint(value="evil.example", kind="domain", evidences=[], enrichment=enrichment)


def _shodan_with_cpe(cpe: str, vulns: list[str] | None = None) -> dict:
    return {
        "services": [{"port": 80, "product": "Apache httpd", "version": "2.4.7", "cpe": [cpe]}],
        "vulns": vulns or [],
        "source": "shodan",
    }


# --------------------------------------------------------------------------- 基础

def test_no_fingerprint_skips_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    """shodan/recon 未提供指纹 → ok=True 无值，绝不触网、绝不报错。"""
    fake = _FakeRequests(200, _NVD_PAYLOAD)
    monkeypatch.setattr(cve_mod, "requests", fake)
    res = CveEnricher().enrich(_ep_with())  # 无 enrichment
    assert res.ok is True
    assert "无 CPE/指纹" in res.data.get("note", "")
    assert not fake.calls  # 无指纹绝不触网


def test_cpe_queries_nvd_and_normalizes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeRequests(200, _NVD_PAYLOAD)
    monkeypatch.setattr(cve_mod, "requests", fake)
    ep = _ep_with(shodan=_shodan_with_cpe("cpe:2.3:a:apache:http_server:2.4.7"))
    res = CveEnricher().enrich(ep)
    assert res.ok is True
    cves = res.data["cves"]
    # CVSS 降序：9.8 CRITICAL 排在 8.1 HIGH 前。
    assert cves[0]["id"] == "CVE-2021-44790" and cves[0]["cvss"] == 9.8
    assert cves[0]["severity"] == "CRITICAL"
    assert cves[1]["id"] == "CVE-2017-15715"
    # 走了 cpeName 精确查。
    assert fake.calls and fake.calls[0]["params"].get("cpeName") == "cpe:2.3:a:apache:http_server:2.4.7"


def test_reuses_shodan_known_cve_marked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shodan 已给的 CVE 在 NVD 结果里命中 → 标 reused_from_shodan（印证），仍计入。"""
    fake = _FakeRequests(200, _NVD_PAYLOAD)
    monkeypatch.setattr(cve_mod, "requests", fake)
    ep = _ep_with(
        shodan=_shodan_with_cpe("cpe:2.3:a:apache:http_server:2.4.7", vulns=["CVE-2021-44790"])
    )
    res = CveEnricher().enrich(ep)
    reused = [c for c in res.data["cves"] if c.get("reused_from_shodan")]
    assert any(c["id"] == "CVE-2021-44790" for c in reused)
    assert res.data["reused_from_shodan"] >= 1


def test_recon_keyword_fallback_when_no_cpe(monkeypatch: pytest.MonkeyPatch) -> None:
    """无 shodan CPE 时退化用 recon 的 server 头作 NVD keyword 查询。"""
    fake = _FakeRequests(200, _NVD_PAYLOAD)
    monkeypatch.setattr(cve_mod, "requests", fake)
    ep = _ep_with(recon={"http": [{"port": 80, "server": "Apache/2.4.7 (Ubuntu)"}]})
    res = CveEnricher().enrich(ep)
    assert res.ok is True
    assert fake.calls and fake.calls[0]["params"].get("keywordSearch") == "Apache 2.4.7"
    assert all("cpeName" not in c["params"] for c in fake.calls)


def test_cache_hit_skips_network(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeRequests(200, _NVD_PAYLOAD)
    monkeypatch.setattr(cve_mod, "requests", fake)
    e = CveEnricher()
    ep = _ep_with(shodan=_shodan_with_cpe("cpe:2.3:a:apache:http_server:2.4.7"))
    e.enrich(ep)
    n = len(fake.calls)
    e.enrich(_ep_with(shodan=_shodan_with_cpe("cpe:2.3:a:apache:http_server:2.4.7")))
    assert len(fake.calls) == n  # 同 CPE 命中缓存，未再触网


def test_all_nvd_fail_ok_false(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeRequests(503, {})  # 503 → raise_for_status 抛 → 单 CPE 失败
    monkeypatch.setattr(cve_mod, "requests", fake)
    ep = _ep_with(shodan=_shodan_with_cpe("cpe:2.3:a:apache:http_server:2.4.7"))
    res = CveEnricher().enrich(ep)
    assert res.ok is False
    assert "全部失败" in (res.error or "")


def test_optional_key_only_speeds_not_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    """配 FXAPK_NVD_KEY 仅透传 apiKey 头提速；不配也能查（与 shodan 强 opt-in 不同）。"""
    monkeypatch.setenv("FXAPK_NVD_KEY", "k123")
    fake = _FakeRequests(200, _NVD_PAYLOAD)
    monkeypatch.setattr(cve_mod, "requests", fake)
    ep = _ep_with(shodan=_shodan_with_cpe("cpe:2.3:a:apache:http_server:2.4.7"))
    res = CveEnricher().enrich(ep)
    assert res.ok is True
    assert fake.calls[0]["headers"].get("apiKey") == "k123"


# --------------------------------------------------------------------------- 限速

def test_rate_limiter_blocks_over_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """限速器：窗口内超 max 次 → acquire 阻塞（这里用受控 monotonic/sleep 验证逻辑，不真等）。"""
    fake_now = {"t": 1000.0}
    slept: list[float] = []

    def _mono() -> float:
        return fake_now["t"]

    def _sleep(s: float) -> None:
        slept.append(s)
        fake_now["t"] += s  # 推进虚拟时钟，让下一轮可获取

    monkeypatch.setattr(cve_mod.time, "monotonic", _mono)
    monkeypatch.setattr(cve_mod.time, "sleep", _sleep)

    lim = _RateLimiter(max_calls=2, window=30.0)
    lim.acquire()
    lim.acquire()
    lim.acquire()  # 第 3 次：窗口满 → 必 sleep 一次再获取
    assert slept, "超窗口应触发限速 sleep"


def test_rate_limiter_allows_within_window(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(cve_mod.time, "sleep", lambda s: slept.append(s))
    lim = _RateLimiter(max_calls=5, window=30.0)
    for _ in range(5):
        lim.acquire()
    assert not slept  # 窗口内未超限，不应 sleep


# --------------------------------------------------------------------------- 渲染

def test_render_cve_surface() -> None:
    lines = forensic.render_cve_surface({
        "cves": [
            {"id": "CVE-2021-44790", "cvss": 9.8, "severity": "CRITICAL", "reused_from_shodan": True},
            {"id": "CVE-2017-15715", "cvss": 8.1, "severity": "HIGH"},
        ],
        "cve_total": 2,
        "source": "nvd",
    })
    blob = "\n".join(lines)
    assert "CVE-2021-44790(9.8 CRITICAL)" in blob
    assert "印证Shodan" in blob
    assert "CVE-2017-15715(8.1 HIGH)" in blob
    assert "非利用" in blob


def test_render_cve_surface_empty() -> None:
    assert forensic.render_cve_surface({"cves": [], "source": "nvd"}) == []
    assert forensic.render_cve_surface({"note": "无 CPE/指纹"}) == []
    assert forensic.render_cve_surface(None) == []


def test_classify_jurisdiction_accepts_cve_kwarg() -> None:
    """cve 不携带归属国，但须被 classify_jurisdiction 接受（pipeline **enr 透传不 TypeError）。"""
    assert (
        forensic.classify_jurisdiction("evil.example", cve={"cves": []})
        == forensic.JURIS_UNKNOWN
    )
