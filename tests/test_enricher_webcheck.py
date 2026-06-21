"""WebCheckEnricher 单测：mock 网络（requests），不发真实请求。

覆盖 opt-in 门控（未配 env → 跳过）、成功合并多检查、per-check 失败隔离、全失败、缓存命中、
location→country 归一化喂 forensic 辖区判定。
"""

from __future__ import annotations

from pathlib import Path

import pytest

import apkscan.enrichers.webcheck as wc_mod
from apkscan.core import forensic
from apkscan.core.models import Endpoint
from apkscan.enrichers.webcheck import WebCheckEnricher


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wc_mod, "CACHE_DIR", tmp_path / ".apkscan_cache")
    monkeypatch.setattr(wc_mod, "CACHE_FILE", tmp_path / ".apkscan_cache" / "webcheck.json")
    monkeypatch.setenv("FXAPK_WEBCHECK_CHECKS", "location,ssl,ports")
    monkeypatch.delenv("FXAPK_WEBCHECK_URL", raising=False)


class _Resp:
    def __init__(self, status: int, payload: object) -> None:
        self.status_code = status
        self._p = payload

    def json(self) -> object:
        return self._p


class _FakeRequests:
    def __init__(self, mapping: dict[str, tuple[int, object]]) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    def get(self, url: str, timeout: float | None = None) -> _Resp:
        self.calls.append(url)
        for frag, (status, payload) in self.mapping.items():
            if frag in url:
                return _Resp(status, payload)
        return _Resp(404, {})


def _ep(value: str = "evilbackend.com", kind: str = "domain") -> Endpoint:
    return Endpoint(value=value, kind=kind, evidences=[])


def test_disabled_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # 未配 FXAPK_WEBCHECK_URL → opt-in 跳过，不触网。
    fake = _FakeRequests({})
    monkeypatch.setattr(wc_mod, "requests", fake)
    res = WebCheckEnricher().enrich(_ep())
    assert res.ok is False
    assert not fake.calls


def test_success_merges_checks_and_country(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_WEBCHECK_URL", "http://localhost:3000")
    fake = _FakeRequests({
        "/api/location": (200, {"country": "United States", "city": "Ashburn"}),
        "/api/ssl": (200, {"issuer": "R3"}),
        "/api/ports": (200, {"openPorts": [80, 443, 8080]}),
    })
    monkeypatch.setattr(wc_mod, "requests", fake)
    res = WebCheckEnricher().enrich(_ep())
    assert res.ok is True
    assert res.data["location"]["country"] == "United States"
    assert res.data["ssl"]["issuer"] == "R3"
    assert res.data["ports"]["openPorts"] == [80, 443, 8080]
    assert res.data["country"] == "United States"  # 归一化喂 forensic


def test_per_check_failure_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_WEBCHECK_URL", "http://localhost:3000")
    fake = _FakeRequests({
        "/api/location": (200, {"country": "China"}),
        "/api/ssl": (500, {}),  # 单检查失败
        "/api/ports": (200, {"openPorts": []}),
    })
    monkeypatch.setattr(wc_mod, "requests", fake)
    res = WebCheckEnricher().enrich(_ep())
    assert res.ok is True
    assert "location" in res.data and "ports" in res.data
    assert "ssl" not in res.data
    assert res.data["_errors"]["ssl"] == "HTTP 500"


def test_all_checks_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_WEBCHECK_URL", "http://localhost:3000")
    fake = _FakeRequests({})  # 全部 404
    monkeypatch.setattr(wc_mod, "requests", fake)
    res = WebCheckEnricher().enrich(_ep())
    assert res.ok is False


def test_cache_hit_skips_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_WEBCHECK_URL", "http://localhost:3000")
    fake = _FakeRequests({"/api/location": (200, {"country": "China"})})
    monkeypatch.setattr(wc_mod, "requests", fake)
    e = WebCheckEnricher()
    e.enrich(_ep())
    n = len(fake.calls)
    e.enrich(_ep())  # 二次：命中缓存
    assert len(fake.calls) == n  # 未再触网


def test_forensic_uses_webcheck_country() -> None:
    assert (
        forensic.classify_jurisdiction("evilbackend.com", webcheck={"country": "United States"})
        == forensic.JURIS_FOREIGN
    )
    assert (
        forensic.classify_jurisdiction("evilbackend.com", webcheck={"country": "China"})
        == forensic.JURIS_DOMESTIC
    )
