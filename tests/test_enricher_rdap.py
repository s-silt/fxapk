"""RdapEnricher 单测：mock 掉网络层（requests / whois），不发任何真实请求。

RDAP 优先（HTTPS，rdap.org），TLD 无 RDAP / 404 时回退 python-whois。

覆盖：
- 基本属性 name / applies_to。
- 成功路径：rdap.org 返回 JSON → 提取 registrar / events / status / nameservers，source=rdap。
- 404 / TLD 无 RDAP → 回退 whois（复用 whois.py 的查询函数），source=whois-fallback。
- whois 兜底也失败 → ok=False。
- 缓存命中（不触网）。
- 空域名（不触网）。
- 离线/失败不缓存。
"""

from __future__ import annotations

import json
import sys
import types
from datetime import datetime
from pathlib import Path

import pytest

import apkscan.enrichers.rdap as rdap_mod
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.enrichers.rdap import RdapEnricher


# --- 缓存隔离 -------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cache_dir = tmp_path / ".apkscan_cache"
    cache_file = cache_dir / "rdap.json"
    monkeypatch.setattr(rdap_mod, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(rdap_mod, "CACHE_FILE", cache_file)
    return cache_file


# --- 假 requests（RDAP 层）----------------------------------------------


class _FakeResponse:
    def __init__(
        self,
        json_data: object,
        status_code: int = 200,
        raise_for_status_exc: Exception | None = None,
    ) -> None:
        self._json = json_data
        self.status_code = status_code
        self._raise_for_status_exc = raise_for_status_exc

    def raise_for_status(self) -> None:
        if self._raise_for_status_exc is not None:
            raise self._raise_for_status_exc

    def json(self) -> object:
        return self._json


class _FakeRequests:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.response: _FakeResponse | None = None
        self.raises: Exception | None = None

    def get(self, url: str, **kwargs: object) -> _FakeResponse:
        self.calls.append((url, dict(kwargs)))
        if self.raises is not None:
            raise self.raises
        assert self.response is not None, "测试未配置 response"
        return self.response


@pytest.fixture
def fake_requests(monkeypatch: pytest.MonkeyPatch) -> _FakeRequests:
    fake = _FakeRequests()
    monkeypatch.setattr(rdap_mod, "requests", fake)
    return fake


# --- 假 whois 模块（回退层）----------------------------------------------


class _FakeWhoisModule(types.ModuleType):
    def __init__(self) -> None:
        super().__init__("whois")
        self.calls: list[tuple[str, dict]] = []
        self.return_value: object = {}
        self.raises: Exception | None = None

    def whois(self, domain: str, **kwargs):  # noqa: ANN003
        self.calls.append((domain, kwargs))
        if self.raises is not None:
            raise self.raises
        return self.return_value


@pytest.fixture
def fake_whois(monkeypatch: pytest.MonkeyPatch) -> _FakeWhoisModule:
    mod = _FakeWhoisModule()
    monkeypatch.setitem(sys.modules, "whois", mod)
    return mod


def _ep(value: str = "pay.fraud-gw.com") -> Endpoint:
    return Endpoint(value=value, kind="domain")


def _rdap_payload() -> dict[str, object]:
    """典型 rdap.org 域名响应骨架。"""
    return {
        "objectClassName": "domain",
        "ldhName": "fraud-gw.com",
        "status": ["client transfer prohibited", "active"],
        "events": [
            {"eventAction": "registration", "eventDate": "2021-05-01T12:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-05-01T12:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-03-02T08:00:00Z"},
        ],
        "nameservers": [
            {"ldhName": "ns1.dnspod.net"},
            {"ldhName": "ns2.dnspod.net"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "GoDaddy.com, LLC"],
                    ],
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Fraud Gateway Co"],
                    ],
                ],
            },
        ],
    }


# --- 基本属性 -------------------------------------------------------------


def test_name_and_applies_to() -> None:
    enr = RdapEnricher()
    assert enr.name == "rdap"
    assert enr.applies_to == ["domain"]


# --- RDAP 成功路径 --------------------------------------------------------


def test_rdap_success_extracts_fields(
    fake_requests: _FakeRequests, fake_whois: _FakeWhoisModule
) -> None:
    fake_requests.response = _FakeResponse(_rdap_payload(), status_code=200)
    result = RdapEnricher().enrich(_ep())

    assert isinstance(result, EnrichmentResult)
    assert result.provider == "rdap"
    assert result.ok is True
    assert result.error is None
    assert result.data["source"] == "rdap"
    assert result.data["registrar"] == "GoDaddy.com, LLC"
    assert result.data["registrant"] == "Fraud Gateway Co"
    assert result.data["created"] == "2021-05-01T12:00:00Z"
    assert result.data["expires"] == "2026-05-01T12:00:00Z"
    assert result.data["updated"] == "2024-03-02T08:00:00Z"
    assert "active" in result.data["status"]
    assert result.data["nameservers"] == ["ns1.dnspod.net", "ns2.dnspod.net"]

    # HTTPS rdap.org，带 domain；whois 未被触发。
    assert len(fake_requests.calls) == 1
    url, _kwargs = fake_requests.calls[0]
    assert url.startswith("https://")
    assert "fraud-gw.com" in url
    assert fake_whois.calls == []


def test_rdap_org_fallback_for_registrar(
    fake_requests: _FakeRequests, fake_whois: _FakeWhoisModule
) -> None:
    """registrar 实体只有 org（无 fn）时取 org。"""
    payload = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["org", {}, "text", "Registrar Org Ltd"]],
                ],
            }
        ],
    }
    fake_requests.response = _FakeResponse(payload, status_code=200)
    result = RdapEnricher().enrich(_ep())
    assert result.ok is True
    assert result.data["registrar"] == "Registrar Org Ltd"


# --- 404 / 无 RDAP → 回退 whois ------------------------------------------


def test_rdap_404_falls_back_to_whois(
    fake_requests: _FakeRequests, fake_whois: _FakeWhoisModule
) -> None:
    import requests as real_requests

    fake_requests.response = _FakeResponse(
        {},
        status_code=404,
        raise_for_status_exc=real_requests.HTTPError("404 Not Found"),
    )
    fake_whois.return_value = {
        "registrar": "WhoisFallback Reg",
        "registrant_name": "Zhang San",
        "creation_date": datetime(2020, 1, 2, 0, 0, 0),
        "country": "CN",
    }

    result = RdapEnricher().enrich(_ep())

    assert result.ok is True
    assert result.data["source"] == "whois-fallback"
    assert result.data["registrar"] == "WhoisFallback Reg"
    assert result.data["registrant"] == "Zhang San"
    assert result.data["created"] == "2020-01-02T00:00:00"
    # whois 确实被调用了一次。
    assert len(fake_whois.calls) == 1
    assert fake_whois.calls[0][0] == "pay.fraud-gw.com"


def test_rdap_network_error_falls_back_to_whois(
    fake_requests: _FakeRequests, fake_whois: _FakeWhoisModule
) -> None:
    fake_requests.raises = TimeoutError("rdap.org timed out")
    fake_whois.return_value = {"registrar": "Backup Reg"}
    result = RdapEnricher().enrich(_ep())
    assert result.ok is True
    assert result.data["source"] == "whois-fallback"
    assert result.data["registrar"] == "Backup Reg"


def test_both_rdap_and_whois_fail_returns_not_ok(
    fake_requests: _FakeRequests, fake_whois: _FakeWhoisModule
) -> None:
    fake_requests.raises = TimeoutError("rdap down")
    fake_whois.raises = TimeoutError("whois down")
    result = RdapEnricher().enrich(_ep())
    assert result.ok is False
    assert result.error
    assert result.data == {} or not any(result.data.values())


# --- 空域名（不触网）------------------------------------------------------


def test_empty_domain_short_circuits(
    fake_requests: _FakeRequests, fake_whois: _FakeWhoisModule
) -> None:
    result = RdapEnricher().enrich(Endpoint(value="   ", kind="domain"))
    assert result.ok is False
    assert result.error
    assert fake_requests.calls == []
    assert fake_whois.calls == []


# --- 缓存 -----------------------------------------------------------------


def test_rdap_result_written_to_cache(
    fake_requests: _FakeRequests, fake_whois: _FakeWhoisModule, _isolated_cache: Path
) -> None:
    fake_requests.response = _FakeResponse(_rdap_payload(), status_code=200)
    RdapEnricher().enrich(_ep("cache-me.com"))

    assert _isolated_cache.is_file()
    cache = json.loads(_isolated_cache.read_text(encoding="utf-8"))
    assert "cache-me.com" in cache
    assert cache["cache-me.com"]["registrar"] == "GoDaddy.com, LLC"
    assert cache["cache-me.com"]["source"] == "rdap"


def test_rdap_cache_hit_skips_network(
    fake_requests: _FakeRequests, fake_whois: _FakeWhoisModule
) -> None:
    fake_requests.response = _FakeResponse(_rdap_payload(), status_code=200)
    enr = RdapEnricher()

    first = enr.enrich(_ep("repeat.com"))
    assert first.ok is True
    assert len(fake_requests.calls) == 1

    # 第二次：命中缓存，不再触网。
    fake_requests.response = _FakeResponse(
        {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "SHOULD NOT BE USED"]]]}]},
        status_code=200,
    )
    second = enr.enrich(_ep("repeat.com"))
    assert second.ok is True
    assert second.data["registrar"] == "GoDaddy.com, LLC"
    assert len(fake_requests.calls) == 1


def test_failed_query_not_cached(
    fake_requests: _FakeRequests, fake_whois: _FakeWhoisModule, _isolated_cache: Path
) -> None:
    fake_requests.raises = TimeoutError("rdap down")
    fake_whois.raises = TimeoutError("whois down")
    RdapEnricher().enrich(_ep("fail.com"))
    assert not _isolated_cache.exists()
