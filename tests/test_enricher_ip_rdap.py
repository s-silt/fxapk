"""IpRdapEnricher 单测：mock 掉网络层，不发任何真实请求。

覆盖：基本属性、成功路径（netname/org/country，source=rdap-ip）、registrant 优先、
缓存命中不触网、空 IP 不触网、网络失败 ok=False 不缓存、全空响应不缓存。
"""

from __future__ import annotations

from pathlib import Path

import pytest

import apkscan.enrichers.ip_rdap as ip_rdap_mod
from apkscan.core.models import Endpoint
from apkscan.enrichers.ip_rdap import IpRdapEnricher, _extract_ip_rdap


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cache_dir = tmp_path / ".apkscan_cache"
    monkeypatch.setattr(ip_rdap_mod, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(ip_rdap_mod, "CACHE_FILE", cache_dir / "ip_rdap.json")
    return cache_dir / "ip_rdap.json"


class _FakeResponse:
    def __init__(self, json_data: object, exc: Exception | None = None) -> None:
        self._json = json_data
        self._exc = exc

    def raise_for_status(self) -> None:
        if self._exc is not None:
            raise self._exc

    def json(self) -> object:
        return self._json


class _FakeRequests:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.response: _FakeResponse | None = None
        self.raises: Exception | None = None

    def get(self, url: str, **kwargs: object) -> _FakeResponse:
        self.calls.append(url)
        if self.raises is not None:
            raise self.raises
        assert self.response is not None
        return self.response


@pytest.fixture
def fake_requests(monkeypatch: pytest.MonkeyPatch) -> _FakeRequests:
    fake = _FakeRequests()
    monkeypatch.setattr(ip_rdap_mod, "requests", fake)
    return fake


def _ip_payload() -> dict[str, object]:
    """典型 rdap.org IP 响应骨架（RIR bootstrap）。"""
    return {
        "handle": "45.76.0.0 - 45.76.255.255",
        "name": "VULTR-AS20473",
        "startAddress": "45.76.0.0",
        "endAddress": "45.76.255.255",
        "country": "US",
        "entities": [
            {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Desk"]]]},
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Vultr Holdings, Inc."]]]},
        ],
    }


def test_basic_attributes() -> None:
    e = IpRdapEnricher()
    assert e.name == "ip_rdap" and e.applies_to == ["ip"] and e.active is False


def test_extract_registrant_preferred_over_other_entities() -> None:
    """★取登记机构名优先 registrant，而非碰到的第一个实体（abuse）。"""
    ext = _extract_ip_rdap(_ip_payload())
    assert ext["netname"] == "VULTR-AS20473"
    assert ext["org"] == "Vultr Holdings, Inc."  # registrant，非 "Abuse Desk"
    assert ext["country"] == "US" and ext["source"] == "rdap-ip"


def test_success_path_writes_cache(fake_requests: _FakeRequests, _isolated_cache: Path) -> None:
    fake_requests.response = _FakeResponse(_ip_payload())
    res = IpRdapEnricher().enrich(Endpoint(value="45.76.1.1", kind="ip"))
    assert res.ok and res.data["netname"] == "VULTR-AS20473" and res.data["source"] == "rdap-ip"
    assert _isolated_cache.is_file()  # 成功写缓存


def test_cache_hit_no_network(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(_ip_payload())
    ep = Endpoint(value="45.76.1.1", kind="ip")
    IpRdapEnricher().enrich(ep)  # 首查写缓存
    fake_requests.calls.clear()
    res = IpRdapEnricher().enrich(ep)  # 二查命中缓存
    assert res.ok and not fake_requests.calls  # 未触网


def test_empty_ip_no_network(fake_requests: _FakeRequests) -> None:
    res = IpRdapEnricher().enrich(Endpoint(value="  ", kind="ip"))
    assert not res.ok and not fake_requests.calls


def test_network_failure_not_cached(fake_requests: _FakeRequests, _isolated_cache: Path) -> None:
    fake_requests.raises = ConnectionError("boom")
    res = IpRdapEnricher().enrich(Endpoint(value="45.76.1.1", kind="ip"))
    assert not res.ok and "ConnectionError" in (res.error or "")
    assert not _isolated_cache.is_file()  # 失败不缓存


def test_empty_record_not_cached(fake_requests: _FakeRequests, _isolated_cache: Path) -> None:
    """RDAP 返回但无任何登记字段（netname/org/country/handle 全空）→ ok=False，不缓存。"""
    fake_requests.response = _FakeResponse({"startAddress": "1.2.3.0", "entities": []})
    res = IpRdapEnricher().enrich(Endpoint(value="1.2.3.4", kind="ip"))
    assert not res.ok and not _isolated_cache.is_file()


def test_non_dict_payload_ok_false(fake_requests: _FakeRequests) -> None:
    fake_requests.response = _FakeResponse(["unexpected"])
    res = IpRdapEnricher().enrich(Endpoint(value="1.2.3.4", kind="ip"))
    assert not res.ok
