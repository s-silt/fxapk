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


def test_extract_abuse_only_does_not_fill_org() -> None:
    """★P0（RFC 9083）：只有 abuse/technical 等联系人、无 registrant → org 不填（绝不拿滥用联系人冒充
    资源持有方）；netname 顶层仍保留作兜底标识。"""
    payload = {
        "name": "SOME-NET",
        "entities": [
            {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Desk"]]]},
            {"roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "NOC"]]]},
        ],
    }
    ext = _extract_ip_rdap(payload)
    assert ext["org"] is None and ext["netname"] == "SOME-NET"


def test_extract_registrant_org_preferred_over_fn() -> None:
    """★P1：registrant 同时有联系人(fn)和机构(org) → 取机构名 org（资源持有方是机构、非个人）。"""
    payload = {"name": "NET", "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [
        ["fn", {}, "text", "Joe User"], ["org", {}, "text", "Example Networks"]]]}]}
    assert _extract_ip_rdap(payload)["org"] == "Example Networks"


def test_extract_vcard_structured_array_value() -> None:
    """★P1（RFC 7095）：jCard 结构化数组值（[机构, 部门]）过滤空后空格连接，不产 Python repr 垃圾。"""
    def _reg(org_value: object) -> dict:
        vcard = ["vcard", [["org", {}, "text", org_value]]]
        return {"name": "NET", "entities": [{"roles": ["registrant"], "vcardArray": vcard}]}

    assert _extract_ip_rdap(_reg(["Example", "", "Network Unit"]))["org"] == "Example Network Unit"
    assert _extract_ip_rdap(_reg({"weird": 1}))["org"] is None   # 非法 dict 值 → 跳过、不抛
    assert _extract_ip_rdap(_reg("Plain Org"))["org"] == "Plain Org"  # 普通字符串仍正常


def test_extract_registrant_after_abuse_still_matched() -> None:
    """registrant 排在 abuse 之后也能命中（遍历所有实体、按 role 认，不因顺序漏）。"""
    payload = {"name": "NET", "entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"]]]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Vultr Holdings"]]]},
    ]}
    assert _extract_ip_rdap(payload)["org"] == "Vultr Holdings"


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
