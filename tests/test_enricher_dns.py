"""DnsEnricher 单测：mock 掉网络层（requests / socket / _ipinfo.lookup_ip），不发真实请求。

DoH 解析 A 记录（dns.google），异常回退 socket.gethostbyname_ex；
对每个解析出的 IP 复用 _ipinfo.lookup_ip 拿托管(org/asn/country)。

覆盖：
- 基本属性 name / applies_to。
- DoH 成功：解析多 IP，每 IP 富化托管 → data.ips / data.hosting 聚合。
- DoH 失败 → 回退 socket.gethostbyname_ex。
- 两者都失败 → ok=False。
- 空域名（不触网）。
- 缓存命中（不触网）。
- 离线/失败不缓存。
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

import apkscan.enrichers.dns as dns_mod
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.enrichers.dns import DnsEnricher


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """把 time.sleep 置空（项目 enricher 测试约定）：_hosting 每个 IP 前过 _respect_rate_limit，
    HOSTING_MIN_INTERVAL=1.4，多 IP 会触发真实 sleep 把测试墙钟卡成秒级。置空后降到毫秒级，
    测试由逻辑驱动而非限速器。限速间隔逻辑可另用 fake monotonic 做纯逻辑断言（见下）。"""
    monkeypatch.setattr(dns_mod.time, "sleep", lambda *_a, **_k: None)


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cache_dir = tmp_path / ".apkscan_cache"
    cache_file = cache_dir / "dns.json"
    monkeypatch.setattr(dns_mod, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(dns_mod, "CACHE_FILE", cache_file)
    return cache_file


class _FakeResponse:
    def __init__(
        self, json_data: object, raise_for_status_exc: Exception | None = None
    ) -> None:
        self._json = json_data
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
    monkeypatch.setattr(dns_mod, "requests", fake)
    return fake


@pytest.fixture
def fake_lookup(monkeypatch: pytest.MonkeyPatch) -> dict[str, dict]:
    """把 _ipinfo.lookup_ip 打桩为查表函数（不触网）。"""
    table: dict[str, dict] = {}

    def _fake(ip: str, **kwargs: object) -> dict:
        return table.get(
            ip, {"isp": None, "org": None, "asn": None, "country": None}
        )

    monkeypatch.setattr(dns_mod, "lookup_ip", _fake)
    return table


def _ep(value: str = "pay.fraud-gw.com") -> Endpoint:
    return Endpoint(value=value, kind="domain")


def _doh_payload(ips: list[str]) -> dict[str, object]:
    """dns.google /resolve A 记录响应：Status=0，Answer 含 type=1（A）记录。"""
    answers = [{"name": "x.", "type": 1, "TTL": 300, "data": ip} for ip in ips]
    # 掺一条 CNAME（type=5）应被忽略。
    answers.insert(0, {"name": "x.", "type": 5, "TTL": 300, "data": "cdn.x."})
    return {"Status": 0, "Answer": answers}


# --- 基本属性 -------------------------------------------------------------


def test_name_and_applies_to() -> None:
    enr = DnsEnricher()
    assert enr.name == "dns"
    assert enr.applies_to == ["domain"]


# --- DoH 成功，多 IP 托管聚合 ----------------------------------------------


def test_doh_success_aggregates_hosting(
    fake_requests: _FakeRequests, fake_lookup: dict[str, dict]
) -> None:
    fake_requests.response = _FakeResponse(_doh_payload(["1.1.1.1", "2.2.2.2"]))
    fake_lookup["1.1.1.1"] = {
        "isp": "ISP A", "org": "Org A", "asn": "AS111", "country": "US"
    }
    fake_lookup["2.2.2.2"] = {
        "isp": "ISP B", "org": "Org B", "asn": "AS222", "country": "CN"
    }

    result = DnsEnricher().enrich(_ep())

    assert isinstance(result, EnrichmentResult)
    assert result.provider == "dns"
    assert result.ok is True
    assert result.error is None
    assert result.data["ips"] == ["1.1.1.1", "2.2.2.2"]

    hosting = {h["ip"]: h for h in result.data["hosting"]}
    assert hosting["1.1.1.1"]["org"] == "Org A"
    assert hosting["1.1.1.1"]["asn"] == "AS111"
    assert hosting["1.1.1.1"]["country"] == "US"
    assert hosting["2.2.2.2"]["org"] == "Org B"

    # DoH 走 HTTPS dns.google。
    assert len(fake_requests.calls) == 1
    url, kwargs = fake_requests.calls[0]
    assert url.startswith("https://")
    assert kwargs["params"]["name"] == "pay.fraud-gw.com"
    assert kwargs["params"]["type"] == "A"


def test_doh_failure_falls_back_to_socket(
    fake_requests: _FakeRequests,
    fake_lookup: dict[str, dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_requests.raises = TimeoutError("dns.google timed out")
    fake_lookup["9.9.9.9"] = {
        "isp": "Q", "org": "Quad9", "asn": "AS999", "country": "US"
    }

    def fake_gethostbyname_ex(name: str) -> tuple[str, list, list[str]]:
        assert name == "pay.fraud-gw.com"
        return ("pay.fraud-gw.com", [], ["9.9.9.9"])

    monkeypatch.setattr(
        dns_mod.socket, "gethostbyname_ex", fake_gethostbyname_ex
    )

    result = DnsEnricher().enrich(_ep())
    assert result.ok is True
    assert result.data["ips"] == ["9.9.9.9"]
    assert result.data["hosting"][0]["org"] == "Quad9"


def test_both_doh_and_socket_fail_returns_not_ok(
    fake_requests: _FakeRequests,
    fake_lookup: dict[str, dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_requests.raises = TimeoutError("doh down")

    def boom(name: str) -> tuple[str, list, list[str]]:
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(dns_mod.socket, "gethostbyname_ex", boom)

    result = DnsEnricher().enrich(_ep())
    assert result.ok is False
    assert result.error


def test_doh_no_answer_returns_not_ok(
    fake_requests: _FakeRequests,
    fake_lookup: dict[str, dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DoH 返回 Status=3（NXDOMAIN）/ 无 A 记录，socket 也无 → ok=False。"""
    fake_requests.response = _FakeResponse({"Status": 3, "Answer": []})

    def boom(name: str) -> tuple[str, list, list[str]]:
        raise socket.gaierror("nxdomain")

    monkeypatch.setattr(dns_mod.socket, "gethostbyname_ex", boom)

    result = DnsEnricher().enrich(_ep())
    assert result.ok is False


# --- 空域名（不触网）------------------------------------------------------


def test_empty_domain_short_circuits(
    fake_requests: _FakeRequests, fake_lookup: dict[str, dict]
) -> None:
    result = DnsEnricher().enrich(Endpoint(value="   ", kind="domain"))
    assert result.ok is False
    assert result.error
    assert fake_requests.calls == []


# --- 缓存 -----------------------------------------------------------------


def test_dns_result_written_to_cache(
    fake_requests: _FakeRequests, fake_lookup: dict[str, dict], _isolated_cache: Path
) -> None:
    fake_requests.response = _FakeResponse(_doh_payload(["3.3.3.3"]))
    fake_lookup["3.3.3.3"] = {
        "isp": "I", "org": "O", "asn": "AS333", "country": "JP"
    }
    DnsEnricher().enrich(_ep("cache-me.com"))

    assert _isolated_cache.is_file()
    cache = json.loads(_isolated_cache.read_text(encoding="utf-8"))
    assert "cache-me.com" in cache
    assert cache["cache-me.com"]["ips"] == ["3.3.3.3"]


def test_dns_cache_hit_skips_network(
    fake_requests: _FakeRequests, fake_lookup: dict[str, dict]
) -> None:
    fake_requests.response = _FakeResponse(_doh_payload(["4.4.4.4"]))
    fake_lookup["4.4.4.4"] = {
        "isp": "I", "org": "O", "asn": "AS444", "country": "DE"
    }
    enr = DnsEnricher()

    first = enr.enrich(_ep("repeat.com"))
    assert first.ok is True
    assert len(fake_requests.calls) == 1

    fake_requests.response = _FakeResponse(_doh_payload(["5.5.5.5"]))
    second = enr.enrich(_ep("repeat.com"))
    assert second.ok is True
    assert second.data["ips"] == ["4.4.4.4"]  # 仍是首查结果
    assert len(fake_requests.calls) == 1


def test_failed_query_not_cached(
    fake_requests: _FakeRequests,
    fake_lookup: dict[str, dict],
    monkeypatch: pytest.MonkeyPatch,
    _isolated_cache: Path,
) -> None:
    fake_requests.raises = TimeoutError("doh down")

    def boom(name: str) -> tuple[str, list, list[str]]:
        raise socket.gaierror("fail")

    monkeypatch.setattr(dns_mod.socket, "gethostbyname_ex", boom)
    DnsEnricher().enrich(_ep("fail.com"))
    assert not _isolated_cache.exists()


# --- 限速器纯逻辑（fake monotonic，不睡真实时间）---------------------------


def test_respect_rate_limit_sleeps_when_too_soon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """间隔 < HOSTING_MIN_INTERVAL 时按差值 sleep；用 fake monotonic 驱动，sleep 仅记录入参。

    第 1 次调用上次时间戳=0、当下 t=0.5（<1.4）→ 应 sleep 约 0.9s（=1.4-0.5）。
    """
    now = [0.5]
    slept: list[float] = []
    monkeypatch.setattr(dns_mod.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(dns_mod.time, "sleep", lambda s: slept.append(s))

    enr = DnsEnricher()
    enr._respect_rate_limit()

    assert len(slept) == 1
    assert slept[0] == pytest.approx(dns_mod.HOSTING_MIN_INTERVAL - 0.5)


def test_respect_rate_limit_no_sleep_when_elapsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """间隔 >= HOSTING_MIN_INTERVAL 时不 sleep（已过冷却窗口）。"""
    now = [dns_mod.HOSTING_MIN_INTERVAL + 1.0]
    slept: list[float] = []
    monkeypatch.setattr(dns_mod.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(dns_mod.time, "sleep", lambda s: slept.append(s))

    enr = DnsEnricher()
    enr._respect_rate_limit()

    assert slept == []
