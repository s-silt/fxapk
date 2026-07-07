"""DnsEnricher 单测：mock 掉网络层（requests / socket / _ipinfo.lookup_ips_batch），不发真实请求。

DoH 解析 A 记录（国内优先 DoH 链），异常回退 socket.gethostbyname_ex；
对解析出的 IP 列表**一次** lookup_ips_batch 批量拿托管(org/asn/country)。

覆盖：
- 基本属性 name / applies_to。
- DoH 成功：解析多 IP，批量富化托管 → data.ips / data.hosting 聚合。
- DoH 失败 → 回退 socket.gethostbyname_ex。
- 两者都失败 → ok=False。
- 空域名（不触网）。
- 缓存命中（不触网）。
- 离线/失败不缓存。
- 托管查询走 lookup_ips_batch 单次批量（非逐 IP）。
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
        self.post_calls: list[tuple[str, dict]] = []
        self.response: _FakeResponse | None = None
        self.post_response: _FakeResponse | None = None
        self.raises: Exception | None = None

    def get(self, url: str, **kwargs: object) -> _FakeResponse:
        self.calls.append((url, dict(kwargs)))
        if self.raises is not None:
            raise self.raises
        assert self.response is not None, "测试未配置 response"
        return self.response

    def post(self, url: str, **kwargs: object) -> _FakeResponse:
        self.post_calls.append((url, dict(kwargs)))
        if self.raises is not None:
            raise self.raises
        assert self.post_response is not None, "测试未配置 post_response"
        return self.post_response


@pytest.fixture
def fake_requests(monkeypatch: pytest.MonkeyPatch) -> _FakeRequests:
    fake = _FakeRequests()
    monkeypatch.setattr(dns_mod, "requests", fake)
    return fake


class _FakeBatchLookup:
    """_ipinfo.lookup_ips_batch 的查表打桩（不触网）。

    - ``table[ip] = info`` 由测试填充；调用时仅对 table 里有的 IP 返回（与真实批量跳过
      查不到的 IP 行为一致）。
    - ``calls`` 记录每次调用传入的 ips 列表，供"单次批量"断言（len(calls)==1）。
    """

    def __init__(self) -> None:
        self.table: dict[str, dict] = {}
        self.calls: list[list[str]] = []

    def __call__(self, ips: list[str], **kwargs: object) -> dict[str, dict]:
        self.calls.append(list(ips))
        return {ip: self.table[ip] for ip in ips if ip in self.table}


@pytest.fixture
def fake_lookup(monkeypatch: pytest.MonkeyPatch) -> _FakeBatchLookup:
    """把 _ipinfo.lookup_ips_batch 打桩为查表对象（不触网）。"""
    fake = _FakeBatchLookup()
    monkeypatch.setattr(dns_mod, "lookup_ips_batch", fake)
    return fake


def _ep(value: str = "pay.fraud-gw.com") -> Endpoint:
    return Endpoint(value=value, kind="domain")


def _doh_payload(ips: list[str]) -> dict[str, object]:
    """dns.google /resolve A 记录响应：Status=0，Answer 含 type=1（A）记录。"""
    answers = [{"name": "x.", "type": 1, "TTL": 300, "data": ip} for ip in ips]
    # 掺一条 CNAME（type=5）：不进 A 记录，但会被 _extract_cnames 捞进 data["cname"]。
    answers.insert(0, {"name": "x.", "type": 5, "TTL": 300, "data": "cdn.x."})
    return {"Status": 0, "Answer": answers}


# --- 基本属性 -------------------------------------------------------------


def test_name_and_applies_to() -> None:
    enr = DnsEnricher()
    assert enr.name == "dns"
    assert enr.applies_to == ["domain"]


# --- DoH 成功，多 IP 托管聚合 ----------------------------------------------


def test_doh_success_aggregates_hosting(
    fake_requests: _FakeRequests, fake_lookup: _FakeBatchLookup
) -> None:
    fake_requests.response = _FakeResponse(_doh_payload(["1.1.1.1", "2.2.2.2"]))
    fake_lookup.table["1.1.1.1"] = {
        "isp": "ISP A", "org": "Org A", "asn": "AS111", "country": "US"
    }
    fake_lookup.table["2.2.2.2"] = {
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
    fake_lookup: _FakeBatchLookup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_requests.raises = TimeoutError("dns.google timed out")
    fake_lookup.table["9.9.9.9"] = {
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
    fake_lookup: _FakeBatchLookup,
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
    fake_lookup: _FakeBatchLookup,
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
    fake_requests: _FakeRequests, fake_lookup: _FakeBatchLookup
) -> None:
    result = DnsEnricher().enrich(Endpoint(value="   ", kind="domain"))
    assert result.ok is False
    assert result.error
    assert fake_requests.calls == []


# --- 缓存 -----------------------------------------------------------------


def test_dns_result_written_to_cache(
    fake_requests: _FakeRequests, fake_lookup: _FakeBatchLookup, _isolated_cache: Path
) -> None:
    fake_requests.response = _FakeResponse(_doh_payload(["3.3.3.3"]))
    fake_lookup.table["3.3.3.3"] = {
        "isp": "I", "org": "O", "asn": "AS333", "country": "JP"
    }
    DnsEnricher().enrich(_ep("cache-me.com"))

    assert _isolated_cache.is_file()
    cache = json.loads(_isolated_cache.read_text(encoding="utf-8"))
    assert "cache-me.com" in cache
    assert cache["cache-me.com"]["ips"] == ["3.3.3.3"]


def test_dns_cache_hit_skips_network(
    fake_requests: _FakeRequests, fake_lookup: _FakeBatchLookup
) -> None:
    fake_requests.response = _FakeResponse(_doh_payload(["4.4.4.4"]))
    fake_lookup.table["4.4.4.4"] = {
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
    fake_lookup: _FakeBatchLookup,
    monkeypatch: pytest.MonkeyPatch,
    _isolated_cache: Path,
) -> None:
    fake_requests.raises = TimeoutError("doh down")

    def boom(name: str) -> tuple[str, list, list[str]]:
        raise socket.gaierror("fail")

    monkeypatch.setattr(dns_mod.socket, "gethostbyname_ex", boom)
    DnsEnricher().enrich(_ep("fail.com"))
    assert not _isolated_cache.exists()


# --- 缓存 TTL：过期触发重查 -----------------------------------------------


def test_cache_entry_carries_cached_at(
    fake_requests: _FakeRequests, fake_lookup: _FakeBatchLookup, _isolated_cache: Path
) -> None:
    """成功缓存条目带 _cached_at 时间戳，供 TTL 过期判断。"""
    fake_requests.response = _FakeResponse(_doh_payload(["6.6.6.6"]))
    fake_lookup.table["6.6.6.6"] = {"isp": "I", "org": "O", "asn": "AS6", "country": "US"}
    DnsEnricher().enrich(_ep("stamp.com"))

    cache = json.loads(_isolated_cache.read_text(encoding="utf-8"))
    assert isinstance(cache["stamp.com"].get("_cached_at"), (int, float))


def test_expired_cache_triggers_requery(
    fake_requests: _FakeRequests,
    fake_lookup: _FakeBatchLookup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """缓存 _cached_at 超过 TTL → 重新查询（拿到新结果），而非返回陈旧缓存。"""
    fake_requests.response = _FakeResponse(_doh_payload(["7.7.7.7"]))
    fake_lookup.table["7.7.7.7"] = {"isp": "I", "org": "O", "asn": "AS7", "country": "US"}
    fake_lookup.table["8.8.8.8"] = {"isp": "I2", "org": "O2", "asn": "AS8", "country": "DE"}
    enr = DnsEnricher()

    # 冻结时刻 t0 写入缓存。
    now = {"t": 1_000.0}
    monkeypatch.setattr(dns_mod.time, "time", lambda: now["t"])

    first = enr.enrich(_ep("ttl.com"))
    assert first.ok is True
    assert first.data["ips"] == ["7.7.7.7"]

    # 时钟推进超过 TTL → 应重查（返回新 IP）。
    now["t"] = 1_000.0 + dns_mod.CACHE_TTL_SECONDS + 1
    fake_requests.response = _FakeResponse(_doh_payload(["8.8.8.8"]))
    second = enr.enrich(_ep("ttl.com"))
    assert second.ok is True
    assert second.data["ips"] == ["8.8.8.8"]  # 拿到重查后的新结果
    assert len(fake_requests.calls) == 2


def test_fresh_cache_within_ttl_skips_network(
    fake_requests: _FakeRequests,
    fake_lookup: _FakeBatchLookup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TTL 内的缓存仍命中，不触网。"""
    fake_requests.response = _FakeResponse(_doh_payload(["9.9.9.9"]))
    fake_lookup.table["9.9.9.9"] = {"isp": "I", "org": "O", "asn": "AS9", "country": "US"}
    enr = DnsEnricher()

    now = {"t": 2_000.0}
    monkeypatch.setattr(dns_mod.time, "time", lambda: now["t"])

    enr.enrich(_ep("fresh.com"))
    assert len(fake_requests.calls) == 1

    now["t"] = 2_000.0 + dns_mod.CACHE_TTL_SECONDS - 1  # 仍在 TTL 内
    second = enr.enrich(_ep("fresh.com"))
    assert second.ok is True
    assert len(fake_requests.calls) == 1  # 未重查


# --- 限速/托管失败：不固化空 hosting -------------------------------------


def test_hosting_ratelimit_marks_incomplete_and_not_cached(
    fake_requests: _FakeRequests,
    fake_lookup: _FakeBatchLookup,
    monkeypatch: pytest.MonkeyPatch,
    _isolated_cache: Path,
) -> None:
    """托管批量查询因 429/限速抛错 → hosting 空但标 hosting_incomplete，且不写缓存（不冻结管辖判定）。"""
    fake_requests.response = _FakeResponse(_doh_payload(["1.2.3.4"]))

    def boom_batch(ips: list[str], **kwargs: object) -> dict:
        raise RuntimeError("429 Too Many Requests")

    monkeypatch.setattr(dns_mod, "lookup_ips_batch", boom_batch)

    result = DnsEnricher().enrich(_ep("rl.com"))
    assert result.ok is True
    assert result.data["ips"] == ["1.2.3.4"]  # IP 列表仍在（有价值线索）
    assert result.data["hosting"] == []
    assert result.data.get("hosting_incomplete") is True
    # 不固化：hosting 缺失的结果不写缓存，下次可重查补全归属。
    assert not _isolated_cache.exists()


def test_hosting_success_not_marked_incomplete(
    fake_requests: _FakeRequests, fake_lookup: _FakeBatchLookup, _isolated_cache: Path
) -> None:
    """托管查询成功 → 不标 incomplete，正常写缓存。"""
    fake_requests.response = _FakeResponse(_doh_payload(["1.1.1.1"]))
    fake_lookup.table["1.1.1.1"] = {"isp": "I", "org": "O", "asn": "AS1", "country": "US"}
    result = DnsEnricher().enrich(_ep("ok.com"))
    assert result.ok is True
    assert result.data.get("hosting_incomplete") is not True
    assert _isolated_cache.is_file()


# --- 托管查询走单次批量（非逐 IP）-----------------------------------------


def test_hosting_uses_single_batch_call(
    fake_requests: _FakeRequests, fake_lookup: _FakeBatchLookup
) -> None:
    """多 IP 时托管查询只调一次 lookup_ips_batch（限速/去重集中到 _ipinfo 批量端点）。"""
    fake_requests.response = _FakeResponse(
        _doh_payload(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    )
    for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        fake_lookup.table[ip] = {
            "isp": f"I-{ip}", "org": f"O-{ip}", "asn": f"AS-{ip}", "country": "CN"
        }

    result = DnsEnricher().enrich(_ep("multi.com"))

    assert result.ok is True
    # 关键：只一次批量调用，且传入全部解析出的 IP（而非逐 IP）。
    assert len(fake_lookup.calls) == 1
    assert fake_lookup.calls[0] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    # data 结构不变：hosting 仍逐 IP 一项。
    assert [h["ip"] for h in result.data["hosting"]] == [
        "1.1.1.1", "2.2.2.2", "3.3.3.3"
    ]


def test_hosting_batch_partial_miss_keeps_ips(
    fake_requests: _FakeRequests, fake_lookup: _FakeBatchLookup
) -> None:
    """批量结果缺某 IP（查不到/被跳过）时，IP 列表保留，hosting 仅含查到的项。"""
    fake_requests.response = _FakeResponse(_doh_payload(["1.1.1.1", "2.2.2.2"]))
    fake_lookup.table["1.1.1.1"] = {
        "isp": "I", "org": "O", "asn": "AS1", "country": "US"
    }
    # 2.2.2.2 不在 table → 批量返回里缺它。

    result = DnsEnricher().enrich(_ep("partial.com"))

    assert result.ok is True
    assert result.data["ips"] == ["1.1.1.1", "2.2.2.2"]  # IP 列表完整
    hosting_ips = [h["ip"] for h in result.data["hosting"]]
    assert hosting_ips == ["1.1.1.1"]  # 仅查到的入 hosting


# --- CNAME 链捕获（被动接线，喂 forensic 的 CDN 边缘判定）--------------------


def test_extract_cnames_from_doh_answer() -> None:
    """_extract_cnames 抽 type=5 记录的 data（去 DNS 末点），忽略 A 记录；无 CNAME → 空。"""
    payload = {
        "Status": 0,
        "Answer": [
            {"name": "api.evil.com.", "type": 5, "data": "api.evil.com.w.kunlungr.com."},
            {"name": "x.kunlungr.com.", "type": 1, "data": "1.2.3.4"},
        ],
    }
    assert dns_mod._extract_cnames(payload) == ["api.evil.com.w.kunlungr.com"]
    assert dns_mod._extract_cnames({"Answer": [{"type": 1, "data": "1.2.3.4"}]}) == []


def test_enrich_populates_cname_from_doh(
    fake_requests: _FakeRequests, fake_lookup: _FakeBatchLookup
) -> None:
    """★ 接线（此前是死代码）：DoH 响应里的 CNAME 落进 data["cname"]，CDN 边缘判定才拿得到。"""
    fake_requests.response = _FakeResponse(_doh_payload(["1.1.1.1"]))
    fake_lookup.table["1.1.1.1"] = {"isp": "I", "org": "O", "asn": "AS1", "country": "CN"}

    result = DnsEnricher().enrich(_ep())

    assert result.ok is True
    assert result.data["cname"] == ["cdn.x"]  # _doh_payload 掺的 CNAME "cdn.x." 被捞进来
    # 端到端：这样的 dns dict 现在真能触发 forensic 的 CNAME CDN 判定（曾因永无 cname 而是死代码）。
    from apkscan.core import forensic

    assert forensic._cname_cdn_marker({"cname": ["x.w.kunlungr.com"]}) is not None


def test_enrich_populates_cname_from_socket_aliases(
    fake_requests: _FakeRequests,
    fake_lookup: _FakeBatchLookup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """socket 回退时 gethostbyname_ex 的 aliases（CNAME）也落进 data["cname"]（纯本地，被动）。"""
    fake_requests.raises = TimeoutError("doh down")
    fake_lookup.table["9.9.9.9"] = {"isp": "Q", "org": "Quad9", "asn": "AS999", "country": "US"}

    def fake_gethostbyname_ex(name: str) -> tuple[str, list, list[str]]:
        return (name, ["edge.alicdn.com"], ["9.9.9.9"])

    monkeypatch.setattr(dns_mod.socket, "gethostbyname_ex", fake_gethostbyname_ex)

    result = DnsEnricher().enrich(_ep())
    assert result.ok is True
    assert result.data["ips"] == ["9.9.9.9"]
    assert result.data["cname"] == ["edge.alicdn.com"]


def test_enrich_captures_canonical_name_from_socket(
    fake_requests: _FakeRequests,
    fake_lookup: _FakeBatchLookup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """★ 回归（codex review P2）：socket 回退时 CDN 落点常在规范名（gethostbyname_ex 第一元素），
    aliases 可能为空——必须把与查询域不同的规范名也补进 data["cname"]，否则边缘判定漏它。"""
    fake_requests.raises = TimeoutError("doh down")
    fake_lookup.table["9.9.9.9"] = {"isp": "Q", "org": "Q9", "asn": "AS9", "country": "US"}

    def fake_gethostbyname_ex(name: str) -> tuple[str, list, list[str]]:
        # 规范名=CDN 落点，aliases 为空（真实系统解析器的常见形态）。
        return ("pay.fraud-gw.com.w.kunlungr.com", [], ["9.9.9.9"])

    monkeypatch.setattr(dns_mod.socket, "gethostbyname_ex", fake_gethostbyname_ex)

    result = DnsEnricher().enrich(_ep())
    assert result.ok is True
    assert result.data["cname"] == ["pay.fraud-gw.com.w.kunlungr.com"]
    from apkscan.core import forensic

    assert forensic._cname_cdn_marker({"cname": result.data["cname"]}) is not None
