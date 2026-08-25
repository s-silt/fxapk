"""富化器接线锁 —— 证明新增富化器在真解析路径上**可达**，不是死代码。

★为什么单开这一份：只调 ``enricher.enrich()`` 的单测**永远测不到接线**。
本仓有过实证：删掉调用点，六条单测照样全绿。所以这里一律：
  - 用**真的** ``discover_enrichers()``，不 stub —— 才能锁住"新模块真被自动发现"；
  - 走 ``enrich_selected_targets()`` 这个 ``_stage_enrich`` 实际调用的编排入口；
  - 断言结果真的落进 ``endpoint.enrichment`` 与 ``source_status``，而不是只看返回值。

每条锁都配了突变验证：破坏被锁的那条接线，对应用例必须变红。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from apkscan.core.enrichment import enrich_selected_targets
from apkscan.core.models import Endpoint
from apkscan.core.registry import discover_enrichers
from apkscan.enrichers import spamhaus
from apkscan.enrichers.spamhaus import SpamhausDropEnricher

_DROP_BODY = (
    '{"cidr":"192.0.2.0/24","sblid":"SBL000001","rir":"arin"}\n'
    '{"type":"metadata","timestamp":1700000000,"size":0,"records":1}'
)


class _Response:
    def __init__(self, text: str) -> None:
        self.text = text
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None


class _CountingHttp:
    """替身 HTTP：记调用次数，确保编排层真的驱动了下载。"""

    def __init__(self, text: str) -> None:
        self.text = text
        self.calls = 0

    def capped_get(self, url: str, timeout: float | None = None) -> _Response:
        del url, timeout
        self.calls += 1
        return _Response(self.text)


@pytest.fixture()
def drop_http(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _CountingHttp:
    """隔离 spamhaus 的缓存与共享状态，并把网络层换成替身。"""
    cache_dir = tmp_path / ".apkscan_cache"
    monkeypatch.setattr(spamhaus, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(spamhaus, "CACHE_FILE", cache_dir / "spamhaus_drop_v4.json")
    fake = _CountingHttp(_DROP_BODY)
    monkeypatch.setattr(spamhaus, "_http", fake)
    SpamhausDropEnricher._table = None
    SpamhausDropEnricher._refreshing = False
    SpamhausDropEnricher._last_failure_at = None
    SpamhausDropEnricher._last_failure_error = None
    SpamhausDropEnricher._last_failure_cache_file = None
    yield fake
    SpamhausDropEnricher._table = None
    SpamhausDropEnricher._last_failure_at = None


def _ip(value: str) -> Endpoint:
    return Endpoint(value=value, kind="ip", is_suspicious=True)


def _providers(stats: list[dict[str, Any]]) -> set[str]:
    return {str(item.get("provider", "")) for item in stats}


# --------------------------------------------------------------------------- #
# 自动发现
# --------------------------------------------------------------------------- #
def test_spamhaus_is_reachable_via_real_discovery() -> None:
    """★用真 discover_enrichers()：新模块放进包里就该被自动发现，无需手工注册。"""
    names = {enricher.name for enricher in discover_enrichers()}

    assert "spamhaus" in names
    assert "ripestat_bgp" in names


# --------------------------------------------------------------------------- #
# 普通解析路径
# --------------------------------------------------------------------------- #
def test_spamhaus_runs_on_ordinary_analysis_path(drop_http: _CountingHttp) -> None:
    """★普通解析（include_case_close=False）必须真的驱动 spamhaus 并落盘结果。

    锁三件事：编排层选中了它、它真发了请求、结果进了 endpoint.enrichment。
    """
    endpoint = _ip("192.0.2.10")

    stats = enrich_selected_targets(
        [endpoint], discover_enrichers(), include_case_close=False
    )

    assert "spamhaus" in _providers(stats)
    assert drop_http.calls == 1  # 编排层真的驱动了下载，不是拿了个空壳
    payload = endpoint.enrichment.get("spamhaus")
    assert isinstance(payload, dict)
    assert payload["network_listed"] is True
    assert payload["matched_cidr"] == "192.0.2.0/24"
    assert payload["evidence_type"] == "third_party_network_list"


def test_spamhaus_result_lands_in_source_status(drop_http: _CountingHttp) -> None:
    """来源状态是报告里"这个源查过没有"的单一真源，必须被写上。"""
    endpoint = _ip("192.0.2.10")

    enrich_selected_targets([endpoint], discover_enrichers(), include_case_close=False)

    source_status = endpoint.enrichment.get("source_status")
    assert isinstance(source_status, dict)
    assert source_status.get("spamhaus", {}).get("status") == "hit"


def test_spamhaus_shares_one_download_across_endpoints(drop_http: _CountingHttp) -> None:
    """一次解析里几十个 IP 端点，整表只能下载一次。"""
    endpoints = [_ip(f"192.0.2.{index}") for index in range(10, 16)]

    enrich_selected_targets(endpoints, discover_enrichers(), include_case_close=False)

    assert drop_http.calls == 1
    assert all(isinstance(ep.enrichment.get("spamhaus"), dict) for ep in endpoints)


# --------------------------------------------------------------------------- #
# 结案路径分流
# --------------------------------------------------------------------------- #
def test_ripestat_is_case_close_only_and_reachable_there(
    monkeypatch: pytest.MonkeyPatch, drop_http: _CountingHttp
) -> None:
    """★ripestat_bgp 是 case_close_only：普通解析不跑、结案才跑。

    这条同时锁住"分流正确"与"结案路径确实够得着它"——两侧都断言，
    只断言其一的话，把 case_close_only 翻成 False 也不会被发现。
    """
    from apkscan.enrichers import multisource

    seen: list[str] = []

    class _RecordingSession:
        def get(self, url: str, **kwargs: Any):  # noqa: ANN401
            seen.append(url)
            raise RuntimeError("stub: 不实际出网")

    monkeypatch.setattr(
        multisource.RipeStatBgpEnricher, "__init__",
        lambda self, session=None: super(multisource.RipeStatBgpEnricher, self).__init__(
            _RecordingSession()
        ),
    )

    ordinary = _ip("192.0.2.20")
    enrich_selected_targets([ordinary], discover_enrichers(), include_case_close=False)
    assert not seen, "普通解析不得触发 case_close_only 富化器"

    closing = _ip("192.0.2.21")
    stats = enrich_selected_targets([closing], discover_enrichers(), include_case_close=True)
    assert "ripestat_bgp" in _providers(stats)
    assert any("stat.ripe.net" in url for url in seen), "结案路径没够着 ripestat"


def test_ripestat_new_data_calls_are_actually_requested(
    monkeypatch: pytest.MonkeyPatch, drop_http: _CountingHttp
) -> None:
    """★新接的三个 data call 必须真被请求到——否则字段永远为空，等于没接。"""
    from apkscan.enrichers import multisource

    requested: list[str] = []

    class _RipeSession:
        def get(self, url: str, params: dict[str, Any] | None = None, **kwargs: Any):  # noqa: ANN401
            requested.append(url)

            class _R:
                status_code = 200

                @staticmethod
                def raise_for_status() -> None:
                    return None

                @staticmethod
                def json() -> dict[str, Any]:
                    if "prefix-overview" in url:
                        return {
                            "data": {
                                "resource": "192.0.2.0/24",
                                "asns": [{"asn": "64500", "holder": "Example"}],
                            }
                        }
                    if "routing-history" in url:
                        return {
                            "data": {
                                "latest_max_ff_peers": {"v4": 100},
                                "by_origin": [
                                    {
                                        "origin": "64500",
                                        "prefixes": [
                                            {
                                                "prefix": "192.0.2.0/24",
                                                "timelines": [
                                                    {
                                                        "starttime": "2024-01-01T00:00:00",
                                                        "endtime": "2024-02-01T00:00:00",
                                                        "full_peers_seeing": 50,
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        }
                    if "whois" in url:
                        return {
                            "data": {
                                "authorities": ["ARIN"],
                                "records": [
                                    [
                                        {"key": "NetName", "value": "EXAMPLE-NET"},
                                        {"key": "Organization", "value": "Example Corp"},
                                    ]
                                ],
                            }
                        }
                    if "abuse-contact-finder" in url:
                        return {
                            "data": {
                                "abuse_contacts": ["abuse@example.invalid"],
                                "authoritative_rir": "arin",
                            }
                        }
                    return {"data": {}}

            return _R()

    monkeypatch.setattr(
        multisource.RipeStatBgpEnricher, "__init__",
        lambda self, session=None: super(multisource.RipeStatBgpEnricher, self).__init__(
            _RipeSession()
        ),
    )

    endpoint = _ip("192.0.2.30")
    enrich_selected_targets([endpoint], discover_enrichers(), include_case_close=True)

    # 三个新 data call 都被请求到
    assert any("routing-history" in url for url in requested)
    assert any("/whois/" in url for url in requested)
    assert any("abuse-contact-finder" in url for url in requested)

    # 归一后的字段真的落进了 endpoint.enrichment（不是产出了没人接）
    payload = endpoint.enrichment.get("ripestat_bgp")
    assert isinstance(payload, dict)
    assert payload["origin_asn"] == 64500
    assert payload["routing_history_origins"] == [64500]
    assert payload["whois_netname"] == "EXAMPLE-NET"
    assert payload["registered_organization"] == "Example Corp"
    assert payload["abuse_complaint_contacts"] == ["abuse@example.invalid"]


# --------------------------------------------------------------------------- #
# 结案路径：域名 → 解析 IP → 富化
# --------------------------------------------------------------------------- #
def test_resolved_ips_of_a_domain_reach_spamhaus_on_closure(
    drop_http: _CountingHttp,
) -> None:
    """★锁住"域名端点的解析 IP 也被检查"这条链路。

    普通解析的 ``_enrichment_targets`` **不展开**域名的解析 IP，只处理独立 IP 端点；
    结案路径的 ``_enrich_resolved_ips`` 才会为每个解析 IP 造 transient 端点去富化。
    没有这条锁，"函数调通了但真实业务对象（域名）走不到"这类缺口测不出来。

    ★夹具必须用**全球可路由**地址：``_normalized_public_ip`` 明确排除私网/回环/
    文档段（192.0.2/198.51.100/203.0.113）与 CGNAT（100.64/10），
    用保留段会被判 ``excluded_nonpublic``、整条链路根本不触发。
    此处取众所周知的公共 DNS 服务地址，与本仓分析对象无关。
    """
    from apkscan.core.closure import ClosureConfig
    from apkscan.core.closure.sources import _enrich_resolved_ips

    public_ip = "8.8.8.8"  # leak-scan: allow 该链路要求全球可路由地址，保留段会被 _normalized_public_ip 排除
    drop_http.text = (
        '{"cidr":"8.8.8.0/24","sblid":"SBL000009","rir":"arin"}\n'  # leak-scan: allow 同上，需与上面的夹具地址同段
        '{"type":"metadata","timestamp":1700000000,"size":0,"records":1}'
    )

    domain = Endpoint(value="resolved.example", kind="domain", is_suspicious=True)
    domain.enrichment["dns"] = {"ips": [public_ip]}
    # provider_payload_if_hit 只认「本源已记 hit」的载荷，缺状态时解析 IP 取不到。
    domain.enrichment["source_status"] = {"dns": {"status": "hit"}}

    spamhaus_only = [e for e in discover_enrichers() if e.name == "spamhaus"]
    _enrich_resolved_ips(domain, spamhaus_only, ClosureConfig(online=True))

    resolved = domain.enrichment.get("resolved_ip_enrichment")
    assert isinstance(resolved, dict)
    assert public_ip in resolved, "域名的解析 IP 没有进入结案富化"
    payload = resolved[public_ip].get("spamhaus")
    assert isinstance(payload, dict)
    assert payload["network_listed"] is True
    assert payload["matched_cidr"] == "8.8.8.0/24"  # leak-scan: allow 同上
