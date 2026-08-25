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

# --------------------------------------------------------------------------- #
# 结案路径：域名 → 解析 IP → 富化 → 落盘
# --------------------------------------------------------------------------- #
def _patch_public_ip_filter(monkeypatch: pytest.MonkeyPatch, allowed: str) -> None:
    """让 TEST-NET 地址通过公网过滤，从而能走完真实链路。

    ★为什么要 patch 而不是直接写一个真公网地址：``_normalized_public_ip`` 排除全部
    私网/回环/文档段（192.0.2、198.51.100、203.0.113）与 CGNAT（100.64/10），
    而标准库里**不存在**既被判为全球可路由、又不代表真实公网空间的 IPv4 段。
    只 patch 这一个过滤判据，接线本身（close_report → _enrich_resolved_ips →
    enrich_selected_targets → spamhaus）仍是真的。

    ★patch 打在**定义它的子模块** ``closure.sources`` 上：该函数只在子模块内部被互相
    调用，打到包命名空间够不着，会静默失效（测试照绿但已不测原来那件事）。
    """
    from apkscan.core.closure import sources as closure_sources

    monkeypatch.setattr(
        closure_sources,
        "_normalized_public_ip",
        lambda value: value if str(value).strip() == allowed else None,
    )


def test_closure_entrypoint_reaches_resolved_ip_and_lands_in_report(
    drop_http: _CountingHttp, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★从**公开结案入口** close_report 出发，锁到落盘 JSON。

    上一层的接线锁只证明了 ``_enrich_resolved_ips`` 这条私有函数链能通，
    并不能证明真实结案编排一定调用它、也不能证明结果活到序列化之后。
    这条把两端都补上：调 close_report，再把报告 JSON 序列化一遍做断言。
    """
    import json

    from apkscan.core.closure import ClosureConfig, close_report
    from apkscan.core.models import Confidence, Evidence, Lead, LeadCategory, Report

    resolved_ip = "198.51.100.77"
    _patch_public_ip_filter(monkeypatch, resolved_ip)
    drop_http.text = (
        '{"cidr":"198.51.100.0/24","sblid":"SBL000077","rir":"arin"}\n'
        '{"type":"metadata","timestamp":1700000000,"size":0,"records":1}'
    )

    # ★端点必须带本案证据：闭环目标选择要求 has_case_evidence，否则计入 scope_excluded
    #   （批量/跨案参考材料不占当前案件的闭环名额）——缺这条会静默选不中，
    #   表现成"结案没跑富化"，很容易被误读成接线断了。
    domain = Endpoint(
        value="resolved.example",
        kind="domain",
        evidences=[Evidence(source="dex", location="synthetic", snippet="resolved.example")],
        is_suspicious=True,
    )
    domain.enrichment["dns"] = {"ips": [resolved_ip]}
    # provider_payload_if_hit 只认已记 hit 的载荷；缺状态时解析 IP 取不到。
    domain.enrichment["source_status"] = {"dns": {"status": "hit"}}
    report = Report(
        package_name="com.example.synthetic",
        meta={},
        leads=[
            Lead(
                category=LeadCategory.DOMAIN,
                value=domain.value,
                confidence=Confidence.HIGH,
                advice="建议调证",
            )
        ],
        endpoints=[domain],
        findings=[],
        analyzer_status=[{"name": "manifest", "status": "ran"}],
    )

    spamhaus_only = [e for e in discover_enrichers() if e.name == "spamhaus"]
    close_report(report, ClosureConfig(online=True), enrichers=spamhaus_only)

    # ① 结案编排真的驱动到了解析 IP
    resolved = report.endpoints[0].enrichment.get("resolved_ip_enrichment")
    assert isinstance(resolved, dict), "close_report 没有产出 resolved_ip_enrichment"
    assert resolved_ip in resolved
    payload = resolved[resolved_ip].get("spamhaus")
    assert isinstance(payload, dict)
    assert payload["network_listed"] is True
    assert payload["matched_cidr"] == "198.51.100.0/24"

    # ② 证据活过序列化（"落进 report.json"这句话的实际含义）
    serialized = json.loads(
        json.dumps(
            {"endpoints": [ep.enrichment for ep in report.endpoints]},
            ensure_ascii=False,
            default=str,
        )
    )
    landed = serialized["endpoints"][0]["resolved_ip_enrichment"][resolved_ip]["spamhaus"]
    assert landed["network_listed"] is True
    assert landed["evidence_type"] == "third_party_network_list"


def test_resolved_ip_cap_is_disclosed_not_silent(
    drop_http: _CountingHttp, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★一个域名最多只查 8 个解析 IP，第 9 个起不可达——这个上限必须被披露。

    否则"这 8 个都没被列入"会被读成"该域名全部解析地址都没被列入"。
    """
    from apkscan.core.closure import ClosureConfig
    from apkscan.core.closure import sources as closure_sources
    from apkscan.core.closure.sources import _MAX_RESOLVED_IPS_PER_TARGET, _enrich_resolved_ips

    # ★期望值**写死 8**，不拿被测常量算：用 _MAX_RESOLVED_IPS_PER_TARGET 反算期望，
    #   改动该常量时测试会跟着变、永远不红（实测过这个突变逃逸）。上限是对外契约，
    #   真要调整就该显式改这里的数字。
    expected_cap = 8
    assert _MAX_RESOLVED_IPS_PER_TARGET == expected_cap, "解析 IP 上限变更须同步本契约"
    total = expected_cap + 3
    ips = [f"198.51.100.{index}" for index in range(10, 10 + total)]
    monkeypatch.setattr(closure_sources, "_normalized_public_ip", lambda value: str(value).strip())

    domain = Endpoint(value="many.example", kind="domain", is_suspicious=True)
    domain.enrichment["dns"] = {"ips": ips}
    domain.enrichment["source_status"] = {"dns": {"status": "hit"}}

    spamhaus_only = [e for e in discover_enrichers() if e.name == "spamhaus"]
    _enrich_resolved_ips(domain, spamhaus_only, ClosureConfig(online=True))

    selection = domain.enrichment.get("resolved_ip_selection")
    assert isinstance(selection, dict)
    assert selection["observed"] == total
    assert selection["selected"] == expected_cap
    assert selection["truncated"] == total - expected_cap
    # 未被选中的地址确实没有被检查——不能让人以为全查过了
    checked = domain.enrichment.get("resolved_ip_enrichment") or {}
    assert len(checked) == expected_cap


def test_resolved_ip_enrichment_passes_include_case_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """★锁住 ``include_case_close=True`` 真的传到解析 IP 这一层。

    用 spamhaus 测不到这条：它 ``case_close_only=False``，无论该参数真假都会跑。
    必须用一个**结案专属**的富化器，才能让"参数被传错"暴露出来。
    """
    from apkscan.core.closure import ClosureConfig
    from apkscan.core.closure import sources as closure_sources
    from apkscan.core.closure.sources import _enrich_resolved_ips
    from apkscan.core.models import EnrichmentResult
    from apkscan.core.registry import BaseEnricher

    calls: list[str] = []

    class _CaseCloseOnlyProbe(BaseEnricher):
        name = "probe_case_close_only"
        applies_to = ["ip"]
        case_close_only = True  # 只有 include_case_close=True 才会被选中

        def enrich(self, ep: Endpoint) -> EnrichmentResult:
            calls.append(ep.value)
            return EnrichmentResult(provider=self.name, ok=True, data={"probed": True})

    resolved_ip = "198.51.100.88"
    monkeypatch.setattr(
        closure_sources,
        "_normalized_public_ip",
        lambda value: value if str(value).strip() == resolved_ip else None,
    )

    domain = Endpoint(value="probe.example", kind="domain", is_suspicious=True)
    domain.enrichment["dns"] = {"ips": [resolved_ip]}
    domain.enrichment["source_status"] = {"dns": {"status": "hit"}}

    _enrich_resolved_ips(domain, [_CaseCloseOnlyProbe()], ClosureConfig(online=True))

    assert calls == [resolved_ip], "结案专属富化器没有在解析 IP 上被调用"
    resolved = domain.enrichment.get("resolved_ip_enrichment") or {}
    assert resolved[resolved_ip]["probe_case_close_only"]["probed"] is True


# --------------------------------------------------------------------------- #
# 结案专属源在普通解析里的留痕
# --------------------------------------------------------------------------- #
def test_case_close_only_source_is_marked_deferred_not_silent(
    drop_http: _CountingHttp,
) -> None:
    """★普通解析不跑结案专属源，但必须留痕。

    不留痕的话，"尚未结案所以没查"和"查过、没查到"在报告里长得一模一样，
    读的人会把前者读成后者——这正是本仓反复强调的"不可判定不得表现成正常值"。
    """
    endpoint = _ip("192.0.2.40")

    enrich_selected_targets(
        [endpoint], discover_enrichers(), include_case_close=False
    )

    source_status = endpoint.enrichment.get("source_status")
    assert isinstance(source_status, dict)
    entry = source_status.get("ripestat_bgp")
    assert entry is not None, "结案专属源被静默跳过，报告里查不出它没跑过"
    assert entry["status"] == "skipped"
    assert entry["reason"] == "deferred_case_close"


def test_deferred_marking_never_overwrites_a_real_outcome(
    drop_http: _CountingHttp,
) -> None:
    """本轮真跑出来的结果永远优先，不能被 deferred 标记盖掉。"""
    endpoint = _ip("192.0.2.41")
    endpoint.enrichment["source_status"] = {"ripestat_bgp": {"status": "hit"}}

    enrich_selected_targets(
        [endpoint], discover_enrichers(), include_case_close=False
    )

    assert endpoint.enrichment["source_status"]["ripestat_bgp"]["status"] == "hit"


def test_deferred_marking_respects_applies_to(drop_http: _CountingHttp) -> None:
    """只标适用于该端点类型的源：ripestat 只适用 IP，域名端点不该被标。"""
    domain = Endpoint(value="only-domain.example", kind="domain", is_suspicious=True)

    enrich_selected_targets([domain], discover_enrichers(), include_case_close=False)

    source_status = domain.enrichment.get("source_status") or {}
    assert "ripestat_bgp" not in source_status


def test_deferred_marking_is_replaced_by_real_outcome_at_closure(
    drop_http: _CountingHttp, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★sol 复审关注点：普通解析标了 deferred，结案跑完必须被**真实结果**取代。

    否则 deferred 会变成"终态"，让结案时的真实查询结果永远写不进去——
    等于把一个占位状态固化成了结论。
    """
    from apkscan.enrichers import multisource

    class _RipeSession:
        def get(self, url: str, params: dict[str, Any] | None = None, **kwargs: Any):  # noqa: ANN401
            class _R:
                status_code = 200

                @staticmethod
                def raise_for_status() -> None:
                    return None

                @staticmethod
                def json() -> dict[str, Any]:
                    if "prefix-overview" in url:
                        return {"data": {"resource": "192.0.2.0/24", "asns": [{"asn": "64500"}]}}
                    return {"data": {}}

            return _R()

    monkeypatch.setattr(
        multisource.RipeStatBgpEnricher, "__init__",
        lambda self, session=None: super(multisource.RipeStatBgpEnricher, self).__init__(
            _RipeSession()
        ),
    )

    endpoint = _ip("192.0.2.50")

    # ① 普通解析：只留下 deferred 占位
    enrich_selected_targets([endpoint], discover_enrichers(), include_case_close=False)
    assert endpoint.enrichment["source_status"]["ripestat_bgp"] == {
        "status": "skipped",
        "reason": "deferred_case_close",
    }

    # ② 结案：真实结果必须顶掉占位
    enrich_selected_targets([endpoint], discover_enrichers(), include_case_close=True)
    entry = endpoint.enrichment["source_status"]["ripestat_bgp"]
    assert entry["status"] != "skipped", "deferred 占位没有被结案的真实结果取代"
    assert entry.get("reason") != "deferred_case_close"
    assert endpoint.enrichment["ripestat_bgp"]["origin_asn"] == 64500


def test_deferred_marking_is_idempotent(drop_http: _CountingHttp) -> None:
    """重复跑普通解析不得叠加或改写已有 reason。"""
    endpoint = _ip("192.0.2.51")

    enrich_selected_targets([endpoint], discover_enrichers(), include_case_close=False)
    first = dict(endpoint.enrichment["source_status"]["ripestat_bgp"])
    enrich_selected_targets([endpoint], discover_enrichers(), include_case_close=False)

    assert endpoint.enrichment["source_status"]["ripestat_bgp"] == first
