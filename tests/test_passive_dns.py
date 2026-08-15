"""被动 DNS 历史：取回来 + 归一 + **真的被人读到**。

为什么要有这条链：报告此前只有"当前解析 IP"。可涉案域名换 IP 很快，取证时点解析到的往往
已经不是案发时点那台机器——可能换过，也可能已被拦截、指向拦截页。只写当前解析，等于把发函
落点押在一个未必相关的地址上。

★本文件一半的分量在**接线**上：VT / OTX 各自把历史记录取回来还不够，它得出现在读报告的人真会
  看的地方。文书渲染读的是 ``evidence_to_obtain``，不读 ``notes``——只写进 notes 的信号，
  在最终文书里等于不存在（本仓踩过这个坑）。
"""

from __future__ import annotations

import pytest

from apkscan.core.leads import _passive_dns_note, _passive_dns_records, build_endpoint_leads
from apkscan.core.models import Endpoint, Evidence
from apkscan.enrichers.multisource import (
    OtxPassiveEnricher,
    VirusTotalPassiveEnricher,
    _epoch_to_date,
)


class _FakeResponse:
    def __init__(self, payload: object, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> object:
        return self._payload


class _FakeSession:
    """按 URL 片段派发假响应；记录调用过的 URL 供断言。"""

    def __init__(self, routes: dict[str, object]) -> None:
        self.routes = routes
        self.calls: list[str] = []
        self.trust_env = True

    def get(self, url: str, **kwargs) -> _FakeResponse:
        self.calls.append(url)
        for fragment, payload in self.routes.items():
            if fragment in url:
                if isinstance(payload, Exception):
                    raise payload
                return _FakeResponse(payload)
        return _FakeResponse({}, status=404)


def _domain_ep(value: str = "shop.evil-synthetic.test") -> Endpoint:
    return Endpoint(
        kind="domain",
        value=value,
        evidences=[Evidence(source="static", location="classes.dex", snippet=value)],
    )


# ---------------------------------------------------------------------------
# 取回与归一
# ---------------------------------------------------------------------------


def test_virustotal_pulls_resolutions_not_just_last_dns_records(monkeypatch) -> None:
    """★VT 的 ``/resolutions`` 与主查询的 ``last_dns_records`` 不是一回事。

    后者是**最后一次**解析；前者才是历史。此前只取了后者，于是"案发时点落在哪"无从回答。
    """
    monkeypatch.setenv("FXAPK_VT_KEY", "k")
    session = _FakeSession({
        "/resolutions": {"data": [
            {"attributes": {"ip_address": "198.51.100.7", "date": 1750000000}},
            {"attributes": {"ip_address": "198.51.100.8", "date": 1740000000}},
        ]},
        "/domains/": {"data": {"attributes": {"asn": 64500}}},
    })
    enricher = VirusTotalPassiveEnricher(session=session)
    result = enricher.enrich(_domain_ep())

    assert any("/resolutions" in url for url in session.calls), "根本没打 resolutions 端点"
    assert result.data["passive_dns_status"] == "hit"
    values = [r["value"] for r in result.data["passive_dns"]]
    assert values == ["198.51.100.7", "198.51.100.8"]
    assert result.data["passive_dns"][0]["kind"] == "ip"
    assert result.data["passive_dns"][0]["last_seen"], "VT 的 date 应归一成日期"


def test_otx_pulls_passive_dns_with_time_window(monkeypatch) -> None:
    """OTX 带 first/last 时间窗——这正是"案发那天指向谁"要用的字段。"""
    monkeypatch.setenv("FXAPK_OTX_KEY", "k")
    session = _FakeSession({
        "/passive_dns": {"passive_dns": [
            {"address": "203.0.113.9", "first": "2026-05-01T00:00:00",
             "last": "2026-06-30T00:00:00", "record_type": "A"},
        ]},
        "/general": {"pulse_info": {"count": 0, "pulses": []}},
    })
    result = OtxPassiveEnricher(session=session).enrich(_domain_ep())

    record = result.data["passive_dns"][0]
    assert record["value"] == "203.0.113.9"
    assert record["first_seen"].startswith("2026-05-01")
    assert record["last_seen"].startswith("2026-06-30")
    assert record["record_type"] == "A"


def test_ip_endpoint_gets_hostnames_not_ips(monkeypatch) -> None:
    """查 IP 时对端是**域名**（这台机器上历史挂过谁），字段与 kind 都要跟着换。"""
    monkeypatch.setenv("FXAPK_OTX_KEY", "k")
    session = _FakeSession({
        "/passive_dns": {"passive_dns": [{"hostname": "a.evil-synthetic.test", "last": "2026-06-01"}]},
        "/general": {"pulse_info": {"count": 0, "pulses": []}},
    })
    ep = Endpoint(kind="ip", value="203.0.113.9",
                  evidences=[Evidence(source="static", location="classes.dex", snippet="x")])
    record = OtxPassiveEnricher(session=session).enrich(ep).data["passive_dns"][0]
    assert record == {"value": "a.evil-synthetic.test", "kind": "domain", "last_seen": "2026-06-01"}


def test_passive_dns_failure_does_not_void_the_main_result(monkeypatch) -> None:
    """★独立成败：历史查询挂了，主查询拿到的归属数据仍须留下，且状态如实记。"""
    monkeypatch.setenv("FXAPK_VT_KEY", "k")
    session = _FakeSession({
        "/resolutions": RuntimeError("boom"),
        "/domains/": {"data": {"attributes": {"asn": 64500, "as_owner": "Example AS"}}},
    })
    result = VirusTotalPassiveEnricher(session=session).enrich(_domain_ep())

    assert result.ok is True, "被动 DNS 失败不该作废整条结果"
    assert result.data.get("as_owner") == "Example AS"
    assert str(result.data["passive_dns_status"]).startswith("failed:")
    assert "passive_dns" not in result.data


def test_empty_history_is_recorded_as_no_record(monkeypatch) -> None:
    """★"查过没有"必须与"压根没查"可分：两者在数据上同形（都没有 passive_dns 字段）。"""
    monkeypatch.setenv("FXAPK_VT_KEY", "k")
    session = _FakeSession({"/resolutions": {"data": []}, "/domains/": {"data": {"attributes": {}}}})
    data = VirusTotalPassiveEnricher(session=session).enrich(_domain_ep()).data
    assert data["passive_dns_status"] == "no_record"


def test_status_alone_does_not_count_as_a_hit(monkeypatch) -> None:
    """状态字段是元数据：整条什么都没查到时，``_source_status`` 不能因它变成 hit。"""
    monkeypatch.setenv("FXAPK_VT_KEY", "k")
    session = _FakeSession({"/resolutions": {"data": []}, "/domains/": {"data": {"attributes": {}}}})
    data = VirusTotalPassiveEnricher(session=session).enrich(_domain_ep()).data
    assert data["_source_status"] == "no_record"


@pytest.mark.parametrize("value", [0, -1, "x", None, True, 10**12])
def test_epoch_conversion_never_raises(value) -> None:
    """坏时间戳只会得到 None，绝不炸富化。"""
    assert _epoch_to_date(value) in (None,) or isinstance(_epoch_to_date(value), str)


# ---------------------------------------------------------------------------
# 接线：信号必须落到读报告的人看得到的地方
# ---------------------------------------------------------------------------


def _enriched_domain(**blocks) -> Endpoint:
    ep = _domain_ep()
    ep.enrichment.update(blocks)
    return ep


def test_records_from_both_sources_merge_and_dedupe() -> None:
    """同一个落点被两源命中时合并来源，且缺失的时间窗互相补齐。"""
    ep = _enriched_domain(
        virustotal={"passive_dns": [{"value": "198.51.100.7", "kind": "ip", "last_seen": "2026-06-01"}]},
        otx={"passive_dns": [{"value": "198.51.100.7", "kind": "ip", "first_seen": "2026-05-01",
                              "record_type": "A"}]},
    )
    records = _passive_dns_records(ep.enrichment)
    assert len(records) == 1
    assert sorted(records[0]["sources"]) == ["otx", "virustotal"]
    assert records[0]["first_seen"] == "2026-05-01"
    assert records[0]["last_seen"] == "2026-06-01"
    assert records[0]["record_type"] == "A"


def test_note_carries_the_time_window_caveat() -> None:
    """措辞必须点明"取证时点 ≠ 案发时点"，否则读的人会直接拿当前落点发函。"""
    note = _passive_dns_note({
        "otx": {"passive_dns": [{"value": "198.51.100.7", "kind": "ip",
                                 "first_seen": "2026-05-01", "last_seen": "2026-06-30"}]},
    })
    assert "198.51.100.7" in note
    assert "2026-05-01→2026-06-30" in note
    assert "案发日" in note and "时间窗" in note


def test_no_history_yields_no_note() -> None:
    assert _passive_dns_note({}) == ""
    assert _passive_dns_note({"otx": {"passive_dns": []}}) == ""


def test_wired_into_evidence_to_obtain_not_only_notes() -> None:
    """★接线锁：文书渲染读 ``evidence_to_obtain``、不读 ``notes``。

    只写进 notes 的信号在最终文书里等于不存在——本仓在 SNI 伪装那条上踩过一模一样的坑。
    """
    ep = _enriched_domain(
        otx={"passive_dns": [{"value": "198.51.100.7", "kind": "ip", "last_seen": "2026-06-30"}]},
    )
    lead = build_endpoint_leads([ep], online=False)[0]
    joined = " ".join(lead.evidence_to_obtain)
    assert "198.51.100.7" in joined, "历史落点没进 evidence_to_obtain，文书里看不到"
    assert "198.51.100.7" in (lead.notes or "")


def test_wired_for_ip_endpoints_too() -> None:
    """IP 侧同样要有：这台机器上历史挂过哪些域名，既是落点佐证也是并簇线索。"""
    ep = Endpoint(kind="ip", value="203.0.113.9",
                  evidences=[Evidence(source="static", location="classes.dex", snippet="203.0.113.9")])
    ep.enrichment["virustotal"] = {
        "passive_dns": [{"value": "a.evil-synthetic.test", "kind": "domain", "last_seen": "2026-06-01"}]
    }
    lead = build_endpoint_leads([ep], online=False)[0]
    assert "a.evil-synthetic.test" in " ".join(lead.evidence_to_obtain)
