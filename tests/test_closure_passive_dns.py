"""结案期富化拿到的被动 DNS 历史，必须补回线索的取证要项。

线索是在 ``analyze`` 阶段建的，那时富化已跑过一轮，历史落点顺着 ``build_endpoint_leads``
自然进了线索。但结案会**再富化一轮**（选中的目标、常常是首次联网，因为静态分析多半离线跑），
这一轮产物只落在 ``endpoint.enrichment``——``_update_target_leads`` 只回写 where_to_request
与五层证据字段，不重算历史解析这条。

不补这一步的后果很具体：联网结案明明查到了案发时段的落点，报告 endpoints 段里有，
文书里却一个字没有——文书渲染只读 ``evidence_to_obtain``。
"""

from __future__ import annotations

from apkscan.core.closure import _sync_passive_dns_evidence
from apkscan.core.models import Endpoint, Evidence, Lead, LeadCategory, Report

_HISTORY = {
    "otx": {"passive_dns": [
        {"value": "198.51.100.7", "kind": "ip", "first_seen": "2026-05-01", "last_seen": "2026-06-30"},
    ]}
}


def _report(*leads: Lead) -> Report:
    return Report(
        package_name="com.example.synthetic",
        meta={},
        leads=list(leads),
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def _domain_lead(value: str = "shop.evil-synthetic.test") -> Lead:
    return Lead(category=LeadCategory.DOMAIN, value=value, evidence_to_obtain=["RDAP/WHOIS 注册人"])


def _domain_ep(value: str = "shop.evil-synthetic.test", **enrichment: object) -> Endpoint:
    ep = Endpoint(kind="domain", value=value)
    ep.enrichment.update(enrichment)
    return ep


def test_closure_enrichment_reaches_the_letter_fields() -> None:
    """★核心：结案期查到的历史落点要出现在 evidence_to_obtain 里。"""
    lead = _domain_lead()
    report = _report(lead)
    _sync_passive_dns_evidence(report, [_domain_ep(**_HISTORY)])

    joined = " ".join(lead.evidence_to_obtain)
    assert "198.51.100.7" in joined
    assert "2026-05-01→2026-06-30" in joined
    assert "RDAP/WHOIS 注册人" in joined, "原有取证要项不得被覆盖"


def test_repeated_closure_does_not_stack_duplicates() -> None:
    """幂等：反复结案不得把同一条堆成一摞。"""
    lead = _domain_lead()
    report = _report(lead)
    for _ in range(3):
        _sync_passive_dns_evidence(report, [_domain_ep(**_HISTORY)])
    hits = [line for line in lead.evidence_to_obtain if line.startswith("历史解析（被动 DNS")]
    assert len(hits) == 1


def test_refreshed_history_replaces_the_stale_line() -> None:
    """★历史落点会随富化更新：留着两版会让人不知道该信哪个，必须替换而非追加。"""
    lead = _domain_lead()
    report = _report(lead)
    _sync_passive_dns_evidence(report, [_domain_ep(**_HISTORY)])
    _sync_passive_dns_evidence(report, [_domain_ep(otx={"passive_dns": [
        {"value": "203.0.113.9", "kind": "ip", "last_seen": "2026-07-15"},
    ]})])
    joined = " ".join(lead.evidence_to_obtain)
    assert "203.0.113.9" in joined
    assert "198.51.100.7" not in joined, "旧的历史落点没被替掉"


def test_unmatched_and_empty_cases_leave_leads_alone() -> None:
    """没有历史数据、或端点与线索对不上时，一个字都不该动。"""
    lead = _domain_lead()
    before = list(lead.evidence_to_obtain)

    _sync_passive_dns_evidence(_report(lead), [_domain_ep()])            # 无历史
    assert lead.evidence_to_obtain == before
    _sync_passive_dns_evidence(_report(lead), [_domain_ep("other.test", **_HISTORY)])  # 对不上
    assert lead.evidence_to_obtain == before


def test_ip_leads_match_after_port_stripping() -> None:
    """IP 线索带 ``:port`` 时也要能对上——选目标那侧早就剥了端口。"""
    lead = Lead(category=LeadCategory.IP, value="203.0.113.9:8443/tcp", evidence_to_obtain=[])
    ep = Endpoint(kind="ip", value="203.0.113.9")
    ep.enrichment["virustotal"] = {"passive_dns": [
        {"value": "a.evil-synthetic.test", "kind": "domain", "last_seen": "2026-06-01"},
    ]}
    _sync_passive_dns_evidence(_report(lead), [ep])
    assert "a.evil-synthetic.test" in " ".join(lead.evidence_to_obtain)


def test_wired_into_close_report_end_to_end() -> None:
    """★接线锁：走 :func:`close_report` 这条真路径，历史落点必须自己出现在线索上。

    上面那些测试直接调 ``_sync_passive_dns_evidence``——它们证明函数**能**干活，但函数在不在
    结案链路里调用得到，一个字都没证。把 close_report 里那行删掉，上面六条照样全绿；
    只有这一条会红。本仓反复栽在同一件事上：信号提取出来了，没人接。
    """
    from apkscan.core.closure import close_report
    from apkscan.core.closure._shared import ClosureConfig
    from apkscan.core.infra import ADVICE_INVESTIGATE

    value = "shop.evil-synthetic.test"
    lead = Lead(
        category=LeadCategory.DOMAIN,
        value=value,
        advice=ADVICE_INVESTIGATE,  # 只有「建议核查」的才会被选成结案目标
        evidence_to_obtain=["RDAP/WHOIS 注册人"],
    )
    endpoint = _domain_ep(value, **_HISTORY)
    endpoint.evidences = [Evidence(source="dex", location="classes.dex")]
    report = _report(lead)
    report.endpoints = [endpoint]

    close_report(report, ClosureConfig(online=False, max_targets=6))

    joined = " ".join(lead.evidence_to_obtain)
    assert "198.51.100.7" in joined, "close_report 没把历史落点接到线索上（接线掉了）"


def test_broken_enrichment_never_fails_case_closure() -> None:
    """补注记失败不得让结案失败——结案是收口动作，不该被一段附加信息拖垮。"""
    lead = _domain_lead()
    broken = _domain_ep()
    broken.enrichment["otx"] = {"passive_dns": [{"value": object()}]}  # 非法记录
    _sync_passive_dns_evidence(_report(lead), [broken])  # 不抛即通过
