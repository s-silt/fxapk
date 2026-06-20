"""服务器辖区分流 + 取证路径测试。

国内（ICP/.cn/归属国中国）→ 调证路径；国外（境外归属国）→ 取证路径（镜像/日志/漏洞方向）；
无归属信号 → 辖区未定。经 pipeline 的 _domain_lead/_ip_lead 验证真实接线。
"""

from __future__ import annotations

from apkscan.core import forensic
from apkscan.core.models import Endpoint
from apkscan.core.pipeline import _domain_lead, _ip_lead


def test_classify_icp_is_domestic() -> None:
    assert (
        forensic.classify_jurisdiction("evilbackend.com", icp={"license_no": "京ICP备1号"})
        == forensic.JURIS_DOMESTIC
    )


def test_classify_cn_tld_is_domestic() -> None:
    assert forensic.classify_jurisdiction("api.evil.cn") == forensic.JURIS_DOMESTIC


def test_classify_china_country_is_domestic() -> None:
    dns = {"hosting": [{"ip": "1.1.1.1", "country": "China"}]}
    assert forensic.classify_jurisdiction("evilbackend.com", dns=dns) == forensic.JURIS_DOMESTIC


def test_classify_foreign_country_is_foreign() -> None:
    assert (
        forensic.classify_jurisdiction("evilbackend.com", asn={"country": "United States"})
        == forensic.JURIS_FOREIGN
    )
    # 港澳台按境外 / 难直接调处理。
    assert (
        forensic.classify_jurisdiction("evilbackend.com", asn={"country": "Hong Kong"})
        == forensic.JURIS_FOREIGN
    )


def test_classify_no_signal_is_unknown() -> None:
    assert forensic.classify_jurisdiction("evilbackend.com") == forensic.JURIS_UNKNOWN


def test_forensic_path_contents() -> None:
    dom = forensic.forensic_path(forensic.JURIS_DOMESTIC)
    assert "调证" in dom.note and dom.evidence
    foreign = forensic.forensic_path(forensic.JURIS_FOREIGN)
    assert "镜像" in " ".join(foreign.evidence) and "取证" in foreign.label


def _ep(value: str, *, kind: str = "domain", is_private: bool = False, **enrichment) -> Endpoint:
    return Endpoint(value=value, kind=kind, evidences=[], is_private=is_private, enrichment=enrichment)


def test_domain_lead_foreign_gets_forensic_path() -> None:
    ep = _ep("evilbackend.com", dns={"hosting": [{"ip": "5.6.7.8", "country": "United States"}]})
    lead = _domain_lead(ep, online=True)
    assert lead.advice == "建议调证"
    assert "国外服务器·取证为主" in (lead.notes or "")
    assert any("镜像" in e for e in lead.evidence_to_obtain)


def test_domain_lead_domestic_gets_investigation_path() -> None:
    ep = _ep("evilbackend.com", icp={"license_no": "京ICP备1号", "subject": "某公司"})
    lead = _domain_lead(ep, online=True)
    assert lead.advice == "建议调证"
    assert "国内服务器·可调证" in (lead.notes or "")


def test_ip_lead_foreign_gets_forensic_path() -> None:
    ep = _ep("8.8.8.8", kind="ip", asn={"country": "United States", "org": "Example LLC"})
    lead = _ip_lead(ep, online=True)
    assert lead.advice == "建议调证"
    assert "国外服务器·取证为主" in (lead.notes or "")
    assert any("镜像" in e for e in lead.evidence_to_obtain)
