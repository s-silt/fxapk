"""服务器辖区分流 + 取证路径测试。

国内（ICP/.cn/归属国中国）→ 调证路径；国外（境外归属国）→ 被动定位真实源站 IP + 提取归属标识；
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
    assert "被动定位" in " ".join(foreign.evidence) and "被动定位" in foreign.label


def _ep(value: str, *, kind: str = "domain", is_private: bool = False, **enrichment) -> Endpoint:
    return Endpoint(value=value, kind=kind, evidences=[], is_private=is_private, enrichment=enrichment)


def test_domain_lead_foreign_gets_forensic_path() -> None:
    ep = _ep("evilbackend.com", dns={"hosting": [{"ip": "5.6.7.8", "country": "United States"}]})
    lead = _domain_lead(ep, online=True)
    assert lead.advice == "建议调证"
    assert "国外服务器·被动定位" in (lead.notes or "")
    assert any("真实源站" in e for e in lead.evidence_to_obtain)


def test_domain_lead_domestic_gets_investigation_path() -> None:
    ep = _ep("evilbackend.com", icp={"license_no": "京ICP备1号", "subject": "某公司"})
    lead = _domain_lead(ep, online=True)
    assert lead.advice == "建议调证"
    assert "国内服务器·可调证" in (lead.notes or "")


def test_ip_lead_foreign_gets_forensic_path() -> None:
    ep = _ep("8.8.8.8", kind="ip", asn={"country": "United States", "org": "Example LLC"})
    lead = _ip_lead(ep, online=True)
    assert lead.advice == "建议调证"
    assert "国外服务器·被动定位" in (lead.notes or "")
    assert any("真实源站" in e for e in lead.evidence_to_obtain)


# --------------------------------------------------------------------------- 国内 CDN 边缘判定


def test_cdn_vendor_domestic_org_marker() -> None:
    """解析 IP 归属命中国内 CDN（网宿/白山/阿里/腾讯/字节）→ 判为边缘节点。"""
    wangsu = {"hosting": [{"ip": "1.2.3.4", "org": "Wangsu Science & Technology", "asn": "AS4837"}]}
    assert forensic.cdn_vendor(wangsu) is not None
    alicdn = {"hosting": [{"ip": "1.2.3.4", "org": "Alibaba Cloud (Kunlun)", "asn": "AS37963"}]}
    assert forensic.cdn_vendor(alicdn) is not None
    tencent = {"hosting": [{"ip": "1.2.3.4", "org": "Tencent Tcdn", "asn": "AS132203"}]}
    assert forensic.cdn_vendor(tencent) is not None


def test_cdn_vendor_by_cname() -> None:
    """CNAME 链指向国内 CDN（即便 IP 归属看似普通 IDC）→ 仍判边缘。"""
    dns = {
        "hosting": [{"ip": "1.2.3.4", "org": "Some IDC Ltd", "asn": "AS12345"}],
        "cname": ["evil.com.w.kunlungr.com"],
    }
    assert forensic.cdn_vendor(dns) is not None


def test_cdn_vendor_by_response_headers() -> None:
    """响应头带国内 CDN 信号（acw_tc / via: ens-cache / x-swift-* / x-ser）→ 判边缘。"""
    dns = {
        "hosting": [{"ip": "1.2.3.4", "org": "Some IDC Ltd", "asn": "AS12345"}],
        "headers": {"Set-Cookie": "acw_tc=abc123; path=/", "Via": "cache.51cdn.com"},
    }
    assert forensic.cdn_vendor(dns) is not None
    dns2 = {
        "hosting": [{"ip": "1.2.3.4", "org": "Some IDC Ltd", "asn": "AS12345"}],
        "headers": {"Via": "ens-cache5.l2et2", "X-Swift-CacheTime": "0"},
    }
    assert forensic.cdn_vendor(dns2) is not None


def test_cdn_vendor_non_cdn_headers_and_org_is_none() -> None:
    """普通 IDC + 无 CDN CNAME/头 → 不误判为边缘（可能就是源站）。"""
    dns = {
        "hosting": [{"ip": "1.2.3.4", "org": "Some IDC Ltd", "asn": "AS12345"}],
        "headers": {"Server": "nginx", "Content-Type": "text/html"},
        "cname": ["direct.evil.com"],
    }
    assert forensic.cdn_vendor(dns) is None


def test_render_origin_hint_domestic_cdn() -> None:
    dns = {
        "hosting": [{"ip": "1.2.3.4", "org": "Some IDC Ltd", "asn": "AS12345"}],
        "headers": {"Set-Cookie": "acw_tc=abc123"},
    }
    lines = forensic.render_origin_hint(dns)
    assert len(lines) == 1
    assert "非真实源站" in lines[0] and "穿透" in lines[0]
