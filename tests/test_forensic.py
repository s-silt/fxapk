"""基础设施辖区候选分流 + 取证路径测试。

国内/国外基础设施归属信号分别形成候选路径；ICP、域名后缀与注册国不代表承载辖区，
登记、承载与第三方历史数据
均不能单独确认 Origin 或运营者。经 pipeline 的 _domain_lead/_ip_lead 验证真实接线。
"""

from __future__ import annotations

import pytest

from apkscan.core import forensic, infra
from apkscan.core.models import Endpoint, Evidence
from apkscan.core.leads import _domain_lead, _ip_lead


def test_classify_icp_is_registration_not_hosting() -> None:
    assert (
        forensic.classify_jurisdiction("evilbackend.example.com", icp={"license_no": "京ICP备1号"})
        == forensic.JURIS_UNKNOWN
    )


def test_classify_cn_tld_is_registration_not_hosting() -> None:
    synthetic_cn_host = ".".join(("unit-test", "synthetic", "cn"))
    assert forensic.classify_jurisdiction(synthetic_cn_host) == forensic.JURIS_UNKNOWN


def test_classify_china_country_is_domestic() -> None:
    dns = {"hosting": [{"ip": "198.51.100.11", "country": "China"}]}
    assert forensic.classify_jurisdiction("evilbackend.example.com", dns=dns) == forensic.JURIS_DOMESTIC


def test_classify_foreign_country_is_foreign() -> None:
    assert (
        forensic.classify_jurisdiction("evilbackend.example.com", asn={"country": "United States"})
        == forensic.JURIS_FOREIGN
    )
    # 港澳台常见长名称包含 China，但不属于中国大陆承载信号。
    for country in ("Hong Kong", "Hong Kong, China", "Taiwan, Province of China", "Macao, China"):
        assert (
            forensic.classify_jurisdiction("evilbackend.example.com", asn={"country": country})
            == forensic.JURIS_FOREIGN
        )


def test_classify_hosting_overrides_registration_and_conflicts_stay_unknown() -> None:
    assert (
        forensic.classify_jurisdiction(
            ".".join(("unit-test", "synthetic", "cn")),
            icp={"license_no": "京ICP备1号"},
            dns={"hosting": [{"ip": "198.51.100.12", "country": "United States"}]},
        )
        == forensic.JURIS_FOREIGN
    )
    assert (
        forensic.classify_jurisdiction(
            "mixed.example",
            dns={"hosting": [{"ip": "198.51.100.13", "country": "China"}]},
            asn={"country": "United States"},
        )
        == forensic.JURIS_UNKNOWN
    )


@pytest.mark.parametrize(
    "placeholder",
    ["unknown", "unknown country", "not available", "N/A", "ZZ", "reserved"],
)
def test_classify_placeholder_country_is_unknown(placeholder: str) -> None:
    assert (
        forensic.classify_jurisdiction("infra.example", asn={"country": placeholder})
        == forensic.JURIS_UNKNOWN
    )


@pytest.mark.parametrize("invalid_country", ["Atlantis", "ZZZ", "US??"])
def test_classify_invalid_country_is_unknown(invalid_country: str) -> None:
    assert (
        forensic.classify_jurisdiction("infra.example", asn={"country": invalid_country})
        == forensic.JURIS_UNKNOWN
    )


def test_classify_no_signal_is_unknown() -> None:
    assert forensic.classify_jurisdiction("evilbackend.example.com") == forensic.JURIS_UNKNOWN


def test_forensic_path_contents() -> None:
    dom = forensic.forensic_path(forensic.JURIS_DOMESTIC)
    assert "调证" in dom.note and dom.evidence
    foreign = forensic.forensic_path(forensic.JURIS_FOREIGN)
    assert "Origin 候选" in " ".join(foreign.evidence) and "依法协作" in foreign.label


def _ep(value: str, *, kind: str = "domain", is_private: bool = False, **enrichment) -> Endpoint:
    return Endpoint(
        value=value,
        kind=kind,
        evidences=[Evidence(source="dex", location="classes.dex")],
        is_private=is_private,
        enrichment=enrichment,
    )


def _synthetic_cloudfront_domain() -> str:
    return "d" + ("0" * 13) + ".cloudfront.net"  # leak-scan: allow 公开 CDN 分发域形态的合成回归夹具，非案件 IOC


def test_cloudfront_tenant_distribution_survives_known_infra_and_reaches_lead() -> None:
    domain = _synthetic_cloudfront_domain()
    assert infra.tenant_distribution(domain) == ("Amazon Web Services, Inc.", domain)
    advice, reason = infra.classify_domain(domain)
    assert advice == infra.ADVICE_INVESTIGATE
    assert "租户级 CDN 分发域名" in reason

    lead = _domain_lead(_ep(domain), online=False)
    assert lead.advice == infra.ADVICE_INVESTIGATE
    assert lead.where_to_request == "CDN / 分发服务商：Amazon Web Services, Inc."
    evidence = "\n".join(lead.evidence_to_obtain)
    for field in (
        "CloudFront Distribution",
        "AWS 账号",
        "Distribution ID/配置",
        "Alternate Domain Names",
        "Origin",
        "OAC/OAI",
        "访问日志",
        "CloudTrail",
        "关联 AWS 资源",
    ):
        assert field in evidence
    assert "边缘地址不得写成 Origin" in evidence


def test_domain_lead_foreign_gets_forensic_path() -> None:
    ep = _ep("evilbackend.example.com", dns={"hosting": [{"ip": "198.51.100.48", "country": "United States"}]})
    lead = _domain_lead(ep, online=True)
    assert lead.advice == "建议调证"
    assert "境外基础设施候选·评估依法协作" in (lead.notes or "")
    assert any("Origin 候选" in e for e in lead.evidence_to_obtain)


def test_domain_lead_domestic_gets_investigation_path() -> None:
    ep = _ep(
        "evilbackend.example.com",
        icp={"license_no": "京ICP备1号", "subject": "某公司"},
        dns={"hosting": [{"ip": "198.51.100.14", "country": "China"}]},
    )
    lead = _domain_lead(ep, online=True)
    assert lead.advice == "建议调证"
    assert "国内基础设施候选·评估依法调证" in (lead.notes or "")
    assert "登记关系，不等于 App 运营者" in (lead.notes or "")


def test_ip_lead_foreign_gets_forensic_path(monkeypatch: pytest.MonkeyPatch) -> None:
    # 端点档位在本测试不是被测对象；mock 后可使用 TEST-NET，避免写入真实公网地址。
    monkeypatch.setattr(
        infra,
        "classify_ip",
        lambda *_args, **_kwargs: (infra.ADVICE_INVESTIGATE, "test fixture"),
    )
    ep = _ep(
        "198.51.100.20",
        kind="ip",
        asn={"country": "United States", "org": "Example LLC"},
    )
    lead = _ip_lead(ep, online=True)
    assert lead.advice == "建议调证"
    assert "境外基础设施候选·评估依法协作" in (lead.notes or "")
    assert any("Origin 候选" in e for e in lead.evidence_to_obtain)


# --------------------------------------------------------------------------- 国内 CDN 边缘判定


def test_cdn_vendor_domestic_org_marker() -> None:
    """解析 IP 归属命中 provider 规则中的专指 CDN 主体/产品形态 → 判为边缘候选。"""
    wangsu = {"hosting": [{"ip": "198.51.100.21", "org": "Wangsu Science & Technology", "asn": "AS4837"}]}
    assert forensic.cdn_vendor(wangsu) is not None
    alicdn = {"hosting": [{"ip": "198.51.100.22", "org": "Alibaba Cloud (Kunlun)", "asn": "AS37963"}]}
    assert forensic.cdn_vendor(alicdn) is not None
    tencent = {"hosting": [{"ip": "198.51.100.23", "org": "Tencent Tcdn", "asn": "AS132203"}]}
    assert forensic.cdn_vendor(tencent) is not None

    reverse_proxy = {"hosting": [{"ip": "198.51.100.24", "org": "Imperva Incapsula"}]}
    assert forensic.cdn_vendor(reverse_proxy) is not None


def test_cdn_vendor_keeps_boundary_checked_cname_as_candidate() -> None:
    """非 CDN 归属时，边界正确的 CNAME 也应保留为分发关系候选。"""
    dns = {
        "hosting": [{"ip": "198.51.100.24", "org": "Some IDC Ltd", "asn": "AS12345"}],
        "cname": ["evil.com.w.kunlungr.com"],
    }
    assert forensic.cdn_vendor(dns) is not None
    dns["headers"] = {"X-Swift-CacheTime": "0"}
    assert forensic.cdn_vendor(dns) is not None

    cloudfront = {
        "hosting": [{"ip": "198.51.100.30", "org": "Example Hosting", "asn": "AS64500"}],
        "cname": [_synthetic_cloudfront_domain()],
    }
    assert forensic.cdn_vendor(cloudfront) == ".".join(("cloudfront", "net"))


def test_cdn_vendor_single_header_or_forged_cname_is_not_enough() -> None:
    """单个通用缓存头、伪造后缀或两者组合均不得触发确定性边缘结论。"""
    dns = {
        "hosting": [{"ip": "198.51.100.25", "org": "Some IDC Ltd", "asn": "AS12345"}],
        "headers": {"X-Cache-Status": "MISS"},
    }
    assert forensic.cdn_vendor(dns) is None
    dns["cname"] = ["cloudflare.net.attacker.example"]
    assert forensic.cdn_vendor(dns) is None

    # 品牌词作为攻击者可控的二级标签也不是 CDN 证据；必须命中服务商控制的完整后缀。
    for name in (
        "edge.cloudflare.invalidtld",
        "foo.akamai.invalidtld",
        "cache.fastly.example",
    ):
        assert forensic.cdn_vendor({"cname": [name]}) is None


def test_cdn_vendor_non_cdn_headers_and_org_is_none() -> None:
    """普通 IDC + 无 CDN CNAME/头 → 不误判为边缘（可能就是源站）。"""
    dns = {
        "hosting": [{"ip": "198.51.100.26", "org": "Some IDC Ltd", "asn": "AS12345"}],
        "headers": {"Server": "nginx", "Content-Type": "text/html"},
        "cname": ["direct.evil.com"],
    }
    assert forensic.cdn_vendor(dns) is None


def test_render_origin_hint_domestic_cdn() -> None:
    dns = {
        "hosting": [{"ip": "198.51.100.27", "org": "Cloudflare, Inc.", "asn": "AS13335"}],
    }
    lines = forensic.render_origin_hint(dns)
    assert len(lines) == 1
    assert "不得未经核实写成 Origin" in lines[0] and "分发服务商" in lines[0]


def test_domestic_cdn_domain_lead_keeps_distribution_boundary() -> None:
    ep = _ep(
        "edge.evilbackend.example.com",
        dns={
            "hosting": [
                {
                    "ip": "198.51.100.28",
                    "country": "China",
                    "org": "Cloudflare, Inc.",
                    "asn": "AS13335",
                }
            ]
        },
    )
    lead = _domain_lead(ep, online=True)
    assert "国内基础设施候选" in (lead.notes or "")
    assert "CDN / 分发服务商候选" in (lead.where_to_request or "")
    assert "Cloudflare" in (lead.where_to_request or "")
    blob = "\n".join(lead.evidence_to_obtain)
    assert "不得未经核实写成 Origin" in blob
    assert "分发服务商" in blob
    assert "向云厂商/IDC 调该 IP" not in blob


def test_domestic_cdn_ip_lead_requests_distribution_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        infra,
        "classify_ip",
        lambda *_args, **_kwargs: (infra.ADVICE_INVESTIGATE, "test fixture"),
    )
    ep = _ep(
        "198.51.100.29",
        kind="ip",
        asn={"country": "China", "org": "Cloudflare, Inc.", "asn": "AS13335"},
    )
    lead = _ip_lead(ep, online=True)
    assert "CDN / 分发服务商" in (lead.where_to_request or "")
    blob = "\n".join(lead.evidence_to_obtain)
    assert "边缘 IP 不得写成 Origin" in blob
    assert "控制面审计记录" in blob


@pytest.mark.parametrize("org", ["Bunny Studio LLC", "Limelight Health Inc."])
def test_ip_lead_does_not_treat_brand_names_in_unrelated_orgs_as_cdn(
    monkeypatch: pytest.MonkeyPatch,
    org: str,
) -> None:
    monkeypatch.setattr(
        infra,
        "classify_ip",
        lambda *_args, **_kwargs: (infra.ADVICE_INVESTIGATE, "test fixture"),
    )
    ep = _ep("198.51.100.40", kind="ip", asn={"country": "US", "org": org})

    assert forensic.cdn_vendor(None, ep.enrichment["asn"]) is None
    lead = _ip_lead(ep, online=True)
    assert "CDN / 分发服务商" not in (lead.where_to_request or "")
    assert "边缘 IP 不得写成 Origin" not in "\n".join(lead.evidence_to_obtain)
