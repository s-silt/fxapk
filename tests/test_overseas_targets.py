"""结构化境外基础设施候选段（report.meta["overseas_targets"] + digest）测试。

验证：按主机聚合 shodan/certs（候选归属/端口/服务/技术栈/关联子域）；辖区门控与渲染层同口径
（仅【国外 + 未知】收）；digest 透传该段供机器可读消费，但不把候选当 Origin 或主体结论。
"""

from __future__ import annotations

import pytest

from apkscan.core import forensic
from apkscan.core.leads import _overseas_target_coverage
from apkscan.core.models import Evidence, Endpoint, Lead, LeadCategory, Report
from apkscan.core.pipeline import _build_overseas_targets
from apkscan.report import html as report_html
from apkscan.report.digest import build_digest

# 纯合成的 Cloudflare 承载富化夹具，只用于锁定 CDN 候选边界。
_CF_DNS = {
    "hosting": [
        {"ip": "198.51.100.10", "asn": "AS13335 Cloudflare, Inc.", "org": "Cloudflare, Inc."},
        {"ip": "198.51.100.18", "asn": "AS13335 Cloudflare, Inc.", "org": "Cloudflare, Inc."},
    ]
}


def _ep(value: str, enrichment: dict, kind: str = "domain") -> Endpoint:
    return Endpoint(value=value, kind=kind, evidences=[], enrichment=enrichment)


def _routing_candidate(label: str = "coverage") -> str:
    # 不使用真实可注册域；后缀刻意无效，但 infra 仍将其按高价值候选路由。
    return ".".join((label, "unit-invalidtld"))


def test_overseas_targets_foreign_full() -> None:
    ep = _ep(
        "evil.example",
        {
            "shodan": {
                "country": "United States",  # → 国外
                "ip": "198.51.100.36",
                "asn": "AS63949",
                "org": "Linode",
                "ports": [80, 443],
                "services": [{"port": 80, "product": "nginx", "version": "1.18"}],
                "hostnames": ["cdn.evil.example"],
            },
            "certs": {"related_hostnames": ["api.evil.example", "pay.evil.example"]},
        },
    )
    surface = _build_overseas_targets([ep])
    assert len(surface) == 1
    h = surface[0]
    assert h["host"] == "evil.example" and h["jurisdiction"] == "国外"
    # 基础设施候选归属，不据此确认 Origin 或运营者。
    assert h["ip"] == "198.51.100.36" and h["asn"] == "AS63949" and h["org"] == "Linode"
    assert h["country"] == "United States"
    assert h["ports"] == [80, 443]  # 仅 shodan 被动扫库端口
    assert h["services"][0]["product"] == "nginx"
    # 关联子域：crt.sh CT 日志 + shodan hostnames 合并去重，仅作待复核候选。
    assert set(h["related_subdomains"]) == {
        "api.evil.example", "pay.evil.example", "cdn.evil.example"
    }
    # ★ 无攻击面契约（契约 D）：结构里绝无漏洞 / 暴露文件 / 主动探测字段。
    assert "cves" not in h and "exposed_paths" not in h and "active_probed" not in h


def test_overseas_targets_domestic_excluded() -> None:
    # shodan 归属中国 → 最终判国内 → 不进境外段（与渲染层一致：境内走调证、不做境外定位）。
    ep = _ep("cn.example", {"shodan": {"country": "China", "ports": [80]}})
    assert _build_overseas_targets([ep]) == []


def test_overseas_targets_unknown_included_passive() -> None:
    # 无归属国信号 → 未知：Shodan 数据仍收，但只形成待复核候选。
    ep = _ep(
        "unk.example",
        {"shodan": {"ports": [80], "services": [{"port": 80, "product": "apache"}]}},
    )
    surface = _build_overseas_targets([ep])
    assert len(surface) == 1
    h = surface[0]
    assert h["jurisdiction"] == "未知"
    assert h["ports"] == [80]
    assert h["services"][0]["product"] == "apache"


@pytest.mark.parametrize("status", ["failed", "no_record", "skipped", "disabled"])
def test_overseas_targets_rejects_non_hit_provider_payloads(status: str) -> None:
    ep = _ep(
        "stale.example",
        {
            "source_status": {
                "shodan": {"status": status},
                "certs": {"status": status},
                "asn": {"status": status},
            },
            "shodan": {"country": "United States", "ports": [443]},
            "certs": {"related_hostnames": ["forged.example"]},
            "asn": {"org": "FORGED-ASN"},
        },
    )

    assert _build_overseas_targets([ep]) == []


def test_overseas_targets_skips_endpoints_without_shodan_or_certs() -> None:
    # 只有 ASN 归属不构成 Shodan/CT 「已画像记录」，但不得从候选分母消失。
    ep = _ep(
        _routing_candidate("asn-only"),
        {
            "source_status": {
                "asn": {"status": "hit"},
                "shodan": {"status": "no_record"},
                "certs": {"status": "no_record"},
            },
            "asn": {"country": "US", "org": "Example ASN"},
        },
    )
    profiles = _build_overseas_targets([ep])
    assert profiles == []

    coverage = _overseas_target_coverage([ep], profiles)
    assert coverage["candidate_hosts_total"] == 1
    assert coverage["profiled_hosts"] == 0
    assert coverage["unprofiled_hosts"] == 1
    assert coverage["by_jurisdiction"] == {"国外": 1, "未知": 0}


def test_overseas_target_coverage_uses_only_status_licensed_provider_payloads() -> None:
    """失败源的残留国别不得制造冲突；只有 hit 的 DNS 可以驱动辖区。"""
    ep = _ep(
        _routing_candidate("status-gate"),
        {
            "source_status": {
                "dns": {"status": "hit"},
                "asn": {"status": "failed"},
            },
            "dns": {
                "hosting": [
                    {"ip": "198.51.100.31", "country": "United States"}
                ]
            },
            # 这是 failed 源的旧残留，若被误读会与 DNS 冲突、把国外错记未知。
            "asn": {"country": "China", "org": "STALE"},
        },
    )

    coverage = _overseas_target_coverage([ep], [])
    assert coverage["by_jurisdiction"] == {"国外": 1, "未知": 0}


def test_overseas_target_coverage_obeys_final_lead_advice() -> None:
    """路由时曾是高价值的端点，若最终因作用域/来源档降为待核，不得留在分母。"""
    ep = _ep(
        _routing_candidate("reference-only"),
        {"asn": {"country": "US", "org": "Example ASN"}},
    )
    final_lead = Lead(
        category=LeadCategory.DOMAIN,
        value=ep.value,
        advice="待核",
    )

    coverage = _overseas_target_coverage([ep], [], [final_lead])
    assert coverage["candidate_hosts_total"] == 0
    assert coverage["profiled_hosts"] == 0
    assert coverage["unprofiled_hosts"] == 0


def test_overseas_targets_includes_tech_stack() -> None:
    # 结构化段含 tech_stack（后台/栈指纹弱候选），不据此确认同一后端或主体。
    ep = _ep("evil.example", {
        "shodan": {
            "country": "United States", "ports": [443],
            "services": [{"port": 443, "http_title": "Jeecg-Boot 管理后台",
                          "cpe": ["cpe:/a:php:php"]}],
        },
    })
    h = _build_overseas_targets([ep])[0]
    stack_names = {t["name"] for t in h["tech_stack"]}
    assert "PHP" in stack_names and "Jeecg-Boot 低代码后台" in stack_names
    # 无攻击面契约：无暴露文件段 / 无漏洞字段。
    assert "exposures" not in h and "cves" not in h and "exposed_paths" not in h


def test_digest_includes_overseas_targets() -> None:
    report = {
        "meta": {
            "overseas_targets": [
                {"host": "evil.example", "jurisdiction": "国外", "ports": [80]}
            ]
        },
    }
    d = build_digest(report)
    assert d["overseas_targets"][0]["host"] == "evil.example"
    assert d["summary"]["overseas_target_hosts"] == 1
    assert d["summary"]["overseas_candidate_hosts_total"] == 1
    assert d["summary"]["overseas_profiled_hosts"] == 1
    assert d["summary"]["overseas_unprofiled_hosts"] == 0
    assert d["overseas_target_coverage"]["scope"] == "profile-only"


def test_digest_overseas_targets_absent_is_empty() -> None:
    # 旧报告（无 overseas_targets）→ 安全返回空，向后兼容。
    d = build_digest({"meta": {}, "leads": []})
    assert d["overseas_targets"] == []
    assert d["summary"]["overseas_target_hosts"] == 0
    assert d["summary"]["overseas_candidate_hosts_total"] == 0
    assert "profiled_hosts=0" in d["overseas_target_coverage"]["note"]


def test_digest_and_html_expose_unprofiled_asn_only_candidate() -> None:
    """profile 列表为空时，digest/HTML 仍必须把 ASN-only 候选的覆盖缺口摆出来。"""
    ep = _ep(
        _routing_candidate("asn-gap"),
        {
            "source_status": {
                "asn": {"status": "hit"},
                "shodan": {"status": "no_record"},
                "certs": {"status": "no_record"},
            },
            "asn": {"country": "US", "org": "Example ASN"},
        },
    )
    serialized_endpoint = {
        "kind": ep.kind,
        "value": ep.value,
        "enrichment": ep.enrichment,
        "evidences": [
            {
                "source": "dex",
                "location": "classes.dex",
                "scope": "case_evidence",
            }
        ],
    }
    serialized_lead = {
        "category": "DOMAIN",
        "value": ep.value,
        "advice": "建议调证",
        "confidence": "MEDIUM",
        "source_refs": [
            {
                "source": "dex",
                "location": "classes.dex",
                "scope": "case_evidence",
            }
        ],
    }
    digest = build_digest(
        {
            "meta": {"overseas_targets": []},
            "leads": [serialized_lead],
            "endpoints": [serialized_endpoint],
        }
    )
    assert digest["summary"]["overseas_candidate_hosts_total"] == 1
    assert digest["summary"]["overseas_profiled_hosts"] == 0
    assert digest["summary"]["overseas_unprofiled_hosts"] == 1

    report = Report(
        package_name="com.example.coverage",
        meta={"overseas_targets": []},
        leads=[
            Lead(
                category=LeadCategory.DOMAIN,
                value=ep.value,
                advice="建议调证",
                source_refs=[Evidence(source="dex", location="classes.dex")],
            )
        ],
        endpoints=[ep],
        findings=[],
        analyzer_status=[],
    )
    html = report_html.render_to_string(report)
    assert "候选 1 个" in html
    assert "Shodan/CT 已画像 0 个" in html
    assert "未画像 1 个" in html
    assert "Shodan/CT 未形成可用画像" in html
    assert "可能未运行、未配置、无记录或失败" in html
    assert "已画像 0 个”不表示“没有境外/辖区未知候选”" in html


def test_digest_coverage_excludes_reference_only_network_profile() -> None:
    """raw advice/profile 即使是最高档，也不得绕过 digest 的当案作用域投影。"""
    host = _routing_candidate("reference-profile")
    reference = {
        "source": "batch",
        "location": "case_correlation.json",
        "scope": "batch_reference",
    }
    report = {
        "meta": {
            "overseas_targets": [
                {"host": host, "jurisdiction": "国外", "asn": "AS64500"}
            ]
        },
        "endpoints": [
            {
                "kind": "domain",
                "value": host,
                "evidences": [reference],
                "enrichment": {"asn": {"country": "US", "org": "Example ASN"}},
            }
        ],
        "leads": [
            {
                "category": "DOMAIN",
                "value": host,
                "advice": "建议调证",
                "confidence": "HIGH",
                "source_refs": [reference],
            }
        ],
    }

    digest = build_digest(report)
    assert digest["leads"][0]["advice"] == "待核"
    assert digest["overseas_targets"] == []
    assert digest["overseas_target_coverage"]["candidate_hosts_total"] == 0
    assert digest["overseas_target_coverage"]["profiled_hosts"] == 0


# --------------------------------------------------------------------------- CDN 边缘与 Origin 候选边界


def test_cdn_vendor_all_cloudflare() -> None:
    assert forensic.cdn_vendor(_CF_DNS) == "Cloudflare"
    # IP 端点走 asn 富化。
    assert forensic.cdn_vendor(None, {"org": "Akamai Technologies", "asn": "AS20940"}) == "Akamai Technologies"


def test_cdn_vendor_mixed_or_none() -> None:
    # 有一个非 CDN 归属（可能就是裸源站）→ 不判全 CDN。
    mixed = {"hosting": [
        {"org": "Cloudflare, Inc.", "asn": "AS13335 Cloudflare, Inc."},
        {"org": "DigitalOcean, LLC", "asn": "AS14061"},
    ]}
    assert forensic.cdn_vendor(mixed) is None
    assert forensic.cdn_vendor(None, None) is None
    assert forensic.cdn_vendor({"hosting": []}) is None


def test_render_origin_hint() -> None:
    lines = forensic.render_origin_hint(_CF_DNS)
    assert len(lines) == 1
    blob = lines[0]
    assert "Cloudflare" in blob and "不得未经核实写成 Origin" in blob and "分发服务商" in blob
    # 非全 CDN → 不提示。
    assert forensic.render_origin_hint({"hosting": [{"org": "Vultr"}]}) == []


def test_foreign_forensic_path_keeps_lawful_channel_open() -> None:
    # 境外分支不得一刀切排除调证；第三方数据只形成 Origin 候选。
    fp = forensic.forensic_path(forensic.JURIS_FOREIGN)
    assert "依法协作" in fp.label
    assert "不调证" not in fp.label and "不走调证" not in fp.note
    assert any("Origin 候选" in e for e in fp.evidence)
