"""结构化境外源站段（report.meta["overseas_targets"] + digest）测试。

验证：按主机聚合被动富化 shodan/certs（源站归属/端口/服务/技术栈/关联子域）；辖区门控与渲染层同口径
（境内排除、仅【国外 + 未知】收）；digest 透传该段供 Codex 机器可读消费。全程被动 OSINT，对目标零流量。
"""

from __future__ import annotations

from apkscan.core import forensic
from apkscan.core.models import Endpoint
from apkscan.core.pipeline import _build_overseas_targets
from apkscan.report.digest import build_digest

# 取自 HuaCai 真样本的 dns 富化（两个 C2 全在 Cloudflare 后）。
_CF_DNS = {
    "hosting": [
        {"ip": "104.21.27.56", "asn": "AS13335 Cloudflare, Inc.", "org": "Cloudflare, Inc."},
        {"ip": "172.67.141.119", "asn": "AS13335 Cloudflare, Inc.", "org": "Cloudflare, Inc."},
    ]
}


def _ep(value: str, enrichment: dict, kind: str = "domain") -> Endpoint:
    return Endpoint(value=value, kind=kind, evidences=[], enrichment=enrichment)


def test_overseas_targets_foreign_full() -> None:
    ep = _ep(
        "evil.example",
        {
            "shodan": {
                "country": "United States",  # → 国外
                "ip": "45.33.32.156",
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
    # 源站被动归属（识别真实源站、归属哪，对目标零流量）。
    assert h["ip"] == "45.33.32.156" and h["asn"] == "AS63949" and h["org"] == "Linode"
    assert h["country"] == "United States"
    assert h["ports"] == [80, 443]  # 仅 shodan 被动扫库端口
    assert h["services"][0]["product"] == "nginx"
    # 关联子域：crt.sh CT 日志 + shodan hostnames 合并去重（同源站其它域名 → 疑同团伙串案）。
    assert set(h["related_subdomains"]) == {
        "api.evil.example", "pay.evil.example", "cdn.evil.example"
    }
    # ★ 去武器化（契约 D）：结构里绝无漏洞 / 暴露文件 / 主动探测字段。
    assert "cves" not in h and "exposed_paths" not in h and "active_probed" not in h


def test_overseas_targets_domestic_excluded() -> None:
    # shodan 归属中国 → 最终判国内 → 不进境外段（与渲染层一致：境内走调证、不做境外定位）。
    ep = _ep("cn.example", {"shodan": {"country": "China", "ports": [80]}})
    assert _build_overseas_targets([ep]) == []


def test_overseas_targets_unknown_included_passive() -> None:
    # 无归属国信号 → 未知：被动 shodan 数据仍收（境外被动定位对目标零流量、无害；本仓无任何主动能力）。
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


def test_overseas_targets_skips_endpoints_without_shodan_or_certs() -> None:
    # 无 shodan / certs 被动富化的端点不进段（只有 asn 归属不算境外源站目标）。
    assert _build_overseas_targets([_ep("plain.example", {"asn": {"country": "US"}})]) == []


def test_overseas_targets_includes_tech_stack() -> None:
    # 结构化段含 tech_stack（后台/栈指纹，供 Codex 直读串案）；被动 banner → 同后台疑同团伙。
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
    # 去武器化：无暴露文件段 / 无漏洞字段。
    assert "exposures" not in h and "cves" not in h and "exposed_paths" not in h


def test_digest_includes_overseas_targets() -> None:
    report = {
        "meta": {
            "overseas_targets": [
                {"host": "evil.example", "jurisdiction": "国外", "ports": [80]}
            ]
        },
        "leads": [],
    }
    d = build_digest(report)
    assert d["overseas_targets"][0]["host"] == "evil.example"
    assert d["summary"]["overseas_target_hosts"] == 1


def test_digest_overseas_targets_absent_is_empty() -> None:
    # 旧报告（无 overseas_targets）→ 安全返回空，向后兼容。
    d = build_digest({"meta": {}, "leads": []})
    assert d["overseas_targets"] == []
    assert d["summary"]["overseas_target_hosts"] == 0


# --------------------------------------------------------------------------- CDN 穿透（海外取证第一步）


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
    assert "Cloudflare" in blob and "非真实源站" in blob and "不走调证" in blob and "穿透" in blob
    # 非全 CDN → 不提示。
    assert forensic.render_origin_hint({"hosting": [{"org": "Vultr"}]}) == []


def test_foreign_forensic_path_no_longer_says_diaozheng() -> None:
    # ★ 海外取证原则：国外分支不走调证，转"被动定位真实源站 IP + 提取归属标识"。
    fp = forensic.forensic_path(forensic.JURIS_FOREIGN)
    assert "不调证" in fp.label or "不走调证" in fp.label
    assert any("真实源站" in e for e in fp.evidence)
