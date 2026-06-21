"""结构化攻击面段（report.meta["attack_surface"] + digest）测试。

验证：按主机聚合 shodan/recon/cve/certs；辖区门控与渲染层同口径（国内排除、主动字段仅国外）；
digest 透传该段供 Codex 机器可读消费。
"""

from __future__ import annotations

from apkscan.core import forensic
from apkscan.core.models import Endpoint
from apkscan.core.pipeline import _build_attack_surface
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


def test_attack_surface_foreign_full() -> None:
    ep = _ep(
        "evil.example",
        {
            "shodan": {
                "country": "United States",  # → 国外
                "ports": [80, 443],
                "services": [{"port": 80, "product": "nginx", "version": "1.18"}],
                "vulns": ["CVE-2021-23017"],
            },
            "recon": {
                "open_ports": [6379],
                "exposed_paths": [{"path": "/admin", "status": 200}],
                "tls": {"443": {"subject": "CN=evil.example"}},
                "http": [{"port": 80, "status": 200, "server": "nginx"}],
            },
            "cve": {"cves": [{"id": "CVE-2021-44790", "cvss": 9.8, "severity": "CRITICAL"}]},
            "certs": {"related_hostnames": ["api.evil.example", "pay.evil.example"]},
        },
    )
    surface = _build_attack_surface([ep])
    assert len(surface) == 1
    h = surface[0]
    assert h["host"] == "evil.example" and h["jurisdiction"] == "国外"
    assert h["ports"] == [80, 443, 6379]  # shodan ∪ recon 开放端口
    assert h["services"][0]["product"] == "nginx"
    cve_ids = {c["id"] for c in h["cves"]}
    assert {"CVE-2021-44790", "CVE-2021-23017"} <= cve_ids  # cve 富化 + shodan vulns 合并
    assert h["exposed_paths"][0]["path"] == "/admin"  # 主动字段（国外）
    assert h["tls"] and h["active_probed"] is True
    assert set(h["related_subdomains"]) == {"api.evil.example", "pay.evil.example"}


def test_attack_surface_domestic_excluded() -> None:
    # shodan 归属中国 → 最终判国内 → 不进攻击面段（与渲染层一致：境内走调证、不呈现攻击面）。
    ep = _ep("cn.example", {"shodan": {"country": "China", "ports": [80]}})
    assert _build_attack_surface([ep]) == []


def test_attack_surface_unknown_excludes_active_fields() -> None:
    # 无归属国信号 → 未知：被动字段收，主动探测字段（exposed_paths/tls/recon 端口）不收（仅国外才收）。
    ep = _ep(
        "unk.example",
        {
            "shodan": {"ports": [80], "services": [{"port": 80, "product": "apache"}]},
            # 人为塞 recon 数据（实际未知辖区不会有 recon）：验证 is_foreign 门控把它挡在外。
            "recon": {"open_ports": [6379], "exposed_paths": [{"path": "/admin", "status": 200}]},
        },
    )
    surface = _build_attack_surface([ep])
    assert len(surface) == 1
    h = surface[0]
    assert h["jurisdiction"] == "未知"
    assert h["ports"] == [80]  # 仅 shodan，不含 recon 的 6379
    assert "exposed_paths" not in h and "tls" not in h and "active_probed" not in h


def test_attack_surface_skips_endpoints_without_enrichment() -> None:
    # 无任何攻击面富化的端点不进段。
    assert _build_attack_surface([_ep("plain.example", {"asn": {"country": "US"}})]) == []


def test_attack_surface_recon_skipped_not_marked_active_probed() -> None:
    # ★ 回归（真机发现）：未开 FXAPK_ACTIVE_RECON 时 recon 富化是 {"error": 跳过} 占位，
    # 主动探测并未发生——不得标 active_probed=True；且若该主机无其它攻击面数据则整条丢弃。
    only_skip = _ep("us.example", {
        "asn": {"country": "United States"},
        "recon": {"error": "未设 FXAPK_ACTIVE_RECON=1，跳过主动探测（opt-in，主动探测默认关闭）"},
    })
    assert _build_attack_surface([only_skip]) == []  # 无被动攻击面数据 + recon 仅占位 → 不收

    # 有被动 Shodan 数据但 recon 仅占位 → 收（含被动字段），但 active_probed 不置 True。
    passive_plus_skip = _ep("us2.example", {
        "shodan": {"country": "United States", "ports": [80]},
        "recon": {"error": "未设 FXAPK_ACTIVE_RECON=1，跳过主动探测"},
    })
    surface = _build_attack_surface([passive_plus_skip])
    assert len(surface) == 1
    assert surface[0]["ports"] == [80]
    assert "active_probed" not in surface[0]


def test_digest_includes_attack_surface() -> None:
    report = {
        "meta": {
            "attack_surface": [
                {"host": "evil.example", "kind": "domain", "jurisdiction": "国外", "ports": [80]}
            ]
        },
        "leads": [],
    }
    d = build_digest(report)
    assert d["attack_surface"][0]["host"] == "evil.example"
    assert d["summary"]["attack_surface_hosts"] == 1


def test_digest_attack_surface_absent_is_empty() -> None:
    # 旧报告（无 attack_surface）→ 安全返回空，向后兼容。
    d = build_digest({"meta": {}, "leads": []})
    assert d["attack_surface"] == []
    assert d["summary"]["attack_surface_hosts"] == 0


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


def test_attack_surface_marks_cdn() -> None:
    ep = _ep("evil.example", {
        "shodan": {"country": "United States", "ports": [80, 443]},
        "dns": _CF_DNS,
    })
    surface = _build_attack_surface([ep])
    assert surface[0]["cdn"] == "Cloudflare"  # 标记：下列端口是 CDN 边缘、非源站


def test_foreign_forensic_path_no_longer_says_diaozheng() -> None:
    # ★ 海外取证原则：国外分支不走调证，转"查真实源站、取镜像/磁盘/日志"。
    fp = forensic.forensic_path(forensic.JURIS_FOREIGN)
    assert "不调证" in fp.label or "不走调证" in fp.label
    assert any("真实源站" in e for e in fp.evidence)
