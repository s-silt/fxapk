"""结构化攻击面段（report.meta["attack_surface"] + digest）测试。

验证：按主机聚合 shodan/recon/cve/certs；辖区门控与渲染层同口径（国内排除、主动字段仅国外）；
digest 透传该段供 Codex 机器可读消费。
"""

from __future__ import annotations

from apkscan.core.models import Endpoint
from apkscan.core.pipeline import _build_attack_surface
from apkscan.report.digest import build_digest


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
