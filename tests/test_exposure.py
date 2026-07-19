"""技术栈 / 后台框架指纹研判（exposure）测试：纯映射，零网络 / 零 payload。

只做「被动 banner 指纹 → 是什么技术栈 / 后台框架」的识别，用作**同后台 = 疑同团伙**串案信号；
不研判漏洞、不给利用方向。数据来自 shodan 已采集的被动 banner，对目标零流量。
"""

from __future__ import annotations

from apkscan.core import exposure, forensic


def test_assess_tech_stack_from_shodan_banner() -> None:
    # shodan 被动 banner：product / http_title / cpe → 技术栈 / 后台框架指纹（对目标零流量）。
    shodan = {"services": [
        {"port": 443, "product": "nginx", "http_title": "Jeecg-Boot 管理后台",
         "cpe": ["cpe:/a:php:php:7.4"]},
        {"port": 8080, "product": "Apache Tomcat", "version": "9.0"},
    ]}
    names = {t["name"] for t in exposure.assess_tech_stack(shodan)}
    assert "Jeecg-Boot 低代码后台" in names   # http_title 命中
    assert "PHP" in names                      # cpe 命中
    assert "Spring / Java" in names            # product=tomcat 命中


def test_tech_stack_is_identify_only_no_vuln_fields() -> None:
    # ★ 去武器化：只识别 + 串案方向，绝无 per-CVE / refs / exploit 字段（不内置漏洞靶单）。
    shodan = {"services": [{"port": 443, "http_title": "Jeecg-Boot"}]}
    jeecg = next(t for t in exposure.assess_tech_stack(shodan) if "Jeecg" in t["name"])
    assert "串案" in jeecg["note"]
    assert set(jeecg) == {"name", "note"}  # 只有 name / note
    assert "cves" not in jeecg and "refs" not in jeecg


def test_assess_tech_stack_empty_safe() -> None:
    assert exposure.assess_tech_stack(None) == []
    assert exposure.assess_tech_stack({}) == []
    # 无任何已知栈指纹（纯 nginx）→ 空列表。
    assert exposure.assess_tech_stack({"services": [{"port": 443, "product": "nginx"}]}) == []


def test_build_host_fingerprint_flattens_passive_banners() -> None:
    # 主机指纹拍平：shodan services 的 product / http_server / http_title / module / cpe。
    fp = exposure.build_host_fingerprint(
        {"services": [{"product": "Apache Tomcat", "http_server": "nginx",
                       "http_title": "Login", "module": "https", "cpe": ["cpe:/a:php:php"]}]},
    )
    assert "apache tomcat" in fp["product"] and "nginx" in fp["server"]
    assert "login" in fp["title"] and "https" in fp["module"]
    assert "cpe:/a:php:php" in fp["cpe"]
    # 坏输入安全：非 dict → 全空桶。
    empty = exposure.build_host_fingerprint(None)
    assert all(v == set() for v in empty.values())


def test_render_tech_stack() -> None:
    tech = exposure.assess_tech_stack({"services": [{"port": 443, "http_title": "Jeecg-Boot"}]})
    ts_lines = forensic.render_tech_stack(tech)
    assert any("技术栈/后台框架指纹" in ln for ln in ts_lines)
    assert any("Jeecg" in ln for ln in ts_lines)
    # 渲染空安全。
    assert forensic.render_tech_stack(None) == [] and forensic.render_tech_stack("x") == []
