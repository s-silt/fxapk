"""暴露面研判（exposure）测试：暴露敏感文件检测 + 技术栈/后台指纹（纯映射，零网络/零 payload）。"""

from __future__ import annotations

from apkscan.core import exposure, forensic


def test_assess_exposed_files() -> None:
    recon = {"exposed_paths": [
        {"path": "/.git/config", "status": 200},
        {"path": "/.env", "status": 200},
        {"path": "/phpinfo.php", "status": 200, "title": "phpinfo()"},
    ]}
    exp = exposure.assess_exposure({}, recon)
    names = {e["name"] for e in exp["exposed_files"]}
    assert any("Git" in n for n in names)
    assert any(".env" in n for n in names)
    assert any("phpinfo" in n for n in names)
    # 每条带 forensic_value + refs(CWE) + caveat，无 payload 字段。
    git = next(e for e in exp["exposed_files"] if "Git" in e["name"])
    assert git["severity"] == "critical" and git["refs"] and "情报方向" in git["caveat"]


def test_assess_tech_stack_from_fingerprint() -> None:
    shodan = {"services": [{"port": 443, "product": "nginx"}]}
    recon = {"http": [{"cookies": ["PHPSESSID"], "title": "Jeecg-Boot 管理后台"}]}
    exp = exposure.assess_exposure(shodan, recon)
    names = {t["name"] for t in exp["tech_stack"]}
    assert "PHP" in names                       # PHPSESSID cookie
    assert "Jeecg-Boot 低代码后台" in names      # title
    # tech_stack 只识别 + 通用方向，无 per-CVE 字段（不内置 RCE 靶单）。
    jeecg = next(t for t in exp["tech_stack"] if "Jeecg" in t["name"])
    assert "须授权" in jeecg["note"] and "情报方向" in jeecg["caveat"]
    assert "cves" not in jeecg and "refs" not in jeecg


def test_cookie_exact_match_no_false_positive() -> None:
    # ★ 回归：cookie 精确匹配——JSESSIONID 判 Java，绝不因 "sessionid"⊂"jsessionid" 误判 Python。
    recon = {"http": [{"cookies": ["JSESSIONID"]}]}
    names = {t["name"] for t in exposure.assess_exposure({}, recon)["tech_stack"]}
    assert "Spring / Java" in names
    assert "Python (Flask / Django / Werkzeug)" not in names
    # 反向：Django 的 sessionid 精确命中 Python，不命中 Java。
    recon2 = {"http": [{"cookies": ["sessionid", "csrftoken"]}]}
    names2 = {t["name"] for t in exposure.assess_exposure({}, recon2)["tech_stack"]}
    assert "Python (Flask / Django / Werkzeug)" in names2
    assert "Spring / Java" not in names2


def test_assess_empty_safe() -> None:
    exp = exposure.assess_exposure(None, None)
    assert exp == {"exposed_files": [], "tech_stack": []}
    exp2 = exposure.assess_exposure({}, {"http": [{"server": "nginx"}]})
    assert exp2["exposed_files"] == []  # 无暴露文件


def test_render_exposures_and_tech_stack() -> None:
    exp = exposure.assess_exposure(
        {}, {"exposed_paths": [{"path": "/.git/config"}], "http": [{"cookies": ["laravel_session"]}]}
    )
    ex_lines = forensic.render_exposures(exp["exposed_files"])
    ts_lines = forensic.render_tech_stack(exp["tech_stack"])
    assert any("暴露泄露" in ln and "Git" in ln for ln in ex_lines)
    assert any("技术栈/后台指纹" in ln and "工具不自动利用" in ln for ln in ts_lines)
    assert any("Laravel" in ln for ln in ts_lines)
    # 渲染空安全。
    assert forensic.render_exposures(None) == [] and forensic.render_tech_stack("x") == []
