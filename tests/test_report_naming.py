"""apkscan.core.report_naming 单测：报告文件名 base 计算 + 文件名清理。

覆盖（问题 2「报告按 APK 名命名」的纯函数核心）：
- report_base：APK stem 作 base（含中文保留）；apk 空/清理后空 → 回退包名 → 再回退 "report"。
- sanitize_base：Windows 非法字符 + 控制字符 → "_"；去首尾空白与点；空串。
- 绝不抛：异常路径仍返回安全 base。
"""

from __future__ import annotations

from apkscan.core.report_naming import report_base, sanitize_base


# --- report_base：APK 名去后缀 -------------------------------------------


def test_report_base_from_apk_stem() -> None:
    assert report_base("/p/demo.apk", "pkg") == "demo"
    assert report_base("demo.apk") == "demo"
    # 多重后缀只去最后一段（.apk 单后缀场景无影响）。
    assert report_base("a.b.apk") == "a.b"


def test_report_base_preserves_chinese() -> None:
    """中文 APK 名保留（报告本就中文）。"""
    assert report_base("ybku/深远记算.apk", "") == "深远记算"


def test_report_base_ignores_directory() -> None:
    """只取文件名部分，不含目录。"""
    assert report_base("C:/some dir/sub/app-release.apk") == "app-release"


# --- sanitize_base：非法字符 / 控制字符 / 首尾点空白 ----------------------


def test_sanitize_replaces_illegal_chars() -> None:
    # 每个 Windows 非法字符（<>:"/\|?*）各替成一个 _。
    assert sanitize_base('a<b>:c"/d') == "a_b__c__d"


def test_sanitize_replaces_control_chars() -> None:
    assert sanitize_base("x\x01y") == "x_y"
    assert sanitize_base("a\x00b") == "a_b"


def test_sanitize_strips_whitespace_and_dots() -> None:
    assert sanitize_base("  .a.  ") == "a"
    assert sanitize_base("name.") == "name"
    assert sanitize_base("  spaced  ") == "spaced"


def test_sanitize_empty_returns_empty() -> None:
    assert sanitize_base("") == ""
    assert sanitize_base("   ") == ""
    assert sanitize_base("...") == ""


def test_sanitize_preserves_chinese() -> None:
    assert sanitize_base("深远记算") == "深远记算"


# --- sanitize_base：Windows 保留设备名加 _ 前缀 --------------------------


def test_sanitize_reserved_device_names_prefixed() -> None:
    """CON/NUL/PRN/AUX/COM1/LPT1 等保留名（大小写不敏感）→ 加 _ 前缀。"""
    assert sanitize_base("CON") == "_CON"
    assert sanitize_base("nul") == "_nul"
    assert sanitize_base("Com1") == "_Com1"
    assert sanitize_base("LPT9") == "_LPT9"
    # report_base 经 stem 去后缀后命中保留名也加前缀。
    assert report_base("NUL.apk", "") == "_NUL"


def test_sanitize_non_reserved_names_untouched() -> None:
    """与保留名相近但非保留（com / console / com10 / 中文）不加前缀。"""
    assert sanitize_base("com") == "com"  # 裸 com 非保留（只有 com1-9）
    assert sanitize_base("console") == "console"
    assert sanitize_base("com10") == "com10"
    assert sanitize_base("深远记算") == "深远记算"
    assert report_base("/p/com.fraud.app.apk", "") == "com.fraud.app"


# --- report_base：回退链 -------------------------------------------------


def test_report_base_fallback_to_package_when_stem_empty() -> None:
    """apk stem 清理后为空（如全是点）→ 回退 package_name（清理后）。"""
    assert report_base("...apk", "com.fraud.app") == "com.fraud.app"
    # 包名含非法字符也被清理（极端，但不崩）。
    assert report_base("", 'pkg/with:bad') == "pkg_with_bad"


def test_report_base_fallback_to_report_when_all_empty() -> None:
    """apk 与 package 都空/清理后空 → 最终回退 "report"。"""
    assert report_base("", "") == "report"
    assert report_base("...apk", "...") == "report"
    assert report_base("", "   ") == "report"


def test_report_base_empty_apk_path() -> None:
    """apk_path 为空串 → 直接走包名回退。"""
    assert report_base("", "mypkg") == "mypkg"
