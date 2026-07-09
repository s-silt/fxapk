"""清单投毒加固：包名 androguard × aapt 交叉校验 + MANIFEST-PARSE-ANOMALY Finding。

对抗手法：构造 AndroidManifest 让 androguard 静默 mis-parse（得到错的包名或空），而 aapt /
Android 运行时照常识别 → fxapk 若直接采信 androguard，动态抓包/脱壳会打错目标 App。
本组测试锁死 apk.py 的纯决策函数（全部可单测、不碰真 APK）+ manifest 分析器的异常 Finding。
"""

from __future__ import annotations

import struct

from apkscan.analyzers.manifest import ManifestAnalyzer
from apkscan.core import apk as apk_mod
from tests.conftest import FakeContext


# ---- 纯函数：包名形态判定 ------------------------------------------------


def test_looks_like_package_valid() -> None:
    assert apk_mod._looks_like_package("com.tsng.app")
    assert apk_mod._looks_like_package("a.b")
    assert apk_mod._looks_like_package("com.a_b.c9")


def test_looks_like_package_malformed() -> None:
    assert not apk_mod._looks_like_package("")  # 空
    assert not apk_mod._looks_like_package("nodot")  # 无点、单段
    assert not apk_mod._looks_like_package("com..x")  # 空段
    assert not apk_mod._looks_like_package("com.x y")  # 含空格
    assert not apk_mod._looks_like_package("1com.x")  # 段以数字起
    assert not apk_mod._looks_like_package("com.\x00evil")  # 怪字符
    assert not apk_mod._looks_like_package("a." + "b" * 300)  # 超长


# ---- 纯函数：aapt badging 输出解析 --------------------------------------


def test_parse_aapt_package_ok() -> None:
    out = "package: name='com.evil.app' versionCode='1' versionName='1.0'\napplication-label:'x'"
    assert apk_mod._parse_aapt_package(out) == "com.evil.app"


def test_parse_aapt_package_missing() -> None:
    assert apk_mod._parse_aapt_package("no package line here") == ""
    assert apk_mod._parse_aapt_package("") == ""


# ---- 纯函数：交叉校验决策矩阵 -------------------------------------------


def test_decide_agree_no_anomaly() -> None:
    pkg, anomaly = apk_mod._decide_manifest_package("com.x.app", "com.x.app", True)
    assert pkg == "com.x.app"
    assert anomaly is None


def test_decide_disagree_prefers_aapt_and_flags() -> None:
    # 两个来源不一致 → 采信 aapt（与运行时/安装一致）并报异常。
    pkg, anomaly = apk_mod._decide_manifest_package("com.decoy", "com.real.app", True)
    assert pkg == "com.real.app"
    assert anomaly and "不一致" in anomaly


def test_decide_androguard_malformed_aapt_valid() -> None:
    # androguard 解不出合法包名、aapt 得到合法值 → 采信 aapt + 异常。
    pkg, anomaly = apk_mod._decide_manifest_package("", "com.real.app", True)
    assert pkg == "com.real.app"
    assert anomaly
    pkg2, anomaly2 = apk_mod._decide_manifest_package("gar bage", "com.real.app", True)
    assert pkg2 == "com.real.app"
    assert anomaly2


def test_decide_no_aapt_androguard_malformed_flags_sanity() -> None:
    # 无 aapt 第二意见（None）+ androguard 畸形 + APK 结构有效 → 不改值，只出 sanity 信号。
    pkg, anomaly = apk_mod._decide_manifest_package("gar bage", None, True)
    assert pkg == "gar bage"
    assert anomaly and "无 aapt" in anomaly


def test_decide_no_aapt_androguard_valid_no_anomaly() -> None:
    pkg, anomaly = apk_mod._decide_manifest_package("com.x.app", None, True)
    assert pkg == "com.x.app"
    assert anomaly is None


def test_decide_no_aapt_malformed_but_apk_invalid_silent() -> None:
    # APK 本身结构非法（apk_valid=False）时不额外报清单异常，避免与坏包噪音叠加。
    pkg, anomaly = apk_mod._decide_manifest_package("", None, False)
    assert pkg == ""
    assert anomaly is None


def test_decide_aapt_ran_but_empty_no_second_opinion() -> None:
    # aapt 跑了但没解出（""）等同无第二意见：androguard 合法 → 无异常。
    pkg, anomaly = apk_mod._decide_manifest_package("com.x.app", "", True)
    assert pkg == "com.x.app"
    assert anomaly is None


# ---- 纯函数：AXML 字符串池兜底（第三来源）------------------------------


def test_decide_axml_fallback_when_androguard_empty_no_aapt() -> None:
    # 无 aapt、androguard 空、APK 有效 → 用 AXML 字符串池直读值兜底 + 异常信号（疑投毒）。
    pkg, anomaly = apk_mod._decide_manifest_package("", None, True, axml="com.real.app")
    assert pkg == "com.real.app"
    assert anomaly and "字符串池" in anomaly


def test_decide_axml_fallback_when_androguard_malformed() -> None:
    pkg, anomaly = apk_mod._decide_manifest_package("gar bage", None, True, axml="com.real.app")
    assert pkg == "com.real.app"
    assert anomaly and "字符串池" in anomaly


def test_decide_aapt_wins_over_axml() -> None:
    # aapt 是运行时权威，优先级高于 AXML 兜底。
    pkg, anomaly = apk_mod._decide_manifest_package("", "com.aapt.app", True, axml="com.axml.app")
    assert pkg == "com.aapt.app"
    assert anomaly  # androguard 空、aapt 有值 → 报异常


def test_decide_valid_androguard_ignores_axml() -> None:
    # androguard 已得合法包名 → 不启用 AXML 兜底，也不报异常。
    pkg, anomaly = apk_mod._decide_manifest_package("com.x.app", None, True, axml="com.other.app")
    assert pkg == "com.x.app"
    assert anomaly is None


def test_decide_axml_malformed_falls_back_to_sanity_signal() -> None:
    # AXML 兜底值也不像合法包名 → 退回原 sanity 信号、不改值。
    pkg, anomaly = apk_mod._decide_manifest_package("", None, True, axml="gar bage")
    assert pkg == ""
    assert anomaly and "无 aapt" in anomaly


def test_decide_axml_not_used_when_apk_invalid() -> None:
    # APK 结构非法时不额外改判（与既有静默口径一致）。
    pkg, anomaly = apk_mod._decide_manifest_package("", None, False, axml="com.real.app")
    assert pkg == ""
    assert anomaly is None


# ---- AXML 字符串池容错直读 ---------------------------------------------


def _build_axml_manifest(package: str) -> bytes:
    """构造最小可解析的二进制 AXML：UTF-8 字符串池 + <manifest package=...> START_ELEMENT。"""
    strings = ["manifest", "package", package]
    sdata = b""
    offsets: list[int] = []
    for s in strings:
        offsets.append(len(sdata))
        b = s.encode("utf-8")
        # 短串：字符数/字节数各占 1 字节（本构造仅用 ASCII，长度 <128）。
        sdata += bytes([len(s) & 0x7F, len(b) & 0x7F]) + b + b"\x00"
    while len(sdata) % 4:
        sdata += b"\x00"
    sc = len(strings)
    strings_start = 28 + 4 * sc
    sp_fields = struct.pack("<IIIII", sc, 0, 0x100, strings_start, 0)  # count/style/flags(UTF8)/strStart/styleStart
    sp_offsets = b"".join(struct.pack("<I", o) for o in offsets)
    sp_payload = sp_fields + sp_offsets + sdata
    sp_chunk = struct.pack("<HHI", 0x0001, 28, 8 + len(sp_payload)) + sp_payload

    node = struct.pack("<HHIII", 0x0102, 16, 16 + 20 + 20, 1, 0xFFFFFFFF)
    attr_ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, 0, 20, 20, 1, 0, 0, 0)  # ns/name=manifest/attrStart/attrSize/count/id/class/style
    attribute = struct.pack("<IIIHBBI", 0xFFFFFFFF, 1, 2, 8, 0, 3, 2)  # ns/name=package/rawValue=pkg/size/res0/type=string/data=pkg
    se_chunk = node + attr_ext + attribute

    total = 8 + len(sp_chunk) + len(se_chunk)
    return struct.pack("<HHI", 0x0003, 8, total) + sp_chunk + se_chunk


def test_axml_package_from_bytes_reads_package() -> None:
    blob = _build_axml_manifest("com.evil.app")
    assert apk_mod._axml_package_from_bytes(blob) == "com.evil.app"


def test_axml_package_from_bytes_random_segment_name() -> None:
    # 涉诈马甲包常用随机字母段包名。
    blob = _build_axml_manifest("singansfg.unkhdozmhu.sdancsuhsfj")
    assert apk_mod._axml_package_from_bytes(blob) == "singansfg.unkhdozmhu.sdancsuhsfj"


def test_axml_package_from_bytes_rejects_non_package_value() -> None:
    # 池里 package 值不像合法包名（无点单段）→ 不返回（不臆造）。
    blob = _build_axml_manifest("singlesegment")
    assert apk_mod._axml_package_from_bytes(blob) == ""


def test_axml_package_from_bytes_garbage_returns_empty() -> None:
    assert apk_mod._axml_package_from_bytes(b"") == ""
    assert apk_mod._axml_package_from_bytes(b"not an axml at all") == ""
    assert apk_mod._axml_package_from_bytes(b"\x03\x00\x08\x00\xff\xff\xff\xff") == ""


# ---- manifest 分析器：异常 → HIGH Finding -------------------------------


def _ctx(anomaly: str | None) -> FakeContext:
    return FakeContext(
        package_name="com.real.app",
        manifest_xml="<manifest package='com.real.app'><application/></manifest>",
        manifest_anomaly=anomaly,
    )


def test_analyzer_emits_anomaly_finding() -> None:
    result = ManifestAnalyzer().analyze(_ctx("androguard 与 aapt 不一致——疑清单投毒"))
    hits = [f for f in result.findings if f.id == "MANIFEST-PARSE-ANOMALY"]
    assert len(hits) == 1
    assert hits[0].severity.name == "HIGH"
    assert result.meta.get("manifest_anomaly")


def test_analyzer_no_anomaly_no_finding() -> None:
    # 未设 manifest_anomaly → getattr 默认 None → 不发该 Finding。
    result = ManifestAnalyzer().analyze(_ctx(None))
    assert all(f.id != "MANIFEST-PARSE-ANOMALY" for f in result.findings)
    assert "manifest_anomaly" not in result.meta


def test_analyzer_anomaly_resets_meta_package_to_corrected() -> None:
    # 投毒场景：manifest_xml 内嵌"诱饵"包名，但 ctx.package_name 已被 aapt 交叉校验纠正为真包名。
    # _extract() 会先用诱饵覆盖 meta["package_name"]；异常分支须把它回正到已校验的权威值，
    # 否则 digest/graph ingest（优先取 meta["package_name"]）仍按诱饵包名归档。
    ctx = FakeContext(
        package_name="com.real.app",  # 已交叉校验的权威包名
        manifest_xml="<manifest package='com.decoy.evil'><application/></manifest>",
        manifest_anomaly="androguard 解析包名=com.decoy.evil、aapt=com.real.app 不一致——疑清单投毒",
    )
    result = ManifestAnalyzer().analyze(ctx)
    assert result.meta["package_name"] == "com.real.app"  # 不是 com.decoy.evil


def test_analyzer_no_anomaly_keeps_manifest_package() -> None:
    # 无异常时不改动 _extract 的既有行为：meta 仍取 manifest_xml 内声明的 package。
    ctx = FakeContext(
        package_name="com.real.app",
        manifest_xml="<manifest package='com.real.app'><application/></manifest>",
    )
    result = ManifestAnalyzer().analyze(ctx)
    assert result.meta["package_name"] == "com.real.app"
