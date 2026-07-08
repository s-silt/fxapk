"""清单投毒加固：包名 androguard × aapt 交叉校验 + MANIFEST-PARSE-ANOMALY Finding。

对抗手法：构造 AndroidManifest 让 androguard 静默 mis-parse（得到错的包名或空），而 aapt /
Android 运行时照常识别 → fxapk 若直接采信 androguard，动态抓包/脱壳会打错目标 App。
本组测试锁死 apk.py 的纯决策函数（全部可单测、不碰真 APK）+ manifest 分析器的异常 Finding。
"""

from __future__ import annotations

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
