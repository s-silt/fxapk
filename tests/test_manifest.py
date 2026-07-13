"""manifest 分析器单测：用 FakeContext 喂合成 manifest，断言 meta / Finding。

覆盖命中与不命中两类用例，含空/损坏/XXE manifest 的健壮性。
不依赖 androguard / 网络。
"""

from __future__ import annotations

import pytest

from apkscan.analyzers.manifest import ManifestAnalyzer
from apkscan.core.models import AnalyzerResult, Finding, Severity
from tests.conftest import FakeContext

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _manifest(
    *,
    package: str = "com.fraud.app",
    version_name: str = "1.0",
    version_code: str = "1",
    min_sdk: int | None = 21,
    target_sdk: int | None = 33,
    debuggable: bool | None = None,
    allow_backup: bool | None = None,
    cleartext: bool | None = None,
    network_security_config: str | None = None,
) -> str:
    """构造合成 AndroidManifest XML（属性带 android: 命名空间前缀）。"""
    uses_sdk = ""
    sdk_attrs = []
    if min_sdk is not None:
        sdk_attrs.append(f'android:minSdkVersion="{min_sdk}"')
    if target_sdk is not None:
        sdk_attrs.append(f'android:targetSdkVersion="{target_sdk}"')
    if sdk_attrs:
        uses_sdk = f"  <uses-sdk {' '.join(sdk_attrs)}/>\n"

    app_attrs = []
    if debuggable is not None:
        app_attrs.append(f'android:debuggable="{str(debuggable).lower()}"')
    if allow_backup is not None:
        app_attrs.append(f'android:allowBackup="{str(allow_backup).lower()}"')
    if cleartext is not None:
        app_attrs.append(f'android:usesCleartextTraffic="{str(cleartext).lower()}"')
    if network_security_config is not None:
        app_attrs.append(f'android:networkSecurityConfig="{network_security_config}"')
    app_attr_str = (" " + " ".join(app_attrs)) if app_attrs else ""

    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<manifest xmlns:android="{ANDROID_NS}" package="{package}" '
        f'android:versionName="{version_name}" android:versionCode="{version_code}">\n'
        f"{uses_sdk}"
        f"  <application{app_attr_str}>\n"
        '    <activity android:name=".MainActivity"/>\n'
        "  </application>\n"
        "</manifest>\n"
    )


def _ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


def _run(manifest_xml: str, package_name: str = "com.fraud.app") -> AnalyzerResult:
    ctx = FakeContext(package_name=package_name, manifest_xml=manifest_xml)
    return ManifestAnalyzer().analyze(ctx)


# ---------------------------------------------------------------------------
# 基础元信息提取
# ---------------------------------------------------------------------------


def test_meta_extraction_full() -> None:
    xml = _manifest(
        package="com.fraud.vest",
        version_name="2.3.1",
        version_code="231",
        min_sdk=23,
        target_sdk=33,
    )
    result = _run(xml, package_name="ignored.because.manifest.wins")

    assert result.analyzer == "manifest"
    assert result.error is None
    meta = result.meta
    assert meta["package_name"] == "com.fraud.vest"
    assert meta["version_name"] == "2.3.1"
    assert meta["version_code"] == "231"
    assert meta["min_sdk"] == 23
    assert meta["target_sdk"] == 33


def test_package_name_fallback_to_ctx() -> None:
    # manifest 根节点无 package 属性 → 回退到 ctx.package_name。
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<manifest xmlns:android="{ANDROID_NS}">\n'
        "  <application/>\n"
        "</manifest>\n"
    )
    result = _run(xml, package_name="com.ctx.pkg")
    assert result.meta["package_name"] == "com.ctx.pkg"


def test_non_numeric_sdk_codename_parses_to_none() -> None:
    # 预览版常用代号（如 "S"），应解析为 None 而非崩溃。
    xml = _manifest(min_sdk=None, target_sdk=None).replace(
        "<uses-sdk", '<uses-sdk android:targetSdkVersion="Tiramisu"'
    )
    # 上面 replace 在没有 uses-sdk 时不会注入；显式构造一个。
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.x">\n'
        '  <uses-sdk android:targetSdkVersion="Tiramisu"/>\n'
        "  <application/>\n"
        "</manifest>\n"
    )
    result = _run(xml)
    assert result.meta["target_sdk"] is None
    assert result.error is None


# ---------------------------------------------------------------------------
# 命中：风险 Finding
# ---------------------------------------------------------------------------


def test_debuggable_true_emits_medium_finding() -> None:
    result = _run(_manifest(debuggable=True))
    assert result.meta["debuggable"] is True
    dbg = [f for f in result.findings if f.id == "MANIFEST-DEBUGGABLE"]
    assert len(dbg) == 1
    f = dbg[0]
    assert f.severity is Severity.MEDIUM
    assert f.category == "manifest"
    assert f.evidences and f.evidences[0].source == "manifest"


def test_allow_backup_true_emits_low_finding() -> None:
    result = _run(_manifest(allow_backup=True))
    assert result.meta["allow_backup"] is True
    ab = [f for f in result.findings if f.id == "MANIFEST-ALLOWBACKUP"]
    assert len(ab) == 1
    assert ab[0].severity is Severity.LOW
    assert ab[0].category == "manifest"


def test_cleartext_true_emits_finding() -> None:
    result = _run(_manifest(cleartext=True))
    assert result.meta["uses_cleartext_traffic"] is True
    ct = [f for f in result.findings if f.id == "MANIFEST-CLEARTEXT"]
    assert len(ct) == 1
    assert ct[0].category == "manifest"


def test_network_security_config_triggers_cleartext_finding() -> None:
    # 即便未显式 usesCleartextTraffic，存在自定义 networkSecurityConfig 也告警。
    result = _run(_manifest(network_security_config="@xml/network_security_config"))
    assert result.meta["network_security_config"] == "@xml/network_security_config"
    ct = [f for f in result.findings if f.id == "MANIFEST-CLEARTEXT"]
    assert len(ct) == 1
    assert "networkSecurityConfig" in ct[0].evidences[0].snippet


def test_low_target_sdk_emits_finding() -> None:
    # 规则下限默认 30；target=22 应命中。
    result = _run(_manifest(target_sdk=22))
    assert result.meta["target_sdk"] == 22
    low = [f for f in result.findings if f.id == "MANIFEST-LOW-TARGETSDK"]
    assert len(low) == 1
    assert low[0].severity is Severity.LOW
    assert "22" in low[0].evidences[0].snippet


def test_all_risks_combined() -> None:
    result = _run(
        _manifest(
            debuggable=True,
            allow_backup=True,
            cleartext=True,
            target_sdk=22,
        )
    )
    assert {
        "MANIFEST-DEBUGGABLE",
        "MANIFEST-ALLOWBACKUP",
        "MANIFEST-CLEARTEXT",
        "MANIFEST-LOW-TARGETSDK",
    } <= _ids(result.findings)


def test_suspicious_version_name_annotated() -> None:
    result = _run(_manifest(version_name="1.0-test"))
    assert result.meta.get("suspicious_version_name") is True
    assert "test" in result.meta.get("suspicious_version_hits", [])


# ---------------------------------------------------------------------------
# 不命中：干净 manifest
# ---------------------------------------------------------------------------


def test_clean_manifest_no_findings() -> None:
    # 显式关闭全部风险标志、合规 targetSdk → 不产生任何 Finding。
    result = _run(
        _manifest(
            debuggable=False,
            allow_backup=False,
            cleartext=False,
            target_sdk=34,
            version_name="1.0",
        )
    )
    assert result.error is None
    assert result.findings == []
    assert result.meta["debuggable"] is False
    assert result.meta["allow_backup"] is False
    assert result.meta["uses_cleartext_traffic"] is False
    assert result.meta.get("suspicious_version_name") is None


def test_unset_flags_parse_to_none_no_findings() -> None:
    # 未声明的标志解析为 None；当前实现仅对显式 True 报 Finding。
    result = _run(_manifest(target_sdk=34))
    assert result.meta["debuggable"] is None
    assert result.meta["allow_backup"] is None
    assert result.meta["uses_cleartext_traffic"] is None
    assert _ids(result.findings) == set()


# ---------------------------------------------------------------------------
# 健壮性：空 / 损坏 / XXE
# ---------------------------------------------------------------------------


def test_empty_manifest_records_error_no_crash() -> None:
    result = _run("", package_name="com.empty.app")
    assert result.error is not None
    # 即便解析失败，meta 仍带 ctx 回退包名。
    assert result.meta["package_name"] == "com.empty.app"
    assert result.findings == []


def test_malformed_xml_records_error_no_crash() -> None:
    result = _run("<manifest><application></manifest", package_name="com.broken.app")
    assert result.error is not None
    assert result.meta["package_name"] == "com.broken.app"


def test_xxe_dtd_entity_is_rejected() -> None:
    # billion-laughs / XXE 风格输入：含 DTD + 实体声明，必须被拒绝，不解析、不崩溃。
    malicious = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE manifest [ <!ENTITY lol "loooool"> ]>\n'
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.evil">\n'
        "  <application>&lol;</application>\n"
        "</manifest>\n"
    )
    result = _run(malicious, package_name="com.ctx.fallback")
    assert result.error is not None
    # 拒绝后回退到 ctx 包名，主流程不崩。
    assert result.meta["package_name"] == "com.ctx.fallback"


def test_fixture_context_runs(fake_ctx: FakeContext) -> None:
    # conftest 的 fake_ctx manifest 含 package=com.test.app、无风险标志。
    result = ManifestAnalyzer().analyze(fake_ctx)
    assert result.analyzer == "manifest"
    assert result.error is None
    assert result.meta["package_name"] == "com.test.app"
    # 该 manifest 未声明风险标志 → 无 Finding。
    assert result.findings == []


def test_attributes_without_namespace_prefix() -> None:
    # 兼容上游给出不带命名空间前缀的属性形态。
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest package="com.noprefix" versionName="9.9" versionCode="99">\n'
        '  <uses-sdk targetSdkVersion="22"/>\n'
        '  <application debuggable="true"/>\n'
        "</manifest>\n"
    )
    result = _run(xml)
    assert result.meta["package_name"] == "com.noprefix"
    assert result.meta["version_name"] == "9.9"
    assert result.meta["target_sdk"] == 22
    assert result.meta["debuggable"] is True
    assert "MANIFEST-DEBUGGABLE" in _ids(result.findings)
    assert "MANIFEST-LOW-TARGETSDK" in _ids(result.findings)


@pytest.mark.parametrize(
    ("value", "expected"),
    [("true", True), ("TRUE", True), ("1", True), ("false", False), ("0", False)],
)
def test_bool_parsing_variants(value: str, expected: bool) -> None:
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<manifest xmlns:android="{ANDROID_NS}" package="com.b">\n'
        f'  <application android:debuggable="{value}"/>\n'
        "</manifest>\n"
    )
    result = _run(xml)
    assert result.meta["debuggable"] is expected


# ---------------------------------------------------------------------------
# Xposed/LSPosed 模块身份（现代 LSPosed 模块只用 manifest meta-data 声明）
# ---------------------------------------------------------------------------


def _manifest_with_metadata(metadata_xml: str, package: str = "com.evil.mod") -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<manifest xmlns:android="{ANDROID_NS}" package="{package}">\n'
        "  <application>\n"
        f"{metadata_xml}"
        "  </application>\n"
        "</manifest>\n"
    )


def test_xposed_module_flagged_high_anti_analysis():
    md = (
        '    <meta-data android:name="xposedmodule" android:value="true"/>\n'
        '    <meta-data android:name="xposedminversion" android:value="93"/>\n'
        '    <meta-data android:name="xposedscope" android:resource="@array/scope"/>\n'
    )
    result = _run(_manifest_with_metadata(md))
    assert result.meta.get("xposed_module") is True
    xf = [f for f in result.findings if f.id == "MANIFEST-XPOSED-MODULE"]
    assert len(xf) == 1
    assert xf[0].severity == Severity.HIGH
    assert xf[0].category == "anti_analysis"
    assert result.meta["xposed_markers"] == ["xposedminversion", "xposedmodule", "xposedscope"]


def test_single_xposed_marker_flagged():
    # 仅 xposedminversion（每个 Xposed 模块必带）即足以判定。
    md = '    <meta-data android:name="xposedminversion" android:value="82"/>\n'
    result = _run(_manifest_with_metadata(md))
    assert result.meta.get("xposed_module") is True
    assert any(f.id == "MANIFEST-XPOSED-MODULE" for f in result.findings)


def test_normal_metadata_not_flagged_as_xposed():
    # ★FP 防回归：正常 app 的 meta-data（GMS 版本等）不得被判为 Xposed 模块。
    md = (
        '    <meta-data android:name="com.google.android.gms.version" android:value="12451000"/>\n'
        '    <meta-data android:name="firebase_analytics_collection_enabled" android:value="true"/>\n'
    )
    result = _run(_manifest_with_metadata(md, package="com.normal.app"))
    assert result.meta.get("xposed_module") is None
    assert not any(f.id == "MANIFEST-XPOSED-MODULE" for f in result.findings)


def test_xposed_markers_capped_against_case_variant_flood():
    # ★对抗性防回归：恶意清单塞大量大小写变体 meta-data，marker 集合仍硬性 ≤4（不膨胀 description）。
    import itertools

    variants = []
    base = "xposedminversion"
    # 造 200 条大小写变体（够证明去重按小写、集合不随输入线性膨胀）。
    for i, bits in enumerate(itertools.product("ab", repeat=8)):
        if i >= 200:
            break
        name = "".join(c.upper() if b == "a" else c for c, b in zip(base, bits))
        variants.append(f'    <meta-data android:name="{name}" android:value="1"/>\n')
    result = _run(_manifest_with_metadata("".join(variants)))
    assert result.meta.get("xposed_module") is True
    assert result.meta["xposed_markers"] == ["xposedminversion"]  # 200 变体 → 去重成 1
    assert len(result.meta["xposed_markers"]) <= 4
