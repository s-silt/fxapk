"""PackingAnalyzer 的单测：用 conftest 的 FakeContext 喂合成加固特征。

覆盖：
- 基本属性 name/requires。
- 未加固（无任何特征）→ 空产出，meta["packed"] is None。
- 通过 .so 命中（native_libs / list_files 两路）→ PACKER Lead + HIGH Finding。
- 通过特征文件命中（list_files 子串）→ 命中。
- 通过 dex 类前缀命中（dex_strings 子串）→ 命中。
- 各主流厂商（360/腾讯乐固/爱加密/百度/网易/阿里/几维/娜迦）的 so 名各命中一例。
- Lead 字段契约：category=PACKER, subject=vendor, confidence=HIGH, evidence_to_obtain 三项。
- Finding 契约：HIGH, category=packing, title 含"静态端点不完整"。
- 多厂商同时命中 → 多条 Lead，meta["packers"] 记全部，meta["packed"] 取首个。
- 大小写不敏感（.so 名 / 特征文件）。
- 鲁棒性：native_libs() / list_files() / dex_strings() 抛异常时单源失败不炸整个 analyze。
"""

from __future__ import annotations

from apkscan.analyzers.packing import PackingAnalyzer
from apkscan.core.models import (
    AnalyzerResult,
    Confidence,
    LeadCategory,
    Severity,
)

from tests.conftest import FakeContext


def _analyze(
    *,
    native_libs: list[str] | None = None,
    files: dict[str, bytes] | None = None,
    dex_strings: list[str] | None = None,
) -> AnalyzerResult:
    ctx = FakeContext(
        native_libs=native_libs,
        files=files,
        dex_strings=dex_strings,
    )
    return PackingAnalyzer().analyze(ctx)


# --- 基本属性 -------------------------------------------------------------


def test_analyzer_name_and_requires():
    analyzer = PackingAnalyzer()
    assert analyzer.name == "packing"
    assert analyzer.requires == ["apk"]


# --- 不命中 ---------------------------------------------------------------


def test_no_packing_yields_empty():
    result = _analyze(
        native_libs=["lib/arm64-v8a/libnative.so", "lib/armeabi-v7a/libc++_shared.so"],
        files={"assets/config.json": b"{}", "res/layout/main.xml": b""},
        dex_strings=["com.example.app.MainActivity", "https://example.com"],
    )
    assert result.error is None
    assert result.leads == []
    assert result.findings == []
    assert result.endpoints == []
    assert result.meta["packed"] is None
    # meta["packers"] 在所有 is_hardened=False 分支均显式置空（含"无命中"早退分支），
    # 与"仅弱命中"/"强命中"路径保持键齐全，避免下游 meta["packers"] 触发 KeyError。
    assert result.meta["packers"] == []
    assert result.meta["is_hardened"] is False


def test_meta_packers_present_on_no_rules_branch(monkeypatch):
    # "无可用规则"早退分支也应显式置 meta["packers"]=[]（键齐全、is_hardened=False）。
    from apkscan.analyzers import packing as packing_mod

    monkeypatch.setattr(
        PackingAnalyzer,
        "_load_rules",
        lambda self: ([], list(packing_mod._DEFAULT_EVIDENCE_TO_OBTAIN), "（加固厂商）"),
    )
    result = _analyze(native_libs=["lib/arm64-v8a/libjiagu.so"])
    assert result.meta["packed"] is None
    assert result.meta["packers"] == []
    assert result.meta["is_hardened"] is False
    assert not any(l.category == LeadCategory.PACKER for l in result.leads)


# --- 通过 .so 命中（梆梆）--------------------------------------------------


def test_bangcle_so_in_native_libs_hits():
    result = _analyze(native_libs=["lib/arm64-v8a/libDexHelper.so"])

    assert result.error is None
    assert result.meta["packed"] is not None
    assert "梆梆" in result.meta["packed"]

    # 一条 PACKER Lead
    packer_leads = [l for l in result.leads if l.category == LeadCategory.PACKER]
    assert len(packer_leads) == 1
    lead = packer_leads[0]
    assert "梆梆" in (lead.subject or "")
    assert lead.confidence == Confidence.HIGH
    assert lead.where_to_request and "梆梆" in lead.where_to_request
    assert lead.evidence_to_obtain == [
        "未加固原始安装包",
        "开发者实名注册信息",
        "加固/打包账号与操作日志",
    ]
    # source_refs 指向 native 证据
    assert lead.source_refs
    assert any(ev.source == "native" for ev in lead.source_refs)

    # 一条 HIGH Finding
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.id == "PACK-DETECTED"
    assert finding.severity == Severity.HIGH
    assert finding.category == "packing"
    assert "静态端点不完整" in finding.title


def test_so_detected_via_list_files_only():
    # .so 不在 native_libs，但出现在 list_files（如 assets 下的 so）
    result = _analyze(
        native_libs=[],
        files={"assets/libjiagu.so": b"\x7fELF"},
    )
    assert result.meta["packed"] is not None
    assert "360" in result.meta["packed"]
    assert any(l.category == LeadCategory.PACKER for l in result.leads)


# --- 通过特征文件命中（爱加密 assets/ijiami.dat）--------------------------


def test_ijiami_feature_file_hits():
    result = _analyze(files={"assets/ijiami.dat": b"\x00\x01"})
    assert result.meta["packed"] is not None
    assert "爱加密" in result.meta["packed"]
    lead = next(l for l in result.leads if l.category == LeadCategory.PACKER)
    assert any(ev.source == "resource" for ev in lead.source_refs)


# --- 仅 dex 名词命中（无 so/特征文件强证据）→ 不判加固，降级为 LOW INFO -----


def test_dex_only_match_not_hardened_yields_info_finding():
    # 仅 dex 字符串命中腾讯乐固类名（无任何 so / 特征文件）：
    # 新语义下这是误报场景（内嵌名词表），必须判【未加固】并降级为 LOW Finding。
    result = _analyze(
        dex_strings=["com.tencent.StubShell.TxAppEntry", "com.example.app.A"]
    )
    assert result.meta["packed"] is None
    assert result.meta["is_hardened"] is False
    # 不产 PACKER Lead
    assert not any(l.category == LeadCategory.PACKER for l in result.leads)
    # 出一条 LOW、category=packing、id=PACK-NAME-STRINGS-ONLY 的透明说明 Finding
    info = [
        f
        for f in result.findings
        if f.id == "PACK-NAME-STRINGS-ONLY"
        and f.severity == Severity.LOW
        and f.category == "packing"
    ]
    assert len(info) == 1
    # 溯源：弱 dex-only 信号 → 低置信度（供消费方抑制噪声）。
    assert info[0].confidence == Confidence.LOW
    # 不产 HIGH PACK-DETECTED
    assert not any(f.id == "PACK-DETECTED" for f in result.findings)
    # evidences 透明保留 dex 来源证据
    assert any(ev.source == "dex" for ev in info[0].evidences)


# --- 各主流厂商 so 名命中一例 ---------------------------------------------


def test_each_vendor_detected_by_signature_so():
    cases: dict[str, str] = {
        "libjiagu.so": "360",
        "libshell.so": "腾讯",
        "libexecmain.so": "爱加密",
        "libchaosvmp.so": "娜迦",
        "libbaiduprotect.so": "百度",
        "libnesec.so": "网易",
        "libsgmain.so": "阿里",
        "libkwscmm.so": "几维",
        "libsecexe.so": "梆梆",
    }
    for so_name, vendor_kw in cases.items():
        result = _analyze(native_libs=[f"lib/arm64-v8a/{so_name}"])
        assert result.meta["packed"] is not None, f"{so_name} 应命中"
        assert vendor_kw in result.meta["packed"], (
            f"{so_name} 期望厂商关键词 {vendor_kw}，实际 {result.meta['packed']}"
        )
        assert any(l.category == LeadCategory.PACKER for l in result.leads)
        assert any(
            f.id == "PACK-DETECTED" and f.severity == Severity.HIGH
            for f in result.findings
        )


# --- 大小写不敏感 ---------------------------------------------------------


def test_so_match_case_insensitive():
    result = _analyze(native_libs=["lib/arm64-v8a/LIBJIAGU.SO"])
    assert result.meta["packed"] is not None
    assert "360" in result.meta["packed"]


def test_feature_file_match_case_insensitive():
    result = _analyze(files={"ASSETS/IJIAMI.DAT": b""})
    assert result.meta["packed"] is not None
    assert "爱加密" in result.meta["packed"]


# --- 多厂商同时命中 -------------------------------------------------------


def test_multiple_vendors_each_yield_lead():
    result = _analyze(
        native_libs=["lib/arm64-v8a/libjiagu.so", "lib/arm64-v8a/libshell.so"],
    )
    packer_leads = [l for l in result.leads if l.category == LeadCategory.PACKER]
    assert len(packer_leads) == 2
    vendors = result.meta["packers"]
    assert len(vendors) == 2
    # meta["packed"] 取首个
    assert result.meta["packed"] == vendors[0]
    # 单条 PACK-DETECTED Finding 汇总全部证据
    findings = [f for f in result.findings if f.id == "PACK-DETECTED"]
    assert len(findings) == 1
    assert len(findings[0].evidences) >= 2


# --- 单一厂商多路命中只产一条 Lead ----------------------------------------


def test_single_vendor_multi_source_one_lead_multi_evidence():
    # 360：so + 特征文件 + dex 前缀 三路同时命中，仍只产一条 Lead。
    result = _analyze(
        native_libs=["lib/arm64-v8a/libjiagu.so"],
        files={"assets/libjiagu_art.so": b""},
        dex_strings=["com.stub.StubApp", "com.qihoo.util.QHClassLoader"],
    )
    packer_leads = [l for l in result.leads if l.category == LeadCategory.PACKER]
    assert len(packer_leads) == 1
    # 该 Lead 应聚合多条证据
    assert len(packer_leads[0].source_refs) >= 2


# --- 鲁棒性：单数据源抛异常不炸整个 analyze ------------------------------


def test_native_libs_failure_still_detects_via_files():
    class _Ctx(FakeContext):
        def native_libs(self):  # type: ignore[override]
            raise RuntimeError("boom native_libs")

    ctx = _Ctx(files={"assets/ijiami.dat": b""})
    result = PackingAnalyzer().analyze(ctx)
    # native_libs 失败被吞并记录，但特征文件仍命中
    assert result.error is None
    assert result.meta["packed"] is not None
    assert "爱加密" in result.meta["packed"]


def test_dex_strings_failure_records_not_scanned_no_crash():
    class _Ctx(FakeContext):
        def dex_strings(self):  # type: ignore[override]
            raise RuntimeError("boom dex")

    ctx = _Ctx(native_libs=["lib/arm64-v8a/libjiagu.so"])
    result = PackingAnalyzer().analyze(ctx)
    assert result.error is None
    assert result.meta["dex_scanned"] is False
    # so 路仍命中
    assert result.meta["packed"] is not None
    assert "360" in result.meta["packed"]


def test_list_files_failure_still_detects_via_native_libs():
    class _Ctx(FakeContext):
        def list_files(self):  # type: ignore[override]
            raise RuntimeError("boom list_files")

    ctx = _Ctx(native_libs=["lib/arm64-v8a/libnesec.so"])
    result = PackingAnalyzer().analyze(ctx)
    assert result.error is None
    assert result.meta["packed"] is not None
    assert "网易" in result.meta["packed"]


# --- fixture 样例上下文不应误报 -------------------------------------------


def test_fixture_ctx_not_flagged_as_packed(fake_ctx):
    # conftest 的样例 ctx（libnative.so + 普通 dex 字符串）不应被判为加固。
    result = PackingAnalyzer().analyze(fake_ctx)
    assert result.error is None
    assert result.meta["packed"] is None
    assert result.findings == []
    assert not any(l.category == LeadCategory.PACKER for l in result.leads)


# --- 证据分级回归：强证据(so/file)才判加固，dex-only 降级 -------------------


def test_real_packer_so_still_hardened():
    # 验收①：真加固 fixture（真 vendor .so）→ 仍识别 360、is_hardened=True、有 PACKER Lead
    # 与 HIGH PACK-DETECTED Finding。锚定"强证据存在 → 行为不变"。
    result = _analyze(native_libs=["lib/arm64-v8a/libjiagu.so"])
    assert result.error is None
    assert result.meta["is_hardened"] is True
    assert result.meta["packed"] is not None
    assert "360" in result.meta["packed"]
    packer_leads = [l for l in result.leads if l.category == LeadCategory.PACKER]
    assert len(packer_leads) == 1
    assert any(
        f.id == "PACK-DETECTED" and f.severity == Severity.HIGH for f in result.findings
    )


def test_name_table_dex_strings_not_hardened():
    # 验收②：内嵌加固名词表（dex 字符串）+ uni-app/weex 库（无 vendor so）
    # → NOT packed、is_hardened=False、无 PACKER Lead、一条 LOW INFO Finding，
    #   description 透明声明"未加固"。
    # 注：这些 .so 文件名字符串不匹配 dex_prefixes（类名前缀），仅 com.stub.StubApp/
    #    com.qihoo360. 命中 360（与真实样本一致：名词表里只有 360 类前缀被命中）。
    result = _analyze(
        native_libs=[
            "lib/arm64-v8a/libweexjsb.so",
            "lib/arm64-v8a/libc++_shared.so",
        ],
        dex_strings=[
            "com.stub.StubApp",
            "com.qihoo360.launcher",
            "libSecShell.so",
            "libmobisec.so",
            "libnqshield.so",
            "libDexHelper-x86.so",
        ],
    )
    assert result.error is None
    assert result.meta["packed"] is None
    assert result.meta["is_hardened"] is False
    assert not any(l.category == LeadCategory.PACKER for l in result.leads)

    info = [
        f
        for f in result.findings
        if f.severity == Severity.LOW and f.category == "packing"
    ]
    assert len(info) == 1
    assert info[0].id == "PACK-NAME-STRINGS-ONLY"
    # 透明声明未加固
    assert "未加固" in info[0].description
    # 命中厂商名（360）写进 description
    assert "360" in info[0].description
    # 无 HIGH PACK-DETECTED
    assert not any(f.id == "PACK-DETECTED" for f in result.findings)


def test_multi_vendor_dex_only_flags_name_table():
    # 验收④：≥2 家厂商仅 dex 类前缀命中（真实类名前缀）→ 一条 LOW Finding，
    # description 点明"加固检测词表"。用 YAML 里的真实 dex_prefixes 构造多厂商弱命中。
    result = _analyze(
        native_libs=["lib/arm64-v8a/libweexjsb.so"],  # 无 vendor so
        dex_strings=[
            "com.qihoo360.launcher",  # 360
            "com.tencent.StubShell.TxAppEntry",  # 腾讯乐固
            "com.secneo.apkwrapper.X",  # 梆梆
        ],
    )
    assert result.meta["packed"] is None
    assert result.meta["is_hardened"] is False
    assert not any(l.category == LeadCategory.PACKER for l in result.leads)
    info = [f for f in result.findings if f.id == "PACK-NAME-STRINGS-ONLY"]
    assert len(info) == 1
    assert info[0].severity == Severity.LOW
    assert "加固检测词表" in info[0].description
    assert "未加固" in info[0].description


def test_single_vendor_dex_only_still_info_not_hardened():
    # 单厂商仅 dex 命中（非多厂商）同样走 INFO：不判加固、一条 LOW Finding。
    result = _analyze(dex_strings=["com.tencent.StubShell.TxAppEntry"])
    assert result.meta["packed"] is None
    assert result.meta["is_hardened"] is False
    info = [
        f
        for f in result.findings
        if f.id == "PACK-NAME-STRINGS-ONLY" and f.severity == Severity.LOW
    ]
    assert len(info) == 1
    assert "未加固" in info[0].description


def test_strong_hit_with_extra_dex_noise_still_only_strong_vendor():
    # 强命中厂商正常报加固；同时仅 dex 命中的其他厂商不混入 Lead（互斥分流）。
    result = _analyze(
        native_libs=["lib/arm64-v8a/libjiagu.so"],  # 360 强证据
        dex_strings=["com.tencent.StubShell.TxAppEntry"],  # 腾讯仅 dex 弱命中
    )
    assert result.meta["is_hardened"] is True
    packer_leads = [l for l in result.leads if l.category == LeadCategory.PACKER]
    # 仅 360 一条 Lead，腾讯（仅弱命中）不产 Lead
    assert len(packer_leads) == 1
    assert "360" in (packer_leads[0].subject or "")
    # 强命中存在 → 不产 LOW INFO Finding（2b/2c 互斥）
    assert not any(f.id == "PACK-NAME-STRINGS-ONLY" for f in result.findings)


# --- 新增：开源抽取壳 / DEX-VMP（抗随机化强证据） ---


def test_dex_shell_detected_via_hardcoded_assets_constant():
    # 新版/fork dpt-shell 的 so 名+包名随机化，靠 Const.java 硬编码 assets 常量命中（抗随机化强证据）。
    result = _analyze(files={"assets/OoooooOooo": b"\x00"})
    assert result.error is None
    assert result.meta["is_hardened"] is True
    assert result.meta["packed"] is not None
    assert ("dpt-shell" in result.meta["packed"]) or ("dex-shell" in result.meta["packed"])
    assert any(f.id == "PACK-DETECTED" for f in result.findings)


def test_nmmp_dexvmp_detected_via_so():
    result = _analyze(native_libs=["lib/arm64-v8a/libnmmvm.so"])
    assert result.error is None
    assert result.meta["is_hardened"] is True
    assert "nmmp" in result.meta["packed"]


# --- 容器级诱饵条目（冒充核心文件名的绝对路径条目）-------------------------

_DECOY_FINDING = "APK-CORE-NAME-DECOY-ENTRIES"


def _finding_ids(result: AnalyzerResult) -> list[str]:
    return [f.id for f in result.findings]


def test_core_name_decoy_entries_flagged():
    """★真实样本形态：以 / 开头、首段恰为核心文件名的条目 → 产 Finding 并记 meta。

    实测 24 个样本中 7 个有此构造、共 411 条，首段无一例外只有 AndroidManifest.xml /
    classes.dex / resources.arsc 三种——精确瞄准每个 APK 解析器必找的文件。
    """
    files = {
        "/AndroidManifest.xml///.png": b"x",
        "/resources.arsc/////.png": b"x",
        "/classes.dex/abc.json": b"x",
        "AndroidManifest.xml": b"<manifest/>",
        "classes.dex": b"dex\n035",
    }
    result = _analyze(files=files)
    assert _DECOY_FINDING in _finding_ids(result)
    meta = result.meta["container_decoy_entries"]
    assert meta["absolute_path_entries"] == 3
    assert meta["impersonating_core_names"] == {
        "AndroidManifest.xml": 1, "resources.arsc": 1, "classes.dex": 1,
    }


def test_normal_apk_has_no_decoy_finding():
    """★正常 APK（无绝对路径条目）不得命中——语料中 17/24 样本一条都没有。"""
    files = {
        "AndroidManifest.xml": b"<manifest/>", "classes.dex": b"dex\n035",
        "resources.arsc": b"x", "res/layout/main.xml": b"x", "assets/config.json": b"{}",
    }
    result = _analyze(files=files)
    assert _DECOY_FINDING not in _finding_ids(result)
    assert "container_decoy_entries" not in result.meta


def test_absolute_entry_not_impersonating_core_name_records_meta_only():
    """绝对路径但不冒充核心名：异常但意图不明 → 只记 meta、不产 Finding（宁可漏不可造）。"""
    result = _analyze(files={"/tmp/whatever.txt": b"x", "classes.dex": b"dex\n035"})
    assert _DECOY_FINDING not in _finding_ids(result)
    assert result.meta["container_decoy_entries"]["absolute_path_entries"] == 1
    assert result.meta["container_decoy_entries"]["impersonating_core_names"] == {}


def test_multidex_names_also_covered():
    """多 dex 的 classes2.dex / classes3.dex 同属核心文件名。"""
    result = _analyze(files={"/classes2.dex/x.png": b"x", "/classes3.dex/y.png": b"x"})
    meta = result.meta["container_decoy_entries"]
    assert meta["impersonating_core_names"] == {"classes2.dex": 1, "classes3.dex": 1}
    assert _DECOY_FINDING in _finding_ids(result)


def test_decoy_finding_emitted_even_when_packer_rules_hit():
    """★容器异常与加固命中互不影响：命中加固分支时诱饵 Finding 仍须在（提前 append 对所有 return 生效）。"""
    result = _analyze(
        native_libs=["lib/arm64-v8a/libnmmvm.so"],       # 触发加固强命中分支
        files={"/AndroidManifest.xml///.png": b"x"},
    )
    assert result.meta["is_hardened"] is True
    assert _DECOY_FINDING in _finding_ids(result)
