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
    assert analyzer.requires == []


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


# --- 通过 dex 类前缀命中（腾讯乐固 StubShell）-----------------------------


def test_tencent_legu_dex_prefix_hits():
    result = _analyze(
        dex_strings=["com.tencent.StubShell.TxAppEntry", "com.example.app.A"]
    )
    assert result.meta["packed"] is not None
    assert "腾讯" in result.meta["packed"]
    lead = next(l for l in result.leads if l.category == LeadCategory.PACKER)
    assert any(ev.source == "dex" for ev in lead.source_refs)


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
