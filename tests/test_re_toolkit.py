"""ReToolkitAnalyzer 单测：用 conftest 的 FakeContext 喂合成 hook/反检测工具特征。

覆盖：
- 基本属性 name/requires。
- 未命中 → 空 meta（re_toolkit=[]、hook_frameworks=[]、anti_frida=False），无 Finding。
- .so 命中 hook 框架（ShadowHook）→ RE-TOOLKIT-DETECTED Finding(anti_analysis/HIGH)、hook_frameworks 记名。
- dex 包名命中反 frida 工具（LibcoreSyscall）→ anti_frida=True、Finding HIGH。
- dex 包名命中 hook 框架（pine，仅 dex 弱证据）→ 命中、severity MEDIUM。
- frida-gadget 经特征文件命中。
- 大小写不敏感（.so 名）。
- 多工具同时命中 → 一条 Finding 汇总、meta 列全部。
- fixture 样例 ctx 不误报。
- 鲁棒性：单数据源抛异常不炸整个 analyze。
"""

from __future__ import annotations

from apkscan.analyzers.re_toolkit import ReToolkitAnalyzer
from apkscan.core.models import AnalyzerResult, Severity

from tests.conftest import FakeContext


def _analyze(
    *,
    native_libs: list[str] | None = None,
    files: dict[str, bytes] | None = None,
    dex_strings: list[str] | None = None,
) -> AnalyzerResult:
    ctx = FakeContext(native_libs=native_libs, files=files, dex_strings=dex_strings)
    return ReToolkitAnalyzer().analyze(ctx)


# --- 基本属性 -------------------------------------------------------------


def test_analyzer_name_and_requires():
    analyzer = ReToolkitAnalyzer()
    assert analyzer.name == "re_toolkit"
    assert analyzer.requires == ["apk"]


# --- 不命中 ---------------------------------------------------------------


def test_no_toolkit_yields_empty():
    result = _analyze(
        native_libs=["lib/arm64-v8a/libnative.so", "lib/armeabi-v7a/libc++_shared.so"],
        files={"assets/config.json": b"{}"},
        dex_strings=["com.example.app.MainActivity", "https://example.com"],
    )
    assert result.error is None
    assert result.findings == []
    assert result.meta["re_toolkit"] == []
    assert result.meta["hook_frameworks"] == []
    assert result.meta["anti_frida"] is False


# --- .so 命中 hook 框架（ShadowHook）--------------------------------------


def test_shadowhook_so_hit_yields_medium_finding():
    result = _analyze(native_libs=["lib/arm64-v8a/libshadowhook.so"])
    assert result.error is None

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.id == "RE-TOOLKIT-DETECTED"
    assert finding.category == "anti_analysis"
    # 仅 hook 框架（dual-use，亦见于合法 APM）→ MEDIUM，不单凭此报 HIGH
    assert finding.severity == Severity.MEDIUM
    assert any(ev.source == "native" for ev in finding.evidences)

    assert any("ShadowHook" in name for name in result.meta["hook_frameworks"])
    tools = result.meta["re_toolkit"]
    assert len(tools) == 1
    assert tools[0]["category"] == "hook_framework"
    assert tools[0]["strong"] is True
    assert result.meta["anti_frida"] is False


# --- .so 命中内存插桩工具（Android-Mem-Kit）---------------------------------


def test_android_mem_kit_so_hit_yields_medium_finding():
    result = _analyze(native_libs=["lib/arm64-v8a/libmemkit.so"])
    assert result.error is None
    assert any("Android-Mem-Kit" in name for name in result.meta["hook_frameworks"])
    assert result.findings[0].severity == Severity.MEDIUM


def test_android_mem_kit_and_shadowhook_shim_both_detected():
    # Android-Mem-Kit 依赖 shadowhook 兼容层，两条目应同时命中且不互相抵消。
    result = _analyze(
        native_libs=["lib/arm64-v8a/libmemkit.so", "lib/arm64-v8a/libshadowhook_nothing.so"]
    )
    names = [t["name"] for t in result.meta["re_toolkit"]]
    assert any("Android-Mem-Kit" in n for n in names)
    assert any("ShadowHook" in n for n in names)


# --- dex 命中反 frida 工具（LibcoreSyscall）→ anti_frida=True ---------------


def test_libcoresyscall_sets_anti_frida():
    result = _analyze(dex_strings=["dev.tmpfs.libcoresyscall.core.Syscall"])
    assert result.error is None
    assert result.meta["anti_frida"] is True
    # 反 frida 命中 → HIGH（即便只有 dex 证据）
    finding = result.findings[0]
    assert finding.severity == Severity.HIGH
    assert "frida" in finding.description.lower() or "frida" in finding.recommendation.lower()
    # 反 frida 工具不属 hook_framework 分类
    assert result.meta["hook_frameworks"] == []


# --- dex 命中 hook 框架（pine，仅弱证据）→ MEDIUM --------------------------


def test_pine_dex_only_medium():
    result = _analyze(dex_strings=["top.canyie.pine.Pine", "com.example.A"])
    assert result.error is None
    finding = result.findings[0]
    # 仅 dex 证据、无反 frida → MEDIUM
    assert finding.severity == Severity.MEDIUM
    assert any("pine" in name for name in result.meta["hook_frameworks"])
    assert result.meta["re_toolkit"][0]["strong"] is False


# --- frida-gadget 经特征文件命中 ------------------------------------------


def test_frida_gadget_via_file():
    result = _analyze(files={"lib/arm64-v8a/libfrida-gadget.so": b"\x7fELF"})
    assert result.meta["re_toolkit"]
    assert any("Gadget" in t["name"] for t in result.meta["re_toolkit"])
    # 内嵌 frida gadget（instrumentation，罕见于正常 app）→ HIGH
    assert result.findings[0].severity == Severity.HIGH


# --- 大小写不敏感 ---------------------------------------------------------


def test_so_match_case_insensitive():
    result = _analyze(native_libs=["lib/arm64-v8a/LIBSHADOWHOOK.SO"])
    assert result.meta["re_toolkit"]
    assert any("ShadowHook" in name for name in result.meta["hook_frameworks"])


# --- 多工具同时命中 -------------------------------------------------------


def test_multiple_tools_aggregated_in_one_finding():
    result = _analyze(
        native_libs=["lib/arm64-v8a/libshadowhook.so", "lib/arm64-v8a/libdobby.so"],
        dex_strings=["dev.tmpfs.libcoresyscall.core.MemoryAccess"],
    )
    # 一条 Finding 汇总
    assert len(result.findings) == 1
    tools = result.meta["re_toolkit"]
    names = [t["name"] for t in tools]
    assert any("ShadowHook" in n for n in names)
    assert any("Dobby" in n for n in names)
    assert any("LibcoreSyscall" in n for n in names)
    # 含反 frida → anti_frida=True、HIGH
    assert result.meta["anti_frida"] is True
    assert result.findings[0].severity == Severity.HIGH


# --- fixture 样例 ctx 不误报 ----------------------------------------------


def test_fixture_ctx_not_flagged(fake_ctx):
    result = ReToolkitAnalyzer().analyze(fake_ctx)
    assert result.error is None
    assert result.findings == []
    assert result.meta["re_toolkit"] == []
    assert result.meta["anti_frida"] is False


# --- 鲁棒性：单数据源抛异常不炸整个 analyze -------------------------------


def test_native_libs_failure_still_detects_via_dex():
    class _Ctx(FakeContext):
        def native_libs(self):  # type: ignore[override]
            raise RuntimeError("boom native_libs")

    ctx = _Ctx(dex_strings=["dev.tmpfs.libcoresyscall.core.Syscall"])
    result = ReToolkitAnalyzer().analyze(ctx)
    assert result.error is None
    assert result.meta["anti_frida"] is True


def test_dex_failure_still_detects_via_so():
    class _Ctx(FakeContext):
        def dex_strings(self):  # type: ignore[override]
            raise RuntimeError("boom dex")

    ctx = _Ctx(native_libs=["lib/arm64-v8a/libshadowhook.so"])
    result = ReToolkitAnalyzer().analyze(ctx)
    assert result.error is None
    assert any("ShadowHook" in name for name in result.meta["hook_frameworks"])
