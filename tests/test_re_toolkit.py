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


# --- 新增：反重打包 / 反注入 / 身份伪装 工具链(开源加固·反侦察) ---


def test_signcheck_so_sets_anti_frida():
    result = _analyze(native_libs=["lib/arm64-v8a/libSignVerify.so"])
    assert result.error is None
    assert result.meta["anti_frida"] is True
    assert any("SignCheck" in t["name"] for t in result.meta["re_toolkit"])
    assert result.findings[0].severity == Severity.HIGH


def test_injectdetect_so_sets_anti_frida():
    result = _analyze(native_libs=["lib/arm64-v8a/libcheck_env.so"])
    assert result.meta["anti_frida"] is True
    assert any("InjectDetect" in t["name"] for t in result.meta["re_toolkit"])


def test_xposed_module_identity_via_file():
    result = _analyze(files={"assets/xposed_init": b"com.evil.Hook"})
    assert any("Xposed" in t["name"] for t in result.meta["re_toolkit"])


def test_virtual_camera_via_dex():
    result = _analyze(dex_strings=["com.zensu.camswap.MainHook", "com.example.A"])
    assert any(("虚拟摄像头" in t["name"]) or ("CamSwap" in t["name"]) for t in result.meta["re_toolkit"])


def test_benign_antixposed_string_not_flagged_as_module():
    # ★FP 防回归：正规银行/支付 app 内嵌 de.robv.android.xposed 做反 Xposed 检测,
    # 不得被误判为"Xposed 模块身份"(所以该条目只锚 assets/xposed_init、不加 de.robv 作 dex 前缀)。
    result = _analyze(dex_strings=["de.robv.android.xposed.XposedHelpers", "com.bank.App"])
    assert not any(t["name"] == "Xposed/LSPosed 模块身份" for t in result.meta["re_toolkit"])


# --- 新增：native .so 符号/字符串扫描(抗 so 名/包名改名) ---------------------


def test_arthook_via_native_symbol_string():
    # ArtHook 静态库编入宿主 .so、无独立 so/dex，靠 .so 内 mangled 符号 _ZN7arthook 识别。
    result = _analyze(files={"lib/arm64-v8a/libnative.so": b"xxx _ZN7arthook9InitializeEv yyy"})
    assert result.error is None
    assert any("ArtHook" in t["name"] for t in result.meta["re_toolkit"])
    assert any("ArtHook" in n for n in result.meta["hook_frameworks"])
    # so_strings 命中 = 强证据
    assert any(t["strong"] for t in result.meta["re_toolkit"] if "ArtHook" in t["name"])


def test_signcheck_renamed_so_via_double_string():
    # so 改名为 libfoo.so、无原包名，但 .so 内同含两 native 字面量 → all_of 命中(抗改名)。
    blob = b"aa android.content.pm.IPackageManager bb android.os.IServiceManager cc"
    result = _analyze(files={"lib/arm64-v8a/libfoo.so": blob})
    assert any("SignCheck" in t["name"] for t in result.meta["re_toolkit"])
    assert result.meta["anti_frida"] is True


def test_signcheck_all_of_needs_both_strings():
    # ★FP 防回归：只含 IServiceManager(单独常见)不该触发 SignCheck 的 all_of。
    result = _analyze(files={"lib/arm64-v8a/libfoo.so": b"only android.os.IServiceManager here"})
    assert not any("SignCheck" in t["name"] for t in result.meta["re_toolkit"])


def test_injectdetect_renamed_via_misspelled_string():
    # 改名后靠 .so 内特征串(原作拼写错 bean≠been)识别。
    result = _analyze(files={"lib/arm64-v8a/librenamed.so": b".... detect lib has bean hooked ...."})
    assert any("InjectDetect" in t["name"] for t in result.meta["re_toolkit"])
    assert result.meta["anti_frida"] is True


def test_so_with_no_target_strings_not_flagged():
    # 普通 .so 无任何 so_strings 命中 → 不误报 ArtHook/SignCheck/InjectDetect。
    result = _analyze(files={"lib/arm64-v8a/libapp.so": b"hello world some ordinary strings here"})
    flagged = {t["name"] for t in result.meta["re_toolkit"]}
    assert not any(("ArtHook" in n) or ("SignCheck" in n) or ("InjectDetect" in n) for n in flagged)


def test_benign_so_skipped_by_whitelist():
    # 白名单库(libflutter.so)即便含特征串也不扫(排除以省 IO/降 FP)。
    result = _analyze(files={"lib/arm64-v8a/libflutter.so": b"_ZN7arthook9InitializeEv"})
    assert not any("ArtHook" in t["name"] for t in result.meta["re_toolkit"])
