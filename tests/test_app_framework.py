"""应用框架识别：判据本身 + 分析器 + **下游真的读到了**。

分三层，第三层才是重点：判据写对不等于接上了。此前 ``libapp.so`` 的排除是在
``leads.py`` 里就地写死的一份清单，谁都不知道该样本究竟是不是 Flutter；本模块把
「框架是什么」变成一次识别、写进 ``report.meta``、再由 pipeline 传给判据。
"""

from __future__ import annotations

import inspect

import pytest

from apkscan.analyzers.app_framework import AppFrameworkAnalyzer
from apkscan.core import appframework, pipeline
from apkscan.core.appframework import (
    AppFramework,
    detect_framework,
    framework_from_meta,
    is_app_own_code,
)
from apkscan.core.leads import _vendor_sdk_libraries
from apkscan.core.models import Endpoint, Evidence
from apkscan.core.registry import discover_analyzers
from tests.conftest import FakeContext

# ---------------------------------------------------------------------------
# 1. 判据本身
# ---------------------------------------------------------------------------

_FLUTTER = ["lib/arm64-v8a/libflutter.so", "lib/arm64-v8a/libapp.so"]
_UNITY = ["lib/arm64-v8a/libunity.so", "lib/arm64-v8a/libil2cpp.so"]


@pytest.mark.parametrize(("libs", "name", "own"), [
    (_FLUTTER, "flutter", ("libapp.so",)),
    (_UNITY, "unity", ("libil2cpp.so",)),
    # React Native 的业务代码是 assets 里的 JS bundle，不在 .so 里——own 为空是
    # 判据的正确结论，不是漏写。
    (["lib/arm64-v8a/libhermes.so", "lib/arm64-v8a/libfbjni.so"], "react_native", ()),
    # 多 ABI 拷贝折到同一个 basename，不影响结论。
    (["lib/armeabi-v7a/libflutter.so", "lib/arm64-v8a/libflutter.so",
      "lib/armeabi-v7a/libapp.so"], "flutter", ("libapp.so",)),
])
def test_detect_framework_reads_the_engine_and_locates_app_code(
    libs: list[str], name: str, own: tuple[str, ...]
) -> None:
    fw = detect_framework(libs)
    assert fw.identified and fw.name == name
    assert fw.own_code_libs == own
    assert fw.evidence, "判定要留依据，供人工复核追溯"


@pytest.mark.parametrize("libs", [
    [],
    ["lib/arm64-v8a/libnative.so", "lib/arm64-v8a/libc++_shared.so"],
    # ★只有业务代码容器、没有引擎：不下结论。别的东西也可能叫 libapp.so，
    #   凭一个文件名就断定 Flutter 会把无关样本误标。
    ["lib/arm64-v8a/libapp.so"],
])
def test_no_engine_means_unidentified_not_native(libs: list[str]) -> None:
    """识别不出返回「未识别」，**不是**「原生 Android」——两者下游行为不同。"""
    fw = detect_framework(libs)
    assert not fw.identified
    assert fw.name == "" and fw.own_code_libs == ()


def test_coexisting_frameworks_keep_every_business_code_container() -> None:
    """★★接线不得比不接线更窄——那是把降噪做成了降档。

    不给 framework 时判据用全局并集，libapp.so 与 libil2cpp.so **无条件**都算本应用代码。
    识别结果若只带主框架那一个容器，Unity+Flutter 并存的包里落选那个反而失去保护，
    它里面的真后端会被当第三方常量降档——比不做识别还糟。

    ★变异验证：把 detect_framework 里合并 own_code_libs 的分支删掉（退回 matched[0]），
    本测试必红。
    """
    fw = detect_framework(_UNITY + _FLUTTER)
    assert fw.identified
    assert set(fw.own_code_libs) == {"libapp.so", "libil2cpp.so"}, (
        f"并存时丢了容器：{fw.own_code_libs}"
    )
    for lib in ("libapp.so", "libil2cpp.so"):
        assert is_app_own_code(lib, fw) is True, f"{lib} 在并存包里失去了保护"
        # 与宽口径对齐：接线后不得比不接线更严。
        assert is_app_own_code(lib) is True
    assert any("并存" in e for e in fw.evidence), "并存这个事实要留在证据里，供人复核"


def test_single_framework_still_excludes_a_lookalike_third_party_lib() -> None:
    """★放宽并存后，精确口径的价值不能跟着丢。

    Unity 样本里一个真叫 libapp.so 的第三方库——没有 libflutter.so 撑着，就不该被
    当成本应用代码。这正是精确口径存在的理由。
    """
    fw = detect_framework(_UNITY + ["lib/arm64-v8a/libapp.so"])
    assert fw.own_code_libs == ("libil2cpp.so",), f"误收了假容器：{fw.own_code_libs}"
    assert is_app_own_code("libapp.so", fw) is False


def test_facebook_support_libs_alone_do_not_make_it_react_native() -> None:
    """★libfbjni / libjsi 是 Facebook 系 SDK（Fresco、Flipper…）的支撑库，遍地都是。

    拿它们认定 RN，等于把「引擎在场才认定」这条承诺悄悄放掉；而 RN 的 own_code_libs
    是空的，误判之后精确口径只认空集合，libapp.so 反倒失去保护——降噪变降档。

    ★变异验证：把 libfbjni / libjsi 加回 _FRAMEWORKS 的 RN 引擎前缀，本测试必红。
    """
    fw = detect_framework(["lib/arm64-v8a/libfbjni.so", "lib/arm64-v8a/libapp.so"])
    assert not fw.identified, f"仅凭支撑库就认定了 {fw.name!r}"
    fw2 = detect_framework(["lib/arm64-v8a/libjsi.so"])
    assert not fw2.identified
    # 真正的 RN 引擎仍要认得出。
    assert detect_framework(["lib/arm64-v8a/libhermes.so"]).name == "react_native"
    assert detect_framework(["lib/arm64-v8a/libreactnativejni.so"]).name == "react_native"


def test_a_framework_without_own_code_libs_never_strips_protection() -> None:
    """★不变量：给了 framework 不得比不给更严。

    识别结果的 own_code_libs 为空时（RN 天然如此，误判也会落到这个形态），必须退回
    全局并集。否则任何一次框架误判都能把 libapp.so / libil2cpp.so 的保护整个剥掉——
    框架识别是用来放宽判断的，不该成为新的降档来源。

    ★变异验证：去掉 is_app_own_code 里 `and framework.own_code_libs` 这个条件，本测试必红。
    """
    rn = detect_framework(["lib/arm64-v8a/libhermes.so"])
    assert rn.identified and rn.own_code_libs == (), "前提：RN 的业务代码不在 .so 里"
    for lib in ("libapp.so", "libil2cpp.so"):
        assert is_app_own_code(lib, rn) is True, (
            f"{lib} 因为样本被识别成 RN 而失去保护——精确口径比宽口径还严"
        )
        assert is_app_own_code(lib) is True  # 宽口径基准


def test_is_app_own_code_narrows_when_the_framework_is_known() -> None:
    """★精确口径与宽口径的差别就在这里，也是整条接线存在的理由。

    一个真叫 ``libapp.so`` 的第三方库出现在 Unity 样本里：宽口径（不知道框架）会把它
    当成本应用代码而免检，精确口径知道这份样本的业务代码在 ``libil2cpp.so``，于是照常
    按第三方处理。
    """
    unity = detect_framework(_UNITY)
    assert is_app_own_code("libapp.so") is True, "宽口径：并集里有就算"
    assert is_app_own_code("libapp.so", unity) is False, "精确口径：Unity 的业务代码不在这"
    assert is_app_own_code("libil2cpp.so", unity) is True


@pytest.mark.parametrize("meta", [
    None, {}, "flutter", [], {"identified": True},
    {"identified": True, "name": ""},
    {"identified": False, "name": "flutter", "own_code_libs": ["libapp.so"]},
    {"identified": True, "name": "flutter", "own_code_libs": "libapp.so"},
    {"identified": True, "name": "flutter", "own_code_libs": [None, 3]},
])
def test_framework_from_meta_never_raises_on_bad_shapes(meta: object) -> None:
    """畸形/缺失的 meta 一律降到「未识别」，不抛——上游形状问题不该毁掉整次分析。"""
    fw = framework_from_meta(meta)
    assert isinstance(fw, AppFramework)
    assert not fw.own_code_libs or all(isinstance(x, str) for x in fw.own_code_libs)


def test_framework_from_meta_round_trips_the_analyzer_output() -> None:
    """分析器写出去的结构，消费方要能原样读回来（往返闭合）。"""
    written = AppFrameworkAnalyzer().analyze(
        FakeContext(native_libs=_FLUTTER)
    ).meta[appframework.META_KEY]
    fw = framework_from_meta(written)
    assert fw.identified and fw.name == "flutter"
    assert fw.own_code_libs == ("libapp.so",)


# ---------------------------------------------------------------------------
# 2. 分析器
# ---------------------------------------------------------------------------


def test_analyzer_is_discovered_by_the_registry() -> None:
    """自动发现要真的发现它——只写了类没被注册，等于没做。"""
    assert "app_framework" in {a.name for a in discover_analyzers()}


def test_analyzer_writes_a_complete_structure_even_when_the_source_fails() -> None:
    """★失败安全：取不到库清单也要留完整结构。

    留半个结构或干脆不写，下游 ``framework_from_meta`` 读到的同样是「未识别」，但
    报告里就分不清「跑过、没框架」和「压根没跑」——证据边界要能自证。
    """
    class _Boom(FakeContext):
        def native_libs(self):  # type: ignore[override]
            raise OSError("apk 读坏了")

    meta = AppFrameworkAnalyzer().analyze(_Boom()).meta[appframework.META_KEY]
    assert meta == {
        "identified": False, "name": "", "own_code_libs": [],
        "runtime_libs": [], "evidence": [],
    }


def test_analyzer_produces_no_leads_or_findings() -> None:
    """框架是背景事实：既不是可发函的线索，也不是缺陷。"""
    result = AppFrameworkAnalyzer().analyze(FakeContext(native_libs=_FLUTTER))
    assert result.leads == [] and result.findings == []


# ---------------------------------------------------------------------------
# 3. ★接线：pipeline 真的把识别结果交给了判据
# ---------------------------------------------------------------------------

#: 已知第三方基础设施域名——凑够两个才会把一个库认成「厂商 SDK 的二进制」。
#: 两个都必须真在 ``infra.is_known_infra`` 名单里：少一个就够不上门槛，判据整条不触发，
#: 测试会以「两种口径结果一样」的形式假绿。
_INFRA_DOMAINS = ("gslb.dingrtc.com", "portal-hz.mcs.dingtalk.com")  # leak-scan: allow 判据夹具：须真在 KNOWN_INFRA 名单内才够得上门槛，占位域名判据整条不触发
#: 与上述域名同处一个 .so 的公网地址。要全球可路由字面，否则判据在更早一道就落 SKIP。
_BACKEND_IP = "8.210.13.60"  # leak-scan: allow 判据夹具：与第三方域名同库的地址，测的正是它的降档与否
_THIRD_PARTY_LIB = "lib/arm64-v8a/libapp.so"


def _ep(kind: str, value: str, lib: str) -> Endpoint:
    return Endpoint(kind=kind, value=value,
                    evidences=[Evidence(source="native", location=lib, snippet=value)])


def _unity_sample_with_a_lib_named_libapp() -> tuple[list[Endpoint], dict]:
    """Unity 样本，外加一个真叫 ``libapp.so`` 的第三方库。

    这是精确口径与宽口径唯一会给出不同答案的形态，接线是否通就靠它区分。
    """
    eps = [_ep("domain", d, _THIRD_PARTY_LIB) for d in _INFRA_DOMAINS]
    eps.append(_ep("ip", _BACKEND_IP, _THIRD_PARTY_LIB))
    meta = AppFrameworkAnalyzer().analyze(
        FakeContext(native_libs=_UNITY + [_THIRD_PARTY_LIB])
    ).meta
    return eps, meta


def test_pipeline_passes_the_framework_into_the_lead_criteria() -> None:
    """★接线锁：走 ``_stage_build_leads`` 这个真入口，不打内部函数。

    ★变异验证：把 ``_stage_build_leads`` 里的 ``framework=framework`` 去掉（判据退回
    宽口径），本测试必红——那正是「识别做了、下游没读」的形态。
    """
    eps, meta = _unity_sample_with_a_lib_named_libapp()
    fw = framework_from_meta(meta[appframework.META_KEY])
    # ★两条前置断言，防的是「判据压根没触发」式假绿：夹具的域名若有一个不在
    #   is_known_infra 名单里就够不上 ≥2 的门槛，两种口径都不降档，测试照样"通过"。
    #   实测踩过一次，就是被这两条挡下的。
    assert fw.name == "unity", "前置：夹具确实被认成 Unity"
    assert _THIRD_PARTY_LIB.rsplit("/", 1)[-1] in _vendor_sdk_libraries(eps, framework=fw), (
        "前置：精确口径下 libapp.so 必须被认成厂商 SDK 库，否则判据没被触发"
    )

    state = pipeline._PipelineState(
        ctx=None, config=pipeline.AnalysisConfig(online=False),  # type: ignore[arg-type]
        platform="linux", capabilities=set(), meta=meta, endpoints=eps,
    )
    pipeline._stage_build_leads(state)

    lead = next(x for x in state.leads if x.value == _BACKEND_IP)
    assert lead.advice == "待核", (
        f"libapp.so 在 Unity 样本里是第三方库，其中的 {_BACKEND_IP} 不该按本应用后端处理"
        f"（advice={lead.advice!r}）——framework 没从 meta 传到判据"
    )


def test_framework_stage_runs_before_leads_are_built() -> None:
    """★阶段顺序锁：识别必须在判据消费之前跑完，否则 meta 里还没有结果。

    分析器阶段与 build_leads 都在 ``run()`` 里按序调用，顺序调换不会报错，只会让
    ``framework_from_meta`` 读到空——静默退回宽口径，跟没接一样。
    """
    src = inspect.getsource(pipeline.run)
    assert src.index("_stage_run_analyzers") < src.index("_stage_build_leads")


def test_meta_key_has_one_definition() -> None:
    """分析器与消费方必须共用同一个键名，各写各的迟早对不上。"""
    import apkscan.analyzers.app_framework as analyzer_mod

    assert analyzer_mod.META_KEY is appframework.META_KEY
