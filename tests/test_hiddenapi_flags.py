"""androguard 的 hidden-api flag 校验放宽：别让第三方库的建模错误把整个 DEX 拒在门外。

实测：四次脱壳各抓到 33 个 DEX，只有 10 个载入，23 个卡在
``HiddenApiClassDataItem.DomapiApiFlag`` 的 ``ValueError``——静态可见性凭空少了约七成，
而报告里只有一行 warning。

根因是 androguard 4.1.4 的建模错误，不是 DEX 坏了：AOSP 的 hiddenapi flag 低三位是访问
限制档（0-6），**高位是可叠加的位掩码**（core-platform-api、test-api，新版本还在加），
androguard 却把高位建成了互斥 IntEnum（只有 0/1/2），于是 3/4/6 这些合法组合一律报错。

放行是安全的：本工具从不读这些 flag（要的是字符串/类/方法），且 DEX 各 map 段按各自偏移
独立解析。但容错生效过要如实登记——"载进来了"不等于"本来就没问题"。
"""

from __future__ import annotations

import pytest

from apkscan.core import apk as apk_mod


@pytest.fixture(autouse=True)
def _relaxed():
    """垫子是进程级幂等的；每个用例前确保已应用。"""
    apk_mod._relax_hiddenapi_flags()


def _flags():
    from androguard.core.dex import HiddenApiClassDataItem

    return HiddenApiClassDataItem.RestrictionApiFlag, HiddenApiClassDataItem.DomapiApiFlag


@pytest.mark.parametrize("value", [3, 4, 6, 7, 255])
def test_unknown_domain_api_flag_no_longer_rejects_the_dex(value: int) -> None:
    """★核心：库不认识的取值不再抛 ValueError —— 那个异常会让整个 DEX 拒载。"""
    _restriction, domapi = _flags()
    got = domapi(value)
    assert int(got) == value, "原值必须保留，不能塌缩成某个已知档位"
    assert "UNKNOWN" in got.name, "名字要写明是未知档位，不冒充已知语义"


@pytest.mark.parametrize("value", [7, 8, 31])
def test_unknown_restriction_flag_is_tolerated_too(value: int) -> None:
    """限制档同理：新 Android 版本加档位时不该让分析整批失败。"""
    restriction, _domapi = _flags()
    assert int(restriction(value)) == value


def test_known_values_are_untouched() -> None:
    """★反向护栏：已知取值仍解析成原枚举成员，语义不得被垫子改掉。"""
    restriction, domapi = _flags()
    assert domapi(0) is domapi.NONE
    assert domapi(1) is domapi.CORE_PLATFORM_API
    assert domapi(2) is domapi.TEST_API
    assert restriction(0) is restriction.WHITELIST
    assert restriction(6) is restriction.GREYLIST_MAX_R


@pytest.mark.parametrize("bad", [-1, "x", None, 1.5, [4], b"\x04"])
def test_garbage_still_rejected(bad: object) -> None:
    """★放宽的是"库还不认识的合法档位"，不是"什么都收"。

    负数/非整数仍须抛——把坏输入也放行，等于把解析错误伪装成正常数据。
    """
    _restriction, domapi = _flags()
    with pytest.raises(ValueError):
        domapi(bad)


def test_load_extra_dex_applies_the_shim() -> None:
    """★接线锁：垫子必须由 ``_load_extra_dex`` 自己装上。

    别的用例（含本文件的 autouse fixture）都直接调 ``_relax_hiddenapi_flags``，那验证的是
    垫子本身好不好使，验证不了"真实加载路径有没有用它"——而 23/33 拒载正是发生在那条路径上。
    """
    apk_mod._HIDDENAPI_FLAGS_RELAXED = False
    try:
        apk_mod._load_extra_dex([])  # 空列表：不读任何文件，只看有没有装垫子
        assert apk_mod._HIDDENAPI_FLAGS_RELAXED is True, "加载路径没装容错垫，成批拒载会照旧发生"
    finally:
        apk_mod._relax_hiddenapi_flags()


def test_relax_is_idempotent() -> None:
    """幂等：重复调用不叠加、不重置已记录的取值。"""
    apk_mod._relax_hiddenapi_flags()
    apk_mod._relax_hiddenapi_flags()
    assert apk_mod.hiddenapi_relax_report()["applied"] is True


def test_relax_report_records_which_values_were_waved_through() -> None:
    """★容错生效过要留痕：不写下来，"载入 33/33"看着像一次干净的解析。"""
    _restriction, domapi = _flags()
    domapi(4)
    report = apk_mod.hiddenapi_relax_report()
    assert report["applied"] is True
    assert "DomapiApiFlag=4" in list(report["unknown_flags"])  # type: ignore[call-overload]


def test_pipeline_records_the_relaxation_in_meta() -> None:
    """★接线锁：报告里要看得出这些 DEX 是靠放宽第三方校验才载进来的。

    退回 pipeline 里那几行，报告只剩「载入 33/33」——看着像一次干净的解析。
    """
    from types import SimpleNamespace

    from apkscan.core import pipeline
    from apkscan.core.models import AnalysisConfig

    _restriction, domapi = _flags()
    domapi(6)  # 让本进程确有放行记录

    state = pipeline._PipelineState(
        ctx=SimpleNamespace(  # type: ignore[arg-type]  # 本 stage 只 getattr 这几项
            dex_available=True,
            apk_validation_ok=True,
            extra_dex_report={"requested": 33, "loaded": 33, "failed": 0},
        ),
        config=AnalysisConfig(online=False),
        platform="android",
        capabilities=set(),
    )
    pipeline._stage_degradation_flags(state)

    block = state.meta["extra_dex_visibility"]
    assert block["loaded"] == 33
    assert block["hiddenapi_flags_relaxed"]["applied"] is True
    flags = block["hiddenapi_flags_relaxed"]["unknown_flags"]
    assert any("DomapiApiFlag" in str(f) for f in flags), flags
