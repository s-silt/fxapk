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


# ---------------------------------------------------------------------------
# D-2：放行账目必须按样本隔离（batch 单进程顺序跑，账会串到下一份报告）
# ---------------------------------------------------------------------------


def _degradation_meta(baseline: int | None) -> dict:
    """跑一遍 _stage_degradation_flags，返回 meta（baseline 模拟 load_apk 钉下的快照）。"""
    from types import SimpleNamespace

    from apkscan.core import pipeline
    from apkscan.core.models import AnalysisConfig

    state = pipeline._PipelineState(
        ctx=SimpleNamespace(  # type: ignore[arg-type]  # 本 stage 只 getattr 这几项
            dex_available=True,
            apk_validation_ok=True,
            extra_dex_report={"requested": 5, "loaded": 5, "failed": 0},
            hiddenapi_flags_baseline=baseline,
        ),
        config=AnalysisConfig(online=False),
        platform="android",
        capabilities=set(),
    )
    pipeline._stage_degradation_flags(state)
    return state.meta


def test_second_sample_report_excludes_flags_waved_through_for_the_first() -> None:
    """★D-2：顺序分析两个样本，样本 B 的报告不得含只属于样本 A 的放行 flag。

    放行记录攒在进程级集合里，而 batch（``dynamic/batch.py``）是**单进程顺序**跑整个文件夹。
    不按样本减基线，B 的报告就会挂上 A 放行的取值——一份干净样本凭空多出"靠放宽第三方校验
    才载进来"的账。串案时这是**伪造的共同特征**：两份报告出现同一组 unknown_flags，看着像
    同一条加固工具链的指纹，实际只是它们在同一次 batch 里被先后分析过。
    """
    _restriction, domapi = _flags()

    # —— 样本 A：load_apk 钉基线 → 解析中放行 41 → 出报告
    baseline_a = apk_mod.hiddenapi_flags_snapshot()
    domapi(41)
    meta_a = _degradation_meta(baseline_a)
    flags_a = meta_a["extra_dex_visibility"]["hiddenapi_flags_relaxed"]["unknown_flags"]
    assert "DomapiApiFlag=41" in flags_a, "样本 A 自己的放行没记上，隔离过头了"

    # —— 样本 B：紧随其后，本样本一个都没放行
    baseline_b = apk_mod.hiddenapi_flags_snapshot()
    meta_b = _degradation_meta(baseline_b)
    # B 无自己的账 → 整个 hiddenapi_flags_relaxed 块都不该出现（写入前判 unknown_flags 非空）
    assert "hiddenapi_flags_relaxed" not in meta_b["extra_dex_visibility"], (
        "样本 B 没放行任何取值，却被挂上了容错账——A 的账串过来了"
    )

    # —— 样本 C：自己放行 42，只能看到 42，看不到 A 的 41
    baseline_c = apk_mod.hiddenapi_flags_snapshot()
    domapi(42)
    meta_c = _degradation_meta(baseline_c)
    flags_c = meta_c["extra_dex_visibility"]["hiddenapi_flags_relaxed"]["unknown_flags"]
    assert "DomapiApiFlag=42" in flags_c
    assert "DomapiApiFlag=41" not in flags_c, "样本 A 的放行取值漏进了样本 C 的报告"


def test_applied_stays_process_wide_and_the_shim_is_never_rolled_back() -> None:
    """★反向护栏：隔离的只是「本样本放行了哪些」，**不是**垫子本身。

    垫子是进程级、幂等、一次性的 monkeypatch。若按样本重置 ``_HIDDENAPI_FLAGS_RELAXED``
    并撤回 ``_missing_``，后面的样本会重新成批拒载（实测 23/33），这正是它当初要治的病。
    所以 ``applied`` 如实保持进程级事实；判读"这份报告要不要提容错"看 ``unknown_flags``。
    """
    _restriction, domapi = _flags()
    baseline = apk_mod.hiddenapi_flags_snapshot()
    meta = _degradation_meta(baseline)  # 本样本零放行

    assert "hiddenapi_flags_relaxed" not in meta["extra_dex_visibility"]
    # 垫子仍在：新的未知取值照样被放行，而不是抛 ValueError
    assert int(domapi(43)) == 43, "垫子被回退了——后续样本会重新成批拒载"
    assert apk_mod.hiddenapi_relax_report(baseline)["applied"] is True


def test_snapshot_is_a_frozen_copy_not_a_live_view() -> None:
    """事件游标是不可变整数；后续放行不会移动已取得的基线。"""
    _restriction, domapi = _flags()
    snap = apk_mod.hiddenapi_flags_snapshot()
    domapi(44)
    assert "DomapiApiFlag=44" in apk_mod.hiddenapi_relax_report(snap)["unknown_flags"]  # type: ignore[operator]


def test_same_unknown_flag_in_later_sample_is_still_reported() -> None:
    """样本 B 与 A 使用相同 flag 也必须记在 B 名下；set 差会把它错误消掉。"""
    _restriction, domapi = _flags()
    domapi(47)  # 样本 A
    baseline_b = apk_mod.hiddenapi_flags_snapshot()
    domapi(47)  # 样本 B 使用相同取值

    flags_b = apk_mod.hiddenapi_relax_report(baseline_b)["unknown_flags"]
    assert "DomapiApiFlag=47" in flags_b


def test_relax_report_without_baseline_keeps_the_old_whole_process_semantics() -> None:
    """不传 since → 报进程级全量（旧行为）。手搓 ctx / 老调用点不因缺属性而失效或抛。"""
    _restriction, domapi = _flags()
    domapi(45)
    assert "DomapiApiFlag=45" in apk_mod.hiddenapi_relax_report()["unknown_flags"]  # type: ignore[operator]


def test_load_apk_pins_a_baseline_onto_the_context() -> None:
    """★接线锁：基线必须由 ``load_apk`` 自己钉在 ctx 上。

    只在 pipeline 侧减基线是不够的——没人钉，``getattr`` 恒取到 None，退化回串账。
    这里直接检查构造器契约（真解析 APK 属集成测试范畴，另有样本用例覆盖）。
    """
    import inspect

    src = inspect.getsource(apk_mod.load_apk)
    assert "hiddenapi_flags_snapshot()" in src, "load_apk 没钉基线，隔离形同虚设"
    # 必须在解析 DEX（放行发生地）**之前**钉，否则本样本自己的放行会被算进基线而消失
    assert src.index("hiddenapi_flags_snapshot()") < src.index("_load_extra_dex("), (
        "基线钉晚了：本样本自己放行的取值会被当成前账减掉"
    )
    ctx_sig = inspect.signature(apk_mod.ApkContext.__init__)
    assert "hiddenapi_flags_baseline" in ctx_sig.parameters
