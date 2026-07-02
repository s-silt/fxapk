"""apkscan.dynamic.capture_plan 的单测。

capture_plan 读静态 report.json 的规避信号（加固/endpoint数/加密配方/自建IM），按"探针之外的
抓包方法目录"的决策树，输出**针对该样本的抓包打法**（起手式带外 pcap → 按规避类型选方法）。
纯逻辑、绝不抛。
"""

from __future__ import annotations

import pytest

from apkscan.dynamic import capture_plan


def _joined(steps: list[str]) -> str:
    return "\n".join(steps)


def test_directives_first_then_pcap_baseline() -> None:
    """第一条恒为铁律（时间盒 / fail-fast / 停止门），第二条恒为带外 pcap 保底起手式。"""
    steps = capture_plan.plan_capture({})
    assert len(steps) >= 2
    assert "铁律" in steps[0]
    assert "pcap" in steps[1].lower() or "PCAPdroid" in steps[1]
    assert "pcap-leads" in _joined(steps)


def test_packed_recommends_unpack_and_anti_detect() -> None:
    report = {"findings": [{"id": "PACK-DETECTED", "category": "packing", "title": "已加固"}]}
    steps = capture_plan.plan_capture(report)
    text = _joined(steps)
    assert "加固" in text or "脱壳" in text
    assert "anti-detection" in text or "反检测" in text


def test_packer_lead_also_counts_as_packed() -> None:
    report = {"leads": [{"category": "PACKER", "value": "梆梆"}]}
    steps = capture_plan.plan_capture(report)
    assert "脱壳" in _joined(steps) or "加固" in _joined(steps)


def test_zero_endpoints_flags_native_protocol() -> None:
    report = {"endpoints": []}
    text = _joined(capture_plan.plan_capture(report))
    assert "endpoint" in text.lower()
    assert "native" in text.lower() or "自建协议" in text or "MTProto" in text


def test_with_endpoints_no_zero_endpoint_step() -> None:
    report = {"endpoints": [{"value": "api.x.com", "kind": "domain"}]}
    text = _joined(capture_plan.plan_capture(report))
    assert "endpoint=0" not in text


def test_crypto_recipe_recommends_offline_decrypt() -> None:
    report = {"meta": {"crypto_recipe": {"algo": "AES", "key": "..."}}}
    text = _joined(capture_plan.plan_capture(report))
    assert "解密" in text and ("配方" in text or "cipher" in text)


def test_self_hosted_im_recommends_telegram_line() -> None:
    report = {"leads": [{"category": "SELF_HOSTED_IM", "value": "mtproto 106.53.21.146:30113"}]}
    text = _joined(capture_plan.plan_capture(report))
    assert "telegram-mtproto" in text or "netstat" in text


def test_never_throws_on_bad_input() -> None:
    for bad in (None, "garbage", [], 123, {"leads": "notalist"}):
        steps = capture_plan.plan_capture(bad)  # type: ignore[arg-type]
        assert isinstance(steps, list) and steps  # 至少有铁律 + 起手式


def test_directives_encode_timebox_and_failfast() -> None:
    """铁律必须含 floor 优先、时间盒、frida fail-fast、停止门——治"几小时零产出"的约束。"""
    text = _joined(capture_plan.plan_capture({}))
    assert "floor" in text.lower() or "保底" in text
    assert "时间盒" in text or "≤" in text  # 时间盒
    assert "秒退" in text and ("弃" in text or "别死磕" in text or "fail-fast" in text)  # fail-fast
    assert "停止门" in text


def test_floor_baseline_has_stop_gate() -> None:
    """带外 pcap 起手式必须给"拿到接入节点=已有产出"的停止门，保证不会零产出。"""
    text = _joined(capture_plan.plan_capture({}))
    assert "接入节点" in text
    assert "停止门" in text


def test_recipe_is_zero_inject_priority() -> None:
    """命中加密配方时，离线解密应标为零注入、优先于注入（绕开反 frida 的明文首选）。"""
    report = {"meta": {"crypto_recipe": {"algo": "AES", "key": "..."}}}
    text = _joined(capture_plan.plan_capture(report))
    assert "零注入" in text or "优先于" in text


# ===== decide_capture：结构化决策（供抓包引擎消费，与 plan_capture 文本同源）=====


def test_decide_floor_first_and_budget_always() -> None:
    """任何样本：floor 优先恒为真、总预算=铁律 60min（治零产出的硬约束落到结构化字段）。"""
    d = capture_plan.decide_capture({})
    assert d.floor_first is True
    assert d.total_budget_sec == 3600


def test_decide_never_raises_on_bad_input() -> None:
    """坏输入也返回可用决策（绝不抛），且仍给 floor 保底。"""
    for bad in (None, "garbage", [], 123, {"leads": "notalist"}):
        d = capture_plan.decide_capture(bad)  # type: ignore[arg-type]
        assert d.floor_first is True


def test_decide_recipe_prefers_offline_decrypt() -> None:
    """有加密配方：离线解密优先、可跳过 frida 明文注入。"""
    d = capture_plan.decide_capture({"meta": {"crypto_recipe": {"algo": "AES", "key": "x"}}})
    assert d.prefer_offline_decrypt is True
    assert d.skip_frida_plaintext is True
    assert d.signals["has_crypto_recipe"] is True


def test_decide_no_recipe_does_not_skip_frida() -> None:
    """无配方、有端点：不跳过 frida 明文（仍走注入路径）。"""
    d = capture_plan.decide_capture({"endpoints": [{"value": "a.com", "kind": "domain"}]})
    assert d.prefer_offline_decrypt is False
    assert d.skip_frida_plaintext is False
    assert d.expect_native_protocol is False


def test_decide_zero_endpoints_expects_native() -> None:
    """endpoint=0：预判 native 直发/自建协议，明文难抓、更要靠 floor。"""
    d = capture_plan.decide_capture({"endpoints": []})
    assert d.expect_native_protocol is True
    assert d.signals["zero_endpoints"] is True


def test_decide_self_hosted_im_expects_native() -> None:
    d = capture_plan.decide_capture(
        {"leads": [{"category": "SELF_HOSTED_IM", "value": "mtproto 1.2.3.4:30113"}]}
    )
    assert d.expect_native_protocol is True


def test_decide_packed_lowers_retreat_threshold() -> None:
    """加固样本反检测秒退风险高 → 秒退熔断阈值更低（更早弃明文退 floor）。"""
    packed = capture_plan.decide_capture(
        {"findings": [{"id": "PACK-DETECTED", "category": "packing"}]}
    )
    normal = capture_plan.decide_capture({"endpoints": [{"value": "a.com"}]})
    assert packed.frida_retreat_threshold == 2
    assert normal.frida_retreat_threshold == 3
    assert packed.signals["packed"] is True


def test_decide_reasons_are_human_readable() -> None:
    d = capture_plan.decide_capture({"meta": {"crypto_recipe": {"algo": "AES"}}})
    assert d.reasons
    assert any(("配方" in r) or ("离线" in r) for r in d.reasons)


@pytest.mark.parametrize(
    ("report", "decide_check", "text_needles"),
    [
        # recipe：决策标离线解密优先，文本含『离线/解密』
        (
            {"meta": {"crypto_recipe": {"algo": "AES", "key": "x"}}},
            lambda d: d.prefer_offline_decrypt is True,
            ("离线", "解密"),
        ),
        # zero_ep：决策预判 native，文本含『endpoint=0』
        ({"endpoints": []}, lambda d: d.expect_native_protocol is True, ("endpoint=0",)),
        # self_hosted_im：决策预判 native，文本含专项探针
        (
            {"leads": [{"category": "SELF_HOSTED_IM", "value": "mtproto 1.2.3.4:30113"}]},
            lambda d: d.expect_native_protocol is True,
            ("telegram-mtproto", "netstat"),
        ),
        # packed：决策阈值降 2 / signals.packed，文本含『加固/脱壳』
        (
            {"findings": [{"id": "PACK-DETECTED", "category": "packing"}]},
            lambda d: d.signals["packed"] is True and d.frida_retreat_threshold == 2,
            ("加固", "脱壳"),
        ),
    ],
)
def test_plan_and_decide_same_source_all_signals(report, decide_check, text_needles) -> None:
    """文本打法与结构化决策**同源**：四个信号逐个验证——任一侧单边改动/漂移都应让本测试红。"""
    d = capture_plan.decide_capture(report)
    assert decide_check(d)  # 决策侧
    text = _joined(capture_plan.plan_capture(report))
    assert any(n in text for n in text_needles)  # 文本侧含对应分支标志词


def test_decide_runtime_crypto_recipe_alias() -> None:
    """runtime_crypto_recipe（动态 merge 侧真实写入的实测配方 key）与 crypto_recipe 同权。"""
    d = capture_plan.decide_capture({"meta": {"runtime_crypto_recipe": {"algo": "AES", "key": "x"}}})
    assert d.prefer_offline_decrypt is True
    assert d.skip_frida_plaintext is True
    assert d.signals["has_crypto_recipe"] is True
    text = _joined(capture_plan.plan_capture({"meta": {"runtime_crypto_recipe": {"algo": "AES"}}}))
    assert "离线" in text and "解密" in text


def test_decide_baseline_default_shape() -> None:
    """有端点、无其它信号 → 全默认：不跳 frida、非 native、秒退阈值 3。"""
    d = capture_plan.decide_capture({"endpoints": [{"value": "a.com", "kind": "domain"}]})
    assert d.prefer_offline_decrypt is False
    assert d.skip_frida_plaintext is False
    assert d.expect_native_protocol is False
    assert d.frida_retreat_threshold == 3


def test_decide_empty_report_expects_native() -> None:
    """空报告=无端点 → 有意预判 native（记录这一略反直觉但正确的行为）。"""
    assert capture_plan.decide_capture({}).expect_native_protocol is True


def test_decide_packed_and_recipe_combo() -> None:
    """加固 + 已抠配方（取证现场常见组合）：阈值降 2、跳 frida 明文、依据含两类。"""
    d = capture_plan.decide_capture(
        {"findings": [{"id": "PACK-DETECTED"}], "meta": {"crypto_recipe": {"algo": "AES"}}}
    )
    assert d.frida_retreat_threshold == 2
    assert d.skip_frida_plaintext is True
    joined = " ".join(d.reasons)
    assert ("加固" in joined or "秒退" in joined) and ("配方" in joined or "离线" in joined)
