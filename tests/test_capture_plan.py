"""apkscan.dynamic.capture_plan 的单测。

capture_plan 读静态 report.json 的规避信号（加固/endpoint数/加密配方/自建IM），按"探针之外的
抓包方法目录"的决策树，输出**针对该样本的抓包打法**（起手式带外 pcap → 按规避类型选方法）。
纯逻辑、绝不抛。
"""

from __future__ import annotations

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
