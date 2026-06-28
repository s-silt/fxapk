"""apkscan.dynamic.capture_plan 的单测。

capture_plan 读静态 report.json 的规避信号（加固/endpoint数/加密配方/自建IM），按"探针之外的
抓包方法目录"的决策树，输出**针对该样本的抓包打法**（起手式带外 pcap → 按规避类型选方法）。
纯逻辑、绝不抛。
"""

from __future__ import annotations

from apkscan.dynamic import capture_plan


def _joined(steps: list[str]) -> str:
    return "\n".join(steps)


def test_always_includes_pcap_baseline() -> None:
    """任何样本第一条都是带外 pcap 保底起手式。"""
    steps = capture_plan.plan_capture({})
    assert steps
    assert "pcap" in steps[0].lower() or "PCAPdroid" in steps[0]
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
        assert isinstance(steps, list) and steps  # 至少有起手式
