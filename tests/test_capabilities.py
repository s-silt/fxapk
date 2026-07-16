"""抓包能力矩阵（dynamic/capabilities）纯逻辑测试。

★核心纪律测试点：floor 底座就绪即 ready（缺 frida/mitm 只降级不失败）；both 缺 mitm 增强 → 等效
floor-only 仍抓 pcap；明文阶梯强→弱降级；floor 底座也缺 → 无法抓包；未知模式回退不抛。
"""

from __future__ import annotations

from apkscan.dynamic import capabilities as C

_FLOOR = {C.CAP_ADB, C.CAP_DEVICE, C.CAP_DEVICE_TCPDUMP, C.CAP_ROOT_CAPTURE}


def test_floor_only_ready_with_floor_caps() -> None:
    p = C.resolve("floor-only", _FLOOR)
    assert p.ready and p.missing == frozenset() and p.degraded_to is None
    assert p.mode == "floor-only"


def test_floor_only_missing_tcpdump_not_ready_no_degrade() -> None:
    """floor-only 缺设备 tcpdump → 不 ready，且退无可退（它已是最低公共底座）。"""
    p = C.resolve("floor-only", {C.CAP_ADB, C.CAP_DEVICE, C.CAP_ROOT_CAPTURE})
    assert not p.ready and C.CAP_DEVICE_TCPDUMP in p.missing and p.degraded_to is None


def test_both_full_ready_mitm_is_strongest_plaintext() -> None:
    p = C.resolve("both", _FLOOR | {C.CAP_MITMPROXY, C.CAP_CA_TRUSTED})
    assert p.ready and p.degraded_to is None
    assert p.plaintext_best == "mitm"


def test_both_without_mitm_degrades_to_floor_only_still_ready() -> None:
    """★核心：both 缺 mitm/CA 增强 → 仍 ready（floor 底座在）、标 degraded_to floor-only、无明文层。"""
    p = C.resolve("both", _FLOOR)
    assert p.ready and p.degraded_to == "floor-only"
    assert p.plaintext_best is None  # 无 mitm/frida → 阶梯无可达层，只有 floor 接入节点


def test_mitm_only_missing_mitmproxy_degrades_to_floor() -> None:
    """mitm-only 缺 mitmproxy 但 floor 底座在 → 不 ready、可降级 floor-only（不判整体失败）。"""
    p = C.resolve("mitm-only", _FLOOR)
    assert not p.ready and C.CAP_MITMPROXY in p.missing and p.degraded_to == "floor-only"


def test_plaintext_ladder_strong_to_weak() -> None:
    full = _FLOOR | {C.CAP_MITMPROXY, C.CAP_CA_TRUSTED, C.CAP_FRIDA, C.CAP_TSHARK}
    assert C.resolve("floor-only", full).plaintext_reachable == (
        "mitm", "tls_keylog", "ssl_hook", "cipher_hook")
    assert C.resolve("floor-only", _FLOOR | {C.CAP_FRIDA, C.CAP_TSHARK}).plaintext_best == "tls_keylog"
    assert C.resolve("floor-only", _FLOOR | {C.CAP_FRIDA}).plaintext_best == "ssl_hook"
    assert C.resolve("floor-only", _FLOOR).plaintext_best is None
    # mitm 需 CA 受信：只有 mitmproxy 没 CA → mitm 层不可达
    assert "mitm" not in C.resolve("floor-only", _FLOOR | {C.CAP_MITMPROXY}).plaintext_reachable


def test_no_floor_caps_cannot_capture() -> None:
    """只有 adb、无设备/tcpdump/root → 无法抓包（ready=False，退无可退）。"""
    p = C.resolve("floor-only", {C.CAP_ADB})
    assert not p.ready and p.degraded_to is None
    assert {C.CAP_DEVICE, C.CAP_DEVICE_TCPDUMP, C.CAP_ROOT_CAPTURE} <= p.missing


def test_unknown_mode_falls_back_floor_only_no_raise() -> None:
    p = C.resolve("weird-mode", _FLOOR)
    assert p.mode == "floor-only" and p.ready


def test_plan_fields_and_notes_present() -> None:
    p = C.resolve("both", _FLOOR | {C.CAP_MITMPROXY, C.CAP_CA_TRUSTED})
    assert p.required == C.MODE_FLOOR_CAPS["both"]
    assert p.available >= frozenset(_FLOOR)
    assert isinstance(p.notes, tuple) and p.notes  # 有人读决策依据
