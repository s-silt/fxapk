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


def test_no_proxy_mode_kept_and_allows_frida_plaintext() -> None:
    """★no-proxy 单列（不回退 floor-only 标签）：底座同 floor-only，但允许 frida → 明文可达 frida 层。

    否则能力计划 mode='floor-only' 却记录 frida 明文层，自相矛盾（Fable 对抗复审低危项）。
    """
    p = C.resolve("no-proxy", _FLOOR | {C.CAP_FRIDA})
    assert p.mode == "no-proxy" and p.ready and p.degraded_to is None
    assert p.plaintext_best == "ssl_hook"  # frida 在 → SSL hook 明文层可达（no-proxy 用 frida）
    # 对照：floor-only 按定义不注入 frida，即便 frida 在，其能力计划语义仍是"只有 floor 接入节点"——
    # 但阶梯计算是能力驱动、mode 无关，故此处仅验证 no-proxy 的 mode 标签不再被吞成 floor-only。


def test_plan_fields_and_notes_present() -> None:
    p = C.resolve("both", _FLOOR | {C.CAP_MITMPROXY, C.CAP_CA_TRUSTED})
    assert p.required == C.MODE_FLOOR_CAPS["both"]
    assert p.available >= frozenset(_FLOOR)
    assert isinstance(p.notes, tuple) and p.notes  # 有人读决策依据


def test_missing_floor_base_but_has_mitm_degrades_to_mitm_only() -> None:
    """★缺设备 tcpdump/root（floor 跑不了）但有 mitm+CA → 退 mitm-only（纯代理明文、无 pcap），
    不该误判"无法抓包"。"""
    p = C.resolve("both", {C.CAP_ADB, C.CAP_DEVICE, C.CAP_MITMPROXY, C.CAP_CA_TRUSTED})
    assert not p.ready and p.degraded_to == "mitm-only"
    assert p.plaintext_best == "mitm"  # 代理明文可达


def test_both_with_mitmproxy_but_no_ca_is_effective_floor_only() -> None:
    """★both 有 mitmproxy 但无 CA → mitm 明文实际拿不到（缺 CA）→ 判等效 floor-only，不偏乐观当完整 both。"""
    p = C.resolve("both", _FLOOR | {C.CAP_MITMPROXY})
    assert p.ready and p.degraded_to == "floor-only"  # floor 底座在但 mitm 增强不全
    assert p.plaintext_best is None  # 缺 CA → mitm 层不可达


# ---- A1-3：plan_as_dict 序列化（写进 runtime_report.json / report.meta.capture_capabilities）----


def test_plan_as_dict_json_serializable_floor_only() -> None:
    """plan_as_dict：frozenset→稳定排序 list、字段稳定、JSON 可序列化；floor-only 无明文层。"""
    import json

    d = C.plan_as_dict(C.resolve("floor-only", _FLOOR))
    json.dumps(d)  # 必须 JSON 可序列化（不抛）
    assert d["mode"] == "floor-only" and d["ready"] is True
    assert d["required"] == sorted(["adb", "device", "device_tcpdump", "root_capture"])
    assert d["available"] == d["required"] and d["missing"] == []
    assert d["degraded_to"] is None and d["plaintext_best"] is None
    assert d["plaintext_reachable"] == [] and isinstance(d["notes"], list) and d["notes"]


def test_plan_as_dict_records_plaintext_best_and_missing() -> None:
    """both 全栈 → 记录 plaintext_best=mitm；缺增强 → missing 如实列出（机器可读"为何没明文"）。"""
    full = C.plan_as_dict(C.resolve("both", _FLOOR | {C.CAP_MITMPROXY, C.CAP_CA_TRUSTED}))
    assert full["plaintext_best"] == "mitm" and "mitm" in full["plaintext_reachable"]

    degraded = C.plan_as_dict(C.resolve("mitm-only", _FLOOR))  # 缺 mitmproxy
    assert "mitmproxy" in degraded["missing"] and degraded["degraded_to"] == "floor-only"
