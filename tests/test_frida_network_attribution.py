"""Frida 网络归因门控：别把设备自己的网络故障记成「样本反 Frida」。

★真机实测背景：红米 K40 上「脱壳后全机断网」曾被当成 APK 反 Frida。分层 A/B 后确认，
根因是 Wi-Fi 用了静态地址，Android 网络验证失败并临时拉黑 BSSID——Frida PID 为空时
同样复现；改 DHCP 后无 Frida、仅起 server、真实 attach/detach、frida-dexdump 全部正常。

要区分这两者，唯一办法是在动作**之前**也测一次。基线本来就坏的，事后再坏也不能算 Frida 的。
"""

from __future__ import annotations

from typing import Any

from apkscan.core import device
from apkscan.dynamic import doctor

_HEALTHY = device.DeviceNetworkState(
    connected=True, validated=True, assignment=device.NET_ASSIGN_DHCP,
    ipv4="192.168.10.233", detail="IPv4=192.168.10.233；默认路由=有；网络验证=通过；地址方式=dhcp",
)
_BROKEN = device.DeviceNetworkState(
    connected=True, validated=False, assignment=device.NET_ASSIGN_STATIC,
    ipv4="192.168.10.23", detail="IPv4=192.168.10.23；默认路由=有；网络验证=失败；地址方式=static",
)
_UNKNOWN = device.DeviceNetworkState(detail="设备未响应网络状态查询，状态未知")


# --- 状态模型 ---------------------------------------------------------------


def test_healthy_requires_route_and_validation() -> None:
    assert _HEALTHY.healthy is True
    assert _BROKEN.healthy is False
    assert device.DeviceNetworkState(connected=False).healthy is False


def test_unknown_is_not_broken() -> None:
    """★读不到 ≠ 坏了。判不出来必须是 None，否则会在不支持 dumpsys 的设备上假失败。"""
    assert _UNKNOWN.healthy is None
    assert device.DeviceNetworkState().healthy is None


# --- 四种归因 ---------------------------------------------------------------


def test_bad_baseline_is_never_blamed_on_frida() -> None:
    """★这条是整个门控存在的理由。"""
    outcome, note = doctor._attribute_network(_BROKEN, _BROKEN)
    assert outcome == doctor._ATTR_BASELINE_BAD
    assert "不得归因于 Frida" in note


def test_degradation_after_probe_is_reported() -> None:
    outcome, note = doctor._attribute_network(_HEALTHY, _BROKEN)
    assert outcome == doctor._ATTR_DEGRADED
    assert "退化" in note


def test_stable_network_reads_as_stable() -> None:
    assert doctor._attribute_network(_HEALTHY, _HEALTHY)[0] == doctor._ATTR_STABLE


def test_unknown_state_is_not_counted_against_frida() -> None:
    outcome, note = doctor._attribute_network(_UNKNOWN, _UNKNOWN)
    assert outcome == doctor._ATTR_UNKNOWN
    assert "不将其计为 Frida" in note


# --- 检查项与关键项集 -------------------------------------------------------


def test_unknown_network_passes_but_warns() -> None:
    """判不出来时按通过处理——否则不支持 dumpsys 的设备会被整体判不可用。"""
    item = doctor._check_device_network(_UNKNOWN, _UNKNOWN, doctor._ATTR_UNKNOWN)
    assert item["ok"] is True
    assert "未知" in item["detail"]


def test_bad_baseline_fails_the_network_item_with_fixes() -> None:
    item = doctor._check_device_network(_BROKEN, _BROKEN, doctor._ATTR_BASELINE_BAD)
    assert item["ok"] is False
    assert item["fix_cmd"], "必须给出怎么修"
    assert any("DHCP" in c for c in item["fix_cmd"])
    # ★不得自动改设备网络：修复指引只能是让人去做，不能是工具自己执行的动作。
    assert not any(c.startswith("adb shell svc wifi") for c in item["fix_cmd"])


def test_network_item_is_critical_in_both_profiles() -> None:
    assert doctor._NAME_DEVICE_NETWORK in doctor._FLOOR_CRITICAL
    assert doctor._NAME_DEVICE_NETWORK in doctor._CRITICAL


# --- 接线：doctor 真的采集前后两次并把归因写进 Frida 项 ----------------------


def test_check_frida_server_samples_network_before_and_after(monkeypatch: Any) -> None:
    calls: list[str] = []
    states = iter([_HEALTHY, _BROKEN])

    def _fake_read(serial: str | None = None) -> device.DeviceNetworkState:
        calls.append("read")
        return next(states, _BROKEN)

    monkeypatch.setattr(device, "read_network_state", _fake_read)
    monkeypatch.setattr(
        device, "frida_server_probe",
        lambda serial=None, expected_version="": device.FridaServerProbe(
            ok=True, detail="frida-server 就绪", pid=1234, version="17.0.0"
        ),
    )

    frida_item, net_item = doctor._check_frida_server(
        "dev1", "17.0.0", auto_fix=False, on_progress=None
    )

    assert len(calls) == 2, "必须在验收前后各采一次，否则分不出基线坏还是事后坏"
    assert doctor._ATTR_DEGRADED in frida_item["detail"]
    assert net_item["ok"] is False


def test_frida_failure_on_bad_baseline_is_annotated(monkeypatch: Any) -> None:
    """基线就坏时，Frida 项即便失败也要注明「可能是网络导致」，不许直接算 Frida 的账。"""
    monkeypatch.setattr(device, "read_network_state", lambda serial=None: _BROKEN)
    monkeypatch.setattr(
        device, "frida_server_probe",
        lambda serial=None, expected_version="": device.FridaServerProbe(
            ok=False, detail="attach 失败"
        ),
    )

    frida_item, net_item = doctor._check_frida_server(
        "dev1", "17.0.0", auto_fix=False, on_progress=None
    )

    assert frida_item["ok"] is False
    assert doctor._ATTR_BASELINE_BAD in frida_item["detail"]
    assert "先修网络再判 Frida" in frida_item["detail"]
    assert net_item["ok"] is False


# --- 采集本身：只读、不抛 ---------------------------------------------------


def test_read_network_state_never_raises_on_dead_device(monkeypatch: Any) -> None:
    monkeypatch.setattr(device, "_adb_root_command", lambda cmd, serial=None: None)
    state = device.read_network_state("nope")
    assert state.healthy is None
    assert "未知" in state.detail


def test_adb_error_output_is_not_read_as_a_broken_network(monkeypatch: Any) -> None:
    """★CI 抓到的真 bug：无设备时 adb 打印 error 到 stdout/stderr，那是非空字符串。

    早先的实现只看"输出非空"就去正则找 default 路由，找不到便判断网——于是任何一台
    没插设备的机器都会被报成"基线网络异常"，doctor 整体判不可用。
    这正是本模块要避免的「把读不到当成坏了」，栽在自己手里。
    """
    class _P:
        def __init__(self, out: str) -> None:
            self.stdout = ""
            self.stderr = out
            self.returncode = 1

    for err in (
        "error: no devices/emulators found",
        "adb: device 'xyz' not found",
        "error: device offline",
    ):
        monkeypatch.setattr(device, "_adb_root_command", lambda cmd, serial=None, _e=err: _P(_e))
        state = device.read_network_state("dev1")
        assert state.healthy is None, f"{err!r} 必须判 unknown，不能判断网"
        assert state.connected is None


def test_non_route_output_does_not_imply_disconnected(monkeypatch: Any) -> None:
    """输出不像路由表时（命令不存在、被截断），不得据此判"没有默认路由"。"""
    class _P:
        def __init__(self, out: str) -> None:
            self.stdout = out
            self.stderr = ""
            self.returncode = 0

    def _fake(cmd: str, serial: str | None = None) -> Any:
        if cmd.startswith("ip -4 addr"):
            return _P("inet 192.168.1.5/24 scope global wlan0")
        if cmd.startswith("ip route"):
            return _P("/system/bin/sh: ip: inaccessible or not found")
        return _P("")

    monkeypatch.setattr(device, "_adb_root_command", _fake)
    state = device.read_network_state("dev1")
    assert state.connected is None
    assert state.healthy is None


def test_read_network_state_parses_static_validation_failure(monkeypatch: Any) -> None:
    """★复现真机那台：静态地址 + 网络验证失败。"""
    class _P:
        def __init__(self, out: str) -> None:
            self.stdout = out
            self.stderr = ""
            self.returncode = 0

    def _fake(cmd: str, serial: str | None = None) -> Any:
        if cmd.startswith("ip -4 addr"):
            return _P("inet 127.0.0.1/8 scope host lo\n    inet 192.168.10.23/24 scope global wlan0")
        if cmd.startswith("ip route"):
            return _P("default via 192.168.10.1 dev wlan0")
        if "connectivity" in cmd:
            return _P("NetworkSelectionStatus: NETWORK_SELECTION_DISABLED_NO_INTERNET_TEMPORARY")
        if "wifi" in cmd:
            return _P("ipAssignment: STATIC")
        return _P("")

    monkeypatch.setattr(device, "_adb_root_command", _fake)
    state = device.read_network_state("dev1")
    assert state.ipv4 == "192.168.10.23"
    assert state.connected is True
    assert state.validated is False
    assert state.assignment == device.NET_ASSIGN_STATIC
    assert state.healthy is False


def test_read_network_state_parses_healthy_dhcp(monkeypatch: Any) -> None:
    class _P:
        def __init__(self, out: str) -> None:
            self.stdout = out
            self.stderr = ""
            self.returncode = 0

    def _fake(cmd: str, serial: str | None = None) -> Any:
        if cmd.startswith("ip -4 addr"):
            return _P("inet 192.168.10.233/24 scope global wlan0")
        if cmd.startswith("ip route"):
            return _P("default via 192.168.10.1 dev wlan0")
        if "connectivity" in cmd:
            return _P("Capabilities: NET_CAPABILITY_INTERNET&NET_CAPABILITY_VALIDATED")
        if "wifi" in cmd:
            return _P("ipAssignment: DHCP")
        return _P("")

    monkeypatch.setattr(device, "_adb_root_command", _fake)
    state = device.read_network_state("dev1")
    assert state.healthy is True
    assert state.assignment == device.NET_ASSIGN_DHCP
