"""apkscan.core.device 单测：adb_devices 枚举可靠性（先 start-server 再 devices）+ 解析。

真机实测 bug 回归：本工具结束 kill-server 不留残留 → 每次 adb 冷启；若 adb devices 赶上
server 冷启/版本重启会空表，误判「无设备」（而后续 adb shell 因 server 已热而 OK）。
adb_devices 先 ensure_adb_server（同步 start-server）拉热，枚举才可靠。
"""

from __future__ import annotations

from typing import Any

from apkscan.core import device


class _Proc:
    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout


def test_adb_devices_starts_server_before_enumerate(monkeypatch: Any) -> None:
    """回归：adb_devices 必须先 `adb start-server` 再 `adb devices`（拉热避免冷启空表）。"""
    calls: list[list[str]] = []

    def fake_run(args: list[str], timeout: float = 5.0) -> _Proc | None:
        calls.append(list(args))
        if args[:2] == ["adb", "start-server"]:
            return _Proc(0, "")
        if args[:2] == ["adb", "devices"]:
            return _Proc(0, "List of devices attached\nemulator-5554\tdevice\n")
        return None

    monkeypatch.setattr(device, "_run", fake_run)
    serials = device.adb_devices()

    assert serials == ["emulator-5554"]
    twoheads = [c[:2] for c in calls]
    assert ["adb", "start-server"] in twoheads
    assert ["adb", "devices"] in twoheads
    assert twoheads.index(["adb", "start-server"]) < twoheads.index(["adb", "devices"])


def test_adb_devices_parses_only_online_and_strips_cr(monkeypatch: Any) -> None:
    """Windows \\r\\n + 多状态：只收 state==device 的，且 `device\\r` 被 strip 后仍命中。"""
    out = (
        "List of devices attached\r\n"
        "emulator-5554\tdevice\r\n"
        "10.0.0.2:5555\tdevice\r\n"
        "offline-dev\toffline\r\n"
        "bad-dev\tunauthorized\r\n"
    )

    def fake_run(args: list[str], timeout: float = 5.0) -> _Proc:
        return _Proc(0, out) if args[:2] == ["adb", "devices"] else _Proc(0, "")

    monkeypatch.setattr(device, "_run", fake_run)
    assert device.adb_devices() == ["emulator-5554", "10.0.0.2:5555"]


def test_adb_devices_empty_when_run_none(monkeypatch: Any) -> None:
    monkeypatch.setattr(device, "_run", lambda args, timeout=5.0: None)
    assert device.adb_devices() == []


def test_adb_devices_empty_on_nonzero(monkeypatch: Any) -> None:
    def fake_run(args: list[str], timeout: float = 5.0) -> _Proc:
        return _Proc(1, "")

    monkeypatch.setattr(device, "_run", fake_run)
    assert device.adb_devices() == []


def test_ensure_adb_server_no_raise(monkeypatch: Any) -> None:
    # _run 返回 None（adb 不可用）也不抛。
    monkeypatch.setattr(device, "_run", lambda args, timeout=5.0: None)
    device.ensure_adb_server()


def test_has_device_true_when_serials(monkeypatch: Any) -> None:
    monkeypatch.setattr(device, "adb_devices", lambda: ["emulator-5554"])
    assert device.has_device() is True
    monkeypatch.setattr(device, "adb_devices", lambda: [])
    assert device.has_device() is False


# ---------------------------------------------------------------------------
# frida_server_running：ps 进程名启发式 + frida-ps -U 权威兜底（与 doctor 一致，
# 避免 unpack/capture 因进程名截断/改名漏判「缺 frida-server」）
# ---------------------------------------------------------------------------


def test_frida_server_running_true_when_ps_finds(monkeypatch: Any) -> None:
    """ps 直接命中 frida-server → True，无需 frida-ps 兜底。"""
    monkeypatch.setattr(
        device, "_run", lambda args, timeout=5.0: _Proc(0, "u0_a1 1234 frida-server\n")
    )

    def _boom(serial: Any = None) -> bool:
        raise AssertionError("ps 已命中，不应再调 frida_ps_reachable")

    monkeypatch.setattr(device, "frida_ps_reachable", _boom)
    assert device.frida_server_running() is True


def test_frida_server_running_falls_back_to_frida_ps(monkeypatch: Any) -> None:
    """ps 没命中（进程名被截断/改名）→ frida-ps 权威兜底确认在跑 → True。"""
    monkeypatch.setattr(
        device, "_run", lambda args, timeout=5.0: _Proc(0, "u0_a1 1234 other_proc\n")
    )
    monkeypatch.setattr(device, "frida_ps_reachable", lambda serial=None: True)
    assert device.frida_server_running() is True


def test_frida_server_running_false_when_both_miss(monkeypatch: Any) -> None:
    monkeypatch.setattr(device, "_run", lambda args, timeout=5.0: _Proc(0, "nope\n"))
    monkeypatch.setattr(device, "frida_ps_reachable", lambda serial=None: False)
    assert device.frida_server_running() is False


def test_frida_server_running_ps_probe_fails_uses_frida_ps(monkeypatch: Any) -> None:
    """adb ps 探测失败（None）也走 frida-ps 兜底，而非直接判未运行。"""
    monkeypatch.setattr(device, "_run", lambda args, timeout=5.0: None)
    monkeypatch.setattr(device, "frida_ps_reachable", lambda serial=None: True)
    assert device.frida_server_running() is True


def test_frida_ps_reachable_false_when_no_invocation(monkeypatch: Any) -> None:
    monkeypatch.setattr(device.tools, "frida_invocation", lambda tool: [])
    assert device.frida_ps_reachable() is False


def test_frida_spawn_hint_jailed_gives_root_hint() -> None:
    """「需 Gadget / jailed」→ frida-server 非 root 提示（含 pkill 命令）。"""
    msg = device.frida_spawn_hint(
        "Failed to spawn: need Gadget to attach on jailed Android; ... gadget-android-arm64.so"
    )
    assert "root" in msg
    assert "pkill frida-server" in msg


def test_frida_spawn_hint_not_installed_gives_install_hint() -> None:
    """「unable to find application」→ app 未安装提示（不再误报 root）。"""
    msg = device.frida_spawn_hint(
        "Failed to spawn: unable to find application with identifier 'com.x.y'"
    )
    assert "未安装" in msg
    assert "install" in msg
    assert "root" not in msg  # 不再误把"未安装"当"非 root"


def test_frida_spawn_hint_empty_when_unrelated() -> None:
    # 仅 "Failed to spawn" 不带具体特征 → 不给误导性提示（收窄后不再瞎匹配）。
    assert device.frida_spawn_hint("Failed to spawn: some other reason") == ""
    assert device.frida_spawn_hint("connection refused") == ""
    assert device.frida_spawn_hint("") == ""


# ---------------------------------------------------------------------------
# frida_server_is_root：ps USER 列判属主（保守：探测不到/找不到一律 True 不误杀）
# ---------------------------------------------------------------------------


def test_frida_server_is_root_true_when_root_owner(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        device, "_run", lambda args, timeout=5.0: _Proc(0, "USER PID\nroot 1234 frida-server\n")
    )
    assert device.frida_server_is_root() is True


def test_frida_server_is_root_false_when_shell_owner(monkeypatch: Any) -> None:
    """非 root 属主（shell）→ False（触发以 root 重启）。"""
    monkeypatch.setattr(
        device, "_run", lambda args, timeout=5.0: _Proc(0, "USER PID\nshell 1234 frida-server\n")
    )
    assert device.frida_server_is_root() is False


def test_frida_server_is_root_false_when_ps_fails(monkeypatch: Any) -> None:
    """严格：ps 探测不到 → 未确认 root → False（触发以 root 重启）。"""
    monkeypatch.setattr(device, "_run", lambda args, timeout=5.0: None)
    assert device.frida_server_is_root() is False


def test_frida_server_is_root_false_when_not_found(monkeypatch: Any) -> None:
    """严格：ps 里没 frida-server 行（进程名被截断/MuMu ps 不认）→ 未确认 root → False。"""
    monkeypatch.setattr(device, "_run", lambda args, timeout=5.0: _Proc(0, "USER PID\nroot 1 init\n"))
    assert device.frida_server_is_root() is False


def test_ensure_adb_server_connects_common_emulator_ports(monkeypatch: Any) -> None:
    """真机实测(MuMu 12)：ensure_adb_server 应 best-effort connect 常见模拟器端口
    （16384 等），否则 server 重启后 MuMu 掉线、命令 exit 1。"""
    calls: list[list[str]] = []

    def _rec(args: list[str], timeout: float = 5.0) -> None:
        calls.append(list(args))
        return None

    monkeypatch.setattr(device, "_run", _rec)
    device.ensure_adb_server()

    twoheads = [c[:2] for c in calls]
    assert ["adb", "start-server"] in twoheads
    connect_targets = [c[2] for c in calls if c[:2] == ["adb", "connect"] and len(c) > 2]
    assert "127.0.0.1:16384" in connect_targets  # MuMu 12


def test_ensure_adb_server_skips_connect_when_device_present(monkeypatch: Any) -> None:
    """已有在线设备 → 不再 connect（避免给 MuMu 等加重复 transport 致 "more than one device"）。"""
    calls: list[list[str]] = []

    def _rec(args: list[str], timeout: float = 5.0) -> "_Proc | None":
        calls.append(list(args))
        if args[:2] == ["adb", "devices"]:
            return _Proc(0, "List of devices attached\nemulator-5554\tdevice\n")
        return None

    monkeypatch.setattr(device, "_run", _rec)
    device.ensure_adb_server()

    assert ["adb", "start-server"] in [c[:2] for c in calls]
    assert not any(c[:2] == ["adb", "connect"] for c in calls)  # 设备已可见 → 不 connect
