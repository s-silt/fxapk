"""apkscan.core.tools 单测：frozen 判定 / adb 解析 / frida 调用前缀 / 可用性判定。

策略（无真打包、无真 PATH 工具，纯 monkeypatch）：
- frozen()：monkeypatch tools.sys.frozen（PyInstaller 冻结标志）。
- adb_path()：frozen 时用 tmp 目录冒充 exe 同目录、按是否放 adb.exe 验证；源码用 shutil.which。
- frida_invocation()：frozen → [sys.executable, tool]；源码 → [which] / []。
- has_*()：frozen → importlib.util.find_spec mock；源码 → shutil.which mock。

铁律对齐：解析失败返回 "" / []；判定返回 bool；全程不抛。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from apkscan.core import tools


# ---------------------------------------------------------------------------
# 辅助：进出 frozen 态
# ---------------------------------------------------------------------------


def _set_frozen(monkeypatch: pytest.MonkeyPatch, value: bool) -> None:
    """模拟 PyInstaller 冻结态：设置 / 清除 sys.frozen。"""
    if value:
        monkeypatch.setattr(tools.sys, "frozen", True, raising=False)
    else:
        # 源码态：确保 sys 上没有 frozen 属性。
        monkeypatch.delattr(tools.sys, "frozen", raising=False)


# ---------------------------------------------------------------------------
# frozen()
# ---------------------------------------------------------------------------


def test_frozen_true_when_sys_frozen_set(monkeypatch):
    _set_frozen(monkeypatch, True)
    assert tools.frozen() is True


def test_frozen_false_when_not_set(monkeypatch):
    _set_frozen(monkeypatch, False)
    assert tools.frozen() is False


# ---------------------------------------------------------------------------
# adb_path()
# ---------------------------------------------------------------------------


def test_adb_path_frozen_uses_app_dir_adb_when_present(monkeypatch, tmp_path):
    """frozen 且 exe 同目录有 adb.exe（无 _MEIPASS）→ 返回该绝对路径（不看 PATH）。"""
    _set_frozen(monkeypatch, True)
    monkeypatch.delattr(tools.sys, "_MEIPASS", raising=False)
    fake_exe = tmp_path / "fxapk.exe"
    fake_exe.write_bytes(b"MZ")
    adb_name = "adb.exe" if sys.platform == "win32" else "adb"
    adb_file = tmp_path / adb_name
    adb_file.write_bytes(b"adb-binary")
    monkeypatch.setattr(tools.sys, "executable", str(fake_exe))
    # PATH 即便有别的 adb，也应优先同目录的。
    monkeypatch.setattr(tools.shutil, "which", lambda name: "/other/adb")

    result = tools.adb_path()
    assert result == str(adb_file.resolve())


def test_adb_path_frozen_uses_meipass_internal_when_present(monkeypatch, tmp_path):
    """frozen 且 adb 在 sys._MEIPASS（PyInstaller 6.x onedir 的 _internal/）→ 返回它。

    模拟真实 onedir 布局：exe 在 dist/fxapk/，adb 在 dist/fxapk/_internal/（=_MEIPASS），
    exe 同级根目录没有 adb。优先 _MEIPASS 命中。
    """
    _set_frozen(monkeypatch, True)
    app_root = tmp_path / "fxapk"
    internal = app_root / "_internal"
    internal.mkdir(parents=True)
    fake_exe = app_root / "fxapk.exe"
    fake_exe.write_bytes(b"MZ")
    adb_name = "adb.exe" if sys.platform == "win32" else "adb"
    adb_file = internal / adb_name
    adb_file.write_bytes(b"adb-binary")
    monkeypatch.setattr(tools.sys, "executable", str(fake_exe))
    monkeypatch.setattr(tools.sys, "_MEIPASS", str(internal), raising=False)
    monkeypatch.setattr(tools.shutil, "which", lambda name: "/other/adb")

    assert tools.adb_path() == str(adb_file)


def test_adb_path_frozen_falls_back_to_path_when_no_local_adb(monkeypatch, tmp_path):
    """frozen 但 _MEIPASS / 同目录均无 adb.exe → 回退 PATH。"""
    _set_frozen(monkeypatch, True)
    monkeypatch.delattr(tools.sys, "_MEIPASS", raising=False)
    fake_exe = tmp_path / "fxapk.exe"
    fake_exe.write_bytes(b"MZ")
    monkeypatch.setattr(tools.sys, "executable", str(fake_exe))
    monkeypatch.setattr(tools.shutil, "which", lambda name: "/path/adb" if name == "adb" else None)

    assert tools.adb_path() == "/path/adb"


def test_adb_path_frozen_returns_empty_when_neither(monkeypatch, tmp_path):
    """frozen、_MEIPASS / 同目录均无 adb、PATH 也无 → ""。"""
    _set_frozen(monkeypatch, True)
    monkeypatch.delattr(tools.sys, "_MEIPASS", raising=False)
    fake_exe = tmp_path / "fxapk.exe"
    fake_exe.write_bytes(b"MZ")
    monkeypatch.setattr(tools.sys, "executable", str(fake_exe))
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)

    assert tools.adb_path() == ""


def test_adb_path_source_uses_which(monkeypatch):
    """源码态：直接走 shutil.which。"""
    _set_frozen(monkeypatch, False)
    monkeypatch.setattr(tools.shutil, "which", lambda name: "/usr/bin/adb" if name == "adb" else None)
    assert tools.adb_path() == "/usr/bin/adb"


def test_adb_path_source_empty_when_missing(monkeypatch):
    _set_frozen(monkeypatch, False)
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    assert tools.adb_path() == ""


# ---------------------------------------------------------------------------
# frida_invocation()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool",
    ["frida", "frida-ps", "frida-trace", "frida-dexdump", "mitmdump", "mitmproxy", "mitmweb"],
)
def test_frida_invocation_frozen_returns_self_exec(monkeypatch, tool):
    """frozen：[sys.executable, tool]（经 dispatch 自调用内置库）。"""
    _set_frozen(monkeypatch, True)
    monkeypatch.setattr(tools.sys, "executable", "C:/dist/fxapk.exe")
    assert tools.frida_invocation(tool) == ["C:/dist/fxapk.exe", tool]


def test_frida_invocation_source_returns_which(monkeypatch):
    """源码：[shutil.which(tool)]。"""
    _set_frozen(monkeypatch, False)
    monkeypatch.setattr(tools.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert tools.frida_invocation("frida") == ["/usr/bin/frida"]


def test_frida_invocation_source_empty_when_missing(monkeypatch):
    """源码且 PATH 无该工具 → []。"""
    _set_frozen(monkeypatch, False)
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    assert tools.frida_invocation("frida-dexdump") == []


def test_frida_invocation_unknown_tool_warns_but_returns(monkeypatch, caplog):
    """未知工具名只 warning，不抛；仍按规则返回。"""
    _set_frozen(monkeypatch, False)
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    import logging

    with caplog.at_level(logging.WARNING):
        result = tools.frida_invocation("nonexistent-tool")
    assert result == []
    assert any("未知内置工具名" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# has_adb / has_frida / has_frida_dexdump / has_mitmproxy
# ---------------------------------------------------------------------------


def test_has_adb_reflects_adb_path(monkeypatch):
    _set_frozen(monkeypatch, False)
    monkeypatch.setattr(tools.shutil, "which", lambda name: "/usr/bin/adb" if name == "adb" else None)
    assert tools.has_adb() is True
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    assert tools.has_adb() is False


def test_has_frida_source_uses_which(monkeypatch):
    _set_frozen(monkeypatch, False)
    monkeypatch.setattr(tools.shutil, "which", lambda name: "/usr/bin/frida" if name == "frida" else None)
    assert tools.has_frida() is True
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    assert tools.has_frida() is False


def test_has_frida_frozen_uses_find_spec(monkeypatch):
    """frozen：看 frida_tools 是否在包内（find_spec），不靠 PATH。"""
    _set_frozen(monkeypatch, True)
    monkeypatch.setattr(tools, "_has_module", lambda name: name == "frida_tools")
    assert tools.has_frida() is True
    monkeypatch.setattr(tools, "_has_module", lambda name: False)
    assert tools.has_frida() is False


def test_has_frida_dexdump_source_uses_which(monkeypatch):
    _set_frozen(monkeypatch, False)
    monkeypatch.setattr(
        tools.shutil, "which", lambda name: "/usr/bin/frida-dexdump" if name == "frida-dexdump" else None
    )
    assert tools.has_frida_dexdump() is True
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    assert tools.has_frida_dexdump() is False


def test_has_frida_dexdump_frozen_uses_find_spec(monkeypatch):
    _set_frozen(monkeypatch, True)
    monkeypatch.setattr(tools, "_has_module", lambda name: name == "frida_dexdump")
    assert tools.has_frida_dexdump() is True
    monkeypatch.setattr(tools, "_has_module", lambda name: False)
    assert tools.has_frida_dexdump() is False


def test_has_mitmproxy_source_uses_which_either_binary(monkeypatch):
    """源码：mitmproxy 或 mitmdump 任一在 PATH → True。"""
    _set_frozen(monkeypatch, False)
    monkeypatch.setattr(tools.shutil, "which", lambda name: "/usr/bin/mitmdump" if name == "mitmdump" else None)
    assert tools.has_mitmproxy() is True
    monkeypatch.setattr(tools.shutil, "which", lambda name: "/usr/bin/mitmproxy" if name == "mitmproxy" else None)
    assert tools.has_mitmproxy() is True
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    assert tools.has_mitmproxy() is False


def test_has_mitmproxy_frozen_uses_find_spec(monkeypatch):
    _set_frozen(monkeypatch, True)
    monkeypatch.setattr(tools, "_has_module", lambda name: name == "mitmproxy")
    assert tools.has_mitmproxy() is True
    monkeypatch.setattr(tools, "_has_module", lambda name: False)
    assert tools.has_mitmproxy() is False


# ---------------------------------------------------------------------------
# _has_module 真实行为（不靠 mock）
# ---------------------------------------------------------------------------


def test_has_module_true_for_stdlib():
    """对一定存在的 stdlib 模块返回 True。"""
    assert tools._has_module("json") is True


def test_has_module_false_for_nonexistent():
    assert tools._has_module("definitely_not_a_real_module_xyz") is False


# ---------------------------------------------------------------------------
# kill_adb_server()（问题 1：关 GUI / dynamic 动作后收掉自起的 adb server）
# ---------------------------------------------------------------------------


class _FakeProc:
    """subprocess.run 返回值替身，仅暴露 returncode。"""

    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode


def test_kill_adb_server_runs_kill_when_adb_available(monkeypatch):
    """adb 可用 → 跑 [adb, "kill-server"]，rc=0 → True。"""
    monkeypatch.setattr(tools, "adb_path", lambda: "/x/adb")
    recorded: dict[str, object] = {}

    def _fake_run(args, **kwargs):
        recorded["args"] = args
        recorded["kwargs"] = kwargs
        return _FakeProc(returncode=0)

    monkeypatch.setattr(tools.subprocess, "run", _fake_run)

    assert tools.kill_adb_server() is True
    assert recorded["args"] == ["/x/adb", "kill-server"]
    # check=False（不让非 0 退出码抛 CalledProcessError）、有超时。
    assert recorded["kwargs"]["check"] is False
    assert recorded["kwargs"]["timeout"] == 5.0


def test_kill_adb_server_frozen_uses_bundled_adb(monkeypatch, tmp_path):
    """frozen 且包内有 adb.exe → kill 用的是包内 adb 路径（与起 server 的同一个 adb）。"""
    _set_frozen(monkeypatch, True)
    monkeypatch.delattr(tools.sys, "_MEIPASS", raising=False)
    fake_exe = tmp_path / "fxapk.exe"
    fake_exe.write_bytes(b"MZ")
    adb_name = "adb.exe" if sys.platform == "win32" else "adb"
    adb_file = tmp_path / adb_name
    adb_file.write_bytes(b"adb-binary")
    monkeypatch.setattr(tools.sys, "executable", str(fake_exe))
    monkeypatch.setattr(tools.shutil, "which", lambda name: "/other/adb")

    recorded: dict[str, object] = {}

    def _fake_run(args, **kwargs):
        recorded["args"] = args
        return _FakeProc(returncode=0)

    monkeypatch.setattr(tools.subprocess, "run", _fake_run)

    assert tools.kill_adb_server() is True
    assert recorded["args"] == [str(adb_file.resolve()), "kill-server"]


def test_kill_adb_server_returns_false_when_no_adb(monkeypatch):
    """adb 不可用 → 不调 subprocess.run、返回 False（绝不反而把 server 起起来）。"""
    monkeypatch.setattr(tools, "adb_path", lambda: "")

    def _must_not_run(*a, **k):  # pragma: no cover - 断言不被调用
        raise AssertionError("adb 不可用时不应调用 subprocess.run")

    monkeypatch.setattr(tools.subprocess, "run", _must_not_run)
    assert tools.kill_adb_server() is False


def test_kill_adb_server_false_when_nonzero_returncode(monkeypatch):
    """kill-server 退出码非 0 → False（不假成功）+ 不抛。"""
    monkeypatch.setattr(tools, "adb_path", lambda: "/x/adb")
    monkeypatch.setattr(tools.subprocess, "run", lambda *a, **k: _FakeProc(returncode=1))
    assert tools.kill_adb_server() is False


def test_kill_adb_server_swallows_oserror(monkeypatch, caplog):
    """subprocess.run 抛 OSError → 返回 False + logging（不抛）。"""
    import logging

    monkeypatch.setattr(tools, "adb_path", lambda: "/x/adb")

    def _boom(*a, **k):
        raise OSError("adb not executable")

    monkeypatch.setattr(tools.subprocess, "run", _boom)
    with caplog.at_level(logging.WARNING):
        assert tools.kill_adb_server() is False
    assert any("kill-server" in r.message for r in caplog.records)


def test_kill_adb_server_swallows_timeout(monkeypatch, caplog):
    """subprocess.run 超时（TimeoutExpired）→ 返回 False + logging（不抛）。"""
    import logging
    import subprocess as _sp

    monkeypatch.setattr(tools, "adb_path", lambda: "/x/adb")

    def _timeout(*a, **k):
        raise _sp.TimeoutExpired(cmd="adb kill-server", timeout=5.0)

    monkeypatch.setattr(tools.subprocess, "run", _timeout)
    with caplog.at_level(logging.WARNING):
        assert tools.kill_adb_server() is False
    assert any("超时" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# jadx 插件包解析（resolve_jadx / jadx_addon_dir / has_jadx）
# ---------------------------------------------------------------------------


def _make_jadx_addon(base: Path, *, with_jre: bool = True) -> Path:
    """在 base 下造 jadx-addon/jadx/bin/jadx(.bat)（+可选 jre/bin/java.exe）。"""
    addon = base / "jadx-addon"
    binp = addon / "jadx" / "bin"
    binp.mkdir(parents=True, exist_ok=True)
    (binp / tools._jadx_bat_name()).write_text("@echo jadx", encoding="utf-8")
    if with_jre:
        (addon / "jre" / "bin").mkdir(parents=True, exist_ok=True)
        (addon / "jre" / "bin" / "java.exe").write_bytes(b"MZ")
    return addon


def test_resolve_jadx_prefers_path(monkeypatch, tmp_path):
    """PATH 上有 jadx → 直接用，不注入 JAVA_HOME（即使插件包也在）。"""
    monkeypatch.setattr(tools.shutil, "which", lambda n: r"C:\sys\jadx.exe" if n == "jadx" else None)
    monkeypatch.setattr(tools, "app_data_dirs", lambda: [tmp_path])
    _make_jadx_addon(tmp_path)
    assert tools.resolve_jadx() == ([r"C:\sys\jadx.exe"], {})
    assert tools.has_jadx() is True


def test_resolve_jadx_uses_addon_with_java_home(monkeypatch, tmp_path):
    """PATH 无 jadx，但插件包就位（含 JRE）→ 用包内 jadx.bat 完整路径 + 注入 JAVA_HOME。"""
    monkeypatch.setattr(tools.shutil, "which", lambda n: None)
    monkeypatch.setattr(tools, "app_data_dirs", lambda: [tmp_path])
    addon = _make_jadx_addon(tmp_path, with_jre=True)
    cmd, env = tools.resolve_jadx()
    assert cmd == [str(addon / "jadx" / "bin" / tools._jadx_bat_name())]
    assert env.get("JAVA_HOME") == str(addon / "jre")
    assert tools.jadx_addon_dir() == addon
    assert tools.has_jadx() is True


def test_resolve_jadx_addon_without_jre_no_java_home(monkeypatch, tmp_path):
    """插件包无 jre/ → 不注入 JAVA_HOME（退回系统 Java），仍返回包内 jadx。"""
    monkeypatch.setattr(tools.shutil, "which", lambda n: None)
    monkeypatch.setattr(tools, "app_data_dirs", lambda: [tmp_path])
    _make_jadx_addon(tmp_path, with_jre=False)
    cmd, env = tools.resolve_jadx()
    assert cmd and env == {}


def test_resolve_jadx_none_when_nothing(monkeypatch, tmp_path):
    """PATH 无 jadx、无插件包 → None，has_jadx False。"""
    monkeypatch.setattr(tools.shutil, "which", lambda n: None)
    monkeypatch.setattr(tools, "app_data_dirs", lambda: [tmp_path])
    assert tools.resolve_jadx() is None
    assert tools.has_jadx() is False
    assert tools.jadx_addon_dir() is None
