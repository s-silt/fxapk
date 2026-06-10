"""apkscan._pyi_entry 单测：dispatch 分发与 argv 改写，全 mock、不真打包、不真起工具。

覆盖（呼应 spec §6.2）：
  - CLI 子命令（analyze 等）/ --help / 任意非空首参 → 调 apkscan.cli.main。
  - 内置工具名 → 改写 sys.argv=[tool, *原 argv[2:]] 并调对应库入口；返回 int → SystemExit。
  - 缺库（源码态未装某工具）→ 友好提示 + SystemExit(1)，不抛 traceback。
  - 无参：console → cli help（cli.main）；gui → apkscan.gui.main。

内置工具库用 sys.modules 假桩注入（不依赖真装 frida/mitmproxy），断言被调 + argv 形态。
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from apkscan import _pyi_entry


def _install_fake_module(
    monkeypatch: pytest.MonkeyPatch, mod_name: str, attr: str, fn: Any
) -> None:
    """在 sys.modules 注入一个假模块 mod_name，挂上属性 attr=fn（importlib 即取到它）。

    支持点分模块名：只造叶子模块对象塞进 sys.modules（importlib.import_module 直接命中
    sys.modules 缓存，无需父包真实存在）。
    """
    fake = types.ModuleType(mod_name)
    setattr(fake, attr, fn)
    monkeypatch.setitem(sys.modules, mod_name, fake)


# ---------------------------------------------------------------------------
# CLI 子命令 / --help / 无参
# ---------------------------------------------------------------------------


def test_cli_subcommand_dispatches_to_cli_main(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, Any] = {}
    _install_fake_module(monkeypatch, "apkscan.cli", "main", lambda: called.setdefault("cli", True))
    monkeypatch.setattr(sys, "argv", ["fxapk.exe", "analyze", "a.apk", "--offline"])
    _pyi_entry._run("cli")
    assert called.get("cli") is True
    # CLI 分支不改写 argv（typer 读原 argv[1:]）。
    assert sys.argv == ["fxapk.exe", "analyze", "a.apk", "--offline"]


def test_help_flag_dispatches_to_cli_main(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, Any] = {}
    _install_fake_module(monkeypatch, "apkscan.cli", "main", lambda: called.setdefault("cli", True))
    monkeypatch.setattr(sys, "argv", ["fxapk.exe", "--help"])
    _pyi_entry._run("cli")
    assert called.get("cli") is True


def test_no_arg_console_default_cli_help(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, Any] = {}
    _install_fake_module(monkeypatch, "apkscan.cli", "main", lambda: called.setdefault("cli", True))
    monkeypatch.setattr(sys, "argv", ["fxapk.exe"])
    _pyi_entry._run("cli")
    assert called.get("cli") is True


def test_no_arg_gui_default_opens_gui(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, Any] = {}
    _install_fake_module(monkeypatch, "apkscan.gui", "main", lambda: called.setdefault("gui", True))
    monkeypatch.setattr(sys, "argv", ["fxapk-gui.exe"])
    _pyi_entry._run("gui")
    assert called.get("gui") is True


def test_gui_subcommand_still_goes_to_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    """``fxapk.exe gui`` 是 CLI 子命令（typer 内部开窗），走 cli.main 而非直接 gui.main。"""
    called: dict[str, Any] = {}
    _install_fake_module(monkeypatch, "apkscan.cli", "main", lambda: called.setdefault("cli", True))
    monkeypatch.setattr(sys, "argv", ["fxapk.exe", "gui"])
    _pyi_entry._run("cli")
    assert called.get("cli") is True


# ---------------------------------------------------------------------------
# 内置工具分发 + argv 改写
# ---------------------------------------------------------------------------


def test_frida_dispatches_to_frida_tools_repl_with_argv_rewrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def _fake_main() -> None:
        seen["argv"] = list(sys.argv)

    _install_fake_module(monkeypatch, "frida_tools.repl", "main", _fake_main)
    monkeypatch.setattr(sys, "argv", ["fxapk.exe", "frida", "-U", "--version"])
    _pyi_entry._run("cli")
    # argv 改写为 [tool, *原 argv[2:]]：丢掉 fxapk.exe，工具名落 argv[0]。
    assert seen["argv"] == ["frida", "-U", "--version"]


def test_dispatch_builtin_allocates_console_before_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    """分发内置工具前先 _ensure_console_for_builtin（windowed exe 无控制台 → frida 崩溃的修复）。"""
    order: list[str] = []
    monkeypatch.setattr(_pyi_entry, "_ensure_console_for_builtin", lambda: order.append("console"))
    _install_fake_module(monkeypatch, "frida_tools.repl", "main", lambda: order.append("frida"))
    monkeypatch.setattr(sys, "argv", ["fxapk-gui.exe", "frida", "-U", "-f", "com.x"])
    _pyi_entry._run("gui")
    assert order == ["console", "frida"]  # 控制台分配发生在工具运行之前


def test_ensure_console_noop_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """非 Windows → _ensure_console_for_builtin 直接返回，不碰 ctypes、不抛。"""
    monkeypatch.setattr(_pyi_entry.sys, "platform", "linux")
    _pyi_entry._ensure_console_for_builtin()  # 不抛即通过


def test_frida_dexdump_dispatches_with_argv_rewrite(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    _install_fake_module(
        monkeypatch,
        "frida_dexdump.__main__",
        "main",
        lambda: seen.setdefault("argv", list(sys.argv)),
    )
    monkeypatch.setattr(sys, "argv", ["fxapk.exe", "frida-dexdump", "--help"])
    _pyi_entry._run("cli")
    assert seen["argv"] == ["frida-dexdump", "--help"]


def test_mitmdump_returns_int_raises_systemexit(monkeypatch: pytest.MonkeyPatch) -> None:
    """mitmdump 入口返回 int → 用 SystemExit(rc) 传退出码给 bootloader。"""
    _install_fake_module(monkeypatch, "mitmproxy.tools.main", "mitmdump", lambda: 0)
    monkeypatch.setattr(sys, "argv", ["fxapk.exe", "mitmdump", "--version"])
    with pytest.raises(SystemExit) as ei:
        _pyi_entry._run("cli")
    assert ei.value.code == 0


def test_builtin_tool_name_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    _install_fake_module(
        monkeypatch, "frida_tools.ps", "main", lambda: seen.setdefault("argv", list(sys.argv))
    )
    monkeypatch.setattr(sys, "argv", ["fxapk.exe", "FRIDA-PS", "-D", "emulator"])
    _pyi_entry._run("cli")
    # 小写匹配命中；argv[0] 用规范小写工具名。
    assert seen["argv"] == ["frida-ps", "-D", "emulator"]


def test_missing_builtin_lib_friendly_systemexit(monkeypatch: pytest.MonkeyPatch) -> None:
    """缺库（import 失败）→ 友好提示 + SystemExit(1)，不抛原始 ImportError。"""

    def _raise_import(_name: str) -> Any:
        raise ImportError("No module named 'frida_tools'")

    monkeypatch.setattr(_pyi_entry.importlib, "import_module", _raise_import)
    monkeypatch.setattr(sys, "argv", ["fxapk.exe", "frida", "--version"])
    with pytest.raises(SystemExit) as ei:
        _pyi_entry._run("cli")
    assert ei.value.code == 1


# ---------------------------------------------------------------------------
# console_main / gui_main 包装
# ---------------------------------------------------------------------------


def test_console_main_enables_utf8_and_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(_pyi_entry, "_enable_utf8_console", lambda: order.append("utf8"))
    monkeypatch.setattr(_pyi_entry, "_run", lambda default: order.append(f"run:{default}"))
    _pyi_entry.console_main()
    assert order == ["utf8", "run:cli"]


def test_gui_main_ensures_streams_and_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(_pyi_entry, "_ensure_std_streams", lambda: order.append("streams"))
    monkeypatch.setattr(_pyi_entry, "_run", lambda default: order.append(f"run:{default}"))
    _pyi_entry.gui_main()
    assert order == ["streams", "run:gui"]
