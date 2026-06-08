"""apkscan.cli gui 子命令烟测：调 apkscan.gui.main()，不真起窗口。

monkeypatch apkscan.gui.main 防止真的进入 mainloop（headless 安全）；并测 tkinter
导入失败时的友好退出。
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from apkscan import cli

runner = CliRunner()


def test_cli_gui_invokes_gui_main(monkeypatch: pytest.MonkeyPatch) -> None:
    """fxapk gui → 调 apkscan.gui.main()；mock 掉避免真进 mainloop。"""
    import apkscan.gui as gui_mod

    called: dict[str, bool] = {"main": False}
    monkeypatch.setattr(gui_mod, "main", lambda: called.__setitem__("main", True))

    res = runner.invoke(cli.app, ["gui"])
    assert res.exit_code == 0
    assert called["main"] is True


def test_cli_gui_help_lists_command() -> None:
    """fxapk gui --help 正常（命令已注册）。"""
    res = runner.invoke(cli.app, ["gui", "--help"])
    assert res.exit_code == 0
    assert "图形界面" in res.output


def test_cli_gui_import_failure_exits_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """tkinter 不可用（import apkscan.gui 抛）→ 友好提示 + 退出码 1，不崩。"""
    import builtins

    real_import = builtins.__import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        fromlist = args[2] if len(args) >= 3 else kwargs.get("fromlist")
        if name == "apkscan.gui" and fromlist and "main" in fromlist:
            raise ImportError("simulated no tkinter")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    res = runner.invoke(cli.app, ["gui"])
    assert res.exit_code == 1
    assert "无法启动图形界面" in res.output
