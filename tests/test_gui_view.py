"""apkscan.gui 烟测：import 不需显示器；view 构造 headless 安全（无 X 自动 skip）。

铁律呼应：
- ``import apkscan.gui`` / ``import apkscan.gui.view`` 在无显示器环境也必须成功
  （模块级不建 Tk root）。
- Tk view 构造的烟测用 try: tkinter.Tk() except TclError: skip —— CI 无显示器自动跳过，
  本机 Windows 有显示器会真构造一次验证无异常。
"""

from __future__ import annotations

import importlib

import pytest


def test_import_gui_does_not_need_display() -> None:
    """import apkscan.gui 不构造 Tk，无显示器也能成功；暴露 main。"""
    gui = importlib.import_module("apkscan.gui")
    assert hasattr(gui, "main")
    assert callable(gui.main)


def test_import_gui_view_does_not_create_tk_at_module_level() -> None:
    """import apkscan.gui.view 不在模块级建 root（headless 安全）；暴露 App/run_app。"""
    view = importlib.import_module("apkscan.gui.view")
    assert hasattr(view, "App")
    assert hasattr(view, "run_app")


def test_import_controller_has_no_tk_dependency() -> None:
    """controller 层无 Tk 依赖：import 后其模块未引入 tkinter 名字。"""
    import apkscan.gui.controller as controller

    assert not hasattr(controller, "tk")
    assert not hasattr(controller, "tkinter")


def test_view_app_constructs_without_error_if_display_available() -> None:
    """有显示器：真构造一次 App 验证布局/样式无异常；无显示器（CI）自动 skip。"""
    import tkinter as tk

    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("无显示器环境（headless），跳过 Tk 构造烟测")

    from apkscan.gui.view import App

    try:
        app = App(root)
        # 控件就绪：动作按钮存在、日志框存在、变量默认值合理。
        assert len(app._action_buttons) == 3
        assert app.var_online.get() is False  # 默认离线
        assert app.var_html.get() is True  # 默认勾 HTML
        assert app.var_json.get() is True  # 默认勾 JSON
        assert app.var_pdf.get() is False  # 默认不勾 PDF
        assert app._collect_formats() == ["html", "json"]
        # 强制处理一轮挂起事件，确保渲染无异常。
        root.update_idletasks()
    finally:
        root.destroy()
