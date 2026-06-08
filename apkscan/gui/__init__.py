"""apkscan.gui — 新手友好的 tkinter 单窗口前端壳。

分层（严格遵守，便于 headless 单测）：

- :mod:`apkscan.gui.controller`：**无任何 Tk import**，封装「选哪个动作 → 后台线程调
  auto.run / doctor.run / analyze_static → on_progress 文本回传 UI → 结果格式化」。
  CI headless（无显示器）可直接单测 controller，不构造 Tk。
- :mod:`apkscan.gui.view`：tkinter/ttk 单窗口（扁平化 + 淡色系）。仅这里 import tkinter。

铁律：**本包模块级绝不创建 Tk root**（``import apkscan.gui`` 在无显示器环境也必须成功）。
``main()`` 才创建 root、实例化 App、进入 mainloop——延迟到运行期、且把 view 的
import 也放进 ``main`` 内部，确保 ``import apkscan.gui`` 不触发 tkinter 加载。

GUI 只是前端壳：所有分析/编排逻辑都在已做好的程序化核心（auto/doctor），**不重复**。
"""

from __future__ import annotations


def main() -> None:
    """GUI 入口：创建 Tk root、实例化 App、进入主循环。

    view 在函数内部惰性 import，保证 ``import apkscan.gui`` 本身不加载 tkinter，
    headless 环境只要不调用 ``main()`` 就永远不构造 Tk。
    """
    from apkscan.gui.view import run_app

    run_app()


__all__ = ["main"]
