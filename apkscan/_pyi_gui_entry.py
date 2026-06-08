"""PyInstaller windowed 入口包装脚本（fxapk-gui.exe）。

仅做转发：调用 :func:`apkscan.gui.main`（其内部延迟 import tkinter 并起 Tk root）。
不含任何业务逻辑，便于 PyInstaller 以一个真实脚本文件作为 GUI Analysis 入口。
"""

from __future__ import annotations

from apkscan.gui import main

if __name__ == "__main__":
    main()
