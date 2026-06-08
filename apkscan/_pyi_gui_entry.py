"""PyInstaller windowed 入口壳脚本（fxapk-gui.exe 的 Analysis 入口）。

dispatch 逻辑集中在 :mod:`apkscan._pyi_entry`；本文件仅作 PyInstaller Analysis 的
真实脚本入口（spec 路径不变），转发到 :func:`apkscan._pyi_entry.gui_main`。
"""

from __future__ import annotations

from apkscan._pyi_entry import gui_main

if __name__ == "__main__":
    gui_main()
