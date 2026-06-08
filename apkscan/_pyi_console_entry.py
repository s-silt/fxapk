"""PyInstaller console 入口包装脚本（fxapk.exe）。

仅做转发：调用 :func:`apkscan.cli.main`。不含任何业务逻辑，便于 PyInstaller
以一个真实脚本文件作为 Analysis 入口（spec 引用本文件）。
"""

from __future__ import annotations

from apkscan.cli import main

if __name__ == "__main__":
    main()
