"""双击启动 fxapk 图形界面（.pyw 在 Windows 下不弹控制台黑框）。

直接从源码树运行：把仓库根加入 sys.path 后调用 apkscan.gui.main()。
等价于 ``fxapk gui`` / ``fxapk-gui``，但无需先 pip install。
"""

from __future__ import annotations

import sys
from pathlib import Path

# 允许从未安装的源码树直接运行（把仓库根目录加入 import 路径）。
sys.path.insert(0, str(Path(__file__).resolve().parent))

from apkscan.gui import main  # noqa: E402 - 必须在调整 sys.path 之后再 import

if __name__ == "__main__":
    main()
