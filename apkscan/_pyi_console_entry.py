"""PyInstaller console 入口包装脚本（fxapk.exe）。

转发到 :func:`apkscan.cli.main`；在转发前把 Windows 控制台与标准流切到 UTF-8
（SetConsoleOutputCP/SetConsoleCP = 65001 + reconfigure stdout/stderr），避免打包后
中文日志在控制台显示为乱码。全部 try/except，任何失败都静默、绝不阻断启动。

仅作 PyInstaller Analysis 入口（spec 引用本文件），不含业务逻辑。
"""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)


def _enable_utf8_console() -> None:
    """Windows 下把控制台输出切到 UTF-8，修中文日志乱码。非 Windows 直接返回。

    `sys.platform != "win32"` 早返回让 pyright 在非 win32 平台把下方 ctypes.windll
    判为不可达、跳过检查（与跨平台 API 一致的处理）。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)
        kernel32.SetConsoleCP(65001)
    except Exception:
        logger.debug("设置控制台代码页为 UTF-8 失败（忽略）", exc_info=True)
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except Exception:
            logger.debug("重配标准流为 UTF-8 失败（忽略）", exc_info=True)


def main() -> None:
    _enable_utf8_console()
    from apkscan.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
