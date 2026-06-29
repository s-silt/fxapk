"""apkscan.core.utf8 — 进程级 UTF-8 环境（入口开一次，自动带给子进程）。

为什么需要（真机实测 bug 根因）：Windows 中文版默认 locale 是 GBK(cp936)。直接跑
``fxapk doctor`` 这类命令时：
- 我们用 ``subprocess(text=True)`` 读 adb/frida 子进程输出会按 GBK 解，遇非 GBK 字节
  （如 0xad）→ 崩 ``_readerthread``（已另在各调用点补 ``encoding="utf-8"/errors="replace"``）；
- ``typer.echo`` 的中文按 GBK 写控制台 → 乱码 / 报错；
- 我们再起的子 Python 进程默认也按 GBK 跑。

:func:`enable_utf8_runtime` 在入口调一次：
  ① 控制台代码页(Windows 65001) + 标准流 reconfigure 到 UTF-8(errors=replace)，让本进程
     读写都 UTF-8；
  ② 把 ``PYTHONUTF8`` / ``PYTHONIOENCODING`` 写进 ``os.environ`` —— 之后所有 ``subprocess``
     （``env`` 默认继承 ``os.environ``）的子进程**自动带上 UTF-8 环境**，无需逐个传 ``env``。

幂等、绝不抛、跨平台安全（非 Windows 也设 env + reconfigure，无害）。无第三方依赖，
仅用 stdlib，便于 cli 等入口早调用。
"""

from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger(__name__)


def enable_utf8_runtime() -> None:
    """开启进程级 UTF-8 环境（控制台流 + 子进程继承的 env）。幂等、绝不抛。"""
    # ① 子进程继承：写进 env（setdefault 不覆盖用户显式设定）。后续 subprocess.run(env=None)
    #    默认继承 os.environ → 子进程（尤其子 Python）自动 UTF-8。
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    # ② 本进程控制台：Windows 代码页切 65001（中文/UTF-8 输出不乱码）。
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
        except Exception:
            logger.debug("设置控制台代码页为 UTF-8 失败（忽略）", exc_info=True)

    # ③ 标准流 reconfigure 到 UTF-8（errors=replace：坏字节降级替换而非崩）。
    #    只动 stdout/stderr（我们的输出通道）；stdin 不动，避免管道/重定向场景意外。
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            logger.debug("重配标准流为 UTF-8 失败（忽略）", exc_info=True)


def utf8_subprocess_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """返回带 UTF-8 标记的子进程 env（``PYTHONUTF8`` / ``PYTHONIOENCODING``）。

    一般无需显式用——:func:`enable_utf8_runtime` 已把这两个变量写进 ``os.environ``，
    ``subprocess`` 默认继承。仅在调用方需要显式构造 ``env``（如已自定义部分变量）时，
    用本函数兜上 UTF-8，避免覆盖掉继承的 UTF-8 标记。
    """
    env = dict(base if base is not None else os.environ)
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return env


__all__ = ["enable_utf8_runtime", "utf8_subprocess_env"]
