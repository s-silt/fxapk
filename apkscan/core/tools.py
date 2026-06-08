"""内置工具解析层：frozen 时用包内自调用 / 同目录 adb；源码时用 PATH。

终极目标的"自包含 onedir 胖 exe"里，frida / frida-tools / frida-dexdump / mitmproxy
被打进包，adb 三件套随包放在 exe 同目录。本模块统一回答两个问题：

1. **怎么调起某个工具**：frozen 时不靠 PATH，而是回到 exe 自身（dispatch 入口按工具名
   自调用内置库）；源码时用 shutil.which 找 PATH 上的可执行文件。
2. **某个工具是否可用**：frozen 时基于"内置库是否打进包"（importlib.util.find_spec），
   adb 看 exe 同目录是否有 adb.exe；源码时沿用 shutil.which（与现有 device.has_* 一致）。

设计铁律（与 device / capture / provision 一致）：
- 全程不抛：解析失败返回 "" 或 []；判定函数返回 bool。
- 每个 except 必 logging，不裸 pass、不静默吞错。
- 全量 type hints。
- 本模块**不得 import apkscan.core.device**（device 反过来 import 本模块，避免循环）。
"""

from __future__ import annotations

import logging
import shutil
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

# dispatch 能自调用的内置库工具名（与 _pyi_entry._BUILTIN_TOOLS 对齐）。
_FRIDA_TOOLS: frozenset[str] = frozenset(
    {"frida", "frida-ps", "frida-trace", "frida-dexdump", "mitmdump", "mitmproxy", "mitmweb"}
)


def frozen() -> bool:
    """是否 PyInstaller 冻结态。"""
    return bool(getattr(sys, "frozen", False))


def _bundle_dirs() -> list[Path]:
    """frozen 胖包里 adb 可能落地的目录（按优先级）。

    PyInstaller 6.x onedir 把 spec ``datas`` 收进 ``<dist>/<name>/_internal/``
    （= ``sys._MEIPASS``），而非 exe 同级根目录。onefile 解包时同样落到
    ``sys._MEIPASS`` 临时目录。故需同时探测：

    1. ``sys._MEIPASS``（onedir 的 ``_internal/`` 或 onefile 的解包临时目录）——主路径；
    2. exe 同级目录（若用户手动把 adb 放在 exe 旁，或自定义 spec 落到根）——兜底。
    """
    dirs: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        dirs.append(Path(meipass))
    try:
        dirs.append(Path(sys.executable).resolve().parent)
    except OSError:
        logger.exception("[tools] 解析 exe 同级目录失败")
    return dirs


def adb_path() -> str:
    """adb 可执行路径。

    frozen：优先包内随附的 adb.exe（``sys._MEIPASS`` / exe 同级），回退 PATH；
    源码：  PATH（shutil.which）。
    找不到 → ""（不抛）。
    """
    if frozen():
        name = "adb.exe" if sys.platform == "win32" else "adb"
        for d in _bundle_dirs():
            cand = d / name
            try:
                if cand.is_file():
                    return str(cand)
            except OSError:
                logger.exception("[tools] 探测随包 adb 失败：%s", cand)
    return shutil.which("adb") or ""


def frida_invocation(tool: str) -> list[str]:
    """返回调用某内置工具的命令前缀（argv 列表）。

    frozen：``[sys.executable, tool]``（经 dispatch 入口自调用内置库）；
    源码：  ``[shutil.which(tool)]``（缺则 ``[]``）。

    tool ∈ _FRIDA_TOOLS。未知名只记 warning（不抛），仍按规则返回。
    """
    if tool not in _FRIDA_TOOLS:
        logger.warning("[tools] 未知内置工具名：%s", tool)
    if frozen():
        return [sys.executable, tool]
    exe = shutil.which(tool)
    return [exe] if exe else []


def has_adb() -> bool:
    """adb 是否可用（frozen 看同目录 adb.exe / PATH；源码看 PATH）。"""
    return bool(adb_path())


def _has_module(name: str) -> bool:
    """frozen 下判断内置库是否打进包（importlib.util.find_spec，不真 import 重模块）。"""
    import importlib.util

    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        logger.exception("[tools] find_spec 失败：%s", name)
        return False


def has_frida() -> bool:
    """frida CLI 可用。frozen：看 frida_tools 是否在包内；源码：PATH 有 frida。"""
    return _has_module("frida_tools") if frozen() else shutil.which("frida") is not None


def has_frida_dexdump() -> bool:
    """frida-dexdump 可用。frozen：看 frida_dexdump 是否在包内；源码：PATH 有 frida-dexdump。"""
    return _has_module("frida_dexdump") if frozen() else shutil.which("frida-dexdump") is not None


def has_mitmproxy() -> bool:
    """mitmproxy/mitmdump 可用。frozen：看 mitmproxy 是否在包内；源码：PATH 有 mitmproxy/mitmdump。"""
    if frozen():
        return _has_module("mitmproxy")
    return shutil.which("mitmproxy") is not None or shutil.which("mitmdump") is not None


__all__ = [
    "frozen",
    "adb_path",
    "frida_invocation",
    "has_adb",
    "has_frida",
    "has_frida_dexdump",
    "has_mitmproxy",
]
