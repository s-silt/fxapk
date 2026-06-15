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
import subprocess
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


# jadx 插件包（独立下载、不内置）解压后的约定目录名。用户把 fxapk-jadx zip 解压到
# **应用目录**（frozen=exe 同级 / 源码=repo 根）下的此目录，GUI/CLI 即自动发现并调用。
_JADX_ADDON_NAME = "jadx-addon"


def app_data_dirs() -> list[Path]:
    """jadx 插件包可能落地的"应用目录"（按优先级）。

    frozen：exe 同级目录（用户把插件包放 exe 旁）；源码：repo 根目录。失败仅记日志返回空。
    """
    dirs: list[Path] = []
    try:
        if frozen():
            dirs.append(Path(sys.executable).resolve().parent)
        else:
            # apkscan/core/tools.py → parents[2] = repo 根。
            dirs.append(Path(__file__).resolve().parents[2])
    except Exception:
        logger.exception("[tools] 解析应用目录失败")
    return dirs


def _jadx_bat_name() -> str:
    return "jadx.bat" if sys.platform == "win32" else "jadx"


def jadx_addon_dir() -> Path | None:
    """已就位的 jadx 插件包目录（含 ``jadx/bin/jadx(.bat)``）。未就位返回 None。"""
    name = _jadx_bat_name()
    for base in app_data_dirs():
        cand = base / _JADX_ADDON_NAME
        if (cand / "jadx" / "bin" / name).is_file():
            return cand
    return None


def resolve_jadx() -> tuple[list[str], dict[str, str]] | None:
    """解析 jadx 启动方式：返回 ``(命令前缀 argv, 需注入的环境变量)``；都不可用返回 None。

    优先级：
    1. PATH 上的 jadx（用户自管，与既有行为一致，不注入 JAVA_HOME）；
    2. 插件包 ``jadx-addon/``（独立下载随包自带 JRE）——返回包内 jadx.bat 完整路径，并把
       ``JAVA_HOME`` 注入指向包内 JRE，使**无系统 Java** 的机器也能跑（GUI 一键导入即用）。

    完整路径而非裸名：Windows 上 jadx 是 .bat，裸名经 subprocess 启动会 WinError 2。
    """
    on_path = shutil.which("jadx")
    if on_path:
        return [on_path], {}
    addon = jadx_addon_dir()
    if addon is not None:
        bat = addon / "jadx" / "bin" / _jadx_bat_name()
        env: dict[str, str] = {}
        jre = addon / "jre"
        if (jre / "bin").is_dir():
            env["JAVA_HOME"] = str(jre)
        return [str(bat)], env
    return None


def has_jadx() -> bool:
    """jadx 是否可用（PATH 或已就位的插件包）。"""
    return resolve_jadx() is not None


def kill_adb_server() -> bool:
    """收掉本工具自起的 adb server（仅当 adb 可用时）。绝不抛。

    用与起 server 时同一个 adb（frozen→包内 adb.exe，源码→PATH，经 :func:`adb_path`）跑
    ``[adb, "kill-server"]``。adb 不可用（``adb_path()`` 为空）→ 直接返回 False（不做任何
    子进程调用，绝不会反而把 server 起起来）。

    退出码 0 → True；非 0 / 超时 / OSError / 其它异常 → False + logging（不崩、不假成功）。
    Windows 下用 ``CREATE_NO_WINDOW`` 避免弹控制台。``kill-server`` 对「本就没起 server」
    也安全：adb 文档明确该子命令在无 server 时直接返回，不会拉起新 server。

    设计取舍：不做「只在确实用过 adb 之后才收」的全局状态判定——让本函数幂等 + 仅在
    ``adb_path()`` 非空时执行，已等价于「可用且可能起过 server 时收」；额外的「用过才收」
    状态标志会引入跨模块可变状态、且与 GUI 子进程模型割裂（子进程里的标志主进程看不到）。
    """
    exe = adb_path()
    if not exe:
        # 守住「只在 adb 可用时收」：没装 adb 直接返回，绝不触发子进程、绝不起 server。
        return False
    args = [exe, "kill-server"]
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=5.0,
            check=False,
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[tools] adb kill-server 超时（已忽略）：%s", exe)
        return False
    except OSError:
        logger.warning("[tools] adb kill-server 启动失败（已忽略）：%s", exe)
        return False
    except Exception:  # noqa: BLE001 - 任何意外都不得抛给关窗/退出路径
        logger.exception("[tools] adb kill-server 未预期异常（已忽略）：%s", exe)
        return False
    if proc.returncode != 0:
        logger.warning(
            "[tools] adb kill-server 退出码非 0（%d，已忽略）：%s", proc.returncode, exe
        )
        return False
    logger.info("[tools] 已收掉自起的 adb server：%s", exe)
    return True


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
    "kill_adb_server",
]
