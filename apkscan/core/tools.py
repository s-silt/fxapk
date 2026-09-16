"""工具解析层：显式工具配置、当前 Python 环境、PATH 与既有 frozen 调度。

终极目标的"自包含 onedir 胖 exe"里，frida / frida-tools / frida-dexdump / mitmproxy
被打进包，adb 三件套随包放在 exe 同目录。本模块统一回答两个问题：

1. **怎么调起某个工具**：frozen 时不靠 PATH，而是回到 exe 自身（dispatch 入口按工具名
   自调用内置库）；源码优先显式配置、当前解释器的脚本目录，再回退 PATH。
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
import json
import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

logger = logging.getLogger(__name__)

# dispatch 能自调用的内置库工具名。
_FRIDA_TOOLS: frozenset[str] = frozenset(
    {"frida", "frida-ps", "frida-trace", "frida-dexdump", "mitmdump", "mitmproxy", "mitmweb"}
)


def _toolchain_file() -> Path:
    """Per-environment configuration; never read configuration from a sample directory."""
    return Path(os.environ.get("FXAPK_TOOLCHAIN_FILE") or Path(sys.prefix) / "fxapk-tools.json")


def _configured_tool(name: str) -> str | None:
    """None means unconfigured; an invalid explicit selection fails closed with ''."""
    try:
        override = os.environ.get("FXAPK_TOOLCHAIN_FILE")
        if override and not Path(override).is_absolute():
            raise ValueError("toolchain configuration path must be absolute")
        config = _toolchain_file()
        if not os.path.lexists(config) and not override:
            return None
        if not config.is_file():
            raise ValueError("toolchain configuration must be a regular file")
        if config.stat().st_size > 65536:
            raise ValueError("toolchain configuration exceeds 64 KiB")
        data = json.loads(config.read_text(encoding="utf-8-sig"))
        if (
            not isinstance(data, dict)
            or type(data.get("schema")) is not int
            or data.get("schema") != 1
        ):
            raise ValueError("unsupported toolchain schema")
        mapping = data.get("tools")
        if not isinstance(mapping, dict):
            raise ValueError("tools must be an object")
        if name not in mapping:
            return None
        value = mapping[name]
        if not isinstance(value, str) or not value or not Path(value).is_absolute():
            raise ValueError("tool path must be absolute")
        resolved = shutil.which(value)
        if not resolved:
            raise ValueError("configured executable is unavailable")
        return resolved
    except (OSError, ValueError, TypeError):
        logger.warning("[tools] Invalid toolchain selection for %s; PATH fallback disabled", name)
        return ""


def _python_scripts_dir() -> Path:
    return Path(sysconfig.get_path("scripts"))


def executable_path(name: str) -> str:
    """Resolve without permanent PATH changes.

    Frozen: only shutil.which(name), ignoring toolchain configuration and scripts.
    Source: explicit configuration > interpreter scripts (only _FRIDA_TOOLS) > PATH.
    Tools outside _FRIDA_TOOLS (adb/tshark/jadx) use configuration > PATH;
    jadx's additional addon fallback belongs to resolve_jadx, not this function.
    """
    if frozen():
        return shutil.which(name) or ""
    selected = _configured_tool(name)
    if selected is not None:
        return selected
    if name in _FRIDA_TOOLS:
        local = _python_scripts_dir() / (name + (".exe" if os.name == "nt" else ""))
        if local.is_file() and os.access(local, os.X_OK):
            return str(local)
    return shutil.which(name) or ""


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
    源码：显式工具配置，再回退 PATH。
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
    return executable_path("adb")


def frida_invocation(tool: str) -> list[str]:
    """返回调用某内置工具的命令前缀（argv 列表）。

    frozen：``[sys.executable, tool]``（经 dispatch 入口自调用内置库）；
    源码：显式配置 > 当前解释器脚本目录 > PATH（缺则 ``[]``）。

    tool ∈ _FRIDA_TOOLS。未知名只记 warning（不抛），仍按规则返回。
    """
    if tool not in _FRIDA_TOOLS:
        logger.warning("[tools] 未知内置工具名：%s", tool)
    if frozen():
        return [sys.executable, tool]
    exe = executable_path(tool)
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
    0. 环境级工具配置中的绝对路径；配置失效不回退。
    1. PATH 上的 jadx（用户自管，与既有行为一致，不注入 JAVA_HOME）；
    2. 插件包 ``jadx-addon/``（独立下载随包自带 JRE）——返回包内 jadx.bat 完整路径，并把
       ``JAVA_HOME`` 注入指向包内 JRE，使**无系统 Java** 的机器也能跑（GUI 一键导入即用）。

    完整路径而非裸名：Windows 上 jadx 是 .bat，裸名经 subprocess 启动会 WinError 2。
    """
    selected = _configured_tool("jadx")
    if selected is not None:
        return ([selected], {}) if selected else None
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


# ---- 重打包工具链（apksigner / zipalign / keytool）：PATH 优先，仿 resolve_jadx 返回 (argv, env) ----


def resolve_apksigner() -> tuple[list[str], dict[str, str]] | None:
    """解析 apksigner（Android SDK build-tools；重签名）：PATH 优先。返回 (argv, 注入 env) 或 None。

    完整路径而非裸名：Windows 上 apksigner 是 .bat，shutil.which 已解析为全名，避免 subprocess WinError 2。
    """
    exe = shutil.which("apksigner")
    return ([exe], {}) if exe else None


def has_apksigner() -> bool:
    """apksigner 是否可用。"""
    return resolve_apksigner() is not None


def resolve_zipalign() -> tuple[list[str], dict[str, str]] | None:
    """解析 zipalign（Android SDK build-tools；4 字节对齐）：PATH 优先。返回 (argv, env) 或 None。"""
    exe = shutil.which("zipalign")
    return ([exe], {}) if exe else None


def has_zipalign() -> bool:
    """zipalign 是否可用。"""
    return resolve_zipalign() is not None


def resolve_keytool() -> tuple[list[str], dict[str, str]] | None:
    """解析 keytool（JDK 自带；首次生成 debug keystore）：PATH 优先，回退 ``JAVA_HOME/bin``。"""
    exe = shutil.which("keytool")
    if exe:
        return ([exe], {})
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        cand = Path(java_home) / "bin" / ("keytool.exe" if os.name == "nt" else "keytool")
        if cand.is_file():
            return ([str(cand)], {})
    return None


def has_keytool() -> bool:
    """keytool 是否可用。"""
    return resolve_keytool() is not None


def aapt_path() -> str:
    """aapt / aapt2 可执行路径（Android SDK build-tools）——PATH 优先，优选 aapt2。

    用途：给清单包名做“第二意见”交叉校验（``aapt dump badging``，口径同 Android 安装/运行时），
    对抗构造 AndroidManifest 让 androguard 静默 mis-parse 的“清单投毒”。找不到 → ""（不抛，
    调用方据此降级为纯 sanity 信号，不改判）。
    """
    return shutil.which("aapt2") or shutil.which("aapt") or ""


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


def adb_server_running(host: str = "127.0.0.1", port: int = 5037, timeout: float = 0.3) -> bool:
    """判本机是否已有 adb server 在监听（默认 127.0.0.1:5037）——**无副作用**：只 TCP 连一下，
    绝不 ``start-server``。用于命令起手判 adb server 归属：起手已在跑 = 外部/先前存在、收尾不该杀。绝不抛。
    """
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
    except Exception:
        logger.exception("[tools] 探测 adb server 监听失败（保守视作在跑，收尾不杀）")
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
    return _has_module("frida_tools") if frozen() else bool(frida_invocation("frida"))


def has_frida_dexdump() -> bool:
    """frida-dexdump 可用。frozen：看 frida_dexdump 是否在包内；源码：PATH 有 frida-dexdump。"""
    return _has_module("frida_dexdump") if frozen() else bool(frida_invocation("frida-dexdump"))


def has_mitmproxy() -> bool:
    """mitmproxy/mitmdump 可用。frozen：看 mitmproxy 是否在包内；源码：PATH 有 mitmproxy/mitmdump。"""
    if frozen():
        return _has_module("mitmproxy")
    return bool(frida_invocation("mitmproxy") or frida_invocation("mitmdump"))


__all__ = [
    "frozen",
    "aapt_path",
    "adb_path",
    "frida_invocation",
    "has_adb",
    "has_frida",
    "has_frida_dexdump",
    "has_mitmproxy",
    "kill_adb_server",
]
