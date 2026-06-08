"""动态能力探测助手：设备 / Frida / mitmproxy 是否可用。

设计铁律：
- 纯 subprocess + shutil.which，全部 try/except + logging + 超时，**绝不抛异常**，
  探测不到一律返回安全默认值（False / 空列表）。
- 本模块**不得 import apkscan.core.registry**（registry 反过来 import 本模块，避免循环导入）。

供 registry.detect_capabilities 与 apkscan.dynamic（unpack/capture）模块共用。
"""

from __future__ import annotations

import logging
import shutil
import subprocess

from apkscan.core import tools

logger = logging.getLogger(__name__)

# adb / frida 子命令的默认超时（秒）。设备无响应时不应卡死主流程。
_DEFAULT_TIMEOUT = 5.0


def _run(args: list[str], timeout: float = _DEFAULT_TIMEOUT) -> subprocess.CompletedProcess | None:
    """运行外部命令并捕获输出。任何失败（缺命令/超时/非零退出/异常）返回 None，绝不抛。

    ``adb`` 走 tools.adb_path()（frozen 用同目录随包 adb.exe，源码用 PATH）；
    其它命令仍走 shutil.which。
    """
    if not args:
        exe = None
    elif args[0] == "adb":
        exe = tools.adb_path() or None
    else:
        exe = shutil.which(args[0])
    if exe is None:
        logger.debug("命令不在 PATH，跳过：%s", args[0] if args else "(空)")
        return None
    try:
        return subprocess.run(
            [exe, *args[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("命令超时（%ss）：%s", timeout, " ".join(args))
        return None
    except Exception:
        logger.exception("命令执行异常：%s", " ".join(args))
        return None


# ---------------------------------------------------------------------------
# 设备（adb）
# ---------------------------------------------------------------------------


def adb_devices() -> list[str]:
    """解析 `adb devices`，返回**在线**设备序列号列表（状态为 device 的行）。

    adb 缺失 / 未启动 / 解析失败 → 返回空列表（不抛）。
    """
    proc = _run(["adb", "devices"])
    if proc is None or proc.returncode != 0:
        if proc is not None:
            logger.debug("adb devices 非零退出：%s", proc.returncode)
        return []

    serials: list[str] = []
    try:
        lines = proc.stdout.splitlines()
        for line in lines[1:]:  # 首行是 "List of devices attached"
            line = line.strip()
            if not line or "\t" not in line:
                continue
            serial, state = line.split("\t", 1)
            serial = serial.strip()
            state = state.strip()
            # 只收在线设备；忽略 offline / unauthorized / no permissions 等。
            if serial and state == "device":
                serials.append(serial)
    except Exception:
        logger.exception("解析 adb devices 输出失败")
        return []
    return serials


def has_device() -> bool:
    """是否有至少一台在线 adb 设备。"""
    return bool(adb_devices())


# ---------------------------------------------------------------------------
# 工具是否安装（PATH 探测）
# ---------------------------------------------------------------------------


def has_frida() -> bool:
    """frida CLI 是否可用（frozen 看内置 frida_tools；源码看 PATH）。"""
    return tools.has_frida()


def has_frida_dexdump() -> bool:
    """frida-dexdump 是否可用（frozen 看内置 frida_dexdump；源码看 PATH）。"""
    return tools.has_frida_dexdump()


def has_mitmproxy() -> bool:
    """mitmproxy（或 mitmdump）是否可用（frozen 看内置 mitmproxy；源码看 PATH）。"""
    return tools.has_mitmproxy()


# ---------------------------------------------------------------------------
# frida-server 运行状态（best-effort）
# ---------------------------------------------------------------------------


def frida_server_running(serial: str | None = None) -> bool:
    """best-effort 判断目标设备上 frida-server 进程是否在跑。

    通过 `adb [-s serial] shell ps` 查找 frida-server。查不到 / adb 缺失 / 异常
    一律返回 False（不报错）。
    """
    args = ["adb"]
    if serial:
        args += ["-s", serial]
    args += ["shell", "ps", "-A"]

    proc = _run(args)
    if proc is None or proc.returncode != 0:
        # 部分 Android 版本 `ps -A` 不支持，回退到 `ps`。
        fallback = ["adb"]
        if serial:
            fallback += ["-s", serial]
        fallback += ["shell", "ps"]
        proc = _run(fallback)
    if proc is None or proc.returncode != 0:
        # 探测本身没成功（adb 缺失 / 超时 / shell 非零）——这与"确认 frida-server
        # 没在跑"不同。返回 False 之外记一条 warning，避免排障被误导到错误方向。
        logger.warning(
            "无法确认 frida-server 运行状态（adb 不可用 / 超时 / ps 失败）；"
            "按未运行处理，但实际可能是探测失败"
        )
        return False

    try:
        return "frida-server" in proc.stdout or "frida_server" in proc.stdout
    except Exception:
        logger.exception("解析 ps 输出查找 frida-server 失败")
        return False
