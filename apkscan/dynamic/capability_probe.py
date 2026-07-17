"""抓包能力**探测** —— 探本次抓包实际可用的能力（主机侧工具 + 设备侧 tcpdump/root）。

与 [capabilities.py] 分工：本模块碰 adb / 文件系统 IO（best-effort、绝不抛），产出**能力集**；
capabilities.resolve 是纯逻辑，消费这个能力集做模式门控 / 降级判断。doctor 分层体检、capture 起手
门控共用本探测入口，保证"体检说环境行"与"抓包真能跑"用同一份能力事实。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from apkscan.dynamic import capabilities as _caps

logger = logging.getLogger(__name__)

#: 设备无 tcpdump 时可 push 的二进制路径（与 capture._TCPDUMP_ENV 同名，须与设备 ABI 匹配）。
_TCPDUMP_ENV = "FXAPK_TCPDUMP_BIN"


def probe_available(serial: str | None = None) -> set[str]:
    """探测本次抓包实际可用的能力集（主机侧工具 + 设备侧 tcpdump/root）。碰 adb IO、best-effort、绝不抛。

    主机侧：adb / frida / mitmproxy / tshark。设备侧（仅有在线设备时探）：root 抓包权限、tcpdump 可用。
    ★ca_trusted（mitm CA 是否已装进设备信任库）暂不探——保守视为不满足，使 mitm 明文层保守判不可达，
    不误报代理明文可用（精确探测留后续 slice）。
    """
    from apkscan.core import device, tools

    caps: set[str] = set()
    try:
        if tools.has_adb():
            caps.add(_caps.CAP_ADB)
        if device.has_frida():
            caps.add(_caps.CAP_FRIDA)
        if device.has_mitmproxy():
            caps.add(_caps.CAP_MITMPROXY)
        if _has_tshark():
            caps.add(_caps.CAP_TSHARK)
        if device.has_device():
            caps.add(_caps.CAP_DEVICE)
            caps |= _probe_device_side(serial)
    except Exception:
        logger.exception("[capability_probe] 能力探测异常（返回已探到的部分）")
    return caps


def _has_tshark() -> bool:
    """主机侧 tshark 是否可用（keylog 深度解密需要）。探测失败按不可用。"""
    try:
        from apkscan.dynamic.tshark_backend import has_tshark

        return has_tshark()
    except Exception:
        logger.debug("[capability_probe] tshark 探测失败，按不可用", exc_info=True)
        return False


def _probe_device_side(serial: str | None) -> set[str]:
    """探设备侧能力（root 抓包权限 / tcpdump 可用）。需 adb 到设备，best-effort、绝不抛。

    复用 provision._adb_root_shell（adbd-root 直执 / 多形态 su 兜底，同 floor pcap 起动逻辑）。
    """
    from apkscan.dynamic import provision

    caps: set[str] = set()
    try:
        if provision._adb_root_shell('[ "$(id -u)" = 0 ]', serial):
            caps.add(_caps.CAP_ROOT_CAPTURE)
        # 设备 tcpdump：已装（command -v）→ 直接可用；否则配了 FXAPK_TCPDUMP_BIN 且文件在 → 可 push。
        if provision._adb_root_shell("command -v tcpdump >/dev/null 2>&1", serial):
            caps.add(_caps.CAP_DEVICE_TCPDUMP)
        else:
            src = os.environ.get(_TCPDUMP_ENV)
            if src and Path(src).is_file():
                caps.add(_caps.CAP_DEVICE_TCPDUMP)  # 可 push 上去
    except Exception:
        logger.exception("[capability_probe] 设备侧能力探测异常")
    return caps
