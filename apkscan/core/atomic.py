"""apkscan.core.atomic — 主证据文件的原子写。

回灌层（pcap_ingest / probe_ingest）把带外线索合并进 report.json 时，若在 ``write_text``
中途（序列化后半程、磁盘满、进程被杀）失败，直接覆写会把主证据文件留成**半截坏 JSON**——
下一次读取即崩、取证链断裂。本模块提供 :func:`atomic_write_text`：同目录写临时文件
（带 pid+uuid 后缀，避免多进程互踩）→ ``os.replace`` 原子替换。写失败时抛出，让调用方
（回灌层已有 try/except + logging）能感知失败并保底 return 0；**关键不变式：无论成功或失败，
目标文件要么是旧内容完整、要么是新内容完整，绝不留半截。**

设计对齐 ``apkscan/track/ledger.py`` 与 ``apkscan/dynamic/ledger.py`` 的原子落盘习惯。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import uuid4

logger = logging.getLogger(__name__)


def atomic_write_text(path: str | os.PathLike[str], data: str) -> None:
    """把 ``data`` 原子写入 ``path``（UTF-8）：同目录 tmp → ``os.replace`` 覆盖。

    临时名带 ``pid+uuid`` 后缀：多进程并发写同一文件时各写各的 ``.tmp``，再各自
    ``os.replace``（同目录、原子，最后一个胜出但永远是完整文件）。写 tmp 失败时清理残留的
    半截临时文件后重新抛出——目标文件此刻尚未被触碰，保持旧内容完整。

    Args:
        path: 目标文件路径。父目录不存在会先创建。
        data: 要写入的文本。

    Raises:
        OSError: 写临时文件或 ``os.replace`` 失败时抛出（清理 tmp 后原样上抛，不静默吞）。
    """
    target = Path(path)
    tmp = target.with_suffix(target.suffix + f".{os.getpid()}.{uuid4().hex}.tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # newline=""：禁用文本模式的换行翻译。否则 Windows 把 "\n" 写成 "\r\n"，落盘字节 ≠ 入参
        # 字节——破坏证据字节保真（corpus add 原样存证）、且让同一内容跨平台产生不同 sha（与 #105 抓
        # 的 frida JS CRLF 同类）。恒按 data 原样字节落盘，跨平台确定。
        tmp.write_text(data, encoding="utf-8", newline="")
        os.replace(tmp, target)  # 同目录原子替换，不留半截坏文件
    except OSError:
        # 目标文件在 os.replace 成功前从未被触碰，故此刻仍是旧内容完整。
        # 清理可能残留的半截临时文件后把异常上抛，交由调用方保底。
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            # 清理失败不掩盖原始写异常（tmp 残留无害，不覆盖主文件），但记一条便于排查磁盘态。
            logger.debug("[atomic] 清理临时文件失败：%s", tmp, exc_info=True)
        raise


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes) -> None:
    """把 ``data`` 原子写入 ``path``（二进制）：同目录 tmp → ``os.replace`` 覆盖。

    与 :func:`atomic_write_text` 同一"要么旧内容完整、要么新内容完整、绝不留半截"不变式，用于落盘取证
    制品的原始字节（如下载的远程配置对象）——字节原样保真（不经文本换行翻译，跨平台 sha 一致）。

    Args:
        path: 目标文件路径。父目录不存在会先创建。
        data: 要写入的原始字节。

    Raises:
        OSError: 写临时文件或 ``os.replace`` 失败时抛出（清理 tmp 后原样上抛，不静默吞）。
    """
    target = Path(path)
    tmp = target.with_suffix(target.suffix + f".{os.getpid()}.{uuid4().hex}.tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(data)
        os.replace(tmp, target)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            logger.debug("[atomic] 清理临时文件失败：%s", tmp, exc_info=True)
        raise
