# -*- coding: utf-8 -*-
"""富化本地缓存的安全根与有界读取。

默认缓存根落在**每用户缓存目录**（Windows: ``%LOCALAPPDATA%/fxapk/cache``；
POSIX: ``$XDG_CACHE_HOME/fxapk`` 或 ``~/.cache/fxapk``），绝不落在分析工作目录——
工作目录里的 ``.apkscan_cache`` 可以被样本仓库 / 共享目录预置投毒条目。
``FXAPK_CACHE_DIR`` 可显式覆盖（测试隔离 / 受控部署）。
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ENV_VAR = "FXAPK_CACHE_DIR"

#: 缓存 JSON 解析前的大小硬帽。富化缓存正常远小于此值；超大文件直接判损坏丢弃，
#: 不给 ``json.loads`` 分配无界内存（种植的巨型缓存文件曾是投毒放大器）。
MAX_CACHE_FILE_BYTES = 8 * 1024 * 1024


def cache_root() -> Path:
    """富化缓存根目录：FXAPK_CACHE_DIR 覆盖 > 每用户缓存目录。"""
    override = (os.environ.get(ENV_VAR) or "").strip()
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "fxapk" / "cache"
    xdg = (os.environ.get("XDG_CACHE_HOME") or "").strip()
    return (Path(xdg) if xdg else Path.home() / ".cache") / "fxapk"


def read_cache_json(path: Path, *, limit: int = MAX_CACHE_FILE_BYTES) -> dict[str, Any]:
    """有界读缓存 JSON：非常规文件/符号链接/超限/坏 JSON/非 dict 顶层一律返回 ``{}``。

    读取本身也有界（``limit + 1`` 字节即停），stat 之后文件被撑大不会击穿内存帽。
    """
    try:
        if path.is_symlink() or not path.is_file():
            return {}
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            logger.warning("富化缓存超过大小上限，忽略：%s（>%d 字节）", path, limit)
            return {}
        data = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 — 缓存损坏/不可读一律按无缓存处理，不炸富化
        logger.warning("富化缓存读取/解析失败，忽略：%s", path, exc_info=True)
        return {}
    if not isinstance(data, dict):
        logger.warning("富化缓存顶层非 dict，忽略：%s", path)
        return {}
    return data
