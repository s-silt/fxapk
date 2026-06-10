"""Mach-O / 任意二进制的朴素可打印字符串提取（纯字节扫描，零依赖）。

用途：iOS IPA 的主二进制（Mach-O）不是 DEX，没有现成的"字符串池"。本模块朴素扫连续可打印
串，把主二进制里可读的 URL / 域名 / key 等当作"字符串"喂给 endpoints/contacts 等字符串型
analyzer（弥补 IPA 无 DEX 字符串池）。

提取两类（不做 Mach-O 结构解析，不依赖 macholib）：
  1. **ASCII**：逐字节扫 ``[0x20,0x7e]`` 连续段（C 字符串）。
  2. **UTF-16LE 对齐串**：iOS 的 CFString/``__cfstring`` 常以 UTF-16LE 存（每字符后跟 0x00）；
     扫 ``(可打印, 0x00)`` 对齐对，捞回纯 ASCII 扫描会漏掉的入口 URL/域名。

FairPlay 加密：App Store 分发的 IPA 主二进制经 FairPlay 加密，扫出来基本是高熵乱码、几乎没有
可读串；本模块据此**优雅降级**——两类合计可读串低于阈值即判为加密/不可读，返回空列表（不报错、
不把乱码当线索引入误报）。涉诈样本走超级签/企业签侧载，通常**不加密**，可读。
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

#: 可打印 ASCII 范围（含空格 0x20 到 ~ 0x7e）。
_PRINTABLE = frozenset(range(0x20, 0x7F))

#: 单条字符串最短长度（短于此的连续段噪音多，丢弃）。
_MIN_LEN = 4

#: 单次提取的字符串数量上限（防超大二进制扫出海量串拖慢/撑爆下游）。
_MAX_STRINGS = 200_000

#: 判定"加密/不可读"的可读串数量阈值：低于此视为 FairPlay 加密或非文本二进制 → 返回空。
_ENCRYPTED_BELOW = 10


def scan_ascii_strings(
    data: bytes,
    *,
    min_len: int = _MIN_LEN,
    max_strings: int = _MAX_STRINGS,
) -> list[str]:
    """从二进制字节里提取连续可打印串（ASCII + UTF-16LE，长度 >= ``min_len``）。

    Args:
        data: 二进制内容（Mach-O 主二进制 / 任意文件）。
        min_len: 单条串最短长度。
        max_strings: 数量上限（超过即停，记 warning）。

    Returns:
        可读字符串列表（保序去重）；空输入 / 加密不可读（合计可读串 < 阈值）→ ``[]``。绝不抛。
    """
    if not data:
        return []
    runs: list[str] = []
    try:
        runs.extend(_scan_ascii_runs(data, min_len, max_strings))
        if len(runs) < max_strings:
            runs.extend(_scan_utf16le_runs(data, min_len, max_strings - len(runs)))
    except Exception:  # noqa: BLE001 — 字符串提取失败不得炸主流程
        logger.exception("[macho] 字符串提取异常，返回已提取部分")

    # 保序去重（ASCII 与 UTF-16 可能扫到同一串）。
    seen: set[str] = set()
    out: list[str] = []
    for s in runs:
        if s not in seen:
            seen.add(s)
            out.append(s)

    # 可读串过少 → 多半 FairPlay 加密 / 非文本二进制：不把乱码当线索，返回空。
    if len(out) < _ENCRYPTED_BELOW:
        logger.info("[macho] 可读串仅 %d 条（< %d），疑似加密/非文本二进制，按空处理", len(out), _ENCRYPTED_BELOW)
        return []
    return out


def _scan_ascii_runs(data: bytes, min_len: int, limit: int) -> list[str]:
    """逐字节扫连续可打印 ASCII 段（C 字符串）。"""
    out: list[str] = []
    cur: list[int] = []
    for b in data:
        if b in _PRINTABLE:
            cur.append(b)
            continue
        if len(cur) >= min_len:
            out.append(bytes(cur).decode("ascii", errors="ignore"))
            if len(out) >= limit:
                logger.warning("[macho] ASCII 可读串超上限 %d，截断", limit)
                return out
        cur = []
    if cur and len(cur) >= min_len and len(out) < limit:
        out.append(bytes(cur).decode("ascii", errors="ignore"))
    return out


def _scan_utf16le_runs(data: bytes, min_len: int, limit: int) -> list[str]:
    """扫 UTF-16LE 对齐的可打印串：``(可打印 ASCII, 0x00)`` 连续对（iOS CFString 常见形态）。

    不匹配时步进 1（而非 2）以容忍起始奇偶对齐；``limit`` 封顶防超大二进制扫爆。
    """
    out: list[str] = []
    cur: list[int] = []
    n = len(data)
    i = 0
    while i + 1 < n:
        lo = data[i]
        if data[i + 1] == 0x00 and lo in _PRINTABLE:
            cur.append(lo)
            i += 2
            continue
        if len(cur) >= min_len:
            out.append(bytes(cur).decode("ascii", errors="ignore"))
            if len(out) >= limit:
                logger.warning("[macho] UTF-16 可读串超上限 %d，截断", limit)
                return out
        cur = []
        i += 1
    if cur and len(cur) >= min_len and len(out) < limit:
        out.append(bytes(cur).decode("ascii", errors="ignore"))
    return out


__all__ = ["scan_ascii_strings"]
