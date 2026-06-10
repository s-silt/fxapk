"""Mach-O / 任意二进制的朴素可打印 ASCII 字符串提取（纯字节扫描，零依赖）。

用途：iOS IPA 的主二进制（Mach-O）不是 DEX，没有现成的"字符串池"。本模块朴素扫连续可打印
ASCII 串，把主二进制里可读的 URL / 域名 / key 等当作"字符串"喂给 endpoints/contacts 等字符串
型 analyzer（弥补 IPA 无 DEX 字符串池）。

不做 Mach-O 结构解析（不依赖 macholib 等）：只逐字节扫 ``[0x20,0x7e]`` 连续段。

FairPlay 加密：App Store 分发的 IPA 主二进制经 FairPlay 加密，扫出来基本是高熵乱码、几乎没有
可读串；本模块据此**优雅降级**——可读串数量低于阈值即判为加密/不可读，返回空列表（不报错、
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
    """从二进制字节里提取连续可打印 ASCII 串（长度 >= ``min_len``）。

    Args:
        data: 二进制内容（Mach-O 主二进制 / 任意文件）。
        min_len: 单条串最短长度。
        max_strings: 数量上限（超过即停，记 warning）。

    Returns:
        可读字符串列表（去重前的原始顺序）；空输入 / 加密不可读（可读串 < 阈值）→ ``[]``。
        绝不抛。
    """
    if not data:
        return []
    out: list[str] = []
    cur: list[int] = []
    try:
        for b in data:
            if b in _PRINTABLE:
                cur.append(b)
                continue
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", errors="ignore"))
                if len(out) >= max_strings:
                    logger.warning("[macho] 可读串超上限 %d，截断", max_strings)
                    cur = []
                    break
            cur = []
        # 收尾：末段未被非可打印字节终结。
        if cur and len(cur) >= min_len and len(out) < max_strings:
            out.append(bytes(cur).decode("ascii", errors="ignore"))
    except Exception:  # noqa: BLE001 — 字符串提取失败不得炸主流程
        logger.exception("[macho] 字符串提取异常，返回已提取部分")
        return out

    # 可读串过少 → 多半 FairPlay 加密 / 非文本二进制：不把乱码当线索，返回空。
    if len(out) < _ENCRYPTED_BELOW:
        logger.info("[macho] 可读串仅 %d 条（< %d），疑似加密/非文本二进制，按空处理", len(out), _ENCRYPTED_BELOW)
        return []
    return out


__all__ = ["scan_ascii_strings"]
