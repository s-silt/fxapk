"""图标 / favicon mmh3 指纹 —— 测绘引擎 pivot 的纯函数实现（零第三方依赖）。

杀猪盘换皮但复用同一套后台前端 / 图标。一个 favicon hash 能把单包后端扩成同团伙站群：
办案人把 hash 丢 FOFA/Quake/Shodan/Censys 反查同 hash 的全部公网 IP/域名（后台面板与
钓鱼站群），再向机房/IDC 调服务器租用主体。也是团伙聚类的强连边键。

本模块只提供两个纯函数：
- ``mmh3_x86_32``：纯 Python MurmurHash3 x86 32-bit，返回**有符号** 32-bit int
  （与 Shodan/FOFA 的 favicon hash 口径一致）。
- ``favicon_hash``：Shodan/FOFA 口径 = ``mmh3_x86_32(base64.encodebytes(raw))``。

★ 经典踩坑点：必须用 ``base64.encodebytes``（RFC2045 每 76 字符插 ``\\n``），
  不是 ``base64.b64encode``（无换行）——否则算出来的 hash 与测绘平台对不上，
  丢过去的查询串就是废线索。
"""

from __future__ import annotations

import base64

__all__ = ["mmh3_x86_32", "favicon_hash"]

# MurmurHash3 x86_32 常量。
_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_MASK32 = 0xFFFFFFFF


def _rotl32(x: int, r: int) -> int:
    """32-bit 循环左移。"""
    return ((x << r) | (x >> (32 - r))) & _MASK32


def _fmix32(h: int) -> int:
    """MurmurHash3 的 32-bit 终结混淆（finalization mix）。"""
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & _MASK32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & _MASK32
    h ^= h >> 16
    return h


def mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """纯 Python 实现 MurmurHash3 x86 32-bit，返回**有符号** 32-bit int。

    与 C 实现 / Python ``mmh3.hash`` 口径一致（seed=0 时 ``b""→0``、``b"foo"→-156908512``）。
    这是 Shodan/FOFA favicon hash 所用的有符号口径，办案查询串依赖此值正确。
    """
    length = len(data)
    h1 = seed & _MASK32

    # body：每 4 字节一块，小端读取。
    nblocks = length // 4
    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4 : i * 4 + 4], "little")
        k1 = (k1 * _C1) & _MASK32
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK32

        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & _MASK32

    # tail：剩余 0~3 字节。
    tail_index = nblocks * 4
    k1 = 0
    remaining = length & 3
    if remaining == 3:
        k1 ^= data[tail_index + 2] << 16
    if remaining >= 2:
        k1 ^= data[tail_index + 1] << 8
    if remaining >= 1:
        k1 ^= data[tail_index]
        k1 = (k1 * _C1) & _MASK32
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK32
        h1 ^= k1

    # finalization。
    h1 ^= length & _MASK32
    h1 = _fmix32(h1)

    # 转有符号 32-bit（与 Shodan/FOFA 一致）。
    if h1 & 0x80000000:
        return h1 - 0x100000000
    return h1


def favicon_hash(raw: bytes) -> int:
    """Shodan/FOFA 口径的 favicon hash = ``mmh3_x86_32(base64.encodebytes(raw))``。

    ★ 用 ``base64.encodebytes``（每 76 字符插 ``\\n``、末尾带 ``\\n``）而非 ``b64encode``。
    """
    return mmh3_x86_32(base64.encodebytes(raw))
