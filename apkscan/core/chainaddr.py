"""链上钱包地址校验 + 判链（纯函数、零第三方依赖）。

涉诈资金流最硬的物证是收款钱包地址——一个地址即可上链做钱包聚类→归集点→落地交易所，
对接 TronScan/Etherscan，向交易所/Tether 申请冻结与调 KYC。

本模块只做**校验和**与**判链**，不产 Lead（那是 analyzer 层的事）：

- ``validate_address(s)``：对单个候选串判链 + 校验和，通过返回 :class:`ChainAddress`，否则 None。
- ``find_addresses(text)``：宽松正则扫候选 + 逐个校验过滤，去重保序。

★ 设计要点：**校验和是把误报砍到可用的命门**。随机 hex / base58 标识符解码后校验和几乎
不可能对上，故敢把误报高的 BTC legacy(1.../3...) 重新纳入。各链算法：

- TRON / BTC legacy：Base58Check（双 SHA256 取前 4 字节比对）。
- EVM(ETH/BSC/Polygon… 同形态)：EIP-55 大小写校验和（需 **Keccak-256**，非 SHA3-256，
  两者仅 padding 字节不同 0x01 vs 0x06；标准库只有 SHA3，故纯 Python 自实现）。混合大小写
  必须过 EIP-55；**全小写/全大写无法校验 → 仍判合法但 checksum_verified=False（低可信，不一票杀）**。
- BTC bech32 / bech32m：BIP-173 / BIP-350 polymod。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

__all__ = ["ChainAddress", "keccak256", "validate_address", "find_addresses"]


@dataclass(frozen=True)
class ChainAddress:
    """一个通过校验的链上地址。chain ∈ {TRON, EVM, BTC}；EVM 全小写时 checksum_verified=False。"""

    value: str
    chain: str
    checksum_verified: bool


# ---------------------------------------------------------------------------
# Keccak-256（纯 Python；以太坊 EIP-55 用，≠ 标准库 sha3_256）
# ---------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1
_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# rho 旋转量 _KECCAK_ROT[x][y]（标准 Keccak）。
_KECCAK_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotl64(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f1600(a: list[list[int]]) -> None:
    """就地跑 Keccak-f[1600] 置换（24 轮 theta/rho/pi/chi/iota）。a 为 5×5 lane 数组。"""
    for rc in _KECCAK_RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(a[x][y], _KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Keccak-256（以太坊版）。rate=136 字节，pad10*1 用 Keccak 域字节 0x01（SHA3 才是 0x06）。"""
    rate = 136
    a = [[0] * 5 for _ in range(5)]
    msg = bytearray(data)
    msg.append(0x01)  # pad10*1 起始 1 比特（Keccak 域，非 SHA3 的 0x06）
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] ^= 0x80  # pad10*1 结尾 1 比特
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):  # 17 lanes
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            a[i % 5][i // 5] ^= lane
        _keccak_f1600(a)
    out = bytearray()
    for i in range(4):  # 256 bit = 4 lanes
        out += a[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


# ---------------------------------------------------------------------------
# Base58Check（TRON / BTC legacy）
# ---------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _b58decode(s: str) -> bytes | None:
    num = 0
    for ch in s:
        idx = _B58.find(ch)
        if idx < 0:
            return None
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))  # 前导 '1' → 前导零字节
    return b"\x00" * pad + raw


def _b58check_payload(s: str) -> bytes | None:
    """解码 Base58Check，校验和通过则返回 payload（含版本字节），否则 None。"""
    raw = _b58decode(s)
    if raw is None or len(raw) < 5:
        return None
    data, chk = raw[:-4], raw[-4:]
    if _sha256(_sha256(data))[:4] != chk:
        return None
    return data


# ---------------------------------------------------------------------------
# Bech32 / Bech32m（BTC SegWit / Taproot）
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_verify(s: str) -> bool:
    """校验 bech32/bech32m 串（含 hrp）。要求全小写或全大写、字符合法、polymod 命中常量。"""
    if any(ord(c) < 33 or ord(c) > 126 for c in s):
        return False
    if s.lower() != s and s.upper() != s:  # 不得大小写混合
        return False
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return False
    hrp, data = s[:pos], []
    for c in s[pos + 1:]:
        d = _BECH32_CHARSET.find(c)
        if d < 0:
            return False
        data.append(d)
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    poly = _bech32_polymod(expand + data)
    return poly in (1, _BECH32M_CONST)


# ---------------------------------------------------------------------------
# EVM EIP-55
# ---------------------------------------------------------------------------

_EVM_RE = re.compile(r"0x[0-9a-fA-F]{40}")


def _eip55_ok(body: str) -> bool:
    """混合大小写 EVM 地址（40 hex，无 0x）是否符合 EIP-55 校验和。"""
    digest = keccak256(body.lower().encode()).hex()
    for i, ch in enumerate(body):
        if ch.isalpha():
            should_upper = int(digest[i], 16) >= 8
            if should_upper and not ch.isupper():
                return False
            if not should_upper and not ch.islower():
                return False
    return True


# ---------------------------------------------------------------------------
# 对外：判链 + 校验
# ---------------------------------------------------------------------------


def validate_address(s: str) -> ChainAddress | None:
    """对单个候选串判链 + 校验和。通过返回 ChainAddress，否则 None。绝不抛。"""
    if not s:
        return None
    try:
        if _EVM_RE.fullmatch(s):
            body = s[2:]
            if body == body.lower() or body == body.upper():
                return ChainAddress(s, "EVM", False)  # 全小写/全大写无法校验 → 低可信
            return ChainAddress(s, "EVM", True) if _eip55_ok(body) else None
        if s[0] == "T" and len(s) == 34:
            data = _b58check_payload(s)
            if data is not None and len(data) == 21 and data[0] == 0x41:
                return ChainAddress(s, "TRON", True)
            return None
        if s[:3].lower() == "bc1":
            if _bech32_verify(s):
                return ChainAddress(s.lower(), "BTC", True)
            return None
        if s[0] in ("1", "3") and 26 <= len(s) <= 35:
            data = _b58check_payload(s)
            if data is not None and len(data) == 21 and data[0] in (0x00, 0x05):
                return ChainAddress(s, "BTC", True)
            return None
    except (ValueError, IndexError):
        return None
    return None


_CANDIDATE_RES = (
    re.compile(r"0x[0-9a-fA-F]{40}"),
    re.compile(r"T[1-9A-HJ-NP-Za-km-z]{33}"),
    re.compile(r"bc1[ac-hj-np-z02-9]{25,87}"),
    re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}"),
)


def find_addresses(text: str) -> list[ChainAddress]:
    """从文本扫所有候选地址并过校验和，去重保序返回。校验失败的随机串被滤掉。"""
    seen: dict[str, ChainAddress] = {}
    for pat in _CANDIDATE_RES:
        for m in pat.finditer(text):
            addr = validate_address(m.group(0))
            if addr is not None and addr.value not in seen:
                seen[addr.value] = addr
    return list(seen.values())
