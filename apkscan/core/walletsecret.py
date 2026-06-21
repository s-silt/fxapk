"""钱包私钥 / 助记词检测（纯函数、零第三方依赖）。

涉诈资金物证里，**私钥 / 助记词比地址更致命**——掌握即可直接转移 / 冻结资金、上链回溯
全部派生地址。本模块用 **BIP-39 校验和** 与 **Base58Check** 把误报砍到近零（随机文本
几乎不可能凑出合法校验和，延续 chainaddr「校验和是 FP 命门」的设计）：

- ``validate_mnemonic(words)``：单组词判 BIP-39（11bit/词 → ENT|CS，校验 CS=SHA256(ENT) 前缀）。
- ``find_mnemonics(text)``：在连续 BIP-39 词的 run 上滑窗试 12/15/18/21/24 词并过校验和。
- ``find_wif_keys(text)``：WIF 私钥（Base58Check，版本字节 0x80）。
- ``find_evm_privkey_candidates(text)``：EVM 裸私钥候选（0x+64hex）；**与哈希同形，需调用方
  上下文门控**（近邻有 私钥/助记词/mnemonic/seed 等才可采信），本函数只给候选 + 位置。
"""

from __future__ import annotations

import functools
import hashlib
import re
from dataclasses import dataclass

__all__ = [
    "WalletSecret",
    "load_wordlist",
    "validate_mnemonic",
    "find_mnemonics",
    "find_wif_keys",
    "find_evm_privkey_candidates",
]

# 助记词合法词数（BIP-39）。
_VALID_WORD_COUNTS = (12, 15, 18, 21, 24)
# 单段文本最多扫描的小写词数（防极端大文本拖慢；真实助记词远少于此）。
_MAX_TOKENS = 200_000
# 连续 BIP-39 词 run 超此长度 → 视为词表 / 字典资产（非助记词），整段跳过。
# 真实助记词 ≤24 词且被非词表词包围；超 48（2×最大词数）的连续 BIP-39 词几乎必是内嵌词表文件。
# 这一护栏同时杀掉「APK 自带 BIP-39 词表→数百误报」与超长 run 的性能放大（code review N1+N2）。
_MAX_RUN_WORDS = 48

_WORD_RE = re.compile(r"[a-z]+")
#: 空白匹配（C 级扫描，供 find_mnemonics 预筛数空白——比 Python 逐字符 isspace 累加快得多）。
_WS_RE = re.compile(r"\s")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# WIF：版本 0x80，主体 51~52 字符；否定后顾/前瞻避免截断更长 base58 串。
_WIF_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[5KL][1-9A-HJ-NP-Za-km-z]{50,51}(?![1-9A-HJ-NP-Za-km-z])")
# EVM 裸私钥候选：0x + 64 hex（与 sha256 等哈希同形 → 必须上下文门控）。
_EVM_PK_RE = re.compile(r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{64}(?![0-9a-fA-F])")


@dataclass(frozen=True)
class WalletSecret:
    """一个通过校验的钱包凭据。kind ∈ {mnemonic, wif, evm_privkey}。"""

    kind: str
    value: str
    detail: str = ""


@functools.lru_cache(maxsize=1)
def load_wordlist() -> tuple[dict[str, int], frozenset[str]]:
    """加载 BIP-39 英文词表 → (word→index, wordset)。缺文件 / 非 2048 词 → 空（降级不抛）。"""
    try:
        from importlib.resources import files

        data = (files("apkscan.rules") / "bip39_english.txt").read_text(encoding="utf-8")
    except Exception:
        return {}, frozenset()
    words = data.split()
    if len(words) != 2048:
        return {}, frozenset()
    return {w: i for i, w in enumerate(words)}, frozenset(words)


def validate_mnemonic(words: list[str]) -> bool:
    """判一组词是否为合法 BIP-39 助记词（词数合法 + 全在词表 + 校验和通过）。绝不抛。"""
    n = len(words)
    if n not in _VALID_WORD_COUNTS:
        return False
    index, _wordset = load_wordlist()
    if not index:
        return False
    bits = 0
    for w in words:
        idx = index.get(w)
        if idx is None:
            return False
        bits = (bits << 11) | idx
    total = n * 11
    ent_bits = total * 32 // 33  # ENT = total * 32/33；CS = ENT/32
    cs_bits = total - ent_bits
    ent = bits >> cs_bits
    cs = bits & ((1 << cs_bits) - 1)
    ent_bytes = ent.to_bytes(ent_bits // 8, "big")
    expected = hashlib.sha256(ent_bytes).digest()[0] >> (8 - cs_bits)
    return cs == expected


def find_mnemonics(text: str) -> list[WalletSecret]:
    """扫文本里的合法 BIP-39 助记词（连续词 run 上滑窗 + 校验和过滤）。去重保序，绝不抛。"""
    _index, wordset = load_wordlist()
    if not wordset or not text:
        return []
    # 性能预筛：12 词助记词至少 11 个空白分隔；空白不足直接跳过——杀掉海量无空白的 dex 类描述符串，
    # 避免对每条都 lower()+findall 分词。是安全超集（真助记词必含 ≥11 空白），行为不变。
    # ★ 提速：用 C 级 _WS_RE.finditer + 短路到 11，替代对每条字符串逐字符 Python 级 isspace 累加
    #   （实测 12 万条 dex 串 → 1170 万次 isspace 是分析器热点；无空白串现一次 C 扫即返回）。
    _ws = 0
    for _ in _WS_RE.finditer(text):
        _ws += 1
        if _ws >= 11:
            break
    if _ws < 11:
        return []
    tokens = _WORD_RE.findall(text.lower())
    if len(tokens) > _MAX_TOKENS:
        tokens = tokens[:_MAX_TOKENS]
    out: list[WalletSecret] = []
    seen: set[str] = set()
    n = len(tokens)
    i = 0
    while i < n:
        if tokens[i] not in wordset:
            i += 1
            continue
        j = i
        while j < n and tokens[j] in wordset:
            j += 1
        run = tokens[i:j]
        # 超长连续 BIP-39 词 run = 内嵌词表/字典资产，非助记词 → 整段跳过（杀词表误报 + 性能放大）。
        if len(run) <= _MAX_RUN_WORDS:
            for cnt in _VALID_WORD_COUNTS:
                for s in range(0, len(run) - cnt + 1):
                    cand = run[s : s + cnt]
                    # 互异度护栏：真助记词的词几近全互异（12 词≈12 个不同词）；而 CSS/常见英文词
                    # （day/color/top/left…恰在 BIP-39 词表内）凑出的窗口虽偶过校验和，却只有 3-4 个
                    # 不同词在重复 → 互异度 <2/3 滤掉（真样本 HuaCai uni-app JS 的实测误报根因）。
                    if (
                        len(set(cand)) * 3 >= cnt * 2
                        and validate_mnemonic(cand)
                    ):
                        phrase = " ".join(cand)
                        if phrase not in seen:
                            seen.add(phrase)
                            out.append(WalletSecret("mnemonic", phrase, f"{cnt}-word BIP-39"))
        i = j
    return out


def _b58check_payload(s: str) -> bytes | None:
    num = 0
    for ch in s:
        idx = _B58.find(ch)
        if idx < 0:
            return None
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    raw = b"\x00" * pad + raw
    if len(raw) < 5:
        return None
    data, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] != chk:
        return None
    return data


def find_wif_keys(text: str) -> list[WalletSecret]:
    """扫 WIF 比特币私钥（Base58Check，版本字节 0x80）。去重保序，绝不抛。"""
    out: list[WalletSecret] = []
    seen: set[str] = set()
    for m in _WIF_RE.finditer(text):
        s = m.group(0)
        if s in seen:
            continue
        payload = _b58check_payload(s)
        # payload = 0x80 + 32 字节私钥 (+ 可选 0x01 压缩标志)，故 33 或 34 字节。
        if payload is not None and len(payload) in (33, 34) and payload[0] == 0x80:
            seen.add(s)
            out.append(WalletSecret("wif", s, "WIF private key"))
    return out


def find_evm_privkey_candidates(text: str) -> list[tuple[str, int, int]]:
    """EVM 裸私钥候选 (value, start, end)。与哈希同形 → 调用方须做上下文门控后才可采信。"""
    return [(m.group(0), m.start(), m.end()) for m in _EVM_PK_RE.finditer(text)]
