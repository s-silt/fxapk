"""apkscan.core.appcrypto — 应用层加密信封解密器（C5b）。

用 C5a 静态逆出的「加密配方」（算法/模式/填充、硬编码 key、iv 推导、信封字段、
载荷编码）把抓到的密文信封 ``{"data": <密文>, "timestamp": <ts>}`` 解成明文。

设计铁律：
- crypto 依赖 **lazy import cryptography**（mitmproxy 传递依赖；capture 链路通常已装，
  但本模块不能假设它在）。缺库 → 不解密、不假成功、不崩，只 ``logging.warning`` 提示
  「装 cryptography 可自动解密」并返回 None。
- ``cryptography`` 的 ``modes.CFB`` 在 48→49 间从 ``primitives`` 移到 ``decrepit``：
  导入前向兼容（先试 decrepit，回退 primitives），否则未来升级即崩。
- 解密失败（base64 解析失败 / padding 错 / 配方不全）→ 返回 None + ``logging.warning``，
  由调用方保留原密文条目，绝不静默吞错、绝不抛给调用方。
- 全程 type hints。

配方对照真值（仅用于测试，不进产品逻辑）：真样本 AES-256-CFB128 + Pkcs7，
key=UTF-8("55f0e4afd83cf8dcae7a4d3daf663467")（32B），iv=MD5(key+str(ts)).hexdigest()[:16]
的 UTF-8 字节（16B），载荷裸 base64（无 OpenSSL Salted__ 前缀）。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import warnings
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# 顶层探测 cryptography 是否可用（lazy：真正的 hazmat 子模块在函数内才导入）。
try:
    import cryptography  # noqa: F401

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ---------------------------------------------------------------------------
# 配方数据结构
# ---------------------------------------------------------------------------


@dataclass
class CryptoRecipe:
    """应用层加密配方（C5a 静态逆出，C5b 据此解密）。

    字段语义见 §2.2 spec：algo/mode/padding/segment_size + key/key_encoding +
    iv_derive/iv_value + payload_encoding。默认值即真样本形态（AES-CFB/Pkcs7/utf8）。
    """

    algo: str = "AES"  # AES|DES|3DES
    mode: str = "CFB"  # CFB|CBC|ECB
    padding: str = "Pkcs7"  # Pkcs7|None
    segment_size: int = 128  # CFB 段大小（CryptoJS 默认 128）
    key: str = ""  # 原始 key 串（utf8 文本或 hex 串）
    key_encoding: str = "utf8"  # utf8|hex
    iv_derive: str = "md5(key+ts)[:16]"  # md5(key+ts)[:16]|fixed|same_as_key|none
    iv_value: str | None = None  # iv_derive=fixed 时的 iv 串
    payload_encoding: str = "base64"  # base64|hex|auto

    @classmethod
    def from_meta(cls, d: Any) -> "CryptoRecipe | None":
        """从 ``report.meta["crypto_recipe"]``（dict）构造配方；非 dict / 空 → None。

        缺字段走 dataclass 默认值。绝不抛：字段类型异常时记 warning 并尽量回退默认。
        """
        if not isinstance(d, dict) or not d:
            return None
        try:
            return cls(
                algo=str(d.get("algo", "AES") or "AES"),
                mode=str(d.get("mode", "CFB") or "CFB"),
                padding=str(d.get("padding", "Pkcs7") or "Pkcs7"),
                segment_size=int(d.get("segment_size", 128) or 128),
                key=str(d.get("key", "") or ""),
                key_encoding=str(d.get("key_encoding", "utf8") or "utf8"),
                iv_derive=str(d.get("iv_derive", "md5(key+ts)[:16]") or "md5(key+ts)[:16]"),
                iv_value=(str(d["iv_value"]) if d.get("iv_value") not in (None, "") else None),
                payload_encoding=str(d.get("payload_encoding", "base64") or "base64"),
            )
        except (TypeError, ValueError):
            logger.warning("[appcrypto] 配方 meta 字段类型异常，无法构造 CryptoRecipe：%r", d)
            return None


# ---------------------------------------------------------------------------
# 公开 API
# ---------------------------------------------------------------------------


def decrypt_envelope(
    payload: str,
    recipe: CryptoRecipe,
    timestamp: int | str,
) -> str | None:
    """把信封里的密文载荷解密为明文 str。

    Args:
        payload: 信封 ``data`` 字段（base64 或 hex 串）。
        recipe: 解密配方。
        timestamp: 信封 ``timestamp`` 字段（用于派生 iv）。

    Returns:
        成功 → 明文 str；缺 cryptography → None + warning（不假成功）；
        解密失败（base64/hex 解析失败、padding 错、配方不全、key/iv 长度非法）→
        None + warning（调用方保留原密文）。绝不抛。
    """
    if not _HAS_CRYPTO:
        logger.warning(
            "[appcrypto] 未安装 cryptography，已抓到密文+配方但无法自动解密；"
            "pip install cryptography 后可解"
        )
        return None

    if not isinstance(payload, str) or not payload:
        logger.warning("[appcrypto] 密文载荷为空或非 str，跳过解密")
        return None

    try:
        ct = _decode_payload(payload, recipe.payload_encoding)
        if ct is None:
            logger.warning("[appcrypto] 密文载荷解码失败（编码=%s），保留原密文", recipe.payload_encoding)
            return None

        key = _build_key(recipe)
        if not key:
            logger.warning("[appcrypto] 配方无 key 或 key 解析失败，跳过解密")
            return None

        iv = _derive_iv(recipe, timestamp)

        plain = _decrypt_bytes(ct, key, iv, recipe)
        if plain is None:
            return None

        if recipe.padding.lower() in ("pkcs7", "pkcs5"):
            unpadded = _unpad_pkcs7(plain)
            if unpadded is None:
                logger.warning("[appcrypto] PKCS7 去填充失败（padding 错/配方不全），保留原密文")
                return None
            plain = unpadded

        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError:
            # 解出来不是合法 UTF-8 → 多半 key/iv/mode 不对，按解密失败处理（不假成功）。
            logger.warning("[appcrypto] 解密结果非合法 UTF-8（key/iv/mode 可能不匹配），保留原密文")
            return None
    except Exception:  # noqa: BLE001 - 解密任一环节异常都不得抛给调用方
        logger.exception("[appcrypto] 解密信封异常，保留原密文")
        return None


# ---------------------------------------------------------------------------
# 内部：cryptography 前向兼容 import
# ---------------------------------------------------------------------------


def _import_cfb() -> Any:
    """前向兼容地拿到 CFB mode 类（48→49 从 primitives 移到 decrepit）。"""
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB  # 新位置（≥43 已有）

        return CFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB  # 旧位置（≤48）

        return CFB


# ---------------------------------------------------------------------------
# 内部：key / iv / payload 解析
# ---------------------------------------------------------------------------


def _build_key(recipe: CryptoRecipe) -> bytes:
    """按 key_encoding 把 key 串解析为字节。失败 → 空 bytes（调用方判空跳过）。"""
    raw = recipe.key or ""
    if not raw:
        return b""
    enc = recipe.key_encoding.lower()
    if enc == "hex":
        try:
            return bytes.fromhex(raw)
        except ValueError:
            logger.warning("[appcrypto] key_encoding=hex 但 key 非合法 hex：%r", raw[:16])
            return b""
    # 默认 utf8（CryptoJS enc.Utf8.parse 口径：原始字符按 UTF-8 字节当 key）。
    return raw.encode("utf-8")


def _derive_iv(recipe: CryptoRecipe, timestamp: int | str) -> bytes:
    """按 iv_derive 派生 iv 字节。

    - ``md5(key+ts)[:16]``：``MD5(key + str(ts)).hexdigest()[:16]`` 的 UTF-8 字节（16B）。
      关键：取 hexdigest 的**前 16 个字符**再当 UTF-8 字节（即 16 字节），对齐 CryptoJS
      ``MD5(e).toString().substring(0,16)``。
    - ``fixed``：按 key_encoding 同法解析 ``iv_value``。
    - ``same_as_key``：取 key 前 16（AES）/ 8（DES）字节。
    - ``none``：空 iv（ECB 用）。
    """
    derive = (recipe.iv_derive or "").lower()
    if derive in ("md5(key+ts)[:16]", "md5(key+ts)", "md5"):
        digest = hashlib.md5((recipe.key + str(timestamp)).encode("utf-8")).hexdigest()
        return digest[:16].encode("utf-8")
    if derive == "fixed":
        iv_val = recipe.iv_value or ""
        if not iv_val:
            logger.warning("[appcrypto] iv_derive=fixed 但无 iv_value，使用空 iv")
            return b""
        if recipe.key_encoding.lower() == "hex":
            try:
                return bytes.fromhex(iv_val)
            except ValueError:
                logger.warning("[appcrypto] fixed iv_value 非合法 hex：%r", iv_val[:16])
                return b""
        return iv_val.encode("utf-8")
    if derive == "same_as_key":
        key = _build_key(recipe)
        block = 8 if recipe.algo.upper() in ("DES", "3DES", "TRIPLEDES") else 16
        return key[:block]
    if derive in ("none", ""):
        # ECB 等无 iv 模式：空 iv 合法。
        return b""
    # unknown / 其它未识别推导式：静态侧没逆出 iv 来源，无法派生 → 空 iv。
    # 对 CFB/CBC 这会让 cryptography 抛 ValueError（iv 长度非法）→ decrypt 安全降级，
    # 不假成功。这里 warning 提示需人工补全配方的 iv 推导。
    logger.warning(
        "[appcrypto] iv_derive=%r 未识别/未支持，无法派生 iv（需人工补全配方）",
        recipe.iv_derive,
    )
    return b""


def _decode_payload(payload: str, encoding: str) -> bytes | None:
    """把载荷串按 encoding 解为密文字节。``auto`` 先试 base64 再 hex。失败 → None。"""
    enc = (encoding or "base64").lower()
    if enc == "hex":
        return _try_hex(payload)
    if enc == "auto":
        b = _try_base64(payload)
        if b is not None:
            return b
        return _try_hex(payload)
    # 默认 base64。
    return _try_base64(payload)


def _try_base64(s: str) -> bytes | None:
    try:
        # validate=True 拒绝非 base64 字符（避免 hex 串被静默当 base64 解出垃圾）。
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _try_hex(s: str) -> bytes | None:
    try:
        return bytes.fromhex(s.strip())
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# 内部：解密 / 去填充
# ---------------------------------------------------------------------------


def _build_algorithm(algo: str, key: bytes) -> Any:
    """按 algo 名构造 cryptography 的对称算法对象。不支持 → None。"""
    from cryptography.hazmat.primitives.ciphers import algorithms

    name = algo.upper()
    if name == "AES":
        return algorithms.AES(key)
    if name in ("3DES", "TRIPLEDES", "DES3"):
        return algorithms.TripleDES(key)
    if name == "DES":
        # cryptography 无单 DES（罕见，且已弃用）；TripleDES 在 8 字节 key 下退化为单 DES。
        return algorithms.TripleDES(key)
    logger.warning("[appcrypto] 暂不支持的算法：%s", algo)
    return None


def _build_mode(recipe: CryptoRecipe, iv: bytes) -> Any:
    """按 mode 名构造 cryptography 的模式对象。不支持 → None。"""
    from cryptography.hazmat.primitives.ciphers import modes

    name = recipe.mode.upper()
    if name == "CFB":
        cfb = _import_cfb()
        return cfb(iv)
    if name == "CBC":
        return modes.CBC(iv)
    if name == "ECB":
        return modes.ECB()
    logger.warning("[appcrypto] 暂不支持的模式：%s", recipe.mode)
    return None


def _decrypt_bytes(
    ct: bytes, key: bytes, iv: bytes, recipe: CryptoRecipe
) -> bytes | None:
    """用 cryptography 解密密文字节。算法/模式不支持、key/iv 长度非法 → None + warning。"""
    from cryptography.hazmat.primitives.ciphers import Cipher

    algorithm = _build_algorithm(recipe.algo, key)
    if algorithm is None:
        return None
    mode = _build_mode(recipe, iv)
    if mode is None:
        return None

    try:
        # CryptoJS CFB 默认整块反馈（segment_size=128 == 一个 AES 块）；cryptography 的
        # modes.CFB 默认也是 128，二者匹配。warning 静默以免污染测试输出。
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cipher = Cipher(algorithm, mode)
            decryptor = cipher.decryptor()
            return decryptor.update(ct) + decryptor.finalize()
    except ValueError:
        # key/iv 长度非法、密文长度非块整数倍（CBC/ECB）等。
        logger.warning(
            "[appcrypto] 解密失败（key/iv 长度非法或密文长度异常）：algo=%s mode=%s key_len=%d iv_len=%d",
            recipe.algo,
            recipe.mode,
            len(key),
            len(iv),
        )
        return None


def _unpad_pkcs7(data: bytes) -> bytes | None:
    """手写校验 PKCS7 去填充（更可控）。非法填充 → None。

    CFB 是流模式，cryptography 不强制块对齐，但 CryptoJS 仍按 Pkcs7 在明文末尾补/剥
    填充。这里校验末字节填充长度合法（1..block）且尾部全为该值，再剥离。
    """
    if not data:
        return None
    pad_len = data[-1]
    # 块大小未知（CFB 流模式），但 PKCS7 填充值必在 1..16（AES 块）范围。
    if pad_len < 1 or pad_len > 16 or pad_len > len(data):
        return None
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return None
    return data[:-pad_len]


__all__ = [
    "CryptoRecipe",
    "decrypt_envelope",
]
