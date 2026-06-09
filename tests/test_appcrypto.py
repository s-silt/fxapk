"""apkscan.core.appcrypto（C5b 解密器）单测。

覆盖：
- 合成密文解密成功（AES-CFB/Pkcs7 + base64 + iv=md5(key+ts).hex[:16]）→ 解回原明文。
- iv 派生正确性：ts=1700000000000 → 7c4debf4a67ed0bf。
- 缺 crypto 库降级：monkeypatch _HAS_CRYPTO=False → None + warning，不抛。
- 解密失败保留密文：坏 base64 / 错 padding → None + warning，不抛。
- hex payload + hex key 变体解密成功（覆盖多解析分支）。
- CryptoRecipe.from_meta：从 dict 构造 / None 输入。
全程 type hints。
"""

from __future__ import annotations

import base64
import hashlib
import logging
import warnings

import pytest

from apkscan.core import appcrypto
from apkscan.core.appcrypto import CryptoRecipe, decrypt_envelope

_KEY = "55f0e4afd83cf8dcae7a4d3daf663467"
_TS = 1700000000000
_PLAINTEXT = (
    '{"webName":"示例证券","register":"/api/register",'
    '"login":"/api/login","inviteCode":"ABC123"}'
)


# ---------------------------------------------------------------------------
# 合成密文构造（测试内用 cryptography 加密，复刻真样本配方）
# ---------------------------------------------------------------------------


def _import_cfb():  # type: ignore[no-untyped-def]
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB

        return CFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB

        return CFB


def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def _encrypt_envelope_b64(
    plaintext: str,
    *,
    key: str = _KEY,
    ts: int = _TS,
    payload_encoding: str = "base64",
) -> str:
    """用真样本配方加密明文，返回信封 data 字段（base64 或 hex）。"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    kb = key.encode("utf-8")
    iv = hashlib.md5(kb + str(ts).encode()).hexdigest()[:16].encode("utf-8")
    cfb = _import_cfb()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        enc = Cipher(algorithms.AES(kb), cfb(iv)).encryptor()
        ct = enc.update(_pkcs7_pad(plaintext.encode("utf-8"))) + enc.finalize()
    if payload_encoding == "hex":
        return ct.hex()
    return base64.b64encode(ct).decode("ascii")


# ---------------------------------------------------------------------------
# 解密成功
# ---------------------------------------------------------------------------


def test_decrypt_envelope_roundtrip_success() -> None:
    payload = _encrypt_envelope_b64(_PLAINTEXT)
    recipe = CryptoRecipe(key=_KEY)
    out = decrypt_envelope(payload, recipe, _TS)
    assert out == _PLAINTEXT


def test_decrypt_envelope_timestamp_as_str() -> None:
    """timestamp 以 str 传入也能正确派生 iv。"""
    payload = _encrypt_envelope_b64(_PLAINTEXT)
    recipe = CryptoRecipe(key=_KEY)
    assert decrypt_envelope(payload, recipe, str(_TS)) == _PLAINTEXT


def test_derive_iv_known_value() -> None:
    """iv 派生正确性：ts=1700000000000 → 7c4debf4a67ed0bf。"""
    recipe = CryptoRecipe(key=_KEY)
    iv = appcrypto._derive_iv(recipe, _TS)
    assert iv == b"7c4debf4a67ed0bf"


def test_decrypt_hex_payload_and_hex_key() -> None:
    """hex 载荷 + hex key 变体解密成功（覆盖多解析分支）。"""
    hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    kb = bytes.fromhex(hex_key)
    iv = hashlib.md5(hex_key.encode() + str(_TS).encode()).hexdigest()[:16].encode("utf-8")
    cfb = _import_cfb()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        enc = Cipher(algorithms.AES(kb), cfb(iv)).encryptor()
        ct = enc.update(_pkcs7_pad(_PLAINTEXT.encode("utf-8"))) + enc.finalize()
    hex_payload = ct.hex()

    recipe = CryptoRecipe(key=hex_key, key_encoding="hex", payload_encoding="hex")
    assert decrypt_envelope(hex_payload, recipe, _TS) == _PLAINTEXT


def test_decrypt_auto_payload_encoding() -> None:
    """payload_encoding=auto 先试 base64。"""
    payload = _encrypt_envelope_b64(_PLAINTEXT)
    recipe = CryptoRecipe(key=_KEY, payload_encoding="auto")
    assert decrypt_envelope(payload, recipe, _TS) == _PLAINTEXT


# ---------------------------------------------------------------------------
# 缺库降级
# ---------------------------------------------------------------------------


def test_missing_crypto_degrades(monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    monkeypatch.setattr(appcrypto, "_HAS_CRYPTO", False)
    payload = "anything"
    recipe = CryptoRecipe(key=_KEY)
    with caplog.at_level(logging.WARNING):
        out = decrypt_envelope(payload, recipe, _TS)
    assert out is None
    assert any("cryptography" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# 解密失败保留密文（None + warning，不抛）
# ---------------------------------------------------------------------------


def test_bad_base64_returns_none(caplog) -> None:
    recipe = CryptoRecipe(key=_KEY)
    with caplog.at_level(logging.WARNING):
        out = decrypt_envelope("!!!not base64!!!", recipe, _TS)
    assert out is None
    assert caplog.records


def test_wrong_key_returns_none() -> None:
    """key 不对 → 解出非合法 UTF-8 或 padding 错 → None（不假成功）。"""
    payload = _encrypt_envelope_b64(_PLAINTEXT)
    recipe = CryptoRecipe(key="ffffffffffffffffffffffffffffffff")
    assert decrypt_envelope(payload, recipe, _TS) is None


def test_empty_payload_returns_none() -> None:
    assert decrypt_envelope("", CryptoRecipe(key=_KEY), _TS) is None


def test_empty_key_returns_none() -> None:
    payload = _encrypt_envelope_b64(_PLAINTEXT)
    assert decrypt_envelope(payload, CryptoRecipe(key=""), _TS) is None


def test_corrupt_padding_returns_none() -> None:
    """密文被改动 → padding 校验失败 → None。"""
    payload = _encrypt_envelope_b64(_PLAINTEXT)
    raw = bytearray(base64.b64decode(payload))
    raw[-1] ^= 0xFF  # 破坏最后一块 → padding 错
    corrupt = base64.b64encode(bytes(raw)).decode()
    assert decrypt_envelope(corrupt, CryptoRecipe(key=_KEY), _TS) is None


# ---------------------------------------------------------------------------
# CryptoRecipe.from_meta
# ---------------------------------------------------------------------------


def test_from_meta_builds_recipe() -> None:
    meta = {
        "algo": "AES",
        "mode": "CFB",
        "padding": "Pkcs7",
        "key": _KEY,
        "key_encoding": "utf8",
        "iv_derive": "md5(key+ts)[:16]",
        "payload_encoding": "base64",
    }
    recipe = CryptoRecipe.from_meta(meta)
    assert recipe is not None
    assert recipe.key == _KEY
    payload = _encrypt_envelope_b64(_PLAINTEXT)
    assert decrypt_envelope(payload, recipe, _TS) == _PLAINTEXT


def test_from_meta_none_when_empty() -> None:
    assert CryptoRecipe.from_meta(None) is None
    assert CryptoRecipe.from_meta({}) is None
    assert CryptoRecipe.from_meta("not a dict") is None
