"""config-chain slice-1b-1：远程配置**多层解码引擎**测试（纯离线，fixture 现造）。

覆盖：明文 JSON / gzip / base64 / base64+gzip / AES(信封) 各解码链，域名/IP 抽取与私网噪音清洗，
不可解字节优雅降级为 decoded=False。
"""

from __future__ import annotations

import base64
import gzip
import json

import pytest

from apkscan.config.decode import decode_config_blob

_CONFIG = {"domains": ["api.evil-c2.com", "backup.evil-c2.com"], "ips": ["45.11.22.33"]}
_JSON_BYTES = json.dumps(_CONFIG).encode("utf-8")
_EXPECT_DOMAINS = ("api.evil-c2.com", "backup.evil-c2.com")
_EXPECT_IPS = ("45.11.22.33",)


def test_plaintext_json() -> None:
    r = decode_config_blob(_JSON_BYTES)
    assert r.decoded is True
    assert r.decode_chain == ("json",)
    assert r.domains == _EXPECT_DOMAINS
    assert r.ips == _EXPECT_IPS


def test_gzip_json() -> None:
    r = decode_config_blob(gzip.compress(_JSON_BYTES))
    assert r.decoded is True
    assert r.decode_chain == ("gzip", "json")
    assert r.domains == _EXPECT_DOMAINS and r.ips == _EXPECT_IPS


def test_base64_json() -> None:
    r = decode_config_blob(base64.b64encode(_JSON_BYTES))
    assert r.decoded is True
    assert r.decode_chain == ("base64", "json")
    assert r.domains == _EXPECT_DOMAINS


def test_base64_gzip_json() -> None:
    blob = base64.b64encode(gzip.compress(_JSON_BYTES))
    r = decode_config_blob(blob)
    assert r.decoded is True
    assert r.decode_chain == ("base64", "gzip", "json")
    assert r.domains == _EXPECT_DOMAINS


def test_plain_text_domain_list() -> None:
    r = decode_config_blob(b"api.evil-c2.com\nbackup.evil-c2.com\n45.11.22.33\n")
    assert r.decoded is True
    assert r.decode_chain == ("text",)
    assert r.domains == _EXPECT_DOMAINS and r.ips == _EXPECT_IPS


def test_private_and_loopback_ips_are_dropped() -> None:
    r = decode_config_blob(json.dumps({"ips": ["10.0.0.1", "127.0.0.1", "169.254.1.1", "45.11.22.33"]}).encode())
    assert r.ips == ("45.11.22.33",)  # 私网 10.x / 回环 127.x / 链路本地 169.254 清洗掉，公网留


def test_undecodable_blob_degrades_gracefully() -> None:
    r = decode_config_blob(bytes(range(256)) * 4)  # 非 gzip/base64/json/可读文本
    assert r.decoded is False
    assert r.domains == () and r.ips == () and r.text is None


def test_empty_or_bad_input() -> None:
    assert decode_config_blob(b"").decoded is False
    assert decode_config_blob("not bytes").decoded is False  # type: ignore[arg-type]


def test_aes_envelope_json() -> None:
    """AES-CBC/PKCS7 信封（fixed iv）解密链——复用 core.appcrypto 的 decrypt_envelope。缺 cryptography → skip。"""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from apkscan.core.appcrypto import CryptoRecipe

    key = b"0123456789abcdef0123456789abcdef"  # 32B utf8 → AES-256
    iv = b"fedcba9876543210"  # 16B utf8
    pad = 16 - (len(_JSON_BYTES) % 16)
    padded = _JSON_BYTES + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    payload = base64.b64encode(ciphertext)  # 信封 data 字段（base64 密文）

    recipe = CryptoRecipe(
        algo="AES", mode="CBC", padding="Pkcs7",
        key=key.decode(), key_encoding="utf8",
        iv_derive="fixed", iv_value=iv.decode(), payload_encoding="base64",
    )
    r = decode_config_blob(payload, recipe=recipe)
    assert r.decoded is True
    assert r.decode_chain == ("aes", "json")
    assert r.domains == _EXPECT_DOMAINS and r.ips == _EXPECT_IPS
