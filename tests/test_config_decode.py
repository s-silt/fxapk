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


def test_base64_json_with_trailing_newline() -> None:
    """★远程配置常带尾随换行；validate=True 见空白即抛。判形/解码须先规范化同一文本，
    否则整份配置静默解不开（decoded=False, chain=()）。"""
    r = decode_config_blob(base64.b64encode(_JSON_BYTES) + b"\n")
    assert r.decoded is True
    assert r.decode_chain == ("base64", "json")
    assert r.domains == _EXPECT_DOMAINS


def test_base64_json_with_mime_line_folding() -> None:
    """★MIME 76 列折行（CRLF 内插）的 base64 也须解开——OSS/邮件系统导出的配置常见此形。"""
    raw = base64.b64encode(gzip.compress(_JSON_BYTES))
    folded = b"\r\n".join(raw[i:i + 76] for i in range(0, len(raw), 76))
    r = decode_config_blob(folded)
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


def test_gzip_bomb_rejected_without_oom() -> None:
    """复审 P1 回归：gzip 炸弹（几 KB 压缩 → 超 cap 解压）被**有界解压**拒之，绝不全量解压 OOM。

    直接断言 _gunzip 返回 None（可判别：修前 gzip.decompress(...)[:cap] 会先全量解压再切片、返回 5MB 字节
    而非 None，本断言在修前必失败）。"""
    from apkscan.config.decode import _gunzip

    bomb = gzip.compress(b"\x00" * (6 * 1024 * 1024))  # 解压后 6MB > 5MB 上限
    assert len(bomb) < 64 * 1024  # 压缩后仅几 KB（真炸弹形态）
    assert _gunzip(bomb) is None  # 有界解压：超帽即拒，不返回 5MB 截断结果
    assert decode_config_blob(bomb).decoded is False


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


# --- 二进制紧凑端点数组提取（codex #16 / A3）--------------------------------


def _bin_records(pairs: list, endian: str = ">") -> bytes:
    """把 [(ip, port)] 编成连续 6 字节记录 [IPv4(4) + port(2)]（默认大端）。"""
    import socket
    import struct

    out = b""
    for ip, port in pairs:
        out += socket.inet_aton(ip) + struct.pack(endian + "H", port)
    return out


def test_binary_endpoint_array_big_endian() -> None:
    """★5 记录二进制数组（非 UTF-8 leaf）→ 抽出 5 个公网 IP，chain=('binary',)。"""
    pairs = [("45.11.22.33", 40009), ("8.8.8.8", 33033), ("1.1.1.1", 50505),
             ("9.9.9.9", 44044), ("208.67.222.222", 53000)]
    r = decode_config_blob(_bin_records(pairs))
    assert r.decoded is True
    assert r.decode_chain == ("binary",)
    assert set(r.ips) == {ip for ip, _ in pairs}
    assert r.domains == ()


def test_binary_endpoint_array_little_endian() -> None:
    pairs = [("45.11.22.33", 40009), ("8.8.8.8", 33033), ("1.1.1.1", 50505)]
    r = decode_config_blob(_bin_records(pairs, endian="<"))
    assert r.decoded is True and r.decode_chain == ("binary",)
    assert set(r.ips) == {ip for ip, _ in pairs}


def test_binary_below_min_records_not_matched() -> None:
    """★仅 2 条记录（< _MIN_BIN_RECORDS=3）→ 不命中（抗假阳），decoded=False。"""
    r = decode_config_blob(_bin_records([("45.11.22.33", 40009), ("8.8.8.8", 33033)]))
    assert r.decoded is False


def test_random_bytes_no_false_positive() -> None:
    """★随机字节 leaf → 不误判出二进制端点（连续 ≥3 条合法记录概率极低）。"""
    import hashlib

    blob = b"".join(hashlib.sha256(bytes([i])).digest() for i in range(20))  # 640 字节确定性"随机"
    r = decode_config_blob(blob)
    assert r.decode_chain != ("binary",)  # 不得误抽二进制端点


def test_gzip_json_not_preempted_by_binary() -> None:
    """★不抢 gzip 路径：gzip'd JSON 仍走 gzip→json，不被二进制提取抢先（二进制只在剥不动的 leaf 跑）。"""
    r = decode_config_blob(gzip.compress(_JSON_BYTES))
    assert r.decode_chain == ("gzip", "json")  # 非 ('binary',)
