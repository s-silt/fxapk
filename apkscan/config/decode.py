"""多层解码：把下载/抓到的远程配置**原始字节**链式解成明文，抽出其中的域名/IP 池。

涉诈远程配置常见套壳：JSON 之上叠 gzip / base64 / AES（信封式）任意组合。本模块做**有界深度**的链式
尝试（gzip → base64 → AES → JSON/文本），命中即返回成功的解码步序（``decode_chain``）。对称解密复用
``core.appcrypto``（同一份 CryptoRecipe / decrypt_envelope），域名/IP 清洗复用 ``core.textutil``。

纯离线、绝不联网、绝不抛：任一层失败静默降级，全链走不通 → ``decoded=False``（保留原始供人工）。
"""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import logging
import re
import zlib
from dataclasses import dataclass

from apkscan.core import textutil
from apkscan.core.appcrypto import CryptoRecipe, decrypt_envelope

logger = logging.getLogger(__name__)

# 解码工作集上限（远程配置应很小；防超大 blob 拖垮解码）。
_MAX_BLOB_BYTES = 5 * 1024 * 1024
# 有界 BFS：最大剥层深度 + 最大同层状态数（防 base64/gzip 组合爆炸）。真实远程配置最多 2~3 层套壳，
# 深度 5 留足余量；_MAX_FRONTIER 兜住 base64/AES 分支的组合展开。
_MAX_DEPTH = 5
_MAX_FRONTIER = 24

_URL_RE = re.compile(r"""(?:https?|wss?|mqtt)://[^\s"'`<>()\[\]{}\\^|,;]+""", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"""(?<![\w@./-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})(?![\w.-])"""
)
_IPV4_RE = re.compile(r"""(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])""")
# base64 文本形态（宽松）：仅 base64 字母表 + 合理长度 + 4 的倍数（含 padding）。
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


@dataclass(frozen=True)
class DecodeResult:
    """一次多层解码的结果。``decoded=False`` 时 text/domains/ips 为空、chain 记已试到的步序前缀。"""

    decoded: bool
    text: str | None
    decode_chain: tuple[str, ...]
    domains: tuple[str, ...]
    ips: tuple[str, ...]


def decode_config_blob(
    raw: bytes, *, recipe: CryptoRecipe | None = None, timestamp: int | str | None = None
) -> DecodeResult:
    """把远程配置原始字节链式解成明文并抽域名/IP。绝不抛、绝不联网。

    有界 BFS 依次尝试 gzip / base64 剥壳与（有配方时）AES 解密，每到一个可读文本态就试抽端点：抽到
    域名/IP 或解出合法 JSON 即判成功、返回该步序。全链无果 → ``decoded=False``。
    """
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        return DecodeResult(False, None, (), (), ())
    data0 = bytes(raw[:_MAX_BLOB_BYTES])

    seen: set[bytes] = set()
    frontier: list[tuple[bytes, tuple[str, ...]]] = [(data0, ())]
    for _ in range(_MAX_DEPTH):
        nxt: list[tuple[bytes, tuple[str, ...]]] = []
        for data, chain in frontier:
            fingerprint = data[:64]
            if fingerprint in seen:
                continue
            seen.add(fingerprint)

            text = _as_text(data)
            if text is not None:
                is_json = _is_json(text)
                domains, ips = _extract_endpoints(text)
                if domains or ips or is_json:
                    step = "json" if is_json else "text"
                    return DecodeResult(True, text, chain + (step,), domains, ips)

            for peeled, name in _peels(data, text, recipe, timestamp):
                if len(nxt) >= _MAX_FRONTIER:
                    break
                nxt.append((peeled, chain + (name,)))
        if not nxt:
            break
        frontier = nxt

    return DecodeResult(False, None, frontier[0][1] if frontier else (), (), ())


def _peels(
    data: bytes, text: str | None, recipe: CryptoRecipe | None, timestamp: int | str | None
) -> list[tuple[bytes, str]]:
    """产出 data 的下一层候选字节形态（gzip 解压 / base64 解码 / AES 解密），各自带步名。失败层不产出。"""
    out: list[tuple[bytes, str]] = []
    if data[:2] == b"\x1f\x8b":  # gzip magic
        unzipped = _gunzip(data)
        if unzipped is not None:
            out.append((unzipped, "gzip"))
    if text is not None and _looks_base64(text):
        decoded = _b64(text)
        if decoded is not None:
            out.append((decoded, "base64"))
    if recipe is not None and text is not None:
        # AES/信封：把当前文本当密文载荷（decrypt_envelope 内部按 recipe.payload_encoding 自解 base64/hex）。
        plain = decrypt_envelope(text.strip(), recipe, timestamp if timestamp is not None else 0)
        if plain is not None:
            out.append((plain.encode("utf-8", errors="replace"), "aes"))
    return out


def _gunzip(data: bytes) -> bytes | None:
    try:
        return gzip.decompress(data)[:_MAX_BLOB_BYTES]
    except (OSError, EOFError, zlib.error):
        return None


def _b64(text: str) -> bytes | None:
    try:
        return base64.b64decode(text, validate=True)[:_MAX_BLOB_BYTES]
    except (binascii.Error, ValueError):
        return None


def _looks_base64(text: str) -> bool:
    s = text.strip()
    # 足够长、长度为 4 的倍数、仅 base64 字母表——避免把普通短串/JSON 当 base64 徒劳解码。
    return len(s) >= 16 and len(s) % 4 == 0 and _BASE64_RE.match(s) is not None


def _as_text(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_json(text: str) -> bool:
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return False
    try:
        obj = json.loads(stripped)
    except (ValueError, RecursionError):
        return False
    return isinstance(obj, (dict, list))


def _extract_endpoints(text: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """从明文里抽域名/IP 池（清洗掉私网/回环/占位噪音 IP 与非法域名）。返回 (domains, ips)，均已排序去重。"""
    domains: set[str] = set()
    ips: set[str] = set()

    for match in _URL_RE.finditer(text):
        host = textutil.host_from_url(match.group(0))
        _classify_host(host, domains, ips)
    for match in _DOMAIN_RE.finditer(text):
        _classify_host(match.group(1), domains, ips)
    for match in _IPV4_RE.finditer(text):
        _classify_host(match.group(1), domains, ips)

    return tuple(sorted(domains)), tuple(sorted(ips))


def _classify_host(host: str, domains: set[str], ips: set[str]) -> None:
    """把一个 host 归入 domains 或 ips，顺带清洗噪音；空/非法/私网 → 丢弃。"""
    if not host:
        return
    host = host.strip().rstrip(".").lower()
    ip = textutil.parse_ipv4(host)
    if ip is not None:
        if not textutil.ip_is_private(ip) and not textutil.is_noise_bare_ip(host):
            ips.add(host)
        return
    if textutil.valid_url_host(host) and not textutil.host_is_private(host):
        domains.add(host)


__all__ = ["DecodeResult", "decode_config_blob"]
