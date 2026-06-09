"""ASN 富化器：对 IP 查归属 ISP / 机构(云厂商 / IDC) / ASN / 国家。

用 ip-api.com 免费接口（``http://ip-api.com/json/{ip}?fields=...``）。
免费档限速约 45 次/分钟，本模块在每次真实网络查询前加 ~1s 间隔保护。
结果带本地 JSON 文件缓存（键=IP，放 ``.apkscan_cache/asn.json``）避免重复查询。

错误处理（符合规范）：
- 网络/解析全部异常 → 返回 ``EnrichmentResult(ok=False, error=...)``，不抛出、不静默。
- 接口返回 ``status != "success"`` → 同样视为失败（ok=False）。
- 全程 logging 记录，不裸 ``except: pass``。
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

import requests

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher

logger = logging.getLogger(__name__)

#: 查询超时（秒）。
ASN_TIMEOUT = 8

#: ip-api 免费接口地址模板与需要的字段。
ASN_API_URL = "http://ip-api.com/json/{ip}"
ASN_FIELDS = "status,country,isp,org,as,query"

#: 免费档限速约 45/min；每次真实查询前的最小间隔（秒），保护性留余量。
ASN_MIN_INTERVAL = 1.0

#: 本地缓存目录与文件。
CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "asn.json"


def _to_str(value: Any) -> str | None:
    """统一成可 JSON 序列化的字符串；None/空 → None。"""
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _extract(payload: dict[str, Any]) -> dict[str, str | None]:
    """从 ip-api 返回 JSON 提取关心字段。

    - ``isp``：网络服务商。
    - ``org``：归属机构（常为云厂商 / IDC）。
    - ``as``：ASN（含编号与名称）。
    - ``country``：国家。
    """
    return {
        "isp": _to_str(payload.get("isp")),
        "org": _to_str(payload.get("org")),
        "asn": _to_str(payload.get("as")),
        "country": _to_str(payload.get("country")),
    }


class AsnEnricher(BaseEnricher):
    """对 IP 端点做 ASN 富化（ISP / 机构 / ASN / 国家）。"""

    name = "asn"
    applies_to = ["ip"]

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()
        # 限速：记录上次真实查询时间戳（单调时钟），串行化访问。
        self._rate_lock = threading.Lock()
        self._last_query_ts: float = 0.0

    # ------------------------------------------------------------------ 缓存
    def _load_cache(self) -> dict[str, dict[str, Any]]:
        if not CACHE_FILE.is_file():
            return {}
        try:
            text = CACHE_FILE.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception:
            logger.warning("ASN 缓存读取/解析失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        if not isinstance(data, dict):
            logger.warning("ASN 缓存顶层非 dict，忽略：%s", CACHE_FILE)
            return {}
        return data

    def _save_cache_entry(self, ip: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            cache[ip] = entry
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                CACHE_FILE.write_text(
                    json.dumps(cache, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            except Exception:
                logger.warning("ASN 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 限速
    def _respect_rate_limit(self) -> None:
        """每次真实查询前确保与上次间隔 >= ASN_MIN_INTERVAL 秒。"""
        with self._rate_lock:
            elapsed = time.monotonic() - self._last_query_ts
            wait = ASN_MIN_INTERVAL - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_query_ts = time.monotonic()

    # ------------------------------------------------------------------ 查询
    def _query(self, ip: str) -> dict[str, str | None]:
        """实际网络查询；网络/HTTP/解析异常向上抛由 enrich() 统一捕获。

        接口语义上的失败（``status != "success"``）以 ValueError 形式抛出，
        同样由 enrich() 转成 ok=False。
        """
        self._respect_rate_limit()

        url = ASN_API_URL.format(ip=ip)
        resp = requests.get(
            url, params={"fields": ASN_FIELDS}, timeout=ASN_TIMEOUT
        )
        resp.raise_for_status()
        payload = resp.json()

        if not isinstance(payload, dict):
            raise ValueError(f"ip-api 返回非对象：{type(payload).__name__}")

        status = payload.get("status")
        if status != "success":
            message = payload.get("message") or status or "unknown"
            raise ValueError(f"ip-api 查询未成功：{message}")

        return _extract(payload)

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        ip = (ep.value or "").strip()
        if not ip:
            return EnrichmentResult(
                provider=self.name, ok=False, error="空 IP，跳过 ASN 查询"
            )

        # 1) 缓存命中直接返回（不消耗网络）。
        cache = self._load_cache()
        cached = cache.get(ip)
        if isinstance(cached, dict):
            logger.debug("ASN 缓存命中：%s", ip)
            return EnrichmentResult(provider=self.name, ok=True, data=dict(cached))

        # 2) 网络查询，全部异常吞成 ok=False，绝不炸主流程。
        try:
            data = self._query(ip)
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            # 不带 exc_info：富化失败（超时/限速/无应答）很常见，整段 traceback 是噪音；
            # 消息已含异常摘要，排障足够。
            logger.warning("ASN 查询失败：%s（%s）", ip, exc)
            return EnrichmentResult(
                provider=self.name, ok=False, error=f"{type(exc).__name__}: {exc}"
            )

        # 3) 成功才写缓存（失败不缓存，便于后续重试）。
        self._save_cache_entry(ip, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
