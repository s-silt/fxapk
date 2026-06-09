"""WHOIS 富化器：对域名查注册商/注册人/机构/注册时间/国家。

用 python-whois（``import whois``）。结果带本地 JSON 文件缓存（键=域名，
放 ``.apkscan_cache/whois.json``）避免重复查询。

错误处理（符合规范）：
- 网络/解析全部异常 → 返回 ``EnrichmentResult(ok=False, error=...)``，不抛出、不静默。
- 全程 logging 记录，不裸 ``except: pass``。
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import date, datetime
from pathlib import Path
from typing import Any

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher

logger = logging.getLogger(__name__)

#: 查询超时（秒）。python-whois 透传到底层 socket。
WHOIS_TIMEOUT = 8

#: 本地缓存目录与文件。
CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "whois.json"

# python-whois 库自身的 logger（名为 "whois"）在连接超时/无应答时会刷 ERROR
# 「Error trying to connect to socket: ...」——对富化失败属预期内噪音，抬高其级别静默
# （与 androguard loguru 同思路：不影响我方结构化降级，只是不让它喧哗）。
logging.getLogger("whois").setLevel(logging.CRITICAL)


def _short_err(exc: object) -> str:
    """把异常压成一行短摘要：取首个非空行、截到 120 字符。

    必要性：whois 服务器（如 VeriSign .com）会把整段 NOTICE / TERMS OF USE 法律声明塞进
    响应，python-whois 又把它带进异常消息——直接打日志会刷出几十行 boilerplate 噪音。
    取「No match for X」/「timed out」这类首行关键信息即可。
    """
    text = str(exc).strip()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:120]
    return text[:120] or type(exc).__name__


def _first(value: Any) -> Any:
    """WHOIS 字段常为 list（多注册商/多时间）；取首个非空元素。"""
    if isinstance(value, (list, tuple)):
        for item in value:
            if item not in (None, ""):
                return item
        return None
    return value


def _to_str(value: Any) -> str | None:
    """把 WHOIS 字段统一成可 JSON 序列化的字符串；None/空 → None。"""
    value = _first(value)
    if value in (None, ""):
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value).strip() or None


def _extract(record: Any) -> dict[str, str | None]:
    """从 python-whois 返回对象提取关心的字段。

    python-whois 的 ``WhoisEntry`` 是 dict-like，键名跨 TLD 略有差异，
    这里对多个候选键做兜底。
    """

    def pick(*keys: str) -> str | None:
        for key in keys:
            try:
                raw = record[key]  # type: ignore[index]
            except (KeyError, TypeError):
                raw = getattr(record, key, None)
            text = _to_str(raw)
            if text is not None:
                return text
        return None

    return {
        "registrar": pick("registrar"),
        "registrant": pick("registrant_name", "registrant", "name"),
        "org": pick("org", "organization", "registrant_org", "registrant_organization"),
        "creation_date": pick("creation_date", "created"),
        "country": pick("country", "registrant_country"),
    }


class WhoisEnricher(BaseEnricher):
    """对域名端点做 WHOIS 富化（注册商/注册人/机构/注册时间/国家）。"""

    name = "whois"
    applies_to = ["domain"]

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 缓存
    def _load_cache(self) -> dict[str, dict[str, Any]]:
        if not CACHE_FILE.is_file():
            return {}
        try:
            text = CACHE_FILE.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception:
            logger.warning("WHOIS 缓存读取/解析失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        if not isinstance(data, dict):
            logger.warning("WHOIS 缓存顶层非 dict，忽略：%s", CACHE_FILE)
            return {}
        return data

    def _save_cache_entry(self, domain: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            cache[domain] = entry
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                CACHE_FILE.write_text(
                    json.dumps(cache, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            except Exception:
                logger.warning("WHOIS 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 查询
    def _query(self, domain: str) -> dict[str, str | None]:
        """实际网络查询；任何异常向上抛由 enrich() 统一捕获。"""
        import whois  # 延迟导入：缓存命中或离线时无需该依赖

        record = whois.whois(domain, timeout=WHOIS_TIMEOUT)
        return _extract(record)

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        domain = (ep.value or "").strip().lower()
        if not domain:
            return EnrichmentResult(
                provider=self.name, ok=False, error="空域名，跳过 WHOIS 查询"
            )

        # 0) 系统性不可用（如 whois 库数据文件未打进 exe）→ 本次起跳过所有查询，
        #    避免对每个域名重复刷同一条 traceback（已在首次失败时记过一次清晰提示）。
        if getattr(self, "_data_unavailable", False):
            return EnrichmentResult(
                provider=self.name, ok=False, error="WHOIS 不可用（数据文件缺失），已跳过"
            )

        # 1) 缓存命中直接返回（不消耗网络）。
        cache = self._load_cache()
        cached = cache.get(domain)
        if isinstance(cached, dict):
            logger.debug("WHOIS 缓存命中：%s", domain)
            return EnrichmentResult(provider=self.name, ok=True, data=dict(cached))

        # 2) 网络查询，全部异常吞成 ok=False（不刷 traceback：富化失败很常见）。
        try:
            data = self._query(domain)
        except FileNotFoundError as exc:
            # whois 库数据文件（public_suffix_list.dat）缺失 —— 系统性失败（常见于打包 exe
            # 未收 whois 数据）。记一次清晰提示后本次禁用 WHOIS，不再逐域名刷 traceback。
            self._data_unavailable = True
            logger.warning("WHOIS 数据文件缺失，本次运行跳过所有 WHOIS 查询：%s", exc)
            return EnrichmentResult(
                provider=self.name, ok=False, error=f"WHOIS 数据缺失: {exc}"
            )
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            short = _short_err(exc)
            logger.warning("WHOIS 查询失败：%s（%s）", domain, short)
            return EnrichmentResult(
                provider=self.name, ok=False, error=f"{type(exc).__name__}: {short}"
            )

        # 3) 区分"查到了"与"全空"：全空可能是网络抖动/限速/无应答，
        #    不写缓存（避免把偶发空响应永久固化成"该域名 WHOIS 为空"），返回 ok=False。
        if not any(v not in (None, "") for v in data.values()):
            logger.info("WHOIS 返回全空，不缓存（可能限速/无应答）：%s", domain)
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                error="WHOIS 无有效记录（可能限速/无应答，未缓存）",
            )

        # 4) 有有效字段才写缓存。
        self._save_cache_entry(domain, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
