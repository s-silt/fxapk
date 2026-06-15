"""RDAP 富化器：对域名查注册商/注册人/注册时间/状态/名称服务器（HTTPS，权威）。

RDAP（Registration Data Access Protocol）是 WHOIS 的结构化 JSON 继任者，经 ``rdap.org``
统一引导到各注册局/注册商的 RDAP 服务，且走 **HTTPS**（不像 ip-api/老 WHOIS 的明文
port-43），对"建议调证"端点更安全、更可解析。

策略：**RDAP 优先 + whois 兜底**——
- ``https://rdap.org/domain/<domain>`` 拿到 JSON → 抽取 registrar / registrant / events
  (registration→created, expiration→expires, last changed→updated) / status / nameservers，
  ``data["source"] = "rdap"``。
- HTTP 404（该 TLD 无 RDAP / 域名不存在）或任何网络失败 → 回退 ``whois.query_whois``
  （复用 whois.py 的查询+抽取），``data["source"] = "whois-fallback"``。
- 两者都失败 → ``EnrichmentResult(ok=False, error=...)``。

归属收敛：本富化器是域名注册归属的唯一联网入口（独立 WhoisEnricher 的 applies_to 已置空、
不再被 pipeline 路由），避免对同一域名 RDAP + WHOIS 双查（WHOIS port-43 最慢）。

结果带本地 JSON 文件缓存（键=域名，放 ``.apkscan_cache/rdap.json``）避免重复查询。

错误处理（符合规范）：网络/解析全部异常 → ok=False，不抛出、不静默；全程 logging。
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

import requests

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher
from apkscan.enrichers.whois import query_whois

logger = logging.getLogger(__name__)

#: 查询超时（秒）。
RDAP_TIMEOUT = 8

#: rdap.org 域名查询入口（HTTPS，统一 bootstrap 到各注册局/注册商 RDAP 服务）。
RDAP_URL = "https://rdap.org/domain/{domain}"

#: 本地缓存目录与文件。
CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "rdap.json"

#: RDAP event action → 我方字段名映射。
_EVENT_MAP = {
    "registration": "created",
    "expiration": "expires",
    "last changed": "updated",
}


def _to_str(value: Any) -> str | None:
    """统一成可 JSON 序列化的字符串；None/空 → None。"""
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _vcard_field(vcard_array: Any, field: str) -> str | None:
    """从 RDAP 实体的 ``vcardArray`` 取某属性（如 fn / org）的文本值。

    vcardArray 形如 ``["vcard", [["fn", {}, "text", "GoDaddy.com, LLC"], ...]]``。
    """
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    props = vcard_array[1]
    if not isinstance(props, list):
        return None
    for prop in props:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == field:
            return _to_str(prop[3])
    return None


def _entity_name(entity: dict[str, Any]) -> str | None:
    """取实体的展示名：优先 vcard 的 fn，其次 org。"""
    vcard = entity.get("vcardArray")
    return _vcard_field(vcard, "fn") or _vcard_field(vcard, "org")


def _extract_rdap(payload: dict[str, Any]) -> dict[str, Any]:
    """从 rdap.org 域名响应 JSON 提取关心字段。"""
    registrar: str | None = None
    registrant: str | None = None
    entities = payload.get("entities")
    if isinstance(entities, list):
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles") or []
            if not isinstance(roles, list):
                continue
            if "registrar" in roles and registrar is None:
                registrar = _entity_name(entity)
            if "registrant" in roles and registrant is None:
                registrant = _entity_name(entity)

    created = expires = updated = None
    events = payload.get("events")
    if isinstance(events, list):
        for ev in events:
            if not isinstance(ev, dict):
                continue
            key = _EVENT_MAP.get(str(ev.get("eventAction", "")).lower())
            if key is None:
                continue
            date = _to_str(ev.get("eventDate"))
            if key == "created" and created is None:
                created = date
            elif key == "expires" and expires is None:
                expires = date
            elif key == "updated" and updated is None:
                updated = date

    status_raw = payload.get("status")
    status: list[str] = []
    if isinstance(status_raw, list):
        status = [s for s in (_to_str(x) for x in status_raw) if s]

    nameservers: list[str] = []
    ns_raw = payload.get("nameservers")
    if isinstance(ns_raw, list):
        for ns in ns_raw:
            if isinstance(ns, dict):
                name = _to_str(ns.get("ldhName"))
                if name:
                    nameservers.append(name)

    return {
        "registrar": registrar,
        "registrant": registrant,
        "created": created,
        "expires": expires,
        "updated": updated,
        "status": status,
        "nameservers": nameservers,
        "source": "rdap",
    }


def _has_values(data: dict[str, Any]) -> bool:
    """是否含任何有效字段（忽略 source / 空容器）。"""
    for key, val in data.items():
        if key == "source":
            continue
        if val not in (None, "", [], {}):
            return True
    return False


class RdapEnricher(BaseEnricher):
    """对域名端点做 RDAP 富化（RDAP 优先 + whois 兜底）。"""

    name = "rdap"
    applies_to = ["domain"]

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 缓存
    def _load_cache(self) -> dict[str, dict[str, Any]]:
        """读缓存文件。★必须持 self._lock 调用：Windows 下读句柄 open 与另一线程的
        os.replace(rdap.json) 撞同一文件会抛 PermissionError(WinError 5)/Errno 13，
        让缓存静默丢失。读写共用一把锁消除该重叠窗口；enrich() 经 _load_cache_locked 进入。"""
        if not CACHE_FILE.is_file():
            return {}
        try:
            text = CACHE_FILE.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception:
            logger.warning("RDAP 缓存读取/解析失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        if not isinstance(data, dict):
            logger.warning("RDAP 缓存顶层非 dict，忽略：%s", CACHE_FILE)
            return {}
        return data

    def _load_cache_locked(self) -> dict[str, dict[str, Any]]:
        """持锁读缓存，供 enrich() 的命中检查用，避免与并发写的 os.replace 撞车。"""
        with self._lock:
            return self._load_cache()

    def _save_cache_entry(self, domain: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            cache[domain] = entry
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                # 原子写：临时文件 + replace，避免崩溃/并发留半截坏缓存。
                # tmp 名带 pid+线程 id 唯一后缀：避免多写者复用固定 rdap.json.tmp 互相覆盖/再撞 replace。
                tmp = CACHE_FILE.with_name(
                    f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(CACHE_FILE)
            except Exception:
                logger.warning("RDAP 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 查询
    def _query_rdap(self, domain: str) -> dict[str, Any]:
        """RDAP 网络查询；网络/HTTP/解析异常向上抛由 enrich() 的兜底逻辑处理。"""
        url = RDAP_URL.format(domain=domain)
        resp = requests.get(url, timeout=RDAP_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError(f"RDAP 返回非对象：{type(payload).__name__}")
        return _extract_rdap(payload)

    def _query_whois_fallback(self, domain: str) -> dict[str, Any]:
        """RDAP 不可用时回退 python-whois（复用 whois.query_whois）。

        把 whois 的原生字段名归一到与 RDAP 一致的形态（``creation_date`` → ``created``），
        让下游（pipeline）无论 source=rdap 还是 whois-fallback 都按同一组键读取。
        """
        raw = dict(query_whois(domain))
        return {
            "registrar": raw.get("registrar"),
            "registrant": raw.get("registrant") or raw.get("org"),
            "org": raw.get("org"),
            "created": raw.get("creation_date"),
            "country": raw.get("country"),
            "source": "whois-fallback",
        }

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        domain = (ep.value or "").strip().lower()
        if not domain:
            return EnrichmentResult(
                provider=self.name, ok=False, error="空域名，跳过 RDAP 查询"
            )

        # 1) 缓存命中直接返回（不消耗网络）。持锁读，避免与并发写 os.replace 撞车。
        cache = self._load_cache_locked()
        cached = cache.get(domain)
        if isinstance(cached, dict):
            logger.debug("RDAP 缓存命中：%s", domain)
            return EnrichmentResult(provider=self.name, ok=True, data=dict(cached))

        # 2) RDAP 优先；失败（404 / TLD 无 RDAP / 网络）记一次 warning 后回退 whois。
        rdap_err: str | None = None
        try:
            data = self._query_rdap(domain)
            if _has_values(data):
                self._save_cache_entry(domain, data)
                return EnrichmentResult(provider=self.name, ok=True, data=data)
            logger.info("RDAP 返回无有效字段，回退 whois：%s", domain)
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            rdap_err = f"{type(exc).__name__}: {exc}"
            logger.warning("RDAP 查询失败，回退 whois：%s（%s）", domain, exc)

        # 3) whois 兜底。
        try:
            data = self._query_whois_fallback(domain)
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            logger.warning("RDAP 的 whois 兜底也失败：%s（%s）", domain, exc)
            err = f"RDAP+whois 均失败: {rdap_err or 'RDAP 无结果'}; whois: {type(exc).__name__}: {exc}"
            return EnrichmentResult(provider=self.name, ok=False, error=err)

        # 4) 兜底成功但全空 → 视为查无记录（不缓存，便于重试），区分"没查到"与"查到了"。
        if not _has_values(data):
            logger.info("RDAP+whois 兜底均无有效记录，不缓存：%s", domain)
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                error="RDAP/whois 均无有效记录（可能限速/无应答，未缓存）",
            )

        self._save_cache_entry(domain, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
