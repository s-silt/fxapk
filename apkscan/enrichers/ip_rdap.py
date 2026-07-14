"""IP RDAP 富化器：查 IP 的 RDAP 拿**资源登记方**（netname / 登记机构 / 国家），填五层归因第 1 层。

``rdap.org/ip/{ip}`` bootstrap 到各 RIR（ARIN/RIPE/APNIC/LACNIC/AFRINIC）的 RDAP 服务。
★这是 IP **资源持有方**（谁持有该网段，从 IP RDAP/WHOIS 登记），区别于：
  - 域名 RDAP（rdap 富化器，applies_to=['domain']）= 域名注册方，**不是** IP 资源持有方；
  - ip-api 的 ISP/org（asn 富化器）= 网络运营方，粒度粗、非权威登记。
故本富化器专供 core/attribution 的 ``resource_holder`` 层（第 1 层）——此前恒 unknown，因为没有 IP 级
权威登记源。被动 OSINT（对目标零流量，HTTPS）。

错误处理（符合规范）：网络/HTTP/解析异常 → ok=False 不抛不静默；查无有效记录（全空）→ 不缓存，便于重试。
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

logger = logging.getLogger(__name__)

#: 查询超时（秒）。
IP_RDAP_TIMEOUT = 8

#: rdap.org IP 查询入口（HTTPS，bootstrap 到各 RIR RDAP 服务）。
IP_RDAP_URL = "https://rdap.org/ip/{ip}"

#: 本地缓存目录与文件。
CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "ip_rdap.json"


def _to_str(value: Any) -> str | None:
    """统一成可 JSON 序列化的字符串；None/空 → None。"""
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _vcard_value(value: Any) -> str | None:
    """jCard 属性值 → 字符串。RFC 7095：值可为字符串或**结构化数组**（如 org 的 [机构, 部门]）；
    数组只取其中的字符串组件、过滤空后用空格连接；dict/嵌套等非法类型 → None（不产 repr 垃圾）。"""
    if isinstance(value, str):
        return _to_str(value)
    if isinstance(value, list):
        parts = [p for p in (_to_str(v) for v in value if isinstance(v, str)) if p]
        return " ".join(parts) or None
    return None


def _vcard_field(vcard_array: Any, field: str) -> str | None:
    """从 RDAP 实体的 ``vcardArray`` 取某属性（fn/org）的文本值。

    vcardArray 形如 ``["vcard", [["fn", {}, "text", "APNIC Pty Ltd"], ...]]``；值可为字符串或结构化数组。
    """
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    props = vcard_array[1]
    if not isinstance(props, list):
        return None
    for prop in props:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == field:
            return _vcard_value(prop[3])
    return None


def _registrant_org(payload: dict[str, Any]) -> str | None:
    """取网段**登记机构**名：★仅认 role 含 ``registrant`` 的实体（RFC 9083：abuse/technical/administrative
    是联系人、**不是**资源持有方，绝不 fallback 到它们冒充持有方）。机构名优先 ``org``、其次 ``fn``。
    无 registrant → None，交由顶层 ``name``(netname) 兜底。"""
    entities = payload.get("entities")
    if not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles") or []
        if not (isinstance(roles, list) and "registrant" in roles):
            continue
        vcard = entity.get("vcardArray")
        name = _vcard_field(vcard, "org") or _vcard_field(vcard, "fn")  # 机构名(org)优先于联系人名(fn)
        if name:
            return name
    return None


def _extract_ip_rdap(payload: dict[str, Any]) -> dict[str, Any]:
    """从 rdap.org IP 响应 JSON 提取资源登记方字段（netname/org/country/handle/网段）。"""
    return {
        "netname": _to_str(payload.get("name")),          # 网段名（最直接的资源持有标识）
        "org": _registrant_org(payload),                   # 登记机构名
        "country": _to_str(payload.get("country")),        # RIR 提供的归属国
        "handle": _to_str(payload.get("handle")),
        "cidr": _to_str(payload.get("startAddress")),      # 网段起始（便于人工核网段范围）
        "source": "rdap-ip",
    }


def _has_values(data: dict[str, Any]) -> bool:
    """是否含任何有效登记字段（忽略 source/cidr 等非归属字段）。"""
    return any(data.get(k) for k in ("netname", "org", "country", "handle"))


class IpRdapEnricher(BaseEnricher):
    """对 IP 端点做 RDAP 富化（资源持有方 netname/登记机构/国家）——填 attribution resource_holder 层。"""

    name = "ip_rdap"
    applies_to = ["ip"]

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 缓存
    def _load_cache(self) -> dict[str, dict[str, Any]]:
        """读缓存文件。★必须持 self._lock 调用：Windows 下读句柄 open 与另一线程的
        os.replace(ip_rdap.json) 撞同一文件会抛 PermissionError(WinError 5)/Errno 13，
        让缓存静默丢失。读写共用一把锁消除该重叠窗口；enrich() 经 _load_cache_locked 进入。"""
        if not CACHE_FILE.is_file():
            return {}
        try:
            text = CACHE_FILE.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception:
            logger.warning("IP-RDAP 缓存读取/解析失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        if not isinstance(data, dict):
            logger.warning("IP-RDAP 缓存顶层非 dict，忽略：%s", CACHE_FILE)
            return {}
        return data

    def _load_cache_locked(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return self._load_cache()

    def _save_cache_entry(self, ip: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            cache[ip] = entry
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                # 原子写：临时文件 + replace，避免崩溃/并发留半截坏缓存。
                # tmp 名带 pid+线程 id 唯一后缀：避免多写者复用固定 ip_rdap.json.tmp 互相覆盖/再撞 replace。
                tmp = CACHE_FILE.with_name(
                    f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(CACHE_FILE)
            except Exception:
                logger.warning("IP-RDAP 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 查询
    def _query(self, ip: str) -> dict[str, Any]:
        """RDAP 网络查询；网络/HTTP/解析异常向上抛由 enrich() 兜底。"""
        resp = requests.get(IP_RDAP_URL.format(ip=ip), timeout=IP_RDAP_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError(f"IP-RDAP 返回非对象：{type(payload).__name__}")
        return _extract_ip_rdap(payload)

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        ip = (ep.value or "").strip()
        if not ip:
            return EnrichmentResult(provider=self.name, ok=False, error="空 IP，跳过 IP-RDAP 查询")

        # 1) 缓存命中直接返回（不消耗网络）。持锁读，避免与并发写 os.replace 撞车（Windows race）。
        cache = self._load_cache_locked()
        cached = cache.get(ip)
        if isinstance(cached, dict):
            logger.debug("IP-RDAP 缓存命中：%s", ip)
            return EnrichmentResult(provider=self.name, ok=True, data=dict(cached))

        # 2) 网络查询，全部异常吞成 ok=False，绝不炸主流程。
        try:
            data = self._query(ip)
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            logger.debug("IP-RDAP 查询失败：%s（%s）", ip, exc)
            return EnrichmentResult(provider=self.name, ok=False, error=f"{type(exc).__name__}: {exc}")

        # 3) 区分"查到了"与"全空"：全空（限速/无应答/无记录）不缓存，便于重试。
        if not _has_values(data):
            logger.debug("IP-RDAP 返回无有效登记字段，不缓存：%s", ip)
            return EnrichmentResult(provider=self.name, ok=False, error="IP-RDAP 无有效记录（未缓存）")

        self._save_cache_entry(ip, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
