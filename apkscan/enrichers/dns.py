"""DNS 富化器：DoH 解析域名 A 记录 + 对每个解析 IP 查托管（云厂商/IDC）。

为什么有它：注册归属（rdap/whois）回答"谁注册了这个域名"，但诈骗 App 的真后端往往
托管在云上——把域名当前**解析到的 IP** 及其 **ASN/机构**摸清，才能定位"向哪家云厂商调
租户/访问日志"。这条是注册归属之外的第二条调证落点。

策略：
- DoH（DNS over HTTPS）优先：``https://dns.google/resolve?name=<d>&type=A``（HTTPS，比明文
  UDP 53 更难被在途投毒/观测）。
- DoH 失败 → 回退本机 ``socket.gethostbyname_ex``（系统解析器）。
- 对解析出的全部 IP **一次** ``_ipinfo.lookup_ips_batch`` 批量拿托管(org/asn/country/isp)
  ——走 ip-api ``/batch`` 端点（最多 100 IP/请求），与 asn 富化器共用同一份查询逻辑与内存缓存。
  注意 ``/batch`` 端点限额 **15/min**（按 HTTP 请求计数），低于单查 ``/json`` 的 45/min，故由
  ``_ipinfo`` 内**批量专用**限速器（4.0s/次）节流，与单查闸（1.4s）独立计时、互不挤占。
- data = ``{ips: [...], hosting: [{ip, asn, org, country, isp}, ...]}``。

结果带本地 JSON 文件缓存（键=域名，放 ``.apkscan_cache/dns.json``）避免重复查询。

错误处理（符合规范）：网络/解析全部异常 → ok=False，不抛出、不静默；全程 logging。
ip-api 免费档限速：``/batch`` 端点 **15/min**（按 HTTP 请求计数），由 ``_ipinfo`` 内部的批量
专用进程级限速器（4.0s/次）节流（独立于单查 ``/json`` 的 45/min·1.4s 闸），避免触发 429。
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any

import requests

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher
from apkscan.enrichers._ipinfo import lookup_ips_batch

logger = logging.getLogger(__name__)

#: DoH 单提供方查询超时（秒）。DoH 是小 HTTP 请求、正常 <1s；3 家链式失败时按此封顶，
#: 取 4s 既容忍国内慢网、又避免失败链拖太久（最坏 ~3×4s 后落系统解析）。
DNS_TIMEOUT = 4

#: 托管批量查询超时（秒，传给 _ipinfo.lookup_ips_batch 的单次 /batch 请求）。
HOSTING_TIMEOUT = 8

#: DoH JSON API 提供方（**国内优先**，逐个尝试，首个 HTTP 成功的结果即采用）。
#: 阿里 AliDNS / 腾讯 doh.pub 国内直连（dns.google 被 GFW 墙时仍可用）；Google 作海外兜底。
#: 三家均支持同一套 Google 风格 JSON API（``?name=&type=A`` → ``Answer`` 数组）。
DOH_URLS: tuple[str, ...] = (
    "https://dns.alidns.com/resolve",   # 阿里 AliDNS（国内直连）
    "https://doh.pub/dns-query",         # 腾讯 DNSPod（国内直连）
    "https://dns.google/resolve",        # Google（海外兜底，国内常被墙）
)

#: DNS A 记录类型码（RFC 1035）。
_DNS_TYPE_A = 1
_DNS_TYPE_CNAME = 5  # CNAME 记录（DoH Answer 里 type=5），构成 CDN 边缘判定的链路信号。

#: 本地缓存目录与文件。
CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "dns.json"

#: DNS 富化缓存 TTL（秒）。DNS 解析（A 记录 + 托管归属）会随诈骗后端换 IP / 迁云而变，
#: 无 TTL 的缓存会把首次解析永久固化，导致后续再查还看到旧 IP（辖区/托管判定失真）。
#: 取 24h：既省掉同批次重复查询，又保证跨天/换基础设施时能重新解析。缓存条目写入时打
#: ``_cached_at`` 时间戳，命中时超过本 TTL 即视为过期、丢弃并重查。
CACHE_TTL_SECONDS = 24 * 60 * 60

#: 缓存条目里记录写入时刻的字段名（epoch 秒）。旧缓存无此字段 → 视为过期、触发重查。
_CACHED_AT_KEY = "_cached_at"


def _extract_a_records(payload: dict) -> list[str]:
    """从 DoH JSON 响应抽取 A 记录 IP（忽略 CNAME 等非 A 记录）。"""
    ips: list[str] = []
    answers = payload.get("Answer")
    if isinstance(answers, list):
        for ans in answers:
            if not isinstance(ans, dict) or ans.get("type") != _DNS_TYPE_A:
                continue
            ip = ans.get("data")
            if isinstance(ip, str) and ip.strip():
                ips.append(ip.strip())
    return ips


def _extract_cnames(payload: dict) -> list[str]:
    """从 DoH JSON 响应抽取 CNAME 链（type=5 记录的 data），供 CDN 边缘判定。

    纯被动——CNAME 就在同一次 A 记录查询的响应里，**不额外发任何包、不碰目标**。诈骗后端
    常把 A 记录藏在 CDN 调度域名之后（A 记录看似普通 IDC，CNAME 直指 ``*.kunlungr.com`` /
    ``*.alicdn.com``），这条链是最可靠的边缘信号之一（见 ``forensic._cname_cdn_marker``）。
    """
    cnames: list[str] = []
    answers = payload.get("Answer")
    if isinstance(answers, list):
        for ans in answers:
            if not isinstance(ans, dict) or ans.get("type") != _DNS_TYPE_CNAME:
                continue
            c = ans.get("data")
            if isinstance(c, str) and c.strip():
                cnames.append(c.strip().rstrip("."))  # 去 DNS 末点，便于子串匹配
    return cnames


def _resolve_doh(domain: str) -> tuple[list[str], list[str]]:
    """逐个 DoH 提供方解析（**国内优先**），返回 ``(A 记录 IP, CNAME 链)``，首个 HTTP 成功即采用。

    单个提供方网络/HTTP/解析失败 → 记 debug 后试下一个（国内 dns.google 常被墙，自动落到
    阿里/腾讯）。首个成功响应（即便 ``Answer`` 为空 = 该域无 A 记录）即返回，不再试其余。
    全部提供方都失败 → 抛最后一个异常，由调用方回退系统解析器。
    """
    last_exc: Exception | None = None
    for url in DOH_URLS:
        try:
            resp = requests.get(
                url,
                params={"name": domain, "type": "A"},
                headers={"accept": "application/dns-json"},
                timeout=DNS_TIMEOUT,
            )
            resp.raise_for_status()
            payload = resp.json()
            if not isinstance(payload, dict):
                raise ValueError(f"DoH 返回非对象：{type(payload).__name__}")
            return _extract_a_records(payload), _extract_cnames(payload)
        except Exception as exc:  # noqa: BLE001 - 单提供方失败试下一个，不中断
            last_exc = exc
            logger.debug("DoH 提供方失败，试下一个：%s（%s: %s）", url, type(exc).__name__, exc)
            continue
    if last_exc is not None:
        raise last_exc
    return [], []


def _resolve_socket(domain: str) -> tuple[list[str], list[str]]:
    """回退：本机系统解析器；异常向上抛由调用方兜底。

    ``gethostbyname_ex`` 的 aliases 即 CNAME 别名，一并回带供 CDN 边缘判定（纯本地解析，被动）。
    """
    _name, aliases, addrs = socket.gethostbyname_ex(domain)
    return [a for a in addrs if a], [c for c in aliases if isinstance(c, str) and c]


class DnsEnricher(BaseEnricher):
    """对域名端点做 DNS 富化（DoH A 记录 + 每 IP 托管归属）。"""

    name = "dns"
    applies_to = ["domain"]

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 缓存
    def _load_cache(self) -> dict[str, dict[str, Any]]:
        """读缓存文件。★必须持 self._lock 调用（Windows os.replace race，见 asn/rdap 注释）。"""
        if not CACHE_FILE.is_file():
            return {}
        try:
            text = CACHE_FILE.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception:
            logger.warning("DNS 缓存读取/解析失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        if not isinstance(data, dict):
            logger.warning("DNS 缓存顶层非 dict，忽略：%s", CACHE_FILE)
            return {}
        return data

    def _load_cache_locked(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return self._load_cache()

    @staticmethod
    def _cache_is_fresh(entry: dict[str, Any]) -> bool:
        """缓存条目是否在 TTL 内（未过期）。无 ``_cached_at``（旧缓存）→ 判过期、触发重查。"""
        stamped = entry.get(_CACHED_AT_KEY)
        if not isinstance(stamped, (int, float)):
            return False
        return (time.time() - stamped) < CACHE_TTL_SECONDS

    def _save_cache_entry(self, domain: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            # 打时间戳供 TTL 过期判断（见 CACHE_TTL_SECONDS）。
            cache[domain] = {**entry, _CACHED_AT_KEY: time.time()}
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                tmp = CACHE_FILE.with_name(
                    f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(CACHE_FILE)
            except Exception:
                logger.warning("DNS 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 托管
    def _hosting(self, ips: list[str]) -> tuple[list[dict[str, Any]], bool]:
        """对解析出的全部 IP **一次** 批量查托管归属（ip-api ``/batch``）。

        限速（/batch 专用 4.0s 闸）+ 去重 + 共享内存缓存均下沉到 ``_ipinfo.lookup_ips_batch``；
        本处只负责按原 IP 顺序拼出 ``hosting`` 列表。批量返回里查不到
        的 IP（网络/语义失败被跳过）不进 hosting，但其 IP 仍保留在 ``data["ips"]``——IP 列表
        本身已是有价值的调证线索。

        返回 ``(hosting, incomplete)``：整批查询异常（如 429/限速、网络失败）→
        ``incomplete=True`` 且 hosting 为空，供调用方**不固化**该结果（否则一次限速空响应会
        被永久缓存，冻结托管/辖区判定）。整批异常向上不抛（吞成 incomplete，记 debug）。
        """
        try:
            table = lookup_ips_batch(ips, http=requests, timeout=HOSTING_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — 托管整批失败不阻塞 IP 列表，但标 incomplete
            logger.debug("DNS 托管批量查询失败（限速/网络？不缓存该结果）：%s（%s）", ips, exc)
            return [], True
        hosting: list[dict[str, Any]] = []
        for ip in ips:
            info = table.get(ip)
            if info is None:
                continue
            hosting.append(
                {
                    "ip": ip,
                    "asn": info.get("asn"),
                    "org": info.get("org"),
                    "country": info.get("country"),
                    "isp": info.get("isp"),
                }
            )
        return hosting, False

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        domain = (ep.value or "").strip().lower()
        if not domain:
            return EnrichmentResult(
                provider=self.name, ok=False, error="空域名，跳过 DNS 查询"
            )

        # 1) 缓存命中且未过期直接返回（不消耗网络）。过期（超 TTL / 无时间戳的旧缓存）→ 重查。
        cache = self._load_cache_locked()
        cached = cache.get(domain)
        if isinstance(cached, dict) and self._cache_is_fresh(cached):
            logger.debug("DNS 缓存命中：%s", domain)
            data = {k: v for k, v in cached.items() if k != _CACHED_AT_KEY}
            return EnrichmentResult(provider=self.name, ok=True, data=data)
        if isinstance(cached, dict):
            logger.debug("DNS 缓存过期，重查：%s", domain)

        # 2) DoH 优先解析 A 记录（+同响应里的 CNAME 链）；失败回退本机解析器。
        ips: list[str] = []
        cnames: list[str] = []
        doh_err: str | None = None
        try:
            ips, cnames = _resolve_doh(domain)
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            doh_err = f"{type(exc).__name__}: {exc}"
            logger.debug("DoH 解析失败，回退系统解析器：%s（%s）", domain, exc)

        if not ips:
            try:
                ips, cnames = _resolve_socket(domain)
            except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
                logger.debug("DNS 解析失败（DoH+系统解析器）：%s（%s）", domain, exc)
                err = doh_err or f"{type(exc).__name__}: {exc}"
                return EnrichmentResult(
                    provider=self.name, ok=False, error=f"DNS 解析失败: {err}"
                )

        if not ips:
            return EnrichmentResult(
                provider=self.name, ok=False, error="DNS 无 A 记录（解析为空）"
            )

        # 3) 对每个 IP 查托管归属。
        hosting, incomplete = self._hosting(ips)
        data: dict[str, Any] = {"ips": ips, "hosting": hosting}
        if cnames:
            # CNAME 链（被动，同 DoH 响应/系统解析器 aliases）→ 喂 forensic 的 CDN 边缘判定。
            data["cname"] = cnames
        if incomplete:
            # 托管整批因限速/网络失败 → 标不完整；返回结果仍带 IP 列表（有价值），但**不写缓存**，
            # 避免把一次限速空响应永久固化、冻结托管/辖区判定，下次运行可重查补全。
            data["hosting_incomplete"] = True
            logger.debug("DNS 托管不完整（限速/网络），不缓存以便重查：%s", domain)
            return EnrichmentResult(provider=self.name, ok=True, data=data)

        # 4) 解析成功且托管完整才缓存（即便个别 IP 托管查不到，整批未失败仍算完整）。
        self._save_cache_entry(domain, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
