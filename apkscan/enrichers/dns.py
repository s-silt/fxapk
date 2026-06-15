"""DNS 富化器：DoH 解析域名 A 记录 + 对每个解析 IP 查托管（云厂商/IDC）。

为什么有它：注册归属（rdap/whois）回答"谁注册了这个域名"，但诈骗 App 的真后端往往
托管在云上——把域名当前**解析到的 IP** 及其 **ASN/机构**摸清，才能定位"向哪家云厂商调
租户/访问日志"。这条是注册归属之外的第二条调证落点。

策略：
- DoH（DNS over HTTPS）优先：``https://dns.google/resolve?name=<d>&type=A``（HTTPS，比明文
  UDP 53 更难被在途投毒/观测）。
- DoH 失败 → 回退本机 ``socket.gethostbyname_ex``（系统解析器）。
- 对每个解析出的 IP 复用 ``_ipinfo.lookup_ip`` 拿托管(org/asn/country/isp)——与 asn 富化器
  同一份查询逻辑，不重复造轮子。
- data = ``{ips: [...], hosting: [{ip, asn, org, country, isp}, ...]}``。

结果带本地 JSON 文件缓存（键=域名，放 ``.apkscan_cache/dns.json``）避免重复查询。

错误处理（符合规范）：网络/解析全部异常 → ok=False，不抛出、不静默；全程 logging。
ip-api 免费档 45/min 硬限：托管查询前过共享限速器，避免与 asn 富化器叠加触发 429。
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
from apkscan.enrichers._ipinfo import lookup_ip

logger = logging.getLogger(__name__)

#: DoH 查询超时（秒）。
DNS_TIMEOUT = 8

#: 单 IP 托管查询超时（秒）。
HOSTING_TIMEOUT = 8

#: Google DoH JSON API（HTTPS）。
DOH_URL = "https://dns.google/resolve"

#: DNS A 记录类型码（RFC 1035）。
_DNS_TYPE_A = 1

#: ip-api 免费档 45/min → 安全间隔（与 asn 富化器一致，避免叠加触发 429）。
HOSTING_MIN_INTERVAL = 1.4

#: 本地缓存目录与文件。
CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "dns.json"


def _resolve_doh(domain: str) -> list[str]:
    """用 Google DoH 解析 A 记录，返回 IP 列表；网络/解析异常向上抛由调用方兜底。"""
    resp = requests.get(
        DOH_URL,
        params={"name": domain, "type": "A"},
        headers={"accept": "application/dns-json"},
        timeout=DNS_TIMEOUT,
    )
    resp.raise_for_status()
    payload = resp.json()
    if not isinstance(payload, dict):
        raise ValueError(f"DoH 返回非对象：{type(payload).__name__}")

    ips: list[str] = []
    answers = payload.get("Answer")
    if isinstance(answers, list):
        for ans in answers:
            if not isinstance(ans, dict):
                continue
            if ans.get("type") != _DNS_TYPE_A:  # 只取 A 记录，忽略 CNAME 等
                continue
            ip = ans.get("data")
            if isinstance(ip, str) and ip.strip():
                ips.append(ip.strip())
    return ips


def _resolve_socket(domain: str) -> list[str]:
    """回退：本机系统解析器；异常向上抛由调用方兜底。"""
    _name, _aliases, addrs = socket.gethostbyname_ex(domain)
    return [a for a in addrs if a]


class DnsEnricher(BaseEnricher):
    """对域名端点做 DNS 富化（DoH A 记录 + 每 IP 托管归属）。"""

    name = "dns"
    applies_to = ["domain"]

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()
        # ip-api 限速：记录上次托管查询时间戳（单调时钟），串行化访问。
        self._rate_lock = threading.Lock()
        self._last_query_ts: float = 0.0

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

    def _save_cache_entry(self, domain: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            cache[domain] = entry
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                tmp = CACHE_FILE.with_name(
                    f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(CACHE_FILE)
            except Exception:
                logger.warning("DNS 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 限速
    def _respect_rate_limit(self) -> None:
        """每次真实托管查询前确保与上次间隔 >= HOSTING_MIN_INTERVAL 秒。"""
        with self._rate_lock:
            elapsed = time.monotonic() - self._last_query_ts
            wait = HOSTING_MIN_INTERVAL - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_query_ts = time.monotonic()

    # ------------------------------------------------------------------ 托管
    def _hosting(self, ips: list[str]) -> list[dict[str, Any]]:
        """对每个 IP 查托管归属；单 IP 失败不阻塞其余，记 warning 后跳过该 IP。"""
        hosting: list[dict[str, Any]] = []
        for ip in ips:
            self._respect_rate_limit()
            try:
                info = lookup_ip(ip, http=requests, timeout=HOSTING_TIMEOUT)
            except Exception as exc:  # noqa: BLE001 — 单 IP 托管失败不阻塞其余
                logger.warning("DNS 托管查询失败：%s（%s）", ip, exc)
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
        return hosting

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        domain = (ep.value or "").strip().lower()
        if not domain:
            return EnrichmentResult(
                provider=self.name, ok=False, error="空域名，跳过 DNS 查询"
            )

        # 1) 缓存命中直接返回（不消耗网络）。
        cache = self._load_cache_locked()
        cached = cache.get(domain)
        if isinstance(cached, dict):
            logger.debug("DNS 缓存命中：%s", domain)
            return EnrichmentResult(provider=self.name, ok=True, data=dict(cached))

        # 2) DoH 优先解析 A 记录；失败回退本机解析器。
        ips: list[str] = []
        doh_err: str | None = None
        try:
            ips = _resolve_doh(domain)
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            doh_err = f"{type(exc).__name__}: {exc}"
            logger.warning("DoH 解析失败，回退系统解析器：%s（%s）", domain, exc)

        if not ips:
            try:
                ips = _resolve_socket(domain)
            except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
                logger.warning("DNS 解析失败（DoH+系统解析器）：%s（%s）", domain, exc)
                err = doh_err or f"{type(exc).__name__}: {exc}"
                return EnrichmentResult(
                    provider=self.name, ok=False, error=f"DNS 解析失败: {err}"
                )

        if not ips:
            return EnrichmentResult(
                provider=self.name, ok=False, error="DNS 无 A 记录（解析为空）"
            )

        # 3) 对每个 IP 查托管归属。
        hosting = self._hosting(ips)
        data = {"ips": ips, "hosting": hosting}

        # 4) 解析成功即缓存（即便托管查询部分失败，IP 列表本身已是有价值的线索）。
        self._save_cache_entry(domain, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
