"""web-check 富化器：对域名 / IP 调用自托管 web-check（lissy93/web-check）再查一轮 OSINT。

把每个「建议调证」域名 / IP 过一遍 web-check 的多项检查（服务器地理 / SSL / DNS / whois /
技术栈 / 开放端口 / 邮件配置 / 威胁情报 / 子域 …），结果并进 ``endpoint.enrichment['webcheck']``。
这一轮外部情报直接喂三处：
- **辖区分流**：``location`` 的归属国 → forensic 判国内 / 国外（见 core/forensic）。
- **国外被动定位**：``ports`` / ``tech-stack`` → 识别真实源站与技术栈 / 后台框架指纹（同后台疑同团伙 → 并簇串案）。
- **图谱串案**：``subdomains`` / ``linked-pages`` → 关联主机（后续可纳入并簇键）。

**opt-in**：仅当配置环境变量 ``FXAPK_WEBCHECK_URL``（自托管实例，如 ``http://localhost:3000``，
或公共实例 ``https://web-check.xyz``）时启用；未配置 → 跳过（ok=False），核心分析不受影响。
仅在 ``--online`` 下随其它富化器在线程池里跑。结果按 value 本地缓存避免重复查询。

合规：只做对外公开 OSINT 查询（被动情报），不向目标发起任何攻击 / 扫描；web-check 自身的
端口/技术栈检查由用户自负其责在授权范围内使用。
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher

logger = logging.getLogger(__name__)

_ENV_URL = "FXAPK_WEBCHECK_URL"
_ENV_CHECKS = "FXAPK_WEBCHECK_CHECKS"
_ENV_TIMEOUT = "FXAPK_WEBCHECK_TIMEOUT"

#: 默认 curated 检查集（调证高价值、多数免第三方 key）。用户可用 FXAPK_WEBCHECK_CHECKS 覆盖。
_DEFAULT_CHECKS: tuple[str, ...] = (
    "location",
    "get-ip",
    "whois",
    "dns",
    "dnssec",
    "ssl",
    "http-security",
    "tech-stack",
    "ports",
    "mail-config",
    "threats",
    "subdomains",
    "redirects",
    "archives",
    "firewall",
)

_DEFAULT_TIMEOUT = 12.0
CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "webcheck.json"


def _base_url() -> str:
    return (os.environ.get(_ENV_URL) or "").strip().rstrip("/")


def _checks() -> tuple[str, ...]:
    raw = (os.environ.get(_ENV_CHECKS) or "").strip()
    if not raw:
        return _DEFAULT_CHECKS
    picked = tuple(c.strip() for c in raw.split(",") if c.strip())
    return picked or _DEFAULT_CHECKS


def _timeout() -> float:
    try:
        return float(os.environ.get(_ENV_TIMEOUT) or _DEFAULT_TIMEOUT)
    except ValueError:
        return _DEFAULT_TIMEOUT


def _extract_country(location: object) -> str:
    """从 location 检查结果里尽力抽出归属国（喂 forensic 辖区判定）。取不到 → 空串。"""
    if not isinstance(location, dict):
        return ""
    for key in ("country", "country_name", "countryName", "countryCode", "country_code"):
        v = location.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


class WebCheckEnricher(BaseEnricher):
    """对域名 / IP 调 web-check 多项检查（opt-in，配 FXAPK_WEBCHECK_URL 才启用）。"""

    name = "webcheck"
    applies_to = ["domain", "ip"]

    def __init__(self) -> None:
        self._lock = threading.Lock()

    # ---- 缓存（按 value，原子写，绝不让坏缓存炸主流程） ----------------------
    def _load_cache(self) -> dict[str, Any]:
        if not CACHE_FILE.is_file():
            return {}
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("webcheck 缓存读取失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        return data if isinstance(data, dict) else {}

    def _load_cache_locked(self) -> dict[str, Any]:
        with self._lock:
            return self._load_cache()

    def _save_cache_entry(self, key: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            cache[key] = entry
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                tmp = CACHE_FILE.with_name(
                    f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(CACHE_FILE)
            except Exception:
                logger.warning("webcheck 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ---- 查询 ---------------------------------------------------------------
    def _query(self, value: str, base: str, checks: tuple[str, ...], timeout: float) -> dict[str, Any]:
        """逐项查 web-check；单检查失败只跳过该项（记入 _errors），不影响其余。"""
        out: dict[str, Any] = {}
        errors: dict[str, str] = {}
        target = quote(value, safe="")
        for check in checks:
            url = f"{base}/api/{check}?url={target}"
            try:
                resp = requests.get(url, timeout=timeout)
                if resp.status_code != 200:
                    errors[check] = f"HTTP {resp.status_code}"
                    continue
                out[check] = resp.json()
            except Exception as exc:  # noqa: BLE001 — 单检查失败不得炸主流程
                errors[check] = f"{type(exc).__name__}: {exc}"
        if errors:
            out["_errors"] = errors
        country = _extract_country(out.get("location"))
        if country:
            out["country"] = country  # 归一化，供 forensic 辖区判定直接读
        return out

    # ---- 入口 ---------------------------------------------------------------
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        value = (ep.value or "").strip()
        if not value:
            return EnrichmentResult(provider=self.name, ok=False, error="空值，跳过 web-check")
        base = _base_url()
        if not base:
            return EnrichmentResult(
                provider=self.name, ok=False, error=f"未配置 {_ENV_URL}，跳过 web-check（opt-in）"
            )

        cache = self._load_cache_locked()
        cached = cache.get(value)
        if isinstance(cached, dict):
            logger.debug("webcheck 缓存命中：%s", value)
            return EnrichmentResult(provider=self.name, ok=True, data=dict(cached))

        data = self._query(value, base, _checks(), _timeout())
        # 全部检查都失败（只有 _errors）→ 视为失败，不缓存，便于重试。
        if not any(k for k in data if k != "_errors"):
            return EnrichmentResult(
                provider=self.name, ok=False, error="web-check 全部检查失败（实例不可达？）"
            )
        self._save_cache_entry(value, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
