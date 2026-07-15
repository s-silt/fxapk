"""Shodan 富化器：海外服务器**被动 IP 归属**取证（开放端口 / 服务 banner / 产品版本 / 归属）。

对「建议调证」的 IP / 域名查 Shodan 已扫库（``/shodan/host/{ip}``）：对目标**零流量**——Shodan 早替我们
扫过，我们只读它的库，属**被动 OSINT**。用于识别「这是不是真实源站、归属在哪」，一次拿到：

- 开放端口 ``ports`` + 每服务 ``product``/``version``/``cpe``/``http.server``/``http.title``（服务 banner
  与技术栈指纹——同后台 / 同栈可作**串案**信号）；
- ``hostnames``（历史 / 关联主机名，疑同团伙基础设施，可并簇串案）、``org``/``isp``/``asn``/归属国
  （反哺辖区判定与源站归属识别）。

★ 用途见 ``core/forensic`` 海外（国外）分支：难直接调证 → **被动定位真实源站 IP + 提取归属标识**
（不主动探测 / 不接触任何第三方基础设施），据此并簇串案、指向可依法协作的落点。

**opt-in**：仅当配置 ``FXAPK_SHODAN_KEY``（或 ``SHODAN_API_KEY``）时启用；未配置 → 跳过(ok=False)，
核心分析不受影响。key 走项目根 ``.env``（见 ``core/dotenv``），不硬编码、不入库。仅在 ``--online`` 下
随其它富化器在线程池里跑；结果按 value 本地缓存，避免重复消耗 Shodan query 额度。

domain 端点：先用 Shodan ``/dns/resolve`` 解析成 IP 再 host 查询（域名在 CDN 后会拿到 CDN IP，属已知局限）。

合规：只查 Shodan 公开库（被动情报），不向目标发起任何连接 / 扫描 / 探测。
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

#: key 环境变量名（任一非空即启用）。FXAPK_ 前缀优先，兼容 Shodan 官方 SDK 习惯的 SHODAN_API_KEY。
_ENV_KEYS = ("FXAPK_SHODAN_KEY", "SHODAN_API_KEY")

HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
RESOLVE_URL = "https://api.shodan.io/dns/resolve"
SHODAN_TIMEOUT = 12

#: 归一化截断上限（防止个别巨型主机塞爆缓存 / 报告）。
_MAX_SERVICES = 40
_MAX_HOSTNAMES = 30

CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "shodan.json"


def _api_key() -> str:
    """取 Shodan API key（任一环境变量非空即用）；未配置返回空串。"""
    for name in _ENV_KEYS:
        val = (os.environ.get(name) or "").strip()
        if val:
            return val
    return ""


class _ShodanMiss(Exception):
    """Shodan 库中无该主机记录（HTTP 404）——属"查无结果"而非错误，单独处理以便缓存避免复查。"""


def _as_dict(value: object) -> dict[str, Any]:
    """value 是 dict 则返回之，否则空 dict（兼容缺字段 / 坏结构）。"""
    return value if isinstance(value, dict) else {}


def _parse_host(payload: dict[str, Any]) -> dict[str, Any]:
    """把 ``/shodan/host`` 原始 JSON 归一成稳定扁平字段（缺字段安全留空）。

    只保留**被动归属 / 服务 banner / 技术栈指纹**字段（识别真实源站与归属、供同栈串案）；
    不采集任何漏洞 / 利用向的字段。
    """
    services: list[dict[str, Any]] = []
    for svc in payload.get("data") or []:
        if not isinstance(svc, dict):
            continue
        http = _as_dict(svc.get("http"))
        shodan_meta = _as_dict(svc.get("_shodan"))
        services.append(
            {
                "port": svc.get("port"),
                "transport": svc.get("transport"),
                "module": shodan_meta.get("module"),
                "product": svc.get("product"),
                "version": svc.get("version"),
                "cpe": svc.get("cpe") or svc.get("cpe23"),  # 技术栈指纹（供 exposure 串案），非漏洞判定
                "http_server": http.get("server"),
                "http_title": http.get("title"),
            }
        )
        if len(services) >= _MAX_SERVICES:
            break

    ports = sorted({p for p in (payload.get("ports") or []) if isinstance(p, int)})
    return {
        "ip": payload.get("ip_str") or payload.get("ip"),
        "ports": ports,
        "services": services,
        "hostnames": [h for h in (payload.get("hostnames") or []) if isinstance(h, str)][
            :_MAX_HOSTNAMES
        ],
        "org": payload.get("org"),
        "isp": payload.get("isp"),
        "asn": payload.get("asn"),
        "country": payload.get("country_name") or payload.get("country_code"),
        "os": payload.get("os"),
        "tags": [t for t in (payload.get("tags") or []) if isinstance(t, str)],
        "source": "shodan",
    }


class ShodanEnricher(BaseEnricher):
    """对 IP / 域名查 Shodan 已扫库，产出服务器**被动归属画像**（opt-in，配 FXAPK_SHODAN_KEY 才启用）。

    产出仅用于识别「是否真实源站、归属在哪、同栈可否串案」，对目标零流量、不做任何漏洞 / 利用判定。
    """

    name = "shodan"
    applies_to = ["ip", "domain"]
    #: 境外归属阶段（两遍富化第二遍）；被动（active=False，查 Shodan 库、对目标零流量），仅对国外(+未知)端点跑。
    phase = "overseas"
    active = False
    required_env = _ENV_KEYS

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 缓存
    def _load_cache(self) -> dict[str, dict[str, Any]]:
        """读缓存文件。★必须持 self._lock 调用：Windows 下读句柄 open 与另一线程的
        os.replace(shodan.json) 撞同一文件会抛 PermissionError(WinError 5)/Errno 13，
        让缓存静默丢失。读写共用一把锁消除该重叠窗口；enrich() 经 _load_cache_locked 进入。"""
        if not CACHE_FILE.is_file():
            return {}
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("Shodan 缓存读取/解析失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        if not isinstance(data, dict):
            logger.warning("Shodan 缓存顶层非 dict，忽略：%s", CACHE_FILE)
            return {}
        return data

    def _load_cache_locked(self) -> dict[str, dict[str, Any]]:
        """持锁读缓存，供 enrich() 的命中检查用，避免与并发写的 os.replace 撞车。"""
        with self._lock:
            return self._load_cache()

    def _save_cache_entry(self, value: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            cache[value] = entry
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                # 原子写：临时文件 + replace，避免崩溃/并发留半截坏缓存。
                # tmp 名带 pid+线程 id 唯一后缀：避免多写者复用固定 shodan.json.tmp 互相覆盖/再撞 replace。
                tmp = CACHE_FILE.with_name(
                    f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(CACHE_FILE)
            except Exception:
                logger.warning("Shodan 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 查询
    def _resolve(self, domain: str, key: str) -> str | None:
        """用 Shodan dns/resolve 把域名解析成 IP；解析不到返回 None。网络异常向上抛由 enrich 兜底。"""
        resp = requests.get(
            RESOLVE_URL, params={"hostnames": domain, "key": key}, timeout=SHODAN_TIMEOUT
        )
        resp.raise_for_status()
        payload = resp.json()
        if isinstance(payload, dict):
            ip = payload.get(domain)
            if isinstance(ip, str) and ip.strip():
                return ip.strip()
        return None

    def _query(self, value: str, kind: str, key: str) -> dict[str, Any]:
        """解析（域名时）→ host 查询 → 归一。404（库中无记录）抛 _ShodanMiss；其余异常向上抛。"""
        if kind == "domain":
            ip = self._resolve(value, key)
            if not ip:
                raise _ShodanMiss(f"Shodan 无法解析域名为 IP：{value}")
        else:
            ip = value

        resp = requests.get(HOST_URL.format(ip=ip), params={"key": key}, timeout=SHODAN_TIMEOUT)
        if resp.status_code == 404:
            raise _ShodanMiss(f"Shodan 库中无该主机记录：{ip}")
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError(f"Shodan 返回非对象：{type(payload).__name__}")
        return _parse_host(payload)

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        value = (ep.value or "").strip()
        if not value:
            return EnrichmentResult(provider=self.name, ok=False, error="空值，跳过 Shodan 查询")

        key = _api_key()
        if not key:
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                error=f"未配置 {_ENV_KEYS[0]}，跳过 Shodan（opt-in）",
            )

        # 1) 缓存命中直接返回（不消耗 query 额度）。持锁读，避免与并发写 os.replace 撞车（Windows race）。
        cache = self._load_cache_locked()
        cached = cache.get(value)
        if isinstance(cached, dict):
            logger.debug("Shodan 缓存命中：%s", value)
            return EnrichmentResult(provider=self.name, ok=True, data=dict(cached))

        # 2) 网络查询。
        try:
            data = self._query(value, ep.kind, key)
        except _ShodanMiss as miss:
            # 库中无记录：缓存空标记避免复查（耗额度），按"查询无结果"返回（ok=True 无值）。
            entry = {"note": str(miss), "source": "shodan"}
            self._save_cache_entry(value, entry)
            return EnrichmentResult(provider=self.name, ok=True, data=entry)
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            # requests 的异常文本可能包含带 key 的完整 URL，只保留异常类型，避免密钥进日志/报告。
            error_type = type(exc).__name__
            logger.debug("Shodan 查询失败：%s（%s）", value, error_type)
            return EnrichmentResult(provider=self.name, ok=False, error=error_type)

        # 3) 成功才写缓存（失败不缓存，便于后续重试）。
        self._save_cache_entry(value, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
