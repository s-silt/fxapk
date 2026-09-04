"""Shodan 富化器：境外基础设施候选（开放端口 / 服务 banner / 产品版本 / 归属）。

对「建议调证」的 IP / 域名查 Shodan 已有数据库（``/shodan/host/{ip}``）。本模块不直接连接目标
业务服务，但会把目标标识提交给 Shodan；记录可能过期，只能形成基础设施与 Origin 候选：

- 开放端口 ``ports`` + 每服务 ``product``/``version``/``cpe``/``http.server``/``http.title``（服务 banner
  与技术栈指纹——相同常见栈只能作弱候选）；
- ``hostnames``（历史 / 关联主机名候选）、``org``/``isp``/``asn``/归属国
  （反哺基础设施辖区候选与承载归属识别）。

★ 用途见 ``core/forensic`` 境外分支：区分资源登记、承载、CDN 边缘和 Origin 候选，并按合法渠道
评估调证或协作。单一 Shodan 记录不能确认 Origin、家族或运营者。

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
import re
import threading
import time
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Any


from apkscan.enrichers import _http

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
_MAX_HTTP_HEADER_VALUES = 20
_MAX_COOKIE_NAMES = 20
_MAX_HTTP_HEADER_VALUE_LENGTH = 512

# RFC 7230 token 的可见 ASCII 子集；只把合法 Cookie 名写入报告，绝不保留 Cookie 值。
_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$")

CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "shodan.json"

#: Shodan 富化缓存 TTL（秒）。主机开放端口/服务/banner 变化快（比 ASN/注册人频繁得多）——无 TTL 会把
#: 首次探测结果永久固化，主机换服务/下线后仍返回旧画像。取 24h：与 dns.py 同档，贴合主机态高波动性。
CACHE_TTL_SECONDS = 24 * 60 * 60
#: 缓存条目里记录写入时刻的字段名（epoch 秒）。旧缓存无此字段 → 视为过期、触发重查。
_CACHED_AT_KEY = "_cached_at"


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


def _http_header_values(http: dict[str, Any], name: str) -> list[str]:
    """从 Shodan ``http.headers`` 中按大小写无关方式取一个响应头的非空值。

    Shodan banner 的头值可能是字符串或字符串列表；其它形态安全忽略。数量和长度均有界，避免异常
    banner 撑大缓存或报告。此函数只供明确白名单头使用，不复制完整响应头集合。
    """
    headers = http.get("headers")
    if not isinstance(headers, dict):
        return []

    target = name.casefold()
    values: list[str] = []
    seen: set[str] = set()
    for raw_name, raw_value in headers.items():
        if not isinstance(raw_name, str) or raw_name.strip().casefold() != target:
            continue
        candidates = raw_value if isinstance(raw_value, (list, tuple)) else [raw_value]
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            value = candidate.strip()[:_MAX_HTTP_HEADER_VALUE_LENGTH]
            folded = value.casefold()
            if not value or folded in seen:
                continue
            seen.add(folded)
            values.append(value)
            if len(values) >= _MAX_HTTP_HEADER_VALUES:
                return values
    return values


def _cookie_names(http: dict[str, Any]) -> list[str]:
    """从 ``Set-Cookie`` 白名单头提取 Cookie 名；不保留值或属性。

    ``SimpleCookie`` 能处理常见的多条/合并头与 ``Expires`` 中的逗号。遇到非标准但仍以合法
    ``name=value`` 开头的头时，仅回退取首个名字；坏输入安全跳过。
    """
    names: list[str] = []
    seen: set[str] = set()
    for value in _http_header_values(http, "set-cookie"):
        parsed_names: list[str] = []
        jar = SimpleCookie()
        try:
            jar.load(value)
            parsed_names.extend(str(name) for name in jar)
        except (CookieError, ValueError):
            pass

        if not parsed_names:
            first_pair = value.split(";", 1)[0]
            candidate, separator, _ = first_pair.partition("=")
            if separator:
                parsed_names.append(candidate.strip())

        for raw_name in parsed_names:
            name = raw_name.strip().lower()
            if not _COOKIE_NAME_RE.fullmatch(name) or name in seen:
                continue
            seen.add(name)
            names.append(name)
            if len(names) >= _MAX_COOKIE_NAMES:
                return names
    return names


def _parse_host(payload: dict[str, Any]) -> dict[str, Any]:
    """把 ``/shodan/host`` 原始 JSON 归一成稳定扁平字段（缺字段安全留空）。

    只保留基础设施候选归属 / 服务 banner / 技术栈指纹字段（供分层和人工复核）；
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
                "cpe": svc.get("cpe") or svc.get("cpe23"),  # 技术栈弱候选，非漏洞判定
                "http_server": http.get("server"),
                "http_title": http.get("title"),
                "x_powered_by": _http_header_values(http, "x-powered-by"),
                "cookie_names": _cookie_names(http),
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
    """对 IP / 域名查 Shodan 已扫库，产出基础设施候选画像（opt-in，配 FXAPK_SHODAN_KEY 才启用）。

    产出仅用于候选分层和人工复核，不确认 Origin、家族或运营者，也不做任何漏洞 / 利用判定。
    """

    name = "shodan"
    applies_to = ["ip", "domain"]
    #: 境外归属阶段（两遍富化第二遍）；active=False（查 Shodan 库、不直连目标业务服务），仅对国外(+未知)端点跑。
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

    @staticmethod
    def _cache_is_fresh(entry: dict[str, Any]) -> bool:
        """缓存条目是否在 TTL 内（未过期）。无 ``_cached_at``（旧缓存）→ 判过期、触发重查。"""
        stamped = entry.get(_CACHED_AT_KEY)
        if not isinstance(stamped, (int, float)):
            return False
        return (time.time() - stamped) < CACHE_TTL_SECONDS

    def _save_cache_entry(self, value: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            # 打时间戳供 TTL 过期判断（见 CACHE_TTL_SECONDS）。
            cache[value] = {**entry, _CACHED_AT_KEY: time.time()}
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
        resp = _http.capped_get(
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

        resp = _http.capped_get(HOST_URL.format(ip=ip), params={"key": key}, timeout=SHODAN_TIMEOUT)
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

        # 1) 缓存命中且未过期直接返回（不消耗 query 额度）。过期（超 TTL / 无时间戳的旧缓存）→ 重查，
        #    避免主机换服务/下线后永久返回旧画像。持锁读，避免与并发写 os.replace 撞车（Windows race）。
        cache = self._load_cache_locked()
        cached = cache.get(value)
        if isinstance(cached, dict) and self._cache_is_fresh(cached):
            logger.debug("Shodan 缓存命中：%s", value)
            data = {k: v for k, v in cached.items() if k != _CACHED_AT_KEY}
            return EnrichmentResult(provider=self.name, ok=True, data=data)
        if isinstance(cached, dict):
            logger.debug("Shodan 缓存过期，重查：%s", value)

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
