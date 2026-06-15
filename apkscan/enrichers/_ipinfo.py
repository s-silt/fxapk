"""共享 IP 归属查询：单 / 批量 IP → ISP / 机构(云厂商 / IDC) / ASN / 国家。

把对 ip-api.com 的查询集中到本模块，供 asn（IP 富化器）与 dns（域名解析后查托管）共用：

- **分端点限速器**：ip-api 免费档**两个端点限额不同**——单查 ``/json`` 为 45/min、批量
  ``/batch`` 为 15/min（官方文档；/batch 按 **HTTP 请求**计数，不按批内 IP 数）。故单查与
  批量各走一把**进程级线程安全限速器**（单查 1.4s ≈43/min、批量 4.0s ≈15/min），asn 与 dns
  在各自端点上共用同一把闸，避免各自独立限速叠加触发 429 封禁。两闸独立计时，互不挤占。
- **共享内存缓存**：同一次运行内同一 IP 只查一次 —— 跨 asn/dns、跨多个共用同组 IP 的域名
  （如同一团伙多域名指向同一组后端 IP）去重，省去大批重复查询。
- **批量查询**：``lookup_ips_batch`` 用 ip-api ``/batch`` 端点（最多 100 IP/请求），把
  N 个 IP 的 N×限速间隔压成 ``ceil(N/100)`` 个请求，多 IP 场景耗时大降。

⚠️ 明文 HTTP：ip-api 免费档不支持 HTTPS（HTTPS 需付费 key）。仅对"建议调证"端点查询已缩小
暴露面（见 asn.py 注释）。

错误处理：网络/HTTP/解析异常向上抛，由调用方 ``enrich`` 统一转 ok=False；接口语义失败
（``status != "success"``）以 ValueError 抛出（单查）/ 跳过该 IP（批量）。
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

#: 查询超时（秒）。
IPINFO_TIMEOUT = 8

#: ip-api 免费接口（明文 HTTP，见模块 docstring）。单查 + 批量端点。
IPINFO_API_URL = "http://ip-api.com/json/{ip}"
IPINFO_BATCH_URL = "http://ip-api.com/batch"
IPINFO_FIELDS = "status,country,isp,org,as,query"

#: 单查 ``/json`` 端点 ≈45/min → 安全间隔（60/45≈1.33，取 1.4s 留余量；1.0s 会触发 429 封禁）。
IPINFO_MIN_INTERVAL = 1.4

#: 批量 ``/batch`` 端点 15/min（官方文档，按 HTTP 请求计数）→ 安全间隔 60/15=4.0s。
#: 与单查闸**独立**：/batch 限额低得多，复用 1.4s 单查闸会把 batch POST 推到 ~43/min（≈上限
#: 3 倍）→ 429 封源。dns 富化器每域名打一次 /batch，DNS-heavy 工况几乎全是 batch POST，故
#: 必须单设此更保守的闸。
IPINFO_BATCH_MIN_INTERVAL = 4.0

#: 单次 /batch 最多 IP 数（ip-api 上限 100）。
IPINFO_BATCH_MAX = 100

# 限速走模块级可替换的间接函数 _SLEEP / _MONOTONIC（默认指向 stdlib time）：测试只 monkeypatch
# 本模块这两个名字即可禁/控限速，不污染全进程 time.sleep（避免误把别处的 time.sleep 也置空）。
_SLEEP = time.sleep
_MONOTONIC = time.monotonic

# 进程级共享状态：单查/批量各一把限速锁与时钟（端点限额不同，独立计时互不挤占）；内存缓存
# 用 _CACHE_LOCK（分开，避免缓存读被限速 sleep 阻塞）。各锁顺序无嵌套，无死锁风险。
_RATE_LOCK = threading.Lock()
_RATE_BATCH_LOCK = threading.Lock()
_CACHE_LOCK = threading.Lock()
_last_call: float = 0.0
_last_batch_call: float = 0.0
_cache: dict[str, dict[str, str | None]] = {}


def reset_state() -> None:
    """清空共享缓存并重置单查/批量两把限速时钟。供测试隔离用（生产不调用）。"""
    global _last_call, _last_batch_call
    with _CACHE_LOCK:
        _cache.clear()
    with _RATE_LOCK:
        _last_call = 0.0
    with _RATE_BATCH_LOCK:
        _last_batch_call = 0.0


def _respect_rate_limit() -> None:
    """单查端点限速：保证相邻两次 ``/json`` 请求间隔 ≥ IPINFO_MIN_INTERVAL（≈45/min）。

    持锁 sleep → 并发下所有单查请求被串行化到该节奏（这正是 /json 45/min 硬限要求的；
    RDAP/DoH 等无硬限的查询仍由 pipeline 的线程池并发，不受此影响）。
    ★ sleep 必须在锁内：持锁 sleep 才能真正串行化；移到锁外会让多线程同时穿过 → 退化失效。
    """
    global _last_call
    with _RATE_LOCK:
        wait = IPINFO_MIN_INTERVAL - (_MONOTONIC() - _last_call)
        if wait > 0:
            _SLEEP(wait)
        _last_call = _MONOTONIC()


def _respect_batch_rate_limit() -> None:
    """批量端点限速：保证相邻两次 ``/batch`` POST 间隔 ≥ IPINFO_BATCH_MIN_INTERVAL（≈15/min）。

    与 ``_respect_rate_limit`` 用**独立**的锁与时钟（_RATE_BATCH_LOCK / _last_batch_call），
    因 /batch 限额（15/min）远低于单查（45/min），两端点须分别计时、互不挤占节奏。
    同样持锁 sleep 以串行化（见 ``_respect_rate_limit`` 说明）。
    """
    global _last_batch_call
    with _RATE_BATCH_LOCK:
        wait = IPINFO_BATCH_MIN_INTERVAL - (_MONOTONIC() - _last_batch_call)
        if wait > 0:
            _SLEEP(wait)
        _last_batch_call = _MONOTONIC()


def _cache_get(ip: str) -> dict[str, str | None] | None:
    with _CACHE_LOCK:
        hit = _cache.get(ip)
        return dict(hit) if hit is not None else None


def _cache_put(ip: str, info: dict[str, str | None]) -> None:
    with _CACHE_LOCK:
        _cache[ip] = dict(info)


def _to_str(value: Any) -> str | None:
    """统一成可 JSON 序列化的字符串；None/空 → None。"""
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _extract(payload: dict[str, Any]) -> dict[str, str | None]:
    """从 ip-api 返回 JSON 提取关心字段（isp / org=云厂商 / asn / country）。"""
    return {
        "isp": _to_str(payload.get("isp")),
        "org": _to_str(payload.get("org")),
        "asn": _to_str(payload.get("as")),
        "country": _to_str(payload.get("country")),
    }


def lookup_ip(ip: str, *, http: Any = None, timeout: int = IPINFO_TIMEOUT) -> dict[str, str | None]:
    """对单个 IP 查 ip-api，返回 ``{isp, org, asn, country}``。命中共享缓存则不触网。

    :param http: requests 兼容模块（须有 ``get``）。默认本模块 ``requests``；asn 透传自己
        （被测试 monkeypatch 的）requests，保持既有 mock 路径。
    :raises ValueError: 接口返回非对象 / ``status != "success"``。
    :raises Exception: 网络/HTTP/解析异常原样向上抛。
    """
    cached = _cache_get(ip)
    if cached is not None:
        return cached

    client = http if http is not None else requests
    _respect_rate_limit()
    resp = client.get(IPINFO_API_URL.format(ip=ip), params={"fields": IPINFO_FIELDS}, timeout=timeout)
    resp.raise_for_status()
    payload = resp.json()
    if not isinstance(payload, dict):
        raise ValueError(f"ip-api 返回非对象：{type(payload).__name__}")
    if payload.get("status") != "success":
        message = payload.get("message") or payload.get("status") or "unknown"
        raise ValueError(f"ip-api 查询未成功：{message}")

    info = _extract(payload)
    _cache_put(ip, info)
    return info


def lookup_ips_batch(
    ips: list[str], *, http: Any = None, timeout: int = IPINFO_TIMEOUT
) -> dict[str, dict[str, str | None]]:
    """批量查多个 IP 的归属，返回 ``{ip: {isp,org,asn,country}}``（仅含查到的 IP）。

    先吃共享缓存，未命中的去重后按 100/批走 ip-api ``/batch``；每批前过**批量专用**限速器
    （IPINFO_BATCH_MIN_INTERVAL=4.0s，/batch 端点 15/min，独立于单查 1.4s 闸）。
    单个 IP 在批量响应里 ``status != success`` → 跳过（不入结果、不缓存，允许后续重试）。
    整批网络/HTTP/解析异常向上抛由调用方兜底。
    """
    client = http if http is not None else requests
    result: dict[str, dict[str, str | None]] = {}
    todo: list[str] = []
    seen: set[str] = set()
    for ip in ips:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        cached = _cache_get(ip)
        if cached is not None:
            result[ip] = cached
        else:
            todo.append(ip)

    for start in range(0, len(todo), IPINFO_BATCH_MAX):
        chunk = todo[start : start + IPINFO_BATCH_MAX]
        _respect_batch_rate_limit()
        body = [{"query": ip, "fields": IPINFO_FIELDS} for ip in chunk]
        resp = client.post(IPINFO_BATCH_URL, json=body, timeout=timeout)
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, list):
            raise ValueError(f"ip-api /batch 返回非数组：{type(payload).__name__}")
        for item in payload:
            if not isinstance(item, dict) or item.get("status") != "success":
                continue
            ip = _to_str(item.get("query"))
            if not ip:
                continue
            info = _extract(item)
            _cache_put(ip, info)
            result[ip] = info
    return result
