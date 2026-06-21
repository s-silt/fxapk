"""CVE 补查富化器：被动查 NVD 2.0，补 Shodan 没覆盖的技术栈指纹的已知漏洞方向。

★ 定位：本模块是**攻击面阶段（``phase="attack_surface"``）的被动 enricher**（``active=False``，
不向目标发任何连接），与 ``recon``（主动探测）同阶段但互补。它消费**同端点上游富化**已写入的
指纹——``ep.enrichment["shodan"]`` 的 ``services[*].cpe`` / ``vulns``、``ep.enrichment["recon"]``
的 ``http[*].server`` / ``x_powered_by``——把"技术栈"翻成"已知漏洞方向"（CVE id + CVSS + severity），
**仅作情报方向提示，绝不含 exploit、绝不做漏洞利用**。

为什么还要它（Shodan 已经给 vulns 了）：
- Shodan 的 ``vulns`` 只覆盖它**扫库时点**识别到的 CPE，且对很多产品**根本不给** vulns；
- recon 主动探测只交付"暴露了什么"（server/版本头），不做漏洞判定。
两者留下的"有指纹、无 CVE 方向"的缺口，由本模块对 NVD 2.0 在线补查填上。

复用优先（省额度、避免重复）：
- 若某 CPE 已在 Shodan ``vulns`` 中出现对应 CVE，**直接复用**，不再查 NVD；
- 仅对 **Shodan 未给 vulns 的 CPE**（或 recon 的 server/版本关键词）走在线 NVD 查询。

NVD 2.0（``services.nvd.nist.gov/rest/json/cves/2.0``）：
- 无 key 限速 **5 次 / 30s**；配 ``FXAPK_NVD_KEY`` 提速到 **50 次 / 30s**（可选、不强制，仅加速）。
- 进程级线程安全限速器（与 pipeline 按端点并发兼容）+ 按 CPE/keyword 本地 JSON 缓存（原子写）。
- 优雅失败：网络/解析/限速任何异常 → ``EnrichmentResult(ok=False)``，绝不抛、绝不裸 except、
  绝不在 try 里 swallow log（debug 记录）。

★ 组内顺序（与两遍富化协调）：本 enricher 的输入来自 ``shodan`` / ``recon`` 的产物，故调度上
**必须排在 shodan/recon 之后**（同一 worker 串行跑富化器时其 enrichment 已就绪）。``phase=
"attack_surface"`` 标记其归属攻击面阶段；单遍 pipeline 下若顺序未保证，则当 shodan/recon 尚未
写入时本模块仅"无指纹可查"地优雅返回（ok=True 无值），不报错。

合规：只查 NVD 公开漏洞库（被动情报，对目标零流量），不向目标发起任何连接 / 扫描 / 利用。
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

import requests

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher

logger = logging.getLogger(__name__)

#: 可选 NVD API key 环境变量名（配了仅提速限速档，不强制 / 不门控；与 shodan 的强 opt-in 不同）。
_ENV_KEY = "FXAPK_NVD_KEY"

#: NVD 2.0 CVE 检索端点。
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 20

#: NVD 限速窗口（秒）与每窗口最大请求数（无 key 5/30s；有 key 50/30s）。官方建议保守。
_RATE_WINDOW = 30.0
_RATE_MAX_NOKEY = 5
_RATE_MAX_KEYED = 50

#: 单端点最多对几个不同 CPE/keyword 走 NVD（防个别巨型主机几十个指纹刷爆限速 / 报告）。
_MAX_QUERIES_PER_EP = 6

#: 每个 CPE 取回的 CVE 上限（NVD resultsPerPage），再在本地按 CVSS 取 top-N。
_NVD_RESULTS_PER_PAGE = 50

#: 归一后每个查询保留的高危 CVE 上限（取 top-N，按 CVSS 降序）。
_TOP_N = 8

#: 端点聚合后整体保留的 CVE 上限（跨多个 CPE 合并去重后再截，防刷屏）。
_MAX_CVES_PER_EP = 20

CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "cve.json"


def _api_key() -> str:
    """取可选 NVD API key（仅用于提速限速档）；未配置返回空串（仍可用，只是慢档限速）。"""
    return (os.environ.get(_ENV_KEY) or "").strip()


# ---------------------------------------------------------------------------
# 进程级限速器：NVD 无 key 5/30s、有 key 50/30s。pipeline 按端点并发，多个 cve 实例
# 共用同一把闸（模块级单例），保证全局窗口内请求数不超限（否则必被 429/403 拒）。
# ---------------------------------------------------------------------------
class _RateLimiter:
    """滑动窗口限速器（线程安全）：窗口内最多 max 次；超了就 sleep 到最早一次出窗。"""

    def __init__(self, max_calls: int, window: float) -> None:
        self._max = max_calls
        self._window = window
        self._calls: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """阻塞直到可发起一次请求（必要时 sleep）。线程安全。"""
        while True:
            with self._lock:
                now = time.monotonic()
                # 丢弃窗口外的旧时间戳。
                self._calls = [t for t in self._calls if now - t < self._window]
                if len(self._calls) < self._max:
                    self._calls.append(now)
                    return
                # 需等到最早一次出窗。
                wait = self._window - (now - self._calls[0])
            if wait > 0:
                time.sleep(min(wait, self._window))


_LIMITER_LOCK = threading.Lock()
_LIMITER: _RateLimiter | None = None
_LIMITER_KEYED: bool | None = None


def _limiter() -> _RateLimiter:
    """取进程级限速器（首次按是否配 key 选档惰性建；之后复用同一把全局闸）。

    若运行期 key 配置变化（罕见，主要见于测试），按新档重建——以当前档为准。
    """
    global _LIMITER, _LIMITER_KEYED
    keyed = bool(_api_key())
    with _LIMITER_LOCK:
        if _LIMITER is None or _LIMITER_KEYED != keyed:
            _LIMITER = _RateLimiter(
                _RATE_MAX_KEYED if keyed else _RATE_MAX_NOKEY, _RATE_WINDOW
            )
            _LIMITER_KEYED = keyed
        return _LIMITER


# ---------------------------------------------------------------------------
# 指纹抽取：从同端点 shodan / recon 富化产物里抽 (cpe 列表, 已知 CVE, 关键词)。
# ---------------------------------------------------------------------------
def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _collect_cpes(shodan: object) -> list[str]:
    """从 shodan services 抽 CPE 字符串（去重保序）。无 → 空列表。"""
    out: list[str] = []
    seen: set[str] = set()
    if not isinstance(shodan, dict):
        return out
    for svc in _as_list(shodan.get("services")):
        if not isinstance(svc, dict):
            continue
        cpe = svc.get("cpe")
        candidates = cpe if isinstance(cpe, list) else [cpe]
        for c in candidates:
            if isinstance(c, str) and c.strip() and c not in seen:
                seen.add(c)
                out.append(c.strip())
    return out


def _shodan_known_cves(shodan: object) -> set[str]:
    """Shodan 已给的 CVE 集合（这些不必再查 NVD，直接复用其结论的"已覆盖"判断）。"""
    out: set[str] = set()
    if not isinstance(shodan, dict):
        return out
    for v in _as_list(shodan.get("vulns")):
        if isinstance(v, str) and v.upper().startswith("CVE-"):
            out.add(v.upper())
    return out


def _recon_keywords(recon: object) -> list[str]:
    """从 recon 的 HTTP 指纹抽 server / x_powered_by 作为 NVD keyword 兜底（Shodan 无 CPE 时）。

    形如 ``"Apache/2.4.7 (Ubuntu)"`` / ``"nginx"``；只取头部产品+版本片段，去重保序。
    """
    out: list[str] = []
    seen: set[str] = set()
    if not isinstance(recon, dict):
        return out
    for h in _as_list(recon.get("http")):
        if not isinstance(h, dict):
            continue
        for field in ("server", "x_powered_by"):
            v = h.get(field)
            if isinstance(v, str):
                kw = _clean_keyword(v)
                if kw and kw not in seen:
                    seen.add(kw)
                    out.append(kw)
    return out


def _clean_keyword(server: str) -> str:
    """把 Server 头清成 NVD keyword：取首段产品/版本（去括号注释），如 ``Apache/2.4.7``。"""
    s = server.strip()
    if not s:
        return ""
    # 去括号注释 "(Ubuntu)" 之类，只留首 token（product/version）。
    head = s.split("(")[0].strip()
    first = head.split()[0] if head.split() else ""
    # NVD keyword 用空格分词更友好：Apache/2.4.7 → "Apache 2.4.7"。
    return first.replace("/", " ").strip()


# ---------------------------------------------------------------------------
# NVD 响应归一。
# ---------------------------------------------------------------------------
def _extract_cvss(metrics: object) -> tuple[float | None, str | None]:
    """从 NVD ``metrics`` 抽 (baseScore, baseSeverity)，优先 v3.1 > v3.0 > v2。坏字段安全留空。"""
    if not isinstance(metrics, dict):
        return None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if not isinstance(arr, list) or not arr:
            continue
        first = arr[0]
        if not isinstance(first, dict):
            continue
        data = first.get("cvssData")
        if not isinstance(data, dict):
            continue
        score = data.get("baseScore")
        # severity：v3 在 cvssData.baseSeverity；v2 在外层 baseSeverity。
        severity = data.get("baseSeverity") or first.get("baseSeverity")
        if isinstance(score, (int, float)):
            return float(score), (str(severity) if severity else None)
    return None, None


def _parse_nvd(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """把 NVD 2.0 ``/cves`` 响应归一成 [{id, cvss, severity}]，按 CVSS 降序取 top-N。坏字段跳过。"""
    rows: list[dict[str, Any]] = []
    for item in payload.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
            continue
        cvss, severity = _extract_cvss(cve.get("metrics"))
        rows.append({"id": cve_id.upper(), "cvss": cvss, "severity": severity})
    # CVSS 降序（None 视为 -1 排后），稳定取 top-N。
    rows.sort(key=lambda r: (r["cvss"] if isinstance(r["cvss"], float) else -1.0), reverse=True)
    return rows[:_TOP_N]


class CveEnricher(BaseEnricher):
    """对 IP / 域名补查 NVD CVE 方向（被动；消费同端点 shodan/recon 指纹）。

    阶段标识 ``phase="attack_surface"`` + ``active=False``：攻击面阶段的**被动** enricher
    （不触目标），与 ``recon``（主动）区分。组内调度须排在 shodan/recon 之后（输入依赖其产物）。
    无可选 NVD key 也能用（仅慢档限速）；配 ``FXAPK_NVD_KEY`` 仅提速。
    """

    name = "cve"
    applies_to = ["ip", "domain"]
    #: 攻击面阶段（两遍富化的第二遍）；active=False 标记被动（不向目标发连接）。
    phase = "attack_surface"
    active = False

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 缓存
    def _load_cache(self) -> dict[str, Any]:
        """读缓存文件。★必须持 self._lock 调用：Windows 下读句柄与另一线程 os.replace
        撞同一文件会抛 PermissionError，让缓存静默丢失。读写共用一把锁消除该重叠窗口。"""
        if not CACHE_FILE.is_file():
            return {}
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("CVE 缓存读取/解析失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        if not isinstance(data, dict):
            logger.warning("CVE 缓存顶层非 dict，忽略：%s", CACHE_FILE)
            return {}
        return data

    def _load_cache_locked(self) -> dict[str, Any]:
        with self._lock:
            return self._load_cache()

    def _save_cache_entry(self, cache_key: str, entry: list[dict[str, Any]]) -> None:
        """按 CPE/keyword 缓存其 NVD 查询结果（命中即不再触网，省限速额度）。原子写。"""
        with self._lock:
            cache = self._load_cache()
            cache[cache_key] = entry
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                # 原子写：临时文件 + replace；tmp 名带 pid+线程 id 唯一后缀，避免多写者互相覆盖/撞 replace。
                tmp = CACHE_FILE.with_name(
                    f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(CACHE_FILE)
            except Exception:
                logger.warning("CVE 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 查询
    def _query_nvd(self, params: dict[str, Any], key: str) -> list[dict[str, Any]]:
        """对 NVD 2.0 发一次检索（已过限速闸），归一返回 top-N CVE。网络/HTTP/解析异常向上抛。"""
        _limiter().acquire()  # 限速：无 key 5/30s、有 key 50/30s（进程级全局闸）
        headers = {"apiKey": key} if key else {}
        resp = requests.get(NVD_URL, params=params, headers=headers, timeout=NVD_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError(f"NVD 返回非对象：{type(payload).__name__}")
        return _parse_nvd(payload)

    def _lookup(
        self, cache_key: str, params: dict[str, Any], key: str, cache: dict[str, Any]
    ) -> list[dict[str, Any]] | None:
        """查单个 CPE/keyword：先缓存，未命中走 NVD。失败 → None（调用方计入 errors，不炸整体）。"""
        cached = cache.get(cache_key)
        if isinstance(cached, list):
            logger.debug("CVE 缓存命中：%s", cache_key)
            return cached
        try:
            rows = self._query_nvd(params, key)
        except Exception as exc:  # noqa: BLE001 — 单 CPE 查询失败不得影响其它 CPE / 主流程
            logger.debug("NVD 查询失败：%s（%s）", cache_key, exc)
            return None
        self._save_cache_entry(cache_key, rows)
        cache[cache_key] = rows  # 同端点内多 query 复用，避免重复读盘
        return rows

    def _gather(self, ep: Endpoint, key: str) -> dict[str, Any]:
        """主编排：抽指纹 → 复用 Shodan 已覆盖 → 对未覆盖 CPE/keyword 查 NVD → 聚合归一。"""
        shodan = ep.enrichment.get("shodan")
        recon = ep.enrichment.get("recon")

        cpes = _collect_cpes(shodan)
        known = _shodan_known_cves(shodan)
        keywords = _recon_keywords(recon) if not cpes else []  # 有 CPE 优先，无 CPE 才退化用 keyword

        cache = self._load_cache_locked()

        findings: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        queried = 0
        errors: list[str] = []
        reused = 0

        # 1) CPE 精确查（优先）。
        for cpe in cpes:
            if queried >= _MAX_QUERIES_PER_EP:
                break
            queried += 1
            rows = self._lookup(
                f"cpe::{cpe}",
                {"cpeName": cpe, "resultsPerPage": _NVD_RESULTS_PER_PAGE},
                key,
                cache,
            )
            if rows is None:
                errors.append(cpe)
                continue
            for r in rows:
                cid = r.get("id")
                if not isinstance(cid, str) or cid in seen_ids:
                    continue
                seen_ids.add(cid)
                r = dict(r)
                r["cpe"] = cpe
                r["reused_from_shodan"] = cid in known  # 标注：Shodan 已覆盖（复用印证）
                if cid in known:
                    reused += 1
                findings.append(r)

        # 2) recon keyword 兜底（仅当无 CPE 时；NVD keywordSearch）。
        for kw in keywords:
            if queried >= _MAX_QUERIES_PER_EP:
                break
            queried += 1
            rows = self._lookup(
                f"kw::{kw}",
                {"keywordSearch": kw, "resultsPerPage": _NVD_RESULTS_PER_PAGE},
                key,
                cache,
            )
            if rows is None:
                errors.append(kw)
                continue
            for r in rows:
                cid = r.get("id")
                if not isinstance(cid, str) or cid in seen_ids:
                    continue
                seen_ids.add(cid)
                r = dict(r)
                r["keyword"] = kw
                findings.append(r)

        # 聚合排序：CVSS 降序，截断防刷屏。
        findings.sort(
            key=lambda r: (r["cvss"] if isinstance(r.get("cvss"), float) else -1.0), reverse=True
        )
        findings = findings[:_MAX_CVES_PER_EP]

        return {
            "cves": findings,
            "cve_total": len(findings),
            "queried": queried,
            "reused_from_shodan": reused,
            "errors": errors,
            "note": "情报方向（CPE/指纹→NVD CVE），非利用、不含 exploit",
            "source": "nvd",
        }

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        value = (ep.value or "").strip()
        if not value:
            return EnrichmentResult(provider=self.name, ok=False, error="空值，跳过 CVE 补查")

        # 无指纹可查（shodan/recon 未写入或无 services）→ 优雅返回 ok=True 无值（非错误）。
        # ★ 这也是"组内顺序未保证"时的安全退化：若本模块先于 shodan/recon 跑，此处无指纹即跳过。
        shodan = ep.enrichment.get("shodan")
        recon = ep.enrichment.get("recon")
        if not _collect_cpes(shodan) and not _recon_keywords(recon):
            return EnrichmentResult(
                provider=self.name,
                ok=True,
                data={"note": "无 CPE/指纹（shodan/recon 未提供），跳过 NVD 补查", "source": "nvd"},
            )

        key = _api_key()  # 可空：无 key 仍查，仅慢档限速。

        try:
            data = self._gather(ep, key)
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            logger.debug("CVE 补查失败：%s（%s）", value, exc)
            return EnrichmentResult(
                provider=self.name, ok=False, error=f"{type(exc).__name__}: {exc}"
            )

        # 全部查询都失败（有指纹却一条 CVE 没拿到且有 errors）→ ok=False 便于重试。
        if not data["cves"] and data["errors"]:
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                error=f"NVD 查询全部失败（{len(data['errors'])} 个指纹），稍后重试",
            )
        return EnrichmentResult(provider=self.name, ok=True, data=data)
