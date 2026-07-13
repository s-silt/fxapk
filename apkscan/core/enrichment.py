"""联网富化执行：两遍富化编排、主动/被动门控、富化器→端点调用与统计聚合。

从 pipeline.py 物理拆出（纯搬移、逻辑不变）：这一簇负责挑「建议调证」端点、按端点并发跑富化器、
两遍（归属→定辖区→境外被动取证）编排、以及 --mode 的主动/被动门控。pipeline 在 _stage_enrich
里调用 _enrichment_targets / _run_enrichment / _mode_gate。
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from apkscan.core import forensic, infra
from apkscan.core.models import (
    ANALYSIS_MODE_AUTHORIZED_ACTIVE,
    ANALYSIS_MODE_PASSIVE,
    Endpoint,
)
from apkscan.core.registry import BaseEnricher

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


#: 富化并发度：按端点并发跑富化器（I/O 密集，瓶颈是 whois/rdap 的 ~30s 超时串行累加）。
#: 默认 8 个 worker。每个端点由单一 worker 串行跑其匹配的全部富化器，故同一 ep.enrichment
#: 无并发写竞争；只有跨端点共享的 provider 统计需加锁聚合。
ENRICH_MAX_WORKERS = 8


def _enrichment_targets(endpoints: list[Endpoint]) -> list[Endpoint]:
    """筛出"高度可疑"端点（域名/IP 且 infra 分级为"建议调证"）作为联网富化目标。

    只对疑似 App 自有服务/C2 的域名/IP 查 WHOIS/ICP/ASN；已知第三方基础设施/SDK/CDN
    （无需调证）、私网/回环 IP / 行情代码伪域名（待核）都不查。这正是"最后只对高度可疑的查、
    而不是有一个查一个"：省时（网络受限不被 infra 域名拖死、不误查 127.0.0.1）+ 聚焦调证。
    """
    targets: list[Endpoint] = []
    for ep in endpoints:
        if ep.kind not in ("domain", "ip"):
            continue  # 非 domain/ip 本就不被 WHOIS/ICP/ASN 路由
        advice, _reason = infra.classify_domain(ep.value)
        if advice == infra.ADVICE_INVESTIGATE:
            targets.append(ep)
    return targets


def _enrich_endpoints(
    endpoints: list[Endpoint],
    enrichers: list[BaseEnricher],
    *,
    gate: "Callable[[Endpoint, BaseEnricher], bool] | None" = None,
) -> list[dict]:
    """对每个端点按 applies_to 跑匹配的富化器，结果写入 endpoint.enrichment[provider]。

    ``gate``（可选）：额外的 (端点, 富化器)→bool 谓词，返回 False 则跳过该富化器（不计入统计）。
    不传则对匹配 applies_to 的富化器全跑（向后兼容；本仓当前富化器全部为被动，对目标零流量）。

    按端点并发（``ThreadPoolExecutor``，worker 数 = ``ENRICH_MAX_WORKERS``）：富化是
    I/O 密集（whois/rdap 单次可达 ~30s 超时），串行双重循环单包可达 7 分钟，按端点并发
    把这些超时叠在一起跑而非顺序累加。

    并发不变量：
    - 每个端点由**单一** worker 串行跑其匹配的全部富化器 → 同一 ``ep.enrichment``
      无并发写竞争；端点之间互不共享 enrichment dict。
    - ``endpoints`` 列表**原地不动、顺序不变**（只就地写 ``ep.enrichment``，绝不重排）。
    - 跨端点共享的 provider 统计用锁聚合，``attempted/ok/failed/typical_error`` 准确。
    - ip-api 免费档限速由 ``_ipinfo`` 内部的进程级线程安全限速器担保（asn 单查走 45/min·1.4s 闸、
      dns 批量走 /batch 15/min·4.0s 独立闸）——并发下仍是全局闸，本层只管并发分发。

    返回每个富化器的聚合状态 [{provider, attempted, ok, failed, typical_error}]，
    使富化器层的系统性失败（如某 provider 全部失败）在报告里透明可见，
    而非打散进各 endpoint 难以察觉。
    """
    stats: dict[str, dict] = {}
    stats_lock = threading.Lock()

    if endpoints:
        # max_workers 不超过端点数，避免端点少时空建大量线程。
        workers = max(1, min(ENRICH_MAX_WORKERS, len(endpoints)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="enrich") as pool:
            # list() 强制求值 → 任一 worker 内未捕获异常会在此重抛（_run_enrichers_on_endpoint
            # 内部已逐 enrich try/except，正常不会到这；这里是兜底，不让异常被 executor 静默吞掉）。
            list(pool.map(
                lambda ep: _run_enrichers_on_endpoint(ep, enrichers, stats, stats_lock, gate),
                endpoints,
            ))

    return list(stats.values())


def _stat(stats: dict[str, dict], provider: str) -> dict:
    """取/建某 provider 的统计条目（调用方须持 stats 的锁）。"""
    return stats.setdefault(
        provider,
        {"provider": provider, "attempted": 0, "ok": 0, "failed": 0, "typical_error": None},
    )


def _run_enrichers_on_endpoint(
    ep: Endpoint,
    enrichers: list[BaseEnricher],
    stats: dict[str, dict],
    stats_lock: threading.Lock,
    gate: "Callable[[Endpoint, BaseEnricher], bool] | None" = None,
) -> None:
    """对单个端点**串行**跑匹配的富化器（applies_to + gate 过滤），就地写 ep.enrichment + 聚合 stats。

    在单一 worker 内调用：同一 ep.enrichment 无并发写竞争；跨端点共享的 stats 用锁聚合。
    """
    for enricher in enrichers:
        applies_to = list(getattr(enricher, "applies_to", []) or [])
        if ep.kind not in applies_to:
            continue
        if gate is not None and not gate(ep, enricher):
            continue  # 门控谓词返回 False：跳过该富化器，不计统计
        provider = getattr(enricher, "name", "") or enricher.__class__.__name__

        with stats_lock:
            _stat(stats, provider)["attempted"] += 1

        try:
            result = enricher.enrich(ep)
        except Exception:  # noqa: BLE001 - 富化失败不阻塞主流程
            logger.exception("富化器执行异常：provider=%s endpoint=%s", provider, ep.value)
            ep.enrichment[provider] = {"ok": False, "error": "富化器异常"}
            with stats_lock:
                _note_fail(_stat(stats, provider), "富化器异常")
            continue

        if result is None:
            logger.warning("富化器 %s 返回 None：%s", provider, ep.value)
            ep.enrichment[provider] = {"ok": False, "error": "enrich 返回 None"}
            with stats_lock:
                _note_fail(_stat(stats, provider), "enrich 返回 None")
            continue

        data = dict(result.data)
        has_values = any(v not in (None, "", [], {}) for v in data.values())
        with stats_lock:
            st = _stat(stats, provider)
            if result.ok and has_values:
                st["ok"] += 1
            elif result.ok and not has_values:
                # 成功但零信息：显式标注，避免与"查到了"在报告里视觉混淆。
                data.setdefault("note", "查询无结果")
                _note_fail(st, "查询无结果")
            else:
                if result.error:
                    data.setdefault("error", result.error)
                _note_fail(st, result.error or "富化失败")
        ep.enrichment[provider] = data


def _note_fail(st: dict, msg: str) -> None:
    """记一次失败到 provider 统计（调用方须持 stats_lock）。"""
    st["failed"] += 1
    if not st["typical_error"]:
        st["typical_error"] = msg


# overseas 阶段的组内顺序（确定性排序；shodan/certs 均被动、互不依赖，固定序保证串行==并行逐字节一致）。
_OVERSEAS_ORDER = {"shodan": 0, "certs": 1}


def _enricher_phase(enricher: BaseEnricher) -> str:
    """富化器阶段（缺失/空 → 默认 attribution，兼容未标 phase 的旧富化器）。"""
    return getattr(enricher, "phase", "attribution") or "attribution"


def _classify_endpoint_jurisdiction(ep: Endpoint) -> str:
    """据第①遍归属富化结果判该端点服务器辖区（国内/国外/未知）。绝不抛（失败→未知，保守）。"""
    e = ep.enrichment
    try:
        return forensic.classify_jurisdiction(
            ep.value,
            icp=e.get("icp"),
            rdap=e.get("rdap"),
            whois=e.get("whois"),
            dns=e.get("dns"),
            asn=e.get("asn"),
            webcheck=e.get("webcheck"),
        )
    except Exception:  # noqa: BLE001 — 辖区判定失败不得炸主流程；保守判未知（宁可漏归类也不误标辖区）
        logger.debug("辖区判定失败，按未知处理：%s", ep.value, exc_info=True)
        return forensic.JURIS_UNKNOWN


def _mode_gate(mode: str) -> "Callable[[Endpoint, BaseEnricher], bool]":
    """按网络模式生成富化器门控谓词（防御纵深：真正在**调用点**拦，任何富化路径都过此闸）。

    - ``authorized-active``：全放行（含 active=True 的主动富化器）。
    - 其它（含默认 ``passive`` 及任何非法值 → 保守当被动）：只放行被动富化器（active 为假）。
    """
    if mode == ANALYSIS_MODE_AUTHORIZED_ACTIVE:
        return lambda _ep, _e: True
    return lambda _ep, enricher: not getattr(enricher, "active", False)


def _run_enrichment(
    targets: list[Endpoint],
    enrichers: list[BaseEnricher],
    gate: "Callable[[Endpoint, BaseEnricher], bool] | None" = None,
) -> list[dict]:
    """两遍富化编排（**单遍并发·每端点内两阶段**，无跨端点栅栏）：
    每个端点在自己的 worker 里串行跑 ①归属(attribution) → 定辖区 → ②境外被动取证(overseas)，
    端点之间互不等待——慢端点（如 30s WHOIS 超时）不再阻塞其它端点的第②阶段（去掉旧版两遍之间的栅栏）。

    第②遍只对【国外 + 未知】端点跑（境内走调证、不做境外取证）；overseas 富化器全部**被动**
    （shodan/certs 读公开库，对目标零流量）。辖区结果仅为 worker 内局部变量，**绝不写入 ep.enrichment**
    （避免 ``_jurisdiction`` 等内部键泄漏进 report.json）。

    ``gate=None`` **fail-closed**：缺省按 passive 门控（拦 active 富化器）。这样任何调用方（现在或
    将来）漏传 gate 都得到**安全**行为，绝不会静默把 webcheck 等主动富化器放进被动运行。要全放行须
    显式传 ``gate=_mode_gate("authorized-active")``。
    """
    if gate is None:
        gate = _mode_gate(ANALYSIS_MODE_PASSIVE)
    attribution = [e for e in enrichers if _enricher_phase(e) == "attribution"]
    overseas = sorted(
        (e for e in enrichers if _enricher_phase(e) == "overseas"),
        key=lambda e: _OVERSEAS_ORDER.get(getattr(e, "name", ""), 0),
    )

    stats: dict[str, dict] = {}
    stats_lock = threading.Lock()

    def _enrich_one_two_phase(ep: Endpoint) -> None:
        # ① 归属富化。
        _run_enrichers_on_endpoint(ep, attribution, stats, stats_lock, gate)
        if not overseas:
            return
        # 定辖区（worker 内局部，绝不写回 ep.enrichment）。
        juris = _classify_endpoint_jurisdiction(ep)
        if juris not in (forensic.JURIS_FOREIGN, forensic.JURIS_UNKNOWN):
            return  # 境内：走调证、不做境外被动取证

        # ② 境外被动取证富化（同 worker 内串行，组内顺序由 overseas 排序保证确定性）。
        _run_enrichers_on_endpoint(ep, overseas, stats, stats_lock, gate)

    if targets:
        workers = max(1, min(ENRICH_MAX_WORKERS, len(targets)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="enrich") as pool:
            list(pool.map(_enrich_one_two_phase, targets))

    return list(stats.values())
