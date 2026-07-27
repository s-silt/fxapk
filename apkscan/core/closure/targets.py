"""目标选择与排序：从报告的建议调证 leads 里挑出 domain/IP 端点，按 runtime-first 稳定排序并截断。

为什么这样切：这是闭环流程的入口筛选层——决定「对哪些目标做五层归因」，只依赖共享底座
``_shared``，不依赖五层组装（layers）、富化（sources）与验收（gates）。
FOFA 命名行解析（``_FOFA_FIELDS`` / ``_parse_fofa_row``）与运行时信号读取（``_runtime_info``）
也放这里：它们是排序依据（runtime 信号）与被动证据解析的最底层输入侧工具，被 layers 复用。
"""

from __future__ import annotations

import logging
from typing import Any

from apkscan.core.models import Endpoint, Report

from apkscan.core.closure._shared import _mapping

logger = logging.getLogger(__name__)


#: FOFA 数组行的字段顺序（与富化器 ``multisource.FOFA_QUERY_FIELDS`` 查询串**逐字段同序**——
#  有漂移守卫测试比对二者，改一处必同步另一处）。FOFA 按数组返回，此前 closure 用魔数下标（row[10] 等）
#  取值，一旦 FOFA 改字段序/富化器改查询就静默错位污染归属；改用命名解析 + 形状校验（codex #3）。
_FOFA_FIELDS: tuple[str, ...] = (
    "host", "ip", "port", "protocol", "title", "server",
    "country", "region", "city", "as_number", "as_organization",
)


def _parse_fofa_row(row: object) -> dict[str, Any] | None:
    """把一条 FOFA 数组行按 ``_FOFA_FIELDS`` 解析成命名 dict。

    行长与字段数不符 → 记 warning 并**跳过该行**（形状漂移：FOFA 改列或富化器改查询，宁可少一条也不错位取值）。
    非 list / 空 → None。绝不抛。
    """
    if not isinstance(row, list):
        return None
    if len(row) != len(_FOFA_FIELDS):
        logger.warning(
            "FOFA 行字段数 %d 与预期 %d 不符（疑 FOFA 改列 / 富化器查询漂移），跳过该行以免错位取值",
            len(row), len(_FOFA_FIELDS),
        )
        return None
    return dict(zip(_FOFA_FIELDS, row))


def _runtime_info(endpoint: Endpoint) -> dict[str, Any]:
    runtime = _mapping(endpoint.enrichment.get("runtime"))
    runtime["observed"] = any(ev.source.startswith("runtime") for ev in endpoint.evidences)
    return runtime


def _target_rank(endpoint: Endpoint, confidence_rank: int) -> tuple[int, int, int, int, int, str]:
    runtime = _runtime_info(endpoint)
    has_name = bool(runtime.get("sni") or runtime.get("http_host") or runtime.get("host"))
    return (
        0 if runtime.get("target_attributed") is True else 1,
        0 if runtime.get("has_payload") is True else 1,
        0 if has_name else 1,
        0 if runtime.get("observed") else 1,
        confidence_rank,
        endpoint.value.lower() if endpoint.kind == "domain" else endpoint.value,
    )


def _select_targets_with_stats(report: Report, max_targets: int) -> tuple[list[Endpoint], dict[str, object]]:
    """Order suspicious domain/IP leads (runtime-first) and split at ``max_targets``.

    Returns the selected endpoints plus a selection-stats mapping mirroring
    ``resolved_ip_selection`` so top-level target truncation is never silent: the
    caller records ``candidate_total``/``truncated``/``dropped`` and downgrades
    closure to partial when advisable candidates were dropped past the limit.
    """
    if max_targets <= 0:
        raise ValueError("max_targets must be greater than zero")

    lead_rank: dict[tuple[str, str], int] = {}
    for lead in report.leads:
        if lead.advice != "建议调证" or lead.category.value not in {"DOMAIN", "IP"}:
            continue
        key = (lead.category.value.lower(), lead.value.lower())
        lead_rank[key] = min(lead_rank.get(key, 9), {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(lead.confidence.value, 3))

    candidates: list[tuple[Endpoint, int]] = []
    for endpoint in report.endpoints:
        if endpoint.kind not in {"domain", "ip"} or endpoint.is_private:
            continue
        key = (endpoint.kind, endpoint.value.lower())
        if key not in lead_rank:
            continue
        candidates.append((endpoint, lead_rank[key]))

    candidates.sort(key=lambda item: _target_rank(item[0], item[1]))
    ordered: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()
    for endpoint, _rank in candidates:
        value = endpoint.value.lower() if endpoint.kind == "domain" else endpoint.value
        key = (endpoint.kind, value)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(endpoint)

    selected = ordered[:max_targets]
    dropped = ordered[max_targets:]
    stats: dict[str, object] = {
        "candidate_total": len(ordered),
        "selected": len(selected),
        "limit": max_targets,
        "truncated": len(dropped),
        "dropped": [endpoint.value for endpoint in dropped],
    }
    return selected, stats


def select_targets(report: Report, max_targets: int = 6) -> list[Endpoint]:
    """Select suspicious domain/IP leads in stable runtime-first order."""
    return _select_targets_with_stats(report, max_targets)[0]
