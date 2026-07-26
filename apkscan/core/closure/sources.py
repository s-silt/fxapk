"""富化源与解析 IP：判断哪些富化源还需要跑（终态/配置/覆盖兜底），域名 DNS 解析出的公网 IP
的筛选与逐 IP 富化，以及端点归因视图的重建入口。

为什么这样切：这是闭环里唯一"发起富化/改写 enrichment"的一侧（layers 只读、gates 只判定）。

★关键不变量：``_normalized_public_ip`` / ``_is_known_intercept_ip`` 与它们唯一的调用方
``_resolved_ips`` 必须同在本模块，且 ``_resolved_ips`` 直接（经本模块命名空间）调用它们——
测试用 ``monkeypatch.setattr(closure.sources, "_normalized_public_ip", ...)`` 打桩，若二者被拆到
不同模块、或调用侧改成 ``from x import`` 后直呼函数对象，patch 会静默失效（测试仍绿但不再测
原来那件事）。再拆分时不得破坏此共置。
"""

from __future__ import annotations

import ipaddress
import os
from typing import Mapping, Sequence

from apkscan.core.models import ANALYSIS_MODE_PASSIVE, Endpoint

from apkscan.core.closure._shared import ClosureConfig, _mapping
from apkscan.core.closure.layers import _normalize_source_status

_MAX_RESOLVED_IPS_PER_TARGET = 8


def _source_is_terminal(
    enricher: object,
    item: Mapping[str, object],
    mode: str,
) -> bool:
    status = item.get("status")
    if status in {"hit", "no_record"}:
        return True
    if status == "disabled":
        return not _source_is_configured(enricher)
    if status == "skipped":
        return bool(
            item.get("reason") == "active_mode_blocked"
            and mode == ANALYSIS_MODE_PASSIVE
            and getattr(enricher, "active", False)
        )
    return False


def _enrichers_to_run(
    endpoint: Endpoint,
    enrichers: Sequence[object],
    *,
    mode: str,
    refresh: bool,
) -> list[object]:
    applicable = [
        enricher
        for enricher in enrichers
        if endpoint.kind in (getattr(enricher, "applies_to", []) or [])
    ]
    if refresh:
        return applicable
    statuses = _normalize_source_status(endpoint.enrichment)
    return [
        enricher
        for enricher in applicable
        if not _source_is_terminal(
            enricher,
            statuses.get(str(getattr(enricher, "name", "")), {}),
            mode,
        )
    ]


def _source_is_configured(enricher: object) -> bool:
    raw_required = getattr(enricher, "required_env", ())
    required = (
        [str(name) for name in raw_required]
        if isinstance(raw_required, (list, tuple))
        else []
    )
    return not required or any((os.environ.get(name) or "").strip() for name in required)


def _ensure_source_status_coverage(
    endpoint: Endpoint,
    enrichers: Sequence[object],
    config: ClosureConfig,
) -> None:
    raw_statuses = endpoint.enrichment.setdefault("source_status", {})
    if not isinstance(raw_statuses, dict):
        raw_statuses = {}
        endpoint.enrichment["source_status"] = raw_statuses
    for enricher in enrichers:
        if endpoint.kind not in (getattr(enricher, "applies_to", []) or []):
            continue
        provider = str(getattr(enricher, "name", "") or type(enricher).__name__)
        current = _mapping(raw_statuses.get(provider))
        if current.get("status") in {"hit", "no_record", "failed"}:
            continue
        if not _source_is_configured(enricher):
            raw_statuses[provider] = {
                "status": "disabled",
                "reason": "credential_not_configured",
            }
        elif config.mode == ANALYSIS_MODE_PASSIVE and getattr(enricher, "active", False):
            raw_statuses[provider] = {
                "status": "skipped",
                "reason": "active_mode_blocked",
            }
        elif not config.online:
            raw_statuses[provider] = {"status": "skipped", "reason": "offline"}
        else:
            raw_statuses[provider] = {"status": "failed", "reason": "missing_outcome"}


def _normalized_public_ip(value: object) -> str | None:
    text = str(value).strip()
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(address) if address.is_global else None


def _is_known_intercept_ip(value: str) -> bool:
    from apkscan.dynamic.pcap_ingest import is_known_intercept_ip

    return is_known_intercept_ip(value)


def _resolved_ips(endpoint: Endpoint) -> list[str]:
    if endpoint.kind != "domain":
        return []
    dns = _mapping(endpoint.enrichment.get("dns"))
    raw = dns.get("ips") or dns.get("addresses")
    if not isinstance(raw, list):
        endpoint.enrichment["resolved_ip_selection"] = {
            "observed": 0,
            "total": 0,
            "selected": 0,
            "limit": _MAX_RESOLVED_IPS_PER_TARGET,
            "truncated": 0,
            "excluded_nonpublic": 0,
            "excluded_intercept": 0,
        }
        return []
    observed = sorted({str(value).strip() for value in raw if str(value).strip()})
    values: set[str] = set()
    excluded_nonpublic = 0
    excluded_intercept = 0
    for value in observed:
        normalized = _normalized_public_ip(value)
        if normalized is None:
            excluded_nonpublic += 1
            continue
        if _is_known_intercept_ip(normalized):
            excluded_intercept += 1
            continue
        values.add(normalized)
    ordered = sorted(values)
    selected = ordered[:_MAX_RESOLVED_IPS_PER_TARGET]
    endpoint.enrichment["resolved_ip_selection"] = {
        "observed": len(observed),
        "total": len(ordered),
        "selected": len(selected),
        "limit": _MAX_RESOLVED_IPS_PER_TARGET,
        "truncated": max(0, len(ordered) - len(selected)),
        "excluded_nonpublic": excluded_nonpublic,
        "excluded_intercept": excluded_intercept,
    }
    return selected


def _set_attribution(endpoint: Endpoint) -> None:
    from apkscan.core.attribution import build_endpoint_attribution

    attribution = build_endpoint_attribution(endpoint.kind, endpoint.value, endpoint.enrichment)
    if attribution is not None:
        endpoint.enrichment["attribution"] = attribution


def _enrich_resolved_ips(
    endpoint: Endpoint,
    enrichers: Sequence[object],
    config: ClosureConfig,
) -> None:
    from apkscan.core.enrichment import enrich_selected_targets

    existing = _mapping(endpoint.enrichment.get("resolved_ip_enrichment"))
    runtime = _mapping(endpoint.enrichment.get("runtime"))
    resolved: dict[str, object] = {}
    for ip in _resolved_ips(endpoint):
        cached = existing.get(ip)
        enrichment = dict(cached) if isinstance(cached, Mapping) else {}
        if runtime:
            enrichment["runtime"] = runtime
        transient = Endpoint(
            value=ip,
            kind="ip",
            evidences=list(endpoint.evidences),
            is_suspicious=True,
            enrichment=enrichment,
        )
        typed_enrichers = [enricher for enricher in enrichers if hasattr(enricher, "enrich")]
        pending = _enrichers_to_run(
            transient,
            typed_enrichers,
            mode=config.mode,
            refresh=config.refresh,
        )
        if config.online and pending:
            enrich_selected_targets(
                [transient],
                pending,  # type: ignore[arg-type]
                mode=config.mode,
                include_case_close=True,
            )
        _ensure_source_status_coverage(transient, typed_enrichers, config)
        _set_attribution(transient)
        transient.enrichment.pop("runtime", None)
        resolved[ip] = transient.enrichment
    if resolved:
        endpoint.enrichment["resolved_ip_enrichment"] = resolved
