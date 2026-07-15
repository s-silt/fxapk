"""Deterministic case-closure gates over static, runtime, and attribution evidence."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from apkscan.core.models import (
    ANALYSIS_MODE_PASSIVE,
    ANALYSIS_MODES,
    ANALYSIS_STATUS_COMPLETE,
    ANALYSIS_STATUS_FAILED,
    Endpoint,
    Report,
)

CLOSURE_COMPLETE = "complete"
CLOSURE_PARTIAL = "partial"
CLOSURE_FAILED = "failed"

SOURCE_STATUSES = frozenset({"hit", "no_record", "failed", "skipped", "disabled"})
LAYER_NAMES = (
    "runtime_evidence",
    "resource_registration",
    "bgp_announcement",
    "hosting_delivery",
    "request_target",
)


@dataclass(frozen=True)
class ClosureConfig:
    online: bool = True
    mode: str = ANALYSIS_MODE_PASSIVE
    max_targets: int = 6
    refresh: bool = False
    require_dynamic: bool | None = None

    def __post_init__(self) -> None:
        if self.mode not in ANALYSIS_MODES:
            raise ValueError(f"unsupported analysis mode: {self.mode}")
        if self.max_targets <= 0:
            raise ValueError("max_targets must be greater than zero")


def _mapping(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


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


def select_targets(report: Report, max_targets: int = 6) -> list[Endpoint]:
    """Select suspicious domain/IP leads in stable runtime-first order."""
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
    selected: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()
    for endpoint, _rank in candidates:
        value = endpoint.value.lower() if endpoint.kind == "domain" else endpoint.value
        key = (endpoint.kind, value)
        if key in seen:
            continue
        seen.add(key)
        selected.append(endpoint)
        if len(selected) >= max_targets:
            break
    return selected


def _non_negative_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return max(0, int(value))
    return 0


def evaluate_capture_quality(meta: Mapping[str, object]) -> dict[str, object]:
    """Separate channel readiness from target-attributed business evidence."""
    raw = _mapping(meta.get("quality"))
    raw.update({key: value for key, value in meta.items() if key not in raw})

    attribution = _mapping(raw.get("pcap_app_attribution"))
    attributed = sum(
        1
        for item in attribution.values()
        if isinstance(item, Mapping) and item.get("is_target_app") is True
    )
    target_count = _non_negative_int(raw.get("target_attributed_count")) or attributed
    business_count = _non_negative_int(raw.get("business_candidate_count"))
    if business_count == 0:
        business_count = _non_negative_int(raw.get("endpoint_total"))
    packet_count = _non_negative_int(raw.get("packet_count"))
    pcap_valid = bool(raw.get("pcap_valid")) and packet_count > 0
    channel_ready = bool(
        raw.get("channel_ready")
        or raw.get("mitm_channel_ok")
        or raw.get("floor_started")
    )

    if target_count > 0 and business_count > 0:
        status = CLOSURE_COMPLETE
        reason = "target-attributed public business candidate observed"
    elif business_count > 0:
        status = CLOSURE_PARTIAL
        reason = "public business candidate observed without unique target attribution"
    else:
        status = CLOSURE_FAILED
        reason = "no target business candidate observed"

    return {
        "channel_ready": channel_ready,
        "pcap_valid": pcap_valid,
        "packet_count": packet_count,
        "business_candidate_count": business_count,
        "target_attributed_count": target_count,
        "dynamic_status": status,
        "reason": reason,
    }


def _layer(status: str, evidence: Mapping[str, object] | None = None, *, reason: str = "") -> dict[str, object]:
    result: dict[str, object] = {"status": status, "evidence": dict(evidence or {})}
    if reason:
        result["reason"] = reason
    return result


def _registration_layer(enrichment: Mapping[str, object]) -> dict[str, object]:
    rdap = _mapping(enrichment.get("ip_rdap"))
    holder = rdap.get("org") or rdap.get("netname")
    network = rdap.get("cidr") or rdap.get("start_address") or rdap.get("startAddress")
    evidence = {
        key: rdap.get(key)
        for key in ("netname", "org", "country", "handle", "cidr", "start_address", "end_address")
        if rdap.get(key) not in (None, "", [])
    }
    if holder and network:
        return _layer(CLOSURE_COMPLETE, evidence)
    if holder or network:
        return _layer(CLOSURE_PARTIAL, evidence, reason="IP registration record is incomplete")
    return _layer(CLOSURE_FAILED, reason="IP registration record is missing")


def _bgp_layer(enrichment: Mapping[str, object]) -> dict[str, object]:
    bgp = _mapping(enrichment.get("ripestat_bgp"))
    evidence = {
        key: bgp.get(key)
        for key in ("origin_asn", "asn_holder", "prefix", "upstreams")
        if bgp.get(key) not in (None, "", [])
    }
    required = (bgp.get("origin_asn"), bgp.get("asn_holder"), bgp.get("prefix"))
    if all(required):
        return _layer(CLOSURE_COMPLETE, evidence)
    if any(required):
        return _layer(CLOSURE_PARTIAL, evidence, reason="BGP origin record is incomplete")
    return _layer(CLOSURE_FAILED, reason="BGP origin record is missing")


def _attribution_for_endpoint(enrichment: Mapping[str, object]) -> dict[str, Any]:
    attribution = _mapping(enrichment.get("attribution"))
    if "ips" in attribution:
        ips = attribution.get("ips")
        if isinstance(ips, list):
            return next((dict(item) for item in ips if isinstance(item, Mapping)), {})
    return attribution


def _edge_provider(enrichment: Mapping[str, object]) -> str | None:
    attribution = _attribution_for_endpoint(enrichment)
    edge = _mapping(attribution.get("edge_provider"))
    name = edge.get("name")
    return str(name) if name else None


def _origin_status(enrichment: Mapping[str, object]) -> dict[str, object]:
    edge = _edge_provider(enrichment)
    if not edge:
        return {"required": False, "status": "not_applicable"}
    origin = _mapping(enrichment.get("origin"))
    candidates = origin.get("ips") or enrichment.get("origin_candidates")
    if origin.get("ip") or (isinstance(candidates, list) and candidates):
        return {"required": True, "status": CLOSURE_COMPLETE, "evidence": origin}
    return {"required": True, "status": "missing", "edge_provider": edge}


def _hosting_layer(enrichment: Mapping[str, object]) -> dict[str, object]:
    shodan = _mapping(enrichment.get("shodan"))
    asn = _mapping(enrichment.get("asn"))
    attribution = _attribution_for_endpoint(enrichment)
    hosting = _mapping(attribution.get("hosting_provider"))
    provider = shodan.get("org") or hosting.get("name") or asn.get("org") or asn.get("isp")
    services = shodan.get("services") if isinstance(shodan.get("services"), list) else []
    ports = shodan.get("ports") if isinstance(shodan.get("ports"), list) else []
    evidence = {
        "provider": provider,
        "asn": asn.get("asn") or shodan.get("asn"),
        "country": asn.get("country") or shodan.get("country"),
        "ports": ports,
        "services": services,
    }
    evidence = {key: value for key, value in evidence.items() if value not in (None, "", [])}
    if provider and (services or ports or hosting.get("matched_signals")):
        return _layer(CLOSURE_COMPLETE, evidence)
    if provider:
        return _layer(CLOSURE_PARTIAL, evidence, reason="provider found without product or facility evidence")
    return _layer(CLOSURE_FAILED, reason="hosting or delivery provider is missing")


def _request_layer(hosting: Mapping[str, object], origin: Mapping[str, object]) -> dict[str, object]:
    evidence = _mapping(hosting.get("evidence"))
    provider = evidence.get("provider")
    request_evidence = {
        "provider": provider,
        "evidence_fields": [
            "tenant identity",
            "instance binding",
            "payment records",
            "control-plane login logs",
            "access and origin logs",
        ],
    }
    if origin.get("required") is True and origin.get("status") != CLOSURE_COMPLETE:
        edge = origin.get("edge_provider")
        if edge:
            request_evidence["edge_provider"] = edge
        return _layer(CLOSURE_PARTIAL, request_evidence, reason="Origin must be obtained first")
    if provider and hosting.get("status") == CLOSURE_COMPLETE:
        return _layer(CLOSURE_COMPLETE, request_evidence)
    if provider:
        return _layer(CLOSURE_PARTIAL, request_evidence, reason="request target lacks delivery evidence")
    return _layer(CLOSURE_FAILED, reason="no executable provider request target")


def _runtime_layer(endpoint: Endpoint) -> dict[str, object]:
    runtime = _runtime_info(endpoint)
    evidence = {
        "sources": sorted({ev.source for ev in endpoint.evidences if ev.source.startswith("runtime")}),
        "locations": sorted({ev.location for ev in endpoint.evidences if ev.source.startswith("runtime")}),
        "target_attributed": runtime.get("target_attributed") is True,
        "has_payload": runtime.get("has_payload") is True,
    }
    if runtime.get("target_attributed") is True:
        return _layer(CLOSURE_COMPLETE, evidence)
    if runtime.get("observed"):
        return _layer(CLOSURE_PARTIAL, evidence, reason="runtime endpoint is not uniquely attributed")
    return _layer(CLOSURE_FAILED, evidence, reason="endpoint is static-only")


def _normalize_source_status(enrichment: Mapping[str, object]) -> dict[str, dict[str, object]]:
    raw = _mapping(enrichment.get("source_status"))
    normalized: dict[str, dict[str, object]] = {}
    for provider in sorted(raw):
        item = _mapping(raw[provider])
        status = str(item.get("status", "failed"))
        if status not in SOURCE_STATUSES:
            status = "failed"
        normalized[str(provider)] = {**item, "status": status}
    return normalized


def _single_target_closure(endpoint: Endpoint) -> dict[str, object]:
    enrichment = endpoint.enrichment
    origin = _origin_status(enrichment)
    hosting = _hosting_layer(enrichment)
    layers = {
        "runtime_evidence": _runtime_layer(endpoint),
        "resource_registration": _registration_layer(enrichment),
        "bgp_announcement": _bgp_layer(enrichment),
        "hosting_delivery": hosting,
        "request_target": _request_layer(hosting, origin),
    }
    statuses = {str(layer.get("status")) for layer in layers.values()}
    status = CLOSURE_COMPLETE if statuses == {CLOSURE_COMPLETE} else CLOSURE_PARTIAL
    gaps = [name for name in LAYER_NAMES if layers[name]["status"] != CLOSURE_COMPLETE]
    if origin.get("required") is True and origin.get("status") != CLOSURE_COMPLETE:
        status = CLOSURE_PARTIAL
        gaps.append("origin")
    return {
        "value": endpoint.value,
        "kind": endpoint.kind,
        "status": status,
        "layers": layers,
        "source_status": _normalize_source_status(enrichment),
        "origin": origin,
        "actual_service_operator": {"status": "unknown", "evidence": {}},
        "gaps": gaps,
    }


def _aggregate_layer(
    layer_name: str,
    resolved: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    items: list[tuple[str, Mapping[str, object]]] = []
    for target in resolved:
        layers = target.get("layers")
        if not isinstance(layers, Mapping):
            continue
        layer = layers.get(layer_name)
        if isinstance(layer, Mapping):
            items.append((str(target.get("value", "")), layer))
    if not items:
        return _layer(CLOSURE_FAILED, reason=f"{layer_name} is missing for resolved IPs")
    statuses = [str(layer.get("status")) for _ip, layer in items]
    if all(status == CLOSURE_COMPLETE for status in statuses):
        status = CLOSURE_COMPLETE
    elif any(status in {CLOSURE_COMPLETE, CLOSURE_PARTIAL} for status in statuses):
        status = CLOSURE_PARTIAL
    else:
        status = CLOSURE_FAILED
    per_ip = {ip: _mapping(layer.get("evidence")) for ip, layer in items}
    evidence: dict[str, object] = {"per_ip": per_ip}
    if layer_name == "request_target":
        providers = {
            str(data.get("provider"))
            for data in per_ip.values()
            if data.get("provider")
        }
        if len(providers) == 1:
            evidence["provider"] = next(iter(providers))
        fields = next(
            (
                data.get("evidence_fields")
                for data in per_ip.values()
                if isinstance(data.get("evidence_fields"), list)
            ),
            [],
        )
        evidence["evidence_fields"] = fields
    return _layer(
        status,
        evidence,
        reason="one or more resolved IP layers are incomplete" if status != CLOSURE_COMPLETE else "",
    )


def _aggregate_source_status(
    parent: Mapping[str, dict[str, object]],
    resolved: Sequence[Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = {
        provider: [dict(item)] for provider, item in parent.items()
    }
    for target in resolved:
        raw = target.get("source_status")
        if not isinstance(raw, Mapping):
            continue
        for provider, item in raw.items():
            if isinstance(item, Mapping):
                grouped.setdefault(str(provider), []).append(dict(item))
    rank = {"failed": 0, "skipped": 1, "hit": 2, "no_record": 3, "disabled": 4}
    aggregated: dict[str, dict[str, object]] = {}
    for provider in sorted(grouped):
        entries = grouped[provider]
        selected = min(entries, key=lambda item: rank.get(str(item.get("status")), 0))
        aggregated[provider] = selected
    return aggregated


def assemble_target_closure(endpoint: Endpoint) -> dict[str, object]:
    """Assemble five investigation layers and retain per-IP evidence for domains."""
    raw_resolved = endpoint.enrichment.get("resolved_ip_enrichment")
    if endpoint.kind != "domain" or not isinstance(raw_resolved, Mapping) or not raw_resolved:
        return _single_target_closure(endpoint)

    runtime = _mapping(endpoint.enrichment.get("runtime"))
    resolved_targets: list[dict[str, object]] = []
    for ip in sorted(str(value) for value in raw_resolved):
        enrichment = raw_resolved.get(ip)
        if not isinstance(enrichment, Mapping):
            continue
        merged = dict(enrichment)
        if runtime:
            merged["runtime"] = runtime
        resolved_endpoint = Endpoint(
            value=ip,
            kind="ip",
            evidences=list(endpoint.evidences),
            is_suspicious=True,
            enrichment=merged,
        )
        resolved_targets.append(_single_target_closure(resolved_endpoint))

    layers = {"runtime_evidence": _runtime_layer(endpoint)}
    for name in LAYER_NAMES[1:]:
        layers[name] = _aggregate_layer(name, resolved_targets)
    origins = [target.get("origin") for target in resolved_targets]
    required_origins = [origin for origin in origins if isinstance(origin, Mapping) and origin.get("required")]
    if not required_origins:
        origin: dict[str, object] = {"required": False, "status": "not_applicable"}
    elif all(item.get("status") == CLOSURE_COMPLETE for item in required_origins):
        origin = {"required": True, "status": CLOSURE_COMPLETE}
    else:
        origin = {"required": True, "status": "missing"}
    statuses = {str(layer.get("status")) for layer in layers.values()}
    status = CLOSURE_COMPLETE if statuses == {CLOSURE_COMPLETE} else CLOSURE_PARTIAL
    if origin.get("required") is True and origin.get("status") != CLOSURE_COMPLETE:
        status = CLOSURE_PARTIAL
    gaps = [name for name in LAYER_NAMES if layers[name].get("status") != CLOSURE_COMPLETE]
    if origin.get("required") is True and origin.get("status") != CLOSURE_COMPLETE:
        gaps.append("origin")
    return {
        "value": endpoint.value,
        "kind": endpoint.kind,
        "status": status,
        "layers": layers,
        "source_status": _aggregate_source_status(
            _normalize_source_status(endpoint.enrichment),
            resolved_targets,
        ),
        "origin": origin,
        "resolved_ips": [str(target.get("value")) for target in resolved_targets],
        "resolved_ip_targets": resolved_targets,
        "actual_service_operator": {"status": "unknown", "evidence": {}},
        "gaps": gaps,
    }


def _sources_are_terminal(endpoint: Endpoint, enrichers: Sequence[object]) -> bool:
    applicable = [
        enricher
        for enricher in enrichers
        if endpoint.kind in (getattr(enricher, "applies_to", []) or [])
    ]
    if not applicable:
        return True
    statuses = _normalize_source_status(endpoint.enrichment)
    terminal = {"hit", "no_record", "disabled", "skipped"}
    return all(
        statuses.get(getattr(enricher, "name", ""), {}).get("status") in terminal
        for enricher in applicable
    )


def _resolved_ips(endpoint: Endpoint) -> list[str]:
    if endpoint.kind != "domain":
        return []
    dns = _mapping(endpoint.enrichment.get("dns"))
    raw = dns.get("ips") or dns.get("addresses")
    if not isinstance(raw, list):
        return []
    return sorted({str(value).strip() for value in raw if str(value).strip()})


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
        if config.online and (config.refresh or not _sources_are_terminal(transient, typed_enrichers)):
            enrich_selected_targets(
                [transient],
                typed_enrichers,  # type: ignore[arg-type]
                mode=config.mode,
                include_case_close=True,
            )
        _set_attribution(transient)
        transient.enrichment.pop("runtime", None)
        resolved[ip] = transient.enrichment
    if resolved:
        endpoint.enrichment["resolved_ip_enrichment"] = resolved


def _update_target_leads(report: Report, targets: Sequence[Mapping[str, object]]) -> None:
    by_key = {(str(target.get("kind")), str(target.get("value")).lower()): target for target in targets}
    for lead in report.leads:
        kind = "domain" if lead.category.value == "DOMAIN" else "ip" if lead.category.value == "IP" else ""
        target = by_key.get((kind, lead.value.lower()))
        if target is None:
            continue
        layers = target.get("layers")
        request = layers.get("request_target") if isinstance(layers, Mapping) else None
        evidence = request.get("evidence") if isinstance(request, Mapping) else None
        if isinstance(evidence, Mapping):
            provider = evidence.get("provider")
            if provider:
                lead.where_to_request = str(provider)
            fields = evidence.get("evidence_fields")
            if isinstance(fields, list):
                for field in fields:
                    text = str(field)
                    if text and text not in lead.evidence_to_obtain:
                        lead.evidence_to_obtain.append(text)
        marker = "[case-close]"
        retained = [line for line in lead.notes.splitlines() if not line.startswith(marker)]
        raw_gaps = target.get("gaps")
        gaps = [str(gap) for gap in raw_gaps] if isinstance(raw_gaps, list) else []
        summary = f"{marker} status={target.get('status')}; gaps={','.join(gaps) or 'none'}"
        retained.append(summary)
        lead.notes = "\n".join(line for line in retained if line).strip()


def close_report(
    report: Report,
    config: ClosureConfig,
    *,
    enrichers: Sequence[object] | None = None,
) -> dict[str, object]:
    """Run bounded re-enrichment, five-layer assembly, and write ``meta.closure``."""
    from apkscan.core.enrichment import enrich_selected_targets
    from apkscan.core.registry import discover_enrichers

    selected = select_targets(report, config.max_targets)
    available = list(enrichers) if enrichers is not None else list(discover_enrichers())
    typed_enrichers = [enricher for enricher in available if hasattr(enricher, "enrich")]
    for endpoint in selected:
        if config.online and (config.refresh or not _sources_are_terminal(endpoint, typed_enrichers)):
            enrich_selected_targets(
                [endpoint],
                typed_enrichers,  # type: ignore[arg-type]
                mode=config.mode,
                include_case_close=True,
            )
        _set_attribution(endpoint)
        if endpoint.kind == "domain":
            _enrich_resolved_ips(endpoint, typed_enrichers, config)

    targets = [assemble_target_closure(endpoint) for endpoint in selected]
    closure = evaluate_closure(report, targets, require_dynamic=config.require_dynamic)
    report.meta["closure"] = closure
    _update_target_leads(report, targets)
    return closure


def _capture_meta(report: Report) -> dict[str, Any]:
    for key in ("capture_quality", "runtime_capture_quality", "capture_signals"):
        value = report.meta.get(key)
        if isinstance(value, Mapping):
            return dict(value)
    return {}


def _source_summary(targets: Sequence[Mapping[str, object]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for target in targets:
        sources = target.get("source_status")
        if not isinstance(sources, Mapping):
            continue
        for item in sources.values():
            if isinstance(item, Mapping):
                counts[str(item.get("status", "failed"))] += 1
    return {status: counts.get(status, 0) for status in sorted(SOURCE_STATUSES)}


def evaluate_closure(
    report: Report,
    targets: Sequence[Mapping[str, object]],
    *,
    require_dynamic: bool | None,
) -> dict[str, object]:
    """Calculate complete/partial/failed from explicit static, dynamic, and target gates."""
    checks: list[dict[str, object]] = []
    gaps: list[str] = []
    fatal = False

    if report.critical_failures or report.analysis_status == ANALYSIS_STATUS_FAILED:
        fatal = True
        checks.append(
            {
                "id": "static_health",
                "status": "fail",
                "reason": "critical static analysis failure",
                "evidence_refs": list(report.critical_failures),
            }
        )
        gaps.append("static analysis has critical failures")
    elif report.analysis_status != ANALYSIS_STATUS_COMPLETE:
        checks.append(
            {"id": "static_health", "status": "warn", "reason": "static analysis is partial", "evidence_refs": []}
        )
        gaps.append("static analysis is partial")
    else:
        checks.append(
            {"id": "static_health", "status": "pass", "reason": "static analysis completed", "evidence_refs": []}
        )

    dynamic_required = require_dynamic
    if dynamic_required is None:
        dynamic_required = bool(report.meta.get("runtime_merged") or _capture_meta(report))
    if dynamic_required:
        quality = evaluate_capture_quality(_capture_meta(report))
        dynamic_status = quality["dynamic_status"]
        check_status = "pass" if dynamic_status == CLOSURE_COMPLETE else "warn"
        if dynamic_status == CLOSURE_FAILED:
            check_status = "fail"
            fatal = True
        checks.append(
            {
                "id": "dynamic_evidence",
                "status": check_status,
                "reason": quality["reason"],
                "evidence_refs": [],
            }
        )
        if dynamic_status != CLOSURE_COMPLETE:
            gaps.append(str(quality["reason"]))
    else:
        checks.append(
            {
                "id": "dynamic_evidence",
                "status": "not_applicable",
                "reason": "dynamic evidence was not required",
                "evidence_refs": [],
            }
        )

    if not targets:
        fatal = True
        gaps.append("no investigation target selected")
    for target in targets:
        value = str(target.get("value", "target"))
        if target.get("status") != CLOSURE_COMPLETE:
            gaps.append(f"{value}: five-layer attribution is incomplete")
        origin = target.get("origin")
        if isinstance(origin, Mapping) and origin.get("required") is True and origin.get("status") != CLOSURE_COMPLETE:
            gaps.append(f"{value}: Origin is missing behind edge/CDN")
        sources = target.get("source_status")
        if isinstance(sources, Mapping):
            failed_sources = [
                str(name)
                for name, item in sources.items()
                if isinstance(item, Mapping)
                and (
                    item.get("status") == "failed"
                    or (
                        item.get("status") == "skipped"
                        and item.get("reason") != "active_mode_blocked"
                    )
                )
            ]
            if failed_sources:
                gaps.append(f"{value}: source lookup incomplete ({', '.join(sorted(failed_sources))})")

    gaps = list(dict.fromkeys(gaps))
    if fatal:
        status = CLOSURE_FAILED
    elif gaps:
        status = CLOSURE_PARTIAL
    else:
        status = CLOSURE_COMPLETE
    return {
        "schema_version": "1.0",
        "status": status,
        "checks": checks,
        "targets": [dict(target) for target in targets],
        "source_summary": _source_summary(targets),
        "gaps": gaps,
        "next_actions": [f"Resolve closure gap: {gap}" for gap in gaps],
    }


__all__ = [
    "CLOSURE_COMPLETE",
    "CLOSURE_FAILED",
    "CLOSURE_PARTIAL",
    "LAYER_NAMES",
    "SOURCE_STATUSES",
    "ClosureConfig",
    "assemble_target_closure",
    "close_report",
    "evaluate_capture_quality",
    "evaluate_closure",
    "select_targets",
]
