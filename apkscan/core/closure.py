"""Deterministic case-closure gates over static, runtime, and attribution evidence."""

from __future__ import annotations

import ipaddress
import os
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
_MAX_RESOLVED_IPS_PER_TARGET = 8
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
    start_address = rdap.get("start_address") or rdap.get("startAddress")
    end_address = rdap.get("end_address") or rdap.get("endAddress")
    raw_cidr = rdap.get("cidr")
    if isinstance(raw_cidr, str):
        valid_cidr = raw_cidr if "/" in raw_cidr else None
    elif isinstance(raw_cidr, list):
        valid_cidr = [value for value in raw_cidr if isinstance(value, str) and "/" in value]
    else:
        valid_cidr = None
    network = valid_cidr or (start_address and end_address)
    administrative_ref = rdap.get("handle") or rdap.get("remarks")
    evidence = {
        key: value
        for key, value in {
            "netname": rdap.get("netname"),
            "org": rdap.get("org"),
            "country": rdap.get("country"),
            "handle": rdap.get("handle"),
            "remarks": rdap.get("remarks"),
            "cidr": rdap.get("cidr"),
            "start_address": start_address,
            "end_address": end_address,
        }.items()
        if value not in (None, "", [])
    }
    if holder and network and rdap.get("country") and administrative_ref:
        return _layer(CLOSURE_COMPLETE, evidence)
    if evidence:
        return _layer(CLOSURE_PARTIAL, evidence, reason="IP registration record is incomplete")
    return _layer(CLOSURE_FAILED, reason="IP registration record is missing")


def _bgp_layer(enrichment: Mapping[str, object]) -> dict[str, object]:
    bgp = _mapping(enrichment.get("ripestat_bgp"))
    evidence = {
        key: bgp.get(key)
        for key in ("origin_asn", "asn_holder", "prefix", "upstreams")
        if bgp.get(key) not in (None, "", [])
    }
    required = (
        bgp.get("origin_asn"),
        bgp.get("asn_holder"),
        bgp.get("prefix"),
        bgp.get("upstreams"),
    )
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
    origin_ips = origin.get("ips")
    has_origin = bool(origin.get("ip")) or (isinstance(origin_ips, list) and bool(origin_ips))
    confirmed = origin.get("confirmed") is True or origin.get("status") == "confirmed"
    if has_origin and confirmed:
        return {"required": True, "status": CLOSURE_COMPLETE, "evidence": origin}
    candidates = origin.get("candidates") or enrichment.get("origin_candidates")
    missing: dict[str, object] = {
        "required": True,
        "status": "missing",
        "edge_provider": edge,
    }
    if has_origin or (isinstance(candidates, list) and candidates):
        missing["evidence"] = {
            "candidates": origin_ips or candidates or [origin.get("ip")],
            "confirmation_required": True,
        }
    return missing


def _passive_hosting_evidence(
    enrichment: Mapping[str, object],
) -> tuple[list[dict[str, str]], list[dict[str, object]], list[dict[str, object]]]:
    providers: list[dict[str, str]] = []
    services: list[dict[str, object]] = []
    locations: list[dict[str, object]] = []

    def add_provider(source: str, value: object) -> None:
        if not isinstance(value, str) or not value.strip():
            return
        entry = {"source": source, "name": value.strip()}
        if entry not in providers:
            providers.append(entry)

    def add_service(source: str, *records: Mapping[str, object]) -> None:
        fields = (
            "port",
            "protocol",
            "transport",
            "service_name",
            "product",
            "version",
            "server",
            "title",
            "web_title",
            "http_title",
            "module",
            "hostname",
            "hostnames",
        )
        summary: dict[str, object] = {"source": source}
        for record in records:
            for field in fields:
                value = record.get(field)
                if field not in summary and value not in (None, "", [], {}):
                    summary[field] = value
        if len(summary) > 1 and summary not in services:
            services.append(summary)

    def add_location(source: str, record: Mapping[str, object]) -> None:
        summary = {
            key: record.get(key)
            for key in ("country", "country_code", "region", "province", "city")
            if record.get(key) not in (None, "", [], {})
        }
        if summary:
            entry: dict[str, object] = {"source": source, **summary}
            if entry not in locations:
                locations.append(entry)

    fofa = _mapping(enrichment.get("fofa"))
    raw_fofa_records = fofa.get("records")
    if isinstance(raw_fofa_records, list):
        for row in raw_fofa_records[:20]:
            if not isinstance(row, list):
                continue
            add_provider("fofa", row[10] if len(row) > 10 else None)
            add_service(
                "fofa",
                {
                    "port": row[2] if len(row) > 2 else None,
                    "protocol": row[3] if len(row) > 3 else None,
                    "title": row[4] if len(row) > 4 else None,
                    "server": row[5] if len(row) > 5 else None,
                },
            )
            add_location(
                "fofa",
                {
                    "country": row[6] if len(row) > 6 else None,
                    "region": row[7] if len(row) > 7 else None,
                    "city": row[8] if len(row) > 8 else None,
                },
            )

    for source in ("quake", "hunter", "zoomeye", "urlscan"):
        payload = _mapping(enrichment.get(source))
        raw_records = payload.get("records")
        if not isinstance(raw_records, list):
            continue
        for raw_record in raw_records[:20]:
            record = _mapping(raw_record)
            if not record:
                continue
            autonomous_system = _mapping(record.get("autonomous_system"))
            add_provider(
                source,
                record.get("as_organization")
                or record.get("as_org")
                or record.get("organization")
                or record.get("org")
                or record.get("isp")
                or record.get("asnname")
                or autonomous_system.get("organization")
                or autonomous_system.get("org")
                or autonomous_system.get("name"),
            )
            add_service(
                source,
                record,
                _mapping(record.get("service")),
                _mapping(record.get("portinfo")),
            )
            add_location(source, record)
            add_location(source, _mapping(record.get("location") or record.get("geoinfo")))

    censys = _mapping(enrichment.get("censys"))
    censys_asn = _mapping(censys.get("autonomous_system"))
    add_provider(
        "censys",
        censys_asn.get("organization") or censys_asn.get("org") or censys_asn.get("name"),
    )
    raw_censys_services = censys.get("services")
    if isinstance(raw_censys_services, list):
        for raw_service in raw_censys_services[:20]:
            service = _mapping(raw_service)
            if service:
                add_service("censys", service)
    add_location("censys", _mapping(censys.get("location")))

    virustotal = _mapping(enrichment.get("virustotal"))
    add_provider("virustotal", virustotal.get("as_owner"))
    if virustotal.get("country") not in (None, ""):
        add_location("virustotal", {"country": virustotal.get("country")})
    return providers, services, locations


def _hosting_layer(enrichment: Mapping[str, object]) -> dict[str, object]:
    shodan = _mapping(enrichment.get("shodan"))
    asn = _mapping(enrichment.get("asn"))
    attribution = _attribution_for_endpoint(enrichment)
    hosting = _mapping(attribution.get("hosting_provider"))
    passive_providers, passive_services, passive_locations = _passive_hosting_evidence(enrichment)
    passive_provider = passive_providers[0] if passive_providers else {}
    provider = (
        shodan.get("org")
        or passive_provider.get("name")
        or hosting.get("name")
        or asn.get("org")
        or asn.get("isp")
    )
    provider_source = (
        "shodan"
        if shodan.get("org")
        else passive_provider.get("source")
        or hosting.get("source")
        or "asn"
    )
    raw_services = shodan.get("services")
    services = list(raw_services) if isinstance(raw_services, list) else []
    services.extend(passive_services)
    raw_ports = shodan.get("ports")
    ports = raw_ports if isinstance(raw_ports, list) else []
    matched_signals = (
        [str(value) for value in hosting.get("matched_signals", [])]
        if isinstance(hosting.get("matched_signals"), list)
        else []
    )
    corroborating_signals = [value for value in matched_signals if value != "origin_asn_category"]
    service_detail_fields = {
        "product",
        "version",
        "server",
        "title",
        "web_title",
        "http_title",
        "module",
    }
    detailed_service = any(
        isinstance(service, Mapping)
        and any(service.get(field) not in (None, "", [], {}) for field in service_detail_fields)
        for service in services
    )
    delivery_detail = any(
        hosting.get(field) not in (None, "", [], {})
        for field in ("facility", "datacenter", "region", "reassignment", "instance")
    )
    evidence = {
        "provider": provider,
        "provider_source": provider_source,
        "provider_candidates": passive_providers,
        "asn": asn.get("asn") or shodan.get("asn"),
        "country": asn.get("country") or shodan.get("country"),
        "ports": ports,
        "services": services,
        "locations": passive_locations,
        "matched_signals": matched_signals,
    }
    evidence = {key: value for key, value in evidence.items() if value not in (None, "", [])}
    if provider and (detailed_service or corroborating_signals or delivery_detail):
        return _layer(CLOSURE_COMPLETE, evidence)
    if provider:
        return _layer(
            CLOSURE_PARTIAL,
            evidence,
            reason="provider found without corroborating product, facility, or reassignment evidence",
        )
    return _layer(CLOSURE_FAILED, reason="hosting or delivery provider is missing")


def _request_layer(hosting: Mapping[str, object], origin: Mapping[str, object]) -> dict[str, object]:
    evidence = _mapping(hosting.get("evidence"))
    infrastructure_provider = evidence.get("provider")
    request_evidence = {
        "provider": infrastructure_provider,
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
            if infrastructure_provider and infrastructure_provider != edge:
                request_evidence["edge_infrastructure_provider"] = infrastructure_provider
            request_evidence["provider"] = edge
            request_evidence["edge_provider"] = edge
        request_evidence["evidence_fields"] = [
            "customer identity",
            "domain and account binding",
            "payment records",
            "control-plane login logs",
            "origin configuration",
            "access and origin logs",
        ]
        return _layer(CLOSURE_PARTIAL, request_evidence, reason="Origin must be obtained first")
    if origin.get("required") is True:
        origin_evidence = _mapping(origin.get("evidence"))
        raw_origin_provider = (
            origin_evidence.get("request_target")
            or origin_evidence.get("hosting_provider")
            or origin_evidence.get("provider")
        )
        if isinstance(raw_origin_provider, Mapping):
            origin_provider = (
                raw_origin_provider.get("legal_entity")
                or raw_origin_provider.get("name")
                or raw_origin_provider.get("org")
            )
        else:
            origin_provider = raw_origin_provider
        origin_ips = origin_evidence.get("ips")
        origin_ip = origin_evidence.get("ip")
        if not origin_ip and isinstance(origin_ips, list) and origin_ips:
            origin_ip = origin_ips[0]
        request_evidence = {
            "provider": origin_provider,
            "origin_ip": origin_ip,
            "evidence_fields": [
                "tenant identity",
                "instance binding",
                "payment records",
                "control-plane login logs",
                "access and origin logs",
            ],
        }
        request_evidence = {
            key: value for key, value in request_evidence.items() if value not in (None, "", [])
        }
        if origin_provider:
            return _layer(CLOSURE_COMPLETE, request_evidence)
        return _layer(
            CLOSURE_PARTIAL,
            request_evidence,
            reason="confirmed Origin lacks an executable server-provider request target",
        )
    if infrastructure_provider and hosting.get("status") == CLOSURE_COMPLETE:
        return _layer(CLOSURE_COMPLETE, request_evidence)
    if infrastructure_provider:
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
    resolved_ip_selection = _mapping(endpoint.enrichment.get("resolved_ip_selection"))
    if _non_negative_int(resolved_ip_selection.get("truncated")) > 0:
        status = CLOSURE_PARTIAL
        gaps.append("resolved_ip_limit")
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
        "resolved_ip_selection": resolved_ip_selection,
        "resolved_ip_targets": resolved_targets,
        "actual_service_operator": {"status": "unknown", "evidence": {}},
        "gaps": gaps,
    }


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
        pending = _enrichers_to_run(
            endpoint,
            typed_enrichers,
            mode=config.mode,
            refresh=config.refresh,
        )
        if config.online and pending:
            enrich_selected_targets(
                [endpoint],
                pending,  # type: ignore[arg-type]
                mode=config.mode,
                include_case_close=True,
            )
        _ensure_source_status_coverage(endpoint, typed_enrichers, config)
        _set_attribution(endpoint)
        if endpoint.kind == "domain":
            _enrich_resolved_ips(endpoint, typed_enrichers, config)

    targets = [assemble_target_closure(endpoint) for endpoint in selected]
    closure = evaluate_closure(report, targets, require_dynamic=config.require_dynamic)
    report.meta["closure"] = closure
    _populate_network_attribution(report)
    _update_target_leads(report, targets)
    return closure


def _populate_network_attribution(report: Report) -> None:
    """Assemble the additive network_attribution view from the (now refreshed) endpoint
    facts. View-only, passive; its own guard so it never sinks case closure nor mutates
    the returned closure. On failure a minimal deterministic error marker is recorded."""
    import logging

    try:
        from apkscan.attribution.assemble import build_network_attribution

        artifact_id = str(report.meta.get("sample_sha256") or "") or f"pkg:{report.package_name or 'unknown'}"
        blob = build_network_attribution(report.endpoints, artifact_id=artifact_id, phase="close")
        if blob is not None:
            report.meta["network_attribution"] = blob
    except Exception as exc:  # noqa: BLE001 - view-only; a failure never fails case closure
        logging.getLogger(__name__).warning("network_attribution 组装失败：%s", type(exc).__name__)
        report.meta["network_attribution"] = {"phase": "close", "error": type(exc).__name__}


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
