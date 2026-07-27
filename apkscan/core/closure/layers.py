"""五层组装：把单个目标端点的富化证据组装为五层调证结构（runtime_evidence / resource_registration /
bgp_announcement / hosting_delivery / request_target），域名目标另做逐 IP 聚合。

为什么这样切：这是闭环的证据组装核心——输入是端点 enrichment（已由 sources 填好），输出是
``assemble_target_closure`` 的分层 dict；只读证据、不发起任何富化。依赖方向单向：
_shared（常量）→ targets（``_runtime_info``/``_parse_fofa_row`` 输入侧工具）→ gates（``_non_negative_int``），
不 import sources，也不反向 import closure 包本身。
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from apkscan.core.models import Endpoint

from apkscan.core.closure._shared import (
    CLOSURE_COMPLETE,
    CLOSURE_FAILED,
    CLOSURE_PARTIAL,
    LAYER_NAMES,
    SOURCE_STATUSES,
    _mapping,
)
from apkscan.core.closure.gates import _non_negative_int
from apkscan.core.closure.targets import _parse_fofa_row, _runtime_info


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
            fields = _parse_fofa_row(row)  # 命名字段解析 + 形状校验（不再按魔数下标取值）
            if fields is None:
                continue
            add_provider("fofa", fields["as_organization"])
            add_service(
                "fofa",
                {
                    "port": fields["port"],
                    "protocol": fields["protocol"],
                    "title": fields["title"],
                    "server": fields["server"],
                },
            )
            add_location(
                "fofa",
                {
                    "country": fields["country"],
                    "region": fields["region"],
                    "city": fields["city"],
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
