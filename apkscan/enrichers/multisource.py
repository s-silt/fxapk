"""Passive, bounded, case-close-only infrastructure intelligence adapters."""

from __future__ import annotations

import base64
import os
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

import requests

from apkscan.core.closure import SOURCE_STATUSES
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher

_TIMEOUT = 12
_MAX_RECORDS = 20
_MAX_TEXT = 500
_METADATA_ONLY_KEYS = {"source", "count", "pulse_count", "_via"}


class _ProviderResponseError(RuntimeError):
    """Sanitized marker for provider-declared errors in HTTP 200 responses."""


@dataclass(frozen=True)
class SourceOutcome:
    provider: str
    status: str
    data: dict[str, object] = field(default_factory=dict)
    error_type: str | None = None

    def __post_init__(self) -> None:
        if self.status not in SOURCE_STATUSES:
            raise ValueError(f"unsupported source status: {self.status}")


def _dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _list_of_dicts(value: object, *, limit: int = _MAX_RECORDS) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)][:limit]


def _bounded_scalar(value: object) -> str | int | float | bool | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped[:_MAX_TEXT] if stripped else None
    if isinstance(value, bool | int | float):
        return value
    return None


def _bounded_scalar_list(value: object) -> list[str | int | float | bool]:
    if not isinstance(value, list):
        return []
    compact: list[str | int | float | bool] = []
    for item in value[:_MAX_RECORDS]:
        scalar = _bounded_scalar(item)
        if scalar is not None:
            compact.append(scalar)
    return compact


def _compact_mapping(value: object, fields: tuple[str, ...]) -> dict[str, object]:
    source = _dict(value)
    compact: dict[str, object] = {}
    for key in fields:
        scalar = _bounded_scalar(source.get(key))
        if scalar is not None:
            compact[key] = scalar
    return compact


_ASSET_FIELDS = (
    "ip",
    "ip_address",
    "port",
    "protocol",
    "transport",
    "domain",
    "hostname",
    "host",
    "title",
    "web_title",
    "server",
    "product",
    "version",
    "service_name",
    "country",
    "country_code",
    "region",
    "province",
    "city",
    "asn",
    "as_number",
    "as_org",
    "as_organization",
    "isp",
    "org",
    "organization",
    "updated_at",
    "timestamp",
)
_SERVICE_FIELDS = (
    "name",
    "port",
    "protocol",
    "transport",
    "service",
    "service_name",
    "product",
    "version",
    "server",
    "title",
    "web_title",
    "status_code",
)
_LOCATION_FIELDS = (
    "country",
    "country_code",
    "registered_country",
    "region",
    "province",
    "city",
    "latitude",
    "longitude",
    "timezone",
)
_ASN_FIELDS = (
    "asn",
    "as_number",
    "name",
    "org",
    "organization",
    "country_code",
    "bgp_prefix",
)


def _compact_asset_records(value: object) -> list[dict[str, object]]:
    compact: list[dict[str, object]] = []
    for record in _list_of_dicts(value):
        item = _compact_mapping(record, _ASSET_FIELDS)
        for nested_field in ("service", "portinfo"):
            nested = _compact_mapping(record.get(nested_field), _SERVICE_FIELDS)
            if nested:
                item[nested_field] = nested
        for nested_field in ("location", "geoinfo"):
            nested = _compact_mapping(record.get(nested_field), _LOCATION_FIELDS)
            if nested:
                item[nested_field] = nested
        autonomous_system = _compact_mapping(record.get("autonomous_system"), _ASN_FIELDS)
        if autonomous_system:
            item["autonomous_system"] = autonomous_system
        hostnames = _bounded_scalar_list(record.get("hostnames"))
        if hostnames:
            item["hostnames"] = hostnames
        if item:
            compact.append(item)
    return compact


def _provider_declared_error(payload: object, provider: str = "") -> bool:
    root = _dict(payload)
    if root.get("success") is False:
        return True
    for key in ("error", "errors"):
        if root.get(key) not in (None, False, 0, "", [], {}):
            return True
    code = root.get("code")
    if provider == "quake" and code not in (None, 0, "0"):
        return True
    if provider == "hunter" and code not in (None, 0, 200, "0", "200"):
        return True
    return False


def _safe_host_reference(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = urlsplit(text if "://" in text else f"//{text}")
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not hostname:
        return None
    host = f"[{hostname}]" if ":" in hostname else hostname
    authority = f"{host}:{port}" if port is not None else host
    scheme = parsed.scheme.lower()
    return f"{scheme}://{authority}" if scheme in {"http", "https"} else authority


def _http_status_code(exc: Exception) -> int | None:
    response = getattr(exc, "response", None)
    value = getattr(response, "status_code", None)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _safe_error_type(exc: Exception) -> str:
    status_code = _http_status_code(exc)
    if status_code is not None:
        return f"http_{status_code}"
    if isinstance(exc, requests.Timeout):
        return "timeout"
    if isinstance(exc, _ProviderResponseError):
        return "provider_response_error"
    if isinstance(exc, ValueError):
        return "parse_error"
    return type(exc).__name__


def _credential(names: tuple[str, ...]) -> str:
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


class _PassiveLookupEnricher(BaseEnricher, ABC):
    case_close_only = True
    active = False
    required_env: tuple[str, ...] = ()
    #: 境内直连源（如 hunter.qianxin.com）置 True → 会话 trust_env=False 强制直连、绕过系统/环境代理。
    #: 用户跑工具常开境外代理，境内源经代理会 403/被封（见 hunter）；直连才通。国际源保持默认（随系统代理）。
    bypass_system_proxy: bool = False

    def __init__(self, session: Any | None = None) -> None:
        self._http = session if session is not None else requests.Session()
        if self.bypass_system_proxy:
            self._http.trust_env = False  # 忽略 HTTP(S)_PROXY / 系统代理 → 直连（境内源必须）

    def _egress_label(self) -> str:
        """本富化器请求走的出口：绕代理直连 → 'direct'；否则随系统/环境代理（配了代理即 'system_proxy'）。
        仅记策略、不额外探测出口 IP（零多余网络），供报告溯源"此结果来自哪个出口"。绝不抛。"""
        if self.bypass_system_proxy:
            return "direct"
        try:
            return "system_proxy" if urllib.request.getproxies() else "direct"
        except Exception:  # noqa: BLE001 — 出口标注失败不得拖累富化
            return "unknown"

    @abstractmethod
    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        ...

    @abstractmethod
    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        ...

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        via = self._egress_label()  # 本次请求出口（direct=绕代理直连 / system_proxy=随系统代理）——记进每条结果溯源
        credential = _credential(self.required_env)
        if self.required_env and not credential:
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                data={"_source_status": "disabled", "_via": via},
                error="disabled",
            )
        try:
            payload = self._lookup(ep, credential)
            if _provider_declared_error(payload, self.name):
                raise _ProviderResponseError
            data = self._normalize(payload, ep)
        except Exception as exc:  # noqa: BLE001 - provider failures never stop case closure
            error_type = _safe_error_type(exc)
            if _http_status_code(exc) == 404:
                return EnrichmentResult(
                    provider=self.name,
                    ok=True,
                    data={"_source_status": "no_record", "_error_type": error_type, "_via": via},
                )
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                data={"_source_status": "failed", "_error_type": error_type, "_via": via},
                error=error_type,
            )
        has_values = any(
            key not in _METADATA_ONLY_KEYS and value not in (None, "", [], {})
            for key, value in data.items()
        )
        data["_source_status"] = "hit" if has_values else "no_record"
        data["_via"] = via
        return EnrichmentResult(provider=self.name, ok=True, data=data)


class RipeStatBgpEnricher(_PassiveLookupEnricher):
    name = "ripestat_bgp"
    applies_to = ["ip"]
    _URL = "https://stat.ripe.net/data/prefix-overview/data.json"
    _NEIGHBOURS_URL = "https://stat.ripe.net/data/asn-neighbours/data.json"

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        del credential
        response = self._http.get(
            self._URL,
            params={"resource": endpoint.value, "sourceapp": "fxapk-case-close"},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        prefix_payload = response.json()
        if _provider_declared_error(prefix_payload, self.name):
            raise _ProviderResponseError
        result: dict[str, object] = {"prefix_overview": prefix_payload}
        prefix_data = _dict(_dict(prefix_payload).get("data"))
        asns = prefix_data.get("asns")
        first_asn: object = asns[0] if isinstance(asns, list) and asns else None
        if isinstance(first_asn, Mapping):
            first_asn = first_asn.get("asn")
        if first_asn in (None, ""):
            return result
        try:
            neighbour_response = self._http.get(
                self._NEIGHBOURS_URL,
                params={"resource": f"AS{first_asn}", "sourceapp": "fxapk-case-close"},
                timeout=_TIMEOUT,
            )
            neighbour_response.raise_for_status()
            neighbour_payload = neighbour_response.json()
            if _provider_declared_error(neighbour_payload, self.name):
                raise _ProviderResponseError
            result["asn_neighbours"] = neighbour_payload
        except Exception as exc:  # noqa: BLE001 - retain prefix evidence on upstream lookup failure
            result["upstream_lookup"] = {
                "status": "failed",
                "error_type": _safe_error_type(exc),
            }
        return result

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        root = _dict(payload)
        prefix_payload = _dict(root.get("prefix_overview")) if "prefix_overview" in root else root
        data = _dict(prefix_payload.get("data"))
        asns = data.get("asns")
        origin_asn: object = None
        holder: object = data.get("holder")
        if isinstance(asns, list) and asns:
            first = asns[0]
            if isinstance(first, Mapping):
                origin_asn = first.get("asn")
                holder = first.get("holder") or holder
            else:
                origin_asn = first
        neighbour_data = _dict(_dict(root.get("asn_neighbours")).get("data"))
        upstreams: set[int] = set()
        for neighbour in _list_of_dicts(neighbour_data.get("neighbours")):
            if str(neighbour.get("type") or "").lower() != "left":
                continue
            raw_asn = neighbour.get("asn")
            if isinstance(raw_asn, bool):
                continue
            try:
                asn_number = int(str(raw_asn))
            except (TypeError, ValueError):
                continue
            if 1 <= asn_number <= 4_294_967_294:
                upstreams.add(asn_number)
        normalized = {
            key: value
            for key, value in {
                "origin_asn": _bounded_scalar(origin_asn),
                "asn_holder": _bounded_scalar(holder),
                "prefix": _bounded_scalar(data.get("resource")),
                "announced": _bounded_scalar(data.get("announced")),
                "upstreams": sorted(upstreams),
                "source": "ripestat-prefix-overview",
            }.items()
            if value not in (None, "", [])
        }
        upstream_lookup = _dict(root.get("upstream_lookup"))
        if upstream_lookup.get("status") == "failed":
            normalized["upstream_lookup_status"] = "failed"
            error_type = _bounded_scalar(upstream_lookup.get("error_type"))
            if error_type is not None:
                normalized["upstream_error_type"] = error_type
        return normalized


class FofaPassiveEnricher(_PassiveLookupEnricher):
    name = "fofa"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_FOFA_KEY",)

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        base_url = (os.environ.get("FXAPK_FOFA_URL") or "https://fofa.info/api/v1/search/all").rstrip("/")
        query = f'ip="{endpoint.value}"' if endpoint.kind == "ip" else f'domain="{endpoint.value}"'
        response = self._http.get(
            base_url,
            params={
                "key": credential,
                "qbase64": base64.b64encode(query.encode("utf-8")).decode("ascii"),
                "fields": "host,ip,port,protocol,title,server,country,region,city,as_number,as_organization",
                "size": _MAX_RECORDS,
            },
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        root = _dict(payload)
        rows = root.get("results")
        normalized = []
        if isinstance(rows, list):
            for row in rows[:_MAX_RECORDS]:
                if not isinstance(row, list):
                    continue
                compact = [_bounded_scalar(value) for value in row[:11]]
                if compact and any(value is not None for value in compact):
                    compact[0] = _safe_host_reference(row[0]) if row else None
                    normalized.append(compact)
        return {"records": normalized, "count": len(normalized), "source": "fofa"} if normalized else {}


class QuakePassiveEnricher(_PassiveLookupEnricher):
    name = "quake"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_QUAKE_KEY", "FXAPK_QUAKE_KEY2")

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        url = os.environ.get("FXAPK_QUAKE_URL") or "https://quake.360.net/api/v3/search/quake_service"
        query = f'ip:"{endpoint.value}"' if endpoint.kind == "ip" else f'domain:"{endpoint.value}"'
        response = self._http.post(
            url,
            headers={"X-QuakeToken": credential},
            json={"query": query, "start": 0, "size": _MAX_RECORDS},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        records = _compact_asset_records(_dict(payload).get("data"))
        return {"records": records, "count": len(records), "source": "quake"} if records else {}


class HunterPassiveEnricher(_PassiveLookupEnricher):
    name = "hunter"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_HUNTER_KEY",)
    _URL = "https://hunter.qianxin.com/openApi/search"
    #: hunter.qianxin.com 须境内直连——经境外代理返 403（用户跑工具常开境外代理）。强制绕代理直连。
    #: 它是境内定人最有用的源（ICP 备案 company + 机房城市），不能被代理静默打断。
    bypass_system_proxy = True

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        query = f'ip="{endpoint.value}"' if endpoint.kind == "ip" else f'domain="{endpoint.value}"'
        response = self._http.get(
            self._URL,
            params={
                "api-key": credential,
                "search": base64.urlsafe_b64encode(query.encode("utf-8")).decode("ascii"),
                "page": 1,
                "page_size": _MAX_RECORDS,
                "is_web": 3,
            },
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        data = _dict(_dict(payload).get("data"))
        records = _compact_asset_records(data.get("arr") or data.get("list"))
        return {"records": records, "count": len(records), "source": "hunter"} if records else {}


class ZoomEyePassiveEnricher(_PassiveLookupEnricher):
    name = "zoomeye"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_ZOOMEYE_KEY", "ZOOMEYE_API_KEY")
    _URL = "https://api.zoomeye.org/host/search"

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        query = f'ip:"{endpoint.value}"' if endpoint.kind == "ip" else f'hostname:"{endpoint.value}"'
        url = os.environ.get("FXAPK_ZOOMEYE_URL") or self._URL
        response = self._http.get(
            url,
            params={"query": query, "page": 1},
            headers={"API-KEY": credential},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        records = _compact_asset_records(_dict(payload).get("matches"))
        return {"records": records, "count": len(records), "source": "zoomeye"} if records else {}


class CensysPassiveEnricher(_PassiveLookupEnricher):
    name = "censys"
    applies_to = ["ip"]
    required_env = ("FXAPK_CENSYS_TOKEN", "CENSYS_API_TOKEN")
    _URL = "https://api.platform.censys.io/v3/global/asset/host/{ip}"

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        headers = {
            "Authorization": f"Bearer {credential}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        }
        organization = (os.environ.get("FXAPK_CENSYS_ORG_ID") or "").strip()
        if organization:
            headers["X-Organization-ID"] = organization
        response = self._http.get(
            self._URL.format(ip=endpoint.value),
            headers=headers,
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        root = _dict(payload)
        result = _dict(root.get("result") or root.get("data"))
        services = [
            service
            for item in _list_of_dicts(result.get("services"))
            if (service := _compact_mapping(item, _SERVICE_FIELDS))
        ]
        if not result:
            return {}
        normalized: dict[str, object] = {}
        ip = _bounded_scalar(result.get("ip") or result.get("ip_address"))
        if ip is not None:
            normalized["ip"] = ip
        location = _compact_mapping(result.get("location"), _LOCATION_FIELDS)
        if location:
            normalized["location"] = location
        autonomous_system = _compact_mapping(result.get("autonomous_system"), _ASN_FIELDS)
        if autonomous_system:
            normalized["autonomous_system"] = autonomous_system
        if services:
            normalized["services"] = services
        if normalized:
            normalized["source"] = "censys"
        return normalized


class VirusTotalPassiveEnricher(_PassiveLookupEnricher):
    name = "virustotal"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_VT_KEY", "VT_API_KEY")
    _BASE = "https://www.virustotal.com/api/v3"

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        collection = "ip_addresses" if endpoint.kind == "ip" else "domains"
        response = self._http.get(
            f"{self._BASE}/{collection}/{endpoint.value}",
            headers={"x-apikey": credential},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        attributes = _dict(_dict(_dict(payload).get("data")).get("attributes"))
        if not attributes:
            return {}
        normalized: dict[str, object] = {}
        for key in ("asn", "as_owner", "country", "network", "reputation"):
            scalar = _bounded_scalar(attributes.get(key))
            if scalar is not None:
                normalized[key] = scalar
        dns_records = []
        for record in _list_of_dicts(attributes.get("last_dns_records")):
            record_type = str(record.get("type") or "").upper()
            if record_type not in {"A", "AAAA", "CNAME", "MX", "NS"}:
                continue
            compact = _compact_mapping(record, ("type", "value", "ttl", "date", "last_resolved"))
            if compact:
                dns_records.append(compact)
        if dns_records:
            normalized["last_dns_records"] = dns_records
        raw_analysis_stats = _dict(attributes.get("last_analysis_stats"))
        analysis_stats = {
            key: value
            for key in ("harmless", "malicious", "suspicious", "undetected", "timeout")
            if isinstance((value := raw_analysis_stats.get(key)), int)
            and not isinstance(value, bool)
        }
        if analysis_stats:
            normalized["last_analysis_stats"] = analysis_stats
        tags = _bounded_scalar_list(attributes.get("tags"))
        if tags:
            normalized["tags"] = tags
        normalized["source"] = "virustotal"
        return normalized


class OtxPassiveEnricher(_PassiveLookupEnricher):
    name = "otx"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_OTX_KEY", "OTX_API_KEY")
    _BASE = "https://otx.alienvault.com/api/v1/indicators"

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        indicator_type = "IPv4" if endpoint.kind == "ip" else "domain"
        response = self._http.get(
            f"{self._BASE}/{indicator_type}/{endpoint.value}/general",
            headers={"X-OTX-API-KEY": credential},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        root = _dict(payload)
        pulse_info = _dict(root.get("pulse_info"))
        pulses = []
        for pulse in _list_of_dicts(pulse_info.get("pulses")):
            compact = _compact_mapping(
                pulse,
                ("id", "name", "created", "modified", "indicator_count", "public"),
            )
            tags = _bounded_scalar_list(pulse.get("tags"))
            if tags:
                compact["tags"] = tags
            if compact:
                pulses.append(compact)
        if not root:
            return {}
        normalized = _compact_mapping(root, ("reputation", "country_code", "asn"))
        if pulses:
            normalized["pulses"] = pulses
        pulse_count = _bounded_scalar(pulse_info.get("count", len(pulses)))
        if pulse_count is not None:
            normalized["pulse_count"] = pulse_count
        if normalized:
            normalized["source"] = "otx"
        return normalized


class UrlscanPassiveEnricher(_PassiveLookupEnricher):
    name = "urlscan"
    applies_to = ["ip", "domain"]
    _URL = "https://urlscan.io/api/v1/search/"

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        query = f"ip:{endpoint.value}" if endpoint.kind == "ip" else f"domain:{endpoint.value}"
        api_key = _credential(("FXAPK_URLSCAN_KEY", "URLSCAN_API_KEY")) or credential
        headers = {"api-key": api_key} if api_key else {}
        response = self._http.get(
            self._URL,
            params={"q": query, "size": _MAX_RECORDS},
            headers=headers,
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        records = _list_of_dicts(_dict(payload).get("results"))
        compact = []
        for record in records:
            page = _dict(record.get("page"))
            task = _dict(record.get("task"))
            item = _compact_mapping(page, ("domain", "ip", "asn", "asnname", "country"))
            scan_id = _bounded_scalar(task.get("uuid"))
            if scan_id is not None:
                item["scan_id"] = scan_id
            if item:
                compact.append(item)
        return {"records": compact, "count": len(compact), "source": "urlscan"} if compact else {}


def configured_case_close_enrichers() -> list[BaseEnricher]:
    """Return all built-in bounded passive adapters in deterministic order."""
    return [
        RipeStatBgpEnricher(),
        FofaPassiveEnricher(),
        QuakePassiveEnricher(),
        HunterPassiveEnricher(),
        ZoomEyePassiveEnricher(),
        CensysPassiveEnricher(),
        VirusTotalPassiveEnricher(),
        OtxPassiveEnricher(),
        UrlscanPassiveEnricher(),
    ]


__all__ = [
    "CensysPassiveEnricher",
    "FofaPassiveEnricher",
    "HunterPassiveEnricher",
    "OtxPassiveEnricher",
    "QuakePassiveEnricher",
    "RipeStatBgpEnricher",
    "SourceOutcome",
    "UrlscanPassiveEnricher",
    "VirusTotalPassiveEnricher",
    "ZoomEyePassiveEnricher",
    "configured_case_close_enrichers",
]
