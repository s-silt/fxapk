"""Passive, bounded, case-close-only infrastructure intelligence adapters."""

from __future__ import annotations

import base64
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping

import requests

from apkscan.core.closure import SOURCE_STATUSES
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher

_TIMEOUT = 12
_MAX_RECORDS = 20


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

    def __init__(self, session: Any | None = None) -> None:
        self._http = session if session is not None else requests.Session()

    @abstractmethod
    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        ...

    @abstractmethod
    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        ...

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        credential = _credential(self.required_env)
        if self.required_env and not credential:
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                data={"_source_status": "disabled"},
                error="disabled",
            )
        try:
            payload = self._lookup(ep, credential)
            data = self._normalize(payload, ep)
        except Exception as exc:  # noqa: BLE001 - provider failures never stop case closure
            error_type = type(exc).__name__
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                data={"_source_status": "failed", "_error_type": error_type},
                error=error_type,
            )
        has_values = any(value not in (None, "", [], {}) for value in data.values())
        data["_source_status"] = "hit" if has_values else "no_record"
        return EnrichmentResult(provider=self.name, ok=True, data=data)


class RipeStatBgpEnricher(_PassiveLookupEnricher):
    name = "ripestat_bgp"
    applies_to = ["ip"]
    _URL = "https://stat.ripe.net/data/prefix-overview/data.json"

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        del credential
        response = self._http.get(
            self._URL,
            params={"resource": endpoint.value, "sourceapp": "fxapk-case-close"},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        data = _dict(_dict(payload).get("data"))
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
        return {
            key: value
            for key, value in {
                "origin_asn": origin_asn,
                "asn_holder": holder,
                "prefix": data.get("resource"),
                "announced": data.get("announced"),
                "upstreams": [],
                "source": "ripestat-prefix-overview",
            }.items()
            if value not in (None, "", [])
        }


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
        normalized = [list(row[:11]) for row in rows if isinstance(row, list)][: _MAX_RECORDS] if isinstance(rows, list) else []
        return {"records": normalized, "count": len(normalized), "source": "fofa"} if normalized else {}


class QuakePassiveEnricher(_PassiveLookupEnricher):
    name = "quake"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_QUAKE_KEY",)

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
        records = _list_of_dicts(_dict(payload).get("data"))
        return {"records": records, "count": len(records), "source": "quake"} if records else {}


class HunterPassiveEnricher(_PassiveLookupEnricher):
    name = "hunter"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_HUNTER_KEY",)
    _URL = "https://hunter.qianxin.com/openApi/search"

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
        records = _list_of_dicts(data.get("arr") or data.get("list"))
        return {"records": records, "count": len(records), "source": "hunter"} if records else {}


class ZoomEyePassiveEnricher(_PassiveLookupEnricher):
    name = "zoomeye"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_ZOOMEYE_KEY", "ZOOMEYE_API_KEY")
    _URL = "https://api.zoomeye.org/host/search"

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        query = f'ip:"{endpoint.value}"' if endpoint.kind == "ip" else f'hostname:"{endpoint.value}"'
        response = self._http.get(
            self._URL,
            params={"query": query, "page": 1},
            headers={"API-KEY": credential},
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        del endpoint
        records = _list_of_dicts(_dict(payload).get("matches"))
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
        services = _list_of_dicts(result.get("services"))
        if not result:
            return {}
        return {
            "ip": result.get("ip") or result.get("ip_address"),
            "location": result.get("location"),
            "autonomous_system": result.get("autonomous_system"),
            "services": services,
            "source": "censys",
        }


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
        normalized: dict[str, object] = {
            key: attributes.get(key)
            for key in (
                "asn",
                "as_owner",
                "country",
                "network",
                "last_dns_records",
                "last_analysis_stats",
                "reputation",
                "tags",
            )
            if attributes.get(key) not in (None, "", [], {})
        }
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
        pulses = _list_of_dicts(pulse_info.get("pulses"))
        if not root:
            return {}
        return {
            "reputation": root.get("reputation"),
            "country_code": root.get("country_code"),
            "asn": root.get("asn"),
            "pulses": pulses,
            "pulse_count": pulse_info.get("count", len(pulses)),
            "source": "otx",
        }


class UrlscanPassiveEnricher(_PassiveLookupEnricher):
    name = "urlscan"
    applies_to = ["ip", "domain"]
    _URL = "https://urlscan.io/api/v1/search/"

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        query = f"ip:{endpoint.value}" if endpoint.kind == "ip" else f"domain:{endpoint.value}"
        headers = {"api-key": credential} if credential else {}
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
            compact.append(
                {
                    "domain": page.get("domain"),
                    "ip": page.get("ip"),
                    "asn": page.get("asn"),
                    "asnname": page.get("asnname"),
                    "country": page.get("country"),
                    "url": task.get("url"),
                    "scan_id": task.get("uuid"),
                }
            )
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
