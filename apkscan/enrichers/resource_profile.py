"""Explicit, bounded passive resource profiles; never a cloud-tenant attribution.

Separate provider keys keep legacy eleven-column FOFA evidence readable and stop
old basic hits from satisfying a new profile request. All three views require
explicit selection, each costs at most one request per target, with no expansion.
"""
from __future__ import annotations

import base64
from urllib.parse import urlsplit

from apkscan.core.models import Endpoint
from apkscan.enrichers.multisource import (
    _PassiveLookupEnricher, _ServiceError, _api_endpoint, _business_error,
    _dict, _provider_origin, _TIMEOUT,
)
from apkscan.enrichers._profile import bounded_profile as _profile_value, coverage

FOFA_PROFILE_FIELDS = (
    "host,ip,port,protocol,title,server,country,region,city,asn,org,domain,os,"
    "product,product_category,header,banner,cert,lastupdatetime"
)
DAYDAYMAP_PROFILE_FIELDS = (
    "ip,port,protocol,server,title,domain,asn,asn_org,isp,icp_reg_name,country,"
    "province,city,time_stamp,banner,header,os,device_type,manufacturer,device,"
    "product,service,tags,cert,ssl"
)
PROFILE_LIMIT = 20


def _coverage(total: object, returned: int, *, observed: int) -> dict[str, object]:
    return {"page": 1, **coverage(total, returned, limit=PROFILE_LIMIT, observed=observed)}


class FofaResourceProfileEnricher(_PassiveLookupEnricher):
    name = "fofa_profile"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_FOFA_KEY",)
    requires_product_check = True

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        url = _api_endpoint("FXAPK_FOFA_URL", "https://fofa.info", "/api/v1/search/all")
        self.receipt.update(endpoint=_provider_origin(url), api_path=urlsplit(url).path,
                            requested_fields=FOFA_PROFILE_FIELDS.split(","), page=1, size=PROFILE_LIMIT)
        query = f'{endpoint.kind}="{endpoint.value}"'
        response = self._http.get(url, params={"key": credential,
            "qbase64": base64.b64encode(query.encode()).decode(), "fields": FOFA_PROFILE_FIELDS,
            "page": 1, "size": PROFILE_LIMIT}, allow_redirects=False, timeout=_TIMEOUT)
        self._check_response(response)
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        root = _dict(payload)
        rows = root.get("results")
        if not isinstance(rows, list):
            raise _ServiceError("invalid_profile_schema")
        if not rows and coverage(root.get("size"), 0)["truncated"] is True:
            raise _ServiceError("profile_results_missing")
        fields = FOFA_PROFILE_FIELDS.split(",")
        records = []
        for row in rows[:PROFILE_LIMIT]:
            if not isinstance(row, list) or len(row) != len(fields):
                raise _ServiceError("profile_field_count_mismatch")
            record = dict(zip(fields, row))
            if endpoint.kind == "ip" and record["ip"] != endpoint.value:
                raise _ServiceError("profile_target_mismatch")
            records.append(_profile_value(record))
        return {"records": records, "source_family": "fofa", "query_kind": "search_profile",
                "fields": fields, **_coverage(root.get("size"), len(records), observed=len(rows)),
                "_source_status": "hit" if records else "no_record",
                "attribution_scope": "historical_service_fingerprints_not_tenant_identity"}


class FofaHostProfileEnricher(_PassiveLookupEnricher):
    name = "fofa_host"
    applies_to = ["ip"]
    required_env = ("FXAPK_FOFA_KEY",)
    requires_product_check = True

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        # Derive only the documented sibling of /search/all, never forward a key
        # to another origin or guess a sibling of an arbitrary configured path.
        search = _api_endpoint("FXAPK_FOFA_URL", "https://fofa.info", "/api/v1/search/all")
        if not search.endswith("/api/v1/search/all"):
            raise _ServiceError("unsupported_host_api_base")
        url = search[:-len("search/all")] + "host/" + endpoint.value
        self.receipt.update(endpoint=_provider_origin(url), api_path=urlsplit(url).path)
        response = self._http.get(url, params={"key": credential}, allow_redirects=False, timeout=_TIMEOUT)
        self._check_response(response)
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        root = _dict(payload)
        if root.get("ip") != endpoint.value:
            raise _ServiceError("profile_target_mismatch")
        fields = ("host", "ip", "asn", "org", "country_name", "country_code", "protocol", "port",
                  "category", "product", "update_time")
        profile = {k: _profile_value(root[k]) for k in fields if k in root}
        return {"profile": profile, "source_family": "fofa", "query_kind": "host_aggregate",
                "_source_status": "hit", "attribution_scope": "historical_host_profile_not_tenant_identity"}


class DayDayMapResourceProfileEnricher(_PassiveLookupEnricher):
    name = "daydaymap_profile"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_DAYDAYMAP_KEY", "FXAPK_DAYDAYMAP_KEY2")
    bypass_system_proxy = True
    requires_product_check = True

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        url = "https://www.daydaymap.com/api/v1/raymap/search/all"
        self.receipt.update(endpoint=_provider_origin(url), api_path=urlsplit(url).path,
                            requested_fields=DAYDAYMAP_PROFILE_FIELDS.split(","), page=1, size=PROFILE_LIMIT)
        query = f'{endpoint.kind}="{endpoint.value}"'
        response = self._http.post(url, headers={"API-KEY": credential},
            json={"keyword": base64.b64encode(query.encode()).decode(),
                  "fields": DAYDAYMAP_PROFILE_FIELDS, "page": 1, "page_size": PROFILE_LIMIT},
            allow_redirects=False, timeout=_TIMEOUT)
        self._check_response(response)
        data = response.json()
        if _dict(data).get("code") not in (200, "200"):
            raise _business_error(data)
        return data

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        root = _dict(_dict(payload).get("data"))
        rows = root.get("list")
        if not isinstance(rows, list):
            raise _ServiceError("invalid_profile_schema")
        if not rows and coverage(root.get("total"), 0)["truncated"] is True:
            raise _ServiceError("profile_results_missing")
        records = []
        for row in rows[:PROFILE_LIMIT]:
            if not isinstance(row, dict):
                raise _ServiceError("invalid_profile_schema")
            if endpoint.kind == "ip" and row.get("ip") != endpoint.value:
                raise _ServiceError("profile_target_mismatch")
            records.append(_profile_value(row))
        return {"records": records, "source_family": "daydaymap", "query_kind": "search_profile",
                **_coverage(root.get("total"), len(records), observed=len(rows)),
                "_source_status": "hit" if records else "no_record",
                "attribution_scope": "historical_service_fingerprints_not_tenant_identity"}
