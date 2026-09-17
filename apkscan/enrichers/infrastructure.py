"""Bounded no-key DNS/ASN/service views and explicitly selected paid products.

No discovered address or SAN is submitted to another provider automatically.
DNS service responses describe observation views, never prove the origin server.
"""
from __future__ import annotations

import base64
import ipaddress
from datetime import datetime, timezone
from typing import Any

from apkscan.core.models import Endpoint
from apkscan.enrichers.multisource import (
    _PassiveLookupEnricher, _ServiceError, _business_error, _asset_result,
    _dict, _TIMEOUT, _provider_origin, _reject_redirect,
)

_RESOLVERS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


def _public_ip(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast:
        raise ValueError("non_public_ip")
    return str(address)


def _dns_view(session: Any, resolver: str, name: str, qtype: str) -> dict[str, Any]:
    view: dict[str, Any] = {"resolver": resolver, "name": name, "type": qtype,
                            "queried_at": datetime.now(timezone.utc).isoformat()}
    try:
        response = session.get(resolver, params={"name": name, "type": qtype},
                               headers={"Accept": "application/dns-json"}, allow_redirects=False, timeout=_TIMEOUT)
        _reject_redirect(response)
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("Status"), int):
            raise ValueError("invalid_dns_response")
        code = body["Status"]
        answers = body.get("Answer") or []
        if not isinstance(answers, list) or (code != 0 and answers):
            raise ValueError("invalid_dns_answer")
        view["rcode"] = code
        view["status"] = {0: "no_record", 3: "nxdomain"}.get(code, "failed")
        records = []
        rejected = []
        for item in answers[:100]:
            if not isinstance(item, dict):
                continue
            data = str(item.get("data", ""))[:500]
            if item.get("type") in (1, 28):
                try:
                    data = _public_ip(data)
                except ValueError:
                    rejected.append({"value": data, "reason": "non_public_or_proxy_address"})
                    continue
            records.append({"name": str(item.get("name", ""))[:253], "type": item.get("type"),
                            "ttl": item.get("TTL"), "data": data})
        view["records"] = records
        if records and code == 0:
            view["status"] = "hit"
        if rejected:
            view["rejected"] = rejected
            if not records:
                view["status"] = "failed"
        view["truncated"] = len(body.get("Answer") or []) > 100
    except Exception as exc:  # provider free text may contain URLs; keep type only
        view.update(status="failed", error_type=type(exc).__name__)
        if isinstance(exc, _ServiceError):
            view.update(error_type=exc.category, reason=exc.category)
    return view


class DnsRecordsEnricher(_PassiveLookupEnricher):
    name = "dns_records"
    applies_to = ["domain"]
    request_budget = 8

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        return [_dns_view(self._http, resolver, endpoint.value, kind)
                for resolver in _RESOLVERS for kind in ("A", "AAAA", "CNAME", "NS")]

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        views = payload if isinstance(payload, list) else []
        self.receipt["dns_views"] = views
        successful = [v for v in views if v["status"] in {"hit", "no_record", "nxdomain"}]
        has_records = any(v.get("records") for v in successful)
        conflicts = []
        for kind in ("A", "AAAA", "CNAME", "NS"):
            compared = [v for v in successful if v["type"] == kind]
            if len(compared) == 2:
                a, b = compared
                def values(v):
                    return sorted((str(x["type"]), x["data"].lower().rstrip(".")) for x in v["records"])
                if a["rcode"] != b["rcode"] or values(a) != values(b):
                    conflicts.append(kind)
        coverage_complete = len(successful) == 8 and not any(v.get("truncated") or v.get("rejected") for v in views)
        status = "hit" if has_records else "no_record" if coverage_complete else "failed"
        return {"views": views, "query_scope": endpoint.value, "successful_views": len(successful),
                "conflicts": conflicts, "coverage_complete": coverage_complete,
                "gaps": [] if coverage_complete else ["dns_views_incomplete"],
                "ns_scope": "exact_name_only; empty does not establish absence of parent delegation",
                "origin_status": "not_determined", "_source_status": status,
                **({"_error_type": "dns_views_incomplete"} if status == "failed" else {})}


class CymruEnricher(_PassiveLookupEnricher):
    name = "cymru"
    applies_to = ["ip"]
    request_budget = 1

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        ip = ipaddress.ip_address(_public_ip(endpoint.value))
        if ip.version == 4:
            name = ".".join(reversed(str(ip).split("."))) + ".origin.asn.cymru.com"
        else:
            name = ".".join(reversed(ip.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
        self.receipt["endpoint"] = _provider_origin(_RESOLVERS[0])
        return _dns_view(self._http, _RESOLVERS[0], name, "TXT")

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        view = _dict(payload)
        self.receipt["dns_view"] = view
        if view.get("status") == "failed":
            if view.get("reason") == "redirect_not_followed":
                raise _ServiceError("redirect_not_followed")
            raise ValueError("cymru_dns_failed")
        rows = []
        for record in view.get("records", []):
            if record.get("type") != 16:
                continue
            fields = record["data"].replace('"', '').split("|")
            if len(fields) < 5:
                continue
            asns = [int(n) for n in fields[0].split() if n.isdigit() and 0 < int(n) < 4294967295]
            network = ipaddress.ip_network(fields[1].strip(), strict=False)
            if ipaddress.ip_address(endpoint.value) not in network:
                raise _ServiceError("cymru_prefix_mismatch")
            if asns:
                rows.append({"origin_asns": asns, "prefix": fields[1].strip(), "registration_country": fields[2].strip(),
                             "registry": fields[3].strip(), "allocation_date": fields[4].strip()})
        return {"records": rows, "source": "team_cymru", "country_semantics": "registry_not_geolocation"} if rows else {}


class InternetDbEnricher(_PassiveLookupEnricher):
    name = "internetdb"
    applies_to = ["ip"]

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        url = "https://internetdb.shodan.io/" + _public_ip(endpoint.value)
        self.receipt["endpoint"] = _provider_origin(url)
        response = self._http.get(url, allow_redirects=False, timeout=_TIMEOUT)
        self._check_response(response)
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        data = _dict(payload)
        if data.get("ip") != endpoint.value:
            raise ValueError("internetdb_ip_mismatch")
        output = {k: data[k][:100] for k in ("ports", "hostnames", "cpes", "tags", "vulns") if isinstance(data.get(k), list)}
        return {**output, "ip": endpoint.value, "source": "shodan_internetdb", "source_family": "shodan", "live_scan": False}


class DayDayMapEnricher(_PassiveLookupEnricher):
    name = "daydaymap"
    bypass_system_proxy = True
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_DAYDAYMAP_KEY", "FXAPK_DAYDAYMAP_KEY2")
    _URL = "https://www.daydaymap.com/api/v1/raymap/search/all"

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        query = f'{endpoint.kind}="{endpoint.value}"'
        response = self._http.post(self._URL, headers={"API-KEY": credential}, allow_redirects=False, timeout=_TIMEOUT,
                                   json={"keyword": base64.b64encode(query.encode()).decode("ascii"),
                                         "fields": "ip,port,protocol,server,title,domain,asn,asn_org,isp,icp_reg_name,country,province,city,time_stamp", "page": 1, "page_size": 20})
        self.receipt["endpoint"] = _provider_origin(self._URL)
        self._check_response(response)
        data = response.json()
        if _dict(data).get("code") not in (200, "200"):
            raise _business_error(data)
        return data

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        data = _dict(_dict(payload).get("data"))
        items = data.get("list")
        if not isinstance(items, list):
            raise ValueError("invalid_daydaymap_list")
        result = _asset_result(items, source=self.name, total=data.get("total"))
        if result:
            result["attribution_scope"] = "cohosted_sites_not_ip_owner" if endpoint.kind == "ip" else "queried_domain"
        return result


class ThreatBookEnricher(_PassiveLookupEnricher):
    name = "threatbook"
    applies_to = ["ip"]
    required_env = ("FXAPK_THREATBOOK_KEY",)
    requires_product_check = True

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        url = "https://api.threatbook.cn/v3/scene/ip_reputation"
        self.receipt["endpoint"] = _provider_origin(url)
        response = self._http.get(url, params={"apikey": credential, "resource": endpoint.value}, allow_redirects=False, timeout=_TIMEOUT)
        self._check_response(response)
        data = response.json()
        code = _dict(data).get("response_code")
        if code != 0:
            raise _ServiceError("quota_insufficient" if code == -4 else "permission_denied" if code == -1 else "provider_response_error", code)
        return data

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        data = _dict(_dict(_dict(payload).get("data")).get(endpoint.value))
        return {k: data[k] for k in ("is_malicious", "severity", "confidence_level", "scene", "judgments", "basic", "asn", "update_time") if k in data}


class WhoisXmlEnricher(_PassiveLookupEnricher):
    name = "whoisxml"
    applies_to = ["ip", "domain"]
    required_env = ("FXAPK_WHOISXML_KEY",)
    requires_product_check = True

    def _lookup(self, endpoint: Endpoint, credential: str) -> object:
        url = "https://dns-history.whoisxmlapi.com/api/v1"
        self.receipt["endpoint"] = _provider_origin(url)
        response = self._http.post(url, json={"apiKey": credential, "searchType": "reverse" if endpoint.kind == "ip" else "forward",
                                   "recordType": "a", "limit": 20, "outputFormat": "JSON",
                                   "ipAddress" if endpoint.kind == "ip" else "domainName": endpoint.value}, allow_redirects=False, timeout=_TIMEOUT)
        self._check_response(response)
        return response.json()

    def _normalize(self, payload: object, endpoint: Endpoint) -> dict[str, object]:
        data = _dict(payload)
        if not isinstance(data.get("result"), dict):
            raise _business_error(data)
        rows = data["result"].get("records")
        if not isinstance(rows, list):
            raise ValueError("invalid_whoisxml_records")
        return {"records": rows[:20], "source": "whoisxml_dns_chronicle", "coverage": "bounded_first_page"} if rows else {}
