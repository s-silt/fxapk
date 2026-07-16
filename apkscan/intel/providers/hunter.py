"""Hunter (奇安信鹰图) passive intel adapter (LOOKUP_IP, LOOKUP_DOMAIN).

One GET to the fixed authority ``hunter.qianxin.com`` per lookup; the canonical
entity is encoded into the urlsafe-base64 ``search`` filter. Hunter embeds an
HTTP-style ``code`` in the 200 JSON body — ``code == 200`` means OK; any other
code (auth / rate-limit) is a declared error.

Hunter's ICP registrant ``company`` / 备案号 is **resource-holder / ownership
evidence** about the queried infrastructure, never a service or app operator.
"""

from __future__ import annotations

import base64
from typing import Any

from apkscan.attribution.models import AttributionEvidence
from apkscan.intel.models import IntelCapability
from apkscan.intel.providers._http import (
    _MAX_RECORDS,
    MalformedPayloadError,
    ProviderDeclaredError,
    _bounded_text,
    _coerce_asn,
    _coerce_ip,
    _coerce_port,
    _emit,
    _finalize_evidence,
    _HttpIntelProvider,
    _related_hostname,
    _RequestSpec,
    _read_credential,
)
from apkscan.network import NetworkEntity

_OK_CODES = (200, "200")


def _component_name(row: dict[str, Any]) -> str | None:
    """The first usable product name from Hunter's 'component' field.

    Hunter returns 'component' as a list of {name, version} dicts (a truthy list
    that _bounded_text would drop), so extract the first name; fall back to a
    scalar 'component'/'product' string.
    """
    component = row.get("component")
    if isinstance(component, list):
        for item in component:
            if isinstance(item, dict):
                name = _bounded_text(item.get("name"))
                if name:
                    return name
        return _bounded_text(row.get("product"))
    return _bounded_text(component) or _bounded_text(row.get("product"))


class HunterIntelProvider(_HttpIntelProvider):
    """Hunter network-space asset lookup for an IP or domain."""

    name = "hunter"
    capabilities = frozenset({IntelCapability.LOOKUP_IP, IntelCapability.LOOKUP_DOMAIN})
    required_env = ("FXAPK_HUNTER_KEY",)
    active = False
    _API_AUTHORITY = "hunter.qianxin.com"

    def _fetch(self, capability, query):
        return self._fetch_via_http(capability, query)

    def _request_spec(
        self, capability: IntelCapability, query: NetworkEntity
    ) -> _RequestSpec:
        key = _read_credential(type(self).required_env)
        field = "ip" if capability is IntelCapability.LOOKUP_IP else "domain"
        expression = f'{field}="{query.value}"'
        search = base64.urlsafe_b64encode(expression.encode("utf-8")).decode("ascii")
        return _RequestSpec(
            path="/openApi/search",
            params={
                "api-key": key,
                "search": search,
                "page": "1",
                "page_size": str(_MAX_RECORDS),
                "is_web": "3",
            },
        )

    def _interpret(
        self, capability: IntelCapability, query: NetworkEntity, payload: dict[str, Any]
    ) -> tuple[AttributionEvidence, ...]:
        if payload.get("code") not in _OK_CODES:
            raise ProviderDeclaredError
        data = payload.get("data")
        if data is None:
            return ()
        if not isinstance(data, dict):
            raise MalformedPayloadError
        rows = data.get("arr")
        if rows is None:
            rows = data.get("list")
        if rows is None:
            return ()
        if not isinstance(rows, list):
            raise MalformedPayloadError
        provider = type(self).name
        records: list[AttributionEvidence] = []
        seen_row = False
        for row in rows[:_MAX_RECORDS]:
            if not isinstance(row, dict):
                continue
            seen_row = True
            if capability is IntelCapability.LOOKUP_IP:
                self._emit_ip(records, provider, capability, query, row)
            else:
                self._emit_domain(records, provider, capability, query, row)
        if rows and not seen_row:
            # a non-empty rows list whose entries are all the wrong shape is a
            # malformed envelope, not a provider-confirmed absence of records.
            raise MalformedPayloadError
        return _finalize_evidence(records)

    @staticmethod
    def _emit_ip(
        records: list[AttributionEvidence],
        provider: str,
        capability: IntelCapability,
        target: NetworkEntity,
        row: dict[str, Any],
    ) -> None:
        for evidence_type, value in (
            ("asn", _coerce_asn(row.get("as_number") or row.get("asn"))),
            ("as_org", _bounded_text(row.get("as_org") or row.get("as_organization"))),
            ("isp", _bounded_text(row.get("isp"))),
            ("company", _bounded_text(row.get("company"))),
            ("icp", _bounded_text(row.get("number") or row.get("icp"))),
            ("geo_country", _bounded_text(row.get("country"))),
            ("geo_region", _bounded_text(row.get("province") or row.get("region"))),
            ("geo_city", _bounded_text(row.get("city"))),
            ("open_port", _coerce_port(row.get("port"))),
            ("service_server", _bounded_text(row.get("server"))),
            ("service_product", _component_name(row)),
        ):
            _emit(
                records,
                provider=provider,
                capability=capability,
                target=target,
                evidence_type=evidence_type,
                value=value,
            )

    @staticmethod
    def _emit_domain(
        records: list[AttributionEvidence],
        provider: str,
        capability: IntelCapability,
        target: NetworkEntity,
        row: dict[str, Any],
    ) -> None:
        for evidence_type, value in (
            ("related_ip", _coerce_ip(row.get("ip"))),
            ("related_hostname", _related_hostname(row.get("domain") or row.get("host"), target)),
        ):
            _emit(
                records,
                provider=provider,
                capability=capability,
                target=target,
                evidence_type=evidence_type,
                value=value,
            )
