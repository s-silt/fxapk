"""FOFA passive intel adapter (LOOKUP_IP, LOOKUP_DOMAIN).

One GET to the fixed authority ``fofa.info`` per lookup; the canonical entity is
encoded into the base64 ``qbase64`` query filter, never into the URL authority.
FOFA has **no** confirmed SHA-256 certificate-fingerprint query field
(``cert="..."`` matches certificate content, not the fingerprint), so this
adapter does not declare ``LOOKUP_CERT`` — Censys owns certificate lookups.

Resource/hosting/ownership evidence only: ASN / org / geo / port / server /
related host. Page titles and other content fields are excluded.
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

#: Response columns, in order, aligned to the ``fields`` request param. Page
#: title is deliberately absent (content, not infrastructure).
_FIELDS: tuple[str, ...] = (
    "host",
    "ip",
    "port",
    "protocol",
    "server",
    "country",
    "region",
    "city",
    "as_number",
    "as_organization",
)
_FIELDS_PARAM = ",".join(_FIELDS)


class FofaIntelProvider(_HttpIntelProvider):
    """FOFA network-space asset lookup for an IP or domain."""

    name = "fofa"
    capabilities = frozenset({IntelCapability.LOOKUP_IP, IntelCapability.LOOKUP_DOMAIN})
    required_env = ("FXAPK_FOFA_KEY",)
    active = False
    _API_AUTHORITY = "fofa.info"

    def _fetch(self, capability, query):
        return self._fetch_via_http(capability, query)

    def _request_spec(
        self, capability: IntelCapability, query: NetworkEntity
    ) -> _RequestSpec:
        key = _read_credential(type(self).required_env)
        field = "ip" if capability is IntelCapability.LOOKUP_IP else "domain"
        expression = f'{field}="{query.value}"'
        qbase64 = base64.b64encode(expression.encode("utf-8")).decode("ascii")
        return _RequestSpec(
            path="/api/v1/search/all",
            params={
                "key": key,
                "qbase64": qbase64,
                "fields": _FIELDS_PARAM,
                "size": str(_MAX_RECORDS),
            },
        )

    def _interpret(
        self, capability: IntelCapability, query: NetworkEntity, payload: dict[str, Any]
    ) -> tuple[AttributionEvidence, ...]:
        if payload.get("error"):
            raise ProviderDeclaredError
        results = payload.get("results")
        if results is None:
            return ()
        if not isinstance(results, list):
            raise MalformedPayloadError
        provider = type(self).name
        records: list[AttributionEvidence] = []
        seen_row = False
        for row in results[:_MAX_RECORDS]:
            if not isinstance(row, list):
                continue
            seen_row = True
            cells = dict(zip(_FIELDS, row))
            if capability is IntelCapability.LOOKUP_IP:
                self._emit_ip(records, provider, capability, query, cells)
            else:
                self._emit_domain(records, provider, capability, query, cells)
        if results and not seen_row:
            # data-bearing but every row is the wrong shape -> malformed, not
            # a provider-confirmed "no records" (which is results == []).
            raise MalformedPayloadError
        return _finalize_evidence(records)

    @staticmethod
    def _emit_ip(
        records: list[AttributionEvidence],
        provider: str,
        capability: IntelCapability,
        target: NetworkEntity,
        cells: dict[str, Any],
    ) -> None:
        for evidence_type, value in (
            ("open_port", _coerce_port(cells.get("port"))),
            ("service_server", _bounded_text(cells.get("server"))),
            ("geo_country", _bounded_text(cells.get("country"))),
            ("geo_region", _bounded_text(cells.get("region"))),
            ("geo_city", _bounded_text(cells.get("city"))),
            ("asn", _coerce_asn(cells.get("as_number"))),
            ("as_org", _bounded_text(cells.get("as_organization"))),
            ("related_hostname", _related_hostname(cells.get("host"), target)),
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
        cells: dict[str, Any],
    ) -> None:
        # Domain-scoped facts only: never attach an IP's ASN/geo to a domain.
        for evidence_type, value in (
            ("related_ip", _coerce_ip(cells.get("ip"))),
            ("related_hostname", _related_hostname(cells.get("host"), target)),
        ):
            _emit(
                records,
                provider=provider,
                capability=capability,
                target=target,
                evidence_type=evidence_type,
                value=value,
            )
