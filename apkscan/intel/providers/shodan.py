"""Shodan passive intel adapter (LOOKUP_IP host, LOOKUP_DOMAIN resolve-only).

IP lookup is one GET to ``api.shodan.io/shodan/host/{ip}`` (404 => EMPTY). Domain
lookup is **DNS resolve only** — one GET to ``/dns/resolve`` emitting a single
``resolved_ip`` evidence — and never chains a host lookup: the shared transport
gives the interpret hook no session, so a second request is structurally
impossible. Only passive OSINT (Shodan's own scan library); zero traffic to the
target. Threat labels (``tags``) and page titles are excluded.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from apkscan.attribution.models import AttributionEvidence
from apkscan.intel.models import IntelCapability
from apkscan.intel.providers._http import (
    _MAX_RECORDS,
    MalformedPayloadError,
    _as_dict,
    _bounded_text,
    _coerce_asn,
    _coerce_ip,
    _coerce_port,
    _emit,
    _finalize_evidence,
    _HttpIntelProvider,
    _RequestSpec,
    _read_credential,
    _stable_evidence,
)
from apkscan.network import NetworkEntity


class ShodanIntelProvider(_HttpIntelProvider):
    """Shodan host lookup for an IP; DNS resolve only for a domain."""

    name = "shodan"
    capabilities = frozenset({IntelCapability.LOOKUP_IP, IntelCapability.LOOKUP_DOMAIN})
    required_env = ("FXAPK_SHODAN_KEY", "SHODAN_API_KEY")
    active = False
    _API_AUTHORITY = "api.shodan.io"

    def _fetch(self, capability, query):
        return self._fetch_via_http(capability, query)

    def _request_spec(
        self, capability: IntelCapability, query: NetworkEntity
    ) -> _RequestSpec:
        key = _read_credential(type(self).required_env)
        if capability is IntelCapability.LOOKUP_IP:
            return _RequestSpec(
                path=f"/shodan/host/{quote(query.value, safe='')}",
                params={"key": key},
                empty_on_404=True,
            )
        # LOOKUP_DOMAIN: resolve only, no chained host lookup.
        return _RequestSpec(
            path="/dns/resolve",
            params={"hostnames": query.value, "key": key},
        )

    def _interpret(
        self, capability: IntelCapability, query: NetworkEntity, payload: dict[str, Any]
    ) -> tuple[AttributionEvidence, ...]:
        if capability is IntelCapability.LOOKUP_DOMAIN:
            return self._interpret_resolve(capability, query, payload)
        return self._interpret_host(capability, query, payload)

    @staticmethod
    def _interpret_resolve(
        capability: IntelCapability, query: NetworkEntity, payload: dict[str, Any]
    ) -> tuple[AttributionEvidence, ...]:
        raw = payload.get(query.value)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return ()
        ip = _coerce_ip(raw)
        if ip is None:
            raise MalformedPayloadError
        return (
            _stable_evidence(
                provider="shodan",
                capability=capability,
                evidence_type="resolved_ip",
                target=query,
                value=ip,
            ),
        )

    def _interpret_host(
        self, capability: IntelCapability, query: NetworkEntity, payload: dict[str, Any]
    ) -> tuple[AttributionEvidence, ...]:
        provider = type(self).name
        records: list[AttributionEvidence] = []
        for port in _bounded_list(payload.get("ports")):
            _emit(
                records,
                provider=provider,
                capability=capability,
                target=query,
                evidence_type="open_port",
                value=_coerce_port(port),
            )
        for hostname in _bounded_list(payload.get("hostnames")):
            _emit(
                records,
                provider=provider,
                capability=capability,
                target=query,
                evidence_type="related_hostname",
                value=_bounded_text(hostname),
            )
        services = payload.get("data")
        if isinstance(services, list):
            for service in services[:_MAX_RECORDS]:
                if not isinstance(service, dict):
                    continue
                http = _as_dict(service.get("http"))
                for evidence_type, value in (
                    ("service_product", _bounded_text(service.get("product"))),
                    ("service_version", _bounded_text(service.get("version"))),
                    ("service_server", _bounded_text(http.get("server"))),
                ):
                    _emit(
                        records,
                        provider=provider,
                        capability=capability,
                        target=query,
                        evidence_type=evidence_type,
                        value=value,
                    )
        for evidence_type, value in (
            ("hosting_org", _bounded_text(payload.get("org"))),
            ("isp", _bounded_text(payload.get("isp"))),
            ("asn", _coerce_asn(payload.get("asn"))),
            (
                "geo_country",
                _bounded_text(payload.get("country_name") or payload.get("country_code")),
            ),
        ):
            _emit(
                records,
                provider=provider,
                capability=capability,
                target=query,
                evidence_type=evidence_type,
                value=value,
            )
        return _finalize_evidence(records)


def _bounded_list(value: object) -> list[Any]:
    """The first ``_MAX_RECORDS`` items if ``value`` is a list, else []."""
    return value[:_MAX_RECORDS] if isinstance(value, list) else []
