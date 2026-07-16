"""Censys passive intel adapter (LOOKUP_IP host, LOOKUP_CERT).

One GET per lookup to ``api.platform.censys.io`` with Bearer auth (the token is a
header, never a query param). IP host uses the confirmed vendor media type; the
certificate call uses generic ``application/json`` (the vendored certificate
media type is not confirmed, so we do not invent one). A certificate asset's id
is its SHA-256 fingerprint; the returned fingerprint must equal the queried one
or the response is rejected rather than mis-attributed. Host-history /
threat-hunting endpoints are never chained. 404 on either asset => EMPTY.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import quote

from apkscan.attribution.models import AttributionEvidence
from apkscan.intel.models import IntelCapability
from apkscan.intel.providers._http import (
    _MAX_RECORDS,
    CertificateMismatchError,
    MalformedPayloadError,
    _as_dict,
    _as_list,
    _bounded_text,
    _coerce_asn,
    _coerce_port,
    _emit,
    _finalize_evidence,
    _HttpIntelProvider,
    _RequestSpec,
    _read_credential,
)
from apkscan.network import NetworkEntity

_HOST_MEDIA_TYPE = "application/vnd.censys.api.v3.host.v1+json"


class CensysIntelProvider(_HttpIntelProvider):
    """Censys host lookup for an IP; certificate asset lookup for a fingerprint."""

    name = "censys"
    capabilities = frozenset({IntelCapability.LOOKUP_IP, IntelCapability.LOOKUP_CERT})
    required_env = ("FXAPK_CENSYS_TOKEN", "CENSYS_API_TOKEN")
    active = False
    _API_AUTHORITY = "api.platform.censys.io"

    def _fetch(self, capability, query):
        return self._fetch_via_http(capability, query)

    def _request_spec(
        self, capability: IntelCapability, query: NetworkEntity
    ) -> _RequestSpec:
        token = _read_credential(type(self).required_env)
        headers = {"Authorization": f"Bearer {token}"}
        organization = (os.environ.get("FXAPK_CENSYS_ORG_ID") or "").strip()
        if organization:
            headers["X-Organization-ID"] = organization
        if capability is IntelCapability.LOOKUP_IP:
            headers["Accept"] = _HOST_MEDIA_TYPE
            return _RequestSpec(
                path=f"/v3/global/asset/host/{quote(query.value, safe='')}",
                headers=headers,
                empty_on_404=True,
            )
        # LOOKUP_CERT: strip the 'sha256:' prefix off the canonical value.
        headers["Accept"] = "application/json"
        fingerprint = query.value.split(":", 1)[1]
        return _RequestSpec(
            path=f"/v3/global/asset/certificate/{quote(fingerprint, safe='')}",
            headers=headers,
            empty_on_404=True,
        )

    def _interpret(
        self, capability: IntelCapability, query: NetworkEntity, payload: dict[str, Any]
    ) -> tuple[AttributionEvidence, ...]:
        record = _unwrap(payload)
        if capability is IntelCapability.LOOKUP_IP:
            return self._interpret_host(capability, query, record)
        return self._interpret_cert(capability, query, record)

    def _interpret_host(
        self, capability: IntelCapability, query: NetworkEntity, record: dict[str, Any]
    ) -> tuple[AttributionEvidence, ...]:
        provider = type(self).name
        records: list[AttributionEvidence] = []
        autonomous_system = record.get("autonomous_system")
        if isinstance(autonomous_system, dict):
            for evidence_type, value in (
                ("asn", _coerce_asn(autonomous_system.get("asn"))),
                (
                    "as_org",
                    _bounded_text(
                        autonomous_system.get("name")
                        or autonomous_system.get("organization")
                    ),
                ),
                ("bgp_prefix", _bounded_text(autonomous_system.get("bgp_prefix"))),
            ):
                _emit(
                    records,
                    provider=provider,
                    capability=capability,
                    target=query,
                    evidence_type=evidence_type,
                    value=value,
                )
        location = record.get("location")
        if isinstance(location, dict):
            for evidence_type, value in (
                ("geo_country", _bounded_text(location.get("country_code") or location.get("country"))),
                ("geo_region", _bounded_text(location.get("region") or location.get("province"))),
                ("geo_city", _bounded_text(location.get("city"))),
            ):
                _emit(
                    records,
                    provider=provider,
                    capability=capability,
                    target=query,
                    evidence_type=evidence_type,
                    value=value,
                )
        services = record.get("services")
        if isinstance(services, list):
            for service in services[:_MAX_RECORDS]:
                if not isinstance(service, dict):
                    continue
                for evidence_type, value in (
                    ("open_port", _coerce_port(service.get("port"))),
                    ("service_product", _bounded_text(service.get("product"))),
                    ("service_version", _bounded_text(service.get("version"))),
                    ("service_server", _bounded_text(service.get("server"))),
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

    def _interpret_cert(
        self, capability: IntelCapability, query: NetworkEntity, record: dict[str, Any]
    ) -> tuple[AttributionEvidence, ...]:
        provider = type(self).name
        queried = query.value.split(":", 1)[1].lower()
        fingerprint = record.get("fingerprint_sha256")
        # A cert asset with no self-identifying fingerprint cannot be trusted to
        # describe the queried certificate; reject rather than mis-attribute the
        # subject/issuer/SANs. A present-but-different fingerprint is a mismatch.
        if not (isinstance(fingerprint, str) and fingerprint.strip()):
            raise MalformedPayloadError
        if fingerprint.strip().lower() != queried:
            raise CertificateMismatchError
        records: list[AttributionEvidence] = []
        _emit(
            records,
            provider=provider,
            capability=capability,
            target=query,
            evidence_type="cert_fingerprint_sha256",
            value=queried,  # canonical lowercase hex (== the verified fingerprint)
        )
        parsed = _as_dict(record.get("parsed"))
        subject = _as_dict(parsed.get("subject"))
        issuer = _as_dict(parsed.get("issuer"))
        validity = _as_dict(parsed.get("validity_period"))
        scalar_fields = (
            ("cert_subject_dn", _bounded_text(parsed.get("subject_dn"))),
            ("cert_issuer_dn", _bounded_text(parsed.get("issuer_dn"))),
            ("cert_not_before", _bounded_text(validity.get("not_before"))),
            ("cert_not_after", _bounded_text(validity.get("not_after"))),
        )
        for evidence_type, value in scalar_fields:
            _emit(
                records,
                provider=provider,
                capability=capability,
                target=query,
                evidence_type=evidence_type,
                value=value,
            )
        list_fields = (
            ("cert_subject_cn", _as_list(subject.get("common_name"))),
            ("cert_issuer_cn", _as_list(issuer.get("common_name"))),
            ("cert_issuer_org", _as_list(issuer.get("organization"))),
            ("cert_san_dns", _cert_san_dns(record, parsed)),
        )
        for evidence_type, values in list_fields:
            for value in values[:_MAX_RECORDS]:
                _emit(
                    records,
                    provider=provider,
                    capability=capability,
                    target=query,
                    evidence_type=evidence_type,
                    value=_bounded_text(value),
                )
        return _finalize_evidence(records)


def _unwrap(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the single-asset record, tolerating {"result": …} / {"data": …}
    wrappers or an already-unwrapped body — one response, one request."""
    for key in ("result", "data"):
        value = payload.get(key)
        if isinstance(value, dict):
            return value
    return payload


def _cert_san_dns(record: dict[str, Any], parsed: dict[str, Any]) -> list[Any]:
    """Union of ``names[]`` and ``parsed.extensions.subject_alt_name.dns_names[]``
    (dedup happens downstream by stable id)."""
    names = list(_as_list(record.get("names")))
    extensions = _as_dict(parsed.get("extensions"))
    subject_alt = _as_dict(extensions.get("subject_alt_name"))
    names.extend(_as_list(subject_alt.get("dns_names")))
    return names
