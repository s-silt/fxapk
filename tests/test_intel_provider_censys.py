"""Censys-specific adapter behavior: Bearer auth, result/data envelope, cert
fingerprint path + corroboration, and 404=>EMPTY without chaining."""

from __future__ import annotations

import json

import pytest

from apkscan.intel import IntelCapability, IntelStatus
from apkscan.intel.providers.censys import CensysIntelProvider
from apkscan.network import NetworkEntity, NetworkEntityType
from tests.intel_provider_fakes import (  # noqa: F401 - scrub_intel_env is autouse
    FakeResponse,
    FakeSession,
    json_response,
    scrub_intel_env,
    set_credential,
)

_IP = NetworkEntity(NetworkEntityType.IP, "1.2.3.4", ("pcap",))
_HEX = "a" * 64
_CERT = NetworkEntity(NetworkEntityType.CERTIFICATE, "sha256:" + _HEX, ("pcap",))
_DOMAIN = NetworkEntity(NetworkEntityType.DOMAIN, "example.com")

_HOST_INNER = {
    "autonomous_system": {"asn": 4837, "name": "China Telecom", "bgp_prefix": "1.2.0.0/16"},
    "location": {"country_code": "CN", "region": "Shanghai", "city": "Shanghai"},
    "services": [{"port": 443, "product": "nginx", "version": "1.18", "server": "nginx"}],
}
_CERT_INNER = {
    "fingerprint_sha256": _HEX,
    "parsed": {
        "subject_dn": "CN=x.example.com",
        "subject": {"common_name": ["x.example.com"]},
        "issuer_dn": "CN=Root CA",
        "issuer": {"common_name": ["Root CA"], "organization": ["CA Org"]},
        "validity_period": {"not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"},
        "extensions": {"subject_alt_name": {"dns_names": ["x.example.com", "z.example.com"]}},
    },
    "names": ["x.example.com", "y.example.com"],
}


def test_host_uses_bearer_header_no_query_string(monkeypatch) -> None:
    set_credential(monkeypatch, CensysIntelProvider, "tok-123")
    session = FakeSession(json_response({"result": _HOST_INNER}))
    CensysIntelProvider(session=session).lookup_ip(_IP)
    call = session.calls[0]
    assert call["headers"]["Authorization"] == "Bearer tok-123"
    assert call["headers"]["Accept"] == "application/vnd.censys.api.v3.host.v1+json"
    assert call["params"] == {}
    assert "?" not in call["url"]


@pytest.mark.parametrize("envelope", ["result", "data"])
def test_host_envelope_equivalence(monkeypatch, envelope) -> None:
    set_credential(monkeypatch, CensysIntelProvider)
    session = FakeSession(json_response({envelope: _HOST_INNER}))
    result = CensysIntelProvider(session=session).lookup_ip(_IP)
    got = {(e.type, e.value) for e in result.evidence}
    assert ("asn", 4837) in got
    assert ("as_org", "China Telecom") in got
    assert ("bgp_prefix", "1.2.0.0/16") in got
    assert ("geo_country", "CN") in got
    assert ("open_port", 443) in got


def test_host_result_and_data_produce_identical_evidence(monkeypatch) -> None:
    set_credential(monkeypatch, CensysIntelProvider)
    r1 = CensysIntelProvider(session=FakeSession(json_response({"result": _HOST_INNER}))).lookup_ip(_IP)
    r2 = CensysIntelProvider(session=FakeSession(json_response({"data": _HOST_INNER}))).lookup_ip(_IP)
    assert json.dumps(r1.to_dict(), sort_keys=True) == json.dumps(r2.to_dict(), sort_keys=True)


def test_host_404_is_empty(monkeypatch) -> None:
    set_credential(monkeypatch, CensysIntelProvider)
    resp = FakeResponse(status_code=404, body=b"{}")
    result = CensysIntelProvider(session=FakeSession(resp)).lookup_ip(_IP)
    assert result.status is IntelStatus.EMPTY
    assert resp.closed is True


def test_cert_path_strips_prefix_and_accepts_json(monkeypatch) -> None:
    set_credential(monkeypatch, CensysIntelProvider)
    session = FakeSession(json_response({"result": _CERT_INNER}))
    CensysIntelProvider(session=session).lookup_cert(_CERT)
    call = session.calls[0]
    assert call["url"] == f"https://api.platform.censys.io/v3/global/asset/certificate/{_HEX}"
    assert call["headers"]["Accept"] == "application/json"


def test_cert_success_splits_san_cn_issuer(monkeypatch) -> None:
    set_credential(monkeypatch, CensysIntelProvider)
    session = FakeSession(json_response({"result": _CERT_INNER}))
    result = CensysIntelProvider(session=session).lookup_cert(_CERT)
    got = {(e.type, e.value) for e in result.evidence}
    assert ("cert_fingerprint_sha256", _HEX) in got
    assert ("cert_subject_cn", "x.example.com") in got
    assert ("cert_issuer_cn", "Root CA") in got
    assert ("cert_issuer_org", "CA Org") in got
    assert ("cert_not_before", "2024-01-01T00:00:00Z") in got
    # SAN union of names[] and dns_names[], deduped
    sans = {e.value for e in result.evidence if e.type == "cert_san_dns"}
    assert sans == {"x.example.com", "y.example.com", "z.example.com"}
    assert all(e.target == _CERT for e in result.evidence)


def test_cert_fingerprint_mismatch_is_failure(monkeypatch) -> None:
    set_credential(monkeypatch, CensysIntelProvider)
    inner = dict(_CERT_INNER, fingerprint_sha256="b" * 64)
    session = FakeSession(json_response({"result": inner}))
    result = CensysIntelProvider(session=session).lookup_cert(_CERT)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "CertificateMismatchError"
    assert result.evidence == ()


def test_cert_missing_fingerprint_is_failure(monkeypatch) -> None:
    # a cert asset with no self-identifying fingerprint cannot be trusted to
    # describe the queried cert -> reject rather than mis-attribute.
    set_credential(monkeypatch, CensysIntelProvider)
    inner = {k: v for k, v in _CERT_INNER.items() if k != "fingerprint_sha256"}
    session = FakeSession(json_response({"result": inner}))
    result = CensysIntelProvider(session=session).lookup_cert(_CERT)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "MalformedPayloadError"
    assert result.evidence == ()


def test_cert_uppercase_fingerprint_emits_canonical_lowercase(monkeypatch) -> None:
    set_credential(monkeypatch, CensysIntelProvider)
    inner = dict(_CERT_INNER, fingerprint_sha256=_HEX.upper())
    session = FakeSession(json_response({"result": inner}))
    result = CensysIntelProvider(session=session).lookup_cert(_CERT)
    fp = next(e.value for e in result.evidence if e.type == "cert_fingerprint_sha256")
    assert fp == _HEX  # canonical lowercase, identical id across case variants


def test_cert_404_is_empty_no_second_call(monkeypatch) -> None:
    set_credential(monkeypatch, CensysIntelProvider)
    resp = FakeResponse(status_code=404, body=b"{}")
    session = FakeSession(resp)
    result = CensysIntelProvider(session=session).lookup_cert(_CERT)
    assert result.status is IntelStatus.EMPTY
    assert len(session.calls) == 1
    assert all("host" not in call["url"] for call in session.calls)
    assert resp.closed is True


def test_lookup_domain_unsupported(monkeypatch) -> None:
    set_credential(monkeypatch, CensysIntelProvider)
    session = FakeSession()
    result = CensysIntelProvider(session=session).lookup_domain(_DOMAIN)
    assert result.status is IntelStatus.UNSUPPORTED
    assert session.calls == []
    assert CensysIntelProvider.capabilities == frozenset(
        {IntelCapability.LOOKUP_IP, IntelCapability.LOOKUP_CERT}
    )


def test_legacy_token_alias_enables(monkeypatch) -> None:
    monkeypatch.setenv("CENSYS_API_TOKEN", "legacy")
    session = FakeSession(FakeResponse(status_code=404, body=b"{}"))
    result = CensysIntelProvider(session=session).lookup_ip(_IP)
    assert result.status is IntelStatus.EMPTY
    assert session.calls[0]["headers"]["Authorization"] == "Bearer legacy"
