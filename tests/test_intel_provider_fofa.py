"""FOFA-specific adapter behavior: qbase64 query, atomic evidence, EMPTY/FAILURE
boundary, capability narrowing, and the ignored URL override."""

from __future__ import annotations

import base64
import json

from apkscan.intel import IntelCapability, IntelStatus
from apkscan.intel.providers._http import _MAX_EVIDENCE, _MAX_RECORDS, _MAX_SCALAR_LEN
from apkscan.intel.providers.fofa import FofaIntelProvider
from apkscan.network import NetworkEntity, NetworkEntityType
from apkscan.network.fingerprints import stable_digest
from tests.intel_provider_fakes import (  # noqa: F401 - scrub_intel_env is autouse
    FakeResponse,
    FakeSession,
    json_response,
    scrub_intel_env,
    set_credential,
)

_IP = NetworkEntity(NetworkEntityType.IP, "1.2.3.4", ("pcap",))
_DOMAIN = NetworkEntity(NetworkEntityType.DOMAIN, "example.com", ("pcap",))
_CERT = NetworkEntity(NetworkEntityType.CERTIFICATE, "sha256:" + "a" * 64)

_ROW = ["h.example.com", "1.2.3.4", 443, "https", "nginx",
        "CN", "Shanghai", "Shanghai", "4837", "China Telecom Group"]


def _expected_id(etype, target, value):
    return stable_digest(
        "apkscan.intel/fofa",
        {"t": etype, "k": target.kind.value, "e": target.value, "v": value},
    )


def test_ip_query_qbase64_and_size(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    session = FakeSession(json_response({"error": False, "results": []}))
    FofaIntelProvider(session=session).lookup_ip(_IP)
    params = session.calls[0]["params"]
    assert base64.b64decode(params["qbase64"]).decode() == 'ip="1.2.3.4"'
    assert params["size"] == "100"


def test_domain_query_qbase64(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    session = FakeSession(json_response({"error": False, "results": []}))
    FofaIntelProvider(session=session).lookup_domain(_DOMAIN)
    assert base64.b64decode(session.calls[0]["params"]["qbase64"]).decode() == 'domain="example.com"'


def test_ip_row_splits_into_atomic_evidence(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    session = FakeSession(json_response({"error": False, "results": [_ROW]}))
    result = FofaIntelProvider(session=session).lookup_ip(_IP)

    assert result.status is IntelStatus.SUCCESS
    got = {(e.type, e.value) for e in result.evidence}
    assert got == {
        ("open_port", 443),
        ("service_server", "nginx"),
        ("geo_country", "CN"),
        ("geo_region", "Shanghai"),
        ("geo_city", "Shanghai"),
        ("asn", 4837),
        ("as_org", "China Telecom Group"),
        ("related_hostname", "h.example.com"),
    }
    for evidence in result.evidence:
        assert evidence.target == _IP
        assert evidence.id == _expected_id(evidence.type, _IP, evidence.value)


def test_domain_lookup_has_no_ip_scoped_facts(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    session = FakeSession(json_response({"error": False, "results": [_ROW]}))
    result = FofaIntelProvider(session=session).lookup_domain(_DOMAIN)
    types = {e.type for e in result.evidence}
    assert types == {"related_ip", "related_hostname"}
    values = {(e.type, e.value) for e in result.evidence}
    assert ("related_ip", "1.2.3.4") in values
    assert ("related_hostname", "h.example.com") in values


def test_error_true_is_failure(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    session = FakeSession(json_response({"error": True, "errmsg": "bad key"}))
    result = FofaIntelProvider(session=session).lookup_ip(_IP)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ProviderDeclaredError"


def test_empty_results_is_empty(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    session = FakeSession(json_response({"error": False, "results": []}))
    result = FofaIntelProvider(session=session).lookup_ip(_IP)
    assert result.status is IntelStatus.EMPTY
    assert result.reason == "no_records"


def test_missing_results_is_empty(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    session = FakeSession(json_response({"error": False}))
    assert FofaIntelProvider(session=session).lookup_ip(_IP).status is IntelStatus.EMPTY


def test_results_wrong_type_is_failure(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    session = FakeSession(json_response({"error": False, "results": "oops"}))
    result = FofaIntelProvider(session=session).lookup_ip(_IP)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "MalformedPayloadError"


def _unique_row(i: int) -> list:
    # every cell distinct so each row yields 8 distinct evidence ids
    return [f"h{i}.example.com", "1.2.3.4", 1000 + i, "https", f"srv{i}",
            f"C{i}", f"R{i}", f"CT{i}", str(2000 + i), f"org{i}"]


def _row_candidate_ids(i: int) -> list[str]:
    row = _unique_row(i)
    cells = dict(zip(
        ("host", "ip", "port", "protocol", "server", "country", "region", "city",
         "as_number", "as_organization"),
        row,
    ))
    pairs = [
        ("open_port", cells["port"]),
        ("service_server", cells["server"]),
        ("geo_country", cells["country"]),
        ("geo_region", cells["region"]),
        ("geo_city", cells["city"]),
        ("asn", int(cells["as_number"])),
        ("as_org", cells["as_organization"]),
        ("related_hostname", cells["host"]),
    ]
    return [_expected_id(etype, _IP, value) for etype, value in pairs]


def test_evidence_cap_is_sorted_prefix_and_deterministic(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    # 100 rows (== _MAX_RECORDS) x 8 distinct fields = 800 candidate records,
    # well past _MAX_EVIDENCE=256, so the cap is genuinely exercised.
    rows = [_unique_row(i) for i in range(500)]
    body = {"error": False, "results": rows}
    result = FofaIntelProvider(session=FakeSession(json_response(body))).lookup_ip(_IP)

    assert result.status is IntelStatus.SUCCESS
    assert len(result.evidence) == _MAX_EVIDENCE  # cap actually reached

    all_ids = sorted({cid for i in range(_MAX_RECORDS) for cid in _row_candidate_ids(i)})
    kept = [e.id for e in result.evidence]
    assert kept == all_ids[:_MAX_EVIDENCE]  # the sorted-smallest prefix (sort-before-cap)

    # determinism: a second identical lookup serializes byte-for-byte the same
    again = FofaIntelProvider(session=FakeSession(json_response(body))).lookup_ip(_IP)
    assert json.dumps(result.to_dict(), sort_keys=True) == json.dumps(again.to_dict(), sort_keys=True)


def test_scalar_value_truncated_to_cap(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    row = ["h.example.com", "1.2.3.4", 443, "https", "nginx",
           "CN", "R", "C", "4837", "x" * (_MAX_SCALAR_LEN * 3)]
    result = FofaIntelProvider(
        session=FakeSession(json_response({"error": False, "results": [row]}))
    ).lookup_ip(_IP)
    as_org = next(e.value for e in result.evidence if e.type == "as_org")
    assert len(as_org) == _MAX_SCALAR_LEN


def test_all_invalid_rows_is_failure(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    # non-empty results whose rows are all the wrong shape (dicts, not arrays)
    body = {"error": False, "results": [{"host": "h.example.com"}, {"ip": "1.2.3.4"}]}
    result = FofaIntelProvider(session=FakeSession(json_response(body))).lookup_ip(_IP)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "MalformedPayloadError"


def test_host_cell_normalized_to_bare_hostname(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    rows = [
        ["https://h.example.com", "1.2.3.4", 443, "https", "n", "CN", "R", "C", "1", "o"],
        ["h.example.com:8443", "1.2.3.4", 8443, "https", "n", "CN", "R", "C", "1", "o"],
        ["h.example.com", "1.2.3.4", 80, "http", "n", "CN", "R", "C", "1", "o"],
        ["1.2.3.4:443", "1.2.3.4", 443, "https", "n", "CN", "R", "C", "1", "o"],
    ]
    result = FofaIntelProvider(
        session=FakeSession(json_response({"error": False, "results": rows}))
    ).lookup_ip(_IP)
    hostnames = {e.value for e in result.evidence if e.type == "related_hostname"}
    # three scheme/port variants collapse to one bare hostname; the IP:port drops
    assert hostnames == {"h.example.com"}


def test_fofa_url_override_is_ignored(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    monkeypatch.setenv("FXAPK_FOFA_URL", "http://evil.example")
    session = FakeSession(json_response({"error": False, "results": []}))
    FofaIntelProvider(session=session).lookup_ip(_IP)
    assert session.calls[0]["url"].startswith("https://fofa.info/")


def test_lookup_cert_unsupported(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    session = FakeSession()
    result = FofaIntelProvider(session=session).lookup_cert(_CERT)
    assert result.status is IntelStatus.UNSUPPORTED
    assert result.reason == "capability_not_supported"
    assert session.calls == []
    assert FofaIntelProvider.capabilities == frozenset(
        {IntelCapability.LOOKUP_IP, IntelCapability.LOOKUP_DOMAIN}
    )
