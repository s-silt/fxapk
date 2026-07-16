"""Hunter-specific adapter behavior: urlsafe-b64 query, code semantics, ICP/
company ownership evidence, EMPTY/FAILURE boundary, single-page bound."""

from __future__ import annotations

import base64

import pytest

from apkscan.intel import IntelStatus
from apkscan.intel.providers.hunter import HunterIntelProvider
from apkscan.network import NetworkEntity, NetworkEntityType
from tests.intel_provider_fakes import (  # noqa: F401 - scrub_intel_env is autouse
    SECRET,
    FakeSession,
    json_response,
    scrub_intel_env,
    set_credential,
)

_IP = NetworkEntity(NetworkEntityType.IP, "1.2.3.4", ("pcap",))
_DOMAIN = NetworkEntity(NetworkEntityType.DOMAIN, "example.com", ("pcap",))


def test_ip_query_is_urlsafe_b64_and_sends_key(monkeypatch) -> None:
    set_credential(monkeypatch, HunterIntelProvider)
    session = FakeSession(json_response({"code": 200, "data": {"arr": []}}))
    HunterIntelProvider(session=session).lookup_ip(_IP)
    params = session.calls[0]["params"]
    assert base64.urlsafe_b64decode(params["search"]).decode() == 'ip="1.2.3.4"'
    assert params["page"] == "1"
    # positive control: the credential is actually transmitted (so the
    # secret-absence tests prove sanitization, not a never-sent key)
    assert params["api-key"] == SECRET


def test_ip_success_emits_ownership_evidence(monkeypatch) -> None:
    set_credential(monkeypatch, HunterIntelProvider)
    row = {"as_number": "4837", "as_org": "China Telecom", "isp": "CT",
           "company": "Acme Ltd", "number": "京ICP备1号", "country": "CN",
           "province": "Beijing", "city": "Beijing", "port": 443, "server": "nginx"}
    session = FakeSession(json_response({"code": 200, "data": {"arr": [row]}}))
    result = HunterIntelProvider(session=session).lookup_ip(_IP)
    got = {(e.type, e.value) for e in result.evidence}
    assert ("company", "Acme Ltd") in got
    assert ("icp", "京ICP备1号") in got
    assert ("as_org", "China Telecom") in got
    assert ("asn", 4837) in got
    assert ("open_port", 443) in got
    assert all(e.target == _IP for e in result.evidence)


def test_domain_lookup_only_related_facts(monkeypatch) -> None:
    set_credential(monkeypatch, HunterIntelProvider)
    row = {"ip": "5.6.7.8", "domain": "h.example.com", "as_org": "ignored"}
    session = FakeSession(json_response({"code": 200, "data": {"arr": [row]}}))
    result = HunterIntelProvider(session=session).lookup_domain(_DOMAIN)
    assert {e.type for e in result.evidence} == {"related_ip", "related_hostname"}


def test_data_list_fallback(monkeypatch) -> None:
    set_credential(monkeypatch, HunterIntelProvider)
    row = {"company": "Acme"}
    session = FakeSession(json_response({"code": 200, "data": {"list": [row]}}))
    result = HunterIntelProvider(session=session).lookup_ip(_IP)
    assert ("company", "Acme") in {(e.type, e.value) for e in result.evidence}


@pytest.mark.parametrize("code", [401, 40205, "40205"])
def test_non_ok_code_is_failure(monkeypatch, code) -> None:
    set_credential(monkeypatch, HunterIntelProvider)
    session = FakeSession(json_response({"code": code, "message": "quota exhausted secret"}))
    result = HunterIntelProvider(session=session).lookup_ip(_IP)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ProviderDeclaredError"


@pytest.mark.parametrize("body", [
    {"code": 200, "data": {"arr": []}},
    {"code": 200, "data": None},
    {"code": 200},
])
def test_empty_variants(monkeypatch, body) -> None:
    set_credential(monkeypatch, HunterIntelProvider)
    session = FakeSession(json_response(body))
    assert HunterIntelProvider(session=session).lookup_ip(_IP).status is IntelStatus.EMPTY


def test_single_page_no_pagination(monkeypatch) -> None:
    set_credential(monkeypatch, HunterIntelProvider)
    row = {"company": "Acme"}
    session = FakeSession(json_response({"code": 200, "data": {"arr": [row], "total": 99999}}))
    HunterIntelProvider(session=session).lookup_ip(_IP)
    assert len(session.calls) == 1
    assert session.calls[0]["params"]["page"] == "1"


def test_component_list_of_dicts_extracts_name(monkeypatch) -> None:
    set_credential(monkeypatch, HunterIntelProvider)
    # Hunter's real 'component' is a list of {name, version}; a truthy list would
    # be dropped by _bounded_text, so the first name must be extracted.
    row = {"component": [{"name": "nginx", "version": "1.18"}, {"name": "php"}]}
    session = FakeSession(json_response({"code": 200, "data": {"arr": [row]}}))
    result = HunterIntelProvider(session=session).lookup_ip(_IP)
    assert ("service_product", "nginx") in {(e.type, e.value) for e in result.evidence}


@pytest.mark.parametrize("body", [
    {"code": 200, "data": "unexpected-string"},          # truthy non-dict data
    {"code": 200, "data": {"arr": ["1.2.3.4:443", "x"]}},  # non-empty rows, all non-dict
    {"code": 200, "data": {"arr": "not-a-list"}},          # arr wrong type
])
def test_malformed_payload_is_failure(monkeypatch, body) -> None:
    set_credential(monkeypatch, HunterIntelProvider)
    result = HunterIntelProvider(session=FakeSession(json_response(body))).lookup_ip(_IP)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "MalformedPayloadError"
