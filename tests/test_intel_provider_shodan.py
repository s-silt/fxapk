"""Shodan-specific adapter behavior: host array splitting, 404=>EMPTY, and the
resolve-only domain path that must never chain a host lookup."""

from __future__ import annotations

import pytest

from apkscan.intel import IntelStatus
from apkscan.intel.providers.shodan import ShodanIntelProvider
from apkscan.network import NetworkEntity, NetworkEntityType
from tests.intel_provider_fakes import (  # noqa: F401 - scrub_intel_env is autouse
    FakeResponse,
    FakeSession,
    json_response,
    scrub_intel_env,
    set_credential,
)

_IP = NetworkEntity(NetworkEntityType.IP, "1.2.3.4", ("pcap",))
_DOMAIN = NetworkEntity(NetworkEntityType.DOMAIN, "example.com", ("pcap",))

_HOST_BODY = {
    "ip_str": "1.2.3.4",
    "ports": [80, 443],
    "hostnames": ["a.example.com", "b.example.com"],
    "data": [{"product": "nginx", "version": "1.18", "http": {"server": "nginx"}}],
    "org": "Acme", "isp": "CT", "asn": "AS4837", "country_name": "China",
    "tags": ["c2"], "os": "Linux",
}


def test_host_splits_ports_and_hostnames(monkeypatch) -> None:
    set_credential(monkeypatch, ShodanIntelProvider)
    session = FakeSession(json_response(_HOST_BODY))
    result = ShodanIntelProvider(session=session).lookup_ip(_IP)
    got = {(e.type, e.value) for e in result.evidence}
    assert ("open_port", 80) in got
    assert ("open_port", 443) in got
    assert ("related_hostname", "a.example.com") in got
    assert ("related_hostname", "b.example.com") in got
    assert ("service_product", "nginx") in got
    assert ("service_server", "nginx") in got
    assert ("hosting_org", "Acme") in got
    assert ("asn", 4837) in got


def test_host_excludes_tags_and_os(monkeypatch) -> None:
    set_credential(monkeypatch, ShodanIntelProvider)
    session = FakeSession(json_response(_HOST_BODY))
    result = ShodanIntelProvider(session=session).lookup_ip(_IP)
    types = {e.type for e in result.evidence}
    assert "tags" not in types
    assert not any("os" == t for t in types)
    assert not any(e.value == "c2" for e in result.evidence)


def test_host_404_is_empty(monkeypatch) -> None:
    set_credential(monkeypatch, ShodanIntelProvider)
    resp = FakeResponse(status_code=404, body=b"{}")
    session = FakeSession(resp)
    result = ShodanIntelProvider(session=session).lookup_ip(_IP)
    assert result.status is IntelStatus.EMPTY
    assert len(session.calls) == 1
    assert resp.closed is True  # closed even on the early-return 404 path


def test_domain_resolve_404_is_failure(monkeypatch) -> None:
    # Contract asymmetry: host 404 => EMPTY, but /dns/resolve 404 (a broken
    # endpoint) => FAILURE, because resolve has no empty_on_404 flag.
    set_credential(monkeypatch, ShodanIntelProvider)
    resp = FakeResponse(status_code=404, body=b"{}")
    session = FakeSession(resp)
    result = ShodanIntelProvider(session=session).lookup_domain(_DOMAIN)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ClientError"
    assert len(session.calls) == 1
    assert "/dns/resolve" in session.calls[0]["url"]
    assert resp.closed is True


def test_domain_resolve_single_ip_no_host_chain(monkeypatch) -> None:
    set_credential(monkeypatch, ShodanIntelProvider)
    session = FakeSession(json_response({"example.com": "5.6.7.8"}))
    result = ShodanIntelProvider(session=session).lookup_domain(_DOMAIN)

    assert result.status is IntelStatus.SUCCESS
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert (evidence.type, evidence.value) == ("resolved_ip", "5.6.7.8")
    assert evidence.target == _DOMAIN
    # exactly one request, to /dns/resolve, never /shodan/host
    assert len(session.calls) == 1
    assert "/dns/resolve" in session.calls[0]["url"]
    assert all("/shodan/host" not in call["url"] for call in session.calls)


def test_domain_resolve_normalizes_ip(monkeypatch) -> None:
    set_credential(monkeypatch, ShodanIntelProvider)
    session = FakeSession(json_response({"example.com": "2001:0db8:0000:0000:0000:0000:0000:0001"}))
    result = ShodanIntelProvider(session=session).lookup_domain(_DOMAIN)
    assert result.evidence[0].value == "2001:db8::1"


@pytest.mark.parametrize("body", [{"example.com": None}, {}, {"example.com": "  "}])
def test_domain_resolve_missing_is_empty(monkeypatch, body) -> None:
    set_credential(monkeypatch, ShodanIntelProvider)
    session = FakeSession(json_response(body))
    result = ShodanIntelProvider(session=session).lookup_domain(_DOMAIN)
    assert result.status is IntelStatus.EMPTY
    assert len(session.calls) == 1


def test_domain_resolve_non_ip_is_failure(monkeypatch) -> None:
    set_credential(monkeypatch, ShodanIntelProvider)
    session = FakeSession(json_response({"example.com": "not-an-ip"}))
    result = ShodanIntelProvider(session=session).lookup_domain(_DOMAIN)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "MalformedPayloadError"


def test_legacy_alias_enables(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "legacy-token")
    session = FakeSession(FakeResponse(status_code=404, body=b"{}"))
    result = ShodanIntelProvider(session=session).lookup_ip(_IP)
    assert result.status is IntelStatus.EMPTY
    assert session.calls[0]["params"]["key"] == "legacy-token"
