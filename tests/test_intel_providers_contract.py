"""Cross-provider contract tests for the PR6 intel adapters.

Every invariant that belongs to the shared bounded transport rather than one
provider's payload shape lives here, parametrized over all four real adapters:
exactly one fixed-authority GET per lookup (zero when unavailable / unsupported /
non-canonical), no redirects, bounded read, response always closed, typed
sanitized FAILUREs, secret never leaked, and deterministic output.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from urllib.parse import urlsplit

import pytest
import requests

from apkscan.intel import IntelCapability, IntelStatus
from apkscan.intel.providers import _http
from apkscan.intel.providers.censys import CensysIntelProvider
from apkscan.intel.providers.fofa import FofaIntelProvider
from apkscan.intel.providers.hunter import HunterIntelProvider
from apkscan.intel.providers.shodan import ShodanIntelProvider
from apkscan.network import NetworkEntity, NetworkEntityType
from tests.intel_provider_fakes import (  # noqa: F401 - scrub_intel_env is autouse
    SECRET,
    FakeResponse,
    FakeSession,
    assert_secret_absent,
    json_response,
    scrub_intel_env,
    set_credential,
)

_IP = NetworkEntity(NetworkEntityType.IP, "1.2.3.4", ("pcap",))
_DOMAIN = NetworkEntity(NetworkEntityType.DOMAIN, "example.com", ("pcap",))
_CERT = NetworkEntity(NetworkEntityType.CERTIFICATE, "sha256:" + "a" * 64, ("pcap",))


@dataclass(frozen=True)
class Case:
    label: str
    cls: type
    capability: IntelCapability
    entity: NetworkEntity
    authority: str
    success_body: object


_FOFA_IP_ROW = [
    "h.example.com", "1.2.3.4", 443, "https", "nginx",
    "CN", "Shanghai", "Shanghai", "4837", "China Telecom Group",
]

CASES = [
    Case("fofa-ip", FofaIntelProvider, IntelCapability.LOOKUP_IP, _IP, "fofa.info",
         {"error": False, "results": [_FOFA_IP_ROW]}),
    Case("fofa-domain", FofaIntelProvider, IntelCapability.LOOKUP_DOMAIN, _DOMAIN, "fofa.info",
         {"error": False, "results": [_FOFA_IP_ROW]}),
    Case("hunter-ip", HunterIntelProvider, IntelCapability.LOOKUP_IP, _IP, "hunter.qianxin.com",
         {"code": 200, "data": {"arr": [
             {"as_number": "4837", "as_org": "CT", "company": "Acme", "number": "京ICP备1号",
              "country": "CN", "city": "Shanghai", "port": 443, "server": "nginx"}]}}),
    Case("hunter-domain", HunterIntelProvider, IntelCapability.LOOKUP_DOMAIN, _DOMAIN,
         "hunter.qianxin.com",
         {"code": 200, "data": {"arr": [{"ip": "5.6.7.8", "domain": "h.example.com"}]}}),
    Case("shodan-ip", ShodanIntelProvider, IntelCapability.LOOKUP_IP, _IP, "api.shodan.io",
         {"ip_str": "1.2.3.4", "ports": [80, 443], "hostnames": ["h.example.com"],
          "data": [{"product": "nginx", "version": "1.18", "http": {"server": "nginx"}}],
          "org": "Acme", "isp": "CT", "asn": "AS4837", "country_name": "China"}),
    Case("shodan-domain", ShodanIntelProvider, IntelCapability.LOOKUP_DOMAIN, _DOMAIN,
         "api.shodan.io", {"example.com": "5.6.7.8"}),
    Case("censys-ip", CensysIntelProvider, IntelCapability.LOOKUP_IP, _IP,
         "api.platform.censys.io",
         {"result": {"autonomous_system": {"asn": 4837, "name": "CT", "bgp_prefix": "1.2.0.0/16"},
                     "location": {"country_code": "CN", "city": "Shanghai"},
                     "services": [{"port": 443, "product": "nginx", "version": "1.18",
                                   "server": "nginx"}]}}),
    Case("censys-cert", CensysIntelProvider, IntelCapability.LOOKUP_CERT, _CERT,
         "api.platform.censys.io",
         {"result": {"fingerprint_sha256": "a" * 64,
                     "parsed": {"subject_dn": "CN=x", "subject": {"common_name": ["x.example.com"]},
                                "issuer_dn": "CN=CA", "issuer": {"common_name": ["CA"],
                                                                 "organization": ["CA Org"]},
                                "validity_period": {"not_before": "2024-01-01T00:00:00Z",
                                                    "not_after": "2025-01-01T00:00:00Z"}},
                     "names": ["x.example.com", "y.example.com"]}}),
]

_IDS = [c.label for c in CASES]


def _lookup(provider, capability, entity):
    return getattr(provider, capability.value)(entity)


@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_success_single_fixed_authority_request(monkeypatch, case: Case) -> None:
    set_credential(monkeypatch, case.cls)
    session = FakeSession(json_response(case.success_body))
    provider = case.cls(session=session)

    result = _lookup(provider, case.capability, case.entity)

    assert result.status is IntelStatus.SUCCESS
    assert result.evidence
    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["allow_redirects"] is False
    assert call["stream"] is True
    assert call["timeout"] == (5.0, 15.0)
    parts = urlsplit(call["url"])
    assert parts.scheme == "https"
    assert parts.netloc == case.authority
    assert case.entity.value not in parts.netloc


@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_success_evidence_provenance_and_scalar(monkeypatch, case: Case) -> None:
    set_credential(monkeypatch, case.cls)
    provider = case.cls(session=FakeSession(json_response(case.success_body)))
    result = _lookup(provider, case.capability, case.entity)
    for evidence in result.evidence:
        assert evidence.source == case.cls.name
        assert isinstance(evidence.value, (str, int, float, bool, type(None)))
        assert evidence.confidence == 0.5
        assert evidence.timestamp is None
        assert evidence.raw_reference == f"{case.cls.name}:{case.capability.value}"
        assert not any(ch in evidence.raw_reference for ch in "?#&= ")


@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_success_response_closed(monkeypatch, case: Case) -> None:
    set_credential(monkeypatch, case.cls)
    response = json_response(case.success_body)
    provider = case.cls(session=FakeSession(response))
    _lookup(provider, case.capability, case.entity)
    assert response.closed is True


@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_success_deterministic_to_dict(monkeypatch, case: Case) -> None:
    set_credential(monkeypatch, case.cls)
    first = _lookup(case.cls(session=FakeSession(json_response(case.success_body))),
                    case.capability, case.entity)
    second = _lookup(case.cls(session=FakeSession(json_response(case.success_body))),
                     case.capability, case.entity)
    assert json.dumps(first.to_dict(), sort_keys=True) == json.dumps(
        second.to_dict(), sort_keys=True
    )


# --------------------------------------------------------------------------- #
# Guards that never touch the wire                                             #
# --------------------------------------------------------------------------- #
_ADAPTERS = [FofaIntelProvider, HunterIntelProvider, ShodanIntelProvider, CensysIntelProvider]
_ADAPTER_IDS = [c.name for c in _ADAPTERS]


@pytest.mark.parametrize("cls", _ADAPTERS, ids=_ADAPTER_IDS)
def test_unavailable_makes_no_request(cls) -> None:
    session = FakeSession()  # any get would raise
    provider = cls(session=session)
    result = provider.lookup_ip(_IP)
    assert result.status is IntelStatus.UNAVAILABLE
    assert result.missing_env == tuple(sorted(cls.required_env))
    assert session.calls == []


@pytest.mark.parametrize("cls", _ADAPTERS, ids=_ADAPTER_IDS)
def test_kind_mismatch_makes_no_request(monkeypatch, cls) -> None:
    set_credential(monkeypatch, cls)
    session = FakeSession()
    result = cls(session=session).lookup_ip(_DOMAIN)
    assert result.status is IntelStatus.UNSUPPORTED
    assert result.reason == "entity_kind_mismatch"
    assert session.calls == []


def test_undeclared_capability_makes_no_request(monkeypatch) -> None:
    set_credential(monkeypatch, FofaIntelProvider)
    session = FakeSession()
    result = FofaIntelProvider(session=session).lookup_cert(_CERT)
    assert result.status is IntelStatus.UNSUPPORTED
    assert result.reason == "capability_not_supported"
    assert session.calls == []

    set_credential(monkeypatch, CensysIntelProvider)
    session2 = FakeSession()
    result2 = CensysIntelProvider(session=session2).lookup_domain(_DOMAIN)
    assert result2.status is IntelStatus.UNSUPPORTED
    assert result2.reason == "capability_not_supported"
    assert session2.calls == []


@pytest.mark.parametrize("cls", _ADAPTERS, ids=_ADAPTER_IDS)
def test_non_canonical_value_raises_before_wire(monkeypatch, cls) -> None:
    set_credential(monkeypatch, cls)
    session = FakeSession()
    with pytest.raises(ValueError):
        cls(session=session).lookup_ip(NetworkEntity(NetworkEntityType.IP, "01.2.3.4"))
    assert session.calls == []


# --------------------------------------------------------------------------- #
# FAILURE matrix (one representative IP lookup per adapter)                     #
# --------------------------------------------------------------------------- #
_FAILURE_ADAPTERS = [FofaIntelProvider, HunterIntelProvider, ShodanIntelProvider,
                     CensysIntelProvider]


def _failure_outcome(scenario):
    """Return a fresh (outcome, expected_reason) for one FAILURE scenario. The
    reason is pinned exactly so a deleted guard cannot masquerade as a different
    sanitized failure (e.g. a swallowed AssertionError)."""
    return {
        "timeout": (requests.Timeout("connect timed out"), "Timeout"),
        "ssl": (requests.exceptions.SSLError("bad handshake"), "SSLError"),
        "redirect": (
            FakeResponse(status_code=302, headers={"Location": "https://evil.example"}),
            "RedirectResponseError",
        ),
        "auth": (FakeResponse(status_code=401, body=b"{}"), "AuthError"),
        "ratelimit": (FakeResponse(status_code=429, body=b"{}"), "RateLimitedError"),
        "server": (FakeResponse(status_code=500, body=b"{}"), "ServerError"),
        "non_json": (FakeResponse(status_code=200, body=b"not json at all"), "JSONDecodeError"),
        "top_level_list": (FakeResponse(status_code=200, body=b"[1, 2, 3]"), "MalformedPayloadError"),
        "content_length_oversize": (
            FakeResponse(
                status_code=200, headers={"Content-Length": "6000000"}, body=b"{}", raise_on_iter=True
            ),
            "OversizeResponseError",
        ),
    }[scenario]


_FAILURE_SCENARIOS = [
    "timeout", "ssl", "redirect", "auth", "ratelimit", "server",
    "non_json", "top_level_list", "content_length_oversize",
]


@pytest.mark.parametrize("cls", _FAILURE_ADAPTERS, ids=[c.name for c in _FAILURE_ADAPTERS])
@pytest.mark.parametrize("scenario", _FAILURE_SCENARIOS)
def test_failure_matrix(monkeypatch, cls, scenario) -> None:
    set_credential(monkeypatch, cls)
    outcome, expected_reason = _failure_outcome(scenario)
    session = FakeSession(outcome)
    result = cls(session=session).lookup_ip(_IP)

    assert result.status is IntelStatus.FAILURE
    assert result.reason == expected_reason
    assert result.evidence == ()
    assert len(session.calls) == 1
    if isinstance(outcome, FakeResponse):
        assert outcome.closed is True
    if scenario == "content_length_oversize":
        # the oversize Content-Length must be rejected BEFORE the body is read
        assert outcome.iter_called is False


@pytest.mark.parametrize("cls", _FAILURE_ADAPTERS, ids=[c.name for c in _FAILURE_ADAPTERS])
def test_streamed_oversize_rejected(monkeypatch, cls) -> None:
    set_credential(monkeypatch, cls)
    # Small cap + small chunk so the body is multi-chunk: the read must stop
    # mid-stream (a full-buffering rewrite would read every chunk or trip the
    # .content booby-trap).
    monkeypatch.setattr(_http, "_MAX_RESPONSE_BYTES", 16)
    monkeypatch.setattr(_http, "_CHUNK_SIZE", 8)
    big = FakeResponse(status_code=200, body=b'{"padding":"' + b"x" * 200 + b'"}')
    session = FakeSession(big)
    result = cls(session=session).lookup_ip(_IP)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "OversizeResponseError"
    assert big.closed is True
    # stopped after the cap was exceeded, not after reading the whole ~27-chunk body
    assert big.chunks_yielded <= 3


@pytest.mark.parametrize("cls", _FAILURE_ADAPTERS, ids=[c.name for c in _FAILURE_ADAPTERS])
def test_wall_deadline_enforced(monkeypatch, cls) -> None:
    set_credential(monkeypatch, cls)
    monkeypatch.setattr(_http, "_CHUNK_SIZE", 8)
    # monotonic call #1 = deadline baseline (0.0); #2 = first in-loop check (0.0,
    # passes); #3 onward = 1000.0 (>30s deadline) so the SECOND chunk's check
    # trips. A counter (not a finite iter) avoids StopIteration if the clock is
    # read elsewhere.
    state = {"n": 0}

    def fake_monotonic() -> float:
        state["n"] += 1
        return 0.0 if state["n"] <= 2 else 1000.0

    monkeypatch.setattr(_http.time, "monotonic", fake_monotonic)
    body = json.dumps({"error": False, "results": [], "pad": "xxxxxxxxxxxxxxxx"}).encode()
    resp = FakeResponse(status_code=200, body=body)
    session = FakeSession(resp)
    result = cls(session=session).lookup_ip(_IP)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "UpstreamTimeoutError"
    # the deadline tripped mid-stream, not after buffering the whole body
    total_chunks = (len(body) + 7) // 8
    assert resp.chunks_yielded < total_chunks


# --------------------------------------------------------------------------- #
# Secret safety                                                                #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_secret_absent_on_success(monkeypatch, caplog, case: Case) -> None:
    set_credential(monkeypatch, case.cls, SECRET)
    provider = case.cls(session=FakeSession(json_response(case.success_body)))
    with caplog.at_level(logging.DEBUG):
        result = _lookup(provider, case.capability, case.entity)
    assert result.status is IntelStatus.SUCCESS
    assert_secret_absent(SECRET, result, caplog)
    # the credential is read inside _request_spec and never cached on the instance
    assert SECRET not in repr(vars(provider))


@pytest.mark.parametrize("cls", _FAILURE_ADAPTERS, ids=[c.name for c in _FAILURE_ADAPTERS])
def test_secret_absent_on_failure(monkeypatch, caplog, cls) -> None:
    set_credential(monkeypatch, cls, SECRET)
    leaky = requests.exceptions.ConnectionError(
        f"failed to reach https://host/path?key={SECRET}&x=1"
    )
    session = FakeSession(leaky)
    with caplog.at_level(logging.DEBUG):
        result = cls(session=session).lookup_ip(_IP)
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ConnectionError"
    assert_secret_absent(SECRET, result, caplog)


def test_key_is_actually_sent_upstream(monkeypatch) -> None:
    """Positive control: the credential really does go on the wire (so the
    secret-absence tests are proving sanitization, not a no-op)."""
    set_credential(monkeypatch, FofaIntelProvider, SECRET)
    session = FakeSession(json_response({"error": False, "results": []}))
    FofaIntelProvider(session=session).lookup_ip(_IP)
    assert session.calls[0]["params"].get("key") == SECRET
