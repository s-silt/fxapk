"""Synthetic regressions for missing profile fields, budgets and durable output."""
from __future__ import annotations

import json
import time

import pytest

from apkscan.commands.enrich import _append_ndjson, _has_coverage_gaps
from apkscan.core import batch_enrich as batch
from apkscan.core.closure.layers import _passive_hosting_evidence
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.enrichers._profile import bounded_profile
from apkscan.enrichers import shodan
from apkscan.enrichers.multisource import (
    CensysPassiveEnricher, QuakePassiveEnricher, HunterPassiveEnricher,
    RipeStatBgpEnricher, VirusTotalPassiveEnricher, OtxPassiveEnricher, ZoomEyePassiveEnricher,
)
from apkscan.enrichers.resource_profile import DayDayMapResourceProfileEnricher


class Response:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload
        self.content = json.dumps(payload).encode()

    def json(self):
        return self.payload

    def raise_for_status(self):
        pass


class Session:
    def __init__(self, *payloads):
        self.payloads = iter(payloads)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return Response(next(self.payloads))

    post = get


def ep(value="192.0.2.1", kind="ip"):
    return Endpoint(value=value, kind=kind)


@pytest.mark.parametrize("adapter,payload", [
    (QuakePassiveEnricher, {"data": [{"ip": "192.0.2.1", "service": {
        "name": "https", "http": {"server": "Example"}, "tls": {"cert": {"subject": "example.test"}}},
        "components": [{"product_name": "ExampleProxy"}], "time": "2026-01-01T12:00:00Z"}], "total_count": 21}),
    (HunterPassiveEnricher, {"data": {"total": 21, "arr": [{"ip": "192.0.2.1",
        "component": [{"name": "ExampleProxy", "version": "1"}], "update_time": "2026-01-01"}]}}),
])
def test_nested_products_and_observation_time_survive(adapter, payload):
    data = adapter()._normalize(payload, ep())
    assert "ExampleProxy" in json.dumps(data)
    assert "2026-01-01" in json.dumps(data)
    assert data["coverage_complete"] is False and data["total_reported"] == 21


def test_censys_keeps_nested_service_and_ipv6_identity():
    data = CensysPassiveEnricher()._normalize({"result": {"resource": {
        "ip": "2001:db8::1", "last_updated_at": "2026-01-01",
        "services": [{"port": 443, "observed_at": "2025-12-31",
                      "tls": {"certificates": {"leaf_data": {"names": ["example.test"]}}}}]}}},
        ep("2001:0db8:0000:0000:0000:0000:0000:0001"))
    assert data["services"][0]["observed_at"] == "2025-12-31"
    assert data["services"][0]["tls"]["certificates"]["leaf_data"]["names"] == ["example.test"]
    assert data["last_updated_at"] == "2026-01-01"


@pytest.mark.parametrize("value,kind,sub_type", [("192.0.2.1", "ip", "v4"),
    ("2001:db8::1", "ip", "v6"), ("example.test", "domain", "web")])
def test_zoomeye_requests_the_right_collection_and_supported_fields(value, kind, sub_type):
    session = Session({})
    ZoomEyePassiveEnricher(session)._lookup(ep(value, kind), "synthetic")
    request = session.calls[0][1]["json"]
    assert request["sub_type"] == sub_type
    assert {"update_time", "ssl", "product", "organization.name"} <= set(request["fields"].split(","))


def test_receipts_keep_primary_and_auxiliary_hashes(monkeypatch):
    monkeypatch.setenv("FXAPK_VT_KEY", "synthetic")
    session = Session({"data": {"attributes": {"as_owner": "Example"}}},
                      {"data": [], "links": {"next": "https://example.test/next"}})
    adapter = VirusTotalPassiveEnricher(session)
    result = adapter.enrich(ep())
    responses = adapter.receipt["responses"]
    assert len(responses) == 2 and responses[0]["response_sha256"] != responses[1]["response_sha256"]
    assert adapter.receipt["response_sha256"] == responses[0]["response_sha256"]
    assert result.data["passive_dns_coverage"]["truncated"] is True
    assert _has_coverage_gaps(result.data)


def test_otx_ipv6_and_truncation(monkeypatch):
    monkeypatch.setenv("FXAPK_OTX_KEY", "synthetic")
    session = Session({"reputation": 0}, {"passive_dns": [
        {"hostname": f"host{i}.example.test"} for i in range(50)]})
    result = OtxPassiveEnricher(session).enrich(ep("2001:db8::1"))
    assert all("/IPv6/" in url for url, _ in session.calls)
    assert len(result.data["passive_dns"]) == 40
    assert result.data["passive_dns_coverage"]["truncated"] is True


def test_budget_counts_auxiliary_calls_without_network():
    targets = [batch.Target("192.0.2.1", "ip"), batch.Target("example.test", "domain")]
    adapters = [RipeStatBgpEnricher(), VirusTotalPassiveEnricher(), OtxPassiveEnricher(), shodan.ShodanEnricher()]
    env = {"FXAPK_VT_KEY": "synthetic", "FXAPK_OTX_KEY": "synthetic", "FXAPK_SHODAN_KEY": "synthetic"}
    lines = batch.estimate_budget(targets, adapters, env)
    assert batch.budget_total(lines) == 5 + 4 + 4 + 3


def test_daydaymap_profile_respects_secondary_slot(monkeypatch):
    monkeypatch.setenv("FXAPK_DAYDAYMAP_KEY", "first-synthetic")
    monkeypatch.setenv("FXAPK_DAYDAYMAP_KEY2", "second-synthetic")
    adapter = DayDayMapResourceProfileEnricher(Session({"code": 200, "data": {"list": [], "total": 0}}))
    adapter.credential_slot = 2
    adapter.explicitly_selected = True
    result = adapter.enrich(ep())
    assert result.ok and adapter._http.calls[0][1]["headers"]["API-KEY"] == "second-synthetic"
    assert batch.budget_total(batch.estimate_budget([batch.Target("192.0.2.1", "ip")], [adapter],
        {"FXAPK_DAYDAYMAP_KEY": "first-synthetic"})) == 0


def test_completed_target_persisted_before_next_query_and_write_failure_stops(tmp_path):
    path = tmp_path / "enrich.ndjson"
    class Adapter:
        name = "synthetic"
        applies_to = ["ip"]
        active = False
        def enrich(self, endpoint):
            if endpoint.value.endswith(".2"):
                assert path.exists() and len(path.read_text().splitlines()) == 1
                raise KeyboardInterrupt
            return EnrichmentResult(provider=self.name, ok=True, data={"org": "Example"})
    targets = [batch.Target(f"192.0.2.{n}", "ip") for n in (1, 2)]
    with pytest.raises(KeyboardInterrupt):
        batch.enrich_targets(targets, [Adapter()], on_record=lambda r: _append_ndjson([r], path))
    assert batch.read_ledger(path) == {"192.0.2.1": {"synthetic"}}
    def unwritable(record):
        raise OSError("synthetic write failure")
    with pytest.raises(OSError):
        batch.enrich_targets(targets, [Adapter()], on_record=unwritable)


@pytest.mark.parametrize("tail", [b'{"target":"unfinished', b'\xe4\xb8'])
def test_resume_after_truncated_tail_does_not_lose_new_record(tmp_path, tail):
    path = tmp_path / "enrich.ndjson"
    path.write_bytes(tail)
    record = {"target": "192.0.2.1", "kind": "ip", "source_status": {"synthetic": "hit"}}
    _append_ndjson([record], path)
    scan = batch.scan_ledger(path)
    assert scan.bad_lines == 1 and scan.records == [record]


def test_profile_redaction_and_tree_budget(monkeypatch):
    monkeypatch.setenv("FXAPK_SYNTHETIC_KEY", "sensitive-synthetic-marker")
    result = bounded_profile({"header": "HTTP/1.1 200 OK\r\nSet-Cookie: SID=private\r\nServer: Example",
        "cert": {"CN": "example.test"}, "token": "never-display", "banner": "sensitive-synthetic-marker",
        "large": ["x" * 10000 for _ in range(100)]})
    encoded = json.dumps(result)
    assert "private" not in encoded and "never-display" not in encoded and "sensitive-synthetic-marker" not in encoded
    assert "Example" in encoded and result["cert"]["CN"] == "example.test"
    assert len(encoded) < 22000 and "truncated" in encoded


def test_shodan_old_or_future_cache_not_reused():
    assert not shodan.ShodanEnricher._cache_is_fresh({"_cached_at": time.time(), "ip": "192.0.2.1"})
    assert not shodan.ShodanEnricher._cache_is_fresh({"_cached_at": time.time() + 1000, "_profile_contract": 3})


def test_shodan_keeps_measurement_not_collection_time_and_certificate():
    result = shodan._parse_host({"ip_str": "192.0.2.1", "last_update": "2026-01-01", "data": [
        {"port": 443, "timestamp": "2025-12-31", "ssl": {"cert": {"subject": {"CN": "example.test"}}},
         "data": "HTTP/1.1 200 OK\r\nSet-Cookie: SID=private"}]})
    assert result["services"][0]["observed_at"] == "2025-12-31"
    assert result["services"][0]["tls"]["cert"]["subject"]["CN"] == "example.test"
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize("status,expected", [(403, "permission_denied"), (429, "rate_limited"), (302, "redirect_not_followed")])
def test_shodan_http_errors_not_cached_as_host_misses(monkeypatch, tmp_path, status, expected):
    monkeypatch.setenv("FXAPK_SHODAN_KEY", "synthetic")
    monkeypatch.setattr(shodan, "CACHE_FILE", tmp_path / "absent.json")
    calls = []
    def query(url, **kwargs):
        assert kwargs["allow_redirects"] is False
        calls.append(url)
        response = Response({})
        response.status_code = status
        return response
    monkeypatch.setattr(shodan._http, "capped_get", query)
    adapter = shodan.ShodanEnricher()
    result = adapter.enrich(ep())
    assert result.data["_error_type"] == expected and not result.ok
    assert not shodan.CACHE_FILE.exists()
    if status in (403, 429):
        assert adapter.enrich(ep("192.0.2.2")).data["_source_status"] == "skipped"
        assert len(calls) == 1


def test_shodan_rejects_another_hosts_profile(monkeypatch, tmp_path):
    monkeypatch.setenv("FXAPK_SHODAN_KEY", "synthetic")
    monkeypatch.setattr(shodan, "CACHE_FILE", tmp_path / "absent.json")
    monkeypatch.setattr(shodan._http, "capped_get", lambda *args, **kwargs:
        Response({"ip_str": "192.0.2.2", "data": []}))
    result = shodan.ShodanEnricher().enrich(ep())
    assert not result.ok and result.data["_error_type"] == "profile_target_mismatch"


def test_closure_retains_profiles_without_double_counting_fofa_family():
    data = {"source_status": {"fofa_profile": "hit", "daydaymap_profile": "hit"},
        "fofa_profile": {"records": [{"org": "Example", "port": 443, "product": ["Proxy"],
            "lastupdatetime": "2026-01-01", "cert": {"subject": "example.test"}, "country.name": "ExampleLand"}]},
        "daydaymap_profile": {"records": [{"asn_org": "Example", "product": ["Proxy"]}]}}
    providers, services, locations = _passive_hosting_evidence(data)
    assert {p["source"] for p in providers} == {"fofa", "daydaymap"}
    assert services[0]["lastupdatetime"] == "2026-01-01"
    assert services[0]["cert"]["subject"] == "example.test"
    assert locations[0]["country"] == "ExampleLand"


@pytest.mark.parametrize("key", ["token", "  API_KEY  ", "Ａｕｔｈｏｒｉｚａｔｉｏｎ", "_" * 120 + "token"])
def test_sensitive_original_keys(key, monkeypatch):
    monkeypatch.setenv("SYNTHETIC_TOKEN", "token")
    assert "hidden-value" not in json.dumps(bounded_profile({key: "hidden-value"}))


@pytest.mark.parametrize("name", ["Authorization", "cookie", "Ｐｒｏｘｙ－Ａｕｔｈｏｒｉｚａｔｉｏｎ"])
def test_sensitive_header_pairs(name):
    assert bounded_profile({"name": name, "value": "hidden-value"})["value"] == "[redacted]"


def _tree_size(value):
    if isinstance(value, dict):
        parts = [_tree_size(v) for v in value.values()]
        return 1 + len(value) + sum(n for n, _ in parts), sum(len(k) for k in value) + sum(c for _, c in parts)
    if isinstance(value, list):
        parts = [_tree_size(v) for v in value]
        return 1 + sum(n for n, _ in parts), sum(c for _, c in parts)
    return 1, len(value) if isinstance(value, str) else 0


@pytest.mark.parametrize("limit", [0, 1, 9, 64, 16384])
@pytest.mark.parametrize("value", [
    {"nested": [{"token": "secret", "long" * 50: "x" * 10000} for _ in range(40)]},
    [[{"token": "secret"} for _ in range(40)] for _ in range(40)],
    "x" * 20000,
], ids=["characters", "nodes", "string"])
def test_numeric_tree_limits(limit, value):
    nodes, chars = _tree_size(bounded_profile(value, max_chars=limit))
    assert nodes <= 256
    assert chars <= limit


def test_sanitized_preview_hash_name():
    result = bounded_profile("x" * 5000)
    assert "redacted_sha256" in result and "sha256" not in result
    assert _has_coverage_gaps(result)


def test_provider_error_header_redaction():
    from apkscan.enrichers.multisource import _safe_provider_note
    for field in ("message", "errmsg"):
        result = _safe_provider_note({field: "Authorization: Bearer hidden-auth\nCookie: hidden-cookie\nSet-Cookie: hidden-set\nProxy-Authorization: hidden-proxy"})
        assert "hidden" not in result


@pytest.mark.parametrize("sources", [("fofa_profile",), ("fofa_host",), ("fofa_profile", "fofa_host"), ("daydaymap_profile",)])
def test_profiles_are_only_hosting_candidates(sources):
    from apkscan.core.closure.layers import _hosting_layer
    data = {source: ({"profile": {"org": "Example", "product": "Proxy"}} if source == "fofa_host"
                    else {"records": [{"org": "Example", "product": "Proxy"}]}) for source in sources}
    result = _hosting_layer(data)
    assert result["status"] != "complete"
    providers, _, _ = _passive_hosting_evidence(data)
    assert len(providers) == 1
    assert providers[0]["source"] == ("daydaymap" if sources == ("daydaymap_profile",) else "fofa")
    data["asn"] = {"org": "Legacy"}
    assert _hosting_layer(data)["status"] != "complete"


def test_legacy_hosting_completion_unchanged():
    from apkscan.core.closure.layers import _hosting_layer
    data = {"ip_rdap": {"org": "Legacy"}, "asn": {"org": "Legacy"},
            "attribution": {"hosting_provider": {"name": "Legacy", "matched_signals": ["rdap_org"]}}}
    assert _hosting_layer(data)["status"] == "complete"
    data["fofa_profile"] = {"records": [{"org": "Candidate", "product": "Proxy"}]}
    result = _hosting_layer(data)
    assert result["status"] == "complete" and result["evidence"]["provider"] == "Legacy"


@pytest.mark.parametrize("adapter", ["fofa", "daydaymap"])
def test_profile_coverage_counts_raw_rows(adapter):
    from apkscan.enrichers.resource_profile import FofaResourceProfileEnricher, FOFA_PROFILE_FIELDS
    if adapter == "fofa":
        fields = FOFA_PROFILE_FIELDS.split(",")
        row = ["192.0.2.1" if key == "ip" else "" for key in fields]
        result = FofaResourceProfileEnricher()._normalize({"results": [row] * 21, "size": 20}, ep())
    else:
        result = DayDayMapResourceProfileEnricher()._normalize({"data": {"list": [{"ip": "192.0.2.1"}] * 21, "total": 20}}, ep())
    assert result["truncated"] is True and result["coverage_complete"] is False


@pytest.mark.parametrize("services", [[None], [{"port": 443}, "bad"]])
def test_censys_invalid_services_are_failure(services, monkeypatch):
    monkeypatch.setenv("FXAPK_CENSYS_TOKEN", "synthetic")
    adapter = CensysPassiveEnricher(Session({"result": {"services": services}}))
    result = adapter.enrich(ep())
    assert not result.ok and result.data["_source_status"] != "no_record"
    assert "invalid_service_entries" in json.dumps(result.data)
