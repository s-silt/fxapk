from __future__ import annotations

import base64
import json

import pytest
import requests

from apkscan.core.batch_enrich import Target, completed_from_records, enrich_targets, estimate_budget, budget_total
from apkscan.core.enrichment_profiles import api_inventory, select_enrichers, configuration_issues
from apkscan.core.models import Endpoint
from apkscan.enrichers.infrastructure import (
    CymruEnricher, DayDayMapEnricher, DnsRecordsEnricher, InternetDbEnricher, ThreatBookEnricher, WhoisXmlEnricher,
)
from apkscan.enrichers.multisource import CensysPassiveEnricher, HunterPassiveEnricher, QuakePassiveEnricher, ZoomEyePassiveEnricher


class Response:
    def __init__(self, body, status=200):
        self.body = body
        self.status_code = status
        self.content = json.dumps(body).encode()

    def json(self):
        return self.body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


class Session:
    def __init__(self, body, status=200):
        self.response = Response(body, status)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.response

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.response


def ip():
    return Endpoint(kind="ip", value="1.1.1.1")


def domain():
    return Endpoint(kind="domain", value="example.test")


@pytest.mark.parametrize("suffix", ["", "/", "/api/v3/search/quake_service"])
def test_quake_base_and_endpoint(monkeypatch, suffix):
    monkeypatch.setenv("FXAPK_QUAKE_KEY", "SYNTHETIC")
    monkeypatch.setenv("FXAPK_QUAKE_URL", "https://quake.example.test" + suffix)
    session = Session({"code": 0, "data": []})
    result = QuakePassiveEnricher(session=session).enrich(ip())
    assert result.data["_source_status"] == "no_record"
    assert session.calls[0][:2] == ("POST", "https://quake.example.test/api/v3/search/quake_service")


def test_zoomeye_v2_payload_and_fields(monkeypatch):
    monkeypatch.setenv("FXAPK_ZOOMEYE_KEY", "SYNTHETIC")
    monkeypatch.setenv("FXAPK_ZOOMEYE_URL", "https://api.example.test")
    session = Session({"code": 60000, "data": [{"ip": "1.1.1.1", "port": 443, "organization": "Example"}]})
    result = ZoomEyePassiveEnricher(session=session).enrich(ip())
    method, url, args = session.calls[0]
    assert method == "POST" and url.endswith("/v2/search")
    assert base64.b64decode(args["json"]["qbase64"]) == b'ip="1.1.1.1"'
    assert result.data["records"][0]["port"] == 443


def test_censys_current_resource_is_not_false_empty(monkeypatch):
    monkeypatch.setenv("FXAPK_CENSYS_TOKEN", "SYNTHETIC")
    session = Session({"result": {"resource": {"ip": "1.1.1.1", "services": [{"port": 443}],
                       "autonomous_system": {"asn": 13335, "description": "Example"}}}})
    result = CensysPassiveEnricher(session=session).enrich(ip())
    assert result.data["_source_status"] == "hit"
    assert result.data["services"][0]["port"] == 443
    assert result.data["autonomous_system"]["description"] == "Example"


@pytest.mark.parametrize("body,http,category", [
    ({"code": 401, "message": "Invalid API key SYNTHETIC"}, 200, "authentication_failed"),
    ({"code": 400, "message": "credits insufficient"}, 200, "quota_insufficient"),
    ({}, 403, "permission_denied"),
    ({}, 429, "rate_limited"),
    ({"code": 400, "message": "账号无 API 访问权限，需升级为付费账号"}, 200, "permission_denied"),
])
def test_source_stops_after_account_failure_and_retains_safe_receipt(monkeypatch, body, http, category):
    monkeypatch.setenv("FXAPK_HUNTER_KEY", "SYNTHETIC")
    session = Session(body, http)
    adapter = HunterPassiveEnricher(session=session)
    records = enrich_targets([Target("1.1.1.1", "ip"), Target("8.8.8.8", "ip")], [adapter], env={"FXAPK_HUNTER_KEY": "SYNTHETIC"})
    assert len(session.calls) == 1
    assert records[0]["source_status"]["hunter"]["error_type"] == category
    assert records[1]["source_status"]["hunter"]["status"] == "skipped"
    assert records[0]["receipts"]["hunter"]["response_sha256"]
    assert "SYNTHETIC" not in json.dumps(records)


def test_old_censys_empty_does_not_suppress_repaired_query():
    old = {"target": "1.1.1.1", "source_status": {"censys": {"status": "no_record"}, "fofa": "hit"}}
    assert completed_from_records([old]) == {"1.1.1.1": {"fofa"}}
    repaired = {**old, "source_contracts": {"censys": 3}}
    assert completed_from_records([repaired]) == {"1.1.1.1": {"censys", "fofa"}}


def test_dns_two_views_all_types_conflict_and_fake_ip():
    class DNS:
        calls = []
        def get(self, url, **kwargs):
            self.calls.append((url, kwargs["params"]))
            qtype = kwargs["params"]["type"]
            if qtype == "A":
                return Response({"Status": 0, "Answer": [{"type": 1, "name": "example.test", "TTL": 60,
                                  "data": "198.18.0.1" if "google" in url else "1.1.1.1"}]})
            if qtype == "AAAA":
                return Response({"Status": 3 if "google" in url else 0})
            return Response({"Status": 0})
    session = DNS()
    adapter = DnsRecordsEnricher(session=session)
    result = adapter.enrich(domain())
    assert len(session.calls) == 8
    assert {a[1]["type"] for a in session.calls} == {"A", "AAAA", "CNAME", "NS"}
    assert result.data["coverage_complete"] is False
    assert "AAAA" in result.data["conflicts"]
    assert result.data["views"][0]["rejected"][0]["value"] == "198.18.0.1"
    assert result.data["origin_status"] == "not_determined"


@pytest.mark.parametrize("rcode,status", [(0, "no_record"), (3, "no_record"), (2, "failed")])
def test_dns_empty_and_failure_are_distinct(rcode, status):
    result = DnsRecordsEnricher(session=Session({"Status": rcode})).enrich(domain())
    assert result.data["_source_status"] == status
    assert all(v["rcode"] == rcode for v in result.data["views"])


def test_cymru_multiple_origin_asns_and_registry_country():
    # Cymru 富化器要求 is_global 公网 IP，TEST-NET 保留段会被 _public_ip 边界拒绝，
    # 因此本夹具用 Cloudflare 公共 DNS 的知名地址段（见下行豁免理由），非案件资产。
    session = Session({"Status": 0, "Answer": [{"type": 16, "data": '"13335 64496 | 1.1.1.0/24 | AU | apnic | 2010-01-01"'}]})  # leak-scan: allow Cymru 判据要求 is_global 公网 IP（保留段被拒），1.1.1.0/24 为 Cloudflare 公共 DNS 知名值非案件资产
    result = CymruEnricher(session=session).enrich(ip())
    assert result.data["records"][0]["origin_asns"] == [13335, 64496]
    assert session.calls[0][2]["params"]["name"] == "1.1.1.1.origin.asn.cymru.com"
    assert result.data["country_semantics"] == "registry_not_geolocation"


def test_internetdb_404_and_identity_mismatch():
    assert InternetDbEnricher(session=Session({}, 404)).enrich(ip()).data["_source_status"] == "no_record"
    assert InternetDbEnricher(session=Session({"ip": "8.8.8.8"})).enrich(ip()).ok is False
    result = InternetDbEnricher(session=Session({"ip": "1.1.1.1", "ports": [443], "hostnames": []})).enrich(ip())
    assert result.data["source_family"] == "shodan" and "asn" not in result.data


def test_daydaymap_fields_scope_and_explicit_secondary(monkeypatch):
    monkeypatch.setenv("FXAPK_DAYDAYMAP_KEY", "FIRST")
    monkeypatch.setenv("FXAPK_DAYDAYMAP_KEY2", "SECOND")
    session = Session({"code": 200, "data": {"list": [{"ip": "1.1.1.1", "asn_org": "Example", "icp_reg_name": "Cohosted site"}]}})
    adapter = DayDayMapEnricher(session=session)
    adapter.credential_slot = 2
    result = adapter.enrich(ip())
    assert "icp_reg_name" in session.calls[0][2]["json"]["fields"]
    assert session.calls[0][2]["headers"]["API-KEY"] == "SECOND"
    assert adapter.receipt["credential_slot"] == 2
    assert result.data["records"][0]["asn_org"] == "Example"
    assert result.data["attribution_scope"] == "cohosted_sites_not_ip_owner"


def test_optional_products_not_silently_enabled_and_inventory_is_key_free():
    adapters = [ThreatBookEnricher(session=Session({})), WhoisXmlEnricher(session=Session({}))]
    env = {"FXAPK_THREATBOOK_KEY": "SECRET", "FXAPK_WHOISXML_KEY": "SECRET", "NGHIMMO_API_KEY": "SECRET"}
    assert budget_total(estimate_budget([Target("1.1.1.1", "ip")], adapters, env)) == 0
    inventory = api_inventory(adapters, env)
    assert "SECRET" not in json.dumps(inventory)
    assert inventory["configured_without_adapter"] == ["NGHIMMO_API_KEY"]
    chosen = select_enrichers(adapters, "api", "threatbook")
    assert budget_total(estimate_budget([Target("1.1.1.1", "ip")], chosen, env)) == 1


@pytest.mark.parametrize("kind,field,direction", [("ip", "ipAddress", "reverse"), ("domain", "domainName", "forward")])
def test_whoisxml_correct_product_request_and_empty(monkeypatch, kind, field, direction):
    monkeypatch.setenv("FXAPK_WHOISXML_KEY", "SYNTHETIC")
    session = Session({"result": {"records": [], "count": 0}})
    adapter = WhoisXmlEnricher(session=session)
    adapter.explicitly_selected = True
    result = adapter.enrich(ip() if kind == "ip" else domain())
    request = session.calls[0][2]["json"]
    assert request["searchType"] == direction and field in request
    assert result.data["_source_status"] == "no_record"


def test_stage_filters_and_dns_budget():
    adapters = [DnsRecordsEnricher(), DayDayMapEnricher(), InternetDbEnricher()]
    baseline = select_enrichers(adapters, "baseline")
    assert {a.name for a in baseline} == {"dns_records", "internetdb"}
    assert budget_total(estimate_budget([Target("example.test", "domain")], baseline, {})) == 8
    with pytest.raises(ValueError):
        select_enrichers(adapters, "baseline", "daydaymap")


def test_invalid_endpoint_is_reported_without_echoing_secret():
    issue = configuration_issues([QuakePassiveEnricher()], {"FXAPK_QUAKE_URL": "https://user:SECRET@api.example.test/?key=SECRET"})
    assert issue[0]["provider"] == "quake" and "SECRET" not in json.dumps(issue)


def test_repeated_real_host_misses_do_not_trip_account_breaker():
    adapter = InternetDbEnricher(session=Session({}, 404))
    for _ in range(4):
        assert adapter.enrich(ip()).data["_source_status"] == "no_record"
    assert adapter._blocked_error is None


@pytest.mark.parametrize("echo", ["SYNTHETIC_PADDED", "  SYNTHETIC_PADDED  "])
def test_padded_environment_secret_is_redacted(monkeypatch, echo):
    monkeypatch.setenv("FXAPK_HUNTER_KEY", "  SYNTHETIC_PADDED  ")
    adapter = HunterPassiveEnricher(session=Session({"code": 503, "message": "echo " + echo}))
    adapter.enrich(ip())
    assert "SYNTHETIC_PADDED" not in json.dumps(adapter.receipt)


def test_business_code_other_environment_secret(monkeypatch):
    monkeypatch.setenv("FXAPK_HUNTER_KEY", "SYNTHETIC")
    monkeypatch.setenv("OTHER_SECRET", "  OTHER_MOCK_VALUE  ")
    adapter = HunterPassiveEnricher(session=Session({"code": "OTHER_MOCK_VALUE"}))
    adapter.enrich(ip())
    assert adapter.receipt["business_code"] is None


def test_receipt_endpoint_drops_path(monkeypatch):
    monkeypatch.setenv("FXAPK_QUAKE_KEY", "SYNTHETIC")
    monkeypatch.setenv("FXAPK_QUAKE_URL", "https://api.example.test/private/SYNTHETIC")
    session = Session({"code": 0, "data": []})
    adapter = QuakePassiveEnricher(session=session)
    adapter.enrich(ip())
    assert adapter.receipt["endpoint"] == "https://api.example.test"
    session.response.url = "https://api.example.test/private/SYNTHETIC"
    adapter.enrich(ip())
    assert adapter.receipt["endpoint"] == "https://api.example.test"


def test_business_error_stops_current_batch_even_if_upstream_recovers(monkeypatch):
    monkeypatch.setenv("FXAPK_HUNTER_KEY", "SYNTHETIC")
    session = Session({"code": 503})
    adapter = HunterPassiveEnricher(session=session)
    assert adapter.enrich(ip()).data["_source_status"] == "failed"
    for _ in range(9):
        assert adapter.enrich(ip()).data["_source_status"] == "skipped"
    session.response = Response({"code": 200, "data": {"arr": []}})
    for _ in range(20):
        assert adapter.enrich(ip()).data["_source_status"] == "skipped"
    assert len(session.calls) == 1


@pytest.mark.parametrize("extra", [[{"type": 1, "data": "10.0.0.1"}], [{"type": 5, "data": "example.test"}] * 100])
def test_dns_partial_answers_are_incomplete(extra):
    session = Session({"Status": 0, "Answer": [{"type": 5, "data": "example.test"}] + extra})
    result = DnsRecordsEnricher(session=session).enrich(domain())
    assert result.data["coverage_complete"] is False
    assert result.data["_source_status"] == "hit"
    assert result.data["gaps"] == ["dns_views_incomplete"]


@pytest.mark.parametrize("adapter_cls", [InternetDbEnricher, CymruEnricher, QuakePassiveEnricher, DayDayMapEnricher, ThreatBookEnricher, WhoisXmlEnricher])
def test_redirect_is_failed_without_followup(monkeypatch, adapter_cls):
    for name in adapter_cls.required_env:
        monkeypatch.setenv(name, "SYNTHETIC")
    session = Session({}, 302)
    adapter = adapter_cls(session=session)
    adapter.explicitly_selected = True
    result = adapter.enrich(ip())
    assert result.data["_source_status"] == "failed"
    assert adapter.receipt["reason"] == "redirect_not_followed"
    assert len(session.calls) == 1
    assert session.calls[0][2]["allow_redirects"] is False


def test_cymru_prefix_mismatch_is_failed():
    session = Session({"Status": 0, "Answer": [{"type": 16, "data": '\"64496 | 192.0.2.0/24 | ZZ | example | 2020-01-01\"'}]})
    result = CymruEnricher(session=session).enrich(ip())
    assert result.data["_source_status"] == "failed"
    assert result.error == "cymru_prefix_mismatch"


@pytest.mark.parametrize("category", ["authentication_failed", "permission_denied", "quota_insufficient"])
def test_account_breaker_never_probes(category):
    from apkscan.enrichers.multisource import _ServiceError
    class Broken(InternetDbEnricher):
        def _lookup(self, endpoint, credential):
            raise _ServiceError(category)
    adapter = Broken(session=Session({}))
    assert adapter.enrich(ip()).data["_source_status"] == "failed"
    for _ in range(25):
        assert adapter.enrich(ip()).data["_source_status"] == "skipped"


def test_new_bounded_batch_can_query_after_operator_rechecks_failure(monkeypatch):
    monkeypatch.setenv("FXAPK_HUNTER_KEY", "SYNTHETIC")
    session = Session({"code": 503})
    adapter = HunterPassiveEnricher(session=session)
    assert adapter.enrich(ip()).data["_source_status"] == "failed"
    for _ in range(20):
        assert adapter.enrich(ip()).data["_source_status"] == "skipped"
    session.response = Response({"code": 200, "data": {"arr": []}})
    # New instance represents a separately planned run, not hidden probes in the
    # still-running batch. Account/permission failures still need external change.
    next_batch = HunterPassiveEnricher(session=session)
    assert next_batch.enrich(ip()).data["_source_status"] == "no_record"
    assert len(session.calls) == 2


def test_dns_redirect_views_fail_without_following():
    session = Session({}, 302)
    adapter = DnsRecordsEnricher(session=session)
    result = adapter.enrich(domain())
    assert result.data["_source_status"] == "failed"
    assert result.data["coverage_complete"] is False
    assert len(session.calls) == 8  # Eight planned views, no redirect requests.
    assert all(call[2]["allow_redirects"] is False for call in session.calls)
    assert all(v["reason"] == "redirect_not_followed" for v in result.data["views"])


def test_cli_reports_dns_truncation_as_gap(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from apkscan import cli
    adapter = DnsRecordsEnricher(session=Session({"Status": 0, "Answer": [{"type": 5, "data": "example.test"}] * 101}))
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [adapter])
    targets = tmp_path / "targets.txt"
    targets.write_text("example.test\n", encoding="utf-8")
    result = CliRunner().invoke(cli.app, ["enrich", "batch", "--targets", str(targets), "--out", str(tmp_path), "--no-dry-run"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["completed_with_gaps"] is True
