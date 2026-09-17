from __future__ import annotations

import json

import pytest

from apkscan.core.batch_enrich import Target, budget_total, estimate_budget, enrich_targets
from apkscan.core.enrichment_profiles import select_enrichers
from apkscan.core.models import Endpoint
from apkscan.enrichers.infrastructure import DayDayMapEnricher
from apkscan.enrichers.resource_profile import (
    FOFA_PROFILE_FIELDS, DayDayMapResourceProfileEnricher,
    FofaHostProfileEnricher, FofaResourceProfileEnricher,
)


class Response:
    status_code = 200

    def __init__(self, body):
        self.body = body
        self.content = json.dumps(body).encode()

    def json(self):
        return self.body

    def raise_for_status(self):
        pass


class Session:
    trust_env = True

    def __init__(self, body):
        self.body = body
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return Response(self.body)

    post = get


def adapter(cls, body, monkeypatch):
    monkeypatch.setenv("FXAPK_FOFA_KEY", "SYNTHETIC_TOKEN")
    monkeypatch.setenv("FXAPK_DAYDAYMAP_KEY", "SYNTHETIC_TOKEN")
    obj = cls(session=Session(body))
    obj.explicitly_selected = True
    return obj


def ip():
    return Endpoint(kind="ip", value="192.0.2.1")


def fofa_body(**changes):
    record = {"ip": "192.0.2.1", "product": ["ExampleProxy"], "lastupdatetime": "2026-01-02",
              "banner": "x" * 4500, "cert": {"subject": {"CN": "example.test"}}}
    record.update(changes)
    return {"size": 25, "results": [[record.get(k, "") for k in FOFA_PROFILE_FIELDS.split(",")]]}


def test_fofa_preserves_profile_types_time_and_truncation(monkeypatch):
    obj = adapter(FofaResourceProfileEnricher, fofa_body(), monkeypatch)
    result = obj.enrich(ip())
    row = result.data["records"][0]
    assert row["product"] == ["ExampleProxy"]
    assert row["lastupdatetime"] == "2026-01-02"
    assert row["cert"]["subject"]["CN"] == "example.test"
    assert row["banner"]["truncated"] is True
    assert result.data["total_reported"] == 25 and result.data["coverage_complete"] is False
    assert obj._http.calls[0][1]["params"]["fields"] == FOFA_PROFILE_FIELDS
    assert len(obj._http.calls) == 1


@pytest.mark.parametrize("body", [{"results": [["too short"]]}, {}, fofa_body(ip="192.0.2.2"),
                                  {"size": 10, "results": []}])
def test_malformed_or_other_target_is_failure_not_negative(monkeypatch, body):
    result = adapter(FofaResourceProfileEnricher, body, monkeypatch).enrich(ip())
    assert result.ok is False and result.data["_source_status"] == "failed"


def test_empty_valid_profile_is_no_record(monkeypatch):
    result = adapter(FofaResourceProfileEnricher, {"size": 0, "results": []}, monkeypatch).enrich(ip())
    assert result.data["_source_status"] == "no_record"


def test_profiles_opt_in_and_budget_is_per_endpoint():
    objects = [FofaResourceProfileEnricher(), FofaHostProfileEnricher(), DayDayMapResourceProfileEnricher()]
    env = {"FXAPK_FOFA_KEY": "SYNTHETIC", "FXAPK_DAYDAYMAP_KEY": "SYNTHETIC"}
    assert budget_total(estimate_budget([Target("192.0.2.1", "ip")], objects, env)) == 0
    selected = select_enrichers(objects, "api", "fofa_profile,fofa_host,daydaymap_profile")
    assert budget_total(estimate_budget([Target("192.0.2.1", "ip")], selected, env)) == 3


def test_host_uses_same_origin_and_preserves_aggregate(monkeypatch):
    monkeypatch.setenv("FXAPK_FOFA_URL", "https://relay.example.test/api/v1/search/all")
    obj = adapter(FofaHostProfileEnricher, {"ip": "192.0.2.1", "product": ["Example"],
                    "category": ["Management"], "port": [22, 443], "update_time": "2026-01-02"}, monkeypatch)
    result = obj.enrich(ip())
    assert obj._http.calls[0][0] == "https://relay.example.test/api/v1/host/192.0.2.1"
    assert result.data["profile"]["category"] == ["Management"]
    assert obj.receipt["api_path"] == "/api/v1/host/192.0.2.1"


def test_no_guessing_arbitrary_host_endpoint(monkeypatch):
    monkeypatch.setenv("FXAPK_FOFA_URL", "https://relay.example.test/custom")
    obj = adapter(FofaHostProfileEnricher, {}, monkeypatch)
    assert obj.enrich(ip()).ok is False
    assert not obj._http.calls


def test_daydaymap_direct_and_nested_profile_retained(monkeypatch):
    assert DayDayMapEnricher(session=Session({}))._http.trust_env is False
    obj = adapter(DayDayMapResourceProfileEnricher, {"code": 200, "data": {"total": 1,
        "list": [{"ip": "192.0.2.1", "product": [{"name": "Example"}], "cert": {"CN": "example.test"}}]}}, monkeypatch)
    result = obj.enrich(ip())
    assert obj._http.trust_env is False and obj.receipt["via"] == "direct"
    assert result.data["records"][0]["product"][0]["name"] == "Example"


def test_profile_credential_echo_redacted(monkeypatch):
    obj = adapter(FofaResourceProfileEnricher, fofa_body(title="SYNTHETIC_TOKEN"), monkeypatch)
    records = enrich_targets([Target("192.0.2.1", "ip")], [obj], env={"FXAPK_FOFA_KEY": "SYNTHETIC_TOKEN"})
    assert "SYNTHETIC_TOKEN" not in json.dumps(records)


def test_fofa_errmsg_is_retained_safely(monkeypatch):
    obj = adapter(FofaResourceProfileEnricher,
                  {"error": True, "errmsg": "No permission SYNTHETIC_TOKEN"}, monkeypatch)
    assert obj.enrich(ip()).ok is False
    assert "permission" in obj.receipt["provider_message"]
    assert "SYNTHETIC_TOKEN" not in json.dumps(obj.receipt)


def test_permission_insufficient_is_not_quota(monkeypatch):
    obj = adapter(FofaResourceProfileEnricher,
                  {"error": True, "errmsg": "[官方错误信息] [-403] 访问权限不足"}, monkeypatch)
    result = obj.enrich(ip())
    assert result.data["_error_type"] == "permission_denied"


def test_breaker_stays_open_for_rest_of_batch(monkeypatch):
    obj = adapter(FofaResourceProfileEnricher, {}, monkeypatch)
    # Malformed data counts as a transport/schema failure; three requests max.
    for _ in range(30):
        obj.enrich(ip())
    assert len(obj._http.calls) == 3
    assert obj.receipt["network_attempted"] is False
