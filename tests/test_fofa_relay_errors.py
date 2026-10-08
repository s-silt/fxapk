"""Relay upstream failures must not misclassify the caller's own credentials."""
import json

import pytest
import requests

from apkscan.core.models import Endpoint
from apkscan.enrichers.multisource import FofaPassiveEnricher

UPSTREAM = {"error": True, "errmsg": "[官方错误信息] [-403] 访问权限不足"}
EMPTY = {"error": False, "results": [], "size": 0}


class Session:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.calls = 0

    def get(self, url, **kwargs):
        self.calls += 1
        payload, status = next(self.responses)
        response = requests.Response()
        response.status_code = status
        response.url = url
        response._content = json.dumps(payload).encode()
        return response


@pytest.fixture
def relay(monkeypatch):
    monkeypatch.setenv("FXAPK_FOFA_KEY", "test-relay-credential")
    monkeypatch.setenv("FXAPK_FOFA_URL", "https://fofoapi.com")  # leak-scan: allow public relay API hostname required for provider-specific protocol compatibility
    monkeypatch.setenv("FXAPK_FOFA_FIELD_PROFILE", "full")


def target(index):
    return Endpoint(kind="domain", value=f"target{index}.example")


def test_upstream_failure_preserved_and_next_target_queried(relay):
    session = Session((UPSTREAM, 200), (EMPTY, 200))
    adapter = FofaPassiveEnricher(session=session)
    failed = adapter.enrich(target(1))
    assert not failed.ok
    assert failed.data["_source_status"] == "failed"
    assert failed.error == "upstream_permission_denied"
    assert adapter.receipt["business_code"] == "-403"
    assert adapter.receipt["error_scope"] == "upstream"
    assert adapter.receipt["provider_message"] == UPSTREAM["errmsg"]
    assert session.calls == 1  # No retry of the failed query.
    succeeding = adapter.enrich(target(2))
    assert succeeding.ok and succeeding.data["_source_status"] == "no_record"
    assert session.calls == 2


def test_three_consecutive_upstream_failures_still_stop_source(relay):
    session = Session(*[(UPSTREAM, 200)] * 3)
    adapter = FofaPassiveEnricher(session=session)
    results = [adapter.enrich(target(i)) for i in range(4)]
    assert [r.data["_source_status"] for r in results] == ["failed"] * 3 + ["skipped"]
    assert session.calls == 3


def test_success_resets_consecutive_failure_count(relay):
    session = Session((UPSTREAM, 200), (UPSTREAM, 200), (EMPTY, 200), (UPSTREAM, 200), (EMPTY, 200))
    adapter = FofaPassiveEnricher(session=session)
    results = [adapter.enrich(target(i)) for i in range(5)]
    assert [r.data["_source_status"] for r in results] == ["failed", "failed", "no_record", "failed", "no_record"]
    assert session.calls == 5


@pytest.mark.parametrize("base,payload,status,expected", [
    ("https://fofa.info", UPSTREAM, 200, "permission_denied"),
    ("https://fofoapi.com.other.example", UPSTREAM, 200, "permission_denied"),
    ("https://fofoapi.com", UPSTREAM, 403, "permission_denied"),  # leak-scan: allow public relay API hostname required for provider-specific protocol compatibility
    ("https://fofoapi.com", UPSTREAM, 401, "authentication_failed"),  # leak-scan: allow public relay API hostname required for provider-specific protocol compatibility
    ("https://fofoapi.com", {"error": True, "errmsg": "访问权限不足"}, 200, "permission_denied"),  # leak-scan: allow public relay API hostname required for provider-specific protocol compatibility
    ("https://fofoapi.com", {"error": True, "errmsg": "invalid api key"}, 200, "authentication_failed"),  # leak-scan: allow public relay API hostname required for provider-specific protocol compatibility
    ("https://fofoapi.com", {"error": True, "errmsg": "配额已用完"}, 200, "quota_insufficient"),  # leak-scan: allow public relay API hostname required for provider-specific protocol compatibility
    ("https://fofoapi.com", {"error": True, "errmsg": "key不存在"}, 200, "provider_response_error"),  # leak-scan: allow public relay API hostname required for provider-specific protocol compatibility
])
def test_own_permission_authentication_and_quota_errors_still_stop(relay, monkeypatch, base, payload, status, expected):
    monkeypatch.setenv("FXAPK_FOFA_URL", base)
    session = Session((payload, status))
    adapter = FofaPassiveEnricher(session=session)
    failed = adapter.enrich(target(1))
    assert failed.error == expected
    skipped = adapter.enrich(target(2))
    assert skipped.data["_source_status"] == "skipped"
    assert session.calls == 1
