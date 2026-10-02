"""No real sleep/network: HTTP admission and shared account-group boundaries."""
import json
from types import SimpleNamespace

import pytest

from apkscan.enrichers import _rate_limit as rates


class Clock:
    def __init__(self):
        self.now = 100.0
    def clock(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


def controller(**kwargs):
    clock = Clock()
    policy = rates.RatePolicy(**kwargs)
    return rates.RateController(policy, clock=clock.clock, wall_clock=lambda: 1000, sleep=clock.sleep), clock


def test_rolling_window_bounds_request_starts_and_releases_concurrency():
    gate, time = controller(requests=2, period_seconds=1, max_concurrency=2)
    gate.acquire()
    gate.release()
    gate.acquire()
    gate.release()
    assert time.now == 100
    gate.acquire()
    gate.release()
    assert time.now >= 101


def test_concurrency_wait_is_bounded_and_does_not_admit_request():
    gate, _ = controller(requests=10, period_seconds=1, max_concurrency=1, max_wait_seconds=.1)
    gate.acquire()
    with pytest.raises(rates.RequestThrottled):
        gate.acquire()
    assert gate._active == 1
    gate.release()


def test_retry_after_stops_later_request_without_replaying_failed_one():
    gate, time = controller(requests=10, period_seconds=1, max_wait_seconds=2)
    gate.acquire()
    gate.observe(SimpleNamespace(status_code=429, headers={"Retry-After": "60"}))
    gate.release()
    with pytest.raises(rates.RequestThrottled):
        gate.acquire()
    assert len(gate._starts) == 1
    assert time.now == 100


def test_retry_after_http_date_uses_wall_clock_for_delay():
    from email.utils import formatdate
    gate, _ = controller(requests=10, period_seconds=1, max_wait_seconds=2)
    gate.observe(SimpleNamespace(status_code=429, headers={"Retry-After": formatdate(1060, usegmt=True)}))
    with pytest.raises(rates.RequestThrottled):
        gate.acquire()


def test_fofa_views_and_configured_relay_share_one_explicit_group(monkeypatch):
    policy = {"requests": 1, "period_seconds": 1, "group": "synthetic-shared-account"}
    monkeypatch.setenv("FXAPK_HTTP_RATE_LIMITS", json.dumps({"https://first.invalid": policy,"https://second.invalid": policy}))
    one = rates.controller_for("https://first.invalid/api/search")
    assert one is rates.controller_for("https://first.invalid/api/host")
    assert one is rates.controller_for("https://second.invalid/search")


@pytest.mark.parametrize("config", ["invalid", '{"https://a.invalid":{"requests":true,"period_seconds":1}}',
    '{"https://a.invalid/path":{"requests":1,"period_seconds":1}}',
    '{"https://a.invalid":{"requests":1,"period_seconds":1,"unknown":true}}'])
def test_bad_local_configuration_fails_closed(monkeypatch, config):
    monkeypatch.setenv("FXAPK_HTTP_RATE_LIMITS", config)
    with pytest.raises(rates.RequestThrottled, match="invalid_rate_configuration"):
        rates.controller_for("https://a.invalid/api")


def test_slot_releases_even_when_network_or_body_read_fails(monkeypatch):
    gate, _ = controller(requests=10, period_seconds=1)
    monkeypatch.setattr(rates, "controller_for", lambda _: gate)
    with pytest.raises(RuntimeError):
        with rates.request_slot("https://sample.invalid", allow_redirects=False):
            raise RuntimeError("synthetic failure")
    assert gate._active == 0
    with pytest.raises(rates.RequestThrottled, match="redirect"):
        with rates.request_slot("https://sample.invalid", allow_redirects=True):
            pytest.fail("must not make an uncounted redirect")


def test_unconfigured_transport_preserves_legacy_behavior(monkeypatch):
    monkeypatch.delenv("FXAPK_HTTP_RATE_LIMITS", raising=False)
    with rates.request_slot("https://sample.invalid", allow_redirects=True) as gate:
        assert gate is None


@pytest.mark.parametrize("kind", ["session_get", "session_post", "module_get", "module_post"])
def test_real_http_wrappers_admit_before_request_and_share_429_feedback(monkeypatch, kind):
    from apkscan.enrichers import _http
    gate, _ = controller(requests=10, period_seconds=1, max_wait_seconds=1)
    monkeypatch.setattr(rates, "controller_for", lambda _: gate)
    calls = []
    class Response:
        status_code = 429
        headers = {"Retry-After": "30"}
        def iter_content(self, size):
            yield b"{}"
        def close(self):
            pass
    def request(*args, **kwargs):
        calls.append(kwargs)
        return Response()
    monkeypatch.setattr(_http.requests, "get", request)
    monkeypatch.setattr(_http.requests, "post", request)
    monkeypatch.setattr(_http.requests.Session, "get", request)
    monkeypatch.setattr(_http.requests.Session, "post", request)
    session = _http.CappedSession()
    invoke = {"session_get": session.get, "session_post": session.post,
              "module_get": _http.capped_get, "module_post": _http.capped_post}[kind]
    assert invoke("https://synthetic.invalid/api", allow_redirects=False).status_code == 429
    assert gate._active == 0
    with pytest.raises(rates.RequestThrottled):
        invoke("https://synthetic.invalid/other", allow_redirects=False)
    assert len(calls) == 1
    assert calls[0]["stream"] is True


def test_shared_group_conflicting_limits_fail_closed(monkeypatch):
    monkeypatch.setenv("FXAPK_HTTP_RATE_LIMITS", json.dumps({
        "https://one.invalid": {"requests": 1, "period_seconds": 1, "group": "same"},
        "https://two.invalid": {"requests": 2, "period_seconds": 1, "group": "same"}}))
    with pytest.raises(rates.RequestThrottled):
        rates.controller_for("https://one.invalid/api")


def test_local_throttle_is_not_reported_as_remote_provider_failure_type():
    from apkscan.core.enrichment import safe_error_type
    assert safe_error_type(rates.RequestThrottled("local_rate_limit_wait_exceeded")) == "local_rate_limit"
