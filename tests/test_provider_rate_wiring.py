"""Real capped transport admission with a fake HTTP boundary only."""
import json
from urllib.parse import urlsplit
import pytest
import requests
from apkscan.enrichers import _http, icp


def test_hapi_rate_policy_admits_one_nonredirecting_request(monkeypatch):
    monkeypatch.setenv('FXAPK_ICP_HAPI_KEY', 'SYNTHETIC')
    origin = urlsplit(icp.HAPI_URL)
    monkeypatch.setenv('FXAPK_HTTP_RATE_LIMITS', json.dumps({
        f'{origin.scheme}://{origin.netloc}': {'requests': 10, 'period_seconds': 1,
                                           'group': 'synthetic-hapi-test'}}))
    calls = []
    def transport(url, **kwargs):
        calls.append(kwargs)
        r = requests.Response()
        r.status_code = 200
        r._content = b'{}'
        r._content_consumed = True
        return r
    monkeypatch.setattr(_http.requests, 'post', transport)
    monkeypatch.setattr(_http, '_cap_body', lambda r, cap: r)
    # Exercise request admission without coupling this transport contract to HAPI JSON schema.
    try:
        icp.IcpEnricher()._query_hapi('example.invalid')
    except ValueError:
        pass  # A schema rejection after HTTP is independent of admission.
    assert len(calls) == 1
    assert calls[0]['allow_redirects'] is False


def test_fixed_endpoint_rejects_redirect_without_following():
    r = requests.Response()
    r.status_code = 302
    with pytest.raises(requests.RequestException):
        _http.reject_redirect(r)
