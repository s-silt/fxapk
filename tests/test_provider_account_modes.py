"""Local product configuration never implies billing or credential authorization."""
import pytest

from apkscan.core.models import Endpoint
from apkscan.enrichers.multisource import HunterPassiveEnricher, FofaPassiveEnricher, _api_endpoint


@pytest.mark.parametrize("mode,reason", [("free_only", "free_only_billing_unverified"),
                                        ("unknown", "invalid_billing_policy")])
def test_hunter_unverified_billing_mode_never_makes_a_request(monkeypatch, mode, reason):
    monkeypatch.setenv("FXAPK_HUNTER_CREDIT_MODE", mode)
    hunter = HunterPassiveEnricher()
    monkeypatch.setattr(hunter, "_lookup", lambda *a: pytest.fail("no network for unverified free-only billing"))
    result = hunter.enrich(Endpoint(kind="domain", value="synthetic.invalid"))
    assert result.data == {"_source_status": "disabled", "_error_type": reason}
    assert hunter.receipt["network_attempted"] is False


def test_fofa_relay_configuration_is_resolved_each_time(monkeypatch):
    path = "/api/v1/search/all"
    for host in ("https://relay-a.invalid", "https://relay-b.invalid"):
        monkeypatch.setenv("FXAPK_FOFA_URL", host)
        assert _api_endpoint("FXAPK_FOFA_URL", "https://official.invalid", path) == host + path


def test_fofa_relay_schema_drift_cannot_silently_relabel_fields():
    fofa = FofaPassiveEnricher()
    with pytest.raises(ValueError, match="field_count_mismatch"):
        fofa._normalize({"results": [["synthetic.invalid", "wrong-column-count"]]},
                        Endpoint(kind="domain", value="synthetic.invalid"))


@pytest.mark.parametrize("url", ["http://relay.invalid", "https://user:pass@relay.invalid", "https://relay.invalid/?token=synthetic"])
def test_relay_url_cannot_smuggle_credential_or_disable_tls(monkeypatch, url):
    monkeypatch.setenv("FXAPK_FOFA_URL", url)
    with pytest.raises(ValueError, match="invalid_api_endpoint"):
        _api_endpoint("FXAPK_FOFA_URL", "https://official.invalid", "/api/v1/search/all")
