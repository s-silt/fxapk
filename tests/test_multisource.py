from __future__ import annotations

import json

from apkscan.core.enrichment import enrich_selected_targets
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher
from apkscan.enrichers.multisource import (
    FofaPassiveEnricher,
    RipeStatBgpEnricher,
    SourceOutcome,
    configured_case_close_enrichers,
)
from apkscan.enrichers.shodan import ShodanEnricher


class _CaseOnlyEnricher(BaseEnricher):
    name = "case_only_fake"
    applies_to = ["ip"]
    case_close_only = True

    def __init__(self) -> None:
        self.calls = 0

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls += 1
        return EnrichmentResult(provider=self.name, ok=True, data={"ip": ep.value})


class _ConfiguredEnricher(_CaseOnlyEnricher):
    name = "configured_fake"
    required_env = ("FXAPK_SYNTHETIC_KEY",)


class _FailingSession:
    def __init__(self, secret: str) -> None:
        self.secret = secret

    def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError(f"transport failed with credential {self.secret}")


class _Response:
    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")

    def json(self) -> dict:
        return self.payload


class _RipeSession:
    def get(self, url: str, **kwargs):  # noqa: ANN003
        if "prefix-overview" in url:
            return _Response(
                {
                    "data": {
                        "resource": "198.51.100.10/24",
                        "asns": [64500],
                        "holder": "Example Network Ltd",
                    }
                }
            )
        raise AssertionError(f"unexpected URL: {url}")


def _ip() -> Endpoint:
    return Endpoint(value="198.51.100.10", kind="ip", is_suspicious=True)


def test_normal_enrichment_skips_case_close_only_enricher() -> None:
    endpoint = _ip()
    enricher = _CaseOnlyEnricher()

    status = enrich_selected_targets(
        [endpoint],
        [enricher],
        mode="passive",
        include_case_close=False,
    )

    assert enricher.calls == 0
    assert status == []
    assert "case_only_fake" not in endpoint.enrichment


def test_unconfigured_case_source_is_disabled_not_failed(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.delenv("FXAPK_SYNTHETIC_KEY", raising=False)
    endpoint = _ip()
    enricher = _ConfiguredEnricher()

    enrich_selected_targets(
        [endpoint],
        [enricher],
        mode="passive",
        include_case_close=True,
    )

    assert enricher.calls == 0
    assert endpoint.enrichment["source_status"]["configured_fake"]["status"] == "disabled"


def test_fofa_failure_never_contains_secret(monkeypatch) -> None:  # noqa: ANN001
    secret = "synthetic-secret-value"
    monkeypatch.setenv("FXAPK_FOFA_KEY", secret)
    adapter = FofaPassiveEnricher(session=_FailingSession(secret))

    result = adapter.enrich(_ip())
    rendered = json.dumps(result.data, ensure_ascii=False) + str(result.error)

    assert result.ok is False
    assert secret not in rendered
    assert result.error == "RuntimeError"


def test_ripestat_normalizes_origin_prefix_and_holder() -> None:
    result = RipeStatBgpEnricher(session=_RipeSession()).enrich(_ip())

    assert result.ok is True
    assert result.data["origin_asn"] == 64500
    assert result.data["prefix"] == "198.51.100.10/24"
    assert result.data["asn_holder"] == "Example Network Ltd"


def test_all_multisource_adapters_are_passive_case_close_only() -> None:
    enrichers = configured_case_close_enrichers()
    names = {enricher.name for enricher in enrichers}

    assert {
        "ripestat_bgp",
        "fofa",
        "quake",
        "hunter",
        "zoomeye",
        "censys",
        "virustotal",
        "otx",
        "urlscan",
    } <= names
    assert all(enricher.case_close_only for enricher in enrichers)
    assert all(enricher.active is False for enricher in enrichers)


def test_source_outcome_rejects_unknown_status() -> None:
    try:
        SourceOutcome(provider="synthetic", status="unknown")
    except ValueError as exc:
        assert "status" in str(exc)
    else:
        raise AssertionError("SourceOutcome accepted an unknown status")


def test_missing_shodan_key_is_disabled_not_failed(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.delenv("FXAPK_SHODAN_KEY", raising=False)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    endpoint = _ip()

    enrich_selected_targets(
        [endpoint],
        [ShodanEnricher()],
        mode="passive",
        include_case_close=True,
    )

    assert endpoint.enrichment["source_status"]["shodan"]["status"] == "disabled"
