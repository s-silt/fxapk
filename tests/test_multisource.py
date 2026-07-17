from __future__ import annotations

import json

import pytest
import requests

from apkscan.core.enrichment import enrich_selected_targets
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher
from apkscan.enrichers.multisource import (
    CensysPassiveEnricher,
    FofaPassiveEnricher,
    HunterPassiveEnricher,
    OtxPassiveEnricher,
    QuakePassiveEnricher,
    RipeStatBgpEnricher,
    SourceOutcome,
    UrlscanPassiveEnricher,
    VirusTotalPassiveEnricher,
    ZoomEyePassiveEnricher,
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
        if "asn-neighbours" in url:
            return _Response(
                {
                    "data": {
                        "neighbours": [
                            {"asn": 64501, "type": "left", "power": 10},
                            {"asn": 64502, "type": "left", "power": 5},
                            {"asn": 64503, "type": "right", "power": 2},
                        ]
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
    assert result.data["upstreams"] == [64501, 64502]


def test_ripestat_empty_response_is_no_record() -> None:
    class _EmptyRipeSession:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return _Response({"data": {}})

    result = RipeStatBgpEnricher(session=_EmptyRipeSession()).enrich(_ip())

    assert result.ok is True
    assert result.data["_source_status"] == "no_record"


@pytest.mark.parametrize(
    ("adapter", "payload"),
    [
        (
            FofaPassiveEnricher(),
            {
                "results": [
                    [
                        "https://example.test/path?token=COOKIE-SENTINEL",
                        "198.51.100.10",
                        443,
                        "https",
                        "Example",
                        "nginx",
                        "US",
                        "California",
                        "Los Angeles",
                        64500,
                        "Example Hosting Ltd",
                    ]
                ]
            },
        ),
        (
            QuakePassiveEnricher(),
            {
                "data": [
                    {
                        "ip": "198.51.100.10",
                        "port": 443,
                        "service": {"name": "https", "banner": "COOKIE-SENTINEL"},
                    }
                ]
            },
        ),
        (
            HunterPassiveEnricher(),
            {
                "data": {
                    "arr": [
                        {
                            "ip": "198.51.100.10",
                            "port": 443,
                            "web_title": "Example",
                            "headers": {"set-cookie": "COOKIE-SENTINEL"},
                        }
                    ]
                }
            },
        ),
        (
            ZoomEyePassiveEnricher(),
            {
                "matches": [
                    {
                        "ip": "198.51.100.10",
                        "portinfo": {
                            "port": 443,
                            "service": "https",
                            "banner": "COOKIE-SENTINEL",
                        },
                    }
                ]
            },
        ),
        (
            CensysPassiveEnricher(),
            {
                "result": {
                    "ip": "198.51.100.10",
                    "services": [
                        {"port": 443, "service_name": "HTTP", "banner": "COOKIE-SENTINEL"}
                    ],
                    "location": {"country": "US", "raw": "COOKIE-SENTINEL"},
                    "autonomous_system": {"asn": 64500, "name": "Example"},
                }
            },
        ),
        (
            OtxPassiveEnricher(),
            {
                "reputation": 0,
                "pulse_info": {
                    "count": 1,
                    "pulses": [
                        {"id": "pulse-1", "name": "Example", "description": "COOKIE-SENTINEL"}
                    ],
                },
            },
        ),
        (
            UrlscanPassiveEnricher(),
            {
                "results": [
                    {
                        "page": {
                            "domain": "example.test",
                            "ip": "198.51.100.10",
                            "asn": "AS64500",
                        },
                        "task": {
                            "url": "https://example.test/path?token=COOKIE-SENTINEL",
                            "uuid": "synthetic-scan-id",
                        },
                    }
                ]
            },
        ),
    ],
)
def test_provider_normalization_drops_raw_sensitive_payloads(
    adapter, payload: dict
) -> None:  # noqa: ANN001
    normalized = adapter._normalize(payload, _ip())

    assert "COOKIE-SENTINEL" not in json.dumps(normalized, ensure_ascii=False)


def test_provider_normalization_bounds_remaining_text_fields() -> None:
    oversized = "x" * 1_000
    ripe = RipeStatBgpEnricher()._normalize(
        {
            "data": {
                "resource": oversized,
                "asns": [64500],
                "holder": oversized,
            }
        },
        _ip(),
    )
    virustotal = VirusTotalPassiveEnricher()._normalize(
        {
            "data": {
                "attributes": {
                    "as_owner": oversized,
                    "country": oversized,
                    "network": oversized,
                }
            }
        },
        _ip(),
    )
    urlscan = UrlscanPassiveEnricher()._normalize(
        {
            "results": [
                {
                    "page": {"domain": oversized, "asnname": oversized},
                    "task": {"uuid": oversized},
                }
            ]
        },
        _ip(),
    )

    assert len(str(ripe["prefix"])) == 500
    assert len(str(ripe["asn_holder"])) == 500
    assert len(str(virustotal["as_owner"])) == 500
    assert len(str(virustotal["network"])) == 500
    assert len(str(urlscan["records"][0]["domain"])) == 500
    assert len(str(urlscan["records"][0]["scan_id"])) == 500


@pytest.mark.parametrize(
    ("adapter", "payload"),
    [
        (FofaPassiveEnricher(), {"results": [[None] * 11]}),
        (UrlscanPassiveEnricher(), {"results": [{"page": {}, "task": {}}]}),
    ],
)
def test_empty_provider_records_do_not_count_as_hits(adapter, payload: dict) -> None:  # noqa: ANN001
    assert adapter._normalize(payload, _ip()) == {}


def test_urlscan_uses_optional_configured_api_key(monkeypatch) -> None:  # noqa: ANN001
    secret = "synthetic-urlscan-key"
    monkeypatch.setenv("FXAPK_URLSCAN_KEY", secret)

    class _CaptureSession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            self.headers = dict(kwargs.get("headers") or {})
            return _Response({"results": []})

    session = _CaptureSession()
    adapter = UrlscanPassiveEnricher(session=session)

    result = adapter.enrich(_ip())

    assert result.ok is True
    assert session.headers == {"api-key": secret}


def test_zoomeye_uses_configured_api_url(monkeypatch) -> None:  # noqa: ANN001
    configured_url = "https://api.example.test/host/search"
    monkeypatch.setenv("FXAPK_ZOOMEYE_KEY", "synthetic-zoomeye-key")
    monkeypatch.setenv("FXAPK_ZOOMEYE_URL", configured_url)

    class _CaptureSession:
        def __init__(self) -> None:
            self.url = ""

        def get(self, url: str, **kwargs):  # noqa: ANN003
            self.url = url
            return _Response({"matches": []})

    session = _CaptureSession()
    result = ZoomEyePassiveEnricher(session=session).enrich(_ip())

    assert result.ok is True
    assert session.url == configured_url


def test_quake_accepts_secondary_configured_key(monkeypatch) -> None:  # noqa: ANN001
    secret = "synthetic-secondary-quake-key"
    monkeypatch.delenv("FXAPK_QUAKE_KEY", raising=False)
    monkeypatch.setenv("FXAPK_QUAKE_KEY2", secret)

    class _CaptureSession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

        def post(self, *args, **kwargs):  # noqa: ANN002, ANN003
            self.headers = dict(kwargs.get("headers") or {})
            return _Response({"code": 0, "data": []})

    session = _CaptureSession()
    result = QuakePassiveEnricher(session=session).enrich(_ip())

    assert result.ok is True
    assert session.headers == {"X-QuakeToken": secret}


def test_http_200_provider_error_envelope_is_failed_and_sanitized(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("FXAPK_FOFA_KEY", "synthetic-secret-value")

    class _ErrorSession:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return _Response({"error": True, "errmsg": "COOKIE-SENTINEL"})

    result = FofaPassiveEnricher(session=_ErrorSession()).enrich(_ip())
    rendered = json.dumps(result.data, ensure_ascii=False) + str(result.error)

    assert result.ok is False
    assert result.data["_source_status"] == "failed"
    assert "COOKIE-SENTINEL" not in rendered


@pytest.mark.parametrize(
    ("adapter", "env_name", "payload"),
    [
        (
            QuakePassiveEnricher(),
            "FXAPK_QUAKE_KEY",
            {"code": 401, "message": "COOKIE-SENTINEL"},
        ),
        (
            HunterPassiveEnricher(),
            "FXAPK_HUNTER_KEY",
            {"code": 401, "message": "COOKIE-SENTINEL"},
        ),
    ],
)
def test_provider_specific_error_codes_are_failed_and_sanitized(
    monkeypatch,
    adapter,
    env_name: str,
    payload: dict,
) -> None:  # noqa: ANN001
    monkeypatch.setenv(env_name, "synthetic-secret-value")

    class _ProviderErrorSession:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return _Response(payload)

        def post(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return _Response(payload)

    adapter._http = _ProviderErrorSession()
    result = adapter.enrich(_ip())
    rendered = json.dumps(result.data, ensure_ascii=False) + str(result.error)

    assert result.ok is False
    assert result.data["_source_status"] == "failed"
    assert "COOKIE-SENTINEL" not in rendered


@pytest.mark.parametrize(
    ("status_code", "ok", "source_status", "error_type"),
    [
        (404, True, "no_record", "http_404"),
        (401, False, "failed", "http_401"),
        (403, False, "failed", "http_403"),
        (429, False, "failed", "http_429"),
    ],
)
def test_http_statuses_are_classified_without_response_text(
    monkeypatch,
    status_code: int,
    ok: bool,
    source_status: str,
    error_type: str,
) -> None:  # noqa: ANN001
    secret = "synthetic-secret-value"
    monkeypatch.setenv("FXAPK_FOFA_KEY", secret)

    class _HttpErrorSession:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            response = _Response({}, status_code=status_code)
            error = requests.HTTPError(f"request failed with {secret}")
            error.response = response  # type: ignore[assignment]
            raise error

    result = FofaPassiveEnricher(session=_HttpErrorSession()).enrich(_ip())
    rendered = json.dumps(result.data, ensure_ascii=False) + str(result.error)

    assert result.ok is ok
    assert result.data["_source_status"] == source_status
    assert result.data["_error_type"] == error_type
    assert secret not in rendered


def test_timeout_is_classified_without_exception_text(monkeypatch) -> None:  # noqa: ANN001
    secret = "synthetic-secret-value"
    monkeypatch.setenv("FXAPK_FOFA_KEY", secret)

    class _TimeoutSession:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            raise requests.Timeout(f"timeout with {secret}")

    result = FofaPassiveEnricher(session=_TimeoutSession()).enrich(_ip())
    rendered = json.dumps(result.data, ensure_ascii=False) + str(result.error)

    assert result.ok is False
    assert result.data["_source_status"] == "failed"
    assert result.data["_error_type"] == "timeout"
    assert secret not in rendered


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


def test_all_multisource_adapters_are_registered_for_runtime_discovery() -> None:
    from apkscan.core.registry import discover_enrichers

    expected = {enricher.name for enricher in configured_case_close_enrichers()}
    discovered = {enricher.name for enricher in discover_enrichers()}

    assert expected <= discovered


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


# ── 代理感知：境内源绕系统代理 + 出口溯源标注 ─────────────────────────────────
def test_hunter_domestic_source_bypasses_system_proxy() -> None:
    """★境内直连源（hunter）强制 trust_env=False——绕系统/环境代理（用户常开境外代理→hunter 403）；
    国际源保持默认（随系统代理）。"""
    assert HunterPassiveEnricher()._http.trust_env is False
    assert VirusTotalPassiveEnricher()._http.trust_env is True


def test_egress_label_reflects_bypass_and_proxy_env(monkeypatch) -> None:  # noqa: ANN001
    """出口标注：bypass 源恒 'direct'；国际源随系统代理——配了代理即 'system_proxy'，否则 'direct'。"""
    assert HunterPassiveEnricher()._egress_label() == "direct"
    intl = RipeStatBgpEnricher()
    monkeypatch.setattr("urllib.request.getproxies", lambda: {})
    assert intl._egress_label() == "direct"
    monkeypatch.setattr("urllib.request.getproxies", lambda: {"https": "http://127.0.0.1:7890"})
    assert intl._egress_label() == "system_proxy"


def test_enrich_records_via_on_success_and_failure(monkeypatch) -> None:  # noqa: ANN001
    """每条结果记 _via 出口（供报告溯源"此结果来自哪个出口"）；_via 是 metadata，不把空结果误判成 hit。"""
    monkeypatch.setattr("urllib.request.getproxies", lambda: {})
    hit = RipeStatBgpEnricher(session=_RipeSession()).enrich(_ip())
    assert hit.ok and hit.data["_via"] == "direct" and hit.data["_source_status"] == "hit"
    fail = RipeStatBgpEnricher(session=_FailingSession("x")).enrich(_ip())
    assert not fail.ok and fail.data["_via"] == "direct"

    class _EmptyRipe:
        def get(self, url, **kwargs):  # noqa: ANN001, ANN003
            return _Response({"data": {}})
    empty = RipeStatBgpEnricher(session=_EmptyRipe()).enrich(_ip())
    assert empty.ok and empty.data["_via"] == "direct" and empty.data["_source_status"] == "no_record"
