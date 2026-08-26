from __future__ import annotations

import json
import socket
from collections.abc import Iterator, Mapping

import pytest
import requests

from apkscan.core.enrichment import enrich_selected_targets, safe_error_type
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher
from apkscan.enrichers.multisource import (
    AbuseIpDbPassiveEnricher,
    CensysPassiveEnricher,
    FofaPassiveEnricher,
    HunterPassiveEnricher,
    OtxPassiveEnricher,
    QuakePassiveEnricher,
    RipeStatBgpEnricher,
    SourceOutcome,
    _fold_routing_history,
    _normalize_abuse_contacts,
    _normalize_ripestat_whois,
    _ripestat_asn,
    _routing_prefix_relation,
    UrlscanPassiveEnricher,
    VirusTotalPassiveEnricher,
    ZoomEyePassiveEnricher,
    _safe_error_type,
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


class _MalformedDataEnricher(_CaseOnlyEnricher):
    name = "malformed_data_fake"

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls += 1
        return EnrichmentResult(provider=self.name, ok=True, data=None)  # type: ignore[arg-type]


class _EmptySuccessfulEnricher(_CaseOnlyEnricher):
    name = "empty_success_fake"

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls += 1
        return EnrichmentResult(provider=self.name, ok=True, data={})


class _FollowingValidEnricher(_CaseOnlyEnricher):
    name = "following_valid_fake"


class _FalseWithPayloadEnricher(_CaseOnlyEnricher):
    name = "false_with_payload_fake"

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls += 1
        return EnrichmentResult(
            provider=self.name,
            ok=False,
            data={"answer": "must-not-become-a-hit"},
        )


class _InvalidObjectResultEnricher(_CaseOnlyEnricher):
    name = "invalid_object_fake"

    def enrich(self, ep: Endpoint) -> object:
        self.calls += 1
        return object()


class _InvalidPayloadEnricher(_CaseOnlyEnricher):
    name = "invalid_payload_fake"

    def __init__(self, value: object) -> None:
        super().__init__()
        self.value = value

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls += 1
        return EnrichmentResult(provider=self.name, ok=True, data={"value": self.value})


class _RawPayloadEnricher(_CaseOnlyEnricher):
    name = "raw_payload_fake"

    def __init__(self, data: dict[str, object]) -> None:
        super().__init__()
        self.data = data

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls += 1
        return EnrichmentResult(provider=self.name, ok=True, data=self.data)


class _ExplodingMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise RuntimeError("mapping exploded")

    def __iter__(self) -> Iterator[str]:
        yield "value"

    def __len__(self) -> int:
        return 1


class _MappingPayloadEnricher(_CaseOnlyEnricher):
    name = "mapping_payload_fake"

    def __init__(self, data: Mapping[object, object]) -> None:
        super().__init__()
        self.data = data

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls += 1
        return EnrichmentResult(provider=self.name, ok=True, data=self.data)  # type: ignore[arg-type]


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


def test_malformed_provider_data_records_failed_source_outcome() -> None:
    endpoint = _ip()
    enricher = _MalformedDataEnricher()

    enrich_selected_targets(
        [endpoint],
        [enricher],
        mode="passive",
        include_case_close=True,
    )

    assert enricher.calls == 1
    assert endpoint.enrichment["source_status"]["malformed_data_fake"] == {
        "status": "failed",
        "error_type": "invalid_result_data",
    }


def test_generic_successful_empty_provider_is_no_record_not_note_hit() -> None:
    endpoint = _ip()
    enricher = _EmptySuccessfulEnricher()

    enrich_selected_targets(
        [endpoint],
        [enricher],
        mode="passive",
        include_case_close=True,
    )

    assert "empty_success_fake" not in endpoint.enrichment
    assert endpoint.enrichment["source_status"]["empty_success_fake"] == {
        "status": "no_record"
    }


def test_provider_ok_false_cannot_become_a_hit_from_payload_values() -> None:
    endpoint = _ip()
    provider = _FalseWithPayloadEnricher()

    stats = enrich_selected_targets(
        [endpoint], [provider], mode="passive", include_case_close=True
    )

    assert endpoint.enrichment["source_status"][provider.name] == {
        "status": "failed",
        "error_type": "provider_reported_failure",
    }
    assert provider.name not in endpoint.enrichment
    assert stats == [
        {
            "provider": provider.name,
            "attempted": 1,
            "ok": 0,
            "failed": 1,
            "typical_error": "provider_reported_failure",
        }
    ]


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(_InvalidObjectResultEnricher(), id="arbitrary-result-object"),
        pytest.param(_InvalidPayloadEnricher(float("nan")), id="nan"),
        pytest.param(_InvalidPayloadEnricher(float("inf")), id="infinity"),
    ],
)
def test_invalid_provider_result_is_typed_failed_and_next_provider_continues(
    bad: _CaseOnlyEnricher,
) -> None:
    endpoint = _ip()
    following = _FollowingValidEnricher()

    enrich_selected_targets(
        [endpoint],
        [bad, following],
        mode="passive",
        include_case_close=True,
    )

    assert endpoint.enrichment["source_status"][bad.name]["status"] == "failed"
    assert endpoint.enrichment["source_status"][bad.name]["error_type"].startswith(
        "invalid_result"
    )
    assert bad.name not in endpoint.enrichment
    assert endpoint.enrichment["source_status"][following.name] == {"status": "hit"}
    assert endpoint.enrichment[following.name] == {"ip": endpoint.value}


def test_cyclic_provider_payload_is_typed_failed_and_next_provider_continues() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    endpoint = _ip()
    bad = _InvalidPayloadEnricher(cyclic)
    following = _FollowingValidEnricher()

    enrich_selected_targets(
        [endpoint],
        [bad, following],
        mode="passive",
        include_case_close=True,
    )

    assert endpoint.enrichment["source_status"][bad.name] == {
        "status": "failed",
        "error_type": "invalid_result_payload",
    }
    assert endpoint.enrichment["source_status"][following.name] == {"status": "hit"}


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({1: "ambiguous-key"}, id="non-string-key"),
        pytest.param(_ExplodingMapping(), id="mapping-runtime-error"),
    ],
)
def test_non_json_mapping_is_typed_failed_and_next_provider_continues(
    payload: Mapping[object, object],
) -> None:
    endpoint = _ip()
    bad = _MappingPayloadEnricher(payload)
    following = _FollowingValidEnricher()

    enrich_selected_targets(
        [endpoint], [bad, following], mode="passive", include_case_close=True
    )

    assert endpoint.enrichment["source_status"][bad.name] == {
        "status": "failed",
        "error_type": "invalid_result_payload",
    }
    assert endpoint.enrichment["source_status"][following.name] == {"status": "hit"}


def test_provider_payload_is_deep_copied_at_the_boundary() -> None:
    nested: dict[str, object] = {"items": ["before"]}
    endpoint = _ip()
    provider = _InvalidPayloadEnricher(nested)

    enrich_selected_targets(
        [endpoint], [provider], mode="passive", include_case_close=True
    )
    nested["items"] = ["after"]

    assert endpoint.enrichment[provider.name] == {"value": {"items": ["before"]}}


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (
            {"_source_status": "invented", "answer": "looks-like-a-hit"},
            {"status": "failed", "error_type": "invalid_source_status"},
        ),
        ({"_error_type": "timeout", "_via": "direct"}, {"status": "no_record"}),
    ],
)
def test_provider_control_fields_cannot_create_a_hit(
    data: dict[str, object], expected: dict[str, str]
) -> None:
    endpoint = _ip()
    provider = _RawPayloadEnricher(data)

    enrich_selected_targets(
        [endpoint], [provider], mode="passive", include_case_close=True
    )

    assert endpoint.enrichment["source_status"][provider.name] == expected


@pytest.mark.parametrize("marker", ["failed", "invented"])
def test_failed_or_invalid_status_discards_payload_and_cannot_increment_ok(
    marker: str,
) -> None:
    endpoint = _ip()
    provider = _RawPayloadEnricher(
        {"_source_status": marker, "answer": "must-not-enter-report"}
    )

    stats = enrich_selected_targets(
        [endpoint], [provider], mode="passive", include_case_close=True
    )

    assert provider.name not in endpoint.enrichment
    assert endpoint.enrichment["source_status"][provider.name]["status"] == "failed"
    assert stats[0]["ok"] == 0
    assert stats[0]["failed"] == 1


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


def test_safe_error_type_distinguishes_request_encoding_from_parse() -> None:
    """★UnicodeEncodeError 是 ValueError 子类，但语义是请求侧编码失败（非 latin-1 的 key/参数
    塞进 HTTP 头），不能误报成 parse_error——否则把病根指向"响应坏"而非"入参被污染"。"""
    try:
        "深".encode("latin-1")  # 触发真实的 UnicodeEncodeError
    except UnicodeEncodeError as exc:
        assert _safe_error_type(exc) == "request_encoding_error"
    else:
        pytest.fail("预期 UnicodeEncodeError 未抛出")
    # 真·解析错误仍归 parse_error（普通 ValueError）。
    assert _safe_error_type(ValueError("bad json")) == "parse_error"
    # 超时 / 其它类型不受影响。
    assert _safe_error_type(requests.Timeout()) == "timeout"


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

    # ★等值断言而非子集：子集写法下「新 provider 忘了加进显式清单」不会变红，
    #   守卫等于失效。多一个少一个都必须让这条测试红。
    assert names == {
        "ripestat_bgp",
        "fofa",
        "quake",
        "hunter",
        "zoomeye",
        "censys",
        "virustotal",
        "otx",
        "urlscan",
        "abuseipdb",
    }
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


# ── 任务 1a：AbuseIPDB 举报信誉（仅 IP，被动，case-close） ──────────────────
def _abuseipdb_payload(**overrides: object) -> dict:
    """AbuseIPDB /api/v2/check 的响应形状（字段名照官方 camelCase）。"""
    data: dict[str, object] = {
        "ipAddress": "198.51.100.10",
        "isPublic": True,
        "abuseConfidenceScore": 100,
        "countryCode": "SC",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting Ltd",
        "domain": "example.com",
        "totalReports": 42,
        "numDistinctUsers": 7,
        "lastReportedAt": "2026-07-01T12:00:00+00:00",
        "isTor": False,
        "isWhitelisted": False,
    }
    data.update(overrides)
    return {"data": data}


def test_abuseipdb_uses_the_reserved_env_var_name() -> None:
    """★必须复用仓库早已预留的 FXAPK_ABUSEIPDB_KEY（.env.example / COMPANION-TOOLS 已写），
    另起变量名会让用户配了 key 却不生效。"""
    assert AbuseIpDbPassiveEnricher.required_env == ("FXAPK_ABUSEIPDB_KEY",)


def test_abuseipdb_is_passive_ip_only_case_close() -> None:
    adapter = AbuseIpDbPassiveEnricher()
    assert adapter.name == "abuseipdb"
    assert adapter.applies_to == ["ip"]
    assert adapter.case_close_only is True
    assert adapter.active is False
    # 国际源：随系统代理（境内直连只对 hunter 那类源）。
    assert adapter._http.trust_env is True


def test_abuseipdb_sends_key_header_and_bounded_window(monkeypatch) -> None:  # noqa: ANN001
    secret = "synthetic-abuseipdb-key"
    monkeypatch.setenv("FXAPK_ABUSEIPDB_KEY", secret)

    class _CaptureSession:
        def __init__(self) -> None:
            self.url = ""
            self.headers: dict[str, str] = {}
            self.params: dict[str, object] = {}

        def get(self, url: str, **kwargs):  # noqa: ANN003
            self.url = url
            self.headers = dict(kwargs.get("headers") or {})
            self.params = dict(kwargs.get("params") or {})
            return _Response(_abuseipdb_payload())

    session = _CaptureSession()
    result = AbuseIpDbPassiveEnricher(session=session).enrich(_ip())

    assert result.ok is True
    assert session.url == "https://api.abuseipdb.com/api/v2/check"
    assert session.headers["Key"] == secret
    assert session.headers["Accept"] == "application/json"
    assert session.params["ipAddress"] == "198.51.100.10"
    # 回溯窗口必须有界，否则会把陈年举报当现状。
    assert isinstance(session.params["maxAgeInDays"], int)
    assert 0 < int(session.params["maxAgeInDays"]) <= 365


def test_abuseipdb_normalizes_to_snake_case_reputation_fields() -> None:
    normalized = AbuseIpDbPassiveEnricher()._normalize(_abuseipdb_payload(), _ip())

    assert normalized["abuse_confidence_score"] == 100
    assert normalized["total_reports"] == 42
    assert normalized["distinct_reporters"] == 7
    assert normalized["country_code"] == "SC"
    assert normalized["isp"] == "Example Hosting Ltd"
    assert normalized["usage_type"] == "Data Center/Web Hosting/Transit"
    assert normalized["last_reported_at"] == "2026-07-01T12:00:00+00:00"
    assert normalized["is_tor"] is False
    assert normalized["source"] == "abuseipdb"


def test_abuseipdb_drops_reporter_free_text() -> None:
    """★举报正文是第三方未核实的自由文本（可能含 PII），一律不落盘。"""
    payload = _abuseipdb_payload()
    payload["data"]["reports"] = [  # type: ignore[index]
        {"comment": "COOKIE-SENTINEL 举报正文", "reporterId": 999, "reporterCountryName": "X"}
    ]

    normalized = AbuseIpDbPassiveEnricher()._normalize(payload, _ip())

    assert "COOKIE-SENTINEL" not in json.dumps(normalized, ensure_ascii=False)
    assert "reports" not in normalized


def test_abuseipdb_bounds_oversized_text() -> None:
    oversized = "x" * 1_000
    normalized = AbuseIpDbPassiveEnricher()._normalize(
        _abuseipdb_payload(isp=oversized, usageType=oversized), _ip()
    )

    assert len(str(normalized["isp"])) == 500
    assert len(str(normalized["usage_type"])) == 500


def test_abuseipdb_empty_payload_is_no_record(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("FXAPK_ABUSEIPDB_KEY", "synthetic-abuseipdb-key")

    class _EmptySession:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            return _Response({"data": {}})

    result = AbuseIpDbPassiveEnricher(session=_EmptySession()).enrich(_ip())

    assert result.ok is True
    assert result.data["_source_status"] == "no_record"


def test_abuseipdb_invalid_key_is_failed_not_no_record(monkeypatch) -> None:  # noqa: ANN001
    """★401（key 配错）必须记 failed。若被兜成 no_record，就等于把「没查成」
    伪装成「查过、没有记录」——那是造证据。"""
    secret = "synthetic-abuseipdb-key"
    monkeypatch.setenv("FXAPK_ABUSEIPDB_KEY", secret)

    class _UnauthorizedSession:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            response = requests.Response()
            response.status_code = 401
            error = requests.HTTPError("401 Unauthorized")
            error.response = response  # type: ignore[assignment]
            raise error

    result = AbuseIpDbPassiveEnricher(session=_UnauthorizedSession()).enrich(_ip())
    rendered = json.dumps(result.data, ensure_ascii=False) + str(result.error)

    assert result.ok is False
    assert result.data["_source_status"] == "failed"
    assert secret not in rendered


def test_abuseipdb_http_error_status_is_never_normalized_as_a_hit(monkeypatch) -> None:  # noqa: ANN001
    """★HTTP 错误状态必须经 ``raise_for_status()`` 变成 failed，**与响应体长什么样无关**。

    这条与上一条互补：上一条的假会话在 ``get()`` 里就抛，验的是传输层异常；本条**正常返回**
    一个 401 响应、且响应体是「看起来能正常归一化」的形状——若实现漏了 ``raise_for_status()``，
    这个 401 就会被当成命中落进证据。变异验证第 3 条正是靠本条才 kill。
    """
    monkeypatch.setenv("FXAPK_ABUSEIPDB_KEY", "synthetic-abuseipdb-key")

    class _UnauthorizedWithBodySession:
        """返回 401，但响应体故意是可正常归一化的 payload（不含 errors）。"""

        def get(self, url: str, **kwargs):  # noqa: ANN003
            response = requests.Response()
            response.status_code = 401
            payload = _abuseipdb_payload()

            class _Wrapped:
                status_code = 401

                @staticmethod
                def raise_for_status() -> None:
                    error = requests.HTTPError("401 Unauthorized")
                    error.response = response  # type: ignore[assignment]
                    raise error

                @staticmethod
                def json() -> dict:
                    return payload

            return _Wrapped()

    result = AbuseIpDbPassiveEnricher(session=_UnauthorizedWithBodySession()).enrich(_ip())

    assert result.ok is False, "401 绝不能被当成命中"
    assert result.data["_source_status"] == "failed"
    assert "abuse_confidence_score" not in result.data


def test_abuseipdb_provider_declared_error_is_failed(monkeypatch) -> None:  # noqa: ANN001
    """AbuseIPDB 在 HTTP 200 里用 ``errors`` 报错（如超配额），不能当命中。"""
    monkeypatch.setenv("FXAPK_ABUSEIPDB_KEY", "synthetic-abuseipdb-key")

    class _QuotaSession:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            return _Response({"errors": [{"detail": "Daily rate limit exceeded", "status": 429}]})

    result = AbuseIpDbPassiveEnricher(session=_QuotaSession()).enrich(_ip())

    assert result.ok is False
    assert result.data["_source_status"] == "failed"


def test_abuseipdb_failure_never_leaks_the_key(monkeypatch) -> None:  # noqa: ANN001
    secret = "synthetic-abuseipdb-key"
    monkeypatch.setenv("FXAPK_ABUSEIPDB_KEY", secret)

    result = AbuseIpDbPassiveEnricher(session=_FailingSession(secret)).enrich(_ip())
    rendered = json.dumps(result.data, ensure_ascii=False) + str(result.error)

    assert result.ok is False
    assert secret not in rendered


def test_abuseipdb_without_key_is_disabled_not_failed(monkeypatch) -> None:  # noqa: ANN001
    """没配 key → disabled（未启用），不是 failed（查失败）。两者结案含义不同。"""
    monkeypatch.delenv("FXAPK_ABUSEIPDB_KEY", raising=False)
    endpoint = _ip()

    enrich_selected_targets(
        [endpoint],
        [AbuseIpDbPassiveEnricher()],
        mode="passive",
        include_case_close=True,
    )

    assert endpoint.enrichment["source_status"]["abuseipdb"]["status"] == "disabled"


def test_abuseipdb_is_skipped_by_ordinary_analysis(monkeypatch) -> None:  # noqa: ANN001
    """case_close_only：普通 analyze 不得触碰它（配额只花在有界的结案目标集上）。"""
    monkeypatch.setenv("FXAPK_ABUSEIPDB_KEY", "synthetic-abuseipdb-key")

    class _ExplodingSession:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            raise AssertionError("普通 analyze 路径不该请求 abuseipdb")

    endpoint = _ip()
    enrich_selected_targets(
        [endpoint],
        [AbuseIpDbPassiveEnricher(session=_ExplodingSession())],
        mode="passive",
        include_case_close=False,
    )

    assert "abuseipdb" not in endpoint.enrichment


def test_abuseipdb_reaches_the_case_close_target_and_status_map(monkeypatch) -> None:  # noqa: ANN001
    """★信号必须接线：结案路径要真把 abuseipdb 写进 enrichment 与 source_status。"""
    monkeypatch.setenv("FXAPK_ABUSEIPDB_KEY", "synthetic-abuseipdb-key")

    class _HitSession:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            return _Response(_abuseipdb_payload())

    endpoint = _ip()
    enrich_selected_targets(
        [endpoint],
        [AbuseIpDbPassiveEnricher(session=_HitSession())],
        mode="passive",
        include_case_close=True,
    )

    assert endpoint.enrichment["abuseipdb"]["abuse_confidence_score"] == 100
    assert endpoint.enrichment["source_status"]["abuseipdb"]["status"] == "hit"


def test_abuseipdb_does_not_apply_to_domains() -> None:
    """AbuseIPDB 只查 IP；域名端点不该被它标状态（否则结案面出现查不了的源）。"""
    domain = Endpoint(value="api.example.com", kind="domain", is_suspicious=True)

    enrich_selected_targets(
        [domain],
        [AbuseIpDbPassiveEnricher()],
        mode="passive",
        include_case_close=True,
    )

    assert "abuseipdb" not in (domain.enrichment.get("source_status") or {})


def test_abuseipdb_is_not_wired_into_five_layer_attribution() -> None:
    """★有意不进五层归属：``isp`` 是 ISP 名而非 BGP AS 组织名，硬映射进 origin_network
    等于造证据。信誉分只作旁证留在 enrichment。"""
    from apkscan.core.closure.layers import _passive_hosting_evidence

    providers, services, locations = _passive_hosting_evidence(
        {"abuseipdb": {"isp": "Example Hosting Ltd", "country_code": "SC", "source": "abuseipdb"}}
    )

    assert providers == []
    assert services == []
    assert locations == []


# --------------------------------------------------------------------------- #
# RIPEstat 扩展：routing-history / whois / abuse-contact-finder
# 所有示例地址一律用 RFC 5737 文档保留段，绝不出现真实案件值。
# --------------------------------------------------------------------------- #


class _RipeFullSession:
    """覆盖全部五个 data call 的成功路径。"""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def get(self, url: str, **kwargs):  # noqa: ANN003
        self.urls.append(url)
        if "prefix-overview" in url:
            return _Response(
                {
                    "data": {
                        "resource": "100.64.100.0/24",
                        "asns": [{"asn": "64500", "holder": "Example Network Ltd"}],
                    }
                }
            )
        if "asn-neighbours" in url:
            return _Response({"data": {"neighbours": [{"asn": "64501", "type": "left"}]}})
        if "routing-history" in url:
            return _Response(
                {
                    "data": {
                        "latest_max_ff_peers": {"v4": 100, "v6": 200},
                        "by_origin": [
                            {
                                "origin": "64500",
                                "prefixes": [
                                    {
                                        "prefix": "100.64.100.0/24",
                                        "timelines": [
                                            {
                                                "starttime": "2024-03-01T00:00:00",
                                                "endtime": "2024-03-31T23:59:59",
                                                "full_peers_seeing": 50.0,
                                            },
                                            {
                                                "starttime": "2024-01-01T00:00:00",
                                                "endtime": "2024-01-31T23:59:59",
                                                "full_peers_seeing": 80.0,
                                            },
                                        ],
                                    }
                                ],
                            },
                            {
                                "origin": "64510",
                                "prefixes": [
                                    {
                                        "prefix": "100.64.0.0/16",
                                        "timelines": [
                                            {
                                                "starttime": "2010-01-01T00:00:00",
                                                "endtime": "2010-12-31T23:59:59",
                                                "full_peers_seeing": 10.0,
                                            }
                                        ],
                                    }
                                ],
                            },
                        ],
                    }
                }
            )
        if "whois" in url:
            return _Response(
                {
                    "data": {
                        "authorities": ["APNIC"],
                        "records": [
                            [
                                {"key": "inetnum", "value": "100.64.100.0/24"},
                                {"key": "netname", "value": "EXAMPLE-NET"},
                                {"key": "descr", "value": "Example Cloud &amp; Data Co."},
                                {"key": "descr", "value": "No.1 Example Road"},
                                {"key": "country", "value": "CN"},
                                {"key": "tech-c", "value": "TC1-AP"},
                            ]
                        ],
                    }
                }
            )
        if "abuse-contact-finder" in url:
            return _Response(
                {"data": {"abuse_contacts": ["abuse@example.invalid"], "authoritative_rir": "APNIC"}}
            )
        raise AssertionError(f"unexpected URL: {url}")


def test_ripestat_routing_history_separates_supernet_from_effective() -> None:
    """超网宣告不得混进本网段的归属史——否则调证函会发给上游大段的持有者。"""
    result = RipeStatBgpEnricher(session=_RipeFullSession()).enrich(_ip())

    assert result.ok is True
    assert result.data["routing_history_origins"] == [64500]
    history = result.data["routing_history"]
    assert [item["origin_asn"] for item in history] == [64500]
    supernets = result.data["routing_history_supernets"]
    assert [item["origin_asn"] for item in supernets] == [64510]


def test_ripestat_routing_origin_change_ignores_supernet_churn() -> None:
    """只有超网换过手时，本网段不算发生归属变更。"""
    result = RipeStatBgpEnricher(session=_RipeFullSession()).enrich(_ip())

    assert result.data["routing_origin_changed"] is False


def test_ripestat_routing_history_merges_timelines_per_origin() -> None:
    """同一 origin 的分段时间片合并成一个首见/末见区间，可见度取最大比例。"""
    result = RipeStatBgpEnricher(session=_RipeFullSession()).enrich(_ip())

    entry = result.data["routing_history"][0]
    assert entry["first_seen"] == "2024-01-01T00:00:00"
    assert entry["last_seen"] == "2024-03-31T23:59:59"
    assert entry["max_visibility_ratio"] == pytest.approx(0.8)


def test_ripestat_whois_and_abuse_contacts_are_normalized() -> None:
    result = RipeStatBgpEnricher(session=_RipeFullSession()).enrich(_ip())

    assert result.data["whois_network"] == "100.64.100.0/24"
    assert result.data["whois_netname"] == "EXAMPLE-NET"
    # HTML 实体还原，且多条同名 descr 全部保留
    assert result.data["registered_organization"] == "Example Cloud & Data Co."
    assert result.data["registration_descriptions"] == [
        "Example Cloud & Data Co.",
        "No.1 Example Road",
    ]
    assert result.data["registration_country"] == "CN"
    assert result.data["authoritative_rirs"] == ["apnic"]
    assert result.data["abuse_complaint_contacts"] == ["abuse@example.invalid"]
    assert result.data["abuse_contact_authoritative_rir"] == "apnic"


def test_ripestat_auxiliary_failures_never_drop_primary_result() -> None:
    """三个辅助 data call 全挂，主结果（prefix-overview）必须完好。"""

    class _OnlyPrimarySession:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            if "prefix-overview" in url:
                return _Response({"data": {"resource": "100.64.100.0/24", "asns": [64500]}})
            raise RuntimeError("auxiliary down")

    result = RipeStatBgpEnricher(session=_OnlyPrimarySession()).enrich(_ip())

    assert result.ok is True
    assert result.data["origin_asn"] == 64500
    assert result.data["routing_history_lookup_status"] == "failed"
    assert result.data["whois_lookup_status"] == "failed"
    assert result.data["abuse_contact_lookup_status"] == "failed"
    assert "routing_history" not in result.data


def test_ripestat_asn_rejects_bool_and_out_of_range() -> None:
    """ASN 归一的取值边界。bool 当前由 ``str()`` 挡住（``int("True")`` 抛 ValueError），
    显式检查是防 ``str()`` 被移除的第二道闸，故此处只锁对外行为、不锁实现路径。"""
    assert _ripestat_asn("64500") == 64500
    assert _ripestat_asn(True) is None
    assert _ripestat_asn(False) is None
    assert _ripestat_asn(0) is None
    assert _ripestat_asn(-1) is None
    assert _ripestat_asn(4_294_967_295) is None
    assert _ripestat_asn("not-an-asn") is None
    assert _ripestat_asn(None) is None


def test_routing_prefix_relation_classifies_by_containment() -> None:
    import ipaddress

    reference = ipaddress.ip_network("100.64.100.0/24")
    assert _routing_prefix_relation(ipaddress.ip_network("100.64.100.0/24"), reference) == "exact"
    assert (
        _routing_prefix_relation(ipaddress.ip_network("100.64.100.128/25"), reference)
        == "more_specific"
    )
    assert _routing_prefix_relation(ipaddress.ip_network("100.64.0.0/16"), reference) == "supernet"
    assert _routing_prefix_relation(ipaddress.ip_network("100.65.0.0/24"), reference) is None
    # 跨 IP 版本不得相互判定
    assert _routing_prefix_relation(ipaddress.ip_network("2001:db8::/32"), reference) is None


def test_whois_contact_fields_never_become_registrant() -> None:
    """★取证纪律：abuse/tech-c/admin-c 是上游 IDC 或代理商的联系人，
    拿它当网段持有方会把调证函发错对象。"""
    data = {
        "records": [
            [
                {"key": "inetnum", "value": "100.64.100.0/24"},
                {"key": "abuse-c", "value": "Upstream IDC Abuse Desk"},
                {"key": "tech-c", "value": "Reseller Tech Contact"},
                {"key": "admin-c", "value": "Reseller Admin Contact"},
            ]
        ]
    }

    normalized = _normalize_ripestat_whois(data)

    assert "registered_organization" not in normalized
    assert normalized["whois_network"] == "100.64.100.0/24"


def test_whois_normalizes_arin_style_field_names() -> None:
    """ARIN 用 NetRange/NetName/Organization/RegDate，与 APNIC 那套完全不同名。"""
    data = {
        "authorities": ["ARIN"],
        "records": [
            [
                {"key": "CIDR", "value": "203.0.113.0/24"},
                {"key": "NetName", "value": "EXAMPLE-ARIN"},
                {"key": "Organization", "value": "Example Corp (EXC)"},
                {"key": "RegDate", "value": "2023-12-28"},
            ]
        ],
    }

    normalized = _normalize_ripestat_whois(data)

    assert normalized["whois_network"] == "203.0.113.0/24"
    assert normalized["whois_netname"] == "EXAMPLE-ARIN"
    assert normalized["registered_organization"] == "Example Corp (EXC)"
    assert normalized["registration_date"] == "2023-12-28"
    assert normalized["authoritative_rirs"] == ["arin"]


def test_fold_routing_history_marks_truncation() -> None:
    """超上限必须显式标 truncated，绝不静默截断（静默截断会被读成"历史就这些"）。"""
    origins = [
        {
            "origin": str(64500 + index),
            "prefixes": [
                {
                    "prefix": "100.64.100.0/24",
                    "timelines": [{"starttime": "2024-01-01T00:00:00", "endtime": "2024-01-02T00:00:00"}],
                }
            ],
        }
        for index in range(300)
    ]

    folded = _fold_routing_history({"by_origin": origins}, "100.64.100.0/24")

    assert folded["truncated"] is True
    assert len(folded["origins"]) <= 256


def test_fold_routing_history_survives_malformed_payload() -> None:
    """字段缺失/类型错乱不得抛异常——富化失败绝不能炸结案流程。"""
    folded = _fold_routing_history(
        {
            "by_origin": [
                "not-a-dict",
                {"origin": None, "prefixes": []},
                {"origin": "64500", "prefixes": [{"prefix": "bad-prefix", "timelines": None}]},
                {
                    "origin": "64500",
                    "prefixes": [
                        {
                            "prefix": "100.64.100.0/24",
                            "timelines": [{"starttime": None, "full_peers_seeing": "NaN"}],
                        }
                    ],
                },
            ],
            "latest_max_ff_peers": {"v4": 0},
        },
        "100.64.100.0/24",
    )

    assert folded["origins"] == [64500]
    # 分母为 0 时不得产出比例字段（更不能抛 ZeroDivisionError）
    assert "max_visibility_ratio" not in folded["history"][0]


def test_fold_routing_history_without_reference_returns_empty() -> None:
    assert _fold_routing_history({"by_origin": []}, None) == {}


def test_abuse_contacts_dedupe_and_lowercase_rir() -> None:
    normalized = _normalize_abuse_contacts(
        {
            "abuse_contacts": ["a@example.invalid", "a@example.invalid", 123, None],
            "authoritative_rir": "RIPE",
        }
    )

    assert normalized["abuse_complaint_contacts"] == ["a@example.invalid"]
    assert normalized["abuse_contact_authoritative_rir"] == "ripe"


# --------------------------------------------------------------------------- #
# codex 复审挑出的 6 个问题的回归测试
# --------------------------------------------------------------------------- #


def test_routing_origin_changed_is_undetermined_when_truncated() -> None:
    """★codex#1：截断时"没看到第二个 origin"不等于"确定没换过手"。

    请求带 min_peers 阈值、结果又被截断，未处理部分仍可能有别的 origin，
    此时输出 False 会被读成"归属从未变更"这一确定结论。
    """
    origins = [
        {
            "origin": "64500",
            "prefixes": [
                {
                    "prefix": "100.64.100.0/24",
                    "timelines": [
                        {"starttime": "2024-01-01T00:00:00", "endtime": "2024-01-02T00:00:00"}
                    ],
                }
            ],
        }
    ] * 300

    class _TruncatedSession:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            if "prefix-overview" in url:
                return _Response(
                    {"data": {"resource": "100.64.100.0/24", "asns": [{"asn": "64500"}]}}
                )
            if "routing-history" in url:
                return _Response({"data": {"by_origin": origins}})
            raise RuntimeError("not needed")

    result = RipeStatBgpEnricher(session=_TruncatedSession()).enrich(_ip())

    assert result.data["routing_history_truncated"] is True
    assert "routing_origin_changed" not in result.data
    assert result.data["routing_origin_changed_status"] == "undetermined"
    # 判定依据的阈值须随结论落进报告，供复核结论强度
    assert result.data["routing_history_min_peers"] == 10


def test_routing_origin_changed_true_survives_truncation() -> None:
    """发现 ≥2 个 origin 这一侧是可靠的，截断也照样输出 True。"""
    entries = [
        {
            "origin": str(asn),
            "prefixes": [
                {
                    "prefix": "100.64.100.0/24",
                    "timelines": [
                        {"starttime": "2024-01-01T00:00:00", "endtime": "2024-01-02T00:00:00"}
                    ],
                }
            ],
        }
        for asn in range(64500, 64500 + 300)
    ]

    folded = _fold_routing_history({"by_origin": entries}, "100.64.100.0/24")

    assert folded["truncated"] is True
    assert len(folded["origins"]) > 1


def test_visibility_ratio_never_emits_non_finite() -> None:
    """★codex#2：极小分母会算出 inf，而 inf 会让核心层拒收整个 provider payload，
    把已经到手的主结果一起连坐丢掉。越界比例同样不可信（可见 peer 数不可能超过全表）。"""
    folded = _fold_routing_history(
        {
            "latest_max_ff_peers": {"v4": 1e-320},
            "by_origin": [
                {
                    "origin": "64500",
                    "prefixes": [
                        {
                            "prefix": "100.64.100.0/24",
                            "timelines": [
                                {
                                    "starttime": "2024-01-01T00:00:00",
                                    "endtime": "2024-01-02T00:00:00",
                                    "full_peers_seeing": 1e300,
                                }
                            ],
                        }
                    ],
                }
            ],
        },
        "100.64.100.0/24",
    )

    entry = folded["history"][0]
    assert "max_visibility_ratio" not in entry
    assert folded["visibility_degraded"] is True
    # 整条 payload 必须仍可 JSON 序列化（inf 会让 json.dumps(allow_nan=False) 抛）
    json.dumps(folded, allow_nan=False)


def test_visibility_ratio_rejects_above_one() -> None:
    folded = _fold_routing_history(
        {
            "latest_max_ff_peers": {"v4": 100},
            "by_origin": [
                {
                    "origin": "64500",
                    "prefixes": [
                        {
                            "prefix": "100.64.100.0/24",
                            "timelines": [
                                {
                                    "starttime": "2024-01-01T00:00:00",
                                    "endtime": "2024-01-02T00:00:00",
                                    "full_peers_seeing": 101,
                                }
                            ],
                        }
                    ],
                }
            ],
        },
        "100.64.100.0/24",
    )

    assert "max_visibility_ratio" not in folded["history"][0]
    assert folded["visibility_degraded"] is True


def test_auxiliary_failure_status_never_upgrades_no_record_to_hit() -> None:
    """★codex#3：主查询查无记录时，辅助端点的失败状态不得把结果撑成 hit——
    那等于把"没查到"伪装成"查到了"。"""

    class _EmptyPrimaryFailingAuxSession:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            if "prefix-overview" in url:
                return _Response({"data": {}})
            raise RuntimeError("auxiliary down")

    result = RipeStatBgpEnricher(session=_EmptyPrimaryFailingAuxSession()).enrich(_ip())

    assert result.ok is True
    assert result.data["_source_status"] == "no_record"
    assert result.data["routing_history_lookup_status"] == "failed"


def test_whois_truncation_is_reported() -> None:
    """★codex#4：whois 各层截断此前全部静默——"只有这些登记信息"会成为错误结论。"""
    data = {
        "records": [
            [{"key": "inetnum", "value": "100.64.100.0/24"}]
            + [{"key": "descr", "value": f"Example Line {index}"} for index in range(70)]
        ]
    }

    normalized = _normalize_ripestat_whois(data)

    assert normalized["whois_truncated"] is True
    assert len(normalized["registration_descriptions"]) == 32


def test_whois_authorities_are_bounded() -> None:
    """authorities 此前完全无上限——外部输入一律要有界。"""
    data = {
        "records": [[{"key": "inetnum", "value": "100.64.100.0/24"}]],
        "authorities": [f"rir{index}" for index in range(40)],
    }

    normalized = _normalize_ripestat_whois(data)

    assert len(normalized["authoritative_rirs"]) == 16
    assert normalized["whois_truncated"] is True


def test_abuse_contacts_truncation_is_reported() -> None:
    normalized = _normalize_abuse_contacts(
        {"abuse_contacts": [f"a{index}@example.invalid" for index in range(40)]}
    )

    assert len(normalized["abuse_complaint_contacts"]) == 32
    assert normalized["abuse_contacts_truncated"] is True


def test_whois_recognizes_inet6num() -> None:
    """★codex#5：RIPE/APNIC 的 IPv6 对象用 inet6num，此前归一结果为空。"""
    data = {
        "authorities": ["RIPE"],
        "records": [
            [
                {"key": "inet6num", "value": "2001:db8::/32"},
                {"key": "netname", "value": "EXAMPLE-V6"},
                {"key": "descr", "value": "Example IPv6 Holder"},
            ]
        ],
    }

    normalized = _normalize_ripestat_whois(data)

    assert normalized["whois_network"] == "2001:db8::/32"
    assert normalized["whois_netname"] == "EXAMPLE-V6"
    assert normalized["registered_organization"] == "Example IPv6 Holder"


def test_exactly_exhausted_timeline_budget_is_not_truncation() -> None:
    """★codex#6：恰好用满预算 ≠ 后面还有数据。"""
    folded = _fold_routing_history(
        {
            "by_origin": [
                {
                    "origin": "64500",
                    "prefixes": [
                        {
                            "prefix": "100.64.100.0/24",
                            "timelines": [
                                {"starttime": "2024-01-01T00:00:00", "endtime": "2024-01-02T00:00:00"}
                            ],
                        }
                    ],
                }
            ]
        },
        "100.64.100.0/24",
    )

    assert folded["truncated"] is False


def test_safe_error_type_classifies_builtin_timeout() -> None:
    """内置 TimeoutError 也归 timeout —— DoH / socket 那条路抛的是它，不是 requests.Timeout。"""
    assert safe_error_type(TimeoutError("https://canary.example.test/?key=SECRET")) == "timeout"


def test_safe_error_type_classifies_socket_timeout() -> None:
    """socket.timeout 同样归 timeout。

    3.10+ 里 socket.timeout 就是 TimeoutError 的别名，本条看似冗余——但它锁的是
    「socket 超时归 timeout」这条**契约**：将来别名关系若变，这条会先红。
    """
    assert safe_error_type(socket.timeout("/cases/CASE-CANARY")) == "timeout"
