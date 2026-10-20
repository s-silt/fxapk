"""ip/domain 端点值不符合 kind 时仍可加载，但不得作为富化查询目标；拼进 provider URL 时只能占一个 path segment。"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote, urlsplit

import pytest

import apkscan.enrichers._ipinfo as ipinfo_mod
import apkscan.enrichers.ip_rdap as ip_rdap_mod
import apkscan.enrichers.rdap as rdap_mod
import apkscan.enrichers.shodan as shodan_mod
from apkscan.core.enrichment import _enrich_endpoints
from apkscan.core.json_io import BoundedJsonError
from apkscan.core.models import Endpoint, EnrichmentResult, endpoint_value_matches_kind
from apkscan.core.registry import BaseEnricher
from apkscan.core.report_io import load_report
from apkscan.enrichers.ip_rdap import IpRdapEnricher
from apkscan.enrichers.multisource import (
    CensysPassiveEnricher,
    OtxPassiveEnricher,
    VirusTotalPassiveEnricher,
)
from apkscan.enrichers.rdap import RdapEnricher
from apkscan.enrichers.resource_profile import FofaHostProfileEnricher
from apkscan.enrichers.shodan import ShodanEnricher

_EVIL_IP = "100.64.0.1/../x?y=1#z"
_EVIL_DOMAIN = "a.example.com/../x?y=1#z"


def _write_report(tmp_path: Path, endpoints: list[dict[str, str]]) -> Path:
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps({"schema_version": "1.0", "endpoints": endpoints}),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("ip", "100.64.0.1/../../users/me?x=1#f"),
        ("domain", "a.example.com/../x"),
        ("domain", "a.example.com?x=1"),
        ("domain", "a.example.com#x"),
        ("ip", "fe80::1%eth0"),
    ],
)
def test_load_report_keeps_endpoint_value_that_does_not_match_kind(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, kind: str, value: str
) -> None:
    path = _write_report(tmp_path, [{"value": value, "kind": kind}])
    with caplog.at_level(logging.WARNING, logger="apkscan.core.report_io"):
        report = load_report(path)
    assert len(report.endpoints) == 1
    assert report.endpoints[0].value == value
    assert report.endpoints[0].kind == kind
    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    text = warnings[0].getMessage()
    assert value not in text
    assert text == "report 中有 1 个 ip/domain 端点的值不符合其 kind，已保留但富化时将跳过"


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("ip", "192.0.2.1"),
        ("ip", "2001:db8::1"),
        ("domain", "例子.example"),
        ("domain", "under_score.example"),
        ("url", "100.64.0.1/../x?y=1#z"),
    ],
)
def test_load_report_accepts_matching_endpoint_values(
    tmp_path: Path, kind: str, value: str
) -> None:
    report = load_report(_write_report(tmp_path, [{"value": value, "kind": kind}]))
    assert report.endpoints[0].value == value
    assert report.endpoints[0].kind == kind


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("ip", "100.64.0.1/../../users/me?x=1#f", False),
        ("domain", "a.example.com/../x", False),
        ("domain", "a.example.com?x=1", False),
        ("domain", "a.example.com#x", False),
        ("ip", "fe80::1%eth0", False),
        ("domain", "%s.example.com", False),
        ("domain", "/dir/file.json", False),
        ("ip", "192.0.2.1", True),
        ("ip", "2001:db8::1", True),
        ("domain", "例子.example", True),
        ("domain", "under_score.example", True),
        ("url", "100.64.0.1/../x?y=1#z", True),
    ],
)
def test_endpoint_value_matches_kind(kind: str, value: str, expected: bool) -> None:
    assert endpoint_value_matches_kind(value, kind) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("हिन्दी.example", True),
        ("例子.example", True),
        ("under_score.example", True),
        ("xn--j2bd4cyah0f.example", True),
        ("%s.example.com", False),
        ("/dir/file.json", False),
        ("a.example.com?x", False),
        ("a.example.com#x", False),
        ("a b.example", False),
        ("a..example", False),
        ("", False),
        ("a" * 64 + ".example", False),
        ("a\u0080.example", False),
        ("a\ud800.example", False),
        ("a\u202e.example", False),
        ("a\u2066.example", False),
        ("a\u200d.example", True),
    ],
)
def test_domain_rejection_keeps_url_structure(value: str, expected: bool) -> None:
    assert endpoint_value_matches_kind(value, "domain") is expected


class _RecordingEnricher(BaseEnricher):
    name = "recording"
    applies_to = ["ip"]

    def __init__(self) -> None:
        self.calls: list[str] = []

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls.append(ep.value)
        return EnrichmentResult(provider=self.name, ok=True, data={"seen": True})


def test_enrich_skips_endpoint_value_that_does_not_match_kind() -> None:
    bad = Endpoint(value="100.64.0.1/../x", kind="ip")
    good = Endpoint(value="192.0.2.1", kind="ip")
    enricher = _RecordingEnricher()
    stats = _enrich_endpoints([bad, good], [enricher])
    assert enricher.calls == [good.value]
    assert len(stats) == 1
    assert stats[0]["attempted"] == 1


def test_load_report_rejects_excessive_nesting(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(
        '{"endpoints": ' + "[" * 200_000 + "]" * 200_000 + "}",
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as excinfo:
        load_report(path)
    assert isinstance(excinfo.value, BoundedJsonError)
    assert not isinstance(excinfo.value, RecursionError)


class _Capture:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def get(self, url: str, **kwargs: object) -> object:
        del kwargs
        self.urls.append(url)
        raise RuntimeError("captured")


def _call(fn: Callable[[], object]) -> None:
    try:
        fn()
    except Exception:
        return


def _assert_safe_or_blocked(urls: list[str], raw: str) -> None:
    """没发请求（值在出网前被拒绝）或发出的 URL 已把该值编成单个 path segment。"""
    if not urls:
        return  # 出网前拒绝也算挡住路径注入
    encoded = quote(raw, safe=":")
    assert "%2F" in encoded and "%3F" in encoded and "%23" in encoded
    for url in urls:
        parts = urlsplit(url)
        assert "y=1" not in parts.query
        assert "z" not in parts.fragment
        assert "/../" not in parts.path
        assert encoded in parts.path.split("/")


def test_provider_urls_encode_endpoint_value_as_one_segment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evil_ip = Endpoint(value=_EVIL_IP, kind="ip")
    evil_domain = Endpoint(value=_EVIL_DOMAIN, kind="domain")

    vt = _Capture()
    _call(lambda: VirusTotalPassiveEnricher(vt)._lookup(evil_ip, "synthetic"))
    _assert_safe_or_blocked(vt.urls, _EVIL_IP)

    otx = _Capture()
    _call(lambda: OtxPassiveEnricher(otx)._lookup(evil_ip, "synthetic"))
    _assert_safe_or_blocked(otx.urls, _EVIL_IP)

    censys = _Capture()
    _call(lambda: CensysPassiveEnricher(censys)._lookup(evil_ip, "synthetic"))
    _assert_safe_or_blocked(censys.urls, _EVIL_IP)

    monkeypatch.delenv("FXAPK_FOFA_URL", raising=False)
    fofa = _Capture()
    _call(lambda: FofaHostProfileEnricher(fofa)._lookup(evil_ip, "synthetic"))
    _assert_safe_or_blocked(fofa.urls, _EVIL_IP)

    shodan_http = _Capture()
    monkeypatch.setattr(shodan_mod._http, "capped_get", shodan_http.get)
    _call(lambda: ShodanEnricher()._query(_EVIL_IP, "ip", "synthetic"))
    _assert_safe_or_blocked(shodan_http.urls, _EVIL_IP)

    ipinfo_mod.reset_state()
    monkeypatch.setattr(ipinfo_mod, "_SLEEP", lambda _seconds: None)
    ipinfo_http = _Capture()
    _call(lambda: ipinfo_mod.lookup_ip(_EVIL_IP, http=ipinfo_http))
    _assert_safe_or_blocked(ipinfo_http.urls, _EVIL_IP)

    rdap_http = _Capture()
    monkeypatch.setattr(rdap_mod, "requests", rdap_http)
    _call(lambda: RdapEnricher()._query_rdap(evil_domain.value))
    _assert_safe_or_blocked(rdap_http.urls, evil_domain.value)

    ip_rdap_http = _Capture()
    monkeypatch.setattr(ip_rdap_mod._http.capped_requests, "get", ip_rdap_http.get)
    _call(lambda: IpRdapEnricher()._query(_EVIL_IP))
    _assert_safe_or_blocked(ip_rdap_http.urls, _EVIL_IP)
