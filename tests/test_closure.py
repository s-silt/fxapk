from __future__ import annotations

from apkscan.core.closure import (
    CLOSURE_COMPLETE,
    CLOSURE_FAILED,
    CLOSURE_PARTIAL,
    LAYER_NAMES,
    ClosureConfig,
    assemble_target_closure,
    evaluate_capture_quality,
    evaluate_closure,
    select_targets,
)
from apkscan.core.models import Confidence, Endpoint, Evidence, Lead, LeadCategory, Report


def _endpoint(
    value: str,
    *,
    kind: str = "ip",
    runtime: bool = False,
    target: bool = False,
    payload: bool = False,
    sni: bool = False,
    enrichment: dict | None = None,
) -> Endpoint:
    source = "runtime" if runtime else "dex"
    merged_enrichment = dict(enrichment or {})
    if runtime:
        merged_enrichment["runtime"] = {
            "target_attributed": target,
            "has_payload": payload,
            "sni": "api.example.test" if sni else None,
        }
    return Endpoint(
        value=value,
        kind=kind,
        evidences=[Evidence(source=source, location="synthetic", snippet=value)],
        is_suspicious=True,
        enrichment=merged_enrichment,
    )


def _report(*endpoints: Endpoint) -> Report:
    leads = [
        Lead(
            category=LeadCategory.IP if ep.kind == "ip" else LeadCategory.DOMAIN,
            value=ep.value,
            confidence=Confidence.HIGH,
            source_refs=list(ep.evidences),
            advice="建议调证",
        )
        for ep in endpoints
    ]
    return Report(
        package_name="com.example.synthetic",
        meta={},
        leads=leads,
        endpoints=list(endpoints),
        findings=[],
        analyzer_status=[{"name": "manifest", "status": "ran"}],
    )


def _complete_endpoint() -> Endpoint:
    return _endpoint(
        "198.51.100.10",
        runtime=True,
        target=True,
        payload=True,
        enrichment={
            "ip_rdap": {
                "netname": "EXAMPLE-NET",
                "org": "Example Registry Ltd",
                "country": "US",
                "handle": "NET-198-51-100-0-1",
                "cidr": "198.51.100.0/24",
            },
            "ripestat_bgp": {
                "origin_asn": 64500,
                "asn_holder": "Example Network Ltd",
                "prefix": "198.51.100.0/24",
                "upstreams": [64501],
            },
            "asn": {
                "asn": "AS64500",
                "org": "Example Hosting Ltd",
                "isp": "Example Hosting Ltd",
                "country": "US",
            },
            "shodan": {
                "org": "Example Hosting Ltd",
                "ports": [443],
                "services": [{"port": 443, "product": "nginx"}],
            },
            "source_status": {
                "ip_rdap": {"status": "hit"},
                "ripestat_bgp": {"status": "hit"},
                "shodan": {"status": "hit"},
                "urlscan": {"status": "no_record"},
            },
        },
    )


def test_select_targets_prioritizes_target_attributed_runtime_endpoint() -> None:
    report = _report(
        _endpoint("198.51.100.30", runtime=False),
        _endpoint("198.51.100.20", runtime=True, target=True),
        _endpoint("198.51.100.10", runtime=True, payload=True, sni=True),
    )

    selected = select_targets(report, max_targets=2)

    assert [ep.value for ep in selected] == ["198.51.100.20", "198.51.100.10"]


def test_select_targets_is_stable_and_deduplicates_domain_case() -> None:
    upper = _endpoint("API.EXAMPLE.TEST", kind="domain", runtime=True)
    lower = _endpoint("api.example.test", kind="domain", runtime=True)
    report = _report(upper, lower, _endpoint("198.51.100.10", runtime=True))

    first = [ep.value for ep in select_targets(report, max_targets=6)]
    second = [ep.value for ep in select_targets(report, max_targets=6)]

    assert first == second
    assert len([value for value in first if value.lower() == "api.example.test"]) == 1


def test_capture_channel_without_packets_is_failed() -> None:
    quality = evaluate_capture_quality(
        {"channel_ready": True, "pcap_valid": False, "packet_count": 0}
    )

    assert quality["dynamic_status"] == CLOSURE_FAILED


def test_capture_business_candidate_without_target_attribution_is_partial() -> None:
    quality = evaluate_capture_quality(
        {
            "channel_ready": True,
            "pcap_valid": True,
            "packet_count": 12,
            "business_candidate_count": 2,
            "target_attributed_count": 0,
        }
    )

    assert quality["dynamic_status"] == CLOSURE_PARTIAL


def test_capture_target_attributed_candidate_is_complete() -> None:
    quality = evaluate_capture_quality(
        {
            "channel_ready": True,
            "pcap_valid": True,
            "packet_count": 12,
            "business_candidate_count": 2,
            "target_attributed_count": 1,
        }
    )

    assert quality["dynamic_status"] == CLOSURE_COMPLETE


def test_assemble_target_closure_builds_all_investigation_layers() -> None:
    target = assemble_target_closure(_complete_endpoint())

    assert set(target["layers"]) == set(LAYER_NAMES)
    assert all(layer["status"] == CLOSURE_COMPLETE for layer in target["layers"].values())
    assert target["layers"]["resource_registration"]["evidence"]["cidr"] == "198.51.100.0/24"
    assert target["layers"]["request_target"]["evidence"]["provider"] == "Example Hosting Ltd"
    assert target["status"] == CLOSURE_COMPLETE


def test_cdn_without_origin_cannot_be_complete() -> None:
    report = _report(_complete_endpoint())
    target = assemble_target_closure(report.endpoints[0])
    target["origin"] = {"required": True, "status": "missing"}

    closure = evaluate_closure(report, [target], require_dynamic=False)

    assert closure["status"] == CLOSURE_PARTIAL
    assert "origin" in " ".join(closure["gaps"]).lower()


def test_static_critical_failure_makes_closure_failed() -> None:
    report = _report(_complete_endpoint())
    report.analysis_status = "partial"
    report.critical_failures = ["manifest"]

    closure = evaluate_closure(
        report,
        [assemble_target_closure(report.endpoints[0])],
        require_dynamic=False,
    )

    assert closure["status"] == CLOSURE_FAILED
    assert closure["checks"][0]["id"] == "static_health"
    assert closure["checks"][0]["status"] == "fail"


def test_closure_config_rejects_non_positive_target_limit() -> None:
    try:
        ClosureConfig(max_targets=0)
    except ValueError as exc:
        assert "max_targets" in str(exc)
    else:
        raise AssertionError("ClosureConfig accepted max_targets=0")
