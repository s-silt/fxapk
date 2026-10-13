"""Runtime evidence preservation: lead refs, observation budget, round binding."""
from __future__ import annotations

import json
from copy import deepcopy

import pytest

from apkscan.core.models import (
    Confidence,
    Endpoint,
    Evidence,
    EvidenceScope,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.dynamic.capture_provenance import (
    capture_scope,
    project_observations,
    retain_observations,
    scoped_evidence,
    sync_endpoint_refs,
)


def rep() -> Report:
    return Report(
        package_name="com.example.synthetic",
        meta={},
        endpoints=[],
        leads=[],
        findings=[],
        analyzer_status=[],
    )


def _lead(value: str = "api.example.invalid", category: LeadCategory = LeadCategory.DOMAIN) -> Lead:
    return Lead(
        category=category,
        value=value,
        advice="待核",
        confidence=Confidence.LOW,
        base_advice="待核",
        downgrades={"synthetic-rule": "kept"},
        source_refs=[Evidence(source="dex", location="classes.dex", snippet=value)],
    )


def _verdict(lead: Lead) -> tuple:
    return (lead.advice, lead.confidence, lead.base_advice, dict(lead.downgrades))


def test_legacy_merge_propagates_decrypted_ref_without_changing_verdict() -> None:
    from apkscan.dynamic.merge import merge_runtime_endpoints

    report = rep()
    lead = _lead()
    report.leads = [lead]
    report.endpoints = [Endpoint(kind="domain", value=lead.value, evidences=list(lead.source_refs))]
    evidence = Evidence(
        source="runtime-decrypted",
        location="https://config.example.invalid/cfg",
        snippet="https://api.example.invalid/v1",
        scope=EvidenceScope.CASE_EVIDENCE,
        observed_at=1767225600.25,
    )
    incoming = Endpoint(kind="domain", value="API.example.invalid.", evidences=[evidence])
    before = _verdict(lead)
    merge_runtime_endpoints(report, [incoming])
    merge_runtime_endpoints(report, [incoming])
    assert _verdict(lead) == before
    copied = [item for item in lead.source_refs if item.source == "runtime-decrypted"]
    assert copied == [evidence]
    assert copied[0].location == evidence.location
    assert copied[0].snippet == evidence.snippet
    assert copied[0].scope is EvidenceScope.CASE_EVIDENCE
    assert copied[0].observed_at == evidence.observed_at


def test_url_and_ip_match_existing_leads_and_keep_namespace() -> None:
    report = rep()
    domain = _lead()
    ip = _lead("192.0.2.10:443/tcp", LeadCategory.IP)
    report.leads = [domain, ip]
    ns = "capture:" + "ab" * 4
    with capture_scope(ns, verified=True):
        url_ev = scoped_evidence(
            source="runtime-decrypted",
            location="body:1",
            snippet="https://API.example.invalid/v1",
            scope=EvidenceScope.CASE_EVIDENCE,
            observed_at=10.0,
        )
        ip_ev = scoped_evidence(
            source="runtime-pcap",
            location="flow:9",
            snippet="192.0.2.10",
            scope=EvidenceScope.CASE_EVIDENCE,
            observed_at=11.0,
        )
        foreign = Evidence(
            source="runtime-decrypted",
            location="other::skip",
            snippet="nope",
            scope=EvidenceScope.CASE_EVIDENCE,
        )
        sync_endpoint_refs(report, [
            Endpoint(kind="url", value="https://API.example.invalid/v1", evidences=[url_ev, foreign]),
            Endpoint(kind="ip", value="192.0.2.10", evidences=[ip_ev]),
        ])
        sync_endpoint_refs(report, [
            Endpoint(kind="url", value="https://API.example.invalid/v1", evidences=[url_ev]),
        ])
    assert [item.location for item in domain.source_refs if item.source.startswith("runtime")] == [url_ev.location]
    assert url_ev.location.startswith(ns + "::")
    assert ip.source_refs[-1].source == "runtime-pcap"
    assert ip.source_refs[-1].observed_at == 11.0
    assert all(item.location != "other::skip" for item in domain.source_refs)
    assert _verdict(domain) == ("待核", Confidence.LOW, "待核", {"synthetic-rule": "kept"})


def test_superseded_runtime_pcap_is_not_resurrected() -> None:
    report = rep()
    lead = _lead()
    revoked = Evidence(
        source="runtime-pcap",
        location="flow:1",
        snippet="same",
        scope=EvidenceScope.CASE_EVIDENCE,
        observed_at=1.0,
    )
    lead.source_refs.append(revoked)
    report.leads = [lead]
    derived = Evidence(
        source="runtime-derived",
        location="flow:1",
        snippet="same",
        scope=EvidenceScope.CASE_EVIDENCE,
        observed_at=2.0,
    )
    sync_endpoint_refs(report, [Endpoint(
        kind="domain",
        value=lead.value,
        evidences=[derived, revoked],
    )])
    sources = [item.source for item in lead.source_refs]
    assert "runtime-pcap" not in sources
    assert sources.count("runtime-derived") == 1
    assert lead.advice == "待核"


def test_later_stale_pcap_is_filtered_against_existing_derived_refs() -> None:
    """Second sync must not resurrect pcap already superseded by a stored derived ref."""
    report = rep()
    lead = _lead()
    report.leads = [lead]
    derived = Evidence(
        source="runtime-derived",
        location="flow:1",
        snippet="same",
        scope=EvidenceScope.CASE_EVIDENCE,
        observed_at=2.5,
    )
    stale = Evidence(
        source="runtime-pcap",
        location="flow:1",
        snippet="same",
        scope=EvidenceScope.CASE_EVIDENCE,
        observed_at=1.25,
    )
    sync_endpoint_refs(report, [Endpoint(kind="domain", value=lead.value, evidences=[derived])])
    sync_endpoint_refs(report, [Endpoint(kind="domain", value=lead.value, evidences=[stale])])
    sources = [item.source for item in lead.source_refs]
    assert "runtime-pcap" not in sources
    kept = next(item for item in lead.source_refs if item.source == "runtime-derived")
    assert kept.observed_at == 2.5
    assert kept.location == derived.location
    assert kept.snippet == derived.snippet
    assert kept.scope is EvidenceScope.CASE_EVIDENCE
    assert stale.source == "runtime-pcap"
    assert stale.observed_at == 1.25


def _contact(i: int, ref: str, runtime: dict) -> Endpoint:
    with capture_scope(ref, verified=True):
        return Endpoint(
            kind="domain",
            value=f"h{i}.example.invalid",
            evidences=[scoped_evidence(
                source="runtime-pcap",
                location=f"flow:{i}",
                scope=EvidenceScope.CASE_EVIDENCE,
            )],
            enrichment={"runtime": dict(runtime)},
        )


def test_observation_budget_boundary_and_unrelated_overflow() -> None:
    report = rep()
    ref = "capture:budget"
    runtime = {"target_attributed": True, "has_payload": True, "variant": "original-runtime"}
    batch = [_contact(i, ref, runtime) for i in range(12000)]
    with capture_scope(ref, verified=True):
        retain_observations(report, batch)
    assert len(report.meta["runtime_observations"]) == 12000
    assert "runtime_observations_truncated" not in report.meta
    report.endpoints = [batch[0]]
    with capture_scope(ref, verified=True):
        project_observations(report)
    assert report.endpoints[0].enrichment["runtime"]["target_attributed"] is True
    ledger = deepcopy(report.meta["runtime_observations"])
    enrichment = deepcopy(report.endpoints[0].enrichment)
    extra = _contact(12000, ref, runtime)
    with pytest.raises(ValueError, match="runtime_observation_budget_exceeded"):
        with capture_scope(ref, verified=True):
            retain_observations(report, [extra])
    assert report.meta["runtime_observations"] == ledger
    assert report.endpoints[0].enrichment == enrichment
    assert report.meta["runtime_observation_overflow"]["status"] == "rejected"
    assert report.meta["runtime_observation_overflow"]["affected_targets"] == []
    assert "runtime_observations_truncated" not in report.meta


def test_same_target_overflow_keeps_history_and_drops_only_that_claim() -> None:
    report = rep()
    ref = "capture:budget"
    ok = {"target_attributed": True, "has_payload": True, "variant": "original-runtime"}
    other = [_contact(i, ref, ok) for i in range(11999)]
    target = _contact(11999, ref, ok)
    with capture_scope(ref, verified=True):
        retain_observations(report, other + [target])
    report.endpoints = [other[0], target]
    with capture_scope(ref, verified=True):
        project_observations(report)
    assert report.endpoints[1].enrichment["runtime"]["target_attributed"] is True
    history = deepcopy(report.meta["runtime_observations"])
    other_enrichment = deepcopy(report.endpoints[0].enrichment)
    conflict = _contact(11999, ref, {"target_attributed": False, "has_payload": False, "variant": "original-runtime"})
    with pytest.raises(ValueError, match="runtime_observation_budget_exceeded"):
        with capture_scope(ref, verified=True):
            retain_observations(report, [conflict])
    assert report.meta["runtime_observations"] == history
    stored = [row for row in history if row["value"] == target.value]
    assert stored[0]["runtime"]["target_attributed"] is True
    assert report.endpoints[1].enrichment["runtime"]["target_attributed"] is None
    assert report.endpoints[1].enrichment["runtime"]["sequence_identity_unconfirmed"] is True
    assert report.endpoints[0].enrichment == other_enrichment
    assert not any(
        row["runtime"].get("target_attributed") is False
        for row in report.meta["runtime_observations"]
    )


def test_later_unrelated_overflow_keeps_earlier_affected_target() -> None:
    """Three retains: fill, same-target conflict, then unrelated overflow.

    The third rejection must not clear affected_targets or let projection
    promote the earlier target from the surviving ledger.
    """
    report = rep()
    ref = "capture:budget"
    ok = {"target_attributed": True, "has_payload": True, "variant": "original-runtime"}
    other = [_contact(i, ref, ok) for i in range(11999)]
    target = _contact(11999, ref, ok)
    with capture_scope(ref, verified=True):
        retain_observations(report, other + [target])
    report.endpoints = [target]
    with capture_scope(ref, verified=True):
        project_observations(report)
    conflict = _contact(
        11999, ref,
        {"target_attributed": False, "has_payload": False, "variant": "original-runtime"},
    )
    with pytest.raises(ValueError, match="runtime_observation_budget_exceeded"):
        with capture_scope(ref, verified=True):
            retain_observations(report, [conflict])
    extra = _contact(20000, ref, ok)
    with pytest.raises(ValueError, match="runtime_observation_budget_exceeded"):
        with capture_scope(ref, verified=True):
            retain_observations(report, [extra])
    overflow = report.meta["runtime_observation_overflow"]
    assert [target.kind, target.value] in overflow["affected_targets"]
    assert overflow["omitted_count"] == 2
    assert len(overflow["rejections"]) == 2
    assert overflow["rejections"][1]["affected_targets"] == []
    assert "runtime_observations_truncated" not in report.meta
    with capture_scope(ref, verified=True):
        project_observations(report)
    assert report.endpoints[0].enrichment["runtime"]["target_attributed"] is None
    assert report.endpoints[0].enrichment["runtime"]["sequence_identity_unconfirmed"] is True
    assert ref in report.endpoints[0].enrichment["runtime_observation_conflicts"]


def test_legacy_truncated_ledger_does_not_project_complete_contact() -> None:
    report = rep()
    ref = "capture:legacy"
    runtime = {"target_attributed": True, "has_payload": True, "variant": "original-runtime"}
    endpoint = _contact(1, ref, runtime)
    with capture_scope(ref, verified=True):
        retain_observations(report, [endpoint])
    report.endpoints = [endpoint]
    report.meta["runtime_observations_truncated"] = True
    with capture_scope(ref, verified=True):
        project_observations(report)
    projected = report.endpoints[0].enrichment["runtime"]
    assert projected["target_attributed"] is None
    assert projected["sequence_identity_unconfirmed"] is True


def test_namespace_without_matching_round_is_not_verified(tmp_path) -> None:
    from apkscan.core.integrity import sha256_file
    from apkscan.dynamic.merge import merge_and_rerender

    report = rep()
    sample = "ab" * 32
    report.meta["capture_apk_identity"] = {"which": "original", "original": {"sha256": sample}}
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps({
        "package_name": report.package_name,
        "runtime_variant": "original-runtime",
        "endpoints": [],
    }), encoding="utf-8")
    namespace = "capture:" + sha256_file(str(path))
    endpoint = Endpoint(
        kind="domain",
        value="api.example.invalid",
        evidences=[Evidence(source="runtime-pcap", location="flow:1", scope=EvidenceScope.CASE_EVIDENCE)],
    )
    for rounds in (None, []):
        report.endpoints = []
        report.meta.pop("capture_rounds", None)
        if rounds is not None:
            report.meta["capture_rounds"] = rounds
        merge_and_rerender(
            report, [deepcopy(endpoint)], str(tmp_path / "out"), "report",
            formats=["json"], runtime_report_path=str(path), evidence_namespace=namespace,
        )
        saved = next(item for item in report.endpoints if item.value == endpoint.value)
        assert all(item.source != "runtime-pcap" for item in saved.evidences)
        assert any(item.source == "runtime-derived" for item in saved.evidences)


def test_namespace_with_matching_round_keeps_contact_source(tmp_path) -> None:
    from apkscan.core.integrity import sha256_file
    from apkscan.dynamic.merge import merge_and_rerender

    report = rep()
    sample = "cd" * 32
    report.meta["capture_apk_identity"] = {"which": "original", "original": {"sha256": sample}}
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps({
        "package_name": report.package_name,
        "runtime_variant": "original-runtime",
        "endpoints": [],
    }), encoding="utf-8")
    file_hash = sha256_file(str(path))
    report.meta["capture_rounds"] = [{
        "sample_sha256": sample,
        "runtime_report_sha256": file_hash,
    }]
    endpoint = Endpoint(
        kind="domain",
        value="api.example.invalid",
        evidences=[Evidence(source="runtime-pcap", location="flow:1", scope=EvidenceScope.CASE_EVIDENCE)],
    )
    merge_and_rerender(
        report, [endpoint], str(tmp_path / "out"), "report",
        formats=["json"], runtime_report_path=str(path),
        evidence_namespace="capture:" + file_hash,
    )
    saved = next(item for item in report.endpoints if item.value == endpoint.value)
    assert any(item.source == "runtime-pcap" for item in saved.evidences)


def test_legacy_merge_without_namespace_stays_compatible(tmp_path) -> None:
    from apkscan.dynamic.merge import merge_and_rerender

    report = rep()
    endpoint = Endpoint(
        kind="domain",
        value="api.example.invalid",
        evidences=[Evidence(source="runtime-pcap", location="flow:1", scope=EvidenceScope.CASE_EVIDENCE)],
    )
    merge_and_rerender(
        report, [endpoint], str(tmp_path / "out"), "report",
        formats=["json"], runtime_report_path=str(tmp_path / "missing.json"),
    )
    saved = next(item for item in report.endpoints if item.value == endpoint.value)
    assert any(item.source == "runtime-pcap" for item in saved.evidences)


def test_plaintext_endpoints_do_not_upgrade_contact_or_closure() -> None:
    from apkscan.attribution.assemble import _runtime_contact_observed
    from apkscan.core.closure.targets import _runtime_info
    from apkscan.dynamic.merge import _endpoints_from_plaintext, merge_runtime_endpoints

    report = rep()
    lead = _lead()
    report.leads = [lead]
    report.endpoints = [Endpoint(kind="domain", value=lead.value, evidences=list(lead.source_refs))]
    derived = _endpoints_from_plaintext(
        '{"url":"https://api.example.invalid/v1"}',
        "https://config.example.invalid/cfg",
    )
    assert derived
    assert all(
        evidence.source == "runtime-decrypted" and "runtime" not in endpoint.enrichment
        for endpoint in derived for evidence in endpoint.evidences
    )
    before = _verdict(lead)
    merge_runtime_endpoints(report, derived)
    host = next(item for item in report.endpoints if item.kind == "domain" and item.value == lead.value)
    assert _verdict(lead) == before
    assert lead.is_runtime_contact is False
    assert _runtime_contact_observed(host) is False
    assert _runtime_info(host).get("target_attributed") is not True


def test_legacy_credential_events_keep_distinct_refs() -> None:
    from apkscan.dynamic.merge import _add_runtime_credential_leads

    report = rep()
    for path in ("first", "second", "second"):
        _add_runtime_credential_leads(
            report,
            [{"source": "okhttp", "url": "https://api.example.test/" + path, "body": "SYNTHETIC"}],
        )
    assert len(report.leads) == 1
    assert len(report.leads[0].source_refs) == 2


def test_runtime_brand_finding_retains_earlier_and_later_rounds() -> None:
    from apkscan.dynamic.merge import _add_brand_hint_finding

    report = rep()
    report.meta["runtime_brand_hints"] = ["SYNTHETIC FIRST"]
    with capture_scope("capture:one", verified=True):
        _add_brand_hint_finding(report, ["SYNTHETIC FIRST"])
    report.meta["runtime_brand_hints"] = ["SYNTHETIC FIRST", "SYNTHETIC SECOND"]
    with capture_scope("capture:two", verified=True):
        _add_brand_hint_finding(report, ["SYNTHETIC FIRST", "SYNTHETIC SECOND"])
    findings = [item for item in report.findings if item.id == "RUNTIME-BRAND-HINTS"]
    assert len(findings) == 1
    assert {item.location.split("::")[0] for item in findings[0].evidences} == {
        "capture:one",
        "capture:two",
    }
    assert report.meta["runtime_brand_hints"] == ["SYNTHETIC FIRST", "SYNTHETIC SECOND"]
