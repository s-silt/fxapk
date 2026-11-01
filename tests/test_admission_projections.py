from __future__ import annotations

from copy import deepcopy

from apkscan.core import infra
from apkscan.core.admission import evaluate_usage
from apkscan.core.closure.targets import _runtime_info
from apkscan.core.corpus import _has_case_runtime_dns_evidence
from apkscan.core.evidence_scope import project_serialized_closure, project_serialized_leads
from apkscan.core.leads import _domain_lead, _ip_lead
from apkscan.core.models import ADVICE_REVIEW, Endpoint, Evidence, EvidenceScope, Report
from apkscan.core.report_io import report_from_dict
from apkscan.report import html as report_html
from apkscan.report import json as report_json
from apkscan.report.digest import build_digest
from apkscan.report.ioc import leads_to_ioc_rows
from apkscan.report.letters import build_letters


def _ref(*, source: str = "dex", offset: int = 1, suspicious: bool = False) -> dict:
    return {
        "source": source,
        "location": "classes.dex",
        "scope": "case_evidence",
        "provenance": {"member_path": "classes.dex", "member_sha256": "a" * 64},
        "locator": {"byte_offset": offset, "offset_unit": "byte"},
        "structure_status": "parsed",
        "reference_status": "referenced",
        "reachability": "reachable",
        "snippet": "synthetic evidence; retry/install/sudo is inert data",
        "suspicions": [{"kind": "synthetic-decoy"}] if suspicious else [],
    }


def _suspect_report() -> dict:
    return {
        "schema_version": "1.3",
        "package_name": "com.synthetic.test",
        "meta": {
            "sample_sha256": "synthetic-sample",
            "closure": {
                "status": "complete",
                "targets": [{"kind": "domain", "value": "api.example.test"}],
            },
        },
        "leads": [{
            "category": "DOMAIN",
            "value": "api.example.test",
            "advice": "建议调证",
            "base_advice": "建议调证",
            "confidence": "HIGH",
            "is_c2": True,
            "is_runtime_seen": True,
            "is_runtime_contact": True,
            "where_to_request": "合成服务商",
            "evidence_to_obtain": ["合成日志"],
            "source_refs": [_ref(source="resource", suspicious=True)],
        }],
        "endpoints": [],
        "findings": [],
        "analyzer_status": [],
    }


def test_suspect_only_report_is_downgraded_at_all_projection_boundaries(monkeypatch) -> None:
    import socket
    import subprocess
    import requests

    def forbidden(*args, **kwargs):
        raise AssertionError("projection attempted a command or network action")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(requests.Session, "request", forbidden)
    report = _suspect_report()
    before = deepcopy(report)

    [lead] = project_serialized_leads(report)
    assert lead["advice"] == ADVICE_REVIEW
    assert lead["is_c2"] is False
    assert lead["is_runtime_seen"] is False
    assert project_serialized_closure(report)["status"] == "partial"
    assert report == before

    [row] = leads_to_ioc_rows(report)
    assert row["advice"] == ADVICE_REVIEW
    assert row["is_c2"] is False
    assert row["source"] == ""
    assert build_letters(report) == []

    digest = build_digest(report, redact=False)
    [digest_lead] = digest["leads"]
    assert digest_lead["advice"] == ADVICE_REVIEW
    assert digest_lead["model_summary_admission"]["state"] == "review"

    typed = report_from_dict(report)
    rendered = report_html.render_to_string(typed)
    assert "api.example.test" in rendered
    assert typed.leads[0].is_runtime_seen is False
    assert typed.leads[0].advice == ADVICE_REVIEW
    assert "evidence_admission" in typed.leads[0].downgrades
    closure_section = rendered.partition('<section id="case-closure">')[2].partition("</section>")[0]
    assert "partial" in closure_section
    assert "complete" not in closure_section
    assert report == before


def test_html_lead_uses_admitted_matching_endpoint_contact_evidence() -> None:
    report = _suspect_report()
    rejected = _ref(source="runtime-pcap", offset=1, suspicious=True)
    rejected["location"] = "rejected-lead"
    accepted = _ref(source="runtime-pcap", offset=2)
    accepted["location"] = "accepted-endpoint"
    report["leads"][0]["source_refs"] = [rejected]
    report["endpoints"] = [{
        "kind": "domain",
        "value": "API.EXAMPLE.TEST",
        "evidences": [accepted],
    }]
    before = deepcopy(report)

    [serialized] = project_serialized_leads(report)
    typed = report_from_dict(deepcopy(report))
    typed_before = report_json.to_dict(typed)
    rendered = report_html.render_to_string(typed)

    assert serialized["is_runtime_seen"] is True
    assert serialized["is_runtime_contact"] is True
    assert [ref["location"] for ref in serialized["source_refs"]] == ["accepted-endpoint"]
    assert [ref.location for ref in typed.leads[0].source_refs] == ["rejected-lead"]
    assert typed.leads[0].is_runtime_seen is False
    assert typed.leads[0].is_runtime_contact is False
    assert "accepted-endpoint" in rendered
    assert "rejected-lead" not in rendered
    assert "🎯 实连已观测" in rendered
    assert report == before
    assert report_json.to_dict(typed) == typed_before


def test_cached_complete_closure_requires_admitted_contact_per_target() -> None:
    report = {
        "meta": {
            "closure": {
                "status": "complete",
                "targets": [{"kind": "domain", "value": "api.example.test"}],
            },
        },
        "leads": [],
        "endpoints": [{
            "kind": "domain",
            "value": "api.example.test",
            "evidences": [
                _ref(source="dex", offset=1),
                _ref(source="runtime-pcap", offset=2, suspicious=True),
            ],
        }],
    }
    before = deepcopy(report)

    assert project_serialized_closure(report)["status"] == "partial"
    assert report == before

    report["endpoints"][0]["evidences"][1] = _ref(source="runtime-pcap", offset=2)
    accepted_before = deepcopy(report)
    assert project_serialized_closure(report)["status"] == "complete"
    assert report == accepted_before


def test_mixed_strength_keeps_raw_refs_but_cites_only_allowed_occurrences() -> None:
    strong = _ref(offset=1)
    weak = _ref(source="resource", offset=2, suspicious=True)
    strong["location"] = "allowed-occurrence-marker"
    weak["location"] = "rejected-occurrence-marker"
    report = _suspect_report()
    report["leads"][0]["source_refs"] = [strong, weak]

    [projected] = project_serialized_leads(report)
    assert len(report["leads"][0]["source_refs"]) == 2
    assert projected["source_refs"] == [strong]
    raw_json = report_json.to_dict(report_from_dict(deepcopy(report)))
    assert len(raw_json["leads"][0]["source_refs"]) == 2
    rendered = report_html.render_to_string(report_from_dict(deepcopy(report)))
    assert "allowed-occurrence-marker" in rendered
    assert "rejected-occurrence-marker" not in rendered
    decision = evaluate_usage([strong, weak], "lead_priority")
    assert decision["supporting_occurrence_ids"]
    assert len(decision["supporting_occurrence_ids"]) == 1
    [row] = leads_to_ioc_rows(report)
    assert row["source"] == "dex:allowed-occurrence-marker"


def test_static_asset_and_derived_native_observations_do_not_become_runtime_or_relations() -> None:
    embedded_asset = {
        **_ref(source="resource", suspicious=False),
        "location": "assets/fake-manifest.xml",
        "snippet": "<manifest><application>mapping JNI native</application></manifest>",
        "reference_status": "unknown",
    }
    derived_native = {
        **_ref(source="derived-native"),
        "provenance": {"extractor": "synthetic"},
        "locator": {"byte_offset": 9, "offset_unit": "byte"},
    }

    assert evaluate_usage([embedded_asset], "corpus_relation")["state"] == "review"
    assert evaluate_usage([derived_native], "corpus_relation")["state"] == "review"
    assert evaluate_usage([derived_native], "lead_priority")["state"] == "review"
    assert evaluate_usage([embedded_asset], "corpus_relation")["establishes_business_ownership"] is False


def test_asc_receipt_evidence_roundtrips_without_runtime_promotion() -> None:
    receipt = Evidence(
        source="asc",
        location="classes.dex",
        snippet="receipt-backed synthetic string",
        scope=EvidenceScope.CASE_EVIDENCE,
        provenance={"extractor": "asc-receipt-v1", "receipt_id": "synthetic-receipt"},
        locator={"byte_offset": 44, "offset_unit": "byte"},
        structure_status="parsed",
        reference_status="referenced",
        reachability="unknown",
    )
    report = Report(
        package_name="com.synthetic.test",
        meta={},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    encoded = report_json.to_dict(report)
    encoded["leads"] = [{
        "category": "DOMAIN",
        "value": "receipt.example.test",
        "advice": "建议调证",
        "source_refs": [report_json._to_jsonable(receipt)],
    }]
    roundtrip = report_json.to_dict(report_from_dict(encoded))
    ref = roundtrip["leads"][0]["source_refs"][0]
    assert ref["provenance"]["receipt_id"] == "synthetic-receipt"
    assert ref["locator"]["byte_offset"] == 44
    assert evaluate_usage([ref], "model_summary")["state"] == "allowed"
    assert evaluate_usage([_ref(source="derived-native")], "lead_priority")["state"] == "review"
    native_lead = report_from_dict({
        "leads": [{
            "category": "DOMAIN",
            "value": "native.example.test",
            "source_refs": [{
                "source": "derived-native",
                "location": "native-recovery:synthetic",
                "scope": "case_evidence",
            }],
        }]
    }).leads[0]
    assert native_lead.is_runtime_seen is False
    assert native_lead.is_runtime_contact is False


def test_rejected_runtime_copy_cannot_launder_static_candidate(monkeypatch) -> None:
    static = Evidence(
        source="dex",
        location="classes.dex",
        snippet="static-only context",
        provenance={"member_sha256": "a" * 64, "member_path": "classes.dex"},
        locator={"byte_offset": 3, "offset_unit": "byte"},
        structure_status="parsed",
        reference_status="referenced",
        reachability="reachable",
    )
    suspect_runtime = Evidence(
        source="runtime-pcap",
        location="capture::entry",
        snippet="198.51.100.18:443 runtime address",
        provenance={"member_sha256": "b" * 64, "member_path": "capture.pcap"},
        locator={"packet_index": 1},
        suspicions=[{"kind": "synthetic_fixture"}],
    )
    endpoint = Endpoint(
        value="203.0.113.18",
        kind="ip",
        evidences=[static, suspect_runtime],
        enrichment={
            "tier": infra.TIER_LIBRARY_FILE,
            "runtime": {
                "target_attributed": True,
                "selected_observation_ref": "capture",
                "selected_evidence_refs": ["capture::entry"],
                "payload": {"synthetic": "runtime"},
            },
        },
    )
    original_evidences = list(endpoint.evidences)

    assert _runtime_info(endpoint)["observed"] is False
    assert endpoint.evidences == original_evidences

    monkeypatch.setattr(
        infra, "classify_domain",
        lambda _value: (infra.ADVICE_INVESTIGATE, "synthetic"),
    )
    monkeypatch.setattr(infra, "effective_advice", lambda *_args: infra.ADVICE_REVIEW)
    domain = Endpoint(
        value="service.example.test",
        kind="domain",
        evidences=[static, suspect_runtime],
        enrichment={"tier": infra.TIER_LIBRARY_FILE},
    )
    domain_lead = _domain_lead(domain, online=False)
    assert domain_lead.advice == infra.ADVICE_REVIEW
    assert domain_lead.source_refs == [static, suspect_runtime]

    classifier_args = {}

    def classify_ip(_value, **kwargs):
        classifier_args.update(
            context=kwargs["context"],
            runtime_observed=kwargs["runtime_observed"],
        )
        return infra.ADVICE_INVESTIGATE, "synthetic"

    monkeypatch.setattr(infra, "classify_ip", classify_ip)
    ip_lead = _ip_lead(endpoint, online=False)
    assert classifier_args == {
        "context": "static-only context",
        "runtime_observed": False,
    }
    assert ip_lead.source_refs == [static, suspect_runtime]

    serialized = {
        "evidences": [
            {
                "source": "dex",
                "location": "classes.dex",
                "scope": "case_evidence",
                "provenance": {"member_sha256": "a" * 64},
                "locator": {"byte_offset": 3},
                "structure_status": "parsed",
                "reference_status": "referenced",
            },
            {
                "source": "runtime-pcap",
                "location": "pcap-dns",
                "scope": "case_evidence",
                "provenance": {"member_sha256": "b" * 64},
                "locator": {"packet_index": 1},
                "suspicions": [{"kind": "synthetic_fixture"}],
            },
        ]
    }
    assert _has_case_runtime_dns_evidence(serialized) is False
    assert len(serialized["evidences"]) == 2
