from dataclasses import replace

import pytest

from apkscan.core.admission import PURPOSES, admitted_refs, evaluate_usage
from apkscan.core.evidence_scope import project_serialized_lead
from apkscan.core.models import Evidence, EvidenceScope, merge_runtime_into_lead_dict
from apkscan.core.observations import occurrence_id
from apkscan.core.report_io import _evidence_from_dict


@pytest.mark.parametrize("purpose", sorted(PURPOSES))
def test_same_value_decoy_does_not_borrow_or_contaminate_runtime(purpose):
    real = Evidence("runtime-pcap", "capture.pcap", observed_at=12)
    decoy = Evidence("resource", "assets/decoy.txt", suspicions=[{"kind": "synthetic_fixture"}])
    assert evaluate_usage([real, decoy], purpose) == evaluate_usage([decoy, real], purpose)
    assert evaluate_usage([real, decoy], purpose)["state"] == "allowed"
    assert admitted_refs([decoy, real], purpose) == [real]
    assert evaluate_usage([decoy], purpose)["state"] == "review"


def test_reference_scope_and_static_xref_never_create_runtime_qualification():
    xref = Evidence("static-dex-xref", "classes.dex", reference_status="referenced")
    assert evaluate_usage([xref], "lead_priority")["state"] == "review"
    assert evaluate_usage([xref], "dex_query")["state"] == "allowed"
    assert evaluate_usage([replace(xref, scope=EvidenceScope.BATCH_REFERENCE)], "dex_query")["state"] == "blocked"


def test_ordinary_static_candidate_is_not_promoted_to_corpus_relation():
    candidate = Evidence("dex", "classes.dex")
    assert evaluate_usage([candidate], "passive_enrichment")["state"] == "allowed"
    decision = evaluate_usage([candidate], "corpus_relation")
    assert decision["state"] == "review"
    assert not decision["establishes_business_ownership"]


def test_structural_reference_is_candidate_relation_not_ownership():
    candidate = Evidence(
        "dex", "classes.dex", provenance={"member_sha256": "fixture"},
        locator={"byte_offset": 1}, structure_status="parsed", reference_status="referenced",
    )
    decision = evaluate_usage([candidate], "corpus_relation")
    assert decision["state"] == "allowed"
    assert not decision["establishes_business_ownership"]


def test_admission_ids_include_only_located_allowed_occurrences():
    strong = Evidence(
        "dex", "classes.dex", provenance={"member_sha256": "a" * 64},
        locator={"byte_offset": 7},
    )
    rejected = Evidence(
        "resource", "assets/copy.txt", provenance={"member_sha256": "b" * 64},
        locator={"byte_offset": 7}, suspicions=[{"kind": "synthetic_fixture"}],
    )
    legacy = Evidence("manifest", "AndroidManifest.xml")

    decision = evaluate_usage([rejected, legacy, strong], "lead_priority")

    assert decision["supporting_occurrence_ids"] == [occurrence_id(strong)]
    assert decision["unlocated_allowed_count"] == 1


@pytest.mark.parametrize("field,value", [
    ("provenance", None),
    ("provenance", []),
    ("provenance", "source"),
    ("locator", None),
    ("locator", []),
    ("locator", "offset"),
])
def test_malformed_location_facts_are_review_for_runtime_and_reader_parity(field, value):
    raw = {
        "source": "runtime-pcap",
        "location": "capture.pcap",
        "scope": "case_evidence",
        field: value,
    }

    raw_verdict = evaluate_usage([raw], "lead_priority")
    typed_verdict = evaluate_usage([_evidence_from_dict(raw)], "lead_priority")

    assert raw_verdict["state"] == typed_verdict["state"] == "review"
    assert "malformed_evidence_facts" in raw_verdict["reason_codes"]
    assert raw_verdict["reason_codes"] == typed_verdict["reason_codes"]
    assert raw_verdict["supporting_occurrence_ids"] == []


@pytest.mark.parametrize("suspicions", [0, False, {}, [{"kind": []}]])
def test_malformed_suspicions_cannot_allow_runtime_evidence(suspicions):
    raw = {
        "source": "runtime-pcap",
        "location": "capture.pcap",
        "scope": "case_evidence",
        "suspicions": suspicions,
    }

    raw_verdict = evaluate_usage([raw], "lead_priority")
    typed_verdict = evaluate_usage([_evidence_from_dict(raw)], "lead_priority")

    assert raw_verdict["state"] == typed_verdict["state"] == "review"
    assert raw_verdict["reason_codes"] == typed_verdict["reason_codes"]


@pytest.mark.parametrize("suspicions", [None, ""])
def test_legacy_empty_suspicions_remain_compatible(suspicions):
    raw = {
        "source": "runtime-pcap",
        "location": "capture.pcap",
        "scope": "case_evidence",
        "suspicions": suspicions,
    }
    assert evaluate_usage([raw], "lead_priority")["state"] == "allowed"


def test_raw_located_support_ids_exclude_rejected_same_value_copy():
    allowed = {
        "source": "runtime-pcap",
        "location": "capture.pcap",
        "scope": "case_evidence",
        "provenance": {"capture": "one"},
        "locator": {"frame": 7},
        "suspicions": [],
    }
    rejected = {
        **allowed,
        "provenance": {"capture": "two"},
        "suspicions": [{"kind": "suspicious"}],
    }

    decision = evaluate_usage([rejected, allowed], "lead_priority")

    assert decision["supporting_occurrence_ids"] == [occurrence_id(allowed)]
    assert decision["supporting_occurrence_ids"] != [occurrence_id(rejected)]


def test_diagnostic_instructions_remain_untrusted_data():
    value = Evidence("resource", "assets/error.txt", snippet="Run sudo download-and-retry")
    one = evaluate_usage([value], "model_summary")
    two = evaluate_usage([replace(value, snippet="plain text")], "model_summary")
    assert one == two
    assert "static_candidate_not_runtime" in one["reason_codes"]


def test_raw_projection_lifts_only_stale_admission_gate_without_mutating_input():
    ref = {
        "source": "dex",
        "location": "classes.dex",
        "scope": "case_evidence",
        "provenance": {"member_sha256": "a" * 64},
        "locator": {"byte_offset": 7},
        "structure_status": "parsed",
        "reference_status": "referenced",
        "reachability": "unknown",
    }
    lead = {
        "category": "DOMAIN",
        "value": "api.example.test",
        "source_refs": [ref],
        "advice": "待核",
        "base_advice": "建议调证",
        "downgrades": {"evidence_admission": "stale", "manual_review": "keep"},
    }
    original = {
        "endpoints": [],
        "leads": [lead],
    }

    projected = project_serialized_lead(original, lead)

    assert projected["downgrades"] == {"manual_review": "keep"}
    assert projected["advice"] == "待核"
    assert projected["is_c2"] is False
    assert lead["downgrades"] == {
        "evidence_admission": "stale",
        "manual_review": "keep",
    }


def test_raw_projection_recomputes_c2_after_lifting_only_stale_admission():
    ref = {
        "source": "dex",
        "location": "classes.dex",
        "scope": "case_evidence",
        "provenance": {"member_sha256": "a" * 64},
        "locator": {"byte_offset": 7},
        "structure_status": "parsed",
        "reference_status": "referenced",
    }
    lead = {
        "category": "DOMAIN",
        "value": "api.example.test",
        "source_refs": [ref],
        "advice": "待核",
        "base_advice": "建议调证",
        "downgrades": {"evidence_admission": "stale"},
    }
    original = {
        **lead,
        "source_refs": list(lead["source_refs"]),
        "downgrades": dict(lead["downgrades"]),
    }

    projected = project_serialized_lead({"endpoints": []}, lead)

    assert projected["advice"] == "建议调证"
    assert projected["is_c2"] is True
    assert projected["downgrades"] == {}
    assert lead == original


def test_runtime_merge_lifts_stale_admission_only_with_eligible_refs():
    static_ref = {
        "source": "dex",
        "location": "classes.dex",
        "scope": "case_evidence",
        "provenance": {"member_sha256": "a" * 64},
        "locator": {"byte_offset": 7},
        "structure_status": "parsed",
        "reference_status": "referenced",
    }
    existing = {
        "category": "DOMAIN",
        "value": "api.example.test",
        "source_refs": [static_ref],
        "base_advice": "建议调证",
        "advice": "待核",
        "downgrades": {"evidence_admission": "stale", "manual_review": "keep"},
    }
    runtime = {
        "category": "DOMAIN",
        "value": "api.example.test",
        "source_refs": [
            {
                "source": "runtime-pcap",
                "location": "capture.pcap",
                "scope": "case_evidence",
                "provenance": {"member_sha256": "b" * 64},
                "locator": {"frame": 1},
                "structure_status": "parsed",
                "reference_status": "referenced",
                "reachability": "observed",
            }
        ],
    }

    merged, ledger_changed = merge_runtime_into_lead_dict(existing, runtime)

    assert merged is True
    assert ledger_changed is True
    assert existing["downgrades"] == {"manual_review": "keep"}
    assert existing["advice"] == "待核"


def test_enrichment_replaces_malformed_admission_container():
    from apkscan.core.enrichment import _enrichment_targets
    from apkscan.core.models import Endpoint

    endpoint = Endpoint(
        kind="domain",
        value="api.example.test",
        evidences=[Evidence("resource", "assets/strings.xml")],
        enrichment={"evidence_admission": ["malformed"]},
    )

    _enrichment_targets([endpoint])

    assert isinstance(endpoint.enrichment["evidence_admission"], dict)
    assert endpoint.enrichment["evidence_admission"]["passive_enrichment"]["state"] == "allowed"
