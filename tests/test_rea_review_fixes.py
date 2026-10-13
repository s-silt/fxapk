"""Portable regressions for the adjudicated REA review defects.

Synthetic fixtures only. These tests must not read ``out_*`` directories,
real samples, devices, or secrets.
"""

from __future__ import annotations

from copy import deepcopy
import json

import pytest

from apkscan.core.case_package import (
    CasePackageError,
    CasePackageErrorCode,
    create_case_package,
    verify_case_package,
)
from apkscan.core.closure.targets import select_targets
from apkscan.core.evidence_scope import (
    project_serialized_closure,
    project_serialized_leads,
)
from apkscan.core.report_io import report_from_dict
from apkscan.report.digest import build_digest
from apkscan.report.ioc import leads_to_ioc_rows

_HISTORY = {
    "history": [
        {
            "content_digest": "ab" * 32,
            "relation_verified": False,
            "runtime_observed": False,
            "closure_evaluated": False,
            "label": "analyst_reconstruction",
        }
    ]
}


def _ref(source: str, scope: str = "case_evidence", location: str = "synthetic") -> dict[str, str]:
    return {
        "source": source,
        "location": location,
        "snippet": "synthetic-observation",
        "scope": scope,
    }


def _report(
    refs: list[dict[str, str]],
    *,
    category: str = "DOMAIN",
    lead_value: str = "pay.example.com",
    endpoint_value: str | None = None,
    endpoint_refs: list[dict[str, str]] | None = None,
    base_advice: str | None = None,
    legacy_effective_advice: str | None = None,
) -> dict:
    kind = category.lower()
    lead: dict[str, object] = {
        "category": category,
        "value": lead_value,
        "advice": "建议调证",
        "source_refs": refs,
        "subject": "synthetic-subject",
        "notes": "synthetic-note",
    }
    if base_advice is not None:
        lead["base_advice"] = base_advice
    if legacy_effective_advice is not None:
        lead["legacy_effective_advice"] = legacy_effective_advice
    return {
        "schema_version": "1.2",
        "package_name": "com.example.synthetic",
        "analysis_status": "complete",
        "meta": {
            "sample_sha256": "a" * 64,
            "tool_version": "1.5.4",
            "ruleset_digest": "b" * 16,
            "native_recovery": deepcopy(_HISTORY),
            "closure": {
                "schema_version": "1.0",
                "status": "complete",
                "targets": [{"kind": kind, "value": lead_value}],
                "gaps": [],
                "next_actions": [],
            },
        },
        "leads": [lead],
        "endpoints": [
            {
                "kind": kind,
                "value": lead_value if endpoint_value is None else endpoint_value,
                "evidences": refs if endpoint_refs is None else endpoint_refs,
            }
        ],
        "findings": [],
    }


def _assert_not_direct(payload: dict, tmp_path) -> None:  # noqa: ANN001
    original = deepcopy(payload)
    lead_value = payload["leads"][0]["value"]
    sources = [ref["source"] for ref in payload["leads"][0]["source_refs"]]

    closure = project_serialized_closure(payload)
    projected = project_serialized_leads(payload)
    digest = build_digest(payload, redact=False)
    investigate = leads_to_ioc_rows(payload, only_investigate=True)
    visible = leads_to_ioc_rows(payload, only_investigate=False)
    typed = report_from_dict(deepcopy(payload))

    assert payload == original
    assert closure["status"] != "complete"
    assert projected[0]["advice"] != "建议调证"
    assert [ref["source"] for ref in projected[0]["source_refs"]] == sources
    assert projected[0]["value"] == lead_value
    assert digest["closure"]["status"] != "complete"
    assert all(item.get("advice") != "建议调证" for item in digest["leads"])
    assert investigate == []
    assert visible[0]["value"] == lead_value
    assert visible[0]["advice"] != "建议调证"
    assert typed.leads[0].advice != "建议调证"
    assert typed.leads[0].value == lead_value
    assert [item.source for item in typed.leads[0].source_refs] == sources
    assert typed.meta["native_recovery"] == _HISTORY
    assert typed.meta["native_recovery"]["history"][0]["relation_verified"] is False
    assert select_targets(typed) == []

    report_path = tmp_path / "report.json"
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    report_path.write_bytes(raw)
    manifest = tmp_path / "case-package.json"
    with pytest.raises(CasePackageError) as excinfo:
        create_case_package(
            report_path,
            manifest,
            case_id="case-001",
            producer="analyst-a",
        )
    assert excinfo.value.code is CasePackageErrorCode.CLOSURE_TARGET_LACKS_EVIDENCE
    assert not manifest.exists()
    assert report_path.read_bytes() == raw


@pytest.mark.parametrize(
    "refs",
    [
        [_ref("derived-native")],
        [_ref("external-web-observation")],
        [_ref("derived-native"), _ref("external-web-observation", location="web")],
        [
            _ref("derived-native"),
            _ref("batch", "batch_reference", "batch.csv"),
            _ref("legacy", "legacy_unspecified", "old.json"),
        ],
        [
            _ref("external-web-observation"),
            _ref("corpus", "batch_reference", "corpus.json"),
            _ref("import", "legacy_unspecified", "old.json"),
        ],
        [_ref(" Derived-Native ")],
        [_ref("EXTERNAL-WEB-OBSERVATION")],
        [
            _ref(" derived-native "),
            _ref(" External-Web-Observation ", location="web"),
            _ref("batch", "batch_reference", "batch.csv"),
            _ref("legacy", "legacy_unspecified", "old.json"),
        ],
    ],
    ids=[
        "derived-native",
        "external-web",
        "both-non-direct",
        "derived-plus-legacy-batch",
        "web-plus-legacy-batch",
        "derived-case-whitespace",
        "web-case",
        "normalized-plus-legacy-batch",
    ],
)
def test_r3_unverified_sources_are_not_direct_case_evidence(refs, tmp_path) -> None:  # noqa: ANN001
    payload = _report(refs)
    _assert_not_direct(payload, tmp_path)
    typed = report_from_dict(payload)
    assert typed.leads[0].legacy_effective_advice == "建议调证"
    assert typed.leads[0].base_advice is None
    assert "evidence_scope" in typed.leads[0].downgrades


def test_r3_existing_advice_anchors_are_preserved() -> None:
    payload = _report(
        [_ref("derived-native"), _ref("batch", "batch_reference", "batch.csv")],
        base_advice="建议调证",
        legacy_effective_advice="建议调证",
    )
    original = deepcopy(payload)
    typed = report_from_dict(payload)

    assert payload == original
    assert typed.leads[0].advice == "待核"
    assert typed.leads[0].base_advice == "建议调证"
    assert typed.leads[0].legacy_effective_advice == "建议调证"
    assert typed.leads[0].value == "pay.example.com"
    assert [item.source for item in typed.leads[0].source_refs] == [
        "derived-native",
        "batch",
    ]


def test_r3_whitespace_scope_token_stays_non_direct(tmp_path) -> None:  # noqa: ANN001
    payload = _report([_ref("dex", " case_evidence ", "classes.dex")])
    _assert_not_direct(payload, tmp_path)


def test_r3_missing_source_case_evidence_remains_direct(tmp_path) -> None:  # noqa: ANN001
    ref = {"location": "classes.dex", "snippet": "synthetic", "scope": "case_evidence"}
    payload = _report([ref])  # type: ignore[list-item]
    closure = project_serialized_closure(payload)
    typed = report_from_dict(deepcopy(payload))
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    manifest = tmp_path / "case-package.json"

    assert closure["status"] == "complete"
    assert typed.leads[0].advice == "建议调证"
    assert select_targets(typed)
    created = create_case_package(
        report_path, manifest, case_id="case-001", producer="analyst-a",
    )
    assert created["closure_snapshot"] == "complete"
    assert verify_case_package(manifest)["status"] == "verified"


@pytest.mark.parametrize("source", ["dex", "runtime-pcap"])
def test_r3_independent_case_evidence_keeps_trust(source: str, tmp_path) -> None:  # noqa: ANN001
    refs = [
        _ref("derived-native"),
        _ref("external-web-observation", location="web"),
        _ref("batch", "batch_reference", "batch.csv"),
        _ref(source, "case_evidence", "independent"),
    ]
    payload = _report(refs)
    original = deepcopy(payload)
    typed = report_from_dict(deepcopy(payload))
    digest = build_digest(payload, redact=False)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    manifest = tmp_path / "case-package.json"

    assert payload == original
    assert project_serialized_closure(payload)["status"] == "complete"
    assert project_serialized_leads(payload)[0]["advice"] == "建议调证"
    assert leads_to_ioc_rows(payload, only_investigate=True)
    assert digest["closure"]["status"] == "complete"
    assert typed.leads[0].advice == "建议调证"
    assert [item.source for item in typed.leads[0].source_refs] == [
        ref["source"] for ref in refs
    ]
    assert typed.meta["native_recovery"]["history"][0]["runtime_observed"] is False
    assert select_targets(typed)
    created = create_case_package(
        report_path, manifest, case_id="case-001", producer="analyst-a",
    )
    assert created["closure_snapshot"] == "complete"
    assert verify_case_package(manifest)["status"] == "verified"


@pytest.mark.parametrize(
    ("category", "lead_value", "endpoint_value", "direct_source"),
    [
        ("DOMAIN", "pay.example.com", "Pay.Example.com", "dex"),
        ("IP", "192.0.2.73:443/tcp", "192.0.2.73", "runtime-pcap"),
    ],
)
def test_r3_normalized_match_keeps_independent_evidence(
    category: str,
    lead_value: str,
    endpoint_value: str,
    direct_source: str,
    tmp_path,  # noqa: ANN001
) -> None:
    payload = _report(
        [_ref(" Derived-Native "), _ref("legacy", "legacy_unspecified", "old.json")],
        category=category,
        lead_value=lead_value,
        endpoint_value=endpoint_value,
        endpoint_refs=[_ref(direct_source, "case_evidence", "independent")],
    )
    original = deepcopy(payload)
    typed = report_from_dict(deepcopy(payload))
    projected = project_serialized_leads(payload)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    assert payload == original
    assert project_serialized_closure(payload)["status"] == "complete"
    assert projected[0]["advice"] == "建议调证"
    assert any(ref["source"] == direct_source for ref in projected[0]["source_refs"])
    assert payload["leads"][0]["source_refs"][0]["source"] == " Derived-Native "
    assert typed.leads[0].advice == "建议调证"
    assert typed.leads[0].value == lead_value
    assert select_targets(typed)
    assert leads_to_ioc_rows(payload, only_investigate=True)
    assert build_digest(payload, redact=False)["closure"]["status"] == "complete"
    manifest = tmp_path / "case-package.json"
    created = create_case_package(
        report_path, manifest, case_id="case-001", producer="analyst-a",
    )
    assert created["closure_snapshot"] == "complete"
    assert verify_case_package(manifest)["status"] == "verified"


def test_f2_current_round_brand_evidence_does_not_restamp_history(tmp_path) -> None:  # noqa: ANN001
    import base64

    from apkscan.core.models import Report
    from apkscan.dynamic.capture_provenance import capture_scope
    from apkscan.dynamic.merge import decrypt_runtime_messages

    def event(name: str) -> dict[str, str]:
        raw = json.dumps({"webName": name}).encode("utf-8")
        return {"plaintext_b64": base64.b64encode(raw).decode("ascii")}

    report = Report(
        package_name="com.example.synthetic",
        meta={},
        endpoints=[],
        leads=[],
        findings=[],
        analyzer_status=[],
    )
    missing = str(tmp_path / "missing-runtime.json")
    with capture_scope("capture:sha1", verified=False):
        decrypt_runtime_messages(report, missing, recipe_events=[event("EarlierOnly")])
    with capture_scope("capture:sha2", verified=True):
        decrypt_runtime_messages(report, missing, recipe_events=[event("LaterOnly")])

    finding = next(item for item in report.findings if item.id == "RUNTIME-BRAND-HINTS")
    earlier = [item for item in finding.evidences if item.snippet == "EarlierOnly"]
    later = [item for item in finding.evidences if item.snippet == "LaterOnly"]
    assert report.meta["runtime_brand_hints"] == ["EarlierOnly", "LaterOnly"]
    assert "EarlierOnly" in finding.description
    assert "LaterOnly" in finding.description
    assert len(earlier) == 1
    assert earlier[0].source == "runtime-derived"
    assert earlier[0].location.startswith("capture:sha1::")
    assert "sha2" not in earlier[0].location
    assert len(later) == 1
    assert later[0].source == "runtime"
    assert later[0].location.startswith("capture:sha2::")


def test_f1_supplement_html_keeps_lead_warnings(tmp_path) -> None:  # noqa: ANN001
    from apkscan.core.web_supplement_report import supplement_report

    report_path = tmp_path / "in" / "report.json"
    report_path.parent.mkdir()
    payload = {
        "schema_version": "1.2",
        "package_name": "com.example.synthetic",
        "analysis_status": "complete",
        "meta": {"sample_sha256": "c" * 64, "tool_version": "1.5.4"},
        "endpoints": [],
        "findings": [],
        "leads": [
            {
                "category": "DOMAIN",
                "value": "pay.example.test",
                "advice": "建议调证",
                "base_advice": "建议调证",
                "legacy_effective_advice": "待核",
                "confidence": "HIGH",
                "subject": "keep-subject",
                "where_to_request": "keep-where",
                "evidence_to_obtain": ["keep-obtain"],
                "notes": "keep-note",
                "downgrades": {"synthetic-rule": "kept"},
                "shape_uncertain": True,
                "sni_masquerade": ["music.example.test"],
                "case_note": "keep-extension",
                "source_refs": [{
                    "source": "dex",
                    "location": "Synthetic.java",
                    "snippet": "pay.example.test",
                    "scope": "case_evidence",
                }],
            },
            {
                "category": "NOT-A-REAL-CATEGORY",
                "value": "unknown-token",
                "advice": "待核",
                "notes": "unknown-note",
            },
        ],
    }
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    report_path.write_bytes(raw)
    config = tmp_path / "off.json"
    config.write_text(json.dumps({
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "off",
        "source": "bundle",
        "path": str(tmp_path / "unused-bundle"),
    }), encoding="utf-8")
    out = tmp_path / "out"
    result = supplement_report(report_path, config, out)
    written = json.loads((out / "report.json").read_text(encoding="utf-8"))
    html = (out / "report.html").read_text(encoding="utf-8")
    lead = written["leads"][0]

    assert result["exit_code"] == 3
    assert report_path.read_bytes() == raw
    assert lead["shape_uncertain"] is True
    assert lead["sni_masquerade"] == ["music.example.test"]
    assert lead["case_note"] == "keep-extension"
    assert lead["notes"] == "keep-note"
    assert lead["downgrades"] == {"synthetic-rule": "kept"}
    assert lead["base_advice"] == "建议调证"
    assert lead["legacy_effective_advice"] == "待核"
    assert written["leads"][1]["category"] == "NOT-A-REAL-CATEGORY"
    assert "标的形态存疑" in html
    assert "切勿向其发函" in html
    assert "music.example.test" in html
