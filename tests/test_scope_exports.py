"""Evidence scope must survive every raw-report decision/output boundary."""

from __future__ import annotations

from copy import deepcopy

from apkscan.core.evidence_scope import project_serialized_leads
from apkscan.core.jsonl import report_to_events
from apkscan.report.digest import build_digest
from apkscan.report.ioc import leads_to_ioc_rows
from apkscan.report.letters import build_letters


def _evidence(scope: str | None, *, source: str = "dex", location: str = "classes.dex") -> dict:
    item = {"source": source, "location": location}
    if scope is not None:
        item["scope"] = scope
    return item


def _lead(
    value: str,
    scope: str | None,
    *,
    category: str = "DOMAIN",
    source: str = "runtime-pcap",
) -> dict:
    return {
        "category": category,
        "value": value,
        "where_to_request": "示例云厂商",
        "evidence_to_obtain": ["租户实名与访问日志"],
        "advice": "建议调证",
        "confidence": "HIGH",
        "is_c2": True,
        # Forged materialized caches must never outrank Evidence.scope.
        "is_runtime_seen": True,
        "is_runtime_contact": True,
        "source_refs": [_evidence(scope, source=source)],
    }


def _report() -> dict:
    return {
        "schema_version": "1.2",
        "meta": {"sample_sha256": "scope-export-sample"},
        "leads": [
            _lead("batch-only.example.test", "batch_reference"),
            _lead("legacy-only.example.test", None),
            _lead("bad-scope.example.test", "not-a-scope"),
            _lead("direct.example.test", "case_evidence"),
            # A matching direct Endpoint is also current-case evidence.  The
            # Lead may still contain a batch reference; case+batch is valid.
            _lead("endpoint-direct.example.test", "batch_reference"),
        ],
        "endpoints": [
            {
                "kind": "domain",
                "value": "endpoint-direct.example.test",
                "evidences": [
                    _evidence(
                        "case_evidence",
                        source="runtime-pcap",
                        location="capture.pcap:flow-7",
                    )
                ],
            }
        ],
    }


def test_digest_projects_scope_before_sorting_and_does_not_mutate_input() -> None:
    report = _report()
    before = deepcopy(report)

    digest = build_digest(report, redact=False)

    assert report == before
    by_value = {item["value"]: item for item in digest["leads"]}
    for value in (
        "batch-only.example.test",
        "legacy-only.example.test",
        "bad-scope.example.test",
    ):
        assert by_value[value]["advice"] == "待核"
        assert by_value[value]["is_c2"] is False
        assert by_value[value]["is_runtime_seen"] is False
        assert by_value[value]["is_runtime_contact"] is False

    assert by_value["direct.example.test"]["advice"] == "建议调证"
    assert by_value["direct.example.test"]["is_c2"] is True
    assert by_value["direct.example.test"]["is_runtime_contact"] is True
    assert by_value["endpoint-direct.example.test"]["advice"] == "建议调证"
    assert by_value["endpoint-direct.example.test"]["is_runtime_contact"] is True
    # Raw order starts with a forged batch C2.  Sorting must use the projected
    # advice, so both directly-supported leads precede every reference-only one.
    assert [item["value"] for item in digest["leads"][:2]] == [
        "direct.example.test",
        "endpoint-direct.example.test",
    ]
    assert digest["summary"]["by_advice"] == {"待核": 3, "建议调证": 2}


def test_letters_never_render_batch_legacy_or_bad_scope_as_case_evidence() -> None:
    report = _report()
    before = deepcopy(report)

    letters = build_letters(report)

    assert report == before
    assert {item["target"] for item in letters} == {
        "direct.example.test",
        "endpoint-direct.example.test",
    }
    by_target = {item["target"]: item for item in letters}
    assert by_target["direct.example.test"]["evidence_refs"] == [
        "runtime-pcap:classes.dex"
    ]
    assert by_target["endpoint-direct.example.test"]["evidence_refs"] == [
        "runtime-pcap:capture.pcap:flow-7"
    ]


def test_ioc_normal_export_retains_references_but_demotes_them() -> None:
    report = _report()
    before = deepcopy(report)

    rows = leads_to_ioc_rows(report)
    investigate = leads_to_ioc_rows(report, only_investigate=True)

    assert report == before
    assert len(rows) == 5
    by_value = {item["value"]: item for item in rows}
    for value in (
        "batch-only.example.test",
        "legacy-only.example.test",
        "bad-scope.example.test",
    ):
        assert by_value[value]["advice"] == "待核"
        assert by_value[value]["is_c2"] is False
    assert {item["value"] for item in investigate} == {
        "direct.example.test",
        "endpoint-direct.example.test",
    }
    # When a matching Endpoint grants eligibility, cite its direct evidence,
    # not the Lead's batch-only reference.
    assert by_value["endpoint-direct.example.test"]["source"] == (
        "runtime-pcap:capture.pcap:flow-7"
    )


def test_jsonl_projects_scope_before_discarding_source_refs() -> None:
    report = _report()
    before = deepcopy(report)

    events = report_to_events(report)

    assert report == before
    leads = {item["value"]: item for item in events if item["type"] == "lead"}
    for value in (
        "batch-only.example.test",
        "legacy-only.example.test",
        "bad-scope.example.test",
    ):
        assert leads[value]["advice"] == "待核"
        assert leads[value]["evidence_scope_summary"] == {
            "qualified": False,
            "case_evidence_refs": 0,
        }
    assert leads["direct.example.test"]["advice"] == "建议调证"
    assert leads["direct.example.test"]["evidence_scope_summary"] == {
        "qualified": True,
        "case_evidence_refs": 1,
    }
    assert leads["endpoint-direct.example.test"]["advice"] == "建议调证"
    assert leads["endpoint-direct.example.test"]["evidence_scope_summary"] == {
        "qualified": True,
        "case_evidence_refs": 1,
    }


def test_projection_recomputes_is_c2_even_when_direct_evidence_exists() -> None:
    report = {
        "leads": [
            _lead(
                "synthetic-contact",
                "case_evidence",
                category="CONTACT",
                source="dex",
            ),
            {
                **_lead("review.example.test", "case_evidence", source="dex"),
                "advice": "待核",
                "is_c2": True,
            },
        ]
    }

    projected = project_serialized_leads(report)

    assert projected[0]["advice"] == "建议调证"
    assert projected[0]["is_c2"] is False
    assert projected[1]["advice"] == "待核"
    assert projected[1]["is_c2"] is False
