"""Typed report outputs must apply the same scope gate as raw exports."""

from __future__ import annotations

from copy import deepcopy

import pytest

from apkscan.core.report_io import report_from_dict


def _contact(scope: str | None) -> dict:
    evidence = {"source": "dex", "location": "classes.dex", "snippet": "contact"}
    if scope is not None:
        evidence["scope"] = scope
    return {
        "category": "CONTACT",
        "value": "synthetic-contact",
        "advice": "建议调证",
        "source_refs": [evidence],
    }


@pytest.mark.parametrize(
    "scope", ["batch_reference", "legacy_unspecified", None, "bad", " case_evidence "]
)
def test_typed_load_demotes_reference_only_non_network_leads(scope: str | None) -> None:
    payload = {
        "schema_version": "1.2",
        "package_name": "com.example.synthetic",
        "leads": [_contact(scope)],
    }
    before = deepcopy(payload)

    report = report_from_dict(payload)

    assert payload == before
    assert report.leads[0].advice == "待核"
    assert "evidence_scope" in report.leads[0].downgrades


def test_typed_load_preserves_direct_non_network_lead() -> None:
    payload = {
        "schema_version": "1.2",
        "package_name": "com.example.synthetic",
        "leads": [_contact("case_evidence")],
    }

    report = report_from_dict(payload)

    assert report.leads[0].advice == "建议调证"
    assert "evidence_scope" not in report.leads[0].downgrades
