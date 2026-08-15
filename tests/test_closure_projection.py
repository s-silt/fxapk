"""Adversarial checks for the shared, scope-aware closure projection."""

from __future__ import annotations

from copy import deepcopy
import json

import pytest

from apkscan.core.case_package import (
    CasePackageError,
    create_case_package,
    project_case_status,
    verify_case_package,
)
from apkscan.core.evidence_scope import project_serialized_closure
from apkscan.core.report_io import report_from_dict
from apkscan.report.digest import build_digest


def _report(
    *,
    scope: str | None = "case_evidence",
    evidence_on: str = "lead",
    targets: list[dict[str, str]] | None = None,
) -> dict:
    evidence = {
        "source": "runtime-pcap",
        "location": "capture.pcap",
        "snippet": "synthetic",
    }
    if scope is not None:
        evidence["scope"] = scope
    target_list = (
        targets
        if targets is not None
        else [{"kind": "domain", "value": "backend.example"}]
    )
    lead_refs = [evidence] if evidence_on == "lead" else []
    endpoint_refs = [evidence] if evidence_on == "endpoint" else []
    return {
        "schema_version": "1.2",
        "package_name": "com.example.synthetic",
        "analysis_status": "complete",
        "meta": {
            "sample_sha256": "a" * 64,
            "tool_version": "1.5.4",
            "ruleset_digest": "b" * 16,
            "closure": {
                "schema_version": "1.0",
                "status": "complete",
                "targets": target_list,
                "gaps": [],
                "next_actions": [],
            },
        },
        "leads": [
            {
                "category": "DOMAIN",
                "value": "backend.example",
                "advice": "建议调证",
                "source_refs": lead_refs,
            }
        ],
        "endpoints": [
            {
                "kind": "domain",
                "value": "backend.example",
                "evidences": endpoint_refs,
            }
        ],
    }


@pytest.mark.parametrize(
    "scope", ["batch_reference", "legacy_unspecified", None, "bad", " case_evidence "]
)
def test_complete_closure_downgrades_when_target_has_no_direct_case_evidence(
    scope: str | None,
) -> None:
    payload = _report(scope=scope)
    before = deepcopy(payload)

    closure = project_serialized_closure(payload)

    assert payload == before
    assert closure["status"] == "partial"
    assert "backend.example" in " ".join(closure["gaps"])
    assert closure["next_actions"]


@pytest.mark.parametrize("evidence_on", ["lead", "endpoint"])
def test_complete_closure_stays_complete_with_matching_direct_evidence(
    evidence_on: str,
) -> None:
    payload = _report(evidence_on=evidence_on)

    closure = project_serialized_closure(payload)

    assert closure["status"] == "complete"
    assert closure["gaps"] == []


def test_complete_closure_with_mixed_target_support_downgrades_to_partial() -> None:
    payload = _report(
        targets=[
            {"kind": "domain", "value": "backend.example"},
            {"kind": "ip", "value": "192.0.2.44"},
        ]
    )

    closure = project_serialized_closure(payload)

    assert closure["status"] == "partial"
    assert "192.0.2.44" in " ".join(closure["gaps"])


@pytest.mark.parametrize("field", ["endpoint", "lead"])
def test_malformed_whitespace_network_kind_cannot_qualify_closure(field: str) -> None:
    payload = _report(scope="case_evidence", evidence_on=field)
    if field == "endpoint":
        payload["endpoints"][0]["kind"] = " domain "
    else:
        payload["leads"][0]["category"] = " DOMAIN "

    closure = project_serialized_closure(payload)

    assert closure["status"] == "partial"


def test_whitespace_complete_status_cannot_bypass_scope_projection() -> None:
    payload = _report(scope="batch_reference")
    payload["meta"]["closure"]["status"] = " complete "

    closure = project_serialized_closure(payload)

    assert closure["status"] == "partial"


@pytest.mark.parametrize("targets", [None, [], "bad"])
def test_complete_closure_without_valid_target_inventory_fails(targets: object) -> None:
    payload = _report()
    if targets is None:
        payload["meta"]["closure"].pop("targets")
    else:
        payload["meta"]["closure"]["targets"] = targets

    closure = project_serialized_closure(payload)

    assert closure["status"] == "failed"
    assert closure["gaps"]
    assert closure["next_actions"]


def test_non_complete_closure_is_never_upgraded_and_input_is_unchanged() -> None:
    payload = _report(scope="case_evidence")
    payload["meta"]["closure"]["status"] = "partial"
    before = deepcopy(payload)

    closure = project_serialized_closure(payload)

    assert payload == before
    assert closure == before["meta"]["closure"]


def test_typed_load_digest_and_bare_status_share_safe_closure_projection(tmp_path) -> None:  # noqa: ANN001
    payload = _report(scope="batch_reference")
    typed = report_from_dict(payload)
    digest = build_digest(payload, redact=False)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    assert typed.meta["closure"]["status"] == "partial"
    assert digest["closure"]["status"] == "partial"
    assert project_case_status(report_path)["closure"] == "partial"


def test_phase1_package_strictly_rejects_raw_complete_claim_that_projection_downgrades(
    tmp_path,
) -> None:  # noqa: ANN001
    payload = _report(scope="batch_reference")
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    manifest = tmp_path / "case-package.json"

    with pytest.raises(CasePackageError, match="complete closure"):
        create_case_package(
            report_path,
            manifest,
            case_id="case-001",
            producer="analyst-a",
        )

    assert not manifest.exists()


def test_verifier_rejects_forged_package_even_when_snapshot_matches_projection(
    tmp_path,
) -> None:  # noqa: ANN001
    payload = _report(scope="case_evidence")
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    manifest = tmp_path / "case-package.json"
    create_case_package(
        report_path,
        manifest,
        case_id="case-001",
        producer="analyst-a",
    )

    payload = _report(scope="batch_reference")
    report_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_payload["closure_snapshot"] = "partial"
    # Keep the artifact byte hash honest so the verifier must reject the scope
    # conflict, not merely report an unrelated integrity mismatch.
    import hashlib

    raw = report_path.read_bytes()
    manifest_payload["artifacts"][0]["size"] = len(raw)
    manifest_payload["artifacts"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    body = {
        key: value for key, value in manifest_payload.items() if key != "package_id"
    }
    manifest_payload["package_id"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest.write_text(json.dumps(manifest_payload, ensure_ascii=False), encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert any("complete closure" in issue for issue in result["issues"])
