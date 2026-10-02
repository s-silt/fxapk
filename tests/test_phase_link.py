# -*- coding: utf-8 -*-
"""Phase1 → Phase2 接缝：Phase2 只消费经公开验包器核验过的不可变包。"""
from __future__ import annotations

import json
from pathlib import Path

import apkscan.core.phase2.inventory as inventory
from tests.phase2_fixtures import write_verified_package


def _lead(value: str) -> dict:
    return {
        "category": "DOMAIN", "value": value, "advice": "待核",
        "is_runtime_seen": False, "is_runtime_contact": False, "is_c2": False,
        "source_refs": [{"evidence_id": f"ev-{value}", "scope": "case_evidence"}],
    }


def test_tampered_report_is_rejected_before_enumeration(tmp_path: Path) -> None:
    case_dir = tmp_path / "dir-name"
    package = write_verified_package(
        case_dir, "pkg", leads=[_lead("a.example.test")], case_id="CASE-1"
    )
    report = package / "report.json"
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["leads"].append(_lead("injected.example.test"))
    report.write_text(json.dumps(payload), encoding="utf-8")

    inv = inventory.build_inventory(case_dir)

    assert [i.code for i in inv.issues] == ["package_integrity_failed"]
    assert inv.candidates == []


def test_case_id_comes_from_manifest_never_directory_name(tmp_path: Path) -> None:
    case_dir = tmp_path / "dir-name"
    write_verified_package(case_dir, "pkg", leads=[_lead("a.example.test")], case_id="CASE-1")

    inv = inventory.build_inventory(case_dir)

    assert inv.issues == []
    assert inv.case_id == "CASE-1"


def test_packages_from_different_cases_fail_closed(tmp_path: Path) -> None:
    case_dir = tmp_path / "mixed"
    write_verified_package(case_dir, "p1", leads=[_lead("a.example.test")], case_id="CASE-1")
    write_verified_package(case_dir, "p2", leads=[_lead("b.example.test")], case_id="CASE-2")

    codes = {i.code for i in inventory.build_inventory(case_dir).issues}

    assert "case_id_conflict" in codes


def test_explicit_case_id_must_match_manifest(tmp_path: Path) -> None:
    case_dir = tmp_path / "c"
    write_verified_package(case_dir, "p1", leads=[_lead("a.example.test")], case_id="CASE-1")

    inv = inventory.build_inventory(case_dir, case_id="CASE-OTHER")

    assert {i.code for i in inv.issues} == {"case_id_mismatch"}


def test_registered_report_name_is_honoured(tmp_path: Path) -> None:
    case_dir = tmp_path / "c"
    write_verified_package(
        case_dir, "p1", leads=[_lead("a.example.test")], case_id="CASE-1",
        report_name="sample-analysis.json",
    )

    inv = inventory.build_inventory(case_dir)

    assert inv.issues == []
    assert {c.report_relpath for c in inv.candidates} == {"sample-analysis.json"}


def test_triage_reads_registered_report_not_fixed_name(tmp_path: Path) -> None:
    import apkscan.core.phase2.triage as triage

    case_dir = tmp_path / "c"
    write_verified_package(
        case_dir, "p1", case_id="CASE-1", report_name="sample-analysis.json",
        leads=[_lead("100.64.7.1")],
        endpoints=[{"kind": "ip", "value": "100.64.7.1",
                    "evidences": [{"evidence_id": "ev-ep", "scope": "case_evidence"}]}],
    )
    inv = inventory.build_inventory(case_dir)
    assert inv.issues == []

    result = triage.build_triage(inv, case_dir)

    [endpoint] = [p for p in result.parents if p.collection == "endpoints"]
    assert endpoint.tier == "R1-MIRROR"
