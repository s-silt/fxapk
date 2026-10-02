# -*- coding: utf-8 -*-
"""Phase1EvidenceInventory → ReviewCoverage：用独立分母证明第二阶段没有漏处理。"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

import apkscan.core.phase2.inventory as coverage
from apkscan.core.json_contract import JsonContractError
from tests.phase2_fixtures import write_verified_package


def _default_report() -> dict:
    return {
        "leads": [{
            "category": "DOMAIN", "value": "api.example.test", "advice": "待核",
            "source_refs": [{"evidence_id": "ev-lead", "scope": "case_evidence"}],
        }],
        "endpoints": [{
            "kind": "ip", "value": "100.64.0.10",
            "evidences": [{"evidence_id": "ev-endpoint", "scope": "case_evidence"}],
        }],
        "findings": [{
            "id": "SYNTHETIC-RULE", "title": "Synthetic finding",
            "evidences": [{"evidence_id": "ev-finding", "scope": "case_evidence"}],
        }],
    }


def _write_package(
    case_dir: Path,
    name: str = "synthetic-package",
    *,
    report: dict | None = None,
    report_name: str = "report.json",
) -> Path:
    """Signed Phase1 package that passes the public verifier."""
    payload = report if report is not None else _default_report()
    return write_verified_package(
        case_dir, name,
        leads=payload.get("leads"), endpoints=payload.get("endpoints"),
        findings=payload.get("findings"), case_id="synthetic-case",
        report_name=report_name,
    )


def _write_stub_package(
    case_dir: Path,
    name: str = "synthetic-package",
    *,
    report: dict | list | None = None,
    package_id: str = "pkg-synthetic-1",
) -> Path:
    """Unsigned stub; only valid with ``build_inventory(..., verify_packages=False)``."""
    package = case_dir / name
    package.mkdir(parents=True)
    (package / "case-package.json").write_text(
        json.dumps({"package_id": package_id}), encoding="utf-8"
    )
    payload = report if report is not None else _default_report()
    (package / "report.json").write_text(json.dumps(payload), encoding="utf-8")
    return package


def _coverage_entry(candidate, disposition="report_only", **extra):
    entry = {
        "candidate_id": candidate.candidate_id,
        "disposition": disposition,
    }
    if disposition == "accepted_clue":
        entry.update({
            "clue_id": extra.pop("clue_id", "clue-synthetic-1"),
            "provenance": candidate.provenance_dict(),
        })
    else:
        entry["reason"] = extra.pop("reason", "synthetic review decision")
    entry.update(extra)
    return entry


def _complete_snapshot(inv, overrides=None):
    overrides = overrides or {}
    return {
        "schema_version": "1.0",
        "case_id": inv.case_id,
        "inventory_fingerprint": inv.fingerprint,
        "entries": [
            overrides.get(c.candidate_id, _coverage_entry(c)) for c in inv.candidates
        ],
    }


def _expanded_clue(candidate, clue_id="clue-synthetic-1"):
    return {
        "clue_id": clue_id,
        "case_id": "synthetic-case",
        "origin": "phase1",
        "phase1_provenance": candidate.provenance_dict(),
    }


def test_inventory_enumerates_all_three_phase1_collections(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir)
    inv = coverage.build_inventory(case_dir)

    assert inv.issues == []
    assert [c.collection for c in inv.candidates] == ["endpoints", "findings", "leads"]
    assert len({c.candidate_id for c in inv.candidates}) == 3


def test_inventory_reads_report_artifact_registered_by_public_case_package(
    tmp_path: Path,
) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir, report_name="sample-analysis.json")

    inv = coverage.build_inventory(case_dir)

    assert inv.issues == []
    assert len(inv.candidates) == 3
    assert {c.report_relpath for c in inv.candidates} == {"sample-analysis.json"}
    assert inv.case_id == "synthetic-case"


def test_inventory_rejects_tampered_package(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    package = _write_package(case_dir)
    report = json.loads((package / "report.json").read_text(encoding="utf-8"))
    report["leads"] = []
    (package / "report.json").write_text(json.dumps(report), encoding="utf-8")

    inv = coverage.build_inventory(case_dir)

    assert [i.code for i in inv.issues] == ["package_integrity_failed"]
    assert inv.candidates == []


def test_inventory_case_id_comes_from_manifest_not_directory(tmp_path: Path) -> None:
    case_dir = tmp_path / "directory-label"
    write_verified_package(case_dir, "pkg", case_id="CASE-SYNTH-1", leads=[{
        "category": "DOMAIN", "value": "api.example.test",
        "source_refs": [{"evidence_id": "ev-1", "scope": "case_evidence"}],
    }])

    inv = coverage.build_inventory(case_dir)
    assert inv.issues == []
    assert inv.case_id == "CASE-SYNTH-1"

    mismatch = coverage.build_inventory(case_dir, case_id="CASE-OTHER")
    assert any(i.code == "case_id_mismatch" for i in mismatch.issues)


def test_inventory_blocks_packages_from_different_cases(tmp_path: Path) -> None:
    case_dir = tmp_path / "mixed"
    for name, cid in (("a", "CASE-A"), ("b", "CASE-B")):
        write_verified_package(case_dir, name, case_id=cid)

    inv = coverage.build_inventory(case_dir)
    assert any(i.code == "case_id_conflict" for i in inv.issues)


def test_repeated_finding_rule_ids_remain_distinct_by_finding_content(
    tmp_path: Path,
) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir, report={
        "leads": [], "endpoints": [],
        "findings": [
            {"id": "COMPONENT", "title": "exported", "description": "Activity A",
             "evidences": [{"evidence_id": "ev-a", "scope": "case_evidence"}]},
            {"id": "COMPONENT", "title": "exported", "description": "Activity B",
             "evidences": [{"evidence_id": "ev-b", "scope": "case_evidence"}]},
        ],
    })

    inv = coverage.build_inventory(case_dir)

    assert inv.issues == []
    assert len(inv.candidates) == 2
    assert len({c.parent_id for c in inv.candidates}) == 2


def test_repeated_evidence_identity_under_one_parent_is_one_review_candidate(
    tmp_path: Path,
) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir, report={
        "leads": [{
            "category": "DOMAIN", "value": "api.example.test",
            "source_refs": [
                {"evidence_id": "ev-one", "scope": "case_evidence", "location": "a"},
                {"evidence_id": "ev-one", "scope": "case_evidence", "location": "b"},
            ],
        }],
        "endpoints": [], "findings": [],
    })

    inv = coverage.build_inventory(case_dir)

    assert inv.issues == []
    assert len(inv.candidates) == 1


def test_parent_without_evidence_still_requires_disposition(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir, report={
        "leads": [{"category": "OTHER", "value": "synthetic marker", "source_refs": []}],
        "endpoints": [], "findings": [],
    })
    inv = coverage.build_inventory(case_dir)
    [candidate] = inv.candidates

    assert candidate.has_evidence is False
    assert candidate.evidence_id == "__parent__"
    audit = coverage.audit_coverage(inv, {
        "schema_version": "1.0", "case_id": inv.case_id, "entries": [],
    }, [])
    assert any(issue.code == "missing_disposition" for issue in audit.blockers)


def test_malformed_report_collection_blocks_instead_of_becoming_empty(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_stub_package(case_dir, report={"leads": {}, "endpoints": [], "findings": []})
    inv = coverage.build_inventory(case_dir, verify_packages=False)
    assert any(issue.code == "wrong_collection_shape" for issue in inv.issues)
    assert coverage.audit_coverage(inv, {}, []).ok is False


def test_candidate_identity_ignores_directory_and_json_key_order(tmp_path: Path) -> None:
    report_a = {
        "leads": [{"category": "DOMAIN", "value": "api.example.test", "source_refs": [
            {"evidence_id": "ev-1", "scope": "case_evidence", "snippet": "x"}
        ]}], "endpoints": [], "findings": [],
    }
    report_b = {
        "findings": [], "endpoints": [],
        "leads": [{"source_refs": [
            {"snippet": "x", "scope": "case_evidence", "evidence_id": "ev-1"}
        ], "value": "api.example.test", "category": "DOMAIN"}],
    }
    case_a, case_b = tmp_path / "a", tmp_path / "b"
    # 同 package_id 才可比较候选身份；签名包的 package_id 含 created_at，故用 stub。
    _write_stub_package(case_a, "left", report=report_a)
    _write_stub_package(case_b, "right", report=report_b)
    assert coverage.build_inventory(case_a, verify_packages=False).candidates[0].candidate_id == (
        coverage.build_inventory(case_b, verify_packages=False).candidates[0].candidate_id
    )


def test_duplicate_and_unknown_dispositions_block(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir)
    inv = coverage.build_inventory(case_dir)
    entries = [_coverage_entry(c) for c in inv.candidates]
    entries.append(dict(entries[0]))
    entries.append({
        "candidate_id": "p1:" + "0" * 64,
        "disposition": "report_only", "reason": "stale synthetic entry",
    })
    audit = coverage.audit_coverage(inv, {
        "schema_version": "1.0", "case_id": inv.case_id, "entries": entries,
    }, [])
    assert {issue.code for issue in audit.blockers} >= {
        "duplicate_disposition", "unknown_candidate",
    }


def test_nonaccepted_reason_and_pending_action_are_required(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir)
    inv = coverage.build_inventory(case_dir)
    first, second = inv.candidates[:2]
    snapshot = _complete_snapshot(inv, {
        first.candidate_id: _coverage_entry(first, reason=""),
        second.candidate_id: _coverage_entry(
            second, "pending_with_action", reason="needs evidence", next_action="",
        ),
    })
    codes = {i.code for i in coverage.audit_coverage(inv, snapshot, []).blockers}
    assert {"missing_reason", "missing_next_action"} <= codes


def test_expanded_accepted_clue_must_match_bidirectionally(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir)
    inv = coverage.build_inventory(case_dir)
    candidate = inv.candidates[0]
    snapshot = _complete_snapshot(inv, {
        candidate.candidate_id: _coverage_entry(candidate, "accepted_clue"),
    })
    good = coverage.audit_coverage(inv, snapshot, [_expanded_clue(candidate)])
    assert good.ok

    bad_clue = _expanded_clue(candidate)
    bad_clue["phase1_provenance"]["evidence_id"] = "ev-contradiction"
    bad = coverage.audit_coverage(inv, snapshot, [bad_clue])
    assert any(i.code == "provenance_mismatch" for i in bad.blockers)


def test_clue_pointing_to_nonaccepted_candidate_blocks(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir)
    inv = coverage.build_inventory(case_dir)
    candidate = inv.candidates[0]
    audit = coverage.audit_coverage(
        inv, _complete_snapshot(inv), [_expanded_clue(candidate)]
    )
    assert any(i.code == "clue_not_accepted" for i in audit.blockers)


def test_legacy_evidence_id_is_allowed_only_when_package_mapping_unique(tmp_path: Path) -> None:
    # 构造后改写 report 以制造歧义，必然破坏包哈希；本测试只验 legacy 映射，故用 stub。
    case_dir = tmp_path / "synthetic-case"
    package = _write_stub_package(case_dir)
    inv = coverage.build_inventory(case_dir, verify_packages=False)
    candidate = next(c for c in inv.candidates if c.evidence_id == "ev-lead")
    snapshot = _complete_snapshot(inv, {
        candidate.candidate_id: _coverage_entry(candidate, "accepted_clue"),
    })
    legacy = {
        "clue_id": "clue-synthetic-1", "case_id": inv.case_id, "origin": "phase1",
        "phase1_provenance": {
            "evidence_id": "ev-lead", "report_relpath": "report.json",
            "manifest_sha256": hashlib.sha256(
                (package / "case-package.json").read_bytes()
            ).hexdigest(),
        },
    }
    assert coverage.audit_coverage(inv, snapshot, [legacy]).ok

    report = json.loads((package / "report.json").read_text(encoding="utf-8"))
    report["endpoints"].append({
        "kind": "domain", "value": "second.example.test",
        "evidences": [{"evidence_id": "ev-lead", "scope": "case_evidence"}],
    })
    (package / "report.json").write_text(json.dumps(report), encoding="utf-8")
    ambiguous_inv = coverage.build_inventory(case_dir, verify_packages=False)
    ambiguous_candidate = next(
        c for c in ambiguous_inv.candidates
        if c.collection == "leads" and c.evidence_id == "ev-lead"
    )
    ambiguous_snapshot = _complete_snapshot(ambiguous_inv, {
        ambiguous_candidate.candidate_id: _coverage_entry(
            ambiguous_candidate, "accepted_clue"
        ),
    })
    audit = coverage.audit_coverage(ambiguous_inv, ambiguous_snapshot, [legacy])
    assert any(i.code == "ambiguous_legacy_provenance" for i in audit.blockers)


def test_legacy_clue_value_disambiguates_parent_and_prefers_lead(
    tmp_path: Path,
) -> None:
    case_dir = tmp_path / "synthetic-case"
    package = _write_package(case_dir, report={
        "leads": [{
            "category": "DOMAIN", "value": "api.example.test",
            "source_refs": [{"evidence_id": "ev-shared", "scope": "case_evidence"}],
        }],
        "endpoints": [{
            "kind": "domain", "value": "api.example.test",
            "evidences": [{"evidence_id": "ev-shared", "scope": "case_evidence"}],
        }],
        "findings": [],
    })
    inv = coverage.build_inventory(case_dir)
    lead = next(c for c in inv.candidates if c.collection == "leads")
    snapshot = _complete_snapshot(inv, {
        lead.candidate_id: _coverage_entry(lead, "accepted_clue"),
    })
    clue = {
        "clue_id": "clue-synthetic-1", "case_id": inv.case_id,
        "clue_value": "api.example.test", "origin": "phase1",
        "phase1_provenance": {
            "evidence_id": "ev-shared", "report_relpath": "report.json",
            "manifest_sha256": hashlib.sha256(
                (package / "case-package.json").read_bytes()
            ).hexdigest(),
        },
    }

    assert coverage.audit_coverage(inv, snapshot, [clue]).ok


def test_duplicate_package_id_and_partial_package_block(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    one = _write_package(case_dir, "one")
    shutil.copytree(one, case_dir / "two")  # 字节同一的包副本 → 相同 package_id
    partial = case_dir / "partial"
    partial.mkdir()
    (partial / "case-package.json").write_text('{"package_id":"partial"}', encoding="utf-8")
    codes = {issue.code for issue in coverage.build_inventory(case_dir).issues}
    assert {"duplicate_package_id", "missing_pair_file"} <= codes


def test_inventory_resource_limit_fails_closed(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir)
    inv = coverage.build_inventory(
        case_dir, coverage.InventoryLimits(max_total_candidates=2)
    )
    assert any(issue.code == "resource_limit_exceeded" for issue in inv.issues)


def test_read_json_bounded_keeps_size_and_depth_limits(tmp_path: Path) -> None:
    flat = tmp_path / "flat.json"
    flat.write_text(
        '{"host":"api.example.test","score":0.5}',
        encoding="utf-8",
    )
    payload, raw = coverage._read_json_bounded(flat, 4096, 8)
    assert payload == {"host": "api.example.test", "score": 0.5}
    assert raw == flat.read_bytes()

    with pytest.raises(OverflowError, match="file size"):
        coverage._read_json_bounded(flat, 1, 8)

    deep = tmp_path / "deep.json"
    deep.write_text('{"a":{"b":1}}', encoding="utf-8")
    with pytest.raises(OverflowError, match="JSON depth"):
        coverage._read_json_bounded(deep, 4096, 1)


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e9999"])
def test_read_json_bounded_rejects_nonfinite_token(tmp_path: Path, token: str) -> None:
    path = tmp_path / "value.json"
    path.write_text('{"bad":' + token + "}", encoding="utf-8")

    with pytest.raises(JsonContractError) as excinfo:
        coverage._read_json_bounded(path, 4096, 8)

    assert excinfo.value.diagnostic_code == "non_finite_json_number"
    assert token not in excinfo.value.public_message


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e9999"])
@pytest.mark.parametrize("which", ["manifest", "report"])
def test_inventory_rejects_nonfinite_json(tmp_path: Path, token: str, which: str) -> None:
    case_dir = tmp_path / "synthetic-case"
    package = case_dir / "pkg"
    package.mkdir(parents=True)
    manifest = '{"package_id":"pkg-synthetic"}'
    report = '{"leads":[],"endpoints":[],"findings":[]}'
    if which == "manifest":
        manifest = '{"package_id":"pkg-synthetic","bad":' + token + "}"
    else:
        report = '{"leads":[],"endpoints":[],"findings":[],"bad":' + token + "}"
    (package / "case-package.json").write_text(manifest, encoding="utf-8")
    (package / "report.json").write_text(report, encoding="utf-8")

    inv = coverage.build_inventory(case_dir, verify_packages=False)

    assert inv.candidates == []
    assert inv.packages == []
    matched = [issue for issue in inv.issues if issue.code == "invalid_json"]
    assert len(matched) == 1
    assert matched[0].detail == "non-finite JSON number is not permitted"
    assert token not in matched[0].detail


def test_inventory_fingerprint_mismatch_blocks(tmp_path: Path) -> None:
    case_dir = tmp_path / "synthetic-case"
    _write_package(case_dir)
    inv = coverage.build_inventory(case_dir)
    snapshot = _complete_snapshot(inv)
    snapshot["inventory_fingerprint"] = "0" * 64
    audit = coverage.audit_coverage(inv, snapshot, [])
    assert any(issue.code == "inventory_fingerprint_mismatch" for issue in audit.blockers)
