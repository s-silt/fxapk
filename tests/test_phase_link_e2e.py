# -*- coding: utf-8 -*-
"""Phase1 包 → fxapk phase2 triage/materialize/gate → case review（绑定回执）→ case status 全链路。"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.case_package import CasePackageError, create_case_review, project_case_status
from tests.phase2_fixtures import write_verified_package

runner = CliRunner()


def _auto_excluded_lead(value: str) -> dict:
    return {
        "category": "DOMAIN", "value": value, "advice": "无需调证",
        "is_runtime_seen": False, "is_runtime_contact": False, "is_c2": False,
        "source_refs": [{"evidence_id": f"ev-{value}", "scope": "case_evidence"}],
    }


def _phase2(*argv: str, entry: str = "phase2") -> int:
    result = runner.invoke(cli.app, [entry, *argv] if entry == "phase2" else ["case", "phase2", *argv])
    return result.exit_code


def _passing_case(tmp_path: Path) -> tuple[Path, Path]:
    case_dir = tmp_path / "any-dir-name"
    package = write_verified_package(
        case_dir, "pkg", leads=[_auto_excluded_lead("sdk.example.test")], case_id="CASE-E2E"
    )
    assert _phase2("triage", "--case-dir", str(case_dir)) == 0
    assert _phase2("materialize", "--case-dir", str(case_dir)) == 0
    assert _phase2("gate", "--case-dir", str(case_dir)) == 0
    return case_dir, package / "case-package.json"


def test_full_chain_binds_review_to_gate_receipt(tmp_path: Path) -> None:
    case_dir, manifest = _passing_case(tmp_path)
    receipt_path = case_dir / "phase2" / "gate-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["result"] == "PASS"
    assert receipt["case_id"] == "CASE-E2E"

    review = tmp_path / "case-review.json"
    reviewed = runner.invoke(cli.app, [
        "case", "review", str(manifest), "--reviewer", "r", "--status", "accepted",
        "--out", str(review), "--gate-receipt", str(receipt_path),
    ])
    assert reviewed.exit_code == 0, reviewed.output
    payload = json.loads(review.read_text(encoding="utf-8"))
    assert set(payload["phase2_gate"]) == {"receipt_sha256", "inventory_fingerprint"}

    shown = runner.invoke(cli.app, ["case", "status", str(manifest), "--review", str(review), "--json"])
    status = json.loads(shown.stdout)
    assert status["package_integrity"] == "verified"
    assert status["review"] == "accepted"
    # review=accepted 不背书分析/闭环
    assert status["closure"] == "not_run"


def test_handoff_case_relocates_without_rewriting_phase1(tmp_path: Path) -> None:
    import hashlib
    import shutil

    source = tmp_path / "OneDrive 空间" / "fxapk-handoff" / "cases" / "合成案件"
    source.mkdir(parents=True)
    case_dir, manifest = _passing_case(source)
    moved = tmp_path / "另一台机器" / "cases" / "合成案件"
    shutil.copytree(case_dir, moved)
    copied_manifest = moved / manifest.relative_to(case_dir)
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
              for p in copied_manifest.parent.iterdir() if p.is_file()}
    review = moved / "case-review.json"
    reviewed = runner.invoke(cli.app, [
        "case", "review", str(copied_manifest), "--reviewer", "synthetic-reviewer",
        "--status", "accepted", "--out", str(review),
        "--gate-receipt", str(moved / "phase2" / "gate-receipt.json"),
    ])
    assert reviewed.exit_code == 0, reviewed.output
    assert project_case_status(copied_manifest, review)["review"] == "accepted"
    assert before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in copied_manifest.parent.iterdir() if p.is_file()}


def test_review_rejects_receipt_after_decision_ledger_deleted(tmp_path: Path) -> None:
    """回执还在、coverage 还在，但判决账本被删时，不能再出具 accepted。"""
    case_dir, manifest = _passing_case(tmp_path)
    (case_dir / "phase2" / "decisions.jsonl").unlink()

    reviewed = runner.invoke(cli.app, [
        "case", "review", str(manifest), "--reviewer", "r", "--status", "accepted",
        "--out", str(tmp_path / "deleted.json"),
        "--gate-receipt", str(case_dir / "phase2" / "gate-receipt.json"),
    ])
    assert reviewed.exit_code != 0, reviewed.output
    assert not (tmp_path / "deleted.json").exists()


@pytest.mark.parametrize("remaining", ["none", "decisions", "coverage"])
def test_review_rejects_detached_receipt(tmp_path: Path, remaining: str) -> None:
    case_dir, manifest = _passing_case(tmp_path)
    detached = tmp_path / "detached"
    detached.mkdir()
    phase2 = case_dir / "phase2"
    receipt = detached / "gate-receipt.json"
    receipt.write_bytes((phase2 / "gate-receipt.json").read_bytes())
    if remaining != "none":
        name = "decisions.jsonl" if remaining == "decisions" else "coverage.json"
        (detached / name).write_bytes((phase2 / name).read_bytes())
    output = tmp_path / "detached-review.json"
    reviewed = runner.invoke(cli.app, [
        "case", "review", str(manifest), "--reviewer", "r", "--status", "accepted",
        "--out", str(output), "--gate-receipt", str(receipt),
    ])
    assert reviewed.exit_code != 0, reviewed.output
    assert not output.exists()


def test_review_rejects_receipt_after_decision_ledger_changes(tmp_path: Path) -> None:
    """回执文件没变，但同目录判决账本被换掉时，不能再出具 accepted。"""
    case_dir, manifest = _passing_case(tmp_path)
    ledger = case_dir / "phase2" / "decisions.jsonl"
    ledger.write_text('{"replaced":true}\n', encoding="utf-8")

    reviewed = runner.invoke(cli.app, [
        "case", "review", str(manifest), "--reviewer", "r", "--status", "accepted",
        "--out", str(tmp_path / "r.json"),
        "--gate-receipt", str(case_dir / "phase2" / "gate-receipt.json"),
    ])
    assert reviewed.exit_code != 0, reviewed.output
    assert not (tmp_path / "r.json").exists()


def test_blocked_gate_receipt_cannot_back_a_review(tmp_path: Path) -> None:
    case_dir, manifest = _passing_case(tmp_path)
    receipt_path = case_dir / "phase2" / "gate-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["result"] = "BLOCKED"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(CasePackageError):
        create_case_review(manifest, tmp_path / "r.json", reviewer="r", status="accepted",
                           gate_receipt=receipt_path)
    assert not (tmp_path / "r.json").exists()


def test_receipt_for_another_package_is_rejected(tmp_path: Path) -> None:
    case_dir, _manifest = _passing_case(tmp_path)
    other = write_verified_package(
        tmp_path / "other-case", "pkg", leads=[_auto_excluded_lead("x.example.test")],
        case_id="CASE-E2E",
    )
    with pytest.raises(CasePackageError):
        create_case_review(other / "case-package.json", tmp_path / "r.json", reviewer="r",
                           status="accepted", gate_receipt=case_dir / "phase2" / "gate-receipt.json")


def test_forged_binding_projects_stale(tmp_path: Path) -> None:
    case_dir, manifest = _passing_case(tmp_path)
    review = tmp_path / "case-review.json"
    create_case_review(manifest, review, reviewer="r", status="accepted",
                       gate_receipt=case_dir / "phase2" / "gate-receipt.json")
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload["phase2_gate"] = {"receipt_sha256": "not-a-hash"}
    review.write_text(json.dumps(payload), encoding="utf-8")

    assert project_case_status(manifest, review)["review"] == "stale"


def test_case_phase2_matches_legacy_alias(tmp_path: Path) -> None:
    case_dir = tmp_path / "any-dir-name"
    write_verified_package(
        case_dir, "pkg", leads=[_auto_excluded_lead("sdk.example.test")], case_id="CASE-E2E"
    )
    legacy = runner.invoke(cli.app, ["phase2", "triage", "--case-dir", str(case_dir)])
    assert legacy.exit_code == 0, legacy.output
    assert "已并入 fxapk case phase2" in legacy.stderr
    # 别名写过 triage 后，正名再跑必须拒绝覆盖或同样成功；这里只核对正名能读同一案件。
    named = runner.invoke(cli.app, ["case", "phase2", "materialize", "--case-dir", str(case_dir)])
    assert named.exit_code == 0, named.output
    group_help = runner.invoke(cli.app, ["case", "phase2", "--help"])
    assert group_help.exit_code == 0, group_help.output
    assert "inventory-phase1" in group_help.stdout
    redispatched = runner.invoke(cli.app, [
        "case", "phase2", "status", "--command-name", "triage", "--help",
    ])
    assert redispatched.exit_code == 0
    assert "fxapk phase2 status" in redispatched.stdout
    assert "fxapk phase2 triage" not in redispatched.stdout


def test_corpus_rejects_foreign_report_package_binding(tmp_path: Path) -> None:
    case_dir, manifest = _passing_case(tmp_path)
    other = write_verified_package(
        tmp_path / "other", "pkg", leads=[_auto_excluded_lead("other.example.test")],
        case_id="CASE-OTHER",
    )
    corpus = tmp_path / "corpus"
    result = runner.invoke(cli.app, [
        "corpus", "add", str(other / "report.json"), "--package", str(manifest),
        "--corpus", str(corpus),
    ])
    assert result.exit_code != 0, result.output
    assert not corpus.exists()


def test_corpus_accepts_byte_identical_report_copy(tmp_path: Path) -> None:
    _case_dir, manifest = _passing_case(tmp_path)
    copied = tmp_path / "copied-report.json"
    copied.write_bytes((manifest.parent / "report.json").read_bytes())
    result = runner.invoke(cli.app, [
        "corpus", "add", str(copied), "--package", str(manifest),
        "--corpus", str(tmp_path / "corpus"),
    ])
    assert result.exit_code == 0, result.output


def test_tampered_package_blocks_phase2_entry(tmp_path: Path) -> None:
    case_dir = tmp_path / "c"
    package = write_verified_package(
        case_dir, "pkg", leads=[_auto_excluded_lead("sdk.example.test")], case_id="CASE-E2E"
    )
    report = package / "report.json"
    report.write_text(report.read_text(encoding="utf-8") + " ", encoding="utf-8")

    assert _phase2("triage", "--case-dir", str(case_dir)) == 1
    assert not (case_dir / "phase2").exists()


def test_materialize_uses_manifest_case_id_not_directory_name(tmp_path: Path) -> None:
    """目录名 ≠ manifest case_id 时，真实判决物化后 coverage.case_id 仍取 manifest，gate PASS。"""
    case_dir = tmp_path / "dir-name-is-not-the-case"
    write_verified_package(
        case_dir, "pkg", case_id="CASE-P1A",
        leads=[{
            "category": "DOMAIN", "value": "api.example.test", "advice": "建议调证",
            "is_runtime_seen": False, "is_runtime_contact": False, "is_c2": False,
            "source_refs": [{"evidence_id": "ev-api", "scope": "case_evidence"}],
        }],
    )
    assert case_dir.name != "CASE-P1A"

    triage_run = runner.invoke(cli.app, ["phase2", "triage", "--case-dir", str(case_dir)])
    assert triage_run.exit_code == 0, triage_run.output
    triage = json.loads((case_dir / "phase2" / "triage.json").read_text(encoding="utf-8"))
    humans = [p for p in triage["parents"] if p["bucket"] == "human"]
    assert len(humans) == 1
    parent_id = humans[0]["parent_id"]

    decided = runner.invoke(cli.app, [
        "phase2", "decide", "--case-dir", str(case_dir),
        "--parent", parent_id, "--disposition", "report_only",
        "--reason", "synthetic review", "--decided-by", "tester",
    ])
    assert decided.exit_code == 0, decided.output

    materialized = runner.invoke(cli.app, ["phase2", "materialize", "--case-dir", str(case_dir)])
    assert materialized.exit_code == 0, materialized.output
    coverage = json.loads((case_dir / "phase2" / "coverage.json").read_text(encoding="utf-8"))
    assert coverage["case_id"] == "CASE-P1A"

    gated = runner.invoke(cli.app, ["phase2", "gate", "--case-dir", str(case_dir)])
    assert gated.exit_code == 0, gated.output
    receipt = json.loads((case_dir / "phase2" / "gate-receipt.json").read_text(encoding="utf-8"))
    assert receipt["result"] == "PASS"
    assert receipt["case_id"] == "CASE-P1A"
