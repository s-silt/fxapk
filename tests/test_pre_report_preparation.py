"""One offline path from immutable package to pre-report review material."""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan.cli import app
from apkscan.core.phase2.inventory import build_coverage_skeleton, build_inventory
from apkscan.core.phase2.preparation import PreparationError, build_run_review, prepare_case_materials
from tests.phase2_fixtures import write_verified_package


def _run(name, *, parent=None, source="hit", provider="PRIVATE PROVIDER CANARY", entity="ENTITY CANARY"):
    return {"run_id": name, "parent_run_id": parent, "case_id": "PRIVATE CASE CANARY",
            "run_type": "enrichment", "status": "complete", "source_statuses": {provider: source},
            "closure": {"hosting_provider": entity}}


def test_run_history_retains_failed_observation_and_scoped_conflict():
    runs = [_run("A", source="failed"), _run("B", parent="A", entity="OTHER CANARY")]
    before = deepcopy(runs)
    result = build_run_review(runs, case_id="PRIVATE CASE CANARY")
    assert runs == before
    assert "CANARY" not in json.dumps(result)
    source = result["source_history"][0]
    assert source["has_failed_observation"] is True
    assert [row["status"] for row in source["observations"]] == ["failed", "hit"]
    assert result["conflicts"][0]["status"].startswith("potential_conflict")
    assert result["artifact_provenance_verified"] is False


@pytest.mark.parametrize("runs,code", [
    ([_run("A"), _run("A")], "duplicate"),
    ([_run("A", parent="missing")], "missing_parent"),
    ([_run("A", parent="B"), _run("B", parent="A")], "cycle"),
])
def test_run_graph_rejects_ambiguous_history(runs, code):
    with pytest.raises(PreparationError, match=code):
        build_run_review(runs, case_id="PRIVATE CASE CANARY")


def test_run_from_another_case_is_rejected():
    with pytest.raises(PreparationError, match="case_mismatch"):
        build_run_review([_run("A")], case_id="OTHER CASE")


def test_verified_package_preparation_does_not_modify_originals(tmp_path: Path):
    case = tmp_path / "case"
    package = write_verified_package(case, "sample", case_id="PRIVATE CASE CANARY", leads=[
        {"category": "DOMAIN", "value": "private-target-canary.invalid", "advice": "待核", "source_refs": []}])
    before = {p.name: p.read_bytes() for p in package.iterdir() if p.is_file()}
    result = prepare_case_materials(case)
    assert result["state"] == "review_required"
    assert result["candidate_count"] > 0
    assert result["coverage"]["status"] == "not_supplied"
    assert result["family_review"]["status"] == "insufficient_samples"
    assert "CANARY" not in json.dumps(result)
    assert "private-target-canary" not in json.dumps(result)
    assert result["formal_report_generated"] is False
    assert before == {p.name: p.read_bytes() for p in package.iterdir() if p.is_file()}


def test_tampered_package_stops_preparation(tmp_path: Path):
    case = tmp_path / "case"
    package = write_verified_package(case, "sample")
    (package / "report.json").write_text('{}')
    result = prepare_case_materials(case)
    assert result["state"] == "blocked"
    assert result["inventory_issue_codes"]
    assert result["packages"] == []


def test_pending_coverage_is_not_provider_verification(tmp_path: Path):
    case = tmp_path / "case"
    write_verified_package(case, "sample", leads=[
        {"category": "DOMAIN", "value": "example.invalid", "advice": "待核", "source_refs": []}])
    coverage = build_coverage_skeleton(build_inventory(case))
    result = prepare_case_materials(case, coverage=coverage, clue_records=[])
    assert result["coverage"]["status"] == "structurally_consistent"
    assert result["coverage"]["disposition_counts"]["pending_with_action"] > 0
    assert result["provider_identity_verified"] is False
    assert result["state"] == "review_required"


def test_case_family_review_uses_existing_engine(tmp_path: Path):
    case = tmp_path / "case"
    write_verified_package(case, "sample-a")
    write_verified_package(case, "sample-b")
    result = prepare_case_materials(case)
    assert result["family_review"]["kind"] == "linkage_review_groups"
    assert result["formal_report_generated"] is False


def test_prepare_materials_cli_stops_before_rendering_and_preserves_output(tmp_path: Path):
    case = tmp_path / "case"
    write_verified_package(case, "sample")
    out = tmp_path / "materials.json"
    runner = CliRunner()
    result = runner.invoke(app, ["case", "prepare-materials", str(case), "--out", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["formal_report_generated"] is False and data["network_requests"] == 0
    before = out.read_bytes()
    result = runner.invoke(app, ["case", "prepare-materials", str(case), "--out", str(out)])
    assert result.exit_code == 2 and out.read_bytes() == before
    assert not list(case.rglob('*.pdf')) and not list(case.rglob('*.html'))


def test_capture_quality_reuses_same_endpoint_gate_and_modified_ceiling():
    from apkscan.core.models import Report
    from apkscan.core.phase2.preparation import _stage_observations

    report = Report(package_name="synthetic", leads=[], endpoints=[], findings=[], analyzer_status=[], meta={"capture_quality": {
        "target_attributed_count": 1, "business_candidate_count": 2,
        "bidirectional_business_count": 1, "bidirectional_target_count": 0}})
    payload = {"analysis_status": []}
    stage = _stage_observations(payload, report)
    assert stage["static"]["analysis_status"] == "unknown"
    assert stage["dynamic"]["status"] == "partial"
    report.meta["capture_quality"]["bidirectional_target_count"] = 1
    assert _stage_observations(payload, report)["dynamic"]["status"] == "complete"
    report.meta["capture_quality"]["runtime_variant"] = "modified-runtime"
    assert _stage_observations(payload, report)["dynamic"]["status"] == "partial"


def test_core_requires_paired_coverage_and_clues(tmp_path):
    with pytest.raises(PreparationError, match="must_be_paired"):
        prepare_case_materials(tmp_path, coverage={})
