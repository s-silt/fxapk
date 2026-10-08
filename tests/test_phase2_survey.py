"""Synthetic survey gate regressions: absence needs complete, bound evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

from apkscan.commands.phase2 import main
from apkscan.core.case_package import create_case_package
from apkscan.core.phase2.inventory import build_inventory
from apkscan.core.phase2.link import GateReceiptError, load_receipt_for_package
from tests.phase2_fixtures import write_verified_package


def _case(tmp_path: Path, *, captures: int = 1, packages: int = 1, extension: str = ".pcap"):
    case_dir = tmp_path / "case"
    manifests = []
    for index in range(packages):
        package = write_verified_package(case_dir, f"pkg-{index}", case_id="CASE-SURVEY", leads=[{
            "category": "IP", "value": "100.64.1.1", "advice": "无需调证",
            "is_runtime_seen": False, "is_runtime_contact": False, "is_c2": False,
            "source_refs": [{"evidence_id": "ev-sdk", "scope": "case_evidence"}],
        }])
        evidence = []
        for capture in range(captures):
            path = package / f"capture-{capture}{extension}"
            path.write_bytes(b"synthetic capture " + bytes([capture]))
            evidence.append(path)
        (package / "case-package.json").unlink()
        manifests.append(create_case_package(
            package / "report.json", package / "case-package.json",
            case_id="CASE-SURVEY", producer="synthetic-test", case_evidence=evidence,
        ))
    assert main(["materialize", "--case-dir", str(case_dir)]) == 0
    inventory = build_inventory(case_dir)
    assert not inventory.issues
    bindings = [{
        "package_id": manifest["package_id"],
        "sample_sha256": manifest["sample_sha256"],
        "artifact_path": artifact["path"], "sha256": artifact["sha256"],
    } for manifest in manifests for artifact in manifest["artifacts"]
       if artifact["kind"] == "evidence"]
    survey = {
        "schema_version": "phase2-survey/1.0", "case_id": "CASE-SURVEY",
        "inventory_fingerprint": inventory.fingerprint,
        "status": "complete", "truncated": False,
        "endpoints": [], "capture_bindings": bindings,
    }
    return case_dir, manifests, survey


def _gate(case_dir: Path, tmp_path: Path, survey: object) -> int:
    source = tmp_path / "source-survey.json"
    source.write_text(json.dumps(survey), encoding="utf-8")
    return main(["gate", "--case-dir", str(case_dir), "--survey", str(source)])


# Ignoring malformed input used to erase the honest G10 gap.
@pytest.mark.parametrize("payload", [
    {}, [], {"endpoints": None}, {"endpoints": {}}, {"endpoints": [None]},
    {"endpoints": [{"ip": "100.64.1.1", "observations": None}]},
    {"endpoints": [{"ip": "100.64.1.1", "observations": [None]}]},
    {"endpoints": [{"ip": "100.64.1.1", "observations": [{"state": 4}]}]},
    {"endpoints": [{"ip": "not-an-ip", "observations": [{"state": "established"}]}]},
])
def test_malformed_survey_is_material_error(tmp_path: Path, payload: object) -> None:
    case_dir, _, _ = _case(tmp_path)
    assert _gate(case_dir, tmp_path, payload) == 2
    assert not (case_dir / "phase2/gate-receipt.json").exists()


@pytest.mark.parametrize("payload", [
    {"endpoints": []},
    {"endpoints": [], "status": "complete", "truncated": False},
])
def test_legacy_empty_survey_keeps_g10(tmp_path: Path, capsys, payload: object) -> None:
    case_dir, _, _ = _case(tmp_path)
    capsys.readouterr()
    assert _gate(case_dir, tmp_path, payload) == 0
    assert "HONEST_GAP[G10]" in capsys.readouterr().out
    receipt = json.loads((case_dir / "phase2/gate-receipt.json").read_text(encoding="utf-8"))
    assert receipt["survey_assessment"] == "unassessed"


@pytest.mark.parametrize(("status", "truncated"), [
    ("partial", False), ("unassessed", False), ("complete", True),
])
def test_incomplete_survey_keeps_g10(tmp_path: Path, capsys, status: str, truncated: bool) -> None:
    case_dir, _, survey = _case(tmp_path)
    survey.update(status=status, truncated=truncated)
    capsys.readouterr()
    assert _gate(case_dir, tmp_path, survey) == 0
    assert "HONEST_GAP[G10]" in capsys.readouterr().out


@pytest.mark.parametrize(("field", "value"), [
    ("case_id", "OTHER-CASE"), ("inventory_fingerprint", "a" * 64),
    ("schema_version", "phase2-survey/99"), ("status", "success"),
    ("truncated", "false"), ("capture_bindings", {}),
])
def test_wrong_contract_or_case_is_rejected(tmp_path: Path, field: str, value: object) -> None:
    case_dir, _, survey = _case(tmp_path)
    survey[field] = value
    assert _gate(case_dir, tmp_path, survey) == 2


@pytest.mark.parametrize(("field", "value"), [
    ("package_id", "b" * 64), ("sample_sha256", "a" * 64),
    ("sha256", "c" * 64), ("artifact_path", "unregistered.pcap"),
    ("artifact_path", "../outside.pcap"),
])
def test_capture_binding_must_match_verified_package(tmp_path: Path, field: str, value: str) -> None:
    case_dir, _, survey = _case(tmp_path)
    survey["capture_bindings"][0][field] = value
    assert _gate(case_dir, tmp_path, survey) == 2


@pytest.mark.parametrize(("captures", "packages"), [(2, 1), (1, 2), (0, 1)])
def test_complete_survey_requires_all_registered_captures_per_package(
    tmp_path: Path, captures: int, packages: int,
) -> None:
    case_dir, _, survey = _case(tmp_path, captures=captures, packages=packages)
    survey["capture_bindings"] = survey["capture_bindings"][:1]
    assert _gate(case_dir, tmp_path, survey) == 2


def test_partial_survey_can_cover_subset_but_retains_gap(tmp_path: Path, capsys) -> None:
    case_dir, _, survey = _case(tmp_path, captures=2)
    survey.update(status="partial")
    survey["capture_bindings"] = survey["capture_bindings"][:1]
    capsys.readouterr()
    assert _gate(case_dir, tmp_path, survey) == 0
    assert "HONEST_GAP[G10]" in capsys.readouterr().out


@pytest.mark.parametrize("versioned", [True, False])
def test_positive_established_still_blocks_exclusion_when_unassessed(
    tmp_path: Path, capsys, versioned: bool,
) -> None:
    case_dir, _, survey = _case(tmp_path)
    survey.update(status="partial", endpoints=[{
        "ip": "100.64.1.1", "observations": [{"state": "established"}],
    }])
    if not versioned:
        survey = {"endpoints": survey["endpoints"]}
    capsys.readouterr()
    assert _gate(case_dir, tmp_path, survey) == 1
    output = capsys.readouterr()
    assert "G9:" in output.err
    assert "HONEST_GAP[G10]" in output.out


@pytest.mark.parametrize("extension", [".pcap", ".pcapng"])
def test_complete_empty_survey_binds_exact_bytes_and_clears_g10(tmp_path: Path, capsys, extension: str) -> None:
    case_dir, manifests, survey = _case(tmp_path, extension=extension)
    source = tmp_path / "source-survey.json"
    raw = (json.dumps(survey, indent=1) + "\r\n").encode("utf-8")
    source.write_bytes(raw)
    capsys.readouterr()
    assert main(["gate", "--case-dir", str(case_dir), "--survey", str(source)]) == 0
    assert "HONEST_GAP[G10]" not in capsys.readouterr().out
    phase2 = case_dir / "phase2"
    assert (phase2 / "survey.json").read_bytes() == raw
    receipt = json.loads((phase2 / "gate-receipt.json").read_text(encoding="utf-8"))
    assert receipt["survey_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["survey_assessment"] == "complete"
    # Changing the original source must not change what review accepts.
    source.write_text("{}", encoding="utf-8")
    binding = load_receipt_for_package(
        phase2 / "gate-receipt.json", package_id=manifests[0]["package_id"],
        manifest_sha256=hashlib.sha256((case_dir / "pkg-0/case-package.json").read_bytes()).hexdigest(),
        case_id="CASE-SURVEY", coverage_path=phase2 / "coverage.json",
        decisions_path=phase2 / "decisions.jsonl",
    )
    assert binding["receipt_sha256"]


@pytest.mark.parametrize("change", ["tamper", "delete", "relocate"])
def test_review_rejects_missing_or_changed_survey_snapshot(tmp_path: Path, change: str) -> None:
    case_dir, manifests, survey = _case(tmp_path)
    assert _gate(case_dir, tmp_path, survey) == 0
    receipt_path = case_dir / "phase2/gate-receipt.json"
    snapshot = receipt_path.parent / "survey.json"
    if change == "tamper":
        snapshot.write_text("{}", encoding="utf-8")
    elif change == "delete":
        snapshot.unlink(missing_ok=True)
    else:
        destination = tmp_path / "relocated"
        destination.mkdir()
        shutil.copyfile(receipt_path, destination / receipt_path.name)
        receipt_path = destination / receipt_path.name
    with pytest.raises(GateReceiptError):
        load_receipt_for_package(
            receipt_path, package_id=manifests[0]["package_id"],
            manifest_sha256=hashlib.sha256((case_dir / "pkg-0/case-package.json").read_bytes()).hexdigest(),
            case_id="CASE-SURVEY",
        )


@pytest.mark.parametrize("raw", [b'{"endpoints":[],"extra":NaN}', b'{"endpoints":[],"extra":1e999}'])
def test_nonfinite_survey_is_rejected_without_echo(tmp_path: Path, capsys, raw: bytes) -> None:
    case_dir, _, _ = _case(tmp_path)
    source = tmp_path / "nonfinite.json"
    source.write_bytes(raw)
    capsys.readouterr()
    assert main(["gate", "--case-dir", str(case_dir), "--survey", str(source)]) == 2
    assert "NaN" not in capsys.readouterr().err


def test_error_does_not_echo_input_state(tmp_path: Path, capsys) -> None:
    case_dir, _, _ = _case(tmp_path)
    capsys.readouterr()
    assert _gate(case_dir, tmp_path, {"endpoints": [{
        "ip": "100.64.1.1", "observations": [{"state": "private-secret-value\n"}],
    }]}) == 2
    assert "private-secret-value\n" not in capsys.readouterr().err


@pytest.mark.parametrize("state", ["arbitrary", "established_external_tool_suffix"])
def test_legacy_unknown_states_are_unassessed_and_keep_positive_g9(
    tmp_path: Path, capsys, state: str,
) -> None:
    case_dir, _, _ = _case(tmp_path)
    capsys.readouterr()
    result = _gate(case_dir, tmp_path, {"endpoints": [{
        "ip": "100.64.1.1", "observations": [{"state": state}],
    }]})
    assert result == (1 if state.startswith("established") else 0)
    output = capsys.readouterr()
    assert "HONEST_GAP[G10]" in output.out
    if state.startswith("established"):
        assert "G9:" in output.err


def test_versioned_unknown_observation_state_is_unsupported(tmp_path: Path) -> None:
    case_dir, _, survey = _case(tmp_path)
    survey["endpoints"] = [{"ip": "100.64.1.1", "observations": [{"state": "arbitrary"}]}]
    assert _gate(case_dir, tmp_path, survey) == 2


@pytest.mark.parametrize("assessment", [[], {}, None, "success"])
def test_review_rejects_malformed_survey_assessment(tmp_path: Path, assessment: object) -> None:
    case_dir, manifests, survey = _case(tmp_path)
    assert _gate(case_dir, tmp_path, survey) == 0
    receipt_path = case_dir / "phase2/gate-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["survey_assessment"] = assessment
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(GateReceiptError):
        load_receipt_for_package(
            receipt_path, package_id=manifests[0]["package_id"],
            manifest_sha256=hashlib.sha256((case_dir / "pkg-0/case-package.json").read_bytes()).hexdigest(),
            case_id="CASE-SURVEY",
        )


@pytest.mark.parametrize(("field", "limit"), [
    ("max_bytes", 8), ("max_json_depth", 2), ("max_endpoints", 0),
    ("max_observations_per_endpoint", 0), ("max_total_observations", 0),
    ("max_capture_bindings", 0),
])
def test_survey_read_and_collection_limits(tmp_path: Path, field: str, limit: int) -> None:
    from dataclasses import replace
    from apkscan.core.phase2.survey import SurveyError, SurveyLimits, load_survey

    case_dir, _, survey = _case(tmp_path)
    survey["endpoints"] = [{"ip": "100.64.1.1", "observations": [{"state": "syn_only"}]}]
    source = tmp_path / "bounded.json"
    source.write_text(json.dumps(survey), encoding="utf-8")
    with pytest.raises(SurveyError):
        load_survey(source, inventory=build_inventory(case_dir), case_dir=case_dir,
                    limits=replace(SurveyLimits(), **{field: limit}))


@pytest.mark.parametrize("change", ["manifest", "capture"])
def test_loaded_inventory_does_not_authorize_changed_package(tmp_path: Path, change: str) -> None:
    from apkscan.core.phase2.survey import SurveyError, load_survey

    case_dir, _, survey = _case(tmp_path)
    inventory = build_inventory(case_dir)
    source = tmp_path / "survey.json"
    source.write_text(json.dumps(survey), encoding="utf-8")
    if change == "manifest":
        manifest = case_dir / "pkg-0/case-package.json"
        manifest.write_bytes(manifest.read_bytes() + b" ")
    else:
        (case_dir / "pkg-0/capture-0.pcap").write_bytes(b"different synthetic capture")
    with pytest.raises(SurveyError):
        load_survey(source, inventory=inventory, case_dir=case_dir)


@pytest.mark.parametrize("ip", ["2001:db8:0:0::1", "[2001:db8::1]:443", "100.64.1.1:443"])
def test_legacy_ip_normalization_preserves_positive_observation(tmp_path: Path, ip: str) -> None:
    from apkscan.core.phase2.survey import load_survey

    case_dir, _, _ = _case(tmp_path)
    source = tmp_path / "survey.json"
    source.write_text(json.dumps({"endpoints": [{
        "ip": ip, "observations": [{"state": "established"}],
    }]}), encoding="utf-8")
    assessed = load_survey(source, inventory=build_inventory(case_dir), case_dir=case_dir)
    assert assessed.established_hosts == frozenset({"100.64.1.1" if ip.startswith("100.") else "2001:db8::1"})
    assert assessed.assessment == "unassessed"
