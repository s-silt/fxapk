from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from apkscan.core import fetch_intake
from apkscan.core.offline_review.runner import write_json


def fake_fetch(tmp_path, monkeypatch, *, web_state="completed", invalid=False, packages=None, report_health="complete"):
    package_data = b"synthetic original package"
    packages = packages if packages is not None else [{"kind": "package", "package_kind": "apk", "path": "attachments/original.apk",
                  "sha256": hashlib.sha256(package_data).hexdigest(), "size": len(package_data), "complete": True,
                  "validation": {"status": "passed", "reason_code": None}}]
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for package in packages:
            bundle.writestr(package["path"], package_data)
    commands = []
    monkeypatch.setattr(fetch_intake, "_resolve_executable", lambda value: value)
    monkeypatch.setattr(fetch_intake, "_default_fxapk", lambda: "synthetic-fxapk")

    def execute(command, prefix, deadline):
        commands.append(command)
        out = Path(command[command.index("--out") + 1])
        out.mkdir(parents=True)
        if command[1] == "analyze-data":
            import shutil
            shutil.copyfile(archive, out / "source.zip")
            (out / "report").mkdir()
            write_json(out / "report/input.json", {"analysis_status": "complete", "meta": {"online": False}})
            write_json(out / "analysis.json", {
                "schema_version": "fxfetch.analysis-handoff.v1",
                "source_archive": {"sha256": fetch_intake.file_hash(archive, 100000), "integrity_verified": not invalid},
                "source_manifest": {"attachments": packages, "external_packages": []},
                "analysis": {"state": web_state, "reason_code": "web_failed" if web_state == "failed" else None,
                             "report": {"sha256": fetch_intake.file_hash(out / "report/input.json", 100000), "load_errors": []}},
            })
        else:
            assert "analyze" in command and "--offline" in command
            assert Path(command[command.index("analyze") + 1]).read_bytes() == package_data
            write_json(out / "original.json", {"schema_version": "1.2", "package_name": "synthetic",
                       "meta": {"sample_sha256": hashlib.sha256(package_data).hexdigest(), "online": False},
                       "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
                       "analysis_status": report_health})
            (out / "original.html").write_text("synthetic report")
        return {"state": "ok", "reason_codes": [], "returncode": 0, "timed_out": False, "process_tree_complete": True}

    monkeypatch.setattr(fetch_intake, "_process", execute)
    return archive, commands


def test_verified_web_and_apk_route_to_distinct_reports(tmp_path, monkeypatch):
    archive, commands = fake_fetch(tmp_path, monkeypatch)
    result = fetch_intake.run(archive, tmp_path / "out")
    assert result["state"] == "ok"
    assert commands[0][1] == "analyze-data"
    assert commands[1][1:4] == ["-m", "apkscan.cli", "analyze"]
    assert result["stages"][3]["report_path"] == "package-001/report/original.html"
    assert result["stages"][2]["state"] == "not_run"
    assert "explicit_review_manifest_required" in (tmp_path / "out/index.html").read_text(encoding="utf-8")


def test_unverified_archive_never_executes_apk(tmp_path, monkeypatch):
    archive, commands = fake_fetch(tmp_path, monkeypatch, invalid=True)
    result = fetch_intake.run(archive, tmp_path / "out")
    assert result["state"] == "failed" and len(commands) == 1
    assert result["stages"][1]["state"] == "not_run"
    assert result["reason_code"] == "fetch_handoff_not_verified"


def test_web_failure_does_not_swallow_independent_apk(tmp_path, monkeypatch):
    archive, commands = fake_fetch(tmp_path, monkeypatch, web_state="failed")
    result = fetch_intake.run(archive, tmp_path / "out")
    assert len(commands) == 2 and result["state"] == "partial"
    assert result["stages"][0]["state"] == "failed" and result["stages"][3]["state"] == "ok"


@pytest.mark.parametrize("kind,validation,expected", [("ipa", "passed", "unsupported"), ("apk", "failed", "not_run")])
def test_ipa_and_invalid_original_have_visible_states(tmp_path, monkeypatch, kind, validation, expected):
    archive, commands = fake_fetch(tmp_path, monkeypatch, packages=[{
        "kind": "package", "package_kind": kind, "path": "attachments/original.bin", "size": 26,
        "sha256": "a" * 64, "complete": True, "validation": {"status": validation}}])
    result = fetch_intake.run(archive, tmp_path / "out")
    assert len(commands) == 1 and result["stages"][3]["state"] == expected
    assert result["stages"][3]["reason_codes"]


def test_child_partial_health_is_not_hidden_by_exit_zero(tmp_path, monkeypatch):
    archive, commands = fake_fetch(tmp_path, monkeypatch, report_health="partial")
    result = fetch_intake.run(archive, tmp_path / "out")
    assert result["state"] == "partial"
    assert result["stages"][3]["reason_codes"] == ["apk_analysis_incomplete"]


def test_review_manifest_is_consumed_after_matching_apk_and_visible(tmp_path, monkeypatch):
    archive, commands = fake_fetch(tmp_path, monkeypatch)
    plan = tmp_path / "review-plan.json"
    plan.write_text(json.dumps({"schema_version": "fxapk.offline-review.v1",
                                "sample_sha256": hashlib.sha256(b"synthetic original package").hexdigest(),
                                "tasks": [{"id": "unsupported", "kind": "future"}]}))
    result = fetch_intake.run(archive, tmp_path / "out", review_manifest=plan)
    assert result["stages"][2]["state"] == "partial"
    assert result["stages"][2]["report_path"] == "targeted-review/report.html"
    digest = json.loads((tmp_path / "out/targeted-review/digest.json").read_text(encoding="utf-8"))
    assert digest["offline_evidence_review"]["tasks"][0]["state"] == "unsupported"


def test_missing_cli_has_terminal_failure_receipt(tmp_path, monkeypatch):
    path = tmp_path / "source.zip"
    path.write_bytes(b"synthetic")
    monkeypatch.setattr(fetch_intake.tools.shutil, "which", lambda value: None)
    result = fetch_intake.run(path, tmp_path / "out")
    assert result["reason_code"] == "executable_unavailable"
    assert result["stages"][1]["reason_codes"] == ["executable_unavailable"]
    assert (tmp_path / "out/intake.json").is_file()


def test_timeout_or_unowned_process_cannot_publish_or_continue(tmp_path, monkeypatch):
    archive, commands = fake_fetch(tmp_path, monkeypatch)
    monkeypatch.setattr(fetch_intake, "_process", lambda *args: {
        "state": "failed", "timed_out": True, "process_tree_complete": True,
        "reason_codes": ["subprocess_timeout"]})
    result = fetch_intake.run(archive, tmp_path / "out")
    assert result["state"] == "failed" and result["reason_code"] == "fetch_process_incomplete"
    assert result["stages"][1]["state"] == "not_run"
    assert "subprocess_timeout" in result["stages"][0]["reason_codes"]
    assert not (tmp_path / "out/package-001").exists()


def test_all_failed_intake_is_not_partial(tmp_path, monkeypatch):
    archive, _ = fake_fetch(tmp_path, monkeypatch, web_state="failed", packages=[])
    result = fetch_intake.run(archive, tmp_path / "out")
    assert result["state"] == "failed"


def test_later_malformed_package_preserves_earlier_skip_reason(tmp_path, monkeypatch):
    packages = [{"kind": "package", "package_kind": "apk", "path": "attachments/first.apk",
                 "sha256": "a" * 64, "size": 26, "complete": True, "validation": {"status": "failed"}},
                {"kind": "package", "package_kind": "apk", "path": "attachments/second.apk"}]
    archive, _ = fake_fetch(tmp_path, monkeypatch, packages=packages)
    result = fetch_intake.run(archive, tmp_path / "out")
    first = next(row for row in result["stages"] if row["id"] == "package-001")
    assert first["state"] == "not_run"
    assert "original_package_validation_failed" in first["reason_codes"]
    assert "fetch_intake_failed" in first["reason_codes"]


def test_offline_process_disables_device_probes_only_in_child(tmp_path, monkeypatch):
    import os
    import time
    from apkscan.core import tools
    from apkscan.core.proctree import OwnedRun

    monkeypatch.delenv("FXAPK_NO_DEVICE_PROBE", raising=False)
    observed = []
    def execute(command, **kwargs):
        observed.append(kwargs["env"])
        return OwnedRun(0, "", "", False, True, True, False, ())
    monkeypatch.setattr(fetch_intake, "run_owned", execute)
    fetch_intake._process(["synthetic"], tmp_path / "offline", time.monotonic() + 10)
    fetch_intake._process(["synthetic"], tmp_path / "capture", time.monotonic() + 10, allow_device=True)
    assert observed[0]["FXAPK_NO_DEVICE_PROBE"] == "1"
    assert "FXAPK_NO_DEVICE_PROBE" not in observed[1] and "FXAPK_NO_DEVICE_PROBE" not in os.environ
    monkeypatch.setenv("FXAPK_NO_DEVICE_PROBE", "1")
    monkeypatch.setattr(tools, "executable_path", lambda name: pytest.fail("device resolution must not run"))
    assert tools.adb_path() == ""


def test_failed_child_report_cannot_become_partial_success(tmp_path, monkeypatch):
    archive, _ = fake_fetch(tmp_path, monkeypatch, web_state="failed", report_health="failed")
    receipt = fetch_intake.run(archive, tmp_path / "out")
    assert receipt["state"] == "failed" and receipt["stages"][3]["state"] == "failed"
