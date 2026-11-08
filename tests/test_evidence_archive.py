from __future__ import annotations

import hashlib
import json
import os
import struct
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan.cli import app
from apkscan.core.evidence_archive import (
    INDEX, SCHEMA, ArchiveError, EvidenceArchive, Limits, materialize, pack,
    read_reference, resolve_reference,
)
from apkscan.core.evidence_output import EvidenceOutput


def source_tree(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "nested").mkdir()
    (root / "nested/原始.bin").write_bytes(bytes(range(256)) * 257)
    (root / "empty").write_bytes(b"")
    (root / "events.jsonl").write_bytes(b'{"event":"synthetic"}\r\n' * 3000)
    return root


def forged(path, files, rows=None, hint=None):
    if rows is None:
        rows = [{"path": n, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()} for n, data in files]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            z.writestr(name, data)
        z.writestr(INDEX, json.dumps({"schema_version": SCHEMA, "files": rows, "source_root_hint": hint}))
    return path


@pytest.mark.parametrize("compression,method", [("zstd", 93), ("deflate", 8)])
def test_round_trip_exact_bytes_names_and_original_manifests(tmp_path, compression, method):
    root = source_tree(tmp_path)
    (root / "empty-directory").mkdir()
    original = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    archive = tmp_path / "evidence.zip"
    receipt = pack(root, archive, compression=compression)
    assert receipt["compression_methods"] == [method]
    assert receipt["compression"] == compression and receipt["compression_level"] == 6
    assert receipt["state"] == "verified"
    assert receipt["original_bytes"] == sum(map(len, original.values()))
    assert receipt["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert archive.stat().st_size < receipt["original_bytes"]
    with EvidenceArchive(archive) as reader:
        assert reader.verify()["files"] == len(original)
    with EvidenceArchive(archive) as reader:
        reader.extract(tmp_path / "restored")
    assert {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()} == original
    assert {p.relative_to(tmp_path / 'restored').as_posix(): p.read_bytes()
            for p in (tmp_path / "restored").rglob("*") if p.is_file()} == original
    assert (tmp_path / "restored/empty-directory").is_dir()


def test_only_selected_member_is_materialized_and_cleaned(tmp_path):
    root = source_tree(tmp_path)
    archive = tmp_path / "evidence.zip"
    pack(root, archive)
    with materialize(f"{archive}::nested/原始.bin") as local:
        assert local.read_bytes() == (root / "nested/原始.bin").read_bytes()
        assert [p.name for p in local.parent.iterdir()] == ["原始.bin"]
        folder = local.parent
    assert not folder.exists()


@pytest.mark.parametrize("member", ["../escape", "/absolute", "C:/drive", "a\\b", "a/../b", "a//b", "NUL.txt", "a:stream", "a."])
def test_unsafe_names_rejected_before_any_output(tmp_path, member):
    archive = forged(tmp_path / "bad.zip", [(member, b"synthetic")])
    with pytest.raises(ArchiveError, match="archive_member_path_invalid"):
        EvidenceArchive(archive)


@pytest.mark.parametrize("names", [["A.bin", "a.bin"], ["a", "a/b"], ["é", "e\u0301"]])
def test_duplicate_and_alias_collisions_rejected(tmp_path, names):
    archive = forged(tmp_path / "bad.zip", [(n, b"synthetic") for n in names])
    with pytest.raises(ArchiveError, match="archive_(duplicate_member|member_path_collision)"):
        EvidenceArchive(archive)


def test_hash_mismatch_is_never_returned_as_bytes(tmp_path):
    row = {"path": "evidence", "size": 3, "sha256": "0" * 64}
    archive = forged(tmp_path / "bad.zip", [("evidence", b"bad")], [row])
    with pytest.raises(ArchiveError, match="archive_member_hash_mismatch"):
        read_reference(f"{archive}::evidence", 100)


def test_crc_corruption_and_truncation_fail_visible_cli(tmp_path):
    root = source_tree(tmp_path)
    archive = tmp_path / "data.zip"
    pack(root, archive)
    data = bytearray(archive.read_bytes())
    with zipfile.ZipFile(archive) as z:
        item = z.getinfo("events.jsonl")
        header = struct.unpack_from("<4s5H3L2H", data, item.header_offset)
        start = item.header_offset + 30 + header[-2] + header[-1]
        data[start + item.compress_size // 2] ^= 0x7F
    archive.write_bytes(data)
    result = CliRunner().invoke(app, ["evidence", "verify", str(archive)])
    assert result.exit_code == 6 and '"state": "failed"' in result.output
    archive.write_bytes(data[:-16])
    result = CliRunner().invoke(app, ["evidence", "verify", str(archive)])
    assert result.exit_code == 6 and "archive_directory_invalid" in result.output


def test_size_budgets_apply_to_uncompressed_data(tmp_path):
    archive = forged(tmp_path / "data.zip", [("zeros", b"0" * 100000)])
    assert archive.stat().st_size < 10000
    with pytest.raises(ArchiveError, match="archive_member_budget"):
        read_reference(f"{archive}::zeros", 99999)
    with pytest.raises(ArchiveError, match="archive_directory_budget"):
        EvidenceArchive(archive, replace(Limits(), metadata_bytes=1))
    with EvidenceArchive(archive, replace(Limits(), total_bytes=100000)) as reader:
        assert reader.read("zeros", 100000) == b"0" * 100000
        with pytest.raises(ArchiveError, match="archive_total_budget"):
            reader.read("zeros", 100000)


def test_source_changed_during_pack_never_publishes(tmp_path):
    root = source_tree(tmp_path)
    archive = tmp_path / "data.zip"
    def mutate(event):
        (root / "new-file").write_text("new")
    with pytest.raises(ArchiveError, match="archive_source_changed"):
        pack(root, archive, progress=mutate)
    assert not archive.exists()
    assert not list(tmp_path.glob(".fxapk-pack-*"))


def test_existing_outputs_and_inside_source_are_not_overwritten(tmp_path):
    root = source_tree(tmp_path)
    out = tmp_path / "archive.zip"
    out.write_bytes(b"original")
    with pytest.raises(ArchiveError, match="archive_output_exists"):
        pack(root, out)
    assert out.read_bytes() == b"original"
    with pytest.raises(ArchiveError, match="archive_output_inside_source"):
        pack(root, root / "archive.zip")


def test_symlinks_not_archived_or_followed(tmp_path):
    root = source_tree(tmp_path)
    try:
        os.symlink(tmp_path, root / "link", target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ArchiveError, match="archive_links_not_supported"):
        pack(root, tmp_path / "data.zip")


def test_index_must_cover_every_member(tmp_path):
    archive = forged(tmp_path / "bad.zip", [("evidence", b"raw")], [])
    with pytest.raises(ArchiveError, match="archive_index_inventory_mismatch"):
        EvidenceArchive(archive)


def test_new_output_archive_preserves_original_absolute_reference_resolution(tmp_path):
    out = tmp_path / "new.zip"
    with EvidenceOutput(None, out) as destination:
        destination.path.mkdir()
        original = destination.path / "evidence.bin"
        original.write_bytes(b"exact")
        (destination.path / "plan.json").write_text(json.dumps({"input": str(original)}))
        staged = destination.path
    assert not staged.exists()
    assert destination.storage["staging_cleanup"] == "complete"
    reference = resolve_reference(f"{out}::plan.json", str(original))
    assert read_reference(reference, 99) == b"exact"
    with pytest.raises(ArchiveError, match="archive_external_reference"):
        resolve_reference(f"{out}::plan.json", str(tmp_path / "outside"))
    with pytest.raises(ArchiveError, match="archive_member_path_invalid"):
        resolve_reference(f"{out}::plan.json", "../../outside")


def test_failed_new_output_retains_staging_and_failure_receipt(tmp_path, monkeypatch):
    from apkscan.core import evidence_output
    def fail(*args, **kwargs):
        raise ArchiveError("archive_source_changed")
    monkeypatch.setattr(evidence_output, "pack", fail)
    out = tmp_path / "new.zip"
    with pytest.raises(ArchiveError):
        with EvidenceOutput(None, out) as destination:
            destination.path.mkdir()
            (destination.path / "evidence").write_bytes(b"retain")
    assert (destination.path / "evidence").read_bytes() == b"retain"
    receipt = json.loads(Path(str(out) + ".receipt.json").read_text())
    assert receipt["state"] == "failed" and receipt["reason_codes"] == ["archive_source_changed"]
    assert not out.exists()


@pytest.mark.parametrize("compression", ["zstd", "deflate"])
def test_review_archive_round_trip_and_bad_member_reaches_all_projections(tmp_path, compression):
    root = tmp_path / "inputs"
    root.mkdir()
    data = b'{"run_id":"synthetic","address_space":"space","seq":1,"op":"write","address":100,"size":4,"data_hex":"01020304"}\n'
    (root / "events.jsonl").write_bytes(data)
    common = {"kind": "trace", "input": "events.jsonl", "run_id": "synthetic", "address_space": "space", "address": 100, "size": 4}
    tasks = [{**common, "id": "bad", "sha256": "0" * 64}, {**common, "id": "good", "sha256": hashlib.sha256(data).hexdigest()}]
    (root / "plan.json").write_text(json.dumps({"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64, "tasks": tasks}))
    archive = tmp_path / "source.zip"
    pack(root, archive)
    output = tmp_path / "review.zip"
    result = CliRunner().invoke(app, ["evidence-review", str(archive), "--archive-member", "plan.json", "--archive-out", str(output),
                                     "--archive-compression", compression])
    assert result.exit_code == 5, result.output
    with EvidenceArchive(output) as reader:
        receipt = json.loads(reader.read("review.json", 100000))
        assert [r["state"] for r in receipt["tasks"]] == ["failed", "ok"]
        for name in ["report.json", "digest.json", "report.html", "feedback.json"]:
            assert b"review_input_hash_mismatch" in reader.read(name, 5 * 1024**2)
    replay = CliRunner().invoke(app, ["evidence-review", str(output), "--archive-member", "replay-plan.json", "--out", str(tmp_path / "replayed")])
    assert replay.exit_code == 5, replay.output
    rerun = json.loads((tmp_path / "replayed/review.json").read_text())
    assert [(r["state"], r["reason_codes"]) for r in rerun["tasks"]] == [(r["state"], r["reason_codes"]) for r in receipt["tasks"]]


def test_archived_pcap_and_runtime_readers_match_original_bytes(tmp_path):
    from apkscan.dynamic.pcap_ingest import parse_pcap
    from apkscan.dynamic.runtime_input import read_runtime_input, RuntimeReadFailure
    root = tmp_path / "capture"
    root.mkdir()
    pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    (root / "empty.pcap").write_bytes(pcap)
    raw = b'{"messages":[],"endpoints":[]}'
    (root / "runtime_report.json").write_bytes(raw)
    archive = tmp_path / "capture.zip"
    pack(root, archive)
    assert parse_pcap(f"{archive}::empty.pcap") == parse_pcap(str(root / "empty.pcap"))
    runtime = read_runtime_input(Path(f"{archive}::runtime_report.json"))
    assert not isinstance(runtime, RuntimeReadFailure)
    assert runtime.sha256 == hashlib.sha256(raw).hexdigest()
    missing = read_runtime_input(Path(f"{archive}::missing.json"))
    assert isinstance(missing, RuntimeReadFailure) and missing.reason == "archive_member_missing"


@pytest.mark.parametrize("compression", ["zstd", "deflate"])
def test_capture_to_archive_keeps_partial_state_and_can_read_pcap(tmp_path, monkeypatch, compression):
    from apkscan.dynamic import capture
    from apkscan.dynamic.pcap_ingest import parse_pcap
    def captured(package, *, out, **kwargs):
        folder = Path(out)
        folder.mkdir(parents=True)
        (folder / "capture.pcap").write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        (folder / "runtime_report.json").write_text('{"capture_quality":{"status":"partial"},"messages":[]}')
        return {"status": "error", "runtime_report": str(folder / "runtime_report.json")}
    monkeypatch.setattr(capture, "run", captured)
    target = tmp_path / "capture.zip"
    result = CliRunner().invoke(app, ["capture", "com.example.synthetic", "--archive-out", str(target), "--archive-compression", compression])
    assert result.exit_code == 1, result.output
    assert target.exists()
    with EvidenceArchive(target) as reader:
        assert b'"partial"' in reader.read("runtime_report.json", 1000)
    assert parse_pcap(f"{target}::capture.pcap").parse_status == "ok"
    assert not list(tmp_path.glob(".fxapk-evidence-*"))


def test_archived_case_verification_runs_original_gate_and_preserves_package_id(tmp_path):
    from apkscan.core.case_package import create_case_package, verify_case_package
    from apkscan.core.models import Report
    from apkscan.core.report_io import write_report
    root = tmp_path / "case"
    root.mkdir()
    report = Report(package_name="com.example.synthetic", meta={"sample_sha256": "a" * 64,
        "tool_version": "1.24.0", "ruleset_digest": "b" * 16}, leads=[], endpoints=[], findings=[],
        analyzer_status=[], analysis_status="partial")
    write_report(report, root / "report.json", render_existing_html=False)
    (root / "evidence.bin").write_bytes(b"original evidence")
    manifest = root / "manifest.json"
    package = create_case_package(root / "report.json", manifest, case_id="synthetic", producer="test",
                                  case_evidence=[root / "evidence.bin"])
    original_manifest = manifest.read_bytes()
    expected = verify_case_package(manifest)
    assert expected["status"] == "verified"
    archive = tmp_path / "case.zip"
    pack(root, archive)
    result = CliRunner().invoke(app, ["evidence", "case-verify", str(archive), "--member", "manifest.json"])
    assert result.exit_code == 0, result.output
    actual = json.loads(result.stdout)
    assert actual["package_id"] == package["package_id"] and actual["status"] == expected["status"]
    assert read_reference(f"{archive}::manifest.json", 100000) == original_manifest


def test_archive_corruption_reaches_review_report_without_hiding_other_tasks(tmp_path):
    data = b'{"run_id":"synthetic","seq":1,"type":"end"}'
    plan = {"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64,
            "tasks": [{"id": "jni", "kind": "jni", "input": "events.jsonl", "sha256": hashlib.sha256(data).hexdigest()}]}
    files = [("plan.json", json.dumps(plan).encode()), ("events.jsonl", data)]
    rows = [{"path": n, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for n, d in files]
    rows[1]["sha256"] = "0" * 64
    archive = forged(tmp_path / "damaged.zip", files, rows)
    out = tmp_path / "out"
    result = CliRunner().invoke(app, ["evidence-review", str(archive), "--archive-member", "plan.json", "--out", str(out)])
    assert result.exit_code == 6, result.output
    for name in ["review.json", "feedback.json", "report.json", "digest.json", "report.html"]:
        assert "archive_member_hash_mismatch" in (out / name).read_text(encoding="utf-8")
    receipt = json.loads((out / "review.json").read_text())
    assert receipt["tasks"][0]["storage_integrity"] == "failed"


def test_archive_analysis_failure_keeps_process_reason(tmp_path, monkeypatch):
    from apkscan.core import fetch_intake
    root = tmp_path / "source"
    root.mkdir()
    (root / "sample.apk").write_bytes(b"synthetic invalid apk")
    archive = tmp_path / "source.zip"
    pack(root, archive)
    monkeypatch.setattr(fetch_intake, "_process", lambda *a, **k: {"state": "failed", "reason_codes": ["subprocess_timeout"]})
    out = tmp_path / "out"
    result = CliRunner().invoke(app, ["evidence", "analyze", str(archive), "--member", "sample.apk", "--out", str(out)])
    assert result.exit_code == 6
    receipt = json.loads((out / "archive-analysis.json").read_text())
    assert "subprocess_timeout" in receipt["reason_codes"] and "archive_analysis_report_missing" in receipt["reason_codes"]


@pytest.mark.slow
@pytest.mark.skipif(os.sys.platform == "darwin", reason="bounded analyzer requires enforceable memory limits")
def test_archive_apk_real_offline_pipeline_preserves_hash_and_reports_storage(tmp_path, monkeypatch):
    from tests.test_parser_bridge import _make_apk
    monkeypatch.setenv("FXAPK_NO_PARALLEL", "1")
    root = tmp_path / "source"
    root.mkdir()
    apk = root / "synthetic.apk"
    _make_apk(apk, **{"assets/settings.json": b'{"mode":"offline"}'})
    archive = tmp_path / "apk.zip"
    pack(root, archive)
    out = tmp_path / "analysis"
    result = CliRunner().invoke(app, ["evidence", "analyze", str(archive), "--member", "synthetic.apk", "--out", str(out)])
    assert result.exit_code in {0, 5}, result.output
    receipt = json.loads((out / "archive-analysis.json").read_text())
    assert receipt["input_sha256"] == hashlib.sha256(apk.read_bytes()).hexdigest()
    report = json.loads((out / receipt["report"]).read_text(encoding="utf-8"))
    assert report["meta"]["sample_sha256"] == receipt["input_sha256"] and report["meta"]["online"] is False
    assert report["meta"]["evidence_manifest"]["archive_storage"]["state"] == "verified"
    assert json.loads((out / "digest.json").read_text(encoding="utf-8"))["archive_storage"]["state"] == "verified"
    assert "归档读取校验" in (out / receipt["report"]).with_suffix(".html").read_text(encoding="utf-8")


def test_zip64_directory_and_member_count_budget(tmp_path):
    archive = forged(tmp_path / "zip64.zip", [("raw", b"synthetic")])
    raw = archive.read_bytes()
    offset = raw.rfind(b"PK\x05\x06")
    eocd = list(struct.unpack("<4s4H2LH", raw[offset:]))
    record = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0,
                         eocd[3], eocd[4], eocd[5], eocd[6])
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, offset, 1)
    eocd[3:7] = [65535, 65535, 0xFFFFFFFF, 0xFFFFFFFF]
    archive.write_bytes(raw[:offset] + record + locator + struct.pack("<4s4H2LH", *eocd))
    with EvidenceArchive(archive) as reader:
        assert reader.read("raw", 100) == b"synthetic"
    with pytest.raises(ArchiveError, match="archive_directory_budget"):
        EvidenceArchive(archive, replace(Limits(), members=0))


def test_atomic_publish_race_does_not_replace_other_writer(tmp_path, monkeypatch):
    from apkscan.core import evidence_archive
    root = source_tree(tmp_path)
    out = tmp_path / "archive.zip"
    real_publish = evidence_archive._publish
    def competing_writer(temporary, target):
        target.write_bytes(b"other writer")
        real_publish(temporary, target)
    monkeypatch.setattr(evidence_archive, "_publish", competing_writer)
    with pytest.raises(ArchiveError, match="archive_output_exists"):
        pack(root, out)
    assert out.read_bytes() == b"other writer"


def test_cleanup_gap_does_not_downgrade_failed_analysis_to_partial(tmp_path, monkeypatch):
    from apkscan.core import evidence_output
    def cleanup_failure(*args):
        raise OSError("synthetic")
    monkeypatch.setattr(evidence_output, "remove_owned_staging", cleanup_failure)
    source = tmp_path / "source.bin"
    source.write_bytes(b"synthetic")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64,
        "tasks": [{"id": "bad", "kind": "trace", "input": source.name, "sha256": "0" * 64}]}))
    archive = tmp_path / "review.zip"
    result = CliRunner().invoke(app, ["evidence-review", str(plan), "--archive-out", str(archive)])
    assert result.exit_code == 6, result.output
    storage = json.loads(Path(str(archive) + ".receipt.json").read_text())
    assert storage["state"] == "partial" and Path(storage["retained_staging"]).is_dir()


def test_archived_socket_discovery_stays_in_same_capture_directory(tmp_path):
    from apkscan.core.evidence_archive import archived_siblings
    from apkscan.dynamic.socket_attr import load_socket_tables
    root = tmp_path / "source"
    (root / "capture-one").mkdir(parents=True)
    (root / "capture-two").mkdir()
    data = b'{"type":"meta","package":"com.example.synthetic","target_uid":10}\n'
    data += b'{"proto":"tcp","uid":10,"local":"192.0.2.2:1234","remote":"198.51.100.2:443","ts":1}\n'
    (root / "capture-one/socket_timeline.jsonl").write_bytes(data)
    (root / "capture-two/socket_timeline.jsonl").write_bytes(data)
    archive = tmp_path / "source.zip"
    pack(root, archive)
    found = archived_siblings(f"{archive}::capture-one/traffic.pcap", ("uid_sockets.txt", "socket_timeline.*"))
    assert len(found) == 1 and "::capture-one" in str(found[0])
    table, used = load_socket_tables(found)
    assert table is not None and table.target_uid == 10 and len(table.entries) == 1 and len(used) == 1


def test_unreadable_subtree_never_becomes_successful_incomplete_archive(tmp_path, monkeypatch):
    from apkscan.core import evidence_archive
    root = source_tree(tmp_path)
    def blocked_walk(*args, onerror, **kwargs):
        onerror(PermissionError("synthetic"))
        yield from ()
    monkeypatch.setattr(evidence_archive.os, "walk", blocked_walk)
    target = tmp_path / "output.zip"
    with pytest.raises(ArchiveError, match="archive_directory_unreadable"):
        pack(root, target)
    assert not target.exists()


@pytest.mark.parametrize("extra", [b'NaN', b'1e9999', b'[' * 80 + b'0' + b']' * 80])
def test_index_json_is_finite_and_depth_bounded(tmp_path, extra):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(INDEX, b'{"schema_version":"fxapk.evidence-archive.v1","files":[],"extra":' + extra + b'}')
    with pytest.raises(ArchiveError, match="archive_index_invalid"):
        EvidenceArchive(archive)


def test_empty_directory_cannot_have_file_as_ancestor(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("a", b"original")
        bundle.writestr(INDEX, json.dumps({"schema_version": SCHEMA, "directories": ["a/b"],
            "files": [{"path": "a", "size": 8, "sha256": hashlib.sha256(b"original").hexdigest()}]}))
    with pytest.raises(ArchiveError, match="archive_member_path_collision"):
        EvidenceArchive(archive)


@pytest.mark.parametrize("web_state,expected_exit", [("completed", 0), ("failed", 5)])
@pytest.mark.parametrize("compression", ["zstd", "deflate"])
def test_nested_fetch_input_through_intake_to_verified_archive(tmp_path, monkeypatch, web_state, expected_exit, compression):
    from tests.test_fetch_intake import fake_fetch
    nested, commands = fake_fetch(tmp_path, monkeypatch, web_state=web_state)
    source = tmp_path / "outer-source"
    source.mkdir()
    (source / "saved-task.zip").write_bytes(nested.read_bytes())
    archive = tmp_path / "outer.zip"
    pack(source, archive)
    target = tmp_path / "intake.zip"
    result = CliRunner().invoke(app, ["intake-fetch", str(archive), "--archive-member", "saved-task.zip",
                                     "--archive-out", str(target), "--archive-compression", compression])
    assert result.exit_code == expected_exit, result.output
    assert len(commands) == 2
    with EvidenceArchive(target) as reader:
        assert reader.verify()["state"] == "verified"
    receipt = json.loads(read_reference(f"{target}::intake.json", 1000000))
    assert receipt["stages"][0]["state"] == ("ok" if expected_exit == 0 else "failed")
    assert receipt["stages"][3]["state"] == "ok"
    assert not list(tmp_path.glob(".fxapk-evidence-*"))


def test_frozen_report_version_survives_reader_migration_without_rewriting(tmp_path):
    from apkscan.core.case_package import create_case_package, verify_case_package
    from apkscan.core.report_io import load_report
    from tests.test_case_package import _write_report
    report = _write_report(tmp_path, closure="partial")
    raw = json.loads(report.read_bytes())
    raw["schema_version"] = "1.2"
    report.write_text(json.dumps(raw), encoding="utf-8")
    original_report = report.read_bytes()
    assert load_report(report).schema_version != "1.2"
    manifest = tmp_path / "case-package.json"
    package = create_case_package(report, manifest, case_id="synthetic", producer="test")
    assert package["report_schema_version"] == "1.2"
    original_manifest = manifest.read_bytes()
    assert verify_case_package(manifest)["status"] == "verified"
    assert report.read_bytes() == original_report and manifest.read_bytes() == original_manifest
    # Versions 1.22-1.24 recorded the migrated schema for this same frozen JSON.
    package["report_schema_version"] = load_report(report).schema_version
    body = {k:v for k,v in package.items() if k != "package_id"}
    package["package_id"] = hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True,
                                                     separators=(",", ":")).encode()).hexdigest()
    manifest.write_text(json.dumps(package), encoding="utf-8")
    assert verify_case_package(manifest)["status"] == "verified"
    archive = tmp_path.parent / (tmp_path.name + "-legacy.zip")
    pack(tmp_path, archive)
    result = CliRunner().invoke(app, ["evidence", "case-verify", str(archive), "--member", "case-package.json"])
    assert result.exit_code == 0, result.output
    # Unrelated schema declarations still fail even with a recomputed identity.
    package["report_schema_version"] = "9.9"
    body = {k:v for k,v in package.items() if k != "package_id"}
    package["package_id"] = hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True,
                                                     separators=(",", ":")).encode()).hexdigest()
    manifest.write_text(json.dumps(package), encoding="utf-8")
    rejected = verify_case_package(manifest)
    assert rejected["status"] == "failed" and "report_schema_version does not match report" in rejected["issues"]


@pytest.mark.parametrize("tamper", [False, True])
def test_archive_corpus_entry_preserves_report_or_refuses_bad_package(tmp_path, tamper):
    from apkscan.core.case_package import create_case_package
    from apkscan.core.corpus import load_manifest_strict
    from tests.test_case_package import _write_report
    source = tmp_path / "source"
    source.mkdir()
    report = _write_report(source, closure="partial")
    manifest = source / "case-package.json"
    create_case_package(report, manifest, case_id="synthetic", producer="test")
    if tamper:
        package = json.loads(manifest.read_bytes())
        package["package_id"] = "0" * 64
        manifest.write_text(json.dumps(package), encoding="utf-8")
    archive = tmp_path / "source.zip"
    pack(source, archive)
    corpus = tmp_path / "corpus"
    result = CliRunner().invoke(app, ["evidence", "corpus-add", str(archive), "--corpus", str(corpus)])
    if tamper:
        assert result.exit_code == 6 and '"stage": "case_verification"' in result.output
        assert not corpus.exists()
    else:
        assert result.exit_code == 0, result.output
        rows = load_manifest_strict(corpus)
        assert len(rows) == 1
        assert any(path.read_bytes() == report.read_bytes() for path in corpus.rglob("*.json"))
        repeated = CliRunner().invoke(app, ["evidence", "corpus-add", str(archive), "--corpus", str(corpus)])
        assert repeated.exit_code == 0 and len(load_manifest_strict(corpus)) == 1


def test_archive_generation_failure_preserves_original_integrity_reason(tmp_path):
    archive = forged(tmp_path / "bad-plan.zip", [("plan.json", b"{}")],
                     [{"path": "plan.json", "size": 2, "sha256": "0" * 64}])
    output = tmp_path / "review.zip"
    result = CliRunner().invoke(app, ["evidence-review", str(archive), "--archive-member", "plan.json",
                                      "--archive-out", str(output)])
    assert result.exit_code == 2
    assert "archive_member_hash_mismatch" in result.output
    receipt = json.loads(Path(str(output) + ".receipt.json").read_bytes())
    assert "archive_member_hash_mismatch" in receipt["reason_codes"]
    assert receipt["exception_type"] == "ArchiveError"
    assert receipt["archive_published"] is False and Path(receipt["retained_staging"]).is_dir()


@pytest.mark.parametrize("identifier", ["replay-plan", "source-report", "Replay-Plan", "SOURCE-REPORT"])
def test_review_generated_files_cannot_be_overwritten_by_task_ids(tmp_path, identifier):
    manifest = tmp_path / "plan.json"
    manifest.write_text(json.dumps({"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64,
        "tasks": [{"id": identifier, "kind": "trace", "input": "events.jsonl", "sha256": "b" * 64}]}))
    output = tmp_path / "review.zip"
    result = CliRunner().invoke(app, ["evidence-review", str(manifest), "--archive-out", str(output)])
    assert result.exit_code == 2
    assert "reserved_task_identifier" in result.output
    assert not output.exists()


def test_false_directory_count_is_bounded_before_zipinfo_allocation(tmp_path, monkeypatch):
    from apkscan.core import evidence_archive as module
    archive = forged(tmp_path / "false-count.zip", [(str(i), b"x") for i in range(4)])
    raw = bytearray(archive.read_bytes())
    offset = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", raw, offset + 8, 1, 1)
    archive.write_bytes(raw)

    def forbidden(*args, **kwargs):
        pytest.fail("central-directory budget must apply before ZipInfo allocation")

    monkeypatch.setattr(module.zipfile, "ZipFile", forbidden)
    with pytest.raises(ArchiveError, match="archive_directory_budget"):
        EvidenceArchive(archive, Limits(members=1))


@pytest.mark.parametrize("command", ["capture", "recover-runtime", "intake-fetch", "evidence-review"])
def test_output_selection_errors_are_cli_parameter_errors(tmp_path, command):
    result = CliRunner().invoke(app, [command, "synthetic", "--out", str(tmp_path / "out"),
                                     "--archive-out", str(tmp_path / "out.zip")])
    assert result.exit_code == 2, result.output
    assert "choose_output_directory_or_archive" in result.output


@pytest.mark.parametrize("command,module_name", [
    ("evidence-review", "apkscan.core.offline_review.runner"),
    ("intake-fetch", "apkscan.core.fetch_intake"),
    ("recover-runtime", "apkscan.dynamic.recovery"),
])
def test_output_storage_failure_is_not_a_parameter_error(tmp_path, monkeypatch, command, module_name):
    import importlib
    from apkscan.core import evidence_output

    def generate(*args, **kwargs):
        path = Path(args[1])
        path.mkdir(parents=True)
        (path / "evidence.bin").write_bytes(b"retained evidence")
        return {"state": "ok"}

    def fail_pack(*args, **kwargs):
        raise ArchiveError("archive_test_storage_failure")

    monkeypatch.setattr(importlib.import_module(module_name), "run", generate)
    monkeypatch.setattr(evidence_output, "pack", fail_pack)
    source = tmp_path / "input.bin"
    source.write_bytes(b"input")
    output = tmp_path / "output.zip"
    result = CliRunner().invoke(app, [command, str(source), "--archive-out", str(output)])
    assert result.exit_code == 6, result.output
    receipt = json.loads(Path(str(output) + ".receipt.json").read_bytes())
    assert receipt["phase"] == "storage"
    assert (Path(receipt["retained_staging"]) / "data/evidence.bin").read_bytes() == b"retained evidence"


def test_output_display_handles_unresolved_parent_path(tmp_path):
    (tmp_path / "parent").mkdir()
    output = tmp_path / "parent/../archive.zip"
    with EvidenceOutput(None, output) as destination:
        destination.path.mkdir()
        item = destination.path / "evidence.bin"
        item.write_bytes(b"original")
    assert destination.display(str(item)) == destination.reference("evidence.bin")
    assert read_reference(destination.display(str(item)), 100) == b"original"


@pytest.mark.parametrize("hint", ["/synthetic/source", "C:/synthetic/source"])
def test_review_replays_absolute_source_paths_from_either_platform(tmp_path, hint):
    data = b'{"run_id":"synthetic","address_space":"space","seq":1,"op":"write","address":100,"size":4,"data_hex":"01020304"}\n'
    plan = {"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64,
            "tasks": [{"id": "trace", "kind": "trace", "input": hint + "/events.jsonl",
                       "sha256": hashlib.sha256(data).hexdigest(), "run_id": "synthetic",
                       "address_space": "space", "address": 100, "size": 4}]}
    archive = forged(tmp_path / "source.zip", [("events.jsonl", data), ("plan.json", json.dumps(plan).encode())], hint=hint)
    result = CliRunner().invoke(app, ["evidence-review", str(archive), "--archive-member", "plan.json",
                                     "--out", str(tmp_path / "review")])
    assert result.exit_code == 0, result.output
    with pytest.raises(ArchiveError, match="archive_external_reference"):
        resolve_reference(f"{archive}::plan.json", "/elsewhere/events.jsonl")
