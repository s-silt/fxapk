from __future__ import annotations

import hashlib
import json
import socket
import struct
from dataclasses import fields
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fxapk.cli import app
from fxapk.core.models import Report
from fxapk.core.offline_review import crypto, filesystem, native, runner, trace


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("offline review attempted a network connection")
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


def encoded(rows):
    return b"\n".join(json.dumps(row).encode() for row in rows)


def event(seq, address=100, data_hex="01020304", size=4, **kwargs):
    return {"run_id": "synthetic", "address_space": "pid-1-map-1", "seq": seq,
            "op": "write", "address": address, "size": size, "data_hex": data_hex, **kwargs}


TRACE = {"address": 100, "size": 4, "run_id": "synthetic", "address_space": "pid-1-map-1"}


def test_trace_tracks_overwrite_and_intersecting_boundaries():
    rows = [event(1, 98, "aabb0102"), event(2, 102, "0304ccdd"), event(3, 101, "ff", 1)]
    result = trace.review(encoded(rows), TRACE)
    assert result["bytes_hex"] == "01ff0304" and result["known_bytes"] == 4
    assert result["event_counts"]["clipped_to_requested_window"] == 2
    assert result["complete_execution_verified"] is False


@pytest.mark.parametrize("bad", [event(2, data_hex=None), event(3), event(2, data_hex="01"),
                                   event(2, run_id="different"), {"op": "mystery"}])
def test_trace_never_fills_unknown_bytes_with_zero(bad):
    result = trace.review(encoded([event(1), bad]), TRACE)
    assert result["state"] == "partial"
    if bad.get("seq") != 3:
        assert result["bytes_hex"] == "????????"
    assert result["reason_codes"]


def test_trace_read_conflict_and_invalid_tail_invalidate_state():
    conflict = trace.review(encoded([event(1), event(2, op="read", data_hex="ff020304")]), TRACE)
    assert conflict["bytes_hex"] == "??020304"
    malformed = trace.review(encoded([event(1)]) + b"\nnot json", TRACE)
    assert malformed["unknown_bytes"] == 4


def test_fs_paths_and_process_attribution_are_not_fabricated():
    rows = [{"run_id": "r", "seq": n, "timestamp": n, "op": "modify", "path": path, "pid": 7}
            for n, path in enumerate(["/data/user/0/app/file", "/data/user/10/app/file", "/data/user_de/0/app/file"], 1)]
    result = filesystem.review(encoded(rows), {"run_id": "r", "backend": "inotify", "timestamp_basis": "monotonic_ns", "capture_complete": True})
    assert len({row["path"] for row in result["events"]}) == 3
    assert {row["process_attribution"] for row in result["events"]} == {"unknown"}
    assert result["device_collection"] == "not_performed"
    assert not result["file_contents_verified"]


def elf_fixture(machine=183):
    data = bytearray(0x120)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, machine, 1, 0x4000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0x100, 0x4000, 0x4000, 0x20, 0x40, 0x1000)
    struct.pack_into("<IIII", data, 0x100, 0x94000004, 0xD503201F, 0xFFFFFFFF, 0xD65F03C0)
    data[0x110:0x120] = b"needle-synthetic"
    return bytes(data)


def test_elf_mapping_keeps_bss_without_fabricated_file_offset():
    pytest.importorskip("elftools")
    result = native.review(elf_fixture(), {"query": "map", "address_kind": "elf_va", "address": 0x4030})
    assert result["mappings"] == [{"elf_va": 0x4030, "file_offset": None, "file_backed": False}]
    mapped = native.review(elf_fixture(), {"query": "strings", "needle": "synthetic"})
    assert mapped["matches"][0]["mappings"][0]["elf_va"] == 0x4010


def test_arm64_callers_continue_after_invalid_instruction():
    pytest.importorskip("elftools")
    pytest.importorskip("capstone")
    result = native.review(elf_fixture(), {"query": "callers", "address": 0x4000, "size": 16, "target": 0x4010})
    assert result["state"] == "partial" and result["invalid_instruction_words"] == 1
    assert result["matches"][0]["elf_va"] == 0x4000
    assert native.review(elf_fixture(62), {"query": "disasm"})["state"] == "unsupported"


def gcm_document():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = bytes(range(16))
    rows = []
    for n, role in enumerate(["fit", "validation"], 1):
        iv = bytes([n]) * 12
        text = b"synthetic" + bytes([n])
        rows.append({"role": role, "iv_hex": iv.hex(), "ciphertext_hex": AESGCM(key).encrypt(iv, text, b"scope").hex(),
                     "aad_hex": b"scope".hex(), "expected_plaintext_hex": text.hex()})
    return {"algorithm": "AES-GCM", "key_hex": key.hex(), "vectors": rows}


def test_crypto_requires_validation_and_rejects_counterexample_without_secrets():
    document = gcm_document()
    good = crypto.review(json.dumps(document).encode(), {})
    assert good["state"] == "ok" and all(row["tamper_rejected"] for row in good["vectors"])
    assert document["key_hex"] not in json.dumps(good)
    document["vectors"][1]["aad_hex"] = "00"
    bad = crypto.review(json.dumps(document).encode(), {})
    assert bad["state"] == "failed" and bad["vectors"][1]["reason_code"] == "authentication_failed"
    document["vectors"] = document["vectors"][:1]
    assert crypto.review(json.dumps(document).encode(), {})["state"] == "partial"


def test_cli_failure_reaches_receipt_digest_html_and_continues(tmp_path):
    data = encoded([event(1)])
    (tmp_path / "trace.jsonl").write_bytes(data)
    tasks = [
        {"id": "bad-hash", "kind": "trace", "input": "trace.jsonl", "sha256": "f" * 64, **TRACE},
        {"id": "good", "kind": "trace", "input": "trace.jsonl", "sha256": hashlib.sha256(data).hexdigest(), **TRACE},
        {"id": "unknown", "kind": "future-kind"},
    ]
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64, "tasks": tasks}))
    out = tmp_path / "review"
    invocation = CliRunner().invoke(app, ["evidence-review", str(plan), "--out", str(out)])
    assert invocation.exit_code == 5, invocation.output
    receipt = json.loads((out / "review.json").read_text())
    assert [row["state"] for row in receipt["tasks"]] == ["failed", "ok", "unsupported"]
    digest = json.loads((out / "digest.json").read_text(encoding="utf-8"))
    assert digest["offline_evidence_review"]["tasks"][0]["reason_codes"] == ["review_input_hash_mismatch"]
    html_text = (out / "report.html").read_text(encoding="utf-8")
    assert "bad-hash" in html_text and "review_input_hash_mismatch" in html_text
    assert "trace.jsonl" not in json.dumps(digest)
    assert invocation.output.count('"state": "running"') == 3
    before = (out / "review.json").read_bytes()
    assert CliRunner().invoke(app, ["evidence-review", str(plan), "--out", str(out)]).exit_code == 2
    assert (out / "review.json").read_bytes() == before


@pytest.mark.parametrize(
    ("source_health", "expected_health", "reliable"),
    [
        pytest.param({}, {"analysis_status": None, "completeness": None},
                     False, id="legacy-omitted-both"),
        pytest.param({"completeness": 1.0}, {"analysis_status": None, "completeness": 1.0},
                     False, id="omitted-status"),
        pytest.param({"analysis_status": "complete"}, {"analysis_status": "complete", "completeness": None},
                     False, id="omitted-completeness"),
        pytest.param({"analysis_status": "complete", "completeness": 1.0},
                     {"analysis_status": "complete", "completeness": 1.0}, True, id="healthy"),
        pytest.param({"analysis_status": "partial", "completeness": 0.4},
                     {"analysis_status": "partial", "completeness": 0.4}, False, id="partial"),
        pytest.param({"analysis_status": "partial", "completeness": 1.0},
                     {"analysis_status": "partial", "completeness": 1.0}, False, id="partial-with-full-count"),
        pytest.param({"analysis_status": "failed", "completeness": 0.0},
                     {"analysis_status": "failed", "completeness": 0.0}, False, id="failed"),
        pytest.param({"analysis_status": "unknown", "completeness": 1.0},
                     {"analysis_status": "unknown", "completeness": 1.0}, False, id="explicit-unknown"),
        pytest.param({"analysis_status": "complete", "completeness": 0.0},
                     {"analysis_status": "complete", "completeness": 0.0}, False, id="observed-zero"),
        pytest.param({"analysis_status": None, "completeness": 1.0},
                     {"analysis_status": None, "completeness": 1.0}, False, id="null-status"),
        pytest.param({"analysis_status": "complete", "completeness": None},
                     {"analysis_status": "complete", "completeness": None}, False, id="null-count"),
        pytest.param({"analysis_status": "complete", "completeness": "synthetic-untrusted-value"},
                     {"analysis_status": "complete", "completeness": None}, False, id="wrong-count"),
        pytest.param({"analysis_status": "complete", "completeness": True},
                     {"analysis_status": "complete", "completeness": None}, False, id="boolean-count"),
        pytest.param({"analysis_status": "synthetic-untrusted-value", "completeness": 1.0},
                     {"analysis_status": None, "completeness": 1.0}, False, id="untrusted-status-string"),
        pytest.param({"analysis_status": {"note": "synthetic-untrusted-value"}, "completeness": 1.0},
                     {"analysis_status": None, "completeness": 1.0}, False, id="untrusted-status-object"),
        pytest.param({"analysis_status": "Complete", "completeness": 1.0},
                     {"analysis_status": None, "completeness": 1.0}, False, id="noncanonical-status"),
    ],
)
def test_cli_offline_revision_preserves_only_observed_analysis_health(
    tmp_path: Path, source_health: dict[str, object],
    expected_health: dict[str, object], reliable: bool,
) -> None:
    sample = "a" * 64
    source = tmp_path / "source-report.json"
    original = json.dumps({"package_name": "com.example.synthetic", "meta": {"sample_sha256": sample},
                           "leads": [], **source_health}).encode()
    source.write_bytes(original)
    manifest = tmp_path / "plan.json"
    manifest.write_text(json.dumps({
        "schema_version": "fxapk.offline-review.v1", "sample_sha256": sample,
        "tasks": [{"id": "synthetic-inert", "kind": "fixture_unsupported"}],
    }), encoding="utf-8")
    out = tmp_path / "review"
    cli = CliRunner()

    source_check = cli.invoke(app, ["digest", str(source)])
    review = cli.invoke(app, ["evidence-review", str(manifest), "--report", str(source), "--out", str(out)])
    assert (source_check.exit_code, review.exit_code) == (0, 5)
    assert json.loads(source_check.stdout)["integrity"]["reliable"] is reliable
    assert json.loads(review.stdout)["state"] == "partial"
    assert source.read_bytes() == original

    report_text = (out / "report.json").read_text(encoding="utf-8")
    digest_text = (out / "digest.json").read_text(encoding="utf-8")
    html_text = (out / "report.html").read_text(encoding="utf-8")
    revision = json.loads(report_text)
    assert set(revision) == {field.name for field in fields(Report)}
    assert {key: revision[key] for key in ("analysis_status", "completeness")} == expected_health
    digest = json.loads(digest_text)
    integrity = digest["integrity"]
    assert integrity["reliable"] is reliable
    for field in ("analysis_status", "completeness"):
        assert integrity[field] == expected_health.get(field)
    assert bool(integrity["warnings"]) is (not reliable)
    again = cli.invoke(app, ["digest", str(out / "report.json")])
    assert again.exit_code == 0
    assert json.loads(again.stdout)["integrity"] == integrity
    assert "synthetic-untrusted-value" not in report_text + digest_text + html_text + again.stdout

    receipt = json.loads((out / "review.json").read_text(encoding="utf-8"))
    task = json.loads((out / "synthetic-inert.json").read_text(encoding="utf-8"))
    assert (receipt["state"], receipt["publication"]) == ("partial", "ok")
    assert (task["state"], task["reason_codes"], task["input_sha256"]) == (
        "unsupported", ["review_kind_unsupported"], None,
    )
    assert digest["offline_evidence_review"]["tasks"][0]["reason_codes"] == ["review_kind_unsupported"]
    assert "review_kind_unsupported" in html_text
    assert not (out / "inputs").exists() and not list(out.glob("*-artifacts"))


@pytest.mark.parametrize("identifiers", [["manifest"], ["REPORT"], ["A", "a"], ["NUL"]])
def test_output_identifiers_cannot_clobber_receipts(tmp_path, identifiers):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64,
                                "tasks": [{"id": item, "kind": "future"} for item in identifiers]}))
    with pytest.raises(ValueError):
        runner.run(plan, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_missing_optional_library_is_visible_and_later_stage_runs(tmp_path, monkeypatch):
    data = encoded([event(1)])
    source = tmp_path / "input.jsonl"
    source.write_bytes(data)
    def unavailable(*args):
        raise ImportError("not installed")
    monkeypatch.setitem(runner.REVIEWERS, "native", unavailable)
    tasks = [{"id": kind, "kind": kind, "input": source.name, "sha256": hashlib.sha256(data).hexdigest(), **TRACE}
             for kind in ("native", "trace")]
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64, "tasks": tasks}))
    receipt = runner.run(plan, tmp_path / "out")
    assert [row["state"] for row in receipt["tasks"]] == ["unsupported", "ok"]
    assert receipt["tasks"][0]["reason_codes"] == ["optional_dependency_unavailable"]


def test_hash_mismatch_never_retains_unverified_input(tmp_path):
    """★顺序修复回归（sfind-d0e9f024）：sha256 不匹配的输入不得写进 inputs/。"""
    data = encoded([event(1)])
    (tmp_path / "trace.jsonl").write_bytes(data)
    good_hash = hashlib.sha256(data).hexdigest()
    tasks = [
        {"id": "bad-hash", "kind": "trace", "input": "trace.jsonl", "sha256": "0" * 64, **TRACE},
        {"id": "bad-format", "kind": "trace", "input": "trace.jsonl", "sha256": "not-hex", **TRACE},
        {"id": "good", "kind": "trace", "input": "trace.jsonl", "sha256": good_hash, **TRACE},
    ]
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"schema_version": "fxapk.offline-review.v1",
                                "sample_sha256": "a" * 64, "tasks": tasks}))
    out = tmp_path / "review"
    receipt = runner.run(plan, out, retain_inputs=True)
    states = {row["id"]: row for row in receipt["tasks"]}
    assert states["bad-hash"]["state"] == "failed"
    assert states["bad-hash"]["reason_codes"] == ["review_input_hash_mismatch"]
    assert states["bad-format"]["reason_codes"] == ["review_input_hash_mismatch"]
    assert states["good"]["state"] == "ok"
    retained = sorted(p.name for p in (out / "inputs").iterdir())
    assert retained == ["good.bin"]
