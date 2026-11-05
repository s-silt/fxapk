from __future__ import annotations

import hashlib
import json
import socket
import struct

import pytest
from typer.testing import CliRunner

from apkscan.cli import app
from apkscan.core.offline_review import crypto, filesystem, native, runner, trace


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
