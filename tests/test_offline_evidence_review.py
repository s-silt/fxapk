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
        pytest.param({"analysis_status": "complete", "completeness": 1.2},
                     {"analysis_status": "complete", "completeness": None}, False, id="out-of-range-count"),
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
    original = json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {"sample_sha256": sample, "tool_version": "1.5.4", "ruleset_digest": "b" * 16},
        "leads": [],
        **source_health,
    }).encode()
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

    revision_path = out / "report.json"
    receipt_path = out / "review.json"
    receipt_bytes = receipt_path.read_bytes()
    close = cli.invoke(app, ["case", "close", str(revision_path), "--offline"])
    assert close.exit_code == 6, close.output  # no investigation target in this fixture
    assert "闭环状态：failed" in close.stdout
    persisted = json.loads(revision_path.read_text(encoding="utf-8"))
    closure = persisted["meta"]["closure"]
    assert closure["status"] == "failed"
    static_gate = next(check for check in closure["checks"] if check["id"] == "static_health")
    assert static_gate["status"] == {"complete": "pass", "failed": "fail"}.get(
        expected_health["analysis_status"], "warn",
    )
    assert {key: persisted[key] for key in expected_health} == expected_health
    after = cli.invoke(app, ["digest", str(revision_path)])
    assert after.exit_code == 0
    assert json.loads(after.stdout)["integrity"] == integrity
    assert source.read_bytes() == original and receipt_path.read_bytes() == receipt_bytes

    if expected_health["analysis_status"] in (None, "unknown"):
        package_path = out / "case-package.json"
        package = cli.invoke(app, [
            "case", "package", str(revision_path), "--case-id", "synthetic-test",
            "--producer", "synthetic", "--out", str(package_path),
        ])
        assert package.exit_code == 2
        assert "invalid analysis status" in package.stderr
        assert not package_path.exists()


_CLOSURE_FIXTURE_TARGET = {"kind": "domain", "value": "fixture.example.invalid"}


@pytest.mark.parametrize(("closure_meta", "status", "show_section", "projected_status", "admitted_contact"), [
    pytest.param({}, None, False, None, False, id="absent"),
    pytest.param({"closure": {}}, None, False, None, False, id="empty"),
    pytest.param({"closure": None}, None, False, None, False, id="null-receipt"),
    pytest.param({"closure": [{}]}, None, False, None, False, id="invalid-receipt"),
    pytest.param({"closure": {"gaps": ["fixture gap"]}}, None, True, None, False, id="missing-status"),
    pytest.param({"closure": {"status": None}}, None, True, None, False, id="null-status"),
    pytest.param({"closure": {"status": False}}, None, True, None, False, id="boolean-status"),
    pytest.param({"closure": {"status": ["failed"]}}, None, True, None, False, id="array-status"),
    pytest.param({"closure": {"status": "unknown"}}, None, True, None, False, id="unknown-status"),
    pytest.param({"closure": {"status": "unavailable"}}, None, True, None, False, id="unavailable-status"),
    pytest.param({"closure": {"status": "FIXTURE_STATUS_FREE_TEXT <b>"}}, None, True, None, False, id="free-text-status"),
    pytest.param({"closure": {"status": "failed"}}, "failed", True, None, False, id="observed-failure"),
    pytest.param({"closure": {"status": "not_run"}}, "not_run", True, None, False, id="not-run"),
    pytest.param({"closure": {"status": "interrupted"}}, "interrupted", True, None, False, id="interrupted"),
    pytest.param({"closure": {"status": "partial"}}, "partial", True, None, False, id="partial"),
    pytest.param({"closure": {"status": " failed "}}, "failed", True, None, False, id="padded-failure"),
    pytest.param({"closure": {"status": "\tpartial\n"}}, "partial", True, None, False, id="padded-partial"),
    pytest.param({"closure": {"status": " not_run "}}, "not_run", True, None, False, id="padded-not-run"),
    pytest.param({"closure": {"status": " interrupted "}}, "interrupted", True, None, False, id="padded-interrupted"),
    pytest.param({"closure": {"status": " unknown "}}, None, True, None, False, id="padded-unknown"),
    pytest.param({"closure": {"status": " Complete "}}, None, True, None, False, id="padded-case-variant"),
    pytest.param({"closure": {"status": " \t "}}, None, True, None, False, id="whitespace-only-status"),
    pytest.param({"closure": {"status": "complete", "targets": []}}, "failed", True, "failed", False, id="unsupported-complete"),
    pytest.param({"closure": {"status": " complete ", "targets": []}},
                 "failed", True, "failed", False, id="padded-complete-no-target"),
    pytest.param({"closure": {"status": " complete ", "targets": [_CLOSURE_FIXTURE_TARGET]}},
                 "partial", True, "partial", False, id="padded-complete-unattested"),
    pytest.param({"closure": {"status": " complete ", "targets": [_CLOSURE_FIXTURE_TARGET]}},
                 "complete", True, "complete", True, id="padded-complete-attested"),
])
def test_cli_offline_revision_displays_only_known_closure_status(
    tmp_path: Path, closure_meta: dict[str, object], status: str | None, show_section: bool,
    projected_status: str | None, admitted_contact: bool,
) -> None:
    sample = "a" * 64
    source = tmp_path / "source.json"
    payload: dict[str, object] = {
        "package_name": "com.example.synthetic",
        "analysis_status": "complete", "completeness": 1.0,
        "meta": {"sample_sha256": sample, **closure_meta},
    }
    if admitted_contact:
        payload["endpoints"] = [{**_CLOSURE_FIXTURE_TARGET, "evidences": [{
            "source": "runtime-pcap", "location": "fixture-memory", "scope": "case_evidence",
            "provenance": {"member_path": "classes.dex", "member_sha256": sample},
            "locator": {"byte_offset": 2, "offset_unit": "byte"},
            "structure_status": "parsed", "reference_status": "referenced", "reachability": "reachable",
        }]}]
    original = json.dumps(payload).encode()
    source.write_bytes(original)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "schema_version": "fxapk.offline-review.v1", "sample_sha256": sample,
        "tasks": [{"id": "synthetic-inert", "kind": "fixture_unsupported"}],
    }), encoding="utf-8")
    out = tmp_path / "review"
    cli = CliRunner()
    before = cli.invoke(app, ["digest", str(source)])
    review = cli.invoke(app, ["evidence-review", str(plan), "--report", str(source), "--out", str(out)])
    after = cli.invoke(app, ["digest", str(out / "report.json")])
    assert (before.exit_code, review.exit_code, after.exit_code) == (0, 5, 0), review.output
    assert json.loads(review.stdout)["state"] == "partial"
    assert json.loads((out / "review.json").read_text(encoding="utf-8"))["publication"] == "ok"
    assert not (out / "inputs").exists()
    assert source.read_bytes() == original

    closure = json.loads(before.stdout)["closure"]
    assert closure == json.loads(after.stdout)["closure"]
    assert closure == json.loads((out / "digest.json").read_text(encoding="utf-8"))["closure"]
    assert closure["status"] == status
    published = json.loads((out / "report.json").read_text(encoding="utf-8"))["meta"]
    if projected_status is None:
        assert {key: published[key] for key in ("closure",) if key in published} == closure_meta
    else:
        raw_closure = closure_meta["closure"]
        assert isinstance(raw_closure, dict)
        assert published["closure"]["status"] == projected_status
        assert published["closure"]["targets"] == raw_closure["targets"]
        assert bool(closure["gaps"]) is (projected_status != "complete")

    html = (out / "report.html").read_text(encoding="utf-8")
    closure_section = html.partition('<section id="case-closure">')[2].partition("</section>")[0]
    assert bool(closure_section) is show_section
    if show_section:
        assert f'>{status or "未记录或无法确认"}</div>' in closure_section
    assert ("fixture gap" in closure_section) == ("fixture gap" in closure["gaps"])
    assert "FIXTURE_STATUS_FREE_TEXT" not in html + before.stdout + after.stdout


_WEB_PLAN = {"status": "pending", "reason": "no_config", "execute": False, "platform": "android"}
_UNRECOGNIZED_WEB_STATE = "FIXTURE_UNRECOGNIZED_WEB_STATE"
_WEB_RECEIPT_SCHEMA = "fxapk.web_supplement/1"


@pytest.mark.parametrize(("web_meta", "expected"), [
    pytest.param({}, None, id="legacy-absent-both"),
    pytest.param({"web_observation_plan": _WEB_PLAN}, ("unknown", "", 0, 0), id="planner-only"),
    pytest.param({"web_supplement": None}, ("unknown", "", 0, 0), id="explicit-null"),
    pytest.param({"web_supplement": _UNRECOGNIZED_WEB_STATE}, ("unknown", "", 0, 0), id="bad-container"),
    pytest.param({"web_supplement": {}}, ("unknown", "", 0, 0), id="empty-receipt"),
    pytest.param({"web_supplement": {"status": "complete"}}, ("unknown", "", 0, 0), id="not-a-web-status"),
    pytest.param({"web_supplement": {"status": _UNRECOGNIZED_WEB_STATE, "reason": "worker_not_stopped"}},
                 ("unknown", "", 0, 0), id="bad-status-with-known-reason"),
    pytest.param({"web_supplement": {"status": "skipped", "reason": "config_rejected"}},
                 ("skipped", "config_rejected", 1, 0), id="recorded-skip"),
    pytest.param({"web_supplement": {"status": "failed", "reason": "worker_not_stopped"}},
                 ("failed", "worker_not_stopped", 1, 1), id="recorded-failure"),
    pytest.param({"web_supplement": {"status": "pending"}},
                 ("pending", "", 0, 0), id="pending-without-reason"),
    pytest.param({"web_supplement": {"status": "pending", "reason": "no_config"}},
                 ("pending", "no_config", 0, 0), id="pending-with-known-reason"),
    pytest.param({"web_supplement": {"status": "failed"}},
                 ("failed", "", 1, 1), id="failure-without-reason"),
    pytest.param({"web_supplement": {"status": "failed", "reason": _UNRECOGNIZED_WEB_STATE}},
                 ("failed", "", 1, 1), id="failure-with-unrecognized-reason"),
    pytest.param({"web_supplement": {"status": "skipped", "reason": False}},
                 ("skipped", "", 1, 0), id="skip-with-malformed-reason"),
    pytest.param({"web_supplement": {"status": "skipped", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 0}},
                 ("skipped", "", 0, 0), id="canonical-skip-without-attempt"),
    pytest.param({"web_supplement": {"status": "skipped", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": False}},
                 ("skipped", "", 1, 0), id="bool-zero-cannot-override-legacy-terminal"),
    pytest.param({"web_supplement": {"status": "unavailable", "reason": "plugin_unavailable"}},
                 ("unavailable", "plugin_unavailable", 0, 0), id="unavailable-without-attempt"),
    pytest.param({"web_supplement": {
        "status": "unavailable", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 1, "latest_status": "failed",
    }}, ("unavailable", "", 1, 0, "failed", ""), id="canonical-unavailable-attempt-with-distinct-latest"),
    pytest.param({"web_supplement": {
        "status": "unavailable", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 0, "latest_status": "failed",
    }}, ("unavailable", "", 0, 0, "failed", ""), id="canonical-unavailable-with-no-attempt"),
    pytest.param({"web_supplement": {
        "status": "unavailable", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": True,
    }}, ("unavailable", "", 0, 0), id="bool-one-is-not-a-canonical-attempt"),
    pytest.param({"web_supplement": {
        "status": "unavailable", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 1.0,
    }}, ("unavailable", "", 0, 0), id="float-one-is-not-a-canonical-attempt"),
    pytest.param({"web_supplement": {
        "status": "unavailable", "schema_version": "fixture.unsupported", "attempt": 1,
    }}, ("unavailable", "", 0, 0), id="unrecognized-schema-cannot-prove-an-attempt"),
    pytest.param({"web_supplement": {"status": "not_applicable"}},
                 ("not_applicable", "", 0, 0), id="recorded-not-applicable-without-reason"),
    pytest.param({"web_supplement": {
        "status": "not_applicable", "reason": "no_config", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 1,
        "latest_status": "failed", "latest_reason": "timeout",
    }}, ("not_applicable", "no_config", 0, 0, "failed", "timeout"), id="not-applicable-has-no-inferred-attempt"),
    pytest.param({"web_supplement": {
        "status": "not_applicable", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 0,
        "attempts": [{"status": "unavailable"}, {"status": "failed"}, {"status": "pending"}],
    }}, ("not_applicable", "", 2, 1), id="explicit-unavailable-and-failed-attempts"),
    pytest.param({"web_supplement": {
        "status": "skipped",
        "attempts": [
            {"status": "not_applicable", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 1},
            {"status": "skipped", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 0},
            {"status": "failed", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 0},
            {"status": "unavailable", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 1},
            {"status": "failed", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": False},
            {"status": "skipped", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 0.0},
            {"status": "failed", "schema_version": "fixture.unsupported", "attempt": 0},
            {"status": "skipped"},
        ],
    }}, ("skipped", "", 5, 2), id="listed-attempts-respect-only-the-canonical-integer-zero"),
    pytest.param({"web_supplement": {
        "status": "unavailable", "schema_version": _WEB_RECEIPT_SCHEMA, "attempt": 1, "attempts": [],
    }}, ("unavailable", "", 0, 0), id="explicit-empty-attempts-override-canonical-marker"),
    pytest.param({"web_supplement": {
        "status": "ok", "reason": "executed", "latest_status": "failed",
    }}, ("ok", "executed", 1, 0, "failed", ""), id="latest-failure-does-not-borrow-reason"),
    pytest.param({"web_supplement": {
        "status": "ok", "reason": "executed", "latest_status": "failed", "latest_reason": "timeout",
    }}, ("ok", "executed", 1, 0, "failed", "timeout"), id="latest-failure-own-reason-not-a-primary-failure"),
    pytest.param({"web_supplement": {
        "status": "failed", "reason": "worker_not_stopped", "latest_status": "executed", "latest_reason": "executed",
    }}, ("failed", "worker_not_stopped", 1, 1, "executed", "executed"), id="legacy-primary-failure-still-counts"),
    pytest.param({"web_supplement": {
        "status": "ok", "reason": "executed", "latest_status": None, "latest_reason": "timeout",
    }}, ("ok", "executed", 1, 0, "unknown", ""), id="malformed-latest-status-does-not-borrow-reason"),
    pytest.param({"web_supplement": {
        "status": "failed", "reason": "worker_not_stopped", "latest_status": "failed", "latest_reason": None,
    }}, ("failed", "worker_not_stopped", 1, 1, "failed", ""), id="explicit-null-latest-reason"),
    pytest.param({"web_supplement": {
        "status": "failed", "reason": "worker_not_stopped", "latest_status": "failed",
    }}, ("failed", "worker_not_stopped", 1, 1), id="same-latest-status-inherits-known-reason"),
    pytest.param({"web_supplement": {
        "status": _UNRECOGNIZED_WEB_STATE, "latest_status": "failed",
    }}, ("unknown", "", 0, 0, "failed", ""), id="bad-primary-no-estimated-attempt"),
    pytest.param({"web_supplement": {
        "status": _UNRECOGNIZED_WEB_STATE, "latest_status": "failed", "latest_reason": "timeout",
        "attempts": [{"status": "ok"}, {"status": "failed"}],
    }}, ("unknown", "", 2, 1, "failed", "timeout"), id="bad-primary-with-latest-and-explicit-attempts"),
    pytest.param({"web_supplement": {
        "status": _UNRECOGNIZED_WEB_STATE,
        "attempts": [
            {"status": "failed"}, {"status": "ok"}, {"status": "pending"},
            {"status": _UNRECOGNIZED_WEB_STATE}, {"status": False}, None,
        ],
    }}, ("unknown", "", 2, 1), id="bad-status-with-independent-attempts"),
])
def test_cli_saved_web_supplement_distinguishes_unknown_from_recorded_outcomes(
    tmp_path: Path, web_meta: dict[str, object],
    expected: tuple[str, str, int, int] | tuple[str, str, int, int, str, str] | None,
) -> None:
    sample = "a" * 64
    source = tmp_path / "source.json"
    original = json.dumps({
        "package_name": "com.example.synthetic",
        "analysis_status": "complete", "completeness": 1.0,
        "meta": {"sample_sha256": sample, **web_meta},
    }).encode()
    source.write_bytes(original)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "schema_version": "fxapk.offline-review.v1", "sample_sha256": sample,
        "tasks": [{"id": "synthetic-inert", "kind": "fixture_unsupported"}],
    }), encoding="utf-8")
    out = tmp_path / "review"
    cli = CliRunner()
    before = cli.invoke(app, ["digest", str(source)])
    review = cli.invoke(app, ["evidence-review", str(plan), "--report", str(source), "--out", str(out)])
    replay = cli.invoke(app, ["digest", str(out / "report.json")])
    assert (before.exit_code, review.exit_code, replay.exit_code) == (0, 5, 0), review.output
    assert json.loads(review.stdout)["state"] == "partial"
    assert json.loads((out / "review.json").read_text(encoding="utf-8"))["publication"] == "ok"
    assert not (out / "inputs").exists()
    assert source.read_bytes() == original

    published = json.loads((out / "report.json").read_text(encoding="utf-8"))["meta"]
    assert {key: published[key] for key in ("web_observation_plan", "web_supplement") if key in published} == web_meta
    digests = (json.loads(before.stdout), json.loads((out / "digest.json").read_text(encoding="utf-8")),
               json.loads(replay.stdout))
    view = digests[0].get("web_supplement")
    assert view == digests[1].get("web_supplement") == digests[2].get("web_supplement")
    if "web_observation_plan" in web_meta:
        assert all(digest["web_observation_plan"]["status"] == "pending" for digest in digests)

    html = (out / "report.html").read_text(encoding="utf-8")
    section = html.partition('<section id="web-supplement">')[2].partition("</section>")[0]
    assert _UNRECOGNIZED_WEB_STATE not in html + before.stdout + replay.stdout
    if expected is None:
        assert view is None and not section
        return
    status, reason, attempts, failures, *latest = expected
    latest_status, latest_reason = latest or (status, reason)
    assert (view["status"], view["reason"], view["attempt_count"], view["failure_count"]) == (
        status, reason, attempts, failures,
    )
    assert (view["latest_status"], view["latest_reason"]) == (latest_status, latest_reason)
    assert view["capture_started"] is view["app_attribution_verified"] is view["closure_evaluated"] is False
    assert view["summary_line"] in section and "仍缺证据" in view["summary_line"]
    assert f'<div class="k">最近状态</div><div>{latest_status}</div>' in section
    assert f'<div class="k">最近原因</div><div class="mono">{latest_reason}</div>' in section
    assert f'<div class="k">尝试 / 失败</div><div class="mono">{attempts} / {failures}</div>' in section
    if status in {"unknown", "pending", "unavailable", "not_applicable"}:
        assert "已跳过" not in section and "补采失败" not in section
    labels = {
        "pending": "网页补采待处理", "skipped": "网页补采已跳过", "failed": "网页补采失败",
        "unavailable": "网页补采不可用", "not_applicable": "网页补采不适用",
    }
    if status in labels:
        suffix = f"：{reason}" if reason else ""
        assert view["summary_line"] == f"{labels[status]}{suffix}；仍缺证据"


@pytest.mark.parametrize(("receipts", "counts"), [
    pytest.param(("no_config",), (0, 0), id="no-config"),
    pytest.param(("mode_off",), (0, 0), id="mode-off"),
    pytest.param(("duplicate_raw",), (1, 0), id="attempted-duplicate"),
    pytest.param(("no_config", "mode_off", "duplicate_raw", "plugin_unavailable", "parse_failed"), (3, 1),
                 id="mixed-canonical-attempt-receipts"),
])
def test_cli_saved_web_supplement_counts_produced_attempts(
    tmp_path: Path, receipts: tuple[str, ...], counts: tuple[int, int],
) -> None:
    from fxapk.core.web_observation_plan import WebSupplementRequest, build_plan
    from fxapk.core.web_supplement import _record
    from fxapk.core.web_supplement_preservation import commit_supplement

    no_config = build_plan(None, platform="android", meta={})
    mode_off = build_plan(WebSupplementRequest(mode="off"), platform="android", meta={})
    selected = build_plan(
        WebSupplementRequest(mode="auto", source="bundle", path="synthetic"), platform="android", meta={},
    )
    rows = {
        "no_config": (no_config, "not_applicable", 0),
        "mode_off": (mode_off, "skipped", 0),
        "duplicate_raw": (selected, "skipped", 1),
        "plugin_unavailable": (selected, "unavailable", 1),
        "parse_failed": (selected, "failed", 1),
    }
    sample = "a" * 64
    meta: dict[str, object] = {"sample_sha256": sample}
    for reason in receipts:
        plan, status, attempted = rows[reason]
        state = _record(plan) if reason in {"no_config", "mode_off"} else _record(plan, status=status, reason=reason)
        assert (state["schema_version"], state["status"], state["reason"], state["attempt"]) == (
            _WEB_RECEIPT_SCHEMA, status, reason, attempted,
        )
        commit_supplement(meta, state)

    source = tmp_path / "source.json"
    original = json.dumps({
        "package_name": "com.example.synthetic", "analysis_status": "complete", "completeness": 1.0, "meta": meta,
    }).encode()
    source.write_bytes(original)
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps({
        "schema_version": "fxapk.offline-review.v1", "sample_sha256": sample,
        "tasks": [{"id": "synthetic-inert", "kind": "fixture_unsupported"}],
    }), encoding="utf-8")
    out = tmp_path / "review"
    cli = CliRunner()
    before = cli.invoke(app, ["digest", str(source)])
    review = cli.invoke(app, ["evidence-review", str(plan_file), "--report", str(source), "--out", str(out)])
    assert (before.exit_code, review.exit_code) == (0, 5), review.output
    view = json.loads(before.stdout)["web_supplement"]
    assert view == json.loads((out / "digest.json").read_text(encoding="utf-8"))["web_supplement"]
    assert (view["attempt_count"], view["failure_count"]) == counts
    html = (out / "report.html").read_text(encoding="utf-8")
    section = html.partition('<section id="web-supplement">')[2].partition("</section>")[0]
    assert f'<div class="k">尝试 / 失败</div><div class="mono">{counts[0]} / {counts[1]}</div>' in section
    assert json.loads((out / "report.json").read_text(encoding="utf-8"))["meta"]["web_supplement"] == meta["web_supplement"]
    assert source.read_bytes() == original


@pytest.mark.parametrize(("visibility_fields", "state"), [
    pytest.param({}, "absent", id="legacy-absent"),
    pytest.param({"visibility": None}, "absent", id="legacy-null"),
    pytest.param({"visibility": {
        "sources": {"resource": {"visibility": "partial", "why": ["synthetic coverage gap"]}},
        "blocked_claims": ["static_endpoint_exhaustive"],
    }}, "valid", id="valid"),
    pytest.param({"visibility": "synthetic-untrusted-visibility"}, "invalid", id="wrong-root"),
    pytest.param({"visibility": {"sources": [{"visibility": "partial"}]}}, "invalid", id="list-sources"),
    pytest.param({"visibility": {"sources": []}}, "invalid", id="empty-list-sources"),
    pytest.param({"visibility": {"blocked_claims": {"synthetic-untrusted-visibility": True}}},
                 "invalid", id="wrong-blocked-claims"),
    pytest.param({"visibility": {"notes": "synthetic-untrusted-visibility"}}, "invalid", id="wrong-notes"),
    pytest.param({"visibility": {"next_actions": None}}, "invalid", id="wrong-next-actions"),
])
def test_cli_offline_revision_preserves_coverage_when_visibility_is_invalid(
    tmp_path: Path, visibility_fields: dict[str, object], state: str,
) -> None:
    sample = "a" * 64
    source = tmp_path / "source.json"
    scan = {"files_scanned": 1, "files_total": 2}
    original = json.dumps({
        "package_name": "com.example.synthetic", "analysis_status": "complete", "completeness": 1,
        "meta": {
            "sample_sha256": sample, "jadx_receipt": {"scan": scan}, "card_merchant_read_failed": 1,
            **visibility_fields,
        },
    }).encode()
    source.write_bytes(original)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "schema_version": "fxapk.offline-review.v1", "sample_sha256": sample,
        "tasks": [{"id": "synthetic-inert", "kind": "fixture_unsupported"}],
    }), encoding="utf-8")
    out = tmp_path / "review"
    cli = CliRunner()
    source_digest = cli.invoke(app, ["digest", str(source)])
    assert source_digest.exit_code == 0

    review = cli.invoke(app, ["evidence-review", str(plan), "--report", str(source), "--out", str(out)])
    assert review.exit_code == 5, review.output
    assert json.loads(review.stdout)["state"] == "partial"
    assert source.read_bytes() == original
    receipt = json.loads((out / "review.json").read_text(encoding="utf-8"))
    task = json.loads((out / "synthetic-inert.json").read_text(encoding="utf-8"))
    assert (receipt["state"], receipt["publication"]) == ("partial", "ok")
    assert (task["state"], task["reason_codes"], task["input_sha256"]) == (
        "unsupported", ["review_kind_unsupported"], None,
    )
    assert not (out / "inputs").exists()
    published = json.loads((out / "report.json").read_text(encoding="utf-8"))["meta"]
    assert ("visibility" in published) is ("visibility" in visibility_fields)
    assert published.get("visibility") == visibility_fields.get("visibility")

    digest = json.loads((out / "digest.json").read_text(encoding="utf-8"))
    assert digest["visibility"] == json.loads(source_digest.stdout)["visibility"]
    assert digest["visibility"]["available"] is (state == "valid")
    assert digest["visibility"]["java_scan"] == scan
    assert digest["coverage"]["card_merchant_read_failed"] == 1

    html = (out / "report.html").read_text(encoding="utf-8")
    assert ('可见性字段结构异常；输入完整性未知' in html) is (state == "invalid")
    assert ("<li>static_endpoint_exhaustive</li>" in html) is (state == "valid")
    assert ("synthetic coverage gap" in html) is (state == "valid")
    assert "synthetic-untrusted-visibility" not in html
    assert 'id="jadx-java-scan"' in html and "1/2" in html
    assert "card_merchant_read_failed = 1" in html


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



@pytest.mark.parametrize(("read_failures", "cleanup_failed"), [
    pytest.param((), False, id="limit-only"),
    pytest.param((), True, id="cleanup-incomplete"),
    pytest.param(("A.java",), False, id="read-failed"),
    pytest.param(("A.java",), True, id="read-and-cleanup-failed"),
    pytest.param(("A.java", "B.java"), False, id="all-selected-reads-failed"),
])
def test_offline_review_projects_saved_java_file_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    read_failures: tuple[str, ...], cleanup_failed: bool,
) -> None:
    from shutil import rmtree

    from fxapk.analyzers import jadx
    from tests.conftest import FakeContext

    java_tree = tmp_path / "synthetic-java"
    java_tree.mkdir()
    for name in ("C", "A", "B"):
        (java_tree / f"{name}.java").write_text(f"class {name} {{}}", encoding="utf-8")
    analyzer = jadx.JadxAnalyzer()
    original_open = Path.open

    def read_java(path: Path, mode="r", *args, **kwargs):
        if path.parent == java_tree and path.name in read_failures and mode == "rb":
            raise PermissionError("synthetic unpublishable I/O diagnostic")
        return original_open(path, mode, *args, **kwargs)

    def cleanup(path: str) -> None:
        if cleanup_failed and Path(path) == java_tree:
            raise PermissionError("synthetic unpublishable I/O diagnostic")
        rmtree(path)

    run = jadx._JadxRun(
        "ok", "synthetic", jadx.proctree.OwnedRun(
            returncode=0, stdout="", stderr="", timed_out=False, ownership_complete=True,
            termination_complete=True, forced_tree_kill=False, reason_codes=(),
        ),
    )
    with monkeypatch.context() as scope:
        # Replace only the decompiler process, temporary path and selected filesystem errors.
        scope.setattr(analyzer, "_run_jadx", lambda *_args, **_kwargs: run)
        scope.setattr(jadx.tempfile, "mkdtemp", lambda **_kwargs: str(java_tree))
        scope.setattr(jadx, "_MAX_JAVA_FILES", 2)
        scope.setattr(jadx, "_CLEANUP_ATTEMPTS", 1)
        scope.setattr(jadx, "_CLEANUP_BACKOFF", 0)
        scope.setattr(Path, "open", read_java)
        scope.setattr(jadx.shutil, "rmtree", cleanup)
        result = analyzer.analyze(FakeContext(apk_path=str(tmp_path / "unused.apk")))
    assert java_tree.exists() is cleanup_failed
    if cleanup_failed:
        rmtree(java_tree)
    assert result.error is None
    receipt = result.meta["jadx_receipt"]
    assert receipt["status"] == "ok" and receipt["complete"] is False
    expected_reasons = ["scan_limit_hit"]
    if read_failures:
        expected_reasons.append("read_failed")
    if cleanup_failed:
        expected_reasons.append("cleanup_incomplete")
    assert receipt["reason_codes"] == sorted(expected_reasons)
    assert receipt["cleanup"]["complete"] is (not cleanup_failed)
    scan = receipt["scan"]
    scanned = 2 - len(read_failures)
    assert (scan["files_scanned"], scan["files_selected"], scan["files_total"]) == (scanned, 2, 3)
    assert scan["read_failed"] == len(read_failures)
    assert scan["scan_limit_hit"] is True and scan["truncated_files"] == 0

    sample = "a" * 64
    saved = {
        "sources": {"java": {"visibility": "complete", "why": []}, "dex": "stub_only"},
        "claims": {"static_endpoint_exhaustive": {"eligible": True, "missing_sources": []}},
        "blocked_claims": ["unrelated_claim"],
    }
    source = tmp_path / "source.json"
    original = json.dumps({
        "package_name": "com.example.synthetic", "analysis_status": "complete", "completeness": 1.0,
        "meta": {"sample_sha256": sample, "visibility": saved, "jadx_receipt": receipt},
    }).encode()
    source.write_bytes(original)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "schema_version": "fxapk.offline-review.v1", "sample_sha256": sample,
        "tasks": [{"id": "synthetic-inert", "kind": "fixture_unsupported"}],
    }), encoding="utf-8")
    out = tmp_path / "review"
    cli = CliRunner()
    source_digest = cli.invoke(app, ["digest", str(source)])
    review = cli.invoke(app, ["evidence-review", str(plan), "--report", str(source), "--out", str(out)])
    replay = cli.invoke(app, ["digest", str(out / "report.json")])
    assert (source_digest.exit_code, review.exit_code, replay.exit_code) == (0, 5, 0), review.output
    assert json.loads(review.stdout)["state"] == "partial"
    assert json.loads((out / "review.json").read_text(encoding="utf-8"))["publication"] == "ok"
    assert not (out / "inputs").exists()
    assert source.read_bytes() == original

    published = json.loads((out / "report.json").read_text(encoding="utf-8"))["meta"]
    assert published["visibility"] == saved
    assert published["jadx_receipt"] == receipt
    digest = json.loads((out / "digest.json").read_text(encoding="utf-8"))["visibility"]
    assert digest == json.loads(source_digest.stdout)["visibility"] == json.loads(replay.stdout)["visibility"]
    assert digest["sources"] == {"java": "partial", "dex": "stub_only"}
    assert digest["java_scan"] == {"files_scanned": scanned, "files_total": 3}
    assert [item["claim"] for item in digest["blocked_claims"]] == [
        "unrelated_claim", "static_endpoint_exhaustive", "no_hardcoded_credential",
    ]
    assert any(note.startswith("[java] ") and "scan_limit_hit" in note for note in digest["notes"])

    html = (out / "report.html").read_text(encoding="utf-8")
    java = html.split("<td>java</td>", 1)[1].split("</tr>", 1)[0]
    assert "<td>partial</td>" in java and "scan_limit_hit" in java
    assert f"{scanned}/3" in html.split('id="jadx-java-scan"', 1)[1].split("</p>", 1)[0]
    assert "synthetic unpublishable I/O diagnostic" not in html + source_digest.stdout + replay.stdout
    for claim in ("unrelated_claim", "static_endpoint_exhaustive", "no_hardcoded_credential"):
        assert f"<li>{claim}</li>" in html


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
