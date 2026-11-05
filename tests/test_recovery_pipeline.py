from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

from apkscan.core.offline_review import acquisition, dex, jni, recover, runner
from apkscan.dynamic import recovery


def plan_task(identifier, kind, path, **options):
    return {"id": identifier, "kind": kind, "input": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), **options}


def elf(code):
    data = bytearray(0x100) + code
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 183, 1, 0x4000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0x100, 0x4000, 0x4000, len(code), len(code), 0x1000)
    return bytes(data)


def emu_options(**extra):
    return {"format": "raw_aarch64", "entry": 0,
            "vectors": [{"args": [3, 4], "expected_return": 7},
                        {"args": [9, 5], "expected_return": 14}], **extra}


def execute(code, options, tmp_path):
    import uuid
    return runner.isolated_review(code, {**options, "kind": "emulate", "id": uuid.uuid4().hex}, tmp_path)


@pytest.mark.skipif(sys.platform == "darwin", reason="bounded workers require enforceable memory limits")
def test_real_unicorn_calls_and_negative_vectors(tmp_path):
    pytest.importorskip("unicorn")
    code = bytes.fromhex("0000018bc0035fd6")  # add x0,x0,x1; ret
    good = execute(code, emu_options(), tmp_path)
    assert good["state"] == "ok" and all(row["returned"] for row in good["vectors"])
    bad = execute(code, emu_options(vectors=[{"args": [1, 2], "expected_return": 4}]), tmp_path)
    assert bad["state"] == "failed" and "emulation_output_mismatch" in bad["reason_codes"]
    assert good["independent_algorithm"] is False


@pytest.mark.parametrize("hex_code,reason", [
    ("00000014", "emulation_budget_exhausted"),  # b self
    ("010000d4", "system_instruction_unsupported"),  # svc 0
    ("000040f9c0035fd6", "emulation_fault"),  # ldr x0,[x0];ret -> unmapped
])
@pytest.mark.skipif(sys.platform == "darwin", reason="bounded workers require enforceable memory limits")
def test_execution_budgets_and_missing_environment_fail_explicitly(hex_code, reason, tmp_path):
    pytest.importorskip("unicorn")
    value = execute(bytes.fromhex(hex_code), emu_options(instruction_limit=16), tmp_path)
    assert value["state"] == "failed" and reason in value["reason_codes"]


@pytest.mark.skipif(sys.platform == "darwin", reason="bounded workers require enforceable memory limits")
def test_emulation_obeys_buffer_comparison_and_elf_mapping(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("elftools")
    code = bytes.fromhex("01000039c0035fd6")  # strb w1,[x0];ret
    vectors = [{"args": [{"hex": "00", "expected_hex": "07"}, 7]},
               {"args": [{"hex": "00", "expected_hex": "09"}, 9]}]
    checked = execute(elf(code), {"format": "elf", "entry": 0x4000, "vectors": vectors}, tmp_path)
    assert checked["state"] == "ok" and checked["vectors"][0]["outputs"][0]["matches"]
    assert "actual_return" not in checked["vectors"][0]


def test_jni_zero_hits_loss_and_truncation_are_visible():
    rows = [{"type": "hook_installed", "hook": "RegisterNatives"}, {"type": "end"}]
    def encoded(values):
        return b"\n".join(json.dumps({**v, "seq": i, "run_id": "test"}).encode() for i, v in enumerate(values, 1))
    assert jni.review(encoded(rows), {"run_id": "test"})["reason_codes"] == ["jni_no_hits_in_window"]
    rows.insert(1, {"type": "jni_registration", "name": "f", "signature": "()I", "address": "0x1000", "module": "libtest.so"})
    assert jni.review(encoded(rows), {"run_id": "test"})["state"] == "ok"
    rows[-1]["truncated"] = True
    assert "jni_event_budget" in jni.review(encoded(rows), {"run_id": "test"})["reason_codes"]
    assert "jni_capture_incomplete" in jni.review(encoded(rows[:-1]), {"run_id": "test"})["reason_codes"]


def test_field_recovery_does_not_invent_full_size_or_original_names():
    pytest.importorskip("capstone")
    pytest.importorskip("elftools")
    # ldr w1,[x0,#8]; str w1,[x0,#12]; ret
    value = recover.review(elf(bytes.fromhex("010840b9010c00b9c0035fd6")),
                           {"functions": [{"address": 0x4000, "size": 12}]})
    assert [(r["offset"], r["width"]) for r in value["fields"]] == [(8, 4), (12, 4)]
    assert value["minimum_observed_extent"] == 16 and value["structure_size"] == "unknown"
    assert value["state"] == "partial" and value["original_names_recovered"] is False


def test_dex_header_corruption_never_repaired():
    data = bytearray(112)
    data[:8] = b"dex\n035\0"
    value = dex.review(bytes(data), {"targets": ["LTest;->f()I"]})
    assert value["state"] == "failed" and value["repair_performed"] is False


def test_recovered_dex_exact_descriptor_and_missing_body_are_separate():
    import base64
    data = base64.b64decode((Path(__file__).parent / "fixtures/recovery/synthetic.dex.b64").read_bytes())
    value = dex.review(data, {"targets": ["LRecoveryFixture;->add(II)I", "LRecoveryFixture;->add(I)I"]})
    assert [row["state"] for row in value["targets"]] == ["decoded", "missing"]
    assert value["targets"][0]["instructions"] == 2
    assert "dex_target_missing" in value["reason_codes"]
    assert "jadx_not_requested" in value["reason_codes"]
    assert value["all_dex_recovered"] == "unknown"


@pytest.mark.skipif(sys.platform == "darwin", reason="bounded workers require enforceable memory limits")
def test_same_vectors_do_not_count_as_distinct_validation(tmp_path):
    pytest.importorskip("unicorn")
    value = execute(bytes.fromhex("0000018bc0035fd6"), emu_options(vectors=[
        {"args": [3, 4], "expected_return": 7}, {"args": [3, 4], "expected_return": 7}]), tmp_path)
    assert value["state"] == "partial" and "distinct_validation_inputs_required" in value["reason_codes"]


def test_native_worker_crash_becomes_terminal_receipt(monkeypatch, tmp_path):
    from apkscan.core import proctree
    monkeypatch.setattr(proctree, "run_owned", lambda *a, **k: proctree.OwnedRun(
        returncode=7, stdout="", stderr="", timed_out=False, ownership_complete=True,
        termination_complete=True, forced_tree_kill=False, reason_codes=()))
    value = runner.isolated_review(b"bad", {"id": "crash", "kind": "emulate"}, tmp_path)
    assert value["state"] == "failed" and "review_worker_exit" in value["reason_codes"]


def test_dependencies_fail_closed_but_independent_tasks_publish(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_text('{"type":"end","run_id":"test","seq":1}\n')
    plan = {"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64, "tasks": [
        plan_task("first", "jni", source, run_id="test"),
        plan_task("dependent", "jni", source, run_id="test", depends_on=["first"]),
        plan_task("independent", "jni", source, run_id="test")]}
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    value = runner.run(path, tmp_path / "out")
    assert [r["state"] for r in value["tasks"]] == ["partial", "not_run", "partial"]
    assert (tmp_path / "out/feedback.json").exists()
    for name in ("report.json", "digest.json", "report.html"):
        assert "dependency_not_verified" in (tmp_path / "out" / name).read_text(encoding="utf-8")


def test_failed_review_with_unrun_dependency_has_no_partial_success(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_text('{"type":"end","run_id":"test","seq":1}\n')
    first = plan_task("first", "jni", source, run_id="test")
    first["sha256"] = "0" * 64
    plan = {"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64,
            "tasks": [first, plan_task("dependent", "jni", source, depends_on=["first"])]}
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    receipt = runner.run(path, tmp_path / "out")
    assert [row["state"] for row in receipt["tasks"]] == ["failed", "not_run"]
    assert receipt["state"] == "failed"
    report = json.loads((tmp_path / "out/report.json").read_text(encoding="utf-8"))
    assert report["analysis_status"] == "failed" and report["completeness"] == 0.0


def test_capture_failure_cannot_be_hidden_by_other_stages():
    raw = json.dumps({"schema_version": "fxapk.runtime-recovery-result.v1", "source_binding_verified": False,
                      "stages": [{"id": "capture", "state": "failed", "reason_codes": ["adb_command_failed"]}]}).encode()
    result = acquisition.review(raw, {})
    assert result["state"] == "failed" and "adb_command_failed" in result["reason_codes"]


def test_proc_memory_collector_preserves_original_bytes_and_identity(monkeypatch, tmp_path):
    import base64
    data = bytearray(4096)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<I", data, 32, 112)
    def adb(serial, command, limit=0):
        if command.endswith("cmdline"):
            return "test.synthetic\x00"
        if command.endswith("stat"):
            return "1 (test.synthetic) " + " ".join(["1"] * 20)
        if command.endswith("maps"):
            return "1000-2000 r--p 00000000 00:00 0 /synthetic.dex"
        return base64.b64encode(data).decode()
    monkeypatch.setattr(recovery, "_adb", adb)
    value = recovery.capture({"serial": "device", "process_name": "test.synthetic", "pid": 1,
                              "backend": "proc_mem", "map_name_contains": "synthetic.dex"}, tmp_path)
    assert value["state"] == "ok" and len(value["dex_files"]) == 1
    assert Path(value["dex_files"][0]["path"]).read_bytes() == data[:112]
    assert value["source_binding_verified"] is False

    # An exit after bytes were read must retain the recovered-byte inventory.
    identity = recovery._identity
    calls = 0
    def exits_after_capture(*args):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise ValueError("adb_command_failed")
        return identity(*args)
    monkeypatch.setattr(recovery, "_identity", exits_after_capture)
    second = tmp_path / "exited"
    second.mkdir()
    with pytest.raises(ValueError, match="adb_command_failed"):
        recovery.capture({"serial": "device", "process_name": "test.synthetic", "pid": 1,
                          "backend": "proc_mem", "map_name_contains": "synthetic.dex"}, second)
    retained = json.loads((second / "capture.json").read_text(encoding="utf-8"))
    assert retained["dex_files"][0]["sha256"] == value["dex_files"][0]["sha256"]


def test_recovery_failure_receipt_publishes_report(monkeypatch, tmp_path):
    apk = tmp_path / "synthetic.apk"
    apk.write_bytes(b"synthetic-original")
    plan = {"schema_version": "fxapk.runtime-recovery.v1", "apk": str(apk),
            "sample_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(), "capture": {"backend": "frida"}}
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan))
    monkeypatch.setattr(recovery, "_process", lambda *a, **k: {"state": "failed", "reason_codes": ["capture_timeout"]})
    value = recovery.run(plan_path, tmp_path / "result")
    assert value["state"] == "failed"
    assert "capture_timeout" in (tmp_path / "result/reviewed/report.html").read_text(encoding="utf-8")
    assert all(s["state"] != "running" for s in value["stages"])


@pytest.mark.parametrize("analysis_status", ["partial", "failed", "complete"])
@pytest.mark.parametrize("process_failed", [False, True])
@pytest.mark.parametrize("extra_loaded", [True, False])
def test_reanalysis_status_reaches_recovery_and_report(monkeypatch, tmp_path, analysis_status, process_failed, extra_loaded):
    from apkscan.core.models import Report
    from apkscan.report.json import to_dict

    apk = tmp_path / "synthetic.apk"
    apk.write_bytes(b"synthetic-original")
    sample = hashlib.sha256(apk.read_bytes()).hexdigest()
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({
        "schema_version": "fxapk.runtime-recovery.v1", "apk": str(apk),
        "sample_sha256": sample, "capture": {"backend": "proc_mem"},
    }))
    output = tmp_path / "result"

    def process(command, prefix, deadline, **kwargs):
        if prefix.name == "capture-process":
            dex_path = output / "capture/dex/synthetic.dex"
            dex_path.parent.mkdir()
            dex_path.write_bytes(b"synthetic-dex")
            recovery.write_json(output / "capture/capture.json", {
                "state": "ok", "reason_codes": [],
                "dex_files": [{"path": str(dex_path), "sha256": hashlib.sha256(dex_path.read_bytes()).hexdigest()}],
            })
            return {"state": "ok", "reason_codes": []}
        report_dir = output / "reanalyzed"
        report_dir.mkdir()
        report = Report(package_name="test.synthetic", meta={"sample_sha256": sample, "online": False,
                        "extra_dex_visibility": {"requested": 1, "loaded": int(extra_loaded), "failed": int(not extra_loaded)}},
                        leads=[], endpoints=[], findings=[], analyzer_status=[], analysis_status=analysis_status)
        recovery.write_json(report_dir / "synthetic.json", to_dict(report))
        return {"state": "failed" if process_failed else "ok",
                "reason_codes": ["subprocess_timeout"] if process_failed else []}

    monkeypatch.setattr(recovery, "_process", process)
    monkeypatch.setattr(runner, "isolated_review", lambda *a: {"state": "ok", "reason_codes": []})
    value = recovery.run(plan_path, output)
    reanalyzed = next(row for row in value["stages"] if row["id"] == "reanalyze")
    expected = "failed" if process_failed or analysis_status == "failed" else analysis_status
    if expected == "complete" and not extra_loaded:
        expected = "partial"
    assert reanalyzed["state"] == ("ok" if expected == "complete" else expected)
    if process_failed:
        assert "subprocess_timeout" in reanalyzed["reason_codes"]
    if not extra_loaded:
        assert "reanalyzed_extra_dex_not_loaded" in reanalyzed["reason_codes"]
        for name in ("report.json", "digest.json", "report.html"):
            assert "reanalyzed_extra_dex_not_loaded" in (output / "reviewed" / name).read_text(encoding="utf-8")
    if analysis_status != "complete":
        reason = "reanalyzed_report_" + analysis_status
        assert reason in reanalyzed["reason_codes"]
        for name in ("report.json", "digest.json", "report.html"):
            assert reason in (output / "reviewed" / name).read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "darwin", reason="bounded workers require enforceable memory limits")
def test_public_cli_runs_real_review_workers_and_publishes_states(tmp_path):
    import base64
    import subprocess
    import sys

    pytest.importorskip("unicorn")
    code = tmp_path / "add.bin"
    code.write_bytes(bytes.fromhex("0000018bc0035fd6"))
    recovered = tmp_path / "synthetic.dex"
    recovered.write_bytes(base64.b64decode((Path(__file__).parent / "fixtures/recovery/synthetic.dex.b64").read_bytes()))
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64,
        "tasks": [plan_task("function", "emulate", code, **emu_options()),
                  plan_task("dex", "dex", recovered, targets=["LRecoveryFixture;->add(II)I"]),
                  plan_task("dependent", "emulate", code, depends_on=["dex"], **emu_options())],
    }), encoding="utf-8")
    output = tmp_path / "review"
    run = subprocess.run([sys.executable, "-m", "apkscan.cli", "evidence-review", str(plan),
                          "--out", str(output)], capture_output=True, timeout=90)
    assert run.returncode == 5, run.stderr.decode("utf-8", errors="replace")
    receipt = json.loads((output / "review.json").read_text(encoding="utf-8"))
    assert [row["state"] for row in receipt["tasks"]] == ["ok", "partial", "not_run"]
    function = json.loads((output / "function.json").read_text(encoding="utf-8"))
    assert function["process_isolation"]["termination_complete"] is True
    dex_result = json.loads((output / "dex.json").read_text(encoding="utf-8"))
    assert dex_result["targets"][0]["state"] == "decoded"
    for name in ("report.json", "digest.json", "report.html", "feedback.json"):
        text = (output / name).read_text(encoding="utf-8")
        assert "jadx_not_requested" in text and "dependency_not_verified" in text


def test_public_recovery_cli_retains_unavailable_device_stage(tmp_path):
    import os
    import subprocess
    import sys

    apk = tmp_path / "synthetic.apk"
    apk.write_bytes(b"synthetic-original")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "schema_version": "fxapk.runtime-recovery.v1", "apk": str(apk),
        "sample_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "capture": {"serial": "synthetic-device", "pid": 1, "process_name": "test.synthetic",
                    "backend": "proc_mem", "ranges": [{"address": 4096, "size": 4096}]},
    }), encoding="utf-8")
    toolchain = tmp_path / "tools.json"
    toolchain.write_text(json.dumps({"schema": 1, "tools": {"adb": str(tmp_path / "missing-adb")}}), encoding="utf-8")
    output = tmp_path / "recovery"
    run = subprocess.run([sys.executable, "-m", "apkscan.cli", "recover-runtime", str(plan),
                          "--out", str(output)], env={**os.environ, "FXAPK_TOOLCHAIN_FILE": str(toolchain)},
                         capture_output=True, timeout=90)
    assert run.returncode == 6, run.stderr.decode("utf-8", errors="replace")
    receipt = json.loads((output / "recovery.json").read_text(encoding="utf-8"))
    expected = "platform_memory_limit_unavailable" if sys.platform == "darwin" else "adb_unavailable"
    assert receipt["stages"][0]["state"] == ("unsupported" if sys.platform == "darwin" else "failed")
    assert expected in receipt["stages"][0]["reason_codes"]
    for name in ("report.json", "digest.json", "report.html", "feedback.json"):
        assert expected in (output / "reviewed" / name).read_text(encoding="utf-8")


def test_memory_limit_unavailable_is_explicit_unsupported(monkeypatch, tmp_path):
    from apkscan.core import proctree
    from apkscan.core.fetch_intake import _process
    import time

    monkeypatch.setattr(proctree, "run_owned", lambda *a, **k: proctree.OwnedRun(
        None, "", "", False, False, True, False, ("memory_limit_unavailable",)))
    value = runner.isolated_review(b"test", {"id": "platform", "kind": "emulate"}, tmp_path)
    assert value["state"] == "unsupported"
    assert value["reason_codes"] == ["platform_memory_limit_unavailable"]
    monkeypatch.setattr("apkscan.core.fetch_intake.run_owned", proctree.run_owned)
    process = _process(["synthetic"], tmp_path / "process", time.monotonic() + 5)
    assert process["state"] == "unsupported"


def test_standalone_failed_review_has_failed_report_health(tmp_path):
    source = tmp_path / "data.bin"
    source.write_bytes(b"synthetic")
    plan = tmp_path / "plan.json"
    task = plan_task("bad", "jni", source)
    task["sha256"] = "f" * 64
    plan.write_text(json.dumps({"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64,
                               "tasks": [task]}), encoding="utf-8")
    output = tmp_path / "review"
    assert runner.run(plan, output)["state"] == "failed"
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["analysis_status"] == "failed" and report["completeness"] == 0.0
    assert report["analyzer_status"][0]["status"] == "error"


def test_intake_deadline_stops_tasks_and_bounds_worker(monkeypatch, tmp_path):
    import time
    from apkscan.core import proctree

    source = tmp_path / "data.bin"
    source.write_bytes(b"synthetic")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"schema_version": "fxapk.offline-review.v1", "sample_sha256": "a" * 64,
                               "tasks": [plan_task("later", "jni", source)]}), encoding="utf-8")
    receipt = runner.run(plan, tmp_path / "expired", deadline=time.monotonic() - 1)
    assert receipt["tasks"][0]["state"] == "not_run"
    assert receipt["tasks"][0]["reason_codes"] == ["intake_time_budget"]
    observed = []
    def timed_out(*args, **kwargs):
        observed.append(kwargs["timeout"])
        return proctree.OwnedRun(None, "", "", True, True, True, False, ("timeout",))
    monkeypatch.setattr(proctree, "run_owned", timed_out)
    receipt = runner.run(plan, tmp_path / "bounded", deadline=time.monotonic() + 1)
    assert len(observed) == 1 and 0 < observed[0] <= 1
    assert "intake_time_budget" in receipt["tasks"][0]["reason_codes"]
