"""Explicit PID/range observation -> immutable DEX -> reanalysis -> targeted receipts.

This entry point never installs/launches apps, starts servers, or changes network settings.
All device operations require the caller's explicit runtime plan and selected serial.
"""
from __future__ import annotations

import base64
import json
import re
import sys
import time
import uuid
from importlib.resources import files
from pathlib import Path

from apkscan.core import tools
from apkscan.core.fetch_intake import _process, file_hash
from apkscan.core.offline_review.common import integer, json_value, read_bytes, sha256
from apkscan.core.offline_review.runner import run as review_run, write_json
from apkscan.core.proctree import run_owned


def _adb(serial: str, command: str, limit: int = 1024**2) -> str:
    executable = tools.adb_path()
    if not executable:
        raise ValueError("adb_unavailable")
    run = run_owned([executable, "-s", serial, "shell", "su", "-c", command], timeout=15,
                    max_stdout_bytes=limit, max_stderr_bytes=65536)
    if run.returncode != 0 or run.timed_out or run.reason_codes or not run.ownership_complete or not run.termination_complete or run.forced_tree_kill:
        raise ValueError("adb_command_failed")
    return run.stdout


def _identity(serial: str, pid: int, process_name: str) -> dict:
    name = _adb(serial, f"cat /proc/{pid}/cmdline", 65536).split("\x00")[0].strip()
    if name != process_name:
        raise ValueError("runtime_process_name_mismatch")
    stat = _adb(serial, f"cat /proc/{pid}/stat", 65536)
    start = stat[stat.rfind(")") + 2:].split()[19]
    return {"pid": pid, "process_name": name, "start_ticks": start}


def _ranges(serial: str, pid: int, config: dict, folder: Path) -> list[dict]:
    raw_maps = _adb(serial, f"cat /proc/{pid}/maps")
    (folder / "maps.txt").write_text(raw_maps, encoding="utf-8")
    readable = []
    for line in raw_maps.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5 or not parts[1].startswith("r"):
            continue
        start, end = (int(v, 16) for v in parts[0].split("-"))
        readable.append({"start": start, "end": end, "name": parts[5] if len(parts) > 5 else ""})
    selections = config.get("ranges")
    if selections is None:
        match = config.get("map_name_contains")
        if not isinstance(match, str) or not 4 <= len(match) <= 256:
            raise ValueError("explicit_runtime_ranges_required")
        selections = [{"address": row["start"], "size": row["end"] - row["start"]}
                      for row in readable if match in row["name"]]
    if not isinstance(selections, list) or not 1 <= len(selections) <= 32:
        raise ValueError("runtime_ranges_missing_or_budget")
    ranges, total = [], 0
    for selection in selections:
        address = integer(selection.get("address"))
        size = integer(selection.get("size"), 112, 8 * 1024**2)
        if address % 4096 or size % 4096:
            raise ValueError("runtime_ranges_require_page_alignment")
        if not any(row["start"] <= address and address + size <= row["end"] for row in readable):
            raise ValueError("runtime_range_not_readable")
        total += size
        if total > 32 * 1024**2:
            raise ValueError("runtime_range_byte_budget")
        ranges.append({"address": hex(address), "size": size})
    return ranges


def capture(config: dict, folder: Path) -> dict:
    serial = config.get("serial")
    name = config.get("process_name")
    if not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", serial):
        raise ValueError("runtime_serial_required")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:$-]{1,200}", name):
        raise ValueError("runtime_process_name_required")
    pid = integer(config.get("pid"), 1, 2**31 - 1)
    seconds = integer(config.get("seconds", 5), 1, 60)
    if config.get("backend") not in {"proc_mem", "frida"}:
        raise ValueError("runtime_backend_unsupported")
    modules = config.get("modules", [])
    if config.get("backend") == "frida":
        if not isinstance(modules, list) or len(modules) > 16 or not all(isinstance(m, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", m) for m in modules):
            raise ValueError("runtime_module_selection_invalid")
        import frida  # type: ignore[import-not-found]  # optional dynamic extra; checked before device access
    before = _identity(serial, pid, name)
    ranges = _ranges(serial, pid, config, folder)
    run_id = uuid.uuid4().hex
    receipt = {"state": "running", "reason_codes": [], "run_id": run_id, "serial": serial,
               "identity": before, "ranges": ranges, "backend": config.get("backend"),
               "dex_files": [], "source_binding_verified": False, "started_unix_ns": time.time_ns()}
    write_json(folder / "capture.json", receipt)
    output = folder / "dex"
    output.mkdir()
    events = folder / "events.jsonl"
    seen: dict[str, str] = {}
    received_bytes = 0

    def save_dex(data: bytes, address: str) -> None:
        nonlocal received_bytes
        if len(data) > 8 * 1024**2 or received_bytes + len(data) > 32 * 1024**2 or len(receipt["dex_files"]) >= 32:
            receipt["reason_codes"].append("dex_capture_budget")
            return
        received_bytes += len(data)
        digest = sha256(data)
        path = output / (digest + ".dex")
        if digest not in seen:
            path.write_bytes(data)
        receipt["dex_files"].append({"path": str(path.resolve()), "sha256": digest, "size": len(data),
                                     "address": address, "duplicate_of": seen.get(digest)})
        seen[digest] = str(path.resolve())
        write_json(folder / "capture.json", receipt)

    if config.get("backend") == "proc_mem":
        # Root, ptrace-free reads of only preselected pages; no SIGSTOP or process changes.
        for region in ranges:
            address, size = int(region["address"], 16), region["size"]
            text = _adb(serial, f"dd if=/proc/{pid}/mem bs=4096 skip={address // 4096} count={size // 4096} 2>/dev/null | base64", 12 * 1024**2)
            raw = base64.b64decode("".join(text.split()), validate=True)
            if len(raw) != size:
                receipt["reason_codes"].append("proc_memory_short_read")
                continue
            for match in re.finditer(rb"dex\n0[0-9]{2}\x00", raw):
                start = match.start()
                if start + 36 > len(raw):
                    continue
                length = int.from_bytes(raw[start + 32:start + 36], "little")
                if length < 112 or start + length > len(raw):
                    receipt["reason_codes"].append("dex_outside_selected_range")
                else:
                    save_dex(raw[start:start + length], hex(address + start))
        events.write_text(json.dumps({"type": "end", "run_id": run_id, "seq": 1, "backend": "proc_mem"}) + "\n", encoding="utf-8")
        if config.get("jni"):
            receipt["reason_codes"].append("proc_mem_does_not_observe_jni")
    elif config.get("backend") == "frida":
        settings = {"run_id": run_id, "ranges": ranges, "jni": config.get("jni") is True,
                    "modules": modules, "event_limit": 10000, "max_dex_size": 8 * 1024**2,
                    "byte_limit": 32 * 1024**2}
        source = "const CONFIG = " + json.dumps(settings) + ";\n" + files("apkscan.dynamic").joinpath("frida_js/recovery_observer.js").read_text(encoding="utf-8")
        session = script = None
        count = 0
        with events.open("w", encoding="utf-8") as stream:
            def message(value, binary):
                nonlocal count
                if count >= 10001:
                    receipt["reason_codes"].append("host_event_budget")
                    return
                count += 1
                try:
                    payload = value.get("payload") if value.get("type") == "send" else None
                    if not isinstance(payload, dict):
                        receipt["reason_codes"].append("frida_script_error")
                        return
                    encoded = json.dumps(payload, ensure_ascii=False)
                    if len(encoded.encode("utf-8")) > 65536:
                        receipt["reason_codes"].append("host_event_size_budget")
                        return
                    stream.write(encoded + "\n")
                    stream.flush()
                    if payload.get("type") == "error":
                        receipt["reason_codes"].append(str(payload.get("reason_code", "observer_error")))
                    if payload.get("type") == "dex" and binary is not None:
                        save_dex(bytes(binary), str(payload.get("address")))
                except Exception:
                    receipt["reason_codes"].append("observer_message_failed")
            try:
                device = frida.get_device(serial, timeout=5)
                session = device.attach(pid)
                script = session.create_script(source)
                script.on("message", message)
                script.load()
                time.sleep(seconds)
                end = script.exports_sync.finish()
                if end.get("truncated"):
                    receipt["reason_codes"].append("observer_event_budget")
            finally:
                if script is not None:
                    try:
                        script.unload()
                    except Exception:
                        receipt["reason_codes"].append("observer_unload_failed")
                if session is not None:
                    try:
                        session.detach()
                    except Exception:
                        receipt["reason_codes"].append("observer_detach_failed")
    else:
        raise ValueError("runtime_backend_unsupported")
    # Preserve collected bytes and errors even if the process exits before the final identity check.
    write_json(folder / "capture.json", receipt)
    after = _identity(serial, pid, name)
    if after != before:
        receipt["reason_codes"].append("runtime_identity_changed")
    if not seen:
        receipt["reason_codes"].append("no_dex_in_selected_ranges")
    receipt.update(state="partial" if receipt["reason_codes"] else "ok", finished_unix_ns=time.time_ns(),
                   reason_codes=sorted(set(receipt["reason_codes"])), events_sha256=sha256(events.read_bytes()))
    write_json(folder / "capture.json", receipt)
    return receipt


def _run(plan_path: Path, output: Path, progress=None, *, retain_review_inputs: bool = False) -> dict:
    raw = read_bytes(plan_path, 1024**2)
    plan = json_value(raw)
    if not isinstance(plan, dict) or plan.get("schema_version") != "fxapk.runtime-recovery.v1":
        raise ValueError("runtime_plan_schema_invalid")
    apk = Path(plan["apk"])
    if not apk.is_absolute():
        apk = plan_path.parent / apk
    sample = file_hash(apk, 1024**3)
    if sample != plan.get("sample_sha256"):
        raise ValueError("runtime_sample_hash_mismatch")
    if output.exists():
        raise ValueError("runtime_output_exists")
    output.mkdir(parents=True)
    (output / "plan.json").write_bytes(raw)
    capture_dir = output / "capture"
    capture_dir.mkdir()
    config_path = capture_dir / "config.json"
    write_json(config_path, plan["capture"])
    receipt = {"schema_version": "fxapk.runtime-recovery-result.v1", "sample_sha256": sample,
               "state": "running", "source_binding_verified": False, "stages": []}
    write_json(output / "recovery.json", receipt)

    def stage(identifier, state, reasons=None, **extra):
        row = {"id": identifier, "state": state, "reason_codes": reasons or [], **extra}
        receipt["stages"].append(row)
        write_json(output / "recovery.json", receipt)
        if progress:
            progress(row)

    if progress:
        progress({"id": "capture", "state": "running"})
    execution = _process([sys.executable, "-m", "apkscan.dynamic.recovery", str(config_path.resolve()), str(capture_dir.resolve())],
                         output / "capture-process", time.monotonic() + 180, allow_device=True)
    capture_path = capture_dir / "capture.json"
    captured = json_value(read_bytes(capture_path)) if capture_path.exists() else {"state": "failed", "reason_codes": ["capture_receipt_missing"], "dex_files": []}
    if execution["state"] != "ok":
        captured.update(state=execution["state"], reason_codes=sorted(set(captured.get("reason_codes", []) + execution["reason_codes"])))
        write_json(capture_path, captured)
    stage("capture", captured["state"], captured.get("reason_codes", []))
    tasks = []
    seen = set()
    if captured["state"] in {"ok", "partial"}:
        for row in captured.get("dex_files", []):
            if row["sha256"] in seen:
                continue
            seen.add(row["sha256"])
            tasks.append({"id": "dex_" + str(len(seen)), "kind": "dex", "input": row["path"],
                          "sha256": row["sha256"], "targets": plan.get("targets", []), "jadx": True})
        if plan["capture"].get("jni"):
            tasks.append({"id": "jni_observation", "kind": "jni", "input": str((capture_dir / "events.jsonl").resolve()),
                          "sha256": captured["events_sha256"], "run_id": captured["run_id"]})
    report_path = None
    if seen:
        report_dir = output / "reanalyzed"
        execution = _process([sys.executable, "-m", "apkscan.cli", "analyze", str(apk.resolve()), "--offline", "--extra-dex",
                              str((capture_dir / "dex").resolve()), "--fmt", "json,html", "--out", str(report_dir.resolve())],
                             output / "reanalyze-process", time.monotonic() + 300)
        candidates = list(report_dir.glob("*.json")) if report_dir.exists() else []
        for candidate in candidates:
            value = json_value(read_bytes(candidate))
            if isinstance(value, dict) and value.get("meta", {}).get("sample_sha256") == sample:
                report_path = candidate
                extra_dex = value.get("meta", {}).get("extra_dex_visibility")
                expected_count = len(seen)
                counts = {key: extra_dex.get(key) for key in ("requested", "loaded", "failed")} if isinstance(extra_dex, dict) else {}
                execution["extra_dex_visibility"] = counts
                if (any(type(counts.get(key)) is not int for key in ("requested", "loaded", "failed"))
                        or counts.get("requested") != expected_count or counts.get("loaded") != expected_count
                        or counts.get("failed") != 0):
                    if execution["state"] == "ok":
                        execution["state"] = "partial"
                    execution["reason_codes"] = sorted(set([*execution["reason_codes"], "reanalyzed_extra_dex_not_loaded"]))
                analysis_status = value.get("analysis_status")
                if analysis_status != "complete":
                    state = "partial" if analysis_status == "partial" else "failed"
                    if execution["state"] == "ok" or state == "failed":
                        execution["state"] = state
                    reason = ("reanalyzed_report_" + analysis_status
                              if analysis_status in {"partial", "failed"} else "reanalyzed_report_status_invalid")
                    execution["reason_codes"] = sorted(set([*execution["reason_codes"], reason]))
                break
        if report_path is None:
            execution.update(state="failed", reason_codes=sorted(set([
                *execution["reason_codes"], "reanalyzed_report_missing"])))
        stage("reanalyze", execution["state"], execution["reason_codes"],
              extra_dex_visibility=execution.get("extra_dex_visibility", {}))
    else:
        stage("reanalyze", "not_run", ["no_verified_capture_dex"])
    for task in plan.get("tasks", []):
        task = dict(task)
        source = Path(task["input"])
        task["input"] = str((source if source.is_absolute() else plan_path.parent / source).resolve())
        tasks.append(task)
    # A failed capture remains a report task even if independent offline tasks succeed.
    acquisition_path = output / "acquisition.json"
    write_json(acquisition_path, receipt)
    tasks.insert(0, {"id": "runtime_acquisition", "kind": "acquisition", "input": str(acquisition_path.resolve()),
                     "sha256": sha256(acquisition_path.read_bytes())})
    independent_result = False
    if tasks:
        manifest = output / "review-plan.json"
        write_json(manifest, {"schema_version": "fxapk.offline-review.v1", "sample_sha256": sample, "tasks": tasks})
        try:
            reviewed = review_run(manifest, output / "reviewed", report_path, progress,
                                  retain_inputs=retain_review_inputs)
            independent_result = any(row["id"] != "runtime_acquisition" and row["state"] in {"ok", "partial"}
                                     for row in reviewed["tasks"])
            stage("review", reviewed["state"], sorted({reason for row in reviewed["tasks"] for reason in row["reason_codes"]}))
        except Exception as error:
            stage("review", "failed", ["runtime_review_failed"], exception_type=type(error).__name__)
    else:
        stage("review", "not_run", ["no_review_inputs"])
    receipt["state"] = "ok" if all(s["state"] == "ok" for s in receipt["stages"]) else "partial"
    if not independent_result and not any(s["id"] != "review" and s["state"] in {"ok", "partial"} for s in receipt["stages"]):
        receipt["state"] = "failed"
    write_json(output / "recovery.json", receipt)
    return receipt


def run(plan_path: Path, output: Path, progress=None, *, retain_review_inputs: bool = False) -> dict:
    existed = output.exists()
    try:
        return _run(plan_path, output, progress, retain_review_inputs=retain_review_inputs)
    except Exception as error:
        if not existed and (output / "recovery.json").exists():
            receipt = json_value(read_bytes(output / "recovery.json"))
            code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else "runtime_chain_failed"
            receipt.update(state="failed")
            receipt["stages"].append({"id": "pipeline", "state": "failed", "reason_codes": [code],
                                       "exception_type": type(error).__name__})
            write_json(output / "recovery.json", receipt)
            return receipt
        raise


if __name__ == "__main__":
    config_file, capture_folder = map(Path, sys.argv[1:3])
    try:
        capture(json_value(read_bytes(config_file)), capture_folder)
    except Exception as error:
        path = capture_folder / "capture.json"
        failed: dict = json_value(read_bytes(path)) if path.exists() else {"dex_files": []}
        code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else "runtime_capture_failed"
        if isinstance(error, ImportError):
            code = "optional_dependency_unavailable"
        failed.update(state="unsupported" if isinstance(error, ImportError) else "failed",
                      reason_codes=sorted(set(failed.get("reason_codes", []) + [code])), exception_type=type(error).__name__)
        write_json(path, failed)
        sys.exit(6)
