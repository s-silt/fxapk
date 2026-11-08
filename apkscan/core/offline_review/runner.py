"""Manifest -> per-task receipts -> report revision, with explicit terminal states."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Callable

from apkscan.core.atomic import atomic_write_text
from apkscan.core.evidence_archive import materialize, resolve_reference, split_reference
from apkscan.core.json_io import REPORT_JSON_MAX_BYTES
from apkscan.core.models import Report
from apkscan.core.report_io import load_report
from apkscan.report import html, json as report_json

from . import acquisition, crypto, dex, emulate, filesystem, jni, native, recover, trace
from .common import json_value, read_bytes, result, sha256

META_WRITE_OWNER = "core.offline_review.runner"
META_WRITE_CATEGORIES = {"offline_evidence_review": "coverage", "sample_sha256": "record"}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)
REVIEWERS = {"native": native.review, "trace": trace.review, "filesystem": filesystem.review,
             "crypto": crypto.review, "dex": dex.review, "jni": jni.review,
             "emulate": emulate.review, "recover": recover.review, "acquisition": acquisition.review}


def isolated_review(data: bytes, task: dict, output: Path, *, deadline: float | None = None) -> dict:
    from apkscan.core.proctree import run_owned

    timeout = 150.0 if task["kind"] == "dex" else 100.0
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
        if timeout <= 0:
            return result("not_run", ["intake_time_budget"])
    artifacts = output / (task["id"] + "-artifacts")
    artifacts.mkdir()
    source, config, destination = (artifacts / name for name in ("input.bin", "task.json", "result.json"))
    source.write_bytes(data)
    # Runtime paths are supplied by this runner, never accepted from the manifest.
    write_json(config, {**task, "_artifact_dir": str(artifacts.resolve())})
    execution = run_owned([sys.executable, "-m", "apkscan.core.offline_review.worker",
                           str(source.resolve()), str(config.resolve()), str(destination.resolve())],
                          timeout=timeout,
                          memory_bytes=3 * 1024**3, max_stdout_bytes=1024**2, max_stderr_bytes=1024**2)
    (artifacts / "worker.stdout.log").write_text(execution.stdout, encoding="utf-8")
    (artifacts / "worker.stderr.log").write_text(execution.stderr, encoding="utf-8")
    reasons = list(execution.reason_codes)
    if "memory_limit_unavailable" in reasons:
        return result("unsupported", ["platform_memory_limit_unavailable"])
    if execution.timed_out:
        reasons.append("review_worker_timeout")
        if deadline is not None:
            reasons.append("intake_time_budget")
    if execution.returncode != 0:
        reasons.append("review_worker_exit")
    if not execution.ownership_complete or not execution.termination_complete or execution.forced_tree_kill:
        reasons.append("review_worker_process_tree_incomplete")
    if reasons or not destination.is_file():
        return result("failed", reasons or ["review_worker_receipt_missing"])
    detail = json_value(read_bytes(destination))
    if not isinstance(detail, dict) or detail.get("state") not in {"ok", "partial", "failed", "unsupported"}:
        return result("failed", ["review_worker_receipt_invalid"])
    detail["process_isolation"] = {"ownership_complete": True, "termination_complete": True,
                                   "memory_limit_enforced": execution.memory_limit_enforced}
    return detail


def feedback(receipt: dict) -> dict:
    items = []
    for row in receipt["tasks"]:
        for reason in row["reason_codes"]:
            category = ("dependency" if "unavailable" in reason else "budget" if any(s in reason for s in ("budget", "timeout"))
                        else "coverage" if any(s in reason for s in ("missing", "no_hits", "partial", "not_", "candidate", "unknown"))
                        else "verification")
            items.append({"task_id": row["id"], "kind": row["kind"], "category": category,
                          "reason_code": reason, "receipt_sha256": row.get("receipt_sha256"),
                          "reproduction": {"manifest_sha256": receipt["manifest_sha256"], "input_sha256": row.get("input_sha256")},
                          "method_update": "review_required_no_automatic_rule_change"})
    return {"schema_version": "fxapk.review-feedback.v1", "items": items}


def projection(value: object) -> dict | None:
    """Metadata only: never expose decoded buffers, file paths, keys or plaintext."""
    if not isinstance(value, dict) or not isinstance(value.get("tasks"), list):
        return None
    return {"state": value.get("state"), "coverage": "supplied_inputs_only",
            "source_binding_verified": False,
            "tasks": [{key: row.get(key) for key in ("id", "kind", "state", "reason_codes", "input_sha256", "receipt_sha256", "storage_integrity", "input_storage")
                       if key not in {"storage_integrity", "input_storage"} or row.get(key) is not None}
                      for row in value["tasks"] if isinstance(row, dict)],
            "not_requested": value.get("not_requested", [])}


def write_json(path: Path, value: object) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2))


def run(manifest: Path, output: Path, report_path: Path | None = None,
        progress: Callable[[dict], None] | None = None, *, deadline: float | None = None,
        retain_inputs: bool = False) -> dict:
    raw = read_bytes(manifest, 1024 * 1024)
    plan = json_value(raw)
    if not isinstance(plan, dict) or plan.get("schema_version") != "fxapk.offline-review.v1":
        raise ValueError("review_manifest_schema_invalid")
    tasks = plan.get("tasks")
    if not isinstance(tasks, list) or not 1 <= len(tasks) <= 32:
        raise ValueError("review_task_budget_or_shape")
    sample = plan.get("sample_sha256")
    if not isinstance(sample, str) or not re.fullmatch("[0-9a-f]{64}", sample):
        raise ValueError("sample_sha256_required")
    identifiers = set()
    for task in tasks:
        if not isinstance(task, dict) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(task.get("id", ""))):
            raise ValueError("task_identifier_invalid")
        identifier = task["id"].casefold()
        if identifier in {"manifest", "review", "report", "digest", "feedback", "replay-plan", "source-report", "con", "prn", "aux", "nul"} or re.fullmatch(r"(?:com|lpt)[0-9]", identifier):
            raise ValueError("reserved_task_identifier")
        if identifier in identifiers:
            raise ValueError("duplicate_task_identifier")
        dependencies = task.get("depends_on", [])
        if not isinstance(dependencies, list) or not all(isinstance(d, str) and d.casefold() in identifiers for d in dependencies):
            raise ValueError("dependencies_must_reference_prior_tasks")
        identifiers.add(identifier)
        if not isinstance(task.get("kind"), str) or len(task["kind"]) > 64:
            raise ValueError("task_kind_invalid")
    report = None
    if report_path:
        with materialize(report_path, limit=REPORT_JSON_MAX_BYTES) as local_report:
            report = load_report(local_report)
    if report is not None and report.meta.get("sample_sha256") != sample:
        raise ValueError("review_report_sample_mismatch")
    if output.exists():
        raise ValueError("review_output_exists")
    output.mkdir(parents=True, exist_ok=False)
    (output / "manifest.json").write_bytes(raw)
    replay = {**plan, "tasks": [dict(task) for task in tasks]}
    if retain_inputs:
        (output / "inputs").mkdir()
        if report_path:
            (output / "source-report.json").write_bytes(read_bytes(report_path, REPORT_JSON_MAX_BYTES))
    receipt = {"schema_version": "fxapk.offline-review-result.v1", "manifest_sha256": sha256(raw),
               "sample_sha256": sample, "state": "running", "source_binding_verified": False,
               "not_requested": sorted(set(REVIEWERS) - {task["kind"] for task in tasks}),
               "tasks": [{"id": task["id"], "kind": task["kind"], "state": "not_run",
                          "reason_codes": ["awaiting_execution"]} for task in tasks]}
    write_json(output / "review.json", receipt)
    for task, replay_task, row in zip(tasks, replay["tasks"], receipt["tasks"]):
        row.update(state="running", reason_codes=[])
        write_json(output / "review.json", receipt)
        if progress:
            progress({"id": row["id"], "state": "running"})
        try:
            reviewer = REVIEWERS.get(task["kind"])
            predecessors = [r for r in receipt["tasks"] if r["id"].casefold() in {d.casefold() for d in task.get("depends_on", [])}]
            if deadline is not None and time.monotonic() >= deadline:
                detail = result("not_run", ["intake_time_budget"])
            elif any(r["state"] != "ok" for r in predecessors):
                detail = result("not_run", ["dependency_not_verified"])
            elif reviewer is None:
                detail = result("unsupported", ["review_kind_unsupported"])
            else:
                source = task.get("input")
                if not isinstance(source, str) or not source:
                    raise ValueError("review_input_required")
                reference = resolve_reference(manifest, source)
                parsed = split_reference(reference)
                input_path = parsed[0] if parsed else Path(reference)
                if input_path.resolve().is_relative_to(output.resolve()):
                    raise ValueError("review_input_inside_output")
                if parsed:
                    row.update(input_storage="archive_member", storage_integrity="pending")
                source_data = read_bytes(Path(reference))
                if retain_inputs:
                    retained = f"inputs/{row['id']}.bin"
                    (output / retained).write_bytes(source_data)
                    replay_task["input"] = retained
                if parsed:
                    row.update(input_storage="archive_member", storage_integrity="verified")
                row["input_sha256"] = sha256(source_data)
                row["input_size"] = len(source_data)
                expected = task.get("sha256")
                if expected != row["input_sha256"]:
                    raise ValueError("review_input_hash_mismatch")
                if deadline is not None:
                    detail = isolated_review(source_data, task, output, deadline=deadline)
                elif task["kind"] in {"dex", "emulate", "recover"}:
                    detail = isolated_review(source_data, task, output)
                else:
                    detail = reviewer(source_data, task)
        except ImportError as error:
            detail = result("unsupported", ["optional_dependency_unavailable"], exception_type=type(error).__name__)
        except Exception as error:
            # A broken parser must not silently remove this stage or suppress later tasks.
            code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else "review_failed"
            detail = result("failed", [code], exception_type=type(error).__name__)
            if row.get("storage_integrity") == "pending":
                row["storage_integrity"] = "failed"
        detail.update(id=row["id"], kind=row["kind"], input_sha256=row.get("input_sha256"),
                      source_binding_verified=False)
        if "input_storage" in row:
            detail.update(input_storage=row["input_storage"], storage_integrity=row["storage_integrity"])
        detail_path = output / f"{row['id']}.json"
        write_json(detail_path, detail)
        row.update(state=detail["state"], reason_codes=detail["reason_codes"],
                   receipt_path=detail_path.name, receipt_sha256=sha256(detail_path.read_bytes()))
        write_json(output / "review.json", receipt)
        if progress:
            progress({"id": row["id"], "state": row["state"], "reason_codes": row["reason_codes"]})
    states = {row["state"] for row in receipt["tasks"]}
    receipt["state"] = ("ok" if states == {"ok"} else
                        "failed" if "failed" in states and not states & {"ok", "partial"} else "partial")
    write_json(output / "review.json", receipt)
    write_json(output / "feedback.json", feedback(receipt))
    if retain_inputs:
        write_json(output / "replay-plan.json", replay)
    if report is None:
        report = Report(package_name="offline-evidence-review", meta={}, leads=[], endpoints=[], findings=[], analyzer_status=[])
        report.meta["sample_sha256"] = sample
        report.analysis_status = "complete" if receipt["state"] == "ok" else receipt["state"]
        checked = [row for row in receipt["tasks"] if row["state"] not in {"not_run", "unsupported"}]
        report.completeness = sum(row["state"] == "ok" for row in checked) / len(checked) if checked else 0.0
        for row in receipt["tasks"]:
            name = "offline_review:" + row["id"]
            status = "ran" if row["state"] == "ok" else "skipped" if row["state"] in {"not_run", "unsupported"} else "error"
            report.analyzer_status.append({"name": name, "status": status, "reason": ";".join(row["reason_codes"])})
            if status == "skipped":
                report.skipped_analyzers.append(name)
    # Only attach the bounded metadata projection. Full sensitive details remain in local receipts.
    report.meta["offline_evidence_review"] = projection(receipt)
    try:
        report_json.dump(report, str(output / "report.json"))
        html.render(report, str(output / "report.html"))
        from apkscan.report.digest import build_digest

        write_json(output / "digest.json", build_digest(report_json.to_dict(report)))
        receipt["publication"] = "ok"
    except Exception as error:
        receipt.update(state="failed", publication="failed", reason_code="review_publication_failed")
        write_json(output / "review.json", receipt)
        raise ValueError("review_publication_failed") from error
    write_json(output / "review.json", receipt)
    return receipt
