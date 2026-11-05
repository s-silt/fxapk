"""Consume fxfetch's verified CLI handoff, then analyze each original APK offline.

No fxfetch Python imports, live service calls, target downloads or implicit retries.
"""
from __future__ import annotations

import hashlib
import html
import os
import re
import shutil
import sys
import sysconfig
import time
import zipfile
from pathlib import Path
from typing import Callable

from apkscan.core.offline_review.common import json_value, read_bytes
from apkscan.core.offline_review.runner import write_json
from apkscan.core.proctree import run_owned

MAX_ARCHIVE = 2 * 1024**3
MAX_APK = 512 * 1024**2
MAX_PACKAGES = 8


def file_hash(path: Path, limit: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            total += len(block)
            if total > limit:
                raise ValueError("input_byte_budget")
            digest.update(block)
    return digest.hexdigest()


def _resolve_executable(executable: str) -> str:
    found = shutil.which(executable)
    if not found:
        raise ValueError("executable_unavailable")
    return str(Path(found).resolve())


def _default_fxapk() -> str:
    sibling = Path(sysconfig.get_path("scripts")) / ("fxapk.exe" if sys.platform == "win32" else "fxapk")
    if not sibling.is_file():
        raise ValueError("same_interpreter_fxapk_entrypoint_unavailable")
    return str(sibling)


def _process(command: list[str], prefix: Path, deadline: float, *, allow_device: bool = False) -> dict:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {"state": "not_run", "reason_codes": ["intake_time_budget"]}
    child_env = dict(os.environ)
    if not allow_device:
        child_env["FXAPK_NO_DEVICE_PROBE"] = "1"
    run = run_owned(command, timeout=remaining, env=child_env, memory_bytes=2 * 1024**3,
                    max_stdout_bytes=1024**2, max_stderr_bytes=1024**2)
    # Local logs may contain evidence; console and index expose metadata only.
    prefix.with_suffix(".stdout.log").write_text(run.stdout, encoding="utf-8")
    prefix.with_suffix(".stderr.log").write_text(run.stderr, encoding="utf-8")
    reasons = list(run.reason_codes)
    if "memory_limit_unavailable" in reasons:
        return {"state": "unsupported", "reason_codes": ["platform_memory_limit_unavailable"],
                "returncode": None, "timed_out": False, "process_tree_complete": False}
    if run.timed_out:
        reasons.append("subprocess_timeout")
    if not run.ownership_complete or not run.termination_complete or run.forced_tree_kill:
        reasons.append("process_tree_incomplete")
    if run.returncode != 0:
        reasons.append("subprocess_nonzero_exit")
    return {"state": "failed" if reasons else "ok", "reason_codes": sorted(set(reasons)),
            "returncode": run.returncode, "timed_out": run.timed_out,
            "process_tree_complete": run.ownership_complete and run.termination_complete and not run.forced_tree_kill}


def _index(output: Path, receipt: dict) -> None:
    rows = []
    for stage in receipt["stages"]:
        label = html.escape(stage["id"])
        destination = stage.get("report_path")
        if destination:
            label = f'<a href="{html.escape(destination, quote=True)}">{label}</a>'
        rows.append(f'<tr><td>{label}</td><td>{html.escape(stage["state"])}</td>'
                    f'<td>{html.escape(", ".join(stage.get("reason_codes", [])))}</td></tr>')
    output.joinpath("index.html").write_text(
        '<!doctype html><meta charset="utf-8"><title>采集材料衔接</title>'
        '<style>body{font:16px system-ui;max-width:1100px;margin:32px auto;padding:16px}'
        'td,th{border:1px solid #bbb;padding:10px;text-align:left}table{border-collapse:collapse;width:100%}</style>'
        f'<h1>采集材料衔接：{html.escape(receipt["state"])}</h1>'
        '<p>仅处理已保存材料，未访问目标或启动设备。采集覆盖仍为 partial；分析成功不表示案件闭环。</p>'
        '<table><tr><th>分路 / 报告</th><th>状态</th><th>原因或缺口</th></tr>'
        + "".join(rows) + '</table><p>原始材料、失败状态和各阶段回执保留在本目录。</p>', encoding="utf-8")


def run(archive: Path, output: Path, *, fxfetch: str = "fxfetch", fxapk: str | None = None,
        timeout: int = 600, review_manifest: Path | None = None,
        progress: Callable[[dict], None] | None = None) -> dict:
    if not 1 <= timeout <= 3600:
        raise ValueError("intake_timeout_invalid")
    if output.exists():
        raise ValueError("intake_output_exists")
    output.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + timeout
    receipt = {"schema_version": "fxapk.fetch-intake.v1", "state": "running", "online": False,
               "source_coverage": "partial", "authenticity_verified": False,
               "stages": [{"id": "web", "state": "not_run", "reason_codes": ["awaiting_verification"]},
                          {"id": "packages", "state": "not_run", "reason_codes": ["awaiting_verification"]},
                          {"id": "targeted_reviews", "state": "not_run", "reason_codes": ["explicit_review_manifest_required"]}]}

    def publish() -> None:
        write_json(output / "intake.json", receipt)
        _index(output, receipt)
        if progress:
            progress({"state": receipt["state"], "stages": [
                {"id": row["id"], "state": row["state"], "reason_codes": row.get("reason_codes", [])}
                for row in receipt["stages"]]})

    publish()
    try:
        source_hash = file_hash(archive, MAX_ARCHIVE)
        receipt["source_sha256"] = source_hash
        fetch_exe = _resolve_executable(fxfetch)
        apk_exe = _resolve_executable(fxapk or _default_fxapk())
        web_stage = receipt["stages"][0]
        web_stage.update(state="running", reason_codes=[])
        publish()
        command = [fetch_exe, "analyze-data", str(archive.resolve()), "--out", str((output / "web").resolve()),
                   "--fxapk", apk_exe, "--timeout", str(max(1, min(300, timeout)))]
        process = _process(command, output / "fetch-process", deadline)
        web_stage["process"] = process
        if process["state"] == "unsupported":
            web_stage.update(state="unsupported", reason_codes=process["reason_codes"])
            raise ValueError("platform_memory_limit_unavailable")
        if not process.get("process_tree_complete") or process.get("timed_out"):
            raise ValueError("fetch_process_incomplete")
        handoff = json_value(read_bytes(output / "web" / "analysis.json"))
        if isinstance(handoff, dict):
            upstream_reason = handoff.get("reason_code")
            if isinstance(upstream_reason, str) and re.fullmatch(r"[a-z_]{1,100}", upstream_reason):
                web_stage["upstream_reason_code"] = upstream_reason
        if (not isinstance(handoff, dict) or handoff.get("schema_version") != "fxfetch.analysis-handoff.v1"
                or handoff.get("source_archive", {}).get("sha256") != source_hash
                or handoff.get("source_archive", {}).get("integrity_verified") is not True):
            raise ValueError("fetch_handoff_not_verified")
        source_copy = output / "web" / "source.zip"
        if file_hash(source_copy, MAX_ARCHIVE) != source_hash:
            raise ValueError("fetch_source_copy_mismatch")
        analysis = handoff.get("analysis", {})
        state = analysis.get("state")
        reason = analysis.get("reason_code")
        if reason is not None and (not isinstance(reason, str) or not re.fullmatch(r"[a-z_]{1,100}", reason)):
            raise ValueError("web_reason_code_invalid")
        if state == "completed" and process["state"] == "ok":
            web_report_path = output / "web" / "report" / "input.json"
            if file_hash(web_report_path, 32 * 1024**2) != analysis.get("report", {}).get("sha256"):
                raise ValueError("web_report_hash_mismatch")
            web_report = json_value(read_bytes(web_report_path))
            errors = analysis.get("report", {}).get("load_errors")
            if not isinstance(errors, list) or web_report.get("meta", {}).get("online") is not False:
                raise ValueError("web_report_contract_mismatch")
            incomplete = bool(errors) or web_report.get("analysis_status") != "complete"
            web_stage.update(state="partial" if incomplete else "ok",
                             reason_codes=["web_analysis_incomplete"] if incomplete else [],
                             report_path="web/report/input.json", load_error_count=len(errors))
        elif state == "not_run":
            web_stage.update(state="not_run", reason_codes=[reason or "web_not_run"])
        else:
            web_stage.update(state="failed", reason_codes=[reason or "web_analysis_failed"])
        # A web failure does not erase an independently verified original APK attachment.
        manifest = handoff["source_manifest"]
        attachments = manifest.get("attachments", [])
        packages = [item for item in attachments if item.get("kind") == "package"]
        package_stage = receipt["stages"][1]
        package_stage.update(state="ok" if packages else "not_run", reason_codes=[] if packages else ["no_embedded_original_package"])
        receipt["unembedded_packages"] = len([item for item in manifest.get("external_packages", []) if not item.get("embedded_path")])
        if receipt["unembedded_packages"]:
            package_stage.update(state="partial", reason_codes=["external_package_bytes_missing"])
        receipt["certificate_attachments"] = sum(item.get("kind") == "certificate" for item in attachments)
        for index, package in enumerate(packages, 1):
            stage = {"id": f"package-{index:03d}", "state": "not_run", "reason_codes": [],
                     "sha256": package["sha256"], "package_kind": package["package_kind"],
                     "source_member": package["path"]}
            receipt["stages"].append(stage)
            if package.get("complete") is not True or package.get("validation", {}).get("status") != "passed":
                stage.update(state="not_run", reason_codes=["original_package_validation_failed"])
            elif package["package_kind"] != "apk":
                stage.update(state="unsupported", reason_codes=["ipa_analysis_not_supported"])
            elif index > MAX_PACKAGES or package["size"] > MAX_APK:
                stage.update(state="not_run", reason_codes=["package_analysis_budget"])
            else:
                try:
                    directory = output / stage["id"]
                    directory.mkdir()
                    sample = directory / "original.apk"
                    digest = hashlib.sha256()
                    total = 0
                    # Extract only the explicitly verified member to our fixed filename.
                    with zipfile.ZipFile(source_copy) as bundle, bundle.open(package["path"]) as incoming, sample.open("xb") as outgoing:
                        while block := incoming.read(65536):
                            total += len(block)
                            if total > MAX_APK or total > package["size"]:
                                raise ValueError("attachment_byte_budget")
                            outgoing.write(block)
                            digest.update(block)
                    if total != package["size"] or digest.hexdigest() != package["sha256"]:
                        raise ValueError("attachment_hash_mismatch")
                    stage.update(state="running", reason_codes=[])
                    publish()
                    analyzer = [apk_exe] if fxapk is not None else [sys.executable, "-m", "apkscan.cli"]
                    process = _process([*analyzer, "analyze", str(sample.resolve()), "--offline", "--fmt", "html,json",
                                        "--out", str((directory / "report").resolve())], directory / "analyze-process", deadline)
                    stage.update(state=process["state"], reason_codes=process["reason_codes"], process=process)
                    if process["state"] == "ok":
                        report = json_value(read_bytes(directory / "report" / "original.json"))
                        meta = report.get("meta", {})
                        if meta.get("sample_sha256") != package["sha256"] or meta.get("online") is not False:
                            raise ValueError("apk_report_contract_mismatch")
                        stage["report_path"] = f"{stage['id']}/report/original.html"
                        stage["json_report_path"] = f"{stage['id']}/report/original.json"
                        stage["analysis_status"] = report.get("analysis_status", "unknown")
                        stage["tool_version"] = meta.get("tool_version", "unknown")
                        if stage["analysis_status"] != "complete":
                            stage.update(state="partial" if stage["analysis_status"] == "partial" else "failed",
                                         reason_codes=["apk_analysis_incomplete"])
                except Exception as error:
                    code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else "package_stage_failed"
                    stage.update(state="failed", reason_codes=[code], exception_type=type(error).__name__)
            publish()
        if review_manifest is not None:
            from apkscan.core.offline_review.runner import run as review_evidence

            review_stage = receipt["stages"][2]
            try:
                plan = json_value(read_bytes(review_manifest, 1024**2))
                matches = [row for row in receipt["stages"] if row.get("sha256") == plan.get("sample_sha256")
                           and row.get("json_report_path")]
                if len(matches) != 1:
                    raise ValueError("review_requires_unique_analyzed_sample")
                if time.monotonic() >= deadline:
                    raise ValueError("intake_time_budget")
                review_stage.update(state="running", reason_codes=[])
                publish()
                reviewed = review_evidence(review_manifest, output / "targeted-review",
                                           output / matches[0]["json_report_path"], progress, deadline=deadline)
                review_stage.update(state=reviewed["state"], reason_codes=sorted({
                    reason for row in reviewed["tasks"] for reason in row["reason_codes"]}),
                    report_path="targeted-review/report.html")
            except Exception as error:
                code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else "targeted_review_failed"
                review_stage.update(state="failed", reason_codes=[code], exception_type=type(error).__name__)
        active = [row for row in receipt["stages"] if row["id"] != "targeted_reviews"]
        if review_manifest is not None:
            active.append(receipt["stages"][2])
        useful = [row for row in active if row["id"] != "packages"]
        receipt["state"] = ("ok" if all(row["state"] == "ok" for row in active) else
                            "partial" if any(row["state"] in {"ok", "partial"} for row in useful) else "failed")
    except Exception as error:
        code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else "fetch_intake_failed"
        receipt.update(state="failed", reason_code=code, exception_type=type(error).__name__)
        for stage in receipt["stages"]:
            if stage["state"] == "running":
                reasons = [code, *stage.get("process", {}).get("reason_codes", [])]
                if stage.get("upstream_reason_code"):
                    reasons.append(stage["upstream_reason_code"])
                stage.update(state="failed", reason_codes=sorted(set(reasons)))
            elif stage["state"] == "not_run" and stage["id"] != "targeted_reviews":
                prior = [r for r in stage.get("reason_codes", []) if r != "awaiting_verification"]
                stage["reason_codes"] = sorted(set([*prior, code]))
    publish()
    return receipt
