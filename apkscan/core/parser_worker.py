"""Bounded subprocess bridge for APK parsing and isolated lazy reads."""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from apkscan.core.models import AnalysisConfig, CertInfo, Component, ComponentSet
from apkscan.core.observations import DexStringRecord
from apkscan.core.parser_limits import ParserLimits

IPC_VERSION = 1
_REQUEST_MAX_BYTES = 8 * 1024 * 1024


class ParserBridgeError(RuntimeError):
    def __init__(self, message: str, receipt: dict[str, Any]) -> None:
        super().__init__(message)
        self.receipt = receipt


def _backend() -> tuple[str, str]:
    if sys.platform == "win32":
        return "windows_job_object", "job_memory"
    if sys.platform == "darwin":
        return "posix_process_group", "unavailable"
    if sys.platform.startswith("linux"):
        return "posix_process_group_rlimit_as", "address_space"
    return "posix_process_group", "platform_dependent"


def _receipt(
    limits: ParserLimits,
    *,
    status: str,
    reason: str | None = None,
    ownership_complete: bool = False,
    termination_complete: bool = False,
    forced_tree_kill: bool = False,
    memory_limit_enforced: bool = False,
) -> dict[str, Any]:
    backend, memory_scope = _backend()
    value: dict[str, Any] = {
        "schema_version": IPC_VERSION,
        "status": status,
        "parser_isolation": (
            "enforced" if ownership_complete and memory_limit_enforced else "not_enforced"
        ),
        "policy": limits.to_dict(),
        "backend": backend,
        "platform": sys.platform,
        "memory_limit_scope": memory_scope,
        "memory_limit_enforced": memory_limit_enforced,
        "ownership_complete": ownership_complete,
        "termination_complete": termination_complete,
        "forced_tree_kill": forced_tree_kill,
        "tree_cleanup_complete": termination_complete,
    }
    if reason:
        value["reason"] = reason
        value["blocked_claims"] = ["parser_derived_observations"]
    return value


def _fail_reason(run: Any) -> str | None:
    codes = set(run.reason_codes)
    if run.timed_out or "timeout" in codes:
        return "parser_timeout"
    if "output_limit" in codes:
        return "parser_output_limit"
    if "memory_limit_unavailable" in codes:
        return "parser_memory_limit_unavailable"
    if (
        not run.ownership_complete
        or not run.termination_complete
        or run.forced_tree_kill
        or "survivors_after_kill" in codes
        or "internal_error" in codes
    ):
        return "parser_worker_failed"
    if not run.memory_limit_enforced:
        return "parser_memory_limit_unavailable"
    if run.returncode != 0:
        return "parser_worker_failed"
    return None


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _loads(data: str | bytes) -> Any:
    return json.loads(
        data,
        parse_constant=_reject_constant,
        object_pairs_hook=_reject_duplicate_keys,
    )


def _read_request(path: str) -> dict[str, Any]:
    request_path = Path(path)
    size = request_path.stat().st_size
    if size <= 0 or size > _REQUEST_MAX_BYTES:
        raise ValueError("parser_invalid_request")
    value = _loads(request_path.read_bytes())
    if (
        not isinstance(value, dict)
        or type(value.get("version")) is not int
        or value.get("version") != IPC_VERSION
    ):
        raise ValueError("parser_invalid_request")
    operation = value.get("operation")
    if not isinstance(operation, str) or operation not in {"load", "read_file"}:
        raise ValueError("parser_invalid_request")
    expected = (
        {
            "version", "operation", "path", "config", "extra_dex",
            "jadx_cache_root", "jadx_baseline_index", "parser_limits",
        }
        if operation == "load"
        else {
            "version", "operation", "apk_path", "expected_sha256", "file_path",
            "declared_sizes", "parser_limits",
        }
    )
    if set(value) != expected:
        raise ValueError("parser_invalid_request")
    return value


def _limits_from_request(value: object) -> ParserLimits:
    keys = {"timeout_sec", "memory_bytes", "max_output_bytes", "max_stderr_bytes"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("parser_invalid_request")
    return ParserLimits(**value)


def _config_from_request(value: object) -> AnalysisConfig:
    if not isinstance(value, dict):
        raise ValueError("parser_invalid_request")
    allowed = set(AnalysisConfig.__dataclass_fields__)
    if set(value) != allowed:
        raise ValueError("parser_invalid_request")
    if (
        type(value.get("online", True)) is not bool
        or not isinstance(value.get("out_dir", "out"), str)
        or not isinstance(value.get("formats", ["html", "json"]), list)
        or any(not isinstance(fmt, str) for fmt in value.get("formats", ["html", "json"]))
        or not isinstance(value.get("mode", "passive"), str)
        or type(value.get("enrich_max_targets", 32)) is not int
        or type(value.get("enrich_static_ip_max_targets", 16)) is not int
        or type(value.get("enrichment_dry_run", False)) is not bool
        or not isinstance(value.get("flutter"), str)
        or value.get("flutter") not in {"auto", "off", "required"}
        or type(value.get("flutter_timeout")) is not int
        or not 1 <= value.get("flutter_timeout", 0) <= 1800
        or (value.get("flutter_toolchain") is not None and not isinstance(value.get("flutter_toolchain"), str))
        or (
            value.get("web_supplement") is not None
            and not isinstance(value.get("web_supplement"), str)
        )
        or (
            value.get("web_supplement_request") is not None
            and not isinstance(value.get("web_supplement_request"), dict)
        )
    ):
        raise ValueError("parser_invalid_request")
    return AnalysisConfig(**value)


def _component_set_to_dict(components: ComponentSet) -> dict[str, list[dict[str, Any]]]:
    return {
        name: [asdict(item) for item in getattr(components, name)]
        for name in ("activities", "services", "receivers", "providers")
    }


def snapshot_to_dict(snapshot: Any) -> dict[str, Any]:
    components = snapshot.components()
    files = snapshot._files
    return {
        "package_name": snapshot.package_name,
        "manifest_xml": snapshot.manifest_xml,
        "platform": snapshot.platform,
        "config": asdict(snapshot.config),
        "apk_path": snapshot.apk_path,
        "sample_sha256": snapshot.sample_sha256,
        "extra_dex_paths": snapshot.extra_dex_paths,
        "jadx_cache_root": snapshot.jadx_cache_root,
        "jadx_baseline_index": snapshot.jadx_baseline_index,
        "permissions": snapshot.permissions(),
        "components": _component_set_to_dict(components),
        "records": [
            {
                "value": record.value,
                "provenance": record.provenance,
                "locator": record.locator,
            }
            for record in snapshot.dex_string_records()
        ],
        "file_list": snapshot.list_files(),
        "native_libs": snapshot.native_libs(),
        "certificates": [asdict(item) for item in snapshot.certificates()],
        "files": {
            path: base64.b64encode(data).decode("ascii")
            for path, data in files.items()
        },
        "read_failures": snapshot.file_read_ledger.failure_reasons,
        "dex_available": snapshot.dex_available,
        "apk_validation_ok": snapshot.apk_validation_ok,
        "manifest_anomaly": snapshot.manifest_anomaly,
        "main_dex_report": snapshot.main_dex_report,
        "extra_dex_report": snapshot.extra_dex_report,
        "dex_decode_report": snapshot.dex_decode_report,
        "parser_limits": snapshot.parser_limits,
        "parser_execution": snapshot.parser_execution,
        "declared_sizes": snapshot.declared_sizes,
        "hiddenapi_relaxation": snapshot.hiddenapi_relaxation,
    }


def _require_dict(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"parser_invalid_response:{name}")
    return value


def _require_string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"parser_invalid_response:{name}")
    return value


def _require_string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"parser_invalid_response:{name}")
    return value


def _decode_components(value: object) -> ComponentSet:
    raw = _require_dict(value, "components")
    names = ("activities", "services", "receivers", "providers")
    if set(raw) != set(names):
        raise ValueError("parser_invalid_response:components")
    result: dict[str, list[Component]] = {}
    for name in names:
        rows = raw[name]
        if not isinstance(rows, list):
            raise ValueError("parser_invalid_response:components")
        parsed: list[Component] = []
        for row in rows:
            item = _require_dict(row, "component")
            if (
                set(item) != {"name", "exported", "kind"}
                or not isinstance(item["name"], str)
                or type(item["exported"]) is not bool
                or not isinstance(item["kind"], str)
            ):
                raise ValueError("parser_invalid_response:component")
            parsed.append(Component(**item))
        result[name] = parsed
    return ComponentSet(**result)


def snapshot_from_dict(value: object) -> Any:
    from apkscan.core.snapshot import SnapshotContext

    raw = _require_dict(value, "snapshot")
    required = {
        "package_name", "manifest_xml", "platform", "config", "apk_path",
        "sample_sha256", "extra_dex_paths", "jadx_cache_root", "jadx_baseline_index",
        "permissions", "components", "records", "file_list", "native_libs",
        "certificates", "files", "read_failures", "dex_available",
        "apk_validation_ok", "manifest_anomaly", "main_dex_report",
        "extra_dex_report", "dex_decode_report", "parser_limits", "parser_execution",
        "declared_sizes", "hiddenapi_relaxation",
    }
    if set(raw) != required:
        raise ValueError("parser_invalid_response:snapshot_fields")
    config = _config_from_request(raw["config"])
    package_name = _require_string(raw["package_name"], "package_name")
    manifest_xml = _require_string(raw["manifest_xml"], "manifest_xml")
    platform = _require_string(raw["platform"], "platform")
    apk_path = _require_string(raw["apk_path"], "apk_path")
    sample_sha256 = _require_string(raw["sample_sha256"], "sample_sha256")
    extra_dex_paths = _require_string_list(raw["extra_dex_paths"], "extra_dex_paths")
    permissions = _require_string_list(raw["permissions"], "permissions")
    file_list = _require_string_list(raw["file_list"], "file_list")
    native_libs = _require_string_list(raw["native_libs"], "native_libs")
    if raw["jadx_cache_root"] is not None and not isinstance(raw["jadx_cache_root"], str):
        raise ValueError("parser_invalid_response:jadx_cache_root")
    if raw["jadx_baseline_index"] is not None and not isinstance(
        raw["jadx_baseline_index"], str
    ):
        raise ValueError("parser_invalid_response:jadx_baseline_index")
    if type(raw["dex_available"]) is not bool or type(raw["apk_validation_ok"]) is not bool:
        raise ValueError("parser_invalid_response:status")
    if raw["manifest_anomaly"] is not None and not isinstance(raw["manifest_anomaly"], str):
        raise ValueError("parser_invalid_response:manifest_anomaly")
    records_raw = raw["records"]
    if not isinstance(records_raw, list):
        raise ValueError("parser_invalid_response:records")
    records: list[DexStringRecord] = []
    for row in records_raw:
        item = _require_dict(row, "record")
        if (
            set(item) != {"value", "provenance", "locator"}
            or not isinstance(item["value"], str)
            or not isinstance(item["provenance"], dict)
            or not isinstance(item["locator"], dict)
        ):
            raise ValueError("parser_invalid_response:record")
        records.append(DexStringRecord(**item))
    certificates_raw = raw["certificates"]
    if not isinstance(certificates_raw, list):
        raise ValueError("parser_invalid_response:certificates")
    certificates: list[CertInfo] = []
    for row in certificates_raw:
        item = _require_dict(row, "certificate")
        expected = {
            "subject", "issuer", "sha256", "not_before", "not_after",
            "is_debug", "schemes",
        }
        if (
            set(item) != expected
            or any(not isinstance(item[key], str) for key in (
                "subject", "issuer", "sha256", "not_before", "not_after",
            ))
            or type(item["is_debug"]) is not bool
            or not isinstance(item["schemes"], list)
            or any(not isinstance(scheme, str) for scheme in item["schemes"])
        ):
            raise ValueError("parser_invalid_response:certificate")
        certificates.append(CertInfo(**item))
    encoded_files = _require_dict(raw["files"], "files")
    files: dict[str, bytes] = {}
    for path, encoded in encoded_files.items():
        if not isinstance(encoded, str):
            raise ValueError("parser_invalid_response:files")
        try:
            files[path] = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("parser_invalid_response:files") from exc
    failures = _require_dict(raw["read_failures"], "read_failures")
    if any(not isinstance(key, str) or not isinstance(reason, str) for key, reason in failures.items()):
        raise ValueError("parser_invalid_response:read_failures")
    reports = {
        key: _require_dict(raw[key], key)
        for key in ("main_dex_report", "extra_dex_report", "dex_decode_report")
    }
    limits = raw["parser_limits"]
    if not isinstance(limits, dict):
        raise ValueError("parser_invalid_response:parser_limits")
    _limits_from_request(limits)
    parser_execution = _require_dict(raw["parser_execution"], "parser_execution")
    if not isinstance(raw["declared_sizes"], dict):
        raise ValueError("parser_invalid_response:declared_sizes")
    if any(
        not isinstance(key, str) or type(size) is not int or size < 0
        for key, size in raw["declared_sizes"].items()
    ):
        raise ValueError("parser_invalid_response:declared_sizes")
    hiddenapi = _require_dict(raw["hiddenapi_relaxation"], "hiddenapi_relaxation")
    return SnapshotContext(
        package_name=package_name,
        manifest_xml=manifest_xml,
        platform=platform,
        config=config,
        apk_path=apk_path,
        extra_dex_paths=extra_dex_paths,
        jadx_cache_root=raw["jadx_cache_root"],
        jadx_baseline_index=raw["jadx_baseline_index"],
        permissions=permissions,
        components=_decode_components(raw["components"]),
        dex_strings=tuple(record.value for record in records),
        records=tuple(records),
        file_list=file_list,
        native_libs=native_libs,
        certificates=certificates,
        files=files,
        read_failures=failures,
        dex_available=raw["dex_available"],
        apk_validation_ok=raw["apk_validation_ok"],
        manifest_anomaly=raw["manifest_anomaly"],
        main_dex_report=reports["main_dex_report"],
        extra_dex_report=reports["extra_dex_report"],
        dex_decode_report=reports["dex_decode_report"],
        sample_sha256=sample_sha256,
        parser_limits=limits,
        parser_execution=parser_execution,
        declared_sizes=raw["declared_sizes"],
        hiddenapi_relaxation=hiddenapi,
    )


def _run_operation(request: dict[str, Any], limits: ParserLimits) -> dict[str, Any]:
    from apkscan.core.proctree import run_owned

    try:
        payload = json.dumps(
            request, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ParserBridgeError(
            "Parser request is not JSON-compatible.",
            _receipt(limits, status="failed", reason="parser_worker_failed"),
        ) from exc
    if len(payload) > _REQUEST_MAX_BYTES:
        raise ParserBridgeError(
            "Parser request exceeds the IPC request cap.",
            _receipt(limits, status="failed", reason="parser_worker_failed"),
        )
    try:
        with tempfile.TemporaryDirectory(prefix="fxapk-parser-") as directory:
            request_path = Path(directory) / "request.json"
            request_path.write_bytes(payload)
            run = run_owned(
                [sys.executable, "-m", "apkscan.core.parser_worker", str(request_path)],
                timeout=limits.timeout_sec,
                memory_bytes=limits.memory_bytes,
                max_stdout_bytes=limits.max_output_bytes,
                max_stderr_bytes=limits.max_stderr_bytes,
            )
            reason = _fail_reason(run)
            if reason:
                raise ParserBridgeError(
                    "Parser worker did not complete within its configured policy.",
                    _receipt(
                        limits,
                        status="failed",
                        reason=reason,
                        ownership_complete=run.ownership_complete,
                        termination_complete=run.termination_complete,
                        forced_tree_kill=run.forced_tree_kill,
                        memory_limit_enforced=run.memory_limit_enforced,
                    ),
                )
            try:
                response = _loads(run.stdout)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as exc:
                raise ParserBridgeError(
                    "Parser worker returned invalid JSON.",
                    _receipt(
                        limits,
                        status="failed",
                        reason="parser_invalid_response",
                        ownership_complete=run.ownership_complete,
                        termination_complete=run.termination_complete,
                        forced_tree_kill=run.forced_tree_kill,
                        memory_limit_enforced=run.memory_limit_enforced,
                    ),
                ) from exc
            if (
                not isinstance(response, dict)
                or type(response.get("version")) is not int
                or response.get("version") != IPC_VERSION
                or not isinstance(response.get("kind"), str)
                or response.get("kind") not in {"snapshot", "read_file", "error"}
            ):
                raise ParserBridgeError(
                    "Parser worker response failed schema validation.",
                    _receipt(
                        limits,
                        status="failed",
                        reason="parser_invalid_response",
                        ownership_complete=run.ownership_complete,
                        termination_complete=run.termination_complete,
                        forced_tree_kill=run.forced_tree_kill,
                        memory_limit_enforced=run.memory_limit_enforced,
                    ),
                )
            if response["kind"] == "error":
                if (
                    set(response) != {"version", "kind", "reason", "message"}
                    or not isinstance(response["reason"], str)
                    or not isinstance(response["message"], str)
                ):
                    raise ParserBridgeError(
                        "Parser worker returned an invalid failure response.",
                        _receipt(
                            limits,
                            status="failed",
                            reason="parser_invalid_response",
                            ownership_complete=run.ownership_complete,
                            termination_complete=run.termination_complete,
                            forced_tree_kill=run.forced_tree_kill,
                            memory_limit_enforced=run.memory_limit_enforced,
                        ),
                    )
                worker_reason = response.get("reason")
                reason = worker_reason if worker_reason in {
                    "parser_memory_limit", "parser_input_changed",
                    "parser_invalid_response",
                } else "parser_worker_failed"
                raise ParserBridgeError(
                    response.get("message", "Parser worker failed."),
                    _receipt(
                        limits,
                        status="failed",
                        reason=reason,
                        ownership_complete=run.ownership_complete,
                        termination_complete=run.termination_complete,
                        forced_tree_kill=run.forced_tree_kill,
                        memory_limit_enforced=run.memory_limit_enforced,
                    ),
                )
            response["_run_receipt"] = {
                "ownership_complete": run.ownership_complete,
                "termination_complete": run.termination_complete,
                "forced_tree_kill": run.forced_tree_kill,
                "memory_limit_enforced": run.memory_limit_enforced,
            }
            return response
    except ParserBridgeError:
        raise
    except OSError as exc:
        raise ParserBridgeError(
            "Parser worker could not be started.",
            _receipt(limits, status="failed", reason="parser_worker_failed"),
        ) from exc


def run_parser_load(
    path: str,
    config: AnalysisConfig,
    extra_dex: list[str] | None,
    jadx_cache_root: str | None,
    jadx_baseline_index: str | None,
    limits: ParserLimits,
) -> Any:
    request = {
        "version": IPC_VERSION,
        "operation": "load",
        "path": path,
        "config": asdict(config),
        "extra_dex": list(extra_dex or []),
        "jadx_cache_root": jadx_cache_root,
        "jadx_baseline_index": jadx_baseline_index,
        "parser_limits": limits.to_dict(),
    }
    response = _run_operation(request, limits)
    run_receipt = response.pop("_run_receipt")
    if response["kind"] != "snapshot" or set(response) != {
        "version", "kind", "snapshot",
    }:
        raise ParserBridgeError(
            "Parser worker returned an unexpected result.",
            _receipt(
                limits, status="failed", reason="parser_invalid_response",
                **run_receipt,
            ),
        )
    try:
        snapshot = snapshot_from_dict(response["snapshot"])
    except (TypeError, ValueError, KeyError, RecursionError) as exc:
        raise ParserBridgeError(
            "Parser worker snapshot failed schema validation.",
            _receipt(
                limits, status="failed", reason="parser_invalid_response",
                **run_receipt,
            ),
        ) from exc
    if snapshot.parser_limits != limits.to_dict():
        raise ParserBridgeError(
            "Parser worker returned a snapshot with a different parser policy.",
            _receipt(
                limits, status="failed", reason="parser_invalid_response",
                **run_receipt,
            ),
        )
    snapshot.parser_execution = _receipt(
        limits, status="completed_under_limits", **run_receipt
    )
    return snapshot


def run_parser_read(
    *,
    apk_path: str,
    expected_sha256: str,
    file_path: str,
    limits: ParserLimits,
    declared_sizes: dict[str, int],
) -> tuple[bytes | None, str | None]:
    request = {
        "version": IPC_VERSION,
        "operation": "read_file",
        "apk_path": apk_path,
        "expected_sha256": expected_sha256,
        "file_path": file_path,
        "declared_sizes": (
            {file_path: declared_sizes[file_path]} if file_path in declared_sizes else {}
        ),
        "parser_limits": limits.to_dict(),
    }
    try:
        response = _run_operation(request, limits)
    except ParserBridgeError as exc:
        return None, str(exc.receipt.get("reason") or "parser_worker_failed")
    response.pop("_run_receipt", None)
    if response["kind"] == "error":
        reason = response.get("reason")
        if reason not in {
            "parser_timeout", "parser_output_limit", "parser_memory_limit_unavailable",
            "parser_worker_failed", "parser_invalid_response", "parser_input_changed",
            "parser_memory_limit",
        }:
            reason = "parser_worker_failed"
        return None, reason
    if response["kind"] != "read_file" or set(response) != {
        "version", "kind", "data", "failure_reason", "parser_limits",
    }:
        return None, "parser_invalid_response"
    if response["parser_limits"] != limits.to_dict():
        return None, "parser_invalid_response"
    failure_reason = response["failure_reason"]
    if failure_reason is not None and not isinstance(failure_reason, str):
        return None, "parser_invalid_response"
    encoded = response["data"]
    if encoded is not None and failure_reason is not None:
        return None, "parser_invalid_response"
    if encoded is None:
        return None, failure_reason or "unavailable_context"
    if not isinstance(encoded, str) or len(encoded) > limits.max_output_bytes:
        return None, "parser_invalid_response"
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None, "parser_invalid_response"
    return data, None


def _handle_request(request: dict[str, Any]) -> dict[str, Any]:
    limits = _limits_from_request(request.get("parser_limits"))
    operation = request["operation"]
    if operation == "load":
        if not isinstance(request.get("path"), str):
            raise ValueError("parser_invalid_request")
        extra_dex = request.get("extra_dex")
        if not isinstance(extra_dex, list) or any(not isinstance(path, str) for path in extra_dex):
            raise ValueError("parser_invalid_request")
        from apkscan.core.apk import _load_apk_inprocess, hiddenapi_relax_report
        from apkscan.core.integrity import sha256_file
        from apkscan.core.snapshot import build_snapshot

        config = _config_from_request(request.get("config"))
        cache_root = request.get("jadx_cache_root")
        baseline_index = request.get("jadx_baseline_index")
        if cache_root is not None and not isinstance(cache_root, str):
            raise ValueError("parser_invalid_request")
        if baseline_index is not None and not isinstance(baseline_index, str):
            raise ValueError("parser_invalid_request")
        try:
            initial_digest = sha256_file(request["path"])
        except OSError:
            return {
                "version": IPC_VERSION,
                "kind": "error",
                "reason": "parser_input_changed",
                "message": "Parser worker could not verify the APK input before parsing.",
            }
        ctx: Any = _load_apk_inprocess(
            request["path"],
            config,
            extra_dex=extra_dex,
            jadx_cache_root=cache_root,
            jadx_baseline_index=baseline_index,
        )
        ctx.parser_limits = limits.to_dict()
        ctx.hiddenapi_relaxation = hiddenapi_relax_report(
            getattr(ctx, "hiddenapi_flags_baseline", None)
        )
        ctx.declared_sizes = dict(ctx._declared_sizes)
        snapshot = build_snapshot(ctx)
        try:
            final_digest = sha256_file(request["path"])
        except OSError:
            final_digest = ""
        if (
            final_digest != initial_digest
            or snapshot.sample_sha256 != initial_digest
        ):
            return {
                "version": IPC_VERSION,
                "kind": "error",
                "reason": "parser_input_changed",
                "message": "APK input changed while the parser snapshot was being created.",
            }
        return {"version": IPC_VERSION, "kind": "snapshot", "snapshot": snapshot_to_dict(snapshot)}
    if operation == "read_file":
        apk_path = request.get("apk_path")
        expected_sha256 = request.get("expected_sha256")
        file_path = request.get("file_path")
        declared_sizes = request.get("declared_sizes")
        if (
            not isinstance(apk_path, str)
            or not isinstance(expected_sha256, str)
            or not isinstance(file_path, str)
            or not isinstance(declared_sizes, dict)
            or any(
                not isinstance(key, str) or type(size) is not int or size < 0
                for key, size in declared_sizes.items()
            )
        ):
            raise ValueError("parser_invalid_request")
        from apkscan.core.integrity import sha256_file
        from apkscan.core.snapshot import SnapshotContext

        try:
            digest = sha256_file(apk_path)
        except OSError:
            digest = ""
        if not expected_sha256 or digest != expected_sha256:
            return {
                "version": IPC_VERSION,
                "kind": "error",
                "reason": "parser_input_changed",
                "message": "APK input changed since the parser snapshot was created.",
            }
        snapshot = SnapshotContext(
            package_name="",
            manifest_xml="",
            platform="android",
            config=AnalysisConfig(online=False),
            apk_path=apk_path,
            extra_dex_paths=[],
            jadx_cache_root=None,
            jadx_baseline_index=None,
            permissions=[],
            components=ComponentSet(),
            dex_strings=(),
            file_list=[],
            native_libs=[],
            certificates=[],
            files={},
            sample_sha256=expected_sha256,
            parser_limits=None,
            declared_sizes=declared_sizes,
        )
        data = snapshot._lazy_read(file_path)
        try:
            digest_after_read = sha256_file(apk_path)
        except OSError:
            digest_after_read = ""
        if digest_after_read != expected_sha256:
            return {
                "version": IPC_VERSION,
                "kind": "error",
                "reason": "parser_input_changed",
                "message": "APK input changed while the parser read was running.",
            }
        return {
            "version": IPC_VERSION,
            "kind": "read_file",
            "data": base64.b64encode(data).decode("ascii") if data is not None else None,
            "failure_reason": snapshot.file_read_ledger.failure_for(file_path),
            "parser_limits": limits.to_dict(),
        }
    raise ValueError("parser_invalid_request")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        return 2
    try:
        request = _read_request(args[0])
        with contextlib.redirect_stdout(sys.stderr):
            response = _handle_request(request)
        encoded = json.dumps(
            response, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
    except MemoryError:
        encoded = json.dumps({
            "version": IPC_VERSION,
            "kind": "error",
            "reason": "parser_memory_limit",
            "message": "Parser worker raised MemoryError.",
        }, separators=(",", ":")).encode("utf-8")
    except Exception as exc:  # noqa: BLE001 - child errors cross the IPC as a stable failure
        message = str(exc)
        reason = "parser_invalid_response" if message.startswith("parser_invalid_response") else (
            "parser_worker_failed"
        )
        encoded = json.dumps({
            "version": IPC_VERSION,
            "kind": "error",
            "reason": reason,
            "message": message,
        }, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
