"""把已发布的 REA / CDP 观察副本挂到既有报告。离线、create-only。"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import typer

from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.web_observations import classify_gaps

from .bundlecompat import FLAGS, assess
from .trace_limits import MAX_RAW_BYTES as _MAX_TRACE

_RAW_NAMES = {
    "rea-web-observation/1": "rea-original.json",
    "fxapk-cdp-trace-observation/1": "cdp-trace-original.json",
}
_PROJECTORS = {
    "rea-web-observation/1": ("fxapk_rea.evidence", "project"),
    "fxapk-cdp-trace-observation/1": ("fxapk_rea.trace", "project_trace"),
}
_PROVIDERS = {
    "rea-web-observation/1": "rea",
    "fxapk-cdp-trace-observation/1": "fxapk-cdp-trace",
}
_SCRIPT_NAME = re.compile(r"scripts/[0-9a-f]{64}\.js")
_HEX = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){0,8}")
_CONTEXT_REQUIRED = frozenset({"schema_version", "sample_sha256", "target_id", "origin"})
_CONTEXT_OPTIONAL = frozenset({"package_name", "process_id", "webview_target_id", "recorded_at"})
_MAX_RAW = 16 * 1024 * 1024
_MAX_OBSERVATION = 2 * 1024 * 1024
_MAX_CONTEXT = 8192
_MAX_READY = 64 * 1024
_MAX_MARKER = 4096
_MAX_REPORT = 32 * 1024 * 1024
_MAX_FILES = 80
_MAX_OBSERVATIONS = 32
_MAX_ATTACHMENT_BYTES = 32 * 1024 * 1024


logger = logging.getLogger(__name__)


class AttachError(ValueError):
    """稳定原因码，不携带不受信任的原值。"""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttachError("duplicate_json_key")
        result[key] = value
    return result


def _nonfinite(_value: str) -> Any:
    raise AttachError("invalid_json")


def _loads(raw: bytes, limit: int) -> Any:
    if len(raw) > limit:
        raise AttachError("oversize")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except AttachError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise AttachError("invalid_json") from None


def _is_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def _reject_link(path: Path) -> None:
    if _is_link(path):
        raise AttachError("link_escape")


def _safe_parts(relative: str) -> list[str]:
    if (
        not isinstance(relative, str)
        or not relative
        or relative.startswith(("/", "\\"))
        or "\\" in relative
        or "\x00" in relative
    ):
        raise AttachError("path_escape")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise AttachError("path_escape")
    return parts


def _inside(root: Path, relative: str, *, expect_file: bool) -> Path:
    parts = _safe_parts(relative)
    _reject_link(root)
    current = root
    for part in parts:
        current = current / part
        if _is_link(current):
            raise AttachError("link_escape")
    if expect_file and not current.is_file():
        raise AttachError("not_a_file")
    try:
        current.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        raise AttachError("path_escape") from None
    return current


def _read_limited(path: Path, limit: int) -> bytes:
    """先看声明大小，再读到上限为止。读到的字节变多也拒绝。"""
    _reject_link(path)
    if not path.is_file():
        raise AttachError("not_a_file")
    if path.stat().st_size > limit:
        raise AttachError("oversize")
    with path.open("rb") as handle:
        blob = handle.read(limit + 1)
    if len(blob) > limit:
        raise AttachError("oversize")
    return blob


def _read_file(root: Path, relative: str, limit: int) -> bytes:
    return _read_limited(_inside(root, relative, expect_file=True), limit)


def _project(schema: str, raw: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    module_name, function_name = _PROJECTORS[schema]
    module = importlib.import_module(module_name)
    try:
        projected = getattr(module, function_name)(raw)
    except AttachError:
        raise
    except Exception as exc:
        logger.exception("observation projection failed")
        code = exc.args[0] if exc.args and isinstance(exc.args[0], str) else ""
        if re.fullmatch(r"[a-z0-9_]{1,80}", code):
            raise AttachError(code) from None
        raise AttachError("projection_failed") from None
    if not isinstance(projected, tuple) or len(projected) < 2:
        raise AttachError("projection_failed")
    receipt, files = projected[0], projected[1]
    if not isinstance(receipt, dict) or not isinstance(files, dict):
        raise AttachError("projection_failed")
    return receipt, files


def _binding(schema: str, receipt: dict[str, Any]) -> tuple[str, str]:
    if schema == "rea-web-observation/1":
        target = receipt.get("target")
        if not isinstance(target, dict):
            raise AttachError("receipt_mismatch")
        target_id, origin = target.get("target_id"), target.get("origin")
    else:
        capture = receipt.get("capture")
        if not isinstance(capture, dict):
            raise AttachError("receipt_mismatch")
        target_id, origin = capture.get("target_id"), capture.get("origin")
    if not isinstance(target_id, str) or not isinstance(origin, str):
        raise AttachError("receipt_mismatch")
    return target_id, origin


def _check_context(
    path: Path | None, report_sha: object, target_id: str, origin: str
) -> tuple[str, bytes | None, dict[str, Any] | None]:
    if path is None:
        return "unknown", None, None
    raw = _read_limited(path, _MAX_CONTEXT)
    payload = _loads(raw, _MAX_CONTEXT)
    if not isinstance(payload, dict):
        raise AttachError("context_schema")
    allowed = _CONTEXT_REQUIRED | _CONTEXT_OPTIONAL
    if set(payload) - allowed or not _CONTEXT_REQUIRED <= set(payload):
        raise AttachError("context_schema")
    if payload.get("schema_version") != "fxapk-web-context/1":
        raise AttachError("context_schema")
    sample = payload.get("sample_sha256")
    if not isinstance(sample, str) or _HEX.fullmatch(sample) is None or sample != report_sha:
        raise AttachError("context_sample_mismatch")
    if payload.get("target_id") != target_id or payload.get("origin") != origin:
        raise AttachError("context_binding_mismatch")
    if not isinstance(target_id, str) or _TOKEN.fullmatch(payload["target_id"]) is None:
        raise AttachError("context_schema")
    if not isinstance(origin, str) or len(origin) > 300 or any(ord(char) < 32 for char in origin):
        raise AttachError("context_schema")
    package = payload.get("package_name")
    if package is not None and (
        not isinstance(package, str) or _PACKAGE.fullmatch(package) is None or len(package) > 200
    ):
        raise AttachError("context_schema")
    process_id = payload.get("process_id")
    if process_id is not None and (
        isinstance(process_id, bool)
        or not isinstance(process_id, int)
        or not 0 <= process_id <= 2**31 - 1
    ):
        raise AttachError("context_schema")
    webview = payload.get("webview_target_id")
    if webview is not None and (not isinstance(webview, str) or _TOKEN.fullmatch(webview) is None):
        raise AttachError("context_schema")
    recorded = payload.get("recorded_at")
    if recorded is not None:
        if not isinstance(recorded, str) or len(recorded) > 40:
            raise AttachError("context_schema")
        try:
            moment = datetime.fromisoformat(recorded.replace("Z", "+00:00"))
        except ValueError:
            raise AttachError("context_schema") from None
        if moment.utcoffset() is None:
            raise AttachError("context_schema")
    pointer = {
        "relative_path": "",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "schema_version": "fxapk-web-context/1",
        "authentication": "declared",
        "sample_sha256_matches_report": True,
        "target_binding_matches_bundle": True,
    }
    return "declared", raw, pointer


def _allowed_copy_name(name: str) -> None:
    _safe_parts(name)
    if name in {
        "rea-original.json",
        "cdp-trace-original.json",
        "fxapk-rea-bundle.json",
        "observation.json",
        "observation-reprojected.json",
        "projection-record.json",
        "ready.json",
        "context-record.json",
    }:
        return
    if _SCRIPT_NAME.fullmatch(name) is None:
        raise AttachError("unexpected_artifact")


def _artifact_name(relative: str, raw_name: str) -> None:
    if relative != raw_name and _SCRIPT_NAME.fullmatch(relative) is None:
        _safe_parts(relative)
        raise AttachError("unexpected_artifact")


def _verify_bundle(bundle: Path) -> dict[str, Any]:
    _reject_link(bundle)
    if not bundle.is_dir():
        raise AttachError("not_a_directory")
    if (bundle / "failure.json").exists() or (bundle / "failure.json").is_symlink():
        raise AttachError("failed_bundle")
    marker = _read_file(bundle, "fxapk-rea-bundle.json", _MAX_MARKER)
    marker_payload = _loads(marker, _MAX_MARKER)
    if (
        not isinstance(marker_payload, dict)
        or marker_payload.get("schema_version") != "fxapk-rea-bundle-marker/1"
        or marker_payload.get("kind") != "unverified_external_observation_bundle"
    ):
        raise AttachError("invalid_bundle_marker")
    observation_bytes = _read_file(bundle, "observation.json", _MAX_OBSERVATION)
    observation = _loads(observation_bytes, _MAX_OBSERVATION)
    if not isinstance(observation, dict):
        raise AttachError("invalid_observation")
    schema = observation.get("schema_version")
    if schema not in _RAW_NAMES:
        raise AttachError("unsupported_observation")
    raw_name = _RAW_NAMES[schema]
    source = observation.get("source")
    if not isinstance(source, dict) or source.get("relative_path") != raw_name:
        raise AttachError("receipt_mismatch")
    limit = _MAX_TRACE if schema == "fxapk-cdp-trace-observation/1" else _MAX_RAW
    raw = _read_file(bundle, raw_name, limit)
    raw_sha = hashlib.sha256(raw).hexdigest()
    if source.get("sha256") != raw_sha:
        raise AttachError("source_hash_mismatch")
    for flag in (
        "click_attribution_verified",
        "target_app_attribution_verified",
        "provenance_authenticated",
        "closure_evaluated",
    ):
        if observation.get(flag) is not False:
            raise AttachError("saved_flag_rejected")
    receipt, files = _project(schema, raw)
    if receipt.get("source", {}).get("sha256") != raw_sha:
        raise AttachError("source_hash_mismatch")
    compat = assess(observation, receipt)
    if not compat.ok:
        raise AttachError("receipt_mismatch")
    artifacts = observation.get("artifacts")
    if not isinstance(artifacts, list):
        raise AttachError("artifact_missing")
    seen: dict[str, bytes] = {}
    for item in artifacts:
        if not isinstance(item, dict) or not isinstance(item.get("relative_path"), str):
            raise AttachError("artifact_missing")
        relative = item["relative_path"]
        _artifact_name(relative, raw_name)
        blob = _read_file(bundle, relative, limit)
        if hashlib.sha256(blob).hexdigest() != item.get("sha256") or item.get("size") != len(blob):
            raise AttachError("artifact_hash_mismatch")
        seen[relative] = blob
    if seen.get(raw_name) != raw:
        raise AttachError("artifact_hash_mismatch")
    projected_files = {str(name): content for name, content in files.items()}
    for name, content in projected_files.items():
        if not isinstance(content, bytes) or seen.get(name) != content:
            raise AttachError("script_mismatch")
    for name, blob in seen.items():
        if name != raw_name and projected_files.get(name) != blob:
            raise AttachError("script_mismatch")
    ready: bytes | None = None
    ready_path = bundle / "ready.json"
    if ready_path.exists() or ready_path.is_symlink():
        ready = _read_file(bundle, "ready.json", _MAX_READY)
    copies = {
        "fxapk-rea-bundle.json": marker,
        "observation.json": observation_bytes,
        raw_name: raw,
    }
    for name, blob in seen.items():
        if name != raw_name:
            copies[name] = blob
    if ready is not None:
        copies["ready.json"] = ready
    if compat.changed:
        copies["observation-reprojected.json"] = _canonical(receipt)
        copies["projection-record.json"] = _canonical(
            {
                "schema_version": "fxapk-observation-projection-record/1",
                "base_schema_version": schema,
                "coverage_status": "partial",
                "certification_upgraded": False,
                "gap_reordered": compat.gap_reordered,
                "added_paths": compat.added_paths,
                "legacy_frame_paths": compat.legacy_frame_paths,
                "compatibility_gap": "legacy_script_frame_id" if compat.legacy_frame_paths else "",
            }
        )
    return {
        "schema": schema,
        "provider": _PROVIDERS[schema],
        "raw_sha": raw_sha,
        "receipt": receipt,
        "copies": copies,
        "binding": _binding(schema, receipt),
    }


def _counts(receipt: dict[str, Any], copies: dict[str, bytes]) -> dict[str, int]:
    requests = receipt.get("requests")
    request_count = len(requests) if isinstance(requests, list) else 0
    async_count = 0
    if isinstance(requests, list):
        for item in requests:
            if not isinstance(item, dict):
                continue
            hops = item.get("hops")
            hop_async = isinstance(hops, list) and any(
                isinstance(hop, dict) and hop.get("async_parent_present") is True for hop in hops
            )
            if item.get("async_parent_present") is True or hop_async:
                async_count += 1
    actions = receipt.get("actions")
    scripts = [name for name in copies if _SCRIPT_NAME.fullmatch(name)]
    return {
        "request_count": request_count,
        "script_count": len(scripts),
        "async_count": async_count,
        "action_count": len(actions) if isinstance(actions, list) else 0,
    }


def _entry(
    verified: dict[str, Any], identity: str, context: dict[str, Any] | None
) -> dict[str, Any]:
    receipt = verified["receipt"]
    coverage = receipt.get("coverage") if isinstance(receipt.get("coverage"), dict) else {}
    gaps, unknown = classify_gaps(coverage.get("gaps"))
    counts = _counts(receipt, verified["copies"])
    sha = verified["raw_sha"]
    if context is not None:
        context["relative_path"] = f"external_observations/{sha}/context-record.json"
    return {
        "schema_version": "fxapk-web-observation-attachment/1",
        "provider": verified["provider"],
        "source_sha256": sha,
        "bundle_relative_path": f"external_observations/{sha}/",
        "request_count": counts["request_count"],
        "script_count": counts["script_count"],
        "async_count": counts["async_count"],
        "action_count": counts["action_count"],
        "identity": identity,
        "coverage_status": "partial",
        "gaps": gaps,
        "unclassified_gap_count": unknown,
        "bundle_integrity_checked": True,
        "provenance_authenticated": False,
        "target_app_attribution_verified": False,
        "click_attribution_verified": False,
        "closure_evaluated": False,
        "context_record": context,
    }


def _canonical(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode(
        "utf-8"
    )


# 当前验证可以补出的派生投影。旧目录里没有它们时，只允许在新目录追加，
# 且追加前旧清单必须逐字节覆盖当时列出的原始文件。
# 旧清单已经登记的派生文件保持磁盘字节，不用当前投影覆盖。
_DERIVED_PROJECTION = frozenset({
    "observation-reprojected.json",
    "projection-record.json",
})
_RECORD_REQUIRED = frozenset({
    "schema_version",
    "base_schema_version",
    "coverage_status",
    "certification_upgraded",
    "gap_reordered",
    "added_paths",
})
_RECORD_OPTIONAL = frozenset({"legacy_frame_paths", "compatibility_gap"})


def _historical_derivatives(
    blobs: dict[str, bytes], verified: dict[str, Any], compat: Any
) -> None:
    """旧派生文件只证明当时的兼容形状，不能充当当前回执或认证。"""
    receipt = verified["receipt"]
    schema = verified["schema"]
    raw_sha = verified["raw_sha"]
    reprojected = blobs.get("observation-reprojected.json")
    if reprojected is not None:
        projected = _loads(reprojected, len(reprojected))
        if not isinstance(projected, dict):
            raise AttachError("existing_observation_mismatch")
        for flag in FLAGS:
            if projected.get(flag) is not False:
                raise AttachError("existing_observation_mismatch")
        coverage = projected.get("coverage")
        source = projected.get("source")
        if (
            not isinstance(coverage, dict)
            or coverage.get("status") != "partial"
            or not isinstance(source, dict)
            or source.get("sha256") != raw_sha
            or source.get("relative_path") != _RAW_NAMES[schema]
        ):
            raise AttachError("existing_observation_mismatch")
        if not assess(projected, receipt).ok:
            raise AttachError("existing_observation_mismatch")
    record_bytes = blobs.get("projection-record.json")
    if record_bytes is None:
        return
    record = _loads(record_bytes, len(record_bytes))
    if not isinstance(record, dict):
        raise AttachError("existing_observation_mismatch")
    unknown = set(record) - _RECORD_REQUIRED - _RECORD_OPTIONAL
    if unknown or not _RECORD_REQUIRED <= set(record):
        raise AttachError("existing_observation_mismatch")
    if (
        record.get("schema_version") != "fxapk-observation-projection-record/1"
        or record.get("base_schema_version") != schema
        or record.get("coverage_status") != "partial"
        or record.get("certification_upgraded") is not False
        or record.get("gap_reordered") is not compat.gap_reordered
    ):
        raise AttachError("existing_observation_mismatch")
    added = record.get("added_paths")
    if not isinstance(added, list) or any(not isinstance(item, str) for item in added):
        raise AttachError("existing_observation_mismatch")
    allowed = set(compat.added_paths)
    allowed.update(f"{path}/script_frame_id" for path in compat.legacy_frame_paths)
    if any(item not in allowed for item in added):
        raise AttachError("existing_observation_mismatch")
    if "legacy_frame_paths" in record and record["legacy_frame_paths"] != compat.legacy_frame_paths:
        raise AttachError("existing_observation_mismatch")
    expected_gap = "legacy_script_frame_id" if compat.legacy_frame_paths else ""
    if "compatibility_gap" in record and record["compatibility_gap"] != expected_gap:
        raise AttachError("existing_observation_mismatch")


def _manifest(sha: str, copies: dict[str, bytes]) -> bytes:
    rows = [
        {
            "relative_path": name,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "size": len(blob),
        }
        for name, blob in sorted(copies.items())
    ]
    payload = {
        "schema_version": "fxapk-web-observation-manifest/1",
        "source_sha256": sha,
        "bundle_relative_path": f"external_observations/{sha}/",
        "files": rows,
    }
    return _canonical(payload)


def _disk_names(root: Path) -> set[str]:
    names: set[str] = set()
    _reject_link(root)
    for child in root.iterdir():
        _reject_link(child)
        if child.is_file():
            names.add(child.name)
            continue
        if child.name != "scripts" or not child.is_dir():
            raise AttachError("unexpected_artifact")
        for script in child.iterdir():
            _reject_link(script)
            if not script.is_file():
                raise AttachError("unexpected_artifact")
            names.add(f"scripts/{script.name}")
    return names


def _row_set(rows: object) -> set[tuple[str, str, int]]:
    if not isinstance(rows, list):
        raise AttachError("existing_observation_unverified")
    seen: set[tuple[str, str, int]] = set()
    paths: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"relative_path", "sha256", "size"}:
            raise AttachError("existing_observation_unverified")
        name = row.get("relative_path")
        digest = row.get("sha256")
        size = row.get("size")
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or _HEX.fullmatch(digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or name in paths
        ):
            raise AttachError("existing_observation_unverified")
        paths.add(name)
        seen.add((name, digest, size))
    return seen


def _existing(
    report_path: Path, entries: object, new_sha: str, report_sample: object
) -> tuple[list[tuple[dict[str, Any], dict[str, bytes]]], int]:
    if entries is None:
        return [], 0
    if not isinstance(entries, list):
        raise AttachError("web_observations_malformed")
    if len(entries) >= _MAX_OBSERVATIONS:
        raise AttachError("oversize")
    parent = report_path.parent
    prepared: list[tuple[dict[str, Any], dict[str, bytes]]] = []
    seen: set[str] = set()
    total = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise AttachError("existing_observation_unverified")
        sha = entry.get("source_sha256")
        relative = entry.get("bundle_relative_path")
        claimed = entry.get("manifest_sha256")
        if (
            not isinstance(sha, str)
            or _HEX.fullmatch(sha) is None
            or relative != f"external_observations/{sha}/"
            or not isinstance(claimed, str)
            or _HEX.fullmatch(claimed) is None
        ):
            raise AttachError("existing_observation_unverified")
        if sha == new_sha or sha in seen:
            raise AttachError("duplicate_observation")
        seen.add(sha)
        root = parent / "external_observations" / sha
        _reject_link(root)
        if not root.is_dir():
            raise AttachError("existing_observation_unverified")
        manifest_bytes = _read_file(parent, f"external_observations/{sha}/manifest.json", _MAX_OBSERVATION)
        if hashlib.sha256(manifest_bytes).hexdigest() != claimed:
            raise AttachError("existing_observation_mismatch")
        manifest = _loads(manifest_bytes, _MAX_OBSERVATION)
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"schema_version", "source_sha256", "bundle_relative_path", "files"}
            or manifest.get("schema_version") != "fxapk-web-observation-manifest/1"
            or manifest.get("source_sha256") != sha
            or manifest.get("bundle_relative_path") != relative
        ):
            raise AttachError("existing_observation_unverified")
        listed = _row_set(manifest.get("files"))
        if len(listed) > _MAX_FILES:
            raise AttachError("oversize")
        names = {name for name, _digest, _size in listed}
        if _disk_names(root) != names | {"manifest.json"}:
            raise AttachError("existing_observation_mismatch")
        verified = _verify_bundle(root)
        if verified["raw_sha"] != sha:
            raise AttachError("existing_observation_mismatch")
        identity, context_bytes, context_pointer = "unknown", None, None
        if "context-record.json" in names:
            context_bytes = _read_file(
                parent, f"external_observations/{sha}/context-record.json", _MAX_CONTEXT
            )
            identity, _raw, context_pointer = _check_context(
                root / "context-record.json",
                report_sample,
                *verified["binding"],
            )
            if context_bytes != _raw:
                raise AttachError("existing_observation_mismatch")
        elif entry.get("identity") != "unknown" or entry.get("context_record") is not None:
            raise AttachError("existing_observation_unverified")
        copies = dict(verified["copies"])
        if context_bytes is not None:
            copies["context-record.json"] = context_bytes
        listed_blobs: dict[str, bytes] = {}
        reserved = 0
        for name, digest, size in listed:
            if size > _MAX_ATTACHMENT_BYTES - total - reserved:
                raise AttachError("oversize")
            if name not in _DERIVED_PROJECTION:
                verified_blob = copies.get(name)
                if (
                    not isinstance(verified_blob, bytes)
                    or len(verified_blob) != size
                    or hashlib.sha256(verified_blob).hexdigest() != digest
                ):
                    raise AttachError("existing_observation_mismatch")
                listed_blobs[name] = verified_blob
                reserved += size
                continue
            blob = _read_file(parent, f"external_observations/{sha}/{name}", size)
            if hashlib.sha256(blob).hexdigest() != digest or len(blob) != size:
                raise AttachError("existing_observation_mismatch")
            listed_blobs[name] = blob
            reserved += size
        originals: dict[str, bytes] = {}
        historical: dict[str, bytes] = {}
        for name, blob in listed_blobs.items():
            if name in _DERIVED_PROJECTION:
                historical[name] = blob
            elif copies.get(name) != blob:
                raise AttachError("existing_observation_mismatch")
            else:
                originals[name] = blob
        for name in copies:
            if name not in originals and name not in _DERIVED_PROJECTION:
                raise AttachError("existing_observation_mismatch")
        saved_observation = originals.get("observation.json")
        if saved_observation is None:
            raise AttachError("existing_observation_mismatch")
        saved_payload = _loads(saved_observation, len(saved_observation))
        if not isinstance(saved_payload, dict):
            raise AttachError("existing_observation_mismatch")
        compat = assess(saved_payload, verified["receipt"])
        if not compat.ok:
            raise AttachError("existing_observation_mismatch")
        _historical_derivatives(historical, verified, compat)
        stored = {**originals, **historical}
        if _manifest(sha, stored) != manifest_bytes:
            raise AttachError("existing_observation_mismatch")
        rebuilt = _entry(verified, identity, context_pointer)
        rebuilt["manifest_sha256"] = claimed
        if rebuilt != entry:
            raise AttachError("existing_observation_unverified")
        published = dict(stored)
        derived = {
            name: copies[name]
            for name in _DERIVED_PROJECTION
            if name not in historical and name in copies
        }
        published.update(derived)
        if derived:
            published["manifest.json"] = _manifest(sha, {**stored, **derived})
            rebuilt["manifest_sha256"] = hashlib.sha256(published["manifest.json"]).hexdigest()
        else:
            published["manifest.json"] = manifest_bytes
        total += sum(len(blob) for blob in published.values())
        if total > _MAX_ATTACHMENT_BYTES:
            raise AttachError("oversize")
        prepared.append((rebuilt, published))
    return prepared, total


def _parsed_web_trees(
    report: Path, payload: dict[str, Any], excluded: set[str], new_sha: str
) -> list[tuple[str, dict[str, bytes]]]:
    from apkscan.core.web_supplement_report import (
        SupplementRefusal,
        _accepted_files,
        _bounded_files,
        _referenced_trees,
    )

    groups: list[tuple[str, dict[str, bytes]]] = []
    try:
        trees = _referenced_trees(payload, report.parent)
        for sha, root in trees:
            if sha in excluded:
                continue
            if sha == new_sha:
                raise AttachError("duplicate_observation")
            verified = _verify_bundle(root)
            if verified["raw_sha"] != sha:
                raise AttachError("existing_observation_mismatch")
            groups.append((sha, _accepted_files(sha, verified["copies"], _bounded_files(root))))
    except SupplementRefusal as exc:
        raise AttachError(exc.reason) from None
    return groups


def _publish_tree(out: Path, groups: list[tuple[str, dict[str, bytes]]]) -> None:
    for sha, copies in groups:
        root = out / "external_observations" / sha
        root.mkdir(parents=True, exist_ok=False)
        for name, blob in copies.items():
            target = root.joinpath(*_safe_parts(name))
            target.parent.mkdir(parents=True, exist_ok=True)
            if not atomic_create_bytes(target, blob):
                raise AttachError("publish_failed")


def _write_new(path: Path, blob: bytes) -> None:
    if not atomic_create_bytes(path, blob):
        raise AttachError("publish_failed")


def attach(
    bundle: Path,
    report: Path,
    out: Path,
    context_record: Path | None = None,
) -> dict[str, Any]:
    """验证 bundle 后写入新目录。失败时不留下 report.json。"""
    bundle, report, out = Path(bundle), Path(report), Path(out)
    if context_record is not None:
        context_record = Path(context_record)
    for path in (bundle, report, out):
        if _is_link(path):
            raise AttachError("link_escape")
    if out.exists():
        raise AttachError("output_exists")
    verified = _verify_bundle(bundle)
    report_bytes = _read_limited(report, _MAX_REPORT)
    payload = _loads(report_bytes, _MAX_REPORT)
    if not isinstance(payload, dict) or not isinstance(payload.get("meta"), dict):
        raise AttachError("report_meta_missing")
    native_files = _preserved_native(report, payload)
    dex_files = _preserved_dex_receipts(report, payload)
    meta: dict[str, Any] = payload["meta"]
    identity, context_bytes, context_pointer = _check_context(
        context_record,
        meta.get("sample_sha256"),
        *verified["binding"],
    )
    kept, kept_bytes = _existing(
        report, meta.get("web_observations"), verified["raw_sha"], meta.get("sample_sha256")
    )
    extras = _parsed_web_trees(
        report,
        payload,
        {item["source_sha256"] for item, _blobs in kept},
        verified["raw_sha"],
    )
    extra_bytes = sum(len(blob) for _sha, blobs in extras for blob in blobs.values())
    entry = _entry(verified, identity, context_pointer)
    copies = dict(verified["copies"])
    if context_bytes is not None:
        copies["context-record.json"] = context_bytes
    manifest = _manifest(verified["raw_sha"], copies)
    entry["manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
    copies["manifest.json"] = manifest
    if kept_bytes + extra_bytes + sum(len(blob) for blob in copies.values()) > _MAX_ATTACHMENT_BYTES:
        raise AttachError("oversize")
    meta["web_observations"] = [item for item, _blobs in kept] + [entry]
    encoded_report = (
        json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")
    from apkscan.core.report_io import report_from_dict
    from apkscan.report.digest import build_digest
    from apkscan.report.html import render_to_string

    try:
        digest_bytes = (
            json.dumps(build_digest(payload), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        ).encode("utf-8")
        html_bytes = render_to_string(report_from_dict(payload)).encode("utf-8")
    except AttachError:
        raise
    except Exception:
        logger.exception("attached report render failed")
        raise AttachError("report_render_failed") from None
    if out.exists():
        raise AttachError("output_exists")
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise AttachError("output_exists") from None
    groups = [(verified["raw_sha"], copies)]
    groups.extend(extras)
    groups.extend((item["source_sha256"], blobs) for item, blobs in kept)
    _publish_tree(out, groups)
    _publish_native(out, native_files)
    _publish_native(out, dex_files)
    return _finish(out, verified, identity, encoded_report, digest_bytes, html_bytes)


def _preserved_dex_receipts(report: Path, payload: dict[str, Any]) -> list[tuple[str, bytes]]:
    """核验 dex-query 回执后再发布。没有 dex_query 时不改变 attach。"""
    meta = payload.get("meta")
    if not isinstance(meta, dict) or "dex_query" not in meta:
        return []
    from apkscan.core.dex_query import DexQueryError, collect_receipt_files

    try:
        collected = collect_receipt_files(report.parent, meta)
    except DexQueryError as exc:
        raise AttachError(exc.reason) from None
    return list(collected.items())


def _preserved_native(report: Path, payload: dict[str, Any]) -> list[tuple[str, bytes]]:
    """Copy native recovery files and input snapshots. PCAP stays at source_artifact_base."""
    from fxapk_rea import native as native_mod

    try:
        copied = list(native_mod._read_history(report, payload))
        copied.extend(native_mod._snapshot_chain(report, payload))
    except native_mod.NativeError as exc:
        raise AttachError("history_snapshot_mismatch") from exc
    _align_native_history(payload, copied)
    return copied


def _align_native_history(payload: dict[str, Any], copied: list[tuple[str, bytes]]) -> None:
    """Reject contradictory history flags before any output directory is created."""
    from apkscan.core.native_handoff import reconcile_native_history_item

    meta = payload.get("meta")
    if not isinstance(meta, dict):
        return
    history = meta.get("native_recovery")
    if not isinstance(history, list):
        return
    by_path = {relative: blob for relative, blob in copied}
    for item in history:
        if not isinstance(item, dict):
            continue
        relative = _history_result_path(item)
        raw = by_path.get(relative) if relative is not None else None
        if raw is None:
            raise AttachError("result_mismatch")
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise AttachError("result_mismatch") from None
        try:
            reconcile_native_history_item(item, result)
        except ValueError:
            raise AttachError("result_mismatch") from None


def _history_result_path(item: dict[str, Any]) -> str | None:
    files = item.get("files")
    if isinstance(files, list):
        for entry in files:
            path = entry.get("path") if isinstance(entry, dict) else None
            if isinstance(path, str) and path.endswith("/result.json"):
                return path
    digest = item.get("content_digest")
    if isinstance(digest, str):
        return f"native_recovery/{digest}/result.json"
    return None


def _publish_native(out: Path, files: list[tuple[str, bytes]]) -> None:
    for relative, blob in files:
        if not isinstance(relative, str) or "\\" in relative or relative.startswith("/"):
            raise AttachError("link_escape")
        parts = relative.split("/")
        if ".." in parts or not parts:
            raise AttachError("link_escape")
        target = out.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.resolve().is_relative_to(out.resolve()):
            raise AttachError("link_escape")
        _write_new(target, blob)


def attach_command(
    bundle: Path = typer.Option(..., "--bundle"),
    report: Path = typer.Option(..., "--report"),
    out: Path = typer.Option(..., "--out"),
    context_record: Path | None = typer.Option(None, "--context-record"),
) -> None:
    """离线核验观察副本并挂到报告的新目录。不访问设备或网络。"""
    try:
        summary = attach(bundle, report, out, context_record=context_record)
    except AttachError as exc:
        typer.echo(json.dumps({"status": "failed", "reason": str(exc)}))
        raise typer.Exit(1) from None
    except OSError:
        typer.echo(json.dumps({"status": "failed", "reason": "evidence_io_failed"}))
        raise typer.Exit(1) from None
    typer.echo(json.dumps(summary, ensure_ascii=False))


def register_attach(rea_app: Any) -> None:
    """把 attach 命令挂到调用方给出的 Typer 应用。本模块不改插件入口。"""
    rea_app.command("attach")(attach_command)


def _finish(
    out: Path,
    verified: dict[str, Any],
    identity: str,
    encoded_report: bytes,
    digest_bytes: bytes,
    html_bytes: bytes,
) -> dict[str, Any]:
    _write_new(out / "report.digest.json", digest_bytes)
    _write_new(out / "report.html", html_bytes)
    _write_new(out / "report.json", encoded_report)
    return {
        "status": "ok",
        "source_sha256": verified["raw_sha"],
        "bundle_relative_path": f"external_observations/{verified['raw_sha']}/",
        "identity": identity,
        "closure_evaluated": False,
        "provenance_authenticated": False,
    }
