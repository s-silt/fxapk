"""Supplement an existing canonical report without a second analysis pipeline.

The command reuses ``apply_static`` for provider, parse, and merge. Typed objects
are only a delta workspace. Unknown raw fields stay on the deep-copied payload.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from apkscan.core.atomic import atomic_create_bytes, atomic_write_text
from apkscan.core.bounded_io import read_limited
from apkscan.core.json_contract import parse_finite_json_float, reject_nonfinite_json_constant
from apkscan.core.web_observation_plan import _json_too_deep
from apkscan.core.models import (
    ADVICE_REVIEW,
    ANALYSIS_STATUS_COMPLETE,
    REPORT_SCHEMA_VERSION,
    AnalysisConfig,
    Confidence,
    Endpoint,
    Evidence,
    EvidenceScope,
    Finding,
    Lead,
    LeadCategory,
    Report,
    Severity,
)
from apkscan.core.report_schema import UnsupportedReportSchema, ensure_writable_report_version
from apkscan.core.web_observation_plan import load_config_path, parse_config
from apkscan.core.web_supplement import apply_static, restore_held_endpoints
from apkscan.report.json import _to_jsonable

logger = logging.getLogger(__name__)

META_WRITE_OWNER = "core.web_supplement_report"
META_WRITE_CATEGORIES = {
    "closure": "signal",
    "supplement_web_input": "record",
    "web_supplement_runtime": "record",
}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)

_SHA = re.compile(r"^[0-9a-f]{64}$")
_SNAPSHOT_REL = re.compile(r"^input_report/([0-9a-f]{64})/report\.json$")
_NATIVE_REL = re.compile(
    r"^native_recovery/([0-9a-f]{64})/"
    r"(manifest\.json|recipe\.json|result\.json|binary\.bin|"
    r"dossier/(?:stdout\.bin|stderr\.bin|inspect-manifest\.json|execution\.json|provenance\.json))$"
)
_SNAPSHOT_KEYS = ("supplement_web_input", "native_recovery_input")
_NATIVE_REQUIRED = frozenset({
    "manifest.json",
    "recipe.json",
    "result.json",
    "binary.bin",
    "dossier/stdout.bin",
    "dossier/stderr.bin",
    "dossier/inspect-manifest.json",
    "dossier/execution.json",
    "dossier/provenance.json",
})
_REF = re.compile(r"external_observations/([0-9a-f]{64})/")
_MAX_FILES = 128
_MAX_BYTES = 32 * 1024 * 1024
_MAX_NATIVE_FILE_BYTES = 64 * 1024 * 1024
_MAX_NATIVE_HISTORY_BYTES = 256 * 1024 * 1024
_MAX_DEPTH = 8
_MAX_JSON_DEPTH = 32
_MAX_ANCESTORS = 4096
_MAX_TREES = 32
_EXTRA_NAMES = frozenset({"manifest.json", "context-record.json"})
_MANIFEST_KEYS = frozenset({
    "schema_version", "source_sha256", "bundle_relative_path", "files",
})


class SupplementRefusal(Exception):
    """Caller input cannot be supplemented. No report is written."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def supplement_report(report_path: Path, config_path: Path, out_dir: Path) -> dict[str, Any]:
    """Write a new report directory. Return status counts and an exit code.

    Exit 0 is an executed result, including a duplicate raw hash. Exit 2 is a
    refusal. Exit 1 is a provider or parse failure with an honest receipt when
    the new report could be written. Exit 3 is an honest non-execution (off or
    skipped) that is not a duplicate.
    """
    original = _read_report_bytes(report_path)
    payload = _payload(original)
    request, rejected = _request(config_path)
    if request is None:
        raise SupplementRefusal(rejected or "config_rejected")
    meta = payload.get("meta")
    if not isinstance(meta, dict):
        raise SupplementRefusal("invalid_report")
    prior_snapshots = _prepare_prior_snapshots(report_path, payload)
    native_files = _prepare_native_history(report_path, payload)
    endpoints, endpoint_rows = _endpoints(payload.get("endpoints"))
    leads, lead_rows = _leads(payload.get("leads"))
    findings, finding_rows = _findings(payload.get("findings"))
    _verify_attachment_claims(payload, report_path.parent)
    trees = _referenced_trees(payload, report_path.parent)
    _reject_output(out_dir, report_path, request.path)
    _reject_output_under_trees(out_dir, [root for _sha, root in trees])
    verified_files = _reverify_trees(trees)
    prior_leads = {id(item) for item in leads}
    prior_findings = {id(item) for item in findings}
    endpoint_map = {id(item): row for item, row in zip(endpoints, endpoint_rows, strict=True)}
    lead_map = {id(item): row for item, row in zip(leads, lead_rows, strict=True)}
    finding_map = {id(item): row for item, row in zip(findings, finding_rows, strict=True)}
    try:
        out_dir.mkdir(parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise SupplementRefusal("output_exists") from exc
    except OSError as exc:
        logger.exception("[supplement-web] output directory rejected")
        raise SupplementRefusal("output_rejected") from exc
    prior_evidence = {
        id(evidence)
        for collection in (endpoints, leads, findings)
        for item in collection
        for evidence in _typed_evidence(item)
    }
    closure_before = _clone(meta.get("closure"))
    runtime_before = _clone(meta.get("web_supplement_runtime"))
    plan_before = meta.get("web_observation_plan")
    state = SimpleNamespace(
        config=AnalysisConfig(
            online=False,
            out_dir=str(out_dir),
            web_supplement=str(config_path),
        ),
        platform=_platform(meta),
        meta=meta,
        endpoints=endpoints,
        leads=leads,
        findings=findings,
    )
    before_endpoint_count = len(endpoints)
    before_lead_count = len(leads)
    try:
        apply_static(state)
    except Exception as exc:
        logger.exception("[supplement-web] supplement stage failed")
        raise SupplementRefusal("parse_failed") from exc
    restore_held_endpoints(state)
    _grade_new_leads(state.leads, prior_leads)
    _grade_new_findings(state.findings, prior_findings)
    if closure_before != meta.get("closure"):
        if closure_before is None:
            meta.pop("closure", None)
        else:
            meta["closure"] = closure_before
    if runtime_before != meta.get("web_supplement_runtime"):
        if runtime_before is None:
            meta.pop("web_supplement_runtime", None)
        else:
            meta["web_supplement_runtime"] = runtime_before
    _keep_unknown_plan_fields(meta, plan_before)
    _write_collections(
        payload,
        state,
        endpoint_rows,
        lead_rows,
        finding_rows,
        prior_evidence,
        endpoint_map,
        lead_map,
        finding_map,
    )
    _place_trees(out_dir, verified_files)
    _place_prior_snapshots(out_dir, prior_snapshots)
    _place_native_history(out_dir, native_files)
    snapshot = _snapshot_input(out_dir, original, report_path)
    meta["supplement_web_input"] = snapshot
    written = _emit(payload, state, out_dir)
    status, reason = _receipt_status(meta)
    exit_code = _exit_code(status, reason)
    return {
        "exit_code": exit_code,
        "status": status,
        "reason": reason,
        "endpoints_added": max(0, len(state.endpoints) - before_endpoint_count),
        "leads_added": max(0, len(state.leads) - before_lead_count),
        "report": str(written),
        "live_cdp": _live_cdp(meta),
    }


def _is_reparse(path: Path) -> bool:
    """symlink、junction 和其他 Windows reparse point 都算链接。"""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    if getattr(info, "st_reparse_tag", 0):
        return True
    probe = getattr(path, "is_junction", None)
    return bool(probe and probe())


def _reject_reparse_ancestors(path: Path) -> None:
    """拒绝路径上任一已存在组件的链接，并拒绝祖先环。

    到不了根、或同一设备号/inode 再次出现，都是失败，不在固定层数后放行。
    """
    current = path
    seen: set[tuple[int, int]] = set()
    for _ in range(_MAX_ANCESTORS):
        if current.exists() or current.is_symlink() or _is_reparse(current):
            if _is_reparse(current):
                raise SupplementRefusal("link_escape")
            try:
                info = os.lstat(current)
            except OSError as exc:
                raise SupplementRefusal("link_escape") from exc
            key = (int(info.st_dev), int(info.st_ino))
            if key in seen:
                raise SupplementRefusal("link_escape")
            seen.add(key)
        parent = current.parent
        if parent == current:
            return
        current = parent
    raise SupplementRefusal("link_escape")


def _read_capped(path: Path, reason: str) -> bytes:
    try:
        if _is_reparse(path) or not path.is_file():
            raise SupplementRefusal(reason)
        with path.open("rb") as stream:
            blob = read_limited(stream, _MAX_BYTES)
    except SupplementRefusal:
        raise
    except OSError as exc:
        logger.exception("[supplement-web] bounded read failed")
        raise SupplementRefusal(reason) from exc
    if len(blob) > _MAX_BYTES:
        raise SupplementRefusal("oversize")
    return blob


def _read_report_bytes(path: Path) -> bytes:
    _reject_reparse_ancestors(path)
    return _read_capped(path, "invalid_report")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _loads_strict(blob: bytes) -> Any:
    if _json_too_deep(blob, _MAX_JSON_DEPTH):
        raise SupplementRefusal("invalid_report")
    try:
        parsed = json.loads(
            blob.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=reject_nonfinite_json_constant,
            parse_float=parse_finite_json_float,
        )
    except SupplementRefusal:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise SupplementRefusal("invalid_report") from exc
    return parsed


def _payload(blob: bytes) -> dict[str, Any]:
    parsed = _loads_strict(blob)
    if not isinstance(parsed, dict):
        raise SupplementRefusal("invalid_report")
    try:
        ensure_writable_report_version(parsed.get("schema_version"))
    except UnsupportedReportSchema as exc:
        raise SupplementRefusal("unsupported_report") from exc
    return parsed


def _request(path: Path) -> tuple[Any, str]:
    try:
        if path.is_symlink() or not path.is_file():
            return None, "config_rejected"
        loaded = load_config_path(str(path))
    except (OSError, ValueError) as exc:
        logger.warning("[supplement-web] config rejected: %s", type(exc).__name__)
        return None, "config_rejected"
    request, rejected = parse_config(loaded if isinstance(loaded, dict) else {"invalid": True})
    if request is None:
        return None, rejected or "config_rejected"
    return request, ""


def _safe_resolve(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SupplementRefusal("link_escape") from exc


def _within(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def _reject_output(out_dir: Path, report_path: Path, material: str) -> None:
    if out_dir.exists() or _is_reparse(out_dir):
        raise SupplementRefusal("output_exists")
    _reject_reparse_ancestors(out_dir)
    _reject_reparse_ancestors(report_path)
    resolved = _safe_resolve(out_dir)
    report_resolved = _safe_resolve(report_path)
    if resolved == report_resolved:
        raise SupplementRefusal("output_nested")
    if material:
        source = Path(material)
        _reject_reparse_ancestors(source)
        source_resolved = _safe_resolve(source)
        if _within(resolved, source_resolved):
            raise SupplementRefusal("output_nested")
    observations = report_path.parent / "external_observations"
    if observations.exists() or _is_reparse(observations):
        _reject_reparse_ancestors(observations)
        if _within(resolved, _safe_resolve(observations)):
            raise SupplementRefusal("output_nested")


def _reject_output_under_trees(out_dir: Path, roots: list[Path]) -> None:
    resolved = _safe_resolve(out_dir)
    for root in roots:
        _reject_reparse_ancestors(root)
        if _is_reparse(root):
            raise SupplementRefusal("link_escape")
        if _within(resolved, _safe_resolve(root)):
            raise SupplementRefusal("output_nested")


def _referenced_trees(payload: dict[str, Any], base: Path) -> list[tuple[str, Path]]:
    found: list[str] = []
    _collect_refs(payload, found)
    ordered: list[str] = []
    for sha in found:
        if sha not in ordered:
            ordered.append(sha)
    if len(ordered) > _MAX_TREES:
        raise SupplementRefusal("oversize")
    trees: list[tuple[str, Path]] = []
    observations = (base / "external_observations").resolve(strict=False)
    for sha in ordered:
        if _SHA.fullmatch(sha) is None:
            raise SupplementRefusal("invalid_report")
        root = base / "external_observations" / sha
        _reject_reparse_ancestors(root)
        if _is_reparse(root):
            raise SupplementRefusal("link_escape")
        resolved = _safe_resolve(root)
        if observations not in resolved.parents:
            raise SupplementRefusal("link_escape")
        if not root.is_dir():
            raise SupplementRefusal("missing_observation")
        trees.append((sha, root))
    return trees


def _collect_refs(node: object, found: list[str]) -> None:
    if isinstance(node, str):
        found.extend(_REF.findall(node))
        return
    if isinstance(node, dict):
        for value in node.values():
            _collect_refs(value, found)
        return
    if isinstance(node, list):
        for value in node:
            _collect_refs(value, found)


def _reverify_trees(trees: list[tuple[str, Path]]) -> list[tuple[str, dict[str, bytes]]]:
    if not trees:
        return []
    plugin = _plugin()
    if plugin is None:
        raise SupplementRefusal("unsupported_prior_artifact")
    checked: list[tuple[str, dict[str, bytes]]] = []
    for sha, root in trees:
        try:
            result = plugin.run_supplement({"source": "bundle", "path": str(root)})
        except Exception as exc:
            logger.exception("[supplement-web] prior bundle reverify failed")
            raise SupplementRefusal("tampered_observation") from exc
        if not isinstance(result, dict) or result.get("status") not in {"ok", "executed"}:
            raise SupplementRefusal("tampered_observation")
        verified = result.get("verified")
        if not isinstance(verified, dict) or verified.get("raw_sha") != sha:
            raise SupplementRefusal("source_hash_mismatch")
        copies = verified.get("copies")
        if not isinstance(copies, dict):
            raise SupplementRefusal("tampered_observation")
        disk = _bounded_files(root)
        files = _accepted_files(sha, copies, disk)
        checked.append((sha, files))
    return checked


def _plugin() -> Any | None:
    from apkscan.core import web_supplement

    try:
        plugins, _statuses = web_supplement.discover_plugins()
    except Exception:
        logger.exception("[supplement-web] plugin discovery failed")
        return None
    for plugin in plugins:
        if getattr(plugin, "name", "") == "rea" and callable(getattr(plugin, "run_supplement", None)):
            return plugin
    return None


def _bounded_files(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    total = 0
    _reject_reparse_ancestors(root)
    if _is_reparse(root):
        raise SupplementRefusal("link_escape")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        if _is_reparse(current):
            raise SupplementRefusal("link_escape")
        relative_dir = current.relative_to(root)
        if len(relative_dir.parts) > _MAX_DEPTH:
            raise SupplementRefusal("oversize")
        kept: list[str] = []
        for name in dirnames:
            child = current / name
            if _is_reparse(child) or not child.is_dir():
                raise SupplementRefusal("link_escape")
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            path = current / name
            if _is_reparse(path) or not path.is_file():
                raise SupplementRefusal("link_escape")
            relative = path.relative_to(root).as_posix()
            if ".." in Path(relative).parts or relative in files:
                raise SupplementRefusal("link_escape")
            if len(files) >= _MAX_FILES:
                raise SupplementRefusal("oversize")
            remaining = _MAX_BYTES - total
            blob = _read_capped_remaining(path, remaining)
            total += len(blob)
            files[relative] = blob
    return files


def _read_capped_remaining(path: Path, remaining: int) -> bytes:
    if remaining < 0:
        raise SupplementRefusal("oversize")
    try:
        with path.open("rb") as stream:
            blob = read_limited(stream, remaining)
    except OSError as exc:
        logger.exception("[supplement-web] observation read failed")
        raise SupplementRefusal("tampered_observation") from exc
    if len(blob) > remaining:
        raise SupplementRefusal("oversize")
    return blob


def _accepted_files(sha: str, copies: dict[str, Any], disk: dict[str, bytes]) -> dict[str, bytes]:
    expected: dict[str, bytes] = {}
    for name, blob in copies.items():
        if not isinstance(name, str) or not isinstance(blob, bytes) or ".." in Path(name).parts:
            raise SupplementRefusal("tampered_observation")
        expected[name] = blob
        if disk.get(name) != blob:
            raise SupplementRefusal("tampered_observation")
    extras = set(disk) - set(expected)
    if not extras:
        return dict(disk)
    if not extras <= _EXTRA_NAMES or "manifest.json" not in disk:
        raise SupplementRefusal("unexpected_artifact")
    _validate_manifest(sha, disk, expected)
    return dict(disk)


def _verify_attachment_claims(payload: dict[str, Any], base: Path) -> None:
    """核对报告里记录的 manifest 哈希和上下文绑定。此步不调用插件、不建目录。"""
    meta = payload.get("meta")
    if not isinstance(meta, dict):
        raise SupplementRefusal("invalid_report")
    entries = meta.get("web_observations")
    if entries is None:
        return
    if not isinstance(entries, list):
        raise SupplementRefusal("invalid_report")
    for entry in entries:
        if not isinstance(entry, dict):
            raise SupplementRefusal("invalid_report")
        sha = entry.get("source_sha256")
        relative = entry.get("bundle_relative_path")
        if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
            raise SupplementRefusal("invalid_report")
        if relative != f"external_observations/{sha}/":
            raise SupplementRefusal("source_hash_mismatch")
        root = base / "external_observations" / sha
        _reject_reparse_ancestors(root)
        if _is_reparse(root) or not root.is_dir():
            raise SupplementRefusal("missing_observation")
        manifest_path = root / "manifest.json"
        claimed = entry.get("manifest_sha256")
        manifest_on_disk = manifest_path.is_file() and not _is_reparse(manifest_path)
        if not manifest_on_disk and claimed is None:
            if entry.get("context_record") not in (None,):
                raise SupplementRefusal("tampered_observation")
            continue
        if (
            not manifest_on_disk
            or not isinstance(claimed, str)
            or _SHA.fullmatch(claimed) is None
        ):
            raise SupplementRefusal("source_hash_mismatch")
        blob = _read_capped(manifest_path, "tampered_observation")
        if hashlib.sha256(blob).hexdigest() != claimed:
            raise SupplementRefusal("source_hash_mismatch")
        disk = _bounded_files(root)
        _validate_manifest(sha, disk, {})
        _verify_context_binding(entry, root, meta, sha)


def _verify_context_binding(
    entry: dict[str, Any], root: Path, meta: dict[str, Any], sha: str,
) -> None:
    path = root / "context-record.json"
    present = path.is_file() and not _is_reparse(path)
    pointer = entry.get("context_record")
    if not present:
        if pointer is not None:
            raise SupplementRefusal("tampered_observation")
        return
    if not isinstance(pointer, dict):
        raise SupplementRefusal("tampered_observation")
    raw = _read_capped(path, "tampered_observation")
    expected = f"external_observations/{sha}/context-record.json"
    if (
        pointer.get("relative_path") != expected
        or pointer.get("sha256") != hashlib.sha256(raw).hexdigest()
        or pointer.get("sample_sha256_matches_report") is not True
        or pointer.get("target_binding_matches_bundle") is not True
    ):
        raise SupplementRefusal("source_hash_mismatch")
    parsed = _loads_strict(raw)
    if not isinstance(parsed, dict) or parsed.get("sample_sha256") != meta.get("sample_sha256"):
        raise SupplementRefusal("source_hash_mismatch")
    observation = root / "observation.json"
    if not observation.is_file() or _is_reparse(observation):
        raise SupplementRefusal("tampered_observation")
    observed = _loads_strict(_read_capped(observation, "tampered_observation"))
    bound = _observation_binding(observed)
    target_id = parsed.get("target_id")
    origin = parsed.get("origin")
    if bound is None or target_id != bound[0] or origin != bound[1]:
        raise SupplementRefusal("source_hash_mismatch")


def _observation_binding(payload: object) -> tuple[str, str] | None:
    if not isinstance(payload, dict):
        return None
    target = payload.get("target")
    if not isinstance(target, dict):
        target = payload.get("capture")
    if not isinstance(target, dict):
        return None
    target_id = target.get("target_id")
    origin = target.get("origin")
    if isinstance(target_id, str) and isinstance(origin, str):
        return target_id, origin
    return None


def _validate_manifest(sha: str, disk: dict[str, bytes], copies: dict[str, bytes]) -> None:
    try:
        manifest = _loads_strict(disk["manifest.json"])
    except SupplementRefusal as exc:
        raise SupplementRefusal("tampered_observation") from exc
    relative = f"external_observations/{sha}/"
    if (
        not isinstance(manifest, dict)
        or set(manifest) != _MANIFEST_KEYS
        or manifest.get("schema_version") != "fxapk-web-observation-manifest/1"
        or manifest.get("source_sha256") != sha
        or manifest.get("bundle_relative_path") != relative
    ):
        raise SupplementRefusal("source_hash_mismatch")
    rows = manifest.get("files")
    if not isinstance(rows, list):
        raise SupplementRefusal("tampered_observation")
    listed: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"relative_path", "sha256", "size"}:
            raise SupplementRefusal("tampered_observation")
        name = row.get("relative_path")
        digest = row.get("sha256")
        size = row.get("size")
        if not isinstance(name, str) or not isinstance(digest, str) or not isinstance(size, int):
            raise SupplementRefusal("tampered_observation")
        blob = disk.get(name)
        if blob is None or len(blob) != size or hashlib.sha256(blob).hexdigest() != digest:
            raise SupplementRefusal("tampered_observation")
        if name in copies and copies[name] != blob:
            raise SupplementRefusal("source_hash_mismatch")
        listed.add(name)
    if set(disk) - {"manifest.json"} != listed:
        raise SupplementRefusal("unexpected_artifact")
    if "context-record.json" in disk and "context-record.json" not in listed:
        raise SupplementRefusal("unsupported_prior_artifact")


def _platform(meta: dict[str, Any]) -> str:
    platform = meta.get("platform")
    if platform == "web":
        return "web"
    return "android"


def _require_rows(value: object, name: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SupplementRefusal("invalid_report")
    rows: list[Any] = []
    for item in value:
        if not isinstance(item, dict):
            raise SupplementRefusal("invalid_report")
        rows.append(item)
    if name and len(rows) > 100_000:
        raise SupplementRefusal("oversize")
    return rows


def _endpoints(value: object) -> tuple[list[Endpoint], list[dict[str, Any]]]:
    rows = _require_rows(value, "endpoints")
    typed: list[Endpoint] = []
    for row in rows:
        enrichment = row.get("enrichment")
        if enrichment is not None and not isinstance(enrichment, dict):
            raise SupplementRefusal("invalid_report")
        typed.append(Endpoint(
            value=str(row.get("value", "")),
            kind=str(row.get("kind", "")),
            evidences=_evidence_list(row.get("evidences")),
            is_cleartext=bool(row.get("is_cleartext", False)),
            is_private=bool(row.get("is_private", False)),
            is_suspicious=bool(row.get("is_suspicious", False)),
            enrichment=dict(enrichment) if isinstance(enrichment, dict) else {},
        ))
    return typed, rows


def _leads(value: object) -> tuple[list[Lead], list[dict[str, Any]]]:
    rows = _require_rows(value, "leads")
    typed: list[Lead] = []
    for row in rows:
        raw_category: str | None = None
        try:
            category = LeadCategory(str(row.get("category", "")))
        except ValueError:
            raw_category = str(row.get("category", ""))
            category = LeadCategory.UNKNOWN
        downgrades = row.get("downgrades")
        if downgrades is None:
            parsed_downgrades: dict[str, str] = {}
        elif not isinstance(downgrades, dict) or any(
            not isinstance(key, str) or not isinstance(item, str) for key, item in downgrades.items()
        ):
            raise SupplementRefusal("invalid_report")
        else:
            parsed_downgrades = dict(downgrades)
        obtain = row.get("evidence_to_obtain")
        if obtain is None:
            evidence_to_obtain: list[str] = []
        elif not isinstance(obtain, list) or any(not isinstance(item, str) for item in obtain):
            raise SupplementRefusal("invalid_report")
        else:
            evidence_to_obtain = list(obtain)
        raw_masquerade = row.get("sni_masquerade")
        if raw_masquerade is None:
            sni_masquerade: list[str] = []
        elif not isinstance(raw_masquerade, list) or any(
            not isinstance(item, str) for item in raw_masquerade
        ):
            raise SupplementRefusal("invalid_report")
        else:
            sni_masquerade = list(raw_masquerade)
        typed.append(Lead(
            category=category,
            value=str(row.get("value", "")),
            subject=str(row["subject"]) if row.get("subject") is not None else None,
            where_to_request=(
                str(row["where_to_request"]) if row.get("where_to_request") is not None else None
            ),
            evidence_to_obtain=evidence_to_obtain,
            confidence=_confidence(row.get("confidence")),
            source_refs=_evidence_list(row.get("source_refs")),
            notes=str(row.get("notes", "")),
            advice=str(row.get("advice", "")),
            shape_uncertain=row.get("shape_uncertain") is True,
            sni_masquerade=sni_masquerade,
            base_advice=row.get("base_advice") if isinstance(row.get("base_advice"), str) else None,
            downgrades=parsed_downgrades,
            legacy_effective_advice=(
                row.get("legacy_effective_advice")
                if isinstance(row.get("legacy_effective_advice"), str) else None
            ),
            raw_category=raw_category,
        ))
    return typed, rows


def _findings(value: object) -> tuple[list[Finding], list[dict[str, Any]]]:
    rows = _require_rows(value, "findings")
    typed: list[Finding] = []
    for row in rows:
        typed.append(Finding(
            id=str(row.get("id", "")),
            title=str(row.get("title", "")),
            severity=_severity(row.get("severity")),
            category=str(row.get("category", "")),
            description=str(row.get("description", "")),
            recommendation=str(row.get("recommendation", "")),
            evidences=_evidence_list(row.get("evidences")),
            references=_string_list(row.get("references")),
            analyzer=str(row.get("analyzer", "")),
            confidence=_confidence(row.get("confidence")),
            kind=str(row.get("kind", "inference")),
        ))
    return typed, rows


def _evidence_list(value: object) -> list[Evidence]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SupplementRefusal("invalid_report")
    evidences: list[Evidence] = []
    allowed = {item.value for item in EvidenceScope}
    for row in value:
        if not isinstance(row, dict):
            raise SupplementRefusal("invalid_report")
        raw_scope = row.get("scope")
        if raw_scope is None:
            scope = EvidenceScope.LEGACY_UNSPECIFIED
        elif not isinstance(raw_scope, str) or raw_scope not in allowed:
            raise SupplementRefusal("invalid_report")
        else:
            scope = EvidenceScope(raw_scope)
        observed = row.get("observed_at")
        if isinstance(observed, bool) or (
            observed is not None and not isinstance(observed, (int, float))
        ):
            raise SupplementRefusal("invalid_report")
        evidences.append(Evidence(
            source=str(row.get("source", "")),
            location=str(row.get("location", "")),
            snippet=str(row.get("snippet", "")),
            observed_at=float(observed) if isinstance(observed, (int, float)) else None,
            scope=scope,
        ))
    return evidences


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SupplementRefusal("invalid_report")
    return list(value)


def _confidence(value: object) -> Confidence:
    try:
        return Confidence(str(value or Confidence.MEDIUM.value))
    except ValueError:
        return Confidence.MEDIUM


def _severity(value: object) -> Severity:
    try:
        return Severity(str(value or Severity.INFO.value))
    except ValueError:
        return Severity.INFO


def _typed_evidence(item: Any) -> list[Evidence]:
    evidences = getattr(item, "evidences", None)
    if evidences is None:
        evidences = getattr(item, "source_refs", None)
    if not isinstance(evidences, list):
        return []
    return [evidence for evidence in evidences if isinstance(evidence, Evidence)]


def _grade_new_leads(leads: list[Lead], prior: set[int]) -> None:
    from apkscan.core.models import seal_base_advice

    fresh = [lead for lead in leads if id(lead) not in prior]
    for lead in fresh:
        lead.advice = ADVICE_REVIEW
        lead.confidence = Confidence.LOW
        for evidence in lead.source_refs:
            if isinstance(evidence, Evidence) and evidence.scope is EvidenceScope.CASE_EVIDENCE:
                evidence.scope = EvidenceScope.BATCH_REFERENCE
    if fresh:
        seal_base_advice(fresh)


def _grade_new_findings(findings: list[Any], prior: set[int]) -> None:
    for finding in findings:
        if id(finding) in prior or not isinstance(finding, Finding):
            continue
        finding.confidence = Confidence.LOW
        for evidence in finding.evidences:
            if isinstance(evidence, Evidence) and evidence.scope is EvidenceScope.CASE_EVIDENCE:
                evidence.scope = EvidenceScope.BATCH_REFERENCE


def _keep_unknown_plan_fields(meta: dict[str, Any], previous: object) -> None:
    if not isinstance(previous, dict):
        return
    current = meta.get("web_observation_plan")
    if not isinstance(current, dict):
        return
    for key, value in previous.items():
        if key not in current:
            current[key] = value


def _write_collections(
    payload: dict[str, Any],
    state: SimpleNamespace,
    endpoint_rows: list[dict[str, Any]],
    lead_rows: list[dict[str, Any]],
    finding_rows: list[dict[str, Any]],
    prior_evidence: set[int],
    endpoint_map: dict[int, dict[str, Any]],
    lead_map: dict[int, dict[str, Any]],
    finding_map: dict[int, dict[str, Any]],
) -> None:
    _sync_rows(payload, "endpoints", endpoint_rows, state.endpoints, "evidences", prior_evidence, endpoint_map)
    _sync_rows(payload, "leads", lead_rows, state.leads, "source_refs", prior_evidence, lead_map)
    _sync_obtain(state.leads, lead_map)
    _sync_rows(payload, "findings", finding_rows, state.findings, "evidences", prior_evidence, finding_map)


def _sync_rows(
    payload: dict[str, Any],
    key: str,
    rows: list[dict[str, Any]],
    typed: list[Any],
    evidence_field: str,
    prior_evidence: set[int],
    mapping: dict[int, dict[str, Any]],
) -> None:
    for item in typed:
        row = mapping.get(id(item))
        if row is None:
            serialized = _to_jsonable(item)
            if not isinstance(serialized, dict):
                raise SupplementRefusal("parse_failed")
            rows.append(serialized)
            continue
        _append_new_evidence(row, item, evidence_field, prior_evidence)
    if rows or key in payload:
        payload[key] = rows


def _append_new_evidence(
    row: dict[str, Any],
    item: Any,
    evidence_field: str,
    prior_evidence: set[int],
) -> None:
    current = getattr(item, evidence_field, None)
    if not isinstance(current, list):
        return
    fresh = [
        evidence for evidence in current
        if isinstance(evidence, Evidence) and id(evidence) not in prior_evidence
    ]
    if not fresh:
        return
    existing = row.get(evidence_field)
    if existing is None:
        row[evidence_field] = []
        existing = row[evidence_field]
    if not isinstance(existing, list):
        raise SupplementRefusal("invalid_report")
    for evidence in fresh:
        serialized = _to_jsonable(evidence)
        if isinstance(serialized, dict):
            existing.append(serialized)


def _sync_obtain(leads: list[Lead], mapping: dict[int, dict[str, Any]]) -> None:
    for lead in leads:
        row = mapping.get(id(lead))
        if row is None:
            continue
        existing = row.get("evidence_to_obtain")
        if existing is None:
            if not lead.evidence_to_obtain:
                continue
            row["evidence_to_obtain"] = []
            existing = row["evidence_to_obtain"]
        if not isinstance(existing, list):
            raise SupplementRefusal("invalid_report")
        seen = {item for item in existing if isinstance(item, str)}
        for item in lead.evidence_to_obtain:
            if isinstance(item, str) and item not in seen:
                existing.append(item)
                seen.add(item)


def _clone(value: object) -> object:
    if value is None:
        return None
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def _place_trees(out_dir: Path, trees: list[tuple[str, dict[str, bytes]]]) -> None:
    for _sha, files in trees:
        for name, blob in files.items():
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise SupplementRefusal("link_escape")
            _create_or_same(out_dir / "external_observations" / _sha / relative, blob)


def _create_or_same(target: Path, blob: bytes) -> None:
    """缺文件才创建。已有字节相同则保留，字节不同拒绝，从不覆盖。"""
    _reject_reparse_ancestors(target)
    if _is_reparse(target):
        raise SupplementRefusal("link_escape")
    if target.exists():
        if not target.is_file():
            raise SupplementRefusal("publish_conflict")
        if _read_capped(target, "publish_conflict") != blob:
            raise SupplementRefusal("publish_conflict")
        return
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SupplementRefusal("publish_conflict") from exc
    if _is_reparse(target.parent):
        raise SupplementRefusal("link_escape")
    if not atomic_create_bytes(target, blob):
        if target.is_file() and not _is_reparse(target) and _read_capped(target, "publish_conflict") == blob:
            return
        raise SupplementRefusal("publish_conflict")


def _prepare_prior_snapshots(
    source_report: Path, payload: dict[str, Any],
) -> list[tuple[str, bytes]]:
    """只读核对整条 input_report 链。不建目录、不调用插件、不补写缺失环节。"""
    meta = payload.get("meta")
    if not isinstance(meta, dict):
        raise SupplementRefusal("invalid_report")
    queue: list[object] = []
    for key in _SNAPSHOT_KEYS:
        if key in meta:
            queue.append(meta.get(key))
    if not queue:
        return []
    prepared: list[tuple[str, bytes]] = []
    sizes: dict[str, int] = {}
    stack: set[str] = set()
    total = 0

    def visit(record: object) -> None:
        nonlocal total
        if not isinstance(record, dict):
            raise SupplementRefusal("invalid_report")
        digest = _snapshot_link(record)
        if digest in stack:
            raise SupplementRefusal("invalid_report")
        if digest in sizes:
            _check_byte_length(record, sizes[digest])
            return
        if len(prepared) >= _MAX_TREES:
            raise SupplementRefusal("oversize")
        remaining = _MAX_BYTES - total
        blob = _read_snapshot_file(source_report.parent, digest, remaining)
        if hashlib.sha256(blob).hexdigest() != digest:
            raise SupplementRefusal("source_hash_mismatch")
        _check_byte_length(record, len(blob))
        sizes[digest] = len(blob)
        total += len(blob)
        prepared.append((digest, blob))
        stack.add(digest)
        try:
            for child in _next_snapshot_links(_loads_strict(blob)):
                visit(child)
        finally:
            stack.remove(digest)

    for record in queue:
        visit(record)
    return prepared


def _prepare_native_history(
    source_report: Path, payload: dict[str, Any],
) -> list[tuple[str, bytes]]:
    """Copy only the exact native recovery allowlist. Other artifacts stay put."""
    meta = payload.get("meta")
    if not isinstance(meta, dict) or "native_recovery" not in meta:
        return []
    history = meta.get("native_recovery")
    if history is None:
        return []
    if not isinstance(history, list):
        raise SupplementRefusal("invalid_report")
    prepared: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    total = 0
    for item in history:
        if not isinstance(item, dict) or not isinstance(item.get("files"), list):
            raise SupplementRefusal("invalid_report")
        names: list[str] = []
        digest: str | None = None
        staged: list[tuple[str, dict[str, Any]]] = []
        for entry in item["files"]:
            if not isinstance(entry, dict):
                raise SupplementRefusal("invalid_report")
            relative = entry.get("path")
            if not isinstance(relative, str):
                raise SupplementRefusal("link_escape")
            match = _NATIVE_REL.fullmatch(relative)
            if match is None:
                raise SupplementRefusal("link_escape")
            item_digest = match.group(1)
            name = relative.split("/", 2)[2]
            if digest is None:
                digest = item_digest
            elif digest != item_digest:
                raise SupplementRefusal("invalid_report")
            if relative in seen or name in names:
                raise SupplementRefusal("invalid_report")
            names.append(name)
            staged.append((relative, entry))
        if (
            digest is None
            or item.get("content_digest") != digest
            or len(names) != len(_NATIVE_REQUIRED)
            or set(names) != _NATIVE_REQUIRED
        ):
            raise SupplementRefusal("invalid_report")
        planned: list[tuple[str, dict[str, Any], int]] = []
        for relative, entry in staged:
            size = entry.get("size")
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise SupplementRefusal("invalid_report")
            if size > _MAX_NATIVE_FILE_BYTES or total + size > _MAX_NATIVE_HISTORY_BYTES:
                raise SupplementRefusal("oversize")
            total += size
            planned.append((relative, entry, size))
        for relative, entry, size in planned:
            seen.add(relative)
            path = source_report.parent / Path(relative)
            _reject_reparse_ancestors(path)
            blob = _read_capped_remaining(path, size)
            claimed = entry.get("sha256")
            size = entry.get("size")
            if (
                not isinstance(claimed, str)
                or _SHA.fullmatch(claimed) is None
                or isinstance(size, bool)
                or not isinstance(size, int)
                or hashlib.sha256(blob).hexdigest() != claimed
                or len(blob) != size
            ):
                raise SupplementRefusal("source_hash_mismatch")
            prepared.append((relative, blob))
        _align_native_history_item(item, prepared[-len(planned):])
    return prepared


def _align_native_history_item(item: dict[str, Any], files: list[tuple[str, bytes]]) -> None:
    """Reject contradictory flags. Fill only absent flags on the new-output item."""
    from apkscan.core.native_handoff import reconcile_native_history_item

    raw = next((blob for relative, blob in files if relative.endswith("/result.json")), None)
    if raw is None:
        raise SupplementRefusal("result_mismatch")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise SupplementRefusal("result_mismatch") from None
    try:
        reconcile_native_history_item(item, result)
    except ValueError:
        raise SupplementRefusal("result_mismatch") from None


def _place_native_history(out_dir: Path, files: list[tuple[str, bytes]]) -> None:
    for relative, blob in files:
        if _NATIVE_REL.fullmatch(relative) is None:
            raise SupplementRefusal("link_escape")
        _create_or_same(out_dir / Path(relative), blob)


def _snapshot_link(record: object) -> str:
    if not isinstance(record, dict):
        raise SupplementRefusal("invalid_report")
    relative = record.get("relative_path")
    if not isinstance(relative, str):
        raise SupplementRefusal("tampered_observation")
    match = _SNAPSHOT_REL.fullmatch(relative)
    if match is None:
        raise SupplementRefusal("link_escape")
    digest = match.group(1)
    claimed = record.get("sha256")
    if not isinstance(claimed, str) or _SHA.fullmatch(claimed) is None or claimed != digest:
        raise SupplementRefusal("source_hash_mismatch")
    return digest


def _check_byte_length(record: dict[str, Any], size: int) -> None:
    if "byte_length" not in record:
        return
    length = record.get("byte_length")
    if isinstance(length, bool) or not isinstance(length, int) or length != size:
        raise SupplementRefusal("invalid_report")


def _next_snapshot_link(nested: object) -> object:
    links = _next_snapshot_links(nested)
    return links[0] if links else None


def _next_snapshot_links(nested: object) -> list[object]:
    if not isinstance(nested, dict):
        raise SupplementRefusal("invalid_report")
    if "meta" not in nested:
        return []
    nested_meta = nested.get("meta")
    if nested_meta is None:
        return []
    if not isinstance(nested_meta, dict):
        raise SupplementRefusal("invalid_report")
    return [nested_meta.get(key) for key in _SNAPSHOT_KEYS if key in nested_meta]


def _read_snapshot_file(base: Path, digest: str, remaining: int) -> bytes:
    if remaining < 0:
        raise SupplementRefusal("oversize")
    path = base / "input_report" / digest / "report.json"
    _reject_reparse_ancestors(path)
    if any(_is_reparse(item) for item in (base / "input_report", base / "input_report" / digest, path)):
        raise SupplementRefusal("link_escape")
    resolved = _safe_resolve(path)
    if not _within(resolved, _safe_resolve(base)):
        raise SupplementRefusal("link_escape")
    if resolved.parts[-3:] != ("input_report", digest, "report.json"):
        raise SupplementRefusal("link_escape")
    if not path.is_file():
        raise SupplementRefusal("missing_observation")
    blob = _read_capped_remaining(path, remaining)
    if len(blob) > remaining:
        raise SupplementRefusal("oversize")
    return blob


def _place_prior_snapshots(out_dir: Path, prepared: list[tuple[str, bytes]]) -> None:
    """只用预检已读入的字节创建副本，不再回读来源。"""
    for digest, blob in prepared:
        if _SHA.fullmatch(digest) is None:
            raise SupplementRefusal("tampered_observation")
        _create_or_same(out_dir / "input_report" / digest / "report.json", blob)


def _snapshot_input(out_dir: Path, original: bytes, report_path: Path) -> dict[str, Any]:
    digest = hashlib.sha256(original).hexdigest()
    relative = f"input_report/{digest}/report.json"
    _create_or_same(out_dir / "input_report" / digest / "report.json", original)
    return {
        "sha256": digest,
        "relative_path": relative,
        "byte_length": len(original),
        "source_report_absolute": _absolute_input(report_path),
        "source_artifact_base": _absolute_input(report_path.parent),
    }


def _absolute_input(path: Path) -> str:
    resolved = _safe_resolve(path)
    if not resolved.is_absolute():
        raise SupplementRefusal("link_escape")
    return str(resolved)


def _emit(payload: dict[str, Any], state: SimpleNamespace, out_dir: Path) -> Path:
    text = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    report_path = out_dir / "report.json"
    atomic_write_text(report_path, text)
    from apkscan.report.digest import build_digest

    digest = build_digest(json.loads(text), redact=True)
    digest_path = out_dir / "report.digest.json"
    atomic_write_text(
        digest_path,
        json.dumps(digest, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
    )
    view = _render_view(payload, state)
    from apkscan.report.html import render

    render(view, str(out_dir / "report.html"))
    _sidecar(out_dir, [report_path, digest_path, out_dir / "report.html", _snapshot_path(payload, out_dir)])
    return report_path


def _snapshot_path(payload: dict[str, Any], out_dir: Path) -> Path:
    meta = payload.get("meta")
    record = meta.get("supplement_web_input") if isinstance(meta, dict) else None
    relative = record.get("relative_path") if isinstance(record, dict) else ""
    if not isinstance(relative, str) or not relative.startswith("input_report/"):
        raise SupplementRefusal("parse_failed")
    return out_dir / relative


def _render_view(payload: dict[str, Any], state: SimpleNamespace) -> Report:
    meta = payload.get("meta")
    analyzers = payload.get("analyzer_status")
    enrichers = payload.get("enricher_status")
    completeness = payload.get("completeness", 1.0)
    return Report(
        package_name=str(payload.get("package_name", "")),
        meta=meta if isinstance(meta, dict) else {},
        leads=list(state.leads),
        endpoints=list(state.endpoints),
        findings=list(state.findings),
        analyzer_status=[item for item in analyzers if isinstance(item, dict)]
        if isinstance(analyzers, list) else [],
        enricher_status=[item for item in enrichers if isinstance(item, dict)]
        if isinstance(enrichers, list) else [],
        schema_version=str(payload.get("schema_version") or REPORT_SCHEMA_VERSION),
        analysis_status=str(payload.get("analysis_status") or ANALYSIS_STATUS_COMPLETE),
        completeness=float(completeness) if isinstance(completeness, (int, float)) else 1.0,
        critical_failures=[item for item in payload.get("critical_failures", []) if isinstance(item, str)]
        if isinstance(payload.get("critical_failures"), list) else [],
        skipped_analyzers=[item for item in payload.get("skipped_analyzers", []) if isinstance(item, str)]
        if isinstance(payload.get("skipped_analyzers"), list) else [],
    )


def _sidecar(out_dir: Path, products: list[Path]) -> None:
    lines: list[str] = []
    for path in products:
        if not path.is_file():
            continue
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    atomic_write_text(out_dir / "report.sha256", "\n".join(lines) + "\n")


def _receipt_status(meta: dict[str, Any]) -> tuple[str, str]:
    supplement = meta.get("web_supplement")
    if not isinstance(supplement, dict):
        plan = meta.get("web_observation_plan")
        if isinstance(plan, dict):
            return str(plan.get("status") or "skipped"), str(plan.get("reason") or "skipped")
        return "failed", "parse_failed"
    status = str(supplement.get("latest_status") or supplement.get("status") or "failed")
    reason = str(supplement.get("latest_reason") or supplement.get("reason") or status)
    return status, reason


def _live_cdp(meta: dict[str, Any]) -> bool:
    supplement = meta.get("web_supplement")
    if not isinstance(supplement, dict):
        return False
    boundary = supplement.get("boundary")
    if isinstance(boundary, dict) and boundary.get("live_cdp") is True:
        return True
    attempts = supplement.get("attempts")
    if isinstance(attempts, list) and attempts:
        last = attempts[-1]
        if isinstance(last, dict):
            last_boundary = last.get("boundary")
            if isinstance(last_boundary, dict):
                return last_boundary.get("live_cdp") is True
    return False


def _exit_code(status: str, reason: str) -> int:
    if reason == "duplicate_raw":
        return 0
    if status in {"executed", "ok"}:
        return 0
    if status == "failed" or status == "unavailable":
        return 1
    if status in {"skipped", "pending", "not_applicable"}:
        return 3
    return 1
