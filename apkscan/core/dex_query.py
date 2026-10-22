"""中立 DEX 定点查询契约。

核心不导入 ASC。引擎只在隔离 worker 里运行。缺插件时 capabilities 返回
provider_unavailable，engine_executed 保持 false。静态 xref 不改运行时标志，
也不把闭环标成 complete。
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import io
import ipaddress
import json
import re
import shutil
import struct
import sys
import tempfile
import zlib
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.bounded_io import read_limited
from apkscan.core.integrity import evidence_id
from apkscan.core.proctree import run_owned

SCHEMA_VERSION = "dex-query-receipt/1"
META_WRITE_OWNER = "core.dex_query"
META_WRITE_CATEGORIES = {
    "dex_query": "record",
    "source_artifact_base": "record",
}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)
WORKER_REQUEST_SCHEMA = "asc-worker-request/1"
WORKER_RESULT_SCHEMA = "asc-worker-result/1"
PINNED_PROVIDER = "asc"
PINNED_VERSION = "0.1.2.post2"
PINNED_REVISION = "b93cbd0798131312b6dc083198e6decbca28a12e"
PINNED_FINDREFS_SHA256 = "19bab436bf154df6ca1da9cbede95e004de8260a6b22a5d2231862f94efde503"
# Preserve exact legacy identities for rollback and immutable receipt replay.
SUPPORTED_IDENTITIES = {
    PINNED_VERSION: (PINNED_REVISION, PINNED_FINDREFS_SHA256),
    "0.1.1.post5": (
        "d3d75ab7a3c092345102d2ec66ab614ad4a6cc75",
        "99f170737a2a9fb67e4a7a681b98fbc0f56d9e53601cb33f3125b37fd6487b7c",
    ),
}
SOURCE_STATIC_XREF = "static-dex-xref"
_DOMAIN_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_RECEIPT_FILES = 64


class DexQueryError(Exception):
    """稳定 reason 的查询/导入失败。不携带路径或原始异常文本。"""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class DexQueryLimits:
    timeout_sec: float = 30.0
    input_bytes: int = 64 * 1024 * 1024
    uncompressed_bytes: int = 64 * 1024 * 1024
    max_hits: int = 200
    max_stdout_bytes: int = 1024 * 1024
    max_stderr_bytes: int = 64 * 1024
    memory_bytes: int = 512 * 1024 * 1024
    max_processes: int = 8
    max_dex_members: int = 32
    max_compression_ratio: int = 100

    def as_dict(self) -> dict[str, int | float]:
        return {
            "timeout_sec": self.timeout_sec,
            "input_bytes": self.input_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "max_hits": self.max_hits,
            "max_stdout_bytes": self.max_stdout_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
            "memory_bytes": self.memory_bytes,
            "max_processes": self.max_processes,
            "max_dex_members": self.max_dex_members,
            "max_compression_ratio": self.max_compression_ratio,
        }


@dataclass(frozen=True)
class DexMember:
    name: str
    ordinal: int
    sha256: str
    data: bytes
    role: str = "original"


class _DexParseError(Exception):
    """DEX 结构读不出来。调用方把它当成未核，不当成 xref 矛盾。"""


@dataclass(frozen=True)
class _DexCode:
    insns_off: int
    insns_size: int
    insns: bytes


@dataclass(frozen=True)
class _ParsedDex:
    strings: tuple[str, ...]
    methods: Mapping[str, _DexCode]


class _DexParseState:
    """单次解析的共享缓存与累计预算；每个 _parse_dex_bytes 一份，不落模块全局。"""

    def __init__(self) -> None:
        self.type_lists: dict[int, tuple[int, ...]] = {}
        self.param_entries = 0
        self.proto_params: dict[int, tuple[str, int]] = {}
        self.code_items: dict[int, _DexCode] = {}
        self.code_bytes = 0
        self.class_data_seen: set[int] = set()
        self.class_entries = 0


@dataclass(frozen=True)
class _XrefCheck:
    verified: bool
    status: str
    hit_ids: frozenset[int]


def resolve_worker_argv() -> list[str] | None:
    """发现已安装的 fxapk-asc 发行物。不导入插件模块，也不导入 ASC。"""
    try:
        importlib.metadata.distribution("fxapk-asc")
    except importlib.metadata.PackageNotFoundError:
        return None
    return [sys.executable, "-I", "-m", "fxapk_asc.worker"]


def _supported_identity(payload: Mapping[str, Any], *, source_hash: bool = True) -> bool:
    version = payload.get("provider_version")
    expected = SUPPORTED_IDENTITIES.get(version) if isinstance(version, str) else None
    return expected is not None and payload.get("provider_revision") == expected[0] and (
        not source_hash or payload.get("findrefs_sha256") == expected[1]
    )


def _unavailable(reason: str = "provider_unavailable") -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "provider": PINNED_PROVIDER,
        "provider_version": PINNED_VERSION,
        "provider_revision": PINNED_REVISION,
        "available": False,
        "reason": reason,
        "engine_executed": False,
    }


def capabilities(
    *,
    worker_argv: list[str] | None = None,
    limits: DexQueryLimits | None = None,
) -> dict[str, object]:
    """探测提供方。capabilities 请求不打开 APK，回执里的 engine_executed 固定为 false。"""
    argv = resolve_worker_argv() if worker_argv is None else worker_argv
    if not argv:
        return _unavailable()
    bounds = limits or DexQueryLimits()
    payload, reason = _invoke_worker(argv, {"op": "capabilities"}, bounds, query=False)
    if payload is None:
        return _unavailable(reason or "provider_unavailable")
    version = payload.get("provider_version")
    revision = payload.get("provider_revision")
    if not _supported_identity(payload):
        return _unavailable("provider_version_mismatch")
    if payload.get("runtime_encoding") == "rejected":
        return _unavailable("runtime_encoding_rejected")
    if payload.get("engine_executed") is not False:
        return _unavailable("engine_not_executed")
    return {
        "schema_version": SCHEMA_VERSION,
        "provider": PINNED_PROVIDER,
        "provider_version": version,
        "provider_revision": revision,
        "available": True,
        "reason": None,
        "engine_executed": False,
        "memory_limit_enforced": True,
        "process_limit_enforced": sys.platform == "win32",
        "linux_memory_limit": "rlimit_as_unverified" if sys.platform != "linux" else "rlimit_as",
        "linux_process_limit": "not_enforced",
    }


def inventory_dex_members(path: Path, limits: DexQueryLimits | None = None) -> tuple[list[DexMember], list[dict[str, object]], bool]:
    """按同一份有界快照清点 DEX。哈希和成员清单不再分次打开文件。"""
    bounds = limits or DexQueryLimits()
    return inventory_dex_bytes(_stable_snapshot(path, bounds.input_bytes), bounds)


def inventory_dex_bytes(
    data: bytes, limits: DexQueryLimits | None = None,
) -> tuple[list[DexMember], list[dict[str, object]], bool]:
    """从已读入的字节清点 DEX。超限、坏路径、重复成员、CRC 和压缩炸弹在解压前或有界解压时拒绝。"""
    bounds = limits or DexQueryLimits()
    if len(data) > bounds.input_bytes:
        raise DexQueryError("oversize")
    try:
        handle = io.BytesIO(data)
        size = len(data)
        entries = _central_directory(handle, size, bounds)
        members: list[DexMember] = []
        skipped: list[dict[str, object]] = []
        seen: set[str] = set()
        uncompressed = 0
        truncated = False
        for ordinal, entry in enumerate(entry for entry in entries if _is_dex_name(entry["name"])):
            name = str(entry["name"])
            if name in seen:
                raise DexQueryError("duplicate_member")
            seen.add(name)
            declared = int(entry["uncompressed"])
            if ordinal >= bounds.max_dex_members or uncompressed + declared > bounds.uncompressed_bytes:
                truncated = True
                skipped.append({
                    "ordinal": ordinal, "name": name, "status": "skipped", "reason": "oversize",
                })
                continue
            member_data = _read_member(handle, entry, bounds)
            uncompressed += len(member_data)
            members.append(DexMember(
                name=name,
                ordinal=ordinal,
                sha256=hashlib.sha256(member_data).hexdigest(),
                data=member_data,
            ))
    except DexQueryError:
        raise
    except (OSError, zipfile.BadZipFile, zlib.error) as exc:
        raise DexQueryError("input_rejected") from exc
    return members, skipped, truncated


def query_apk(
    apk: Path,
    values: list[str],
    *,
    provider: str = PINNED_PROVIDER,
    worker_argv: list[str] | None = None,
    limits: DexQueryLimits | None = None,
    out: Path | None = None,
) -> dict[str, Any]:
    """清点 APK 内全部 DEX 成员并经 worker 查询。原件不改写。"""
    if provider != PINNED_PROVIDER:
        raise DexQueryError("unsupported_provider")
    if not values or any(not isinstance(item, str) or not item or len(item) > 8192 for item in values):
        raise DexQueryError("input_rejected")
    bounds = limits or DexQueryLimits()
    argv = resolve_worker_argv() if worker_argv is None else worker_argv
    if not argv:
        raise DexQueryError("provider_unavailable")
    apk_bytes = _stable_snapshot(apk, bounds.input_bytes)
    apk_hash = hashlib.sha256(apk_bytes).hexdigest()
    members, skipped, truncated = inventory_dex_bytes(apk_bytes, bounds)
    with tempfile.TemporaryDirectory(prefix="fxapk-dex-") as temp_name:
        temp = Path(temp_name)
        request_members = []
        for member in members:
            target = temp / f"{member.ordinal}.dex"
            target.write_bytes(member.data)
            request_members.append({
                "name": member.name,
                "ordinal": member.ordinal,
                "sha256": member.sha256,
                "path": str(target),
            })
        request = {
            "schema_version": WORKER_REQUEST_SCHEMA,
            "op": "query",
            "queries": list(values),
            "max_hits": bounds.max_hits,
            "members": request_members,
        }
        payload, reason = _invoke_worker(argv, request, bounds, query=True)
    if payload is None:
        raise DexQueryError(reason or "provider_unavailable")
    if not _supported_identity(payload):
        raise DexQueryError("provider_version_mismatch")
    if payload.get("reason") == "runtime_encoding_rejected" or payload.get("runtime_encoding") != "mutf8-1.1.0":
        raise DexQueryError("runtime_encoding_rejected")
    if payload.get("engine_executed") is not True:
        raise DexQueryError("engine_not_executed")
    receipt = _receipt_from_worker(
        payload, apk_hash, values, members, skipped, truncated, bounds,
    )
    if out is not None:
        _publish_receipt(out, receipt)
    return receipt


def import_receipt(
    receipt_path: Path,
    report_path: Path,
    out_dir: Path,
    *,
    apk: Path | None = None,
) -> dict[str, Any]:
    """把已核验的回执导入新报告目录。相同字节重放幂等；失败不删除已有成功记录。"""
    receipt_bytes = _read_bounded(receipt_path, DexQueryLimits().input_bytes)
    report_bytes = _read_bounded(report_path, DexQueryLimits().input_bytes)
    receipt = _load_json(receipt_bytes)
    report = _load_json(report_bytes)
    _validate_receipt(receipt)
    if not isinstance(report, dict) or not isinstance(report.get("meta"), dict):
        raise DexQueryError("invalid_schema")
    meta = report["meta"]
    sample = meta.get("sample_sha256")
    if not isinstance(sample, str) or _HEX64.fullmatch(sample) is None:
        raise DexQueryError("report_identity_mismatch")
    if receipt["apk_sha256"] != sample:
        raise DexQueryError("report_identity_mismatch")
    prior_dex = _dex_receipt_specs(report)
    apk_bytes: bytes | None = None
    if apk is not None:
        apk_bytes = _stable_snapshot(apk, DexQueryLimits().input_bytes)
        if hashlib.sha256(apk_bytes).hexdigest() != sample:
            raise DexQueryError("identity_mismatch")
        _reject_forged_members(apk_bytes, receipt)
        xref = _verify_xref_hits(apk_bytes, receipt)
    else:
        xref = _XrefCheck(False, "not_verified_locally", frozenset())
    merged = json.loads(report_bytes.decode("utf-8"))
    _merge_receipt(merged, receipt, receipt_bytes, xref)
    attachment_note = _retain_report_attachments(report_path, merged, prior_dex)
    encoded_report = _canonical_text(merged)
    digest_bytes, html_bytes = _render_projections(merged)
    receipt_rel = f"dex-query/{receipt['receipt_id']}.json"
    planned = {
        "report.json": encoded_report,
        "report.digest.json": digest_bytes,
        "report.html": html_bytes,
        receipt_rel: receipt_bytes,
    }
    for relative, blob in attachment_note["files"]:
        if relative in planned and planned[relative] != blob:
            raise DexQueryError("receipt_conflict")
        planned.setdefault(relative, blob)
    if out_dir.exists():
        if _tree_matches(out_dir, planned):
            return {
                "status": "idempotent",
                "receipt_id": receipt["receipt_id"],
                "out": str(out_dir),
                "attachments": attachment_note["summary"],
            }
        raise DexQueryError("receipt_conflict")
    created = False
    try:
        out_dir.mkdir(parents=False)
        created = True
        for relative, blob in planned.items():
            _reject_relative(relative)
            target = out_dir.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            if not atomic_create_bytes(target, blob):
                raise DexQueryError("receipt_conflict")
    except DexQueryError:
        if created:
            shutil.rmtree(out_dir, ignore_errors=True)
        raise
    except OSError as exc:
        if created:
            shutil.rmtree(out_dir, ignore_errors=True)
        raise DexQueryError("evidence_io_failed") from exc
    return {
        "status": "imported",
        "receipt_id": receipt["receipt_id"],
        "out": str(out_dir),
        "closure_evaluated": False,
        "runtime_observed_upgraded": False,
        "attachments": attachment_note["summary"],
    }


def _member_hit_count(member: Mapping[str, Any]) -> int:
    if "hits" in member:
        hits = member.get("hits")
        return len(hits) if isinstance(hits, list) else 0
    count = member.get("hit_count")
    if type(count) is int and count >= 0:
        return count
    return 0


def project_dex_query(meta: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """默认投影只保留哈希、覆盖和定位，不复制 query 原文。"""
    if not isinstance(meta, Mapping) or "dex_query" not in meta:
        return None
    raw = meta.get("dex_query")
    if not isinstance(raw, dict):
        return {"status": "invalid", "reason": "invalid_type"}
    receipts = raw.get("receipts")
    projected_receipts = []
    if isinstance(receipts, list):
        for item in receipts:
            if not isinstance(item, dict):
                continue
            projected = {
                "receipt_id": item.get("receipt_id"),
                "sha256": item.get("sha256"),
                "provider": item.get("provider"),
                "provider_version": item.get("provider_version"),
                "query_summary_sha256": item.get("query_summary_sha256"),
                "engine_executed": item.get("engine_executed") is True,
                "members": [
                    {
                        "name": member.get("name"),
                        "ordinal": member.get("ordinal"),
                        "sha256": member.get("sha256"),
                        "role": member.get("role"),
                        "status": member.get("status"),
                        "reason": member.get("reason"),
                        "precision": member.get("precision"),
                        "hit_count": _member_hit_count(member),
                    }
                    for member in item.get("members", [])
                    if isinstance(member, dict)
                ],
            }
            if "xref_verified" in item:
                projected["xref_verified"] = item.get("xref_verified") is True
            verification = item.get("xref_verification")
            if verification in {"not_verified_locally", "verified_against_apk", "parse_unavailable", "no_exact_hits"}:
                projected["xref_verification"] = verification
            projected_receipts.append(projected)
    return {"receipts": projected_receipts}


def project_dex_handoff(meta: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """有查询记录或显式计划时才给下一步。mode=off 不给动作，也不自动安装、采集或闭环。"""
    if not isinstance(meta, Mapping):
        return None
    if "dex_query" not in meta and "dex_query_plan" not in meta:
        return None
    plan = meta.get("dex_query_plan")
    mode = plan.get("mode") if isinstance(plan, dict) else None
    if mode == "off":
        return {
            "mode": "off",
            "auto_execute": False,
            "actions": [],
            "install": False,
            "capture": False,
            "close": False,
        }
    jadx_status = meta.get("jadx_index_status")
    if jadx_status in {"built", "reused"}:
        command = "fxapk jadx usage"
        when = "jadx_index_available"
    else:
        command = "fxapk dex query"
        when = "constant_without_callsite_or_index_missing"
    return {
        "mode": mode if isinstance(mode, str) else "manual",
        "auto_execute": False,
        "actions": [{"command": command, "when": when}],
        "install": False,
        "capture": False,
        "close": False,
    }


def _invoke_worker(
    argv: list[str],
    request: Mapping[str, Any],
    limits: DexQueryLimits,
    *,
    query: bool,
) -> tuple[dict[str, Any] | None, str | None]:
    body = dict(request)
    body["schema_version"] = WORKER_REQUEST_SCHEMA
    encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="fxapk-asc-req-") as temp_name:
        request_path = Path(temp_name) / "request.json"
        request_path.write_bytes(encoded)
        owned = run_owned(
            [*argv, str(request_path)],
            timeout=limits.timeout_sec,
            memory_bytes=limits.memory_bytes,
            max_processes=limits.max_processes + 1,
            max_stdout_bytes=limits.max_stdout_bytes,
            max_stderr_bytes=limits.max_stderr_bytes,
        )
    if not owned.memory_limit_enforced:
        return None, "memory_limit_unavailable"
    if "timeout" in owned.reason_codes:
        return None, "timeout"
    if "output_limit" in owned.reason_codes:
        return None, "output_limit"
    if not owned.ownership_complete or not owned.termination_complete:
        return None, "provider_unavailable"
    if owned.forced_tree_kill:
        return None, "worker_tree_killed"
    if owned.returncode != 0:
        return None, "provider_unavailable"
    try:
        payload = json.loads(owned.stdout)
    except json.JSONDecodeError:
        return None, "invalid_schema"
    if not isinstance(payload, dict) or payload.get("schema_version") != WORKER_RESULT_SCHEMA:
        return None, "invalid_schema"
    if query and payload.get("op") not in (None, "query"):
        return None, "invalid_schema"
    payload["_peak_memory_bytes"] = owned.peak_memory_bytes
    payload["_memory_limit_enforced"] = owned.memory_limit_enforced
    payload["_process_limit_enforced"] = owned.process_limit_enforced
    return payload, None


def _receipt_from_worker(
    payload: Mapping[str, Any],
    apk_hash: str,
    values: list[str],
    members: list[DexMember],
    skipped: list[dict[str, object]],
    truncated: bool,
    limits: DexQueryLimits,
) -> dict[str, Any]:
    by_ordinal = {member.ordinal: member for member in members}
    returned = payload.get("members")
    if not isinstance(returned, list):
        raise DexQueryError("invalid_schema")
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()
    for item in returned:
        if not isinstance(item, dict):
            raise DexQueryError("invalid_type")
        ordinal = item.get("ordinal")
        sha = item.get("sha256")
        member = by_ordinal.get(ordinal) if isinstance(ordinal, int) and not isinstance(ordinal, bool) else None
        name_ok = member is not None and item.get("name") == member.name
        if member is None or sha != member.sha256 or ordinal in seen or not name_ok:
            rows.append({
                "ordinal": member.ordinal if member is not None and ordinal not in seen else None,
                "name": member.name if member is not None and ordinal not in seen else None,
                "sha256": member.sha256 if member is not None and ordinal not in seen else None,
                "role": "original",
                "status": "failed",
                "reason": "identity_mismatch",
                "precision": "unsupported",
                "truncated": False,
                "hits": [],
                "lineage": None,
            })
            if member is not None and isinstance(ordinal, int) and ordinal not in seen:
                seen.add(ordinal)
            continue
        if not isinstance(ordinal, int) or isinstance(ordinal, bool):
            raise DexQueryError("invalid_type")
        seen.add(ordinal)
        allowed_hashes = {
            hashlib.sha256(value.encode("utf-8")).hexdigest() for value in values
        }
        hits = _clean_hits(item.get("hits"), limits.max_hits, allowed_hashes)
        status = item.get("status")
        if status not in {"hit", "no_match", "partial", "failed", "skipped", "unsupported"}:
            status = "failed"
        if hits and any(hit["precision"] != "exact" for hit in hits):
            status = "partial"
        rows.append({
            "ordinal": member.ordinal,
            "name": member.name,
            "sha256": member.sha256,
            "role": member.role,
            "status": status,
            "reason": item.get("reason") if isinstance(item.get("reason"), str) else None,
            "precision": item.get("precision") if item.get("precision") in {"exact", "partial", "unsupported"} else "partial",
            "truncated": bool(item.get("truncated")),
            "hits": hits,
            "lineage": None,
        })
    for member in members:
        if member.ordinal not in seen:
            rows.append({
                "ordinal": member.ordinal,
                "name": member.name,
                "sha256": member.sha256,
                "role": member.role,
                "status": "failed",
                "reason": "identity_mismatch",
                "precision": "unsupported",
                "truncated": False,
                "hits": [],
                "lineage": None,
            })
    rows.extend({
        "ordinal": item.get("ordinal"),
        "name": item.get("name"),
        "sha256": None,
        "role": "original",
        "status": "skipped",
        "reason": item.get("reason"),
        "precision": "unsupported",
        "truncated": True,
        "hits": [],
        "lineage": None,
    } for item in skipped)
    rows.sort(key=lambda item: (item["ordinal"] is None, item["ordinal"]))
    summary = hashlib.sha256(
        json.dumps(list(values), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "provider": PINNED_PROVIDER,
        "provider_version": payload.get("provider_version", PINNED_VERSION),
        "provider_revision": payload.get("provider_revision", PINNED_REVISION),
        "apk_sha256": apk_hash,
        "query_kind": "string-xref",
        "query_summary_sha256": summary,
        "query_values": list(values),
        "engine_executed": True,
        "limits": limits.as_dict(),
        "inventory": {
            "member_count": len(members) + len(skipped),
            "queried_count": len(members),
            "truncated": truncated or any(row["truncated"] for row in rows),
        },
        "members": rows,
        "consumption": {
            "peak_memory_bytes": payload.get("_peak_memory_bytes"),
            "memory_limit_enforced": payload.get("_memory_limit_enforced") is True,
            "process_limit_enforced": payload.get("_process_limit_enforced") is True,
        },
    }
    receipt["receipt_id"] = hashlib.sha256(_canonical_text(receipt)).hexdigest()
    return receipt


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _legal_descriptor(value: object) -> str | None:
    """完整方法描述符。空串、缺返回类型和布尔偏移都不能当成 exact。"""
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        return None
    class_part, arrow, rest = value.partition("->")
    if arrow != "->" or not class_part.startswith("L") or not class_part.endswith(";"):
        return None
    if any(part in {"", ".", ".."} for part in class_part[1:-1].split("/")):
        return None
    name, opened, tail = rest.partition("(")
    if opened != "(" or not name or ")" not in tail:
        return None
    _params, closed, returned = tail.rpartition(")")
    if closed != ")" or not returned:
        return None
    return value


def _clean_hits(
    raw: object, max_hits: int, allowed_hashes: set[str] | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    hits: list[dict[str, Any]] = []
    for item in raw[:max_hits]:
        if not isinstance(item, dict):
            continue
        precision = item.get("precision")
        if precision not in {"exact", "partial", "unsupported"}:
            precision = "partial"
        offset = _nonnegative_int(item.get("offset"))
        unit = item.get("offset_unit")
        if offset is None or unit not in {"code_units", "dex_file_bytes"}:
            offset = None
            unit = None
            precision = "partial" if precision == "exact" else precision
        descriptor = _legal_descriptor(item.get("descriptor"))
        file_offset = _nonnegative_int(item.get("file_offset"))
        if descriptor is None or file_offset is None or offset is None or unit is None:
            precision = "partial" if precision == "exact" else precision
        value_sha = item.get("value_sha256")
        if not isinstance(value_sha, str) or _HEX64.fullmatch(value_sha) is None:
            continue
        if allowed_hashes is not None and value_sha not in allowed_hashes:
            continue
        hit = {
            "value_sha256": value_sha,
            "descriptor": descriptor,
            "offset": offset,
            "offset_unit": unit,
            "file_offset": file_offset,
            "grade": "static-reference",
            "precision": precision,
        }
        hit["evidence_sha256"] = hashlib.sha256(_canonical_text(hit)).hexdigest()
        hits.append(hit)
    return hits


def _publish_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    blob = _canonical_text(dict(receipt))
    if path.exists():
        if path.read_bytes() != blob:
            raise DexQueryError("receipt_conflict")
        return
    if not atomic_create_bytes(path, blob) and path.read_bytes() != blob:
        raise DexQueryError("receipt_conflict")


def _validate_receipt(receipt: Mapping[str, Any]) -> None:
    required = {
        "schema_version", "receipt_id", "provider", "provider_version", "provider_revision",
        "apk_sha256", "query_kind", "query_summary_sha256", "engine_executed", "limits",
        "inventory", "members", "consumption",
    }
    allowed = required | {"query_values"}
    if set(receipt) - allowed:
        raise DexQueryError("unknown_field")
    if not required <= set(receipt):
        raise DexQueryError("invalid_schema")
    if receipt.get("schema_version") != SCHEMA_VERSION:
        raise DexQueryError("invalid_schema")
    if receipt.get("provider") != PINNED_PROVIDER:
        raise DexQueryError("unsupported_provider")
    if not _supported_identity(receipt, source_hash=False):
        raise DexQueryError("provider_version_mismatch")
    if receipt.get("engine_executed") is not True:
        raise DexQueryError("engine_not_executed")
    for key in ("receipt_id", "apk_sha256", "query_summary_sha256"):
        if not isinstance(receipt.get(key), str) or _HEX64.fullmatch(str(receipt[key])) is None:
            raise DexQueryError("invalid_type")
    if not isinstance(receipt.get("members"), list):
        raise DexQueryError("invalid_type")
    without_id = {key: value for key, value in receipt.items() if key != "receipt_id"}
    if hashlib.sha256(_canonical_text(without_id)).hexdigest() != receipt["receipt_id"]:
        raise DexQueryError("identity_mismatch")
    _validate_query_binding(receipt)
    _validate_member_rows(receipt["members"], _query_hashes(receipt))


def _merge_receipt(
    report: dict[str, Any],
    receipt: Mapping[str, Any],
    receipt_bytes: bytes,
    xref: _XrefCheck,
) -> None:
    meta = report["meta"]
    dex_query = meta.get("dex_query")
    if dex_query is None:
        dex_query = {"receipts": []}
        meta["dex_query"] = dex_query
    if not isinstance(dex_query, dict) or not isinstance(dex_query.get("receipts"), list):
        raise DexQueryError("invalid_schema")
    digest = hashlib.sha256(receipt_bytes).hexdigest()
    for existing in dex_query["receipts"]:
        if isinstance(existing, dict) and existing.get("receipt_id") == receipt["receipt_id"]:
            if existing.get("sha256") != digest:
                raise DexQueryError("receipt_conflict")
            return
    fields = _summary_fields(receipt, digest)
    fields["xref_verified"] = xref.verified
    fields["xref_verification"] = xref.status
    summary = project_dex_query({"dex_query": {"receipts": [fields]}})
    assert summary is not None
    dex_query["receipts"].append(summary["receipts"][0] | {"sha256": digest})
    _attach_observations(report, receipt, xref.hit_ids)


def _summary_fields(receipt: Mapping[str, Any], digest: str) -> dict[str, Any]:
    return {
        "receipt_id": receipt["receipt_id"],
        "sha256": digest,
        "provider": receipt["provider"],
        "provider_version": receipt["provider_version"],
        "query_summary_sha256": receipt["query_summary_sha256"],
        "engine_executed": receipt["engine_executed"] is True,
        "members": receipt["members"],
    }


def _attach_observations(
    report: dict[str, Any], receipt: Mapping[str, Any], verified_ids: frozenset[int],
) -> None:
    values = receipt.get("query_values")
    if not isinstance(values, list):
        values = []
    by_hash = {
        hashlib.sha256(value.encode("utf-8")).hexdigest(): value
        for value in values if isinstance(value, str)
    }
    leads = report.get("leads")
    if not isinstance(leads, list):
        leads = []
        report["leads"] = leads
    for member in receipt["members"]:
        if not isinstance(member, dict):
            continue
        if member.get("status") in {"failed", "skipped", "unsupported"}:
            continue
        for hit in member.get("hits") or []:
            if not isinstance(hit, dict) or hit.get("grade") != "static-reference":
                continue
            value_sha = hit.get("value_sha256")
            raw_value = by_hash.get(value_sha) if isinstance(value_sha, str) else None
            if not isinstance(raw_value, str):
                continue
            _add_observation(
                leads, raw_value, member, hit, str(receipt["receipt_id"]),
                xref_checked=id(hit) in verified_ids,
            )
    closure = report.get("meta", {}).get("closure")
    if isinstance(closure, dict) and closure.get("status") == "complete":
        return


def _add_observation(
    leads: list[Any],
    value: str,
    member: Mapping[str, Any],
    hit: Mapping[str, Any],
    receipt_id: str,
    *,
    xref_checked: bool,
) -> None:
    source = SOURCE_STATIC_XREF
    location = f"{member.get('name')}!{hit.get('descriptor')}@{hit.get('offset_unit')}:{hit.get('offset')}"
    marker = "xref=verified" if xref_checked else "xref=unverified"
    evidence = {
        "source": source,
        "location": location,
        "snippet": (
            f"receipt:{receipt_id[:12]} grade=static-reference precision={hit.get('precision')} {marker}"
        ),
        "scope": "case_evidence",
        "evidence_id": evidence_id(source, location),
    }
    for lead in leads:
        if isinstance(lead, dict) and lead.get("value") == value:
            refs = lead.get("source_refs")
            if not isinstance(refs, list):
                refs = []
                lead["source_refs"] = refs
            signature = (evidence["source"], evidence["location"], evidence["snippet"], evidence["scope"])
            if not any(
                isinstance(item, dict) and (
                    item.get("source"), item.get("location"), item.get("snippet"), item.get("scope"),
                ) == signature
                for item in refs
            ):
                refs.append(evidence)
            return
    kind = _lead_kind(value)
    if kind is None or hit.get("precision") == "unsupported":
        return
    leads.append({
        "category": kind,
        "value": value,
        "subject": None,
        "where_to_request": None,
        "evidence_to_obtain": [],
        "confidence": "LOW",
        "source_refs": [evidence],
        "notes": "静态 DEX xref 候选。未观察运行时连接。",
        "advice": "待核",
        "is_runtime_seen": False,
        "is_runtime_contact": False,
    })


def _lead_kind(value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if _DOMAIN_RE.fullmatch(value) and "." in value and not value.endswith("."):
            return "DOMAIN"
        return None
    return "IP"


def _reject_forged_members(apk_bytes: bytes, receipt: Mapping[str, Any]) -> None:
    members, skipped, _truncated = inventory_dex_bytes(apk_bytes)
    actual = {(member.name, member.ordinal, member.sha256, member.role) for member in members}
    skipped_ids = {(item.get("name"), item.get("ordinal")) for item in skipped}
    seen: set[tuple[str, int, str, str]] = set()
    for member in receipt["members"]:
        if not isinstance(member, dict):
            raise DexQueryError("invalid_type")
        if member.get("status") == "skipped":
            if (member.get("name"), member.get("ordinal")) not in skipped_ids:
                raise DexQueryError("identity_mismatch")
            continue
        ordinal = member.get("ordinal")
        sha = member.get("sha256")
        role = member.get("role")
        if isinstance(ordinal, bool) or not isinstance(ordinal, int) or not isinstance(sha, str):
            raise DexQueryError("identity_mismatch")
        if not isinstance(role, str):
            role = "original"
        key = (str(member.get("name")), ordinal, sha, role)
        if key not in actual or key in seen:
            raise DexQueryError("identity_mismatch")
        seen.add(key)
    if seen != actual:
        raise DexQueryError("identity_mismatch")


_DEX_VERSIONS = {b"035", b"036", b"037", b"038", b"039"}


def _verify_xref_hits(apk_bytes: bytes, receipt: Mapping[str, Any]) -> _XrefCheck:
    """有原件时核对 exact static-reference。矛盾则整次拒绝；解析不了则该成员未核。"""
    members, _skipped, _truncated = inventory_dex_bytes(apk_bytes)
    by_key = {(member.name, member.ordinal): member for member in members}
    by_hash: dict[str, str] = {}
    values = receipt.get("query_values")
    if isinstance(values, list):
        for value in values:
            if isinstance(value, str):
                by_hash[hashlib.sha256(value.encode("utf-8")).hexdigest()] = value
    verified: set[int] = set()
    parse_failed = False
    budget = DexQueryLimits().uncompressed_bytes
    raw_members = receipt.get("members")
    if not isinstance(raw_members, list):
        return _XrefCheck(False, "parse_unavailable", frozenset())
    for member in raw_members:
        if not isinstance(member, dict):
            parse_failed = True
            continue
        if member.get("status") in {"failed", "skipped", "unsupported"}:
            continue
        name = member.get("name")
        ordinal = member.get("ordinal")
        if not isinstance(name, str) or isinstance(ordinal, bool) or not isinstance(ordinal, int):
            parse_failed = True
            continue
        loaded = by_key.get((name, ordinal))
        if loaded is None or len(loaded.data) > budget:
            parse_failed = True
            continue
        try:
            parsed = _parse_dex(loaded.data)
        except _DexParseError:
            parse_failed = True
            continue
        hits = member.get("hits")
        if not isinstance(hits, list):
            parse_failed = True
            continue
        wanted: dict[str, set[int]] = {}
        for hit in hits:
            if not isinstance(hit, dict) or hit.get("grade") != "static-reference":
                continue
            if hit.get("precision") != "exact":
                continue
            offset = hit.get("offset")
            descriptor = hit.get("descriptor")
            if (
                isinstance(offset, bool) or not isinstance(offset, int) or offset < 0
                or not isinstance(descriptor, str) or descriptor not in parsed.methods
            ):
                continue
            wanted.setdefault(descriptor, set()).add(offset)
        decoded: dict[str, Mapping[int, int] | None] = {}
        for descriptor, offsets in wanted.items():
            try:
                decoded[descriptor] = _const_string_indexes(parsed.methods[descriptor].insns, offsets)
            except _DexParseError:
                parse_failed = True
                decoded[descriptor] = None
        for hit in hits:
            if not isinstance(hit, dict) or hit.get("grade") != "static-reference":
                continue
            if hit.get("precision") != "exact":
                continue
            descriptor = hit.get("descriptor")
            if isinstance(descriptor, str) and descriptor in decoded and decoded[descriptor] is None:
                continue
            refs = decoded[descriptor] if isinstance(descriptor, str) and descriptor in decoded else None
            if not _exact_hit_matches(parsed, hit, by_hash, string_refs=refs):
                raise DexQueryError("xref_mismatch")
            verified.add(id(hit))
    if parse_failed:
        return _XrefCheck(False, "parse_unavailable", frozenset(verified))
    if not verified:
        return _XrefCheck(False, "no_exact_hits", frozenset())
    return _XrefCheck(True, "verified_against_apk", frozenset(verified))


def _exact_hit_matches(
    parsed: _ParsedDex,
    hit: Mapping[str, Any],
    by_hash: Mapping[str, str],
    *,
    string_refs: Mapping[int, int] | None = None,
) -> bool:
    # code_units 是相对该方法 insns 起点的下标。file_offset 须等于 insns 文件偏移 + offset*2。
    if hit.get("offset_unit") != "code_units":
        return False
    offset = hit.get("offset")
    descriptor = hit.get("descriptor")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or not isinstance(descriptor, str):
        return False
    code = parsed.methods.get(descriptor)
    if code is None or offset >= code.insns_size:
        return False
    if "file_offset" in hit:
        file_offset = hit.get("file_offset")
        if isinstance(file_offset, bool) or not isinstance(file_offset, int):
            return False
        if file_offset != code.insns_off + offset * 2:
            return False
    if string_refs is None:
        string_index = _const_string_index(code.insns, offset)
    else:
        string_index = string_refs.get(offset)
    value_sha = hit.get("value_sha256")
    expected = by_hash.get(value_sha) if isinstance(value_sha, str) else None
    if string_index is None or string_index >= len(parsed.strings) or expected is None:
        return False
    return parsed.strings[string_index] == expected


def _instruction_width(insns: bytes, offset: int) -> int:
    units = len(insns) // 2
    if offset >= units:
        raise _DexParseError()
    word = struct.unpack_from("<H", insns, offset * 2)[0]
    op = word & 0xFF
    if op == 0 and word != 0:
        if offset % 2 or offset + 2 > units:
            raise _DexParseError()
        count = struct.unpack_from("<H", insns, offset * 2 + 2)[0]
        if word == 0x0100:
            width = 4 + 2 * count
        elif word == 0x0200:
            width = 2 + 4 * count
        elif word == 0x0300 and offset + 4 <= units:
            if count not in (1, 2, 4, 8):
                raise _DexParseError()
            size = struct.unpack_from("<I", insns, offset * 2 + 4)[0]
            width = 4 + (count * size + 1) // 2
        else:
            raise _DexParseError()
    elif (
        op in (0x00, 0x01, 0x04, 0x07, 0x1D, 0x1E, 0x21, 0x27, 0x28)
        or 0x0A <= op <= 0x12
        or 0x7B <= op <= 0x8F
        or 0xB0 <= op <= 0xCF
    ):
        width = 1
    elif (
        op in (
            0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1F, 0x20,
            0x22, 0x23, 0x29, 0xFE, 0xFF,
        )
        or 0x2D <= op <= 0x3D
        or 0x44 <= op <= 0x6D
        or 0x90 <= op <= 0xAF
        or 0xD0 <= op <= 0xE2
    ):
        width = 2
    elif (
        op in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C, 0xFC, 0xFD)
        or 0x6E <= op <= 0x72
        or 0x74 <= op <= 0x78
    ):
        width = 3
    elif op in (0xFA, 0xFB):
        width = 4
    elif op == 0x18:
        width = 5
    else:
        raise _DexParseError()
    if offset + width > units:
        raise _DexParseError()
    return width


def _const_string_indexes(insns: bytes, wanted: set[int]) -> dict[int, int]:
    found: dict[int, int] = {}
    if not wanted:
        return found
    offset = 0
    last = max(wanted)
    while offset < len(insns) // 2 and offset <= last:
        width = _instruction_width(insns, offset)
        opcode = insns[offset * 2]
        if offset in wanted and opcode in (0x1A, 0x1B):
            found[offset] = struct.unpack_from("<H" if opcode == 0x1A else "<I", insns, offset * 2 + 2)[0]
        offset += width
    return found


def _const_string_index(insns: bytes, offset: int) -> int | None:
    return _const_string_indexes(insns, {offset}).get(offset)


def _parse_dex(data: bytes) -> _ParsedDex:
    try:
        return _parse_dex_bytes(data)
    except (struct.error, _DexParseError, IndexError, OverflowError) as exc:
        raise _DexParseError() from exc


def _parse_dex_bytes(data: bytes) -> _ParsedDex:
    if len(data) < 0x70 or not data.startswith(b"dex\n") or data[7:8] != b"\x00":
        raise _DexParseError()
    if data[4:7] not in _DEX_VERSIONS:
        raise _DexParseError()
    file_size = _u32(data, 32)
    if _u32(data, 36) != 0x70 or _u32(data, 40) != 0x12345678:
        raise _DexParseError()
    if file_size < 0x70 or file_size > len(data):
        raise _DexParseError()
    limit = file_size
    string_ids_size, string_ids_off = _u32(data, 56), _u32(data, 60)
    type_ids_size, type_ids_off = _u32(data, 64), _u32(data, 68)
    proto_ids_size, proto_ids_off = _u32(data, 72), _u32(data, 76)
    method_ids_size, method_ids_off = _u32(data, 88), _u32(data, 92)
    class_defs_size, class_defs_off = _u32(data, 96), _u32(data, 100)
    _require_table(string_ids_off, string_ids_size, 4, limit)
    _require_table(type_ids_off, type_ids_size, 4, limit)
    _require_table(proto_ids_off, proto_ids_size, 12, limit)
    _require_table(method_ids_off, method_ids_size, 8, limit)
    _require_table(class_defs_off, class_defs_size, 32, limit)
    strings: list[str] = []
    decoded_strings: dict[int, str] = {}
    total_string_chars = 0
    for index in range(string_ids_size):
        offset = _u32(data, string_ids_off + 4 * index)
        text = decoded_strings.get(offset)
        if text is None:
            text, _end = _decode_mutf8(data, offset, limit)
            decoded_strings[offset] = text
        total_string_chars += len(text)
        if total_string_chars > 2 * limit:
            raise _DexParseError()
        strings.append(text)
    type_ids: list[int] = []
    for index in range(type_ids_size):
        descriptor_idx = _u32(data, type_ids_off + 4 * index)
        if descriptor_idx >= len(strings) or not strings[descriptor_idx]:
            raise _DexParseError()
        type_ids.append(descriptor_idx)
    state = _DexParseState()
    protos: list[tuple[int, tuple[int, ...]]] = []
    for index in range(proto_ids_size):
        base = proto_ids_off + 12 * index
        shorty_idx = _u32(data, base)
        return_idx = _u32(data, base + 4)
        params_off = _u32(data, base + 8)
        if shorty_idx >= len(strings) or return_idx >= len(type_ids):
            raise _DexParseError()
        protos.append((return_idx, _type_list(data, params_off, limit, len(type_ids), state)))
    descriptors: list[str] = []
    seen_descriptors: set[str] = set()
    total_descriptor_chars = 0
    for index in range(method_ids_size):
        base = method_ids_off + 8 * index
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, base)
        if class_idx >= len(type_ids) or proto_idx >= len(protos) or name_idx >= len(strings):
            raise _DexParseError()
        return_idx, param_idxs = protos[proto_idx]
        cached = state.proto_params.get(proto_idx)
        if cached is None:
            params = ""
            params_len = sum(len(strings[type_ids[item]]) for item in param_idxs)
        else:
            params, params_len = cached
        descriptor_len = (
            len(strings[type_ids[class_idx]]) + 2 + len(strings[name_idx]) + 1
            + params_len + 1 + len(strings[type_ids[return_idx]])
        )
        if total_descriptor_chars + descriptor_len > 8 * limit:
            raise _DexParseError()
        if cached is None:
            params = _join_params(strings, type_ids, param_idxs)
            state.proto_params[proto_idx] = (params, params_len)
        descriptor = (
            f"{strings[type_ids[class_idx]]}->{strings[name_idx]}({params}){strings[type_ids[return_idx]]}"
        )
        if descriptor in seen_descriptors:
            raise _DexParseError()
        seen_descriptors.add(descriptor)
        total_descriptor_chars += descriptor_len
        descriptors.append(descriptor)
    methods: dict[str, _DexCode] = {}
    for index in range(class_defs_size):
        class_data_off = _u32(data, class_defs_off + 32 * index + 24)
        if class_data_off == 0:
            continue
        if class_data_off >= limit:
            raise _DexParseError()
        if class_data_off in state.class_data_seen:
            continue
        state.class_data_seen.add(class_data_off)
        _read_class_methods(data, class_data_off, limit, descriptors, methods, state)
    return _ParsedDex(tuple(strings), methods)


def _join_params(
    strings: list[str], type_ids: list[int], param_idxs: tuple[int, ...],
) -> str:
    return "".join(strings[type_ids[item]] for item in param_idxs)


def _read_class_methods(
    data: bytes,
    start: int,
    limit: int,
    descriptors: list[str],
    methods: dict[str, _DexCode],
    state: _DexParseState,
) -> None:
    pos = start
    static_count, pos = _uleb128(data, pos, limit)
    instance_count, pos = _uleb128(data, pos, limit)
    direct_count, pos = _uleb128(data, pos, limit)
    virtual_count, pos = _uleb128(data, pos, limit)
    remaining = limit - pos
    if static_count > remaining // 2 or instance_count > remaining // 2:
        raise _DexParseError()
    if direct_count + virtual_count > len(descriptors):
        raise _DexParseError()
    state.class_entries += static_count + instance_count + direct_count + virtual_count
    if state.class_entries > 2 * limit:
        raise _DexParseError()
    for _index in range(static_count + instance_count):
        _diff, pos = _uleb128(data, pos, limit)
        _access, pos = _uleb128(data, pos, limit)
    for count in (direct_count, virtual_count):
        method_idx = 0
        for _index in range(count):
            diff, pos = _uleb128(data, pos, limit)
            _access, pos = _uleb128(data, pos, limit)
            code_off, pos = _uleb128(data, pos, limit)
            method_idx += diff
            if method_idx >= len(descriptors):
                raise _DexParseError()
            if code_off == 0:
                continue
            code = _read_code_item(data, code_off, limit, state)
            descriptor = descriptors[method_idx]
            previous = methods.get(descriptor)
            if previous is not None and previous != code:
                raise _DexParseError()
            methods[descriptor] = code


def _read_code_item(
    data: bytes, code_off: int, limit: int, state: _DexParseState,
) -> _DexCode:
    cached = state.code_items.get(code_off)
    if cached is not None:
        return cached
    if code_off <= 0 or code_off % 4 or code_off + 16 > limit:
        raise _DexParseError()
    insns_size = struct.unpack_from("<HHHHII", data, code_off)[5]
    if insns_size > (limit - (code_off + 16)) // 2:
        raise _DexParseError()
    insns_len = insns_size * 2
    if state.code_bytes + insns_len > 2 * limit:
        raise _DexParseError()
    insns_off = code_off + 16
    insns = data[insns_off:insns_off + insns_len]
    if len(insns) != insns_len:
        raise _DexParseError()
    code = _DexCode(insns_off, insns_size, insns)
    state.code_bytes += insns_len
    state.code_items[code_off] = code
    return code


def _type_list(
    data: bytes, offset: int, limit: int, type_count: int, state: _DexParseState,
) -> tuple[int, ...]:
    if offset == 0:
        return ()
    cached = state.type_lists.get(offset)
    if cached is not None:
        return cached
    if offset % 4 or offset + 4 > limit:
        raise _DexParseError()
    size = _u32(data, offset)
    if size > (limit - (offset + 4)) // 2:
        raise _DexParseError()
    state.param_entries += size
    if state.param_entries > 2 * limit:
        raise _DexParseError()
    params: list[int] = []
    for index in range(size):
        type_idx = struct.unpack_from("<H", data, offset + 4 + 2 * index)[0]
        if type_idx >= type_count:
            raise _DexParseError()
        params.append(type_idx)
    result = tuple(params)
    state.type_lists[offset] = result
    return result


def _decode_mutf8(data: bytes, pos: int, limit: int) -> tuple[str, int]:
    utf16_size, pos = _uleb128(data, pos, limit)
    chars: list[str] = []
    while True:
        if pos >= limit:
            raise _DexParseError()
        lead = data[pos]
        pos += 1
        if lead == 0:
            break
        if lead < 0x80:
            chars.append(chr(lead))
            continue
        if lead & 0xE0 == 0xC0:
            if pos >= limit:
                raise _DexParseError()
            follow = data[pos]
            pos += 1
            if follow & 0xC0 != 0x80:
                raise _DexParseError()
            chars.append(chr(((lead & 0x1F) << 6) | (follow & 0x3F)))
            continue
        if lead & 0xF0 == 0xE0:
            if pos + 1 >= limit:
                raise _DexParseError()
            second = data[pos]
            third = data[pos + 1]
            pos += 2
            if second & 0xC0 != 0x80 or third & 0xC0 != 0x80:
                raise _DexParseError()
            chars.append(chr(((lead & 0x0F) << 12) | ((second & 0x3F) << 6) | (third & 0x3F)))
            continue
        raise _DexParseError()
    if len(chars) != utf16_size:
        raise _DexParseError()
    return _join_surrogates("".join(chars)), pos


def _join_surrogates(text: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(text):
        code = ord(text[index])
        if 0xD800 <= code <= 0xDBFF and index + 1 < len(text):
            low = ord(text[index + 1])
            if 0xDC00 <= low <= 0xDFFF:
                point = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                out.append(chr(point))
                index += 2
                continue
        out.append(text[index])
        index += 1
    return "".join(out)


def _uleb128(data: bytes, pos: int, limit: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _index in range(5):
        if pos >= limit:
            raise _DexParseError()
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            if value > 0xFFFFFFFF:
                raise _DexParseError()
            return value, pos
        shift += 7
    raise _DexParseError()


def _u32(data: bytes, pos: int) -> int:
    if pos < 0 or pos + 4 > len(data):
        raise _DexParseError()
    return struct.unpack_from("<I", data, pos)[0]


def _require_table(offset: int, count: int, width: int, limit: int) -> None:
    if count == 0:
        return
    if offset < 0 or offset > limit or offset % 4 or width <= 0:
        raise _DexParseError()
    if (limit - offset) // width < count:
        raise _DexParseError()


def _render_projections(report: dict[str, Any]) -> tuple[bytes, bytes]:
    from apkscan.core.report_io import report_from_dict
    from apkscan.report.digest import build_digest
    from apkscan.report.html import render_to_string

    digest = (json.dumps(build_digest(report), ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    html = render_to_string(report_from_dict(report)).encode("utf-8")
    return digest, html


def _central_directory(handle: Any, size: int, limits: DexQueryLimits) -> list[dict[str, Any]]:
    tail_len = min(size, 22 + 65535)
    handle.seek(size - tail_len)
    tail = handle.read(tail_len)
    total, cd_size, cd_off = _end_of_central_directory(tail)
    if cd_size > limits.input_bytes or cd_off > size or cd_off + cd_size > size:
        raise DexQueryError("oversize")
    handle.seek(cd_off)
    central = handle.read(cd_size)
    if len(central) != cd_size:
        raise DexQueryError("input_rejected")
    entries: list[dict[str, Any]] = []
    names: set[str] = set()
    cursor = 0
    for _index in range(total):
        if cursor + 46 > len(central) or central[cursor:cursor + 4] != b"PK\x01\x02":
            raise DexQueryError("input_rejected")
        (
            flags, method, _time, _date, crc, compressed, uncompressed,
            name_len, extra_len, comment_len,
        ) = struct.unpack_from("<HHHHIIIHHH", central, cursor + 8)
        record_end = cursor + 46 + name_len + extra_len + comment_len
        if record_end > len(central):
            raise DexQueryError("input_rejected")
        local_off = struct.unpack_from("<I", central, cursor + 42)[0]
        try:
            name = central[cursor + 46:cursor + 46 + name_len].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DexQueryError("path_rejected") from exc
        if name in names:
            raise DexQueryError("duplicate_member")
        names.add(name)
        if _bad_zip_name(name):
            raise DexQueryError("path_rejected")
        if flags & 0x1:
            raise DexQueryError("input_rejected")
        if compressed > limits.uncompressed_bytes or uncompressed > limits.uncompressed_bytes:
            raise DexQueryError("oversize")
        if compressed and uncompressed > compressed * limits.max_compression_ratio:
            raise DexQueryError("zip_bomb")
        entries.append({
            "name": name,
            "flags": flags,
            "method": method,
            "crc": crc,
            "compressed": compressed,
            "uncompressed": uncompressed,
            "local_off": local_off,
        })
        cursor = record_end
    if cursor != len(central):
        raise DexQueryError("input_rejected")
    return entries


def _end_of_central_directory(tail: bytes) -> tuple[int, int, int]:
    """只接受注释长度刚好落到文件末尾的 EOCD。签名本身不计入后续字段。"""
    for offset in range(len(tail) - 22, -1, -1):
        if tail[offset:offset + 4] != b"PK\x05\x06":
            continue
        disk, central_disk, disk_entries, total, cd_size, cd_off, comment_len = struct.unpack_from(
            "<HHHHIIH", tail, offset + 4,
        )
        if offset + 22 + comment_len != len(tail):
            continue
        if disk != 0 or central_disk != 0 or disk_entries != total:
            raise DexQueryError("input_rejected")
        if total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF:
            raise DexQueryError("input_rejected")
        return total, cd_size, cd_off
    raise DexQueryError("input_rejected")


def _read_member(handle: Any, entry: Mapping[str, Any], limits: DexQueryLimits) -> bytes:
    handle.seek(int(entry["local_off"]))
    local = handle.read(30)
    if len(local) != 30 or local[:4] != b"PK\x03\x04":
        raise DexQueryError("input_rejected")
    local_flags, method, _time, _date, local_crc, local_comp, local_uncomp = struct.unpack_from(
        "<HHHHIII", local, 6,
    )
    name_len, extra_len = struct.unpack_from("<HH", local, 26)
    compressed = int(entry["compressed"])
    uncompressed = int(entry["uncompressed"])
    if method != int(entry["method"]):
        raise DexQueryError("input_rejected")
    if not (local_flags & 0x08) and (
        local_comp != compressed or local_uncomp != uncompressed or local_crc != int(entry["crc"])
    ):
        raise DexQueryError("crc_mismatch")
    handle.seek(int(entry["local_off"]) + 30 + name_len + extra_len)
    compressed_blob = handle.read(compressed)
    if len(compressed_blob) != compressed:
        raise DexQueryError("input_rejected")
    if method == 0:
        data = compressed_blob
    elif method == 8:
        data = _inflate_bounded(compressed_blob, uncompressed)
    else:
        raise DexQueryError("input_rejected")
    if len(data) != uncompressed or len(data) > limits.uncompressed_bytes:
        raise DexQueryError("zip_bomb")
    if (zlib.crc32(data) & 0xFFFFFFFF) != int(entry["crc"]):
        raise DexQueryError("crc_mismatch")
    return data


def _inflate_bounded(blob: bytes, uncompressed: int) -> bytes:
    """解压输出停在声明长度加一字节。超出或流未结束都按炸弹拒绝，不把整段展开后再限额。"""
    decoder = zlib.decompressobj(wbits=-15)
    try:
        data = decoder.decompress(blob, uncompressed + 1)
        if not decoder.eof:
            raise DexQueryError("zip_bomb")
        remainder = decoder.flush()
    except DexQueryError:
        raise
    except zlib.error as exc:
        raise DexQueryError("zip_bomb") from exc
    if remainder:
        raise DexQueryError("zip_bomb")
    return data


def _bad_zip_name(name: str) -> bool:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        return True
    if len(name) > 1 and name[1] == ":":
        return True
    parts = name.removesuffix("/").split("/")
    return any(part in {"", ".", ".."} for part in parts)


def _is_dex_name(name: object) -> bool:
    return isinstance(name, str) and name.lower().endswith(".dex") and not name.endswith("/")


def _validate_query_binding(receipt: Mapping[str, Any]) -> None:
    if receipt.get("query_kind") != "string-xref":
        raise DexQueryError("invalid_schema")
    values = receipt.get("query_values")
    if not isinstance(values, list) or not values:
        raise DexQueryError("invalid_schema")
    if any(not isinstance(item, str) or not item for item in values):
        raise DexQueryError("invalid_type")
    summary = hashlib.sha256(
        json.dumps(list(values), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if summary != receipt.get("query_summary_sha256"):
        raise DexQueryError("identity_mismatch")


_MEMBER_KEYS = frozenset({
    "ordinal", "name", "sha256", "role", "status", "reason",
    "precision", "truncated", "hits", "lineage",
})
_HIT_KEYS = frozenset({
    "value_sha256", "descriptor", "offset", "offset_unit",
    "file_offset", "grade", "precision", "evidence_sha256",
})
_MEMBER_STATUS = frozenset({"hit", "no_match", "partial", "failed", "skipped", "unsupported"})


def _validate_member_rows(members: list[Any], allowed_hashes: set[str]) -> None:
    for member in members:
        if not isinstance(member, dict):
            raise DexQueryError("invalid_type")
        if set(member) - _MEMBER_KEYS:
            raise DexQueryError("unknown_field")
        if not _MEMBER_KEYS <= set(member):
            raise DexQueryError("invalid_schema")
        if member.get("status") not in _MEMBER_STATUS:
            raise DexQueryError("invalid_type")
        hits = member.get("hits")
        if not isinstance(hits, list):
            raise DexQueryError("invalid_type")
        if member.get("status") in {"failed", "skipped", "unsupported"} and hits:
            raise DexQueryError("invalid_schema")
        for hit in hits:
            _validate_hit(hit, allowed_hashes)


def _validate_hit(hit: object, allowed_hashes: set[str]) -> None:
    if not isinstance(hit, dict):
        raise DexQueryError("invalid_type")
    if set(hit) != _HIT_KEYS:
        raise DexQueryError("unknown_field")
    value_sha = hit.get("value_sha256")
    if not isinstance(value_sha, str) or value_sha not in allowed_hashes:
        raise DexQueryError("identity_mismatch")
    if hit.get("precision") == "exact" and (
        _legal_descriptor(hit.get("descriptor")) is None
        or _nonnegative_int(hit.get("offset")) is None
        or hit.get("offset_unit") not in {"code_units", "dex_file_bytes"}
        or _nonnegative_int(hit.get("file_offset")) is None
    ):
        raise DexQueryError("invalid_type")
    body = {key: value for key, value in hit.items() if key != "evidence_sha256"}
    if hashlib.sha256(_canonical_text(body)).hexdigest() != hit.get("evidence_sha256"):
        raise DexQueryError("identity_mismatch")


def _query_hashes(receipt: Mapping[str, Any]) -> set[str]:
    values = receipt.get("query_values")
    if not isinstance(values, list):
        return set()
    return {
        hashlib.sha256(value.encode("utf-8")).hexdigest()
        for value in values if isinstance(value, str)
    }


_CLAIM_KEYS = frozenset({"path", "relpath", "relative_path", "bundle_relative_path"})
_ATTACHMENT_ROOTS = frozenset({
    "dex-query", "native_recovery", "external_observations", "input_report", "raw-responses",
})


def _reject_relative(relative: str) -> None:
    if not relative or "\\" in relative or relative.startswith("/") or ".." in relative.split("/"):
        raise DexQueryError("path_escape")
    if any(part in {"", ".", ".."} for part in relative.split("/")):
        raise DexQueryError("path_escape")


def _resolve_relative(root: Path, relative: str) -> Path:
    _reject_relative(relative)
    current = root
    if current.is_symlink():
        raise DexQueryError("path_escape")
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            raise DexQueryError("path_escape")
    try:
        if not current.is_file():
            raise DexQueryError("attachment_missing")
        current.resolve().relative_to(root.resolve())
    except DexQueryError:
        raise
    except (OSError, ValueError) as exc:
        raise DexQueryError("path_escape") from exc
    return current


def _read_resolved(target: Path, limit: int) -> bytes:
    if target.stat().st_size > limit:
        raise DexQueryError("oversize")
    with target.open("rb") as stream:
        blob = read_limited(stream, limit)
    if len(blob) > limit:
        raise DexQueryError("oversize")
    return blob


def _read_relative(root: Path, relative: str, limit: int) -> bytes:
    return _read_resolved(_resolve_relative(root, relative), limit)


def _dex_receipt_specs(report: Mapping[str, Any]) -> list[tuple[str, str]]:
    meta = report.get("meta")
    raw = meta.get("dex_query") if isinstance(meta, dict) else None
    receipts = raw.get("receipts") if isinstance(raw, dict) else None
    if receipts is None:
        return []
    if not isinstance(receipts, list):
        raise DexQueryError("dex_receipt_mismatch")
    specs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in receipts:
        receipt_id = item.get("receipt_id") if isinstance(item, dict) else None
        digest = item.get("sha256") if isinstance(item, dict) else None
        if (
            not isinstance(receipt_id, str)
            or _HEX64.fullmatch(receipt_id) is None
            or receipt_id in seen
            or not isinstance(digest, str)
            or _HEX64.fullmatch(digest) is None
        ):
            raise DexQueryError("dex_receipt_mismatch")
        seen.add(receipt_id)
        specs.append((receipt_id, digest))
    return specs


def _copy_dex_receipts(report_path: Path, specs: list[tuple[str, str]]) -> list[tuple[str, bytes]]:
    copied: list[tuple[str, bytes]] = []
    limit = DexQueryLimits().input_bytes
    for receipt_id, digest in specs:
        relative = f"dex-query/{receipt_id}.json"
        blob = _read_relative(report_path.parent, relative, limit)
        if hashlib.sha256(blob).hexdigest() != digest:
            raise DexQueryError("tampered_attachment")
        copied.append((relative, blob))
    return copied


def collect_receipt_files(report_dir: Path, meta: Mapping[str, Any]) -> dict[str, bytes]:
    if not isinstance(meta, Mapping) or "dex_query" not in meta:
        return {}
    raw = meta["dex_query"]
    receipts = raw.get("receipts") if isinstance(raw, Mapping) else None
    if not isinstance(receipts, list):
        raise DexQueryError("dex_receipt_mismatch")
    if len(receipts) > _MAX_RECEIPT_FILES:
        raise DexQueryError("dex_receipt_oversize")
    collected: dict[str, bytes] = {}
    seen: set[str] = set()
    limit = DexQueryLimits().input_bytes
    total = 0
    for item in receipts:
        receipt_id = item.get("receipt_id") if isinstance(item, dict) else None
        digest = item.get("sha256") if isinstance(item, dict) else None
        if (
            not isinstance(receipt_id, str)
            or _HEX64.fullmatch(receipt_id) is None
            or receipt_id in seen
            or not isinstance(digest, str)
            or _HEX64.fullmatch(digest) is None
        ):
            raise DexQueryError("dex_receipt_mismatch")
        seen.add(receipt_id)
        relative = f"dex-query/{receipt_id}.json"
        try:
            target = _resolve_relative(report_dir, relative)
            remaining = limit - total
            blob = _read_resolved(target, min(limit, remaining))
        except DexQueryError as exc:
            if exc.reason == "attachment_missing":
                raise DexQueryError("dex_receipt_missing") from None
            if exc.reason in {"oversize", "dex_receipt_oversize"}:
                raise DexQueryError("dex_receipt_oversize") from None
            raise DexQueryError("dex_receipt_mismatch") from None
        if hashlib.sha256(blob).hexdigest() != digest:
            raise DexQueryError("dex_receipt_mismatch")
        total += len(blob)
        if total > limit:
            raise DexQueryError("dex_receipt_oversize")
        collected[relative] = blob
    return collected


def _copy_raw_responses(report_path: Path, report: Mapping[str, Any]) -> list[tuple[str, bytes]]:
    found: list[dict[str, Any]] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            relative = node.get("relpath")
            if (
                node.get("status") == "retained"
                and isinstance(relative, str)
                and relative.startswith("raw-responses/")
            ):
                found.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(report)
    copied: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    limit = DexQueryLimits().input_bytes
    for item in found:
        relative = str(item["relpath"])
        if relative in seen:
            continue
        seen.add(relative)
        blob = _read_relative(report_path.parent, relative, limit)
        digest = item.get("sha256")
        size = item.get("bytes")
        if (
            not isinstance(digest, str)
            or hashlib.sha256(blob).hexdigest() != digest
            or isinstance(size, bool)
            or size != len(blob)
        ):
            raise DexQueryError("tampered_attachment")
        copied.append((relative, blob))
    return copied


def _copy_known_history(report_path: Path, report: dict[str, Any]) -> list[tuple[str, bytes]]:
    from apkscan.core import web_supplement_report as supplement

    copied: list[tuple[str, bytes]] = []
    try:
        for digest, blob in supplement._prepare_prior_snapshots(report_path, report):
            copied.append((f"input_report/{digest}/report.json", blob))
        copied.extend(supplement._prepare_native_history(report_path, report))
        supplement._verify_attachment_claims(report, report_path.parent)
        meta = report.get("meta")
        if isinstance(meta, dict) and isinstance(meta.get("web_observations"), list):
            for sha, root in supplement._referenced_trees(report, report_path.parent):
                disk = supplement._bounded_files(root)
                supplement._validate_manifest(sha, disk, {})
                for name, blob in sorted(disk.items()):
                    _reject_relative(name)
                    copied.append((f"external_observations/{sha}/{name}", blob))
    except supplement.SupplementRefusal as exc:
        raise DexQueryError(exc.reason) from exc
    return copied


def _collect_claim_paths(node: object, found: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _CLAIM_KEYS and isinstance(value, str):
                found.append(value)
            else:
                _collect_claim_paths(value, found)
    elif isinstance(node, list):
        for value in node:
            _collect_claim_paths(value, found)


def _reject_unknown_claims(report: Mapping[str, Any], copied: set[str]) -> None:
    claims: list[str] = []
    _collect_claim_paths(report, claims)
    for value in claims:
        normalized = value.replace("\\", "/")
        if PurePosixPath(normalized).is_absolute() or Path(value).is_absolute() or (len(value) > 2 and value[1] == ":"):
            continue
        if normalized.startswith("/") or ".." in normalized.split("/"):
            raise DexQueryError("path_escape")
        root = normalized.split("/", 1)[0]
        if root not in _ATTACHMENT_ROOTS:
            continue
        prefix = normalized if normalized.endswith("/") else normalized
        covered = prefix in copied or any(
            item == prefix or item.startswith(prefix if prefix.endswith("/") else prefix + "/")
            for item in copied
        )
        if not covered:
            raise DexQueryError("unknown_attachment")


def _retain_report_attachments(
    report_path: Path, report: dict[str, Any], prior_dex: list[tuple[str, str]],
) -> dict[str, Any]:
    """把原报告已经核验过的相对附件复制进新目录。绝对路径和 PCAP 仍留在 source_artifact_base。"""
    meta = report["meta"]
    existing = meta.get("source_artifact_base")
    if isinstance(existing, str) and Path(existing).is_absolute():
        source_base = existing
    else:
        source_base = str(report_path.parent.resolve())
        meta["source_artifact_base"] = source_base
    files = _copy_dex_receipts(report_path, prior_dex)
    files.extend(_copy_raw_responses(report_path, report))
    files.extend(_copy_known_history(report_path, report))
    copied = {relative for relative, _blob in files}
    _reject_unknown_claims(report, copied)
    return {
        "files": files,
        "summary": {
            "copied": sorted(copied),
            "source_artifact_base": source_base,
            "unmoved_types_remain_at_source_artifact_base": ["pcap"],
        },
    }


def _stable_snapshot(path: Path, limit: int) -> bytes:
    """一次读完。读入长度和前后大小不一致就拒绝，避免 APK 哈希和 DEX 清单来自两份字节。"""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DexQueryError("input_rejected") from exc
    if size > limit:
        raise DexQueryError("oversize")
    try:
        with path.open("rb") as handle:
            blob = handle.read(limit + 1)
        after = path.stat().st_size
    except OSError as exc:
        raise DexQueryError("input_rejected") from exc
    if len(blob) != size or after != size or len(blob) > limit:
        raise DexQueryError("input_rejected")
    return blob


def _sha256_file(path: Path, limit: int) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DexQueryError("input_rejected") from exc
    if size > limit:
        raise DexQueryError("oversize")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        remaining = size
        while remaining:
            block = handle.read(min(1024 * 1024, remaining))
            if not block:
                raise DexQueryError("input_rejected")
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DexQueryError("input_rejected") from exc
    if size > limit:
        raise DexQueryError("oversize")
    return path.read_bytes()


def _load_json(blob: bytes) -> Any:
    try:
        return json.loads(blob.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DexQueryError("invalid_schema") from exc


def _canonical_text(payload: Mapping[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _tree_matches(root: Path, planned: Mapping[str, bytes]) -> bool:
    for relative, blob in planned.items():
        target = root / relative
        try:
            if target.read_bytes() != blob:
                return False
        except OSError:
            return False
    return True
