"""隔离进程里的 ASC 查询。宿主 fxapk 不导入本模块。

只调用 FindRefManager 已经使用的定位器和指令扫描器，不走 ApkHandler，
也不解析 findrefs 的人类文本。描述符或偏移对不上时标 partial，不挑选歧义方法。
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import re
import sys
from pathlib import Path
from typing import Any

PINNED_VERSION = "0.1.1.post5"
PINNED_REVISION = "d3d75ab7a3c092345102d2ec66ab614ad4a6cc75"
PINNED_FINDREFS_SHA256 = "99f170737a2a9fb67e4a7a681b98fbc0f56d9e53601cb33f3125b37fd6487b7c"
_SUPPORTED_MAGIC = {b"035", b"037", b"038", b"039"}


def _findrefs_sha256() -> str:
    module = importlib.import_module("droidasc.asc_core.findrefs.findrefs_manager")
    source = getattr(module, "__file__", None)
    if not isinstance(source, str):
        return ""
    return hashlib.sha256(Path(source).read_bytes()).hexdigest()


def _runtime_encoding() -> str:
    """只有 mutf8 1.1.0 且 U+1F600 为 CESU-8 eda0bdedb880 才算可用。不靠宿主偶然装到的旧包。"""
    try:
        version = importlib.metadata.version("mutf8")
        module = importlib.import_module("mutf8")
        encoded = module.encode_modified_utf8("\U0001F600")
    except Exception:
        return "rejected"
    if version != "1.1.0" or encoded != bytes.fromhex("eda0bdedb880"):
        return "rejected"
    return "mutf8-1.1.0"


def _identity() -> dict[str, str]:
    try:
        version = importlib.metadata.version("droidasc")
    except importlib.metadata.PackageNotFoundError:
        version = ""
    digest = _findrefs_sha256()
    revision = PINNED_REVISION if digest == PINNED_FINDREFS_SHA256 else "unknown"
    return {
        "provider_version": version,
        "provider_revision": revision,
        "findrefs_sha256": digest,
    }


def _emit(op: str, **extra: object) -> None:
    payload: dict[str, object] = {
        "schema_version": "asc-worker-result/1",
        "provider": "asc",
        "op": op,
    }
    payload.update(_identity())
    payload["runtime_encoding"] = _runtime_encoding()
    payload.update(extra)
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))


def _descriptor(dex: Any, mid: int) -> str | None:
    try:
        method = dex.methods[mid]
        proto = method.prototype
        params = "".join(item.descriptor for item in proto.parameters_type)
        returned = dex.get_type(proto.return_type_idx).descriptor
        return f"{method.cls.fullname}->{method.name}({params}){returned}"
    except Exception:
        return None


def _one_hit(
    dex: Any,
    scanner: Any,
    file_offset: int,
    mid: object,
    value_sha256: str,
) -> dict[str, object]:
    hit: dict[str, object] = {
        "value_sha256": value_sha256,
        "descriptor": None,
        "offset": None,
        "offset_unit": None,
        "file_offset": file_offset,
        "precision": "partial",
    }
    if not isinstance(mid, int) or isinstance(mid, bool):
        return hit
    descriptor = _descriptor(dex, mid)
    start = scanner.insn_locator.method_bounds.get(mid)
    if descriptor is None or not isinstance(start, int):
        return hit
    if file_offset < start or (file_offset - start) % 2:
        return hit
    hit["descriptor"] = descriptor
    hit["offset"] = (file_offset - start) // 2
    hit["offset_unit"] = "code_units"
    hit["precision"] = "exact"
    return hit


def _query_member(data: bytes, queries: list[str], max_hits: int) -> dict[str, object]:
    if not data.startswith(b"dex\n") or len(data) < 8:
        return {
            "status": "failed",
            "reason": "input_rejected",
            "precision": "unsupported",
            "truncated": False,
            "hits": [],
        }
    magic = data[4:7]
    if magic == b"041" or magic not in _SUPPORTED_MAGIC:
        return {
            "status": "unsupported",
            "reason": "dex_unsupported",
            "precision": "unsupported",
            "truncated": False,
            "hits": [],
        }
    dex_type = importlib.import_module("droidasc.asc_core.utils.tinydex").DEX
    manager_type = importlib.import_module(
        "droidasc.asc_core.findrefs.findrefs_manager"
    ).FindRefManager
    try:
        dex = dex_type(data)
        manager = manager_type(dex)
        scanner = manager._get_code_scanner()
        locator = manager._get_str_locator(True)
    except Exception:
        return {
            "status": "failed",
            "reason": "input_rejected",
            "precision": "unsupported",
            "truncated": False,
            "hits": [],
        }
    hits: list[dict[str, object]] = []
    truncated = False
    partial = False
    for query in queries:
        if truncated:
            break
        try:
            # ASC 把查询字节当正则。默认字面量，避免 '.' 命中别的常量。
            indexes = locator.locate(re.escape(query))
        except Exception:
            partial = True
            continue
        confirmed: list[int] = []
        for index in indexes or ():
            if isinstance(index, bool) or not isinstance(index, int):
                partial = True
                continue
            try:
                text = dex.get_string(index)
            except Exception:
                partial = True
                continue
            if text != query:
                continue
            confirmed.append(index)
        if not confirmed:
            continue
        offsets = scanner._scan_code_item("string", set(confirmed), True)
        located = scanner.insn_locator.locate(offsets)
        if not isinstance(located, list) or len(located) != len(offsets):
            partial = True
            continue
        value_sha = hashlib.sha256(query.encode("utf-8")).hexdigest()
        for file_offset, mid in zip(offsets, located, strict=True):
            if len(hits) >= max_hits:
                truncated = True
                break
            if isinstance(file_offset, bool) or not isinstance(file_offset, int):
                partial = True
                continue
            method_ids = _method_ids(mid)
            if not method_ids:
                partial = True
                hits.append(_one_hit(dex, scanner, file_offset, mid, value_sha))
                continue
            for method_id in method_ids:
                if len(hits) >= max_hits:
                    truncated = True
                    break
                hit = _one_hit(dex, scanner, file_offset, method_id, value_sha)
                if hit["precision"] != "exact":
                    partial = True
                hits.append(hit)
    if truncated or partial:
        status = "partial" if hits else "failed"
        precision = "partial"
    elif hits:
        status = "hit"
        precision = "exact"
    else:
        status = "no_match"
        precision = "exact"
    return {
        "status": status,
        "reason": None if hits else ("hit_limit" if truncated else "no_match"),
        "precision": precision,
        "truncated": truncated,
        "hits": hits,
    }


def _method_ids(mid: object) -> list[int]:
    """共享 code_item 时 locate 给出方法号列表。每个真实引用方法都要单独留下。"""
    if isinstance(mid, bool):
        return []
    if isinstance(mid, int):
        return [mid]
    if isinstance(mid, list) and mid and all(isinstance(item, int) and not isinstance(item, bool) for item in mid):
        return list(mid)
    return []


def _query(request: dict[str, Any]) -> None:
    if _runtime_encoding() != "mutf8-1.1.0":
        _emit(
            "query",
            engine_executed=False,
            reason="runtime_encoding_rejected",
            runtime_encoding="rejected",
            members=[],
        )
        return
    queries = request.get("queries")
    members = request.get("members")
    max_hits = request.get("max_hits")
    if not isinstance(queries, list) or not isinstance(members, list):
        sys.exit(2)
    if isinstance(max_hits, bool) or not isinstance(max_hits, int) or max_hits < 0:
        max_hits = 0
    rows = []
    for member in members:
        if not isinstance(member, dict):
            sys.exit(2)
        path = member.get("path")
        if not isinstance(path, str):
            sys.exit(2)
        data = Path(path).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        row: dict[str, object] = {
            "name": member.get("name"),
            "ordinal": member.get("ordinal"),
            "sha256": actual,
        }
        if actual != member.get("sha256"):
            row.update(
                status="failed",
                reason="identity_mismatch",
                precision="unsupported",
                truncated=False,
                hits=[],
            )
        else:
            row.update(_query_member(data, [item for item in queries if isinstance(item, str)], max_hits))
        rows.append(row)
    _emit("query", engine_executed=True, members=rows)


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(2)
    request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if not isinstance(request, dict) or request.get("schema_version") != "asc-worker-request/1":
        sys.exit(2)
    op = request.get("op")
    if op == "capabilities":
        _emit("capabilities", engine_executed=False)
        return
    if op == "query":
        _query(request)
        return
    sys.exit(2)


if __name__ == "__main__":
    main()
