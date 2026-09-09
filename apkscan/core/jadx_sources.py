"""Immutable, bounded Java query snapshots beside (not inside) legacy indexes.

Index 1.6 postings only cover values selected at build time. These snapshots let
later questions search actual decompiler output without changing frozen shards.
They are local sensitive evidence, never an upload format.
Path checks statically reject absolute paths, traversal and existing links.
They do not protect against concurrent changes or replacement after checks.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from apkscan.core.atomic import atomic_create_bytes

MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_FILES = 12000
MAX_SNAPSHOTS = 8
MAX_HITS = 10000
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def contained(root: Path, relative: str) -> Path:
    """Statically reject absolute paths, traversal and existing symlinks.

    Concurrent changes and replacement after checks are not guarded against.
    Paths whose ``resolve()`` differs from ``absolute()`` for benign reasons
    (Windows 8.3 short names, case normalization, macOS /var aliases) are
    accepted: only an actual symlink on the path is rejected.
    """
    root = root.absolute()
    path = root / relative
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("unsafe_relative_path")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("path_outside_root")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("linked_path")
        if part == root:
            break
    return path


def capture_sources(cache: Path, index_key: str, source: Path, *, coverage: str,
                    coverage_reasons: list[str] | None = None) -> dict[str, Any]:
    if not _HEX.fullmatch(index_key):
        raise ValueError("invalid_index_key")
    manifest = contained(cache, f"{index_key}/manifest.json").read_bytes()
    files = []
    total = 0
    reasons: set[str] = set(coverage_reasons or [])
    if coverage != "complete" and not reasons:
        reasons.add("upstream_coverage_partial")
    paths = sorted(source.rglob("*.java"), key=lambda p: p.relative_to(source).as_posix())
    if len(paths) > MAX_FILES:
        reasons.add("source_file_limit")
    for path in paths[:MAX_FILES]:
        if total >= MAX_SOURCE_BYTES:
            reasons.add("source_byte_limit")
            break
        relative = path.relative_to(source).as_posix()
        try:
            safe = contained(source, relative)
            with safe.open("rb") as stream:
                raw = stream.read(min(MAX_FILE_BYTES, MAX_SOURCE_BYTES - total) + 1)
            total += len(raw)
            if len(raw) > MAX_FILE_BYTES or total > MAX_SOURCE_BYTES:
                reasons.add("source_byte_limit")
                continue
            text = raw.decode("utf-8")
        except (OSError, UnicodeError, ValueError):
            reasons.add("source_unreadable")
            continue
        files.append({"path": relative, "sha256": digest_bytes(raw), "text": text})
    if not files:
        reasons.add("source_empty")
    payload = {
        "schema": "jadx-query-sources-1", "index_key": index_key,
        "index_manifest_sha256": digest_bytes(manifest),
        "coverage": "complete" if coverage == "complete" and not reasons else "partial",
        "reason_codes": sorted(reasons), "files": files,
        "source_kind": "decompiler_output",
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    digest = digest_bytes(raw)
    relative = f"query-sources/{index_key}/{digest}.json.gz"
    dest = contained(cache, relative)
    dest.parent.mkdir(parents=True, exist_ok=True)
    compressed = gzip.compress(raw, mtime=0)
    if dest.exists():
        if dest.read_bytes() != compressed:
            raise ValueError("source_snapshot_conflict")
    else:
        if not atomic_create_bytes(dest, compressed) and dest.read_bytes() != compressed:
            raise ValueError("source_snapshot_conflict")
    return {"locator": relative, "sha256": digest, "coverage": payload["coverage"],
            "file_count": len(files), "reason_codes": sorted(reasons)}


def query_sources(cache: Path, index_key: str, value: str) -> dict[str, Any]:
    if not _HEX.fullmatch(index_key) or not value or len(value) > 8192:
        raise ValueError("invalid_query")
    root = contained(cache, f"query-sources/{index_key}")
    paths = sorted(root.glob("*.json.gz")) if root.is_dir() else []
    reasons: set[str] = set()
    receipts = []
    hits = []
    manifest_digest = digest_bytes(contained(cache, f"{index_key}/manifest.json").read_bytes())
    if len(paths) > MAX_SNAPSHOTS:
        reasons.add("snapshot_limit")
    for path in paths[:MAX_SNAPSHOTS]:
        relative = path.relative_to(cache).as_posix()
        try:
            path = contained(cache, relative)
            with gzip.open(path, "rb") as stream:
                raw = stream.read(MAX_SOURCE_BYTES * 2 + 1)
            if len(raw) > MAX_SOURCE_BYTES * 2:
                raise ValueError("snapshot_too_large")
            digest = digest_bytes(raw)
            if path.name != f"{digest}.json.gz":
                raise ValueError("snapshot_hash_mismatch")
            data = json.loads(raw)
            if (data["schema"] != "jadx-query-sources-1" or data["index_key"] != index_key
                    or data["index_manifest_sha256"] != manifest_digest):
                raise ValueError("snapshot_binding_mismatch")
            if data["coverage"] not in ("complete", "partial"):
                raise ValueError("snapshot_coverage_invalid")
            files = data["files"]
            if not isinstance(files, list) or len(files) > MAX_FILES:
                raise ValueError("snapshot_files_invalid")
            # Validate the whole snapshot before admitting any hit.
            seen: set[str] = set()
            total = 0
            for item in files:
                text = item["text"]
                name = item["path"]
                contained(Path("/snapshot").absolute(), name)
                encoded = text.encode("utf-8")
                total += len(encoded)
                if (name in seen or not name.endswith(".java") or len(encoded) > MAX_FILE_BYTES
                        or total > MAX_SOURCE_BYTES or digest_bytes(encoded) != item["sha256"]):
                    raise ValueError("snapshot_file_invalid")
                seen.add(name)
            receipts.append({"locator": relative, "sha256": digest, "coverage": data["coverage"],
                             "file_count": len(files)})
            if data["coverage"] != "complete" or not files:
                reasons.add("source_partial")
            for item in files:
                for line, text in enumerate(item["text"].splitlines(), 1):
                    offset = text.find(value)
                    while offset >= 0:
                        if len(hits) >= MAX_HITS:
                            reasons.add("source_hit_limit")
                            break
                        hits.append({"path": item["path"], "line": line, "column": offset + 1,
                                     "value_digest": "sha256:" + digest_bytes(value.encode()),
                                     "source_sha256": item["sha256"], "snapshot_sha256": digest,
                                     "context_binding": "source_snapshot_only"})
                        offset = text.find(value, offset + 1)
                if len(hits) >= MAX_HITS:
                    reasons.add("source_hit_limit")
                    break
        except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError):
            reasons.add("source_snapshot_invalid")
    if not paths:
        reasons.add("query_value_coverage_unknown")
    return {"hits": hits, "snapshots": receipts, "reason_codes": sorted(reasons),
            "coverage": "complete" if receipts and not reasons else "partial"}
