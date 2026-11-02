"""Bounded local evidence IO and exact APK-member binding."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import stat
import zipfile

SCHEMA = "fxapk-flutter/1"
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_FILES = 20000
MEMBERS = ("lib/arm64-v8a/libapp.so", "lib/arm64-v8a/libflutter.so")


class FlutterError(ValueError):
    """Stable reason code only; never include sample values in exceptions."""


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read(path: Path, limit: int = MAX_FILE) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise FlutterError("invalid_or_oversize_file")
    with path.open("rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise FlutterError("file_limit")
    return data


def load(path: Path, limit: int = 16 * 1024 * 1024):
    try:
        return json.loads(read(path, limit))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise FlutterError("invalid_json") from exc


def save(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def contained(root: Path, relative: str) -> Path:
    p = Path(relative)
    if not relative or p.is_absolute() or ".." in p.parts or "\\" in relative or ":" in relative:
        raise FlutterError("unsafe_path")
    target = root / p
    if not target.resolve().is_relative_to(root.resolve()):
        raise FlutterError("unsafe_path")
    for parent in (target, *target.parents):
        if parent == root.parent:
            break
        if parent.is_symlink() or getattr(parent, "is_junction", lambda: False)():
            raise FlutterError("unsafe_link")
    return target


def inventory(root: Path) -> list[dict]:
    rows = []
    total = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(base) / name
            relative = path.relative_to(root).as_posix()
            contained(root, relative)
            if name in dirs:
                continue
            if relative == "manifest.json":
                continue
            mode = path.stat().st_mode
            if not stat.S_ISREG(mode):
                raise FlutterError("invalid_file_type")
            size = path.stat().st_size
            total += size
            if size > MAX_FILE or total > MAX_TOTAL or len(rows) >= MAX_FILES:
                raise FlutterError("artifact_limit")
            rows.append({"path": relative, "size": size, "sha256": digest(path)})
    return sorted(rows, key=lambda row: row["path"])


def validate_bundle(root: Path) -> dict:
    data = load(root / "manifest.json")
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA:
        raise FlutterError("unsupported_bundle_schema")
    if not isinstance(data.get("cache_key"), str) or not re.fullmatch(r"[0-9a-f]{64}", data["cache_key"]):
        raise FlutterError("invalid_cache_key")
    source = data.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("apk_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", source["apk_sha256"]):
        raise FlutterError("invalid_bundle_source")
    if any(not isinstance(data.get(key), dict) for key in ("coverage", "compatibility", "identity")) or type(data.get("cache_hit")) is not bool:
        raise FlutterError("invalid_bundle_metadata")
    if data.get("status") != "ok" or inventory(root) != data.get("files"):
        raise FlutterError("bundle_incomplete_or_changed")
    for key, member in zip(("libapp", "libflutter"), MEMBERS):
        item = source.get(key)
        if not isinstance(item, dict):
            raise FlutterError("bundle_member_mismatch")
        if item.get("member") != member or digest(root / "input" / Path(member).name) != item.get("sha256"):
            raise FlutterError("bundle_member_mismatch")
    return data


def extract(apk: Path, destination: Path) -> dict:
    before = digest(apk)
    result: dict = {"apk_sha256": before}
    try:
        with zipfile.ZipFile(apk) as z:
            names = z.namelist()
            for key, member in zip(("libapp", "libflutter"), MEMBERS):
                if names.count(member) != 1:
                    raise FlutterError("arm64_flutter_pair_missing_or_duplicate")
                info = z.getinfo(member)
                if info.file_size <= 0 or info.file_size > MAX_FILE:
                    raise FlutterError("member_size_limit")
                target = destination / Path(member).name
                destination.mkdir(parents=True, exist_ok=True)
                total = 0
                with z.open(info) as src, target.open("xb") as out:
                    while chunk := src.read(min(1024 * 1024, MAX_FILE + 1 - total)):
                        total += len(chunk)
                        if total > MAX_FILE:
                            raise FlutterError("member_size_limit")
                        out.write(chunk)
                result[key] = {"member": member, "sha256": digest(target), "size": total}
    except (zipfile.BadZipFile, RuntimeError) as exc:
        raise FlutterError("invalid_apk_archive") from exc
    if digest(apk) != before:
        raise FlutterError("input_changed")
    return result
