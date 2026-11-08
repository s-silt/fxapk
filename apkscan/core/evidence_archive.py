"""Immutable ZIP64 evidence containers and bounded, verified member access.

The archive index is storage metadata, never a replacement for a case manifest.
Original member bytes (including manifests) are preserved without rewriting.
"""
from __future__ import annotations

import hashlib
import importlib
import fnmatch
import io
import json
import os
import posixpath
import re
import shutil
import stat
import struct
import sys
import tempfile
import time
import unicodedata
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO, Iterator

from apkscan.core.json_contract import parse_finite_json_float, reject_nonfinite_json_constant
from apkscan.core.json_io import loads_bounded

INDEX = "__fxapk_evidence_index__.json"
SCHEMA = "fxapk.evidence-archive.v1"
CHUNK = 1024 * 1024
ZSTD_METHODS = {20, 93}


class Compression(str, Enum):
    zstd = "zstd"
    deflate = "deflate"


class ArchiveError(ValueError):
    """Only stable metadata codes cross the command/report boundary."""


def _zstd_backend():
    """Lazy loading keeps existing DEFLATE archives usable if the codec is absent."""
    try:
        module = "compression.zstd" if sys.version_info >= (3, 14) else "backports.zstd"
        return importlib.import_module(module)
    except ImportError as error:
        raise ArchiveError("archive_zstd_dependency_missing") from error


def _writer(compression: str, level: int):
    if compression not in {"zstd", "deflate"}:
        raise ArchiveError("archive_compression_unsupported")
    if type(level) is not int or not (1 if compression == "zstd" else 0) <= level <= 9:
        raise ArchiveError("archive_level_invalid")
    if compression == "deflate":
        return zipfile, zipfile.ZIP_DEFLATED
    _zstd_backend()
    try:
        module = zipfile if sys.version_info >= (3, 14) else importlib.import_module("backports.zstd.zipfile")
        return module, 93
    except ImportError as error:
        raise ArchiveError("archive_zstd_dependency_missing") from error


@dataclass(frozen=True)
class Limits:
    archive_bytes: int = 256 * 1024**3
    total_bytes: int = 256 * 1024**3
    member_bytes: int = 64 * 1024**3
    members: int = 100_000
    metadata_bytes: int = 32 * 1024**2
    seconds: float = 3600


def _name(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ArchiveError("archive_member_path_invalid")
    parts = value.split("/")
    if any(not p or p in {".", ".."} or p.endswith((".", " ")) or
           re.search(r'[\\:\x00-\x1f<>"|?*]', p) or
           re.fullmatch(r"(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?", p)
           for p in parts):
        raise ArchiveError("archive_member_path_invalid")
    return value


def _key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _regular(path: Path, *, directory: bool = False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ArchiveError("archive_links_not_supported")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ArchiveError("archive_input_not_regular")
    return info


def _identity(info) -> tuple:
    # CPython on Windows can expose creation time through lstat().st_ctime
    # and change time through fstat().st_ctime. Birth time is consistent.
    stamp = getattr(info, "st_birthtime_ns", info.st_ctime_ns) if os.name == "nt" else info.st_ctime_ns
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, stamp


def _deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise ArchiveError("archive_time_budget")


def _json(data: bytes) -> dict:
    def pairs(rows):
        out = {}
        for k, v in rows:
            if k in out:
                raise ArchiveError("archive_index_duplicate_key")
            out[k] = v
        return out
    try:
        value = loads_bounded(data, object_pairs_hook=pairs,
                              parse_float=parse_finite_json_float,
                              parse_constant=reject_nonfinite_json_constant)
    except (ValueError, RecursionError, UnicodeError) as error:
        raise ArchiveError("archive_index_invalid") from error
    if not isinstance(value, dict):
        raise ArchiveError("archive_index_invalid")
    return value


def _directory_entries(stream: BinaryIO, offset: int, size: int, count: int, limits: Limits) -> None:
    """Count actual headers without allocating ZipInfo objects or trusting EOCD."""
    end, actual = offset + size, 0
    stream.seek(offset)
    while stream.tell() < end:
        actual += 1
        if actual > limits.members + 1:
            raise ArchiveError("archive_directory_budget")
        header = stream.read(46)
        if len(header) != 46 or header[:4] != b"PK\x01\x02":
            raise ArchiveError("archive_directory_invalid")
        namesize, extrasize, commentsize = struct.unpack_from("<3H", header, 28)
        next_offset = stream.tell() + namesize + extrasize + commentsize
        if next_offset > end:
            raise ArchiveError("archive_directory_invalid")
        stream.seek(next_offset)
    if actual != count:
        raise ArchiveError("archive_directory_invalid")


def _directory_budget(stream: BinaryIO, size: int, limits: Limits) -> None:
    """Bound central-directory allocation BEFORE constructing ZipFile."""
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise ArchiveError("archive_directory_invalid")
    _, disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = struct.unpack_from("<4s4H2LH", tail, offset)
    if disk or cd_disk or disk_count != count or offset + 22 + comment != len(tail):
        raise ArchiveError("archive_directory_invalid")
    if count == 65535 or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        eocd = size - len(tail) + offset
        if eocd < 20:
            raise ArchiveError("archive_directory_invalid")
        stream.seek(eocd - 20)
        locator = stream.read(20)
        signature, disk, zip64_offset, disks = struct.unpack("<4sLQL", locator)
        if signature != b"PK\x06\x07" and count == 65535 and cd_size != 0xFFFFFFFF and cd_offset != 0xFFFFFFFF:
            # Classic ZIP can contain exactly 65535 members without a ZIP64 record.
            if count > limits.members + 1 or cd_size > limits.metadata_bytes or cd_offset + cd_size > size:
                raise ArchiveError("archive_directory_budget")
            _directory_entries(stream, cd_offset, cd_size, count, limits)
            stream.seek(0)
            return
        if signature != b"PK\x06\x07" or disk or disks != 1 or zip64_offset > eocd - 76:
            raise ArchiveError("archive_directory_invalid")
        stream.seek(zip64_offset)
        record = stream.read(56)
        if len(record) != 56:
            raise ArchiveError("archive_directory_invalid")
        signature, record_size, _, _, disk, cd_disk, disk_count, count, cd_size, cd_offset = struct.unpack("<4sQ2H2L4Q", record)
        if signature != b"PK\x06\x06" or record_size != 44 or disk or cd_disk or count != disk_count:
            raise ArchiveError("archive_directory_invalid")
    if count > limits.members + 1 or cd_size > limits.metadata_bytes or cd_offset + cd_size > size:
        raise ArchiveError("archive_directory_budget")
    _directory_entries(stream, cd_offset, cd_size, count, limits)
    stream.seek(0)


class EvidenceArchive:
    """Pinned archive handle; bounded decoding always verifies full member bytes."""

    def __init__(self, path: str | Path, limits: Limits | None = None):
        self.path = Path(path)
        self.limits = limits or Limits()
        self.deadline = time.monotonic() + self.limits.seconds
        before = _regular(self.path)
        if before.st_size > self.limits.archive_bytes:
            raise ArchiveError("archive_file_budget")
        self.stream = self.path.open("rb")
        self.zip: zipfile.ZipFile | None = None
        try:
            self.identity = _identity(os.fstat(self.stream.fileno()))
            if self.identity != _identity(before):
                raise ArchiveError("archive_changed")
            _directory_budget(self.stream, before.st_size, self.limits)
            self.zip = zipfile.ZipFile(self.stream)
            infos = self.zip.infolist()
            if len(infos) > self.limits.members + 1:
                raise ArchiveError("archive_directory_budget")
            seen: set[str] = set()
            total = 0
            self.infos: dict[str, zipfile.ZipInfo] = {}
            for item in infos:
                _deadline(self.deadline)
                name = _name(item.filename)
                folded = _key(name)
                if folded in seen:
                    raise ArchiveError("archive_duplicate_member")
                seen.add(folded)
                mode = item.external_attr >> 16
                if item.is_dir() or (stat.S_IFMT(mode) not in {0, stat.S_IFREG}) or item.flag_bits & 1:
                    raise ArchiveError("archive_member_type_unsupported")
                if item.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, *ZSTD_METHODS}:
                    raise ArchiveError("archive_compression_unsupported")
                if item.file_size > self.limits.member_bytes:
                    raise ArchiveError("archive_member_budget")
                total += item.file_size
                if total > self.limits.total_bytes + self.limits.metadata_bytes:
                    raise ArchiveError("archive_total_budget")
                self.infos[name] = item
            ordered = sorted(infos, key=lambda item: item.header_offset)
            self.member_ends = {item.filename: (ordered[i + 1].header_offset if i + 1 < len(ordered)
                                                else self.zip.start_dir) for i, item in enumerate(ordered)}
            if INDEX not in self.infos:
                raise ArchiveError("archive_index_missing")
            raw = self._decode(INDEX, self.limits.metadata_bytes)
            self.index_sha256 = hashlib.sha256(raw).hexdigest()
            self.index = _json(raw)
            rows = self.index.get("files")
            if self.index.get("schema_version") != SCHEMA or not isinstance(rows, list) or len(rows) > self.limits.members:
                raise ArchiveError("archive_index_invalid")
            self.files: dict[str, dict] = {}
            for row in rows:
                if not isinstance(row, dict):
                    raise ArchiveError("archive_index_invalid")
                name = _name(row.get("path"))
                if name in self.files or name == INDEX or name not in self.infos:
                    raise ArchiveError("archive_index_inventory_mismatch")
                if type(row.get("size")) is not int or row["size"] != self.infos[name].file_size:
                    raise ArchiveError("archive_member_size_mismatch")
                if not isinstance(row.get("sha256"), str) or not re.fullmatch("[0-9a-f]{64}", row["sha256"]):
                    raise ArchiveError("archive_index_invalid")
                self.files[name] = row
            if set(self.files) != set(self.infos) - {INDEX}:
                raise ArchiveError("archive_index_inventory_mismatch")
            directories = self.index.get("directories", [])
            if not isinstance(directories, list) or len(directories) > self.limits.members:
                raise ArchiveError("archive_index_invalid")
            self.directories = [_name(d) for d in directories]
            if len({_key(d) for d in self.directories}) != len(self.directories):
                raise ArchiveError("archive_member_path_collision")
            # A file cannot also be the parent directory of another member.
            folded_files = {_key(n) for n in self.files}
            if (any(_key(d) in folded_files for d in self.directories) or
                    any(_key(p.as_posix()) in folded_files for n in [*self.files, *self.directories]
                        for p in PurePosixPath(n).parents if p.as_posix() != ".")):
                raise ArchiveError("archive_member_path_collision")
            namespaces: dict[str, str] = {}
            for name in [*self.files, *self.directories]:
                for part in [PurePosixPath(name), *PurePosixPath(name).parents]:
                    text = part.as_posix()
                    if text == ".":
                        continue
                    key = _key(text)
                    if key in namespaces and namespaces[key] != text:
                        raise ArchiveError("archive_member_path_collision")
                    namespaces[key] = text
            self.decoded_bytes = 0
        except (zipfile.BadZipFile, zlib.error, EOFError, struct.error, UnicodeError) as error:
            self.close()
            raise ArchiveError("archive_directory_invalid") from error
        except Exception:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        if self.zip is not None:
            self.zip.close()
        self.stream.close()

    def _unchanged(self):
        if (_identity(os.fstat(self.stream.fileno())) != self.identity
                or _identity(_regular(self.path)) != self.identity):
            raise ArchiveError("archive_changed")

    def _member_data(self, info: zipfile.ZipInfo) -> None:
        """Validate the local header and position the stream at member data."""
        self.stream.seek(info.header_offset)
        header = self.stream.read(30)
        if len(header) != 30:
            raise ArchiveError("archive_local_header_invalid")
        signature, _, flags, method, _, _, crc, packed, plain, namesize, extrasize = struct.unpack("<4s5H3L2H", header)
        if (signature != b"PK\x03\x04" or method != info.compress_type or flags != info.flag_bits
                or flags & ~(0x80E if method == zipfile.ZIP_DEFLATED else 0x808)):
            raise ArchiveError("archive_local_header_invalid")
        name, extra = self.stream.read(namesize), self.stream.read(extrasize)
        if len(name) != namesize or len(extra) != extrasize:
            raise ArchiveError("archive_local_header_invalid")
        if name.decode("utf-8" if flags & 0x800 else "cp437") != info.orig_filename:
            raise ArchiveError("archive_local_header_invalid")
        # ZIP64 local sizes are in the extra field in uncompressed/compressed order.
        cursor, extended = 0, None
        while cursor < len(extra):
            if cursor + 4 > len(extra):
                raise ArchiveError("archive_local_header_invalid")
            tag, length = struct.unpack_from("<HH", extra, cursor)
            cursor += 4
            if cursor + length > len(extra):
                raise ArchiveError("archive_local_header_invalid")
            if tag == 1:
                if extended is not None:
                    raise ArchiveError("archive_local_header_invalid")
                extended = extra[cursor:cursor + length]
            cursor += length
        if not flags & 8:
            offset = 0
            sizes = [plain, packed]
            for i, size in enumerate(sizes):
                if size == 0xFFFFFFFF:
                    if extended is None or len(extended) < offset + 8:
                        raise ArchiveError("archive_local_header_invalid")
                    sizes[i] = struct.unpack_from("<Q", extended, offset)[0]
                    offset += 8
            if sizes != [info.file_size, info.compress_size] or crc != info.CRC:
                raise ArchiveError("archive_local_header_invalid")
        position = self.stream.tell()
        if info.header_offset < 0 or position + info.compress_size > self.member_ends[info.filename]:
            raise ArchiveError("archive_member_overlap")

    def _zstd_blocks(self, info: zipfile.ZipInfo, limit: int) -> Iterator[bytes]:
        """Require a complete bounded frame, exact span, CRC and original size."""
        codec = _zstd_backend()
        self._member_data(info)
        decoder = codec.ZstdDecompressor(options={codec.DecompressionParameter.window_log_max: 26})
        remaining, size, checksum = info.compress_size, 0, 0
        try:
            while not decoder.eof:
                _deadline(self.deadline)
                block = b""
                if decoder.needs_input:
                    if not remaining:
                        raise ArchiveError("archive_decode_failed")
                    block = self.stream.read(min(CHUNK, remaining))
                    if not block:
                        raise ArchiveError("archive_decode_failed")
                    remaining -= len(block)
                data = decoder.decompress(block, max_length=min(CHUNK, limit - size + 1, info.file_size - size + 1))
                size += len(data)
                if size > limit or size > info.file_size:
                    raise ArchiveError("archive_member_budget")
                checksum = zlib.crc32(data, checksum)
                if data:
                    yield data
            if remaining or decoder.unused_data or checksum != info.CRC:
                raise ArchiveError("archive_decode_failed")
        except codec.ZstdError as error:
            raise ArchiveError("archive_decode_failed") from error

    def _deflate_blocks(self, info: zipfile.ZipInfo, limit: int) -> Iterator[bytes]:
        # ZipExtFile stops at the advertised size, even without stream EOF or
        # with additional compressed payload. Do not let that certify integrity.
        self._member_data(info)
        decoder = zlib.decompressobj(-15)
        remaining, size, checksum = info.compress_size, 0, 0
        pending = b""
        while not decoder.eof:
            _deadline(self.deadline)
            if not pending:
                if not remaining:
                    raise ArchiveError("archive_decode_failed")
                pending = self.stream.read(min(CHUNK, remaining))
                if not pending:
                    raise ArchiveError("archive_decode_failed")
                remaining -= len(pending)
            data = decoder.decompress(pending, max_length=min(CHUNK, limit - size + 1, info.file_size - size + 1))
            pending = decoder.unconsumed_tail
            size += len(data)
            if size > limit or size > info.file_size:
                raise ArchiveError("archive_member_budget")
            checksum = zlib.crc32(data, checksum)
            if data:
                yield data
        if remaining or decoder.unused_data or checksum != info.CRC:
            raise ArchiveError("archive_decode_failed")

    def _copy(self, name: str, destination: BinaryIO, limit: int) -> tuple[str, int]:
        self._unchanged()
        info = self.infos.get(_name(name))
        if info is None:
            raise ArchiveError("archive_member_missing")
        if info.file_size > limit:
            raise ArchiveError("archive_member_budget")
        digest, size = hashlib.sha256(), 0
        assert self.zip is not None
        try:
            if info.compress_type in ZSTD_METHODS or info.compress_type == zipfile.ZIP_DEFLATED:
                blocks = (self._zstd_blocks(info, limit) if info.compress_type in ZSTD_METHODS
                          else self._deflate_blocks(info, limit))
                for block in blocks:
                    size += len(block)
                    digest.update(block)
                    destination.write(block)
            else:
                self._member_data(info)
                if info.compress_size != info.file_size:
                    raise ArchiveError("archive_member_size_mismatch")
                with self.zip.open(info) as source:
                    while True:
                        _deadline(self.deadline)
                        block = source.read(min(CHUNK, limit - size + 1))
                        if not block:
                            break
                        size += len(block)
                        if size > limit or size > info.file_size:
                            raise ArchiveError("archive_member_budget")
                        digest.update(block)
                        destination.write(block)
        except (zipfile.BadZipFile, EOFError, RuntimeError, zlib.error, struct.error, UnicodeError) as error:
            raise ArchiveError("archive_decode_failed") from error
        self._unchanged()
        if size != info.file_size:
            raise ArchiveError("archive_member_size_mismatch")
        return digest.hexdigest(), size

    def _decode(self, name: str, limit: int) -> bytes:
        output = io.BytesIO()
        self._copy(name, output, limit)
        return output.getvalue()

    def copy(self, name: str, destination: BinaryIO, *, limit: int | None = None) -> dict:
        row = self.files.get(_name(name))
        if row is None:
            raise ArchiveError("archive_member_missing")
        maximum = min(self.limits.member_bytes, limit if limit is not None else self.limits.member_bytes)
        if self.decoded_bytes + row["size"] > self.limits.total_bytes:
            raise ArchiveError("archive_total_budget")
        digest, size = self._copy(name, destination, maximum)
        self.decoded_bytes += size
        if digest != row["sha256"]:
            raise ArchiveError("archive_member_hash_mismatch")
        return {"state": "verified", "sha256": digest, "size": size, "index_sha256": self.index_sha256}

    def read(self, name: str, limit: int) -> bytes:
        output = io.BytesIO()
        self.copy(name, output, limit=limit)
        return output.getvalue()

    def verify(self) -> dict:
        with open(os.devnull, "wb") as sink:
            for name in self.files:
                self.copy(name, sink)
        return {"state": "verified", "files": len(self.files),
                "original_bytes": sum(r["size"] for r in self.files.values()),
                "index_sha256": self.index_sha256, "coverage": "all_members",
                "compression_methods": sorted({self.infos[n].compress_type for n in self.files})}

    def extract(self, output: Path, names: list[str] | None = None) -> dict:
        """A fresh directory only; failed extraction is retained as a failed stage."""
        output.mkdir(parents=True, exist_ok=False)
        if names is None:
            for name in self.directories:
                (output / name).mkdir(parents=True, exist_ok=True)
        selected = list(self.files) if names is None else names
        for name in selected:
            _name(name)
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                self.copy(name, stream)
        return {"state": "verified", "files": len(selected), "coverage": "selected_members" if names is not None else "all_members"}


def _walk_error(error: OSError) -> None:
    # os.walk otherwise silently skips unreadable directories, losing evidence.
    raise ArchiveError("archive_directory_unreadable") from error


def _inventory(root: Path, limits: Limits, deadline: float) -> list[tuple[str, os.stat_result]]:
    _regular(root, directory=True)
    rows, seen, total, directories = [], set(), 0, 0
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=_walk_error):
        _deadline(deadline)
        for name in dirs:
            _regular(Path(directory) / name, directory=True)
            _name((Path(directory) / name).relative_to(root).as_posix())
            directories += 1
            if directories > limits.members:
                raise ArchiveError("archive_source_budget")
        for name in sorted(files):
            path = Path(directory) / name
            info = _regular(path)
            rel = _name(path.relative_to(root).as_posix())
            if _key(rel) in seen or _key(rel) == _key(INDEX):
                raise ArchiveError("archive_duplicate_member")
            seen.add(_key(rel))
            total += info.st_size
            if len(rows) >= limits.members or total > limits.total_bytes or info.st_size > limits.member_bytes:
                raise ArchiveError("archive_source_budget")
            rows.append((rel, info))
    return sorted(rows)


def _publish(temporary: Path, target: Path) -> None:
    try:
        os.link(temporary, target)
    except FileExistsError:
        raise ArchiveError("archive_output_exists") from None
    except OSError:
        if os.name != "nt":
            raise ArchiveError("archive_atomic_publish_unsupported") from None
        try:
            os.rename(temporary, target)  # Windows rename is no-replace.
        except FileExistsError:
            raise ArchiveError("archive_output_exists") from None


def _directories(root: Path, limits: Limits, deadline: float) -> list[str]:
    result = []
    for folder, dirs, _ in os.walk(root, followlinks=False, onerror=_walk_error):
        _deadline(deadline)
        for name in dirs:
            path = Path(folder) / name
            _regular(path, directory=True)
            result.append(_name(path.relative_to(root).as_posix()))
            if len(result) > limits.members:
                raise ArchiveError("archive_source_budget")
    return sorted(result)


def pack(root: Path, output: Path, *, limits: Limits | None = None, level: int = 6,
         compression: str = "zstd", progress=None) -> dict:
    limits = limits or Limits()
    deadline = time.monotonic() + limits.seconds
    _regular(root, directory=True)
    root = root.resolve()
    output = output.absolute()
    if output.exists():
        raise ArchiveError("archive_output_exists")
    if output.resolve().is_relative_to(root):
        raise ArchiveError("archive_output_inside_source")
    writer, method = _writer(compression, level)
    inventory = _inventory(root, limits, deadline)
    directories = _directories(root, limits, deadline)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".fxapk-pack-", suffix=".tmp", dir=output.parent)
    temporary = Path(temp_name)
    rows = []
    try:
        with os.fdopen(fd, "w+b") as stream:
            with writer.ZipFile(stream, "w", compression=method, compresslevel=level, allowZip64=True) as bundle:
                for number, (name, before) in enumerate(inventory, 1):
                    digest, size = hashlib.sha256(), 0
                    path = root / name
                    if _identity(_regular(path)) != _identity(before):
                        raise ArchiveError("archive_source_changed")
                    with path.open("rb") as source, bundle.open(name, "w", force_zip64=True) as destination:
                        if _identity(os.fstat(source.fileno())) != _identity(before):
                            raise ArchiveError("archive_source_changed")
                        while block := source.read(CHUNK):
                            _deadline(deadline)
                            size += len(block)
                            if size > before.st_size:
                                raise ArchiveError("archive_source_changed")
                            digest.update(block)
                            destination.write(block)
                        if size != before.st_size or _identity(os.fstat(source.fileno())) != _identity(before):
                            raise ArchiveError("archive_source_changed")
                    rows.append({"path": name, "size": size, "sha256": digest.hexdigest(),
                                 "mtime_ns": before.st_mtime_ns, "mode": stat.S_IMODE(before.st_mode)})
                    if stream.tell() > limits.archive_bytes:
                        raise ArchiveError("archive_file_budget")
                    if progress:
                        progress({"id": "archive_pack", "state": "running", "completed_files": number, "total_files": len(inventory)})
                index = {"schema_version": SCHEMA, "files": rows, "directories": directories, "source_root_hint": str(root),
                         "byte_preservation": "exact", "metadata_coverage": "path_size_sha256_mtime_ns_mode",
                         "metadata_not_preserved": ["acl", "alternate_data_streams", "xattrs"]}
                raw = json.dumps(index, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
                if len(raw) > limits.metadata_bytes:
                    raise ArchiveError("archive_index_budget")
                # The index stays readable even when the Zstandard dependency is missing.
                bundle.writestr(INDEX, raw, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
            stream.flush()
            os.fsync(stream.fileno())
        after = _inventory(root, limits, deadline)
        if [(n, _identity(s)) for n, s in after] != [(n, _identity(s)) for n, s in inventory]:
            raise ArchiveError("archive_source_changed")
        if _directories(root, limits, deadline) != directories:
            raise ArchiveError("archive_source_changed")
        _deadline(deadline)
        with EvidenceArchive(temporary, replace(limits, seconds=max(0.001, deadline - time.monotonic()))) as archive:
            receipt = archive.verify()
        digest = hashlib.sha256()
        with temporary.open("rb") as source:
            while block := source.read(CHUNK):
                _deadline(deadline)
                digest.update(block)
        receipt.update(archive_sha256=digest.hexdigest(), archive_bytes=temporary.stat().st_size,
                       compression=compression, compression_level=level,
                       schema_version=SCHEMA, metadata_coverage=index["metadata_coverage"],
                       metadata_not_preserved=index["metadata_not_preserved"])
        _publish(temporary, output)
        if progress:
            progress({"id": "archive_pack", "state": "verified", "files": len(rows)})
        return receipt
    finally:
        temporary.unlink(missing_ok=True)


def split_reference(reference: str | Path) -> tuple[Path, str] | None:
    value = str(reference)
    if "::" not in value:
        return None
    outer, member = value.split("::", 1)
    if not outer:
        raise ArchiveError("archive_reference_invalid")
    return Path(outer), _name(member.replace("\\", "/"))


def resolve_reference(base: str | Path, reference: str) -> str:
    """Resolve relative inputs in a plan without escaping its archived source tree."""
    parent = split_reference(base)
    if parent is None:
        nested = split_reference(reference)
        if nested:
            path, member = nested
            return f"{path if path.is_absolute() else Path(base).parent / path}::{member}"
        path = Path(reference)
        return str(path if path.is_absolute() else Path(base).parent / path)
    outer, member = parent
    if "::" in reference:
        raise ArchiveError("archive_nested_reference_unsupported")
    if PurePosixPath(reference).is_absolute() or PureWindowsPath(reference).is_absolute():
        with EvidenceArchive(outer) as archive:
            hint = archive.index.get("source_root_hint")
        if not isinstance(hint, str):
            raise ArchiveError("archive_external_reference")
        path_type = PureWindowsPath if PureWindowsPath(hint).is_absolute() else PurePosixPath
        try:
            resolved = path_type(reference).relative_to(path_type(hint)).as_posix()
        except ValueError as error:
            raise ArchiveError("archive_external_reference") from error
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(member), reference.replace("\\", "/")))
    return f"{outer}::{_name(resolved)}"


def read_reference(reference: str | Path, limit: int) -> bytes:
    parsed = split_reference(reference)
    if parsed:
        with EvidenceArchive(parsed[0]) as archive:
            return archive.read(parsed[1], limit)
    path = Path(reference)
    if not path.is_file():
        raise ValueError("input_not_regular_file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input_byte_budget")
    return data


def archived_siblings(reference: str | Path, patterns: tuple[str, ...]) -> list[Path]:
    parsed = split_reference(reference)
    if parsed is None:
        return []
    outer, member = parsed
    parent = posixpath.dirname(member)
    with EvidenceArchive(outer) as archive:
        names = [name for name in archive.files if posixpath.dirname(name) == parent
                 and any(fnmatch.fnmatchcase(posixpath.basename(name), pattern) for pattern in patterns)]
    return [Path(f"{outer}::{name}") for name in sorted(names)]


def storage_projection(value: object) -> dict | None:
    """Public report metadata contains no original paths or unchecked strings."""
    if not isinstance(value, dict) or value.get("state") != "verified":
        return None
    if not all(isinstance(value.get(k), str) and re.fullmatch("[0-9a-f]{64}", value[k])
               for k in ("index_sha256", "input_sha256")):
        return None
    size = value.get("input_size")
    if type(size) is not int or not 0 <= size <= 64 * 1024**3:
        return None
    return {"state": "verified", "coverage": "selected_member", "source_binding_verified": False,
            "index_sha256": value["index_sha256"], "input_sha256": value["input_sha256"], "input_size": size}


@contextmanager
def materialize(reference: str | Path, *, limit: int = 64 * 1024**3) -> Iterator[Path]:
    parsed = split_reference(reference)
    if parsed is None:
        yield Path(reference)
        return
    with EvidenceArchive(parsed[0]) as archive, tempfile.TemporaryDirectory(prefix="fxapk-evidence-read-") as directory:
        path = Path(directory) / PurePosixPath(parsed[1]).name
        with path.open("xb") as output:
            archive.copy(parsed[1], output, limit=limit)
        yield path


def remove_owned_staging(path: Path, parent: Path) -> None:
    """Delete only our fresh staging tree, after verifying its containment/types."""
    resolved = path.resolve()
    if resolved.parent != parent.resolve() or not resolved.name.startswith(".fxapk-evidence-"):
        raise ArchiveError("archive_cleanup_boundary")
    _regular(path, directory=True)
    for folder, dirs, files in os.walk(path, followlinks=False, onerror=_walk_error):
        for name in dirs:
            _regular(Path(folder) / name, directory=True)
        for name in files:
            _regular(Path(folder) / name)
    shutil.rmtree(path)
