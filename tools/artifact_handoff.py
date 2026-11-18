"""Offline artifact checks. Acceptance does not grant publication authority.

All context is explicit; importing this module performs no I/O. The optional
download adapter belongs to the caller and is invoked only after receipt checks.
No archive extraction, networking, or publishing is implemented here.
"""
import hashlib
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
import re
import stat
import zipfile
import zlib
from typing import NoReturn, TypeGuard


@dataclass(frozen=True, slots=True)
class Check:
    reason: str | None

    @property
    def accepted(self) -> bool:
        return self.reason is None


class _Reject(Exception):
    pass


def _reject(reason: str) -> NoReturn:
    raise _Reject(reason)


_FORMATS = {
    "GITHUB_REPOSITORY_ID": r"[1-9][0-9]{0,18}",
    "GITHUB_RUN_ID": r"[1-9][0-9]{0,18}",
    "GITHUB_RUN_ATTEMPT": r"[1-9][0-9]{0,18}",
    "GITHUB_SHA": r"[a-f0-9]{40}",
    "VERSION": r"[0-9]+\.[0-9]+\.[0-9]+",
}
_REASONS = {
    "GITHUB_REPOSITORY_ID": "REPOSITORY_MISMATCH",
    "GITHUB_RUN_ID": "RUN_MISMATCH",
    "GITHUB_RUN_ATTEMPT": "STALE_PRODUCER_ATTEMPT",
    "GITHUB_SHA": "COMMIT_MISMATCH",
    "VERSION": "VERSION_MISMATCH",
}

_LIMIT = 64 * 1024 * 1024
_DIGEST = re.compile(r"[a-f0-9]{64}")
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}")

def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result

def receipt_check(
    receiver: Mapping[str, object], raw: str, artifact_id: str, outer_digest: str
) -> Check:
    try:
        _receipt(dict(receiver), raw, artifact_id, outer_digest)
    except _Reject as failure:
        return Check(str(failure))
    return Check(None)


def _receipt(receiver: dict[str, object], raw: str, artifact_id: str, outer_digest: str) -> None:
    def valid_context(context: object) -> TypeGuard[dict[str, str]]:
        return (
            type(context) is dict
            and context.keys() == _FORMATS.keys()
            and all(type(context[key]) is str and len(context[key]) <= 40
                    and re.fullmatch(pattern, context[key])
                    for key, pattern in _FORMATS.items())
        )

    if not valid_context(receiver):
        _reject("RECEIVER_CONTEXT_INVALID")
    if not 0 < len(raw) <= 1024 or not raw.isascii():
        _reject("PRODUCER_RECEIPT_INVALID")
    try:
        producer = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, RecursionError):
        _reject("PRODUCER_RECEIPT_INVALID")
    if not valid_context(producer):
        _reject("PRODUCER_RECEIPT_INVALID")
    for key, reason in _REASONS.items():
        if producer[key] != receiver[key]:
            if key == "GITHUB_RUN_ATTEMPT" and int(producer[key]) > int(receiver[key]):
                _reject("FUTURE_PRODUCER_ATTEMPT")
            _reject(reason)

    if not re.fullmatch(r"[1-9][0-9]{0,18}", artifact_id):
        _reject("ARTIFACT_ID_INVALID")
    if not re.fullmatch(r"[a-f0-9]{64}", outer_digest):
        _reject("ARTIFACT_DIGEST_INVALID")


def archive_check(target: Path | None, raw: str, outer: str) -> Check:
    try:
        _archive(target, raw, outer)
    except _Reject as failure:
        return Check(str(failure))
    return Check(None)


def _archive(target: Path | None, raw: str, outer: str) -> None:
    if not 0 < len(raw) <= 4096 or not raw.isascii():
        _reject("INVENTORY_INVALID")
    try:
        expected = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, RecursionError):
        _reject("INVENTORY_INVALID")
    if (type(expected) is not dict or len(expected) != 11
            or "SHA256SUMS.txt" not in expected
            or not all(_FILENAME.fullmatch(name) and type(digest) is str and _DIGEST.fullmatch(digest)
                       for name, digest in expected.items())):
        _reject("INVENTORY_INVALID")
    if not _DIGEST.fullmatch(outer):
        _reject("ARTIFACT_DIGEST_INVALID")

    if target is None:
        _reject("ARCHIVE_PATH_INVALID")
    try:
        if target.is_symlink():
            _reject("ARCHIVE_PATH_INVALID")
        with os.scandir(target) as found:
            first = next(found, None)
            if first is None or next(found, None) is not None or not first.is_file(follow_symlinks=False):
                _reject("ARCHIVE_PATH_INVALID")
        with open(first.path, "rb") as archive:
            info = os.fstat(archive.fileno())
            if not stat.S_ISREG(info.st_mode):
                _reject("ARCHIVE_PATH_INVALID")
            if not 0 < info.st_size <= _LIMIT:
                _reject("ARCHIVE_SIZE_INVALID")
            if hashlib.file_digest(archive, "sha256").hexdigest() != outer:
                _reject("ARCHIVE_DIGEST_MISMATCH")
            archive.seek(0)
            with zipfile.ZipFile(archive) as bundle:
                entries = bundle.infolist()
                if len(entries) != len(expected) or {e.filename for e in entries} != expected.keys():
                    _reject("ARCHIVE_INVENTORY_MISMATCH")
                if sum(e.file_size for e in entries) > _LIMIT:
                    _reject("ARCHIVE_SIZE_INVALID")
                for e in entries:
                    if (e.is_dir() or e.flag_bits & 1 or e.orig_filename != e.filename
                            or stat.S_IFMT(e.external_attr >> 16) not in (0, stat.S_IFREG)
                            or e.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                        _reject("ARCHIVE_MEMBER_INVALID")
                    with bundle.open(e) as member:
                        digest = hashlib.sha256()
                        while chunk := member.read(65536):
                            digest.update(chunk)
                        if digest.hexdigest() != expected[e.filename]:
                            _reject("ARCHIVE_MEMBER_DIGEST_MISMATCH")
    except (OSError, zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, UnicodeDecodeError, zlib.error):
        _reject("ARCHIVE_READ_FAILED")


def inspect_handoff(
    receiver: Mapping[str, object],
    producer_context: str,
    artifact_id: str,
    outer_digest: str,
    accepted_inventory: str,
    download: Callable[[], Path],
) -> Check:
    """Reject stale provenance before fetching, then inspect exactly that download."""
    identity = receipt_check(receiver, producer_context, artifact_id, outer_digest)
    if not identity.accepted:
        return identity
    return archive_check(download(), accepted_inventory, outer_digest)
