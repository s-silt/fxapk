"""Verify the MIT license metadata and bytes in the built release archives."""

from __future__ import annotations

import argparse
import gzip
import io
import stat
import tarfile
import zipfile
import zlib
from email.parser import BytesHeaderParser
from pathlib import Path
from typing import Protocol

from tools.release_preflight import PROJECTS, archive_names, projects


# The largest audited input is ~4 MiB compressed, ~15 MiB as tar, 870 members.
# This command checks our own small distribution format, not arbitrary packages.
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_TAR_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_MEMBER_BYTES = 256 * 1024
SUPPORTED_METADATA_VERSIONS = {"2.4", "2.5", "2.6"}


class _Reader(Protocol):
    def read(self, size: int, /) -> bytes: ...


def _read_member(stream: _Reader, size: int, name: str) -> bytes:
    if not 0 <= size <= MAX_MEMBER_BYTES:
        raise ValueError(f"member exceeds size budget: {name}")
    data = stream.read(size + 1)
    if len(data) != size:
        raise ValueError(f"member size mismatch: {name}")
    return data


class _TarBudget(io.BufferedIOBase):
    """Cap actual decompression, including tar padding and extension headers."""

    def __init__(self, stream: gzip.GzipFile) -> None:
        self.stream = stream
        self.remaining = MAX_TAR_BYTES

    def read(self, size: int | None = -1) -> bytes:
        size = -1 if size is None else size
        amount = min(size, self.remaining + 1) if size >= 0 else self.remaining + 1
        data = self.stream.read(amount)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ValueError("tar exceeds decompression budget")
        return data


def wheel_contents(path: Path) -> tuple[bytes, bytes]:
    prefix = path.name.removesuffix("-py3-none-any.whl") + ".dist-info"
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_MEMBERS:
            raise ValueError("wheel exceeds member count budget")

        def read(name: str) -> bytes:
            members = [item for item in entries if item.filename == name]
            if len(members) != 1 or stat.S_IFMT(members[0].external_attr >> 16) not in (0, stat.S_IFREG):
                raise ValueError(f"expected one regular {name}")
            member = members[0]
            with archive.open(member) as stream:
                return _read_member(stream, member.file_size, name)

        return read(f"{prefix}/METADATA"), read(f"{prefix}/licenses/LICENSE")


def sdist_contents(path: Path) -> tuple[bytes, bytes]:
    prefix = path.name.removesuffix(".tar.gz")
    expected = (f"{prefix}/PKG-INFO", f"{prefix}/LICENSE")
    found: dict[str, bytes] = {}
    with gzip.open(path, "rb") as stream, tarfile.open(fileobj=_TarBudget(stream), mode="r|") as archive:
        for count, member in enumerate(archive, start=1):
            if count > MAX_MEMBERS:
                raise ValueError("sdist exceeds member count budget")
            if member.name not in expected:
                continue
            if member.name in found or not member.isreg() or member.issparse():
                raise ValueError(f"expected one regular {member.name}")
            reader = archive.extractfile(member)
            if reader is None:
                raise ValueError(f"could not read {member.name}")
            with reader:
                found[member.name] = _read_member(reader, member.size, member.name)
    for name in expected:
        if name not in found:
            raise ValueError(f"expected one regular {name}")
    return found[expected[0]], found[expected[1]]


def verify_archives(root: Path, directory: Path) -> None:
    for project_path, project in zip(PROJECTS, projects(root), strict=True):
        source = (root / project_path).with_name("LICENSE").read_bytes()
        for name in sorted(archive_names(project)):
            path = directory / name
            reader = wheel_contents if path.suffix == ".whl" else sdist_contents
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("expected a regular archive file")
                if info.st_size > MAX_ARCHIVE_BYTES:
                    raise ValueError("archive exceeds compressed size budget")
                metadata, license_bytes = reader(path)
                headers = BytesHeaderParser().parsebytes(metadata)
                versions = headers.get_all("Metadata-Version", [])
                if headers.defects or len(versions) != 1 or versions[0] not in SUPPORTED_METADATA_VERSIONS:
                    raise ValueError("expected one supported Metadata-Version (2.4, 2.5 or 2.6)")
                if "License" in headers:
                    raise ValueError("legacy License field conflicts with License-Expression")
                if headers.get_all("License-Expression") != ["MIT"]:
                    raise ValueError("expected exactly one License-Expression: MIT")
                if headers.get_all("License-File") != ["LICENSE"]:
                    raise ValueError("expected exactly one License-File: LICENSE")
                if license_bytes != source:
                    raise ValueError("LICENSE bytes differ from the source file")
            except (ValueError, OSError, EOFError, RecursionError, tarfile.TarError, zipfile.BadZipFile, zlib.error) as exc:
                raise ValueError(f"{name}: {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--archives", type=Path, default=Path("release-assets"))
    args = parser.parse_args()
    try:
        verify_archives(args.root, args.archives)
    except ValueError as exc:
        parser.exit(1, f"release license check failed: {exc}\n")
    print("release license check OK: all five wheels and five sdists match source MIT licenses")


if __name__ == "__main__":
    main()
