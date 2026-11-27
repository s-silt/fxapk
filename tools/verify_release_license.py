"""Verify the MIT license metadata and bytes in the built release archives."""

from __future__ import annotations

import argparse
import stat
import tarfile
import zipfile
from email.parser import BytesHeaderParser
from pathlib import Path

from tools.release_preflight import PROJECTS, archive_names, projects


def wheel_contents(path: Path) -> tuple[bytes, bytes]:
    prefix = path.name.removesuffix("-py3-none-any.whl") + ".dist-info"
    with zipfile.ZipFile(path) as archive:

        def read(name: str) -> bytes:
            members = [item for item in archive.infolist() if item.filename == name]
            if len(members) != 1 or stat.S_IFMT(members[0].external_attr >> 16) not in (0, stat.S_IFREG):
                raise ValueError(f"expected one regular {name}")
            return archive.read(members[0])

        return read(f"{prefix}/METADATA"), read(f"{prefix}/licenses/LICENSE")


def sdist_contents(path: Path) -> tuple[bytes, bytes]:
    prefix = path.name.removesuffix(".tar.gz")
    with tarfile.open(path, "r:gz") as archive:

        def read(name: str) -> bytes:
            members = [item for item in archive.getmembers() if item.name == name]
            if len(members) != 1 or not members[0].isfile():
                raise ValueError(f"expected one regular {name}")
            stream = archive.extractfile(members[0])
            if stream is None:
                raise ValueError(f"could not read {name}")
            with stream:
                return stream.read()

        return read(f"{prefix}/PKG-INFO"), read(f"{prefix}/LICENSE")


def verify_archives(root: Path, directory: Path) -> None:
    for project_path, project in zip(PROJECTS, projects(root), strict=True):
        source = (root / project_path).with_name("LICENSE").read_bytes()
        for name in sorted(archive_names(project)):
            path = directory / name
            reader = wheel_contents if path.suffix == ".whl" else sdist_contents
            try:
                metadata, license_bytes = reader(path)
                headers = BytesHeaderParser().parsebytes(metadata)
                if headers.get_all("License-Expression") != ["MIT"]:
                    raise ValueError("expected exactly one License-Expression: MIT")
                if headers.get_all("License-File") != ["LICENSE"]:
                    raise ValueError("expected exactly one License-File: LICENSE")
                if license_bytes != source:
                    raise ValueError("LICENSE bytes differ from the source file")
            except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
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
