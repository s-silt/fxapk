"""Exercise the license verifier through the same command used by rehearsal CI."""

from __future__ import annotations

import io
import subprocess
import sys
import tarfile
import warnings
from pathlib import Path
from zipfile import ZipFile

import pytest

from tools.release_preflight import PROJECTS, archive_names, projects

ROOT = Path(__file__).resolve().parents[1]
METADATA = b"Metadata-Version: 2.4\nLicense-Expression: MIT\nLicense-File: LICENSE\n\n"
CORE = archive_names(projects(ROOT)[0])
CORE_WHEEL = next(name for name in CORE if name.endswith(".whl"))
CORE_SDIST = next(name for name in CORE if name.endswith(".tar.gz"))


def _write_archive(path: Path, metadata: bytes, license_bytes: bytes | None, *, duplicate: bool = False) -> None:
    if path.suffix == ".whl":
        prefix = path.name.removesuffix("-py3-none-any.whl") + ".dist-info"
        with ZipFile(path, "w") as archive:
            archive.writestr(f"{prefix}/METADATA", metadata)
            if license_bytes is not None:
                name = f"{prefix}/licenses/LICENSE"
                archive.writestr(name, license_bytes)
                if duplicate:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        archive.writestr(name, license_bytes)
    else:
        prefix = path.name.removesuffix(".tar.gz")
        with tarfile.open(path, "w:gz") as archive:
            members = [(f"{prefix}/PKG-INFO", metadata)]
            if license_bytes is not None:
                members.append((f"{prefix}/LICENSE", license_bytes))
                if duplicate:
                    members.append(members[-1])
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


@pytest.fixture
def archives(tmp_path: Path) -> Path:
    for project_path, project in zip(PROJECTS, projects(ROOT), strict=True):
        license_bytes = (ROOT / project_path).with_name("LICENSE").read_bytes()
        for name in archive_names(project):
            _write_archive(tmp_path / name, METADATA, license_bytes)
    return tmp_path


def _verify(archives: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tools.verify_release_license", "--archives", str(archives)],
        cwd=ROOT, check=False, capture_output=True, text=True, timeout=30,
    )


def test_accepts_all_ten_archives(archives: Path) -> None:
    result = _verify(archives)
    assert result.returncode == 0, result.stderr
    assert "all five wheels and five sdists" in result.stdout


@pytest.mark.parametrize("name", [CORE_WHEEL, CORE_SDIST])
@pytest.mark.parametrize(
    ("defect", "diagnostic"),
    [
        ("no-expression", "exactly one License-Expression: MIT"),
        ("duplicate-header", "exactly one License-File: LICENSE"),
        ("missing-license", "expected one regular"),
        ("duplicate-license", "expected one regular"),
        ("same-size-different-license", "LICENSE bytes differ"),
    ],
)
def test_rejects_defective_archive(archives: Path, name: str, defect: str, diagnostic: str) -> None:
    metadata = METADATA
    source = (ROOT / "LICENSE").read_bytes()
    license_bytes: bytes | None = source
    if defect == "no-expression":
        metadata = metadata.replace(b"License-Expression: MIT\n", b"")
    elif defect == "duplicate-header":
        metadata = metadata.replace(b"\n\n", b"\nLicense-File: LICENSE\n\n")
    elif defect == "missing-license":
        license_bytes = None
    elif defect == "same-size-different-license":
        license_bytes = bytes([source[0] ^ 1]) + source[1:]
    _write_archive(archives / name, metadata, license_bytes, duplicate=defect == "duplicate-license")
    result = _verify(archives)
    assert result.returncode == 1
    assert name in result.stderr
    assert diagnostic in result.stderr
    assert not result.stdout


def test_rejects_missing_last_plugin_sdist(archives: Path) -> None:
    name = next(name for name in archive_names(projects(ROOT)[-1]) if name.endswith(".tar.gz"))
    (archives / name).unlink()
    result = _verify(archives)
    assert result.returncode == 1
    assert name in result.stderr
