"""Synthetic release bundles; no build, network or publishing required."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tools.release_preflight import PROJECTS, archive_names, projects, render_notes, validate_archives

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    for relative in (*PROJECTS, "CHANGELOG.md", ".github/release-notes-template.md"):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    for directory in ("dist", "plugin-dist", "release-assets"):
        (tmp_path / directory).mkdir()
    for index, project in enumerate(projects(tmp_path)):
        for name in archive_names(project):
            # The gate validates byte identity, not archive extraction semantics.
            payload = ("synthetic archive: " + name).encode()
            (tmp_path / ("plugin-dist" if index else "dist") / name).write_bytes(payload)
            (tmp_path / "release-assets" / name).write_bytes(payload)
    checksum(tmp_path)
    return tmp_path


def checksum(root: Path) -> None:
    assets = root / "release-assets"
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
             for p in sorted(assets.iterdir()) if p.name != "SHA256SUMS.txt"]
    (assets / "SHA256SUMS.txt").write_text("".join(lines), encoding="utf-8")


def validate(root: Path) -> None:
    validate_archives(root, root / "dist", root / "plugin-dist", root / "release-assets")


def test_complete_bundle_and_real_template(bundle: Path) -> None:
    validate(bundle)
    core = projects(bundle)[0]
    notes = render_notes(bundle, "v" + core["version"], "example/synthetic", "a" * 40)
    assert "### 本版变更" in notes
    assert core["version"] in notes
    assert "$changes" not in notes


def test_distribution_name_normalization_and_independent_versions() -> None:
    assert archive_names({"name": "Example.Mixed-Name", "version": "1.2.3"}) == {
        "example_mixed_name-1.2.3-py3-none-any.whl", "example_mixed_name-1.2.3.tar.gz",
    }
    assert len({p["version"] for p in projects(ROOT)}) > 1


@pytest.mark.parametrize("change", ["missing", "wrong_version", "extra"])
def test_inventory_cannot_be_repaired_by_rehashing(bundle: Path, change: str) -> None:
    name = sorted(archive_names(projects(bundle)[1]))[0]
    for directory in ("plugin-dist", "release-assets"):
        path = bundle / directory / name
        if change == "missing":
            path.unlink()
        elif change == "wrong_version":
            path.rename(path.with_name(name.replace(projects(bundle)[1]["version"], "99.99.99", 1)))
        else:
            (path.parent / "unexpected-1.0.tar.gz").write_bytes(b"synthetic")
    checksum(bundle)
    with pytest.raises(ValueError, match="inventory mismatch"):
        validate(bundle)


@pytest.mark.parametrize("change", ["missing", "duplicate", "digest", "extra"])
def test_checksum_contract(bundle: Path, change: str) -> None:
    path = bundle / "release-assets/SHA256SUMS.txt"
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if change == "missing":
        lines.pop()
    elif change == "duplicate":
        lines.append(lines[0])
    elif change == "digest":
        lines[0] = "0" * 64 + lines[0][64:]
    else:
        lines.append("0" * 64 + "  unexpected.tar.gz\n")
    path.write_text("".join(lines), encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        validate(bundle)


def test_rehashed_staged_bytes_must_match_original_build(bundle: Path) -> None:
    name = sorted(archive_names(projects(bundle)[0]))[0]
    (bundle / "release-assets" / name).write_bytes(b"changed synthetic bytes")
    checksum(bundle)
    with pytest.raises(ValueError, match="differ from built"):
        validate(bundle)


@pytest.mark.parametrize("change", ["missing_section", "empty_section", "empty_template", "missing_template", "wrong_tag"])
def test_notes_fail_closed(bundle: Path, change: str) -> None:
    version = projects(bundle)[0]["version"]
    tag = "v" + version
    if change == "missing_section":
        (bundle / "CHANGELOG.md").write_text("## 0.0.0\nold\n", encoding="utf-8")
    elif change == "empty_section":
        (bundle / "CHANGELOG.md").write_text(f"## {version}\n\n## 0.0.0\nold\n", encoding="utf-8")
    elif change == "empty_template":
        (bundle / ".github/release-notes-template.md").write_text("", encoding="utf-8")
    elif change == "missing_template":
        (bundle / ".github/release-notes-template.md").unlink()
    else:
        tag = "v0.0.0"
    with pytest.raises((ValueError, FileNotFoundError)):
        render_notes(bundle, tag, "example/synthetic", "a" * 40)


def test_workflow_gates_before_upload_without_rebuilding() -> None:
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    gate = workflow.index("python tools/release_preflight.py")
    assert workflow.index("tools/release_smoke.py") < gate
    assert gate < workflow.index("uses: pypa/gh-action-pypi-publish") < workflow.index("gh release create")
    assert "python -m build" not in workflow[gate:]


def test_workflow_retains_manifest_before_publishing() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["publish"]["steps"]
    gate = next(i for i, step in enumerate(steps) if "tools/release_preflight.py" in step.get("run", ""))
    upload = steps[gate + 1]
    path = "release-build-manifest.json"
    assert f"--build-manifest {path}" in steps[gate]["run"]
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert upload["with"]["path"] == path
    assert all(part in upload["with"]["name"] for part in (
        "${{ github.sha }}", "${{ github.run_id }}", "${{ github.run_attempt }}",
    ))
    assert upload["with"]["if-no-files-found"] == "error"
    assert not {"if", "continue-on-error"} & upload.keys()
    assert "continue-on-error" not in workflow["jobs"]["publish"]
    assert steps[gate + 2]["uses"].startswith("pypa/gh-action-pypi-publish@")
    assert "gh release create" in steps[gate + 3]["run"]
    assert path not in steps[gate + 3]["run"]


def _preflight(bundle: Path, output: Path, *, notes: str = "release-notes.md") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(ROOT / "tools/release_preflight.py"),
         "--tag", "v" + projects(bundle)[0]["version"], "--repository", "example/synthetic", "--commit", "a" * 40,
         "--notes", notes, "--build-manifest", str(output)],
        cwd=bundle, capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
    )


def test_cli_build_manifest_matches_exact_inventory(bundle: Path) -> None:
    from tools.release_state_probe import _inventory_valid

    path = bundle / "first.json"
    result = _preflight(bundle, path)
    assert result.returncode == 0, result.stderr
    assert (bundle / "release-notes.md").is_file()
    expected = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in (bundle / "release-assets").iterdir()}
    assert len(expected) == 11 and "SHA256SUMS.txt" in expected
    assert json.loads(path.read_bytes()) == expected
    assert _inventory_valid(json.loads(path.read_bytes()))
    second = bundle / "second.json"
    result = _preflight(bundle, second)
    assert result.returncode == 0, result.stderr
    assert second.read_bytes() == path.read_bytes()
    assert len(list((bundle / "release-assets").iterdir())) == 11


@pytest.mark.parametrize("failure", ["archive", "notes", "unwritable", "stale", "inside_assets", "same_as_notes"])
def test_cli_rejects_untrustworthy_manifest_output(bundle: Path, failure: str) -> None:
    path = bundle / "manifest.json"
    diagnostic = {
        "archive": "staged archives differ",
        "notes": "missing release CHANGELOG section",
        "unwritable": "No such file or directory",
        "stale": "File exists",
        "inside_assets": "must be outside the release input directories",
        "same_as_notes": "must not be the release notes",
    }[failure]
    if failure == "archive":
        name = sorted(archive_names(projects(bundle)[0]))[0]
        (bundle / "release-assets" / name).write_bytes(b"changed synthetic archive")
        checksum(bundle)
    elif failure == "notes":
        (bundle / "CHANGELOG.md").write_text("## 0.0.0\nold\n", encoding="utf-8")
    elif failure == "unwritable":
        path = bundle / "missing-parent" / "manifest.json"
    elif failure == "stale":
        path.write_text("previous attempt", encoding="utf-8")
    elif failure == "inside_assets":
        path = bundle / "release-assets" / "manifest.json"
    elif failure == "same_as_notes":
        path = bundle / "release-notes.md"
    result = _preflight(bundle, path)
    assert result.returncode != 0
    assert diagnostic in result.stderr
    assert "release preflight OK" not in result.stdout
    if failure == "stale":
        assert path.read_text(encoding="utf-8") == "previous attempt"
    else:
        assert not path.exists()


def test_cli_writes_notes_only_after_successful_gate(bundle: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from tools.release_preflight import main

    notes = bundle / "notes.md"
    argv = ["release_preflight", "--root", str(bundle), "--core", str(bundle / "dist"),
            "--plugins", str(bundle / "plugin-dist"), "--assets", str(bundle / "release-assets"),
            "--notes", str(notes), "--tag", "v" + projects(bundle)[0]["version"],
            "--repository", "example/synthetic", "--commit", "a" * 40]
    monkeypatch.setattr(sys, "argv", argv)
    main()
    assert notes.read_text(encoding="utf-8").strip()
    notes.unlink()
    (bundle / "release-assets/SHA256SUMS.txt").write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        main()
    assert not notes.exists()


def test_verified_inventory_returns_only_the_accepted_bytes(bundle: Path) -> None:
    from tools.release_preflight import verified_inventory

    assets = bundle / "release-assets"
    result = verified_inventory(bundle, bundle / "dist", bundle / "plugin-dist", assets)
    assert len(result) == 11
    assert result == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in assets.iterdir()}
    assert validate_archives(bundle, bundle / "dist", bundle / "plugin-dist", assets) is None


def test_verified_inventory_rejects_rehashed_changed_asset(bundle: Path) -> None:
    from tools.release_preflight import verified_inventory

    name = sorted(archive_names(projects(bundle)[0]))[0]
    (bundle / "release-assets" / name).write_bytes(b"other synthetic package contents")
    checksum(bundle)
    with pytest.raises(ValueError, match="differ from built"):
        verified_inventory(bundle, bundle / "dist", bundle / "plugin-dist", bundle / "release-assets")


def test_verified_inventory_rejects_a_manifest_with_different_valid_bytes(
    bundle: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools.release_preflight import verified_inventory

    manifest = bundle / "release-assets/SHA256SUMS.txt"
    original_read_bytes = Path.read_bytes
    alternate_format = original_read_bytes(manifest).replace(b"  ", b" *")

    def read_bytes(path: Path) -> bytes:
        return alternate_format if path == manifest else original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    with pytest.raises(ValueError, match="checksum file changed during preflight"):
        verified_inventory(bundle, bundle / "dist", bundle / "plugin-dist", bundle / "release-assets")
