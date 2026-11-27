"""Synthetic release bundles; no build, network or publishing required."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
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
        "${{ steps.release-preflight.outputs.commit }}", "${{ github.run_id }}", "${{ github.run_attempt }}",
    ))
    assert upload["with"]["if-no-files-found"] == "error"
    assert not {"if", "continue-on-error"} & upload.keys()
    assert "continue-on-error" not in workflow["jobs"]["publish"]
    assert steps[gate + 2]["uses"].startswith("pypa/gh-action-pypi-publish@")
    assert "gh release create" in steps[gate + 3]["run"]
    assert path not in steps[gate + 3]["run"]


@pytest.mark.parametrize("annotated", [False, True])
def test_preflight_workflow_names_manifest_after_checked_out_commit(bundle: Path, annotated: bool) -> None:
    import os

    shell = shutil.which("bash")
    if shell is None or sys.platform == "win32":
        pytest.skip("release shell step runs on Ubuntu")

    git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    git_env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

    def git(*args: str) -> str:
        return subprocess.check_output(
            ["git", *args], cwd=bundle, env=git_env, encoding="utf-8", timeout=20,
        ).strip()

    git("init", "--template=")
    git("-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "--allow-empty", "-m", "test")
    commit = git("rev-parse", "HEAD")
    tag = "v" + projects(bundle)[0]["version"]
    if annotated:
        git("-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "tag", "-a", tag, "-m", "test")
    else:
        git("tag", tag)
    event_sha = git("rev-parse", tag)
    assert (event_sha != commit) is annotated
    (bundle / "tools").mkdir()
    shutil.copyfile(ROOT / "tools/release_preflight.py", bundle / "tools/release_preflight.py")
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["publish"]["steps"]
    gate = next(i for i, step in enumerate(steps) if "tools/release_preflight.py" in step.get("run", ""))
    output = bundle / "step-output"
    env = dict(git_env, PATH=os.pathsep.join((str(Path(sys.executable).parent), git_env.get("PATH", os.defpath))),
               GITHUB_OUTPUT=str(output), GITHUB_SHA=event_sha, GITHUB_REF_NAME=tag,
               GITHUB_REPOSITORY="example/synthetic")
    proc = subprocess.run(
        [shell, "-e", "-o", "pipefail", "-c", steps[gate]["run"]], cwd=bundle, env=env,
        capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert output.read_text(encoding="utf-8") == f"commit={commit}\n"
    suffix = f"${{{{ steps.{steps[gate]['id']}.outputs.commit }}}}"
    assert suffix in steps[gate + 1]["with"]["name"]
    notes = (bundle / "release-notes.md").read_text(encoding="utf-8")
    assert f"/commit/{commit}" in notes
    if annotated:
        assert event_sha not in notes


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


def test_preflight_manifest_drives_strict_offline_diagnosis(bundle: Path) -> None:
    manifest = bundle / "release-build-manifest.json"
    run = _preflight(bundle, manifest)
    assert run.returncode == 0, run.stderr
    raw_inventory = manifest.read_bytes()
    version = projects(bundle)[0]["version"]
    before = datetime.now(timezone.utc) - timedelta(seconds=1)
    downloads = bundle / "github-download"
    shutil.copytree(bundle / "release-assets", downloads)
    names = archive_names(projects(bundle)[0])
    assets: list[dict[str, str | int]] = [
        {"id": asset_id, "name": file.name, "size": file.stat().st_size, "state": "uploaded",
         **({"digest": "sha256:" + hashlib.sha256(file.read_bytes()).hexdigest()}
            if file.name in names else {})}
        for asset_id, file in enumerate(sorted(downloads.iterdir()), 1)
    ]
    observed = {"observed_at": before.isoformat(), "capture_id": "synthetic-release"}
    repo, commit = 1234, "a" * 40
    tag = f"v{version}"

    # Only the independent build inventory supplies the non-core digests.
    non_core = {min(archive_names(projects(bundle)[1])), "SHA256SUMS.txt"}
    assert {asset["name"] for asset in assets if "digest" in asset} == names

    def snapshot(host: str, path: str, body: dict[str, object]) -> dict[str, object]:
        return {
            **observed, "http_status": 200, "body": body,
            "release_request": {"method": "GET", "request_origin": host, "response_origin": host,
                                "path": path, "response_path": path},
        }

    github = snapshot("https://api.github.com", f"/repos/s-silt/fxapk/releases/tags/{tag}", {
        "id": 17, "tag_name": tag, "draft": False, "assets": assets,
        "published_at": (before - timedelta(days=1)).isoformat(),
    })
    github.update(
        repository_id=repo,
        tag_observation={**observed, "repository_id": repo, "tag": tag, "peeled_tag_commit": commit},
        download_observation={**observed, "repository_id": repo, "release_id": 17,
                              "asset_ids": {a["name"]: a["id"] for a in assets}},
    )
    pypi = snapshot("https://pypi.org", f"/pypi/fxapk/{version}/json", {
        "info": {"name": "fxapk", "version": version},
        "urls": [{"filename": name, "yanked": False,
                  "digests": {"sha256": hashlib.sha256((bundle / "dist" / name).read_bytes()).hexdigest()}}
                 for name in sorted(names)],
    })
    args = [sys.executable, "-m", "tools.release_channel_metadata", "--version", version,
            "--repository-id", str(repo), "--github-commit", commit,
            "--downloaded", str(downloads), "--require-evidence", "--inventory", str(manifest)]
    for channel, capture in (("github", github), ("pypi", pypi)):
        path = bundle / f"{channel}.json"
        path.write_text(json.dumps(capture), encoding="utf-8")
        args.extend((f"--{channel}", str(path)))

    def diagnose() -> tuple[int, dict[str, object]]:
        result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                                timeout=20, check=False)
        assert not result.stderr
        receipt = json.loads(result.stdout)
        assert manifest.read_bytes() == raw_inventory
        assert receipt["input_sha256"]["inventory"] == hashlib.sha256(raw_inventory).hexdigest()
        assert receipt["metadata_comparison"]["state"] == "metadata_agrees"
        return result.returncode, receipt

    code, receipt = diagnose()
    assert (code, receipt["state"]) == (0, "evidence_checks_passed")
    for name in sorted(non_core):
        name_path = downloads / name
        original = name_path.read_bytes()
        changed = bytes([original[0] ^ 1]) + original[1:]
        name_path.write_bytes(changed)
        code, receipt = diagnose()
        assert (code, receipt["state"]) == (2, "conflict")
        evidence = receipt["github_evidence"]
        assert isinstance(evidence, dict)
        assert evidence["reason"] == "download_digest_mismatch"
        assert evidence["download_conflict"] == {
            "asset_name": name, "observed_sha256": hashlib.sha256(changed).hexdigest(),
        }
        name_path.write_bytes(original)


def test_cli_preserves_notes_symlink_when_writing_build_manifest(bundle: Path) -> None:
    notes = bundle / "original.md"
    notes.write_text("previous notes", encoding="utf-8")
    alias = bundle / "alias.md"
    try:
        alias.symlink_to(notes.name)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    manifest = bundle / "manifest.json"
    result = _preflight(bundle, manifest, notes=alias.name)
    assert result.returncode == 0, result.stderr
    assert alias.is_symlink()
    assert "### 本版变更" in notes.read_text(encoding="utf-8")
    assert len(json.loads(manifest.read_bytes())) == 11


@pytest.mark.parametrize("failure", ["archive", "notes", "unwritable", "stale", "inside_assets", "same_as_notes"])
def test_cli_rejects_untrustworthy_manifest_output(bundle: Path, failure: str) -> None:
    path = bundle / "manifest.json"
    diagnostic = {
        "archive": "staged archives differ",
        "notes": "missing release CHANGELOG section",
        "unwritable": "--build-manifest parent directory does not exist",
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
    assert not (bundle / "release-notes.md").exists()


@pytest.mark.parametrize("step", ["manifest_write", "notes_install"])
def test_preflight_output_failure_preserves_previous_notes_and_allows_retry(
    bundle: Path, monkeypatch: pytest.MonkeyPatch, step: str,
) -> None:
    import os

    from tools.release_preflight import main

    manifest = bundle / "manifest.json"
    notes = bundle / "notes.md"
    notes.write_text("previous notes", encoding="utf-8")
    before = {p.name for p in bundle.iterdir()}
    monkeypatch.chdir(bundle)
    monkeypatch.setattr(sys, "argv", [
        "release_preflight", "--tag", "v" + projects(bundle)[0]["version"],
        "--repository", "example/synthetic", "--commit", "a" * 40,
        "--notes", str(notes), "--build-manifest", str(manifest),
    ])

    write_text = Path.write_text
    replace = os.replace

    def broken_write(
        path: Path, text: str, encoding: str | None = None,
        errors: str | None = None, newline: str | None = None,
    ) -> int:
        if text.startswith("{"):
            write_text(path, text[:8], encoding=encoding, errors=errors, newline=newline)
            raise OSError("synthetic incomplete manifest write")
        return write_text(path, text, encoding=encoding, errors=errors, newline=newline)

    def broken_replace(src: Path, dst: Path) -> None:
        if Path(dst) == notes:
            raise OSError("synthetic notes installation failure")
        return replace(src, dst)

    with monkeypatch.context() as interrupted:
        if step == "manifest_write":
            interrupted.setattr(Path, "write_text", broken_write)
        else:
            interrupted.setattr(os, "replace", broken_replace)
        with pytest.raises(OSError, match="synthetic"):
            main()

    assert not manifest.exists()
    assert notes.read_text(encoding="utf-8") == "previous notes"
    assert {p.name for p in bundle.iterdir()} == before
    main()
    assert len(json.loads(manifest.read_bytes())) == 11
    assert "### 本版变更" in notes.read_text(encoding="utf-8")


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
