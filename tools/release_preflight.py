"""Offline gate for the exact pure-Python archives published by release.yml."""
from __future__ import annotations

import argparse
import hashlib
import re
import string
import tomllib
from pathlib import Path

PROJECTS = (
    "pyproject.toml",
    "plugins/fxapk-android-ui/pyproject.toml",
    "plugins/fxapk-rea/pyproject.toml",
    "plugins/fxapk-asc/pyproject.toml",
    "plugins/fxapk-flutter/pyproject.toml",
)


def projects(root: Path) -> list[dict[str, str]]:
    return [tomllib.loads((root / path).read_text(encoding="utf-8"))["project"] for path in PROJECTS]


def archive_names(project: dict[str, str]) -> set[str]:
    # All five distributions currently build universal pure-Python wheels.
    # A wheel-tag change must update this release contract explicitly.
    name = re.sub(r"[-_.]+", "_", project["name"]).lower()
    version = project["version"].replace("-", "_")
    return {f"{name}-{version}-py3-none-any.whl", f"{name}-{version}.tar.gz"}


def inventory(directory: Path, expected: set[str]) -> dict[str, str]:
    paths = list(directory.iterdir())
    if {p.name for p in paths} != expected:
        raise ValueError(f"archive inventory mismatch: {directory.name}")
    result = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("release assets must be regular files")
        with path.open("rb") as stream:
            result[path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    return result


def validate_archives(root: Path, core: Path, plugins: Path, assets: Path) -> None:
    declared = projects(root)
    core_names = archive_names(declared[0])
    plugin_names = set().union(*(archive_names(p) for p in declared[1:]))
    expected = core_names | plugin_names
    if len(expected) != 10:
        raise ValueError("expected ten distinct release archives")
    built = inventory(core, core_names) | inventory(plugins, plugin_names)
    staged = inventory(assets, expected | {"SHA256SUMS.txt"})
    staged.pop("SHA256SUMS.txt")
    if built != staged:
        raise ValueError("staged archives differ from built archives")
    checksums: dict[str, str] = {}
    for line in (assets / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\\]+)", line)
        if match is None or match[2] in checksums:
            raise ValueError("invalid or duplicate checksum entry")
        checksums[match[2]] = match[1]
    if checksums != staged:
        raise ValueError("checksum inventory or digest mismatch")


def render_notes(root: Path, tag: str, repository: str, commit: str) -> str:
    core, plugin, rea, asc, flutter = projects(root)
    if tag != "v" + core["version"]:
        raise ValueError("release tag does not match core version")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.search(r"(?m)^## " + re.escape(core["version"]) + r"(?: — [^\n]+)?$", changelog)
    if heading is None:
        raise ValueError("missing release CHANGELOG section")
    section = re.split(r"(?m)^## ", changelog[heading.end():], maxsplit=1)[0].strip()
    section = section.split("\n以下为各版本发布时的历史记录；", 1)[0].strip()
    if not section:
        raise ValueError("empty release CHANGELOG section")
    template = (root / ".github/release-notes-template.md").read_text(encoding="utf-8")
    notes = string.Template(template).substitute(
        changes=section, tag=tag, repository=repository, commit=commit,
        core_version=core["version"], plugin_version=plugin["version"],
        requires_python=core["requires-python"], rea_version=rea["version"],
        asc_version=asc["version"], flutter_version=flutter["version"],
    )
    if not notes.strip() or "$changes" not in template:
        raise ValueError("release notes must include CHANGELOG changes")
    return notes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--core", type=Path, default=Path("dist"))
    parser.add_argument("--plugins", type=Path, default=Path("plugin-dist"))
    parser.add_argument("--assets", type=Path, default=Path("release-assets"))
    parser.add_argument("--notes", type=Path, default=Path("release-notes.md"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    validate_archives(args.root, args.core, args.plugins, args.assets)
    notes = render_notes(args.root, args.tag, args.repository, args.commit)
    args.notes.write_text(notes, encoding="utf-8")
    print("release preflight OK: ten archives, exact SHA-256 inventory, nonempty notes")


if __name__ == "__main__":
    main()
