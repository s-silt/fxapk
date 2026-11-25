"""Read-only GitHub release diagnostic from captured JSON and local asset bytes.

The caller must obtain the capture and downloads from the intended repository.
Results describe supplied evidence, not authorization to publish. A 404 does
not establish that a draft is absent. This tool neither calls the network nor
reads credentials.

Capture fields: http_status, body (the release-by-tag response), and
peeled_tag_commit (from the Git tag, not the release's target_commitish).
Inventory is a JSON object of expected asset names to lower-case SHA-256 from
a trusted build; downloaded must be a separate, stable local directory.
Exit 0 means these supplied observations match; 2 means not verified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

MAX_JSON = 2 * 1024 * 1024
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


@dataclass(frozen=True)
class Diagnosis:
    state: str
    reason: str


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate JSON key")
    return obj


def _read_json(path: Path) -> Any:
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise ValueError("JSON capture exceeds size limit")
    return json.loads(raw, object_pairs_hook=_unique_object)


def _inventory_valid(expected: object) -> bool:
    return isinstance(expected, dict) and bool(expected) and all(
        isinstance(name, str) and ASSET_NAME.fullmatch(name)
        and isinstance(digest, str) and DIGEST.fullmatch(digest)
        for name, digest in expected.items()
    )


def _published_at_valid(raw: object) -> bool:
    if not isinstance(raw, str) or "T" not in raw:
        return False
    try:
        return datetime.fromisoformat(raw).tzinfo is not None
    except ValueError:
        return False


def diagnose(
    captured: object, *, tag: str, commit: str, expected: dict[str, str], downloaded: Path | None,
) -> Diagnosis:
    if not tag or COMMIT.fullmatch(commit) is None or not _inventory_valid(expected):
        return Diagnosis("unknown", "invalid_expectation")
    if not isinstance(captured, dict) or type(status := captured.get("http_status")) is not int:
        return Diagnosis("unknown", "invalid_capture")
    if status == 404:
        return Diagnosis("not_observed", "not_found_does_not_prove_absent")
    if status != 200:
        return Diagnosis("unknown", "lookup_failed")
    release = captured.get("body")
    if not isinstance(release, dict) or release.get("tag_name") != tag:
        return Diagnosis("unknown", "unexpected_release_identity")
    if release.get("draft") is True:
        return Diagnosis("incomplete", "draft")
    if release.get("draft") is not False or not _published_at_valid(release.get("published_at")):
        return Diagnosis("unknown", "invalid_publication_state")
    # The release API target_commitish is not the peeled Git tag.
    observed_commit = captured.get("peeled_tag_commit")
    if not isinstance(observed_commit, str) or not COMMIT.fullmatch(observed_commit):
        return Diagnosis("unknown", "tag_commit_unverified")
    if observed_commit != commit:
        return Diagnosis("conflict", "tag_commit_mismatch")
    assets = release.get("assets")
    if not isinstance(assets, list):
        return Diagnosis("unknown", "invalid_asset_list")
    names = set()
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(name := asset.get("name"), str):
            return Diagnosis("unknown", "invalid_asset_list")
        if name in names:
            return Diagnosis("conflict", "duplicate_asset")
        names.add(name)
        if asset.get("state") != "uploaded":
            return Diagnosis("incomplete", "asset_not_uploaded")
        recorded = asset.get("digest")
        if recorded is not None and name in expected and recorded != f"sha256:{expected[name]}":
            return Diagnosis("conflict", "metadata_digest_mismatch")
    if names != expected.keys():
        return Diagnosis("incomplete", "asset_inventory_mismatch")
    if downloaded is None:
        return Diagnosis("unknown", "downloaded_bytes_unverified")
    try:
        if downloaded.is_symlink() or not downloaded.is_dir():
            return Diagnosis("unknown", "invalid_download_path")
        if {item.name for item in downloaded.iterdir()} != expected.keys():
            return Diagnosis("unknown", "download_inventory_mismatch")
        for name, digest in expected.items():
            path = downloaded / name
            if path.is_symlink() or not path.is_file():
                return Diagnosis("unknown", "invalid_download_path")
            with path.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                    return Diagnosis("conflict", "download_digest_mismatch")
    except OSError:
        return Diagnosis("unknown", "download_read_failed")
    return Diagnosis("evidence_matches", "tag_and_downloaded_bytes_match")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--downloaded", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        result = diagnose(_read_json(args.capture), tag=args.tag, commit=args.commit,
                          expected=_read_json(args.inventory), downloaded=args.downloaded)
    except (OSError, ValueError, RecursionError):
        result = Diagnosis("unknown", "input_unreadable_or_invalid")
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.state == "evidence_matches" else 2


if __name__ == "__main__":
    raise SystemExit(main())
