"""Read-only GitHub release diagnostic from captured JSON and local asset bytes.

The caller must obtain the capture and downloads from the intended repository.
Results describe supplied evidence, not authorization to publish. A 404 does
not establish that a draft is absent. This tool neither calls the network nor
reads credentials.

Capture fields: http_status, body, repository_id, observed_at (UTC or with
offset), tag_repository_id, peeled_tag_commit, and download_observation.
The latter binds repository_id, release_id and asset_ids (name to REST ID).
These records must come from the same trusted capture, not from generated
assertions. An old snapshot cannot establish present-day publication.
Inventory is a JSON object of expected asset names to lower-case SHA-256 from
a trusted build; downloaded must be a separate, stable local directory.
Exit 0 means these supplied observations match; 2 means not verified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import os
import stat
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

MAX_JSON = 2 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_CAPTURE_AGE = timedelta(hours=24)
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


@dataclass(frozen=True)
class Diagnosis:
    state: str
    reason: str
    observed_at: str | None = None


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


def _timestamp(raw: object) -> datetime | None:
    if not isinstance(raw, str) or "T" not in raw:
        return None
    try:
        value = datetime.fromisoformat(raw)
        return value.astimezone(timezone.utc) if value.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def diagnose(
    captured: object, *, repository_id: int, tag: str, commit: str,
    expected: dict[str, str], downloaded: Path | None,
) -> Diagnosis:
    if repository_id <= 0 or not tag or COMMIT.fullmatch(commit) is None or not _inventory_valid(expected):
        return Diagnosis("unknown", "invalid_expectation")
    if not isinstance(captured, dict) or type(captured.get("http_status")) is not int:
        return Diagnosis("unknown", "invalid_capture")
    observed = _timestamp(captured.get("observed_at"))
    if observed is None:
        return Diagnosis("unknown", "observation_time_unverified")
    stamp = observed.isoformat()
    age = datetime.now(timezone.utc) - observed
    if not timedelta(0) <= age <= MAX_CAPTURE_AGE:
        return Diagnosis("unknown", "observation_outside_freshness_window", stamp)
    if not _matches_id(captured.get("repository_id"), repository_id):
        return Diagnosis("unknown", "release_repository_mismatch", stamp)
    result = _diagnose_capture(captured, repository_id, tag, commit, expected, downloaded, observed)
    return replace(result, observed_at=stamp)


def _matches_id(raw: object, expected: int) -> bool:
    return type(raw) is int and raw == expected


def _diagnose_capture(
    captured: dict[str, Any], repository_id: int, tag: str, commit: str,
    expected: dict[str, str], downloaded: Path | None, observed: datetime,
) -> Diagnosis:
    status = captured["http_status"]
    if status == 404:
        return Diagnosis("not_observed", "not_found_does_not_prove_absent")
    if status != 200:
        return Diagnosis("unknown", "lookup_failed")
    release = captured.get("body")
    if not isinstance(release, dict) or release.get("tag_name") != tag:
        return Diagnosis("unknown", "unexpected_release_identity")
    if release.get("draft") is True:
        return Diagnosis("incomplete", "draft")
    published = _timestamp(release.get("published_at"))
    release_id = release.get("id")
    if release.get("draft") is not False or published is None or published > observed:
        return Diagnosis("unknown", "invalid_publication_state")
    if type(release_id) is not int or release_id <= 0:
        return Diagnosis("unknown", "invalid_release_id")
    if not _matches_id(captured.get("tag_repository_id"), repository_id):
        return Diagnosis("unknown", "tag_repository_mismatch")
    # The release API target_commitish is not the peeled Git tag.
    observed_commit = captured.get("peeled_tag_commit")
    if not isinstance(observed_commit, str) or not COMMIT.fullmatch(observed_commit):
        return Diagnosis("unknown", "tag_commit_unverified")
    if observed_commit != commit:
        return Diagnosis("conflict", "tag_commit_mismatch")
    assets = release.get("assets")
    if not isinstance(assets, list):
        return Diagnosis("unknown", "invalid_asset_list")
    names: set[str] = set()
    sizes: dict[str, int] = {}
    ids: dict[str, int] = {}
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
        size, asset_id = asset.get("size"), asset.get("id")
        if type(size) is not int or size < 0 or type(asset_id) is not int or asset_id <= 0:
            return Diagnosis("unknown", "invalid_asset_metadata")
        sizes[name], ids[name] = size, asset_id
    if names != expected.keys():
        return Diagnosis("incomplete", "asset_inventory_mismatch")
    if downloaded is None:
        return Diagnosis("unknown", "downloaded_bytes_unverified")
    if len(set(ids.values())) != len(ids):
        return Diagnosis("conflict", "duplicate_asset_id")
    download_evidence = captured.get("download_observation")
    if not (
        isinstance(download_evidence, dict)
        and _matches_id(download_evidence.get("repository_id"), repository_id)
        and _matches_id(download_evidence.get("release_id"), release_id)
        and isinstance(asset_ids := download_evidence.get("asset_ids"), dict)
        and asset_ids.keys() == ids.keys()
        and all(_matches_id(asset_ids[name], asset_id) for name, asset_id in ids.items())
    ):
        return Diagnosis("unknown", "download_identity_unverified")
    if max(sizes.values()) > MAX_FILE or sum(sizes.values()) > MAX_TOTAL:
        return Diagnosis("unknown", "asset_read_budget")
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
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    return Diagnosis("unknown", "invalid_download_path")
                if info.st_size > MAX_FILE:
                    return Diagnosis("unknown", "asset_read_budget")
                remaining = sizes[name]
                if info.st_size != remaining:
                    return Diagnosis("conflict", "download_size_mismatch")
                hasher = hashlib.sha256()
                while remaining:
                    chunk = stream.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        return Diagnosis("conflict", "download_size_mismatch")
                    hasher.update(chunk)
                    remaining -= len(chunk)
                if stream.read(1):
                    return Diagnosis("conflict", "download_size_mismatch")
                if hasher.hexdigest() != digest:
                    return Diagnosis("conflict", "download_digest_mismatch")
    except OSError:
        return Diagnosis("unknown", "download_read_failed")
    return Diagnosis("evidence_matches", "tag_and_downloaded_bytes_match")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--downloaded", type=Path)
    parser.add_argument("--repository-id", type=int, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        result = diagnose(_read_json(args.capture), repository_id=args.repository_id, tag=args.tag, commit=args.commit,
                          expected=_read_json(args.inventory), downloaded=args.downloaded)
    except (OSError, ValueError, RecursionError):
        result = Diagnosis("unknown", "input_unreadable_or_invalid")
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.state == "evidence_matches" else 2


if __name__ == "__main__":
    raise SystemExit(main())
