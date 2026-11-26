"""Read-only GitHub release diagnostic from captured JSON and local asset bytes.

The caller must obtain the capture and downloads from the intended repository.
Results describe supplied evidence, not authorization to publish. A 404 does
not establish that a draft is absent. This tool neither calls the network nor
reads credentials.

Capture fields: http_status, body, repository_id, observed_at (UTC or with
offset), capture_id, release_request, tag_observation, and download_observation.
Record method, path, request_origin, response_origin and response_path from
the actual GET /repos/{owner}/{repo}/releases/tags/{tag}, including on errors.
Origins must be https://api.github.com and both encoded paths must match the
independently expected repository slug and tag (only the repository slug is
case-insensitive). A redirect to a different endpoint cannot contribute an
HTTP status. Independently supply the expected numeric repository ID too.
The tag observation binds repository_id, requested tag and peeled_tag_commit.
The download observation binds repository_id, release_id and asset_ids (name
to REST ID). Both record their actual observed_at, not the release lookup's
timestamp. Use a new capture_id per collection attempt: 1 to 128 ASCII
letters, digits, underscores or hyphens. Record it at each source when
collected (never retroactively assign it to mixed records).
For a match, read the release again after obtaining the tag and downloads and
store that final response and time. The observations must be at most 24 hours
old and within 15 minutes of one another. Out-of-window HTTP status is only
historical context. These checks catch accidental mixing of trusted records;
they do not authenticate inputs, give an atomic remote snapshot, or prove
that the remote state has not changed.
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
from urllib.parse import quote

MAX_JSON = 2 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_CAPTURE_AGE = timedelta(hours=24)
MAX_CAPTURE_SPAN = timedelta(minutes=15)
CAPTURE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


@dataclass(frozen=True)
class Diagnosis:
    state: str
    reason: str
    observed_at: str | None = None
    http_status: int | None = None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate JSON key")
    return obj


def _read_json_bytes(path: Path) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise ValueError("JSON capture exceeds size limit")
    return raw


def _parse_json(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=_unique_object)


def _read_json(path: Path) -> Any:
    return _parse_json(_read_json_bytes(path))


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
    captured: object, *, repository: str, repository_id: int, tag: str, commit: str,
    expected: dict[str, str], downloaded: Path | None,
) -> Diagnosis:
    if (
        repository_id <= 0 or REPOSITORY.fullmatch(repository) is None
        or repository.split("/")[1] in {".", ".."} or not tag
        or COMMIT.fullmatch(commit) is None or not _inventory_valid(expected)
    ):
        return Diagnosis("unknown", "invalid_expectation")
    if not isinstance(captured, dict) or type(captured.get("http_status")) is not int:
        return Diagnosis("unknown", "invalid_capture")
    observed = _timestamp(captured.get("observed_at"))
    if observed is None:
        return Diagnosis("unknown", "observation_time_unverified")
    stamp = observed.isoformat()
    if not _matches_id(captured.get("repository_id"), repository_id):
        return Diagnosis("unknown", "release_repository_mismatch", stamp)
    request = captured.get("release_request")
    if not _matches_github_release_request(request, repository, tag):
        return Diagnosis("unknown", "release_request_mismatch", stamp)
    capture_id = captured.get("capture_id")
    if not isinstance(capture_id, str) or not CAPTURE_ID.fullmatch(capture_id):
        return Diagnosis("unknown", "capture_id_unverified", stamp)
    status = captured["http_status"]
    now = datetime.now(timezone.utc)
    age = now - observed
    if not timedelta(0) <= age <= MAX_CAPTURE_AGE:
        return Diagnosis("unknown", "observation_outside_freshness_window", stamp, status)
    result = _diagnose_capture(captured, repository_id, tag, commit, expected, downloaded, observed, now, capture_id)
    return replace(result, observed_at=stamp, http_status=status)


def _matches_github_release_request(request: object, repository: str, tag: str) -> bool:
    if not isinstance(request, dict) or request.get("method") != "GET" or any(
        request.get(field) != "https://api.github.com" for field in ("request_origin", "response_origin")
    ):
        return False
    suffix = f"releases/tags/{quote(tag, safe='')}"
    for field in ("path", "response_path"):
        path = request.get(field)
        if not isinstance(path, str):
            return False
        parts = path.split("/", 4)
        if len(parts) != 5 or parts[:2] != ["", "repos"] or parts[4] != suffix:
            return False
        slug = "/".join(parts[2:4])
        if not REPOSITORY.fullmatch(slug) or slug.lower() != repository.lower():
            return False
    return True


def _matches_id(raw: object, expected: int) -> bool:
    return type(raw) is int and raw == expected


def _diagnose_capture(
    captured: dict[str, Any], repository_id: int, tag: str, commit: str,
    expected: dict[str, str], downloaded: Path | None, observed: datetime, now: datetime, capture_id: str,
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
    tag_evidence = captured.get("tag_observation")
    if not isinstance(tag_evidence, dict) or not _matches_id(tag_evidence.get("repository_id"), repository_id):
        return Diagnosis("unknown", "tag_repository_mismatch")
    if tag_evidence.get("tag") != tag:
        return Diagnosis("unknown", "tag_observation_mismatch")
    tag_time = _timestamp(tag_evidence.get("observed_at"))
    if tag_time is None or not timedelta(0) <= now - tag_time <= MAX_CAPTURE_AGE:
        return Diagnosis("unknown", "tag_observation_time_unverified")
    if tag_evidence.get("capture_id") != capture_id or not timedelta(0) <= observed - tag_time <= MAX_CAPTURE_SPAN:
        return Diagnosis("unknown", "observation_batch_mismatch")
    # The release API target_commitish is not the peeled Git tag.
    observed_commit = tag_evidence.get("peeled_tag_commit")
    if not isinstance(observed_commit, str) or not COMMIT.fullmatch(observed_commit):
        return Diagnosis("unknown", "tag_commit_unverified")
    if observed_commit != commit:
        return Diagnosis("conflict", "tag_commit_mismatch")
    assets = release.get("assets")
    if not isinstance(assets, list):
        return Diagnosis("unknown", "invalid_asset_list")
    names: set[str] = set()
    seen_ids: set[int] = set()
    sizes: dict[str, int] = {}
    ids: dict[str, int] = {}
    issues: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(name := asset.get("name"), str):
            issues.add("invalid_asset_list")
            continue
        if name in names:
            issues.add("duplicate_asset")
        names.add(name)
        if asset.get("state") != "uploaded":
            issues.add("asset_not_uploaded")
            continue
        recorded = asset.get("digest")
        if recorded is not None and name in expected:
            digest = recorded[7:].lower() if isinstance(recorded, str) and recorded.startswith("sha256:") else ""
            if not DIGEST.fullmatch(digest):
                issues.add("metadata_digest_unverified")
            elif digest != expected[name]:
                issues.add("metadata_digest_mismatch")
        size, asset_id = asset.get("size"), asset.get("id")
        if type(asset_id) is not int or asset_id <= 0:
            issues.add("invalid_asset_metadata")
            continue
        if asset_id in seen_ids:
            issues.add("duplicate_asset_id")
        seen_ids.add(asset_id)
        if type(size) is not int or size < 0:
            issues.add("invalid_asset_metadata")
            continue
        sizes[name], ids[name] = size, asset_id
    digest_unverified = "metadata_digest_unverified" in issues
    # Contradictory evidence outranks uncertainty; use a fixed reason order.
    for state, reason in (
        ("conflict", "metadata_digest_mismatch"),
        ("conflict", "duplicate_asset"),
        ("conflict", "duplicate_asset_id"),
        ("unknown", "invalid_asset_list"),
        ("unknown", "invalid_asset_metadata"),
        ("incomplete", "asset_not_uploaded"),
    ):
        if reason in issues:
            if state == "incomplete" and digest_unverified:
                return Diagnosis("unknown", "metadata_digest_unverified")
            return Diagnosis(state, reason)
    if names != expected.keys() or downloaded is None:
        if digest_unverified:
            return Diagnosis("unknown", "metadata_digest_unverified")
        if names != expected.keys():
            return Diagnosis("incomplete", "asset_inventory_mismatch")
        return Diagnosis("unknown", "downloaded_bytes_unverified")
    result = _diagnose_downloads(
        captured.get("download_observation"), repository_id=repository_id, release_id=release_id,
        expected=expected, sizes=sizes, ids=ids, observed=observed, now=now,
        capture_id=capture_id, downloaded=downloaded,
    )
    if digest_unverified and result.state != "conflict":
        return Diagnosis("unknown", "metadata_digest_unverified")
    return result


def _diagnose_downloads(
    download_evidence: object, *, repository_id: int, release_id: int,
    expected: dict[str, str], sizes: dict[str, int], ids: dict[str, int], observed: datetime,
    now: datetime, capture_id: str, downloaded: Path,
) -> Diagnosis:
    if not (
        isinstance(download_evidence, dict)
        and _matches_id(download_evidence.get("repository_id"), repository_id)
        and _matches_id(download_evidence.get("release_id"), release_id)
        and isinstance(asset_ids := download_evidence.get("asset_ids"), dict)
        and asset_ids.keys() == ids.keys()
        and all(_matches_id(asset_ids[name], asset_id) for name, asset_id in ids.items())
    ):
        return Diagnosis("unknown", "download_identity_unverified")
    download_time = _timestamp(download_evidence.get("observed_at"))
    if download_time is None or not timedelta(0) <= now - download_time <= MAX_CAPTURE_AGE:
        return Diagnosis("unknown", "download_observation_time_unverified")
    if download_evidence.get("capture_id") != capture_id or not timedelta(0) <= observed - download_time <= MAX_CAPTURE_SPAN:
        return Diagnosis("unknown", "observation_batch_mismatch")
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
    parser.add_argument("--repository", required=True, help="Canonical expected GitHub owner/repository")
    parser.add_argument("--repository-id", type=int, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        result = diagnose(_read_json(args.capture), repository=args.repository, repository_id=args.repository_id, tag=args.tag, commit=args.commit,
                          expected=_read_json(args.inventory), downloaded=args.downloaded)
    except (OSError, ValueError, RecursionError):
        result = Diagnosis("unknown", "input_unreadable_or_invalid")
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.state == "evidence_matches" else 2


if __name__ == "__main__":
    raise SystemExit(main())
