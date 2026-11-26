"""Compare saved fxapk GitHub and PyPI metadata against a trusted core build manifest.

Run from the checkout root with python -m tools.release_channel_metadata.
Inputs are trusted local captures, not live or authenticated remote evidence.
Both captures require capture_id, observed_at, http_status and body. GitHub
also requires repository_id and release_request as in release_state_probe.
PyPI requires release_request with method, path, request_origin,
response_origin and response_path, bound to its exact release JSON endpoint.
The build manifest maps this version's core wheel and sdist names to SHA-256
digests. Comparisons cover the two named files, not the complete GitHub
release or its other attached packages. A bound 404 is not an observation of
missing files; the combined diagnosis stays unknown unless independent
comparable evidence establishes a conflict. Matching is about metadata digests,
not downloaded bytes, the Git tag commit, or permission to publish or retry.
Input SHA-256 values identify exactly the input files read in full within the
size limit, even on parse failure. They are not package hashes or validation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tools.release_state_probe import (
    CAPTURE_ID,
    MAX_CAPTURE_AGE,
    MAX_CAPTURE_SPAN,
    _inventory_valid,
    _matches_github_release_request,
    _matches_id,
    _parse_json,
    _read_json_bytes,
    _timestamp,
)

VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
REPOSITORY = "s-silt/fxapk"
DIGEST = re.compile(r"[0-9a-f]{64}")
PYPI_ORIGIN = "https://pypi.org"


@dataclass(frozen=True)
class Channel:
    state: str
    reason: str
    observed_at: str | None = None
    http_status: int | None = None
    capture_id: str | None = None


def _inspect(
    capture: object, *, github: bool, version: str, repository_id: int,
    expected: dict[str, str], now: datetime,
) -> Channel:
    if not isinstance(capture, dict) or type(capture.get("http_status")) is not int:
        return Channel("unknown", "invalid_capture")
    request = capture.get("release_request")
    if github:
        valid_request = _matches_id(capture.get("repository_id"), repository_id) and (
            _matches_github_release_request(request, REPOSITORY, f"v{version}")
        )
    else:
        path = f"/pypi/fxapk/{version}/json"
        valid_request = isinstance(request, dict) and (
            request.get("method"), request.get("path"), request.get("response_path"),
            request.get("request_origin"), request.get("response_origin"),
        ) == ("GET", path, path, PYPI_ORIGIN, PYPI_ORIGIN)
    if not valid_request:
        return Channel("unknown", "request_mismatch")
    observed = _timestamp(capture.get("observed_at"))
    batch = capture.get("capture_id")
    if observed is None or not isinstance(batch, str) or not CAPTURE_ID.fullmatch(batch):
        return Channel("unknown", "observation_unverified")

    def result(state: str, reason: str) -> Channel:
        return Channel(state, reason, observed.isoformat(), capture["http_status"], batch)

    if not timedelta(0) <= now - observed <= MAX_CAPTURE_AGE:
        return result("unknown", "stale_or_future_observation")
    status = capture["http_status"]
    if status == 404:
        return result("not_observed", "not_found_does_not_prove_absent")
    if status != 200:
        return result("unknown", "lookup_failed")
    body = capture.get("body")
    if not isinstance(body, dict):
        return result("unknown", "invalid_response")
    if github:
        if body.get("tag_name") != f"v{version}":
            return result("unknown", "response_identity_mismatch")
        if body.get("draft") is True:
            return result("incomplete", "draft")
        published = _timestamp(body.get("published_at"))
        if body.get("draft") is not False or published is None or published > observed:
            return result("unknown", "publication_unverified")
    else:
        info = body.get("info")
        if not isinstance(info, dict) or info.get("name") != "fxapk" or info.get("version") != version:
            return result("unknown", "response_identity_mismatch")
    files = body.get("assets" if github else "urls")
    if not isinstance(files, list):
        return result("unknown", "invalid_file_list")
    found: set[str] = set()
    issues: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(name := item.get("name" if github else "filename"), str):
            issues.add("invalid_file_list")
            continue
        if name not in expected and github:
            continue
        if name in found or name not in expected:
            issues.add("unexpected_or_duplicate_core_file")
            continue
        found.add(name)
        yanked = False
        if github:
            if item.get("state") != "uploaded":
                issues.add("asset_not_uploaded")
                continue
            value = item.get("digest")
            digest = value[7:] if isinstance(value, str) and value.startswith("sha256:") else None
        else:
            yanked = item.get("yanked") is True
            if yanked:
                issues.add("file_yanked")
            elif item.get("yanked") is not False:
                issues.add("file_yank_state_unverified")
                # Check the independent digest even if the yank state is unknown.
            digests = item.get("digests")
            digest = digests.get("sha256") if isinstance(digests, dict) else None
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            if not yanked:
                issues.add("digest_unverified")
            continue
        if digest != expected[name]:
            issues.add("build_digest_mismatch")
    if found != expected.keys():
        issues.add("core_file_missing")
    # Prefer observed conflicts, then unverified evidence, then incompleteness.
    for state, reason in (
        ("conflict", "unexpected_or_duplicate_core_file"),
        ("conflict", "build_digest_mismatch"),
        ("unknown", "invalid_file_list"),
        ("unknown", "file_yank_state_unverified"),
        ("unknown", "digest_unverified"),
        ("incomplete", "asset_not_uploaded"),
        ("incomplete", "file_yanked"),
        ("incomplete", "core_file_missing"),
    ):
        if reason in issues:
            return result(state, reason)
    return result("metadata_matches", "expected_core_digests_match_build_manifest")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github", type=Path, required=True)
    parser.add_argument("--pypi", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--version", required=True, help="Final fxapk version (major.minor.patch)")
    parser.add_argument("--repository-id", type=int, required=True)
    args = parser.parse_args()
    version = args.version
    names = {f"fxapk-{version}-py3-none-any.whl", f"fxapk-{version}.tar.gz"}
    input_sha256: dict[str, str] = {}

    def load(name: str, path: Path) -> object:
        raw = _read_json_bytes(path)
        input_sha256[name] = hashlib.sha256(raw).hexdigest()
        return _parse_json(raw)

    try:
        if not VERSION.fullmatch(version) or args.repository_id <= 0:
            raise ValueError("expected a final version and positive repository ID")
        expected = load("inventory", args.inventory)
        if not isinstance(expected, dict) or not _inventory_valid(expected) or expected.keys() != names:
            raise ValueError("expected the two core fxapk files")
        github = load("github", args.github)
        pypi = load("pypi", args.pypi)
    except (OSError, ValueError, RecursionError):
        print(json.dumps({
            "state": "unknown", "reason": "input_unreadable_or_invalid",
            "version": version if VERSION.fullmatch(version) else None,
            "input_sha256": input_sha256,
        }, sort_keys=True))
        return 2
    now = datetime.now(timezone.utc)
    g = _inspect(github, github=True, version=version, repository_id=args.repository_id, expected=expected, now=now)
    p = _inspect(pypi, github=False, version=version, repository_id=args.repository_id, expected=expected, now=now)
    gt, pt = _timestamp(g.observed_at), _timestamp(p.observed_at)
    comparable = (
        gt is not None and pt is not None and abs(gt - pt) <= MAX_CAPTURE_SPAN
        and timedelta(0) <= now - gt <= MAX_CAPTURE_AGE and timedelta(0) <= now - pt <= MAX_CAPTURE_AGE
        and g.capture_id == p.capture_id
    )
    state = "unknown"
    reason = "snapshots_not_comparable"
    if comparable:
        if g.state == p.state == "metadata_matches":
            state, reason = "metadata_agrees", "both_channels_match_expected_core_digests"
        elif "conflict" in {g.state, p.state}:
            state, reason = "conflict", "channel_metadata_conflict"
        elif "unknown" in {g.state, p.state}:
            reason = "channel_unverified"
        elif "not_observed" in {g.state, p.state}:
            reason = "channel_not_observed"
        else:
            state, reason = "incomplete", "channel_not_verified"
    print(json.dumps({
        "state": state, "reason": reason, "version": version,
        "github": asdict(g), "pypi": asdict(p),
        "input_sha256": input_sha256,
    }, sort_keys=True))
    return 0 if state == "metadata_agrees" else 2


if __name__ == "__main__":
    raise SystemExit(main())
