"""Offline release lookup evidence and actual CLI output."""
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import pytest

TOOL = Path(__file__).resolve().parents[1] / "tools" / "release_state_probe.py"
NAME = "synthetic-0.0.0.whl"
GOOD = b"synthetic asset bytes"
GIT_SHA = "a" * 40
TAG = "v0.0.0"
SHA256 = hashlib.sha256(GOOD).hexdigest()
REPO_ID, RELEASE_ID, ASSET_ID = 54321, 12345, 42
ASSET = {"name": NAME, "state": "uploaded", "digest": f"sha256:{SHA256}", "size": len(GOOD), "id": ASSET_ID}


Probe = Callable[..., tuple[int, dict[str, Any]]]


def _oversized(directory: Path) -> None:
    with (directory / NAME).open("r+b") as stream:
        stream.truncate(129 * 1024 * 1024)


@pytest.fixture
def probe(tmp_path: Path) -> Probe:
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    (downloads / NAME).write_bytes(GOOD)
    expected = tmp_path / "inventory.json"
    expected.write_text(json.dumps({NAME: SHA256}), encoding="utf-8")

    def run(*, status: object = 200, release: dict[str, Any] | None = None, observed: str | None = GIT_SHA,
            use_bytes: bool = True, extra: Callable[[Path], Any] | None = None,
            raw: str | None = None, evidence: dict[str, Any] | None = None,
            inventory: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
        if inventory is not None:
            expected.write_text(json.dumps(inventory), encoding="utf-8")
        body = {"tag_name": TAG, "draft": False, "published_at": "2026-01-01T00:00:00Z",
                "target_commitish": GIT_SHA, "id": RELEASE_ID, "assets": [ASSET]}
        capture = tmp_path / "capture.json"
        capture.write_text(raw if raw is not None else json.dumps({
            "http_status": status, "peeled_tag_commit": observed, "body": {**body, **(release or {})},
            "repository_id": REPO_ID, "tag_repository_id": REPO_ID,
            "observed_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            "download_observation": {"repository_id": REPO_ID, "release_id": RELEASE_ID,
                                     "asset_ids": {NAME: ASSET_ID}},
            **(evidence or {}),
        }), encoding="utf-8")
        args = [sys.executable, "-I", str(TOOL), "--capture", str(capture), "--inventory", str(expected),
                "--repository-id", str(REPO_ID), "--tag", TAG, "--commit", GIT_SHA]
        if use_bytes:
            args += ["--downloaded", str(downloads)]
        if extra:
            extra(downloads)
        before = capture.read_bytes(), expected.read_bytes()
        result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=10)
        assert not result.stderr
        assert before == (capture.read_bytes(), expected.read_bytes())
        return result.returncode, json.loads(result.stdout)

    return run


@pytest.mark.parametrize(("options", "reason"), [
    ({}, "tag_and_downloaded_bytes_match"),
    ({"release": {"target_commitish": "master"}}, "tag_and_downloaded_bytes_match"),
    ({"evidence": {"repository_id": 7}}, "release_repository_mismatch"),
    ({"evidence": {"tag_repository_id": 7}}, "tag_repository_mismatch"),
    ({"evidence": {"observed_at": "2001-01-01T00:00:00Z"}}, "observation_outside_freshness_window"),
    ({"evidence": {"observed_at": "2200-01-01T00:00:00Z"}}, "observation_outside_freshness_window"),
    ({"evidence": {"observed_at": None}}, "observation_time_unverified"),
    ({"evidence": {"download_observation": {"repository_id": 7, "release_id": RELEASE_ID,
                                             "asset_ids": {NAME: ASSET_ID}}}}, "download_identity_unverified"),
    ({"evidence": {"download_observation": {"repository_id": REPO_ID, "release_id": 7,
                                             "asset_ids": {NAME: ASSET_ID}}}}, "download_identity_unverified"),
    ({"evidence": {"download_observation": {"repository_id": REPO_ID, "release_id": RELEASE_ID,
                                             "asset_ids": {NAME: 7}}}}, "download_identity_unverified"),
    ({"release": {"assets": [{**ASSET, "size": 129 * 1024 * 1024}]}}, "asset_read_budget"),
    ({"extra": _oversized}, "asset_read_budget"),
    ({"release": {"draft": True}}, "draft"),
    ({"release": {"assets": []}}, "asset_inventory_mismatch"),
    ({"release": {"draft": 0}}, "invalid_publication_state"),
    ({"release": {"published_at": None}}, "invalid_publication_state"),
    ({"release": {"published_at": "not a timestamp"}}, "invalid_publication_state"),
    ({"release": {"published_at": "2026-01-01T00:00:00"}}, "invalid_publication_state"),
    ({"release": {"tag_name": "v999"}}, "unexpected_release_identity"),
    ({"release": {"assets": [{"name": NAME, "state": "open"}]}}, "asset_not_uploaded"),
    ({"release": {"assets": [{"name": NAME, "state": "uploaded", "digest": "sha256:" + "f" * 64}]}},
     "metadata_digest_mismatch"),
    ({"release": {"assets": [ASSET] * 2}}, "duplicate_asset"),
    ({"release": {"assets": [{**ASSET, "digest": None}]}},
     "tag_and_downloaded_bytes_match"),
    ({"observed": None}, "tag_commit_unverified"),
    ({"observed": "b" * 40}, "tag_commit_mismatch"),
    ({"status": 404}, "not_found_does_not_prove_absent"),
    ({"status": 403}, "lookup_failed"),
    ({"status": 503}, "lookup_failed"),
    ({"status": "200"}, "invalid_capture"),
    ({"use_bytes": False}, "downloaded_bytes_unverified"),
    ({"extra": lambda d: (d / NAME).write_bytes(b"x" * len(GOOD))}, "download_digest_mismatch"),
    ({"extra": lambda d: (d / NAME).write_bytes(b"short")}, "download_size_mismatch"),
    ({"extra": lambda d: (d / "extra").touch()}, "download_inventory_mismatch"),
    ({"raw": '{"http_status":404,"http_status":200}'}, "input_unreadable_or_invalid"),
])
def test_release_state_probe(probe: Probe, options: dict[str, Any], reason: str) -> None:
    code, actual = probe(**options)
    assert code == (0 if reason == "tag_and_downloaded_bytes_match" else 2)
    assert actual["reason"] == reason
    assert (actual["state"] == "evidence_matches") == (code == 0)
    if code == 0 or reason == "observation_outside_freshness_window":
        assert datetime.fromisoformat(actual["observed_at"]).tzinfo == timezone.utc



def test_aggregate_asset_budget_is_checked_before_opening_files(probe: Probe) -> None:
    assets = [{**ASSET, "name": f"asset-{i}.whl", "id": i, "size": 128 * 1024 * 1024}
              for i in range(1, 6)]
    code, diagnostic = probe(
        release={"assets": assets},
        inventory={asset["name"]: SHA256 for asset in assets},
        evidence={"download_observation": {
            "repository_id": REPO_ID, "release_id": RELEASE_ID,
            "asset_ids": {asset["name"]: asset["id"] for asset in assets},
        }},
    )
    assert code == 2
    assert diagnostic["reason"] == "asset_read_budget"
