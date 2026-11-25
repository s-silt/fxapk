"""Offline release lookup evidence and actual CLI output."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / "tools" / "release_state_probe.py"
NAME = "synthetic-0.0.0.whl"
GOOD = b"synthetic asset bytes"
GIT_SHA = "a" * 40
TAG = "v0.0.0"
SHA256 = hashlib.sha256(GOOD).hexdigest()


@pytest.fixture
def probe(tmp_path):
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    (downloads / NAME).write_bytes(GOOD)
    expected = tmp_path / "inventory.json"
    expected.write_text(json.dumps({NAME: SHA256}), encoding="utf-8")

    def run(*, status=200, release=None, observed=GIT_SHA, use_bytes=True, extra=None, raw=None):
        body = {"tag_name": TAG, "draft": False, "published_at": "2026-01-01T00:00:00Z",
                "target_commitish": GIT_SHA,
                "assets": [{"name": NAME, "state": "uploaded", "digest": f"sha256:{SHA256}"}]}
        capture = tmp_path / "capture.json"
        capture.write_text(raw if raw is not None else json.dumps({
            "http_status": status, "peeled_tag_commit": observed, "body": {**body, **(release or {})},
        }), encoding="utf-8")
        args = [sys.executable, "-I", str(TOOL), "--capture", str(capture), "--inventory", str(expected),
                "--tag", TAG, "--commit", GIT_SHA]
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
    ({"release": {"assets": [{"name": NAME, "state": "uploaded"}] * 2}}, "duplicate_asset"),
    ({"release": {"assets": [{"name": NAME, "state": "uploaded", "digest": None}]}},
     "tag_and_downloaded_bytes_match"),
    ({"observed": None}, "tag_commit_unverified"),
    ({"observed": "b" * 40}, "tag_commit_mismatch"),
    ({"status": 404}, "not_found_does_not_prove_absent"),
    ({"status": 403}, "lookup_failed"),
    ({"status": 503}, "lookup_failed"),
    ({"status": "200"}, "invalid_capture"),
    ({"use_bytes": False}, "downloaded_bytes_unverified"),
    ({"extra": lambda d: (d / NAME).write_bytes(b"different")}, "download_digest_mismatch"),
    ({"extra": lambda d: (d / "extra").touch()}, "download_inventory_mismatch"),
    ({"raw": '{"http_status":404,"http_status":200}'}, "input_unreadable_or_invalid"),
])
def test_release_state_probe(probe, options, reason):
    code, actual = probe(**options)
    assert code == (0 if reason == "tag_and_downloaded_bytes_match" else 2)
    assert actual["reason"] == reason
    assert (actual["state"] == "evidence_matches") == (code == 0)
