"""Exercise the offline two-channel diagnostic using inert captures."""
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
VERSION, REPO_ID = "2.0.6", 1234
WHEEL, SDIST = f"fxapk-{VERSION}-py3-none-any.whl", f"fxapk-{VERSION}.tar.gz"
INVENTORY = {WHEEL: "a" * 64, SDIST: "b" * 64}


def _capture(channel: str) -> dict[str, Any]:
    github = channel == "github"
    host = "https://api.github.com" if github else "https://pypi.org"
    path = f"/repos/s-silt/fxapk/releases/tags/v{VERSION}" if github else f"/pypi/fxapk/{VERSION}/json"
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    snap: dict[str, Any] = {
        "http_status": 200, "capture_id": "same-collection", "observed_at": now.isoformat(),
        "release_request": {
            "method": "GET", "request_origin": host, "response_origin": host, "path": path, "response_path": path,
        },
    }
    if github:
        snap["repository_id"] = REPO_ID
        snap["body"] = {
            "tag_name": f"v{VERSION}", "draft": False, "published_at": (now - timedelta(days=1)).isoformat(),
            "assets": [{"name": n, "state": "uploaded", "digest": f"sha256:{d}"} for n, d in INVENTORY.items()]
            + [{"name": "optional_plugin.whl"}, {"name": "SHA256SUMS.txt"}],
        }
    else:
        snap["body"] = {
            "info": {"name": "fxapk", "version": VERSION},
            "urls": [{"filename": n, "yanked": False, "digests": {"sha256": d}} for n, d in INVENTORY.items()],
        }
    return snap


def _run(tmp_path: Path, github: dict[str, Any], pypi: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    args = [sys.executable, "-m", "tools.release_channel_metadata", "--version", VERSION, "--repository-id", str(REPO_ID)]
    files = {"github": github, "pypi": pypi, "inventory": INVENTORY}
    for key, value in files.items():
        path = tmp_path / f"{key}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        args.extend((f"--{key}", str(path)))
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=10, check=False)
    assert not result.stderr
    for key, value in files.items():
        assert json.loads((tmp_path / f"{key}.json").read_text(encoding="utf-8")) == value
    return result.returncode, json.loads(result.stdout)


def test_both_channels_match_core_build_metadata_despite_github_extras(tmp_path: Path) -> None:
    code, receipt = _run(tmp_path, _capture("github"), _capture("pypi"))
    assert code == 0
    assert receipt["state"] == "metadata_agrees"
    assert receipt["github"]["state"] == receipt["pypi"]["state"] == "metadata_matches"


@pytest.mark.parametrize(("problem", "state", "reason"), [
    ("yanked", "incomplete", "file_yanked"),
    ("yank_unknown", "unknown", "file_yank_state_unverified"),
    ("missing", "incomplete", "core_file_missing"),
    ("changed_digest", "conflict", "build_digest_mismatch"),
    ("missing_digest", "unknown", "digest_unverified"),
    ("duplicate", "conflict", "unexpected_or_duplicate_core_file"),
    ("extra", "conflict", "unexpected_or_duplicate_core_file"),
    ("404", "incomplete", "not_found_does_not_prove_absent"),
    ("503", "unknown", "lookup_failed"),
    ("wrong_project", "unknown", "response_identity_mismatch"),
    ("wrong_version", "unknown", "response_identity_mismatch"),
    ("wrong_path", "unknown", "request_mismatch"),
    ("wrong_origin", "unknown", "request_mismatch"),
    ("mixed_batch", "unknown", "expected_core_digests_match_build_manifest"),
    ("old", "unknown", "stale_or_future_observation"),
])
def test_pypi_uncertainties_do_not_pass(tmp_path: Path, problem: str, state: str, reason: str) -> None:
    snap = _capture("pypi")
    body = snap["body"]
    urls = body["urls"]
    if problem == "yanked":
        urls[0]["yanked"] = True
    elif problem == "yank_unknown":
        del urls[0]["yanked"]
    elif problem == "missing":
        urls.pop()
    elif problem == "changed_digest":
        urls[0]["digests"]["sha256"] = "c" * 64
    elif problem == "missing_digest":
        del urls[0]["digests"]
    elif problem == "duplicate":
        urls.append(urls[0])
    elif problem == "extra":
        urls.append({**urls[0], "filename": "unexpected.whl"})
    elif problem in {"404", "503"}:
        snap["http_status"] = int(problem)
    elif problem == "wrong_project":
        body["info"]["name"] = "other-project"
    elif problem == "wrong_version":
        body["info"]["version"] = "2.0.7"
    elif problem == "wrong_path":
        snap["release_request"]["response_path"] = "/pypi/fxapk/json"
    elif problem == "wrong_origin":
        snap["release_request"]["response_origin"] = "https://mirror.example.test"
    elif problem == "mixed_batch":
        snap["capture_id"] = "other-collection"
    elif problem == "old":
        snap["observed_at"] = "2001-01-01T00:00:00Z"
    code, receipt = _run(tmp_path, _capture("github"), snap)
    assert code == 2
    assert receipt["state"] == state
    assert receipt["pypi"]["reason"] == reason
    assert receipt["github"]["state"] == "metadata_matches"


def test_matching_pypi_cannot_compensate_for_github_digest_conflict(tmp_path: Path) -> None:
    github = _capture("github")
    github["body"]["assets"][0]["digest"] = f"sha256:{'f' * 64}"
    code, receipt = _run(tmp_path, github, _capture("pypi"))
    assert code == 2
    assert receipt["state"] == "conflict"
    assert receipt["github"]["reason"] == "build_digest_mismatch"
    assert receipt["pypi"]["state"] == "metadata_matches"



@pytest.mark.parametrize(("channel", "value"), [("github", "a" * 64), ("pypi", f"sha256:{'a' * 64}")])
def test_channel_specific_digest_encoding_is_required(tmp_path: Path, channel: str, value: str) -> None:
    github, pypi = _capture("github"), _capture("pypi")
    if channel == "github":
        github["body"]["assets"][0]["digest"] = value
    else:
        pypi["body"]["urls"][0]["digests"]["sha256"] = value
    code, receipt = _run(tmp_path, github, pypi)
    assert code == 2
    assert receipt["state"] == "unknown"
    assert receipt[channel]["reason"] == "digest_unverified"


@pytest.mark.parametrize("channel", ["github", "pypi"])
@pytest.mark.parametrize("reverse", [False, True])
def test_incomplete_file_does_not_mask_other_digest_conflict(
    tmp_path: Path, channel: str, reverse: bool,
) -> None:
    github, pypi = _capture("github"), _capture("pypi")
    if channel == "github":
        files = github["body"]["assets"]
        files[0].update(state="open", digest=None)
        files[1]["digest"] = f"sha256:{'c' * 64}"
    else:
        files = pypi["body"]["urls"]
        files[0]["yanked"] = True
        files[1]["digests"]["sha256"] = "c" * 64
    if reverse:
        files.reverse()
    code, receipt = _run(tmp_path, github, pypi)
    assert code == 2
    assert receipt["state"] == "conflict"
    assert receipt[channel]["reason"] == "build_digest_mismatch"


def test_yanked_file_cannot_hide_its_own_recorded_digest_conflict(tmp_path: Path) -> None:
    pypi = _capture("pypi")
    pypi["body"]["urls"][0].update(yanked=True, digests={"sha256": "c" * 64})
    code, receipt = _run(tmp_path, _capture("github"), pypi)
    assert code == 2
    assert receipt["state"] == "conflict"
    assert receipt["pypi"]["reason"] == "build_digest_mismatch"


@pytest.mark.parametrize("extra_seconds", [0, 1])
def test_same_batch_capture_span_boundary(tmp_path: Path, extra_seconds: int) -> None:
    github, pypi = _capture("github"), _capture("pypi")
    gt = datetime.fromisoformat(github["observed_at"])
    pypi["observed_at"] = (gt - timedelta(minutes=15, seconds=extra_seconds)).isoformat()
    code, receipt = _run(tmp_path, github, pypi)
    assert receipt["github"]["state"] == receipt["pypi"]["state"] == "metadata_matches"
    assert code == (2 if extra_seconds else 0)
    assert receipt["reason"] == (
        "snapshots_not_comparable" if extra_seconds else "both_channels_match_expected_core_digests"
    )


def test_receipt_identifies_exact_inputs_without_file_paths(tmp_path: Path) -> None:
    github, pypi = _capture("github"), _capture("pypi")
    hashes = {}
    for capture_id in ("same-collection", "another-collection"):
        github["capture_id"] = pypi["capture_id"] = capture_id
        code, receipt = _run(tmp_path, github, pypi)
        assert code == 0
        assert receipt["version"] == VERSION
        assert receipt["github"]["capture_id"] == receipt["pypi"]["capture_id"] == capture_id
        hashes[capture_id] = receipt["input_sha256"]
        assert hashes[capture_id] == {
            key: hashlib.sha256((tmp_path / f"{key}.json").read_bytes()).hexdigest()
            for key in ("github", "pypi", "inventory")
        }
        assert str(tmp_path) not in json.dumps(receipt)
    assert hashes["same-collection"]["github"] != hashes["another-collection"]["github"]
    assert hashes["same-collection"]["pypi"] != hashes["another-collection"]["pypi"]
    assert hashes["same-collection"]["inventory"] == hashes["another-collection"]["inventory"]


@pytest.mark.parametrize("problem", ["invalid_json", "missing", "oversized", "invalid_inventory"])
def test_failed_input_receipt_identifies_only_complete_reads(tmp_path: Path, problem: str) -> None:
    raw = {
        name: json.dumps(value).encode()
        for name, value in (("inventory", INVENTORY), ("github", _capture("github")), ("pypi", _capture("pypi")))
    }
    if problem == "invalid_json":
        raw["pypi"] = b"{invalid"
    elif problem == "oversized":
        raw["pypi"] = b" " * (2 * 1024 * 1024 + 1)
    elif problem == "invalid_inventory":
        raw["inventory"] = b"{}"
    args = [sys.executable, "-m", "tools.release_channel_metadata", "--version", VERSION, "--repository-id", str(REPO_ID)]
    for name, content in raw.items():
        path = tmp_path / f"{name}.json"
        if not (problem == "missing" and name == "pypi"):
            path.write_bytes(content)
        args.extend((f"--{name}", str(path)))
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 2 and not result.stderr
    receipt = json.loads(result.stdout)
    keys = ["inventory"]
    if problem != "invalid_inventory":
        keys.append("github")
    if problem == "invalid_json":
        keys.append("pypi")
    assert receipt == {
        "version": VERSION, "state": "unknown", "reason": "input_unreadable_or_invalid",
        "input_sha256": {name: hashlib.sha256(raw[name]).hexdigest() for name in keys},
    }



def test_capture_exactly_at_two_mib_is_verified(tmp_path: Path) -> None:
    raw = {
        name: json.dumps(value).encode()
        for name, value in (("inventory", INVENTORY), ("github", _capture("github")), ("pypi", _capture("pypi")))
    }
    raw["pypi"] = raw["pypi"].ljust(2 * 1024 * 1024, b" ")
    args = [sys.executable, "-m", "tools.release_channel_metadata", "--version", VERSION, "--repository-id", str(REPO_ID)]
    for name, content in raw.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(content)
        args.extend((f"--{name}", str(path)))
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0 and not result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["state"] == "metadata_agrees"
    assert receipt["input_sha256"]["pypi"] == hashlib.sha256(raw["pypi"]).hexdigest()
