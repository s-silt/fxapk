"""Exercise the offline two-channel diagnostic using inert captures."""
import hashlib
import json
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

import pytest

from tools.release_state_probe import diagnose

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
    ("404", "unknown", "not_found_does_not_prove_absent"),
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



@pytest.mark.parametrize("channel", ["github", "pypi"])
@pytest.mark.parametrize(
    ("observation", "state", "reason", "detail"),
    [
        ("missing", "incomplete", "channel_not_verified", "core_file_missing"),
        (404, "unknown", "channel_not_observed", "not_found_does_not_prove_absent"),
        (403, "unknown", "channel_unverified", "lookup_failed"),
        (503, "unknown", "channel_unverified", "lookup_failed"),
    ],
)
def test_aggregate_separates_missing_file_from_inconclusive_lookup(
    tmp_path: Path, channel: str, observation: str | int, state: str, reason: str, detail: str,
) -> None:
    github, pypi = _capture("github"), _capture("pypi")
    capture = github if channel == "github" else pypi
    if observation == "missing":
        capture["body"]["assets" if channel == "github" else "urls"].pop(0)
    else:
        capture["http_status"] = observation
        capture["body"] = None
    code, receipt = _run(tmp_path, github, pypi)
    assert (code, receipt["state"], receipt["reason"]) == (2, state, reason)
    assert receipt[channel]["reason"] == detail


@pytest.mark.parametrize(
    ("other", "state", "reason"),
    [
        ("missing", "unknown", "channel_not_observed"),
        (403, "unknown", "channel_unverified"),
        ("conflict", "conflict", "channel_metadata_conflict"),
        (404, "unknown", "channel_not_observed"),
    ],
)
def test_unobserved_github_preserves_independent_pypi_evidence(
    tmp_path: Path, other: str | int, state: str, reason: str,
) -> None:
    github, pypi = _capture("github"), _capture("pypi")
    github.update(http_status=404, body=None)
    if other == "missing":
        pypi["body"]["urls"].pop(0)
    elif other == "conflict":
        pypi["body"]["urls"][0]["digests"]["sha256"] = "c" * 64
    else:
        pypi.update(http_status=other, body=None)
    code, receipt = _run(tmp_path, github, pypi)
    assert (code, receipt["state"], receipt["reason"]) == (2, state, reason)
    assert receipt["github"]["state"] == "not_observed"
    if other == "missing":
        assert receipt["pypi"]["reason"] == "core_file_missing"

@pytest.mark.parametrize("unobserved_channel", ["github", "pypi"])
def test_cross_batch_404_preserves_conflict_without_comparing_snapshots(
    tmp_path: Path, unobserved_channel: str,
) -> None:
    github, pypi = _capture("github"), _capture("pypi")
    pypi["capture_id"] = "other-collection"
    if unobserved_channel == "github":
        github.update(http_status=404, body=None)
        pypi["body"]["urls"][0]["digests"]["sha256"] = "c" * 64
        conflicting_channel = "pypi"
    else:
        pypi.update(http_status=404, body=None)
        github["body"]["assets"][0]["digest"] = f"sha256:{'c' * 64}"
        conflicting_channel = "github"
    code, receipt = _run(tmp_path, github, pypi)
    assert (code, receipt["state"], receipt["reason"]) == (2, "unknown", "snapshots_not_comparable")
    assert receipt[unobserved_channel]["state"] == "not_observed"
    assert receipt[conflicting_channel]["state"] == "conflict"
    assert receipt[conflicting_channel]["reason"] == "build_digest_mismatch"


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


@pytest.mark.parametrize("yank_flag", ["missing", "string"])
@pytest.mark.parametrize(
    ("digest", "state", "reason", "channel_reason"),
    [
        ("c" * 64, "conflict", "channel_metadata_conflict", "build_digest_mismatch"),
        (INVENTORY[WHEEL], "unknown", "channel_unverified", "file_yank_state_unverified"),
        ("invalid", "unknown", "channel_unverified", "file_yank_state_unverified"),
    ],
)
def test_unverified_pypi_yank_state_does_not_mask_valid_digest_conflict(
    tmp_path: Path, yank_flag: str, digest: str, state: str, reason: str, channel_reason: str,
) -> None:
    pypi = _capture("pypi")
    wheel = pypi["body"]["urls"][0]
    assert wheel["filename"] == WHEEL
    if yank_flag == "missing":
        del wheel["yanked"]
    else:
        wheel["yanked"] = "false"
    wheel["digests"]["sha256"] = digest
    code, receipt = _run(tmp_path, _capture("github"), pypi)
    assert (code, receipt["state"], receipt["reason"]) == (2, state, reason)
    assert receipt["github"]["state"] == "metadata_matches"
    assert (receipt["pypi"]["state"], receipt["pypi"]["reason"]) == (state, channel_reason)


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


@pytest.mark.parametrize(("case", "exit_code", "state", "github_reason", "metadata_state"), [
    ("ok", 0, "evidence_checks_passed", "tag_and_downloaded_bytes_match", "metadata_agrees"),
    ("wrong-tag", 2, "conflict", "tag_commit_mismatch", "metadata_agrees"),
    ("no-downloads", 2, "unknown", "downloaded_bytes_unverified", "metadata_agrees"),
    ("wrong-download-size", 2, "conflict", "download_size_mismatch", "metadata_agrees"),
    ("wrong-downloaded-bytes", 2, "conflict", "download_digest_mismatch", "metadata_agrees"),
    ("query-forbidden", 2, "unknown", "lookup_failed", "unknown"),
    ("query-not-found", 2, "unknown", "not_found_does_not_prove_absent", "unknown"),
    ("missing-github-asset", 2, "incomplete", "asset_inventory_mismatch", "metadata_agrees"),
    ("pypi-conflict", 2, "conflict", "tag_and_downloaded_bytes_match", "conflict"),
    ("pypi-missing", 2, "incomplete", "tag_and_downloaded_bytes_match", "incomplete"),
    ("mixed-captures", 2, "unknown", "tag_and_downloaded_bytes_match", "unknown"),
    ("missing-github-digest", 2, "unknown", "tag_and_downloaded_bytes_match", "unknown"),
    ("span-at-limit", 0, "evidence_checks_passed", "tag_and_downloaded_bytes_match", "metadata_agrees"),
    ("span-over-limit-tag-earliest", 2, "unknown", "tag_and_downloaded_bytes_match", "metadata_agrees"),
    ("span-over-limit-download-earliest", 2, "unknown", "tag_and_downloaded_bytes_match", "metadata_agrees"),
    ("span-over-limit-and-conflict", 2, "conflict", "tag_and_downloaded_bytes_match", "conflict"),
])
def test_offline_combined_release_diagnosis(
    tmp_path: Path, case: str, exit_code: int, state: str, github_reason: str, metadata_state: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    github, pypi = _capture("github"), _capture("pypi")
    commit = "c" * 40
    artifacts = {WHEEL: b"synthetic wheel", SDIST: b"synthetic sdist", "SHA256SUMS.txt": b"synthetic sums"}
    inventory = {name: hashlib.sha256(data).hexdigest() for name, data in artifacts.items()}
    downloads = tmp_path / "downloaded"
    downloads.mkdir()
    assets = []
    for asset_id, (name, data) in enumerate(artifacts.items(), 1):
        (downloads / name).write_bytes(data)
        assets.append({"id": asset_id, "name": name, "size": len(data), "state": "uploaded",
                       "digest": f"sha256:{inventory[name]}"})
    github["body"].update(id=17, assets=assets)
    github["tag_observation"] = {
        "repository_id": REPO_ID, "tag": f"v{VERSION}", "observed_at": github["observed_at"],
        "capture_id": github["capture_id"], "peeled_tag_commit": "d" * 40 if case == "wrong-tag" else commit,
    }
    github["download_observation"] = {
        "repository_id": REPO_ID, "release_id": 17, "asset_ids": {a["name"]: a["id"] for a in assets},
        "observed_at": github["observed_at"], "capture_id": github["capture_id"],
    }
    if case.startswith("span-"):
        midpoint = datetime.fromisoformat(github["observed_at"]) - timedelta(minutes=10)
        github["observed_at"] = midpoint.isoformat()
        older = (midpoint - timedelta(minutes=8)).isoformat()
        github["tag_observation"]["observed_at"] = older
        github["download_observation"]["observed_at"] = older
        pypi["observed_at"] = (
            midpoint + timedelta(minutes=7, microseconds=int(case != "span-at-limit"))
        ).isoformat()
        if case == "span-over-limit-download-earliest":
            github["tag_observation"]["observed_at"] = midpoint.isoformat()
        elif case == "span-over-limit-tag-earliest":
            github["download_observation"]["observed_at"] = midpoint.isoformat()
    for file in pypi["body"]["urls"]:
        file["digests"]["sha256"] = inventory[file["filename"]]
    if case == "query-forbidden":
        github["http_status"] = 403
    elif case == "query-not-found":
        github["http_status"] = 404
    elif case == "missing-github-asset":
        github["body"]["assets"].pop()
    elif case == "wrong-download-size":
        (downloads / WHEEL).write_bytes(b"x")
    elif case == "wrong-downloaded-bytes":
        (downloads / WHEEL).write_bytes(b"x" * len(artifacts[WHEEL]))
    elif case == "missing-github-digest":
        del assets[0]["digest"]
    elif case in {"pypi-conflict", "span-over-limit-and-conflict"}:
        pypi["body"]["urls"][0]["digests"]["sha256"] = "e" * 64
    elif case == "pypi-missing":
        pypi["body"]["urls"].pop()
    elif case == "mixed-captures":
        pypi["capture_id"] = "different-collection"

    args = [sys.executable, "-m", "tools.release_channel_metadata", "--version", VERSION,
            "--repository-id", str(REPO_ID), "--github-commit", commit]
    if case != "no-downloads":
        args.extend(("--downloaded", str(downloads)))
    for key, value in {"github": github, "pypi": pypi, "inventory": inventory}.items():
        path = tmp_path / f"{key}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        args.extend((f"--{key}", str(path)))

    def snapshot() -> dict[Path, bytes]:
        return {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}

    before = snapshot()
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=10, check=False)
    assert not result.stderr
    assert result.returncode == exit_code
    receipt = json.loads(result.stdout)
    assert receipt["state"] == state
    assert receipt["expected_commit"] == commit
    assert receipt["github_evidence"]["reason"] == github_reason
    assert receipt["metadata_comparison"]["state"] == metadata_state
    if case == "missing-github-digest":
        assert receipt["github"]["reason"] == "digest_unverified"
    if case in {"span-over-limit-tag-earliest", "span-over-limit-download-earliest"}:
        assert receipt["reason"] == "combined_capture_span_exceeded"
    assert receipt["input_sha256"] == {
        key: hashlib.sha256(before[Path(f"{key}.json")]).hexdigest() for key in ("github", "pypi", "inventory")
    }
    assert snapshot() == before
    if case == "wrong-downloaded-bytes":
        first_observation = {
            "asset_name": WHEEL,
            "observed_sha256": hashlib.sha256(before[Path("downloaded") / WHEEL]).hexdigest(),
        }
        other_bytes = b"y" * len(artifacts[WHEEL])
        (downloads / WHEEL).write_bytes(other_bytes)
        second = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=10, check=False)
        assert second.returncode == 2 and not second.stderr
        second_receipt = json.loads(second.stdout)
        assert second_receipt["input_sha256"] == receipt["input_sha256"]
        assert second_receipt["state"] == receipt["state"] == "conflict"
        assert second_receipt != receipt
        assert receipt["github_evidence"]["download_conflict"] == first_observation
        assert second_receipt["github_evidence"]["download_conflict"] == {
            "asset_name": WHEEL, "observed_sha256": hashlib.sha256(other_bytes).hexdigest(),
        }
    elif case == "wrong-download-size":
        (downloads / WHEEL).write_bytes(b"yy")
        second = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=10, check=False)
        assert second.returncode == 2 and not second.stderr
        second_receipt = json.loads(second.stdout)
        assert second_receipt["input_sha256"] == receipt["input_sha256"]
        assert second_receipt["state"] == receipt["state"] == "conflict"
        assert second_receipt != receipt
        for observed_size, item in enumerate((receipt, second_receipt), start=1):
            assert item["github_evidence"]["reason"] == "download_size_mismatch"
            assert item["github_evidence"]["download_conflict"] == {
                "asset_name": WHEEL,
                "expected_size": len(artifacts[WHEEL]),
                "observed_size": observed_size,
            }

        standalone = subprocess.run(
            [sys.executable, "-m", "tools.release_state_probe",
             "--capture", str(tmp_path / "github.json"), "--inventory", str(tmp_path / "inventory.json"),
             "--downloaded", str(downloads), "--repository", "s-silt/fxapk",
             "--repository-id", str(REPO_ID), "--tag", f"v{VERSION}", "--commit", commit],
            cwd=ROOT, capture_output=True, text=True, timeout=10, check=False,
        )
        assert standalone.returncode == 2 and not standalone.stderr
        assert json.loads(standalone.stdout) == {
            "state": "conflict", "reason": "download_size_mismatch",
            "observed_at": github["observed_at"], "http_status": 200,
        }

        real_open = Path.open
        guarded_paths: list[Path] = []

        def unexpected_read(_size: int) -> bytes:
            pytest.fail("file body was read after a measured size mismatch")

        @contextmanager
        def guarded_open(path: Path, *args: Any, **kwargs: Any) -> Iterator[object]:
            with real_open(path, *args, **kwargs) as stream:
                if path == downloads / WHEEL:
                    guarded_paths.append(path)
                    yield SimpleNamespace(fileno=stream.fileno, read=unexpected_read)
                else:
                    yield stream

        with monkeypatch.context() as guard:
            guard.setattr(Path, "open", guarded_open)
            diagnostic = diagnose(
                github, repository="s-silt/fxapk", repository_id=REPO_ID, tag=f"v{VERSION}",
                commit=commit, expected=inventory, downloaded=downloads,
            )
        assert guarded_paths == [downloads / WHEEL]
        assert diagnostic.to_receipt(include_download_conflict=True) == second_receipt["github_evidence"]
    else:
        assert "download_conflict" not in receipt["github_evidence"]
