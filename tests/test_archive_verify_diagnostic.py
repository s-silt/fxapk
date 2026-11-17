"""The public verify command distinguishes acquisition from member verification."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fxapk.commands.evidence_archive import app
from fxapk.core.evidence_archive import EvidenceArchive, pack


@pytest.fixture
def archive(tmp_path):
    source = tmp_path / "synthetic"
    source.mkdir()
    (source / "note.txt").write_bytes(b"synthetic bytes")
    target = tmp_path / "synthetic.zip"
    pack(source, target, compression="deflate")
    return target


@pytest.mark.parametrize("stage", ["archive_open", "member_verification"])
@pytest.mark.parametrize("error,reason", [
    (PermissionError, "access_denied"),
    (FileNotFoundError, "not_found"),
    (OSError, "io_error"),
])
def test_verify_failure_reports_only_observed_stage(archive, monkeypatch, stage, error, reason):
    original = Path.open

    def fail_open(path, *args, **kwargs):
        if path == archive:
            raise error("/private/synthetic TOKEN=never-output")
        return original(path, *args, **kwargs)

    def fail_copy(self, *args, **kwargs):
        raise error("/private/synthetic TOKEN=never-output")

    if stage == "archive_open":
        monkeypatch.setattr(Path, "open", fail_open)
    else:
        monkeypatch.setattr(EvidenceArchive, "copy", fail_copy)
    result = CliRunner().invoke(app, ["verify", str(archive)])
    assert result.exit_code == 6
    value = json.loads(result.stderr)
    assert value == {
        "state": "failed", "reason_codes": ["archive_operation_failed"],
        "exception_type": error.__name__,
        "diagnostic": {"first_failure": {"stage": stage, "reason": reason,
                       "index_observed": stage != "archive_open", "all_members_verified": False}},
    }
    assert not result.stdout
    assert "private" not in result.stderr and "TOKEN" not in result.stderr


def test_verify_success_receipt_is_unchanged(archive):
    with EvidenceArchive(archive) as source:
        expected = source.verify()
    result = CliRunner().invoke(app, ["verify", str(archive)])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == expected
    assert not result.stderr


def test_verify_close_failure_preserves_completed_observation(archive, monkeypatch):
    original = EvidenceArchive.close

    def fail_close(self):
        original(self)
        raise OSError("/private/synthetic")

    monkeypatch.setattr(EvidenceArchive, "close", fail_close)
    result = CliRunner().invoke(app, ["verify", str(archive)])
    assert result.exit_code == 6
    assert json.loads(result.stderr)["diagnostic"]["first_failure"] == {
        "stage": "archive_close", "reason": "io_error",
        "index_observed": True, "all_members_verified": True,
    }


@pytest.mark.parametrize("open_fails,inspect_fails,close_fails", [
    (True, False, False), (False, True, False), (False, True, True),
    (False, False, True), (False, False, False),
], ids=["open", "inspect", "inspect_and_close", "close", "success"])
def test_verify_first_failure_keeps_exception_flow_and_single_cleanup(
    archive, monkeypatch, open_fails, inspect_fails, close_fails,
):
    from fxapk.commands import evidence_archive as command

    original_open, original_copy, original_close = Path.open, EvidenceArchive.copy, EvidenceArchive.close
    original_failure = command._failure
    open_error = FileNotFoundError("/private/synthetic open")
    inspect_error = PermissionError("/private/synthetic inspect")
    close_error = OSError("/private/synthetic close")
    events, escaped = [], []
    before = archive.read_bytes()

    def open_source(path, *args, **kwargs):
        if path == archive:
            events.append("open")
            if open_fails:
                raise open_error
        return original_open(path, *args, **kwargs)

    def inspect(self, *args, **kwargs):
        events.append("inspect")
        if inspect_fails:
            raise inspect_error
        return original_copy(self, *args, **kwargs)

    def close(self):
        events.append("close")
        original_close(self)
        if close_fails:
            raise close_error

    def failure(error, *args, **kwargs):
        escaped.append(error)
        return original_failure(error, *args, **kwargs)

    with monkeypatch.context() as patches:
        patches.setattr(Path, "open", open_source)
        patches.setattr(EvidenceArchive, "copy", inspect)
        patches.setattr(EvidenceArchive, "close", close)
        patches.setattr(command, "_failure", failure)
        result = CliRunner().invoke(app, ["verify", str(archive)])
    assert archive.read_bytes() == before
    assert events == (["open"] if open_fails else ["open", "inspect", "close"])
    expected_error = open_error if open_fails else close_error if close_fails else inspect_error if inspect_fails else None
    assert escaped == ([] if expected_error is None else [expected_error])
    if expected_error is None:
        assert result.exit_code == 0
        assert json.loads(result.stdout)["state"] == "verified"
        assert not result.stderr
        return
    assert result.exit_code == 6
    assert escaped[0] is expected_error
    assert expected_error.__cause__ is None
    assert expected_error.__suppress_context__ is False
    assert expected_error.__context__ is (inspect_error if inspect_fails and close_fails else None)
    receipt = json.loads(result.stderr)
    assert receipt["reason_codes"] == ["archive_operation_failed"]
    assert receipt["exception_type"] == type(expected_error).__name__
    assert receipt["state"] == "failed"
    assert receipt["diagnostic"]["first_failure"] == {
        "stage": "archive_open" if open_fails else "member_verification" if inspect_fails else "archive_close",
        "reason": "not_found" if open_fails else "access_denied" if inspect_fails else "io_error",
        "index_observed": not open_fails,
        "all_members_verified": not (open_fails or inspect_fails),
    }
    assert not result.stdout
    assert "private" not in result.stderr
