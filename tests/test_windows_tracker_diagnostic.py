"""Portable synthetic contracts; no native processes or Windows APIs required."""
import json
import threading
from types import SimpleNamespace

import pytest

from tests.windows_tracker_diagnostic import diagnose_tracker_assertion


def tracker(**values):
    return SimpleNamespace(lock=threading.Lock(), seen=2, handles=[object()], failed=False, **values)


def record(capsys):
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 1
    return json.loads(lines[0].removeprefix("windows-tracker-failure: "))


def test_original_assertion_and_snapshot_survive_cleanup(capsys):
    state = tracker()
    original = AssertionError("synthetic assertion")
    with pytest.raises(AssertionError) as caught:
        try:
            with diagnose_tracker_assertion(state, lambda: (1, 2)):
                raise original
        finally:
            state.seen, state.handles, state.failed = 0, [], True
    assert caught.value is original
    data = record(capsys)
    assert (data["seen"], data["handles_count"], data["failed"]) == (2, 1, False)
    assert (data["job_active"], data["job_total"]) == (1, 2)
    assert data["notification_identity"] == "unknown"
    assert data["observation"] == "not_atomic_with_assertion_or_job_accounting"


@pytest.mark.parametrize("mode", ["busy", "error"])
def test_tracker_read_categories(capsys, mode):
    state = tracker()
    if mode == "busy":
        state.lock.acquire()
    else:
        state.handles = None
    with pytest.raises(AssertionError):
        with diagnose_tracker_assertion(state, lambda: None):
            assert False, "synthetic"
    if mode == "busy":
        state.lock.release()
    else:
        assert state.lock.acquire(blocking=False)
        state.lock.release()
    data = record(capsys)
    assert data["tracker_read"] == mode
    assert data["seen"] == "unknown"
    assert data["job_read"] == "unavailable"


def test_success_never_reads_or_emits(capsys):
    def forbidden():
        pytest.fail("success must not query accounting")
    with diagnose_tracker_assertion(object(), forbidden):
        assert True
    assert capsys.readouterr().err == ""


def test_unrelated_exception_is_unchanged_and_silent(capsys):
    original = ValueError("synthetic")
    with pytest.raises(ValueError) as caught:
        with diagnose_tracker_assertion(object(), lambda: None):
            raise original
    assert caught.value is original
    assert capsys.readouterr().err == ""


def test_payloads_and_exception_text_never_enter_record(capsys):
    payload = "/synthetic/private --token=not-a-real-secret"
    state = tracker(path=payload, command=payload, environment=payload)
    state.seen, state.failed = payload, payload
    def broken():
        raise PermissionError(payload)
    with pytest.raises(AssertionError):
        with diagnose_tracker_assertion(state, broken):
            assert False, payload
    data = record(capsys)
    assert payload not in json.dumps(data)
    assert data["seen"] == data["failed"] == "unknown"
    assert data["job_read"] == "error"  # No inferred OS failure cause.


def test_output_failure_preserves_original(monkeypatch):
    original = AssertionError("original")
    def broken(*args, **kwargs):
        raise OSError("synthetic output failure")
    monkeypatch.setattr("builtins.print", broken)
    with pytest.raises(AssertionError) as caught:
        with diagnose_tracker_assertion(tracker(), lambda: (0, 1)):
            raise original
    assert caught.value is original


@pytest.mark.parametrize("value", [(-1, 5000), (True, "synthetic")])
def test_accounting_values_are_bounded(capsys, value):
    with pytest.raises(AssertionError):
        with diagnose_tracker_assertion(tracker(), lambda: value):
            assert False
    data = record(capsys)
    assert data["job_active"] == data["job_total"] == "unknown"
