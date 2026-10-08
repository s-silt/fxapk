"""Windows owned-handle exit confirmation; only task-created sleepers are terminated."""
from __future__ import annotations

import ctypes
import subprocess
import sys
import time

import pytest

from apkscan.core import proctree

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows native Job handles")


@pytest.fixture
def owned_sleeper():
    job = proctree._create_kill_on_close_job()
    assert job is not None
    tracker = proctree._JobExitTracker(job)
    executable = getattr(sys, "_base_executable", None) or sys.executable
    proc = subprocess.Popen(
        [executable, "-c", "import time; time.sleep(15)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        assert proctree._assign_pid_to_job(job, proc.pid)
        deadline = time.monotonic() + 2
        while tracker.seen != 1 and not tracker.failed and time.monotonic() < deadline:
            tracker.changed.wait(0.02)
            tracker.changed.clear()
        assert tracker.seen == 1 and len(tracker.handles) == 1 and not tracker.failed
        yield job, tracker, proc
    finally:
        # This Job was created here and contains only the above process; no numeric-PID kill.
        proctree._kernel32.TerminateJobObject(job, 1)
        proc.wait(timeout=5)
        try:
            tracker.close()
        finally:
            proctree._kernel32.CloseHandle(job)


@pytest.mark.parametrize("budget", [0.0, 0.03])
def test_real_live_owned_handle_is_rejected_even_when_job_count_is_zero(
    owned_sleeper, monkeypatch, budget,
):
    _job, tracker, _proc = owned_sleeper
    monkeypatch.setattr(proctree, "_job_process_counts", lambda _job: (0, 1))
    assert proctree._kernel32.WaitForSingleObject(tracker.handles[0], 0) == 258
    started = time.monotonic()
    assert tracker.wait(budget) is False
    assert time.monotonic() - started < 1
    assert proctree._kernel32.WaitForSingleObject(tracker.handles[0], 0) == 258


def test_original_handle_exit_is_confirmed_after_job_termination(owned_sleeper):
    job, tracker, proc = owned_sleeper
    assert proctree._kernel32.TerminateJobObject(job, 1)
    proc.wait(timeout=5)
    assert tracker.wait(1.0) is True


def test_missing_member_notification_remains_unconfirmed(owned_sleeper, monkeypatch):
    job, tracker, proc = owned_sleeper
    proctree._kernel32.TerminateJobObject(job, 1)
    proc.wait(timeout=5)
    monkeypatch.setattr(proctree, "_job_process_counts", lambda _job: (0, 2))
    assert tracker.wait(0.03) is False


@pytest.mark.parametrize("state", [0xFFFFFFFF, 128])
def test_native_wait_failure_never_becomes_complete(owned_sleeper, monkeypatch, state):
    job, tracker, proc = owned_sleeper
    proctree._kernel32.TerminateJobObject(job, 1)
    proc.wait(timeout=5)
    monkeypatch.setattr(proctree._kernel32, "WaitForSingleObject", lambda _handle, _timeout: state)
    assert tracker.wait(0.03) is False


def test_accounting_query_failure_remains_unconfirmed(owned_sleeper, monkeypatch):
    _job, tracker, _proc = owned_sleeper
    monkeypatch.setattr(proctree, "_job_process_counts", lambda _job: None)
    assert tracker.wait(0.03) is False


def test_failed_collector_remains_unconfirmed(owned_sleeper):
    _job, tracker, _proc = owned_sleeper
    tracker.failed = True
    assert tracker.wait(0.03) is False


def test_collector_failure_during_final_confirmation_remains_unconfirmed(
    owned_sleeper, monkeypatch,
):
    job, tracker, proc = owned_sleeper
    proctree._kernel32.TerminateJobObject(job, 1)
    proc.wait(timeout=5)
    calls = []

    def counts(_job):
        calls.append(None)
        if len(calls) == 2:
            tracker.failed = True
        return 0, 1

    monkeypatch.setattr(proctree, "_job_process_counts", counts)
    assert tracker.wait(0.03) is False


def test_collector_lock_cannot_extend_cleanup_budget(owned_sleeper):
    _job, tracker, _proc = owned_sleeper
    tracker.lock.acquire()
    try:
        started = time.monotonic()
        assert tracker.wait(0.03) is False
        assert time.monotonic() - started < 1
    finally:
        tracker.lock.release()


def test_recycled_foreign_pid_is_not_retained_or_waited(monkeypatch):
    tracker = object.__new__(proctree._JobExitTracker)
    tracker.job, tracker.handles, tracker.failed = 3, [], False
    closed = []
    monkeypatch.setattr(proctree._kernel32, "OpenProcess", lambda *_args: 42)
    monkeypatch.setattr(proctree._kernel32, "IsProcessInJob", lambda *_args: False)
    monkeypatch.setattr(proctree._kernel32, "CloseHandle", lambda handle: closed.append(handle))
    tracker._capture(42)
    assert tracker.failed is True and tracker.handles == [] and closed == [42]


@pytest.mark.parametrize(("error", "failed"), [(87, False), (5, True)])
def test_already_gone_and_access_denied_are_distinguished(monkeypatch, error, failed):
    tracker = object.__new__(proctree._JobExitTracker)
    tracker.job, tracker.handles, tracker.failed = 3, [], False
    monkeypatch.setattr(proctree._kernel32, "OpenProcess", lambda *_args: None)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error)
    tracker._capture(42)
    assert tracker.failed is failed and tracker.handles == []


def test_tracking_setup_failure_never_releases_command(monkeypatch, tmp_path):
    marker = tmp_path / "never-run.txt"

    def unavailable(_job):
        raise OSError("synthetic tracker setup failure")

    monkeypatch.setattr(proctree, "_JobExitTracker", unavailable)
    result = proctree.run_owned(
        [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"], timeout=1.0,
    )
    assert not marker.exists()
    assert result.ownership_complete is False
    assert result.termination_complete is True
    assert "exit_tracking_unavailable" in result.reason_codes


def test_native_exit_verification_failure_is_preserved_in_public_result(monkeypatch):
    monkeypatch.setattr(proctree._JobExitTracker, "wait", lambda _self, _budget: False)
    result = proctree.run_owned([sys.executable, "-c", "print('synthetic')"], timeout=5.0)
    assert result.timed_out is False
    assert result.ownership_complete is True
    assert result.termination_complete is False
    assert "process_exit_unverified" in result.reason_codes
