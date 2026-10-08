"""Temporary identity observations for one synthetic Windows timeout test."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
import threading
import time
import warnings

import psutil


class WindowsTimeoutObservation:
    def __init__(self, child, identity_path):
        self.child = child
        self.identity_path = identity_path
        self.started = time.monotonic()
        self.identity = None
        self.handle = None
        self.events = []
        self.stop = threading.Event()
        self.native = ctypes.WinDLL("kernel32", use_last_error=True)
        self.native.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        self.native.OpenProcess.restype = wintypes.HANDLE
        self.native.GetProcessTimes.argtypes = (
            wintypes.HANDLE, *(ctypes.POINTER(wintypes.FILETIME),) * 4,
        )
        self.native.GetProcessTimes.restype = wintypes.BOOL
        self.native.GetExitCodeProcess.argtypes = (
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        )
        self.native.GetExitCodeProcess.restype = wintypes.BOOL
        self.native.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        self.native.WaitForSingleObject.restype = wintypes.DWORD
        self.native.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        self.native.TerminateProcess.restype = wintypes.BOOL
        self.native.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.native.CloseHandle.restype = wintypes.BOOL
        self.thread = threading.Thread(target=self._watch, daemon=True)

    def record(self, kind, **data):
        if len(self.events) < 64:
            self.events.append({"seconds": time.monotonic() - self.started, "kind": kind, **data})

    def _state(self, handle):
        values = [wintypes.FILETIME() for _ in range(4)]
        if not self.native.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
            return {"query_error": ctypes.get_last_error()}
        code = wintypes.DWORD()
        if not self.native.GetExitCodeProcess(handle, ctypes.byref(code)):
            return {"query_error": ctypes.get_last_error()}
        ticks = [(value.dwHighDateTime << 32) | value.dwLowDateTime for value in values]
        epoch = (datetime(1970, 1, 1, tzinfo=timezone.utc)
                 - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()
        return {"created_filetime": ticks[0], "exited_filetime": ticks[1],
                "create_time": ticks[0] / 10**7 - epoch, "exit_code": code.value,
                "wait_result": int(self.native.WaitForSingleObject(handle, 0))}

    def snapshot(self):
        return self._state(self.handle) if self.handle is not None else {"handle_captured": False}

    def _capture(self):
        identity = json.loads(self.identity_path.read_text(encoding="utf-8"))
        process = psutil.Process(identity["pid"])
        if process.create_time() != identity["create_time"] or str(self.child) not in process.cmdline():
            self.record("identity_rejected")
            return
        handle = self.native.OpenProcess(0x1000 | 0x100000 | 0x0001, False, identity["pid"])
        if not handle:
            self.record("open_original_handle_failed", error=ctypes.get_last_error())
            return
        state = self._state(handle)
        if abs(state.get("create_time", 0) - identity["create_time"]) >= 0.001:
            self.native.CloseHandle(handle)
            self.record("native_identity_rejected", state=state)
            return
        self.identity = identity
        self.handle = handle
        self.record("original_handle_captured", identity=identity, state=state)

    def _watch(self):
        deadline = time.monotonic() + 2
        while not self.stop.is_set() and time.monotonic() < deadline:
            if self.identity_path.exists():
                try:
                    self._capture()
                except (OSError, ValueError, psutil.Error) as exc:
                    self.record("capture_error", error=type(exc).__name__)
                return
            self.stop.wait(0.005)

    def install(self, monkeypatch, proctree):
        real_active = proctree._job_active_processes
        real_quiesce = proctree._job_wait_quiesce
        real_terminate = proctree._kernel32.TerminateJobObject
        real_exists = psutil.pid_exists
        self.real_exists = real_exists

        def active(job):
            value = real_active(job)
            self.record("job_active_processes", count=value)
            return value

        def quiesce(job):
            value = real_quiesce(job)
            self.record("job_quiesced", result=value, original_process=self.snapshot())
            return value

        def terminate(job, code):
            self.record("terminate_job_requested", active_processes=real_active(job))
            value = real_terminate(job, code)
            self.record("terminate_job_returned", ok=bool(value), error=ctypes.get_last_error())
            return value

        def exists(pid):
            value = real_exists(pid)
            if self.identity is not None and pid == self.identity["pid"]:
                self.record("original_assertion_pid_exists", value=value,
                            original_process=self.snapshot())
            return value

        monkeypatch.setattr(proctree, "_job_active_processes", active)
        monkeypatch.setattr(proctree, "_job_wait_quiesce", quiesce)
        monkeypatch.setattr(proctree._kernel32, "TerminateJobObject", terminate)
        monkeypatch.setattr(psutil, "pid_exists", exists)
        self.thread.start()

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=1)
        self.record("observation_finished", watcher_alive=self.thread.is_alive(),
                    original_process=self.snapshot())
        # This runs after the original assertions. It cannot turn their failure into success.
        if self.handle is not None:
            wait_result = int(self.native.WaitForSingleObject(self.handle, 1000))
            self.record("bounded_native_exit_observation", wait_result=wait_result,
                        original_process=self.snapshot(),
                        pid_exists=self.real_exists(self.identity["pid"]))

    def cleanup_original(self, pid):
        # No numeric-PID kill: retain the already verified original kernel object.
        state = self.snapshot()
        if (self.identity is not None and pid == self.identity["pid"]
                and abs(state.get("create_time", 0) - self.identity["create_time"]) < 0.001
                and state.get("wait_result") == 258 and state.get("exit_code") == 259):
            ok = self.native.TerminateProcess(self.handle, 1)
            self.record("original_test_cleanup", ok=bool(ok), error=ctypes.get_last_error())
            if ok:
                waited = int(self.native.WaitForSingleObject(self.handle, 3000))
                self.record("original_test_cleanup_wait", wait_result=waited,
                            original_process=self.snapshot())

    def emit_and_close(self, pid, result, elapsed):
        try:
            diagnostic = {"schema": "windows-timeout-observation/1", "pid_from_stdout": pid,
                          "identity": self.identity, "events": self.events,
                          "elapsed": elapsed, "timed_out": result.timed_out,
                          "ownership_complete": result.ownership_complete,
                          "termination_complete": result.termination_complete,
                          "reason_codes": result.reason_codes,
                          "observer_retains_native_handle": self.handle is not None}
            self.identity_path.with_name("timeout-diagnostic.json").write_text(
                json.dumps(diagnostic, sort_keys=True), encoding="utf-8",
            )
            warnings.warn("FXAPK_WINDOWS_TIMEOUT_DIAGNOSTIC=" + json.dumps(diagnostic, sort_keys=True),
                          RuntimeWarning, stacklevel=2)
        finally:
            if self.handle is not None and not self.thread.is_alive():
                self.native.CloseHandle(self.handle)
