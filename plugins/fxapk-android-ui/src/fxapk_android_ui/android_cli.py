"""Narrow subprocess adapter for the official Android CLI."""
from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from apkscan.core.proctree import run_owned


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    ownership_complete: bool = True
    termination_complete: bool = True
    forced_tree_kill: bool = False
    reason_codes: tuple[str, ...] = ()
    output_format: str = "raw_bytes"

    @property
    def ok(self) -> bool:
        return (self.exit_code == 0 and not self.timed_out
                and self.ownership_complete and self.termination_complete
                and not self.forced_tree_kill)


class AndroidCli:
    def __init__(self, executable: str | None = None, *, timeout_sec: float = 15.0, deadline: float | None = None) -> None:
        self.executable = executable or shutil.which("android") or shutil.which("android.exe")
        self.timeout_sec = timeout_sec
        self.deadline = deadline

    @property
    def available(self) -> bool:
        return bool(self.executable)

    def _run(self, *args: str, timeout_sec: float | None = None) -> CommandResult:
        if not self.executable:
            return CommandResult(tuple(args), None, b"", b"android_cli_missing")
        argv = (self.executable, "--no-metrics", *args)
        timeout = self.timeout_sec if timeout_sec is None else timeout_sec
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
        if timeout <= 0:
            return CommandResult(argv, None, b"", b"duration_budget_exceeded", timed_out=True)
        # Windows .cmd -> launcher -> JVM must share a Job Object. Killing only
        # the wrapper leaves descendants running and keeps captured pipes open.
        proc = run_owned(list(argv), timeout=timeout)
        return CommandResult(
            argv, proc.returncode, proc.stdout.encode("utf-8"), proc.stderr.encode("utf-8"),
            timed_out=proc.timed_out, ownership_complete=proc.ownership_complete,
            termination_complete=proc.termination_complete,
            forced_tree_kill=proc.forced_tree_kill, reason_codes=proc.reason_codes,
            output_format="utf8_text_normalized",
        )

    def version(self) -> CommandResult:
        return self._run("--version")

    def capture(self, *, serial: str, output: Path, annotate: bool = False) -> CommandResult:
        args = ["screen", "capture", f"--device={serial}", f"--output={output}"]
        if annotate:
            args.append("--annotate")
        return self._run(*args)

    def layout(
        self, *, serial: str, output: Path, full: bool = False, no_idle: bool = False,
    ) -> CommandResult:
        args = ["layout", f"--device={serial}", "--pretty", f"--output={output}"]
        if full:
            args.append("--full")
        if no_idle:
            args.append("--no-idle")
        return self._run(*args)

    def resolve(self, *, screenshot: Path, expression: str) -> CommandResult:
        return self._run("screen", "resolve", f"--screenshot={screenshot}", f"--string={expression}")
