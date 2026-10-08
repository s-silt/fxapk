"""Restricted Android UI actions for optional interaction plugins.

This module exposes fixed ADB operations only. Root input requires explicit opt-in;
callers cannot supply arbitrary shell commands.
"""
from __future__ import annotations

import math
import re
import subprocess
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Literal

from apkscan.core import device

_MAX_COORDINATE = 20_000
_MAX_TEXT_LENGTH = 256
_MAX_WAIT_SECONDS = 30.0
_KEYEVENTS = frozenset({"BACK", "ENTER", "TAB", "DPAD_UP", "DPAD_DOWN", "DPAD_LEFT", "DPAD_RIGHT", "HOME"})
_FOREGROUND_RE = re.compile(r"(?:mCurrentFocus|mResumedActivity|topResumedActivity).*?\s([A-Za-z0-9_.]+)/")
_INJECTION_DENIED_RE = re.compile(
    r"(?im)^\s*(?:java\.lang\.)?SecurityException(?:\s*:|$)"
    r"|^\s*[^\r\n]*\brequires\b[^\r\n]*\bINJECT_EVENTS\b"
)
_COMMAND_FAILURE_RE = re.compile(
    r"(?im)^\s*(?:error\s*:|exception occurred while executing\b"
    r"|(?:su|/system/bin/sh|sh)\s*:[^\r\n]*(?:permission denied|not found)"
    r"|\*\*\s*no activities found to run, monkey aborted)"
)


@dataclass(frozen=True)
class ActionResult:
    action: str
    ok: bool
    detail: str = ""
    value_length: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _serial_args(serial: str) -> list[str]:
    if not isinstance(serial, str) or not serial.strip() or any(char.isspace() for char in serial):
        raise ValueError("serial_required")
    return ["adb", "-s", serial]


def _bounded_coordinate(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_COORDINATE:
        raise ValueError("invalid_coordinate")
    return value


def _bounded_wait(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("invalid_wait_timeout")
    return min(float(value), _MAX_WAIT_SECONDS)


def _encoded_text(value: object) -> str:
    # Android input text handles ASCII key events and rewrites every literal %s as a space.
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT_LENGTH or "%s" in value or any(not 32 <= ord(c) <= 126 for c in value):
        raise ValueError("invalid_input_text")
    # ADB joins shell argv on the device: host argv alone is insufficient quoting.
    return device._shq(value.replace(" ", "%s"))


def _command_failure(proc: subprocess.CompletedProcess | None) -> str:
    """Android input can print a Java exception while returning exit zero."""
    if proc is None:
        return "command_unavailable_or_timed_out"
    output = "\n".join(str(getattr(proc, field, "") or "") for field in ("stdout", "stderr"))
    if _INJECTION_DENIED_RE.search(output):
        return "injection_permission_denied"
    if proc.returncode != 0:
        return "command_exit_nonzero"
    if _COMMAND_FAILURE_RE.search(output):
        return "device_command_failed"
    return ""


def validate_action(step: object) -> None:
    """Validate the complete fixed action before a plan performs any mutation."""
    if not isinstance(step, Mapping):
        raise ValueError("invalid_action")
    kind = step.get("kind")
    if kind == "tap":
        _bounded_coordinate(step.get("x"))
        _bounded_coordinate(step.get("y"))
    elif kind == "input_text":
        _encoded_text(step.get("value"))
    elif kind == "wait":
        _bounded_wait(step.get("seconds"))
    elif kind == "wait_for_foreground":
        _bounded_wait(step.get("timeout_sec", 5))
    elif kind == "snapshot":
        if "no_idle" in step and not isinstance(step["no_idle"], bool):
            raise ValueError("invalid_no_idle")
    elif kind not in ("launch", "back"):
        raise ValueError("invalid_action")


class AndroidActions:
    """Fixed actions for one selected package, device, and optional deadline."""

    def __init__(
        self, *, serial: str, package: str, deadline: float | None = None,
        root_actions: bool = False,
    ) -> None:
        if not isinstance(package, str) or not device.is_valid_package(package):
            raise ValueError("invalid_package")
        _serial_args(serial)
        if deadline is not None and not math.isfinite(deadline):
            raise ValueError("invalid_deadline")
        if not isinstance(root_actions, bool):
            raise ValueError("invalid_root_actions")
        self.serial = serial
        self.package = package
        self.deadline = deadline
        self.root_actions = root_actions

    def _run(
        self, args: list[str], *, log_args: list[str] | None = None,
    ) -> subprocess.CompletedProcess | None:
        timeout = 5.0
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                return None
            timeout = min(timeout, remaining)
        return device._run(args, timeout=timeout, log_args=log_args)

    def launch_package(self) -> ActionResult:
        proc = self._run(
            _serial_args(self.serial)
            + ["shell", "monkey", "-p", self.package, "-c", "android.intent.category.LAUNCHER", "1"]
        )
        failure = _command_failure(proc)
        return ActionResult("launch", not failure, failure or "launcher_requested")

    def _input_args(self, *tokens: str) -> list[str]:
        command = ["input", *tokens]
        if self.root_actions:
            # ADB joins shell argv, then su interprets its command argument.
            # Tokens such as text are already quoted for the inner shell.
            return _serial_args(self.serial) + ["shell", "su", "-c", device._shq(" ".join(command))]
        return _serial_args(self.serial) + ["shell", *command]

    def foreground_package(self) -> str | None:
        proc = self._run(_serial_args(self.serial) + ["shell", "dumpsys", "activity", "activities"])
        if proc is None or proc.returncode != 0:
            return None
        match = _FOREGROUND_RE.search(proc.stdout or "")
        return match.group(1) if match else None

    def wait_foreground(self, *, timeout_sec: float = 5.0) -> ActionResult:
        deadline = time.monotonic() + _bounded_wait(timeout_sec)
        if self.deadline is not None:
            deadline = min(deadline, self.deadline)
        original_deadline = self.deadline
        self.deadline = deadline
        try:
            while True:
                if self.foreground_package() == self.package:
                    return ActionResult("wait_foreground", True, "target_foreground")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return ActionResult("wait_foreground", False, "target_foreground_timeout")
                time.sleep(min(0.2, remaining))
        finally:
            self.deadline = original_deadline

    def tap(self, x: int, y: int) -> ActionResult:
        x, y = _bounded_coordinate(x), _bounded_coordinate(y)
        if self.foreground_package() != self.package:
            return ActionResult("tap", False, "target_foreground_unconfirmed")
        proc = self._run(self._input_args("tap", str(x), str(y)))
        failure = _command_failure(proc)
        return ActionResult("tap", not failure, failure)

    def input_text(self, value: str) -> ActionResult:
        escaped = _encoded_text(value)
        if self.foreground_package() != self.package:
            return ActionResult("input_text", False, "target_foreground_unconfirmed", value_length=len(value))
        args = self._input_args("text", escaped)
        proc = self._run(args, log_args=self._input_args("text", "[redacted]"))
        failure = _command_failure(proc)
        return ActionResult("input_text", not failure, failure, value_length=len(value))

    def keyevent(self, key: Literal["BACK", "ENTER", "TAB", "DPAD_UP", "DPAD_DOWN", "DPAD_LEFT", "DPAD_RIGHT", "HOME"]) -> ActionResult:
        if key not in _KEYEVENTS:
            raise ValueError("invalid_keyevent")
        if self.foreground_package() != self.package:
            return ActionResult("keyevent", False, "target_foreground_unconfirmed")
        proc = self._run(self._input_args("keyevent", key))
        failure = _command_failure(proc)
        return ActionResult("keyevent", not failure, failure or key)

    def back(self) -> ActionResult:
        return self.keyevent("BACK")

    def wait(self, seconds: float) -> ActionResult:
        bounded = _bounded_wait(seconds)
        if self.deadline is not None and bounded > self.deadline - time.monotonic():
            return ActionResult("wait", False, "duration_budget_exceeded")
        time.sleep(bounded)
        return ActionResult("wait", True, f"waited={bounded:g}s")
