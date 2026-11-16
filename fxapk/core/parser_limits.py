"""Explicit parser budgets; no universal whole-APK memory/time default."""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass


class ParserConfigurationError(ValueError):
    """An incomplete/invalid policy must not silently disable isolation."""


@dataclass(frozen=True)
class ParserLimits:
    timeout_sec: float
    memory_bytes: int
    # IPC budget, not an estimate of APK parser memory consumption.
    max_output_bytes: int = 64 * 1024 * 1024
    max_stderr_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if (isinstance(self.timeout_sec, bool)
                or not isinstance(self.timeout_sec, (int, float))
                or not math.isfinite(self.timeout_sec) or self.timeout_sec <= 0):
            raise ParserConfigurationError("parser_limits_invalid")
        for value in (self.memory_bytes, self.max_output_bytes, self.max_stderr_bytes):
            if type(value) is not int or value <= 0:
                raise ParserConfigurationError("parser_limits_invalid")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> ParserLimits | None:
        values = os.environ if env is None else env
        names = ("FXAPK_PARSER_TIMEOUT_SEC", "FXAPK_PARSER_MEMORY_MB", "FXAPK_PARSER_OUTPUT_MB")
        if not any(name in values for name in names):
            return None
        try:
            timeout = float(values[names[0]])
            memory = int(values[names[1]]) * 1024 * 1024
            output = int(values.get(names[2], "64")) * 1024 * 1024
            return cls(timeout_sec=timeout, memory_bytes=memory, max_output_bytes=output)
        except (KeyError, ValueError, OverflowError) as exc:
            raise ParserConfigurationError("parser_limits_invalid") from exc
