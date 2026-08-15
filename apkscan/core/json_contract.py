"""Strict JSON primitives shared by persisted report/package boundaries."""

from __future__ import annotations

import math
from typing import NoReturn


def reject_nonfinite_json_constant(token: str) -> NoReturn:
    """Reject Python's permissive NaN/Infinity extensions at a JSON boundary."""
    raise ValueError(f"non-finite JSON number is not permitted: {token}")


def parse_finite_json_float(token: str) -> float:
    """Parse a JSON float while rejecting exponent overflow to infinity."""
    value = float(token)
    if not math.isfinite(value):
        reject_nonfinite_json_constant(token)
    return value


__all__ = ["parse_finite_json_float", "reject_nonfinite_json_constant"]
