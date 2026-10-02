"""Bounded strict JSON input shared by collection and review layers.

Only bytes, finite JSON and depth are checked here. Package identity, provenance,
and evidence acceptance belong to their domain-specific validators.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from apkscan.core.bounded_io import read_limited
from apkscan.core.json_contract import parse_finite_json_float, reject_nonfinite_json_constant


def read_json_bounded(path: Path, limit: int, depth_limit: int) -> tuple[Any, bytes]:
    """读取有大小和深度上限的 JSON。NaN / Infinity 走公开 JSON 契约，直接拒绝。"""
    if path.is_symlink():
        raise ValueError("unsafe symlink")
    size = path.stat().st_size
    if size > limit:
        raise OverflowError(f"file size {size} exceeds {limit}")
    # The file can grow after stat(). Bound the actual read as well, rather
    # than trusting an earlier size observation to limit allocation.
    with path.open("rb") as stream:
        raw = read_limited(stream, limit)
    if len(raw) > limit:
        raise OverflowError(f"file size exceeds {limit} while reading")
    payload = json.loads(
        raw.decode("utf-8"),
        parse_constant=reject_nonfinite_json_constant,
        parse_float=parse_finite_json_float,
    )
    if json_depth(payload) > depth_limit:
        raise OverflowError(f"JSON depth exceeds {depth_limit}")
    return payload, raw


def json_depth(value: Any, current: int = 0) -> int:
    if isinstance(value, dict):
        if not value:
            return current + 1
        return max(json_depth(k, current + 1) for k in value) if not value.values() else max(
            max(json_depth(k, current + 1) for k in value),
            max(json_depth(v, current + 1) for v in value.values()),
        )
    if isinstance(value, list):
        return current + 1 if not value else max(
            json_depth(item, current + 1) for item in value
        )
    return current
