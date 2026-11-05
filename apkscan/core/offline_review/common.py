"""Bounded, strict input primitives shared by the offline reviewers."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

MAX_BYTES = 32 * 1024 * 1024
MAX_EVENTS = 100_000


def read_bytes(path: Path, limit: int = MAX_BYTES) -> bytes:
    if not path.is_file():
        raise ValueError("input_not_regular_file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input_byte_budget")
    return data


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pairs(items: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise ValueError("nonfinite_json")


def json_value(data: bytes | str) -> Any:
    try:
        return json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError("invalid_json") from error


def integer(value: Any, minimum: int = 0, maximum: int = 2**64 - 1) -> int:
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]+", value):
        value = int(value, 16)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid_integer")
    return value


def hex_bytes(value: Any, limit: int = 1024 * 1024) -> bytes:
    if not isinstance(value, str) or len(value) > limit * 2 or not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value):
        raise ValueError("invalid_hex_bytes")
    return bytes.fromhex(value)


def lines(data: bytes):
    # The input is already byte-bounded; reject, rather than silently trim, long lines.
    for number, raw in enumerate(data.splitlines(), 1):
        if number > MAX_EVENTS:
            yield number, None, "event_budget"
            return
        if not raw.strip():
            yield number, None, "blank_event"
            continue
        if len(raw) > 64 * 1024:
            yield number, None, "line_byte_budget"
            continue
        try:
            row = json_value(raw)
            if not isinstance(row, dict):
                raise ValueError("event_not_object")
            yield number, row, None
        except ValueError:
            yield number, None, "invalid_event_json"


def result(state: str = "ok", reasons: list[str] | None = None, **values: Any) -> dict:
    return {"state": state, "reason_codes": reasons or [], "runtime_observed": False, **values}
