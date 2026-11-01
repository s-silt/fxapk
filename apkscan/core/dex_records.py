"""Bound decoding before calling StringDataItem.get(), not after get_strings().

These are output/iteration budgets, not a sandbox for the upstream DEX parser.
The limits reuse the endpoint count and snapshot byte envelopes; character
upper bounds deliberately overestimate MUTF-8 decoding and its error fallback.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

from apkscan.core.integrity import sha256_canonical_json
from apkscan.core.observations import DexStringRecord


@dataclass(frozen=True)
class DecodeLimits:
    records: int = 200_000
    record_chars: int = 32 * 1024 * 1024
    total_chars: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        if min(self.records, self.record_chars, self.total_chars) < 1:
            raise ValueError("DEX decode limits must be positive")


def collect_dex_records(
    sources: list[tuple[Any, dict]], limits: DecodeLimits,
) -> tuple[tuple[DexStringRecord, ...], dict]:
    records: list[DexStringRecord] = []
    rows: list[dict] = []
    queue: deque = deque()
    ordered = sorted(sources, key=lambda item: sha256_canonical_json(item[1]))
    for dex, provenance in ordered:
        row = {
            "provenance": provenance, "visited": 0, "decoded": 0,
            "status": "complete", "reason_codes": [], "predecode_bounded": True,
        }
        rows.append(row)
        try:
            strings = getattr(dex, "strings", None)
            if strings is None:
                # Adapters without a raw-item API cannot claim predecode protection.
                row["predecode_bounded"] = False
                strings = dex.get_strings()
            if isinstance(strings, (list, tuple)):
                row["available_records"] = len(strings)
            queue.append((iter(strings), provenance, row))
        except Exception as exc:
            row.update(status="partial", reason_codes=["string_enumeration_failed"],
                       error_type=type(exc).__name__)

    visited = reserved = 0
    while queue and visited < limits.records:
        iterator, provenance, row = queue.popleft()
        try:
            item = next(iterator)
        except StopIteration:
            continue
        except Exception as exc:
            row.update(status="partial", error_type=type(exc).__name__)
            row["reason_codes"].append("string_iteration_failed")
            continue
        row["visited"] += 1
        visited += 1
        raw = getattr(item, "data", item)
        if isinstance(raw, bytes):
            upper = 4 * len(raw) + 32
        elif isinstance(raw, str):
            upper = len(raw)
        else:
            row["status"] = "partial"
            row["reason_codes"].append("unsupported_string_record")
            queue.append((iterator, provenance, row))
            continue
        reason = (
            "record_char_budget" if upper > limits.record_chars else
            "total_char_budget" if reserved + upper > limits.total_chars else ""
        )
        if reason:
            row["status"] = "partial"
            if reason not in row["reason_codes"]:
                row["reason_codes"].append(reason)
            # Skip the remainder of this member, preserving other sources' turns.
            continue
        reserved += upper
        try:
            if isinstance(item, str):
                value = item
            elif isinstance(item, bytes):
                value = item.decode("utf-8", errors="replace")
            else:
                value = item.get()
            if not isinstance(value, str) or len(value) > upper:
                row["status"] = "partial"
                row["reason_codes"].append("decoder_contract_violation")
                continue
            # strings enumerates STRING_DATA_ITEM, not STRING_ID_ITEM.
            offset = getattr(item, "offset", None)
            locator = (
                {"byte_offset": offset, "offset_unit": "dex-bytes"}
                if type(offset) is int and offset >= 0 else {}
            )
            records.append(DexStringRecord(value, provenance, locator))
            row["decoded"] += 1
        except Exception as exc:
            row.update(status="partial", error_type=type(exc).__name__)
            row["reason_codes"].append("string_decode_failed")
        if row.get("available_records") != row["visited"]:
            queue.append((iterator, provenance, row))
    for _, _, row in queue:
        row["status"] = "partial"
        row["reason_codes"].append("record_count_budget")
    for row in rows:
        row["reason_codes"] = sorted(set(row["reason_codes"]))
    return tuple(records), {
        "status": "partial" if any(row["status"] != "complete" for row in rows) else "complete",
        "limits": {"records": limits.records, "record_chars": limits.record_chars,
                   "total_chars": limits.total_chars},
        "visited": visited, "decoded": len(records), "reserved_chars": reserved,
        "members": rows, "parser_isolation": "not_enforced",
    }
