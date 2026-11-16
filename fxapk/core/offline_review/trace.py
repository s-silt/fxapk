"""Reconstruct observed writes without inventing bytes or crossing address spaces."""
from __future__ import annotations

from collections import Counter

from .common import hex_bytes, integer, lines, result


def review(data: bytes, options: dict) -> dict:
    start = integer(options.get("address"))
    size = integer(options.get("size"), 1, 65536)
    if start + size > 2**64:
        raise ValueError("address_overflow")
    run_id, space = options.get("run_id"), options.get("address_space")
    if not isinstance(run_id, str) or not run_id or not isinstance(space, str) or not space:
        raise ValueError("trace_scope_required")
    memory: list[int | None] = [None] * size
    counts: Counter = Counter()
    errors: Counter = Counter()
    previous = 0
    last_line = 0
    for number, row, error in lines(data):
        last_line = number
        if error:
            errors[error] += 1
            memory[:] = [None] * size
            continue
        try:
            assert row is not None
            if row.get("run_id") != run_id or row.get("address_space") != space:
                raise ValueError("trace_scope_mismatch")
            seq = integer(row.get("seq"), 1)
            if seq <= previous:
                raise ValueError("nonmonotonic_sequence")
            if seq != previous + 1:
                errors["sequence_gap"] += 1
                memory[:] = [None] * size
            previous = seq
            operation = row.get("op")
            if operation == "lost":
                errors["lost_events"] += integer(row.get("count"), 1)
                memory[:] = [None] * size
                continue
            if operation not in {"read", "write"}:
                raise ValueError("unsupported_trace_operation")
            address = integer(row.get("address"))
            width = integer(row.get("size"), 1, 16384)
            if address + width > 2**64:
                raise ValueError("address_overflow")
            payload = None if row.get("data_hex") is None else hex_bytes(row["data_hex"], 16384)
            if payload is not None and len(payload) != width:
                raise ValueError("event_size_mismatch")
            # data_hex is address-order bytes; integers/implicit endianness are rejected.
            if "value" in row:
                raise ValueError("ambiguous_integer_payload")
            counts[operation] += 1
            low, high = max(start, address), min(start + size, address + width)
            if low >= high:
                counts["outside_window"] += 1
                continue
            if low != address or high != address + width:
                counts["clipped_to_requested_window"] += 1
            for pos in range(low, high):
                offset = pos - start
                value = None if payload is None else payload[pos - address]
                if operation == "write":
                    memory[offset] = value
                elif value is not None and memory[offset] is not None and memory[offset] != value:
                    errors["read_write_conflict"] += 1
                    memory[offset] = None
            if operation == "write" and payload is None:
                errors["write_value_missing"] += 1
        except (ValueError, AssertionError) as exc:
            errors[str(exc) or "invalid_event"] += 1
            memory[:] = [None] * size
    known = sum(value is not None for value in memory)
    if not last_line:
        errors["empty_trace"] += 1
    return result(
        "partial" if errors or known < size else "ok", sorted(errors),
        address=start, size=size, run_id=run_id, address_space=space,
        known_bytes=known, unknown_bytes=size - known,
        # Never publish a zero-filled binary as reconstructed evidence.
        bytes_hex="".join("??" if value is None else f"{value:02x}" for value in memory),
        last_sequence=previous, lines_seen=last_line, event_counts=dict(counts), errors=dict(errors),
        coverage="observed_writes_only", complete_execution_verified=False,
    )
