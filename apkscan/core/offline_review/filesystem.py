"""Review normalized filesystem observations; never launch or install a collector."""
from __future__ import annotations

from collections import Counter

from .common import integer, lines, result


def review(data: bytes, options: dict) -> dict:
    backend = options.get("backend")
    run_id = options.get("run_id")
    clock = options.get("timestamp_basis")
    if backend not in {"inotify", "fanotify", "unknown"} or clock not in {"unix_ns", "monotonic_ns"}:
        raise ValueError("filesystem_capture_contract_required")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("filesystem_run_id_required")
    errors: Counter = Counter()
    counts: Counter = Counter()
    events = []
    last_seq = last_time = 0
    for number, row, error in lines(data):
        if error:
            errors[error] += 1
            continue
        try:
            assert row is not None
            if row.get("run_id") != run_id:
                raise ValueError("filesystem_scope_mismatch")
            seq = integer(row.get("seq"), 1)
            timestamp = integer(row.get("timestamp"))
            if seq <= last_seq or timestamp < last_time:
                raise ValueError("event_order_invalid")
            if seq != last_seq + 1:
                errors["sequence_gap"] += 1
            last_seq, last_time = seq, timestamp
            op = row.get("op")
            if op == "lost":
                errors["lost_events"] += integer(row.get("count"), 1)
                continue
            if op not in {"create", "modify", "delete", "move_from", "move_to", "open", "close"}:
                raise ValueError("unsupported_filesystem_operation")
            path = row.get("path")
            if not isinstance(path, str) or not path.startswith("/") or len(path) > 4096 or "\0" in path:
                raise ValueError("invalid_filesystem_path")
            pid = None if row.get("pid") is None else integer(row["pid"], 1, 2**31 - 1)
            counts[op] += 1
            # Preserve /data/user/0, /data/user/10 and user_de exactly as observed.
            events.append({"line": number, "seq": seq, "timestamp": timestamp, "op": op,
                           "path": path, "reported_pid": pid,
                           "process_attribution": "candidate" if backend == "fanotify" and pid else "unknown",
                           "target_app_attribution_verified": False})
        except (ValueError, AssertionError) as exc:
            errors[str(exc) or "invalid_event"] += 1
    if not events:
        errors["no_valid_events"] += 1
    if backend == "unknown":
        errors["collector_backend_unknown"] += 1
    if options.get("capture_complete") is not True:
        errors["capture_completeness_unknown"] += 1
    return result("partial" if errors else "ok", sorted(errors), backend=backend, run_id=run_id,
                  timestamp_basis=clock, event_counts=dict(counts), errors=dict(errors), events=events,
                  device_collection="not_performed", file_contents_verified=False,
                  target_app_attribution_verified=False, coverage="supplied_events_only")
