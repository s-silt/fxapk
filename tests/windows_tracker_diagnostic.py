"""Failure-only, bounded observations for the synthetic Windows sleeper fixture."""
from __future__ import annotations

import json
import sys
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any, Iterator


def _count(value: object) -> int | str:
    return value if type(value) is int and 0 <= value <= 4096 else "unknown"


def _snapshot(tracker: Any, counts: Callable[[], object]) -> dict[str, object]:
    result: dict[str, object] = {
        "test": "windows_owned_sleeper", "stage": "post_assertion",
        "observation": "not_atomic_with_assertion_or_job_accounting",
        "notification_identity": "unknown", "tracker_read": "unknown",
        "seen": "unknown", "handles_count": "unknown", "failed": "unknown",
        "job_read": "unknown", "job_active": "unknown", "job_total": "unknown",
    }
    # Never wait for the collector. No handle values or arbitrary object strings.
    try:
        if tracker.lock.acquire(blocking=False):
            try:
                result.update(
                    seen=_count(tracker.seen), handles_count=_count(len(tracker.handles)),
                    failed=tracker.failed if type(tracker.failed) is bool else "unknown",
                    tracker_read="locked",
                )
            finally:
                tracker.lock.release()
        else:
            result["tracker_read"] = "busy"
    except Exception:
        result["tracker_read"] = "error"
    try:
        value = counts()
        if type(value) is tuple and len(value) == 2:
            result.update(job_active=_count(value[0]), job_total=_count(value[1]), job_read="returned")
        else:
            result["job_read"] = "unavailable"
    except Exception:
        result["job_read"] = "error"
    return result


@contextmanager
def diagnose_tracker_assertion(tracker: Any, counts: Callable[[], object]) -> Iterator[None]:
    """Keep the original assertion/exception; observe before fixture teardown."""
    try:
        yield
    except AssertionError as original:
        try:
            print("windows-tracker-failure: " + json.dumps(_snapshot(tracker, counts), sort_keys=True),
                  file=sys.stderr)
        except Exception:
            # Diagnostic failure must not replace the original assertion.
            raise original from None
        raise
