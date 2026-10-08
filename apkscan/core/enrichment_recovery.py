"""Explicit, budgeted recovery for sequential passive batches.

At most one extra adapter call per provider per batch. Every attempt is persisted
before recovery; authentication, credit and unknown errors are never retried.
"""
from __future__ import annotations

import copy
import math
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from apkscan.core import batch_enrich as batch

TRANSIENT_ERRORS = frozenset({"rate_limited", "local_rate_limit", "timeout", "dns_resolution_failed"})


def recovery_budget(lines: Sequence[batch.BudgetLine], enrichers: Sequence[object]) -> dict[str, int]:
    """Upper bound includes auxiliary HTTP requests of a single recovery call."""
    pending = {line.provider for line in lines if line.status == "would_query"}
    result = {}
    for enricher in enrichers:
        name = str(getattr(enricher, "name", ""))
        if name in pending:
            by_kind = getattr(enricher, "request_budget_by_kind", {})
            result[name] = max(1, int(getattr(enricher, "request_budget", 1)), *by_kind.values())
    return result


def enrich_with_recovery(
    targets: Sequence[batch.Target], enrichers: Sequence[object], *,
    mode: str, env: Mapping[str, str], completed: Mapping[str, set[str]],
    on_record: Callable[[dict[str, Any]], None], retry_delay: float = 15,
    provider_interval: float = 2,
) -> list[dict[str, Any]]:
    for value, lower in ((retry_delay, 1), (provider_interval, 0)):
        if isinstance(value, bool) or not math.isfinite(value) or not lower <= value <= 60:
            raise ValueError("invalid_recovery_timing")
    records: list[dict[str, Any]] = []
    retried: set[str] = set()
    stopped: dict[str, str] = {}
    last_call: dict[str, float] = {}

    def persist(record: dict[str, Any]) -> None:
        frozen = copy.deepcopy(record)
        on_record(frozen)  # Persistence failure must stop before another request.
        records.append(frozen)

    def attempt(target: batch.Target, enricher: object, *, retry: bool) -> dict[str, Any]:
        name = str(getattr(enricher, "name"))
        delay = max(0.0, last_call.get(name, -math.inf) + provider_interval - time.monotonic())
        if delay:
            time.sleep(delay)
        rows = batch.enrich_targets([target], [enricher], mode=mode, env=env)
        last_call[name] = time.monotonic()
        record = rows[0]
        record["recovery"] = {"retry": retry, "provider_interval_seconds": provider_interval,
                              "max_extra_calls_per_provider": 1}
        persist(record)
        return record

    for target in targets:
        for enricher in batch.pending_enrichers(target, enrichers, env, completed):
            name = str(getattr(enricher, "name"))
            if name in stopped:
                persist({"target": target.value, "kind": target.kind, "enrichment": {},
                         "source_status": {name: {"status": "skipped", "error_type": stopped[name]}},
                         "recovery": {"reason": "provider_stopped_after_bounded_recovery",
                                      "network_attempted": False}})
                continue
            record = attempt(target, enricher, retry=False)
            state = record.get("source_status", {}).get(name, {})
            error = state.get("error_type")
            if state.get("status") != "failed":
                continue
            if error not in TRANSIENT_ERRORS:
                # No loosening of the adapter's permanent-error breaker.
                continue
            # A DNS miss belongs to this target. Exhausting its recovery
            # allowance must not block independent targets of the provider.
            if error == "dns_resolution_failed" and name in retried:
                continue
            receipt = record.get("receipts", {}).get(name, {})
            remote_delay = receipt.get("retry_after_seconds", 0)
            if (type(remote_delay) not in (int, float) or not math.isfinite(remote_delay)
                    or remote_delay < 0 or remote_delay > 60 or name in retried):
                stopped[name] = error
                continue
            blocked = getattr(enricher, "_blocked_error", None)
            if blocked is not None and blocked not in TRANSIENT_ERRORS:
                stopped[name] = error
                continue
            retried.add(name)
            time.sleep(max(retry_delay, remote_delay))
            if blocked is not None:
                setattr(enricher, "_blocked_error", None)
            repeated = attempt(target, enricher, retry=True)
            state = repeated.get("source_status", {}).get(name, {})
            if (state.get("status") not in {"hit", "no_record"}
                    and state.get("error_type") != "dns_resolution_failed"):
                stopped[name] = str(state.get("error_type") or "recovery_failed")
    return records
