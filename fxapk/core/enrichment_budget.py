"""One-run, thread-safe admission budget shared across target expansion.

Counts adapter invocations, not HTTP subrequests, credits, money or daily account
usage. Failure consumes admission too; there is no refund or automatic retry.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from threading import Lock
from typing import Any


class EnrichmentBudget:
    def __init__(self, *, total: int | None = None, providers: Mapping[str, int] | None = None):
        self._limits = dict(providers or {})
        for name, limit in self._limits.items():
            if not isinstance(name, str) or not name or type(limit) is not int or limit < 0:
                raise ValueError("invalid_provider_budget")
        if total is not None and (type(total) is not int or total < 0):
            raise ValueError("invalid_total_source_budget")
        self._total = total
        self._used: Counter[str] = Counter()
        self._denied: Counter[str] = Counter()
        self._count = 0
        self._lock = Lock()

    def admit(self, provider: str) -> bool:
        with self._lock:
            limit = self._limits.get(provider)
            if ((self._total is not None and self._count >= self._total) or
                    (limit is not None and self._used[provider] >= limit)):
                self._denied[provider] += 1
                return False
            self._used[provider] += 1
            self._count += 1
            return True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"scope": "one_closure_run_including_resolved_ips",
                    "unit": "adapter_invocations", "total_limit": self._total,
                    "provider_limits": dict(sorted(self._limits.items())),
                    "admitted": self._count, "by_provider": dict(sorted(self._used.items())),
                    "denied_by_provider": dict(sorted(self._denied.items())),
                    "account_credit_budget_enforced": False}
