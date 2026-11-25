"""Safe file-read failure ledger shared by serial and snapshot contexts."""

from __future__ import annotations

from collections.abc import Mapping

FILE_READ_FAILURE_REASONS = frozenset({
    "declared_limit",
    "actual_decompression_limit",
    "decompression_budget",
    "read_failure",
    "unavailable_context",
    "parser_timeout",
    "parser_output_limit",
    "parser_memory_limit_unavailable",
    "parser_worker_failed",
    "parser_invalid_response",
    "parser_input_changed",
    "parser_memory_limit",
})


_WORKER_DIAGNOSTICS = frozenset({
    "worker_tree_unverified",
    "worker_tree_forced_cleanup",
    "worker_nonzero_exit",
    "multiple_worker_failures",
})


def worker_diagnostic(reason: str, value: object) -> str | None:
    if reason == "parser_worker_failed" and isinstance(value, str) and value in _WORKER_DIAGNOSTICS:
        return value
    return None


def merge_worker_diagnostics(previous: str | None, current: str | None) -> str | None:
    if previous and current and previous != current:
        return "multiple_worker_failures"
    return previous or current


def normalize_gap(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    path, source, reason = value.get("path"), value.get("source"), value.get("reason")
    if not (
        isinstance(path, str)
        and isinstance(source, str)
        and isinstance(reason, str)
        and reason in FILE_READ_FAILURE_REASONS
    ):
        return None
    item = {"path": path, "source": source, "reason": reason}
    detail = worker_diagnostic(reason, value.get("diagnostic"))
    if detail is not None:
        item["diagnostic"] = detail
    return item


class FileReadLedger:
    def __init__(self, failures: Mapping[str, str] | None = None) -> None:
        self._failures = {
            path: reason
            for path, reason in (failures or {}).items()
            if isinstance(path, str) and isinstance(reason, str)
            and reason in FILE_READ_FAILURE_REASONS
        }
        self._requested: set[str] | None = None
        self._scope_failures: dict[str, tuple[str, str | None]] = {}

    @property
    def failure_reasons(self) -> dict[str, str]:
        return dict(self._failures)

    def failure_for(self, path: str) -> str | None:
        return self._failures.get(path)

    def record_failure(self, path: str, reason: str, *, diagnostic: str | None = None) -> None:
        if not isinstance(path, str):
            return
        safe_reason = (
            reason if reason in FILE_READ_FAILURE_REASONS else "read_failure"
        )
        self._failures[path] = safe_reason
        if self._requested is not None and path in self._requested:
            detail = worker_diagnostic(safe_reason, diagnostic)
            previous_reason, previous_detail = self._scope_failures.get(path, ("", None))
            if previous_reason == safe_reason:
                detail = merge_worker_diagnostics(previous_detail, detail)
            self._scope_failures[path] = safe_reason, detail

    def begin_scope(self) -> None:
        self._requested = set()
        self._scope_failures = {}

    def request(self, path: str) -> None:
        if self._requested is not None and isinstance(path, str):
            self._requested.add(path)

    def end_scope(self, source: str) -> list[dict[str, str]]:
        requested = self._requested or set()
        gaps: list[dict[str, str]] = []
        for path, (reason, detail) in self._scope_failures.items():
            if path in requested:
                gap = {"path": path, "source": source, "reason": reason}
                if detail is not None:
                    gap["diagnostic"] = detail
                gaps.append(gap)
        self._requested = None
        self._scope_failures = {}
        return sorted(gaps, key=lambda gap: (gap["path"], gap["source"], gap["reason"]))
