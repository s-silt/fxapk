"""Safe file-read failure ledger shared by serial and snapshot contexts."""

from __future__ import annotations

from collections.abc import Mapping

FILE_READ_FAILURE_REASONS = frozenset({
    "declared_limit",
    "actual_decompression_limit",
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


class FileReadLedger:
    def __init__(self, failures: Mapping[str, str] | None = None) -> None:
        self._failures = {
            path: reason
            for path, reason in (failures or {}).items()
            if isinstance(path, str) and isinstance(reason, str)
            and reason in FILE_READ_FAILURE_REASONS
        }
        self._requested: set[str] | None = None
        self._scope_failures: dict[str, str] = {}

    @property
    def failure_reasons(self) -> dict[str, str]:
        return dict(self._failures)

    def failure_for(self, path: str) -> str | None:
        return self._failures.get(path)

    def record_failure(self, path: str, reason: str) -> None:
        if not isinstance(path, str):
            return
        safe_reason = (
            reason if reason in FILE_READ_FAILURE_REASONS else "read_failure"
        )
        self._failures[path] = safe_reason
        if self._requested is not None and path in self._requested:
            self._scope_failures[path] = safe_reason

    def begin_scope(self) -> None:
        self._requested = set()
        self._scope_failures = {}

    def request(self, path: str) -> None:
        if self._requested is not None and isinstance(path, str):
            self._requested.add(path)

    def end_scope(self, source: str) -> list[dict[str, str]]:
        requested = self._requested or set()
        gaps = [
            {"path": path, "source": source, "reason": self._scope_failures[path]}
            for path in requested
            if path in self._scope_failures
        ]
        self._requested = None
        self._scope_failures = {}
        return sorted(gaps, key=lambda gap: (gap["path"], gap["source"], gap["reason"]))
