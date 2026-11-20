"""Opt-in diagnostics for synthetic tests; never serialize arbitrary runtime data."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import json
import logging
import sys
from threading import get_ident

_TESTS = frozenset({"ownership_access", "recovery_reanalysis", "diagnostic_contract", "ownership_descendants", "recovery_vectors", "recovery_unicorn"})
_STAGES = frozenset({"ownership_read", "reanalyze", "cleanup", "termination_check", "validation_result", "positive_result", "negative_result"})
_REASONS = frozenset({
    "descendants_after_root_exit", "distinct_validation_inputs_required",
    "tree_state_unverified", "subprocess_timeout", "reanalyzed_extra_dex_not_loaded",
    "reanalyzed_report_partial", "reanalyzed_report_failed",
    "review_worker_timeout", "review_worker_exit", "review_worker_process_tree_incomplete",
    "review_worker_receipt_missing", "review_worker_receipt_invalid", "review_worker_failed",
    "optional_dependency_unavailable", "platform_memory_limit_unavailable",
    "emulation_fault", "emulation_budget_exhausted", "emulation_output_mismatch",
})


def _label(value: object, allowed: frozenset[str]) -> str:
    # Exact primitives only: no repr/str calls on exception objects or payloads.
    return value if type(value) is str and value in allowed else "unknown"


_POSIX_VERIFICATION_STAGES = frozenset({"ownership_scan", "individual_signal"})


@contextmanager
def observe_posix_verification_stage() -> Iterator[Callable[[], str]]:
    """Read the first existing allowlisted DEBUG stage during one test call."""
    logger = logging.getLogger("fxapk.core.proctree")
    level, effective_level = logger.level, logger.getEffectiveLevel()
    caller = get_ident()
    observed = "unknown"

    def collect(record: logging.LogRecord) -> bool:
        nonlocal observed
        if (
            observed == "unknown" and record.thread == caller and record.name == logger.name
            and record.levelno == logging.DEBUG and type(record.msg) is str
            and record.msg == "POSIX tree verification unavailable: stage=%s"
            and type(record.args) is tuple and len(record.args) == 1
        ):
            observed = _label(record.args[0], _POSIX_VERIFICATION_STAGES)
        # Newly enabled DEBUG records remain invisible to existing handlers.
        return record.levelno >= effective_level

    logger.addFilter(collect)
    logger.setLevel(min(logging.DEBUG, effective_level))
    try:
        yield lambda: observed
    finally:
        logger.setLevel(level)
        logger.removeFilter(collect)


def emit_posix_verification_stage(observed: str) -> None:
    stage = _label(observed, _POSIX_VERIFICATION_STAGES)
    print(f"observed-posix-tree-verification-stage: {stage}", file=sys.stderr)


class FirstFailureDiagnostic:
    """Freeze the first observation and emit it only on assertion failure.

    This is not a verdict: an unverified tree does not establish permission
    denial or process absence. Callers supply a read error only at an observed,
    controlled exception site. No exception text, process identifiers or paths.
    """

    def __init__(self, test: object, worker: object = "unknown") -> None:
        self._test = _label(test, _TESTS)
        self._worker = _label(worker, frozenset({"master", *(f"gw{i}" for i in range(256))}))
        self._first: dict[str, object] | None = None

    def observe(self, *, stage: object, ownership: object = None,
                read_error: object = None, reasons: object = None) -> None:
        if self._first is not None:
            return
        safe_reasons = ["unknown"]
        if type(reasons) is tuple or type(reasons) is list:
            safe_reasons = sorted({_label(reason, _REASONS) for reason in reasons[:8]})
        self._first = {
            "stage": _label(stage, _STAGES),
            "ownership": "confirmed" if ownership is True else "false" if ownership is False else "unknown",
            "read_error": _label(read_error, frozenset({"AccessDenied", "PermissionError"})),
            "reasons": safe_reasons,
        }

    def __enter__(self) -> FirstFailureDiagnostic:
        return self

    def __exit__(self, kind, value, traceback) -> bool:
        if kind is not None and issubclass(kind, AssertionError):
            snapshot = self._first or {
                "stage": "unknown", "ownership": "unknown", "read_error": "unknown", "reasons": ["unknown"],
            }
            print("first-failure: " + json.dumps({"test": self._test, "worker": self._worker, **snapshot},
                                               sort_keys=True), file=sys.stderr)
        return False
