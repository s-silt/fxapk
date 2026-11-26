"""Opt-in diagnostics for synthetic tests; never serialize arbitrary runtime data."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import json
import logging
import sys
from threading import get_ident

_TESTS = frozenset({"ownership_access", "recovery_reanalysis", "diagnostic_contract", "ownership_descendants", "recovery_vectors", "recovery_unicorn", "rea_runtime_timeout"})
_STAGES = frozenset({"ownership_read", "reanalyze", "cleanup", "termination_check", "validation_result", "positive_result", "negative_result"})
_REASONS = frozenset({
    "descendants_after_root_exit", "distinct_validation_inputs_required",
    "tree_state_unverified", "survivors_after_kill", "process_exit_unverified", "timeout",
    "subprocess_timeout", "reanalyzed_extra_dex_not_loaded",
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
_POSIX_PROBES = frozenset({"status", "getpgid", "uids", "environ"})
_READ_ERRORS = frozenset({"AccessDenied", "PermissionError"})
_STAGE_NOT_SUPPLIED = object()


def _posix_probe_details(probe: object, error: object) -> dict[str, str]:
    safe_probe = _label(probe, _POSIX_PROBES)
    safe_error = _label(error, _READ_ERRORS)
    if "unknown" in (safe_probe, safe_error):
        return {}
    return {"posix_probe": safe_probe, "posix_error": safe_error}


@contextmanager
def observe_posix_verification_stage(*, details: dict[str, str] | None = None) -> Iterator[Callable[[], str]]:
    """Read the first stage, optionally populating a fresh details dictionary."""
    logger = logging.getLogger("fxapk.core.proctree")
    level, effective_level = logger.level, logger.getEffectiveLevel()
    caller = get_ident()
    observed = "unknown"

    def collect(record: logging.LogRecord) -> bool:
        nonlocal observed
        if (
            observed == "unknown" and record.thread == caller and record.name == logger.name
            and type(record.msg) is str and type(record.args) is tuple
        ):
            legacy = record.levelno == logging.DEBUG
            warning = record.levelno == logging.WARNING
            plain = (legacy or warning) and (
                record.msg == "POSIX tree verification unavailable: stage=%s" and len(record.args) == 1
            )
            detailed_warning = warning and (
                record.msg == "POSIX tree verification unavailable: stage=%s probe=%s error=%s"
                and len(record.args) == 3
            )
            if plain or detailed_warning:
                observed = _label(record.args[0], _POSIX_VERIFICATION_STAGES)
                if observed == "ownership_scan" and details is not None:
                    if detailed_warning:
                        details.update(_posix_probe_details(record.args[1], record.args[2]))
                    elif legacy:
                        details.update(_posix_probe_details(
                            getattr(record, "posix_probe", None), getattr(record, "posix_error", None),
                        ))
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
                read_error: object = None, reasons: object = None,
                posix_verification_stage: object = _STAGE_NOT_SUPPLIED,
                posix_probe: object = None, posix_error: object = None) -> None:
        if self._first is not None:
            return
        safe_reasons = ["unknown"]
        if type(reasons) is tuple or type(reasons) is list:
            safe_reasons = sorted({_label(reason, _REASONS) for reason in reasons[:8]})
        self._first = {
            "stage": _label(stage, _STAGES),
            "ownership": "confirmed" if ownership is True else "false" if ownership is False else "unknown",
            "read_error": _label(read_error, _READ_ERRORS),
            "reasons": safe_reasons,
        }
        if posix_verification_stage is not _STAGE_NOT_SUPPLIED and "tree_state_unverified" in safe_reasons:
            posix_stage = _label(posix_verification_stage, _POSIX_VERIFICATION_STAGES)
            self._first["posix_verification_stage"] = posix_stage
            if posix_stage == "ownership_scan":
                self._first.update(_posix_probe_details(posix_probe, posix_error))

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
