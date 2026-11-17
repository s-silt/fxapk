"""Opt-in diagnostics for synthetic tests; never serialize arbitrary runtime data."""
from __future__ import annotations

import json
import sys

_TESTS = frozenset({"ownership_access", "recovery_reanalysis", "diagnostic_contract", "ownership_descendants", "recovery_vectors"})
_STAGES = frozenset({"ownership_read", "reanalyze", "cleanup", "termination_check", "validation_result"})
_REASONS = frozenset({
    "descendants_after_root_exit", "distinct_validation_inputs_required",
    "tree_state_unverified", "subprocess_timeout", "reanalyzed_extra_dex_not_loaded",
    "reanalyzed_report_partial", "reanalyzed_report_failed",
})


def _label(value: object, allowed: frozenset[str]) -> str:
    # Exact primitives only: no repr/str calls on exception objects or payloads.
    return value if type(value) is str and value in allowed else "unknown"


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
