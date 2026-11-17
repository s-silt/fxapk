"""Last observed harness marker, not a timeout cause or process-exit diagnosis."""
from __future__ import annotations

import subprocess

import pytest

STAGES = ("node_entry", "before_evaluation", "after_evaluation", "assertions_complete")
PREFIX = "fxapk-test-node-stage:"


def last_observed_stage(stderr: bytes | str | None) -> str:
    """Accept only complete LF/CRLF lines from the dedicated stderr stream.

    Missing/partial capture proves no stage. Ordering is capture order, not
    the highest stage name. Unrecognized data is never formatted or returned.
    """
    if type(stderr) is bytes:
        lines = stderr.split(b"\n")[:-1]
        allowed = {(PREFIX + stage).encode("ascii"): stage for stage in STAGES}
        return next((allowed[line.removesuffix(b"\r")] for line in reversed(lines)
                     if line.removesuffix(b"\r") in allowed), "not_observed")
    if type(stderr) is str:
        text_lines = stderr.split("\n")[:-1]
        text_allowed = {PREFIX + stage: stage for stage in STAGES}
        return next((text_allowed[line.removesuffix("\r")] for line in reversed(text_lines)
                     if line.removesuffix("\r") in text_allowed), "not_observed")
    return "not_observed"


def run_node_harness(node: str, program: str) -> subprocess.CompletedProcess[str]:
    """Keep the existing invocation/10s budget; replace only timeout rendering."""
    try:
        return subprocess.run([node], input=program, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired as error:
        stage = last_observed_stage(error.stderr)
    # Outside the except block: no raw TimeoutExpired context, cmd or streams.
    pytest.fail("node-harness-timeout: reason=subprocess_timeout "
                f"last_observed_stage={stage} failure_cause=unknown", pytrace=False)
