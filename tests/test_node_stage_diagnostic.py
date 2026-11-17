"""No observer execution: captured buffers, mocked launch, and benign Node only."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

from tests import node_stage_diagnostic as diagnostic


@pytest.mark.parametrize("buffer,expected", [
    (None, "not_observed"), (b"", "not_observed"), ("", "not_observed"),
    ("private noise\n", "not_observed"),
    ("fxapk-test-node-stage:node_entry", "not_observed"),
    (b"fxapk-test-node-stage:node_entry\n", "node_entry"),
    ("fxapk-test-node-stage:before_evaluation\r\n", "before_evaluation"),
    (b"\xff\nfxapk-test-node-stage:after_evaluation\nprivate noise\n", "after_evaluation"),
    ("fxapk-test-node-stage:assertions_complete\nfxapk-test-node-stage:node_entry\n", "node_entry"),
    (" fxapk-test-node-stage:node_entry\n", "not_observed"),
    ("fxapk-test-node-stage:node_entry suffix\n", "not_observed"),
    ("console.log('fxapk-test-node-stage:node_entry');\n", "not_observed"),
    ("fxapk-test-node-stage:unknown\n", "not_observed"),
    ("fxapk-test-node-stage:node_entry\nfxapk-test-node-stage:after_evaluation", "node_entry"),
    ("noise\rfxapk-test-node-stage:node_entry\n", "not_observed"),
])
def test_last_complete_allowlisted_line(buffer, expected):
    assert diagnostic.last_observed_stage(buffer) == expected


@pytest.mark.parametrize("stage", diagnostic.STAGES)
@pytest.mark.parametrize("binary", [False, True])
def test_each_stage_in_both_capture_types(stage, binary):
    captured = diagnostic.PREFIX + stage + "\n"
    assert diagnostic.last_observed_stage(captured.encode() if binary else captured) == stage


def test_unsupported_capture_is_not_stringified():
    class Unexpected:
        def __str__(self):
            raise AssertionError("must not stringify capture")
    assert diagnostic.last_observed_stage(Unexpected()) == "not_observed"


@pytest.mark.parametrize("captured", [None, "noise\n", b"fxapk-test-node-stage:before_evaluation\n"])
def test_timeout_keeps_budget_and_exposes_only_observed_stage(monkeypatch, captured):
    calls = []
    error = subprocess.TimeoutExpired("PRIVATE_COMMAND", 10,
                                     output="fxapk-test-node-stage:assertions_complete\nPRIVATE_STDOUT",
                                     stderr=captured)

    def timeout(*args, **kwargs):
        calls.append((args, kwargs))
        raise error

    monkeypatch.setattr(diagnostic.subprocess, "run", timeout)
    # Old call exposes the TimeoutExpired command and has no stage diagnostic.
    with pytest.raises(subprocess.TimeoutExpired) as old:
        subprocess.run(["synthetic-node"], input="PRIVATE_SCRIPT", capture_output=True, text=True, timeout=10)
    assert "PRIVATE_COMMAND" in str(old.value)
    assert "last_observed_stage" not in str(old.value)
    with pytest.raises(pytest.fail.Exception) as new:
        diagnostic.run_node_harness("synthetic-node", "PRIVATE_SCRIPT")
    expected = "before_evaluation" if captured == b"fxapk-test-node-stage:before_evaluation\n" else "not_observed"
    assert str(new.value) == ("node-harness-timeout: reason=subprocess_timeout "
                              f"last_observed_stage={expected} failure_cause=unknown")
    assert new.value.__context__ is None
    assert new.value.pytrace is False
    assert calls[0] == calls[1]


def test_normal_and_nonzero_results_are_unchanged(monkeypatch):
    for code in (0, 1):
        result = subprocess.CompletedProcess(["synthetic-node"], code, "unchanged", "unchanged")
        monkeypatch.setattr(diagnostic.subprocess, "run", lambda *args, **kwargs: result)
        assert diagnostic.run_node_harness("synthetic-node", "synthetic") is result


def test_real_harness_wires_markers_without_running_observer(monkeypatch):
    from tests import test_config_body_coverage as harness

    monkeypatch.setattr(harness.shutil, "which", lambda name: "synthetic-node")
    monkeypatch.setattr(Path, "read_text", lambda *args, **kwargs: "")
    programs = []

    def fake_run(node, program):
        programs.append(program)
        return subprocess.CompletedProcess([node], 0, "", "")

    monkeypatch.setattr(harness, "run_node_harness", fake_run)
    harness.test_response_observer_compatibility_and_truthful_coverage("kotlin", "installed")
    program = programs[0]
    markers = [f"require('fs').writeSync(2, '{diagnostic.PREFIX}{stage}\\n');" for stage in diagnostic.STAGES]
    assert all(program.count(marker) == 1 for marker in markers)
    positions = [program.index(marker) for marker in markers]
    assert positions == sorted(positions)
    assert positions[0] < program.index("const vm=")
    assert positions[1] < program.index("vm.runInContext(") < positions[2]
    assert positions[2] < program.rindex("assert.strictEqual(") < positions[3]


def test_benign_node_arithmetic_output():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js unavailable")
    result = diagnostic.run_node_harness(node, "process.stdout.write(String(2 + 3));")
    assert (result.returncode, result.stdout, result.stderr) == (0, "5", "")
