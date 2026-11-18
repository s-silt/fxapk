import subprocess

import pytest

from tools import audit_retry as layer

LINE = ("requests.exceptions.ReadTimeout: HTTPSConnectionPool(host='pypi.org', port=443): "
        "Read timed out. (read timeout=30)")
TRACE = "Traceback (most recent call last):\n  File \"pip_audit/_service/pypi.py\"\n" + LINE + "\n"


def cp(code, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def run_case(results, expected, delays=None):
    now = [0.]
    observed = []
    events = []
    output = []
    schedule = iter(zip(results, delays or [0.] * len(results)))

    def do(argv, budget):
        observed.append((argv, budget))
        result, used = next(schedule)
        now[0] += used
        if isinstance(result, Exception):
            raise result
        return result

    def wait(delay):
        now[0] += delay

    got = layer.audit("/synthetic", invoke=do, clock=lambda: now[0], sleep=wait,
                      log=events.append, emit=lambda a, b: output.append((a, b)))
    assert (got.reason, got.code, got.attempts) == expected
    assert len(observed) == len(results) == expected[2]
    assert all(cmd[-4:] == ["--path", "/synthetic", "--timeout", "30"] for cmd, _ in observed)
    return observed, events, output


@pytest.mark.parametrize(("results", "expected"), [
    ([cp(0, stderr="No known vulnerabilities found")], ("AUDIT_COMPLETED", 0, 1)),
    ([cp(1, stderr=TRACE), cp(1, stderr=TRACE)], ("AUDIT_PYPI_READ_TIMEOUT", 1, 2)),
    ([cp(1, stdout="example-package", stderr="Found 1 known vulnerability")], ("AUDIT_FAILED", 1, 1)),
    ([cp(1, stderr=TRACE), cp(1, stdout="example-package")], ("AUDIT_FAILED", 1, 2)),
    ([cp(1, stdout="partial output", stderr=TRACE)], ("AUDIT_FAILED", 1, 1)),
    ([OSError("synthetic unavailable")], ("AUDIT_START_FAILED", 1, 1)),
])
def test_result_policy(results, expected):
    run_case(results, expected)


def test_network_recovers():
    got, diag, out = run_case([cp(1, stderr=TRACE), cp(0)], ("AUDIT_COMPLETED", 0, 2), [30, 1])
    assert [x[1] for x in got] == [180, 148]
    assert diag == ["AUDIT_PYPI_READ_TIMEOUT: attempt 1 of 2"]
    assert len(out) == 1


@pytest.mark.parametrize("stderr", [
    LINE, TRACE.replace("pypi.org", "example.invalid"), TRACE.replace("ReadTimeout", "SSLError"),
    "usage: pip-audit",
])
def test_generic_network_text_never_enough(stderr):
    run_case([cp(1, stderr=stderr)], ("AUDIT_FAILED", 1, 1))


def test_exhausted_budget_before_retry():
    _, _, output = run_case(
        [cp(1, stderr="too old " + "a" * 9000 + "\n" + TRACE)],
        ("AUDIT_BUDGET_EXHAUSTED", 1, 1), [179],
    )
    assert len(output) == 1
    stdout, stderr = output[0]
    assert stdout == ""
    assert "too old" not in stderr
    assert stderr.endswith("  " + LINE + "\n")


def test_process_timeout_preserves_bounded_pending_output_and_fails():
    _, _, out = run_case([subprocess.TimeoutExpired(
        ["synthetic"], 180, output=b"old marker " + b"a" * 9000 + b"\nlast chunk\n",
        stderr=b"warning: incomplete \xff\n",
    )], ("AUDIT_BUDGET_EXHAUSTED", 1, 1))
    assert len(out) == 1
    stdout, stderr = out[0]
    assert "old marker" not in stdout
    assert stdout.endswith("  last chunk\n")
    assert stderr == "  warning: incomplete \ufffd\n"


def test_process_timeout_without_output_stays_red():
    _, _, out = run_case([subprocess.TimeoutExpired(["synthetic"], 180)],
                         ("AUDIT_BUDGET_EXHAUSTED", 1, 1))
    assert out == [("", "")]
