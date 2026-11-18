import subprocess
import unittest

from tools import audit_retry as layer

LINE = ("requests.exceptions.ReadTimeout: HTTPSConnectionPool(host='pypi.org', port=443): "
        "Read timed out. (read timeout=30)")
TRACE = "Traceback (most recent call last):\n  File \"pip_audit/_service/pypi.py\"\n" + LINE + "\n"


def cp(code, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class Policy(unittest.TestCase):
    def run_case(self, results, expected, delays=None):
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

        def wait(d):
            now[0] += d

        got = layer.audit("/synthetic", invoke=do, clock=lambda: now[0], sleep=wait,
                          log=events.append, emit=lambda a,b:output.append((a,b)))
        self.assertEqual((got.reason, got.code, got.attempts), expected)
        self.assertEqual(len(observed), expected[2])
        for cmd, _ in observed:
            self.assertEqual(cmd[-4:], ["--path", "/synthetic", "--timeout", "30"])
        self.assertEqual(len(observed), len(results))
        return observed, events, output

    def test_normal(self):
        self.run_case([cp(0, stderr="No known vulnerabilities found")],
                      ("AUDIT_COMPLETED", 0, 1))

    def test_network_recovers(self):
        got, diag, out = self.run_case([cp(1, stderr=TRACE), cp(0)],
                                       ("AUDIT_COMPLETED", 0, 2), [30, 1])
        self.assertEqual([x[1] for x in got], [180, 148])
        self.assertEqual(diag, ["AUDIT_PYPI_READ_TIMEOUT: attempt 1 of 2"])
        self.assertEqual(len(out), 1)

    def test_two_timeouts_still_red(self):
        self.run_case([cp(1, stderr=TRACE), cp(1, stderr=TRACE)],
                      ("AUDIT_PYPI_READ_TIMEOUT", 1, 2))

    def test_finding_still_red_without_retry(self):
        self.run_case([cp(1, stdout="example-package", stderr="Found 1 known vulnerability")],
                      ("AUDIT_FAILED", 1, 1))

    def test_finding_after_network_recovery_stays_red(self):
        self.run_case([cp(1, stderr=TRACE), cp(1, stdout="example-package")],
                      ("AUDIT_FAILED", 1, 2))

    def test_generic_network_text_never_enough(self):
        for stderr in (LINE, TRACE.replace("pypi.org","example.invalid"),
                       TRACE.replace("ReadTimeout","SSLError"), "usage: pip-audit"):
            with self.subTest(stderr=stderr):
                self.run_case([cp(1, stderr=stderr)], ("AUDIT_FAILED", 1, 1))

    def test_partial_output_never_treated_as_timeout(self):
        self.run_case([cp(1, stdout="partial output", stderr=TRACE)],
                      ("AUDIT_FAILED", 1, 1))

    def test_exhausted_budget(self):
        self.run_case([cp(1, stderr=TRACE)], ("AUDIT_BUDGET_EXHAUSTED", 1, 1), [179])
        self.run_case([subprocess.TimeoutExpired(["synthetic"], 180)],
                      ("AUDIT_BUDGET_EXHAUSTED", 1, 1))

    def test_start_error(self):
        self.run_case([OSError("synthetic unavailable")], ("AUDIT_START_FAILED", 1, 1))


if __name__ == "__main__":
    unittest.main()
