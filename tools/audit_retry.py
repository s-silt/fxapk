"""Bounded adapter for the existing PyPI-backed audit. No fallback or ignore rules."""
from __future__ import annotations
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable

_PYPI_READ_TIMEOUT = re.compile(
    r"requests\.exceptions\.ReadTimeout: "
    r"HTTPSConnectionPool\(host='pypi\.org', port=443\): Read timed out\. "
    r"\(read timeout=\d+(?:\.\d+)?\)"
)


@dataclass(frozen=True)
class Outcome:
    reason: str
    code: int
    attempts: int


def is_pypi_read_timeout(result: subprocess.CompletedProcess[str]) -> bool:
    """Recognize only the observed pip-audit failure, fail closed otherwise."""
    if result.returncode != 1 or result.stdout.strip():
        return False
    lines = result.stderr.strip().splitlines()
    if not lines or any(re.search(r"(?:Found \d+ known vulnerabilit|No known vulnerabilities found)", line)
                        for line in lines):
        return False
    return (
        any("Traceback (most recent call last):" == x for x in lines)
        and any("pip_audit/_service/pypi.py" in x.replace("\\", "/") for x in lines)
        and bool(_PYPI_READ_TIMEOUT.fullmatch(lines[-1]))
    )


def audit(
    site: str,
    *,
    invoke: Callable[[list[str], float], subprocess.CompletedProcess[str]],
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    log: Callable[[str], None],
    emit: Callable[[str, str], None],
) -> Outcome:
    """Run one audit plus at most one retry, within a 180-second wall budget."""
    deadline = clock() + 180
    command = [sys.executable, "-m", "pip_audit", "--path", site, "--timeout", "30"]
    for attempt in (1, 2):
        remaining = deadline - clock()
        if remaining <= 0:
            return Outcome("AUDIT_BUDGET_EXHAUSTED", 1, attempt - 1)
        try:
            result = invoke(command, remaining)
        except subprocess.TimeoutExpired:
            return Outcome("AUDIT_BUDGET_EXHAUSTED", 1, attempt)
        except OSError:
            return Outcome("AUDIT_START_FAILED", 1, attempt)
        if result.returncode == 0:
            emit(result.stdout, result.stderr)
            return Outcome("AUDIT_COMPLETED", 0, attempt)
        if not is_pypi_read_timeout(result):
            emit(result.stdout, result.stderr)
            return Outcome("AUDIT_FAILED", max(1, result.returncode), attempt)
        log(f"AUDIT_PYPI_READ_TIMEOUT: attempt {attempt} of 2")
        if attempt == 2:
            emit(result.stdout, result.stderr)
            return Outcome("AUDIT_PYPI_READ_TIMEOUT", 1, attempt)
        if deadline - clock() <= 2:
            return Outcome("AUDIT_BUDGET_EXHAUSTED", 1, attempt)
        sleep(2)
    raise RuntimeError("unreachable")


def main(site: str) -> int:
    def invoke(argv: list[str], seconds: float) -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, text=True, capture_output=True, timeout=seconds, check=False)
    def emit(stdout: str, stderr: str) -> None:
        print(stdout, end="", file=sys.stdout)
        print(stderr, end="", file=sys.stderr)
    outcome = audit(site, invoke=invoke, clock=time.monotonic, sleep=time.sleep,
                    log=lambda msg: print(msg, file=sys.stderr), emit=emit)
    print(outcome.reason, file=sys.stderr)
    return outcome.code


if __name__ == "__main__":
    from pathlib import Path
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_dir():
        print("AUDIT_SITE_INVALID", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(main(sys.argv[1]))
