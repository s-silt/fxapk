"""Windows 作业内存和 stdout 限额必须在进程结束前生效。"""

from __future__ import annotations

import sys

import pytest

from apkscan.core.proctree import run_owned

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="本机只验收 Windows 作业限额")


def test_job_memory_cap_stops_an_oversized_allocation() -> None:
    script = (
        "import sys\n"
        "print('START', flush=True)\n"
        "blob = bytearray(400 * 1024 * 1024)\n"
        "print('DONE', len(blob), flush=True)\n"
        "sys.stdout.flush()\n"
    )
    owned = run_owned(
        [sys.executable, "-c", script],
        timeout=20,
        memory_bytes=256 * 1024 * 1024,
        max_processes=4,
    )
    assert owned.memory_limit_enforced is True
    assert owned.process_limit_enforced is True
    assert "START" in owned.stdout
    assert "DONE" not in owned.stdout


def test_stdout_cap_kills_before_a_later_marker() -> None:
    script = (
        "import sys, time\n"
        "sys.stdout.buffer.write(b'A' * 200000)\n"
        "sys.stdout.buffer.flush()\n"
        "time.sleep(3)\n"
        "sys.stdout.buffer.write(b'MARKER\\n')\n"
        "sys.stdout.buffer.flush()\n"
    )
    owned = run_owned(
        [sys.executable, "-c", script],
        timeout=15,
        max_stdout_bytes=1000,
        max_stderr_bytes=1000,
    )
    assert "output_limit" in owned.reason_codes
    assert "MARKER" not in owned.stdout
    assert len(owned.stdout.encode("utf-8")) <= 1000
