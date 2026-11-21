"""An outer stop must not hide a known cleanup failure or accept late success."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from textwrap import dedent
from typing import Any, BinaryIO

import pytest

from tools import local_candidate_commit as dispatcher


@pytest.mark.parametrize(("trigger", "record", "rc", "expected_exit"), [
    ("interrupted", "unverified", 2, 130),
    ("timeout", "unverified", 2, 125),
    ("interrupted", "wrong_work", 2, 130),
    ("timeout", "setup_error", 2, 125),
    ("interrupted", "empty", 2, 130),
    ("timeout", "extra_output", 2, 125),
    ("interrupted", "not_a_boolean", 2, 130),
    ("timeout", "success", 0, 125),
    ("interrupted", "unverified", 130, 130),
])
def test_outer_stop_after_supervisor_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    trigger: str, record: str, rc: int, expected_exit: int,
) -> None:
    body: dict[str, object] = {
        "schema": "fxapk.local-candidate.v1", "accepted": False, "phase": "worker",
        "reason": "cleanup_unverified", "process_group_empty": False, "quarantine": str(tmp_path),
    }
    if record == "wrong_work":
        body["quarantine"] = str(tmp_path / "different-job")
    elif record == "setup_error":
        body.update(phase="setup", reason="unable_to_start_worker")
        del body["process_group_empty"]
    elif record == "not_a_boolean":
        body["process_group_empty"] = 0
    elif record == "success":
        body = {"schema": "fxapk.local-candidate.v1", "accepted": True, "commit": "a" * 40}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if record == "empty":
        raw = b""
    elif record == "extra_output":
        raw += b"x" * 65536

    if record == "unverified" and rc == 2:
        # Stub only the cleanup observation; exercise supervise -> internal -> real stdout.
        script = dedent(f"""\
            import runpy
            from pathlib import Path
            module = runpy.run_path({str(Path(dispatcher.__file__).resolve())!r})
            namespace = module["internal"].__globals__
            namespace["__file__"] = __file__
            namespace["bounded"] = lambda *_: namespace["stopped_worker"]("interrupted", False)
            raise SystemExit(namespace["internal"]())
        """).encode()
    else:
        script = (
            b"import sys\nfrom pathlib import Path\nsys.stdout.buffer.write(Path(sys.argv[6]).read_bytes())\n"
            b"raise SystemExit(int(sys.argv[7]))\n"
        )
    if sys.platform == "win32":
        # Match the Linux supervisor's LF stdout without passing a POSIX ledger fd.
        script = b"import sys\nsys.stdout.reconfigure(newline='\\n')\n" + script
        popen = subprocess.Popen

        def spawn(command: list[str], *, stdout: BinaryIO, cwd: Path, **_: Any) -> subprocess.Popen[bytes]:
            return popen(command, cwd=cwd, stdout=stdout, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        monkeypatch.setattr(dispatcher.subprocess, "Popen", spawn)
    scripts = {Path(dispatcher.__file__).name: script}

    def stop_at_exit(proc: subprocess.Popen[bytes], *_: object) -> str:
        assert proc.wait(timeout=10) == rc
        return trigger

    monkeypatch.setattr(dispatcher, "wait_child", stop_at_exit)
    args = argparse.Namespace(source=tmp_path, base="b" * 40, tree="c" * 40, message=str(rc), timeout=1, deadline=2)
    with open(os.devnull, "rb") as lock:
        state, failure = dispatcher.launch(args, tmp_path, raw, scripts, lock.fileno())

    assert dispatcher.EXIT[state] == expected_exit
    if record == "unverified" and rc == 2:
        assert failure == {
            "phase": "worker", "reason": "cleanup_unverified", "process_group_empty": False, "supervisor_exit": 2,
        }
    else:
        assert failure == {"reason": "supervisor_exit_observed", "supervisor_exit": rc}
