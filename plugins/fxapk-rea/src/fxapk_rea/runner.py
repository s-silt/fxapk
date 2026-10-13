"""Private streaming child, always launched inside core run_owned's process tree."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import BinaryIO


def main() -> None:
    out, limit, argv = Path(sys.argv[1]), int(sys.argv[2]), json.loads(sys.argv[3])
    child_env = None
    if len(sys.argv) > 4:
        overlay = json.loads(sys.argv[4])
        if isinstance(overlay, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in overlay.items()):
            child_env = os.environ.copy()
            child_env.update(overlay)
    stop = threading.Event()
    streams: dict[str, dict] = {}
    errors: list[str] = []

    def drain(pipe: BinaryIO, name: str, budget: int) -> None:
        size, truncated, sha = 0, False, hashlib.sha256()
        try:
            fd = os.open(
                out / f"{name}.bin",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(fd, "wb", buffering=0) as target:
                while block := pipe.read1(65536):  # type: ignore[attr-defined]
                    retained = block[: max(0, budget - size)]
                    target.write(retained)
                    sha.update(retained)
                    size += len(retained)
                    if len(retained) < len(block):
                        truncated = True
                        stop.set()
                        break
        except OSError:
            errors.append("stream_capture_failed")
            stop.set()
        finally:
            streams[name] = {"size": size, "sha256": sha.hexdigest(), "truncated": truncated}

    try:
        child = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            env=child_env,
        )
    except OSError:
        print(json.dumps({"exit_code": None, "streams": {}, "errors": ["tool_spawn_failed"]}))
        return
    assert child.stdout is not None and child.stderr is not None
    threads = [
        threading.Thread(target=drain, args=(child.stdout, "stdout", limit), daemon=True),
        threading.Thread(target=drain, args=(child.stderr, "stderr", 65536), daemon=True),
    ]
    for thread in threads:
        thread.start()
    while child.poll() is None and not stop.wait(0.02):
        pass
    if child.poll() is None:
        child.kill()
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        errors.append("child_wait_failed")
    for thread in threads:
        thread.join(timeout=1)
    if any(thread.is_alive() for thread in threads):
        errors.append("pipe_not_closed")
    print(json.dumps({"exit_code": child.returncode, "streams": streams, "errors": errors}))


if __name__ == "__main__":
    main()
