"""Runs inside a prepared, network-disabled container. Never runs APK code."""

from pathlib import Path
import resource
import subprocess
import time


def main():
    getattr(resource, "setrlimit")(getattr(resource, "RLIMIT_FSIZE"), (128 * 1024 * 1024, 128 * 1024 * 1024))
    proc = subprocess.Popen(["/tool/blutter", "-i", "/input/libapp.so", "-o", "/output/raw"])
    exceeded = False
    try:
        while proc.poll() is None:
            size = count = 0
            for path in Path("/output").rglob("*"):
                if path.is_file():
                    size += path.stat().st_size
                    count += 1
            if size > 480 * 1024 * 1024 or count > 19000:
                exceeded = True
                proc.kill()
                break
            time.sleep(0.25)
    finally:
        if proc.poll() is None:
            proc.kill()
        code = proc.wait()
    raise SystemExit(75 if exceeded else code)


if __name__ == "__main__":
    main()
