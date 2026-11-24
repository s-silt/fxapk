"""Dispatch a trusted patch once into an isolated local Linux Git repository."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
from tempfile import mkdtemp, NamedTemporaryFile, TemporaryFile
import time
from typing import Any, BinaryIO, Iterator

SCHEMA = "fxapk.local-candidate.v1"
GATE = Path(__file__).with_name("fixed_jadx_gate.py")
GIT = ("git", "--no-replace-objects", "-c", "protocol.allow=never")
REF = "refs/heads/candidate"
PROTECTED = (".githooks/pre-commit", "tools/fixed_jadx_gate.py", "fxapk/cli.py", "fxapk/core/leakscan.py")
SHA = re.compile(r"[0-9a-f]{40}")
TASK_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}")
DIGEST = re.compile(r"[a-f0-9]{64}")
EXIT = {"succeeded": 0, "failed": 1, "worker_timeout": 124, "dispatcher_timeout": 125, "interrupted": 130}
CLEANUP_LIMIT = 3.0
PR_SET_CHILD_SUBREAPER = 36


class Rejected(RuntimeError):
    """A failed invariant or subprocess with a stable phase and diagnostic."""

    def __init__(self, phase: str, reason: str, step_exit: int | None = None) -> None:
        super().__init__(reason)
        self.phase = phase
        self.reason = reason
        self.step_exit = step_exit


def rejected(phase: str, reason: str, step_exit: int | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"accepted": False, "phase": phase, "reason": reason}
    if step_exit is not None:
        out["step_exit"] = step_exit
    return out


def child_env(work: Path) -> dict[str, str]:
    return {
        "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"),
        "PATH": f"{Path(sys.executable).parent}:/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "Local Candidate",
        "GIT_COMMITTER_NAME": "Local Candidate",
        "GIT_AUTHOR_EMAIL": "candidate@example.invalid",
        "GIT_COMMITTER_EMAIL": "candidate@example.invalid",
        "FXAPK_LEAK_SCAN_STRICT": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def become_subreaper() -> None:
    # Adopt orphaned descendants in this supervisor so the killed group can be reaped.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    return True


def reap_exited(pgid: int) -> None:
    while True:
        try:
            pid, _ = os.waitpid(-pgid, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def stop_group(proc: subprocess.Popen[bytes]) -> bool:
    deadline = time.monotonic() + CLEANUP_LIMIT
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        proc.poll()  # Leader already exited and its group no longer exists.
    try:
        proc.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        return False
    while True:
        reap_exited(proc.pid)
        if not group_exists(proc.pid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def stopped_worker(reason: str, clean: bool) -> tuple[int, dict[str, Any]]:
    status = (124 if reason == "timeout" else 130) if clean else 2
    return status, {
        **rejected("worker", reason if clean else "cleanup_unverified"),
        "process_group_empty": clean,
    }


def bounded(
    command: list[str], work: Path, seconds: float,
) -> tuple[int, dict[str, Any]]:
    """Run the worker in one group and discard output after a timeout or cancellation."""
    become_subreaper()
    stdout = work / "worker.stdout"
    # A normal stop must not unwind Popen, the handoff to wait, or group cleanup.
    with stop_flag() as requested:
        with stdout.open("xb") as output, (work / "worker.stderr").open("xb") as errors:
            if requested[0]:
                return stopped_worker("interrupted", clean=True)
            proc = subprocess.Popen(
                command, cwd=work, env=child_env(work), stdin=subprocess.DEVNULL,
                stdout=output, stderr=errors, start_new_session=True,
            )
            stop = wait_child(proc, time.monotonic() + seconds, requested)
            if stop is not None or requested[0]:
                try:
                    clean = False
                    if proc.returncode is not None:
                        reap_exited(proc.pid)
                        clean = not group_exists(proc.pid)
                    if not clean:
                        clean = stop_group(proc)
                except OSError:
                    clean = False
                return stopped_worker(stop or "interrupted", clean=clean)
            reap_exited(proc.pid)
            if group_exists(proc.pid):
                clean = stop_group(proc)
                return 2, {**rejected("worker", "leftover_processes"), "process_group_empty": clean}

        if requested[0]:
            return stopped_worker("interrupted", clean=True)
        receipt = read_worker_receipt(stdout, proc.returncode)
        return stopped_worker("interrupted", clean=True) if requested[0] else receipt


def read_worker_receipt(stdout: Path, rc: int | None) -> tuple[int, dict[str, Any]]:
    if stdout.stat().st_size > 65536:
        return 2, rejected("worker", "invalid_worker_receipt")
    try:
        result = json.loads(stdout.read_bytes())
    except (UnicodeError, ValueError):
        return 2, rejected("worker", "invalid_worker_receipt", rc)
    if isinstance(result, dict) and rc == 0 and result.get("accepted") is True:
        return 0, result
    if isinstance(result, dict) and rc == 1 and result.get("accepted") is False:
        return 1, rejected(str(result.get("phase")), str(result.get("reason")), result.get("step_exit"))
    return 2, rejected("worker", "invalid_worker_receipt", rc)


def validate_gate(output: bytes, head: str, tree: str) -> dict[str, Any]:
    contract = runpy.run_path(str(GATE))
    try:
        receipt = json.loads(output)
    except (UnicodeError, ValueError) as exc:
        raise Rejected("gate_receipt", "malformed_json") from exc
    if (
        not isinstance(receipt, dict)
        or set(receipt) != {"version", "base_head", "index_tree", "accepted", "cases", "problems", "pytest_exit"}
        or receipt["version"] != contract["VERSION"]
        or receipt["base_head"] != head
        or receipt["index_tree"] != tree
        or receipt["accepted"] is not True
        or type(receipt["pytest_exit"]) is not int
        or receipt["pytest_exit"] != 0
        or receipt["problems"] != []
        or receipt["cases"] != list(contract["NODES"])
    ):
        raise Rejected("gate_receipt", "unverified_receipt")
    return receipt


class Candidate:
    def __init__(self, work: Path, source: Path, base: str, tree: str) -> None:
        self.work = work
        self.repo = work / "repo"
        self.source = source
        self.base = base
        self.tree = tree
        self.env = child_env(work)

    def run(
        self, phase: str, command: list[str], *, cwd: Path | None = None,
        data: bytes | None = None, stream: BinaryIO | int = subprocess.PIPE,
        infile: BinaryIO | None = None,
    ) -> bytes:
        result = subprocess.run(
            command, cwd=cwd or self.repo, env=self.env,
            stdin=None if data is not None else infile or subprocess.DEVNULL,
            input=data, stdout=stream, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode:
            # Keep actual command errors in the owned repository's evidence directory.
            (self.work / f"{phase}.stderr").write_bytes(result.stderr)
            if result.stdout:
                (self.work / f"{phase}.stdout").write_bytes(result.stdout)
            raise Rejected(phase, "command_failed", result.returncode)
        return result.stdout or b""

    def git(self, phase: str, *args: str) -> bytes:
        return self.run(phase, [*GIT, *args]).strip()

    def verify_staged(self, phase: str) -> None:
        if (
            self.git(phase, "symbolic-ref", "HEAD") != REF.encode()
            or self.git(phase, "rev-parse", "--verify", "HEAD") != self.base.encode()
            or self.git(phase, "write-tree") != self.tree.encode()
        ):
            raise Rejected(phase, "head_or_index_changed")
        if self.git(phase, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z") or self.git(
            phase, "ls-files", "--others", "-z",
        ):
            raise Rejected(phase, "working_tree_changed")

    def prepare(self, patch: Path) -> None:
        self.repo.mkdir()
        self.git("init", "init", "--quiet", "--template=", "--object-format=sha1")
        if self.run("source", [*GIT, "cat-file", "-t", self.base], cwd=self.source).strip() != b"commit":
            raise Rejected("source", "expected_base_is_not_a_commit")
        source_tree = self.run("source", [*GIT, "rev-parse", f"{self.base}^{{tree}}"], cwd=self.source)
        entries = self.run(
            "source", [*GIT, "ls-tree", "-rt", "--format=%(objecttype) %(objectname)", self.base],
            cwd=self.source,
        )
        objects = {self.base.encode(), source_tree.strip()}
        for line in entries.splitlines():
            kind, oid = line.split()
            if kind not in {b"blob", b"tree"}:
                raise Rejected("source", "unsupported_tree_entry")
            objects.add(oid)
        pack = self.work / "base.pack"
        with pack.open("xb") as output:
            self.run(
                "copy_base", [*GIT, "pack-objects", "--stdout"], cwd=self.source,
                data=b"\n".join(sorted(objects)) + b"\n", stream=output,
            )
        (self.repo / ".git" / "shallow").write_text(self.base + "\n", encoding="ascii")
        with pack.open("rb") as source:
            self.run("copy_base", [*GIT, "index-pack", "--strict", "--stdin"], infile=source)
        pack.unlink()
        self.git("checkout", "switch", "--quiet", "-c", "candidate", self.base)
        self.git("stage_patch", "apply", "--index", "--", str(patch))
        self.verify_staged("staged")
        gate_blob = self.run("approved_gate", [*GIT, "show", f"HEAD:{PROTECTED[1]}"])
        if gate_blob != GATE.read_bytes():
            raise Rejected("approved_gate", "base_gate_differs_from_tool")
        if self.git("approved_gate", "diff", "--cached", "--raw", self.base, "--", *PROTECTED):
            raise Rejected("approved_gate", "gate_or_leak_scanner_changed")

        # Run the existing hook normally even though its tracked mode is 0644.
        hooks = self.repo / ".git" / "hooks"
        hooks.mkdir(exist_ok=True)
        hook = hooks / "pre-commit"
        hook.write_text('#!/bin/sh\nexec sh .githooks/pre-commit "$@"\n', encoding="ascii")
        hook.chmod(0o700)

    def execute(self, patch: Path, message: str) -> dict[str, Any]:
        self.prepare(patch)
        self.run("leak_scan", [sys.executable, "-m", "fxapk.cli", "leak-scan", "--staged", "--strict"])
        self.verify_staged("after_leak_scan")
        raw = self.run("fixed_gate", ["sh", ".githooks/pre-commit", "--fixed-jadx", "--scratch", str(self.work)])
        receipt = validate_gate(raw, self.base, self.tree)
        self.verify_staged("before_commit")

        self.git("commit", "commit", "-m", message)
        commit = self.git("verify_commit", "rev-parse", "--verify", "HEAD").decode("ascii")
        observed = self.git("verify_commit", "rev-list", "--parents", "-n", "1", commit).decode("ascii").split()
        if (
            not SHA.fullmatch(commit)
            or observed != [commit, self.base]
            or self.git("verify_commit", "rev-parse", f"{commit}^{{tree}}") != self.tree.encode()
            or self.git("verify_commit", "symbolic-ref", "HEAD") != REF.encode()
            or self.git("verify_commit", "write-tree") != self.tree.encode()
            or self.git("verify_commit", "status", "--porcelain=v1", "--untracked-files=all")
            or self.git("verify_commit", "ls-files", "--others", "-z")
        ):
            raise Rejected("verify_commit", "commit_parent_tree_or_checkout_mismatch")
        return {"accepted": True, "commit": commit, "parent": self.base, "tree": self.tree, "gate": receipt}


def positive_timeout(value: str) -> float:
    seconds = float(value)
    if not math.isfinite(seconds) or not 0 < seconds <= 600:
        raise argparse.ArgumentTypeError("timeout must be greater than 0 and at most 600 seconds")
    return seconds


def supervise(
    work: Path, source: Path, base: str, tree: str, patch: Path, message: str, timeout: float,
) -> tuple[int, dict[str, Any]]:
    for name in ("home", "tmp"):
        (work / name).mkdir()
    command = [
        sys.executable, "-I", str(Path(__file__).resolve()), "--worker",
        str(work), str(source), base, tree, str(patch), message,
    ]
    try:
        status, result = bounded(command, work, timeout)
    except OSError:
        return 2, {**rejected("setup", "unable_to_start_worker"), "quarantine": str(work)}
    if status != 0:
        return status, {**result, "quarantine": str(work)}
    if (
        set(result) != {"accepted", "commit", "parent", "tree", "gate"}
        or not isinstance(result["commit"], str)
        or not SHA.fullmatch(result["commit"])
        or result["parent"] != base
        or result["tree"] != tree
    ):
        return 2, {**rejected("worker", "invalid_verified_commit_receipt"), "quarantine": str(work)}
    return 0, {**result, "repo": str(work / "repo")}


def encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def persist(path: Path, data: dict[str, Any]) -> None:
    with NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(encode(data) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)


def read_record(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise Rejected("ledger", "record_too_large")
    try:
        record = json.loads(data)
    except (ValueError, RecursionError) as error:
        raise Rejected("ledger", "invalid_record") from error
    if not isinstance(record, dict):
        raise Rejected("ledger", "invalid_record")
    state = record.get("state")
    if not isinstance(state, str) or (state != "processing" and state not in EXIT):
        raise Rejected("ledger", "invalid_record")
    work = record.get("work")
    if not isinstance(work, str) or work in {"", ".", ".."} or "\0" in work or Path(work).name != work:
        raise Rejected("ledger", "invalid_record")
    if state == "succeeded" and not isinstance(record.get("receipt"), dict):
        raise Rejected("ledger", "invalid_record")
    return record


def checked_git(repo: Path, *args: str, deadline: float | None = None) -> bytes:
    command = [*GIT, "-C", str(repo), *args]
    seconds = min(5.0, deadline - time.monotonic()) if deadline is not None else 5.0
    if seconds <= 0:
        raise subprocess.TimeoutExpired(command, 0)
    return subprocess.run(
        command, env=child_env(repo.parent), stdin=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, check=True, timeout=seconds,
    ).stdout.strip()


def verify_receipt(
    result: dict[str, Any], base: str, tree: str, work: Path, *, deadline: float | None = None,
) -> None:
    commit = result.get("commit")
    if (
        set(result) != {"schema", "accepted", "commit", "parent", "tree", "gate", "repo"}
        or result.get("schema") != SCHEMA or result.get("accepted") is not True
        or result.get("parent") != base or result.get("tree") != tree
        or not isinstance(commit, str) or not SHA.fullmatch(commit)
        or result.get("repo") != str(work / "repo")
    ):
        raise Rejected("receipt", "invalid_candidate_receipt")
    validate_gate(encode(result["gate"]), base, tree)
    repo = (work / "repo").resolve(strict=True)
    if (
        repo != work / "repo" or not (repo / ".git").is_dir()
        or checked_git(repo, "rev-parse", "--verify", "HEAD", deadline=deadline) != commit.encode()
        or checked_git(repo, "show", "-s", "--format=%P%n%T", commit, deadline=deadline).splitlines()
        != [base.encode(), tree.encode()]
        or checked_git(repo, "remote", deadline=deadline)
    ):
        raise Rejected("receipt", "git_candidate_mismatch")
    # Commit/tree IDs can survive partial object loss. Require local connectivity
    # of the candidate tree without traversing its commit ancestry or fetching.
    checked_git(repo, "rev-list", "--objects", "--missing=error", f"{tree}^{{tree}}", deadline=deadline)
    checked_git(repo, "cat-file", "-e", f"{base}^{{commit}}", deadline=deadline)


@contextmanager
def stop_flag() -> Iterator[list[bool]]:
    requested = [False]

    def stop(_number: int, _frame: object) -> None:
        requested[0] = True

    previous = {}
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, stop)
        yield requested
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def wait_child(proc: subprocess.Popen[bytes], deadline: float, requested: list[bool]) -> str | None:
    """Observe the cancellation flag without extending the caller's deadline."""
    while not requested[0]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout"
        try:
            proc.wait(timeout=min(0.1, remaining))
        except subprocess.TimeoutExpired:
            continue
        if time.monotonic() >= deadline:
            return "timeout"
        return "interrupted" if requested[0] else None
    return "interrupted"


def launch(
    args: argparse.Namespace, work: Path, patch: bytes, scripts: dict[str, bytes], fd: int,
) -> tuple[str, dict[str, Any]]:
    for name, data in scripts.items():
        (work / name).write_bytes(data)
    patch_file = work / "candidate.patch"
    patch_file.write_bytes(patch)
    command = [
        sys.executable, "-I", str(work / Path(__file__).name), "--supervise",
        str(work), str(args.source), args.base, args.tree, str(patch_file), args.message, str(args.timeout),
    ]
    with TemporaryFile(dir=work) as stdout, stop_flag() as requested:
        deadline = time.monotonic() + args.deadline
        proc = subprocess.Popen(
            command, env=child_env(work), cwd=work, stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=subprocess.DEVNULL, start_new_session=True, pass_fds=(fd,),
        )
        stop = wait_child(proc, deadline, requested)
        if stop == "timeout":
            stop = "dispatcher_timeout"
        if stop and proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=CLEANUP_LIMIT + 1)
            except subprocess.TimeoutExpired:
                # The supervisor still holds the inherited lock. Do not detach its worker by killing it.
                return stop, {"reason": "stop_unconfirmed"}
        if stop:
            # A late success is never usable. Only carry the supervisor's exact
            # negative cleanup record for this job across the outer stop.
            if proc.returncode == 2:
                cleanup = {"phase": "worker", "reason": "cleanup_unverified", "process_group_empty": False}
                expected = encode({"schema": SCHEMA, "accepted": False, **cleanup, "quarantine": str(work)}) + b"\n"
                try:
                    stdout.seek(0)
                    matched = stdout.read(len(expected) + 1) == expected
                except (OSError, ValueError):
                    matched = False
                if matched:
                    return stop, {**cleanup, "supervisor_exit": 2}
            return stop, {"reason": "supervisor_exit_observed", "supervisor_exit": proc.returncode}

        stdout.seek(0)
        output = stdout.read(65537)
        result = json.loads(output) if len(output) <= 65536 else None
        if not isinstance(result, dict) or result.get("schema") != SCHEMA:
            raise Rejected("supervisor", "invalid_candidate_receipt")
        if proc.returncode == 0:
            try:
                verify_receipt(result, args.base, args.tree, work, deadline=deadline)
            except subprocess.TimeoutExpired:
                if time.monotonic() < deadline:
                    raise
            if requested[0] or time.monotonic() >= deadline:
                stop = "interrupted" if requested[0] else "dispatcher_timeout"
                return stop, {"reason": "late_candidate_receipt"}
            return "succeeded", result
        state = {124: "worker_timeout", 130: "interrupted"}.get(proc.returncode, "failed")
        failure = {key: result[key] for key in ("phase", "reason", "step_exit", "process_group_empty") if key in result}
        return state, {**failure, "supervisor_exit": proc.returncode}


def submit(args: argparse.Namespace, ledger: Path) -> tuple[int, dict[str, Any]]:
    if (
        not TASK_ID.fullmatch(args.task_id) or not SHA.fullmatch(args.base)
        or not SHA.fullmatch(args.tree) or not DIGEST.fullmatch(args.patch_sha256)
        or not args.message.strip() or len(args.message) > 200
    ):
        raise Rejected("request", "invalid_task_fields")
    patch = args.patch.read_bytes()
    if sha256(patch).hexdigest() != args.patch_sha256:
        raise Rejected("request", "patch_digest_mismatch")
    scripts = {path.name: path.read_bytes() for path in (Path(__file__), GATE)}
    manifest = {
        "base": args.base, "tree": args.tree, "patch_sha256": args.patch_sha256,
        "message": args.message, "timeout": args.timeout, "deadline": args.deadline,
        "tool_sha256": {name: sha256(data).hexdigest() for name, data in scripts.items()},
    }
    identity = {"task_id": args.task_id, "input_sha256": sha256(encode(manifest)).hexdigest()}
    path = ledger / f"{args.task_id}.json"
    # Import only here so repository test collection also works on other platforms.
    import fcntl

    with (ledger / f"{args.task_id}.lock").open("ab") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if path.exists() and read_record(path).get("input_sha256") != identity["input_sha256"]:
                return 3, {**identity, "state": "conflict"}
            return 75, {**identity, "state": "busy"}

        if path.exists():
            entry = read_record(path)
            if entry.get("input_sha256") != identity["input_sha256"]:
                return 3, {**identity, "state": "conflict"}
            if entry["state"] == "processing":
                entry.update(state="interrupted", failure={"reason": "abandoned_dispatch"})
                persist(path, entry)
            if entry["state"] == "succeeded":
                try:
                    scratch = args.scratch.resolve(strict=True)
                    work = (scratch / entry["work"]).resolve(strict=True)
                    if work.parent != scratch or work.name != entry["work"]:
                        raise Rejected("receipt", "invalid_work_directory")
                    verify_receipt(entry["receipt"], args.base, args.tree, work)
                except (OSError, ValueError, subprocess.SubprocessError, Rejected):
                    return 2, {**identity, "state": "unverifiable", "reason": "candidate_unavailable_or_changed"}
            return EXIT[entry["state"]], {**entry, "replayed": True}

        scratch = args.scratch.resolve(strict=True)
        if not scratch.is_dir() or any(os.path.lexists(p / ".git") for p in (scratch, *scratch.parents)):
            raise Rejected("request", "scratch_must_be_outside_git")
        args.source = args.source.resolve(strict=True)
        work = Path(mkdtemp(prefix="fxapk-candidate-", dir=scratch))
        entry = {**identity, "input": manifest, "state": "processing", "work": work.name}
        persist(path, entry)
        try:
            state, result = launch(args, work, patch, scripts, lock.fileno())
        except (OSError, ValueError, subprocess.SubprocessError, Rejected) as error:
            state = "failed"
            result = rejected(error.phase, error.reason, error.step_exit) if isinstance(error, Rejected) else {
                "reason": "invalid_execution",
            }
        entry.update(state=state)
        entry["receipt" if state == "succeeded" else "failure"] = result
        persist(path, entry)
        return EXIT[state], {**entry, "replayed": False}


def internal() -> int:
    mode, work, source, base, tree, patch, message, *tail = sys.argv[1:]
    if Path(__file__).resolve().parent != Path(work) or Path(patch) != Path(work) / "candidate.patch":
        print('{"error":"internal_worker_requires_private_job"}')
        return 2
    if mode == "--supervise":
        status, result = supervise(Path(work), Path(source), base, tree, Path(patch), message, float(tail[0]))
    else:
        try:
            result = Candidate(Path(work), Path(source), base, tree).execute(Path(patch), message)
            status = 0
        except Rejected as error:
            result = rejected(error.phase, error.reason, error.step_exit)
            status = 1
    print(encode({"schema": SCHEMA, **result} if mode == "--supervise" else result).decode("ascii"))
    return status


def main() -> int:
    if sys.platform != "linux" or not sys.flags.isolated:
        print('{"error":"requires_linux_and_python_isolated_mode"}')
        return 2
    if sys.argv[1:2] in (["--supervise"], ["--worker"]):
        return internal()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    modes = parser.add_subparsers(dest="command", required=True)
    modes.add_parser("status")
    request = modes.add_parser("submit")
    for option in ("source", "scratch", "patch"):
        request.add_argument(f"--{option}", type=Path, required=True)
    for option in ("task-id", "base", "tree", "patch-sha256", "message"):
        request.add_argument(f"--{option}", required=True)
    request.add_argument("--timeout", type=positive_timeout, default=120.0)
    request.add_argument("--deadline", type=positive_timeout, default=130.0)
    args = parser.parse_args()
    try:
        ledger = args.state_dir.resolve()
        ledger.mkdir(parents=True, mode=0o700, exist_ok=True)
        if ledger.stat().st_uid != os.getuid() or ledger.stat().st_mode & 0o077:
            raise Rejected("ledger", "owned_private_state_directory_required")
        if args.command == "status":
            code, outcome = 0, {
                "records": [
                    {key: entry[key] for key in ("task_id", "state", "input_sha256", "work", "failure") if key in entry}
                    for entry in (read_record(path) for path in sorted(ledger.glob("*.json")))
                ],
            }
        else:
            code, outcome = submit(args, ledger)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, Rejected) as error:
        code, outcome = 2, rejected(error.phase, error.reason) if isinstance(error, Rejected) else {
            "error": "invalid_request_or_ledger",
        }
    print(encode(outcome).decode("ascii"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
