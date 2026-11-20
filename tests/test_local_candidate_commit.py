"""Check the Linux candidate ledger with isolated synthetic Git objects."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from textwrap import dedent
from types import FrameType, SimpleNamespace
from typing import Any

import pytest

from tools import local_candidate_commit as dispatcher
from tools.fixed_jadx_gate import NODES, VERSION

TOOL = Path(__file__).resolve().parents[1] / "tools" / "local_candidate_commit.py"
GATE = TOOL.with_name("fixed_jadx_gate.py")
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="candidate dispatch requires Linux")


class ReplayFixture:
    def __init__(self, root: Path) -> None:
        self.scratch = root / "scratch"
        self.work = self.scratch / "prior-candidate"
        self.repo = self.work / "repo"
        self.repo.mkdir(parents=True)
        self.ledger = root / "ledger"
        self.ledger.mkdir(mode=0o700)
        self.record = self.ledger / "toy.json"
        self.patch = root / "candidate.patch"
        self.patch.write_bytes(b"synthetic input bound to the ledger\n")
        self.source = root / "unused-source"
        self.message = "Synthetic candidate"
        self.env = {
            "PATH": f"{Path(sys.executable).parent}:{os.defpath}",
            "HOME": str(root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_AUTHOR_NAME": "Synthetic",
            "GIT_COMMITTER_NAME": "Synthetic",
            "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
            "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
        }
        self.git("init", "--quiet", "--template=", "--object-format=sha1")
        path = self.repo / "note.txt"
        path.write_text("before\n", encoding="utf-8")
        self.git("add", "--", path.name)
        self.base = self.git("commit-tree", self.git("write-tree"), "-m", "Synthetic base")
        path.write_text("after\n", encoding="utf-8")
        nested = self.repo / "nested"
        nested.mkdir()
        (nested / "child.txt").write_text("synthetic nested content\n", encoding="utf-8")
        self.git("add", "--", path.name, "nested")
        self.tree = self.git("write-tree")
        self.commit = self.git("commit-tree", self.tree, "-p", self.base, "-m", self.message)
        self.git("update-ref", "HEAD", self.commit)
        self.receipt = {
            "schema": "fxapk.local-candidate.v1", "accepted": True, "commit": self.commit,
            "parent": self.base, "tree": self.tree, "repo": str(self.repo),
            "gate": {
                "version": VERSION, "accepted": True, "base_head": self.base,
                "index_tree": self.tree, "cases": list(NODES), "problems": [], "pytest_exit": 0,
            },
        }
        self.manifest = {
            "base": self.base, "tree": self.tree, "patch_sha256": sha256(self.patch.read_bytes()).hexdigest(),
            "message": self.message, "timeout": 120.0, "deadline": 130.0,
            "tool_sha256": {path.name: sha256(path.read_bytes()).hexdigest() for path in (TOOL, GATE)},
        }
        encoded = json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
        self.identity = {"task_id": "toy", "input_sha256": sha256(encoded).hexdigest()}

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", *args], cwd=self.repo, env=self.env, stdin=subprocess.DEVNULL, text=True, timeout=5,
        ).strip()

    def seed(self, state: str) -> bytes:
        entry = {**self.identity, "input": self.manifest, "state": state, "work": self.work.name}
        if state == "succeeded":
            entry["receipt"] = self.receipt
        self.record.write_text(json.dumps(entry) + "\n", encoding="ascii")
        return self.record.read_bytes()

    def submit(self, *, message: str | None = None) -> tuple[int, dict[str, Any]]:
        # This source cannot be used to launch any new job; it is irrelevant to replay.
        result = subprocess.run(
            [sys.executable, "-I", str(TOOL), "--state-dir", str(self.ledger), "submit",
             "--task-id", "toy", "--source", str(self.source), "--scratch", str(self.scratch),
             "--base", self.base, "--tree", self.tree, "--patch", str(self.patch),
             "--patch-sha256", self.manifest["patch_sha256"], "--message", message or self.message,
             "--timeout", str(self.manifest["timeout"]), "--deadline", str(self.manifest["deadline"])],
            env=self.env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
        )
        assert not result.stderr
        return result.returncode, json.loads(result.stdout)

    def assert_unchanged(self, original_record: bytes) -> None:
        assert self.record.read_bytes() == original_record
        assert list(self.scratch.iterdir()) == [self.work]


@pytest.fixture
def prior_candidate(tmp_path: Path) -> ReplayFixture:
    return ReplayFixture(tmp_path)


def test_replay_validates_exact_existing_commit_and_tree(prior_candidate: ReplayFixture) -> None:
    original = prior_candidate.seed("succeeded")

    status, outcome = prior_candidate.submit()

    assert status == 0
    assert outcome == {**json.loads(original), "replayed": True}
    prior_candidate.assert_unchanged(original)


@pytest.mark.parametrize("loss", ["missing_repo", "missing_tree", "missing_blob", "missing_subtree", "changed_head"])
def test_replay_refuses_changed_or_unavailable_objects(prior_candidate: ReplayFixture, loss: str) -> None:
    original = prior_candidate.seed("succeeded")
    if loss == "missing_repo":
        prior_candidate.repo.rename(prior_candidate.work / "moved-repo")
    elif loss == "missing_tree":
        tree = prior_candidate.tree
        (prior_candidate.repo / ".git" / "objects" / tree[:2] / tree[2:]).unlink()
        assert prior_candidate.git("rev-parse", "HEAD") == prior_candidate.commit
        assert prior_candidate.git("cat-file", "-t", prior_candidate.commit) == "commit"
    elif loss in {"missing_blob", "missing_subtree"}:
        path = "note.txt" if loss == "missing_blob" else "nested"
        oid = prior_candidate.git("rev-parse", f"HEAD:{path}")
        loose = prior_candidate.repo / ".git" / "objects" / oid[:2] / oid[2:]
        loose.rename(prior_candidate.work / "unavailable-object")
        assert prior_candidate.git("rev-parse", "HEAD") == prior_candidate.commit
        assert prior_candidate.git("cat-file", "-t", prior_candidate.tree) == "tree"
    else:
        prior_candidate.git("update-ref", "HEAD", prior_candidate.base, prior_candidate.commit)
        assert prior_candidate.git("rev-parse", "HEAD") == prior_candidate.base
        assert prior_candidate.git("cat-file", "-t", prior_candidate.tree) == "tree"

    assert prior_candidate.submit() == (2, {
        **prior_candidate.identity, "state": "unverifiable", "reason": "candidate_unavailable_or_changed",
    })
    prior_candidate.assert_unchanged(original)


def test_replay_refuses_same_task_with_changed_input(prior_candidate: ReplayFixture) -> None:
    original = prior_candidate.seed("succeeded")

    status, outcome = prior_candidate.submit(message="Another synthetic candidate")

    assert status == 3
    assert outcome["task_id"] == prior_candidate.identity["task_id"]
    assert outcome["state"] == "conflict"
    assert outcome["input_sha256"] != prior_candidate.identity["input_sha256"]
    assert "receipt" not in outcome
    prior_candidate.assert_unchanged(original)


def test_restart_waits_for_real_claim_lock_and_never_relaunches(prior_candidate: ReplayFixture) -> None:
    import fcntl

    original = prior_candidate.seed("processing")
    with (prior_candidate.ledger / "toy.lock").open("ab") as owner:
        fcntl.flock(owner.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert prior_candidate.submit() == (75, {**prior_candidate.identity, "state": "busy"})
        changed_status, changed = prior_candidate.submit(message="Another synthetic candidate")
        assert changed_status == 3
        assert changed["state"] == "conflict"
        prior_candidate.assert_unchanged(original)

    status, recovered = prior_candidate.submit()
    assert status == 130
    assert recovered == {
        **json.loads(original), "state": "interrupted", "replayed": True,
        "failure": {"reason": "abandoned_dispatch"},
    }
    saved = prior_candidate.record.read_bytes()
    assert json.loads(saved) == {key: value for key, value in recovered.items() if key != "replayed"}
    assert prior_candidate.submit() == (130, recovered)
    prior_candidate.assert_unchanged(saved)


def request_for(fixture: ReplayFixture) -> argparse.Namespace:
    return argparse.Namespace(
        **{key: value for key, value in fixture.manifest.items() if key != "tool_sha256"},
        task_id="toy", scratch=fixture.scratch, source=fixture.repo, patch=fixture.patch,
    )


def test_dispatcher_timeout_retains_claim_on_unresponsive_supervisor(
    prior_candidate: ReplayFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual_launch = dispatcher.launch
    spawned: list[subprocess.Popen[Any]] = []
    actual_popen = subprocess.Popen

    def supervised(command: list[str], **kwargs: Any) -> subprocess.Popen[Any]:
        child = actual_popen(command, **kwargs)
        if "--supervise" in command:
            spawned.append(child)
        return child

    def run_stub(
        args: argparse.Namespace, work: Path, patch: bytes, _scripts: dict[str, bytes], fd: int,
    ) -> tuple[str, dict[str, Any]]:
        script = dedent("""            from pathlib import Path
            import signal
            import sys
            import time

            signal.signal(signal.SIGINT, signal.SIG_IGN)
            work = Path(sys.argv[2])
            (work / "waiting").touch()
            for _ in range(250):
                if (work / "finish").exists():
                    break
                time.sleep(0.025)
        """)
        return actual_launch(args, work, patch, {TOOL.name: script.encode()}, fd)

    monkeypatch.setattr(dispatcher, "launch", run_stub)
    monkeypatch.setattr(dispatcher, "CLEANUP_LIMIT", 0.0)
    monkeypatch.setattr(dispatcher.subprocess, "Popen", supervised)
    prior_candidate.manifest["deadline"] = 0.8
    try:
        code, outcome = dispatcher.submit(request_for(prior_candidate), prior_candidate.ledger)
        assert code == 125
        assert outcome["state"] == "dispatcher_timeout"
        assert outcome["failure"] == {"reason": "stop_unconfirmed"}
        assert "receipt" not in outcome
        work = prior_candidate.scratch / outcome["work"]
        assert len(spawned) == 1 and (work / "waiting").exists()
        assert spawned[0].poll() is None
        assert prior_candidate.submit()[0] == 75
        assert prior_candidate.submit(message="new input")[0] == 3
        (work / "finish").touch()
        assert spawned[0].wait(timeout=3) == 0
        assert prior_candidate.submit() == (125, {**outcome, "replayed": True})
        assert set(prior_candidate.scratch.iterdir()) == {prior_candidate.work, work}
    finally:
        for child in spawned:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)


def test_worker_timeout_is_distinct_from_dispatcher_deadline(prior_candidate: ReplayFixture) -> None:
    script = dedent(f"""        import json
        from pathlib import Path
        import runpy
        import sys

        work = Path(sys.argv[2])
        (work / "home").mkdir()
        (work / "tmp").mkdir()
        tool = runpy.run_path({str(TOOL)!r})
        status, outcome = tool["bounded"](
            [sys.executable, "-I", "-c", "import time; time.sleep(8)"], work, 0.06,
        )
        print(json.dumps({{"schema": tool["SCHEMA"], **outcome}}))
        raise SystemExit(status)
    """)
    work = prior_candidate.work
    lock = prior_candidate.ledger / "worker.lock"
    with lock.open("ab") as stream:
        state, outcome = dispatcher.launch(
            request_for(prior_candidate), work, b"synthetic", {TOOL.name: script.encode()}, stream.fileno(),
        )

    assert state == "worker_timeout" and dispatcher.EXIT[state] == 124
    assert outcome == {"phase": "worker", "reason": "timeout", "process_group_empty": True, "supervisor_exit": 124}


@pytest.mark.parametrize("cleanup", ["confirmed", "wait_timeout", "signal_denied"])
def test_cancel_after_worker_handle_acquired(
    prior_candidate: ReplayFixture, monkeypatch: pytest.MonkeyPatch, cleanup: str,
) -> None:
    def default_interrupt(_number: int, _frame: FrameType | None) -> None:
        raise KeyboardInterrupt

    original = {signal.SIGINT: default_interrupt, signal.SIGTERM: signal.SIG_DFL}
    handlers = original.copy()

    def install(number, handler):
        previous = handlers[number]
        handlers[number] = handler
        return previous

    monkeypatch.setattr(dispatcher, "signal", SimpleNamespace(
        SIGINT=signal.SIGINT, SIGTERM=signal.SIGTERM, SIGKILL=signal.SIGKILL, signal=install,
    ))
    monkeypatch.setattr(dispatcher, "become_subreaper", lambda: None)
    wait_calls = []
    group_signals = []
    launches = []
    intercepted = False
    cleanup_confirmed = cleanup == "confirmed"

    class Worker:
        pid = 123
        returncode = None
        running = True

        def wait(self, *, timeout):
            wait_calls.append(timeout)
            if self.running:
                raise subprocess.TimeoutExpired("synthetic-worker", timeout)
            return 0

    worker = Worker()

    def killpg(pgid, number):
        assert pgid == worker.pid
        if number == 0:
            assert not worker.running
            raise ProcessLookupError
        assert number == signal.SIGKILL
        group_signals.append(number)
        # A second ordinary cancellation during cleanup must be deferred too.
        handlers[signal.SIGINT](signal.SIGINT, None)
        if cleanup == "signal_denied":
            raise PermissionError
        worker.running = not cleanup_confirmed

    def waitpid(pid, options):
        assert pid == -worker.pid and options == os.WNOHANG
        raise ChildProcessError

    monkeypatch.setattr(dispatcher.os, "killpg", killpg)
    monkeypatch.setattr(dispatcher.os, "waitpid", waitpid)

    def cancel_after_assignment(frame: FrameType, event: str, _arg: object):
        nonlocal intercepted
        if (frame.f_code is dispatcher.bounded.__code__ and event == "line"
                and not intercepted and frame.f_locals.get("proc") is worker):
            intercepted = True
            assert not wait_calls
            handlers[signal.SIGINT](signal.SIGINT, frame)
        return cancel_after_assignment

    def fake_popen(command, *, cwd, stdout, **_kwargs):
        if command[3] == "--worker":
            # Even an accepted-looking payload from an interrupted worker must be ignored.
            stdout.write(b'{"accepted":true}')
            return worker
        assert command[3] == "--supervise"
        launches.append(cwd)
        parent_handlers = handlers.copy()
        handlers.update(original)  # A separately launched interpreter has independent handlers.
        previous_trace = sys.gettrace()
        try:
            sys.settrace(cancel_after_assignment)
            status, outcome = dispatcher.supervise(
                cwd, Path(command[5]), command[6], command[7], Path(command[8]), command[9], float(command[10]),
            )
        except KeyboardInterrupt:
            # Model the old supervisor exiting without a result or worker cleanup.
            status = -signal.SIGINT
        else:
            stdout.write(dispatcher.encode({"schema": dispatcher.SCHEMA, **outcome}))
        finally:
            sys.settrace(previous_trace)
            assert handlers == original
            handlers.update(parent_handlers)
        return SimpleNamespace(returncode=status, wait=lambda *, timeout: status)

    monkeypatch.setattr(dispatcher.subprocess, "Popen", fake_popen)
    args = request_for(prior_candidate)
    code, outcome = dispatcher.submit(args, prior_candidate.ledger)

    assert intercepted and group_signals == [signal.SIGKILL], "acquired worker was not cleaned up"
    if cleanup == "signal_denied":
        assert not wait_calls
    else:
        assert len(wait_calls) == 1 and 0 < wait_calls[0] <= dispatcher.CLEANUP_LIMIT
    assert worker.running is not cleanup_confirmed
    expected_code, state = (130, "interrupted") if cleanup_confirmed else (1, "failed")
    assert code == expected_code and outcome["state"] == state
    assert outcome["failure"] == {
        "phase": "worker", "reason": "interrupted" if cleanup_confirmed else "cleanup_unverified",
        "process_group_empty": cleanup_confirmed, "supervisor_exit": 130 if cleanup_confirmed else 2,
    }
    assert "receipt" not in outcome
    assert dispatcher.submit(args, prior_candidate.ledger) == (code, {**outcome, "replayed": True})
    assert len(launches) == 1 and handlers == original


def test_dispatcher_rejects_supervisor_that_exits_after_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    with subprocess.Popen([sys.executable, "-I", "-c", "pass"]) as proc:
        assert proc.wait(timeout=5) == 0
        times = iter((1.0, 3.0))
        with monkeypatch.context() as patch:
            patch.setattr(dispatcher.time, "monotonic", lambda: next(times))
            assert dispatcher.wait_child(proc, 2.0, [False]) == "timeout"


def test_cancel_while_reading_completed_worker_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    requested = [False]
    worker = SimpleNamespace(pid=123, returncode=0, wait=lambda *, timeout: 0)
    monkeypatch.setattr(dispatcher, "become_subreaper", lambda: None)
    monkeypatch.setattr(dispatcher, "stop_flag", lambda: nullcontext(requested))
    monkeypatch.setattr(dispatcher.subprocess, "Popen", lambda *args, **kwargs: worker)
    monkeypatch.setattr(dispatcher, "reap_exited", lambda pgid: None)
    monkeypatch.setattr(dispatcher, "group_exists", lambda pgid: False)
    monkeypatch.setattr(dispatcher, "stop_group", lambda proc: pytest.fail("empty group must not be signalled"))

    def read_receipt(path: Path, rc: int) -> tuple[int, dict[str, Any]]:
        assert path.name == "worker.stdout" and rc == 0
        requested[0] = True
        return 0, {"accepted": True}

    monkeypatch.setattr(dispatcher, "read_worker_receipt", read_receipt)
    assert dispatcher.bounded(["synthetic-worker"], tmp_path, 1) == (
        130, {"accepted": False, "phase": "worker", "reason": "interrupted", "process_group_empty": True},
    )
