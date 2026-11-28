"""proctree 进程树所有权执行器：**真实**小 Python 进程树受控测试（不真跑 jadx）。

覆盖 B1 的 Windows/POSIX 终止语义：超时整树终止（含孙进程）、根退出后脱管后代被强杀、
所有权建立失败 fail closed、输出 utf-8 解码。超时用秒级预算，绝不真实等 120/200 秒。
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import sys
import time
from pathlib import Path

import psutil
import pytest

from fxapk.core import proctree
from tests.first_failure_diagnostic import (
    FirstFailureDiagnostic,
    emit_posix_verification_stage,
    observe_posix_verification_stage,
)

#: 「java 等价物」孙进程：长睡眠、输出全部 DEVNULL（不占父的 stdout 管道，
#: 免得 communicate 等孙进程 EOF——真实 jadx 的这类挂起由 timeout 兜底，与本测无关）。
_SPAWN_SLEEPER = (
    "import subprocess, sys;"
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'],"
    " stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL);"
    "print(p.pid, flush=True);"
)


def _sleeper_alive(pid: int) -> bool:
    """孙进程是否仍存活（防 PID 复用：还得仍是那个长睡眠 python）。"""
    try:
        proc = psutil.Process(pid)
        return proc.is_running() and "time.sleep(120)" in " ".join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def _sleeper_gone(pid: int, budget: float = 5.0) -> bool:
    """限时等待孙进程消亡。内核终止（Job 计数归零）后，psutil 在句柄保留窗口内
    仍会短暂报 is_running=True 且 cmdline 可读——立查会把「已死未回收」误判成存活
    （本机实测稳定复现）。真孤儿在长睡 120 秒，几秒的等待不会把它等成假阴。"""
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        if not _sleeper_alive(pid):
            return True
        time.sleep(0.05)
    return not _sleeper_alive(pid)


def _kill_if_alive(pid: int) -> None:
    try:
        psutil.Process(pid).kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass


@pytest.mark.skipif(sys.platform != "linux", reason="Linux inherited ownership tracking")
def test_outer_timeout_kills_nested_owned_session_but_not_unrelated_process(tmp_path):
    import subprocess

    pid_file = tmp_path / "nested.pid"
    leaf = ("import os,time;from pathlib import Path;"
            f"Path({str(pid_file)!r}).write_text(str(os.getpid()));time.sleep(120)")
    middle = ("import sys;from fxapk.core.proctree import run_owned;"
              f"run_owned([sys.executable,'-c',{leaf!r}],timeout=60)")
    unrelated = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(120)"])
    try:
        result = proctree.run_owned([sys.executable, "-c", middle], timeout=5)
        assert result.timed_out and result.termination_complete, result
        assert pid_file.is_file(), "nested worker never started; cleanup path was not exercised"
        assert _sleeper_gone(int(pid_file.read_text(encoding="utf-8")))
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)
        if pid_file.exists():
            _kill_if_alive(int(pid_file.read_text(encoding="utf-8")))


@pytest.mark.parametrize("timed_out", [False, True], ids=["exits", "times-out"])
def test_capped_run_waits_for_process_after_output_eof(
    monkeypatch: pytest.MonkeyPatch, timed_out: bool,
) -> None:
    import subprocess
    from types import SimpleNamespace
    from unittest.mock import Mock

    proc = Mock(spec=subprocess.Popen)
    remaining = 1.0 if timed_out else 4.0
    if timed_out:
        proc.wait.side_effect = subprocess.TimeoutExpired("fixture", remaining)
    read_fds = []
    for data in (b"version\n", b""):
        rd, wr = os.pipe()
        read_fds.append(os.fdopen(rd, encoding="utf-8"))
        with os.fdopen(wr, "wb") as writer:
            writer.write(data)
    capture = proctree._OutputPipes(*read_fds, 64, 64)
    try:
        capture.start()
        assert capture._join(5.0)
        now = time.monotonic()
        monkeypatch.setattr(proctree, "time", SimpleNamespace(monotonic=lambda: now))
        assert capture.wait_for_root(proc, now + remaining) is timed_out
        proc.wait.assert_called_once_with(timeout=remaining)
        reasons = []
        assert capture.finish(reasons) == ("version\n", "")
        assert not reasons
    finally:
        capture.close()


def test_capped_unclosed_pipe_cancels_reader_and_preserves_prefix(monkeypatch) -> None:
    from unittest.mock import Mock

    rd, wr = os.pipe()
    er, ew = os.pipe()
    os.close(ew)
    out, err = os.fdopen(rd, encoding="utf-8"), os.fdopen(er, encoding="utf-8")
    capture = proctree._OutputPipes(out, err, 32, 32)
    monkeypatch.setattr(proctree, "_ROOT_EXIT_GRACE", 0.25)
    root = Mock()
    root.poll.return_value = 0
    with os.fdopen(wr, "wb", buffering=0) as held:
        held.write(b"tail")
        try:
            capture.start()
            assert not capture.wait_for_root(root, time.monotonic() + 10)
            reasons = []
            assert capture.finish(reasons) == ("tail", "")
            assert reasons == ["output_drain_unverified"]
            assert out.closed and err.closed
            assert not any(reader.is_alive() for reader in capture.readers)
        finally:
            capture.close()


@pytest.mark.parametrize(
    ("limit", "expected"), [
        pytest.param(None, "a\nb\nc\n", id="uncapped-normalizes"),
        pytest.param(64, "a\r\nb\rc\n", id="capped-keeps-raw"),
    ],
)
def test_captured_pipes_keep_mode_specific_newline_semantics(limit, expected) -> None:
    result = proctree.run_owned(
        [sys._base_executable, "-c",
         "import sys; sys.stdout.buffer.write(b'a\\r\\nb\\rc\\n'); "
         "sys.stderr.buffer.write(b'a\\r\\nb\\rc\\n')"],
        timeout=10, max_stdout_bytes=limit, max_stderr_bytes=limit,
    )
    assert result.stdout == result.stderr == expected, result
    assert result.returncode == 0 and result.termination_complete
    assert not result.reason_codes


def test_read_failure_is_not_time_or_process_failure(monkeypatch) -> None:
    from unittest.mock import Mock

    def invalid_stream(_fd: int) -> bytes:
        raise OSError("synthetic read failure")

    monkeypatch.setattr(proctree, "_read_pipe_chunk", invalid_stream)
    pipes = []
    for _ in range(2):
        read, write = os.pipe()
        os.close(write)
        pipes.append(os.fdopen(read, encoding="utf-8"))
    capture = proctree._OutputPipes(*pipes, None, None)
    try:
        capture.start()
        assert capture._join(5.0)
        root = Mock()
        root.poll.return_value = 0
        assert not capture.wait_for_root(root, time.monotonic() + 5)
        reasons = []
        assert capture.finish(reasons) == ("", "")
        assert reasons == ["output_read_failed"]
        assert all(pipe.closed for pipe in pipes)
    finally:
        capture.close()


def test_capped_output_limit_keeps_only_requested_bytes() -> None:
    result = proctree.run_owned(
        [sys._base_executable, "-c", "print('123456789')"],
        timeout=10, max_stdout_bytes=3, max_stderr_bytes=64,
    )
    assert result.stdout == "123", result
    assert "output_limit" in result.reason_codes and not result.timed_out, result
    assert result.termination_complete and result.returncode is not None, result


@pytest.mark.parametrize("limit", [64, None], ids=["capped", "uncapped"])
def test_root_exit_reclaims_tree_before_waiting_for_inherited_pipe(limit: int | None) -> None:
    import threading

    # This benign child inherits only our synthetic command's ordinary pipes;
    # it exits by itself even if the old implementation fails to reclaim it.
    root = ("import subprocess,sys;"
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(6)']);"
            "print('root finished', flush=True)")
    result = proctree.run_owned(
        [sys._base_executable, "-c", root], timeout=20,
        max_stdout_bytes=limit, max_stderr_bytes=limit,
    )
    assert result.stdout.strip() == "root finished" and result.returncode == 0, result
    assert not result.timed_out and result.forced_tree_kill, result
    assert result.ownership_complete and result.termination_complete, result
    assert result.reason_codes == ("descendants_after_root_exit",)
    assert not any(t.name.startswith("fxapk-pipe-") for t in threading.enumerate())


@pytest.mark.parametrize("stage", ["write", "close"])
def test_gate_input_failure_still_closes_stdin(stage: str) -> None:
    from unittest.mock import Mock

    stream = Mock()
    getattr(stream, stage).side_effect = BrokenPipeError()
    assert not proctree._write_gate_input(stream, "synthetic\n")
    stream.close.assert_called_once_with()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job exit tracker")
@pytest.mark.parametrize("join_failure", [False, True])
def test_tracker_shutdown_releases_handles_without_losing_result(monkeypatch, join_failure) -> None:
    import threading
    from unittest.mock import Mock

    tracker = object.__new__(proctree._JobExitTracker)
    tracker.thread = Mock()
    tracker.thread.is_alive.return_value = True
    if join_failure:
        tracker.thread.join.side_effect = RuntimeError("synthetic join failure")
    tracker.stop = threading.Event()
    tracker.handle_lock = threading.Lock()
    tracker.handles = [11, 12]
    tracker.port = 15
    closed = []
    monkeypatch.setattr(proctree._kernel32, "CloseHandle", closed.append)
    tracker.close()
    assert tracker.stop.is_set() and closed == [11, 12, 15]


def test_capped_run_terminates_process_after_output_eof(tmp_path: Path) -> None:
    closed = tmp_path / "closed"
    script = (
        "import os, sys, time; from pathlib import Path;"
        "os.close(1); os.close(2);"
        "Path(sys.argv[1]).touch(); time.sleep(30)"
    )
    result = proctree.run_owned(
        [sys._base_executable, "-c", script, str(closed)],
        timeout=4.0,
        max_stdout_bytes=64,
        max_stderr_bytes=64,
    )

    assert closed.is_file(), "the fixture did not reach EOF before the deadline"
    assert result.timed_out and "timeout" in result.reason_codes, result
    assert result.ownership_complete and result.termination_complete, result
    assert result.returncode is not None and result.returncode != 0
    assert "output_limit" not in result.reason_codes


def test_timeout_kills_whole_tree_including_grandchild() -> None:
    """★B1 核心（真实进程）：超时不只杀直接子进程——.bat/cmd→java→后代 的等价形态
    （python→python 孙进程）整树终止并验证无存活，结局如实进 OwnedRun。"""
    script = _SPAWN_SLEEPER + "import time; time.sleep(120)"  # 根进程自己也长睡 → 必超时
    res = proctree.run_owned([sys.executable, "-c", script], timeout=5.0)
    # 重载 runner 上根进程可能没来得及打印 PID 就被超时强杀——此时孙进程必然也没被
    # spawn（print 在 Popen 之后），超时语义照常断言，跳过存活检查即可，别让测试自身
    # IndexError 假红。
    pid_lines = res.stdout.strip().splitlines()
    pid = int(pid_lines[0]) if pid_lines else None
    try:
        assert res.timed_out is True
        # 旧断言把 returncode 锁成 None，那是超时路径跳过 poll/wait 的错误语义。
        # 强杀之后必须回收真实退出码，同时保留 timeout，不能再把已退出进程塌成 null。
        assert isinstance(res.returncode, int)
        assert res.returncode != 0
        assert res.ownership_complete is True
        assert "timeout" in res.reason_codes
        assert res.termination_complete is True, "整树终止未获确认"
        if pid is not None:
            assert _sleeper_gone(pid), "孙进程在超时强杀后仍存活——孤儿 java 形态复现"
    finally:
        if pid is not None:
            _kill_if_alive(pid)  # 断言失败时不留真孤儿



def _fixture_pid_state_before_cleanup(pid: int) -> str:
    """Inspect only the synthetic fixture; disclose neither PID nor command."""
    try:
        process = psutil.Process(pid)
        if process.status() == psutil.STATUS_ZOMBIE:
            return "exited_or_zombie"
        if "time.sleep(120)" in " ".join(process.cmdline()):
            return "fixture_live"
        return "identity_unverified"
    except (psutil.ZombieProcess, psutil.NoSuchProcess, ProcessLookupError):
        return "exited_or_zombie"
    except (psutil.AccessDenied, PermissionError):
        return "unreadable"
    except OSError:
        return "unreadable"


def test_descendants_after_root_exit_force_killed(request) -> None:
    """根进程正常退出但孙进程脱管（daemon 化 java 形态）→ 检出、强杀整树、
    forced_tree_kill=True（该次运行不得算完整覆盖）。"""
    details: dict[str, str] = {}
    with observe_posix_verification_stage(details=details) as observed:
        res = proctree.run_owned([sys.executable, "-c", _SPAWN_SLEEPER], timeout=30.0)
    diagnostic = FirstFailureDiagnostic("ownership_descendants", getattr(request.config, "workerinput", {}).get("workerid", "master"))
    diagnostic.observe(
        stage="termination_check", ownership=res.ownership_complete, reasons=res.reason_codes,
        posix_verification_stage=observed(), posix_probe=details.get("posix_probe"),
        posix_error=details.get("posix_error"),
    )
    pid = int(res.stdout.strip().splitlines()[0])
    try:
        with diagnostic:
            assert res.timed_out is False
            assert res.forced_tree_kill is True
            assert "descendants_after_root_exit" in res.reason_codes
            assert res.termination_complete is True
            assert _sleeper_gone(pid), "脱管孙进程未被强杀"
    except AssertionError:
        print(
            "fixture-pid-before-cleanup: " + _fixture_pid_state_before_cleanup(pid),
            file=sys.stderr,
        )
        emit_posix_verification_stage(observed())
        raise
    finally:
        _kill_if_alive(pid)



@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ("live", "fixture_live"),
        ("gone", "exited_or_zombie"),
        ("zombie", "exited_or_zombie"),
        ("denied", "unreadable"),
        ("other", "identity_unverified"),
    ],
)
def test_fixture_pid_observation_is_not_a_termination_verdict(
    monkeypatch, outcome: str, expected: str,
) -> None:
    class Observed:
        def status(self):
            if outcome == "gone":
                raise psutil.NoSuchProcess(1)
            if outcome == "denied":
                raise psutil.AccessDenied(1)
            return psutil.STATUS_ZOMBIE if outcome == "zombie" else psutil.STATUS_RUNNING

        def cmdline(self):
            return ["time.sleep(120)"] if outcome == "live" else ["other-command"]

    monkeypatch.setattr(psutil, "Process", lambda _pid: Observed())
    assert _fixture_pid_state_before_cleanup(1) == expected


def test_clean_exit_utf8_stdout_and_env_passthrough() -> None:
    """干净退出：stdout 按 utf-8 解码（中文 Windows 默认 GBK 会把 jadx 的 UTF-8 输出打碎），
    env 穿过门进程传到命令（以自定义变量回显直接证明，不只靠编码旁证）；结局全绿、无 reason。"""
    res = proctree.run_owned(
        [
            sys.executable, "-c",
            "import os; print('中文-jadx-输出'); print(os.environ['PROCTREE_TEST_ENV'])",
        ],
        timeout=30.0,
        env={**os.environ, "PYTHONIOENCODING": "utf-8", "PROCTREE_TEST_ENV": "env-穿透"},
    )
    assert res.returncode == 0
    assert res.timed_out is False
    assert res.ownership_complete and res.termination_complete
    assert res.forced_tree_kill is False
    assert res.reason_codes == ()
    assert "中文-jadx-输出" in res.stdout
    assert "env-穿透" in res.stdout, "自定义 env 未穿过门进程传到命令"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object fail-closed 路径")
def test_windows_job_failure_fails_closed_command_never_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path,  # noqa: ANN001
) -> None:
    """★fail closed（受控）：Job 建立失败 → 门进程收口自退，命令**从未执行**；
    ownership_complete=False 落 reason，jadx 侧据此定 failed（宁可不跑，不跑无主 JVM）。"""
    marker = tmp_path / "ran.txt"
    monkeypatch.setattr(proctree, "_create_kill_on_close_job", lambda: None)
    res = proctree.run_owned(
        [sys.executable, "-c", f"open(r'{marker}', 'w').close()"], timeout=10.0
    )
    assert res.ownership_complete is False
    assert "job_assignment_failed" in res.reason_codes
    assert res.returncode is None
    assert res.termination_complete is True  # 门进程未产子、自身已退
    assert not marker.exists(), "所有权未建立时命令不得被放行"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX 实现只在非 win32 绑定")
def test_darwin_memory_limit_unavailable_fails_closed_without_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """macOS 上 RLIMIT_AS 不生效：preexec 内 setrlimit 必败，必须先于 spawn fail closed。"""
    spawned: list[object] = []

    def _no_spawn(*_args: object, **_kwargs: object) -> None:
        spawned.append(1)
        raise AssertionError("spawned")

    monkeypatch.setattr(proctree.subprocess, "Popen", _no_spawn)
    monkeypatch.setattr(proctree.sys, "platform", "darwin")
    res = proctree.run_owned([sys.executable, "-c", "pass"], timeout=5.0, memory_bytes=4096)
    assert res.returncode is None
    assert res.ownership_complete is False
    assert res.termination_complete is True
    assert res.reason_codes == ("memory_limit_unavailable",)
    assert not spawned


def test_internal_error_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """「绝不抛」契约覆盖未知内部故障：impl 半路抛非 OSError → 转 internal_error 结局，
    所有权与终止都按未确认计（fail closed），绝不宣称受控。"""

    def _boom(cmd, *, timeout, env=None):  # noqa: ANN001
        raise ValueError("内部逻辑故障（模拟）")

    monkeypatch.setattr(proctree, "_run_owned_impl", _boom)
    res = proctree.run_owned([sys.executable, "-c", "pass"], timeout=5.0)
    assert res.returncode is None
    assert res.ownership_complete is False
    assert res.termination_complete is False
    assert "internal_error" in res.reason_codes


@pytest.mark.parametrize(
    "internal_error",
    [
        RuntimeError("communicate 内部故障（模拟）"),
        OSError("communicate OS 故障（模拟）"),
    ],
    ids=["runtime-error", "post-spawn-oserror"],
)
def test_posix_internal_error_after_spawn_kills_and_reaps_group(
    monkeypatch: pytest.MonkeyPatch, internal_error: Exception,
) -> None:
    """POSIX 已 setsid 并持有 pgid 后，即使 communicate 内部异常也必须 killpg + reap root。

    当前测试在 Windows 上把同一源码按 POSIX 分支加载，避免这条异常收口只等 Linux CI 才覆盖。
    """
    module_name = "_apkscan_proctree_posix_test"
    spec = importlib.util.spec_from_file_location(module_name, Path(proctree.__file__))
    assert spec is not None and spec.loader is not None
    posix = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, posix)
    with monkeypatch.context() as load_patch:
        load_patch.setattr(sys, "platform", "linux")
        spec.loader.exec_module(posix)

    from unittest.mock import Mock

    calls: list[tuple[str, object]] = []
    capture = Mock()
    capture.wait_for_root.side_effect = internal_error
    monkeypatch.setattr(posix, "_OutputPipes", lambda *_: capture)

    class _BrokenProc:
        pid = 4242
        returncode = None
        stdout = stderr = object()

        def wait(self, timeout: float | None = None) -> int:
            calls.append(("wait", timeout))
            self.returncode = -9
            return self.returncode

    monkeypatch.setattr(posix.subprocess, "Popen", lambda *args, **kwargs: _BrokenProc())
    monkeypatch.setattr(
        posix, "_posix_kill_group", lambda pgid: calls.append(("killpg", pgid))
    )

    result = posix.run_owned(["fake-jadx"], timeout=1.0)

    assert ("killpg", 4242) in calls, "异常路径丢失 pgid，进程组可能继续存活"
    assert any(kind == "wait" for kind, _value in calls), "直接子进程未被 reap"
    assert result.reason_codes == ("internal_error",)
    assert result.termination_complete is False
    capture.close.assert_called_once_with()


@pytest.mark.parametrize("older", [True, False])
def test_posix_access_denied_process_is_ignored_only_when_older(monkeypatch, older, request):
    from types import SimpleNamespace

    name = "_apkscan_proctree_access_test"
    spec = importlib.util.spec_from_file_location(name, Path(proctree.__file__))
    assert spec is not None and spec.loader is not None
    posix = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, posix)
    with monkeypatch.context() as loading:
        loading.setattr(sys, "platform", "linux")
        spec.loader.exec_module(posix)

    diagnostic = FirstFailureDiagnostic("ownership_access", getattr(request.config, "workerinput", {}).get("workerid", "master"))

    class Protected:
        pid = 4243
        def status(self):
            return psutil.STATUS_RUNNING
        def uids(self):
            return SimpleNamespace(real=1000)
        def environ(self):
            diagnostic.observe(stage="ownership_read", read_error="AccessDenied")
            raise psutil.AccessDenied(self.pid)
        def create_time(self):
            return time.time() - 100 if older else time.time() + 1
        def kill(self):
            pytest.fail("unverified unrelated process must never be killed")

    from unittest.mock import Mock

    capture = Mock()
    capture.wait_for_root.return_value = False
    capture.read_failed.is_set.return_value = capture.exceeded.is_set.return_value = False
    capture.finish.return_value = "success", ""
    monkeypatch.setattr(posix, "_OutputPipes", lambda *_: capture)

    class Child:
        pid = 4242
        returncode = 0
        stdout = stderr = object()

        def poll(self):
            return 0

    monkeypatch.setattr(posix.subprocess, "Popen", lambda *a, **kw: Child())
    monkeypatch.setattr(posix.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(posix.os, "getpgid", lambda pid: 9999, raising=False)
    monkeypatch.setattr(psutil, "process_iter", lambda *a: iter([Protected()]))
    monkeypatch.setattr(sys, "platform", "linux")
    with diagnostic:
        result = posix.run_owned(["synthetic"], timeout=1)
        assert result.returncode == 0 and result.stdout == "success"
        assert result.ownership_complete is True
        assert result.termination_complete is older
        assert result.reason_codes == (() if older else ("tree_state_unverified",))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux procfs dumpability")
def test_linux_preexisting_nondumpable_process_does_not_break_owned_run():
    import subprocess

    script = ("import ctypes,time;"
              "assert ctypes.CDLL(None).prctl(4,0,0,0,0)==0;"
              "print('ready',flush=True);time.sleep(120)")
    unrelated = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    try:
        assert unrelated.stdout is not None and unrelated.stdout.readline().strip() == "ready"
        try:
            psutil.Process(unrelated.pid).environ()
        except psutil.AccessDenied:
            pass
        else:
            pytest.skip("host can read nondumpable process; permission condition unavailable")
        time.sleep(1.1)  # Clearly older than run_owned's conservative creation cutoff.
        result = proctree.run_owned([sys.executable, "-c", "print('ok')"], timeout=5)
        assert result.returncode == 0 and result.stdout.strip() == "ok"
        assert result.termination_complete and not result.reason_codes, result
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_spawn_failure_reported_not_raised() -> None:
    """启动失败绝不抛：转 spawn_failed（POSIX 直接 Popen 失败）或门进程内失败（win32，
    命令不存在 → 门非零退出）——两个平台都必须**不抛且不宣称成功**。"""
    res = proctree.run_owned(["definitely-not-a-real-tool-xyz"], timeout=10.0)
    if sys.platform == "win32":
        # 门进程代跑：FileNotFoundError 在门内抛出 → 门非零退出，所有权与终止仍受控。
        assert res.ownership_complete is True
        assert res.returncode not in (0, None)
    else:
        assert res.ownership_complete is False
        assert "spawn_failed" in res.reason_codes


@pytest.mark.parametrize("completed, gone", [
    pytest.param(False, True, id="unverified-tree"),
    pytest.param(True, True, id="verified-tree-sleeper-gone"),
    pytest.param(True, False, id="verified-tree-sleeper-live"),
])
@pytest.mark.parametrize("events, expected_stage, expected_pair", [
    pytest.param((), "unknown", None, id="no-observation"),
    pytest.param(
        (("ownership_scan", "environ", "AccessDenied"),
         ("ownership_scan", "getpgid", "PermissionError")),
        "ownership_scan", ("environ", "AccessDenied"), id="first-allowed-pair",
    ),
    pytest.param(
        (("individual_signal", "environ", "AccessDenied"),
         ("ownership_scan", "getpgid", "PermissionError")),
        "individual_signal", None, id="signal-before-scan",
    ),
    pytest.param(
        (("ownership_scan", "private-probe-424242", "AccessDenied"),
         ("ownership_scan", "getpgid", "PermissionError")),
        "ownership_scan", None, id="first-probe-not-allowlisted",
    ),
    pytest.param(
        (("ownership_scan", "environ", "private-error-424242"),
         ("ownership_scan", "getpgid", "PermissionError")),
        "ownership_scan", None, id="first-error-not-allowlisted",
    ),
])
def test_descendant_failure_observation_precedes_fallback(
    monkeypatch, capsys, caplog, request, completed: bool, gone: bool,
    events: tuple[tuple[str, str, str], ...], expected_stage: str,
    expected_pair: tuple[str, str] | None,
) -> None:
    import subprocess  # No process is started by this contract test.
    from types import SimpleNamespace

    calls: list[str] = []

    def unavailable(_pid: int) -> None:
        calls.append("observe")
        raise psutil.AccessDenied(424242)

    def unexpected_spawn(*args, **kwargs):
        pytest.fail("the diagnostic contract must not spawn a process")

    reasons = ("descendants_after_root_exit",) if completed else (
        "descendants_after_root_exit", "tree_state_unverified",
    )
    result = SimpleNamespace(
        stdout="424242\n", ownership_complete=True, reason_codes=reasons,
        timed_out=False, forced_tree_kill=True, termination_complete=completed,
    )
    logger = proctree.logger
    template = "POSIX tree verification unavailable: stage=%s"

    def run_stub(*_args, **_kwargs):
        logger.debug(template, "unreviewed-stage-424242")
        logger.debug("POSIX tree verification unavailable: stage=ownership_scan")
        logger.debug("unreviewed event: %s", "individual_signal")
        for stage, probe, error in events:
            logger.debug(template, stage, extra={"posix_probe": probe, "posix_error": error})
        return result

    monkeypatch.setattr(proctree, "run_owned", run_stub)
    monkeypatch.setattr(subprocess, "Popen", unexpected_spawn)
    monkeypatch.setattr(psutil, "Process", unavailable)

    def sleeper_gone(_pid: int) -> bool:
        calls.append("check_sleeper")
        return gone

    monkeypatch.setitem(globals(), "_sleeper_gone", sleeper_gone)
    monkeypatch.setitem(globals(), "_kill_if_alive", lambda _pid: calls.append("cleanup"))

    with caplog.at_level(logging.INFO, logger=logger.name):
        initial_filters = tuple(logger.filters)
        if completed and gone:
            test_descendants_after_root_exit_force_killed(request)
            assert capsys.readouterr().err == ""
            assert calls == ["check_sleeper", "cleanup"]
        else:
            with pytest.raises(AssertionError):
                test_descendants_after_root_exit_force_killed(request)
            lines = capsys.readouterr().err.splitlines()
            assert len(lines) == 3 and lines[0].startswith("first-failure: ")
            assert lines[1] == "fixture-pid-before-cleanup: unreadable"
            assert lines[2] == f"observed-posix-tree-verification-stage: {expected_stage}"
            assert not any("424242" in line for line in lines)
            observation = json.loads(lines[0].removeprefix("first-failure: "))
            expected: dict[str, object] = {
                "test": "ownership_descendants",
                "worker": getattr(request.config, "workerinput", {}).get("workerid", "master"),
                "stage": "termination_check",
                "ownership": "confirmed",
                "read_error": "unknown",
                "reasons": list(reasons),
            }
            if not completed:
                expected["posix_verification_stage"] = expected_stage
                if expected_pair:
                    expected.update(posix_probe=expected_pair[0], posix_error=expected_pair[1])
            assert observation == expected
            assert calls == (["check_sleeper"] if completed else []) + ["observe", "cleanup"]
        assert logger.level == logging.INFO and tuple(logger.filters) == initial_filters
        assert not any(record.name == logger.name and record.levelno == logging.DEBUG
                       for record in caplog.records)


@pytest.mark.skipif(sys.platform != "linux", reason="POSIX Linux process scan")
@pytest.mark.parametrize(
    ("observations", "unverified"),
    [
        (("zombie",), False),
        (("gone",), False),
        (("denied",), True),
        (("running",), True),
        (("older",), False),
        (("zombie", "denied"), True),
        (("denied", "gone"), True),
    ],
)
def test_posix_scan_only_drops_confirmed_terminal_observations(
    monkeypatch, observations, unverified
):
    from types import SimpleNamespace

    pgid = 123

    class Observation:
        def __init__(self, pid, outcome):
            self.pid = pid
            self.outcome = outcome
            self.status_count = 0

        def status(self):
            self.status_count += 1
            if self.status_count == 1:
                return psutil.STATUS_RUNNING
            if self.outcome == "gone":
                raise psutil.NoSuchProcess(self.pid)
            if self.outcome == "denied":
                raise psutil.AccessDenied(self.pid)
            return psutil.STATUS_ZOMBIE if self.outcome == "zombie" else psutil.STATUS_RUNNING

        def uids(self):
            return SimpleNamespace(real=1000)

        def environ(self):
            raise psutil.AccessDenied(self.pid)

        def create_time(self):
            return 5.0 if self.outcome == "older" else 15.0

    monkeypatch.setattr(
        psutil, "process_iter",
        lambda attrs: [Observation(600 + i, o) for i, o in enumerate(observations)],
    )
    monkeypatch.setattr(
        proctree,
        "os",
        SimpleNamespace(getpid=lambda: 999, getuid=lambda: 1000, getpgid=lambda pid: 456),
    )
    monkeypatch.setattr(proctree, "_POSIX_TOKENS", {pgid: "synthetic"})
    monkeypatch.setattr(proctree, "_POSIX_STARTED", {pgid: 10.0})
    monkeypatch.setattr(proctree, "_POSIX_UNVERIFIED", set())

    assert not list(proctree._posix_owned_processes(pgid))

    assert (pgid in proctree._POSIX_UNVERIFIED) is unverified


@pytest.mark.skipif(sys.platform != "linux", reason="Linux ownership-token probe")
@pytest.mark.parametrize(("first_probe", "first_error"), [
    ("environ", "AccessDenied"),
    ("getpgid", "PermissionError"),
])
def test_posix_scan_logs_only_first_decisive_probe(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    first_probe: str,
    first_error: str,
) -> None:
    from types import SimpleNamespace

    pgid, own_uid = 987654320, 1000
    error_payload = "synthetic-private-process-name"
    error_path = "/synthetic/private/permission-path"
    env_token = "synthetic-private-ownership-token"
    denied_pids = {987654322, 987654323}

    def reject_real_access(*_args: object, **_kwargs: object) -> None:
        pytest.fail("the diagnostic contract must not inspect or start a real process")

    def getpgid(pid: int) -> int:
        if pid in denied_pids:
            raise PermissionError(13, error_payload, error_path)
        return 10

    def fake_process(pid: int, *, uid: int = own_uid, started: float = 11.0) -> SimpleNamespace:
        def read_environ() -> dict[str, str]:
            raise psutil.AccessDenied(pid, error_payload)

        return SimpleNamespace(
            pid=pid, status=lambda: psutil.STATUS_RUNNING, uids=lambda: SimpleNamespace(real=uid),
            create_time=lambda: started, environ=read_environ, kill=reject_real_access,
        )

    older = fake_process(987654324, started=9.0)
    other_uid = fake_process(987654323, uid=own_uid + 1)
    denied_environ = fake_process(987654321)
    denied_getpgid = fake_process(987654322)
    process_table = [older, other_uid]
    monkeypatch.setattr(psutil, "Process", reject_real_access)
    monkeypatch.setattr(psutil, "process_iter", lambda _attrs: iter(process_table))
    monkeypatch.setattr(proctree, "subprocess", SimpleNamespace(Popen=reject_real_access))
    monkeypatch.setattr(
        proctree, "os", SimpleNamespace(getpid=lambda: 1, getuid=lambda: own_uid, getpgid=getpgid),
    )
    monkeypatch.setattr(proctree, "_POSIX_TOKENS", {pgid: env_token})
    monkeypatch.setattr(proctree, "_POSIX_STARTED", {pgid: 10.0})
    monkeypatch.setattr(proctree, "_POSIX_UNVERIFIED", set())

    with caplog.at_level(logging.DEBUG, logger=proctree.logger.name):
        assert list(proctree._posix_owned_processes(pgid)) == []
        assert pgid not in proctree._POSIX_UNVERIFIED
        assert not caplog.records

    details: dict[str, str] = {}
    with observe_posix_verification_stage(details=details) as observed:
        process_table.extend(
            (denied_environ, denied_getpgid) if first_probe == "environ"
            else (denied_getpgid, denied_environ),
        )
        assert list(proctree._posix_owned_processes(pgid)) == []
        assert pgid in proctree._POSIX_UNVERIFIED
        process_table.reverse()
        assert list(proctree._posix_owned_processes(pgid)) == []
        assert observed() == "ownership_scan"
    assert details == {"posix_probe": first_probe, "posix_error": first_error}

    record, = caplog.records
    assert record.name == proctree.logger.name and record.levelno == logging.WARNING
    assert record.getMessage() == (
        f"POSIX tree verification unavailable: stage=ownership_scan probe={first_probe} error={first_error}"
    )
    default_keys = vars(logging.makeLogRecord({})).keys()
    extras = {
        key: value for key, value in vars(record).items()
        if key not in default_keys and key not in {"message", "asctime"}
    }
    assert extras == {"posix_probe": first_probe, "posix_error": first_error}
    assert record.exc_info is None and record.stack_info is None
    for raw in (error_payload, error_path, env_token, str(pgid), *(str(proc.pid) for proc in process_table)):
        assert raw not in caplog.text
