"""proctree 进程树所有权执行器：**真实**小 Python 进程树受控测试（不真跑 jadx）。

覆盖 B1 的 Windows/POSIX 终止语义：超时整树终止（含孙进程）、根退出后脱管后代被强杀、
所有权建立失败 fail closed、输出 utf-8 解码。超时用秒级预算，绝不真实等 120/200 秒。
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import psutil
import pytest

from apkscan.core import proctree

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
        assert res.returncode is None
        assert res.ownership_complete is True
        assert "timeout" in res.reason_codes
        assert res.termination_complete is True, "整树终止未获确认"
        if pid is not None:
            assert _sleeper_gone(pid), "孙进程在超时强杀后仍存活——孤儿 java 形态复现"
    finally:
        if pid is not None:
            _kill_if_alive(pid)  # 断言失败时不留真孤儿


def test_descendants_after_root_exit_force_killed() -> None:
    """根进程正常退出但孙进程脱管（daemon 化 java 形态）→ 检出、强杀整树、
    forced_tree_kill=True（该次运行不得算完整覆盖）。"""
    res = proctree.run_owned([sys.executable, "-c", _SPAWN_SLEEPER], timeout=30.0)
    pid = int(res.stdout.strip().splitlines()[0])
    try:
        assert res.timed_out is False
        assert res.forced_tree_kill is True
        assert "descendants_after_root_exit" in res.reason_codes
        assert res.termination_complete is True
        assert _sleeper_gone(pid), "脱管孙进程未被强杀"
    finally:
        _kill_if_alive(pid)


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

    calls: list[tuple[str, object]] = []

    class _BrokenProc:
        pid = 4242
        returncode = None

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            raise internal_error

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
