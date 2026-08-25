"""外部工具进程树所有权执行器：启动、限时、**整树终止**并验证无存活后代。

为什么单独一层：``subprocess.run(timeout=...)`` 超时只杀**直接子进程**。Windows 上 jadx 是
``jadx.bat``——直接子进程是 ``cmd.exe``，真正干活的 ``java``（及其后代）是孙进程，超时后
全部成为孤儿继续吃满 CPU/内存；POSIX 上同理只 SIGKILL 了 shell。取证批处理里这会把机器
拖死，且「工具还在偷偷跑」使清理与 receipt 都不可信。

实现（两条路径同一契约，结果落进 :class:`OwnedRun`）：

- **Windows**：Job Object + 门进程（gate）。先启动一个阻塞读 stdin 的极小 Python 门进程，
  把它 assign 进带 ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` 的 Job，**assign 成功后**才把真实
  命令写给它执行——门在收到命令前不产生任何子进程，故 ``gate -> cmd.exe -> java -> 后代``
  必然全员入 Job，不存在「先启动后入组」的竞态窗口。超时 ``TerminateJobObject`` 一击整树，
  并轮询 Job 计数确认归零。assign 失败则**不放行**（fail closed：宁可不跑，不跑无主 JVM）。
- **POSIX**：``start_new_session=True`` 新进程组（setsid 在 exec 前完成，同样无竞态），
  超时 ``killpg(SIGKILL)``，随后扫描进程组确认无存活成员。已知边界：后代若自行调用
  ``setsid()/setpgid()`` 脱离进程组则不可见也杀不到（覆盖协作式工具链如 jadx/java；对抗性
  逃逸需 cgroup/PID namespace，超出本层）。

两条路径在命令正常退出后都**再查一次是否有残留后代**：根进程退出但后代仍在（脱管的
daemon 化 java）时强杀整树并在 ``reason_codes`` 记 ``descendants_after_root_exit``——
这种运行不得算作完整覆盖。

绝不抛（OS 级启动失败转 ``spawn_failed``）；输出统一 utf-8/replace 解码。
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass

from apkscan.core.redact import safe_exception_text

logger = logging.getLogger(__name__)

#: 门进程放弃码：stdin 在收到命令前就 EOF（父进程 assign 失败后主动收口）→ 未执行任何命令。
_GATE_ABORT_EXIT = 250

#: 门进程源码（单行、无换行，规避命令行换行转义差异）。收到一行 JSON 命令前不 spawn 任何
#: 子进程；EOF → 以 _GATE_ABORT_EXIT 退出。子进程继承门的 stdout/stderr（即父进程的管道）。
_GATE_SOURCE = (
    "import json,subprocess,sys;"
    "line=sys.stdin.buffer.readline();"
    "sys.exit(250) if not line.strip() else "
    "sys.exit(subprocess.Popen(json.loads(line)).wait())"
)

#: 终止后确认无存活的轮询预算（秒）与间隔。内核回收进程通常毫秒级；5s 是几个数量级的余量。
_QUIESCE_BUDGET = 5.0
_QUIESCE_INTERVAL = 0.05

#: 超时强杀后排空输出管道的兜底预算（秒）：整树已死、管道理应立即 EOF，此值仅防病态挂起。
_DRAIN_BUDGET = 15.0

#: root 正常退出后「是否有脱管后代」判定的宽限（秒）：Job 计数递减/进程表收割与
#: 根进程对象 signaled 之间没有全序保证，立即单次读数会把毫秒级残影误判成脱管后代
#: （CI Windows runner 实测复现）。真脱管后代长驻，宽限不会把它等成不存在。
_ROOT_EXIT_GRACE = 1.0


@dataclass(frozen=True)
class OwnedRun:
    """一次受控执行的完整结局（确定性字段，可直接进 receipt；不含 PID/耗时/临时路径）。"""

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    #: 是否从头到尾拥有整棵进程树（Windows=Job assign 成功；POSIX=新进程组建立）。
    ownership_complete: bool
    #: 结束时（无论正常/超时/强杀）是否已确认无存活后代。
    termination_complete: bool
    #: 根进程正常退出但仍有后代存活、被本层强杀 → True（该次运行不得算完整覆盖）。
    forced_tree_kill: bool
    reason_codes: tuple[str, ...]


class _SpawnFailed(RuntimeError):
    """仅表示 ``Popen`` 本身失败；进程启动后的异常不得冒充启动失败。"""


def _codes(*items: str) -> tuple[str, ...]:
    return tuple(sorted(set(c for c in items if c)))


def run_owned(
    cmd: list[str], *, timeout: float, env: dict[str, str] | None = None
) -> OwnedRun:
    """执行 ``cmd``，限时 ``timeout`` 秒，保证进程树被拥有并在结束时整树终止。绝不抛。"""
    try:
        return _run_owned_impl(cmd, timeout=timeout, env=env)
    except _SpawnFailed as exc:
        logger.exception("[proctree] 启动失败：%s", cmd[:1])
        return OwnedRun(
            returncode=None, stdout="", stderr=safe_exception_text(exc), timed_out=False,
            ownership_complete=False, termination_complete=True,
            forced_tree_kill=False, reason_codes=_codes("spawn_failed"),
        )
    except Exception as exc:  # noqa: BLE001 — 「绝不抛」是契约：未知内部故障也转结局。
        # 走到这里说明 impl 在启动后半路失败：进程可能已存在（Windows 的 KILL_ON_JOB_CLOSE
        # 会在 impl 的 finally 关句柄时兜底清树；POSIX 无此兜底）。fail closed：
        # 所有权与终止都按「未确认」计，绝不宣称受控。
        logger.exception("[proctree] 内部故障（fail closed，按未确认定性）：%s", cmd[:1])
        return OwnedRun(
            returncode=None, stdout="", stderr=safe_exception_text(exc), timed_out=False,
            ownership_complete=False, termination_complete=False,
            forced_tree_kill=False, reason_codes=_codes("internal_error"),
        )


def _drain(proc: subprocess.Popen) -> tuple[str, str]:
    """强杀后排空输出管道（整树已死理应立即 EOF；兜底限时防病态挂起）。"""
    try:
        return proc.communicate(timeout=_DRAIN_BUDGET)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            return proc.communicate(timeout=_DRAIN_BUDGET)
        except subprocess.TimeoutExpired:
            return "", ""


if sys.platform == "win32":
    # -----------------------------------------------------------------------
    # Windows：Job Object + 门进程
    # -----------------------------------------------------------------------
    import ctypes
    import ctypes.wintypes as wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    _JobObjectExtendedLimitInformation = 9
    _JobObjectBasicAccountingInformation = 1
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_TERMINATE = 0x0001

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),  # ULONG_PTR（值，不是指针）
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", wintypes.LARGE_INTEGER),
            ("TotalKernelTime", wintypes.LARGE_INTEGER),
            ("ThisPeriodTotalUserTime", wintypes.LARGE_INTEGER),
            ("ThisPeriodTotalKernelTime", wintypes.LARGE_INTEGER),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    # ★显式声明 WinAPI 原型：不声明时 ctypes 默认按 c_int（32 位）传参/取返回值——
    #   HANDLE 是指针宽度，64 位进程里默认约定属未定义行为（实践上内核句柄虽只用低
    #   32 位，仍不该赌）。声明后 ctypes 负责正确的宽度与符号扩展。
    _kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD
    )
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.QueryInformationJobObject.argtypes = (
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    _kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL

    def _create_kill_on_close_job() -> int | None:
        """建 Job 并置 KILL_ON_JOB_CLOSE（父进程崩溃时句柄关闭 → 整树兜底清理）。失败 → None。"""
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            logger.error("[proctree] CreateJobObjectW 失败：%d", ctypes.get_last_error())
            return None
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = _kernel32.SetInformationJobObject(
            job, _JobObjectExtendedLimitInformation,
            ctypes.byref(info), ctypes.sizeof(info),
        )
        if not ok:
            logger.error(
                "[proctree] SetInformationJobObject 失败：%d", ctypes.get_last_error()
            )
            _kernel32.CloseHandle(job)
            return None
        return job

    def _assign_pid_to_job(job: int, pid: int) -> bool:
        hproc = _kernel32.OpenProcess(
            _PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid
        )
        if not hproc:
            logger.error("[proctree] OpenProcess(%d) 失败：%d", pid, ctypes.get_last_error())
            return False
        try:
            if not _kernel32.AssignProcessToJobObject(job, hproc):
                logger.error(
                    "[proctree] AssignProcessToJobObject 失败：%d", ctypes.get_last_error()
                )
                return False
            return True
        finally:
            _kernel32.CloseHandle(hproc)

    def _job_active_processes(job: int) -> int | None:
        acct = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        ok = _kernel32.QueryInformationJobObject(
            job, _JobObjectBasicAccountingInformation,
            ctypes.byref(acct), ctypes.sizeof(acct), None,
        )
        if not ok:
            logger.error(
                "[proctree] QueryInformationJobObject 失败：%d", ctypes.get_last_error()
            )
            return None
        return int(acct.ActiveProcesses)

    def _job_wait_quiesce(job: int) -> bool:
        """轮询 Job 计数直到 ActiveProcesses==0；查询失败按「未确认」计（fail closed）。"""
        deadline = time.monotonic() + _QUIESCE_BUDGET
        while time.monotonic() < deadline:
            active = _job_active_processes(job)
            if active == 0:
                return True
            time.sleep(_QUIESCE_INTERVAL)
        return _job_active_processes(job) == 0

    def _job_active_after_grace(job: int) -> int | None:
        """root 退出后读 Job 活跃数：宽限内轮询，归零即干净退出；宽限后仍 >0 才算脱管。"""
        deadline = time.monotonic() + _ROOT_EXIT_GRACE
        while True:
            active = _job_active_processes(job)
            if active == 0 or active is None or time.monotonic() >= deadline:
                return active
            time.sleep(_QUIESCE_INTERVAL)

    def _run_owned_impl(
        cmd: list[str], *, timeout: float, env: dict[str, str] | None
    ) -> OwnedRun:
        job = _create_kill_on_close_job()
        # ★门进程必须用 base 解释器，不能用 sys.executable：uv 建的 venv 里
        #   Scripts\python.exe 是 trampoline 启动器——真解释器是它的**子进程**，而
        #   AssignProcessToJobObject 不追溯已存在的子进程。用 trampoline 起门时，
        #   「assign trampoline」与「trampoline spawn 真解释器」存在竞态：输了则真门
        #   及其整棵后代树都在 Job 外，所有权静默失守（本机实测 Popen.pid ≠ 门内
        #   os.getpid()）。base 解释器的 exe 就是解释器本体，Popen.pid 即门自身，
        #   assign 后才写命令的无竞态保证重新成立。门只用 stdlib，不需要 venv site。
        gate_exe = getattr(sys, "_base_executable", None) or sys.executable
        gate_cmd = [gate_exe, "-I", "-c", _GATE_SOURCE]
        try:
            proc = subprocess.Popen(
                gate_cmd, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                text=True, encoding="utf-8", errors="replace",
            )
        except OSError as exc:
            # 只有门进程 Popen 本身失败才是 spawn_failed；启动后的 OSError 必须走
            # internal_error，不能在清理未确认时伪造 termination_complete=True。
            if job is not None:
                _kernel32.CloseHandle(job)
            raise _SpawnFailed(safe_exception_text(exc)) from exc
        except Exception:
            # 门进程都没起来：先归还 Job 句柄再交由 run_owned 保守定性，
            # 不留无主内核对象。只有上面的 Popen OSError 才明确属于 spawn_failed。
            if job is not None:
                _kernel32.CloseHandle(job)
            raise
        assert proc.stdin is not None
        timed_out = False
        forced = False
        owned = False
        reasons: list[str] = []
        try:
            if job is not None and _assign_pid_to_job(job, proc.pid):
                owned = True
            if not owned:
                # fail closed：门未入 Job 就不放行命令。关 stdin → 门读到 EOF 自退，
                # 不产生任何子进程；本次执行按 job_assignment_failed 定性。
                reasons.append("job_assignment_failed")
                proc.stdin.close()
                stdout, stderr = _drain(proc)
                return OwnedRun(
                    returncode=None, stdout=stdout, stderr=stderr, timed_out=False,
                    ownership_complete=False, termination_complete=True,
                    forced_tree_kill=False, reason_codes=_codes(*reasons),
                )
            assert job is not None  # owned=True 蕴含 job 建立成功
            payload = json.dumps(cmd, ensure_ascii=False) + "\n"
            try:
                stdout, stderr = proc.communicate(input=payload, timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                reasons.append("timeout")
                _kernel32.TerminateJobObject(job, 1)
                stdout, stderr = _drain(proc)
            if not timed_out:
                # 门（含其子命令）已退出：宽限后 Job 计数仍 >0 说明有脱管后代 → 强杀整树。
                active = _job_active_after_grace(job)
                if active is None:
                    reasons.append("tree_state_unverified")
                elif active > 0:
                    forced = True
                    reasons.append("descendants_after_root_exit")
                    _kernel32.TerminateJobObject(job, 1)
            terminated = _job_wait_quiesce(job)
            if not terminated:
                reasons.append("survivors_after_kill")
            returncode: int | None = None if timed_out else proc.returncode
            if returncode == _GATE_ABORT_EXIT:
                # 理论不可达（owned 才发命令），防御性定性为放弃执行。
                reasons.append("gate_aborted")
                returncode = None
            return OwnedRun(
                returncode=returncode, stdout=stdout, stderr=stderr,
                timed_out=timed_out, ownership_complete=owned,
                termination_complete=terminated, forced_tree_kill=forced,
                reason_codes=_codes(*reasons),
            )
        finally:
            if job is not None:
                _kernel32.CloseHandle(job)  # KILL_ON_JOB_CLOSE：兜底再清一次

else:
    # -----------------------------------------------------------------------
    # POSIX：新进程组 + killpg
    # -----------------------------------------------------------------------
    import os
    import signal

    def _posix_group_pids(pgid: int) -> list[int]:
        """当前仍存活的该进程组成员 PID（排除自身；权限/竞态消失的按不存在处理）。"""
        import psutil

        alive: list[int] = []
        for proc in psutil.process_iter(["pid"]):
            pid = proc.info["pid"]
            if pid == os.getpid():
                continue
            try:
                if os.getpgid(pid) == pgid:
                    alive.append(pid)
            except (ProcessLookupError, PermissionError, OSError):
                continue
        return alive

    def _posix_kill_group(pgid: int) -> None:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass  # 组已空/权限异常 → 交由下方存活验证定性，不在这里掩盖

    def _posix_wait_quiesce(pgid: int) -> bool:
        deadline = time.monotonic() + _QUIESCE_BUDGET
        while time.monotonic() < deadline:
            if not _posix_group_pids(pgid):
                return True
            time.sleep(_QUIESCE_INTERVAL)
        return not _posix_group_pids(pgid)

    def _posix_pids_after_grace(pgid: int) -> list[int]:
        """root 退出后查组内存活：宽限内轮询（孙进程被 init 收养后的收割是异步的，
        立查会把待收割僵尸误判成脱管后代）；宽限后仍非空才算真脱管。"""
        deadline = time.monotonic() + _ROOT_EXIT_GRACE
        while True:
            pids = _posix_group_pids(pgid)
            if not pids or time.monotonic() >= deadline:
                return pids
            time.sleep(_QUIESCE_INTERVAL)

    def _run_owned_impl(
        cmd: list[str], *, timeout: float, env: dict[str, str] | None
    ) -> OwnedRun:
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                start_new_session=True, text=True, encoding="utf-8", errors="replace",
            )
        except OSError as exc:
            raise _SpawnFailed(safe_exception_text(exc)) from exc
        pgid = proc.pid  # setsid 后组长即子进程自身
        timed_out = False
        forced = False
        reasons: list[str] = []
        completed = False
        try:
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                reasons.append("timeout")
                _posix_kill_group(pgid)
                stdout, stderr = _drain(proc)
            if not timed_out:
                # 根已退出：宽限后仍有脱管后代才强杀整组，该次运行不算完整覆盖。
                if _posix_pids_after_grace(pgid):
                    forced = True
                    reasons.append("descendants_after_root_exit")
                    _posix_kill_group(pgid)
            terminated = _posix_wait_quiesce(pgid)
            if not terminated:
                reasons.append("survivors_after_kill")
            result = OwnedRun(
                returncode=None if timed_out else proc.returncode,
                stdout=stdout, stderr=stderr, timed_out=timed_out,
                ownership_complete=True, termination_complete=terminated,
                forced_tree_kill=forced, reason_codes=_codes(*reasons),
            )
            completed = True
            return result
        finally:
            if not completed:
                # Popen/setsid 已成功后，communicate、drain 或进程枚举仍可能抛出未知异常。
                # 此时外层会返回 internal_error；先在仍持有 pgid 时 best-effort 整组强杀并
                # reap 直接子进程，不能让错误转换本身制造孤儿 Java。
                try:
                    _posix_kill_group(pgid)
                except Exception:  # noqa: BLE001 - 清理不能遮蔽原始内部故障
                    logger.exception("[proctree] POSIX 异常收口 killpg 失败：pgid=%s", pgid)
                try:
                    proc.wait(timeout=_DRAIN_BUDGET)
                except Exception:  # noqa: BLE001 - 外层保留原始 internal_error
                    logger.exception("[proctree] POSIX 异常收口 reap 失败：pgid=%s", pgid)


__all__ = ["OwnedRun", "run_owned"]
