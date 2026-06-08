"""apkscan.gui.controller 单测：全 mock，**不构造 Tk**、**不起真子进程**（CI headless 安全）。

controller 已**子进程化**（卡死修复）：静态/一键/doctor 都 spawn 子进程跑 CLId，GUI 这边
只阻塞读子进程 stdout（I/O 释放 GIL，主线程不卡）。本测试因此 mock ``_run_subprocess``
（注入假退出码 + 调 on_line 喂几行假日志），并在 ``tmp_path`` 预写 report.json 验证
计数解析、report_paths/html_report/ok 由退出码 + report.json 存在共同判定。

覆盖（呼应 spec §6.1 改写项）：
  1. 子进程命令构造：frozen → exe 自调用；源码 → ``-m apkscan.cli``；各 subcmd 参数正确。
  2. stdout 流式回传：子进程每行经 on_line → 注入的 on_log。
  3. 跑完读 report.json 计数（端点/线索/发现）；report_paths/html_report 探测正确。
  4. 退出码非 0 → ok=False；report.json 不存在 → ok=False（即便退出码 0）。
  5. CREATE_NO_WINDOW：Windows 下 Popen 带隐藏控制台标志。
  6. 异常被吞成友好提示（ActionResult.ok=False），worker 不抛、run 不崩。
  7. busy / 并发拒绝 / 未选 APK 校验（与子进程化无关，行为不变）。

测试用同步 schedule（直接执行 fn），并用同步线程（monkeypatch threading.Thread）把
worker 拉到当前线程跑，避免依赖真实线程时序——既 headless 安全又确定性。
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from apkscan.gui import controller as ctrl_mod
from apkscan.gui.controller import (
    ACTION_AUTO,
    ACTION_DOCTOR,
    ACTION_STATIC,
    ActionRequest,
    ActionResult,
    GuiController,
)


# ---------------------------------------------------------------------------
# 同步执行替身：schedule 直接调 fn；Thread 在 start() 时同步跑 target（无真实线程）
# ---------------------------------------------------------------------------


class _SyncThread:
    """threading.Thread 的同步替身：start() 直接在当前线程执行 target，确定性。"""

    def __init__(self, target: Callable[..., None], args: tuple = (), **_: Any) -> None:
        self._target = target
        self._args = args

    def start(self) -> None:
        self._target(*self._args)


def _make_controller(
    monkeypatch: pytest.MonkeyPatch, confirm: Callable[[str], None] | None = None
) -> tuple[GuiController, list[str], list[ActionResult]]:
    """构造一个全同步的 controller，返回 (controller, logs, results)。"""
    monkeypatch.setattr(ctrl_mod.threading, "Thread", _SyncThread)
    logs: list[str] = []
    results: list[ActionResult] = []
    controller = GuiController(
        on_log=logs.append,
        on_done=results.append,
        schedule=lambda fn: fn(),  # 同步执行
        confirm=confirm,
    )
    return controller, logs, results


def _patch_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    *,
    returncode: int = 0,
    lines: list[str] | None = None,
) -> dict[str, Any]:
    """把 controller._run_subprocess 替成假实现：记录 argv、喂几行假日志、回指定退出码。

    返回一个 captures dict，断言用（captures["argv"] 即子进程命令行）。
    """
    captures: dict[str, Any] = {"argv": None, "called": False}
    fed = lines if lines is not None else []

    def _fake_run(self: GuiController, argv: list[str], on_line: Callable[[str], None]) -> int:
        captures["called"] = True
        captures["argv"] = argv
        for ln in fed:
            on_line(ln)
        return returncode

    monkeypatch.setattr(GuiController, "_run_subprocess", _fake_run)
    return captures


def _write_report_json(out_dir: Path, *, endpoints: int, leads: int, findings: int) -> None:
    """在 out_dir 下写一个最小 report.json，供计数解析。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(
        json.dumps(
            {
                "endpoints": list(range(endpoints)),
                "leads": list(range(leads)),
                "findings": list(range(findings)),
            }
        ),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# 1) 子进程命令构造（frozen vs 源码；各 subcmd 参数）
# ---------------------------------------------------------------------------


def test_subcmd_argv_source_uses_dash_m(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    controller, _logs, _results = _make_controller(monkeypatch)
    req = ActionRequest(
        action=ACTION_STATIC, apk_path="a.apk", out_dir="o", online=True, formats=["json", "html"]
    )
    argv = controller._subcmd_argv("analyze", req)
    assert argv[:4] == [sys.executable, "-m", "apkscan.cli", "analyze"]
    assert "a.apk" in argv
    assert "--online" in argv and "--offline" not in argv
    assert argv[argv.index("--out") + 1] == "o"
    assert argv[argv.index("--fmt") + 1] == "json,html"


def test_subcmd_argv_frozen_uses_exe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: True)
    controller, _logs, _results = _make_controller(monkeypatch)
    req = ActionRequest(action=ACTION_STATIC, apk_path="a.apk", out_dir="o", online=False)
    argv = controller._subcmd_argv("analyze", req)
    # frozen：exe 自调用——argv[0]=sys.executable、argv[1]=子命令（无 -m / apkscan.cli）。
    assert argv[0] == sys.executable
    assert argv[1] == "analyze"
    assert "-m" not in argv and "apkscan.cli" not in argv
    assert "--offline" in argv and "--online" not in argv


def test_subcmd_argv_doctor_fix_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    controller, _logs, _results = _make_controller(monkeypatch)
    fix = controller._subcmd_argv("doctor", ActionRequest(action=ACTION_DOCTOR, auto_fix=True))
    nofix = controller._subcmd_argv("doctor", ActionRequest(action=ACTION_DOCTOR, auto_fix=False))
    assert fix[-1] == "--fix"
    assert nofix[-1] == "--no-fix"


def test_subcmd_argv_auto_full_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    controller, _logs, _results = _make_controller(monkeypatch)
    req = ActionRequest(
        action=ACTION_AUTO,
        apk_path="x.apk",
        out_dir="d",
        online=True,
        auto_fix=False,
        capture_duration=30,
        formats=["html"],
    )
    argv = controller._subcmd_argv("auto", req)
    assert argv[:4] == [sys.executable, "-m", "apkscan.cli", "auto"]
    assert "x.apk" in argv
    assert "--online" in argv
    assert "--no-fix" in argv
    assert argv[argv.index("--duration") + 1] == "30"
    assert argv[argv.index("--out") + 1] == "d"
    assert argv[argv.index("--fmt") + 1] == "html"


# ---------------------------------------------------------------------------
# 2) stdout 流式回传 + 3) 计数解析 + report_paths/html_report
# ---------------------------------------------------------------------------


def test_static_runs_subprocess_streams_log_and_reads_counts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    _write_report_json(tmp_path, endpoints=3, leads=2, findings=1)
    (tmp_path / "report.html").write_text("<html></html>", encoding="utf-8")

    captures = _patch_subprocess(
        monkeypatch, returncode=0, lines=["加载 APK：a.apk", "运行分析流水线 ...", "端点总数：3"]
    )
    controller, logs, results = _make_controller(monkeypatch)
    req = ActionRequest(
        action=ACTION_STATIC, apk_path="a.apk", out_dir=str(tmp_path), online=True, formats=["html"]
    )
    assert controller.start(req) is True

    # 子进程被起；命令是 analyze（不是 auto），且不含 --dynamic（纯静态）。
    assert captures["called"] is True
    argv = captures["argv"]
    assert argv[3] == "analyze"
    assert "--dynamic" not in argv
    # stdout 每行流式回到 on_log。
    assert "加载 APK：a.apk" in logs
    assert "端点总数：3" in logs

    res = results[0]
    assert res.action == ACTION_STATIC
    assert res.ok is True
    # 计数从 report.json 解析。
    assert (res.counts.endpoints, res.counts.leads, res.counts.findings) == (3, 2, 1)
    # report_paths 探测到 json + html；html_report 挑出 .html。
    assert any(p.endswith("report.json") for p in res.report_paths)
    assert res.html_report.endswith("report.html")
    assert res.out_dir == str(tmp_path)


def test_auto_runs_auto_subcommand(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    _write_report_json(tmp_path, endpoints=5, leads=0, findings=0)
    captures = _patch_subprocess(monkeypatch, returncode=0, lines=["===== 一键全自动 ====="])
    controller, logs, results = _make_controller(monkeypatch)
    req = ActionRequest(action=ACTION_AUTO, apk_path="x.apk", out_dir=str(tmp_path))
    assert controller.start(req) is True

    assert captures["argv"][3] == "auto"  # 一键走 auto 子命令
    assert "===== 一键全自动 =====" in logs
    res = results[0]
    assert res.ok is True
    assert res.counts.endpoints == 5


def test_doctor_runs_subprocess_ok_by_returncode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    captures = _patch_subprocess(monkeypatch, returncode=0, lines=["... 检查在线设备"])
    controller, logs, results = _make_controller(monkeypatch)
    assert controller.start(ActionRequest(action=ACTION_DOCTOR)) is True

    assert captures["argv"][3] == "doctor"
    assert "... 检查在线设备" in logs  # on_progress 流式回传
    res = results[0]
    assert res.action == ACTION_DOCTOR
    assert res.ok is True  # 退出码 0 → 体检通过


def test_doctor_nonzero_returncode_marks_not_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    _patch_subprocess(monkeypatch, returncode=1, lines=["[FAIL] 在线设备"])
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_DOCTOR))
    assert results[0].ok is False  # 体检有未通过关键项 → 退出码 1


# ---------------------------------------------------------------------------
# 4) ok 判定：退出码 + report.json 存在
# ---------------------------------------------------------------------------


def test_returncode_nonzero_marks_not_ok(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    _write_report_json(tmp_path, endpoints=1, leads=0, findings=0)  # 有报告
    _patch_subprocess(monkeypatch, returncode=2)  # 但退出码非 0
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path="a.apk", out_dir=str(tmp_path)))
    res = results[0]
    assert res.ok is False  # 有报告但退出码非 0 → 不算成功
    assert res.report_paths  # 报告路径仍被探测/上报


def test_no_report_json_marks_not_ok_even_if_returncode_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    # 只有 html、无 json（如 --fmt html）→ 没 report.json 则 ok=False（计数依赖 json）。
    (tmp_path / "report.html").write_text("<html></html>", encoding="utf-8")
    _patch_subprocess(monkeypatch, returncode=0)
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path="a.apk", out_dir=str(tmp_path)))
    res = results[0]
    assert res.ok is False
    assert res.counts.known is False


def test_counts_unknown_when_json_unreadable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "report.json").write_text("{ not valid json", encoding="utf-8")
    _patch_subprocess(monkeypatch, returncode=0)
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path="x.apk", out_dir=str(tmp_path)))
    res = results[0]
    assert res.counts.known is False  # 坏 JSON 不崩，计数未知
    # report.json 文件存在 → has_json=True、退出码 0 → ok=True（计数未知不影响 ok）。
    assert res.ok is True


# ---------------------------------------------------------------------------
# 5) CREATE_NO_WINDOW：真 _run_subprocess 走 Popen（mock Popen 断言 kwargs）
# ---------------------------------------------------------------------------


def test_run_subprocess_uses_pipe_and_no_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """直接测真 _run_subprocess：mock subprocess.Popen，断言 stdout=PIPE、合并 stderr、
    text 模式、Windows 下带 CREATE_NO_WINDOW；并验证逐行回传 + 返回退出码。"""
    captured: dict[str, Any] = {}

    class _FakeProc:
        def __init__(self) -> None:
            self.stdout = iter(["行1\n", "行2\n"])

        def wait(self) -> int:
            return 7

    def _fake_popen(argv: list[str], **kwargs: Any) -> _FakeProc:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _FakeProc()

    monkeypatch.setattr(ctrl_mod.subprocess, "Popen", _fake_popen)
    controller, _logs, _results = _make_controller(monkeypatch)

    lines: list[str] = []
    rc = controller._run_subprocess(["py", "x"], lines.append)

    assert rc == 7
    assert lines == ["行1", "行2"]  # rstrip 换行后逐行回传
    kw = captured["kwargs"]
    assert kw["stdout"] is subprocess.PIPE
    assert kw["stderr"] is subprocess.STDOUT  # 合并 stderr 到 stdout
    assert kw["text"] is True
    if sys.platform == "win32":
        assert kw["creationflags"] == subprocess.CREATE_NO_WINDOW
    else:
        assert kw["creationflags"] == 0


# ---------------------------------------------------------------------------
# 6) 异常被吞成友好结果（worker 不抛、run 不崩）
# ---------------------------------------------------------------------------


def test_subprocess_exception_becomes_friendly_error_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)

    def _boom(self: GuiController, argv: list[str], on_line: Callable[[str], None]) -> int:
        raise FileNotFoundError("子进程起不来")

    monkeypatch.setattr(GuiController, "_run_subprocess", _boom)
    controller, _logs, results = _make_controller(monkeypatch)

    # 不应抛。
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path="x.apk"))
    res = results[0]
    assert res.ok is False
    assert "出错" in res.message  # 友好提示而非 traceback
    assert controller.busy is False  # 异常后 busy 复位


# ---------------------------------------------------------------------------
# 7) busy / 并发拒绝 / 入参校验（与子进程化无关，行为不变）
# ---------------------------------------------------------------------------


def test_busy_true_during_run_and_reset_after(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    seen_busy: list[bool] = []

    def _fake_run(self: GuiController, argv: list[str], on_line: Callable[[str], None]) -> int:
        seen_busy.append(controller.busy)  # 动作执行中 busy 应为 True
        return 0

    monkeypatch.setattr(GuiController, "_run_subprocess", _fake_run)
    controller, _logs, _results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_DOCTOR))

    assert seen_busy == [True]
    assert controller.busy is False  # 结束后复位


def test_concurrent_start_rejected_while_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    second_accepted: list[bool] = []

    def _fake_run(self: GuiController, argv: list[str], on_line: Callable[[str], None]) -> int:
        second_accepted.append(controller.start(ActionRequest(action=ACTION_DOCTOR)))
        return 0

    monkeypatch.setattr(GuiController, "_run_subprocess", _fake_run)
    controller, _logs, _results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_DOCTOR))

    assert second_accepted == [False]  # 第二次被拒（busy 防护）


def test_static_without_apk_rejected_with_friendly_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller, _logs, results = _make_controller(monkeypatch)
    accepted = controller.start(ActionRequest(action=ACTION_STATIC, apk_path=""))
    assert accepted is False
    assert results[0].ok is False
    assert "请先选择" in results[0].message
    assert controller.busy is False


def test_auto_without_apk_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    controller, _logs, results = _make_controller(monkeypatch)
    assert controller.start(ActionRequest(action=ACTION_AUTO, apk_path="")) is False
    assert results[0].ok is False


def test_doctor_without_apk_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    _patch_subprocess(monkeypatch, returncode=0)
    controller, _logs, results = _make_controller(monkeypatch)
    assert controller.start(ActionRequest(action=ACTION_DOCTOR, apk_path="")) is True
    assert results[0].action == ACTION_DOCTOR


def test_unknown_action_friendly(monkeypatch: pytest.MonkeyPatch) -> None:
    controller, _logs, results = _make_controller(monkeypatch)
    # 直接调内部 dispatch（start 不校验 action 取值）。
    controller.start(ActionRequest(action="bogus"))
    assert results[0].ok is False
    assert "未知动作" in results[0].message
