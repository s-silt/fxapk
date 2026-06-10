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
    FILE_TYPE_APK,
    FILE_TYPE_IPA,
    ActionRequest,
    ActionResult,
    GuiController,
    clamp_duration,
    resolve_out_dir,
    validate_apk_path,
    validate_ipa_path,
    validate_out_dir,
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


def _make_apk(tmp_path: Path, name: str = "app.apk") -> str:
    """在 tmp_path 写一个能过 validate_apk_path 的最小「APK」（.apk 后缀 + PK 魔数 + 非空）。

    start() 现在会校验 APK 路径存在/可读/像 APK（spec §2.3/§2.5），故子进程类用例需真文件。
    """
    p = tmp_path / name
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    return str(p)


def _make_ipa(tmp_path: Path, name: str = "app.ipa", *, with_payload: bool = True) -> str:
    """在 tmp_path 写一个能过 validate_ipa_path 的最小「IPA」（ZIP + 可选 Payload/）。"""
    import zipfile

    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as zf:
        if with_payload:
            zf.writestr("Payload/Demo.app/Info.plist", b"x")
        else:
            zf.writestr("foo.txt", b"bar")
    return str(p)


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
        capture_duration_raw="30",  # 字段改名（spec §2.1）：duration 由 controller 钳制
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


def test_subcmd_argv_analyze_ipa_uses_ipa_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """IPA 栏：analyze 子命令位置参取 ipa_path（而非 apk_path）；CLI load_app 自动分流。"""
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    controller, _logs, _results = _make_controller(monkeypatch)
    req = ActionRequest(
        action=ACTION_STATIC,
        file_type=FILE_TYPE_IPA,
        apk_path="should_not_use.apk",
        ipa_path="fraud.ipa",
        out_dir="o",
        online=False,
    )
    argv = controller._subcmd_argv("analyze", req)
    assert argv[3] == "analyze"
    assert "fraud.ipa" in argv  # 用 ipa_path
    assert "should_not_use.apk" not in argv  # 不用 apk_path
    assert "--offline" in argv
    assert "--dynamic" not in argv  # IPA 纯静态


def test_action_request_target_path() -> None:
    """target_path 按 file_type 选路径：默认 apk，IPA 栏取 ipa_path。"""
    apk_req = ActionRequest(action=ACTION_STATIC, apk_path="a.apk", ipa_path="b.ipa")
    assert apk_req.file_type == FILE_TYPE_APK  # 默认 APK
    assert apk_req.target_path == "a.apk"
    ipa_req = ActionRequest(
        action=ACTION_STATIC, file_type=FILE_TYPE_IPA, apk_path="a.apk", ipa_path="b.ipa"
    )
    assert ipa_req.target_path == "b.ipa"


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
        action=ACTION_STATIC,
        apk_path=_make_apk(tmp_path),
        out_dir=str(tmp_path),
        online=True,
        formats=["html"],
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
    # out_dir 现已被 controller 绝对化（resolve）。
    assert res.out_dir == ctrl_mod.resolve_out_dir(str(tmp_path))


def test_auto_runs_auto_subcommand(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    _write_report_json(tmp_path, endpoints=5, leads=0, findings=0)
    captures = _patch_subprocess(monkeypatch, returncode=0, lines=["===== 一键全自动 ====="])
    controller, logs, results = _make_controller(monkeypatch)
    req = ActionRequest(action=ACTION_AUTO, apk_path=_make_apk(tmp_path), out_dir=str(tmp_path))
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
    apk = _make_apk(tmp_path)
    _patch_subprocess(monkeypatch, returncode=2)  # 但退出码非 0
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path=apk, out_dir=str(tmp_path)))
    res = results[0]
    assert res.ok is False  # 有报告但退出码非 0 → 不算成功
    assert res.report_paths  # 报告路径仍被探测/上报


def test_no_report_json_marks_not_ok_even_if_returncode_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    # 只有 html、无 json（如 --fmt html）→ 没 report.json 则 ok=False（计数依赖 json）。
    (tmp_path / "report.html").write_text("<html></html>", encoding="utf-8")
    apk = _make_apk(tmp_path)
    _patch_subprocess(monkeypatch, returncode=0)
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path=apk, out_dir=str(tmp_path)))
    res = results[0]
    assert res.ok is False
    assert res.counts.known is False


def test_counts_unknown_when_json_unreadable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "report.json").write_text("{ not valid json", encoding="utf-8")
    apk = _make_apk(tmp_path)
    _patch_subprocess(monkeypatch, returncode=0)
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path=apk, out_dir=str(tmp_path)))
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
    assert kw["stdin"] is subprocess.DEVNULL  # 不继承 stdin（防 frida/adb 交互卡读）
    if sys.platform == "win32":
        # CREATE_NO_WINDOW 隐藏控制台 + CREATE_NEW_PROCESS_GROUP 让取消能整树收割。
        assert kw["creationflags"] & subprocess.CREATE_NO_WINDOW
        assert kw["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP
        assert kw["start_new_session"] is False
    else:
        assert kw["creationflags"] == 0
        assert kw["start_new_session"] is True  # POSIX：独立进程组供整组收割


# ---------------------------------------------------------------------------
# 6) 异常被吞成友好结果（worker 不抛、run 不崩）
# ---------------------------------------------------------------------------


def test_subprocess_exception_becomes_friendly_error_not_raise(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)

    def _boom(self: GuiController, argv: list[str], on_line: Callable[[str], None]) -> int:
        raise FileNotFoundError("子进程起不来")

    monkeypatch.setattr(GuiController, "_run_subprocess", _boom)
    controller, _logs, results = _make_controller(monkeypatch)

    # 不应抛。用真 APK 过校验，确保异常发生在子进程阶段而非被前置校验挡掉。
    controller.start(
        ActionRequest(action=ACTION_STATIC, apk_path=_make_apk(tmp_path), out_dir=str(tmp_path))
    )
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


def test_ipa_static_runs_analyze_with_ipa_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """IPA 栏静态分析：start 校验 ipa_path → 子进程跑 analyze、位置参是 ipa_path。"""
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    _write_report_json(tmp_path, endpoints=2, leads=1, findings=1)
    ipa = _make_ipa(tmp_path)
    captures = _patch_subprocess(monkeypatch, returncode=0, lines=["类型：IPA(iOS)"])
    controller, logs, results = _make_controller(monkeypatch)
    assert (
        controller.start(
            ActionRequest(
                action=ACTION_STATIC,
                file_type=FILE_TYPE_IPA,
                ipa_path=ipa,
                out_dir=str(tmp_path),
            )
        )
        is True
    )
    argv = captures["argv"]
    assert argv[3] == "analyze"
    assert ipa in argv  # 位置参是 ipa_path
    assert "--dynamic" not in argv
    assert "类型：IPA(iOS)" in logs
    assert results[0].ok is True


def test_ipa_auto_rejected_friendly(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """IPA 栏点【一键全自动】→ 被挡（iOS 仅静态），友好文案、不起子进程。"""
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    captures = _patch_subprocess(monkeypatch, returncode=0)
    controller, _logs, results = _make_controller(monkeypatch)
    accepted = controller.start(
        ActionRequest(
            action=ACTION_AUTO,
            file_type=FILE_TYPE_IPA,
            ipa_path=_make_ipa(tmp_path),
            out_dir=str(tmp_path),
        )
    )
    assert accepted is False
    assert results[0].ok is False
    assert "仅支持静态分析" in results[0].message
    assert captures["called"] is False  # 不起子进程


def test_ipa_static_without_ipa_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """IPA 栏未选文件 → 用 IPA 校验器挡（友好「请先选择一个 IPA」）。"""
    controller, _logs, results = _make_controller(monkeypatch)
    accepted = controller.start(
        ActionRequest(action=ACTION_STATIC, file_type=FILE_TYPE_IPA, ipa_path="")
    )
    assert accepted is False
    assert results[0].ok is False
    assert "请先选择一个 IPA" in results[0].message
    assert controller.busy is False


def test_unknown_action_friendly(monkeypatch: pytest.MonkeyPatch) -> None:
    controller, _logs, results = _make_controller(monkeypatch)
    # 直接调内部 dispatch（start 不校验 action 取值）。
    controller.start(ActionRequest(action="bogus"))
    assert results[0].ok is False
    assert "未知动作" in results[0].message


# ===========================================================================
# 8) 防呆：APK 路径校验纯函数（headless，零 Tk，绝不抛）
# ===========================================================================


def test_validate_apk_path_empty() -> None:
    msg = validate_apk_path("")
    assert msg is not None
    assert "请先选择" in msg


def test_validate_apk_path_missing(tmp_path: Path) -> None:
    msg = validate_apk_path(str(tmp_path / "不存在.apk"))
    assert msg is not None
    assert "找不到这个文件" in msg


def test_validate_apk_path_is_dir(tmp_path: Path) -> None:
    sub = tmp_path / "adir"
    sub.mkdir()
    msg = validate_apk_path(str(sub))
    assert msg is not None
    assert "文件夹" in msg


def test_validate_apk_path_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty.apk"
    p.write_bytes(b"")
    msg = validate_apk_path(str(p))
    assert msg is not None
    assert "空的" in msg


def test_validate_apk_path_not_apk(tmp_path: Path) -> None:
    p = tmp_path / "thing.bin"
    p.write_bytes(b"NOTPK and some content")
    msg = validate_apk_path(str(p))
    assert msg is not None
    assert "不是一个 APK" in msg


def test_validate_apk_path_ok_by_magic(tmp_path: Path) -> None:
    # PK 魔数 + 非 .apk 后缀 → 放行（容忍改后缀 / 无后缀真 APK）。
    p = tmp_path / "renamed.bin"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 32)
    assert validate_apk_path(str(p)) is None


def test_validate_apk_path_ok_by_suffix(tmp_path: Path) -> None:
    # .apk 后缀 + 非空（即便头部非 PK）→ 放行。
    p = tmp_path / "app.apk"
    p.write_bytes(b"\x01\x02\x03\x04anything")
    assert validate_apk_path(str(p)) is None


# ===========================================================================
# 8b) 防呆：IPA 路径校验纯函数（iOS 栏，headless，零 Tk，绝不抛）
# ===========================================================================


def test_validate_ipa_path_empty() -> None:
    msg = validate_ipa_path("")
    assert msg is not None
    assert "请先选择" in msg


def test_validate_ipa_path_missing(tmp_path: Path) -> None:
    msg = validate_ipa_path(str(tmp_path / "不存在.ipa"))
    assert msg is not None
    assert "找不到这个文件" in msg


def test_validate_ipa_path_is_dir(tmp_path: Path) -> None:
    sub = tmp_path / "adir"
    sub.mkdir()
    msg = validate_ipa_path(str(sub))
    assert msg is not None
    assert "文件夹" in msg


def test_validate_ipa_path_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty.ipa"
    p.write_bytes(b"")
    msg = validate_ipa_path(str(p))
    assert msg is not None
    assert "空的" in msg


def test_validate_ipa_path_not_zip(tmp_path: Path) -> None:
    p = tmp_path / "thing.ipa"
    p.write_bytes(b"NOTPK and content")  # .ipa 后缀但非 ZIP → 挡（IPA 必是 ZIP 容器）
    msg = validate_ipa_path(str(p))
    assert msg is not None
    assert "不是一个 IPA" in msg


def test_validate_ipa_path_ok_by_suffix(tmp_path: Path) -> None:
    # .ipa 后缀 + 是 ZIP（即便无 Payload/）→ 放行（容忍/信任后缀）。
    assert validate_ipa_path(_make_ipa(tmp_path, "app.ipa", with_payload=False)) is None


def test_validate_ipa_path_ok_by_payload_no_suffix(tmp_path: Path) -> None:
    # 无 .ipa 后缀但 ZIP 内含 Payload/ → 放行（兜住改名/无后缀真 IPA）。
    assert validate_ipa_path(_make_ipa(tmp_path, "app.bin", with_payload=True)) is None


def test_validate_ipa_path_rejects_plain_apk(tmp_path: Path) -> None:
    # 普通 APK/ZIP（无 .ipa 后缀、无 Payload/）→ 挡在 iOS 栏外，避免误投。
    msg = validate_ipa_path(_make_apk(tmp_path, "app.apk"))  # PK 魔数但非 ipa、无 Payload
    assert msg is not None
    assert "未找到 Payload" in msg


# ===========================================================================
# 9) 防呆：duration 钳制（空/非数字/越界，绝不抛）
# ===========================================================================


def test_clamp_duration() -> None:
    assert clamp_duration("5") == 10  # 低于下限钳到 10
    assert clamp_duration("9999") == 600  # 超上限钳到 600
    assert clamp_duration("") == 60  # 空 → default
    assert clamp_duration("abc") == 60  # 非数字 → default
    assert clamp_duration("60") == 60  # 正常值原样
    assert clamp_duration(" 30 ") == 30  # 带空白 → strip 后解析
    assert clamp_duration("10") == 10  # 边界值原样
    assert clamp_duration("600") == 600  # 边界值原样


# ===========================================================================
# 10) 防呆：输出目录绝对化 + 可写校验
# ===========================================================================


def test_resolve_out_dir_absolute() -> None:
    import os

    resolved = resolve_out_dir("out")
    assert os.path.isabs(resolved)
    assert resolved == str(Path("out").resolve())


def test_resolve_out_dir_empty_defaults_to_out() -> None:
    import os

    resolved = resolve_out_dir("")
    assert os.path.isabs(resolved)
    assert resolved.endswith("out")


def test_validate_out_dir_creatable(tmp_path: Path) -> None:
    sub = tmp_path / "newsub" / "deep"
    assert validate_out_dir(str(sub)) is None
    assert sub.is_dir()  # 校验顺手创建（受控副作用）


def test_validate_out_dir_existing_writable(tmp_path: Path) -> None:
    assert validate_out_dir(str(tmp_path)) is None


def test_validate_out_dir_unwritable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _boom_mkdir(self: Path, *args: Any, **kwargs: Any) -> None:
        raise PermissionError("只读磁盘")

    monkeypatch.setattr(Path, "mkdir", _boom_mkdir)
    msg = validate_out_dir(str(tmp_path / "cannot_create"))
    assert msg is not None
    assert "无法创建/写入" in msg


def test_validate_out_dir_blocked_by_file(tmp_path: Path) -> None:
    # 目标位置被同名文件占用 → 友好文案（非目录）。
    f = tmp_path / "occupied"
    f.write_text("x", encoding="utf-8")
    msg = validate_out_dir(str(f))
    assert msg is not None


def test_resolve_out_dir_nul_path_does_not_raise() -> None:
    """含 NUL 的路径 Path.resolve() 抛 ValueError（非 OSError）→ resolve_out_dir 须**返回不抛**。

    守「绝不抛」契约：粘贴构造路径可塞进 NUL，逃逸的 ValueError 会崩 UI 回调。
    """
    bad = "C:\\bad\x00dir"
    result = resolve_out_dir(bad)  # 不抛即通过
    assert isinstance(result, str)
    assert result == bad  # resolve 失败退回原串


def test_validate_out_dir_nul_path_does_not_raise() -> None:
    """含 NUL 的路径 → validate_out_dir 须**返回友好文案不抛**（exists/stat 也会抛 ValueError）。"""
    msg = validate_out_dir("C:\\bad\x00dir")  # 不抛即通过
    assert msg is not None
    assert "无法创建/写入" in msg


# ===========================================================================
# 11) 防呆：start() 集成校验（坏 APK / 坏输出目录被挡、out_dir 绝对化、duration 钳制进 argv）
# ===========================================================================


def test_start_rejects_missing_apk(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captures = _patch_subprocess(monkeypatch, returncode=0)
    controller, _logs, results = _make_controller(monkeypatch)
    accepted = controller.start(
        ActionRequest(action=ACTION_STATIC, apk_path=str(tmp_path / "missing.apk"))
    )
    assert accepted is False
    assert results[0].ok is False
    assert "找不到这个文件" in results[0].message
    assert controller.busy is False
    assert captures["called"] is False  # 坏 APK 不被甩给子进程


def test_start_rejects_unwritable_out(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captures = _patch_subprocess(monkeypatch, returncode=0)

    def _reject(out_dir: str) -> str:
        return "无法创建/写入输出目录（测试模拟只读）。"

    monkeypatch.setattr(ctrl_mod, "validate_out_dir", _reject)
    controller, _logs, results = _make_controller(monkeypatch)
    accepted = controller.start(
        ActionRequest(
            action=ACTION_STATIC, apk_path=_make_apk(tmp_path), out_dir=str(tmp_path / "x")
        )
    )
    assert accepted is False
    assert results[0].ok is False
    assert "无法创建/写入" in results[0].message
    assert captures["called"] is False  # 坏输出目录不起子进程


def test_start_absolutizes_out_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import os

    _write_report_json(tmp_path, endpoints=1, leads=0, findings=0)
    captures = _patch_subprocess(monkeypatch, returncode=0)
    controller, _logs, results = _make_controller(monkeypatch)
    # 传相对 out（在 tmp_path 下临时切 cwd，避免污染仓库）。
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        accepted = controller.start(
            ActionRequest(action=ACTION_STATIC, apk_path=_make_apk(tmp_path), out_dir="relout")
        )
    finally:
        os.chdir(cwd)
    assert accepted is True
    argv = captures["argv"]
    out_val = argv[argv.index("--out") + 1]
    assert os.path.isabs(out_val)  # 传给子进程的 --out 已绝对化
    assert os.path.isabs(results[0].out_dir)  # 结果 out_dir 也绝对


def test_auto_duration_clamped_in_argv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _write_report_json(tmp_path, endpoints=1, leads=0, findings=0)
    apk = _make_apk(tmp_path)

    captures = _patch_subprocess(monkeypatch, returncode=0)
    controller, _logs, _results = _make_controller(monkeypatch)
    controller.start(
        ActionRequest(
            action=ACTION_AUTO, apk_path=apk, out_dir=str(tmp_path), capture_duration_raw="9999"
        )
    )
    argv = captures["argv"]
    assert argv[argv.index("--duration") + 1] == "600"  # 越界钳到上限

    captures2 = _patch_subprocess(monkeypatch, returncode=0)
    controller2, _logs2, _results2 = _make_controller(monkeypatch)
    controller2.start(
        ActionRequest(
            action=ACTION_AUTO, apk_path=apk, out_dir=str(tmp_path), capture_duration_raw="abc"
        )
    )
    argv2 = captures2["argv"]
    assert argv2[argv2.index("--duration") + 1] == "60"  # 非数字 → default


# ===========================================================================
# 12) 防呆：取消 / 停止（terminate 子进程 + 回友好「已取消」结果）
# ===========================================================================


def test_cancel_no_run_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    controller, _logs, _results = _make_controller(monkeypatch)
    assert controller.cancel() is False  # 没在跑 → False，无副作用
    assert controller.stop() is False  # stop 是 cancel 别名


def test_cancel_sets_flag_and_worker_returns_cancelled_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """子进程跑时被取消 → worker 据 _cancelled 覆盖为友好「已取消」结果。"""
    _write_report_json(tmp_path, endpoints=1, leads=0, findings=0)

    def _fake_run(self: GuiController, argv: list[str], on_line: Callable[[str], None]) -> int:
        # 模拟「跑到一半被 cancel」：置取消标志后返回非 0（terminate 后退出码通常非 0）。
        self._cancelled.set()
        return 1

    monkeypatch.setattr(GuiController, "_run_subprocess", _fake_run)
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(
        ActionRequest(action=ACTION_STATIC, apk_path=_make_apk(tmp_path), out_dir=str(tmp_path))
    )
    res = results[0]
    assert res.cancelled is True
    assert res.ok is False
    assert res.message == "已取消本次任务。"
    assert controller.busy is False


def test_cancel_during_subprocess_exception_still_friendly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """取消-异常竞态：取消已置标志时子进程拆卸抛异常 → 仍回友好「已取消」（不弹 warning）。

    硬杀子进程时读流 / 回调链路偶发抛异常会落到 worker 的 except；若 _cancelled 已置，应按
    「已取消」语义处理，而非吓人的「运行出错」。
    """
    _write_report_json(tmp_path, endpoints=1, leads=0, findings=0)

    def _boom_after_cancel(
        self: GuiController, argv: list[str], on_line: Callable[[str], None]
    ) -> int:
        self._cancelled.set()  # 取消已发生
        raise OSError("管道被 terminate 强制关闭")  # 拆卸阶段抛异常

    monkeypatch.setattr(GuiController, "_run_subprocess", _boom_after_cancel)
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(
        ActionRequest(action=ACTION_STATIC, apk_path=_make_apk(tmp_path), out_dir=str(tmp_path))
    )
    res = results[0]
    assert res.cancelled is True  # 异常 + 已取消 → 按已取消处理
    assert res.message == "已取消本次任务。"  # 不是「运行出错」
    assert controller.busy is False


def test_late_cancel_does_not_mislabel_successful_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """迟到取消竞态：子进程已成功跑完（rc=0 + report.json），随后 _cancelled 被置 → 仍保留
    成功结果（含 html_report / 打开按钮），**不**被误覆盖成「已取消」。

    复现 _run_subprocess.finally 已置 _proc=None、_run_worker.finally 未置 busy=False 的窄窗内
    点【停止】：cancel() 见 busy=True 置标志却没杀到进程，子进程其实已成功。worker 应据
    `not result.ok` 保留成功结果而非丢掉报告入口。
    """
    _write_report_json(tmp_path, endpoints=2, leads=1, findings=0)
    (tmp_path / "report.html").write_text("<html></html>", encoding="utf-8")

    def _success_then_cancel(
        self: GuiController, argv: list[str], on_line: Callable[[str], None]
    ) -> int:
        # 子进程成功跑完（rc=0），返回后 _cancelled 才被置（模拟迟到的【停止】点击）。
        self._cancelled.set()
        return 0

    monkeypatch.setattr(GuiController, "_run_subprocess", _success_then_cancel)
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(
        ActionRequest(action=ACTION_STATIC, apk_path=_make_apk(tmp_path), out_dir=str(tmp_path))
    )
    res = results[0]
    assert res.ok is True  # 真成功被保留，未被「已取消」覆盖
    assert res.cancelled is False  # 不标记为取消（否则 view 不亮报告按钮）
    assert res.html_report.lower().endswith("report.html")  # 报告入口仍在
    assert res.counts.endpoints == 2  # 计数仍在
    assert controller.busy is False


def test_uncancelled_subprocess_exception_is_run_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """对照：未取消时子进程异常仍是「运行出错」（非取消，view 会弹 warning）。"""

    def _boom(self: GuiController, argv: list[str], on_line: Callable[[str], None]) -> int:
        raise OSError("真实失败")

    monkeypatch.setattr(GuiController, "_run_subprocess", _boom)
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(
        ActionRequest(action=ACTION_STATIC, apk_path=_make_apk(tmp_path), out_dir=str(tmp_path))
    )
    res = results[0]
    assert res.cancelled is False
    assert "出错" in res.message


def test_cancel_calls_proc_terminate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """真 _run_subprocess + 假 Popen：在读首行的 on_line 回调里 cancel()，验证整树收割被调。

    cancel() 现走 `_kill_process_tree`（Windows taskkill /T 整树、POSIX 进程组信号），不再
    只 `proc.terminate()`——故这里 patch `_kill_process_tree` 记录被调，并模拟「收割后 stdout
    EOF」，验证读循环收束 + 句柄清理。
    """

    class _FakeStdout:
        """模拟子进程 stdout：被收割后 EOF（停止 yield），贴近真子进程行为。"""

        def __init__(self, proc: _FakeProc) -> None:
            self._proc = proc
            self._lines = ["第一行\n", "第二行\n"]
            self._i = 0

        def __iter__(self) -> _FakeStdout:
            return self

        def __next__(self) -> str:
            if self._proc.killed:  # 收割后 stdout EOF
                raise StopIteration
            if self._i >= len(self._lines):
                raise StopIteration
            line = self._lines[self._i]
            self._i += 1
            return line

    class _FakeProc:
        def __init__(self) -> None:
            self.stdout = _FakeStdout(self)
            self.killed = 0
            self.pid = 4242

        def poll(self) -> int | None:
            return 1 if self.killed else None

        def wait(self) -> int:
            return 1

    fake = _FakeProc()
    monkeypatch.setattr(ctrl_mod.subprocess, "Popen", lambda argv, **kw: fake)
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)

    reaped: list[object] = []

    def _fake_kill_tree(proc: object) -> None:
        reaped.append(proc)
        fake.killed += 1  # 收割 → 下次读 EOF

    monkeypatch.setattr(ctrl_mod, "_kill_process_tree", _fake_kill_tree)

    controller, _logs, _results = _make_controller(monkeypatch)
    controller._busy = True  # 模拟运行中，cancel 才会动作

    def _on_line(text: str) -> None:
        # 读到第一行时触发取消（此时 _proc 已被 _run_subprocess 持有）。
        controller.cancel()

    rc = controller._run_subprocess(["py", "x"], _on_line)
    assert rc == 1
    assert reaped == [fake]  # cancel() 走整树收割、收到的是该子进程句柄
    assert controller._proc is None  # finally 清句柄


def test_cancel_race_before_proc_assigned_kills_after_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """竞态收口：cancel() 在 _proc 赋值前置标志 → _run_subprocess 赋值后复查并补杀。

    模拟「start 后秒点取消、Popen 刚返回但 _proc 还没赋值」窗口：先置 _cancelled，再进
    _run_subprocess，断言整树收割仍被调用（子进程不会跑满全程）。
    """

    class _FakeProc:
        def __init__(self) -> None:
            self.stdout = iter([])  # 立即 EOF
            self.pid = 99

        def poll(self) -> int | None:
            return 0

        def wait(self) -> int:
            return 0

    fake = _FakeProc()
    monkeypatch.setattr(ctrl_mod.subprocess, "Popen", lambda argv, **kw: fake)
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)

    reaped: list[object] = []
    monkeypatch.setattr(ctrl_mod, "_kill_process_tree", lambda proc: reaped.append(proc))

    controller, _logs, _results = _make_controller(monkeypatch)
    controller._busy = True
    controller._cancelled.set()  # 取消已在 _proc 赋值前发生

    controller._run_subprocess(["py", "x"], lambda _t: None)
    assert reaped == [fake]  # 赋值后复查 → 补杀，竞态不漏


def test_kill_process_tree_swallows_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """_kill_process_tree 对已退出/不可用进程绝不抛（taskkill 报错 / terminate 抛都吞）。"""

    class _DeadProc:
        pid = 1234

        def terminate(self) -> None:
            raise ProcessLookupError("已退出")

        def kill(self) -> None:
            raise ProcessLookupError("已退出")

    # 让 win32 分支的 taskkill 抛、POSIX 分支的 terminate 抛——两条路都不应让本函数抛。
    def _boom_run(*a: Any, **k: Any) -> None:
        raise OSError("taskkill 不可用")

    monkeypatch.setattr(ctrl_mod.subprocess, "run", _boom_run)
    # 不应抛任何异常。
    ctrl_mod._kill_process_tree(_DeadProc())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 问题 1：cleanup_adb（关 GUI 时收掉自起的 adb server）
# ---------------------------------------------------------------------------


def test_controller_cleanup_adb_calls_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """cleanup_adb 惰性 import core.tools 并调 kill_adb_server 一次。"""
    from apkscan.core import tools

    calls = {"n": 0}
    monkeypatch.setattr(tools, "kill_adb_server", lambda: calls.__setitem__("n", calls["n"] + 1))

    controller, _logs, _results = _make_controller(monkeypatch)
    controller.cleanup_adb()
    assert calls["n"] == 1


def test_controller_cleanup_adb_swallows_tools_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """tools.kill_adb_server 抛异常 → cleanup_adb 吞掉（绝不阻断关窗）。"""
    from apkscan.core import tools

    def _boom() -> bool:
        raise RuntimeError("adb 收尾炸了")

    monkeypatch.setattr(tools, "kill_adb_server", _boom)
    controller, _logs, _results = _make_controller(monkeypatch)
    # 不应抛。
    controller.cleanup_adb()


# ---------------------------------------------------------------------------
# 问题 2：_discover_reports 发现按 APK 名命名的报告（glob + 排除 runtime_report.json）
# ---------------------------------------------------------------------------


def test_discover_reports_finds_apk_named(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """报告按 APK 名命名（demo.json/demo.html）→ 子进程结果能发现、html_report 非空、计数读到。"""
    monkeypatch.setattr(ctrl_mod, "_frozen", lambda: False)
    (tmp_path / "demo.json").write_text(
        json.dumps({"endpoints": [1, 2, 3], "leads": [1], "findings": []}), encoding="utf-8"
    )
    (tmp_path / "demo.html").write_text("<html></html>", encoding="utf-8")

    _patch_subprocess(monkeypatch, returncode=0)
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(
        ActionRequest(action=ACTION_STATIC, apk_path=_make_apk(tmp_path), out_dir=str(tmp_path))
    )
    res = results[0]
    assert res.ok is True
    assert any(p.endswith("demo.json") for p in res.report_paths)
    assert res.html_report.endswith("demo.html")  # 「打开 HTML 报告」按钮仍能发现新命名
    assert (res.counts.endpoints, res.counts.leads, res.counts.findings) == (3, 1, 0)


def test_discover_reports_excludes_runtime_report(tmp_path: Path) -> None:
    """同时存在 demo.json + runtime_report.json → 主报告锚点是 demo.json，不误读 runtime。"""
    (tmp_path / "demo.json").write_text(
        json.dumps({"endpoints": [1], "leads": [1, 2], "findings": [1]}), encoding="utf-8"
    )
    # runtime_report.json 结构非主报告（有 endpoints 但无 leads/findings），且 mtime 更新。
    (tmp_path / "runtime_report.json").write_text(
        json.dumps({"endpoints": [1, 2, 3, 4, 5]}), encoding="utf-8"
    )
    found = GuiController._discover_reports(str(tmp_path))
    # runtime_report.json 不被当主报告：返回里没有它，json 首位是 demo.json。
    assert not any(p.endswith("runtime_report.json") for p in found)
    assert found and found[0].endswith("demo.json")


def test_discover_reports_picks_latest_group(tmp_path: Path) -> None:
    """两组按 APK 名报告（不同 mtime）→ 选 mtime 最新一组，不混。"""
    import os
    import time

    (tmp_path / "old.json").write_text(json.dumps({"endpoints": []}), encoding="utf-8")
    (tmp_path / "old.html").write_text("<html>old</html>", encoding="utf-8")
    time.sleep(0.02)
    (tmp_path / "new.json").write_text(json.dumps({"endpoints": [1]}), encoding="utf-8")
    (tmp_path / "new.html").write_text("<html>new</html>", encoding="utf-8")
    # 显式把 new.json 设为更晚 mtime，避免文件系统时间粒度抖动。
    now = time.time()
    os.utime(tmp_path / "old.json", (now - 10, now - 10))
    os.utime(tmp_path / "new.json", (now, now))

    found = GuiController._discover_reports(str(tmp_path))
    assert found[0].endswith("new.json")
    # 同组 html 也是 new.html，不混进 old.html。
    assert any(p.endswith("new.html") for p in found)
    assert not any(p.endswith("old.html") for p in found)


def test_discover_reports_legacy_report_name_still_found(tmp_path: Path) -> None:
    """向后兼容：旧 report.json/report.html 仍被发现（report 是合法 base/回退名）。"""
    (tmp_path / "report.json").write_text(json.dumps({"endpoints": [1]}), encoding="utf-8")
    (tmp_path / "report.html").write_text("<html></html>", encoding="utf-8")
    found = GuiController._discover_reports(str(tmp_path))
    assert found and found[0].endswith("report.json")
    assert any(p.endswith("report.html") for p in found)


def test_discover_reports_html_only_no_json(tmp_path: Path) -> None:
    """只有 html（--fmt html）→ 退化取最新 html，无 json（计数未知、ok 由上层判 False）。"""
    (tmp_path / "demo.html").write_text("<html></html>", encoding="utf-8")
    found = GuiController._discover_reports(str(tmp_path))
    assert found == [str(tmp_path / "demo.html")]


def test_cancel_terminate_exception_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """收割抛异常（进程已退）→ cancel 仍返回 True、不崩。"""

    class _DeadProc:
        pid = 555

        def terminate(self) -> None:
            raise ProcessLookupError("进程已退出")

        def kill(self) -> None:
            raise ProcessLookupError("进程已退出")

    # taskkill 也抛（模拟进程已退/不可用），cancel 仍不应崩。
    def _boom_run(*a: Any, **k: Any) -> None:
        raise OSError("taskkill 失败")

    monkeypatch.setattr(ctrl_mod.subprocess, "run", _boom_run)
    controller, _logs, _results = _make_controller(monkeypatch)
    controller._busy = True
    controller._proc = _DeadProc()  # type: ignore[assignment]
    assert controller.cancel() is True  # 异常被吞，仍返回 True
    assert controller._cancelled.is_set()


def test_cancel_watchdog_force_kills_stuck_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """看门狗：取消后宽限期内仍存活（孙进程拖住管道）→ 强 kill 兜底。

    用极短宽限期直接驱动 _CancelWatchdog：模拟「整树收割没让进程退、poll 仍 None」，断言
    宽限期后 kill() 被调；并验证 disarm（读循环正常收束）后看门狗不强杀。
    """
    import threading as _t

    class _StuckProc:
        pid = 777

        def __init__(self) -> None:
            self.killed = 0

        def poll(self) -> int | None:
            return None  # 始终「存活」

        def kill(self) -> None:
            self.killed += 1

    # 1) 取消 + 宽限期到 → 强杀。
    proc = _StuckProc()
    cancelled = _t.Event()
    wd = ctrl_mod._CancelWatchdog(proc, cancelled, grace_seconds=0.05)  # type: ignore[arg-type]
    wd.start()
    cancelled.set()
    wd._thread.join(timeout=2.0)
    assert proc.killed == 1  # 宽限期后强杀

    # 2) disarm（读循环正常收束）→ 即便后来取消也不强杀。
    proc2 = _StuckProc()
    cancelled2 = _t.Event()
    wd2 = ctrl_mod._CancelWatchdog(proc2, cancelled2, grace_seconds=0.05)  # type: ignore[arg-type]
    wd2.start()
    wd2.disarm()
    wd2._thread.join(timeout=2.0)
    assert proc2.killed == 0  # disarm 后不介入


def test_cancel_watchdog_no_cancel_exits_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    """看门狗：未取消、正常 disarm → 不强杀，线程干净退出。"""
    import threading as _t

    class _Proc:
        pid = 888
        killed = 0

        def poll(self) -> int | None:
            return 0

        def kill(self) -> None:
            self.killed += 1  # type: ignore[misc]

    proc = _Proc()
    cancelled = _t.Event()
    wd = ctrl_mod._CancelWatchdog(proc, cancelled, grace_seconds=5.0)  # type: ignore[arg-type]
    wd.start()
    wd.disarm()
    wd._thread.join(timeout=2.0)
    assert not wd._thread.is_alive()
    assert proc.killed == 0
