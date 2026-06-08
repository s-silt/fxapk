"""apkscan.gui.controller 单测：全 mock，**不构造 Tk**（CI headless 安全）。

覆盖（呼应 spec）：
  1. 正确分派到对应核心：doctor → doctor.run、static → auto.analyze_static、auto → auto.run。
  2. on_progress 文本被转发到注入的 on_log。
  3. 结果计数（端点/线索/发现）从 report.json 正确解析；report_paths / html_report 正确。
  4. confirm 被注入并透传给 auto.run。
  5. 异常被吞成友好提示（ActionResult.ok=False），run 不崩、worker 不抛。
  6. 运行中按钮禁用状态（controller.busy 标志）。
  7. 入参校验：static/auto 未选 APK → 拒绝并回友好 error；doctor 不需要 APK。

测试用同步 schedule（直接执行 fn），并用同步线程（monkeypatch threading.Thread）把
worker 拉到当前线程跑，避免依赖真实线程时序——既 headless 安全又确定性。
"""

from __future__ import annotations

import json
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
# 同步执行替身：schedule 直接调用 fn；Thread 在 start() 时同步跑 target（无真实线程）
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


def _pipeline_result(
    *, steps: list[dict], report_paths: list[str], package_name: str = "com.x", out_dir: str = "out"
) -> dict:
    return {
        "steps": steps,
        "report_paths": report_paths,
        "package_name": package_name,
        "out_dir": out_dir,
    }


# ---------------------------------------------------------------------------
# 1) 分派 + 2) on_progress 转发 + 4) confirm 透传
# ---------------------------------------------------------------------------


def test_doctor_dispatches_to_doctor_run_and_forwards_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import apkscan.dynamic.doctor as doctor_mod

    calls: dict[str, Any] = {}

    def _fake_run(**kwargs: Any) -> dict:
        calls["kwargs"] = kwargs
        cb = kwargs.get("on_progress")
        if cb is not None:
            cb("检查在线设备")
        return {
            "ok": True,
            "items": [
                {"name": "在线设备", "ok": True, "detail": "在线设备：emulator", "fix_cmd": []},
                {"name": "CA 已信任", "ok": False, "detail": "未装", "fix_cmd": ["adb root"]},
            ],
        }

    monkeypatch.setattr(doctor_mod, "run", _fake_run)
    controller, logs, results = _make_controller(monkeypatch)

    assert controller.start(ActionRequest(action=ACTION_DOCTOR)) is True

    assert "检查在线设备" in logs  # on_progress 透传到 on_log
    assert len(results) == 1
    res = results[0]
    assert res.action == ACTION_DOCTOR
    assert res.ok is True
    # items 折叠成 steps（含友好 status_label + fix_cmd 拼进 detail）。
    assert len(res.steps) == 2
    ca = next(s for s in res.steps if s["name"] == "CA 已信任")
    assert ca["status"] == "error"
    assert "建议命令" in ca["detail"] and "adb root" in ca["detail"]


def test_static_dispatches_to_analyze_static_not_auto_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import apkscan.dynamic.auto as auto_mod

    json_path = tmp_path / "report.json"
    json_path.write_text(
        json.dumps({"endpoints": [1, 2, 3], "leads": [1, 1], "findings": [1]}),
        encoding="utf-8",
    )
    html_path = tmp_path / "report.html"

    static_calls: dict[str, Any] = {"called": False}
    run_calls: dict[str, Any] = {"called": False}

    def _fake_static(apk_path: str, **kwargs: Any) -> dict:
        static_calls["called"] = True
        static_calls["apk_path"] = apk_path
        static_calls["kwargs"] = kwargs
        cb = kwargs.get("on_progress")
        if cb is not None:
            cb("静态分析中")
        return _pipeline_result(
            steps=[{"name": "静态分析", "status": "done", "detail": "ok"}],
            report_paths=[str(html_path), str(json_path)],
            out_dir=str(tmp_path),
        )

    def _fake_run(*a: Any, **k: Any) -> dict:
        run_calls["called"] = True
        return _pipeline_result(steps=[], report_paths=[])

    monkeypatch.setattr(auto_mod, "analyze_static", _fake_static)
    monkeypatch.setattr(auto_mod, "run", _fake_run)

    controller, logs, results = _make_controller(monkeypatch)
    req = ActionRequest(action=ACTION_STATIC, apk_path="sample.apk", online=True, formats=["html"])
    assert controller.start(req) is True

    assert static_calls["called"] is True
    assert run_calls["called"] is False  # 静态绝不走 auto.run
    assert static_calls["apk_path"] == "sample.apk"
    assert static_calls["kwargs"]["online"] is True
    assert "静态分析中" in logs

    res = results[0]
    assert res.ok is True
    # 计数从 report.json 正确解析。
    assert (res.counts.endpoints, res.counts.leads, res.counts.findings) == (3, 2, 1)
    # html_report 挑出 .html。
    assert res.html_report == str(html_path)
    assert res.out_dir == str(tmp_path)


def test_auto_dispatches_to_run_with_confirm_injected(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.auto as auto_mod

    run_calls: dict[str, Any] = {}

    def _fake_run(apk_path: str, **kwargs: Any) -> dict:
        run_calls["apk_path"] = apk_path
        run_calls["kwargs"] = kwargs
        # 触发 confirm，确认它被透传。
        confirm = kwargs.get("confirm")
        if confirm is not None:
            confirm("即将抓包，请操作 app")
        return _pipeline_result(
            steps=[{"name": "静态分析", "status": "done", "detail": "ok"}],
            report_paths=["out/report.html"],
        )

    monkeypatch.setattr(auto_mod, "run", _fake_run)

    confirms: list[str] = []
    controller, _logs, results = _make_controller(monkeypatch, confirm=confirms.append)
    req = ActionRequest(action=ACTION_AUTO, apk_path="x.apk", capture_duration=30, auto_fix=False)
    assert controller.start(req) is True

    assert run_calls["apk_path"] == "x.apk"
    kw = run_calls["kwargs"]
    assert kw["capture_duration"] == 30
    assert kw["auto_fix"] is False
    assert callable(kw["confirm"])
    assert callable(kw["on_progress"])
    # confirm 透传：auto.run 调它 → 注入的 confirm 收到文案。
    assert confirms == ["即将抓包，请操作 app"]
    assert results[0].ok is True


# ---------------------------------------------------------------------------
# 3) 计数解析容错
# ---------------------------------------------------------------------------


def test_counts_unknown_when_no_json(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.auto as auto_mod

    monkeypatch.setattr(
        auto_mod,
        "analyze_static",
        lambda *a, **k: _pipeline_result(
            steps=[{"name": "静态分析", "status": "done", "detail": ""}],
            report_paths=["out/report.html"],  # 只有 html，无 json
        ),
    )
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path="x.apk"))
    res = results[0]
    assert res.counts.known is False
    assert res.ok is True  # 有报告即 ok，计数未知不影响


def test_counts_unknown_when_json_unreadable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import apkscan.dynamic.auto as auto_mod

    bad = tmp_path / "report.json"
    bad.write_text("{ not valid json", encoding="utf-8")
    monkeypatch.setattr(
        auto_mod,
        "analyze_static",
        lambda *a, **k: _pipeline_result(
            steps=[{"name": "静态分析", "status": "done", "detail": ""}],
            report_paths=[str(bad)],
        ),
    )
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path="x.apk"))
    assert results[0].counts.known is False  # 坏 JSON 不崩，计数未知


# ---------------------------------------------------------------------------
# 5) 异常被吞成友好结果（worker 不抛、run 不崩）
# ---------------------------------------------------------------------------


def test_core_exception_becomes_friendly_error_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import apkscan.dynamic.auto as auto_mod

    def _boom(*a: Any, **k: Any) -> dict:
        raise RuntimeError("core exploded")

    monkeypatch.setattr(auto_mod, "analyze_static", _boom)
    controller, _logs, results = _make_controller(monkeypatch)

    # 不应抛。
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path="x.apk"))
    res = results[0]
    assert res.ok is False
    assert "出错" in res.message  # 友好提示而非 traceback
    assert controller.busy is False  # 异常后 busy 复位


def test_nondict_core_result_handled(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.auto as auto_mod

    monkeypatch.setattr(auto_mod, "analyze_static", lambda *a, **k: "not a dict")
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path="x.apk"))
    assert results[0].ok is False
    assert "非预期格式" in results[0].message


def test_pipeline_with_error_step_marks_not_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.auto as auto_mod

    monkeypatch.setattr(
        auto_mod,
        "analyze_static",
        lambda *a, **k: _pipeline_result(
            steps=[{"name": "静态分析", "status": "error", "detail": "解析失败"}],
            report_paths=[],
        ),
    )
    controller, _logs, results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_STATIC, apk_path="x.apk"))
    assert results[0].ok is False  # 无报告 + 有 error 步骤


# ---------------------------------------------------------------------------
# 6) 运行中 busy / 按钮禁用语义；并发拒绝
# ---------------------------------------------------------------------------


def test_busy_true_during_run_and_reset_after(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.doctor as doctor_mod

    seen_busy: list[bool] = []

    def _fake_run(**kwargs: Any) -> dict:
        # 动作执行中 busy 应为 True。
        seen_busy.append(controller.busy)
        return {"ok": True, "items": []}

    monkeypatch.setattr(doctor_mod, "run", _fake_run)
    controller, _logs, _results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_DOCTOR))

    assert seen_busy == [True]  # 运行期间 busy
    assert controller.busy is False  # 结束后复位


def test_concurrent_start_rejected_while_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.doctor as doctor_mod

    second_accepted: list[bool] = []

    def _fake_run(**kwargs: Any) -> dict:
        # 正在运行时再次 start 应被拒（busy 防护）。
        second_accepted.append(controller.start(ActionRequest(action=ACTION_DOCTOR)))
        return {"ok": True, "items": []}

    monkeypatch.setattr(doctor_mod, "run", _fake_run)
    controller, _logs, _results = _make_controller(monkeypatch)
    controller.start(ActionRequest(action=ACTION_DOCTOR))

    assert second_accepted == [False]  # 第二次被拒


# ---------------------------------------------------------------------------
# 7) 入参校验：static/auto 需要 APK；doctor 不需要
# ---------------------------------------------------------------------------


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
    import apkscan.dynamic.doctor as doctor_mod

    monkeypatch.setattr(doctor_mod, "run", lambda **k: {"ok": True, "items": []})
    controller, _logs, results = _make_controller(monkeypatch)
    assert controller.start(ActionRequest(action=ACTION_DOCTOR, apk_path="")) is True
    assert results[0].action == ACTION_DOCTOR
