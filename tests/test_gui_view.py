"""apkscan.gui 烟测：import 不需显示器；view 构造 headless 安全（无 X 自动 skip）。

铁律呼应：
- ``import apkscan.gui`` / ``import apkscan.gui.view`` 在无显示器环境也必须成功
  （模块级不建 Tk root）。
- Tk view 构造的烟测用 try: tkinter.Tk() except TclError: skip —— CI 无显示器自动跳过，
  本机 Windows 有显示器会真构造一次验证无异常。
"""

from __future__ import annotations

import importlib

import pytest


def test_import_gui_does_not_need_display() -> None:
    """import apkscan.gui 不构造 Tk，无显示器也能成功；暴露 main。"""
    gui = importlib.import_module("apkscan.gui")
    assert hasattr(gui, "main")
    assert callable(gui.main)


def test_import_gui_view_does_not_create_tk_at_module_level() -> None:
    """import apkscan.gui.view 不在模块级建 root（headless 安全）；暴露 App/run_app。"""
    view = importlib.import_module("apkscan.gui.view")
    assert hasattr(view, "App")
    assert hasattr(view, "run_app")


def test_import_controller_has_no_tk_dependency() -> None:
    """controller 层无 Tk 依赖：import 后其模块未引入 tkinter 名字。"""
    import apkscan.gui.controller as controller

    assert not hasattr(controller, "tk")
    assert not hasattr(controller, "tkinter")


# ---------------------------------------------------------------------------
# 防呆：真 root view 测
#
# 稳定性（呼应评审【中-1】）：早期每个用例各自 ``tk.Tk()`` 建/销，连续大量建销会让 Tcl
# 解释器 root churn → ``Tk()`` 间歇抛 ``TclError`` 被吞成 skip，导致这批核心防呆用例在全量
# 回归里时有时无（单跑 13 passed、连跑变 skip）。修法：**整模块只建一个 ``tk.Tk()``**
# （``_shared_root`` fixture，无显示器才 skip），每个用例在其下建一个 ``Toplevel`` 跑 ``App``
# （``Toplevel`` 用完即 destroy，不碰解释器 root）→ 无 churn、不再间歇 skip。烟测也复用此
# fixture（不再自建第二个 ``tk.Tk()`` 触发 churn）。
#
# 覆盖三面：坏输入被挡（messagebox）/ 取消生效（停止按钮 + 关窗）/ 正常路径仍通。
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def _shared_root():  # noqa: ANN202 - pytest fixture，返回 tk.Tk
    """整模块共享的单个 Tk root（只建一次）。无显示器环境 → 整批 skip（不反复试建）。"""
    import tkinter as tk

    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("无显示器环境（headless），跳过 Tk view 防呆测")
    root.withdraw()  # 不实际显示窗口
    yield root
    try:
        root.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def app(_shared_root):  # noqa: ANN001, ANN201 - pytest fixture
    """在共享 root 下建一个 App（跑在 Toplevel 上），用完即销，不 churn 解释器 root。"""
    import tkinter as tk

    from apkscan.gui.view import App

    top = tk.Toplevel(_shared_root)
    instance = App(top)
    yield instance
    try:
        top.destroy()
    except tk.TclError:
        pass


def test_view_app_constructs_without_error_if_display_available(app) -> None:  # noqa: ANN001
    """有显示器：真构造一次 App 验证布局/样式无异常；无显示器（CI）经 fixture 自动 skip。"""
    # 控件就绪：动作按钮存在、日志框存在、变量默认值合理。
    assert len(app._action_buttons) == 3
    assert app.var_online.get() is True  # 默认联网富化（与 cli 一致）
    assert app.var_html.get() is True  # 默认勾 HTML
    assert app.var_json.get() is True  # 默认勾 JSON
    assert app.var_pdf.get() is False  # 默认不勾 PDF
    assert app._collect_formats() == ["html", "json"]
    # 强制处理一轮挂起事件，确保渲染无异常。
    app.root.update_idletasks()


def test_stop_button_exists_and_disabled_when_idle(app) -> None:  # noqa: ANN001
    assert hasattr(app, "btn_stop")
    assert str(app.btn_stop["state"]) == "disabled"  # 空闲禁用
    assert app.btn_stop not in app._action_buttons  # 不在三动作批里


def test_running_toggles_button_states(app) -> None:  # noqa: ANN001
    app._set_buttons_enabled(False)  # 运行中
    assert all(str(b["state"]) == "disabled" for b in app._action_buttons)
    assert str(app.btn_stop["state"]) == "normal"  # 停止按钮可点
    app._set_buttons_enabled(True)  # 空闲
    assert all(str(b["state"]) == "normal" for b in app._action_buttons)
    assert str(app.btn_stop["state"]) == "disabled"  # 停止按钮禁用


def test_wm_delete_protocol_bound(app) -> None:  # noqa: ANN001
    # 已绑定 WM_DELETE_WINDOW（返回非空回调名）。
    assert app.root.protocol("WM_DELETE_WINDOW")


def test_on_close_idle_destroys(app, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    destroyed: list[bool] = []
    monkeypatch.setattr(app.controller, "_busy", False)
    monkeypatch.setattr(app.root, "destroy", lambda: destroyed.append(True))
    app._on_close()
    assert destroyed == [True]  # 空闲直接 destroy（destroy 被 mock，真销由 fixture 负责）


def test_on_close_busy_confirm_cancels(app, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from apkscan.gui import view as view_mod

    cancelled: list[bool] = []
    destroyed: list[bool] = []
    monkeypatch.setattr(app.controller, "_busy", True)
    monkeypatch.setattr(app.controller, "cancel", lambda: cancelled.append(True) or True)
    monkeypatch.setattr(app.root, "destroy", lambda: destroyed.append(True))

    # 确认关闭 → cancel + destroy 都被调。
    monkeypatch.setattr(view_mod.messagebox, "askyesno", lambda *a, **k: True)
    app._on_close()
    assert cancelled == [True]
    assert destroyed == [True]

    # 取消关闭 → 既不 cancel 也不 destroy。
    cancelled.clear()
    destroyed.clear()
    monkeypatch.setattr(view_mod.messagebox, "askyesno", lambda *a, **k: False)
    app._on_close()
    assert cancelled == []
    assert destroyed == []


def test_bad_apk_triggers_messagebox(app, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from apkscan.gui import view as view_mod

    warnings: list[tuple] = []
    monkeypatch.setattr(view_mod.messagebox, "showwarning", lambda *a, **k: warnings.append(a))
    app.var_apk.set("不存在的路径_xyz.apk")
    app._on_static()
    app.root.update()  # 抽干 after 队列，让 on_done 在主线程跑
    assert warnings, "坏 APK 应触发 showwarning"
    # 文案具体（来自 controller.validate_apk_path）。
    body = " ".join(str(x) for w in warnings for x in w)
    assert "找不到这个文件" in body


def test_duration_blank_does_not_raise(app, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    captured: dict[str, object] = {}
    # 拦截 controller.start，记录 raw duration；不真起任务。
    monkeypatch.setattr(
        app.controller,
        "start",
        lambda req: captured.update(raw=req.capture_duration_raw) or False,
    )
    app.spin_duration.delete(0, "end")  # 清空 Spinbox → 文本为 ""
    # 不应抛 tk.TclError（不再走 IntVar.get()）。
    app._on_static()
    assert captured["raw"] == ""  # view 传原始空串，钳制交给 controller


def test_done_shows_absolute_out_path(app, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from pathlib import Path

    from apkscan.gui.controller import ACTION_STATIC, ActionResult

    logs: list[str] = []
    monkeypatch.setattr(app, "_append_log", lambda text: logs.append(text))
    abs_out = str((Path.cwd() / "out").resolve())
    app._on_done(ActionResult(ok=True, action=ACTION_STATIC, message="完成", out_dir=abs_out))
    assert any("报告已保存到" in line and abs_out in line for line in logs)


def test_cancelled_result_no_messagebox(app, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from apkscan.gui import view as view_mod
    from apkscan.gui.controller import ACTION_STATIC, ActionResult

    warnings: list[tuple] = []
    logs: list[str] = []
    monkeypatch.setattr(view_mod.messagebox, "showwarning", lambda *a, **k: warnings.append(a))
    monkeypatch.setattr(app, "_append_log", lambda text: logs.append(text))
    app._on_done(
        ActionResult(
            ok=False,
            action=ACTION_STATIC,
            message="已取消本次任务。",
            cancelled=True,
        )
    )
    assert warnings == []  # 取消不弹 warning
    assert any("已取消" in line for line in logs)  # 仅记日志


# ---------------------------------------------------------------------------
# 防呆 UX 润色（第 3 轮评审项）：抓包时长钳制可见反馈 + 运行中禁用输入控件
# ---------------------------------------------------------------------------


def test_auto_bad_duration_reflected_and_logged(app, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    """AUTO + 越界时长（9999）→ Spinbox 回写成 600 + 日志出现「已调整为 600 秒」+ 传给
    controller 的 raw 也是钳后值。给新手「实际用了多少秒」的可见反馈（不再静默）。"""
    captured: dict[str, object] = {}
    logs: list[str] = []
    # 拦截 start 返回 True（受理），让 _start 走到清日志 + 追加钳制提示分支。
    monkeypatch.setattr(
        app.controller,
        "start",
        lambda req: captured.update(raw=req.capture_duration_raw) or True,
    )
    monkeypatch.setattr(app, "_append_log", lambda text: logs.append(text))
    monkeypatch.setattr(app, "_clear_log", lambda: None)  # 不动真日志框
    app.spin_duration.delete(0, "end")
    app.spin_duration.insert(0, "9999")  # 越界
    app._on_auto()
    assert captured["raw"] == "600"  # 传给 controller 的是钳后值
    assert app.var_duration.get() == 600  # Spinbox 回写成钳后值（所见即所得）
    assert any("已调整为 600 秒" in line for line in logs)  # 日志有可见反馈


def test_auto_valid_duration_no_clamp_note(app, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    """AUTO + 合法时长（120）→ 不回写、不打扰：无「已调整」日志，raw 原样。"""
    logs: list[str] = []
    monkeypatch.setattr(app.controller, "start", lambda req: True)
    monkeypatch.setattr(app, "_append_log", lambda text: logs.append(text))
    monkeypatch.setattr(app, "_clear_log", lambda: None)
    app.spin_duration.delete(0, "end")
    app.spin_duration.insert(0, "120")  # 合法
    app._on_auto()
    assert app.var_duration.get() == 120  # 未被改动
    assert not any("已调整" in line for line in logs)  # 合法值不打扰


def test_static_does_not_clamp_or_log_duration(app, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    """STATIC 不读时长：即便 Spinbox 是坏值也不回写、不打钳制日志（时长仅 auto 用）。"""
    captured: dict[str, object] = {}
    logs: list[str] = []
    monkeypatch.setattr(
        app.controller,
        "start",
        lambda req: captured.update(raw=req.capture_duration_raw) or True,
    )
    monkeypatch.setattr(app, "_append_log", lambda text: logs.append(text))
    monkeypatch.setattr(app, "_clear_log", lambda: None)
    app.spin_duration.delete(0, "end")
    app.spin_duration.insert(0, "9999")  # 坏值，但 static 不该碰它
    app._on_static()
    assert captured["raw"] == "9999"  # static 原样传（钳制仍由 controller 兜底）
    assert not any("已调整" in line for line in logs)  # static 无钳制日志


def test_running_disables_input_widgets(app) -> None:  # noqa: ANN001
    """运行中：输入控件（浏览/Radio/勾选/Spinbox/路径框）一并禁用；空闲恢复可用。

    用 ttk 的 instate(["disabled"]) 查询（与 .state() 同一套状态标志，最准确）。
    """
    assert app._input_widgets, "应已登记输入控件"
    app._set_buttons_enabled(False)  # 运行中
    assert all(w.instate(["disabled"]) for w in app._input_widgets)
    app._set_buttons_enabled(True)  # 空闲
    assert all(w.instate(["!disabled"]) for w in app._input_widgets)
