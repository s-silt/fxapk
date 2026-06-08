"""apkscan.gui.controller — GUI 控制器（**无任何 Tk import**，headless 可单测）。

职责：把 view 选的动作分派到已做好的程序化核心、在后台线程跑、把进度文本与最终
结果安全回传 UI，并把结果（steps / 计数 / report_paths）格式化为 UI 直接可显示的结构。

分层铁律：
- 本模块**禁止 import tkinter / ttk**——线程与回调编排在这里，Tk 调度由 view 注入。
- view 通过构造 :class:`GuiController` 时注入三个回调：

    * ``on_log(text)``     —— 追加一行进度/日志（view 内部 root.after 调度回主线程）。
    * ``on_done(result)``  —— 动作结束（成功或失败），交回结构化 :class:`ActionResult`。
    * ``schedule(fn)``     —— 把无参可调用对象排到 UI 主线程执行（view 用 root.after(0, fn)）。

  controller 自身**不碰 Tk**：它在 worker 线程里只调 ``schedule(...)`` 把 ``on_log`` /
  ``on_done`` 弹回主线程，从而满足 tkinter「只能在主线程操作控件」的要求，同时保持
  可在无显示器环境用纯 mock 单测（schedule 直接同步执行 fn 即可）。

- confirm 钩子由 view 注入（GUI 用对话框实现「请操作 app 后继续」）；仅一键全自动用。
- 异常被吞成友好提示（``ActionResult.ok=False`` + 友好 message），**绝不抛**、绝不崩 UI。
- 全量 type hints；except 必 logging，不静默。
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 三个动作标识（避免裸字符串漂移；view 按钮 → controller 分派以此识别）。
ACTION_DOCTOR = "doctor"
ACTION_STATIC = "static"
ACTION_AUTO = "auto"

# step / item 状态 → 友好中文标签（view 直接显示）。
_STATUS_LABELS = {
    "done": "完成",
    "skipped": "跳过",
    "error": "出错",
}


@dataclass
class Counts:
    """从 report.json 读出的可读计数（端点 / 线索 / 发现）。未知为 -1。"""

    endpoints: int = -1
    leads: int = -1
    findings: int = -1

    @property
    def known(self) -> bool:
        """是否成功读到计数（任一 >= 0 即视作已知）。"""
        return self.endpoints >= 0 or self.leads >= 0 or self.findings >= 0


@dataclass
class ActionResult:
    """一次动作（doctor/static/auto）跑完后的结构化结果，供 view 直接渲染。

    - ``ok``：动作整体是否成功（doctor 看 ok 字段；static/auto 看是否产出报告且无致命错）。
    - ``action``：ACTION_* 之一。
    - ``message``：一句话结论（友好；出错时是友好提示而非 traceback）。
    - ``steps``：[{name, status, status_label, detail}]，doctor 时为体检项折叠成同结构。
    - ``counts``：端点/线索/发现计数（仅 static/auto 且能读到 report.json 时有意义）。
    - ``report_paths``：产出报告路径（去重保序）。
    - ``html_report``：首个 .html 报告路径（供「打开 HTML 报告」按钮；无则空串）。
    - ``out_dir``：输出目录（供「打开输出目录」按钮）。
    """

    ok: bool
    action: str
    message: str
    steps: list[dict] = field(default_factory=list)
    counts: Counts = field(default_factory=Counts)
    report_paths: list[str] = field(default_factory=list)
    html_report: str = ""
    out_dir: str = ""


@dataclass
class ActionRequest:
    """view 发起一次动作的入参（一个数据类，避免长参数列表漂移）。"""

    action: str
    apk_path: str = ""
    out_dir: str = "out"
    online: bool = False
    formats: list[str] = field(default_factory=lambda: ["html", "json"])
    capture_duration: int = 60
    auto_fix: bool = True


class GuiController:
    """GUI 控制器：分派动作、后台线程编排、结果格式化。无任何 Tk 依赖。

    Args:
        on_log:    追加一行进度/日志文本（view 注入；内部经 schedule 回主线程）。
        on_done:   动作结束回调，参数为 :class:`ActionResult`（view 注入）。
        schedule:  把无参可调用对象排到 UI 主线程执行（view 注入；单测可同步执行）。
        confirm:   抓包前「请操作 app 后继续」钩子（view 注入对话框；仅 auto 用）。
                   None 时 auto 内部不等待直接继续。
    """

    def __init__(
        self,
        *,
        on_log: Callable[[str], None],
        on_done: Callable[[ActionResult], None],
        schedule: Callable[[Callable[[], None]], None],
        confirm: Callable[[str], None] | None = None,
    ) -> None:
        self._on_log = on_log
        self._on_done = on_done
        self._schedule = schedule
        self._confirm = confirm
        self._busy = False
        self._lock = threading.Lock()

    # -- 状态查询 -----------------------------------------------------------

    @property
    def busy(self) -> bool:
        """是否有动作正在运行（运行中 view 应禁用按钮）。"""
        return self._busy

    # -- 对外：发起动作 -----------------------------------------------------

    def start(self, request: ActionRequest) -> bool:
        """发起一次动作（后台线程跑，不卡 UI）。

        运行中再次调用返回 False（view 应已禁用按钮，这里是二次防护）。
        入参校验失败（如未选 APK）也返回 False 并经 on_done 回一个友好 error 结果。

        Returns:
            True 表示已受理并启动后台线程；False 表示被拒（忙 / 校验失败）。
        """
        with self._lock:
            if self._busy:
                logger.warning("[gui] 已有动作在运行，忽略新的 start：%s", request.action)
                return False
            # 静态 / 一键需要 APK；doctor 不需要。
            if request.action in (ACTION_STATIC, ACTION_AUTO) and not request.apk_path:
                self._emit_result(
                    ActionResult(
                        ok=False,
                        action=request.action,
                        message="请先选择一个 APK 文件再开始。",
                    )
                )
                return False
            self._busy = True

        thread = threading.Thread(
            target=self._run_worker, args=(request,), daemon=True, name="apkscan-gui-worker"
        )
        thread.start()
        return True

    # -- worker（后台线程） -------------------------------------------------

    def _run_worker(self, request: ActionRequest) -> None:
        """后台线程主体：调核心 → 解析结果 → 经 schedule 把结果弹回主线程。绝不抛。"""
        try:
            result = self._dispatch(request)
        except Exception as exc:  # noqa: BLE001 - worker 绝不把异常抛出线程，转友好结果
            logger.exception("[gui] 动作执行未预期异常：%s", request.action)
            result = ActionResult(
                ok=False,
                action=request.action,
                message=f"运行出错（详见日志）：{exc}",
                out_dir=request.out_dir,
            )
        finally:
            with self._lock:
                self._busy = False
        self._emit_result(result)

    def _dispatch(self, request: ActionRequest) -> ActionResult:
        """按 action 分派到对应核心（惰性 import，GUI 冷启动友好）。"""
        if request.action == ACTION_DOCTOR:
            return self._run_doctor(request)
        if request.action == ACTION_STATIC:
            return self._run_static(request)
        if request.action == ACTION_AUTO:
            return self._run_auto(request)
        logger.warning("[gui] 未知动作：%s", request.action)
        return ActionResult(ok=False, action=request.action, message=f"未知动作：{request.action}")

    def _run_doctor(self, request: ActionRequest) -> ActionResult:
        """环境体检：调 doctor.run，把 items 折叠成 steps，message 给体检结论。"""
        from apkscan.dynamic import doctor

        result = doctor.run(auto_fix=request.auto_fix, on_progress=self._log)
        ok = bool(result.get("ok")) if isinstance(result, dict) else False
        items = result.get("items") or [] if isinstance(result, dict) else []
        steps = [self._fold_item(it) for it in items if isinstance(it, dict)]
        n_ok = sum(1 for it in items if isinstance(it, dict) and it.get("ok"))
        message = (
            f"体检通过：{n_ok}/{len(steps)} 项 OK，环境就绪。"
            if ok
            else f"体检存在未通过的关键项：{n_ok}/{len(steps)} 项 OK（详见下方列表）。"
        )
        return ActionResult(ok=ok, action=ACTION_DOCTOR, message=message, steps=steps)

    def _run_static(self, request: ActionRequest) -> ActionResult:
        """静态分析：调 auto.analyze_static（仅静态，不触发 doctor/动态）。"""
        from apkscan.dynamic import auto

        result = auto.analyze_static(
            request.apk_path,
            out_dir=request.out_dir,
            online=request.online,
            formats=list(request.formats),
            on_progress=self._log,
        )
        return self._build_pipeline_result(ACTION_STATIC, result)

    def _run_auto(self, request: ActionRequest) -> ActionResult:
        """一键全自动：调 auto.run（含体检/脱壳/抓包），抓包前经注入的 confirm 提示。"""
        from apkscan.dynamic import auto

        result = auto.run(
            request.apk_path,
            out_dir=request.out_dir,
            online=request.online,
            auto_fix=request.auto_fix,
            capture_duration=request.capture_duration,
            formats=list(request.formats),
            on_progress=self._log,
            confirm=self._confirm,
        )
        return self._build_pipeline_result(ACTION_AUTO, result)

    # -- 结果解析 -----------------------------------------------------------

    def _build_pipeline_result(self, action: str, result: object) -> ActionResult:
        """把 auto.run / analyze_static 的 {steps, report_paths, package_name, out_dir}
        解析成 :class:`ActionResult`：折叠 steps、读 report.json 计数、挑 html 报告。"""
        if not isinstance(result, dict):
            logger.warning("[gui] %s 返回非 dict：%r", action, type(result).__name__)
            return ActionResult(ok=False, action=action, message="核心返回值非预期格式（详见日志）。")

        raw_steps = result.get("steps") or []
        steps = [self._fold_step(s) for s in raw_steps if isinstance(s, dict)]
        report_paths = [str(p) for p in (result.get("report_paths") or []) if p]
        out_dir = str(result.get("out_dir") or "")
        package_name = str(result.get("package_name") or "")

        has_error = any(s.get("status") == "error" for s in raw_steps if isinstance(s, dict))
        ok = bool(report_paths) and not has_error
        counts = self._read_counts(report_paths)
        html_report = next((p for p in report_paths if p.lower().endswith(".html")), "")

        if ok:
            pkg = package_name or "(未知)"
            message = f"完成：包名 {pkg}，已产出 {len(report_paths)} 份报告。"
        elif report_paths:
            message = "已产出报告，但部分步骤出错（详见下方步骤列表）。"
        else:
            message = "未产出报告，请检查 APK 是否有效（详见下方步骤列表）。"

        return ActionResult(
            ok=ok,
            action=action,
            message=message,
            steps=steps,
            counts=counts,
            report_paths=report_paths,
            html_report=html_report,
            out_dir=out_dir,
        )

    def _read_counts(self, report_paths: list[str]) -> Counts:
        """从 report.json 读端点/线索/发现计数；读不到 / 无 json → Counts(全 -1)，不抛。"""
        json_path = next((p for p in report_paths if p.lower().endswith(".json")), "")
        if not json_path:
            return Counts()
        try:
            import json as _json
            from pathlib import Path

            data = _json.loads(Path(json_path).read_text(encoding="utf-8"))
        except Exception:
            logger.exception("[gui] 读取报告 JSON 计数失败：%s", json_path)
            return Counts()
        if not isinstance(data, dict):
            logger.warning("[gui] 报告 JSON 顶层非 dict：%s", json_path)
            return Counts()
        return Counts(
            endpoints=_safe_len(data.get("endpoints")),
            leads=_safe_len(data.get("leads")),
            findings=_safe_len(data.get("findings")),
        )

    @staticmethod
    def _fold_step(step: dict) -> dict:
        """auto/analyze_static 的 step → view 可显示结构（附友好 status_label）。"""
        status = str(step.get("status", "?"))
        return {
            "name": str(step.get("name", "?")),
            "status": status,
            "status_label": _STATUS_LABELS.get(status, status),
            "detail": str(step.get("detail", "")),
        }

    @staticmethod
    def _fold_item(item: dict) -> dict:
        """doctor 的 item({name, ok, detail, fix_cmd}) → 与 step 同结构，便于 view 统一渲染。

        fix_cmd 拼进 detail（未通过项给出可复制命令提示，新手友好）。
        """
        ok = bool(item.get("ok"))
        status = "done" if ok else "error"
        detail = str(item.get("detail", ""))
        fix_cmd = item.get("fix_cmd") or []
        if not ok and isinstance(fix_cmd, list) and fix_cmd:
            joined = "  ".join(str(c) for c in fix_cmd)
            detail = f"{detail}  [建议命令] {joined}" if detail else f"[建议命令] {joined}"
        return {
            "name": str(item.get("name", "?")),
            "status": status,
            "status_label": _STATUS_LABELS.get(status, status),
            "detail": detail,
        }

    # -- 回调安全包装（经 schedule 弹回主线程） ----------------------------

    def _log(self, text: str) -> None:
        """on_progress 适配：把进度文本经 schedule 弹回主线程的 on_log。回调异常吞 + logging。"""
        try:
            self._schedule(lambda: self._safe_call(self._on_log, text))
        except Exception:
            logger.exception("[gui] 调度日志到主线程失败（已忽略）：%s", text)

    def _emit_result(self, result: ActionResult) -> None:
        """把最终结果经 schedule 弹回主线程的 on_done。回调异常吞 + logging。"""
        try:
            self._schedule(lambda: self._safe_call(self._on_done, result))
        except Exception:
            logger.exception("[gui] 调度结果到主线程失败（已忽略）：%s", result.action)

    @staticmethod
    def _safe_call(fn: Callable[..., None], *args: object) -> None:
        """在主线程执行 view 注入的回调，回调自身异常吞 + logging（GUI 回调不得炸控制器）。"""
        try:
            fn(*args)
        except Exception:
            logger.exception("[gui] UI 回调执行异常（已忽略）")


def _safe_len(value: object) -> int:
    """list → 长度；否则 -1（计数未知）。"""
    return len(value) if isinstance(value, list) else -1


__all__ = [
    "ACTION_AUTO",
    "ACTION_DOCTOR",
    "ACTION_STATIC",
    "ActionRequest",
    "ActionResult",
    "Counts",
    "GuiController",
]
