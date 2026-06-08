"""apkscan.gui.controller — GUI 控制器（**无任何 Tk import**，headless 可单测）。

职责：把 view 选的动作**派到子进程**跑 CLI（analyze/auto/doctor）、在后台线程读子
进程 stdout、把进度文本与最终结果安全回传 UI，并把结果（计数 / report_paths）格式化
为 UI 直接可显示的结构。

为什么走子进程（卡死修复，根因）：
- 旧版在 controller 的后台 daemon 线程里直接调 ``auto.run`` / ``analyze_static``。但
  androguard 解析是 **CPU 密集的纯 Python**，独占 GIL，把 tkinter 主线程的消息泵饿死
  → Windows 报「无响应」。同进程线程救不了（单 GIL）。
- 改法：分析跑到**子进程**。GUI 这边只**阻塞读子进程 stdout**（I/O 释放 GIL），主线程
  消息泵不再被饿 → 界面全程不卡。子进程命令：frozen 时 ``[sys.executable, <subcmd>, ...]``
  （exe 做 dispatch 入口）；源码时 ``[sys.executable, "-m", "apkscan.cli", <subcmd>, ...]``。

分层铁律：
- 本模块**禁止 import tkinter / ttk**——线程与回调编排在这里，Tk 调度由 view 注入。
- view 通过构造 :class:`GuiController` 时注入三个回调：

    * ``on_log(text)``     —— 追加一行进度/日志（view 内部 root.after 调度回主线程）。
    * ``on_done(result)``  —— 动作结束（成功或失败），交回结构化 :class:`ActionResult`。
    * ``schedule(fn)``     —— 把无参可调用对象排到 UI 主线程执行（view 用 root.after(0, fn)）。

  controller 自身**不碰 Tk**：它在 worker 线程里只调 ``schedule(...)`` 把 ``on_log`` /
  ``on_done`` 弹回主线程，从而满足 tkinter「只能在主线程操作控件」的要求，同时保持
  可在无显示器环境用纯 mock 单测（schedule 直接同步执行 fn 即可）。

- confirm 钩子由 view 注入；子进程模式下子进程无 stdin 交互——无设备时 capture 本就
  skip、不触发 confirm；有设备时 confirm 退化为不提示（已知限制，设备侧后续优化）。
  钩子保留以维持构造契约，但子进程模式不再被 controller 调用。
- 异常被吞成友好提示（``ActionResult.ok=False`` + 友好 message），**绝不抛**、绝不崩 UI。
- 全量 type hints；except 必 logging，不静默。
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# 三个动作标识（避免裸字符串漂移；view 按钮 → controller 分派以此识别）。
ACTION_DOCTOR = "doctor"
ACTION_STATIC = "static"
ACTION_AUTO = "auto"


def _frozen() -> bool:
    """是否 PyInstaller 冻结态（决定子进程命令是 exe 自调用还是 ``-m apkscan.cli``）。

    本阶段不引入 ``apkscan.core.tools``（属打包阶段）；冻结判定就地内联。
    """
    return bool(getattr(sys, "frozen", False))


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
    - ``steps``：[{name, status, status_label, detail}]。子进程模式下进度已实时流入日志框，
      此字段保留以维持 view 渲染契约，但通常为空（view ``_render_steps`` 空则早返回）。
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
        """按 action 分派：全部经**子进程跑 CLI**（卡死修复核心）。"""
        if request.action == ACTION_DOCTOR:
            return self._run_doctor(request)
        if request.action == ACTION_STATIC:
            return self._run_static(request)
        if request.action == ACTION_AUTO:
            return self._run_auto(request)
        logger.warning("[gui] 未知动作：%s", request.action)
        return ActionResult(ok=False, action=request.action, message=f"未知动作：{request.action}")

    # -- 子进程命令构造 -----------------------------------------------------

    @staticmethod
    def _fmt_arg(formats: list[str]) -> str:
        """格式列表 → CLI ``--fmt`` 逗号串（去空、去重保序）。"""
        seen: list[str] = []
        for f in formats:
            f = str(f).strip().lower()
            if f and f not in seen:
                seen.append(f)
        return ",".join(seen) if seen else "html,json"

    def _subcmd_argv(self, subcmd: str, request: ActionRequest) -> list[str]:
        """构造子进程命令行（frozen vs 源码 两形态）。

        - frozen（PyInstaller 冻结）：``[sys.executable, <subcmd>, *args]``——exe 自身做
          dispatch 入口，按 argv[1] 分发到 CLI 子命令。
        - 源码：``[sys.executable, "-m", "apkscan.cli", <subcmd>, *args]``。

        各 subcmd 的参数与 :mod:`apkscan.cli` 的命令签名严格对齐：
        - ``doctor``：``--fix`` / ``--no-fix``（按 ``request.auto_fix``）。
        - ``analyze``（GUI 静态=CLI analyze，纯静态、**不传 --dynamic**、不连设备）：
          ``<apk> --online|--offline --out <dir> --fmt <csv>``。
        - ``auto``：``<apk> --out <dir> --online|--offline --fix|--no-fix
          --duration <n> --fmt <csv>``。
        """
        base: list[str] = (
            [sys.executable, subcmd]
            if _frozen()
            else [sys.executable, "-m", "apkscan.cli", subcmd]
        )
        if subcmd == "doctor":
            return [*base, "--fix" if request.auto_fix else "--no-fix"]
        if subcmd == "analyze":
            return [
                *base,
                request.apk_path,
                "--online" if request.online else "--offline",
                "--out",
                request.out_dir,
                "--fmt",
                self._fmt_arg(request.formats),
            ]
        if subcmd == "auto":
            return [
                *base,
                request.apk_path,
                "--out",
                request.out_dir,
                "--online" if request.online else "--offline",
                "--fix" if request.auto_fix else "--no-fix",
                "--duration",
                str(request.capture_duration),
                "--fmt",
                self._fmt_arg(request.formats),
            ]
        logger.warning("[gui] 未知子命令：%s", subcmd)
        return base

    def _run_subprocess(self, argv: list[str], on_line: Callable[[str], None]) -> int:
        """起子进程跑 argv，**阻塞逐行读 stdout**（I/O 释放 GIL，主线程不卡）→ on_line。

        合并 stderr 到 stdout，UTF-8 解码、坏字节 replace、行缓冲。返回退出码。
        子进程注入 ``PYTHONUTF8=1`` 让它也按 UTF-8 输出（否则 Windows 默认 GBK 写、
        本端按 UTF-8 读 → 中文乱码）。Windows 下用 ``CREATE_NO_WINDOW`` 隐藏子进程控制台窗口。
        起进程/读流失败由调用方（``_run_worker`` 外层 try/except）转友好结果。
        """
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
            creationflags=creationflags,
        )
        stdout = proc.stdout
        if stdout is not None:
            for line in stdout:  # 阻塞读 → 释放 GIL，tkinter 主线程消息泵不被饿死
                on_line(line.rstrip("\n"))
        return proc.wait()

    def _run_doctor(self, request: ActionRequest) -> ActionResult:
        """环境体检：子进程跑 ``doctor``，stdout 流式回日志；ok 由退出码判定。

        doctor 子命令体检全 OK 退出码 0、有未通过项退出码 1（见 cli.doctor）。
        子进程模式拿不到 items 结构 → steps 留空（view 兼容空 steps）；结论看退出码。
        """
        argv = self._subcmd_argv("doctor", request)
        rc = self._run_subprocess(argv, self._log)
        ok = rc == 0
        message = (
            "体检通过：关键项全部 OK，环境就绪（详见上方日志）。"
            if ok
            else "体检存在未通过的关键项（详见上方日志；含可复制的建议命令）。"
        )
        return ActionResult(ok=ok, action=ACTION_DOCTOR, message=message)

    def _run_static(self, request: ActionRequest) -> ActionResult:
        """静态分析：子进程跑 ``analyze``（纯静态、不连设备）；跑完读 report.json 计数。"""
        argv = self._subcmd_argv("analyze", request)
        rc = self._run_subprocess(argv, self._log)
        return self._build_subprocess_result(ACTION_STATIC, request.out_dir, rc)

    def _run_auto(self, request: ActionRequest) -> ActionResult:
        """一键全自动：子进程跑 ``auto``（含体检/脱壳/抓包）；跑完读 report.json 计数。

        子进程无 stdin 交互：无设备时 capture skip、不触发 confirm；有设备时 confirm
        退化为不提示（已知限制）。
        """
        argv = self._subcmd_argv("auto", request)
        rc = self._run_subprocess(argv, self._log)
        return self._build_subprocess_result(ACTION_AUTO, request.out_dir, rc)

    # -- 结果解析（子进程模式：探测 out_dir 下报告 + 读 report.json 计数） --------

    def _build_subprocess_result(self, action: str, out_dir: str, returncode: int) -> ActionResult:
        """子进程跑完 → 探测 ``out_dir`` 下的报告文件，读 report.json 计数，组装结果。

        - ``report_paths``：在 ``out_dir`` 下探测存在的 ``report.{json,html,pdf}``（保序去重）。
        - ``counts``：从 ``report.json`` 解析端点/线索/发现（复用 :meth:`_read_counts`）。
        - ``html_report``：首个 .html 报告路径（供「打开 HTML 报告」按钮）。
        - ``ok``：``returncode == 0`` **且** ``report.json`` 存在（auto 失败步骤会非 0 退出
          或不产出 report.json）。steps 子进程模式留空（日志已实时呈现）。
        """
        report_paths = self._discover_reports(out_dir)
        has_json = any(p.lower().endswith("report.json") for p in report_paths)
        ok = (returncode == 0) and has_json
        counts = self._read_counts(report_paths)
        html_report = next((p for p in report_paths if p.lower().endswith(".html")), "")

        if ok:
            message = f"完成：已产出 {len(report_paths)} 份报告（详见上方日志）。"
        elif report_paths:
            message = (
                f"已产出报告，但子进程退出码非 0（{returncode}），"
                "部分步骤可能出错（详见上方日志）。"
            )
        else:
            message = (
                f"未产出报告（子进程退出码 {returncode}），"
                "请检查 APK 是否有效（详见上方日志）。"
            )

        return ActionResult(
            ok=ok,
            action=action,
            message=message,
            counts=counts,
            report_paths=report_paths,
            html_report=html_report,
            out_dir=out_dir,
        )

    @staticmethod
    def _discover_reports(out_dir: str) -> list[str]:
        """探测 ``out_dir`` 下存在的报告文件（report.json/html/pdf），保序去重、不抛。

        json 放首位（计数读取依赖它），其余按 html、pdf 顺序。读目录失败 → 空列表。
        """
        if not out_dir:
            return []
        found: list[str] = []
        try:
            base = Path(out_dir)
            for name in ("report.json", "report.html", "report.pdf"):
                p = base / name
                if p.is_file():
                    found.append(str(p))
        except OSError:
            logger.exception("[gui] 探测输出目录报告失败：%s", out_dir)
            return []
        return found

    def _read_counts(self, report_paths: list[str]) -> Counts:
        """从 report.json 读端点/线索/发现计数；读不到 / 无 json → Counts(全 -1)，不抛。"""
        json_path = next((p for p in report_paths if p.lower().endswith(".json")), "")
        if not json_path:
            return Counts()
        try:
            import json as _json

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
