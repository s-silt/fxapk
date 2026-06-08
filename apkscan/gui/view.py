"""apkscan.gui.view — tkinter/ttk 单窗口（扁平化 + 淡色系 + 新手友好）。

仅本文件 import tkinter。把控件事件转成 :class:`~apkscan.gui.controller.ActionRequest`
交给 controller，controller 经注入的 schedule/on_log/on_done 把进度与结果弹回主线程。

视觉落点（详见各 STYLE 常量与 _init_style）：
- ttk + 自定义 Style：按钮/边框 flat（relief='flat', borderwidth=0），去老式凸起。
- 淡色系：窗口底 #F5F7FA / 卡片 #FFFFFF / 主强调 柔和蓝 #4C8BF5 / 文字 #2D3748 …
- 主次分明：一键全自动=强调色实心大按钮；静态分析=次按钮；环境体检=描边/文字按钮。
- 字体 Microsoft YaHei UI（中文友好）+ fallback；留白充足；窗口可缩放 + 最小尺寸。
- 新手友好：顶部一句话引导；按钮带说明；出错用友好 messagebox；合理默认；空状态文案。

铁律：模块级**不创建 Tk root**（``import`` 本文件不构造 Tk）；root 在 ``run_app`` 才建。
"""

from __future__ import annotations

import logging
import os
import sys
import tkinter as tk
import webbrowser
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from apkscan.gui.controller import (
    ACTION_AUTO,
    ACTION_DOCTOR,
    ACTION_STATIC,
    ActionRequest,
    ActionResult,
    GuiController,
)

logger = logging.getLogger(__name__)

# -- 淡色系调色板（扁平化）---------------------------------------------------
BG_WINDOW = "#F5F7FA"  # 窗口底
BG_CARD = "#FFFFFF"  # 卡片
COLOR_PRIMARY = "#4C8BF5"  # 主强调（柔和蓝）
COLOR_PRIMARY_ACTIVE = "#3A77E0"  # 主强调按下
COLOR_TEXT = "#2D3748"  # 主文字
COLOR_TEXT_MUTED = "#718096"  # 次要文字
COLOR_SUCCESS = "#38A169"  # 成功
COLOR_WARNING = "#DD6B20"  # 警告
COLOR_BORDER = "#E2E8F0"  # 描边

# 字体：Windows 用微软雅黑（中文友好），其它平台 fallback。
_FONT_FAMILY = "Microsoft YaHei UI" if sys.platform.startswith("win") else "Segoe UI"
FONT_BASE = (_FONT_FAMILY, 10)
FONT_TITLE = (_FONT_FAMILY, 16, "bold")
FONT_HINT = (_FONT_FAMILY, 9)
FONT_BTN_PRIMARY = (_FONT_FAMILY, 12, "bold")
FONT_BTN = (_FONT_FAMILY, 10)
FONT_MONO = ("Consolas" if sys.platform.startswith("win") else "Menlo", 9)

PAD = 14  # 统一留白


class App:
    """apkscan GUI 主窗口（单窗口三动作）。

    构造时注入已建好的 Tk root（便于测试用真 root 或跳过），自身负责样式、布局、
    事件 → controller、结果渲染。controller 用 root.after 把后台线程回调弹回主线程。
    """

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self._init_window()
        self._init_style()

        # tk 变量（控件状态）。
        self.var_apk = tk.StringVar()
        self.var_out = tk.StringVar(value="out")
        self.var_online = tk.BooleanVar(value=False)  # 默认离线
        self.var_html = tk.BooleanVar(value=True)  # 默认勾 HTML
        self.var_json = tk.BooleanVar(value=True)  # 默认勾 JSON
        self.var_pdf = tk.BooleanVar(value=False)  # 默认不勾 PDF
        self.var_duration = tk.IntVar(value=60)
        self.var_counts = tk.StringVar(value="端点 -    线索 -    发现 -")

        # 结果区状态（供「打开报告/目录」按钮）。
        self._last_html = ""
        self._last_out = ""
        self._action_buttons: list[ttk.Button] = []
        # 日志框是否已有真实内容（显式初始化，不依赖 _build_ui 的调用顺序隐式契约）。
        self._log_has_content = False

        self.controller = GuiController(
            on_log=self._append_log,
            on_done=self._on_done,
            schedule=self._schedule,
            confirm=self._confirm_dialog,
        )

        self._build_ui()

    # -- 窗口 / 样式 --------------------------------------------------------

    def _init_window(self) -> None:
        self.root.title("fxapk · 涉诈 APK 调证分析")
        self.root.configure(bg=BG_WINDOW)
        self.root.geometry("860x680")
        self.root.minsize(720, 560)

    def _init_style(self) -> None:
        """自定义 ttk Style：扁平化（flat / borderwidth=0）+ 淡色系。"""
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")  # clam 最易做扁平化定制
        except tk.TclError:
            logger.warning("[gui] 'clam' 主题不可用，沿用默认主题")

        style.configure("TFrame", background=BG_WINDOW)
        style.configure("Card.TFrame", background=BG_CARD)
        style.configure(
            "TLabel", background=BG_WINDOW, foreground=COLOR_TEXT, font=FONT_BASE
        )
        style.configure(
            "Card.TLabel", background=BG_CARD, foreground=COLOR_TEXT, font=FONT_BASE
        )
        style.configure("Title.TLabel", background=BG_WINDOW, foreground=COLOR_TEXT, font=FONT_TITLE)
        style.configure(
            "Hint.TLabel", background=BG_WINDOW, foreground=COLOR_TEXT_MUTED, font=FONT_HINT
        )
        style.configure(
            "CardHint.TLabel", background=BG_CARD, foreground=COLOR_TEXT_MUTED, font=FONT_HINT
        )
        style.configure(
            "Counts.TLabel", background=BG_CARD, foreground=COLOR_PRIMARY, font=(_FONT_FAMILY, 11, "bold")
        )

        style.configure(
            "TCheckbutton", background=BG_CARD, foreground=COLOR_TEXT, font=FONT_BASE
        )
        style.map("TCheckbutton", background=[("active", BG_CARD)])
        style.configure(
            "TRadiobutton", background=BG_CARD, foreground=COLOR_TEXT, font=FONT_BASE
        )
        style.map("TRadiobutton", background=[("active", BG_CARD)])

        # 输入框：扁平细边。
        style.configure(
            "Flat.TEntry",
            fieldbackground=BG_CARD,
            background=BG_CARD,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_BORDER,
            relief="flat",
            padding=6,
        )
        style.configure(
            "Flat.TSpinbox",
            fieldbackground=BG_CARD,
            bordercolor=COLOR_BORDER,
            relief="flat",
            padding=4,
            arrowsize=12,
        )

        # 主操作按钮：强调色实心大按钮（扁平、无凸起）。
        style.configure(
            "Primary.TButton",
            background=COLOR_PRIMARY,
            foreground="#FFFFFF",
            font=FONT_BTN_PRIMARY,
            relief="flat",
            borderwidth=0,
            focusthickness=0,
            padding=(18, 12),
        )
        style.map(
            "Primary.TButton",
            background=[("active", COLOR_PRIMARY_ACTIVE), ("disabled", COLOR_BORDER)],
            foreground=[("disabled", COLOR_TEXT_MUTED)],
        )

        # 次按钮：浅底深字、扁平。
        style.configure(
            "Secondary.TButton",
            background="#EAF1FE",
            foreground=COLOR_PRIMARY,
            font=FONT_BTN,
            relief="flat",
            borderwidth=0,
            focusthickness=0,
            padding=(14, 10),
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#DCE8FD"), ("disabled", BG_WINDOW)],
            foreground=[("disabled", COLOR_TEXT_MUTED)],
        )

        # 文字/描边按钮（最弱化的体检按钮）。
        style.configure(
            "Ghost.TButton",
            background=BG_CARD,
            foreground=COLOR_TEXT_MUTED,
            font=FONT_BTN,
            relief="flat",
            borderwidth=0,
            focusthickness=0,
            padding=(14, 10),
        )
        style.map(
            "Ghost.TButton",
            background=[("active", "#F0F2F5"), ("disabled", BG_CARD)],
            foreground=[("disabled", COLOR_BORDER)],
        )

        # 小工具按钮（浏览 / 打开报告）。
        style.configure(
            "Tool.TButton",
            background="#EDF2F7",
            foreground=COLOR_TEXT,
            font=FONT_BTN,
            relief="flat",
            borderwidth=0,
            focusthickness=0,
            padding=(10, 6),
        )
        style.map("Tool.TButton", background=[("active", "#E2E8F0")])

    # -- 布局 ---------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, style="TFrame", padding=PAD)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        # 日志区那一行可伸缩。
        outer.rowconfigure(4, weight=1)

        self._build_header(outer)
        self._build_input_card(outer)
        self._build_action_bar(outer)
        self._build_log_card(outer)
        self._build_result_card(outer)

    def _build_header(self, parent: ttk.Frame) -> None:
        header = ttk.Frame(parent, style="TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, PAD))
        ttk.Label(header, text="fxapk 调证分析", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="① 选 APK  →  ② 点【一键全自动】或【静态分析】  ·  无设备也能跑纯静态",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(4, 0))

    def _build_input_card(self, parent: ttk.Frame) -> None:
        card = self._card(parent, row=1)
        card.columnconfigure(1, weight=1)

        # APK 选择。
        ttk.Label(card, text="APK 文件", style="Card.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 10), pady=6
        )
        ttk.Entry(card, textvariable=self.var_apk, style="Flat.TEntry").grid(
            row=0, column=1, sticky="ew", pady=6
        )
        ttk.Button(card, text="浏览…", style="Tool.TButton", command=self._browse_apk).grid(
            row=0, column=2, sticky="w", padx=(10, 0), pady=6
        )

        # 输出目录。
        ttk.Label(card, text="输出目录", style="Card.TLabel").grid(
            row=1, column=0, sticky="w", padx=(0, 10), pady=6
        )
        ttk.Entry(card, textvariable=self.var_out, style="Flat.TEntry").grid(
            row=1, column=1, sticky="ew", pady=6
        )
        ttk.Button(card, text="选择…", style="Tool.TButton", command=self._browse_out).grid(
            row=1, column=2, sticky="w", padx=(10, 0), pady=6
        )

        # 选项行：联网 / 格式 / 抓包时长。
        opts = ttk.Frame(card, style="Card.TFrame")
        opts.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(8, 0))

        ttk.Radiobutton(opts, text="离线", value=False, variable=self.var_online).pack(side="left")
        ttk.Radiobutton(opts, text="联网富化", value=True, variable=self.var_online).pack(
            side="left", padx=(8, 18)
        )

        ttk.Label(opts, text="输出：", style="Card.TLabel").pack(side="left")
        ttk.Checkbutton(opts, text="HTML", variable=self.var_html).pack(side="left", padx=(0, 8))
        ttk.Checkbutton(opts, text="JSON", variable=self.var_json).pack(side="left", padx=(0, 8))
        ttk.Checkbutton(opts, text="PDF", variable=self.var_pdf).pack(side="left", padx=(0, 18))

        ttk.Label(opts, text="抓包时长(秒)：", style="Card.TLabel").pack(side="left")
        ttk.Spinbox(
            opts,
            from_=10,
            to=600,
            increment=10,
            width=5,
            textvariable=self.var_duration,
            style="Flat.TSpinbox",
        ).pack(side="left")
        ttk.Label(opts, text="（仅一键全自动用）", style="CardHint.TLabel").pack(
            side="left", padx=(6, 0)
        )

    def _build_action_bar(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent, style="TFrame")
        bar.grid(row=2, column=0, sticky="ew", pady=(PAD, PAD))

        btn_auto = ttk.Button(
            bar, text="🚀 一键全自动", style="Primary.TButton", command=self._on_auto
        )
        btn_auto.pack(side="left")
        self._tooltip(btn_auto, "体检 → 静态 → 脱壳 → 抓包 → 合并；无设备时自动跳过动态步骤")

        btn_static = ttk.Button(
            bar, text="静态分析", style="Secondary.TButton", command=self._on_static
        )
        btn_static.pack(side="left", padx=(10, 0))
        self._tooltip(btn_static, "仅静态分析（不连设备）：提取端点 / 服务归属 / 调证线索")

        btn_doctor = ttk.Button(
            bar, text="环境体检", style="Ghost.TButton", command=self._on_doctor
        )
        btn_doctor.pack(side="left", padx=(10, 0))
        self._tooltip(btn_doctor, "检查设备 / root / frida / mitmproxy / CA，可自动修复")

        self._action_buttons = [btn_auto, btn_static, btn_doctor]

    def _build_log_card(self, parent: ttk.Frame) -> None:
        card = self._card(parent, row=4, sticky="nsew")
        card.rowconfigure(1, weight=1)
        card.columnconfigure(0, weight=1)

        ttk.Label(card, text="运行日志", style="Card.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )

        wrap = ttk.Frame(card, style="Card.TFrame")
        wrap.grid(row=1, column=0, sticky="nsew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        self.log_text = tk.Text(
            wrap,
            wrap="word",
            height=10,
            relief="flat",
            borderwidth=0,
            bg="#FBFCFE",
            fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            font=FONT_MONO,
            padx=10,
            pady=8,
            state="disabled",
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=self.log_text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scroll.set)

        # 空状态提示（新手友好）。
        self._set_log_placeholder()

    def _build_result_card(self, parent: ttk.Frame) -> None:
        card = self._card(parent, row=5)
        card.columnconfigure(0, weight=1)

        ttk.Label(card, text="结果", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(card, textvariable=self.var_counts, style="Counts.TLabel").grid(
            row=1, column=0, sticky="w", pady=(4, 8)
        )

        btns = ttk.Frame(card, style="Card.TFrame")
        btns.grid(row=2, column=0, sticky="w")
        self.btn_open_html = ttk.Button(
            btns, text="打开 HTML 报告", style="Tool.TButton", command=self._open_html, state="disabled"
        )
        self.btn_open_html.pack(side="left")
        self.btn_open_dir = ttk.Button(
            btns, text="打开输出目录", style="Tool.TButton", command=self._open_dir, state="disabled"
        )
        self.btn_open_dir.pack(side="left", padx=(10, 0))

    def _card(self, parent: ttk.Frame, *, row: int, sticky: str = "ew") -> ttk.Frame:
        """统一卡片容器（白底 + 内边距 + 栅格放置）。"""
        card = ttk.Frame(parent, style="Card.TFrame", padding=PAD)
        card.grid(row=row, column=0, sticky=sticky, pady=(0, PAD))
        return card

    # -- 事件：浏览 / 动作 --------------------------------------------------

    def _browse_apk(self) -> None:
        path = filedialog.askopenfilename(
            title="选择 APK 文件",
            filetypes=[("APK 文件", "*.apk"), ("所有文件", "*.*")],
        )
        if path:
            self.var_apk.set(path)

    def _browse_out(self) -> None:
        path = filedialog.askdirectory(title="选择输出目录")
        if path:
            self.var_out.set(path)

    def _on_auto(self) -> None:
        self._start(ACTION_AUTO)

    def _on_static(self) -> None:
        self._start(ACTION_STATIC)

    def _on_doctor(self) -> None:
        self._start(ACTION_DOCTOR)

    def _start(self, action: str) -> None:
        """组装 ActionRequest 并交给 controller；**仅受理后**才清日志 + 禁用按钮。

        先禁用按钮再 start；只有真正受理（start 返回 True）才清掉上一次运行日志，
        避免「忙 / 未选 APK」这类被拒场景把用户上一次的运行记录清空。
        """
        request = ActionRequest(
            action=action,
            apk_path=self.var_apk.get().strip(),
            out_dir=self.var_out.get().strip() or "out",
            online=bool(self.var_online.get()),
            formats=self._collect_formats(),
            capture_duration=int(self.var_duration.get()),
        )
        self._set_buttons_enabled(False)
        if self.controller.start(request):
            # 已受理：清掉占位/上轮日志，开始本次运行（进度经 on_log 实时 append）。
            self._clear_log()
            return
        # 被拒（忙 / 校验失败）：保留上一次日志不清。controller 已经 on_done 回友好结果
        # （含恢复按钮）；但若纯粹是「忙」则 on_done 不触发，这里兜底恢复按钮。
        if not self.controller.busy:
            self._set_buttons_enabled(True)

    def _collect_formats(self) -> list[str]:
        fmts: list[str] = []
        if self.var_html.get():
            fmts.append("html")
        if self.var_json.get():
            fmts.append("json")
        if self.var_pdf.get():
            fmts.append("pdf")
        return fmts or ["html", "json"]

    # -- controller 注入的回调（均在主线程执行：schedule=root.after(0, fn)） ----

    def _schedule(self, fn: Callable[[], None]) -> None:
        """把无参可调用对象排到 UI 主线程执行（tkinter 线程安全要求）。"""
        try:
            self.root.after(0, fn)
        except Exception:
            logger.exception("[gui] root.after 调度失败（窗口可能已销毁）")

    def _append_log(self, text: str) -> None:
        self._ensure_log_ready()
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _on_done(self, result: ActionResult) -> None:
        """动作结束：渲染步骤摘要 + 计数 + 恢复按钮 + 打开按钮可用性 + 友好提示。"""
        self._set_buttons_enabled(True)
        self._render_steps(result)
        self._render_counts(result)

        self._last_html = result.html_report
        self._last_out = result.out_dir
        self.btn_open_html.configure(state=("normal" if result.html_report else "disabled"))
        self.btn_open_dir.configure(state=("normal" if result.out_dir else "disabled"))

        if result.ok:
            self._append_log(f"✓ {result.message}")
        else:
            self._append_log(f"✗ {result.message}")
            messagebox.showwarning("未完全成功", result.message, parent=self.root)

    def _render_steps(self, result: ActionResult) -> None:
        if not result.steps:
            return
        self._append_log("—— 步骤摘要 ——")
        marks = {"done": "✓", "skipped": "·", "error": "✗"}
        for step in result.steps:
            mark = marks.get(str(step.get("status")), "?")
            name = step.get("name", "?")
            detail = step.get("detail", "")
            line = f"  {mark} {name}（{step.get('status_label', '')}）"
            if detail:
                line += f"：{detail}"
            self._append_log(line)

    def _render_counts(self, result: ActionResult) -> None:
        c = result.counts
        if c.known:
            self.var_counts.set(
                f"端点 {_n(c.endpoints)}    线索 {_n(c.leads)}    发现 {_n(c.findings)}"
            )
        else:
            self.var_counts.set("端点 -    线索 -    发现 -")

    # -- confirm 对话框（抓包前提示用户操作 app；在 worker 线程被阻塞调用） ----

    def _confirm_dialog(self, message: str) -> None:
        """抓包前弹模态对话框，阻塞 worker 线程直到用户点确定（tkinter 线程安全：用
        Event 在 worker 线程等待，对话框在主线程经 schedule 弹出）。"""
        import threading

        done = threading.Event()

        def _ask() -> None:
            try:
                messagebox.showinfo("准备抓包", message, parent=self.root)
            except Exception:
                logger.exception("[gui] 抓包确认对话框异常（已忽略，继续抓包）")
            finally:
                done.set()

        self._schedule(_ask)
        # 阻塞 worker 线程直到主线程对话框关闭；最长等 10 分钟兜底防卡死。
        if not done.wait(timeout=600):
            logger.warning("[gui] 抓包确认对话框等待超时，继续抓包")

    # -- 打开报告 / 目录 ----------------------------------------------------

    def _open_html(self) -> None:
        if not self._last_html:
            return
        try:
            webbrowser.open(Path(self._last_html).resolve().as_uri())
        except Exception:
            logger.exception("[gui] 打开 HTML 报告失败：%s", self._last_html)
            messagebox.showerror("打开失败", "无法打开 HTML 报告（详见日志）。", parent=self.root)

    def _open_dir(self) -> None:
        if not self._last_out:
            return
        target = Path(self._last_out)
        try:
            if sys.platform == "win32":
                os.startfile(str(target))  # noqa: S606 - Windows 资源管理器打开目录
            elif sys.platform == "darwin":
                import subprocess

                subprocess.Popen(["open", str(target)])  # noqa: S603,S607
            else:
                import subprocess

                subprocess.Popen(["xdg-open", str(target)])  # noqa: S603,S607
        except Exception:
            logger.exception("[gui] 打开输出目录失败：%s", target)
            messagebox.showerror("打开失败", "无法打开输出目录（详见日志）。", parent=self.root)

    # -- 小工具 -------------------------------------------------------------

    def _set_buttons_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for btn in self._action_buttons:
            btn.configure(state=state)

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._log_has_content = True

    def _set_log_placeholder(self) -> None:
        self._log_has_content = False
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert(
            "end",
            "还没有运行任务。\n选好 APK 后，点上方按钮开始；这里会实时显示进度。\n",
        )
        self.log_text.configure(state="disabled")

    def _ensure_log_ready(self) -> None:
        """首次写真实日志前清掉占位文案。"""
        if not getattr(self, "_log_has_content", False):
            self._clear_log()

    def _tooltip(self, widget: tk.Widget, text: str) -> None:
        """极简 tooltip（悬停显示说明，新手友好；无第三方依赖）。"""
        tip: dict[str, tk.Toplevel | None] = {"win": None}

        def _show(_event: object) -> None:
            if tip["win"] is not None:
                return
            try:
                x = widget.winfo_rootx() + 12
                y = widget.winfo_rooty() + widget.winfo_height() + 6
                win = tk.Toplevel(widget)
                win.wm_overrideredirect(True)
                win.wm_geometry(f"+{x}+{y}")
                tk.Label(
                    win,
                    text=text,
                    bg="#2D3748",
                    fg="#FFFFFF",
                    font=FONT_HINT,
                    padx=8,
                    pady=4,
                    justify="left",
                ).pack()
                tip["win"] = win
            except Exception:
                logger.debug("[gui] 显示 tooltip 失败（忽略）", exc_info=True)

        def _hide(_event: object) -> None:
            win = tip["win"]
            if win is not None:
                try:
                    win.destroy()
                except Exception:
                    logger.debug("[gui] 销毁 tooltip 失败（忽略）", exc_info=True)
                tip["win"] = None

        widget.bind("<Enter>", _show)
        widget.bind("<Leave>", _hide)


def _n(value: int) -> str:
    """计数显示：-1（未知）→ '-'，否则数字。"""
    return "-" if value < 0 else str(value)


def run_app() -> None:
    """创建 Tk root、实例化 App、进入 mainloop。仅 main() 调用，模块级不调。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    root = tk.Tk()
    App(root)
    root.mainloop()


__all__ = ["App", "run_app"]
