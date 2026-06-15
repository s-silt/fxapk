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
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

logger = logging.getLogger(__name__)

# 看门狗必须跑在**真**后台线程上。单测会把 ``threading.Thread`` 替成同步替身（让 worker
# 在当前线程确定性执行），但看门狗若也同步执行就会在 ``_run`` 里空转死循环（永不被 disarm）。
# 故在 import 期固定真 ``Thread``，看门狗专用，不受测试对 ``threading.Thread`` 的 patch 影响。
_RealThread = threading.Thread

# 三个动作标识（避免裸字符串漂移；view 按钮 → controller 分派以此识别）。
ACTION_DOCTOR = "doctor"
ACTION_STATIC = "static"
ACTION_AUTO = "auto"
ACTION_BATCH = "batch"  # 文件夹批量分析（逐个 launch-only auto + 卸载）

# 批量 launch-only 抓包固定时长（秒）：只抓冷启动流量，逐个都短一点；不开放给用户调。
_BATCH_DURATION = 30

# 待分析文件类型（GUI 两栏分别选 APK / IPA）。IPA 仅支持静态分析（不连设备、无动态）。
FILE_TYPE_APK = "apk"
FILE_TYPE_IPA = "ipa"

# 取消后等子进程（及其进程树）退出、stdout 管道 EOF 的看门狗超时（秒）。
# 超时后强杀 + 放弃读循环，避免孙进程（mitmdump/frida）继续占着管道写端 → 读循环永久阻塞。
_CANCEL_GRACE_SECONDS = 5.0


def _frozen() -> bool:
    """是否 PyInstaller 冻结态（决定子进程命令是 exe 自调用还是 ``-m apkscan.cli``）。

    本阶段不引入 ``apkscan.core.tools``（属打包阶段）；冻结判定就地内联。
    """
    return bool(getattr(sys, "frozen", False))


# -- 取消时收割子进程**及其进程树**（孙进程 mitmdump/frida 不能成孤儿，详见 cancel 文档） --


def _kill_process_tree(proc: subprocess.Popen[str]) -> None:
    """尽力杀掉 ``proc`` 及其整棵进程树（含 mitmdump/frida 等孙进程）。绝不抛。

    - Windows：``taskkill /F /T /PID <pid>``（``/T`` 连杀子孙、``/F`` 强杀），失败再退回
      ``proc.kill()``。``taskkill`` 用 ``CREATE_NO_WINDOW`` 避免弹控制台。
    - POSIX：进程以 ``start_new_session`` 起（独立进程组），向进程组发 ``SIGTERM``；拿不到
      进程组就退回 ``proc.terminate()``。
    进程已退出（``taskkill`` 报错 / ``ProcessLookupError`` / ``OSError``）均吞 + logging。
    """
    pid = proc.pid
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                check=False,
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return
        except Exception:  # noqa: BLE001 - taskkill 不可用 / 进程已退；退回 kill
            logger.exception("[gui] taskkill 收割进程树失败，退回 kill：pid=%s", pid)
    # POSIX：向进程组发 SIGTERM 收割整组（含孙进程）。getpgid/killpg 仅 POSIX 有，
    # 故经 getattr 访问以兼容 Windows 静态检查（Windows 不走到此分支）。
    getpgid = getattr(os, "getpgid", None)
    killpg = getattr(os, "killpg", None)
    try:
        import signal

        if getpgid is not None and killpg is not None:
            killpg(getpgid(pid), signal.SIGTERM)
            return
    except (ProcessLookupError, OSError):
        logger.exception("[gui] 向进程组发信号失败，退回 terminate：pid=%s", pid)
    try:
        proc.terminate()
    except Exception:  # noqa: BLE001 - 进程可能已退出，无害
        logger.exception("[gui] 终止子进程失败（可能已退出）：pid=%s", pid)


class _CancelWatchdog:
    """看门狗线程：取消请求发出后，等宽限期仍未退出就强 ``kill()`` 子进程。

    根因：``auto`` 抓包时孙进程（mitmdump/frida）继承了 GUI↔子进程的 stdout 管道写端；
    即便 ``cancel()`` 已收割进程树，竞态下读循环可能短暂仍卡——看门狗是兜底，超时强杀让
    管道彻底 EOF、读循环退出、``wait()`` 返回。``cancelled`` 未置时看门狗空转后即退出。
    """

    def __init__(
        self, proc: subprocess.Popen[str], cancelled: threading.Event, grace_seconds: float
    ) -> None:
        self._proc = proc
        self._cancelled = cancelled
        self._grace = grace_seconds
        self._disarmed = threading.Event()
        # 用固定的真 Thread（见模块顶 _RealThread 注释）：测试把 threading.Thread 替成同步替身
        # 是为 worker，看门狗不能被波及（否则同步执行 _run → 永不 disarm 的死循环）。
        self._thread = _RealThread(
            target=self._run, daemon=True, name="apkscan-gui-cancel-watchdog"
        )

    def start(self) -> None:
        self._thread.start()

    def disarm(self) -> None:
        """读循环正常收束后调用：让看门狗立刻退出，不再强杀。"""
        self._disarmed.set()

    def _run(self) -> None:
        # 等到「取消被请求」或「读循环已收束（disarm）」任一发生。
        while not self._disarmed.is_set():
            if self._cancelled.wait(timeout=0.1):
                break
        if self._disarmed.is_set():
            return  # 读循环已正常结束，无需介入
        # 取消已请求：给整树收割留宽限期；超时仍存活 → 强 kill 兜底（防孙进程拖住管道）。
        if self._disarmed.wait(timeout=self._grace):
            return  # 宽限期内已 EOF 收束
        if self._proc.poll() is None:
            logger.warning("[gui] 取消后子进程仍存活，看门狗强制 kill：pid=%s", self._proc.pid)
            try:
                self._proc.kill()
            except Exception:  # noqa: BLE001 - 进程可能刚退出，无害
                logger.exception("[gui] 看门狗强杀子进程失败：pid=%s", self._proc.pid)


# -- 防呆校验（纯函数，零 Tk，headless 可测；返回 None=通过 / str=友好文案，绝不抛） ----

# ZIP/APK 本质是 ZIP，魔数以下列之一开头（本地文件头 / 空档案 / 跨段档案）。
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def validate_apk_path(apk_path: str) -> str | None:
    """校验 APK 路径（static/auto 用）。返回 ``None`` 通过，否则返回友好错误文案（中文、具体、不吓人）。

    顺序：空 → 不存在 → 是目录 → 不可读 → 空文件 → 既非 ``.apk`` 后缀又非 ZIP(PK) 魔数。
    全程 try/OSError 包裹：任何 IO 异常都转成友好文案而非抛。
    放行策略：``.apk`` 后缀 **或** PK 魔数 任一满足即过（宽松，容忍无后缀真 APK / 改后缀场景）。
    """
    p = (apk_path or "").strip()
    if not p:
        return "请先选择一个 APK 文件再开始。"
    try:
        path = Path(p)
        if not path.exists():
            return f"找不到这个文件，路径可能已改名或被移动：\n{p}"
        if path.is_dir():
            return "这是一个文件夹，请选择 .apk 文件本身。"
        if not os.access(p, os.R_OK):
            return "没有读取权限，请检查文件是否被占用或换个位置。"
        if path.stat().st_size == 0:
            return "这个文件是空的（0 字节），不是有效的 APK。"
        has_apk_suffix = path.suffix.lower() == ".apk"
        try:
            with path.open("rb") as fh:
                head = fh.read(4)
        except OSError:
            logger.exception("[gui] 读取 APK 头部失败：%s", p)
            return "没有读取权限，请检查文件是否被占用或换个位置。"
        is_zip = any(head.startswith(magic) for magic in _ZIP_MAGICS)
        if not has_apk_suffix and not is_zip:
            return "这看起来不是一个 APK 文件（应是 ZIP/PK 格式）。"
    except OSError:
        logger.exception("[gui] 校验 APK 路径时 IO 异常：%s", p)
        return "没有读取权限，请检查文件是否被占用或换个位置。"
    return None


def _zip_has_payload(path: str) -> bool:
    """IPA 判定辅助：ZIP 内是否含 ``Payload/`` 目录（IPA 的标志性结构）。绝不抛。"""
    import zipfile

    try:
        with zipfile.ZipFile(path) as zf:
            return any(name.startswith("Payload/") for name in zf.namelist())
    except (zipfile.BadZipFile, OSError):
        logger.exception("[gui] 探测 IPA Payload 结构失败：%s", path)
        return False


def validate_ipa_path(ipa_path: str) -> str | None:
    """校验 IPA 路径（iOS 栏静态分析用）。返回 ``None`` 通过，否则友好错误文案，绝不抛。

    顺序与 :func:`validate_apk_path` 一致（空 → 不存在 → 目录 → 不可读 → 空文件 → 非 IPA）。
    放行策略：须先是 ZIP(PK 魔数)；再 ``.ipa`` 后缀 **或** ZIP 内含 ``Payload/``（IPA 标志）
    任一满足即过——后缀容忍改名场景，``Payload/`` 探测兜住无后缀真 IPA，且把普通 APK/ZIP
    （无 ``Payload/``、无 ``.ipa`` 后缀）挡在 iOS 栏外，避免误投。
    """
    p = (ipa_path or "").strip()
    if not p:
        return "请先选择一个 IPA 文件再开始。"
    try:
        path = Path(p)
        if not path.exists():
            return f"找不到这个文件，路径可能已改名或被移动：\n{p}"
        if path.is_dir():
            return "这是一个文件夹，请选择 .ipa 文件本身。"
        if not os.access(p, os.R_OK):
            return "没有读取权限，请检查文件是否被占用或换个位置。"
        if path.stat().st_size == 0:
            return "这个文件是空的（0 字节），不是有效的 IPA。"
        has_ipa_suffix = path.suffix.lower() == ".ipa"
        try:
            with path.open("rb") as fh:
                head = fh.read(4)
        except OSError:
            logger.exception("[gui] 读取 IPA 头部失败：%s", p)
            return "没有读取权限，请检查文件是否被占用或换个位置。"
        is_zip = any(head.startswith(magic) for magic in _ZIP_MAGICS)
        if not is_zip:
            return "这看起来不是一个 IPA 文件（应是 ZIP 容器，内含 Payload/<App>.app）。"
        # .ipa 后缀直接放行；无后缀则须含 Payload/ 才认定为 IPA（与普通 APK/ZIP 区分）。
        if not has_ipa_suffix and not _zip_has_payload(p):
            return "这看起来不是一个 IPA 文件（ZIP 内未找到 Payload/<App>.app）。"
    except OSError:
        logger.exception("[gui] 校验 IPA 路径时 IO 异常：%s", p)
        return "没有读取权限，请检查文件是否被占用或换个位置。"
    return None


def resolve_out_dir(out_dir: str) -> str:
    """把 out_dir 解析为绝对路径字符串（**不创建**）。空串 → 'out' → resolve。

    resolve 失败（极端非法路径）→ 退回原（或 'out'）字符串，不抛。
    可发现性：冻结 exe 下 cwd 不可控，绝对化后日志/「打开目录」才指向真实产物位置。

    含 NUL 等非法字符的路径 ``Path.resolve()`` 抛的是 ``ValueError``（"embedded null
    character"）而非 ``OSError``——一并捕获，守住「绝不抛」契约（粘贴构造路径可触发）。
    """
    raw = (out_dir or "").strip() or "out"
    try:
        return str(Path(raw).resolve())
    except (OSError, ValueError):
        logger.exception("[gui] 解析输出目录为绝对路径失败，退回原串：%s", raw)
        return raw


def validate_out_dir(out_dir: str) -> str | None:
    """校验输出目录可创建/可写。返回 ``None`` 通过，否则友好文案，绝不抛。

    策略：已存在 → 须是目录且可写（``os.access(W_OK)``）；不存在 → 尝试 ``mkdir(parents=True,
    exist_ok=True)`` 创建（建成即视为可写，目录留着无害）。失败（OSError/PermissionError）→
    友好文案。提前建目标产物目录是受控副作用（本就要建），且能最真实探测「可写」。

    含 NUL 等非法字符时 ``Path.exists()/stat()`` 抛 ``ValueError`` 而非 ``OSError``——一并捕获，
    守住「绝不抛」契约（resolve_out_dir 已先挡一层，这里再兜底 exists/stat 路径）。
    """
    abs_out = resolve_out_dir(out_dir)
    fail_msg = f"无法创建/写入输出目录（可能无权限或磁盘只读），换一个位置试试：\n{abs_out}"
    try:
        path = Path(abs_out)
        if path.exists():
            if not path.is_dir():
                return f"输出目录的位置被一个同名文件占用了，换一个位置试试：\n{abs_out}"
            if not os.access(abs_out, os.W_OK):
                return fail_msg
            return None
        path.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError):
        logger.exception("[gui] 校验/创建输出目录失败：%s", abs_out)
        return fail_msg
    return None


def validate_folder(folder: str) -> str | None:
    """校验批量分析的文件夹路径。返回 ``None`` 通过，否则友好错误文案（中文、具体），绝不抛。

    顺序：空 → 不存在 → 是文件（非目录）→ 不可读。空文件夹（无 APK）不算错——交由引擎
    扫出 0 个、如实汇总。
    """
    p = (folder or "").strip()
    if not p:
        return "请先选择一个文件夹再开始。"
    try:
        path = Path(p)
        if not path.exists():
            return f"找不到这个文件夹，路径可能已改名或被移动：\n{p}"
        if not path.is_dir():
            return "这是一个文件，请选择一个**文件夹**（里面放待分析的 APK）。"
        if not os.access(p, os.R_OK):
            return "没有读取权限，请检查文件夹是否可访问或换个位置。"
    except OSError:
        logger.exception("[gui] 校验文件夹路径时 IO 异常：%s", p)
        return "没有读取权限，请检查文件夹是否可访问或换个位置。"
    return None


def clamp_duration(raw: str, *, lo: int = 10, hi: int = 600, default: int = 60) -> int:
    """Spinbox 文本 → ``[lo, hi]`` 内的 int。空 / 非数字 → ``default``；越界 → 钳到边界。**绝不抛**。"""
    try:
        value = int((raw or "").strip())
    except (ValueError, TypeError):
        return default
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def install_jadx_addon(zip_path: str, dest_base: str | None = None) -> tuple[bool, str]:
    """把 jadx 插件包 zip 解压到应用目录下的 ``jadx-addon/``，校验 jadx + JRE 就位。

    一键启用 jadx 深度反编译：解压后 ``tools.resolve_jadx()`` 即能发现并调用（GUI 静态/
    一键全自动自动用上 jadx）。dest_base 缺省取 ``tools.app_data_dirs()[0]``（frozen=exe
    同级 / 源码=repo 根）。**绝不抛**——任何失败返回 ``(False, 中文原因)``。
    """
    import zipfile

    from apkscan.core import tools

    p = Path(zip_path)
    if not p.is_file():
        return False, f"插件包不存在：{zip_path}"
    if not zipfile.is_zipfile(p):
        return False, "选择的文件不是有效的 zip 插件包。"

    try:
        dirs = tools.app_data_dirs()
        base = Path(dest_base) if dest_base else (dirs[0] if dirs else Path("."))
    except Exception:
        logger.exception("[gui] 解析应用目录失败，回退当前目录")
        base = Path(".")

    addon = base / tools._JADX_ADDON_NAME
    # 重装前清掉旧目录：**不静默吞错**——被占用（jadx 正在跑 / 杀软锁文件）导致删不净时
    # 如实返回失败，避免旧残留与新内容混合却仍报"已启用"（resolve_jadx 可能指向半残 JRE，
    # 或 bat 校验命中的是上一版 jadx）。
    if addon.exists():
        try:
            shutil.rmtree(addon)
        except OSError as exc:
            logger.exception("[gui] 清理旧 jadx-addon 失败：%s", addon)
            return False, f"无法清理旧插件目录（可能被占用，请关闭正在运行的 jadx 后重试）：{exc}"
    try:
        addon.mkdir(parents=True, exist_ok=True)
        # ★ 依赖 zipfile.extractall 对成员名的清洗（剥离前导分隔符/盘符、丢弃 ".." → 实测无
        #   zip-slip 逃逸）。**勿**改为手写 zf.extract(member, 自拼路径) 循环——那会引入路径穿越。
        with zipfile.ZipFile(p) as zf:
            zf.extractall(addon)
    except Exception as exc:  # noqa: BLE001 - 解压失败如实返回，不崩 GUI
        logger.exception("[gui] 解压 jadx 插件包失败：%s", zip_path)
        return False, f"解压失败：{exc}"

    bat = addon / "jadx" / "bin" / tools._jadx_bat_name()
    if not bat.is_file():
        return False, "插件包内未找到 jadx（缺 jadx/bin/jadx.bat），可能不是 fxapk-jadx 插件包。"
    msg = f"jadx 深度反编译已启用：{addon}"
    if not (addon / "jre" / "bin").is_dir():
        msg += "（注意：插件包未含便携 JRE，需本机已装 Java 才能跑 jadx）"
    return True, msg


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
    - ``out_dir``：输出目录（**绝对路径**，供「打开输出目录」按钮 + 日志可发现性提示）。
    - ``cancelled``：True 表示用户主动取消（view 据此**不弹 warning messagebox**，与真错误区分）。
    """

    ok: bool
    action: str
    message: str
    steps: list[dict] = field(default_factory=list)
    counts: Counts = field(default_factory=Counts)
    report_paths: list[str] = field(default_factory=list)
    html_report: str = ""
    out_dir: str = ""
    cancelled: bool = False


@dataclass
class ActionRequest:
    """view 发起一次动作的入参（一个数据类，避免长参数列表漂移）。"""

    action: str
    apk_path: str = ""
    out_dir: str = "out"
    online: bool = True  # 默认联网富化（与 cli analyze/auto 一致）；view 总是显式传 var_online
    formats: list[str] = field(default_factory=lambda: ["html", "json"])
    # Spinbox 原始文本（可能空 / 非数字）。钳制责任全在 controller `clamp_duration`，
    # 把 ``IntVar.get()`` 的 ``tk.TclError`` 风险从 view 移走（view 改传 widget `.get()` str）。
    capture_duration_raw: str = "60"
    auto_fix: bool = True
    # GUI 两栏分别选 APK / IPA。FILE_TYPE_IPA 时取 ``ipa_path``、仅允许静态分析（CLI analyze
    # 经 load_app 自动分流 IPA，无需额外子命令）。默认 apk 保持旧调用方（含测试）行为不变。
    file_type: str = FILE_TYPE_APK
    ipa_path: str = ""
    # 批量分析（ACTION_BATCH）专用：待扫描文件夹 + 是否无视台账全部重跑。
    folder: str = ""
    force: bool = False

    @property
    def target_path(self) -> str:
        """按 ``file_type`` 取当前要分析的文件路径（IPA 栏 → ipa_path，否则 apk_path）。"""
        return self.ipa_path if self.file_type == FILE_TYPE_IPA else self.apk_path


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
        # 当前子进程句柄（供 cancel 收割）；_lock 同时保护 _proc 与 _busy。
        self._proc: subprocess.Popen[str] | None = None
        # 取消标志（cancel 与 worker 跨线程协作；worker 据此把结果覆盖为友好「已取消」）。
        self._cancelled = threading.Event()

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
            # IPA 仅支持静态分析（不连设备、无脱壳/抓包）；一键全自动是 Android 专属，挡住。
            if request.file_type == FILE_TYPE_IPA and request.action == ACTION_AUTO:
                self._emit_result(
                    ActionResult(
                        ok=False,
                        action=request.action,
                        message="iOS IPA 仅支持静态分析，请改用【静态分析】按钮。",
                    )
                )
                return False
            # 静态 / 一键需要待分析文件（含空串、不存在、非 APK/IPA 等防呆校验）；doctor 不需要。
            # 按 file_type 选对应校验器：IPA 栏校验 .ipa（ZIP+Payload），APK 栏校验 .apk（ZIP/PK）。
            if request.action in (ACTION_STATIC, ACTION_AUTO):
                if request.file_type == FILE_TYPE_IPA:
                    path_err = validate_ipa_path(request.ipa_path)
                else:
                    path_err = validate_apk_path(request.apk_path)
                if path_err:
                    self._emit_result(
                        ActionResult(ok=False, action=request.action, message=path_err)
                    )
                    return False
            # 批量分析：校验待扫描文件夹（存在 / 是目录 / 可读）。
            if request.action == ACTION_BATCH:
                folder_err = validate_folder(request.folder)
                if folder_err:
                    self._emit_result(
                        ActionResult(ok=False, action=request.action, message=folder_err)
                    )
                    return False
            # 输出目录绝对化（各动作都做，可发现性）。绝对路径回填进 request 供子进程/结果用。
            abs_out = resolve_out_dir(request.out_dir)
            request = replace(request, out_dir=abs_out)
            # static/auto/batch 产报告，提前校验可写以免白跑；doctor 不产报告，跳过 out 校验。
            if request.action in (ACTION_STATIC, ACTION_AUTO, ACTION_BATCH):
                out_err = validate_out_dir(abs_out)
                if out_err:
                    self._emit_result(
                        ActionResult(
                            ok=False, action=request.action, message=out_err, out_dir=abs_out
                        )
                    )
                    return False
            self._busy = True
            self._cancelled.clear()  # 新一轮开始前清取消标志

        thread = threading.Thread(
            target=self._run_worker, args=(request,), daemon=True, name="apkscan-gui-worker"
        )
        thread.start()
        return True

    # -- 对外：取消 / 停止 ---------------------------------------------------

    def cancel(self) -> bool:
        """请求取消当前动作：置取消标志 + 收割子进程**及其进程树**。零 Tk。

        无运行中动作 → 返回 False（无副作用）。

        为什么收割整棵进程树（而非只 ``terminate()`` 直接子进程）：``auto`` 抓包阶段，
        子进程（``-m apkscan.cli``）会再 spawn ``mitmdump`` / ``frida`` 等**孙进程**
        （见 :mod:`apkscan.dynamic.capture`）。它们的清理只在 ``capture()`` 的 ``finally``
        里跑——但 Windows 的 ``terminate()`` 是 ``TerminateProcess`` 硬杀、**不跑子进程的
        Python finally** → 孙进程成孤儿（仍占代理端口 / 设备 frida）；更糟的是孙进程继承了
        GUI↔子进程的 stdout 管道写端，直接子进程虽死但管道不 EOF → ``_run_subprocess``
        的读循环**永久阻塞**、「已取消」结果永不送达。故这里用 ``taskkill /F /T``（Windows，
        ``/T`` 连杀进程树）/ 进程组信号（POSIX）把整棵树收掉。``_run_subprocess`` 侧另有
        看门狗：超时仍不 EOF 就强 ``kill()`` 并放弃读循环（双保险）。

        worker 据 ``_cancelled`` 把结果覆盖为友好「已取消」（``cancelled=True``，view 据此
        不弹 warning）。

        Returns:
            True 表示已发出取消请求；False 表示当前无运行中动作。
        """
        with self._lock:
            if not self._busy:
                return False
            self._cancelled.set()
            proc = self._proc
        if proc is not None:
            _kill_process_tree(proc)
        return True

    def stop(self) -> bool:
        """:meth:`cancel` 的别名（spec 文案「取消 / 停止」两词混用）。"""
        return self.cancel()

    # -- 对外：关窗清理（收掉自起的 adb server） ----------------------------

    def cleanup_adb(self) -> None:
        """GUI 关窗时收掉本工具自起的 adb server（headless 安全、**绝不抛**）。

        根因：dynamic 动作（doctor/auto/capture）与每次 analyze 的设备探测都会经
        ``adb`` 起一个常驻 adb server；GUI 退出时无人收 → adb.exe 残留、下次重打 exe 被锁。
        这里在关窗时收掉它。

        惰性 import ``apkscan.core.tools``（不给 import controller 增加 core 依赖；且保持
        「controller 不 import tkinter」分层不变——tools 无 Tk）。tools 缺失 / kill 失败
        一律吞 + logging，绝不阻断关窗。

        注意：GUI 分析走子进程，子进程自起的 adb server 由 CLI 侧 finally 收（见
        :mod:`apkscan.cli`）；本方法收的是 GUI 主进程（若将来直接调 core 时）起的那个。
        两者各管各进程、kill-server 幂等，无冲突。
        """
        try:
            from apkscan.core import tools

            tools.kill_adb_server()
        except Exception:
            logger.exception("[gui] 清理 adb server 失败（已忽略）")

    # -- worker（后台线程） -------------------------------------------------

    def _run_worker(self, request: ActionRequest) -> None:
        """后台线程主体：调核心 → 解析结果 → 经 schedule 把结果弹回主线程。绝不抛。

        取消感知：子进程被 ``cancel()`` 收割后退出码通常非 0，``_build_subprocess_result``
        本会回 error；这里据 ``_cancelled`` 覆盖为友好「已取消」结果（``cancelled=True``），
        保证文案是「已取消」而非「退出码非 0」，view 据此不弹 warning messagebox。

        取消-异常竞态：硬杀子进程时读流 / 回调链路偶发抛异常（管道被强制关闭等），会落到
        ``except``。此时若 ``_cancelled`` 已置，仍应回友好「已取消」而非吓人的「运行出错」
        ——故 ``except`` 分支也优先判 ``_cancelled``（与正常分支同语义）。

        迟到取消竞态：``_run_subprocess`` 的 ``finally`` 已置 ``_proc=None`` 但本方法 ``finally``
        尚未把 ``_busy=False``，这窄窗内点【停止】→ ``cancel()`` 见 ``busy`` 仍 True、置
        ``_cancelled``、却没杀到任何进程（``_proc`` 已 None），子进程其实**已成功跑完、报告
        已落盘**。若无条件覆盖成「已取消」会丢掉 html_report/counts，view 据 ``cancelled``
        只记日志、「打开 HTML 报告」按钮保持禁用——分析跑完了用户却被告知「已取消」且打不开
        报告。故仅在 ``not result.ok`` 时才 relabel：被真正杀掉的子进程 rc 非 0 且无
        report.json → ``ok=False`` → 仍走 relabel（语义不变）；迟到取消撞上真成功 →
        ``ok=True`` → 保留成功结果（含报告入口）。
        """
        try:
            result = self._dispatch(request)
            if self._cancelled.is_set() and not result.ok:
                result = self._cancelled_result(request)
        except Exception as exc:  # noqa: BLE001 - worker 绝不把异常抛出线程，转友好结果
            if self._cancelled.is_set():
                # 取消过程中抛异常：取消是用户意图，按友好「已取消」处理（不弹 warning）。
                logger.info("[gui] 取消时子进程拆卸异常（按已取消处理）：%s", exc)
                result = self._cancelled_result(request)
            else:
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

    @staticmethod
    def _cancelled_result(request: ActionRequest) -> ActionResult:
        """构造统一的友好「已取消」结果（``cancelled=True``，view 据此不弹 warning）。"""
        return ActionResult(
            ok=False,
            action=request.action,
            message="已取消本次任务。",
            cancelled=True,
            out_dir=request.out_dir,
        )

    def _dispatch(self, request: ActionRequest) -> ActionResult:
        """按 action 分派：全部经**子进程跑 CLI**（卡死修复核心）。"""
        if request.action == ACTION_DOCTOR:
            return self._run_doctor(request)
        if request.action == ACTION_STATIC:
            return self._run_static(request)
        if request.action == ACTION_AUTO:
            return self._run_auto(request)
        if request.action == ACTION_BATCH:
            return self._run_batch(request)
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
          ``<target> --online|--offline --out <dir> --fmt <csv>``。``<target>`` 取
          ``request.target_path``（IPA 栏=ipa_path / APK 栏=apk_path）；CLI ``load_app``
          按 ``.ipa``/含 ``Payload`` 自动分流，IPA 走纯静态、无需额外参数。
        - ``auto``：``<apk> --out <dir> --online|--offline --fix|--no-fix
          --duration <n> --fmt <csv>``（仅 APK；IPA 不允许 auto）。
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
                request.target_path,  # IPA 栏=ipa_path / APK 栏=apk_path（CLI load_app 自动分流）
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
                str(clamp_duration(request.capture_duration_raw)),
                "--fmt",
                self._fmt_arg(request.formats),
            ]
        if subcmd == "batch":
            argv = [
                *base,
                request.folder,
                "--out",
                request.out_dir,
                "--online" if request.online else "--offline",
                "--duration",
                str(_BATCH_DURATION),  # launch-only 固定 30s（不开放给用户调）
                "--fmt",
                self._fmt_arg(request.formats),
            ]
            if request.force:
                argv.append("--force")  # 无视台账、全部重跑
            return argv
        logger.warning("[gui] 未知子命令：%s", subcmd)
        return base

    def _run_subprocess(self, argv: list[str], on_line: Callable[[str], None]) -> int:
        """起子进程跑 argv，**阻塞逐行读 stdout**（I/O 释放 GIL，主线程不卡）→ on_line。

        合并 stderr 到 stdout，UTF-8 解码、坏字节 replace、行缓冲。返回退出码。
        子进程注入 ``PYTHONUTF8=1`` 让它也按 UTF-8 输出（否则 Windows 默认 GBK 写、
        本端按 UTF-8 读 → 中文乱码）。Windows 下用 ``CREATE_NO_WINDOW`` 隐藏子进程控制台窗口、
        ``CREATE_NEW_PROCESS_GROUP`` 让 ``cancel()`` 能整树收割（见 :meth:`cancel`）。
        ``stdin=DEVNULL`` 避免子进程意外继承句柄读到不确定输入（如 frida/adb 交互提示）。
        起进程/读流失败由调用方（``_run_worker`` 外层 try/except）转友好结果。

        取消协作（双保险）：
        1) 起进程后立刻把句柄存入 ``self._proc``，**并在同一把锁内复查 ``_cancelled``**——
           收口「start 后秒点取消、_proc 尚未赋值」的竞态（否则取消标志置了却没人杀进程，
           子进程会跑满全程）。若已取消，立即整树收割。
        2) 武装一个看门狗线程：取消请求发出后，等 ``_CANCEL_GRACE_SECONDS`` 仍未退出（孙进程
           可能拖着 stdout 管道写端不 EOF → 读循环卡死）就强 ``kill()`` 收尾，保证读循环能
           走到 EOF、``wait()`` 返回、「已取消」结果送达。
        """
        flags = 0
        if sys.platform == "win32":
            flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        # POSIX：独立 session/进程组，让 cancel() 能向整组发信号收割孙进程。
        new_session = sys.platform != "win32"
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
            creationflags=flags,
            start_new_session=new_session,
        )
        with self._lock:
            self._proc = proc  # 持有句柄，供 cancel() 整树收割
            # 竞态收口：若取消在「set 标志」与「赋值 _proc」之间发生，cancel() 当时拿到的是
            # None（没杀成）；这里赋值后立刻复查，补杀（仍在锁内，与 cancel() 互斥）。
            cancel_pending = self._cancelled.is_set()
        if cancel_pending:
            _kill_process_tree(proc)
        watchdog = self._arm_cancel_watchdog(proc)
        try:
            stdout = proc.stdout
            if stdout is not None:
                for line in stdout:  # 阻塞读 → 释放 GIL，tkinter 主线程消息泵不被饿死
                    on_line(line.rstrip("\n"))
            return proc.wait()
        finally:
            watchdog.disarm()
            with self._lock:
                self._proc = None

    def _arm_cancel_watchdog(self, proc: subprocess.Popen[str]) -> _CancelWatchdog:
        """启动看门狗线程：取消后等宽限期仍未退出就强 ``kill()``（防孙进程拖住管道→读循环卡死）。"""
        watchdog = _CancelWatchdog(proc, self._cancelled, _CANCEL_GRACE_SECONDS)
        watchdog.start()
        return watchdog

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
        """静态分析：子进程跑 ``analyze``（纯静态、不连设备）；跑完发现报告并读其计数。"""
        argv = self._subcmd_argv("analyze", request)
        rc = self._run_subprocess(argv, self._log)
        return self._build_subprocess_result(ACTION_STATIC, request.out_dir, rc)

    def _run_auto(self, request: ActionRequest) -> ActionResult:
        """一键全自动：子进程跑 ``auto``（含体检/脱壳/抓包）；跑完发现报告并读其计数。

        子进程无 stdin 交互：无设备时 capture skip、不触发 confirm；有设备时 confirm
        退化为不提示（已知限制）。
        """
        argv = self._subcmd_argv("auto", request)
        rc = self._run_subprocess(argv, self._log)
        return self._build_subprocess_result(ACTION_AUTO, request.out_dir, rc)

    def _run_batch(self, request: ActionRequest) -> ActionResult:
        """文件夹批量分析：子进程跑 ``batch``（逐个 launch-only auto + 卸载），汇总实时流入日志。

        与 static/auto 不同，batch 的报告分散在 ``<out>/<名>__<sha8>/`` 子目录、没有单一主
        报告，故**不走** :meth:`_build_subprocess_result`（它只 glob out_dir 顶层）；结果按退出
        码判 ok，逐个 [OK]/[ERR]/[SKIP] + 计数已实时打进日志框。out_dir 回传供「打开输出目录」。
        """
        argv = self._subcmd_argv("batch", request)
        rc = self._run_subprocess(argv, self._log)
        ok = rc == 0
        message = (
            "批量完成：详见上方日志的逐个结果与汇总。"
            if ok
            else f"批量分析子进程退出码非 0（{rc}），可能部分失败（详见上方日志）。"
        )
        return ActionResult(ok=ok, action=ACTION_BATCH, message=message, out_dir=request.out_dir)

    # -- 结果解析（子进程模式：探测 out_dir 下报告 + 读主报告 json 计数） --------

    def _build_subprocess_result(self, action: str, out_dir: str, returncode: int) -> ActionResult:
        """子进程跑完 → 探测 ``out_dir`` 下的报告文件，读主报告 json 计数，组装结果。

        - ``report_paths``：在 ``out_dir`` 下 glob 出的主报告 ``<base>.{json,html,pdf}``
          （按 APK 名命名；排除 runtime_report.json；保序去重，json 首位）。
        - ``counts``：从主报告 json 解析端点/线索/发现（复用 :meth:`_read_counts`）。
        - ``html_report``：首个 .html 报告路径（供「打开 HTML 报告」按钮）。
        - ``ok``：``returncode == 0`` **且** 主报告 json 存在（auto 失败步骤会非 0 退出
          或不产出 json）。steps 子进程模式留空（日志已实时呈现）。
        """
        report_paths = self._discover_reports(out_dir)
        # 主报告 json 存在即视作有结果。报告现按 APK 名命名（<base>.json），不能再写死
        # "report.json"；_discover_reports 已排除 runtime_report.json，故任一 .json 即主报告。
        has_json = any(p.lower().endswith(".json") for p in report_paths)
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
        """glob ``out_dir`` 下按 APK 名命名的主报告 ``<base>.{json,html,pdf}``，不抛。

        报告现按 APK 文件名去后缀命名（demo.apk → demo.json/demo.html/demo.pdf），controller
        拿不到 base（base 由子进程内部从 apk 名算），故用 glob 发现：

        - glob ``*.json``，**排除 ``runtime_report.json``**（capture 的独立契约文件，其结构
          非主报告：有 endpoints 但无 leads/findings，被 _read_counts 误读会污染计数）。
        - 以「mtime 最新的非 runtime json」为主报告锚点，其 stem 即 base；再取同 stem 的
          ``.html`` / ``.pdf``（若存在）。一次分析产出的 ``<base>.{json,html,pdf}`` 被当成一组，
          多次分析（不同 base）不混。
        - 若无 json 但有 html（如 ``--fmt html``）：退化为取 mtime 最新的 html，json 列表空
          （_read_counts 返回未知计数，ok 因无 json 判 False，与既有契约一致）。
        - 旧 ``report.{json,html,pdf}`` 命名天然兼容（``report`` 也是合法 base/回退名）。

        返回顺序 ``[<base>.json?, <base>.html?, <base>.pdf?]``（json 首位，供 has_json /
        计数读取）。读目录失败 → 空列表。
        """
        if not out_dir:
            return []
        try:
            base_dir = Path(out_dir)
            json_files = [
                p
                for p in base_dir.glob("*.json")
                if p.is_file() and p.name.lower() != "runtime_report.json"
            ]
        except OSError:
            logger.exception("[gui] 探测输出目录报告失败：%s", out_dir)
            return []

        found: list[str] = []
        try:
            if json_files:
                # 主报告锚点：mtime 最新的非 runtime json，其 stem 即 base。
                main_json = max(json_files, key=lambda p: p.stat().st_mtime)
                stem = main_json.stem
                found.append(str(main_json))
                for ext in (".html", ".pdf"):
                    sibling = base_dir / f"{stem}{ext}"
                    if sibling.is_file():
                        found.append(str(sibling))
            else:
                # 无 json：退化取最新 html（无 json → 计数未知、ok=False，符合既有契约）。
                html_files = [p for p in base_dir.glob("*.html") if p.is_file()]
                if html_files:
                    main_html = max(html_files, key=lambda p: p.stat().st_mtime)
                    found.append(str(main_html))
                    pdf_sibling = base_dir / f"{main_html.stem}.pdf"
                    if pdf_sibling.is_file():
                        found.append(str(pdf_sibling))
        except OSError:
            logger.exception("[gui] 配组输出目录报告失败：%s", out_dir)
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
    "FILE_TYPE_APK",
    "FILE_TYPE_IPA",
    "ActionRequest",
    "ActionResult",
    "Counts",
    "GuiController",
    "clamp_duration",
    "resolve_out_dir",
    "validate_apk_path",
    "validate_ipa_path",
    "validate_out_dir",
]
