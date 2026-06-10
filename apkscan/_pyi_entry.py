"""统一 dispatch 入口（一个入口，多用途）——console / windowed 两个 exe 共用。

按 ``sys.argv[1]``（小写匹配）分发：

- CLI 子命令（analyze/unpack/capture/auto/doctor/gui）/ ``--help`` / 任意非空首参
  → 调 :func:`apkscan.cli.main`（typer 读 ``sys.argv[1:]`` 原样工作；``gui`` 子命令内部开窗）。
- 内置工具名（frida / frida-ps / frida-trace / frida-dexdump / mitmdump / mitmproxy / mitmweb）
  → 修正 ``sys.argv`` 后调对应库的入口（frozen 胖包内置；自调用方式见 ``core.tools``）。
- 无参 → console 版默认 CLI help；windowed 版（fxapk-gui）默认开 GUI（``gui.main``）。

两个 exe 通过 :func:`console_main` / :func:`gui_main` 区分「无参默认」与标准流兜底；
dispatch 主体 :func:`_run` 共享。**内置工具库惰性 import**：仅在真正分发到该工具时
才 import，缺库（源码态未装 frida/mitmproxy）也不影响 CLI / GUI 启动。

全程 type hints；异常按各分支语义处理（内置工具入口自身负责 argparse / 退出码，
SystemExit 透传给 PyInstaller bootloader）。
"""

from __future__ import annotations

import importlib
import logging
import os
import sys

logger = logging.getLogger(__name__)

# CLI 子命令（与 apkscan.cli 的 @app.command 一致）。命中即交给 typer 原样处理。
_CLI_SUBCMDS: frozenset[str] = frozenset(
    {"analyze", "unpack", "capture", "auto", "doctor", "gui"}
)

# 内置工具名 → (模块, 属性)。frozen 胖包把这些库打进 exe，dispatch 自调用它们的 main。
# 入口路径为实测精确值（frida CLI 实为 frida_tools.repl:main，非 frida 包）。
_BUILTIN_TOOLS: dict[str, tuple[str, str]] = {
    "frida": ("frida_tools.repl", "main"),
    "frida-ps": ("frida_tools.ps", "main"),
    "frida-trace": ("frida_tools.tracer", "main"),
    "frida-dexdump": ("frida_dexdump.__main__", "main"),
    "mitmdump": ("mitmproxy.tools.main", "mitmdump"),
    "mitmproxy": ("mitmproxy.tools.main", "mitmproxy"),
    "mitmweb": ("mitmproxy.tools.main", "mitmweb"),
}


def _enable_utf8_console() -> None:
    """Windows 下把控制台输出切到 UTF-8，修中文日志乱码。非 Windows 直接返回。

    `sys.platform != "win32"` 早返回让 pyright 在非 win32 平台把下方 ctypes.windll
    判为不可达、跳过检查（与跨平台 API 一致的处理）。失败静默、绝不阻断启动。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)
        kernel32.SetConsoleCP(65001)
    except Exception:
        logger.debug("设置控制台代码页为 UTF-8 失败（忽略）", exc_info=True)
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except Exception:
            logger.debug("重配标准流为 UTF-8 失败（忽略）", exc_info=True)


def _ensure_std_streams() -> None:
    """windowed exe / pythonw 下 sys.stdout/stderr 可能为 None，给个 devnull 兜底。

    复用 :func:`apkscan.gui._ensure_std_streams` 的实现（单一真相，避免重复逻辑）。
    import 失败（极端环境）则本地兜底，绝不阻断启动。
    """
    try:
        from apkscan.gui import _ensure_std_streams as _gui_ensure

        _gui_ensure()
    except Exception:
        logger.debug("复用 gui._ensure_std_streams 失败，本地兜底标准流", exc_info=True)
        for name in ("stdout", "stderr"):
            if getattr(sys, name, None) is not None:
                continue
            try:
                setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
            except Exception:
                logger.debug("兜底标准流 sys.%s 失败（忽略）", name, exc_info=True)


def _ensure_console_for_builtin() -> None:
    """windowed exe（fxapk-gui，无控制台）自调用内置工具时，分配一个**隐藏**控制台**并把标准
    句柄重新指向它**，让依赖控制台屏幕缓冲的工具（``frida_tools.repl`` → ``prompt_toolkit``）
    能正常初始化。

    根因：``fxapk-gui.exe`` 是 windowed 子系统、无控制台屏幕缓冲；``frida`` CLI 经 prompt_toolkit
    在初始化期取 Windows 控制台屏幕缓冲（``GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT))``），
    无控制台直接抛 ``NoConsoleScreenBufferError``（GUI 跑 auto/capture 自调用内置 frida 即触发）。

    **关键**：仅 ``AllocConsole`` 不够 —— 父进程（capture）已把子进程 stdout 重定向到 NUL
    （DEVNULL），``STD_OUTPUT_HANDLE`` 已被设过，``AllocConsole`` 按规范**不会**覆盖它；于是
    prompt_toolkit 的 ``GetStdHandle(STD_OUTPUT)`` 仍拿到 NUL → ``GetConsoleScreenBufferInfo``
    失败 → 还是崩。故分配后必须 ``CreateFile("CONOUT$"/"CONIN$")`` + ``SetStdHandle`` 把
    STD_{OUTPUT,ERROR,INPUT} 重新指向新控制台。

    ``console`` 版 ``fxapk.exe`` 本就有控制台（``GetConsoleWindow()!=0``）→ 跳过、零副作用。
    非 Windows / 任一步失败 → 静默返回，绝不阻断工具运行。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        if kernel32.GetConsoleWindow() != 0:
            return  # 已有控制台（console exe，或已分配过）
        if not kernel32.AllocConsole():
            return  # 分配失败（罕见）→ 交由工具自身处理
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE=0：隐藏黑框，仅留屏幕缓冲

        # 把 STD_{OUTPUT,ERROR,INPUT} 重新指向新控制台（CONOUT$/CONIN$）。prompt_toolkit 用
        # GetStdHandle(STD_OUTPUT) 取句柄，不重指就还是父进程留下的 NUL → 仍崩。
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.SetStdHandle.argtypes = [wintypes.DWORD, wintypes.HANDLE]
        _GENERIC_RW = 0x80000000 | 0x40000000
        _SHARE_RW = 0x1 | 0x2
        _OPEN_EXISTING = 3
        _INVALID = ctypes.c_void_p(-1).value
        conout = kernel32.CreateFileW(
            "CONOUT$", _GENERIC_RW, _SHARE_RW, None, _OPEN_EXISTING, 0, None
        )
        conin = kernel32.CreateFileW(
            "CONIN$", _GENERIC_RW, _SHARE_RW, None, _OPEN_EXISTING, 0, None
        )
        if conout and conout != _INVALID:
            kernel32.SetStdHandle(0xFFFFFFF5, conout)  # STD_OUTPUT_HANDLE = (DWORD)-11
            kernel32.SetStdHandle(0xFFFFFFF4, conout)  # STD_ERROR_HANDLE  = (DWORD)-12
        if conin and conin != _INVALID:
            kernel32.SetStdHandle(0xFFFFFFF6, conin)  # STD_INPUT_HANDLE  = (DWORD)-10
    except Exception:
        logger.debug("[entry] 为内置工具分配/重指控制台失败（忽略）", exc_info=True)


def _dispatch_builtin(tool: str) -> None:
    """把内置工具的调用透传给其库入口：改写 argv → import → 调 main → 传退出码。

    改写规则：``sys.argv = [tool, *原 argv[2:]]``——丢掉 ``fxapk.exe``、把工具名放
    argv[0]、保留工具后续参数（frida_tools.* / frida_dexdump / mitmproxy 内部 argparse
    读 ``sys.argv[1:]``，需要这种形态）。

    分发前先 :func:`_ensure_console_for_builtin`：windowed exe 自调用 frida/mitmproxy 时
    这些工具需要真实控制台屏幕缓冲，否则崩（见该函数）。

    库入口惰性 import：缺库（源码态未装该工具）抛 ImportError，转友好提示 + 退出码 1。
    """
    _ensure_console_for_builtin()
    mod_name, attr = _BUILTIN_TOOLS[tool]
    sys.argv = [tool, *sys.argv[2:]]
    try:
        module = importlib.import_module(mod_name)
    except Exception as exc:  # noqa: BLE001 - 缺库转友好提示，不抛 traceback 给终端
        logger.exception("[entry] 内置工具 %s 的库未就绪（%s）", tool, mod_name)
        print(f"内置工具 {tool} 不可用（缺少 {mod_name}）：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    main = getattr(module, attr)
    rc = main()
    if isinstance(rc, int):
        raise SystemExit(rc)


def _run(default: str) -> None:
    """dispatch 主体（console / windowed 共享）。``default`` ∈ {"cli", "gui"}。

    分发优先级：内置工具 > CLI 子命令 / --help / 任意非空首参 > 无参默认。
    """
    argv1 = sys.argv[1].lower() if len(sys.argv) > 1 else ""

    if argv1 in _BUILTIN_TOOLS:
        _dispatch_builtin(argv1)
        return

    # CLI 子命令 / --help / 任意非空首参 → 交给 typer 原样处理（含未知子命令的报错）。
    if argv1:
        from apkscan.cli import main as cli_main

        cli_main()
        return

    # 无参：console → CLI help（typer 无参打 help）；windowed → 开 GUI。
    if default == "gui":
        from apkscan.gui import main as gui_main

        gui_main()
    else:
        from apkscan.cli import main as cli_main

        cli_main()


def console_main() -> None:
    """console 版 fxapk.exe 入口：UTF-8 控制台 + 无参默认 CLI help。"""
    _enable_utf8_console()
    _run("cli")


def gui_main() -> None:
    """windowed 版 fxapk-gui.exe 入口：标准流兜底 + 无参默认开 GUI。

    windowed 下 sys.stdout/stderr 可能为 None；先兜底再分发，使得罕见的「windowed
    跑内置工具」分支（其入口会向标准流写）也不致因 None.write 崩溃。GUI 自身
    （apkscan.gui.main）内部亦有 ``_ensure_std_streams``，此处兜底是双保险。

    再 reconfigure 标准流为 UTF-8：GUI 起子进程跑 CLI（自调用本 windowed exe）时，
    若不重配，输出按本地 GBK 编码、父进程按 UTF-8 读 → 日志中文乱码。reconfigure
    直接改流编码（不依赖 PyInstaller 是否认 PYTHONUTF8，实测 env 法对冻结 exe 无效）。
    对真正开 GUI 的无参分支无副作用（标准流是 devnull）。
    """
    _ensure_std_streams()
    _enable_utf8_console()
    _run("gui")


__all__ = ["console_main", "gui_main"]
