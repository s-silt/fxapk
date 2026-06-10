"""启动提速回归锁：``import apkscan.cli`` 不得在导入期拉起重模块。

背景：apk.py 曾在模块导入期调 ``_silence_androguard_logging()`` → import loguru（连带 asyncio）
~114ms，cli.py 又顶层 import pipeline（连带 registry）；非分析命令（--version/doctor/gui 子进程）
白付。已改为延迟到真正分析时才 import。本测试用**全新子进程**导入 cli，断言这些重模块都不在
sys.modules 里——任何人若把 androguard/loguru/pipeline 的 import 挪回启动期，此测试变红。
"""

from __future__ import annotations

import subprocess
import sys


def _modules_after_import(import_stmt: str) -> set[str]:
    """全新子进程执行 import 语句，返回其后 sys.modules 顶层名集合。"""
    code = (
        f"{import_stmt}\n"
        "import sys, json\n"
        "print(json.dumps(sorted({m.split('.')[0] for m in sys.modules})))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=True,
    )
    import json

    return set(json.loads(proc.stdout.strip().splitlines()[-1]))


def test_import_cli_does_not_pull_heavy_modules() -> None:
    mods = _modules_after_import("import apkscan.cli")
    # 这些只应在真正分析时才加载，不该在 import cli 时就拉起。
    for heavy in ("androguard", "loguru", "asyncio"):
        assert heavy not in mods, f"启动期不应加载 {heavy}（启动提速回归）"


def test_import_apk_does_not_pull_loguru() -> None:
    """import apkscan.core.apk 不应在导入期 import loguru（androguard 日志静默已延迟）。"""
    mods = _modules_after_import("import apkscan.core.apk")
    assert "loguru" not in mods
    assert "androguard" not in mods


def test_import_gui_is_clean() -> None:
    """import apkscan.gui 必须轻（GUI 启动走它、不走 cli），不拉 androguard/tkinter/pipeline。"""
    mods = _modules_after_import("import apkscan.gui")
    for heavy in ("androguard", "loguru", "tkinter"):
        assert heavy not in mods
