"""启动提速回归锁：``import fxapk.cli`` 不得在导入期拉起重模块。

背景：apk.py 曾在模块导入期调 ``_silence_androguard_logging()`` → import loguru（连带 asyncio）
~114ms，cli.py 又顶层 import pipeline（连带 registry）；非分析命令（--version/doctor/gui 子进程）
白付。已改为延迟到真正分析时才 import。本测试用**全新子进程**导入 cli，断言这些重模块都不在
sys.modules 里——任何人若把 androguard/loguru/pipeline 的 import 挪回启动期，此测试变红。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _modules_after_import(import_stmt: str) -> set[str]:
    """全新子进程执行 import 语句，返回其后 sys.modules 顶层名集合。"""
    code = (
        "from fxapk.plugins import registry as plugins\n"
        "plugins._entry_points = lambda: []\n"
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
    mods = _modules_after_import("import fxapk.cli")
    # 核心包边界；第三方插件装包后的导入边界另测。
    for heavy in ("androguard", "loguru", "asyncio", "requests", "urllib3", "elftools", "yaml"):
        assert heavy not in mods, f"启动期不应加载 {heavy}（启动提速回归）"


def test_import_apk_does_not_pull_loguru() -> None:
    """import fxapk.core.apk 不应在导入期 import loguru（androguard 日志静默已延迟）。"""
    mods = _modules_after_import("import fxapk.core.apk")
    assert "loguru" not in mods
    assert "androguard" not in mods


def test_digest_does_not_load_yaml_or_html_engine(tmp_path: Path) -> None:
    """A saved JSON report should not initialize the rules or template parser."""
    report = tmp_path / "synthetic.json"
    report.write_text('{"package_name":"example.synthetic","meta":{},"leads":[],"findings":[],"endpoints":[]}',
                      encoding="utf-8")
    code = """
import contextlib, io, json, sys
from fxapk.plugins import registry as plugins
plugins._entry_points = lambda: []
from fxapk.cli import main
sys.argv = ["fxapk", "digest", sys.argv[1]]
stdout = io.StringIO()
with contextlib.redirect_stdout(stdout):
    try:
        main()
    except SystemExit as exc:
        assert exc.code in (0, None), exc.code
assert json.loads(stdout.getvalue())["package"] == "example.synthetic"
print(json.dumps(sorted({name.split(".")[0] for name in sys.modules})))
"""
    proc = subprocess.run(
        [sys.executable, "-c", code, str(report)],
        cwd=tmp_path, capture_output=True, text=True, encoding="utf-8", timeout=60, check=True,
    )
    import json

    modules = set(json.loads(proc.stdout.strip().splitlines()[-1]))
    assert not {"yaml", "jinja2"}.intersection(modules)
