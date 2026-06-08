"""封装 PyInstaller 构建：``python build_exe.py [--onedir] [--clean]``。

- 默认 onefile（单 .exe，新手双击最友好）；``--onedir`` 切到文件夹形态（最稳）。
- 调用 ``pyinstaller fxapk.spec``，构建后打印产物路径与大小。
- 全程 logging，不静默；带 type hints。

形态由环境变量 ``FXAPK_ONEDIR`` 传给 spec（spec 据此选 onefile / onedir）。
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("build_exe")

REPO_ROOT = Path(__file__).resolve().parent
SPEC = REPO_ROOT / "fxapk.spec"
DIST = REPO_ROOT / "dist"


def _fmt_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def _report_artifacts(onedir: bool) -> None:
    """打印 dist/ 下产物路径与大小。"""
    if not DIST.exists():
        log.warning("dist/ 不存在，未发现产物")
        return

    log.info("产物目录: %s", DIST)
    if onedir:
        for sub in ("fxapk", "fxapk-gui"):
            exe = DIST / sub / f"{sub}.exe"
            if exe.exists():
                log.info("  [onedir] %s  (%s)", exe, _fmt_size(exe.stat().st_size))
            else:
                log.warning("  [onedir] 缺失: %s", exe)
    else:
        for name in ("fxapk.exe", "fxapk-gui.exe"):
            exe = DIST / name
            if exe.exists():
                log.info("  [onefile] %s  (%s)", exe, _fmt_size(exe.stat().st_size))
            else:
                log.warning("  [onefile] 缺失: %s", exe)


def build(onedir: bool, clean: bool) -> int:
    """执行 ``pyinstaller fxapk.spec``，返回退出码。"""
    if not SPEC.exists():
        log.error("spec 不存在: %s", SPEC)
        return 2

    env = dict(os.environ)
    env["FXAPK_ONEDIR"] = "1" if onedir else "0"

    cmd = [sys.executable, "-m", "PyInstaller", str(SPEC), "--noconfirm"]
    if clean:
        cmd.append("--clean")

    log.info("形态: %s", "onedir" if onedir else "onefile")
    log.info("执行: %s", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, check=False)
    if proc.returncode != 0:
        log.error("PyInstaller 构建失败，退出码 %d", proc.returncode)
        return proc.returncode

    log.info("构建成功")
    _report_artifacts(onedir)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="PyInstaller 打包 fxapk console + gui exe")
    parser.add_argument(
        "--onedir",
        action="store_true",
        help="onedir 形态（文件夹，启动快最稳）；默认 onefile",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="构建前清理 PyInstaller 缓存（--clean）",
    )
    args = parser.parse_args()
    return build(onedir=args.onedir, clean=args.clean)


if __name__ == "__main__":
    raise SystemExit(main())
