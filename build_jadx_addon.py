"""打包独立 jadx 插件包：``python build_jadx_addon.py [--src DIR] [--out ZIP]``。

产出 ``fxapk-jadx-<ver>-win64.zip``——独立下载、不进主程序。用户在 GUI 点「启用 jadx
深度反编译」选此 zip，自动解压到 exe 同级 ``jadx-addon/``，之后静态/一键全自动自动用 jadx。

zip 内部布局（解压到 ``jadx-addon/`` 后即 ``jadx-addon/jadx/bin/jadx.bat`` +
``jadx-addon/jre/bin/java.exe``，与 ``apkscan.core.tools.resolve_jadx`` 的约定一致）：

    jadx/bin/jadx.bat, jadx/lib/...      ← jadx 反编译器
    jre/bin/java.exe, jre/lib/...        ← 便携 JRE（扁平化，bin 直达）

源目录默认取便携安装位置 ``%USERPROFILE%\\jadx-tools``（含 ``jadx/`` 与 ``jre/<jdk*>/``）。
设计：纯 stdlib（zipfile/shutil）；找不到源/产物即清晰报错退出（不静默）。
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import zipfile
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("build_jadx_addon")

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_SRC = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "jadx-tools"


def _version() -> str:
    """取 fxapk 版本号（供 zip 命名）；取不到回退 0.0.0。"""
    try:
        sys.path.insert(0, str(REPO_ROOT))
        from apkscan import __version__

        return str(__version__)
    except Exception:  # noqa: BLE001 - 命名用，取不到不致命
        log.warning("取 fxapk 版本号失败，zip 名用 0.0.0")
        return "0.0.0"


def _find_jadx_dir(src: Path) -> Path:
    """定位 jadx 目录（含 bin/jadx.bat）。"""
    cand = src / "jadx"
    if (cand / "bin" / "jadx.bat").is_file():
        return cand
    raise SystemExit(f"未找到 jadx（缺 {cand / 'bin' / 'jadx.bat'}）。先把 jadx 解压到 {src}/jadx/")


def _find_jre_dir(src: Path) -> Path:
    """定位 JRE 根（含 bin/java.exe）。兼容 ``jre/`` 直放或 ``jre/<jdk*>/`` 嵌套一层。"""
    jre = src / "jre"
    if (jre / "bin" / "java.exe").is_file():
        return jre
    if jre.is_dir():
        for child in sorted(jre.iterdir()):
            if child.is_dir() and (child / "bin" / "java.exe").is_file():
                return child
    raise SystemExit(f"未找到便携 JRE（缺 bin/java.exe）。先把 JRE 解压到 {src}/jre/")


def _add_tree(zf: zipfile.ZipFile, root: Path, arc_prefix: str) -> int:
    """把 root 整棵目录加入 zip，归档路径前缀 arc_prefix。返回文件数。"""
    n = 0
    for path in sorted(root.rglob("*")):
        if path.is_file():
            arcname = f"{arc_prefix}/{path.relative_to(root).as_posix()}"
            zf.write(path, arcname)
            n += 1
    return n


def main() -> None:
    parser = argparse.ArgumentParser(description="打包 jadx 插件包（jadx + 便携 JRE）")
    parser.add_argument("--src", type=Path, default=DEFAULT_SRC, help=f"源目录（默认 {DEFAULT_SRC}）")
    parser.add_argument("--out", type=Path, default=None, help="输出 zip 路径")
    args = parser.parse_args()

    src: Path = args.src
    if not src.is_dir():
        raise SystemExit(f"源目录不存在：{src}")

    jadx_dir = _find_jadx_dir(src)
    jre_dir = _find_jre_dir(src)
    out: Path = args.out or (REPO_ROOT / f"fxapk-jadx-{_version()}-win64.zip")
    out.parent.mkdir(parents=True, exist_ok=True)

    log.info("jadx 源：%s", jadx_dir)
    log.info("JRE  源：%s", jre_dir)
    log.info("打包到：%s", out)

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        n_jadx = _add_tree(zf, jadx_dir, "jadx")
        n_jre = _add_tree(zf, jre_dir, "jre")

    size_mb = out.stat().st_size / (1024 * 1024)
    log.info("完成：jadx 文件 %d、JRE 文件 %d，总大小 %.1f MB", n_jadx, n_jre, size_mb)
    log.info("用法：GUI →「启用 jadx 深度反编译」选此 zip；或手动解压到 exe 同级 jadx-addon/。")


if __name__ == "__main__":
    main()
