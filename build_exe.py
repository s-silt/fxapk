"""封装 PyInstaller 构建自包含 onedir 胖 exe：``python build_exe.py [--onefile] [--clean]``。

默认 **onedir** 胖包（桌面只跑这一个，frida/mitmproxy/frida-dexdump 内置、adb 随包）：

1. ``_ensure_build_deps()``：pip 装 frida / frida-tools / frida-dexdump / mitmproxy /
   pyinstaller（build-fat 组，仅打包用，不进运行期 dependencies）。装失败 → 退出。
2. ``_ensure_adb()``：下载 Google platform-tools，解压取 adb.exe + AdbWinApi.dll +
   AdbWinUsbApi.dll 到 REPO_ROOT/.platform_tools/（spec datas 据此随包）。失败仅告警跳过
   adb 打包，不阻断其余构建。
2b. ``_ensure_frida_servers()``：下载打包机 frida 版本对应的 frida-server-{ver}-android-{abi}.xz
   各 ABI（arm64/x86_64/x86/arm，保持 .xz 压缩态）到 REPO_ROOT/.frida_servers/（spec datas 据此
   随包进 _internal/frida-servers/）。国内免 github 下载的命门：运行时部署优先用内置，不再卡住。
   单 ABI 失败仅告警跳过，不阻断构建。
3. ``pyinstaller fxapk.spec``：形态由环境变量 ``FXAPK_ONEDIR`` 传给 spec。
4. 构建后把 adb 三件套复制到 dist/ 顶层（满足验收 ``<dist>\adb.exe version``），打印
   产物路径与 onedir 目录总大小。

``--onefile`` 切回单 .exe（胖包单文件启动太慢，仅备用）。全程 logging，不静默；带 type hints。
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
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

# 构建期依赖（胖包内置工具 + pyinstaller），仅打包用，不进运行期 dependencies。
_BUILD_PKGS: tuple[str, ...] = (
    "frida",
    "frida-tools",
    "frida-dexdump",
    "mitmproxy",
    "pyinstaller>=6.0",
)

# adb 三件套来源（Google 官方 platform-tools）。
_PT_DIR = REPO_ROOT / ".platform_tools"
_PT_URL = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
_PT_WANT: tuple[str, ...] = ("adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll")

# 内置 frida-server 缓存目录（spec datas 据此随包进 _internal/frida-servers/）。
_FRIDA_DIR = REPO_ROOT / ".frida_servers"
# frida-server-android 发行包的 ABI 命名（全覆盖 4 个，与 provision._FRIDA_ABI_MAP 的值域一致）。
_FRIDA_ABIS: tuple[str, ...] = ("arm64", "x86_64", "x86", "arm")
# frida releases 下载地址模板（与 provision._FRIDA_RELEASE_URL 同源）。
_FRIDA_URL = (
    "https://github.com/frida/frida/releases/download/"
    "{ver}/frida-server-{ver}-android-{abi}.xz"
)


def _fmt_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def _dir_size(path: Path) -> int:
    """递归累加目录下所有文件大小（字节）。不存在 → 0。"""
    if not path.exists():
        return 0
    total = 0
    for f in path.rglob("*"):
        try:
            if f.is_file():
                total += f.stat().st_size
        except OSError:
            log.warning("无法读取文件大小，跳过：%s", f)
    return total


def _ensure_build_deps() -> None:
    """构建前确保胖包内置工具 + pyinstaller 已装（build-fat）。装失败 → SystemExit。"""
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        *_BUILD_PKGS,
    ]
    log.info("安装构建期依赖（build-fat）：%s", " ".join(_BUILD_PKGS))
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), check=False)
    if proc.returncode != 0:
        log.error("pip 安装构建依赖失败（退出码 %d）", proc.returncode)
        raise SystemExit(proc.returncode)
    log.info("构建期依赖就绪")


def _ensure_adb() -> None:
    """构建前确保 adb 三件套就绪（已在 .platform_tools/ 则跳过下载）。

    下载/解压用 stdlib（urllib + zipfile）。**失败仅告警跳过 adb 打包，不 raise**——
    其余构建照常进行（验收里 adb 项会 FAIL，但不阻断 frida/mitm 等自包含验证）。
    """
    if all((_PT_DIR / f).exists() for f in _PT_WANT):
        log.info("adb 三件套已就绪：%s", _PT_DIR)
        return

    import io
    import urllib.request
    import zipfile

    try:
        log.info("下载 Google platform-tools：%s", _PT_URL)
        with urllib.request.urlopen(_PT_URL, timeout=120) as resp:  # noqa: S310 - 固定 https 官方源
            data = resp.read()
        _PT_DIR.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                base = Path(name).name
                if base in _PT_WANT:  # zip 内路径形如 platform-tools/adb.exe
                    with zf.open(name) as src, open(_PT_DIR / base, "wb") as dst:
                        dst.write(src.read())
        missing = [f for f in _PT_WANT if not (_PT_DIR / f).exists()]
        if missing:
            log.warning("platform-tools 缺文件，跳过 adb 打包：%s", missing)
        else:
            log.info("adb 三件套下载完成：%s", _PT_DIR)
    except Exception:
        log.exception("下载/解压 platform-tools 失败，跳过 adb 打包（不阻断其余构建）")


def _build_frida_version() -> str:
    """打包机 host frida 版本（内置 .xz 的 ver 口径）。

    优先复用 ``provision.host_frida_version()`` —— 与运行时 ``ensure_frida_server`` 取版本
    **同一口径**，保证内置 .xz 文件名（打包时 ver）能被运行时（exe 内置同一个 frida）对上。
    退路：``import frida; frida.__version__``（打包机已装 frida，build-fat 依赖）。皆失败 → ''。
    """
    try:
        from apkscan.dynamic import provision

        ver = provision.host_frida_version()
        if ver:
            return ver
    except Exception:
        log.exception("provision.host_frida_version() 取版本失败，尝试 frida.__version__ 退路")
    try:
        import frida  # type: ignore[import-untyped]

        return str(getattr(frida, "__version__", "") or "")
    except Exception:
        log.exception("import frida 取 __version__ 失败")
        return ""


def _ensure_frida_servers() -> None:
    """构建前下载各 ABI 的 frida-server-{ver}-android-{abi}.xz 到 .frida_servers/（缓存）。

    照 :func:`_ensure_adb` 范式（国内免 github 下载的命门——把 frida-server 也内置进包）：
    - **ver** = 打包机 host frida 版本（:func:`_build_frida_version`，与运行时取版本同口径）。
    - **abi** 全覆盖 :data:`_FRIDA_ABIS`（arm64/x86_64/x86/arm）。
    - **保持 .xz 压缩态**（运行时再解压，省体积）。已存在则跳过（缓存，像 .platform_tools）。
    - 单 ABI 下载失败仅 ``log.warning`` 跳过（不阻断构建——开发机可能下不全，但至少下到的进包）。
    - 取不到 ver 时整体跳过（不阻断其余构建；运行时回退 github 下载）。
    下载用 stdlib urllib（与 _ensure_adb 一致，build_exe 不引 requests）。
    """
    ver = _build_frida_version()
    if not ver:
        log.warning("无法确定打包机 frida 版本，跳过内置 frida-server（运行时将回退 github 下载）")
        return

    import urllib.request

    _FRIDA_DIR.mkdir(parents=True, exist_ok=True)
    for abi in _FRIDA_ABIS:
        dest = _FRIDA_DIR / f"frida-server-{ver}-android-{abi}.xz"
        if dest.exists():
            log.info("内置 frida-server 已就绪（缓存）：%s", dest.name)
            continue
        url = _FRIDA_URL.format(ver=ver, abi=abi)
        try:
            log.info("下载 frida-server：%s", url)
            with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 - 固定 https 官方源
                data = resp.read()
            dest.write_bytes(data)  # 保持 .xz 压缩态，运行时再解压
            log.info("内置 frida-server 下载完成：%s（%s）", dest.name, _fmt_size(len(data)))
        except Exception:
            log.warning("下载 frida-server 失败，跳过该 ABI（不阻断构建）：%s", abi, exc_info=True)


def _copy_adb_to_dist_top() -> None:
    """构建后把 adb 三件套复制到 dist/ 顶层（与 onedir 文件夹同级）。

    COLLECT 已把 adb 放进各 onedir 根（dist/fxapk/、dist/fxapk-gui/），但验收要求
    ``<dist>\\adb.exe``，故再复制一份到 dist/ 顶层。源缺失则告警跳过（不阻断报告）。
    """
    if not DIST.exists():
        log.warning("dist/ 不存在，无法复制 adb 到顶层")
        return
    for fn in _PT_WANT:
        src = _PT_DIR / fn
        if not src.exists():
            log.warning("adb 源缺失，跳过复制到 dist 顶层：%s", src)
            continue
        try:
            shutil.copy2(src, DIST / fn)
            log.info("已复制到 dist 顶层：%s", DIST / fn)
        except OSError:
            log.exception("复制 adb 到 dist 顶层失败：%s", fn)


def _report_artifacts(onedir: bool) -> None:
    """打印 dist/ 下产物路径与大小（onedir 算目录总大小）。"""
    if not DIST.exists():
        log.warning("dist/ 不存在，未发现产物")
        return

    log.info("产物目录: %s", DIST)
    if onedir:
        for sub in ("fxapk", "fxapk-gui"):
            folder = DIST / sub
            exe = folder / f"{sub}.exe"
            if exe.exists():
                log.info(
                    "  [onedir] %s  (exe %s, 文件夹总计 %s)",
                    exe,
                    _fmt_size(exe.stat().st_size),
                    _fmt_size(_dir_size(folder)),
                )
            else:
                log.warning("  [onedir] 缺失: %s", exe)
        log.info("  [onedir] dist/ 顶层总大小: %s", _fmt_size(_dir_size(DIST)))
    else:
        for name in ("fxapk.exe", "fxapk-gui.exe"):
            exe = DIST / name
            if exe.exists():
                log.info("  [onefile] %s  (%s)", exe, _fmt_size(exe.stat().st_size))
            else:
                log.warning("  [onefile] 缺失: %s", exe)


def build(onedir: bool, clean: bool) -> int:
    """构建自包含胖 exe，返回退出码。

    顺序：装构建依赖 → 下 adb → pyinstaller → 复制 adb 到 dist 顶层 → 报告。
    """
    if not SPEC.exists():
        log.error("spec 不存在: %s", SPEC)
        return 2

    _ensure_build_deps()
    _ensure_adb()
    _ensure_frida_servers()

    env = dict(os.environ)
    env["FXAPK_ONEDIR"] = "1" if onedir else "0"

    cmd = [sys.executable, "-m", "PyInstaller", str(SPEC), "--noconfirm"]
    if clean:
        cmd.append("--clean")

    log.info("形态: %s", "onedir（自包含胖包）" if onedir else "onefile")
    log.info("执行: %s", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, check=False)
    if proc.returncode != 0:
        log.error("PyInstaller 构建失败，退出码 %d", proc.returncode)
        return proc.returncode

    log.info("构建成功")
    if onedir:
        _copy_adb_to_dist_top()
    _report_artifacts(onedir)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PyInstaller 打包自包含 onedir 胖 exe（fxapk console + gui）"
    )
    parser.add_argument(
        "--onefile",
        action="store_true",
        help="onefile 形态（单 .exe，胖包启动慢，仅备用）；默认 onedir 胖包",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="构建前清理 PyInstaller 缓存（--clean）",
    )
    args = parser.parse_args()
    return build(onedir=not args.onefile, clean=args.clean)


if __name__ == "__main__":
    raise SystemExit(main())
