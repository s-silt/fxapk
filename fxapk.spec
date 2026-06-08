# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — 一次 Analysis 共享，产出两个 EXE：

- ``fxapk.exe``      console=True   ：命令行 / headless 烟测载体（入口 apkscan.cli:main）
- ``fxapk-gui.exe``  console=False  ：windowed 无黑框，新手双击（入口 apkscan.gui:main）

形态：默认 onefile（单 .exe）。如需 onedir，设环境变量 ``FXAPK_ONEDIR=1`` 后重打。

打包要点（见 docs/build-exe.md）：
1. datas      = collect_data_files('apkscan')  —— rules/*.yaml + report/templates/*.j2
                （运行期用 importlib.resources.files('apkscan') 读，onefile 下靠这些落进 _MEIPASS）
2. hiddenimports = collect_submodules('apkscan') —— analyzers/enrichers 经 pkgutil.iter_modules
                动态发现，PyInstaller 静态分析找不到。
3. androguard（最易缺，有动态导入与资源）：**不能用 collect_all**——它会把
                androguard.pentest 拉进依赖图，而 pentest.__init__ 顶层 `import frida`
                失败时调 exit() 杀掉 PyInstaller 的 isolated 子进程导致构建崩溃。
                改用 collect_submodules(filter=跳过 pentest) + collect_data_files
                + collect_dynamic_libs，并把 androguard.pentest / frida 放进 excludes。
"""

import os

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)

# --- onefile / onedir 切换 -------------------------------------------------
ONEDIR = os.environ.get("FXAPK_ONEDIR", "") not in ("", "0", "false", "False")

# --- 1) 数据文件：rules/*.yaml + report/templates/*.j2 ---------------------
datas = collect_data_files("apkscan")

# --- 2) 自动发现的子模块：analyzers / enrichers / dynamic / gui / core / report
hiddenimports = collect_submodules("apkscan")

# --- 3) androguard：动态导入 + 资源 ---------------------------------------
# 注意：不能直接 collect_all('androguard')。androguard.pentest 在模块顶层
# `import frida`，frida 是可选运行期依赖、本环境未装，且其 __init__ 在 import 失败
# 时调用 exit()，会杀掉 PyInstaller 的 isolated 子进程导致整个构建崩溃。
# fxapk 静态分析链路不用 pentest（动态插桩），故按子包过滤掉 pentest 再收集。
def _skip_pentest(name: str) -> bool:
    return not name.startswith("androguard.pentest")


ag_hidden = collect_submodules("androguard", filter=_skip_pentest)
ag_datas = collect_data_files("androguard")
ag_binaries = collect_dynamic_libs("androguard")
datas += ag_datas
binaries = list(ag_binaries)
hiddenimports += ag_hidden

# lxml 有 C 扩展子模块，androguard 经它解析 AXML/ARSC；补齐子模块兜底。
hiddenimports += collect_submodules("lxml")

# 常规第三方：通常可静态发现，显式列出避免边角遗漏（typer/click/jinja2/yaml/requests）。
hiddenimports += [
    "typer",
    "click",
    "jinja2",
    "yaml",
    "requests",
    # provision 下载 frida-server 解压用，stdlib，显式列出兜底。
    "lzma",
    "_lzma",
]
# 去重，避免重复 import 项。
hiddenimports = sorted(set(hiddenimports))


block_cipher = None

# androguard.pentest 仅用于 frida 动态插桩（fxapk 静态链路不用），且其 __init__ 在
# `import frida` 失败时 exit()，会令 PyInstaller 的二进制依赖扫描子进程崩溃。
# 直接从依赖图中排除该子包及 frida 本身。
EXCLUDES = ["androguard.pentest", "frida"]

a = Analysis(
    ["apkscan/_pyi_console_entry.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# windowed GUI 单独一次 Analysis（不同入口脚本，避免 console 入口被当成 GUI 入口）。
a_gui = Analysis(
    ["apkscan/_pyi_gui_entry.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
pyz_gui = PYZ(a_gui.pure, a_gui.zipped_data, cipher=block_cipher)


if ONEDIR:
    # ---- onedir：每个 EXE 一个文件夹，启动快、最稳 ----
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="fxapk",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name="fxapk",
    )

    exe_gui = EXE(
        pyz_gui,
        a_gui.scripts,
        [],
        exclude_binaries=True,
        name="fxapk-gui",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll_gui = COLLECT(
        exe_gui,
        a_gui.binaries,
        a_gui.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name="fxapk-gui",
    )
else:
    # ---- onefile：单 .exe，新手双击最友好 ----
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name="fxapk",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )

    exe_gui = EXE(
        pyz_gui,
        a_gui.scripts,
        a_gui.binaries,
        a_gui.datas,
        [],
        name="fxapk-gui",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
