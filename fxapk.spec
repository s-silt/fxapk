# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — 一次 Analysis 共享，产出两个 EXE：

- ``fxapk.exe``      console=True   ：命令行 / headless 烟测载体 + dispatch 入口
                                       （壳脚本 _pyi_console_entry → _pyi_entry.console_main）
- ``fxapk-gui.exe``  console=False  ：windowed 无黑框，新手双击
                                       （壳脚本 _pyi_gui_entry → _pyi_entry.gui_main）

形态：本胖包以 **onedir** 为准（COLLECT，启动快）。build_exe.py 默认传 FXAPK_ONEDIR=1。
onefile 分支保留备用（单文件启动太慢，不推荐胖包用）。

自包含胖包：frida / frida-tools / frida-dexdump(+wallbreaker) / mitmproxy 全打进包，
adb 三件套（adb.exe + 2 dll）随 onedir 根。dispatch 入口（apkscan/_pyi_entry.py）按
``sys.argv[1]`` 把内置工具名转给对应库 main，桌面侧只需这一个 exe。

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
    collect_all,
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

# --- 4) 内置工具：frida / frida-tools / frida-dexdump(+wallbreaker) / mitmproxy ---
# 终极目标「自包含胖 exe」——桌面只跑这一个，frida/mitmproxy/frida-dexdump 全内置，
# dispatch 入口（apkscan/_pyi_entry.py）按工具名自调用库 main。
#
# 关键事实（核对真实安装版后）：
# - frida 17.x 原生扩展是 ``frida._frida``（frida/_frida.pyd，~118MB），非顶层 ``_frida``；
#   ``collect_all('frida')`` 把它当 binary 收进去。
# - frida-dexdump 依赖 ``wallbreaker``（requires: click/frida-tools/wallbreaker），
#   submodules 不够，必须额外 ``collect_all('wallbreaker')``。
# - frida-tools 有运行期数据文件（fs_agent.js / repl_agent.js / tracer_agent.js /
#   bridges/*.js 等），``collect_data_files('frida_tools')`` 必须有，否则运行报缺 agent。
# - mitmproxy 自带 PyInstaller hook（pyinstaller40 entry point），PyInstaller 6.x 会
#   自动发现，``collect_all('mitmproxy')`` 再叠加即可（不必手动 hookspath）。
for _pkg in ("frida", "mitmproxy", "wallbreaker"):
    _d, _b, _h = collect_all(_pkg)
    datas += _d
    binaries += _b
    hiddenimports += _h

# frida-tools / frida-dexdump：submodules + data_files（这两个含 console 入口，
# submodules 更稳；data_files 收 *_agent.js / bridges/*.js）。
hiddenimports += collect_submodules("frida_tools")
datas += collect_data_files("frida_tools")
hiddenimports += collect_submodules("frida_dexdump")
datas += collect_data_files("frida_dexdump")

# python-whois：联网富化的 WHOIS 查询依赖随包数据文件 whois/data/public_suffix_list.dat，
# 不收则 frozen exe 里每个域名查询都 FileNotFoundError（whois.py 已优雅降级不崩，但收了
# 才能真正联网查 WHOIS）。whois 可选，缺失时静默跳过不阻断构建。
try:
    datas += collect_data_files("whois")
except Exception:  # noqa: BLE001 — whois 未装则跳过（运行期富化优雅降级）
    pass

# dispatch 入口需显式 import 的内置工具入口模块（保险，防 collect_submodules 漏顶层）。
hiddenimports += [
    "frida",
    "frida._frida",
    "frida_tools.repl",
    "frida_tools.ps",
    "frida_tools.tracer",
    "frida_dexdump",
    "frida_dexdump.__main__",
    "mitmproxy.tools.main",
]

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


# --- 5) adb 三件套（build_exe.py 预先下载到 REPO_ROOT/.platform_tools/）---------
# 作为 datas（目标 "."）。PyInstaller 6.x onedir 把 datas 收进 dist/<name>/_internal/
# （= 运行期 sys._MEIPASS），故 frozen 态 tools.adb_path() 同时探测 _MEIPASS 与 exe 同级；
# build_exe.py 构建后另复制一份到 dist/ 顶层，满足验收 `<dist>\adb.exe version`。
# SPECPATH 是 spec 所在**目录**（PyInstaller 注入的全局），即仓库根；不要再 dirname。
_PT = os.path.join(os.path.abspath(SPECPATH), ".platform_tools")
for _fn in ("adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll"):
    _src = os.path.join(_PT, _fn)
    if os.path.exists(_src):
        datas.append((_src, "."))
    else:
        print(f"[fxapk.spec] adb 文件缺失，跳过打包：{_src}")


block_cipher = None

# androguard.pentest 仅用于 frida 动态插桩；其 __init__ 在 `import frida` 失败时调
# exit()，会令 PyInstaller 的二进制依赖扫描子进程崩溃。本胖包**已内置 frida**，故
# pentest 的 `import frida` 不再失败、不触发 exit()；但 fxapk 静态链路仍不用 pentest，
# 故仅排除 pentest 子包本身（collect_submodules filter 已跳过其子模块，双保险）。
# 注意：不再排除 "frida"——现在要把 frida 打进包供 dispatch 自调用。
EXCLUDES = ["androguard.pentest"]

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
