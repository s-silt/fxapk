# 打包 Windows 可执行文件（PyInstaller）

把 fxapk 打成 **64 位 Windows** 独立可执行文件，目标机器无需安装 Python。

产出两个 exe：

| 产物 | 入口 | 控制台 | 用途 |
|---|---|---|---|
| `fxapk.exe` | `apkscan.cli:main` | 有（console） | 命令行 / 脚本 / headless |
| `fxapk-gui.exe` | `apkscan.gui:main` | 无（windowed，不弹黑框） | 新手双击图形界面 |

> 架构说明：产物架构 = 运行 PyInstaller 的 Python 架构。本机 Python 3.12 为 x64，
> 因此产物即 **64 位**。不做交叉编译。

---

## 1. 安装构建工具

PyInstaller 只是**构建期**工具，不进运行期依赖。已在 `pyproject.toml` 的
`[project.optional-dependencies]` 放了 `build` 组：

```powershell
python -m pip install -e ".[build]"
# 或最小化：
python -m pip install pyinstaller
```

同时确保运行期依赖已装（androguard / jinja2 / typer / pyyaml / requests 等）：

```powershell
python -m pip install -e .
```

---

## 2. 构建

推荐用封装脚本（带 logging、构建后打印产物路径与大小）：

```powershell
# onefile（默认，单 .exe，新手双击最友好）
python build_exe.py

# onedir（文件夹形态，启动快、最稳；androguard 在 onefile 失败时回退用）
python build_exe.py --onedir

# 清缓存重打
python build_exe.py --clean
```

或直接调 PyInstaller：

```powershell
# onefile
pyinstaller fxapk.spec --noconfirm
# onedir（spec 读环境变量切换形态）
$env:FXAPK_ONEDIR = "1"; pyinstaller fxapk.spec --noconfirm
```

---

## 3. 产物在哪

- **onefile**：
  - `dist\fxapk.exe`
  - `dist\fxapk-gui.exe`
- **onedir**：
  - `dist\fxapk\fxapk.exe`（同目录有依赖文件，整个文件夹一起分发）
  - `dist\fxapk-gui\fxapk-gui.exe`

`build\` 是中间产物，可删。`build\` 与 `dist\` 均已在 `.gitignore`，**绝不入库**。

---

## 4. onefile vs onedir

| | onefile | onedir |
|---|---|---|
| 形态 | 单个 .exe | 一个文件夹 |
| 分发 | 拷一个文件 | 拷整个文件夹 |
| 首次启动 | 慢（每次解压到临时目录 `_MEIPASS`） | 快 |
| 稳定性 | 好 | 最好（资源/动态库就在盘上，无解压环节） |
| 体积 | 单文件较大 | 文件夹总和略大 |

默认 onefile。若某依赖（典型是 **androguard** 的动态导入 / 资源）在 onefile 下运行
报错，先按下文“打包要点”补 spec；短时难解则用 `--onedir` 回退——**可复现的工作版优先于单文件**。

---

## 5. spec 打包要点（已落到 `fxapk.spec`）

运行期代码用 `importlib.resources.files('apkscan')` 读数据、用 `pkgutil.iter_modules`
动态发现 analyzers/enrichers，PyInstaller 的静态分析无法自动覆盖，故 spec 显式收集：

1. **数据文件**：`collect_data_files('apkscan')`
   → 把 `apkscan/rules/*.yaml` 和 `apkscan/report/templates/*.j2` 打进包，
   onefile 下落进 `_MEIPASS`，运行期才解析得到。
2. **自动发现的子模块**：`collect_submodules('apkscan')`
   → 含 analyzers / enrichers / dynamic / gui / core / report 全部子模块。
3. **androguard**（最易缺，有动态导入与资源）：**不能用 `collect_all('androguard')`**。
   `collect_all` 会把 `androguard.pentest` 拉进依赖图，而 `pentest.__init__` 顶层
   `import frida` 失败时会调 `exit()`，杀掉 PyInstaller 的 isolated 子进程导致构建直接崩溃
   （frida 是可选运行期依赖，常未安装）。spec 实际改用：
   - `collect_submodules('androguard', filter=跳过 pentest)` 收子模块；
   - `collect_data_files('androguard')` 收资源；
   - `collect_dynamic_libs('androguard')` 收动态库；
   - 并把 `androguard.pentest` 与 `frida` 放进 Analysis 的 `excludes` 彻底排除。

   fxapk 静态分析链路不用 pentest（仅 frida 动态插桩用），排除安全。
   外加 `collect_submodules('lxml')` 兜底其 C 扩展子模块。
4. typer / click / jinja2 / yaml / requests 常规可被静态发现，spec 仍显式列入
   `hiddenimports` 防边角遗漏。
5. `lzma` / `_lzma`（provision 下载 frida-server 解压用）是 stdlib，自动带，spec 也显式列了。

两个 EXE 各跑一次 Analysis（入口脚本不同：`apkscan/_pyi_console_entry.py` 与
`apkscan/_pyi_gui_entry.py`，分别转发到 `cli.main` / `gui.main`），共享同一份
datas / binaries / hiddenimports。

---

## 6. 首次运行 / 杀软误报

- **首次启动慢**：onefile 第一次运行要把内置资源解压到临时目录，属正常，几秒级。
- **SmartScreen / 杀软误报**：未签名的 PyInstaller exe 常被 Windows Defender
  SmartScreen 拦“未知发布者”，或被部分杀软启发式误判。处理：
  - SmartScreen 弹窗点“更多信息” → “仍要运行”。
  - 杀软误报可加白名单，或对产物做代码签名（需自备证书）。
- **Windows 版本**：64 位 Windows 10/11 直接运行。

---

## 7. 烟测（验证引擎确实进包）

用打出来的 **console exe**（不是 python 源码）跑真实样本：

```powershell
dist\fxapk.exe analyze <样本>.apk --offline --out out_exe
```

检查 `out_exe\report.json`：`endpoints > 0`、`leads > 0`、分析器 `ran > 0`，
即证明 analyzers/enrichers + rules + templates + androguard 全部打进去了。
（`out_exe\` 是烟测产物，已在 `.gitignore`，不入库。）
