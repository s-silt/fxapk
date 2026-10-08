# Android UI 观察与固定动作

[项目首页](README.md) · [命令手册](USAGE.md) · [English](ANDROID-UI.en.md)

本指南对应核心 `fxapk 1.18.1` 与可选插件 `fxapk-android-ui 0.1.1`。插件通过 Google Android CLI 保存截图与布局，并通过 adb 执行有界固定动作。UI 观察补充 PCAP、探针和静态证据；截图成功不证明业务连接、运营者归属或案件闭环。

## 安装与前置条件

需要 Python 3.11+，核心和插件安装在同一个 Python 环境。核心不内置插件或 Android CLI；独立 UI 命令不要求 Frida。PCAP 的 `floor-only` 仍需要 adb、设备 root 与设备侧 tcpdump，默认 `capture`/`auto` 仍要求 Frida。

按 [Android 官方下载页](https://developer.android.com/tools/agents) 与 [CLI 安装说明](https://developer.android.com/tools/agents/android-cli) 获取适合本机的 Android CLI，按官方要求准备 SDK 和平台依赖，并将 `android` 可执行文件加入 PATH。不要把旧 Android SDK 同名工具当作此 CLI。平台支持以官方页面为准；2026-10-08 核对时，官方列出 Windows emulator 命令和 PowerShell 下载的限制。fxapk 不提供第三方二进制镜像。

从发布页下载并核对 `SHA256SUMS.txt` 后，可安装核心与独立插件 wheel：

```bash
python -m pip install "fxapk==1.18.1"
python -m pip install ./fxapk_android_ui-0.1.1-py3-none-any.whl
fxapk --version
fxapk ui --help
```

也可在同一版本的源码根目录安装：

```bash
python -m pip install .
python -m pip install ./plugins/fxapk-android-ui
```

这些安装命令可能下载声明依赖，wheel 不包含完整离线依赖。插件版本独立于核心；仅安装核心时没有 `ui` 命令。插件由 `fxapk.plugins` entry point 加载，代码运行在宿主 Python 进程中；只安装可信包。

设备须在本次授权范围内、已启用 USB 调试并接受本机 adb 授权，目标 App 已安装。先自行核对 `adb devices -l` 的设备序列号，再在所有命令和计划中使用相同值。文中 `TEST_SERIAL` 与 `com.example.synthetic` 是合成占位符，不是可操作的真实目标。

## 检查 CLI 与保存一次观察

先查看参数，再检查外部工具版本：

```bash
fxapk ui capabilities --help
fxapk ui snapshot --help
fxapk ui run-plan --help
fxapk ui capabilities --serial TEST_SERIAL
```

`capabilities` 检查本机 Android CLI 路径与 `--version`，不连接设备核验权限，也不证明截图/布局命令在该设备上可用。`capabilities` 和 `snapshot` 可用 `--android <可执行文件路径>` 指定工具；`run-plan` 从 PATH 查找工具，没有该参数。插件调用 Android CLI 时传入 `--no-metrics`；该设置不约束 App 自身流量或其他工具。

`snapshot` 不启动 App。先在已授权设备上把目标 App 切到前台，再运行：

```bash
fxapk ui snapshot --serial TEST_SERIAL --package com.example.synthetic --out evidence/ui-001
fxapk ui snapshot --serial TEST_SERIAL --package com.example.synthetic --annotate --full --no-idle --out evidence/ui-002
```

每次使用**尚不存在的输出目录**；空目录、文件和符号链接也会被拒绝，避免覆盖历史材料。`--annotate` 保存标注截图；`--full` 请求完整布局；`--no-idle` 跳过布局的 UI 空闲等待，适用于持续动画等场景，但不绕过前台身份检查。参数对应官方 [screen capture](https://developer.android.com/tools/agents/android-cli/commands/screen_capture) 和 [layout](https://developer.android.com/tools/agents/android-cli/commands/layout) 接口。

## 执行可复核计划

将仓库的 [合成计划](examples/ui-plan.example.json) 复制到分析目录的 `inputs/ui-plan.json`，将 JSON 内 `serial`、`package` 和命令参数一起替换为已授权目标。示例先启动目标、等前台身份确认，再保存一次观察：

```bash
fxapk ui run-plan --serial TEST_SERIAL --package com.example.synthetic --plan inputs/ui-plan.json --out evidence/ui-plan-001
```

计划格式为 `ui-plan/1`，设备和包名须与命令精确匹配。`max_steps` 为 1–32，`max_duration_sec` 为 1–300 秒；动作数组必须非空，超出步骤或时间预算会停止并保留部分结果。全部动作在第一次设备操作前校验。

| 动作 `kind` | 字段与边界 |
| --- | --- |
| `launch` | 启动指定包，不安装或替换 APK |
| `wait_for_foreground` | 可选 `timeout_sec`，默认 5 秒，最多等待 30 秒 |
| `snapshot` | 可选布尔 `no_idle`，保存截图、布局与观察回执 |
| `tap` | 整数 `x`、`y`，范围 0–20000；执行前后检查目标前台 |
| `input_text` | `value` 为 1–256 个可打印 ASCII 字符；不接受字面 `%s`，执行前后检查目标前台 |
| `back` | 固定返回操作，执行前后检查目标前台 |
| `wait` | `seconds`，每步最多等待 30 秒，仍受总截止时间约束 |

没有任意 shell、脚本或动态代码动作。注入权限被拒绝时，读取回执原因 `injection_permission_denied`；即使 adb 返回码为零也可能被识别为失败。只有该设备上的固定 tap/text/back 已获 root 操作授权时，才在**新输出目录**使用 `--root-actions`；它不会自动提权，也不保证设备允许注入。

## 输出、失败与恢复

| 产物 | 内容 |
| --- | --- |
| `observation.json` | `ui-observation/1`；设备、目标与前后台包名、UTC 时间、状态、操作原因、文件大小和 SHA-256 |
| `screen.png` 或 `screen.annotated.png` | 成功取得的截图 |
| `layout.json` | 成功取得的布局 |
| `operations.json` | `ui-plan-result/1`；设备、包名、原始计划字节哈希、root 选择、开始/结束时间与每步结果 |
| `snapshot-N/` | 计划第 N 步的观察材料 |
| `.diagnostics/` | 有界工具输出；每流最多留存 64 KiB，记录完整输出哈希、截断和输出格式 |

一次观察仅在截图、布局均有效且前后都确认目标在前台时为 `complete`；部分产物为 `partial`，没有有效产物为 `failed`。计划中前台未知、切包、失败或预算耗尽会停止，不继续向其他 App 输入。`snapshot`/`run-plan` 对非 `complete` 返回退出码 1；应同时读取状态与逐步原因。

工具缺失时核对 PATH 与 `capabilities`；前台不符时确认目标及权限弹窗；超时或布局缺失时检查观察回执和受控诊断，可按已授权范围重新尝试 `--no-idle`。保留原输出，在新的目录记录下一次尝试，不把两次部分结果拼成一次成功。诊断中的 UTF-8 规范化输出按 `output_format` 标识，不宣称是未经转换的原始管道字节。

## 与三轮采集及阶段二的关系

安装插件后可运行独立 `fxapk ui ...` 命令。当前 `auto`/`capture` CLI 没有 UI 开关，不会自动执行 UI 计划。程序化 `apkscan.dynamic.auto.run` 只有显式传入 `android_ui_plugin` 且开启 `three_rounds=True` 时才接入轮内观察；还必须有已锁定的设备序列号和目标包，否则标记跳过。轮内 `CaptureRoundContext` 绑定样本 SHA、轮次、运行时变体、目录和共享截止时间，UI 观察不额外延长采集预算。

保留 UI 与 PCAP/探针各自的原始材料、时间和来源，在报告前按 [材料工作流](PRE-REPORT-WORKFLOW.md) 核对。UI 不替代 Survey 的包、样本与抓包绑定，也不能清除缺失的连接或双向载荷证据。

截图、布局、诊断与动作结果可能含个人信息或业务凭据，属于受控证据；`digest` 的有限脱敏不覆盖这些文件。对外流转须另行审核。本版合成测试及 CI 不等于 Android CLI 各平台、权限弹窗、切包和短连接的真机验收。
