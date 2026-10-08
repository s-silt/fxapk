# 可复现的分析工具链

**中文** · [English](TOOLCHAIN.en.md)

使用运行 fxapk 的同一个 Python 解释器安装其 Python 工具：

```powershell
.venv\Scripts\python.exe -m pip install -r tools/toolchain-requirements.txt
.venv\Scripts\python.exe -m pip check
.venv\Scripts\fxapk.exe doctor --no-fix --serial <your-test-device>
```

mitmproxy 12.2.3 应安装在独立的 Python 3.12+ 环境，并在下面的配置中显式映射
`mitmdump`、`mitmproxy` 与 `mitmweb`。在 Python 3.12 上，其 typing-extensions 上限与较新的
Pydantic 冲突；不要降级项目的其他依赖来强行共用环境。两个环境都应执行 `pip check`。
核心静态分析仍支持项目元数据声明的 Python 版本。

```powershell
py -3.12 -m venv .venv/toolchain/mitmproxy-env
.venv/toolchain/mitmproxy-env/Scripts/python.exe -m pip install mitmproxy==12.2.3
.venv/toolchain/mitmproxy-env/Scripts/python.exe -m pip check
```

示例使用 Windows Python launcher 明确选择 Python 3.12；没有该工具时，指定已安装的
Python 3.12+ 解释器的绝对路径，不要用项目的 Python 3.11 解释器创建这个工具环境。

Frida 和 mitmproxy 控制台脚本优先从当前解释器的 scripts 目录解析，再回退到 PATH。
回退可能选中其他安装；需要固定版本时使用显式映射。冻结应用的分派方式保持原样。

为独立安装的原生工具，在 `sys.prefix` 下创建 `fxapk-tools.json`
（通常为 `.venv/fxapk-tools.json`），格式如下：

```json
{
  "schema": 1,
  "tools": {
    "jadx": "C:/analysis-tools/jadx/bin/jadx.bat",
    "apktool": "C:/analysis-tools/apktool/apktool.bat",
    "adb": "C:/analysis-tools/platform-tools/adb.exe",
    "tshark": "C:/analysis-tools/wireshark/tshark.exe",
    "mitmdump": "C:/analysis-tools/mitmproxy-env/Scripts/mitmdump.exe",
    "mitmproxy": "C:/analysis-tools/mitmproxy-env/Scripts/mitmproxy.exe",
    "mitmweb": "C:/analysis-tools/mitmproxy-env/Scripts/mitmweb.exe"
  }
}
```

将示例替换为本机工具的绝对可执行文件路径。`FXAPK_TOOLCHAIN_FILE` 可选择其他配置文件。
显式选择的工具缺失、JSON 无效或 schema 不受支持时拒绝该选择并记录警告，
不会静默回退到其他版本；未列出的工具保持正常发现逻辑。没有显式选择时仍可使用 JADX addon 回退。
该文件是本机配置，不应提交或作为另一台电脑的配置分发，也不要求永久修改 PATH。

`fxapk-tools.json` 属于由本机管理员维护的可信执行配置；Windows `.bat` 工具会经过命令解释器。
手动在 PowerShell 运行 `. ./tools/Use-Toolchain.ps1` 可在当前会话选择同一组工具：
脚本先检查所有已配置工具，全部就绪后才修改会话 PATH。直接运行项目 Python 已使用 fxapk
内部的选择逻辑；仅需执行裸 `jadx` 等命令时才需要点入脚本。该脚本要求所有列出的工具可用，
不支持 fxapk 内部的 JADX addon 回退。

整合环境记录的原生工具版本为 JADX 1.5.6、Apktool 3.0.3、Android Platform-Tools 37.0.1
与 Wireshark/TShark 4.6.8（稳定分支，非 4.7 开发分支）。这是当时的版本目标，不是最新版本
推荐，也不证明真机兼容或本机实际安装状态。请从各工具官方来源下载，核对官方校验和，
在本地记录精确路径与哈希。Apktool 是辅助人工工具；fxapk 当前重打包使用 ZIP 替换和 SDK 签名工具。

设备端 frida-server 应与主机 Frida 版本匹配，并在获授权的测试设备上确认 root、枚举、
native attach 和 Java bridge。安装工具不应顺带升级另一台设备或替换其系统 tcpdump；
主机版本检查不等于动态稳定性测试。

工具升级后执行相关单元测试、lint、类型检查与完整测试，再以合成 APK 和受控本地 HTTP
交换验证集成。明确记录跳过的集成检查，保留既有证据与索引；升级不会追溯性地重新验证旧结果。
