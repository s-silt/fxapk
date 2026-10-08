<h1 align="center">fxapk</h1>

<p align="center">
  APK 调证取证分析 CLI<br>
  <sub>从样本、流量和已有网页证据中整理线索，保留来源、覆盖范围与待核验事项。<br>工具产物支持复核，不替代原始证据与人工归属判断。</sub>
</p>

<p align="center"><strong>中文</strong> &nbsp;·&nbsp; <a href="README.en.md">English</a></p>
<p align="center">
  <a href="#how">怎么工作</a> &nbsp;·&nbsp; <a href="#start">快速开始</a> &nbsp;·&nbsp;
  <a href="#packages">证据包与复核</a> &nbsp;·&nbsp; <a href="#limits">边界</a> &nbsp;·&nbsp; <a href="#docs">文档</a>
</p>
<p align="center">
  <a href="https://github.com/s-silt/fxapk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/s-silt/fxapk/releases/tag/v1.17.0">v1.17.0</a> &nbsp;·&nbsp; Python 3.11+ &nbsp;·&nbsp; <a href="LICENSE">MIT</a>
</p>

CLI 命令 `fxapk`，兼容别名 `apkscan`，PyPI 包名 `fxapk`。面向直接运行源码或 Python 包的人与 AI 助手，不提供 exe 或 GUI。

当前已发布版本为 **1.17.0**；**1.18.0 待发布源码** 收紧 Survey 完整性与证据绑定，补齐 HAR 正文语义分析及 Censys 的 IP 前置条件，并提供可选 Android UI 观察插件。升级保留历史包和旧版流程；代码发布不会迁移案件、修改设备或自动补查第三方服务。变更见 [CHANGELOG.md](CHANGELOG.md)。

| 核心能力 | 说明 |
| --- | --- |
| **静态提取** | 解析 APK 中的配置、端点、组件与加固信号；能力不足时明确标记缺口 |
| **动态证据** | 在已授权设备上采集 PCAP、socket 归因及可用探针信息，分轮保留证据 |
| **基础设施归属** | 分开记录资源持有者、BGP、承载/CDN 与运营者，保留逐来源回执 |
| **包与复核** | 固化报告和附件哈希，独立记录 Phase-2 覆盖、判决与复核状态 |

<a id="how"></a>

## 怎么工作

```text
APK / 已落盘网页证据        已授权设备采集
          │                      │
          └──────► 结构化报告 ◄────┘
                         │
              来源、覆盖、缺口与下一步
                         │
               Phase-1 不可变证据包
                         │
           Phase-2 清单 → 人工判决 → 门禁
                         │
                 独立复核与报告前材料
```

静态分析不需要 JDK 或设备；部分分析器和动态能力需要额外工具。`selfcheck` 显示当前能力，报告中的 `analyzer_status` 与 `source_status` 说明实际执行情况。未发现不等于不存在，采集完成也不等于证据闭环。

<a id="start"></a>

## 快速开始

需要 **Python 3.11+**。下面先演示离线静态分析；联网查询与设备操作的默认行为见[边界说明](#limits)。

### 1. 安装与核对版本

```bash
python -m pip install "fxapk==1.17.0"
fxapk --version
fxapk selfcheck
```

[v1.17.0 发布页](https://github.com/s-silt/fxapk/releases/tag/v1.17.0) 提供 wheel、源码归档和 `SHA256SUMS.txt`。手动下载时，先用 `Get-FileHash <文件> -Algorithm SHA256`（PowerShell）或 `sha256sum -c SHA256SUMS.txt`（Linux）核对附件，再安装 wheel。它不是离线依赖全集。

需要同一发行版源码时，按标签获取；日常开发可 clone 默认 master：

```bash
git clone --branch v1.17.0 https://github.com/s-silt/fxapk.git
cd fxapk
python -m pip install -e .
```

联网服务密钥按 [.env.example](.env.example) 在本地配置；不要写入报告、命令示例或公开仓库。`selfcheck` 不逐个核验账户权益，具体命中和失败以查询回执为准。

### 2. 分析并读取摘要

```bash
fxapk analyze app.apk --offline --out out
fxapk digest out/app.json
```

也可以让 AI 助手读取 [AGENTS.md](AGENTS.md)，明确告诉它样本路径、是否允许联网及设备操作范围。命令没有注册到 PATH 时，用 `python -m apkscan.cli` 替代 `fxapk`。

HTML/JSON 留在本地输出目录；`digest` 用于初筛和定位。正式判断必须回查结构化字段与原始证据。

### 3. 按任务选下一步

| 任务 | 入口与条件 |
| --- | --- |
| 已保存的网页、JS 或 HAR | `fxapk analyze-web <目录> --out out`，读取本地材料；富化联网行为另按参数控制 |
| 真机环境排查 | `fxapk doctor --no-fix`，先检查，再按授权修复 |
| 不用 Frida 的 PCAP 底座 | `fxapk capture <包名> --mode floor-only`，仍需 adb、root 与设备侧 tcpdump |
| 多轮自动采集 | `fxapk auto app.apk --strict-case`，仅在操作已授权的专用设备上运行 |
| 已有报告的补查与闭环 | `fxapk case close out/app.json`，需要联网和报告写回授权 |
| 完整命令与复现环境 | [使用手册](USAGE.md) · `fxapk --help` |

<a id="packages"></a>

## 证据包与阶段二复核

代码仓库与案件材料分开。证据包、语料库与历史材料保存在工作树外；`FXAPK_CORPUS` 显式指向库目录。阶段间以清单登记的相对路径、内容哈希和复核回执衔接，不依赖特定存储服务或目录名称。

新版 `case phase2 ... --case-dir <案件目录>` 读取直接子包目录内的 `case-package.json`，按 manifest 登记的报告路径与哈希验包。旧脚本固定读取 `report.json` 的地方，遇其他报告名应使用新版 CLI，不要重命名历史证据来迁就脚本。升级时保留原件，在工作副本生成新的阶段二材料。

`case review` 必须提供 `--gate-receipt`；回执同目录的 `coverage.json` 和 `decisions.jsonl` 也必须齐全且哈希匹配。`corpus add --package` 要求输入报告与包登记内容逐字节一致。详细命令与兼容边界见 [报告前材料工作流](PRE-REPORT-WORKFLOW.md)。

| 状态 | 回答什么 |
| --- | --- |
| `package_integrity` | 清单、路径和附件哈希是否一致 |
| `analysis` | 分析器是否完整执行 |
| `closure` | 运行时、归属与调证对象是否过证据门 |
| `review` | 精确包哈希是否被复核接受 |

四种状态不能互相推出。`review=accepted` 不会把 `closure=partial` 变成完整；材料变化会使旧复核失效。`auto --strict-case` 的退出码 `0 / 5 / 6` 对应 `complete / partial / failed`。

<a id="limits"></a>

## 默认行为与边界

- **`analyze` 默认联网。** 域名/IP 会交给第三方富化服务；DNS 也可能被递归解析器和权威 DNS 观察。默认富化不主动访问样本声明的业务 URL，但不能承诺零可观察流量；离线用 `--offline`。
- **`doctor` 默认修设备，`auto` 会安装并运行样本。** 自动旁路还需原版基线、判据建议，以及 `--allow-behavior-modification --antidetect java` 双门。行为修改证据不能单独结案；默认 capture/auto 仍要求 Frida。
- **`digest` 默认有限脱敏。** 高敏类别值及线索自由文本中的部分固定形态隐私字段被遮蔽；姓名、地址、境外号码及其他自由文本不保证被移除。`--no-redact` 会恢复原值。

**其他含原值出口需要单独审核：** `jsonl`、`diff`、`lead show/restore/replay`、`corpus events/ls/seen/shared-config/shared-native/shared-build-env/link-candidates`、`probe-leads`、`pcap-leads`、CSV、HTML/PDF、文书、corpus 存证、`case_correlation.json` 与 `report.json`。内部证据视图不能直接当作安全发布版。

`corpus link-discover/link-explain/link-groups` 默认 `--evidence-values omit`，显式 `raw` 会恢复原值；`link-labels-validate/link-evaluate/link-readiness/link-train` 只输出聚合结果。这些独立投影不扩大 `digest` 的保证。

只在合法授权范围内采集与分析。共享 CDN、ASN、证书或技术锚不能单独证明运营者或同一主体；来源目录也不证明账户权限、免费额度或预算充足。本版有合成回归与跨平台 CI，没有以此宣称真实设备、全部第三方账户或文件同步冲突已验收。

<a id="docs"></a>

## 文档与开发

| 内容 | 文档 |
| --- | --- |
| 命令、输出、语料库与复现环境 | [USAGE.md](USAGE.md) |
| AI 操作约定与授权边界 | [AGENTS.md](AGENTS.md) |
| 多轮采集、阶段二与报告前材料 | [PRE-REPORT-WORKFLOW.md](PRE-REPORT-WORKFLOW.md) |
| 代码分层与证据语义 | [ARCHITECTURE.md](ARCHITECTURE.md) |
| 配套能力与工具链 | [COMPANION-TOOLS.md](COMPANION-TOOLS.md) · [tools/TOOLCHAIN.md](tools/TOOLCHAIN.md) |
| 版本变更 | [CHANGELOG.md](CHANGELOG.md) |

源码开发先启用 `git config core.hooksPath .githooks`。代码行为变更运行 Ruff、Pyright、pytest 和严格增量泄漏扫描；纯文档变更检查格式、引用、相关契约与泄漏，合并仍须通过必需 CI。夹具使用合成数据，案件原值与密钥不得入库。具体检查见 [使用手册](USAGE.md#从源码改代码)。

许可：[MIT](LICENSE)。
