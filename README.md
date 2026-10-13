<h1 align="center">fxapk</h1>

<p align="center">
  APK 调证取证分析 CLI<br>
  <sub>从样本、流量和已有网页证据中整理线索，保留来源、覆盖范围与待核验事项。<br>工具产物支持复核，不替代原始证据与人工归属判断。</sub>
</p>

<p align="center"><strong>中文</strong> &nbsp;·&nbsp; <a href="README.en.md">English</a></p>
<p align="center">
  <a href="https://github.com/s-silt/fxapk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/s-silt/fxapk/releases/tag/v1.19.0">v1.19.0</a> &nbsp;·&nbsp; Python 3.11+ &nbsp;·&nbsp; <a href="LICENSE">MIT</a>
</p>

命令 `fxapk`（别名 `apkscan`），PyPI 包名 `fxapk`。面向直接运行源码或 Python 包的人与 AI 助手，不提供 exe 或 GUI。变更见 [CHANGELOG.md](CHANGELOG.md)。

| 核心能力 | 说明 |
| --- | --- |
| **静态提取** | 解析 APK 中的配置、端点、组件与加固信号；能力不足时明确标记缺口 |
| **动态证据** | 在已授权设备上采集 PCAP、socket 归因与探针信息，分轮留档；可选 UI 插件补截图与布局 |
| **基础设施归属** | 分开记录资源持有者、BGP、承载/CDN 与运营者，保留逐来源回执 |
| **包与复核** | 固化报告和附件哈希，独立记录 Phase-2 覆盖、判决与复核状态 |

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
```

静态分析不需要 JDK 或设备；部分分析器和动态能力需要额外工具。`selfcheck` 显示当前能力，报告中的 `analyzer_status` 与 `source_status` 说明实际执行情况。未发现不等于不存在，采集完成也不等于证据闭环。

## 快速开始

```bash
python -m pip install "fxapk==1.19.0"     # 或 clone 后 python -m pip install -e .
fxapk selfcheck
fxapk analyze app.apk --offline --out out
fxapk digest out/app.json
```

[发布页](https://github.com/s-silt/fxapk/releases/tag/v1.19.0) 提供 wheel、源码归档与 `SHA256SUMS.txt`，安装前核对哈希。联网服务密钥按 [.env.example](.env.example) 在本地配置，不写入报告或仓库。命令未注册到 PATH 时用 `python -m apkscan.cli` 代替 `fxapk`。

`digest` 用于初筛和定位；正式判断必须回查 `report.json` 的结构化字段与原始证据。让 AI 助手操作时，给它 [AGENTS.md](AGENTS.md)、样本路径、是否允许联网及设备操作范围。

| 任务 | 入口 |
| --- | --- |
| 已保存的网页、JS 或 HAR | `fxapk analyze-web <目录> --out out` |
| 网页补采 | 首次分析加 `--web-supplement <本地JSON>`；已有报告用 `fxapk supplement-web <report.json> --web-supplement <config> --out <new-out-dir>`（不重跑 APK、不碰设备） |
| 真机环境排查 | `fxapk doctor --no-fix`，再按授权修复 |
| 不用 Frida 的 PCAP 底座 | `fxapk capture <包名> --mode floor-only`（仍需 adb、root、设备侧 tcpdump） |
| 多轮自动采集 | `fxapk auto app.apk --strict-case`（仅限已授权的专用设备） |
| Android UI 截图与动作计划 | 可选插件 `fxapk ui ...`，见 [ANDROID-UI.md](ANDROID-UI.md) |
| 已有报告补查与闭环 | `fxapk case close out/app.json`（需联网与写回授权） |
| 完整命令 | [USAGE.md](USAGE.md) · `fxapk --help` |

### 可选 REA 插件（网页观察 / Native 地址恢复）

默认关闭：即使已安装，也不会被导入、注册命令或用于自动补采。仅在明确需要时为该进程设置 `FXAPK_ENABLE_REA=1`（PowerShell `$env:FXAPK_ENABLE_REA='1'`）。启用不等于授权浏览器、设备或联网操作。`import` / `inspect` / `trace` 只采集，`attach` 只把核验过的观察挂进新目录；它们不自动闭环，也不把观察晋级成 leads 或 runtime。真实 Android WebView 尚未实机验收。命令、限额与边界见 [plugins/fxapk-rea/README.md](plugins/fxapk-rea/README.md)。

## 证据包与阶段二复核

代码仓库与案件材料分开：证据包、语料库与历史材料保存在工作树外，`FXAPK_CORPUS` 显式指向库目录。`case phase2 ... --case-dir <案件目录>` 按 manifest 登记的路径与哈希验包；`case review` 必须提供 `--gate-receipt`，同目录的 `coverage.json` 和 `decisions.jsonl` 须齐全且哈希匹配。升级时保留原件，在工作副本生成新的阶段二材料。详见 [PRE-REPORT-WORKFLOW.md](PRE-REPORT-WORKFLOW.md)。

| 状态 | 回答什么 |
| --- | --- |
| `package_integrity` | 清单、路径和附件哈希是否一致 |
| `analysis` | 分析器是否完整执行 |
| `closure` | 运行时、归属与调证对象是否过证据门 |
| `review` | 精确包哈希是否被复核接受 |

四种状态不能互相推出。`review=accepted` 不会把 `closure=partial` 变成完整。`auto --strict-case` 的退出码 `0 / 5 / 6` 对应 `complete / partial / failed`。

## 默认行为与边界

- **`analyze` 默认联网。** 域名/IP 会交给第三方富化服务，DNS 查询可能被观察；不主动访问样本业务 URL，但不承诺零流量。离线用 `--offline`。
- **`doctor` 默认修设备，`auto` 会安装并运行样本。** 去壳重打包旁路还需原版基线、判据建议，以及 `--allow-behavior-modification --antidetect java` 双门；行为修改证据不能单独结案。
- **`digest` 默认有限脱敏。** 高敏类别值及线索自由文本中固定形态的隐私字段被遮蔽；姓名、地址、境外号码及其他自由文本不保证移除。`--no-redact` 恢复原值。

其他出口原样输出高敏值，需单独审核：`jsonl`、`diff`、`lead show/restore/replay`、`corpus events/ls/seen/shared-config/shared-native/shared-build-env/link-candidates`、`probe-leads`、`pcap-leads`、CSV、HTML/PDF、文书、corpus 存证、`case_correlation.json` 与 `report.json`。`corpus link-discover/link-explain/link-groups` 默认 `--evidence-values omit`，显式 `raw` 恢复原值；`link-labels-validate/link-evaluate/link-readiness/link-train` 只输出聚合结果。

只在合法授权范围内采集与分析。共享 CDN、ASN、证书或技术锚不能单独证明运营者或同一主体。本版有合成回归与跨平台 CI，不以此宣称真实设备或全部第三方账户已验收。

## 开发

源码开发先 `git config core.hooksPath .githooks`。代码行为变更运行 Ruff、Pyright、pytest 和严格增量泄漏扫描；夹具使用合成数据，案件原值与密钥不得入库。见 [USAGE.md](USAGE.md#从源码改代码)、[ARCHITECTURE.md](ARCHITECTURE.md)、[COMPANION-TOOLS.md](COMPANION-TOOLS.md)。

许可：[MIT](LICENSE)。
