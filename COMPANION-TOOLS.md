# 内置能力、外部依赖与配套工具

*English: [COMPANION-TOOLS.en.md](COMPANION-TOOLS.en.md)*

fxapk 需要 Python 3.11+ 及 [pyproject.toml](pyproject.toml) 声明的运行依赖。
安装包含静态分析、报告、证据包、Phase-2 复核、富化适配器和内置探针；
第三方凭据、设备及外部可执行工具由使用者配置。

## 仓库提供什么

| 随包提供 | 仍需准备 |
| --- | --- |
| 静态分析器、规则、HTML/JSON、可选 PDF、CSV 和文书出口 | 检材；PDF 另需本机 Chrome/Edge/Chromium |
| `analyze`、`case close`、`enrich batch` 等入口的富化适配器 | 对应服务凭据、账户权益、查询授权及预算 |
| 动态编排与内置 hook；8 个 Frida 探针 | adb、root 设备、tcpdump，以及所选模式需要的 Frida/mitmproxy 等工具 |
| corpus、Phase-1 包与 Phase-2 CLI | 工作树外的案件/语料库目录；人工复核 |

内置探针位于 `apkscan/dynamic/frida_probes/`：`coldstart-config`、`objstore-config`、
`native-ssl`、`tls-keylog`、`sms-forward-outbound`、`mqtt-xmpp-im`、
`telegram-mtproto`、`push-c2-inbound`。其他探针、MCP 服务、自定义表格模板和消息桥接需自备。
包内脚本不等于主机工具或设备侧 frida-server 已安装，也不表示所有探针都会自动运行。

## 离线静态起步

```bash
python -m pip install "fxapk==1.18.0"
fxapk analyze app.apk --offline --out out
fxapk digest out/app.json
```

基础静态分析不要求 JDK、设备或 API Key；依赖外部能力的分析器可能 skipped。
`analyze` 省略 `--offline` 时默认联网富化，会向第三方及 DNS 提交目标标识。
`analyze-web` 读取已保存的 HTML/JS/HAR，默认不联网，显式 `--online` 只开启富化。

## 在线富化与凭据

以 [.env.example](.env.example) 为配置变量清单，不把真实密钥写入公开文件。
普通分析按能力和端点门控调用基础富化；Shodan 仅用于 `case close` 的有界目标集或
`enrich batch`，不在普通 `analyze` 消耗其额度。DayDayMap 已内置并有逐来源回执。
ThreatBook、WhoisXML 等产品还要求核对账户权限并在 batch 中显式选择。

```bash
fxapk case source-catalog --category all
fxapk enrich inventory
fxapk enrich batch -t targets.txt -o enrich_out
```

目录和 inventory 不查询目标，也不证明账户可用；batch 默认 dry-run。核对目标、披露范围、
服务权限与预算后才加 `--no-dry-run`。画像选择、凭据槽和覆盖边界见 [USAGE.md](USAGE.md)。
配置不等于执行；逐来源区分 `hit/no_record/failed/skipped/disabled`，失败不代表无记录。

## 可选依赖与设备工具

| 用途 | 配置依据 |
| --- | --- |
| 支持的 PCAP 深度解密 | `python -m pip install "fxapk[pcap]"`；`dynamic` extra 同样声明 cryptography，不安装设备工具 |
| 实验串案排序器 | `python -m pip install "fxapk[ml]"`；仍须通过独立标签与训练门 |
| jadx、adb、tshark、Frida、frida-dexdump | [工具链安装与路径配置](tools/TOOLCHAIN.md)、[固定 Python 工具版本](tools/toolchain-requirements.txt) |
| Android UI 插件 | 独立 `fxapk-android-ui 0.1.0`（核心 1.18.0+）；外部 Android CLI、adb 与授权设备；见 [完整指南](ANDROID-UI.md) |
| mitmproxy | 按工具链文档安装在独立环境，并显式映射可执行文件 |

默认 `capture`/`auto` 仍要求 Frida；显式 `capture --mode floor-only` 不用 Frida，
但需要 adb、设备 root 和设备侧 tcpdump。缺少前置条件可能阻断该步骤，不能保证所有命令自动降级。
先用 `fxapk selfcheck` 查看总体能力，再在设备检查已授权时用 `fxapk doctor --no-fix`。
selfcheck 不逐个验证 API Key 或账户权益；doctor 默认修设备，不能把它当成只读自检。

## 导出与外部集成

PDF 由本机浏览器渲染。普通 analyze 的 PDF 失败会提示跳过，只有 `--fmt` 中选中的其他格式
才会另行写出；`origin-check` 的投影失败有独立非零退出与状态回执。必须核对实际产物。
HTML/PDF、JSON、CSV 和文书可能含原值，不能当作已脱敏发布版；digest 也只做有限脱敏。

自定义 MCP、XLSX、消息/工单桥接不是运行核心 CLI 的前置条件。外部集成须保留报告/附件哈希、
来源、作用域和复核状态，不能用外部“成功”替代证据门。旧版集成流程的兼容边界见
[报告前材料工作流](PRE-REPORT-WORKFLOW.md)。
