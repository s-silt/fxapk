# 外部依赖与配套工具（自备，本项目不提供）

*English: [COMPANION-TOOLS.en.md](COMPANION-TOOLS.en.md)*

fxapk 仓库**只提供核心分析 CLI**。核心分析零环境、开箱即用；而在线富化、动态分析、配套脚本 /
MCP / 探针库等能力**都依赖外部资源（API Key、外部工具、你自建的脚本）**——这些**本项目一律不随仓库
提供，需要你自行申请 / 安装 / 搭建**。缺失时对应命令给出提示，核心分析不受影响。

> 一句话：**核心在仓库里，钥匙和配套工具自备。** 本项目不附带任何 API Key、探针库、MCP 服务或报告 / 消息脚本。

---

## 0. 本仓库提供 / 不提供

| | 内容 |
|---|---|
| ✅ 提供（随 `pip install fxapk`） | 静态分析核心、报告渲染、`--mode` 门控、`case close` 闭环、内置的被动富化**接线**（读你配置的 Key） |
| ❌ 不提供（需自备 / 自建） | 任何**第三方 API Key**、动态分析**外部工具**（jadx / adb / frida / mitmproxy）、**MCP 服务**、**frida 探针库**、报告 / 表格 / 消息 **配套脚本** |

---

## 1. 核心分析 —— 零配置

```bash
pip install fxapk
fxapk analyze app.apk --out out
```

不需要 JDK / 模拟器 / 真机 / 任何 Key。以下各节都是**可选增强**。

## 2. 在线富化 API Key（自备）

fxapk 内置了对若干**被动 OSINT / 网络空间测绘**源的接线（读第三方已公开的登记 / 扫库数据）。仓库
**只提供接线，不提供 Key**——你需要自行到各服务申请，写进项目根 `.env`（见 `.env.example`，已 gitignore）。
**全部可选**：不配只是缺对应源的富化，核心分析与 `case close` 仍可运行，未配置的源在来源状态里记为 `disabled`。

| 环境变量 | 服务 | 申请入口 |
|---|---|---|
| `FXAPK_SHODAN_KEY` | Shodan | account.shodan.io |
| `FXAPK_FOFA_KEY` / `FXAPK_FOFA_URL` | FOFA | fofa.info |
| `FXAPK_HUNTER_KEY` | Hunter | hunter.qianxin.com |
| `FXAPK_QUAKE_KEY` / `FXAPK_QUAKE_KEY2` / `FXAPK_QUAKE_URL` | Quake | quake.360.net |
| `FXAPK_CENSYS_ORG_ID` / `FXAPK_CENSYS_TOKEN` | Censys | censys.io |
| `FXAPK_DAYDAYMAP_KEY` / `FXAPK_DAYDAYMAP_KEY2` | DayDayMap | daydaymap.com |
| `FXAPK_ZOOMEYE_KEY` / `FXAPK_ZOOMEYE_URL` | ZoomEye | zoomeye.org |
| `FXAPK_VT_KEY` | VirusTotal | virustotal.com |
| `FXAPK_OTX_KEY` | AlienVault OTX | otx.alienvault.com |
| `FXAPK_URLSCAN_KEY` | urlscan.io | urlscan.io |
| `FXAPK_ABUSEIPDB_KEY` | AbuseIPDB | abuseipdb.com |

> Key 均为你与各服务之间的凭据，`.env` 已 gitignore、不会入库；**本项目不分发任何 Key**。

## 3. 可选 Python 扩展

| 能力 | 安装 | 用途 |
|---|---|---|
| 解密扩展 | `pip install cryptography` | 解密运行时 `{data,timestamp}` 加密信封 |
| 图谱扩展 | `pip install fxapk[graph]`（kuzu） | 本地案件图谱 |

## 4. 动态分析外部工具（自装）

动态脱壳 / 抓包需要**你自行安装**的外部工具 + 一台已 root 的真机 / 模拟器。fxapk 会自动探测、缺失即降级并打印修复提示（见 `fxapk selfcheck` / `fxapk doctor`）。

| 工具 / 能力 | 自行安装 | 用途 |
|---|---|---|
| jadx | 装到 PATH（或用 fxapk-jadx 插件包） | 深度反编译补端点 / 密钥 |
| adb | Android platform-tools | 设备通信 |
| frida / frida-tools | `pip install frida-tools` + 设备侧 frida-server | 运行时注入 |
| frida-dexdump | `pip install frida-dexdump` | 脱壳 |
| mitmproxy | `pip install mitmproxy` | 抓包解析 |
| 设备 | 已 root 的真机 / 模拟器 + adb 连上 | 真机脱壳 / 抓包 |

## 5. PDF 导出

`--fmt pdf` 需本机已装 **Chrome / Edge**（无头渲染）。未装则跳过 PDF、HTML / JSON 照常产出。

## 6. 配套工具（本项目不提供，自行搭建）

除上面的 Key 与外部工具外，一些围绕 fxapk 报告的**辅助工作流**可以自己搭建。**这些脚本 / 服务不在本仓库、
不随 fxapk 发布**——如需，请按自己的流程实现，凭据与实现均自备：

- **独立 / 批量富化脚本、富化 MCP 服务**：在 fxapk 之外对 IP / 域名做批量富化或即时查询。fxapk 只在
  `case close` 内置了被动富化接线（第 2 节的 Key）；独立脚本 / MCP 需自建。
- **跨报告关联 MCP 服务**：把多份 `report.json` 的 IOC 做交叉检索。协议侧走标准 MCP，`report.json` schema
  见仓库；实现自备。
- **报告 / 表格生成脚本**：把 `report.json` / IOC CSV 二次加工成自定义模板。fxapk 自带 HTML / JSON /
  可选 PDF 与 `fxapk export`（IOC CSV）；更花哨的模板自己写。
- **动态分析探针库（frida 脚本）**：动态引擎可加载 `-l <脚本>.js` 形式的 frida 探针，但**本项目不附带
  任何探针库**——探针脚本请自行编写 / 维护。
- **消息 / 交接集成**：任何把结果推送到聊天 / 工单系统的桥接，均非本项目内容，自行配置。

---

## 缺失时的行为（优雅降级）

fxapk 对所有可选项都**缺则降级、绝不崩**：未配 Key 的源记 `disabled`、未装的工具对应命令打印一句话修复
指引、核心静态分析始终可跑。用 `fxapk selfcheck`（或 `fxapk doctor`）一眼看哪些就绪、哪些缺、各自怎么补。

```bash
fxapk selfcheck            # 逐项列出核心 / Key / 外部工具 / 动态能力的就绪状态 + 修复指引
```
