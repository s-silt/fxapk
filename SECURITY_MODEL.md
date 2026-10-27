# 威胁模型：s-silt/fxapk

> 仓库维护者确认的安全扫描威胁模型：攻击者、资产、范围外项均已确认。无基础设施仓库——fxapk 只在本机/分析机运行，无开发者运营的服务端。组件名用于跨扫描对齐发现，改名需同步扫描配置。

## 1. 系统概览与信任边界

fxapk（命令别名 `apkscan`）是 APK 调证取证 CLI（Python ≥3.11，PyPI 发布），分析员/agent 在本机运行 `fxapk analyze|auto|capture|case close|corpus ...`（`apkscan/cli.py`、`apkscan/commands/`）。产物（`report.json`、digest、corpus、phase2 包、文书）用于调证决策。

信任边界：
1. **恶意 APK 样本 → 分析机**：androguard/apkInspector 解析（`apkscan/core/apk.py`：有界解压 shim `_bounded_extract_file_based_on_header_info`，单文件 500MB / 缓存总量 256MB 上限；AXML 包名交叉校验 `_decide_manifest_package`；nsmap 净化 `_sanitize_nsmap`）、JADX/Ghidra/aapt 子进程（`apkscan/analyzers/jadx.py`、`apkscan/core/tools.py`、`apkscan/core/jadx_index*.py`）、43 个分析器（`apkscan/analyzers/`）、进程池快照（`apkscan/core/snapshot.py`、`pipeline.py`，pickle 只在本机进程间）。
2. **第三方富化服务 → 分析机**：WHOIS/RDAP/DNS/ASN/ICP/Shodan/crt.sh/FOFA/Hunter/Spamhaus（`apkscan/enrichers/`；`_http.py` `CappedSession` 流式限响应体、自行逐跳跟随重定向并在跟随前拦截）。API 密钥来自项目根 `.env`（`apkscan/core/dotenv.py`、`secrets.py`）。
3. **分析机 ↔ 测试设备**：adb/Frida/tcpdump/mitmproxy CA（`apkscan/dynamic/`、`apkscan/core/device.py`，subprocess 列表参数 + 超时）；样本在设备上运行，其流量、Frida 回传消息回到主机（`probe_ingest.py`、`pcap_ingest.py`、`tshark_backend.py`、`merge.py`）。
4. **网页/HAR/CDP → 分析机**：`analyze-web`（默认离线）、`apkscan/analyzers/web_har.py`、`web_evidence.py`；可选 REA 插件（`plugins/fxapk-rea`，默认关闭，需 `FXAPK_ENABLE_REA=1`）。
5. **DEX 查询隔离进程**：`plugins/fxapk-asc` 由 `apkscan/core/dex_query.py` 以 `python -I -m fxapk_asc.worker` 子进程调用。
6. **插件加载**：`apkscan/plugins/registry.py` 只加载 `_ALLOWED` 白名单内的 entry point（`android_ui`、`rea`）。
7. **样本派生数据 → 报告/文书**：Jinja2 HTML（`apkscan/report/html.py`，`select_autoescape`）、PDF（`pdf.py`）、文书（`letters.py`，Markdown 出口 `_md_safe`）、CSV `export`、digest（有限脱敏 `apkscan/core/redact.py`）。
8. **案件库**：corpus（`apkscan/core/corpus*.py`，库根须在工作树外，fail-closed 哈希校验）、phase2 不可变包（`apkscan/core/phase2/`）、`lead restore|replay`、`regress`。
9. **本机其他进程**：共享分析机上的低权限用户/进程可读写临时目录、缓存（JADX 索引分片、run ledger）、`.env`。
10. **供应链**：`.github/workflows/ci.yml`、`release.yml`（顶层只读，publish job 声明 `id-token: write` 用 PyPI Trusted Publishing）、`requirements.lock`、提交前泄漏扫描（`apkscan/core/leakscan.py`、`.githooks/`）。

## 2. 主要组件

| 组件 | 覆盖代码 |
|---|---|
| fxapk-Static | `apkscan/core/apk.py`、`apkscan/analyzers/`、`apkscan/config/`（含远程配置拉取 `fetch.py` 的 SSRF 守卫）、`apkscan/core/`（解析、JADX 索引、快照、pipeline、config-probe、web/HAR 摄入） |
| fxapk-Dynamic | `apkscan/dynamic/`、`apkscan/core/device.py` |
| fxapk-Enrich | `apkscan/enrichers/`、`apkscan/core/enrichment*.py`、`apkscan/core/closure/`、`apkscan/attribution/`、`apkscan/network/`、`apkscan/core/dotenv.py`、`secrets.py` |
| fxapk-Output | `apkscan/cli.py`、`apkscan/commands/`、`apkscan/report/`、`apkscan/core/corpus*.py`、`apkscan/core/phase2/`、`redact.py` |
| fxapk-Plugins | `plugins/`（rea、asc、android-ui）、`apkscan/plugins/`、`apkscan/core/dex_query.py` |
| Build-Release | `.github/workflows/`、`tools/`、`skills/`、`.githooks/`、`apkscan/core/leakscan.py`、`pyproject.toml`、`requirements.lock` |

## 3. 入口点与可达者
- 输入文件：APK/目录/HAR/report.json/corpus/phase2 包/web-supplement JSON —— 样本作者可控（APK 及其派生内容），或经他人转交的案件材料。
- 富化 API 响应 —— 第三方服务、中转或网络中间人可控。
- 设备回传：Frida 消息、PCAP、TLS keylog —— 设备上运行的样本可控。
- CDP trace / 网页 —— 网页作者可控。
- 环境变量与 `.env`、共享缓存/临时目录 —— 本机其他进程可能可写/可读。
- CLI 参数 —— 分析员控制，**视为可信**（维护者确认）。
- CI/发布流水线、依赖 —— 供应链攻击者。

## 4. 资产与敏感度（维护者确认：以下四项全部为最高优先级）
- **分析机完整性**：恶意样本/输入导致的代码执行、路径穿越写文件、资源耗尽。
- **证据完整性与可信度**：report.json、corpus、phase2 包、哈希被操纵，导致错误归因、伪造 `closure.status=complete` 或错误调证对象。
- **富化 API 密钥**（`.env`）：泄露到日志、报告、第三方中转或重定向目标。
- **案件敏感数据**：线索中的个人信息、资金线；未声明出口的泄露。
- 次要：测试设备（已授权专用机，`doctor`/`auto` 按设计修改）。

## 5. 攻击者画像（维护者确认：全部都算）
1. **恶意 APK 样本作者**：构造畸形 ZIP/DEX/AXML/ELF、诱饵绝对路径条目（`APK-CORE-NAME-DECOY-ENTRIES`）、压缩炸弹、注入型字符串（HTML/CSV/Markdown/终端转义）、伪造运行时流量与 Frida 回传，干扰归因。
2. **恶意网页/HAR/CDP 来源**。
3. **恶意或被劫持的富化服务/第三方中转/网络中间人**：超大、畸形、注入型响应，诱导重定向窃取密钥。
4. **本机低权限进程/其他用户**：篡改缓存、临时文件、corpus，读取 `.env`、报告。
5. **供应链**：CI/发布流程、依赖、插件包。

## 6. 现有控制
- 有界解压与 DEX 提取总量上限；AXML 包名交叉校验；nsmap 净化；Jinja2 autoescape；Markdown 出口 `_md_safe`。
- `CappedSession` 限响应体、拒 requests 隐式重定向、逐跳拦截；FOFA 禁 URL 内嵌凭据/禁降级 HTTP/不跨地址重定向发送密钥；`FXAPK_HTTP_RATE_LIMITS` 准入。
- 测试在 HTTP 目标层拒绝外网。
- corpus 须在工作树外 + fail-closed；phase2 不可变清单与覆盖审计。
- ASC 隔离子进程（`python -I`）；插件 entry point 白名单；REA 默认关闭；`analyze-web` 默认离线。
- 设备命令走 subprocess 列表参数 + 超时。
- 泄漏扫描 hook + CI（`leak-scan --base origin/master --strict`）；发布用 OIDC Trusted Publishing、顶层权限只读。

## 7. 范围外 / 接受的风险（维护者确认）
- `doctor`/`auto` 修改已授权测试机（部署 frida-server、装 CA、安装样本、脱壳）是设计行为，不算漏洞。
- CLI 参数由分析员控制，视为可信；仅靠恶意 CLI 参数才能触发的问题不算漏洞。
- digest 以外的出口（AGENTS.md §2 列出的 `jsonl`/`diff`/`lead show|restore|replay`/`corpus ...`/`export` CSV/HTML/PDF/文书/`report.json` 等）原样输出高敏值是已记录设计；未声明却泄露的（如密钥进日志、digest 脱敏遗漏声明范围内的类别）仍算问题。
- 未排除 tests/ 或任何插件。

## 8. 开放问题
- 无。
