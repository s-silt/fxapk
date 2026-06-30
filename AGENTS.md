<!-- CODEGRAPH_START -->
## CodeGraph

In repositories indexed by CodeGraph (a `.codegraph/` directory exists at the repo root), reach for it before grep/find or reading source when you need to understand or locate code. If CodeGraph hangs or the target is a small Markdown/runtime artifact, fall back to direct file reads and do not block the task.
<!-- CODEGRAPH_END -->

# AGENTS.md — fxapk 常驻操作指南（Codex / AI agent）

本仓库是 **fxapk（apkscan）**：面向授权样本与隔离取证环境的反诈 APK / URL / 域名 / IP 取证分析 CLI。你通过命令驱动 fxapk 做静态分析、带外抓包、探针取证、线索回灌、基础设施归因、串案和文书草稿。

**授权口径**：仅针对自有或已授权样本、取证设备和测试网络；全程取证语境，不做漏洞利用、爆破、DoS，不在他人网络嗅探。报告中的“调证/协查/办案”只指合法取证路径，不代表官方身份。

**权威资料**：本机主指导书单一权威副本是 `C:\Users\hjjca\OneDrive\doc\fxapk-master.md`。仓库内文档、探针、脚本随 `git pull` 更新；`AGENTS.md` 只保留常驻执行规则。涉及 APK 分析、报告生成、动态抓包、样本复核或批量处理前，还必须先读 `apkscan/memory.md`。

---

## 0. 开工第一步：自更新

每次开案/开工先执行：

```bash
cd <fxapk仓库> && git pull && pip install -e . --upgrade
```

如本地改动阻挡 pull：只保护冲突文件（stash 或移到本地备份），不得覆盖 `apkscan/AGENTS.md`、`apkscan/memory.md`、报告目录、OneDrive 中间件或用户未授权改动。

---

## 1. 核心纪律：先跑命令再判断

- 先跑命令、读输出，再决定下一步；不空想、不手搓逆向、不复述工具过程、不 dump 全 report。
- 事实来源是 `report.json`、`fxapk digest`、pcap/probe 原始台账、web-check/Shodan/RDAP/DNS/TLS/HTTP 实测结果。
- 判断、写探针、归因、证据分级、对抗式核验是你的活；机械步骤交给 fxapk/脚本。
- 不把钱包/收款/四方支付当默认重点，除非用户明确要资金线。
- 每个重要结论写 `【证据】`、`【推理】`、`【可信度 高/中/低】`。
- key-gated 情报（Censys/FOFA/Hunter/ZoomEye/VT/微步等）拿不到正文就只写建议查询/调取语句，绝不编造。
### PowerShell / Markdown 写文件纪律

在 Windows / PowerShell 下生成或修改 `.md`、prompt、README、交接说明、飞书消息草稿时，必须防止 PowerShell 反引号转义污染内容：

- 不要在可展开 here-string（`@"..."@`）里直接放 Markdown 代码围栏（三个反引号）或包含反引号的正文；`` `b``、`` `t`` 等会被解释成控制字符。
- 不需要变量插值时，优先用单引号 here-string（`@'...'@`）；需要变量插值时，优先用逐行数组 + `Set-Content -LiteralPath ... -Encoding UTF8`，或用占位符写完后 `.Replace()`。
- 本机 Windows PowerShell 5.1 的 `New-Item` 不支持 `-LiteralPath`；创建目录/文件禁止写 `New-Item -LiteralPath`。创建目录用 `New-Item -ItemType Directory -Force -Path $dir` 或 `[System.IO.Directory]::CreateDirectory($dir)`；只在 `Copy-Item`、`Get-Content`、`Set-Content`、`Test-Path` 等支持该参数的命令上使用 `-LiteralPath`。
- 说明文档里的命令块可用四空格缩进代码块，少用三反引号，避免被 PowerShell 误转义。
- 写完 Markdown/prompt/README 后，必须抽样读取并检索控制字符：`Select-String -LiteralPath <file> -Pattern "`t|`a|`b|`f|`v"`；发现乱码或控制字符立即重写。

---

## 2. 常用入口

| 意图 | 命令 |
|---|---|
| 环境修复/真机工具链 | `fxapk doctor --fix` |
| 只读自检 | `fxapk selfcheck` |
| 单 APK 静态+富化 | `fxapk analyze <apk> --online --out <out> --fmt html,json` |
| 一把梭 | `fxapk auto <apk> --fix` |
| 读摘要 | `fxapk digest <report.json>` |
| 抓包打法 | `fxapk capture-plan <report.json>` |
| 带外 pcap 回灌 | `fxapk pcap-leads capture.pcap --into <report.json>` |
| 探针日志回灌 | `fxapk probe-leads probe.log --into <report.json>` |
| 串案 | `fxapk graph ...` |
| 文书草稿 | `fxapk letters ...` |
| 台账网页 | `fxapk track` / `fxapk track ingest <report.json...>` |

`analyze` 富化阶段内置 web-check / Shodan / RDAP / 反查等；web-check 需 `FXAPK_WEBCHECK_URL`，Shodan 需 `FXAPK_SHODAN_KEY`，未配置则跳过，不影响核心分析。

---

## 3. APK 标准流程

1. 读 `apkscan/memory.md`，确认本机路径、设备、报告落点。
2. `fxapk doctor --fix` 或按需 `fxapk selfcheck`。
3. `fxapk analyze <apk> --online --out <case_out> --fmt html,json`，再 `fxapk digest <report.json>`。
4. 先跑 `fxapk capture-plan <report.json>`，按打法链执行，不盲试。
5. 抓不到关键目标时按“带外 floor / 探针 / 零注入明文”规则补抓，并全部 `--into` 同一份 `report.json`。
6. 回灌后 `fxapk graph` 串案，`fxapk letters` 套打调证/协查文书草稿。

---

## 4. 抓包打法四铁律

- **floor 优先**：先带外 pcap 保底拿接入节点。零产出不可接受；带外至少应有 dst IP:port，SNI/DNS 视加密情况而定，ECH/DoH 下退 IP+JA3/JA4。
- **时间盒**：单步超时即停，进下一步。
- **frida fail-fast**：秒退累计 2~3 次就弃明文，退带外 pcap；不死磕 frida。
- **停止门**：任一目标达成即停，不追求全都要。

优先链：`capture-plan` → PCAPdroid/网关 tcpdump 带外 pcap → `pcap-leads --into`。需要明文时再按选路矩阵：明文 HTTP+应用层加密走静态 `crypto_recipe` 离线解；TLS+应用层加密走 `tls-keylog` + recipe；pinning 走 LSPosed/系统 CA/静态去 pin/Florida；自建协议/MTProto 通常停在接入节点 + 云厂商调证。

---

## 5. 探针库规则

探针目录：`docs/codex/frida-probes/probe-templates/*.js`，数量以实际文件为准；决策表见 `docs/codex/frida-probes/指导书.md`。

注入顺序：

```bash
frida -U -f <包名> \
  -l docs/codex/frida-probes/probe-templates/anti-detection-hook.js \
  -l docs/codex/frida-probes/probe-templates/anti-detection-native.js \
  -l docs/codex/frida-probes/probe-templates/ssl-unpinning-hook.js \
  -l docs/codex/frida-probes/probe-templates/<业务探针>.js \
  -o probe.log -q
fxapk probe-leads probe.log --into report.json
```

冷启动取证必须 `-f` spawn；反检测/解 pinning 在业务探针前。探针只读，唯一出口 `console.log`，落盘仅设备临时目录；取证结束清理 `/data/local/tmp/fx_*` 和 frida 日志。

库里选不中再自写，遵守 house style：单文件自包含、中文文件头、每个 hook 独立 try/catch、失败打印 `[tag] skip: <e>`、输出 `[LEAD->后端/凭据]`、二进制同时给 text/hex/base64，抓不到写下一步换哪个 hook。

---

## 6. URL / 域名 / IP 取证

目标可能是 URL、域名或 IP。先标准化 scheme/host/port/path/query，再跑命令。首选 `fxapk analyze` 的富化结果；不足时手动复核：

```bash
dig <domain> A AAAA CNAME NS MX TXT
curl -I -L --max-time 15 <url>
openssl s_client -connect <host>:443 -servername <host>
whois <domain-or-ip>
shodan host <ip> ; shodan search <domain-or-ip>
```

`dig/curl/openssl/whois/shodan` 是系统/第三方 CLI，不是 fxapk 子命令。境外目标不主动访问/枚举/抓取；轻量主动核验只对授权范围内的境内目标做。

---

## 7. 归因与调证优先级

P0：境内云/IDC/CDN/WAF/对象存储/注册商/解析商、运营商、有 ICP 的主体。可调实名、订单、支付、登录 IP、操作日志、访问日志、回源配置、源站配置、对象上传记录、绑定域名。即便 fxapk 标为“无需调证”，只要 `endpoints[].enrichment` 显示境内登记/承租主体，也要主动捞出复核。

P1：境外但平台主体明确（Cloudflare/AWS/Google/Telegram/GitHub/Vercel/Netlify 等），走司法协助、平台投诉、保全或情报协作。

P2：历史资产、弱关联、纯攻击面线索，用于扩线，不作核心调证对象。

边缘不等于源站：识别 `via`、`x-cache`、`cf-ray`、`x-oss-*`、`x-amz-*`、`x-tencent-*`、`acw_tc`、`ESA`、`ens-cache`、CDN/WAF/对象存储 CNAME。阿里云 ENS/CDN/WAF 边缘可调客户/配置/回源/日志，但不得写成真实源站。

---

## 8. 排噪音红线

- 线索 `advice=待核` 且 reason 含“疑似编码 / hex / base64 / 随机串 / 伪域名”：只人工核，不调证、不回溯、不主动探测。
- 严格只对 `advice=建议调证` 的目标做主动探测；待核/无需调证一律不动。
- 不把公共 SDK、统计、广告、地图、证书吊销、公共 CDN、公共 DNS、IP 查询站误写为嫌疑人自有资产。
- 不把“备案主体被滥用”直接认定为诈骗主体；要用上传账号、推送路径、登录 IP、云租户交叉定责。
- 可信度“高”只给实测或多源交叉。

---

## 9. 报告与协作

最终报告和成品放本机 OneDrive `C:\Users\hjjca\OneDrive\reports`；交换中间件放 `C:\Users\hjjca\OneDrive\fxapk-handoff\<案子>`；主指导书在 `C:\Users\hjjca\OneDrive\doc\fxapk-master.md`。飞书 handoff 脚本：`docs/codex/handoff/feishu_handoff.py`，协议见 `docs/codex/handoff/PROTOCOL.md`。

报告固定产出《技术侦查与调证建议报告》A-L：基础归因、基础设施图谱、云/CDN/WAF 判断、关联域名、关联 IP、ASN/运营商/IDC、运营主体线索、调证对象、调证优先级、调证后可获数据、建议调取语句、没做到+风险+下一步。风险重点写证据灭失：短效证书、轮换域/IP、删桶、CDN 隐源。

---

## 10. 开发约定

只有在缺少 fxapk 命令或用户要求改 fxapk 代码时进入开发模式。遵守现有架构；用 `pytest`，不新增无必要抽象。合并前本地三关：

```bash
python -m ruff check apkscan tests
python -m pyright apkscan
python -m pytest -q
```

新增可选依赖要进对应 extra，并确保 CI 环境同步。未经用户指示不主动 commit，不 force push，不 `--no-verify`。

---

## 按需文档索引

- `docs/codex/commands.md`：完整命令参数。
- `docs/codex/capture-playbook.md`：带时间盒抓包打法。
- `docs/codex/capture-methods-beyond-frida.md`：PCAPdroid、网关 tcpdump、系统 CA、tls-keylog 等非 frida 方法。
- `docs/codex/frida-probes/指导书.md`：46 个探针决策表。
- `docs/codex/deep-attribution-playbook.md`：深度归因、证据分级、A-L 报告。
- `docs/codex/handoff/PROTOCOL.md`：飞书 + OneDrive 交接协议。