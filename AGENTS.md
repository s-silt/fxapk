# AGENTS.md — fxapk 操作指南（给 AI agent / Codex）

本仓库是 **fxapk（apkscan）**：涉诈 APK/IPA **调证取证分析 CLI**。你（agent）通过命令行驱动它对样本做
全套静态/动态分析 + 海外服务器攻击面取证，产出**可办案化的调证线索（leads）**。本文件让你在新机
clone 后**直接知道怎么操作**。项目背景见 `README.md`；本文件只讲**怎么跑**。

> 设计取向：本项目由人直接跑源码 + agent 驱动，**不打包 exe/GUI**。密钥走项目根 `.env`（已 gitignore）。
> 输出刻意做成 **agent 友好**：核心调证信息进 `evidence_to_obtain`/`notes`/`report.meta`，并由 `digest` 命令压成低 token 摘要。

---

## 1. 环境准备（新机 clone 后一次性）

```bash
# 需 Python >= 3.11
pip install -e .                 # 装运行期依赖 + 注册 fxapk / apkscan 命令
cp .env.example .env             # 创建本地密钥文件（已 gitignore，绝不入库）
#   然后编辑 .env 填入 key（见第 3 节；不填也能跑，仅缺对应富化能力）
fxapk doctor                     # 环境自检：报告 python/依赖/可选工具(jadx/adb/frida)就绪情况
```

命令两种等价调用方式：`fxapk <cmd> ...`（装好后）或 `python -m apkscan.cli <cmd> ...`（免装）。

---

## 2. 全套分析（核心流程）

```bash
# ① 跑分析 → 产出报告（默认联网富化；--offline 跳过所有联网富化）
fxapk analyze <sample.apk> --online --out out --fmt html,json
#   产物：out/<样本名>.json（完整报告） + out/<样本名>.html（人看）

# ② 把完整报告压成【紧凑调证摘要】供你（agent）低 token 消费、直接决策
fxapk digest out/<样本名>.json
#   摘要：leads 按优先级排序（建议调证 > 待核 > 无需调证；高可信/C2 在前）+ 计数摘要。
#   高敏值（钱包私钥/助记词、后端凭据、受害人 PII、加密配方）默认**明文**（取证查看需要）。
#   ★ 若要把摘要再喂给云端模型，加 --redact 脱敏：fxapk digest out/<样本名>.json --redact
```

其它常用：
- `fxapk auto <apk>`：静态 +（有设备则）动态一把梭。`fxapk batch <dir>`：批量。
- `fxapk unpack` / `fxapk capture`：真机脱壳 / 抓包（需 adb 设备 + frida；`analyze --dynamic` 会自动接力）。
- `fxapk graph ...`：把多份报告导入知识图谱做**团伙串案/聚类**（`graph_ingest`/`graph_link`/`graph_cluster`/`graph_query`）。

---

## 3. 海外服务器攻击面取证（联网富化，`--online` 时生效）

对「建议调证」的域名/IP 端点做**两遍富化**：
1. **第①遍·归属** → 判服务器**辖区**（国内/国外/未知）：rdap/whois/dns/asn/icp/webcheck。
2. **第②遍·攻击面**（仅**国外+未知**端点；主动探测仅**国外**）：

| 开关（写进 `.env`） | 能力 | 性质 |
|---|---|---|
| `FXAPK_SHODAN_KEY` | Shodan 被动查库：开放端口/服务 banner/产品版本/**现成 CVE(vulns)**/关联主机名 | 被动·对目标零流量 |
| `FXAPK_NVD_KEY`（可选） | CVE 在线补查提速（无 key 也能用，仅限速更严） | 被动 |
| `FXAPK_ACTIVE_RECON=1` | **主动探测**：实时端口连通/TLS 证书/HTTP 指纹/暴露后台与敏感文件路径/Set-Cookie | **主动·对目标发起连接** |
| crt.sh（免 key，默认开） | 证书透明度关联子域 → 串案 | 被动 |

**暴露面研判（`exposure`，纯映射·零网络·零 payload·默认开）**：把已采集指纹映射到
- **暴露的敏感文件/误配**（/.git→源码+密钥+源站真IP、/.env→DB凭据/APP_KEY、备份dump、phpinfo、目录列表、swagger、source map）——暴露本身即直接取证价值；
- **技术栈/后台框架指纹**（PHP/Laravel/ThinkPHP/Spring/Jeecg/RuoYi/通达·泛微·致远OA…）——**仅识别**+「框架级已知漏洞·须授权人工评估」通用方向+**串案**（同后台疑同团伙），**不内置 per-CVE RCE 靶单**。
> ★ 边界：本层是侦查/取证情报，**不发 exploit/不自动利用**；具体漏洞利用由授权操作者对确认目标人工评估。暴露文件检测的数据来自主动 recon（需开 `FXAPK_ACTIVE_RECON`），栈指纹部分被动 Shodan 也能出。

**结果在哪看**：攻击面证据并进对应 Lead 的 `evidence_to_obtain`/`notes`（自动进 `digest`），例如
`Shodan 暴露面：80(nginx 1.18) …`、`主动探测·已授权 暴露后台路径：/admin(200)`、`⚠ 暴露泄露：Git 源码仓库暴露 (/.git)（critical）→…`、`技术栈/后台指纹（仅识别·须授权人工评估）：PHP、Jeecg-Boot…`、`关联子域(crt.sh)：…建议并簇串案`。
结构化 `attack_surface` 段每主机另带 `exposures[]` / `tech_stack[]` 字段供 Codex 直读。

**取证原则（辖区分流）**：
- **国内服务器** → 走「调证」：向境内云厂商/IDC/ICP 依法调取日志/租户实名，**不做攻击面取证**。
- **国外服务器** → **不走调证**：目标是**定位真实源站服务器、对源站取镜像/磁盘/访问日志**。
  - ★ 若解析 IP 全是 **CDN/反代（如 Cloudflare）** → 那是边缘节点**非源站**：取证落点会提示
    「先穿透 CDN 定位真实源站 IP（历史 DNS/证书透明度 SAN/源站泄露/SSRF/错配/邮件头），再对源站取证」；
    结构化 `attack_surface` 段会给该主机标 `cdn` 字段（提示其 Shodan 端口是边缘、非源站）。**别向 CDN 调证。**

### ⚠️ 主动探测（`FXAPK_ACTIVE_RECON`）合规边界 —— 务必知悉
- **默认关闭**，须显式 `FXAPK_ACTIVE_RECON=1` 才启用；这是本工具**唯一主动向目标发连接**的功能。
- 仅对【**国外** + **建议调证** + **公网 IP**】目标动手（境内/私网/CDN/库内置档一律跳过）。
- **仅侦查不利用**：端口连通 / TLS 证书 / HTTP 指纹 / 已知后台路径状态码——**绝不**漏洞利用/爆破/DoS。
- 启用时会打一条授权声明日志（可审计）。**操作者须确保已获授权、在合法取证范围内使用。**

---

## 4. 读结果（给 agent 的要点）
- 一切以 **leads** 为中心：每条带 `category`/`value`/`subject`/`advice`(建议调证/待核/无需调证)/
  `where_to_request`/`evidence_to_obtain`/`notes`。**优先看 advice=建议调证 的**。
- **结构化攻击面**：`digest` 输出含顶层 `attack_surface`（也在 `report.meta["attack_surface"]`），
  **按主机机器可读**——`[{host, kind, jurisdiction, ports[], services[{port,product,version}],
  cves[{id,cvss,severity,source}], exposed_paths[{path,status}], tls[], related_subdomains[],
  active_probed}]`。要"列所有 C2 开放端口""找所有挂某 CVE 的主机""比对暴露后台"时**直接读这个段**，
  别去解析 evidence 的自然语言串。仅【国外+未知】主机入此段（国内走调证不在此列）。
- `report.meta` 还含 `app_classification`(涉诈类型研判)、`sample_sha256`(检材指纹)、`enriched_target_count` 等。
- 先 `digest` 拿摘要决策；要细节再读 `out/<样本名>.json` 全量（`endpoints[].enrichment` 有富化原始数据）。

---

## 5. 开发约定（改代码时）
- Python type hints；测试用 **pytest**（不要 unittest）；跑全套：`python -m pytest -q`。
- 富化器（`apkscan/enrichers/*.py`）继承 `BaseEnricher`，自动发现；失败吞成 `EnrichmentResult(ok=False)`
  **不抛、不裸 except、不在 try 里 swallow log**。新增富化器标 `phase`（attribution/attack_surface）+ `active`。
- commit：conventional commits OK，中文 OK；**不要** `--no-verify` / 不要 force push 到 master；未经指示不主动 commit。
