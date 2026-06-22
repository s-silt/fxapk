# AGENTS.md — fxapk 操作指南（给 AI agent / Codex）

本仓库是 **fxapk（apkscan）**：涉诈 APK/IPA **调证取证分析 CLI**。你（agent）通过命令行驱动它对样本做
全套静态/动态分析 + 海外服务器攻击面取证，产出**可办案化的调证线索（leads）**。本文件让你在新机
clone 后**直接知道怎么操作**。项目背景见 `README.md`；本文件只讲**怎么跑**。

> 设计取向：本项目由人直接跑源码 + agent 驱动，**不打包 exe/GUI**。密钥走项目根 `.env`（已 gitignore）。
> 输出刻意做成 **agent 友好**：核心调证信息进 `evidence_to_obtain`/`notes`/`report.meta`，并由 `digest` 命令压成低 token 摘要。

---

## 0. 行为铁律：直接用 fxapk 跑，别空想 / 别手搓

你是来**驱动 fxapk 出结果**的，不是来手动逆向、读源码猜结论、或大段推演的。收到「分析这个 APK / 查这些线索 / 准备设备 / 为什么动态跑不起来」一类请求时——**先跑对应 fxapk 命令，再据产物决策**。命令产物（`report.json` / `digest` / track 台账）才是事实来源，不是你的推测。

按意图直接选一条执行（别在跑命令前就长篇分析）：

| 用户想要 | 直接执行 |
|---|---|
| 分析一个 APK（静态 + 联网富化） | `fxapk analyze <apk> --online --out out` 然后 `fxapk digest out/<名>.json` |
| 一把梭（有真机：体检→静态→脱壳→去壳重打包→抓包→合并） | `fxapk auto <apk> --fix` |
| 批量整个文件夹 | `fxapk batch <dir>` |
| 准备真机环境 / 排查动态为什么跑不起来 | `fxapk doctor --fix` |
| 真机脱壳 / 去壳重打包 / 抓包（单步） | `fxapk unpack <apk>` / `fxapk repackage <apk>` / `fxapk capture <pkg>` |
| 看每个 APK 的线索 + 办案进度（网页还能手动加线索、增删图谱） | `fxapk track`（起网页）；`fxapk track ingest <report.json...>` 回填 |
| 串案 / 团伙聚类 | `fxapk graph ...` |
| 清图谱噪音 / 删错误的图谱实体或边 | `fxapk graph prune-weak` / `graph rm-entity <kind> <value>` / `graph unlink <sha256> <kind> <value>`（或 track 网页图谱面板点） |

- 决策只读 `fxapk digest <report.json>`（低 token、已按"建议调证 > 待核"排序）；要细节再读 `out/<名>.json` 全量。
- 命令失败/缺前置 → 看它打印的 `playbook`（每条是可直接复制的修复命令），照着修，**别自己另起炉灶手搓**。
- 只有当**没有**对应 fxapk 命令、或要改 fxapk 代码本身时，才进入"分析/开发"模式（见第 5 节）。

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

## 1.5 真机取证机准备（Android，动态分析前置）

脱壳 / 抓包 / 去壳重打包都需要**已 root 的 Android 真机或模拟器**（frida-server 必须 root 跑）。**纯静态 `analyze` 不需要设备**。一次性配置：

1. **root**（以红米 K40＝代号 `alioth` 为例）：解锁 BL（登小米账号 + 插**任意 SIM**翻开关，翻完可拔；小米有强制等待期）→ 取**与当前 MIUI/HyperOS 版本完全一致的 boot.img** → Magisk「安装 → 修补文件」生成 `magisk_patched.img` → `fastboot flash boot magisk_patched.img`。给 **shell（adb）授予 su 权限**（doctor 的 root 判定就认 `adb shell su -c id` 出 uid=0）。
2. **一键体检 + 自愈**：`fxapk doctor --fix` —— 自动按设备 ABI（K40＝arm64-v8a）+ 主机 frida 版本**下载并部署 frida-server、起进程、把 mitmproxy CA 装进系统信任库**，逐项报 OK / 怎么修。这一步能修的都自动修，别手动逐个搞。
3. **装 APK 绕过 MIUI「USB 安装要插 SIM」闸**：root 后不用开"USB 安装"那个 SIM 限制开关，直接
   `adb push x.apk /data/local/tmp/ && adb shell su -c 'pm install -r -t /data/local/tmp/x.apk'`。
4. **验证**：`frida-ps -U` 能列出设备进程 = frida 通；`fxapk doctor`（不带 --fix，纯体检）全绿即可开跑 `fxapk auto`。

常见坑：
- **frida-server 从 GitHub releases 下载**——PC 在国内无代理会失败/慢。解决：挂代理；或手动下 `frida-server-<主机frida版本>-android-<abi>.xz`（版本须与 PC `frida --version` 一致，doctor 已自动对齐版本号）push 到 `/data/local/tmp/frida-server` 自起。
- **mitmproxy CA** 仅 HTTPS 抓包要：先 `pip install mitmproxy` 跑一次 `mitmdump`（Ctrl-C 退）生成 `~/.mitmproxy`，再 `doctor --fix` 装系统证书。
- **boot.img 必须与当前 ROM 版本匹配**，否则 bootloop。
- 取证测试机建议用**一次性小米账号 + Magisk**，别登个人账号。

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
- `fxapk repackage <apk>`：脱壳后把**去壳版**重打包（zip 替 DEX + apksigner 重签）装回设备，使 capture 抓去壳版（绕壳反 frida）。需 apksigner/zipalign + 设备；auto 默认含此步（`--no-repackage` 关；重签必卸原包会清 app 数据）。能力边界：治不了 VMP/重 native/反模拟器壳，多数样本预期降级、capture 仍跑原版。
- `fxapk track`：起**本地/LAN 网页**看每个 APK 的线索 + 办案进度（手动改状态/备注/进展）；网页还能**手动补线索**（自动没抠到的人工录入，标 manual）和**编辑图谱面板**（看共享强实体/关联 APK、全局删实体、断本 APK 与某实体的边、加实体并连本 APK）。`fxapk track ingest <report.json...>` 回填历史报告。analyze/auto 默认自动入台账（`--no-track` 关）。台账在 `~/.apkscan/tracking.json`（仓库外，`git pull` 不覆盖）。LAN 共享 `--host 0.0.0.0`（自动令牌鉴权，承载 PII）。
- `fxapk graph ...`：把多份报告导入知识图谱做**团伙串案/聚类**（`graph ingest`/`link`/`cluster`/`query`/`stats`/`cypher`）。**入图只留强档降噪**（sign/c2/wallet/crypto_addr/admin_host/im_server/telegram_bot；中档 uni_appid/firebase 不入，避免无关包被串到一起）。analyze/auto 入台账时也顺带喂图谱（kuzu 可用时）。手工维护：`graph rm-entity <kind> <value>`（全局删实体+边）/ `graph unlink <sha256> <kind> <value>`（只断一条边）/ `graph prune-weak`（一次性清存量非强档噪音）；这些也能在 track 网页图谱面板里点。

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
- Python type hints；测试用 **pytest**（不要 unittest）。跑全套：`python -m pytest -q`；快跑（排除重型）：`python -m pytest -q -m "not slow"`。
  - `@pytest.mark.slow` 标记的真 spawn 端到端等价测试需本地 `*.apk` 样本（`FXAPK_TEST_APK` 或仓库内任一 `*.apk`），无样本自动 skip（CI 不挂）。
- 富化器（`apkscan/enrichers/*.py`）继承 `BaseEnricher`，自动发现；失败吞成 `EnrichmentResult(ok=False)`
  **不抛、不裸 except、不在 try 里 swallow log**。新增富化器标 `phase`（attribution/attack_surface）+ `active`。
- **分析器并行**（`apkscan/core/pipeline.py` + `snapshot.py`）：android 多核默认走**进程池并行**（绕 GIL；把 ApkContext 物化成可 pickle 的 `SnapshotContext` 发各 worker）。worker 数按 `min(CPU, 分析器数, 可用内存可容纳数)` 封顶防 OOM，**Linux cgroup 感知**（容器里取 cgroup 限额而非宿主机内存）。逃生 / 调优开关（env）：
  - `FXAPK_NO_PARALLEL=1` 强制串行（排障/兼容）；`FXAPK_MAX_WORKERS=N` 钳死 worker 数（=1 即强制串行）。
  - `FXAPK_WORKER_BASE_MB` / `FXAPK_MEM_SAFETY`（0<v≤1）现场覆盖内存封顶的标定（单 worker 估算 / 安全系数）。
  - ★ 改并行或快照路径须守不变量 **「串行 == 并行 逐字节一致」**（由 slow 等价测试背书）；分析器输出须确定（跨进程 PYTHONHASHSEED 不同，set 派生的顺序要显式排序）。设计文档见 `docs/superpowers/specs/`。
- **合并前必过三关（本地）**：`python -m ruff check apkscan tests` + `python -m pyright apkscan` + `python -m pytest -q`——CI（`.github/workflows/ci.yml`）这三样都跑，**只跑 pytest/pyright 不够，ruff 必跑**（曾因一个未用 import F401 把 CI 刷红）。
- **CI 环境对齐**：CI 装的是 `pip install -e ".[graph,track]"`（含 kuzu + flask）。新增**可选依赖**必须进对应 extra（如 web→`track`、图谱→`graph`），且 ci.yml 两个 job 都要装上它，否则 CI 缺包报 `ModuleNotFoundError`/pyright 解析失败。依赖某可选 extra 的测试在模块顶部 `pytest.importorskip("<pkg>")`，未装该 extra 的环境优雅跳过。
- **合并前等 CI 绿**：开 PR 后 `gh run watch <id> --exit-status` 等 CI 跑完再 `gh pr merge`——别本地绿就盲合（本地与 CI 环境/依赖/平台不一致，本地缺 ruff、CI 缺可选依赖都坑过）。
- commit：conventional commits OK，中文 OK；**不要** `--no-verify` / 不要 force push 到 master；未经指示不主动 commit。
