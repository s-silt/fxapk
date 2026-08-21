# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI 命令 `fxapk`（保留 `apkscan` 别名）· PyPI 包名 `fxapk`* · **English**: [README.en.md](README.en.md)

APK 分析工具，一条命令出一份报告。它主要做四件事：

**翻出应用真正在用的配置。** AppID、AppKey、渠道号、uni-app 的应用 ID 这些，包括塞在资源文件和
native 库里的。

**看它跟哪些服务器说话。** 域名、IP、端口先静态抠一遍；接了设备就再抓一遍包，两边对上。

**顺着加密的远程配置往下追。** 有些应用不把后端地址写死在包里，而是加密后丢在 OSS 或 CDN 上，
启动时拉下来解密。工具会找到那个对象、一层层解出里面的域名和 IP 池，拼成完整的一条链。碰上认不出
解密方式的混淆样本，它不硬猜，把密文原样交出来让人或 AI 接着解。

**查域名和 IP 是谁的。** 分五层写：谁登记的、走哪个 AS、放在哪家云或机房、前面有没有套 CDN、
实际运营者是谁。每层都带来源，查不到就写不知道 —— 不会拿上一层的答案顶下一层，那是这类工具最
容易出错的地方。

装完就能跑静态分析，不需要 JDK、模拟器或真机。要给加固样本脱壳、要抓包，才需要接一台 root 过的
安卓机。

## ⚠ 先看：三条不加参数就会发生的事

前两条会在外部留下记录、或改动那台设备，撤不回来；第三条是安全方向的默认值，写在这里是免得
你以为要额外加参数才安全：

1. **`analyze` 默认联网。** 它不碰目标服务器，但会把样本里的域名 / IP 拿去查公开数据库
   （WHOIS / RDAP / 备案 / 测绘平台）。查询记录留在那些平台上——**等于向第三方平台披露
   你正在分析什么**，而且删不掉。不想联网加 `--offline`。
2. **`doctor` 与 `auto` 默认会改设备**（检测到可用设备时；没接设备则跳过动态步骤）。
   部署 frida-server、装抓包用的 CA 证书；`auto` 还可能对应用脱壳、重打包重签名、
   **卸载原应用并清掉它的数据**，再装上待分析的样本——被清掉的数据回不来。
   别在日常手机、带账号的模拟器或办公网络里跑。只想看看环境状况用 `fxapk doctor --no-fix`。
3. **`digest` 默认脱敏。** 钱包私钥 / 助记词、个人手机号 / 身份证 / 银行卡、后端凭据这些会被打码
   ——因为这条命令的输出通常直接喂给 AI。确需明文原值时显式加 `--no-redact`；
   完整明文一直都在本地的 `report.json` 里，不受这个开关影响。

> **脱敏只管 `digest` 这一条路。** 其余出口若含高敏值，不会替你脱敏：`fxapk jsonl`、
> `fxapk diff`、`fxapk lead show/restore/replay`、
> `fxapk corpus events/ls/seen/shared-config/shared-native/shared-build-env/link-candidates`、
> `fxapk probe-leads`、
> `fxapk pcap-leads`（这些会把线索值打到 stdout 且不脱敏，运行时各自打一行提醒；corpus
> 那几条经台账的 key_iocs 带出，而台账不按类别过滤高敏）、
> `fxapk export` 的 CSV、HTML / PDF 报告、生成的文书、`corpus` 存证，以及 `report.json` 本身。
> 它们多半就该是本地证据载体，但**把它们贴给第三方服务时没有任何东西替你挡着**。
> `corpus link-discover` / `link-explain` / `link-groups` 是例外：默认
> `--evidence-values omit`，只给运行内别名和 allowlist 字段；显式切到 `raw` 才会输出原始家族、
> 样本和锚值，并在 stderr 警告。`link-labels-validate` / `link-evaluate` / `link-readiness` /
> `link-train` 只输出聚合统计，不回显私有标识符。这些是各自的安全投影，不扩大 `digest` 的脱敏范围。
>
> 另外，脱敏是尽力而为、不是完整的数据防泄漏。确切的保证只有两条：高敏类别的**值**被打码；
> **线索自己的**自由文本里，邮箱 / 手机号 / 身份证号 / 长数字串这类有固定形态的被抹掉。
> 这之外一律原样——包括技术发现的标题、可见性与闭环结论的说明文字、境外目标那一段。
> 姓名、地址、境外号码没有稳定形态，哪儿都抹不掉。

动态那部分建议只在专用测试机上跑：没有个人账号与真实短信、没有银行卡钱包通讯录、与办公和家庭
网络隔离、最好是能还原快照的模拟器。

## 怎么用：对 AI 说三句话

这个工具是给 AI 助手（Claude Code、Codex 之类）驱动的。**你不用记命令，只要会说几句话**——
头一次说三句把它装好配好，之后每次干活只说一句。

### 第一次，说这三句

**第一句：「部署 github.com/s-silt/fxapk」**

AI 会去装：

```bash
pip install fxapk
```

想连代码一起拿（要改、要看源码）就说「从源码部署」，它会改用：

```bash
git clone https://github.com/s-silt/fxapk.git && cd fxapk && pip install -e .
```

需要 Python 3.11 或更新。万一 `fxapk` 这个命令没装上，换成 `python -m apkscan.cli` 一样使，
后面参数不变。

普通分析、规则候选和训练就绪检查都不需要 ML 依赖。只有 `link-readiness` 已返回 `ready`、确实要在
本机训练实验 challenger 时才安装 `pip install 'fxapk[ml]'`（源码树用 `pip install -e '.[ml]'`）。

**第二句：「自检并配置环境」**

AI 会跑：

```bash
fxapk selfcheck
```

它一条条列出来：**什么能用、什么不能用、不能用的要装什么**。AI 看完就知道这台机器能干到哪一步，
该提醒你补装什么——不用挨个试命令去猜。

分析 APK 本身不需要额外装东西，装完就能跑。脱壳、抓包、联网查服务器归属是可选的，
少哪个只影响哪一块，自检结果里写得清清楚楚。

**第三句：「把 .env 配好」**

这一步别跳过。查服务器是谁的、在哪，靠的是同时问好几个公开数据库，谁都可能查不到——**问得越多，
拼出来的画面越完整**。其中 RDAP、WHOIS、DNS、ASN、证书透明度这些不用密钥就能查；商用测绘和情报
库（FOFA、Shodan、VirusTotal、Hunter、Quake、ZoomEye、Censys、OTX、AbuseIPDB 等）各自要账号密钥，
写在项目根目录的 `.env` 里。

```bash
cp .env.example .env    # 然后把你有的密钥填进去
```

支持哪些源、各自的变量名，`.env.example` 里列全了。**有几个填几个，一个不填也能跑**——只是查归属
那部分会变弱：没配密钥的源不会瞎猜，报告里如实标成「没查」（`disabled`），而不是「查了没有」
（`no_record`）。这两件事完全不同，别读混。

密钥只在本机用，不会进报告、不会进日志、不会提交到仓库（`.env` 已经在 `.gitignore` 里）。
哪个源这次真的查着了、哪个没查成，跑完之后看报告里的 `source_status`——`fxapk selfcheck` 只报
「联网能力总体通不通」，不逐个源检查。

### 之后每次，只说这一句

**「解析」加一个路径**

```
解析 D:\样本\app.apk
解析 D:\证据\某网站目录
解析 out/app.json
```

AI 看你给的是什么，自己挑命令：

| 你给的东西 | AI 跑的命令 | 会发生什么 |
|---|---|---|
| 一个 `.apk` 文件 | `fxapk analyze <路径> --out out`，然后 `fxapk digest out/<名>.json` | 出一份报告，再压成一页要点（默认联网查归属、摘要默认脱敏） |
| 一个文件夹，里面是存下来的网页（`.html` / `.js` 等） | `fxapk analyze-web <目录> --out out` | 只读你存下来的文件，不去联网访问那个网站 |
| 一份已经跑出来的 `report.json` | `fxapk digest <文件>` | 把长报告缩成一页要点，高敏值默认打码 |
| 一个装了很多 APK 的文件夹 | `fxapk batch <目录>` | 一个个跑，跑过的自动跳过 |

想让它顺便查一下服务器归属，直接说就行——**`analyze` 默认就联网**；反过来，不想让它联网
要专门说一句「别联网」（AI 会加 `--offline`）。

**报告怎么读**：先看开头那段「这次看到了什么」，它会说清楚**哪些话现在还不能说、为什么、
怎么补**。比如应用被加固过、真代码要跑起来才解密，那报告里写「没发现服务器地址」的意思是
**没看着**，不是**没有**。看完这段再往下看线索，不容易读岔。

更多命令和参数：`fxapk --help`。给 AI 看的详细操作约定在 [AGENTS.md](AGENTS.md)。

### 这个工具不做什么

免得你白找：

- **只认 Android 的 APK**，不解析苹果的 `.ipa`。（代码里能搜到 `.ipa` 这三个字，那只是一份
  「这类文件别当文本读」的名单，不是说能分析它。）
- **不去碰目标服务器**。查境外服务器只翻公开数据库，对目标不发一个包；少数确实要发请求的功能
  默认是关着的，见下面「合规边界」。
- **到报告与可验证交接包为止**。这个仓库产出报告文件（HTML / JSON / PDF）、线索 CSV，
  也能把报告与附件固化成 Phase-1 哈希清单并出具绑定精确哈希的 Phase-2 复核记录；
  再往后的案件表格和办公系统编排不在这里。

> 联网查询用的 API Key、动态分析要的外部工具、以及围绕报告的那些配套脚本 / MCP / 探针库，都要自己
> 准备，本项目不提供。见 [COMPANION-TOOLS.md](COMPANION-TOOLS.md)。

## 命令表

要自己敲命令的话，常用的就这些。完整参数 `fxapk --help`；`fxapk` 没装成命令就换
`python -m apkscan.cli`。

| 想干什么 | 命令 |
|---|---|
| 分析一个 APK（**默认联网**查归属） | `fxapk analyze app.apk --out out` |
| 同上，但**不联网**（样本里的域名 / IP 不外发） | `fxapk analyze app.apk --offline --out out` |
| 分析存下来的网页文件 | `fxapk analyze-web <目录> --out out` |
| 批量跑一个文件夹 | `fxapk batch <目录>` |
| 一把梭：体检→静态→脱壳→抓包→合并（接了 root 机才跑动态；没设备就跳过，静态报告照出）。**会改设备**，只在专用测试机上跑 | `fxapk auto app.apk --out out` |
| 同上，当验收门用（退出码 0/5/6 = complete/partial/failed） | `fxapk auto app.apk --out out --strict-case` |
| 给已有报告补齐多源查询与五层归属 | `fxapk case close out/app.json` |
| 固化 Phase-1 证据包（报告和附件须在输出目录树内） | `fxapk case package out/app.json --case-id CASE-001 --producer analyst --out out/case-package.json` |
| 校验 Phase-1 包并与工作树外 corpus 对账（默认 dry-run；确认后加 `--apply`） | `fxapk corpus reconcile out/case-package.json --corpus <库>` |
| 对精确证据包出具 Phase-2 复核记录 | `fxapk case review out/case-package.json --reviewer reviewer --status accepted --out out/case-review.json` |
| 并列查看包完整性、分析、闭环、复核四种状态 | `fxapk case status out/case-package.json --review out/case-review.json` |
| 把报告压成一页要点（**默认脱敏**） | `fxapk digest out/app.json` |
| 同上，但要看高敏值的明文原值 | `fxapk digest out/app.json --no-redact` |
| 真机抓包 | `fxapk capture <包名>` |
| 设备体检（**默认就会动手修**：装 frida-server / CA 证书） | `fxapk doctor` |
| 只体检、什么都不改 | `fxapk doctor --no-fix` |
| 环境自检（哪些能力通/不通/怎么修） | `fxapk selfcheck` |
| 批量查目标清单（默认 `--dry-run` 只估配额不发请求；断了能续跑） | `fxapk enrich batch -t targets.txt -o enrich_out` |
| 报告入库 | `fxapk corpus add out/app.json --corpus <库>` |
| 换版本后看检出变好还是变坏 | `fxapk corpus regress --corpus <库>` |
| 这个值以前见过没（跨样本反查） | `fxapk corpus seen <值> --corpus <库>` |
| 找出自同一套开发环境的样本 | `fxapk corpus shared-build-env --corpus <库>` |
| 按可解释技术锚生成串案复核候选（原值输出；分数不是概率） | `fxapk corpus link-candidates --corpus <库>` |
| 校验工作树外的追加式私有标签（只输出聚合计数） | `fxapk corpus link-labels-validate --labels <标签.jsonl>` |
| 用独立金标评测 rules-v2（循环标签自动排除；只输出聚合指标） | `fxapk corpus link-evaluate --corpus <库> --labels <标签.jsonl>` |
| 从已标关系组发现待人工核验的重复锚（默认不输出原值） | `fxapk corpus link-discover --corpus <库> --labels <标签.jsonl>` |
| 解释候选 / 生成匿名复核关系图（默认 `omit`） | `fxapk corpus link-explain <SHA> <SHA> --corpus <库>` / `fxapk corpus link-groups --corpus <库>` |
| 检查本地训练门槛（按 train/holdout 分量切分，只输出聚合计数） | `fxapk corpus link-readiness --corpus <库> --labels <标签.jsonl>` |
| 门槛通过后训练实验排序器（模型只写工作树外；不足即 `blocked`） | `fxapk corpus link-train --corpus <库> --labels <标签.jsonl> --model-out <模型.json>` |
| 用实验模型 shadow 重排规则候选（不扩张召回、不突破规则 caps） | `fxapk corpus link-candidates --corpus <库> --model <模型.json>` |
| 把线索导成 CSV | `fxapk export out/app.json` |
| 两份报告比差异 / 把报告压成 agent 可读的 JSONL | `fxapk diff a.json b.json`、`fxapk jsonl out/app.json` |
| 在已建的 JADX 持久索引里查某个值用在哪 / 两个方法间有没有静态调用路径（**bounded**；空结果≠不可达，`resolution` 只有 `name_unique` / `ambiguous` / `not_in_index` 三态、不是方法绑定） | `fxapk jadx usage <值> --jadx-cache-root <cache> --jadx-index <key>`、`fxapk jadx callpath 'cls#m/0' 'cls#n/1' --jadx-cache-root <cache> --jadx-index <key>` |
| 识别线（全部只读 / 离线；模型只能写 proposed）：从判断账本投影重分析请求 / 校验标签文件 / 构建与校验防泄漏 split / 评测并过晋级门（门未过退出码 4，可当 CI 闸） | `fxapk recognize reanalysis <ledger> --out <requests.jsonl>`、`fxapk recognize labels validate …`、`fxapk recognize split build\|validate …`、`fxapk recognize evaluate …` |

凡是读取或写入样本库的 `corpus` 子命令，都要指定库目录：`--corpus <库>`，或者先设好
`FXAPK_CORPUS` 环境变量。库根会存样本数据，别放在代码仓库里面。

案件归属与报告索引分开保存：报告内容可重建到 `manifest.jsonl`，人工确认的多案关联、隔离状态和
新入库顺序只写在非派生 `catalog.jsonl`。一个报告可绑定多个规范化 `case_id`；普通查询默认排除
`quarantined`，只有显式 `--include-quarantined` 才显示。旧版/开发版先用 `corpus versions` 审计，
需要隔离时再显式执行 `corpus quarantine-version --apply`，工具不会自动删除历史证据。新记录的
`ingest_sequence` 在库锁内分配并可跨 `reindex` 保持；旧库若没有权威顺序，`corpus regress` 与
多版本 `corpus events` 会要求显式选择修订版，不会拿 manifest 行序或文件 mtime 猜“最新”。

升级到 rules-v2 后，旧 manifest 若还没有 `repack_identity_verdict`，`link-candidates` 会返回
`status=partial` 和结构化 `migration.next_action`，因为缺字段时无法可靠执行正版重打包封顶。按提示
先显式运行 `fxapk corpus reindex --corpus <库>` 从原始报告补投影；它不改 `reports/` 内的报告字节。
字段存在但值不是 `self_built|repack_suspected|unknown` 也按未评估处理。如果重建后仍有缺字段，
说明对应旧报告从未完成该项评估，必须用当前 fxapk 重新分析受影响样本并
重新入库/重建索引，不能用 `reindex` 把“未评估”改写成 `unknown`。
`link-groups` 对大型连通分量只给 `transitive_only_pair_count` 精确总数和最多 100 对稳定预览，
不会把完整传递闭包物化进内存。

Phase 1 到 corpus 的机器接口优先直接传经校验的 `case-package.json`；也兼容显式 JSONL inventory，
每行必须给出字符串 `case_id` 和 `report_path`。`corpus reconcile` 默认纯只读，只把缺记录/缺绑定
列为计划；加 `--apply` 后仍只新增不可变报告或并入案件关联，遇字节冲突、隔离记录或包哈希变化会
非零退出，不覆盖、不解隔离。Phase 2 始终消费并复核精确 package 哈希，不依赖 OneDrive 临时目录。

验收结论写在 `report.meta.closure`：`complete` 是主目标那五层都拿到了证据（运行时、资源登记、
BGP 宣告、托管分发、最终归属对象）；`partial` 是还有明确缺口；`failed` 是静态就跪了、或者要求动态
却没抓到业务流量、或者压根没有能收口的主目标。前面套着 CDN、源站还没定位出来的，不会判 complete。

### 两阶段交接与四种状态

公共协议不绑定 OneDrive、某个 AI 或某台机器。Phase 1 负责产生报告、附件和不可变
`case-package.json`；Phase 2 只读校验 Phase-1 包，再产生独立 `case-review.json`。同一个人可以
按顺序执行两个阶段，但 Phase 2 不得覆盖 Phase 1；要求修改时应产生新的 package，再对新哈希复核。
Phase-1 包还会固定报告的三个复现锚点：64 位十六进制 `sample_sha256`、非空规范化
`tool_version` 与 16 位十六进制 `ruleset_digest`；缺少或使用 `unknown` 占位时拒绝建包且不落盘。

四种状态不能互相推出：

- `package_integrity`：manifest、路径边界和附件字节哈希是否一致；
- `analysis`：分析器/流水线是否完整运行；
- `closure`：当前案件的运行时、归属与调证对象是否闭环；
- `review`：精确 package 哈希是否被复核接受、要求修改或已经失效。

`package_integrity=verified` 不等于分析或闭环 complete；`review=accepted` 也不会把 partial 闭环
变成 complete。报告或附件变化后，旧复核记录显示为 `stale`。

报告 schema 1.2 起，每条 Evidence 带 `scope`：`case_evidence` 是当前案件直接证据；
`batch_reference` 是批量/跨案参考，只能辅助复核，不能独立升级为“建议调证”或满足 closure；
旧报告没有该字段时迁移为 `legacy_unspecified`，同样不自动取得直接证据资格。
这一资格闸同样作用于摘要、调证函、IOC、JSONL 和 HTML/PDF；普通 IOC 仍可保留参考值但标为
`待核`/非 C2，`--only-investigate` 会排除它。JSONL 为保持紧凑不展开完整 `source_refs`，但每条
Lead 事件会带 `evidence_scope_summary`，明确是否有当前案件直接证据及其引用数。
闭环状态也走同一安全投影：报告声称 `complete` 但目标清单为空时按 `failed` 消费；任一目标没有
同值 Lead 或 Endpoint 的显式 `case_evidence` 时只能按 `partial` 消费并附缺口/下一步。Phase-1
建包更严格，会直接拒绝这种虚假 `complete`，不能靠改快照绕过。`evidence_scope` 是事实资格，
不能用 `lead restore/replay` 人工撤销；必须补采当前案件直接证据。

持久化的 report/package JSON 遵循标准 JSON：读取拒绝 `NaN`、`Infinity`、`-Infinity`，写出也
拒绝非有限浮点；失败不会覆盖已有报告或创建半成品包。合法有限浮点保持兼容。

corpus 的案件级 IOC 索引也只接收 `Lead.source_refs[]` / `Endpoint.evidences[]` 中至少一条
显式 `case_evidence`。旧版或未标记的索引投影默认不参与 `seen` / `shared-*`，先核验库内报告，
再显式运行 `fxapk corpus reindex` 从原报告重算；它不改报告字节。旧 `manifest.case_id` 迁移到
非派生 `catalog.jsonl` 时先 dry-run `fxapk corpus migrate-catalog`，确认后才加 `--apply`。

⚠ **这个迁移撤不回来，`--apply` 之前先把整个语料库目录备份一份。** `corpus restore` 帮不上忙：
catalog 是案件绑定的真源、manifest 只是可重建的派生索引，恢复迁移前的 manifest 快照会被 catalog
立刻重新物化回迁移后的形态（而且 restore 会照常报 `applied: true`，看起来像成功了）；手工删掉
`catalog.jsonl` 想补全回滚，则整库 fail-closed，`ls` / `verify` 全部拒绝执行。两条路都不通，
**整目录备份是唯一的退路**。迁移本身不碰 `reports/` 下的报告字节，只往 manifest 加字段。

### 别把「没看着」和「工具没跑成」弄混

报告里的 `visibility` 说的是**样本内容看不看得见**，`analysis_status` 说的是**工具跑得顺不顺**。
分析器全部成功（`analysis_status=complete`），同时 DEX 是个壳、六条结论一条都不能下 ——
这两件事完全可以同时成立。`blocked_claims` 点名哪几条结论现在不能下，`next_actions` 说怎么补。

### 先分清：自己写的包，还是正版被人改过

`repack_identity` 会给三种判定，这一步得先做，因为两种情况下接口、域名、构建路径的归属正好相反。
自己写的包，这些都是开发方自己的；正版被重打包的，这些属于被冒名的那家厂商 —— 照着去查就会找错
对象，找到一家毫不相干的公司头上。

判成重打包时，工具只说「看起来被重新签过名」，不会说「植入了什么」。想认定植入，得拿官方同版本的
包逐个文件比对，光看这个样本本身给不出这种结论。

## 输出

- `out/report.html` — 单文件报告，直接发人或手机上打开都行
- `out/report.json` — 完整数据，给机器读或者接着加工
- `report.meta.closure` — 验收结论、五层证据、来源覆盖、缺口和下一步该干什么
- `case-package.json` — Phase-1 报告/附件作用域、字节哈希与分析/闭环快照
- `case-review.json` — Phase-2 对精确 `package_id + manifest_sha256` 的复核记录
- 加 `--fmt pdf` 可以导 PDF（要本机装了 Chrome 或 Edge）

## 想让同一个样本跑出同一份报告

结论是解析出来的，而解析归上游库管。androguard 换个版本，dex 里读出来的东西就可能不一样；报告也就
跟着不一样了。所以仓里放了一份 [`requirements.lock`](requirements.lock)，把整棵运行时依赖钉死：

```bash
python -m venv .venv-forensic
.venv-forensic/bin/pip install -r requirements.lock
.venv-forensic/bin/pip install --no-deps .
```

第二条命令的 `--no-deps` 别省 —— 省了 pip 会重新算一遍依赖，把刚锁住的版本又升上去。

平时随便装就行，用不着这个。只有要复现一份旧报告、或者要让两个人跑出一模一样的结果时才需要。报告
自己也记着当时实际用的版本（`meta.dependency_versions`），跟这份锁对一下就知道环境一不一样。

## 从源码改代码

clone 完先跑一次，把提交前的检查装上：

```bash
git config core.hooksPath .githooks
```

它只看你这次 staged 的新增行。像真实 IP、像密钥、写了豁免却没给理由的，直接拦下不让提交；域名和
一些敏感词只提示不拦（想连这些一起拦，加 `FXAPK_LEAK_SCAN_STRICT=1`）。确实要放行某一行，就在行内
写 `leak-scan: allow <理由>`，理由必须写。CI 会再扫一遍 PR diff，所以 `--no-verify` 只绕得过本地
这道。

测试数据一律用文档保留段：`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`、
`example.com`。真实地址推上去就收不回来了，改写历史也删不掉平台那边的缓存副本，唯一靠谱的办法是
一开始就别写进去。

## 合规边界

仅用于授权范围内的安全研究与分析。工具只做静态、动态分析和信息提取，不提供任何针对第三方的攻击、
漏洞利用或主动探测能力。

默认被动：境外服务器只做被动归属（RDAP / WHOIS / DNS / ASN / 证书透明度），对目标零主动流量。少数
确实要向目标发请求的能力（比如去取样本自己引用的那个配置对象）默认关着，只有显式加
`--mode authorized-active` 才启用。脱壳只针对样本自身，在你自己的授权分析机上进行。

请在合法授权范围内使用。

## License

[MIT](LICENSE)
