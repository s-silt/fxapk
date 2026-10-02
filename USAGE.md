# fxapk 命令与数据约定

[返回项目首页](README.md) · [English](USAGE.en.md)

## 命令表

要自己敲命令的话，常用的就这些。完整参数 `fxapk --help`；`fxapk` 没装成命令就换
`python -m apkscan.cli`。

| 想干什么 | 命令 |
|---|---|
| 分析一个 APK（**默认联网**查归属） | `fxapk analyze app.apk --out out` |
| 同上，但**不联网**（样本里的域名 / IP 不外发） | `fxapk analyze app.apk --offline --out out` |
| 授权联网留存 HTTP 跳转与响应（不执行 JS；私有 HAR） | `fxapk capture-web https://example.invalid/start --authorized --out private/capture.har` |
| 分析存下来的 HTML/JS/HAR（默认离线；`--online` 只开启富化） | `fxapk analyze-web <目录> --out out` |
| 批量跑一个文件夹 | `fxapk batch <目录>` |
| 一把梭：体检→静态→脱壳重分析→PCAP→通用探针→定向采集→合并（接了 root 机才跑动态；没设备就跳过，静态报告照出）。**会改设备**，只在专用测试机上跑 | `fxapk auto app.apk --out out` |
| 同上，当验收门用（退出码 0/5/6 = complete/partial/failed） | `fxapk auto app.apk --out out --strict-case` |
| 给已有报告补齐多源查询与五层归属 | `fxapk case close out/app.json` |
| 固化 Phase-1 证据包（报告和附件须在输出目录树内） | `fxapk case package out/app.json --case-id CASE-001 --producer analyst --out out/case-package.json` |
| 校验 Phase-1 包并与工作树外 corpus 对账（默认 dry-run；确认后加 `--apply`） | `fxapk corpus reconcile out/case-package.json --corpus <库>` |
| 对精确证据包出具 Phase-2 复核记录 | `fxapk case review out/case-package.json --reviewer reviewer --status accepted --gate-receipt phase2/gate-receipt.json --out out/case-review.json` |
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
| 查询 JADX 使用位置或启发式调用路径；按原 APK SHA 查询主及全部备用索引 | `fxapk jadx usage <值> --jadx-cache-root <cache> --apk-sha256 <sha> --out <receipt.json>`；`fxapk jadx callpath 'cls#m/0' 'cls#n/1' --jadx-cache-root <cache> --apk-sha256 <sha>`；单索引诊断仍可用 `--jadx-index <key>` |
| 对照两份报告与对应 JADX 索引，整理家族候选的共同点、差异和代码定位 | `fxapk jadx compare <subject-report.json> <candidate-report.json> --jadx-cache-root <cache> --out <comparison.json>`；相似性不代表同一运营者 |
| 识别线（全部只读 / 离线；模型只能写 proposed）：从判断账本投影重分析请求 / 校验标签文件 / 构建与校验防泄漏 split / 评测并过晋级门（门未过退出码 4，可当 CI 闸） | `fxapk recognize reanalysis <ledger> --out <requests.jsonl>`、`fxapk recognize labels validate …`、`fxapk recognize split build\|validate …`、`fxapk recognize evaluate …` |

被动资源画像可显式选择 `fofa_profile,fofa_host,daydaymap_profile`。先按已授权目标清单预演：

```bash
fxapk enrich batch -t targets.txt -o enrich_out --stage api --providers fofa_profile,fofa_host,daydaymap_profile
```

核对服务、披露范围与预算后，同一命令加 `--no-dry-run` 执行。FOFA 传统 11 列结果保持兼容；
增强搜索、HOST 聚合分别记录，两者同属 FOFA，不能当成两个独立来源。搜索只取有界首屏，
结果记录已报告总量、实际返回量与覆盖状态；未知总量、缺字段和权限失败不等于“没有资产”。
产品、证书和测绘时间帮助判断服务类型，不能单独确认云实例、租户账号或运营者。

批量结果每完成一个目标就写入 `enrich.ndjson`；`enrich.csv` 是从该文件重建的当前投影。
响应哈希是核对锚点，归一化服务字段是有界、脱敏预览，**不是完整原始响应存档**。
新版画像契约会使受影响来源的旧记录进入补查计划，先 dry-run 核对预算；命中有界首屏后
不会自动翻页。权限/额度错误及连续失败熔断后，本轮其余目标标记跳过；调整配置或恢复服务后
重新启动有界批次。`--credential-slot 2` 支持 Quake、DayDayMap 及其画像，不会自动换号。

JADX 多索引查询默认读取 cache 根的 `fxapk-jadx-index-map.json`，也可用 `--index-map` 指定映射。
旧 1.6 索引只为建库时选定值保存 postings，因此索引 `coverage=complete` 不保证任意新值已覆盖；
查询另报 `query_coverage`。启用 `--jadx-cache-root` 的新分析会在 `query-sources` 保存有界 Java 快照，
供后续新值查询，保持原索引字节不变；缺快照或覆盖不足会明确标记。快照和 `--out` 回执包含受控材料，
保留在本地证据目录，不公开提交。`callpath` 的 `name_unique` 仅是候选简单名唯一，不证明方法绑定。

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

CONTRACTS 版本失效仅作用于 batch 账本续跑；case close 的有限重富化沿用其既有规则，不改写旧报告终态。

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

`repack_identity` 返回 `self_built`、`repack_suspected` 或 `unknown`。自建判定也不意味着
所有接口、域名或构建路径都属于运营方，仍须排除公共 SDK、壳与共享设施。疑似重打包时，
继承和新增范围尚未确定；须与官方同版本包差分，逐资产核对，不能一概归给原厂或样本运营者。

判成重打包时，工具只说「看起来被重新签过名」，不会说「植入了什么」。想认定植入，得拿官方同版本的
包逐个文件比对，光看这个样本本身给不出这种结论。

## 输出

以下用 `app.apk` 为例，文件基名来自输入名；网页报告按证据目录名或来源标注命名。

- `out/app.html` — 单文件内部证据视图，可在手机上打开；含原值，外发前另做审核
- `out/app.json` — 完整数据，给机器读或者接着加工
- `report.meta.closure` — 验收结论、五层证据、来源覆盖、缺口和下一步该干什么
- `case-package.json` — Phase-1 报告/附件作用域、字节哈希与分析/闭环快照
- `case-review.json` — Phase-2 对精确 `package_id + manifest_sha256` 的复核记录
- 加 `--fmt pdf` 可以导 PDF（要本机装了 Chrome 或 Edge）

## 固定依赖与复现边界

结论是解析出来的，而解析归上游库管。androguard 换个版本，dex 里读出来的东西就可能不一样；报告也就
跟着不一样了。所以仓里放了一份 [`requirements.lock`](requirements.lock)，把整棵运行时依赖钉死：

```bash
python -m venv .venv-forensic
.venv-forensic/bin/pip install -r requirements.lock
.venv-forensic/bin/pip install --no-deps .
```

最后一条安装命令保留 `--no-deps`，防止再次解析依赖偏离锁。Windows 对应解释器为
`.venv-forensic\Scripts\python.exe`，用它的 `-m pip` 执行两条安装命令。

复现旧报告应使用当时保存的代码、规则和依赖锁；当前锁不代表所有历史环境。报告中的
`meta.dependency_versions` 可帮助核对。还需保存检材哈希、参数、外部工具、缓存与原始响应，
以及动态采集的设备和时间条件。联网数据、时间戳和设备状态会变化，固定依赖并不保证整份报告逐字节相同。

## 从源码改代码

clone 完先跑一次，把提交前的检查装上：

```bash
git config core.hooksPath .githooks
```

hook 只看 staged 新增行。默认阻断疑似真实 IP、凭据、案件人名、联系方式、二开包名、
无理由及批量豁免；域名和语境规则在 strict 档也阻断。行内例外须写 `leak-scan:` + `allow` +
成立的逐行理由，不能批量压掉告警。已有提交用 `fxapk leak-scan --base origin/master --strict`
核对整个候选 diff；CI 也扫 PR diff 及已跟踪源码/测试，不能用空暂存区的结果代替。

测试数据优先用文档保留段：`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`、
`example.com`。若被测判据无法用保留值触发，应使用 mock 或有逐行理由的合成夹具，
不能使用真实案件值。真实地址推上去就收不回来了，改写历史也删不掉平台那边的缓存副本，唯一靠谱的办法是
一开始就别写进去。

## 合规边界

仅用于授权范围内的安全研究与分析。工具只做静态、动态分析和信息提取，不提供攻击或漏洞利用功能；主动访问须明确授权。授权 HTTP 留存入口 capture-web 需要显式 --authorized，
且仅在指定目标与额外主机允许清单内执行有界 GET。

默认被动：境外服务器只做被动归属（RDAP / WHOIS / DNS / ASN / 证书透明度），默认富化不主动访问样本声明的业务 URL，但 DNS 查询可能被解析器或权威 DNS 观察到。少数
确实要向目标发请求的能力（比如去取样本自己引用的那个配置对象）默认关着，按对应命令的显式授权参数启用。脱壳只针对样本自身，在你自己的授权分析机上进行。

详见 [联网采集、三轮动态与报告前材料工作流](PRE-REPORT-WORKFLOW.md)。

请在合法授权范围内使用。

## 报告前材料的工程入口

分层、兼容边界及尚待真实环境验收的项目见 [ARCHITECTURE.md](ARCHITECTURE.md)。
以下命令不替代原始证据核验；脱敏视图也不是完整隐私清洗证明。

```bash
# 只读查询来源产品目录，不发起第三方查询、不证明账户权益
fxapk case source-catalog --category all
# 已有报告生成服务商角色复核队列，默认不输出目标真值
fxapk case provider-plan private/report.json --out private/provider-plan.json
# 在一个案件目录的子包目录内固化报告；附件资格由操作者显式指定
fxapk case package private/demo/pkg/report.json --case-id DEMO --producer analyst --out private/demo/pkg/case-package.json
# 串联已验包和报告前材料；coverage/clues 可配对提供，缺失会保留缺口
fxapk case prepare-materials private/demo --out private/demo/pre-report.json
```

`review_required`、`partial` 和 `failed` 均不是完成确认。三轮抓包分别留档；某一轮成功不能清除
另一轮失败，也不能跨轮拼接计数后宣称完整。真机兼容性与服务商账户实测须单独验收。

## License

[MIT](LICENSE)
