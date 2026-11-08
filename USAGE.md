# fxapk 命令与数据约定

[返回项目首页](README.md) · [English](USAGE.en.md)

完整参数 `fxapk --help`；`fxapk` 未装成命令时用 `python -m apkscan.cli`。

## 命令表

| 想干什么 | 命令 |
|---|---|
| 分析一个 APK（**默认联网**查归属） | `fxapk analyze app.apk --out out`；不联网加 `--offline` |
| 授权联网留存 HTTP 跳转与响应（不执行 JS） | `fxapk capture-web https://example.invalid/start --authorized --out private/capture.har` |
| 分析存下来的 HTML/JS/HAR（默认离线） | `fxapk analyze-web <目录> --out out`；`--online` 只开归属富化 |
| 接入已保存的 fxfetch 任务包（离线） | `fxapk intake-fetch <ZIP> --fxfetch <可信本机CLI> --out <新目录>`；可加 `--review-manifest <清单>` |
| 复核已提供的定点证据 | `fxapk evidence-review <清单> --report <已有报告.json> --out <新目录>`；`--report` 可省略 |
| 已授权的定点 DEX/JNI 恢复 | `fxapk recover-runtime <计划.json> --out <新目录>`；计划显式指定原 APK 哈希、设备、PID 和范围 |
| 批量 | `fxapk batch <目录>` |
| 一把梭（接了 root 机才跑动态；**会改设备**） | `fxapk auto app.apk --out out`；验收门加 `--strict-case`（退出码 0/5/6 = complete/partial/failed） |
| 已有报告补多源查询与五层归属 | `fxapk case close out/app.json` |
| 固化 Phase-1 证据包 | `fxapk case package out/app.json --case-id CASE-001 --producer analyst --out out/case-package.json` |
| 校验包并与工作树外 corpus 对账（默认 dry-run） | `fxapk corpus reconcile out/case-package.json --corpus <库> [--apply]` |
| Phase-2 复核记录 | `fxapk case review out/case-package.json --reviewer reviewer --status accepted --gate-receipt phase2/gate-receipt.json --out out/case-review.json` |
| 并列查看四种状态 | `fxapk case status out/case-package.json --review out/case-review.json` |
| 一页要点（**默认脱敏**） | `fxapk digest out/app.json`；看原值加 `--no-redact` |
| Android UI 截图、布局与固定动作（可选插件） | `fxapk ui --help`，见 [ANDROID-UI.md](ANDROID-UI.md) |
| 真机抓包 | `fxapk capture <包名>` |
| 设备体检 | `fxapk doctor --no-fix` 只检查；`fxapk doctor` **会动手修**（装 frida-server / CA） |
| 环境自检 | `fxapk selfcheck` |
| 批量查目标清单（默认 `--dry-run` 只估配额；可 `--resume`） | `fxapk enrich batch -t targets.txt -o enrich_out` |
| 报告入库 / 跨版本回归 / 反查 / 共享构建环境 | `fxapk corpus add out/app.json` / `regress` / `seen <值>` / `shared-build-env`（均需 `--corpus <库>`） |
| 串案候选（原值输出；分数不是概率） | `fxapk corpus link-candidates --corpus <库> [--model <模型.json>]` |
| 标签校验 / 离线评测 / 重复锚发现（聚合输出；discover 默认不出原值） | `fxapk corpus link-labels-validate --labels <jsonl>` / `link-evaluate` / `link-discover` |
| 解释候选 / 匿名关系图 | `fxapk corpus link-explain <SHA> <SHA>` / `link-groups`（默认 `--evidence-values omit`） |
| 训练门槛 / 训练实验排序器（模型只写工作树外） | `fxapk corpus link-readiness` / `link-train --model-out <模型.json>` |
| 导出 CSV / 比差异 / JSONL | `fxapk export out/app.json` / `fxapk diff a.json b.json` / `fxapk jsonl out/app.json` |
| JADX 使用位置、调用路径、家族对照 | `fxapk jadx usage <值> --jadx-cache-root <cache> --apk-sha256 <sha>` / `jadx callpath` / `jadx compare <a.json> <b.json>` |
| DEX 字符串引用查询与导入（可选 fxapk-asc 隔离 worker） | `fxapk dex query` / `fxapk dex import`，见 [plugins/fxapk-asc/README.md](plugins/fxapk-asc/README.md) |
| Flutter AOT 静态分析（可选插件，离线容器） | `fxapk flutter capabilities` / `analyze` / `query` / `attach`，见 [plugins/fxapk-flutter/README.md](plugins/fxapk-flutter/README.md) |
| 识别线（只读/离线；晋级门未过退出码 4） | `fxapk recognize reanalysis` / `labels validate` / `split build\|validate` / `evaluate` |

## 隐私与输出

`digest` 默认有限脱敏：遮蔽高敏类别值及线索自由文本中固定形态的邮箱、国内手机号、证件号和长数字串；姓名、地址、境外号码及 findings/visibility/closure/overseas_targets 等说明文字不保证移除。`--no-redact` 恢复原值。

以下出口原样输出高敏值，须单独审核：`jsonl`、`diff`、`lead show/restore/replay`、`corpus events/ls/seen/shared-config/shared-native/shared-build-env/link-candidates`、`probe-leads`、`pcap-leads`、`export` CSV、HTML/PDF、文书、corpus 存证、`case_correlation.json` 与 `report.json`。`corpus link-discover/link-explain/link-groups` 默认 `--evidence-values omit`，显式 `--evidence-values raw` 恢复原值；`link-labels-validate/link-evaluate/link-readiness/link-train` 只输出聚合结果。归档还可能包含源目录路径；压缩不脱敏，也不授权向第三方传输。

## 证据归档

`fxapk evidence pack <目录> --out evidence.zip` 默认 ZIP64/Zstd 6；旧工具兼容用 `--compression deflate`。`evidence verify` 流式校验整包，`evidence extract --out <新目录>` 逐字节提取。原 manifest、SHA-256 与 package_id 保留；归档索引只证明内部一致性，不替代案件证据门。

`capture` / `recover-runtime` / `intake-fetch` / `evidence-review` 可用 `--archive-out <新ZIP>` 代替 `--out`，并可加 `--archive-compression deflate`。业务 partial/failed 不因归档成功变成 ok；只有本次暂存目录在归档发布并校验成功后自动清理，失败保留材料和回执。

归档内读取用 `archive.zip::relative/member`；`evidence-review <ZIP> --archive-member replay-plan.json` 重放已保留输入，`intake-fetch <ZIP> --archive-member saved-task.zip` 接入包内任务，`evidence analyze <ZIP> --member sample.apk --out <新目录>` 固定离线分析。单成员先核验再交给分析器；PCAP 与 socket/UID 命令及运行时读取 API 支持成员引用。`evidence case-verify` / `corpus-add` 是整包临时展开的例外，仍走原案件验包与 corpus 边界。兼容性、上限、隐私及文件系统元数据限制见 [EVIDENCE-ARCHIVE.md](EVIDENCE-ARCHIVE.md)。

## 已保存网页材料

网页材料可附 `--evidence-handoff <证据目录外的JSON>`：
`fxapk.web-evidence-handoff.v1` 逐文件校验原始大小/哈希，绑定采集来源、HAR entry 与覆盖缺口。
文本坐标按解码后 codepoint 计；HAR 正文坐标另带 entry 的 JSON pointer，不当原始字节偏移。
截断、TLS 忽略验证、关联未知、DOM 快照作为待核来源保留；哈希吻合不证明材料真实性或目标 App 归属。
采集范围与未分析附件见 `meta.web_capture_visibility`，完整交接回执见 `meta.web_evidence.handoff`。

`intake-fetch` 调用独立的兼容 fxfetch CLI，校验已保存 ZIP 与副本哈希，将网页和原始 APK 分路离线分析，不重访来源 URL。`--fxapk` 可指定可信本机分析入口；`--timeout` 默认 600 秒、范围 1–3600，用于子进程与定向复核的共享预算（清理与报告落盘可额外耗时）。默认绑定当前 Python 的入口，离线子进程关闭设备探测；仅源码运行且没有同解释器入口时须指定 `--fxapk`。`--review-manifest` 只匹配一个已分析的原始 APK；没有清单时复核阶段明确 `not_run`。原件、各阶段日志、`intake.json` 和 `index.html` 保存在新目录；ZIP 最大 2 GiB，最多分析 8 个、各不超过 512 MiB 的原始 APK。契约见 [OFFLINE-REVIEW.md](OFFLINE-REVIEW.md)。

`evidence-review` 接收绑定输入 SHA-256 的清单，支持 `native/trace/filesystem/crypto/dex/jni/emulate/recover/acquisition`；输出逐任务回执、`review.json`、`feedback.json`、report/digest/HTML。依赖未验证时后续依赖任务 `not_run`，独立任务继续。三个新入口的终态退出码为 `0/5/6 = ok/partial/failed`；入口参数或前置读取错误退出 2。复核状态不等于 `closure` 或 Phase-2 人工接受，详细回执与日志可能含原值。macOS 无法强制内存限额的阶段明确 `unsupported/platform_memory_limit_unavailable`，不启动子进程；没有可用结果的接入或恢复链为 failed。恢复链因来源未绑定，当前有产物时最多 partial，不会以退出 0 声称恢复全贯通。

## 采集与探针记录

- `recover-runtime` 仅观察显式计划中的已运行进程；`proc_mem` 读取选定页，不采 JNI，`frida` 观察 DEX/JNI。最多 32 段、合计 32 MiB、每段 8 MiB，要求页对齐并核对进程启动标识。取得的 DEX 原字节接入 `analyze --offline --extra-dex`、方法验证和真实 JADX 子进程。重分析从报告顶层读取 `analysis_status`，后续成功不抹掉此前失败；`unpack` 请求的重分析失败时返回 error 并保留已取得 DEX。命令不安装/启动 App，不部署 Frida、不改代理或目标方法；详见 [RECOVERY-PIPELINE.md](RECOVERY-PIPELINE.md)。
- `no-proxy` 观察轮不请求 TLS 校验修改；MITM 轮与原版 `floor-only` 轮分别留档。
  OkHttp 不再次执行请求正文的 `writeTo()`，正文标为 `not_read_non_interference`；
  SQLCipher 只观察路径与密钥，不在应用连接上执行导出 SQL，标为
  `not_attempted_non_interference`。因此未读正文、未导出库不是阴性结果或导出失败。
- 探针安装、触发、丢弃和截断分别记录；Java bridge 就绪不等于各 hook 安装成功。
  缺少回执保持 unknown，未触发或未找到 API 不等于反检测，也不证明不存在相应行为。
- `probe-leads` 回灌保存原始日志字节哈希、解码文本哈希、行号及 codepoint 坐标；
  日志超过 8 MiB 或导入线索超过 10,000 条时拒绝导入，而不是静默截断后声称完整。
  内置探针事件并回以同一次读取的运行时报告字节哈希和实际数组 JSON pointer 定位，
  同值的不同 occurrence 保留。脚本/采集身份缺失不补造；哈希不证明真实性或目标 App 归属。
- HTTP `messages[].ts` 为 epoch 秒；Frida 事件的 `ts` 为毫秒，导入后的 `observed_at`
  统一为秒，`event_time_semantics` 保留生产者单位。未知通道或无效时间保持 unavailable。
  回调在脚本加载前绑定本次 spawn 的 PID 与脚本哈希；重试、加载中或迟到的事件保留原身份。
  未逐事件绑定时，PID/UID/脚本不能从最终采集摘要补齐，并记录 `process_binding_missing`。
  端点与事件共享有界读取及同一原始哈希；畸形或超限报告记 unavailable/partial，不当零发现。
- `meta.capture_safety_comparison` 对原版 PCAP 基线与探针轮作保守比较；`digest.capture_safety`
  只压缩该回执。只有同一原版 APK、前台确认、显式引导页/网络检查、匹配动作/初始状态/环境声明
  及仍可验证的检查材料都具备时才形成可比信号。状态可为 `inconclusive`、`reported_regression`、
  `baseline_failed` 或 `no_reported_regression`，均不证明因果或普遍无干扰。
  采集 done 不等于通过引导页；零流量不等于应用无网络。不会自动清数据或重置设备状态。

## 被动资源画像与批量富化

`enrich batch` 可显式选择 `--providers fofa_profile,fofa_host,daydaymap_profile`，先 dry-run 核对服务、披露范围与预算，再加 `--no-dry-run`。搜索只取有界首屏，记录已报告总量、实际返回量与覆盖状态；未知总量、缺字段和权限失败不等于"没有资产"。产品、证书和测绘时间帮助判断服务类型，不能单独确认云实例、租户或运营者。

结果按目标追加写 `enrich.ndjson`，`enrich.csv` 是重建投影。响应哈希是核对锚点，归一化字段是有界脱敏预览，不是原始响应存档。权限/额度错误及连续失败熔断后本轮其余目标标跳过。`--credential-slot 2` 支持 Quake、DayDayMap 及其画像，不自动换号。

配置 `https://fofoapi.com` 时，HTTP 200 中明确标注的“官方错误信息 [-403] 访问权限不足” <!-- leak-scan: allow public relay API hostname required for provider-specific protocol compatibility -->
记为 `failed/upstream_permission_denied`，不能据此判定本机中转 Key 无效。

服务恢复后可加 `--recover-transient`：按来源间隔调用（`--provider-interval` 默认 2 s），瞬时限流、超时或解析失败每个来源最多补试一次（`--retry-delay` 默认 15 s），Retry-After > 60 s 延后；鉴权、权限、额度错误不重试。原失败与补试分别留痕，恢复不抹除历史缺口。

Hunter 默认在搜索前读取账户免费余额并在本机账本（`~/.fxapk/hunter-quota.sqlite3`，可用 `FXAPK_HUNTER_QUOTA_DB` 指定）预留积分，同账户按 UTC+8 日期共享每日 500 积分上限；余额未知或预留失败即停。`FXAPK_HUNTER_CREDIT_MODE=free_only` 在请求前返回 `disabled / free_only_billing_unverified`。账户配置见 [.env.example](.env.example)。

- 多源富化保留查询时间、提供方原始时间字段与来源家族，不把现在的查询结果视作事件发生时的关系。
  Shodan 与 InternetDB 同属一个家族，不当两份独立佐证。调证候选分别列服务角色、所需端点/端口/
  时区时间窗/App 关联标识、要调取的账户/绑定/日志与待核问题；CDN 可先调绑定和回源配置，
  不冒充 Origin。法律渠道与历史关系仍需核实，ASN/RDAP/承载/CDN 不证明 App 运营者。
  `digest.closure.request_targets` 是有界摘要，正式判断回查完整 closure 和逐来源回执。

## JADX 索引

多索引查询默认读 cache 根的 `fxapk-jadx-index-map.json`（或 `--index-map`）。旧 1.6 索引只为建库时选定值保存 postings，`coverage=complete` 不保证新值已覆盖，查询另报 `query_coverage`。启用 `--jadx-cache-root` 的新分析会在 `query-sources` 保存有界 Java 快照供后续新值查询。快照与 `--out` 回执含受控材料，不公开提交。`callpath` 的 `name_unique` 只是简单名唯一，不证明方法绑定。`jadx compare` 的相似性不代表同一运营者。

## 语料库

所有 `corpus` 子命令须 `--corpus <库>` 或 `FXAPK_CORPUS` 指向 **git 工作树外** 的库目录。

- 报告内容可重建到 `manifest.jsonl`；人工确认的多案关联、隔离状态和入库顺序只写在非派生 `catalog.jsonl`。一个报告可绑定多个 `case_id`；普通查询默认排除 `quarantined`。旧版/开发版先 `corpus versions` 审计，再显式 `corpus quarantine-version --apply`；工具不自动删历史证据。
- rules-v2 后，旧 manifest 缺 `repack_identity_verdict` 时 `link-candidates` 返回 `status=partial` 与 `migration.next_action`，先 `fxapk corpus reindex --corpus <库>` 重算投影（不改报告字节）；重建后仍缺则该报告从未完成评估，须用当前 fxapk 重新分析，不能把"未评估"改写成 `unknown`。
- 案件级 IOC 索引只接收至少一条显式 `case_evidence` 的 `Lead.source_refs[]` / `Endpoint.evidences[]`。
- corpus 关系索引使用 `relation_index_version=evidence-admission/1`；缺少标记的历史关系保持 unknown，只有显式 `corpus reindex` 才重建索引，报告原始字节不改。证据准入按 occurrence 和用途分别评估：静态候选不代表运行时观测或业务归属。
- `corpus migrate-catalog` 把旧 `manifest.case_id` 迁到 `catalog.jsonl`：先 dry-run，再 `--apply`。**迁移不可回滚，`--apply` 前整目录备份**——`corpus restore` 恢复的 manifest 会被 catalog 立刻重新物化，手删 `catalog.jsonl` 则整库 fail-closed。
- `corpus reconcile` 默认只读列计划；`--apply` 只新增不可变报告或并入案件关联，字节冲突、隔离记录或包哈希变化非零退出。Phase 2 始终消费精确 package 哈希。

## 阶段间证据契约与四种状态

Phase 1 产生报告、附件和不可变 `case-package.json`；Phase 2 只读校验，产生独立 `case-review.json`，不得覆盖 Phase 1。建包固定三个复现锚点：64 位十六进制 `sample_sha256`、非空 `tool_version`、16 位十六进制 `ruleset_digest`，缺少或 `unknown` 占位时拒绝建包。

- `package_integrity`：manifest、路径边界和附件哈希是否一致
- `analysis`：分析器/流水线是否完整运行
- `closure`：运行时、归属与调证对象是否闭环
- `review`：精确 package 哈希是否被接受、要求修改或已失效

四者不能互相推出；报告或附件变化后旧复核显示 `stale`。`closure=complete` 要求主目标五层（运行时、资源登记、BGP 宣告、托管分发、最终归属对象）都有证据；前面套着 CDN、源站未定位的不判 complete。缓存或导出的 `complete` 声明经安全投影时，还要求每个目标至少有一条用途准入通过的运行时接触证据；这只是最小一致性校验，并不证明其余闭环条件满足或替代逐层核验。

报告 schema 1.2 起每条 Evidence 带 `scope`：`case_evidence`（当前案件直接证据）、`batch_reference`（批量/跨案参考，只辅助复核，不能升级为"建议调证"或满足 closure）、`legacy_unspecified`（旧报告迁移）。该资格闸作用于摘要、调证函、IOC、JSONL 和 HTML/PDF；`--only-investigate` 排除参考值。闭环同走安全投影：声称 `complete` 但目标清单为空按 `failed` 消费，任一目标无显式 `case_evidence` 只能按 `partial` 消费；Phase-1 建包直接拒绝虚假 `complete`。`evidence_scope` 不能用 `lead restore/replay` 撤销。

持久化 JSON 拒绝 `NaN` / `Infinity`，失败不覆盖已有报告。

### 证据来源与准入

报告 schema 1.3 的 Evidence 可携带 `provenance`、`locator`、`structure_status`、
`reference_status`、`reachability` 与 `suspicions`；仅在真实来源和坐标同时存在时输出
稳定的 `occurrence_id`。旧报告缺少这些字段时保持 unknown/空值，不补造定位。

证据准入按 occurrence 和用途分别评估：`passive_enrichment`、`lead_priority`、
`closure_candidate`、`dex_query`、`model_summary`、`corpus_relation`；判定结果为
`allowed`、`review` 或 `blocked`。某个值获准不代表同值的其他引用也获准。静态候选不等于
运行时观测，也不证明业务归属。

### 两组别混淆的字段

- `visibility`（样本内容看不看得见）vs `analysis_status`（工具跑得顺不顺）：分析器全成功与 DEX 是壳、六条结论都不能下可以同时成立。`blocked_claims` 点名哪些结论不能下，`next_actions` 说怎么补。
- `repack_identity`：`self_built` 仍须排除公共 SDK、壳与共享设施；`repack_suspected` 时继承与新增范围未定，须与官方同版本包差分。工具只说「疑似重签名」，不说「植入了什么」。

## 输出

- `out/app.html` — 单文件内部证据视图，含原值，外发前另做审核
- `out/app.json` — 完整数据；`report.meta.closure` 含验收结论、五层证据、来源覆盖、缺口与下一步
- `case-package.json` / `case-review.json` — Phase-1 包与 Phase-2 复核记录
- `--fmt pdf` 导 PDF（需本机 Chrome 或 Edge）

## 解析预算

DEX 解码预算复用既有数量、字符数和快照容量边界；这些边界本身不提供解析进程隔离，
隔离通过以下环境变量单独启用。

可选解析器进程限制通过环境变量启用：必须同时设置 `FXAPK_PARSER_TIMEOUT_SEC` 与
`FXAPK_PARSER_MEMORY_MB`；`FXAPK_PARSER_OUTPUT_MB` 可选，未设置时 IPC 输出上限为 64 MiB。
任一必需项缺失或配置无效都会失败关闭。限制按一次解析或一次隔离延迟读取分别生效，
不是整次分析的总时限，也不是原生代码沙箱。未配置时维持进程内解析，回执明确标为
`not_enforced`；默认不宣称性能收益。Linux 的内存限制是地址空间上限（RLIMIT_AS），不是
RSS 测量；Windows 使用 Job Object，其强制约束须在 Windows 平台验收；macOS 无法执行所需
内存限制时会失败关闭。
配置解析失败会在 analyze 输出目录写入独立的 `*.parser-failure.json` 回执，不生成空报告。

## 固定依赖与复现

解析归上游库管，androguard 换版本报告就可能不同。仓里 [`requirements.lock`](requirements.lock) 钉死运行时依赖：

```bash
python -m venv .venv-forensic
.venv-forensic/bin/pip install -r requirements.lock
.venv-forensic/bin/pip install --no-deps .
```

复现旧报告用当时的代码、规则和依赖锁（`meta.dependency_versions` 可核对），并保存检材哈希、参数、外部工具、缓存与原始响应。联网数据和设备状态会变化，固定依赖不保证逐字节相同。

## 从源码改代码

```bash
git config core.hooksPath .githooks
```

hook 扫 staged 新增行，默认阻断疑似真实 IP、凭据、案件人名、联系方式、二开包名、无理由及批量豁免。行内例外须写 `leak-scan:` + `allow` + 逐行理由。已有提交用 `fxapk leak-scan --base origin/master --strict` 核对整个候选 diff。测试数据优先用保留段 `192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`、`example.com`；无法用保留值触发时用 mock 或有理由的合成夹具。真实地址推上去就收不回来。

代码行为变更本地过 `python -m ruff check apkscan tests`、`python -m pyright apkscan`、`python -m pytest -q`。

## 合规边界

仅用于授权范围内的安全研究与分析，不提供攻击或漏洞利用功能。默认被动：境外服务器只做被动归属（RDAP / WHOIS / DNS / ASN / CT），不主动访问样本业务 URL，但 DNS 查询可能被观察。少数要向目标发请求的能力默认关闭，按显式授权参数启用；`capture-web` 需 `--authorized` 且只在目标与允许清单内做有界 GET。脱壳只针对样本自身，在授权分析机上进行。

## 报告前材料

```bash
fxapk case source-catalog --category all                      # 只读来源目录，不发查询
fxapk case provider-plan private/report.json --out private/provider-plan.json   # 服务商角色复核队列
fxapk case package private/demo/pkg/report.json --case-id DEMO --producer analyst --out private/demo/pkg/case-package.json
fxapk case prepare-materials private/demo --out private/demo/pre-report.json
```

`review_required`、`partial`、`failed` 均不是完成确认。三轮抓包分别留档，不跨轮拼接计数。详见 [PRE-REPORT-WORKFLOW.md](PRE-REPORT-WORKFLOW.md) 与 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 可选 Android UI 插件

`fxapk-android-ui 0.1.2` 提供 `ui capabilities` / `ui snapshot` / `ui run-plan`；设备命令显式 `--serial`，观察/计划还须 `--package` 与新的 `--out`。安装插件不会自动为 `auto`/`capture` 接入 UI 观察。截图、布局与诊断可能含原值。见 [ANDROID-UI.md](ANDROID-UI.md)。

## 可选 Flutter AOT 插件

`fxapk-flutter`（发行附件 wheel，或源码树 `python -m pip install -e ./plugins/fxapk-flutter`；要求核心 ≥1.23.0）对识别为 Flutter 的 APK 做离线 AOT 静态分析（仅 Android ARM64）。`analyze` 的 `--flutter auto`（默认）/ `off` / `required` 控制该阶段，`required` 未成功时保留报告并退出 4；`--flutter-toolchain` 指定本地 toolchain.json（缺省读 `FXAPK_FLUTTER_TOOLCHAIN` 或 `~/.fxapk/flutter/toolchain.json`）；`--flutter-timeout` 范围 1–1800 秒、默认 300，只约束单次容器运行，不是整条流水线的时限。`auto` 命令没有 Flutter 选项。缺插件或工具链时记录覆盖缺口，不自动安装。`analyze` 还会核对解析期快照与最终指纹：输入文件在分析期间被改写时，保留快照绑定的报告并以退出码 4 结束（`--flutter auto` 同样适用）。

```text
fxapk analyze sample.apk --offline --flutter auto --out analysis
fxapk analyze sample.apk --offline --flutter required --out analysis-required
fxapk flutter analyze sample.apk --out flutter-result
fxapk flutter query flutter-result --symbol UploadService.uploadContacts
fxapk flutter query flutter-result --text contacts
fxapk flutter attach flutter-result --report analysis/sample.json --out new-revision
```

`attach` 要求报告 `meta.sample_sha256` 与证据包绑定的 APK 哈希一致，输出必须是新目录；原报告字节原样保留为 `source-report.json`，不重算 lead 分级与闭环。缓存与清单哈希只证明字节一致，不证明内容真实。查询与证据包未脱敏。配置、缓存键与支持范围见 [plugins/fxapk-flutter/README.md](plugins/fxapk-flutter/README.md)。

## License

[MIT](LICENSE)
