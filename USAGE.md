# fxapk 命令与数据约定

[返回项目首页](README.md) · [English](USAGE.en.md)

完整参数 `fxapk --help`；`fxapk` 未装成命令时用 `python -m apkscan.cli`。

## 命令表

| 想干什么 | 命令 |
|---|---|
| 分析一个 APK（**默认联网**查归属） | `fxapk analyze app.apk --out out`；不联网加 `--offline` |
| 授权联网留存 HTTP 跳转与响应（不执行 JS） | `fxapk capture-web https://example.invalid/start --authorized --out private/capture.har` |
| 分析存下来的 HTML/JS/HAR（默认离线） | `fxapk analyze-web <目录> --out out`；`--online` 只开归属富化 |
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
| 识别线（只读/离线；晋级门未过退出码 4） | `fxapk recognize reanalysis` / `labels validate` / `split build\|validate` / `evaluate` |

## 被动资源画像与批量富化

`enrich batch` 可显式选择 `--providers fofa_profile,fofa_host,daydaymap_profile`，先 dry-run 核对服务、披露范围与预算，再加 `--no-dry-run`。搜索只取有界首屏，记录已报告总量、实际返回量与覆盖状态；未知总量、缺字段和权限失败不等于"没有资产"。产品、证书和测绘时间帮助判断服务类型，不能单独确认云实例、租户或运营者。

结果按目标追加写 `enrich.ndjson`，`enrich.csv` 是重建投影。响应哈希是核对锚点，归一化字段是有界脱敏预览，不是原始响应存档。权限/额度错误及连续失败熔断后本轮其余目标标跳过。`--credential-slot 2` 支持 Quake、DayDayMap 及其画像，不自动换号。

配置 `https://fofoapi.com` 时，HTTP 200 中明确标注的“官方错误信息 [-403] 访问权限不足” <!-- leak-scan: allow public relay API hostname required for provider-specific protocol compatibility -->
记为 `failed/upstream_permission_denied`，不能据此判定本机中转 Key 无效。

服务恢复后可加 `--recover-transient`：按来源间隔调用（`--provider-interval` 默认 2 s），瞬时限流、超时或解析失败每个来源最多补试一次（`--retry-delay` 默认 15 s），Retry-After > 60 s 延后；鉴权、权限、额度错误不重试。原失败与补试分别留痕，恢复不抹除历史缺口。

Hunter 默认在搜索前读取账户免费余额并在本机账本（`~/.fxapk/hunter-quota.sqlite3`，可用 `FXAPK_HUNTER_QUOTA_DB` 指定）预留积分，同账户按 UTC+8 日期共享每日 500 积分上限；余额未知或预留失败即停。`FXAPK_HUNTER_CREDIT_MODE=free_only` 在请求前返回 `disabled / free_only_billing_unverified`。账户配置见 [.env.example](.env.example)。

## JADX 索引

多索引查询默认读 cache 根的 `fxapk-jadx-index-map.json`（或 `--index-map`）。旧 1.6 索引只为建库时选定值保存 postings，`coverage=complete` 不保证新值已覆盖，查询另报 `query_coverage`。启用 `--jadx-cache-root` 的新分析会在 `query-sources` 保存有界 Java 快照供后续新值查询。快照与 `--out` 回执含受控材料，不公开提交。`callpath` 的 `name_unique` 只是简单名唯一，不证明方法绑定。`jadx compare` 的相似性不代表同一运营者。

## 语料库

所有 `corpus` 子命令须 `--corpus <库>` 或 `FXAPK_CORPUS` 指向 **git 工作树外** 的库目录。

- 报告内容可重建到 `manifest.jsonl`；人工确认的多案关联、隔离状态和入库顺序只写在非派生 `catalog.jsonl`。一个报告可绑定多个 `case_id`；普通查询默认排除 `quarantined`。旧版/开发版先 `corpus versions` 审计，再显式 `corpus quarantine-version --apply`；工具不自动删历史证据。
- rules-v2 后，旧 manifest 缺 `repack_identity_verdict` 时 `link-candidates` 返回 `status=partial` 与 `migration.next_action`，先 `fxapk corpus reindex --corpus <库>` 重算投影（不改报告字节）；重建后仍缺则该报告从未完成评估，须用当前 fxapk 重新分析，不能把"未评估"改写成 `unknown`。
- 案件级 IOC 索引只接收至少一条显式 `case_evidence` 的 `Lead.source_refs[]` / `Endpoint.evidences[]`。
- `corpus migrate-catalog` 把旧 `manifest.case_id` 迁到 `catalog.jsonl`：先 dry-run，再 `--apply`。**迁移不可回滚，`--apply` 前整目录备份**——`corpus restore` 恢复的 manifest 会被 catalog 立刻重新物化，手删 `catalog.jsonl` 则整库 fail-closed。
- `corpus reconcile` 默认只读列计划；`--apply` 只新增不可变报告或并入案件关联，字节冲突、隔离记录或包哈希变化非零退出。Phase 2 始终消费精确 package 哈希。

## 阶段间证据契约与四种状态

Phase 1 产生报告、附件和不可变 `case-package.json`；Phase 2 只读校验，产生独立 `case-review.json`，不得覆盖 Phase 1。建包固定三个复现锚点：64 位十六进制 `sample_sha256`、非空 `tool_version`、16 位十六进制 `ruleset_digest`，缺少或 `unknown` 占位时拒绝建包。

- `package_integrity`：manifest、路径边界和附件哈希是否一致
- `analysis`：分析器/流水线是否完整运行
- `closure`：运行时、归属与调证对象是否闭环
- `review`：精确 package 哈希是否被接受、要求修改或已失效

四者不能互相推出；报告或附件变化后旧复核显示 `stale`。`closure=complete` 要求主目标五层（运行时、资源登记、BGP 宣告、托管分发、最终归属对象）都有证据；前面套着 CDN、源站未定位的不判 complete。

报告 schema 1.2 起每条 Evidence 带 `scope`：`case_evidence`（当前案件直接证据）、`batch_reference`（批量/跨案参考，只辅助复核，不能升级为"建议调证"或满足 closure）、`legacy_unspecified`（旧报告迁移）。该资格闸作用于摘要、调证函、IOC、JSONL 和 HTML/PDF；`--only-investigate` 排除参考值。闭环同走安全投影：声称 `complete` 但目标清单为空按 `failed` 消费，任一目标无显式 `case_evidence` 只能按 `partial` 消费；Phase-1 建包直接拒绝虚假 `complete`。`evidence_scope` 不能用 `lead restore/replay` 撤销。

持久化 JSON 拒绝 `NaN` / `Infinity`，失败不覆盖已有报告。

### 两组别混淆的字段

- `visibility`（样本内容看不看得见）vs `analysis_status`（工具跑得顺不顺）：分析器全成功与 DEX 是壳、六条结论都不能下可以同时成立。`blocked_claims` 点名哪些结论不能下，`next_actions` 说怎么补。
- `repack_identity`：`self_built` 仍须排除公共 SDK、壳与共享设施；`repack_suspected` 时继承与新增范围未定，须与官方同版本包差分。工具只说「疑似重签名」，不说「植入了什么」。

## 输出

- `out/app.html` — 单文件内部证据视图，含原值，外发前另做审核
- `out/app.json` — 完整数据；`report.meta.closure` 含验收结论、五层证据、来源覆盖、缺口与下一步
- `case-package.json` / `case-review.json` — Phase-1 包与 Phase-2 复核记录
- `--fmt pdf` 导 PDF（需本机 Chrome 或 Edge）

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

`fxapk-android-ui 0.1.1` 提供 `ui capabilities` / `ui snapshot` / `ui run-plan`；设备命令显式 `--serial`，观察/计划还须 `--package` 与新的 `--out`。安装插件不会自动为 `auto`/`capture` 接入 UI 观察。截图、布局与诊断可能含原值。见 [ANDROID-UI.md](ANDROID-UI.md)。

## License

[MIT](LICENSE)
