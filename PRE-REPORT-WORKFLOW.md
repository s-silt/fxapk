# 报告前材料与服务商核验工作流

正式使用支持联网；报告前材料入口是对已产生证据的离线变换，不限制前序采集联网。Android UI 插件见 [ANDROID-UI.md](ANDROID-UI.md)。

## 在线采集与三轮动态

```bash
fxapk capture-web https://example.invalid/start --authorized --out evidence/web/capture.har
fxapk analyze-web evidence/web --online --out outputs/web-analysis
fxapk auto inputs/sample.apk --online --three-rounds --out outputs/run
```

从工作树外的专用分析目录运行；示例域名不可用。

- `capture-web` 只发 GET，同主机跳转自动跟随，额外主机须 `--allow-host`；不继承代理、netrc、浏览器登录态或 cookie；不执行 JS，不捕获全部 XHR/WebSocket 或子资源。HAR 原文是私有证据，默认过滤敏感头并记录过滤状态。
- `auto` CLI 默认三轮（`--single-round` 保留单轮；程序化 `auto.run` 需显式 `three_rounds=True`）：先脱壳重分析，再 PCAP → 通用探针 → 定向采集。`--duration` 是每轮时长，每轮封顶 1200 s。定向轮只按脱壳结果选择内置 crypto/OkHttp/JSBridge/SQLCipher 能力，不把样本代码拼成注入脚本。
- PCAP 单文件上限 256 MiB，超限明确 `resource_limit`，不静默截断。三轮目录互不覆盖，运行时文件哈希与原样本 SHA 绑定；派生端点带来源命名空间。跨轮复用实测配方解既有支持的信封报文时保留密文原件，解出的端点仍是派生证据，不升格为实连或运营者确认。

## 报告前材料入口

```bash
fxapk case provider-plan evidence/report.json --out materials/provider-plan.json
fxapk case prepare-materials cases/CASE-001 --out materials/materials.json
fxapk case prepare-materials cases/CASE-001 --coverage phase2/coverage.json --clues phase2/clues.jsonl --runs phase2/runs.jsonl --out materials/materials-reviewed.json
```

输出拒绝覆盖；`--coverage` / `--clues` 必须一起传。默认省略目标/实体原值，显式 `--evidence-values raw` 才保留；omit 仍含包标识、哈希、计数及结构关系，**不是匿名化或可公开发布保证**。命令不联网、不查付费接口、不改原报告、不生成 HTML/PDF/XLSX。退出 0 只说明材料已生成，`state=review_required` 仍须复核；`blocked` 退出 1，参数/读取/输出冲突退出 2。

## 材料目录与阶段间契约

- 代码在 Git 工作树，证据包、语料库与历史材料在工作树外；`FXAPK_CORPUS` 显式指向库目录，不把材料目录的 `.env` 复制到源码。
- `FXAPK_HANDOFF_ROOT` 指定案件材料根，`manifest_relpath` 相对此根；未配置即拒绝，不回退到仓库。
- `case phase2 ... --case-dir <案件目录>` 读直接子目录中的 `case-package.json`，以 manifest 登记的报告路径和哈希为准；指定包含 Phase1 包的那层目录，不把 `cases/` 根当一个案。旧脚本固定读 `report.json` 的地方改用新版 CLI，不重命名或覆盖不可变包。
- 旧材料缺身份或哈希仍需补证，不自动升格为已验包；旧 PASS 字样不作可复用验收。需要新验收时用单独工作副本和新产物。
- 复核签发要求同目录 `coverage.json`、`decisions.jsonl` 与回执哈希一致，跨机器一起保留。`corpus add --package` 只接受与包登记报告逐字节一致的输入。

## 服务商按角色落实

每个目标分别保留 `resource_holder`（登记持有者）、`origin_network`（BGP 起源）、`hosting_provider`（托管/交付）、`edge_provider`（CDN/反代）、`service_operator`（实际运营方）。服务商计划只把已有结果投影成核验任务，所有角色 `verified=false`。ASN、地址登记、ICP、共用 IP、相同证书、家族关联都不能单独证明运营者；同一域名的不同 IP 可由不同服务商承载，保留资源和时间范围，不用多数票消解。

FOFA 多个 API 视图归同一来源族，Shodan/InternetDB 亦然；不同来源族也未必独立，`independence_verified` 始终 false。`hit/no_record/failed/skipped/disabled` 保留不同下一步；鉴权、权限、配额、限流故障不得当成"无记录"。

补能力顺序：①登记与路由（RDAP、BGP 观测）②交付与边缘（DNS/CNAME、证书、HTTP/TLS 指纹、被动资产）③历史时点（观测、查询、案件时间分开，当前数据不回填历史结论）④运营主体（有授权的第一方材料与人工核验，留下对象、证据引用、复核人和日期）。外部查询会暴露目标；私有样本、带令牌 URL、账户材料不可自动上传。

## 阶段二边界

- 可选 RunRecord JSONL 至少含 `case_id`、`run_id`、`run_type`；父链缺失/环/重复 ID 拒绝。原始运行附件未核验时 `artifact_provenance_verified=false`。
- 动态质量复用"同一目标端点双向载荷"门：单向流量、他人双向流量、modified-runtime、APK 身份不确定不会被提升为完整。
- 全案目标最多 200（超限标 `truncated`）；默认每案最多建议 32 次新查询，其余 `deferred_query_budget`（不是金额额度，清单不自行发请求）。家族自动复核限 2–100 个包，更大案件标 `deferred_resource_budget`。历史声明冲突只标为待核对，不据此指认矛盾或运营者。

## Survey 输入完整性契约

`fxapk case phase2 gate --survey inputs/survey.json` 有界读取并校验端点、IP 和观察状态。旧式 `endpoints` 清单仍可提供 G9 正向连接证据但保持 `unassessed`，不能据空列表删除 G10 未核验声明。

| 字段 | 契约 |
| --- | --- |
| `schema_version` | `phase2-survey/1.0` |
| `case_id` / `inventory_fingerprint` | 当前已验证案件与证据清单的精确身份 |
| `status` / `truncated` | `complete` / `partial` / `unassessed`；显式布尔截断标记 |
| `endpoints` | `ip` 与非空 `observations`（`established`、`established_then_reset`、`syn_only`） |
| `capture_bindings` | `package_id`、`sample_sha256`、`artifact_path`、`sha256`；须精确匹配不可变包登记的 PCAP/PCAPNG |

只有 `complete` 且未截断、覆盖全部包的全部登记抓包、每包至少一份，才去除 G10。默认限制 8 MiB、JSON 深度 32、端点 10 万、总观察 25 万；超限不当成空结果。门禁把实际判读的原始字节原子留为 `phase2/survey.json`，回执记录哈希与 assessment；复核时快照须字节一致。这些检查证明输入身份与声明一致，不重新解析 PCAP，不证明生成方找到了所有连接；gate PASS 不是端点归属或案件闭环证明。

## 验证范围

测试使用合成数据，没有真实 APK、设备或第三方账户实测；Python 层的测试外网保护不能替代操作系统网络隔离。历史标签的 CI 与发行物见 GitHub Actions 与 Releases；后续提交以自身 CI 为准。新增数据源前核对实际套餐、许可和可用历史跨度。
