# 报告前材料与服务商核验工作流

本文对应 1.18.0：阶段二通用入口沿用 origin-check、响应证据与富化覆盖能力，并收紧 Survey 完整性与材料绑定。Android UI 的独立命令、安装与轮内接入边界见 [Android UI 指南](ANDROID-UI.md)。
正式使用支持联网；下面的报告前材料入口是对已产生证据的离线变换，不限制前序采集联网。

## 在线采集与三轮动态流程

    fxapk capture-web https://example.invalid/start --authorized --out evidence/web/capture.har
    fxapk analyze-web evidence/web --online --out outputs/web-analysis
    fxapk auto inputs/sample.apk --online --three-rounds --out outputs/run

示例从代码工作树外的专用分析目录运行，输入与输出使用相对路径。
示例域名不可用，执行时替换为有授权的目标。capture-web 只发 GET，同主机跳转自动跟随，
额外主机须 --allow-host 明确列出；DNS 解析仍受操作系统解析器时限影响；不继承代理、netrc、浏览器登录态或 cookie。复用主线的
公共 IP 校验、IP 钉定、TLS 验证和响应读取总截止机制；次数/体积有界。它不执行 JS，
不捕获全部 XHR/WebSocket 或页面子资源。此类浏览器流量可导出 HAR 后进入 analyze-web。
HAR 原文是私有证据；默认过滤敏感头，过滤状态和缺口写入采集记录，不能当完整浏览器导出。

auto 的 CLI 默认三轮，--single-round 可保留旧单轮；程序化 auto.run 为兼容保留旧默认，
需显式 three_rounds=True。先脱壳重分析，再 PCAP→通用探针→定向采集；--duration 是每轮时长，
每轮封顶 1200 秒。定向轮只按脱壳结果选择内置 crypto/OkHttp/JSBridge/SQLCipher 能力，
不把样本代码或任意路径拼成注入脚本。没有脱壳结果或受支持线索时明确 skipped。
原有设备/行为修改授权边界继续有效；这些命令会影响专用测试机，实际运行前应确认范围。

PCAP 单文件默认上限 256 MiB，超限明确 resource_limit，需先拆分；不会静默截断后宣称完整。
三轮目录互不覆盖，运行时文件哈希与原样本 SHA 绑定；派生端点带来源命名空间，
避免两轮同名 flow 被错误去重。符合原版样本身份、包名、variant 与哈希检查时，
支持跨轮复用实测配方解既有支持的信封报文。保留密文原件，解出的端点仍是派生证据，
不升格为实连或运营者确认。未知算法、缺密钥、不同样本和行为修改轮不混用。

## 报告前材料入口

单份 Phase1 report.json，生成服务商角色核验清单：

    fxapk case provider-plan evidence/report.json --out materials/provider-plan.json

一个包含已登记 case-package.json 的案件目录，串联包完整性、各阶段材料、
家族候选、阶段二覆盖及可选运行历史：

    fxapk case prepare-materials cases/CASE-001 --out materials/materials.json
    fxapk case prepare-materials cases/CASE-001 --coverage phase2/coverage.json --clues phase2/clues.jsonl --runs phase2/runs.jsonl --out materials/materials-reviewed.json

请使用代码工作树外的受控分析目录；示例路径不是实际文件。输出拒绝覆盖。coverage/clues
必须一起传入。默认省略目标/实体原值，显式 --evidence-values raw 才保留相应原值。
omit 仍包含证据包标识、内容哈希、计数及结构关系，**不是完全匿名化或可公开发布保证**。

命令不联网、不查询付费接口、不修改原报告、不生成 HTML/PDF/XLSX。
成功退出只说明材料已生成，state=review_required 仍须复核；blocked 输出后退出 1，
参数、读取或输出冲突退出 2。不要把退出 0 当作服务商确认或结案 PASS。

## 材料目录与阶段间数据契约

代码保存在 Git 工作树，证据包、语料库与历史材料保存在工作树外的案件材料目录。
`FXAPK_CORPUS` 显式指向库目录；不要把证据目录当作源码根，也不要将材料目录中的
`.env` 复制到源码或提交配置值。外部集成的本地配置与公共 CLI 的证据契约分别维护。

来源绑定沿用现有环境变量 `FXAPK_HANDOFF_ROOT` 指定案件材料根，
`manifest_relpath` 相对此根；未配置即拒绝，不回退到仓库或猜测目录。
这是兼容接口名，不要求目录使用同名，也不绑定特定存储服务。

新版 `case phase2 ... --case-dir <案件目录>` 读取直接子目录中的 `case-package.json`，
以 manifest 登记的报告路径和哈希为准，支持中文、空格及换盘后的相对路径。
应指定包含 Phase1 包的那层目录，不把材料根或包含多个案件的 `cases/` 当作一个案。
历史 `run.json` / `manifest.json` / `READY` 保留原有读取约定，不冒充 Phase1 包。

旧版外部集成脚本保持原样。其 Phase2 triage 仍有固定 `report.json` 的读取约定；
manifest 登记其他文件名时应使用新版 `fxapk case phase2`，不要为迁就旧脚本重命名或
覆盖不可变包。现行 Phase1 1.0 包与候选标识保持兼容，但缺失身份或哈希的旧材料仍需补证，
不会自动升格为已验包。已有 Phase2 判决、清单及回执继续留存；新版门禁不把旧 PASS 字样
当作可复用验收。需要新验收时使用单独的工作副本和新产物，不覆盖历史记录。

复核签发要求同目录的 `coverage.json`、`decisions.jsonl` 与回执哈希一致；跨机器传递时
必须一起保留。`corpus add --package` 只接受与包登记报告逐字节一致的输入，允许内容相同的
异地副本，不允许用包 A 给报告 B 补挂身份。设备操作和真实第三方查询仍需对应授权。

## 服务商要按角色落实

每个目标分别保留：
- resource_holder：资源登记持有者
- origin_network：BGP 起源网络
- hosting_provider：托管/交付提供方
- edge_provider：CDN、反代等边缘提供方
- service_operator：实际业务运营方

服务商计划把已有结果投影成核验任务，所有角色仍为 verified=false。
ASN、地址登记、ICP、共用 IP、相同证书、家族关联都不能单独证明业务运营者。
同一域名的不同 IP 可以由不同服务商承载；需保留资源和时间范围，
不能用多数票自动消解。服务商确定需要对应角色的证据和明确复核记录。

FOFA 的多个 API 视图归为同一来源族；Shodan/InternetDB 等亦如此。
不同来源族也未必独立，independence_verified 始终为 false。
hit/no_record/failed/skipped/disabled 保留不同下一步；鉴权、权限、配额、
限流故障不得被当成“无记录”，不会自动重试。

## 优先补哪些能力

已有结果先用，缺什么再查：
1. 登记与路由：RDAP/权威登记、BGP 观测，分别核对持有者和网络
2. 交付与边缘：DNS/CNAME、证书、HTTP/TLS 指纹、被动资产观测交叉核对
3. 历史时点：将观测时间、查询时间、案件相关时间分开；当前数据不能回填历史结论
4. 运营主体：有授权的第一方材料、服务关系与人工核验；留下对象、证据引用、复核人和日期

新增付费源前比较缺口覆盖、来源重合、历史留存、接口权限和单案预算。
外部查询会暴露目标；私有样本、带令牌 URL、账户材料不可自动上传。
这些是接入和复核要求；本次没有新增付费账户、实际查询或自动身份确认。

## 阶段二兼容与边界

阶段二入口采用经脱敏审查的通用声明契约，覆盖已登记证据包及其复核材料。
沿用已有包、coverage、clue 五元组来源绑定与家族规则引擎。
可选 RunRecord JSONL 至少含 case_id、run_id、run_type，可含 parent_run_id、
status、source_statuses、closure；逐次失败记录保留，父链缺失/环/重复 ID 拒绝。
原始运行附件尚未核验时 artifact_provenance_verified=false。

动态质量复用已有“同一目标端点双向载荷”质量门：
单向流量、他人双向流量、modified-runtime、APK 身份不确定不会被这一新入口提升为完整。
质量状态仍只是现有材料的计算结果，不代表原始抓包来源已重新验证。

全案目标最多 200，超限明确标记 truncated；逐目标/来源合并重复角色任务，
默认每案最多建议 32 次新查询，其余 deferred_query_budget；该计数不是金额额度，
核验工作清单不会自行发请求。每个选中目标绑定原证据 candidate_id、作用域与阶段，
同 host 匹配只作查阅导航，不证明同一次连接。家族自动复核限 2–100 个包，
更大案件标记 deferred_resource_budget，不把抽样图当全案完成。
历史声明冲突仅标为待核对资源/时间范围，不能直接据此指认矛盾或运营者。

## 验证与使用限制

历史集成提交已通过本地 Ruff、Pyright、7330 项测试（14 项跳过）及跨平台 CI；旧版流程
的 161 项兼容测试通过。这些是集成时的执行记录，不能代替当前候选的 CI。
1.17.0 的 [发布候选 CI](https://github.com/s-silt/fxapk/actions/runs/37006902961) 与
[发行构建](https://github.com/s-silt/fxapk/actions/runs/37007666701) 已通过；
[Release](https://github.com/s-silt/fxapk/releases/tag/v1.17.0) 提供安装包及校验和。
1.18.0 标签对应提交的[跨平台 CI](https://github.com/s-silt/fxapk/actions/runs/37750331718)
与[发行构建](https://github.com/s-silt/fxapk/actions/runs/37751235930)已通过；
[v1.18.0 Release](https://github.com/s-silt/fxapk/releases/tag/v1.18.0) 提供核心 1.18.0、
独立 UI 插件 0.1.0 的四个归档与 `SHA256SUMS.txt`。已核对发布附件哈希、包元数据、
源码与标签一致性，并在临时环境安装自有 wheel 检查帮助与插件发现。
这些是该标签及发行物的执行记录；后续文档提交以自身 CI 为准。
测试使用合成数据，没有真实 APK、设备或第三方账户实测；目录迁移回归不等于真实跨盘或
文件同步冲突验收。Python 层的测试外网保护不能替代操作系统网络隔离。

## 设计参考

- gpt-load：https://github.com/tbphp/gpt-load
  借鉴调度与执行分离、有界准入的思路，未复制其 Go 实现；单阶段与两阶段富化
  均限制在途 Future 数为 2×workers，保留逐端点门控、阶段顺序和原有逐源失败回执
- 原项目：https://github.com/s-silt/fxapk
  比较参考的 master 提交为 a9fda4969d5139bf5fcbd45b093a122489fff721
- ARIN RDAP：https://www.arin.net/resources/registry/whois/rdap/ <!-- leak-scan: allow ARIN 官方公开登记文档，非案件目标 -->
- RIPE RIS 路由历史：https://data.stat.ripe.net/docs/data-api/api-endpoints/routing-history
- Censys 历史数据：https://docs.censys.com/docs/platform-historical-data <!-- leak-scan: allow Censys 官方公开功能文档，非案件目标 -->

后续接入应先核对相应服务的实际套餐、许可和可用历史跨度；本次未购买或开通。


## Survey 输入完整性契约

`fxapk case phase2 gate --survey inputs/survey.json` 有界读取输入，先校验端点、IP 和观察状态。合法旧式 `endpoints` 清单仍可提供 G9 正向连接证据，但保持 `unassessed`，不能据空列表删除 G10 的未核验声明。畸形输入、未知版本、错误案件/清单/样本/抓包绑定须报材料错误。

新契约为 `phase2-survey/1.0`，字段如下：

| 字段 | 契约 |
| --- | --- |
| `schema_version` | `phase2-survey/1.0` |
| `case_id` / `inventory_fingerprint` | 当前已验证案件与证据清单的精确身份 |
| `status` / `truncated` | `complete`、`partial` 或 `unassessed`；显式布尔截断标记 |
| `endpoints` | `ip` 与非空 `observations` 数组；新版本支持 `established`、`established_then_reset`、`syn_only` |
| `capture_bindings` | 每项包含 `package_id`、`sample_sha256`、`artifact_path`、`sha256`；须精确匹配不可变包登记的 case-evidence PCAP/PCAPNG |

只有 `complete` 且未截断、覆盖当前全部包的全部登记抓包、每包至少一份抓包，才去除 G10。`partial` 和截断结果仍保留声明，已发现的 established 连接继续参与 G9。默认限制为 8 MiB、JSON 深度32、端点10万、总观察25万；超限不会当成空结果。

门禁将实际判读的原始字节原子留为 `phase2/survey.json`，回执记录其哈希和 assessment。复核时快照必须仍在且字节一致；迁移材料须连同 coverage、decisions、survey 与 gate receipt 一起保留。旧式无 survey 的历史回执继续兼容。

这些检查证明输入身份、登记范围与生成方完整性声明一致，不会重新解析 PCAP，也不证明生成方确已找到所有连接。未登记抓包、未知观察语义、解析器覆盖不足和真实流量缺口应继续单列；不得把 gate PASS 当成端点归属或案件闭环证明。
