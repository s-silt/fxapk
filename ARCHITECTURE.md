# 分层与兼容边界

本文描述分层、运行契约和兼容边界。修改特殊分支前先读历史、注释与回归，不能仅以"重复"为由删除已有保护。

## 依赖方向

1. `core/models`、`source_status`、`json_contract`、`json_io`：共享结构、有限 JSON、大小/深度边界
2. `analyzers`、`dynamic`、`enrichers`：各自采集；采集层不得依赖 Phase2 或 CLI
3. `core/enrichment`、`enrichment_budget`：执行准入、有界并发、逐来源状态；失败不等于无记录
4. `core/closure`、`provider_review`：证据层与服务商角色核验；资源持有者、BGP、承载、CDN、运营主体不混同
5. `core/phase2`：不可变包清单、覆盖审计、运行历史、冲突复核、报告前材料组合
6. `commands`：参数和输出适配；报告渲染不反向决定证据是否成立
7. `plugins/`：可选插件经 `fxapk.plugins` 入口白名单加载（`android_ui`、`rea`）；`fxapk-asc` 不走 registry，由 `dex_query` 发现后以 `python -I -m fxapk_asc.worker` 隔离进程调用。坏插件不得拖垮核心命令；REA 另需 `FXAPK_ENABLE_REA=1`

层级 AST 守卫覆盖采集层反向依赖。`run_review` 是纯数据审阅，`preparation` 负责组合；`json_io` 不接受证据身份、不做包 PASS，哈希核验由证据层负责。

## 富化执行

- `case source-catalog` 返回带核验日期的产品目录，不读密钥、不验证套餐、不执行查询。
- `case close --max-source-calls 32` 是运行级预算，单位是"富化器调用"，不是 HTTP 子请求、服务商积分或跨进程账户日额度；主目标与其解析 IP 共用，失败仍消耗。
- `FXAPK_HTTP_RATE_LIMITS` 在有界 HTTP 客户端前做可选准入；同一 group 的多个 origin 共享滚动窗口、在途数与 429 冷却。只约束单进程内置客户端，不是账户全局保证。拒绝 requests 隐式跟随重定向；等待上限 60 s，Retry-After 超出则暂停。
- FOFA 沿用 `FXAPK_FOFA_URL`（HTTPS 基址或完整端点），禁止 URL 内嵌凭据、禁止降到 HTTP、不跟随跨地址重定向发送密钥；第三方中转是另一数据接收方，配置前须确认允许向它提供目标标识。传统 11 列与增强画像分别记录，同属一个来源。
- Hunter：默认先读账户免费余额并在本机账本预留（每日 500 积分，UTC+8）；`free_only` 模式因服务端控制未核实而在请求前返回 `disabled / free_only_billing_unverified`。不借第三方 SDK 字段推断余额，不多账号绕配额。
- 不变量：一个来源的失败、无记录或权限不足不能被另一来源的成功抹掉；非法状态值只记该来源失败；本轮预算拒绝不沿用旧 hit。

## 动态与 AI 辅助

流程：静态 → 脱壳及重新分析 → PCAP → 通用探针 → 定向采集 → 合并/支持的解密。CLI 默认三轮，`--single-round` 保留单轮；程序化 `auto.run` 需显式开启三轮。三轮观察不等于三次行为修改授权。

- 逐轮保留采集、合并、身份、质量及工件哈希；质量投影只选一个完整观测，不把不同轮次的归属、单向载荷和双向计数拼成完整证明。
- 端点运行时信息按捕获标识保留，每次只投影一个有同轮证据支撑的原始观测；派生证据在去重前带入轮次坐标。
- 第一轮 PCAP 不要求故意未启动的 Frida；后轮失败不替换原始基线。未知身份、坏清单、缺失样本绑定及重复工件不得凭状态汇总获得 complete。
- `capture_adaptation` 为 AI/人工提供有限信号与缺口；建议选择器只接受证据支持的内置观察器 ID，不接受脚本、shell 或外部地址。反调试、证书绑定、native 自定义协议及坏 DEX 都可能留下未解决缺口。
- 可选 UI 插件的独立命令不自动接入 `auto`/`capture`；程序化接入需显式传入插件、三轮选项与固定设备。UI 截图与布局不在 digest 脱敏范围内。

## 公共名称与真实连接目标

域名的排除理由不能自动扩散到连接 IP：公共域名可被排除，独立承载 IP 仍进入自己的研判与富化路径。SNI/Host 是客户端声明，DNS、证书、代理、CDN、NAT 和抓包位置都可能影响对应关系；不一致应保留并按同连接、同时间、同采集来源复核。

## 材料契约

- HAR 正文以有界共享输入进入配置、重定向与请求配方分析，保留条目、正文哈希及截断信息，不执行 JavaScript；部分正文不能提升为完整页面或连接证据。
- 阶段二 Survey 区分旧式 `unassessed` 与绑定完整的 `phase2-survey/1.0`，字段与资源限制见 [PRE-REPORT-WORKFLOW.md](PRE-REPORT-WORKFLOW.md#survey-输入完整性契约)。
- 网页观察（REA / CDP trace）、DEX 查询回执、native 恢复各自保留原件、哈希与 JSON Pointer；静态线索、xref 和网页候选不晋级为运行时观察。

## 验收状态

测试在 HTTP 目标层拒绝外网；wheel 校验用隔离解释器；发布标签须与产物版本一致。完整 CI、公开推送和真机增量验收是独立状态，不以局部通过代替。

以下边界不能用代码测试宣称完成：厂商加固均可脱壳、所有密文可解、所有网址可执行 JS、服务端账户全局积分上限、Hunter 免费积分防付费扣款、第三方中转全部兼容、真实 Android WebView 同窗口采集、Linux 上 Ghidra 分析抽出的 ELF，以及真实主体调证落实。代码发布不变更用户账户或设备权限。
