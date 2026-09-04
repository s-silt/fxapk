# Changelog

Notable changes to fxapk. Versioning is semantic; **behavior changes that
affect automated / CI / agent callers are called out explicitly**.

## 1.12.0 — 2026-09-04

本版收紧证据语义并给普通 analyze 的联网富化加上不可绕过的预算硬门：任何画像信号都不再
自动升级为承载/运营结论，高基数集合整轮零联网并留完整审计账本。

### Added

- 普通 analyze 富化预算门：候选总数默认 32、纯静态 IP 默认 16，绝对硬顶 200/100（CLI 与
  程序化调用一致）；超限整轮零联网并写 `meta.enrichment_plan`（`deferred_high_cardinality`，
  含逐供应商 selected/deferred 与 estimated 估算）；`--enrichment-dry-run` 只出计划不发请求；
  HAPI/ICP 每轮单源 20 条预算，缺 key 记 `disabled/credential_not_configured` 不占预算。
- 五态统计（hit/no_record/failed/skipped/disabled）分离计数：`no_record` 不再计入失败，
  `completed_with_gaps` 只由真实 failed 触发；digest 投影 `enrichment` 审计段与 meta 一致。
- CloudFront 默认分发域与自定义域 CNAME 的五层归因，保留 Distribution 检索键；未取得
  Origin 时闭环保持 `partial`。
- `overseas_targets` 明确为 Shodan/CT 已画像投影，新增候选总数/已画像/未画像三计数
  （`overseas_candidate_total` / `overseas_unprofiled_hosts`），零画像不再被误读为零候选。
- Shodan HTTP 白名单头与 Cookie 名解析（不保存 Cookie 值）；补 RIPEstat `asn_holder` 回退。
- 公共入口级对抗回归：CDN 画像不得成为承载商或调证对象、ISO 辖区白名单、批量硬顶
  fail-closed、pipeline→digest 审计一致性等。

### Changed

- **CDN/边缘画像降级为候选证据**：Shodan 的 org/product/banner 只作为 `edge_candidates`，
  不再直接完成 hosting 层或进入调证对象；ASN 缺失 + BGP/RDAP 完整 + CDN 画像的组合不再
  产生 `complete` 闭环。
- **辖区判定改用完整 ISO alpha-2 白名单**：损坏或虚构的国家串（如无法识别的值）保持
  `unknown`，不再猜测为境外。
- 共享签名、原生库、构建环境、配置对象、favicon 与技术栈统一降为待复核关联候选，
  不自动形成主体或并案结论。
- Shodan 仅在 case close 有界目标集或受硬顶保护的批量入口执行；普通 analyze 明确记
  `deferred_case_close`。
- AGENTS.md 与 .env.example 的披露表述与实现对齐（analyze 默认联网的第三方披露边界、
  auto 旁路双门、Shodan 候选能力）。

## 1.11.0 — 2026-08-31

本版强化异常 APK 的 JADX/DEX 可见性与资源边界：对可安全证明为误置 encrypted bit 的顶层
DEX 继续物化，对无效 Manifest 做显式降级而非丢弃全部静态上下文，并将每一处降级状态贯穿到
机器可读的 visibility、运行时合并与后续重分析规划。

### Added

- 新增 DEX 物化的单文件、总字节与数量预算，并按实际解压产出跨条目累计；中央目录低报大小、
  真加密、CRC 损坏、重复核心成员和 zip bomb 继续 fail-closed。
- 新增无效 Manifest 的 `apk_validation_ok=False` 机器状态及正式 `manifest` 可见性来源；
  closure 重算与运行时合并后仍保留该盲区，不再把 Manifest/组件面的「未发现」呈现成完整结论。
- 新增真 ZipCrypto/CRC 损坏反例、pipeline 传播桥、重复结构发布门和预算常量同步等回归锁；
  关键闸门均做突变验证。

### Changed

- `androguard.is_valid_APK()` 失败时，保留可读取的 DEX/JADX 上下文继续分析；报告和 visibility
  明确标记 Manifest、包名、组件和权限面不可信。
- JADX 扫描层遇到相同 `(class name, path)` 的重复声明时保留首条并将 coverage 降为 `partial`；
  存储/加载层对外部注入或损坏索引中的重复结构仍拒绝发布。
- 顶层 `classes*.dex` 的 ZIP encrypted bit 兼容仅在成员白名单与有界物化路径内生效；
  真加密和完整性异常保持稳定错误分类。

## 1.10.1 — 2026-08-26

本版收口 `1.10.0` 之后的安全与运维修复，重点是**不让外部服务的错误信息、子进程输出与
文件写入路径越过公开边界，同时保持富化失败可分类、可重试**。

### Added

- 归属富化接入 RIPEstat 的 routing-history / whois / abuse-contact 三个 data call，
  以及 Spamhaus DROP 清单（整表缓存 + 最长前缀匹配）。

### Fixed

- 富化器对外只写稳定错误分类码，不再把 provider URL、查询参数、响应正文或代理信息带入
  `report.json` / `enricher_status`；原始异常仅保留在受控日志的安全诊断中。
- 统一 ASN、证书、ICP、IP-RDAP、Spamhaus、WHOIS、DNS 与多源富化的错误分类逻辑，区分
  HTTP 状态、超时、响应错误、请求编码错误、解析错误、无记录与输入无效。共享分类器
  `safe_error_type()` 同时覆盖 `requests.Timeout` 与内置 `TimeoutError`。
- WHOIS 数据文件缺失改为固定码 `data_unavailable`，本次运行后续域名继续短路且不再触网；
  删除按首行截断异常消息的旧实现——截断不构成脱敏。
- DNS 的 DoH 与系统解析器双失败改为固定码 `dns_resolution_failed`，不再回显解析器异常
  文本；DoH 已返回被拒答案（Fake-IP／私网）时仍按有效观测处理，不误判为"域名不存在"。
- 重打包链路的 zipalign、apksigner 重签与验签、keytool 生成调试密钥库四处不再把子进程
  输出尾部拼进对外结果；不可信子进程输出可能包含敏感诊断信息，原始输出改走仅证据日志
  （默认终端不接收），对外只保留固定文案与返回码。
- 修复畸形脚本结束标签导致的网页内联配置漏检、真机全局代理影响设备联网，以及证据／临时
  文件权限依赖主机 `umask` 的问题。

### Changed

- 终端日志被明确为公开边界：带 traceback 的记录只输出固定文案，异常消息、异常链与注记
  不再渲染到终端；原始证据改由仅证据通道承载。
- 领域校验错误改用封闭错误码与固定文案，构造器只接受枚举值，公开文案由错误码重新生成，
  不受异常参数事后改写影响。
- 静态守卫覆盖范围扩至 WHOIS、DNS 两个富化器，并加强检测：覆盖 `logger.exception`、
  关键字参数与 f-string 内的子进程输出变量；`repr()` 移出安全出口白名单；仅按完整访问
  形态放行 `diagnostic_code`、`public_message`、`code` 等稳定属性。
- 判定主机身份的测试断言统一改为解析后比对 hostname 与 path，不再使用子串匹配。
- CI 的 `GITHUB_TOKEN` 权限收敛到最小范围。

## 1.10.0 — 2026-08-24

本版只做一件事：**堵住「状态沉默」**（PR #51–#58）。

一次跨全链路的只读审计发现，同一份事实经过 `analyzer → meta → visibility → closure →
digest/HTML/letters` 时缺少统一的「覆盖度、失败态、身份、来源」状态协议，于是多个出口会把
**「没扫到」呈现成「没有」**。八片修复分五条路线依次落地，每片都以「痕迹能不能送达最终读者」
为验收标准，而不是「测试有没有绿」。

> **★对 agent / CI / 自动化调用方的契约变化**
>
> 1. **`fxapk probe-leads --into` 现在必须带 `--sample-sha`**。探针日志本身不含样本标识，
>    此前不做任何校验——A 样本的探针线索可静默写进 B 的报告，还会让同值静态线索升到 HIGH
>    （制造跨样本假印证）。缺参 / 不符 / 目标报告无 sha 一律 **exit 2**。
>    ⚠️ 写死 `probe-leads x.log --into report.json` 的既有脚本会失败；无 `--sample-sha` 的
>    旧报告需重跑 `analyze` 生成 `meta.sample_sha256` 后才能回灌。
> 2. **闭环结论可能变化，两个方向都有**：
>    - 变**好**：做过 UID 归因的 pcap 回灌报告此前被判 `failed`（详见 Fixed 第一条），现在按证据判；
>    - 变**保守**：pcap 解析失败且零观测现在判 `failed` 并说明「空结果不等于零流量」而非当作零流量；
>      业务分析器自报资源面未扫全时，可见性资源维从 `complete` 降为 `partial`。
>    依赖退出码（0/5/6）的自动化需要重新校准基线。
> 3. **`digest` 新增三处输出**：`closure.checks`（逐项检查的保留意见）、`closure.target_selection`
>    （目标为何被排除，仅非零项）、`coverage`（哪些分析器没扫全，仅非零项）。后两者**无事件时整键不出现**。
> 4. **`report.meta` 新增覆盖度键族** `<analyzer>_<suffix>`（见 `apkscan/core/coverage.py`）
>    与 `runtime_merge_steps`（各并回子步骤的 ok/error 结局）。均遵「缺失=无事件」，不写零值。
> 5. **未知 `LeadCategory` 不再被 typed loader 丢弃**：归入新增的 `UNKNOWN` 成员并保留原始串，
>    序列化时写回原值。此前同一份 report.json，digest 看得见该 Lead、HTML 看不见。

### Added

- **`apkscan/core/coverage.py`**：静态扫描覆盖度协议（七种缺口后缀）。9 个分析器
  （7 个关键词分析器 + `api_surface` + `webview_jsbridge`）在超大资源跳过 / 读取失败 /
  累计预算耗尽 / 枚举失败 / 条数截断处记录缺口——此前这些位置多数连日志都没有，而
  uni-app / RN 的 H5 bundle 常有 2–10MB，四方支付网关、短信 webhook、后台凭据恰最可能就在里面。
- **HTML 报告新增「看到了多少」段**与 closure 段内两个区块：不能下的结论（`blocked_claims`）、
  各来源可见性与依据、扫描缺口、结论的保留意见、目标筛选原因。每处都明写「未发现不代表没有」。
- **`apkscan/core/tld_policy.py`**：TLD 双档策略的单一真源 + `POLICY_VERSION`。

### Changed

- **`visibility` 资源维消费分析器自报的覆盖缺口**：有缺口即判 `partial` 并写明是哪个分析器。
  此前 `complete` 只看 endpoints 的成功计数，看不见业务分析器各自跳过了什么。
- **`digest._integrity` 消费 `analysis_status`**：`partial` / `failed` 时追加 warning（含失败阶段名）
  并令 `reliable=False`。此前它读了该字段却只透传——报告自称「部分完成」，摘要却说「可靠」。
- **pipeline 新增 Lead 全局去重**（按 `(category, 归一化值)`，DOMAIN/IP 走 `infra.match_key`）：
  保首条 + 证据并集 + advice 冲突写进 notes 留痕。去重点在 `seal_base_advice` 之前，与撤销账本零交互。

### Fixed

- **动态闭环质量的方向倒挂**：`capture_signals` 是详细取证面（无计数字段），却排在
  `_capture_meta` 的优先链里被整体当作质量摘要，屏蔽了运行时清单的派生基线。结果是
  **做过 UID 归因的报告判 `failed`、没做归因的判 `partial`——证据更强反而结论更差**，
  且 `failed` 那份的输出里 `target_attributed_count=1` 与 reason「未观测到目标业务候选」自相矛盾。
  现降为派生基线之上的 overlay，并新增 `quality_input_source` 让质量输入来源可见。
- **jadx 的 URL 派生 host 错用了裸域名那档的窄集**：`.top/.cc/.info/.online/.live/.work` 等
  29 个 TLD 的域名在该通道被静默滤掉——不建 Lead、不做 ICP/WHOIS/ASN 富化、无计数无日志。
  而 jadx 正是为加固样本（DEX 字符串池拿不全）设的通道。双档本身是刻意设计（窄集治裸 token
  防 JS 属性访问形态（`<对象>.top` / `<对象>.info` 这类点分代码串）被误判为域名，宽集治
  URL host 防误杀真 C2），故做法是收进单一真源
  并只修 jadx 这个 outlier；防漂移测试用 `is`（同一对象）而非 `==`（内容相等）。
- **pcap 解析失败且零观测时报告里毫无痕迹**：inventory 写入整块在 `if observed:` 内，闭环
  拿不到 `parse_status`，把「这份采集根本没读成」误当成「样本确实没有对外通信」。
- **merge 子步骤崩溃与「跑完没结果」同形**：编排层 `stats[dest] = sub.get(src, 0)` 把两者压成
  同一个 0——「样本没有凭据」与「凭据解析器崩了」处置相反（结案 vs 重跑）。现逐步骤记
  `runtime_merge_steps[name] = {status, error_type}`，一步崩不阻断其余。

## 1.9.0 — 2026-08-23

本版以**运行时证据契约**为主（PR #42–#49）：动态侧把「样本自发的行为」与「被我们诱导出来的行为」
在证据层彻底分开——行为修改 shim 从裸奔改为默认关 + 双授权门，运行时证据分 `original-runtime` /
`modified-runtime` 两档且后者不得单独结案，`auto` 改成两遍编排（先原版基线、按需旁路）。
另：首批 8 个 frida 探针脱敏后随包内置；探针线索的 confidence 不再一律 HIGH，改为 advice 的
纯投影、仅二次印证才升；leak-scan 补三条案件值判据并进默认阻断档；3 个 native 探针迁到
Frida 16/17 双向兼容。

> **★对 agent / CI / 自动化调用方的契约变化（本版最需要注意的一节）**
>
> 1. **`auto` / `capture` 的默认行为变了**：第一遍恒跑**原版 APK**取基线（绝不重打包 / 注入），
>    仅当基线不足才进旁路轮。此前单遍即可能改包，现在不会。
> 2. **行为修改 shim 默认关**。要用需 `--allow-behavior-modification` + `--antidetect java`
>    **双授权门**（与 `--mode authorized-active` **正交、不继承**）。此前无开关、默认注入。
>    `--antidetect` 目前只接受 `off` / `java`，`native` 为预留档、传入即报错。
> 3. **闭环结论可能从 `complete` 变 `partial`**：标 `modified-runtime` 的观测不再单独构成
>    动态闭环依据——诱导出来的行为不能当作样本自发行为。依赖退出码的 CI 需要重新校准基线。
> 4. **探针线索的 `confidence` 语义变了**：不再一律 `HIGH`。它现在是 advice 的纯投影，
>    单源探针 待核→`LOW`、建议调证→`MEDIUM`、**永不 HIGH**；只有 merge 阶段与静态 / pcap
>    二次印证才升 `HIGH`。按 `confidence == HIGH` 过滤的下游逻辑会拿到明显更少、但含义更强的结果。
> 5. **leak-scan 三条新判据进默认阻断档**：此前能过的提交（含中文人名 /
>    QQ 微信 Telegram 账号 / 二开样本包名）现在会被**本地 pre-commit 直接拦**。

### Added

- **首批 8 个 frida 探针随包内置**（`apkscan/dynamic/frida_probes/`，已进 wheel package-data）：
  `coldstart-config` / `objstore-config` / `native-ssl` / `tls-keylog` / `sms-forward-outbound` /
  `mqtt-xmpp-im` / `telegram-mtproto` / `push-c2-inbound`。手动 `-l` 注入后用
  `fxapk probe-leads <log> --into <report.json>` 聚成调证台账并回灌。入库前已脱敏（真名 / 账号 /
  二开包名 / 桶名 / 真实接入 IP 全部换成合成值与保留段），另有源级回归锁防止真值回流。
- **leak-scan 补三条案件值判据**（`person_name` / `contact` / `package`），全部进
  `BLOCKING_RULES`。形态门槛均由全树实测定出、误报为 0；**finding 值本身自动脱敏**——
  公开仓库的 CI 日志同样公开，回显真值等于换个地方泄漏。公开第三方库若被误判，
  应登记进 `rules/` 对应规则表，而不是加行内豁免。

### Changed

- **运行时证据分档（P0-a）**：新增 `runtime_variant`（`original-runtime` / `modified-runtime`）
  与 `runtime-modified` source 令牌；后者不进 observed-contact allowlist，自动失去独立结案资格。
- **`auto` 两遍编排（P0-c）**：第一遍原版基线，仅在基线不足且已授权时进旁路轮；
  第二遍只产 `runtime_report.json` + 主报告挂指针（不出完整渲染态对照报告）。
  APK 身份（`apk_identity.which` / `.wrapper`）贯穿进报告。
- **探针线索 confidence 改为 advice 的纯投影**（见上方契约变化 4）。confidence 只影响 closure
  排位与展示排序，**不作硬门**（硬门读 advice），故降档不会关掉任何出口、不产生撤不回的降档。

### Fixed

- **行为修改 shim 加开关 + 第二道授权门（P0-b）**，默认关，止住此前的裸奔注入。
- **3 个 native 探针迁 Frida 16/17 双向兼容**：Frida 17 移除了静态
  `Module.getExportByName / findExportByName / enumerateExportsSync`，原写法在 17 下解析全失效。
  改为内联的特性探测式 `resolveExport`，全走 `find*` 变体保 null 语义（17 的 `get*` 找不到会抛，
  会让缺符号的 strip ROM 上探针崩）。只换符号解析层，取证行为零改动。
- **`_repack_paths` 恒为空**：`_fold_dynamic_step` 取 `report_paths` 而 `repackage.run` 只设
  `artifacts`，wrapper 路径从未被任何人读到过。
- 设备侧 floor pcap 此前两遍共用固定路径会互相覆盖；antidetect 测试补上两个真机收尾 pull 的
  stub，守住「不碰真机」契约。

### Docs

- `AGENTS.md` 补齐 8-17 后的四项新能力（探针库与分级语义、leak-scan 新判据与自验档位、
  两遍编排、Frida 17 的 Java bridge 与 frida-server UID 两个真机坑）。

## 1.8.0 — 2026-08-21

本版以**强化与收口**为主（PR #25–#40）：识别线补齐评测 CLI 与 P3-E 三片（gap 生产 → 入账 →
映射 v2，重分析请求首次非空）；JADX 线走完精度收尾（arity / usage 归属 / 扫描上限 / manifest
身份自洽）并把调用图判据改成按事实自陈、加召回基线 CI 重放与入列预算；报告出口做 C2 文案
纠错与版式精修；zip 炸弹补第二道「按实际产出封顶」闸。全线仍只读 / 离线 / fail-closed /
诚实空。**对 agent / CI 调用方的契约变化集中在 `fxapk jadx callpath` 的输出面与 JADX 索引
schema bump（见各条目「影响」段）。**

### Added（识别线）

- **`fxapk recognize evaluate`（P5-E）**：四任务识别评测 CLI + 显式阈值晋级门——门未过或
  `not_eligible` 以**退出码 4** 结束，可直接当 CI 闸；null 指标门必 fail、canonical 输出、
  manifest_digest 回显（内部域分离 digest）。采纳复审：数值溢出稳定拒、sha 小写口径统一。
- **P3-E：可见性缺口 → 重分析请求的生产端闭环**（三片）：
  - E1 `gap_production.build_visibility_gaps`——`blocked_claims` 的唯一入口产 `EvidenceGap`，
    三口 fail-closed；`unknown`（未评估）**有意**计入责任来源（与 visibility 的 insufficient 分叉，
    理由在模块注释）；gap reason 带 `claim.<主张名>` 令牌，防同因主张封印撞车。
  - E2 visibility gap 入账——第二 visibility question 策略、anchor 簿记、profile `p3e2-v1`
    逐 question 分桶规划；重复主张纯函数拒、visibility 追加事务式护栏、`--ledger-out` 三件套
    一致性 fail-closed。
  - E3 生产映射 v2 实表——java / native / runtime 三源 × 七档授予 → `CALLPATH` /
    `NATIVE_BUILDINFO` / `PCAP`；dex / resource / `claim.*` / 簿记不授（宁计 unknown 不虚授）；
    **gap 按 claim × source 拆分**，每个动作的 criteria 恰可兑现、未授予源独立留痕（native 请求
    只带 native reason、java 只带 java，零跨源污染）。映射 v1 时代 `recognize reanalysis` 只会
    产诚实空；v2 起 P3 线**首次产出非空请求**，且准入谓词一行未动、不靠放宽准入。

### Changed

- **报告版式精修 v1 与无判别条目收敛**：样式整块重写（文书感设计令牌 / 目录导航 / `@page`
  打印规则）；§1.5 无判别条目改为诚实计数指针（带 `shape_uncertain` / `sni_masquerade` 警示的
  skip 行作为安全例外保留——「弱化可以，消失不行」两条既有锁在守）；机器出口不动。CSS 类名
  改名只许「增类并存」不许改名（leak-scan 会把「标签.类名」形态的选择器误判成域名）。
- **JADX 调用图判据诚实化、scope 标注与召回基线（structure schema 1.3 → 1.6）**：
  - **三态名按判据自陈**：调用边的 `resolution` 由两态 `unique` / `ambiguous` 改为三态
    `name_unique` / `ambiguous` / `not_in_index`——`unique` 改名 `name_unique`（只表示简单名
    候选在索引覆盖内全局唯一，不是方法绑定，旧名暗示 JLS 绑定、超出文本提取能支撑的断言）；
    新增 `not_in_index`（索引里没有该名字的可解析 body）只进新增的 `gaps`、绝不表示不可达、
    也不专指动态调用。判据本就是「简单名在索引覆盖内的候选数 1 / >1 / 0」。
  - **边与 gap 带 `scope`**（`method` / `nested_type` / `lambda` / `unknown`）：scope 不参与
    候选解析与 resolution 判定（嵌套体内的调用照常可达），但进入 gap 身份与确定性排序。
    `fxapk jadx callpath` 的边记录新增 `scope` 字段；返回路径含非 `method` 边时追加稳定
    caveat `nested_edge_is_not_direct_execution`。账本投影载荷逐边扩 resolution/scope——
    此前两条语义不同的路径会入账成同一 digest、同为 OBSERVED。
  - **剔除三类伪边**：方法声明、构造器类型名、注解（含限定名，沿点链回溯判定）一律不再
    记成调用点；判不准时 fail-open 保留。真实混淆样本实测 310,675 条调用记录剔除 6,995 条，
    逐条回贴源码可归因、真实调用零损失。
  - **`CallPathLimits` 新增两个可选限额**：`max_fanout`（默认 `None` = 无界，保持 master
    原有的全候选展开；显式整数才启用确定性截断——真样本同名候选重尾，默认截断会在高扇出的
    常见简单名上砍召回）与 `max_gaps`（默认 64，gap 登记上限，撞帽自报 `gaps_limited`）。
  - **新增召回基线**（`tests/jadx_recall_corpus.py` + `tests/jadx_recall_master_baseline.py`）：
    以 master 实测行为为准的四层契约（提取召回地板 / 提取新增须解释 / 遍历 oracle 保真 /
    默认限额对等）；
    CI 新增 `jadx-recall-replay` job，从 origin 历史取基线 commit 的树**实跑**语料与基线字面量
    逐项对账——「基线来自 master 实测」不再靠执行者的命令行纪律。守门边界如实声明：仅改生产
    代码这一层是机器强制，连守门文件一起改只保证不可静默。
  - **schema 三连 bump 的原因**：1.4 calls 记录扩为 `{callee, line, qualifier, scope}`；
    1.5 剔除方法/构造器声明伪调用并修正 switch rule 箭头的 scope；1.6 剔除注解伪调用、
    record 类首次纳入结构段、record 体调用 scope 由 `method` 纠正为 `nested_type`。每次都是
    内容语义变化，不 bump 则同一 `index_key` 会静默复用含伪边 / 缺类 / 错 scope 的旧 shard。

  **对 agent / CI 调用方的影响**：① schema 参与 key material，**全部既有索引工件变为可重建的
  CacheMiss**，下次分析重建一次 structure 索引（jadx 反编译每次分析本就重跑，不受影响）；
  ② Python 接口 `trace_callpath()` 的返回值由 `tuple[CallPath, ...]` 改为
  `CallPathTrace(paths, gaps, coverage, reason_codes)`；③ `fxapk jadx callpath` 的 JSON 顶层
  新增 `gaps`、`reason_codes`，`limits` 回显新增 `max_fanout`（默认 `null`）与 `max_gaps`，
  边记录新增 `scope`，含嵌套体内边时新增 caveat；④ `resolution` 字面值 `unique` 改为
  `name_unique`，按旧名匹配的消费方须改；⑤ 默认无界 fanout 在极端重尾样本上更耗资源
  （BFS 入列量此前不受 `max_visited` 约束，见下方 Fixed 的「入列预算」条目）。

### Fixed

- **zip 炸弹 Level 2：androguard / apkInspector 解压路径按实际产出封顶**：此前全部 zip 炸弹闸
  都是 Level 1——只信 zip **中央目录**声明的解压后大小（`_reject_if_zip_bomb` /
  `ApkContext.read_file` / 并行 worker `_lazy_read`）。但 androguard 4.1.4 的 `APK.get_file`
  走 apkInspector 的 `extract_file_based_on_header_info`：它**优先用 local header 的大小**
  （与中央目录可不一致），DEFLATE 时 `zlib.decompress(data, -15)` **完全无上限**——声明大小
  只决定读多少压缩字节，不约束解压产出；中央目录声明 100 字节、实际膨胀到数 GB 照样全量
  解压。`APK()` 构造期急切解压 manifest（arsc 在解析资源引用时解压）、`get_all_dex()` 解压
  dex 走的都是这一条路。stdlib `zipfile` 按中央目录 file_size 截断、与 Level 1 自洽，只有这条
  路失守。
  现在与 AXML 投毒净化 shim 同模式：`load_apk()` 与并行 worker 惰性重开 APK 前幂等安装
  `_install_bounded_zip_extract_shim()`，把 apkInspector 的解压函数替换为**分支逐一对齐**的
  有界版本——STORED / STORED_TAMPERED 按上限+1 有界读取、DEFLATE 用 `decompressobj` +
  `max_length` 循环、累计产出超 `_MAX_DECOMPRESSED_FILE_BYTES` 立刻抛 `ZipEntryTooLargeError`
  并 warning（`APK()` 构造期也留痕）；DEFLATED_TAMPERED 的回退分支不得吞掉该异常。**压缩输入
  也流式**：原函数按（可伪造的）`compressed_size` 一次性 `read`，伪造巨大值可逼出 ≤ 整个 APK
  体积的一份额外拷贝；现在每次只读 1 MiB 喂 `decompressobj`（codex 第二轮复审 P2）。上限内
  逐字节等价（含不完整 deflate 流照抛 `zlib.error`、尾随字节忽略）。`read_file` / `_lazy_read` 把该异常转成
  warning + `None`（不再是 debug 级「未命中」）。
  **对 agent / CI 调用方的影响**：正常样本零变化；只有「声明过闸、实际膨胀超上限」的条目从
  「全量解压（可致 OOM）」变为「拒读 + warning」。核心条目超限时 `load_apk` 抛 `ApkParseError`
  （与 Level 1 对核心条目的 fail-fast 一致）：manifest 在 `APK()` 构造期即被拦、由既有包装
  转为 `ApkParseError`；DEX 的拒读则**专门捕获**后整体拒绝——不能落进「DEX 不可见（可能加固）
  → 无 DEX 继续分析」的降级分支，否则把炸弹放在 `classes2.dex` 就能让已解析的主 DEX 一并
  清空、形成静态分析规避（codex 复审 P2，已修并有端到端锁）。
- **JADX 调用图 BFS 加「入列预算」：队列占用以 `max_visited` 封顶（零语义变化）**：
  `trace_callpath` 此前每出队一个方法节点就把 `calls × candidates` 全部入列（每项复制整条
  路径元组），`max_visited` 只限制**出队**次数、对入列量没有任何约束——#37 把 fanout 默认
  改为无界后这面更宽。合成夹具（10 候选 × 10 调用点 × 深度 3）实测 `max_visited=1000` 时
  队列峰值 58,503、`max_visited=10` 时 820；真实混淆样本单方法调用点上限 256、单简单名
  候选最大 3038 → 单节点即可入列约 78 万项，100k 次出队前内存即耗尽。
  修法不加旋钮（`CallPathLimits` 字段集与 CLI `limits` 回显键集都有锁）：队列是纯 FIFO、
  出队总次数 ≤ `max_visited`，所以全局入列序号 > `max_visited` 的项**永远不会被出队**——
  只入列前 `max_visited` 项、其余丢弃并计数，循环结束后按 master 循环头的检查顺序补偿
  reason（`paths_limited` / `visited_limited`）；单节点的展开改为**各调用点候选流的稳定
  k 路归并**（`heapq.merge`，同 key 按调用点序出队，与 master 的稳定排序逐项相同）、
  只拉取「剩余预算 + 1」项——第 remaining+1 项存在即判溢出——单节点内存与 CPU 为
  O(calls + 剩余预算 · log calls)，外加每条流在产出前至多跳过 ≤ max_depth+1 个路径内环候选；
  `max_fanout` 显式截断用 `islice` 惰性走前缀、不复制候选表。不再随 calls × candidates 线性
  增长（codex 复审指出 `nsmallest` 版本仍会让预算耗尽前最后一个大扇出节点扫完全部候选、
  切片会先复制 calls × max_fanout 个引用，均已改）。每个出队节点的
  calls 形状校验、gap 登记、`fanout_limited` 登记与 `caller_path` 校验一律照常执行，
  fail-closed 面不缩。
  **等价性不是靠说的**：新增 `tests/test_jadx_callpath_budget.py`——两个合成夹具 × 8 组
  端点 × 2112 组限额（含 `max_fanout=0`）的**完整 `CallPathTrace` 序列化**（路径节点序与
  每条边六元组、gap 六元组、coverage、reason_codes）指纹必须与改动前 master 实测捕获的指纹
  逐字节一致；另内嵌 master 的 BFS 原文作参考实现，在对抗复核给出的反例构型（选取阶段截断
  漏计、预算耗尽后仍有幸存候选、环过滤、畸形 caller_path 异常面、省 arity 多起点）与 1500 例
  含畸形调用点的随机小图上逐例比对返回值或异常；队列峰值 ≤ `max_visited`、展开拉取量 ≤
  「剩余预算 + 流首项」两条资源锁无修复即红。
  **对 agent / CI 调用方的影响**：无——paths / gaps / reason_codes / 异常行为逐字节不变，
  `CallPathLimits` 字段集与 CLI 输出不变，不 bump schema、不触发索引重建；只是极端重尾
  样本上 `fxapk jadx callpath` 的内存上界从「不可控」变为约 `max_visited × 路径长度`。
- **JADX 索引统一扫描上限，修一个「调了不生效的死旋钮」**：`_MAX_JAVA_FILES`（端点/密钥
  扫描的文件数上限）一直在 `options_digest` 里，改它会改 `index_key`、触发缓存自动
  重建；但 structure 索引（`usage`/`callpath`/`ownership` 的数据来源）构建那一行**硬
  编码了空参数 `Limits()`**，用的是默认 `max_files=5000`，完全不读 `_MAX_JAVA_FILES`。
  真实混淆样本反编译出万级 `.java` 时，端点扫描的上限调多大都不影响 structure 索引，
  它始终只扫前 5000 个（按路径字母序，砍掉的是**系统性偏后**的部分，不是随机采样）。
  现在 structure 索引真正读这个常量，且常量本身从 5000 调大到 12000（真实样本实测：
  同一份混淆样本从只扫 5000 个文件 / 55104 个方法，涨到全部 10366 个文件 / 104379 个
  方法，覆盖翻倍）。**不需要 bump schema**——`index_key` 已经把 `options_digest` 算在
  内，调大常量本身就会让旧缓存自动变为可重建的 CacheMiss。

  同时把报告穷尽性主张（`static_endpoint_exhaustive` 等）依赖的 java 源文件数封顶从
  5000 提高到 12000：`jadx_receipt.complete` 此前只要撞上 5000 就恒为 `False`，实测的
  真实混淆样本（万级 `.java`）现在能在这个维度达到 complete。封顶仍然存在——超过
  12000 个文件照样阻断 complete；且 `static_endpoint_exhaustive` 还需要 dex/native/
  resource 各源同时 complete，java 只是其一，不代表整个主张解封。

  **诚实边界（本片刻意不动）**：单方法调用点数上限（`max_calls_per_method`，精确
  256，有边界值回归锁）未变。含超大方法（如混淆生成的巨型 dispatch 方法）的样本，
  structure 索引 coverage 仍会是 `partial`——这是对的，不应假装它已完整。

  **同批加固（codex 复审）**：上限调大 2.4 倍放大了扫描面的资源上界（理论积
  `12000 × 4MiB ≈ 47GiB`），两刀收口——① 端点扫描此前 `read_bytes()` 全量载入后才
  截断，单文件内存峰值实际不受 4MiB 上限约束，改为有界读取（`bytes_total` 统计保持
  「真实文件大小」语义）；② structure 扫描新增**聚合读取预算** `max_total_bytes`
  （默认 512MiB，约为实测真实大样本的 6 倍余量），累计读取触顶即停、剩余文件不扫、
  coverage 诚实降 `partial`——此前撞文件数、单文件截断都有硬帽，唯独聚合量没有，
  敌对样本可用大量各自不超限的文件把总读取量堆起来。

  **对 agent / CI 调用方的影响**：既有索引工件本身不变；下次分析会按新常量派生出
  不同的 `options_digest`（进而不同的 `index_key`），旧工件不再命中、自动重建一份
  新索引（约 +73% 扫描耗时，真实样本约多 6 分钟/样本，一次性成本，不重跑 jadx
  反编译）；`usage`/`callpath` 此后能覆盖此前被截断掉的那部分代码。
- **JADX 索引 manifest 身份自洽 fail-closed**：`JadxIndexManifest.__post_init__` 此前
  只对 `index_key` 做 64-hex 语法校验，不验证它确为身份字段（`dex_lineage` /
  `jadx_version` / `options_digest` / `index_schema_version`）的重算值；而
  `build_index()` 的复用分支只凭 `manifest.index_key` 查已有索引——程序化调用者提交
  「旧 key + 新 options_digest」的不一致 manifest，会**复用旧 structure 数据冒充新配置
  的产物**。生产路径先从新 digest 派生 key 再构造 manifest，不触发；load 侧的重算比对
  只护磁盘读回，不护构造入口——存储层此前不满足独立 fail-closed。现在构造即重算比对，
  不一致抛 `JadxIndexError("key_mismatch")`（复用入口在对象层面封死）；`dex_lineage`
  元素类型一并锁死——非 `DexLineage` 元素此前会让身份重算抛裸 `AttributeError` 而非
  结构化拒绝。
  同批（本刀 codex 复审点名的 P1）：`key_material` 是身份的**持久化副本**，此前只查
  四键集合、不核内容，且对象存的是调用方可变 `Mapping` 的引用（`frozen` 只是浅冻结）——
  「顶层旧身份 + material 新身份」的矛盾 manifest 一旦落盘 load 恒 CacheMiss，
  create-only 发布还会把该 key 槽位毒化成无法修复的死件；构造后改写调用方 dict 则让
  校验整体作废。现在内容与顶层字段的重算结果逐字节比对（不一致抛
  `key_material_mismatch`），通过后存重算份的快照，与调用方引用内外层全隔离；
  物化 / canonical 编码 / 键检查收进同一道异常归一化边界——自定义 Mapping 的遍历
  异常与循环引用的 `RecursionError` 都归一为 `invalid_key_material`，不再裸抛。
  **对 agent / CI 调用方的影响**：正规派生 key 的调用不受影响（生产路径与全部既有夹具
  实测零破坏）；只有身份不一致的 manifest 从「静默复用错误数据 / 落盘死件」变成构造期
  结构化拒绝。

- **`fxapk jadx usage` 的命中现在带类/方法归属**：`UsageHit.class_context` /
  `method_context` 一直在数据结构上、也一直被 CLI 的 JSON 输出透传，但
  `find_value_usage` 从不给它们赋值——输出里**恒为 `null`**，且没有任何测试断言过。
  现在用 structure 段中方法的行号区间反查 posting 所在的方法，把它们填实。
  归属是 fail-closed 的：**恰好一个区间包含该行才归属**，落在 0 个（字段初始化器 /
  静态块——class 段没有行号区间，无法单独定类）或 ≥2 个（区间重叠）一律留 `null`，绝不猜。
  结构段缺失或形状异常时降级为无归属，不会让原本能返回的命中变成异常；异常一律放弃
  **整个 shard** 的归属而非逐条跳过——跳过某条坏记录会让剩余区间冒充「唯一归属」，
  把不确定伪装成确定。单一路径的区间数另有硬上界（构建期有 Limits 约束，但 load 侧
  没有对应计数上限，而反查是逐命中线性扫描）。
  **对 agent / CI 调用方的影响**：字段与类型（`string | null`）都不变，只是 `null`
  被填实；命中集合一字不增不减（有专门的回归锁）。归属覆盖面恒等于 posting 覆盖面——
  为补归属去读索引之外的源文件是被禁止的（只读查询面绝不碰文件系统）。

- **JADX 索引方法 arity 泛型感知计数（structure schema 1.2 → 1.3）**：`_declared_arity`
  此前按 `split(",")` 计参数个数，而方法声明正则允许泛型，于是泛型实参里的逗号被当成
  参数分隔符——`Map<String, String> m` 算成 2 个参数。方法身份是 `cls#name/arity`，
  算错即令 `trace_callpath` 按真实 arity 查**得空**，而空结果在本模块语义里是「未观察到」
  而非「不可达」，这类假阴性不会被任何既有断言揭穿；`jadx_ownership` 的方法身份
  `(class_name, path, "name/arity")` 同样错位、与官方 baseline 对不齐。
  已在真实混淆样本（万级 Java 文件 / 万级类 / 五万级方法）上端到端验证：修复后提取不崩、
  arity 分布合理。

  同批补上参数段的 **fail-closed 缺口**：畸形参数此前会被折叠成一个「看起来正常」的
  arity——`f(,,,,)` 折叠后是 0、`f(x)` 折叠后是 1，分别与真实的 `f()` / `f(String x)`
  撞进同一个 `cls#name/arity` 身份，而 callpath 查询按同 id **合并出边**，等于让敌对
  样本把伪造的调用边挂到真实方法上。现在四类一律判为不可判定：尖括号不配对、存在空的
  顶层段、任一顶层段不含空白（合法形参必是 `类型 名字` 两部分）、形参个数超宽松上界。
  参数段是样本可控输入，不可判定就必须说不可判定：
  现在这类声明整条丢弃，并把该 shard 的 `coverage` 降为 `partial`（丢了声明就不再声称完整）。
  真实混淆样本实测该加固**零误杀**：加固前后提取出的方法数完全一致，即良构样本一条都不会
  被丢弃，它只在畸形/敌对输入上生效。

  **对 agent / CI 调用方的影响**：本次不改 structure 段字段集，只改既有 `arity` 的取值，
  但 schema 参与 key material，**bump 令全部既有索引工件变为可重建的 CacheMiss**——
  下次分析会重建一次 structure 索引（jadx 反编译每次分析本就重跑，不因此多付）。已缓存
  index_key 会变；
  `fxapk jadx callpath` 的端点参数须按修正后的真实 arity 书写（此前对泛型参数方法
  需要传错误的偏大 arity 才能命中，那是缺陷行为，不再兼容）。

- **报告 C2 文案语义纠错**：静态档不再自称「C2」，徽标改为三档「实连已观测 / 运行时出现 /
  疑似自有后端」（seen / contacted 分层措辞）；无人工认定不输出确定性 C2；③节、空态、总览里的
  确定性旧称一并去除。对外文书的措辞边界：没观测到的不替人下结论。
- **`analyze-web` 写入网页证据集指纹与 `evidence_manifest`**：纯网页报告此前没有证据清单，
  过不了 `case package` 门禁；现在与 APK 报告同口径写入（空集 fail-closed、类型收窄）。
- pcap 归因结论改为按抓包 fingerprint 记账（`meta.runtime_pcap_attribution_ledger`，
  版本化、有界字段、fail-closed）：同一 IP 多次抓包各自留痕，反转其中一次的归因不再
  擦掉另一次已确证的 TARGET；显式判否现在能把 IP 撤出目标集（此前 inventory 目标集只增
  不减）、也能把端点 `runtime.target_attributed` 与 lead/endpoint 证据面一并原子更新
  （此前幂等闸把结论更新一起冻住）。`capture_signals.pcap_app_attribution` 从共享草稿
  （carrier 级后写者胜）变为账本投影的派生视图——**机器消费方注意**：同 carrier 跨抓包
  结论相反时该表保留 TARGET 记录（既成事实优先），逐次原始结论在账本 captures 里可审计。
  旧报告无 fingerprint 的归因迁入 `legacy_unscoped` 隔离留痕，不冒充当前抓包证据。
  另修 `remote_endpoints`/域名迭代序不定（同观测换输入顺序产生报告 diff）与
  fingerprint 的 SNI 逗号拼接歧义（含分隔符的异常值改结构化编码，正常值指纹不变）。

## 1.7.0 — 2026-08-17

本版落地「认知闭环」识别线的机制层（P0–P5，PR #2–#23）：判断链合同、JADX 持久索引与
结构查询、重分析请求的提案侧闭环、多任务标签契约、防泄漏切分与四任务评测指标。全线
只读/离线、fail-closed、诚实空（空输出≠无缺口）；模型永远只能写 proposed，不碰证据权。

### Added（识别线）

- P0-A 判断链最小合同：Question/Observation/Claim/Gap/Action/Outcome 与 append-only
  judgment ledger（严格 JSONL、可重放、旧证据不可改）。
- JADX 持久索引：内容寻址 shard、DEX 复算校验、受控 cache root、create-only 发布与
  fail-closed 加载校验链；一次索引、多次定向查询。`fxapk jadx` 新增 usage / callpath
  只读查询子命令与查询账本 sidecar（阴性绝不产观察）。
- JADX 结构层：`trace_callpath` 调用路径、结构 diff（接入 `fxapk diff`）、ownership
  projection（来源归属摘要进报告可见面）。
- 重分析提案侧：`ReanalysisRequest` 契约（AnalysisType 矩阵/PlanningContext/NextAction
  投影）、planner 纯函数（准入谓词 v1、同 dedupe 合并、ceiling 过滤、receipt）、账本
  ACTION_PROPOSED 投影与可验证 sidecar、`fxapk recognize reanalysis` CLI（双文件事务、
  授权提示）。生产映射 v1 可能产生诚实空结果。
- 多任务识别标签：`recognition_labels` 契约（family/clue/relation/ownership/reanalysis
  五 kind、active/effective 双投影、模型只能写 proposed 的写入边界）、FEEDBACK_QUEUED
  账本事件（CandidateLabelFeedback，模型禁入队）、`fxapk recognize labels validate`
  只读校验器。
- 防泄漏切分：split-manifest 契约与构建器（同案/确认家族/确认正例关系/显式派生的传递
  闭包为原子单位，五切分互斥全覆盖，canonical 字节冻结 + 域分离 digest，加载端不信任
  构建端逐项复验）、`fxapk recognize split build/validate`（原子 create-only、错误行
  只出稳定码不回显动态输入）。
- 评测指标层：`recognition_evaluation` 四任务纯函数（Family macro-F1/开放集；Pair
  recall@k/NDCG@k/AP/确认误边；Group B-cubed/cannot-link/官方重打包误并；Clue 有效性
  与 ownership 精度/证据引用完整率）与 promotion_eligible 推导——silver/gold_internal
  与 dev 切分永远出不了晋级数字；负例纪律贯穿：无标签绝不当负例。

### Fixed（识别线）

- 修复真实混淆样本（含脱壳 dump）令 JADX 持久索引整体不可建的问题：结构段类身份从
  仅 `name` 改为 `(name, path)`（`INDEX_SCHEMA_VERSION` 1.1 → 1.2，旧工件按既有漂移
  机制拒收重建）。不同路径的同名类（无 package 声明塌缩的混淆简单名、多 dex dump 的
  同限定名重复类）现在可发布可加载；完全相同 `(name, path)` 的重复仍 fail-closed。
  结构 diff / ownership 按 `(class_name, path)` 对齐（同名类绝不互相污染；
  `structure_diff` 段的 `added_classes`/`removed_classes` 明细从裸类名字符串改为
  `{"class_name", "path"}` 对象，`changed` 明细新增 `path` 字段——影响机器消费方）；
  callpath 对跨 shard 重复 ident 从 fail-closed 拒绝改为确定性合并出边。

### Changed

- 仓库公开化准备：过程性设计文档移出仓库（`docs/`）；面向公开语境统一文档与注释措辞
  （分析告知类文案改为中性技术表述）；CI 恢复 push 触发并将 macOS / Windows 收回
  GitHub 托管矩阵（公共仓库 Actions 不计费，此前的私有仓库省额度形态不再需要）。
- 已知待办：部分测试夹具的合成域名使用了真实可注册 TLD（`.cn`/`.shop`/`.vip` 等）及
  `x.com` 一类占位名，不指向任何真实基础设施，后续逐步替换为保留域（`example.com` /
  `.test` / `.invalid`）。

### Added（串案线）

- `corpus link-candidates` 结果增加稳定 `candidate_id`/`rank`、明确命名的
  `review_priority_score`/`uncapped_score`、特征与归一化版本、策略摘要，以及候选召回
  `complete|partial` 状态。旧 `score`/`raw_score` 暂保留为兼容别名；分数始终只是人工复核优先级。
- 新增严格的工作树外 JSONL 标签契约和 `corpus link-evaluate` 离线评测入口。评测只输出聚合指标，
  不把未标注或不同家族自动当负例，也不输出样本、案件或 IOC 原值。
- 新增 `corpus link-discover`、`link-explain`、`link-groups`：发现组内重复锚、解释单对候选、生成只含
  真实边的人工复核图。三者默认 `--evidence-values omit`；显式 `raw` 才输出原始标识符并告警。
- 新增 `corpus link-readiness` / `link-train` 和可选 `fxapk[ml]` 依赖。LogisticRegression challenger
  使用严格 JSON 产物、先切 entries 再冻结 train-only 预处理、component-balanced scaler/loss 和
  聚合 holdout 排序指标；未达到 200 个 train 样本、10 个独立正例组件、300 正例、600 负例、
  500 hard negative 时在导入 sklearn 前阻断且不写模型。artifact 明示未校准，分数不是概率。
- `corpus link-candidates --model <工作树外.json>` 可显式 shadow 重排规则候选全集；模型不自行召回、
  不改变规则分数/等级，也不能突破 deterministic caps。模型产物固定训练时的 rule policy digest、
  result/feature schema 与 normalization，跨规则版本不兼容时 fail closed。

### Fixed（串案线）

- 修复同一第三方 native 组件在不同 APK 中被随机改名后绕过弱锚规则的问题：同一 SHA-256 须在
  至少三个不同真实样本间一一匹配到三个不同 basename，才标记为 `renamed-shared-component`；
  单个 APK 内复制三份改名不能毒化全库。弱锚零分排除但保留可见。
- 非法样本身份不再进入串案索引；超大锚桶或非法身份使候选召回显式标为 `partial`。同一 APK
  跨案件只输出 `exact_artifact_identity` 关系，不再给容易误读为概率的 100 分。
- 发布 `fxapk-linkage-rules-v2`：合法 `nosha-*` 只保留 `possible_duplicate_report`，不进入普通 pair；
  `repack_suspected` 与显式 quarantined 输入分别标记 `ownership_unresolved` /
  `non_authoritative_input` 并封顶到非高优先人工复核档。覆盖状态升级为五态，候选支持证据增加双侧
  revision provenance。
- `label_basis` 改为非空受控词表；与 remote-config/native/signing/build/IOC 特征重叠的标签仍可
  审计和发现，但从晋级指标与训练中排除。独立正负金标不足时评测返回
  `insufficient_independent_labels`，训练返回 `blocked`。替代链的断链、前向引用、分叉、环、跨自然键
  和孤立 superseded 现在全部 fail closed。
- 排名评测同时报告原始队列位置指标与明确命名的 `pool_conditioned_judged_only` 指标，避免删掉未标
  候选后把排序表现算得过于乐观。
- 未确认的 superseding proposal 不再撤销既有 confirmed 金标；confirmed/rejected replacement 按
  追加式状态机生效。私有标签文件缺失或不可读时也不再由 Typer 回显完整路径。
- 旧 manifest 缺少 `repack_identity_verdict` 时，串案结果显式为 `partial` 并提示 `corpus reindex`；
  字段值为 null、非法字符串或错误类型时同样 fail closed；native 弱锚名单的规则内容进入 policy
  digest，加载失败同样降为 `partial`。
- `link-groups` 不再物化大型连通分量的 O(n²) 传递闭包；改为精确总数和最多 100 对稳定预览。

## 1.6.1 — 2026-08-13

把运行时归因判据收敛为单一真源，消除 `capture` 主路径与 `pcap-leads --into` 两处手写降档
量词靠注释同步的架构隐患——同一份 floor pcap 曾因两侧量词不一致对同一端点给出相反的
observed-contact 结论（历史复发两次）。

### Changed

- 运行时端点「是否降档为未归因」的判据统一取自 `runtime_evidence`（`verdict_for_carriers`
  / `is_denied`），`capture` 不再自算量词。降档语义不变：仍须每个承载远端都已归因、且无一
  属目标应用才降档，信息缺失不推出否定。

### Fixed

- `target_attributed` 保持原量词（存在任一已归因承载端点属目标即为 True），不随降档判据
  统一。两者问的是不同问题（「有没有端点属目标」vs「能否确证都不属目标」），量词本就不同；
  此前误统一，会在「一个端点确证属目标 + 另一个端点缺归因」时把已确证的归属抹掉。

## 1.6.0 — 2026-08-12

本版把「结论可信度」做成结构：每条证据带上对当前案件的资格（作用域）、Phase-1 证据包不可变
且由独立 Phase-2 复核、corpus 以 catalog 为案件绑定真源、多源富化状态统一成五态对象。

★**本版含影响既有调用者的行为变更，不是纯新增**：

- 旧报告缺少 `Evidence.scope` 时按 `legacy_unspecified` 迁移，这类证据**不能**独立进入闭环、
  获得运行时实连资格或升级为「建议调证」。**同一份旧报告在本版下的档位可能低于上一版**；
  旧报告仍可正常读取，收紧的是结论口径，不是兼容性。
- report / package JSON 读写开始拒绝 `NaN` / `Infinity` / `-Infinity`。
- 闭环空目标清单不再自称 `complete`，降为 `failed`。
- `corpus migrate-catalog` **不可用 `corpus restore` 撤销**，`--apply` 前需自行整目录备份。

### Added

- `corpus migrate-catalog` 的 dry-run 与真写输出都带上 `reversibility` 声明：**该迁移不可用
  `corpus restore` 撤销**。catalog 是案件绑定真源、manifest 只是可重建的派生索引，恢复迁移前的
  manifest 快照会被 catalog 立刻重新物化回迁移后形态；而删掉 `catalog.jsonl` 想补全回滚，会让整库
  fail-closed（manifest 残留 catalog-era 事实、对应主键却没了），`ls` / `verify` 全部拒绝执行。
  两条路都不通，唯一有效的回滚是**整目录备份**，故必须在 `--apply` 之前完成。
- `corpus restore` 恢复一份 catalog 建立**之前**的旧快照时，输出新增 `catalog_boundary` 警告。
  此前这种恢复会照常返回 `applied: true` 与 `restored_entries`、看起来成功，实际库并未回退——
  一个报成功却没生效的回滚比明确失败更危险。未跨越该边界时不出这条，避免退化成人人略过的噪音。
- 新增公共两阶段案件交接协议：`fxapk case package/status/review` 生成不可变 Phase-1 证据包、
  对精确包哈希出具独立 Phase-2 复核记录，并并列呈现包完整性、分析、闭环、复核四种正交状态。
  协议不绑定目录、机器或具体执行者，同一人也可按顺序执行两个阶段。
- Phase-1 manifest 的每个附件显式标记 `case_evidence` 或 `batch_reference`，校验相对路径边界、
  文件大小、SHA-256、案件标识规范和状态枚举；同时强制固定 64hex `sample_sha256`、规范化非空
  `tool_version` 与 16hex `ruleset_digest` 三个复现锚点，缺失/占位时零写拒绝。Phase-2 复核只对
  完全一致的 package 有效。

### Changed

- report schema 升至 1.2，`Evidence.scope` 区分当前案件直接证据、批量/跨案参考和旧版未说明作用域。
  仅由 `batch_reference` / `legacy_unspecified` 支撑的 Lead/端点保留为待核参考，但不能独立进入
  closure、获得运行时实连资格或升级为“建议调证”；同端点另有 `case_evidence` 时仍可正常闭环。
  `digest`、调证函、IOC、JSONL 及 typed HTML/PDF 路径统一执行该门；JSONL Lead 事件新增
  `evidence_scope_summary`，在省略完整 `source_refs` 时仍显式给出直接证据资格和引用数。
- 闭环状态新增共享安全投影：伪 `complete` 的空目标清单降为 `failed`，任一目标缺少同值直接
  `case_evidence` 降为 `partial` 并给出缺口；typed load、digest、case status 与回归消费一致，
  Phase-1 建包/验包仍严格拒绝虚假 complete。串案强指纹同样只接收直接案件证据；钱包密钥不再
  因内容格式校验而绕过案件作用域。`evidence_scope` 事实资格禁止由 `lead restore/replay` 撤销。
- report 读取增加显式版本兼容层：缺失版本按 legacy 1.0 迁移，1.0/1.1 缺少 scope 时安全迁移为
  `legacy_unspecified`；未知未来版本禁止进入 typed 原地写回路径，避免旧工具改坏新格式。
- report/package JSON 读写拒绝非标准的 `NaN` / `Infinity` / `-Infinity`；写失败保持既有文件不变、
  不产生半成品，有限浮点仍正常往返。
- 真实 APK 的并行等价慢测改为仅在显式设置 `FXAPK_TEST_APK` 时运行；普通取证工作树即使留有
  `.apk` 证据，默认 `pytest` 也不会意外启动高内存真 spawn 测试。
- 富化文档明确区分内置源与仓库外 DayDayMap 配套工具；仅填写 DayDayMap key 不再被误读为
  fxapk 核心已查询或会生成对应 `source_status`。

### Fixed

- `corpus reindex` 以实际扫描到的库内文件路径重建 `report_path`，避免旧版误命名 unpacked 报告
  被同时误报为 manifest 缺失和孤立文件。

## 1.5.4 — 2026-08-11

本版强化运行时证据归因、远程配置取回、跨报告语料完整性与域名控制链。
无破坏性变更；新增字段和命令均向后兼容，旧报告缺少新证据时保持明确降级。

### Added

- **远程配置探测成为正式阶段。** 新增 `config-probe` 运行链路，按授权模式取回并记录
  远程配置产物；自检同步报告所需凭据是否配置，不再把“能力存在”误写成“当前可用”。
- **应用框架识别成为独立分析阶段。** Flutter、Unity及其他框架信号进入结构化报告，
  并由契约测试约束生产者、消费方与元数据形状，避免信号只写入而无人读取。
- **corpus 完整性校验。** 入库时记录报告内容哈希，新增只读校验与存量哈希补录；
  补录哈希明确标记来源，不能冒充入库时形成的完整性基准。
- **域名与 CNAME 跨报告反查。** corpus 建立规范化域名和已观测 CNAME 边索引，
  `corpus seen --by domain|cname` 可直接反查；缺少 RR owner 的旧摘要不会被补造为边。
- **域名控制链。** 将注册商、权威 DNS 产品、Zone/账户及记录操作者与服务器五层归因分开；
  共享或 Anycast 权威 DNS 只能识别产品，不能据此推断租户或操作者。

### Changed

- **PCAP DNS 证据保留 RR owner。** DNS 记录可在没有业务流的情况下独立、幂等回灌，
  多跳 CNAME 按真实 `owner → target` 保存，后续新增记录不会被旧流量指纹吞掉。
- **`198.18.0.0/15` 解析结果隔离。** 代理 Fake-IP/基准测试地址保留为负证据，
  但不再进入公网主机归属、托管查询或持久缓存；同时记录解析器和单视图覆盖状态。
- **动态 socket 归因更严格。** PCAP 回灌接入 UID/socket 证据，区分当前连接与
  TIME_WAIT残留，并将归因覆盖度写入报告，避免把系统或其他进程流量算给目标应用。
- **第三方生态降噪扩展。** 框架、SDK和共享组件使用合成基线持续回归，
  防止把供应链公共信号误判为应用自建资产。

### Fixed

- 修复业务代码容器中的 native 库路径漏读，以及相关名单死条目和空转测试夹具。
- 修复批量与脱壳报告入库时证据面丢失、manifest 并发缩减及库外报告缺失时的静默覆盖风险。
- 修复运行时网络端点在 socket 归因接缝处丢失、特殊域名与公网 IPv6 分类不完整等问题。
- 收紧泄漏扫描的凭据、域名和工作树提示逻辑，并保留全树与 PR 差异双重门禁。

## 1.5.3 — 2026-08-05

本版主线是**让已经算出来的信号真正到达读报告的人**，外加一批线索判据的收紧。
无破坏性变更；但 HTML 报告与线索档位的输出有可见变化，**自动化消费方请看下面两条**。

### Added

- **`report.meta` 契约层。** 此前反复出现同一类缺陷：某个信号写进了 `report.meta`，
  下游却没有任何消费方——历史上至少四次（`tier` / `dex_available` / `is_hardened` /
  `native_obfuscation`）。现在有静态扫描器把全仓 `report.meta` 的读与写配对，
  声明与实际写入双向一致才通过，孤儿项须显式登记在基线里并注明性质
  （信号 / 留档 / 覆盖度）。
- **证据出口契约。** 逐条锁住「某个分析结论最终出现在哪个人看得见的产物里」，
  并按缺口类型（完全无出口 / 有条件出口 / 字段级缺失）统计。
  契约自身带测试，出口消失会红。

### Changed

- **HTML 报告的技术发现表新增「取证依据」列。** `Finding.evidences` 此前在
  **任何人看得见的出口都不渲染**（HTML 只有 id/标题/严重度/分类/描述/建议，
  digest 只投影 id/严重度/标题，letters 只读 Lead），而全仓 40+ 处把关键取证值
  ——绝对路径条目、命中片段、类名——**只**写进该字段。现在直接铺开 20 条，
  其余收进折叠区，连折叠区都放不下的另行标明「只在 report.json 里」。
  ★三种「没显示」在报告里是分开表述的，别混为一谈。
- **线索档位不再看文件名。** `chunk-vendors*.js` 这类 basename 判据从降档链路撤出，
  降为只影响闭环排序的弱信号——文件名由打包者可控，一旦能决定 advice，
  改个名就能把真后端确定性踢出闭环。噪音改由 closure 层的同源配额压制。
- **闭环目标选择加同源去拥塞。** 同一来源文件贡献的候选首轮只占一个名额，
  实际连接过的不受此限。实测真后端从第 25 位升到第 2 位。
  新增 `closure.target_selection.source_deferred`（顺延数，**顺延不等于排除**）。

### Fixed

- **网页证据里只以完整 URL 出现的后端此前整类漏掉。** 原先只产 `kind="url"` 端点，
  而 URL 端点不产 Lead、不进富化，于是写成完整 URL 的后端既不进线索清单也不进闭环
  ——而完整 URL 恰是最常见的写法。现在为 URL 的 host 另收一条 domain/ip 端点。
  ★IP 过滤强度按来源分档：裸四段字面过噪声判据，完整 URL 里的 host 不过。
- **拦截节点的排除不再静默。** 此前与「无载荷 SYN-only」共用一个计数、日志只提无载荷，
  于是「有个端点被当拦截节点吞了」在报告里完全看不出来。现在两类分开记，
  并落进 playbook 与 `report.meta.capture_signals.endpoint_exclusions`。
- **`leak-scan` 的域名判据改为 token 级。** 对 `.py` 只扫字符串与注释 token，
  不再扫代码里的属性链——属性名恰好是某个国家顶级域时会被整片误判。
- **绝对路径诱饵条目的具体路径此前拿不到。** 原先只放进 `evidence`（不渲染），
  且上限 5 条——而本文件记录的实测样本就有 411 条。上限提到 2000，
  超出部分在描述里如实标明未落进报告。

## 1.5.2 — 2026-08-03

仓库卫生版本，**无功能变更、无行为变更**。已发布的 1.5.1 及更早版本建议不再使用。

### Changed

- **示例值与测试夹具统一为合成值。** 注释、docstring、CLI `--help` 文本与测试夹具中的
  举例值一律改为明显合成的占位值；需要对照真实检材运行的用例改为由环境变量
  `FXAPK_GROUNDTRUTH_KEY` 注入，未设置则跳过。
- **阈值说明改为只保留可复现的测量值。** 判据注释保留数值区间（任何人重跑同类工具都能得到），
  不再记录标定语料的规模与分布。

### Fixed

- **`leak-scan` 的凭据判据补齐三类此前完全命中不到的形态**：
  - 复合命名 —— `client_secret` / `private_key` / `auth_token` / `encryption_key` 等
    （下划线是正则单词字符，原先靠 `\b` 锚定的裸词分支匹配不到它们）；
  - 裸 `key` 命名，以及赋值右侧先过一层编码函数的写法（`key=SomeCodec("…")`）；
  - 占位判定新增标识符形态（枚举成员 / Finding ID），避免上述扩容带来的误报。
- **`leak-scan` 的环境变量豁免改为按语法位置判定。** 仅当值出现在 `os.environ.get(...)` /
  `getenv(...)` 调用内才放行；此前按「值的字符形态」放行，会把长得像变量名的硬编码值整类漏掉。

## 1.5.1 — 2026-08-02

> ⚠ **本版含一处破坏性变更**：`digest` 的默认值由明文翻转为脱敏。版本号取 patch 是有意的
> （功能面无新增、无删除），但**依赖 `digest` 输出明文的脚本必须加 `--no-redact`**，
> 否则拿到的是打码后的值。详见下方第一条。

### Changed

- **★破坏性：`digest` 改为默认脱敏。** `fxapk digest <报告>` 不带任何参数时，钱包私钥 / 助记词、
  后端凭据、个人隐私数据、加密配方一律按类别打码；要明文原值须显式 `--no-redact`。
  函数层 `report.digest.build_digest` 的 `redact` 默认值同步由 `False` 翻成 `True`。

  **调用方须知**：依赖 `digest` 拿明文的脚本要加 `--no-redact`；直接调 `build_digest` 且不传
  `redact` 的代码现在拿到的是脱敏结果。完整明文一直在本地 `report.json` 里，不受此开关影响。

  翻转的理由是这个出口的实际用法：本工具的主推路径就是把 digest 喂给 AI，默认明文意味着
  「按最省事的方式用」等于把高敏原值交出去，而想要安全反倒得额外记得加参数——安全选项不该是
  要额外记得的那个。两类失误的后果也不对称：忘了加 `--no-redact` 只是少看见几个值、回头补跑
  即可；忘了加 `--redact` 则是原值已经出去了、收不回来。

- **维护名单中会把线索值打到 stdout 且不脱敏的命令现在各自如实声明**（往 stderr 打一行；
  stdout 仍纯净，管道与 `| jq` 不受影响）：`jsonl` / `diff` / `lead show|restore|replay` /
  `corpus events|ls|seen|shared-config|shared-native|shared-build-env|link-candidates` /
  `corpus link-discover|link-explain|link-groups --evidence-values raw` / `probe-leads` /
  `pcap-leads`。它们与 `digest` 同样
  面向 agent 消费，却走各自的路径、**不受 `digest` 的默认脱敏保护**——翻转 `digest` 之后若不
  说明，反而会造成「喂 AI 已经安全了」的错觉。

  名单在 `core.redact.UNREDACTED_AGENT_COMMANDS`，并由测试逐条**真跑 CLI** 验证接线（只调
  helper 锁不住「名单列着但忘了接」）。★名单是人工维护的、必然滞后——复审里连着三轮各补出
  一批。判断方法写在常量注释里：问「它的 stdout 会不会出现线索值」。真正的出路是反过来做
  ——让输出线索的命令默认脱敏、显式声明才给明文，那是另一刀。

### Docs

- **明确脱敏的边界**：只有 `digest` 受保护；`jsonl` / `corpus events` / `export` CSV /
  HTML / PDF / 文书 / `corpus` 存证 / `report.json` 若含高敏值不会替你脱敏。并写明脱敏是尽力而为
  ——保证高敏类别的值被 mask、自由文本里**模式化** PII（邮箱 / 手机号 / 身份证号 / 长数字串）
  被抹，而姓名、地址、境外号码这类无稳定形态的抹不掉。此前 `core/redact.py` 的模块注释还写着
  「digest 默认明文，仅 `--redact` 才脱敏」，与新默认值完全相反，一并改正。

- **三条默认行为写进 README / README.en / AGENTS 的开头**：`analyze` 默认联网（样本里的域名 /
  IP 会被拿去查公开数据库，这本身会向第三方平台披露分析对象）、`doctor` 与 `auto` 默认改设备
  （部署 frida-server、装抓包 CA，`auto` 还可能卸载原应用并清空其数据）、`digest` 默认脱敏。

  这三处此前文档与实现**相反**：README 写的是「想联网就加 `--online`」「体检顺带修用
  `--fix`」，读起来像「不加参数就不会做那件事」，而实际默认就做。AGENTS.md 里还有一处
  「`fxapk doctor`（不带 --fix，纯体检）」是明确的错误说明，已改为 `--no-fix`。

  AGENTS.md 另加 §0.0：agent 在一台新机器上首次驱动 `analyze` / `doctor` / `auto` 之前，
  须先把对应那条如实告诉用户；`auto --fix` 这类不可逆改动要先问再做。

## 1.5.0 — 2026-08-02

### Added

- **线索档位的抑制来源可以被撤销**。此前判据链一旦把某条线索压下去，压的原因只留在
  `notes` 的自由文本里，压完就是终点——人再判断「这条其实要查」时无处可写，改 `advice`
  又会在下一次重跑或运行时回灌时被同一条判据重新压回去。现在 `Lead` 带三个新字段：

  - `base_advice`：判据链自己得出的结论，在管线接缝处一次性封存（`seal_base_advice`），
    此后任何抑制都只往 `downgrades` 里加，不再改写它；
  - `downgrades`：`{来源 id: 说明}`，每一次降档都留下**是谁压的、为什么压**；
  - `legacy_effective_advice`：旧报告迁移时的 write-once 快照，保证老产物读进来档位不变。

  实际档位由 `models.effective_advice(base, downgrades, legacy)` 求值，`advice` 退化为
  物化缓存。撤销一条抑制来源，档位自动回到判据链原本的结论，无需人手改档。

  **这套求值只对带 `base_advice` 的新报告完整成立**。旧报告分两种：只有迁移快照
  `legacy_effective_advice` 的，撤销后恢复到的是那份快照、不是判据链的原始结论；两个锚点
  都没有的，`effective_advice()` 返回空串，调用方保留既有 `advice`——这类报告拒绝撤销。
  要拿到完整能力，对旧报告重跑一次分析即可。

- **新增 `fxapk lead` 命令**，三个子命令：`show`（看一条线索的判据链结论、各抑制来源、
  当前实际档位）、`restore`（人工放行一条被压住的线索）、`replay`（把已记录的放行凭据
  重新施加到一份报告上——换版本、补证据后重跑，人的判断不用重做一遍）。

  放行留**墓碑**而非直接改档：`report.meta["manual_restores"]` 里按
  `(category, value, source)` 三元组记录，重跑与运行时回灌都认它，不会再把这条压回去。
  放行凭据以 `restores.jsonl` 落在 corpus 里，`replay` 从那里读。

### Changed

- **四个出口都会标出人工放行**。`digest` / `letters` / `html` / `ioc` 在**各自实际呈现的线索
  中**，凡有人工放行记录的一律显式标出「这条是人放回来的、自动判据本来压住了它」。条件是
  「有墓碑」而不是「回到了最高档」——`digest` / `html` / 全量 `ioc` 里，一条被放行后仍被另一条
  抑制来源压在「待核」的线索照样会标出来。`letters` 是例外，但不是因为标记逻辑不同：它本就
  只对满足套打条件的最高档（`ADVICE_INVESTIGATE`）线索产生结果，其余档位在标记之前就已经不在
  它的输入里了。全出口可见是有意的：墓碑不做
  真伪校验，因此不能让「塞墓碑」比「改 advice」更安静——后者会被守卫挡下，前者若无声
  就成了更隐蔽的绕过路径。`letters` 另有独立提示句，避免据此套打时不知情。

- **档位常量的真源从 `core.infra` 迁到 `core.models`**（`ADVICE_INVESTIGATE` /
  `ADVICE_SKIP` / `ADVICE_REVIEW`，另加 `VALID_ADVICE`）。`core.infra` 仍可导入，取值不变。

- **降档原因从自由文本迁进结构化字段**。此前压档的理由拼在 `notes` 里、部分生产路径还顺手
  把 `confidence` 压到 `LOW`；现在理由一律进 `downgrades`，隔离类路径也不再压 `confidence`
  ——那是证据强度，撤销隔离并不会让证据变强或变弱，两件事本就不该绑在一起。按 `notes` 文本
  匹配降档原因的下游脚本需改读 `downgrades`。

- **报告 schema 由 `1.0` 升到 `1.1`**（`report.json` 的 `schema_version`）。这是向后兼容的
  字段扩展——旧报告缺新字段照常读、`advice` 行为逐字不变。**1.1 此前从未随任何发布 tag 出门**
  （截至 v1.4.0 写出的都是 `1.0`），自 1.5.0 起它成为在野契约。机器可见的新增字段：

  - `Lead`：`base_advice` / `downgrades` / `legacy_effective_advice`；
  - `report.meta.manual_restores[]`：每条墓碑含 `category` / `value` / `source` / `note` /
    `at` / `prior_advice` / `new_advice`。匹配只按前三项归一化后比对；`prior_advice` 与
    `new_advice` **仅作审计留痕**，重放时一律重算档位，不拿它们直接写回——否则一份换了版本、
    判据链结论已经变了的新报告会被旧档位覆盖；
  - `digest` 的每条 lead：`downgrades` / `manually_restored`；
  - `letters` 的每条结构化结果：`manually_restored`；
  - **IOC CSV 表头末列追加 `manually_restored`**——列顺序是下游情报平台的字段映射契约，
    新增一律追加、不插中间，但已配好映射的消费方仍需确认末列不越界；
  - `closure` 统计：`manually_restored` / `inconsistent_excluded`（后者记「档位与抑制账本
    互相矛盾、因而被挡在闭环之外」的线索数，多半意味着有人绕过 `fxapk lead restore` 手改了
    `advice`——它不静默，就是要被看见）。

- **新增持久化契约 `<corpus>/restores.jsonl`**。每行一条放行凭据，按
  `(sample_sha256, category, value, source)` 去重、同键覆盖，字段另含 `note` / `at` /
  `sample_sha256_synthetic`。**键里带 `sample_sha256` 是刻意的**：凭据是对某一个样本的判断，
  不跨样本生效——不同样本上的同名值完全可以是两回事。写入走原子全量重写。

- **`fxapk lead` 的机器输出与退出码**（自动化可依赖）：`show` 出 `leads` / `manual_restores`；
  `restore` 出 `lifted` / `refused_no_anchor` / `written` / `stored_in_corpus`；`replay` 出
  `sample_sha256` / `candidates` / `lifted` / `results[].status` / `written` / `dry_run`
  ——**这六个键在 `replay` 的每个出口都在、类型都一致**，包括「样本库里没有该样本凭据」那条
  早退分支（另附一个仅供人读的 `note`）。报告不存在、解析失败、线索或抑制来源匹配不上
  → **exit 1**；corpus 配置与安全边界类错误 → **exit 2**。

- **`commands.corpus._resolve_corpus` 更名为 `resolve_corpus`**——它现在是 `lead` 命令也走的
  公开入口，不再是 corpus 命令的私有 helper。**旧名未保留别名**（原名以下划线开头，按惯例不属
  对外承诺的接口）。

- **`models.merge_runtime_into_lead_dict` 返回值由 `bool` 改为 `tuple[bool, bool]`**
  （`(evidence_merged, ledger_changed)`），并新增关键字参数 `restored`。直接调用该函数的
  外部调用方须同步解包——回灌合并现在既可能只并证据，也可能只动抑制账本。

- **README 改成「对 AI 说三句话」的上手路径**，命令表纠错去重。

### Fixed

- **厂商推送接入段与公网 IP 回显服务挪出最高档出口**。25 条厂商推送、采集与应用市场主机进
  `KNOWN_INFRA_EXACT`（**精确主机名匹配，不是后缀**）；3 个公网 IP 回显服务降到
  `ADVICE_REVIEW`。精确匹配是刻意的取舍：能证明的只是「这些主机曾被厂商 SDK 使用」，
  证不出「该标签下永远不会出现第三方可控的名字」，而按整棵子树放行会在一份公开名单上
  留出藏身处。代价是厂商换区域主机名后噪音回流——那是安全方向的失效。

  回显服务只降 `ADVICE_REVIEW` 不判 `ADVICE_SKIP`：这类多由小主体运营、整域可被收购易主，
  且「样本去查自己出口 IP」这个行为本身有价值，判 `ADVICE_SKIP` 会把真实出网记录从四个
  出口一并抹掉。

- **厂商推送凭据补齐归属**。`config_keys` 此前只认下划线分词的键名，连写前缀
  （`MIPUSH_` / `OPPOPUSH_` / `VIVOPUSH_`）全部漏归属——分析器本来就提取到了这些
  `meta-data`，缺的是「归到哪家厂商」而不是提取通道。魅族 / 荣耀因证据只覆盖到具体键名，
  按 `exact` 收录，不放宽成前缀（`HONOR_` 这类宽前缀会把 `HONOR_THEME` 误归成推送凭据
  并升到最高档）。

- **对象存储的租户桶不再被云厂商整域豁免吃掉**。`<桶名>.<厂商端点>` 形态的域名是**租户
  自己**能控制的资源，与厂商基础设施不是一回事，此前被整域豁免连带放行。

- **厂商应用市场与钱包域名挪出建议核查出口**。

- **名单匹配定序**。匹配此前遍历集合，同一份报告在不同哈希种子下可能给出不同结果。

- **名单里的无点关键字全部收口为带点后缀**，消除跨域误命中。

- **被冒用的域名不再进 `letters` 出口（P0）**。非标准 TLS 端口上借用知名域名做 SNI 的连接，
  其被借用的域名此前会被判 `ADVICE_INVESTIGATE`，`letters` 据此套打出指向该域名持有方的文书
  ——把无关第三方列成了标的，是本项目定义中最重的一类误判。实测在一份真实报告里已对两个知名
  服务各生成了一份。

  根因是同一个域名有两条 Lead 生产路径，而保护只做在其中一条上：

  1. `dynamic.pcap_ingest.to_report_leads` 产的域名 Lead 只把警示写进 `notes`，未填结构化的
     `sni_masquerade` 字段（IP 侧一直填着，域名侧一直空着）；
  2. `dynamic.pcap_ingest.to_runtime_endpoints` 产的域名端点不带伪装事实，于是这些端点并入
     主报告后，`core.leads._domain_lead` 重新产 Lead 时只能按「陌生域名」判 `ADVICE_INVESTIGATE`；
  3. `models.merge_runtime_into_lead_dict` 本已实现该字段的并集搬运，但因来源字段为空而完全落空。

  同一份报告里因此出现四个伪装域名分裂成两种结局：进了 `endpoints` 的被套打出文书，没进的
  保住了警示——决定安全与否的是「有没有进 endpoints」这条与伪装判断毫不相干的路径分叉。

  四处一并修正：pcap 域名 Lead 补填 `sni_masquerade`；伪装事实随域名端点经
  `Endpoint.enrichment[SNI_MASQUERADE_KEY]` 传递；`_domain_lead` 读到即降为 `ADVICE_REVIEW`
  并附理由；`report.letters._is_actionable` 增加第四道条件——标的自身出现在自己的
  `sni_masquerade` 里即不套打，该闸与上游判据相互独立，上游任何一环退回也拦得住。

  只降到 `ADVICE_REVIEW` 而不判 `ADVICE_SKIP`：样本作者完全可以注册知名域名的近似域自用，
  一律排除会把真 C2 藏起来。真实标的（如对象存储的租户桶域名）不受影响，仍判 `ADVICE_INVESTIGATE`。

  **对已产出的报告不追溯**：历史报告的 `sni_masquerade` 字段为空，直接用新版套打仍会出文书。
  补救办法是对该报告重跑一次 `pcap-leads --into`，合并会补上该字段，出口闸随即生效。

### Internal

- SNI 伪装测试夹具改用合成段；注释与测试说明改用不指名的表述。

## 1.4.0 — 2026-07-30

### Added

- **网页证据成为一级输入**：新增 `analyze-web`，只读取已落盘的 `.body` / `.headers` /
  `.html` / `.js` 证据；网页专属分析器按文件分别记录静态跳转候选，不把不同文件拼成一条
  未经观测的跳转链。
- **批量多源富化**：新增可续跑的 NDJSON 台账与 `enrich` 命令，并接入 AbuseIPDB 被动查询。
- **提交前敏感信息扫描**：本地 hook 与 CI 共用同一套 leak-scan 判据。

### Changed

- **运行时清单字段迁移**：报告元数据从 `runtime_pcap_inventory` 迁移到
  `runtime_merged_inventory`，以统一 PCAP 与 probe 观测。`read_inventory()` 兼容读取新旧字段；
  PCAP/probe 写路径会写入新字段并移除旧别名。直接读取历史报告原始 JSON 的调用方必须同时
  接受旧字段，或改用 `read_inventory()`。
- **可见性快照 schema 升到 1.1**：每个来源维度新增 `inputs_seen`，记录该维度求值时**实际用到
  的输入键**。重算快照时据此区分「输入被裁剪」与「新增了信号」（见下方 Fixed）。1.0 旧快照
  迁移后顶层仍标 `1.0`，不冒充完整记录。消费方读 `inputs_seen` 前须容忍其缺失。
- **运行时端点携带完整端口集合**：每个 IP 的端点新增 `ports` 与 `remote_endpoints`
  （`"ip:port"` 列表）。顶层 `port` 保留为**代表端口**（流量最大的那个）以兼容既有消费方，
  但权威明细在 `ports` / `remote_endpoints`——不要再据顶层 `port` 假设「该 IP 只有一个端口」。

### Fixed

- **多端口运行时端点互相覆盖**：同一 IP 上的多个端口按裸 IP 合并时后者覆盖前者，只剩一个
  端口能进入端点观测。改为按 IP 聚合：端口取并集、字节数与连接数求和、载荷标志取或、
  时间窗取端点。
- **端点归一化只用于选取目标**：目标匹配已剥离 `:port` 后缀，但结果回写与文书渲染两处仍用
  裸 `lower()`，导致带端口的端点匹配不上同一目标。三处改为共用 `infra.match_key()` 这一个
  编解码器。
- **IPv6 端点被截断**：`host:port` 反解未区分 IPv6 —— 裸 IPv6 的末段本身是合法端口号，会被
  当端口剥掉。改用 RFC 3986 括号形态 `[v6]:port`，并把编解码收敛到
  `infra.format_hostport()` / `split_hostport()`。
- **重复回灌累加观测强度**：同一份抓包多次并入同一报告时，字节数与连接数被反复累加，虚增
  观测强度。加入按端点贡献计算的幂等指纹闸；闸只覆盖**具累加语义**的字段，覆盖写字段不受影响。
- **SNI 伪装信号只写不读**：借用知名域名的握手此前只落在自由文本里。改为 `Lead.sni_masquerade`
  结构化字段，跨报告往返保留，并在文书模板中于受文对象之前给出警示，避免把被冒用域名的持有方
  当作查询对象。
- **回灌不刷新派生视图**：PCAP / probe 并入报告时写了运行时标志与清单，却不重算
  `meta.visibility`，落盘的是分析期那份「纯静态」旧快照——报告同时写着「有运行时端点」和
  「未做运行时观测」。抽出 `refresh_visibility_snapshot(meta)`，两条写路径均在落盘前调用；
  两侧各加一条结构性断言「落盘快照 == 对该报告现场重算」，将来任何写方漏刷都会失败。
- **输入被部分裁剪时确证盲区遭解禁**：重算快照时若某维度的输入键只剩一部分（例如加固判定
  依据被移除、只留下一个无关键），该维度会被重算为「完整」，本已阻断的穷尽性结论凭空恢复。
  改为用 `inputs_seen` 做子集比对：当前键集是旧集合真子集即判为裁剪并回填原结论，否则跟随
  重算——脱壳后回灌这类**真实的**信号补全仍能正常升级。

## 1.3.2 — 2026-07-28

**两件事：Frida 17 的 Java hook 终于真的能用；构建环境串案第一次接上出口。**

1.3.1 里"供 Java bridge"只做了一半——宿主写了应答，注入端却从不发请求。
真机上的表现是：注入成功、进程存活、事件全空，与样本反检测一模一样，
一轮真实取参因此白跑，事后才从事件日志里残留的错误串认出根因。

另一件更值得记：`corpus` 的构建环境反查（`find_by_build_env` /
`shared_build_environments`）实现完备、注释里写着"实测一个构建标识横跨多个案件"，
却**没有任何调用方**。提取、解析、入库、反查四步全做了，就是没人调，
于是"这两个样本出自同一开发环境"始终得靠人工比对 JSON 才能发现。
接上出口当天就发现了三个长期存在的假阳性——它们一直在报告里，只因没人消费而看不见。

### Added

- **构建环境跨案反查有了出口**（`commands/corpus.py`）：
  `corpus seen --by build-env <标识>` 按构建标识反查同源样本；
  `corpus shared-build-env` 列出被 ≥2 样本共用的构建环境簇。
  构建路径是编译期烙进 native 库的，改文件名、重打包、重签名、换服务器都动不了它——
  比 `.so` 哈希（同族样本逐份随机化）和服务器 IP（转租机器上多租户共存）都耐用。

### Fixed

- **Frida 17 的 Java bridge 只做了宿主一半**（`dynamic/capture.py`）：
  Python `create_script()` 不会像 frida-tools REPL 那样安装语言桥的惰性全局，
  于是脚本引用 `Java` 时根本不会发出 `frida:load-bridge`，宿主的应答器在等一个
  永远不会到来的请求。现在在所有 Java hook 之前注入 REPL 的同款前导。
- **doctor 凭文件存在就宣称 bridge 可用**（`dynamic/doctor.py`）：
  出故障的真机上 `bridges/java.js` 自始至终都在，该检查会在整个故障期间报绿。
  改为如实表述"源码可取得（尚未运行时验证 `Java.perform`）"——
  运行时结论只能来自一次实际注入，看 `capture_signals.frida_bridges` 的三态。
- **测试套依赖开发机装了 frida-tools**（`tests/`）：CI 上四个平台全红而本机全绿。
  协议断言改为替身，真源码可读性单列一条按环境跳过。
  与 1.3.1 那次"测试依赖 adb 在 PATH"同类。
- **稀疏与第三方构建根污染跨案聚簇**（`core/corpus.py`、`analyzers/build_provenance.py`）：
  一份编解码库内嵌的 HEVC 测试码流路径曾让两个**互不相干**的样本聚成一簇。
  串案维度新增残留路径数下限——32 份真实检材实测，确认的构建环境集中在 26–32 条、
  噪音在 1–2 条，中间是空的，阈值取 3（留余量，宁可放进弱证据也不挡真环境）。
  该门槛**只作用于串案**，`meta.build_provenance` 仍全量如实记录：
  人核报告该看到弱证据，能不能拿去跨案聚簇是另一回事。
  另按项目根名识别放在任意盘符下的第三方 SDK 源码树（听云 / KOOM / Bugly / Matrix）。

## 1.3.1 — 2026-07-27

**这一版全部来自 1.3.0 在真实样本上被复现出来的问题。**

1.3.0 发布后立即用两个新样本做了端到端复跑，暴露出的不是漏检，而是**方向性错判**——
报告不是少说了什么，而是把读的人往错的方向指。三类：把"只观测到基础设施流量"当成业务闭环、
把版本号与协议标识符当成待调证的地址、把第三方开源作者的构建机当成样本作者的。
这类错误比漏检更贵，因为它们看起来像结论。

面向调证的三处关键变化：

- **建议调证的目标数量可能大幅下降，这是修复不是回退**：两个实测样本的建议调证 IP/域名
  从 41 条降到 0 条——该样本的真实后端在 native 控制面里，静态面本就没有可调证目标。
  此前那 41 条是版本号、序号与 ASN.1 协议标识符被当成了 IP。
- **闭环判定收紧**：只观测到单向的公共 DNS 查询不再算业务闭环；缺少双向载荷字段时按
  fail-closed 降为 partial。
- **构建路径的归属判定更保守**：新增"撤回"层——查过但证据不足以判第三方的构建根显式停在
  `unknown` 并带撤回理由，而不是悄悄消失在未知堆里。共现不足以证明作者身份。

### Fixed

- **单向公共 DNS 被判为业务闭环**（`network/fingerprints.py`、`dynamic/capture.py`、
  `core/closure/gates.py`）：新增公共解析器名单与 `is_infrastructure_endpoint`，
  按「IP 名单 ∩ DNS 端口」判定而非单纯按端口——后者会误杀自建 DNS。
  `complete` 现要求双向业务载荷 > 0。
- **closure 的候选被非地址串占满**（`core/infra.py`）：新增 `classify_ip`，与 `classify_domain` 对称。
  四段皆 ≤32 且无端口/URL 语境、ASN.1 OID 弧前缀、非全局地址一律降为待核。
  阈值以线索台账中 180 个已确认目标标定（最小 max-octet = 99）。
- **抓包工具的尾部元数据被当成载荷**（`dynamic/pcap_ingest.py`）：IPv4 按 `total_length`、
  IPv6 按 `40 + payload_length` 截断，字段不可信时回退实际字节。此前会凭空造出并不存在的 SNI。
- **源码文件路径被当成 API 端点**（`analyzers/api_surface.py`）：新增编译型源码扩展与
  代码符号形态两层过滤；语义标记改为按词边界对齐（驼峰在小写前切），
  避免 `logout` 命中 `auth`。实测候选从 54 条收到 1 条。
- **自建构建根整库未被扫到**（`analyzers/build_provenance.py`）：per-root 配额下沉到提取阶段。
  此前单个库内排在前面的噪声根会吃满全局预算，导致后面的自建根根本到不了收集侧——
  同批的另外两项修复因此在真实管线里全然无效。
- **部分 DEX 解析失败被汇总成全部成功**（`core/*`、CLI）：额外 DEX 的加载失败明细进
  `meta.extra_dex_visibility`，`visibility.dex` 相应降为 partial。
- **资源解析错误刷屏且计数为零**（`config/config_keys.py`）：候选匹配改为路径尾锚定，
  解析错误按类型聚合进 meta 而非逐条 traceback。
- **root attach 辅助命令的参数被重新分词**（`core/device.py`）。

### Added

- **native 控制面通道分析器**（`analyzers/native_config_channel.py`、`core/gobuildinfo.py`）：
  还原内嵌于 native 库中的对象存储模板与控制面符号，产出 Finding 与 `next_actions`，不产 Lead。
  Go buildinfo 以哨兵法解析；经 `-ldflags -X` 注入的凭据**只记指纹、原值绝不进任何输出**。
- **设备网络归因门控**（`core/device.py`、`dynamic/doctor.py`）：区分「样本反 Frida」与
  「设备本身网络不通」。★ CI 在此发现一个同类错误：无设备时 adb 写 stderr，
  旧解析会据此判定默认路由缺失——正是这个模块要防的错误，只是低了一层。
- **版本遮蔽自诊断**：`fxapk --version-verbose` 与 selfcheck 版本项，导入路径与分发版本
  不一致时退出码 1。

### Changed

- **构建根撤回层**（`analyzers/build_provenance.py`）：新增 `_WITHDRAWN_THIRD_PARTY_ROOTS`。
  经全样本实证，某构建根仅出现在携带同一套私有符号的样本中、该组之外零命中，
  原「第三方 SDK」依据不成立，予以撤回。**但不改判为自建**——同批样本中另一个个人根
  分布完全相同，却属真实的上游开源贡献者。撤回理由随分层结果进
  `meta.build_provenance.unknown`，不进用户可见正文。

**这一版的主题不是「多认出几种样本」，而是让报告说得出自己哪里没看见。**

加固样本的静态分析常常只看得到壳桩，而此前的报告会平静地输出几十条线索、零条警示——读的人
（尤其是自动消费报告的 agent）无从分辨「扫过了确实没有」和「压根看不见」。本版新增证据可见性层，
把散落各处的可见性事实归一成「哪些结论有资格下」，并接进 digest 与闭环判定；同时把此前
**产出了却无人消费**的一批信号接到消费方。

面向调证的三处关键变化：

- **读结果的顺序变了**：先看 `visibility`（哪里没看见）→ 再看 `findings`（看见了什么事实）
  → 最后 `leads`（该向谁调证）。digest 的字段顺序已按此排列。
- **判样本形态成为前置动作**：自研马甲包与正版重打包件的接口/域名/构建路径**归属完全相反**，
  后者属于被仿冒的厂商，误列会向无关企业发函。
- **修掉四处方向性错判**，包括「脱壳成功但结果没进主报告」与「CDN 边缘被当成源站」。

升级后建议对手头样本重跑一次并用 `fxapk corpus regress` 比对——那正是本版新增的、
用真样本判断「这次更新到底是不是正优化」的手段。

### Added

- **★ 证据可见性层（`meta["visibility"]`）**：新增 `apkscan/core/visibility.py`，把散落各处的可见性
  事实归一成「基于本次实际看到的输入，**哪些结论有资格下**」。
  - **解决的是最隐蔽的一类失真**：`dex_available` / `is_hardened` / `hardening_structural` /
    `dex_string_pool` / `native_obfuscation` / `artifact_lineage` 此前**产出了却无人消费**——
    一份壳桩样本的报告平静地输出几十条线索、零条警示，读的人（尤其 AI）无从分辨
    「扫过了确实没有」与「压根看不见」。
  - **四维来源** dex / native / resource / runtime，各自 complete·partial·stub_only·opaque·
    unavailable·unknown；**主张资格** `blocked_claims` 列出无资格下的穷尽性结论（静态端点已穷尽、
    未发现通讯录窃取、配置链已追全…）；**补法建议** `next_actions` 直接给出该跑 `unpack` 还是
    `capture`、或授权后重跑取配置。
  - **与 `analysis_status` 正交**：那是**工具执行**健康度，样本加固是**样本**属性；混同会让正常
    跑完的加固样本表现成「分析失败」，并冲击既有基线与 `--strict` 退出码。
  - **落到「主张」而非「分析器」**：`endpoints` 同时扫 DEX/manifest/资源/native，DEX 不可见时
    manifest 里声明的域名、pcap 实测的连接照样成立——被阻断的只是需要完整可见性的那几条。
  - **实测**：语料库 多份报告中 14 份 DEX 为壳桩，各阻断 6 条结论。最能说明问题的是同包对照：
    同一样本、同样 87 条线索 99 个端点，旧版报告说 `complete`、新版说 `stub_only`。

- **★ 真样本跨修订版回归对比**：新增 `fxapk corpus regress`，比对同一批**真实样本**换版后的检出变化。
  - **为什么需要**：合成基线（`tests/synthetic`）防的是「改坏」并进 CI，但实测中六个真缺陷
    **没有一个是合成测试发现的**，全部来自跑真样本。corpus 早已按 `(样本, 版本, 规则集)` 并存多份
    报告，缺的只是「拿它做对比」这一步。
  - **版本坐标是 `tool_version@完整 ruleset_digest`**：实测语料库里被重跑过的样本**全部**是同版本号、
    不同规则集——只按版本号切版会把一整轮规则改动量成「两版零重叠」。修订版按**入库顺序**排
    （manifest 无时间戳，字典序会让 `1.10.0` 排在 `1.9.0` 前面）。
  - **只忠实呈现 + 对方向明确的变化加注**，绝不给「优化 / 劣化」总评分——检出变多可能是误报涨了，
    变少可能是降噪，方向要人判。报告读不到时明确报「读不到」，**不当成零线索**。

- **构建来源 / 后端接口面 / 重打包判别三个分析器**（判据均先在 24 个真实样本上实证再写码）：
  - `build_provenance`：提取编译器写进 `__FILE__` 的构建路径并分层（第三方继承 / 疑似自建 / 未知）。
    自建构建标识进 corpus 作**串案维度**——同族 `.so` 文件名逐份随机、sha256 逐份不同，文件名锚与
    `native_lib_hashes` 家族反查双双失效，而构建路径改名、重打包、重签名都动不了。
    **分层只看构建根、只做前缀匹配**：私有构建根下常挂第三方源码，看整条路径会把私有平台误判成第三方。
    公共 CI 目录（Cloud Build 的 `/workspace`、Docker 惯用的 `/build`、Jenkins/GitLab Runner/
    TeamCity/Buildkite 等）一律不给「私有工作区」资格——否则任何在这些环境编译过的合法 SDK
    都会让干净 App 凭空多出一条取证结论。**用户名只进 `meta`、不进 Finding 正文**。
  - `api_surface`：提取后端 HTTP 接口路径并做功能语义标注（通讯录窃取 / 域名存活上报 / 远程配置下发 /
    对象存储 / 资金充提…）。三层过滤各自对应一类实测误报：段首大写＝Java 类名（实测拦下 42484 次
    命中）、`zza`/`zzb` 形态＝R8 混淆类名、已知第三方 SDK 固定段。**不产 Lead**——URL path 没有
    归属主体、无处发函。配置类路径单列 `config_endpoints` 供下游拼探测 URL。
  - `repack_identity`：判别**自研马甲包 vs 正版应用被重打包**。二者的接口 / 域名 / 构建路径归属
    **完全相反**：正版重打包件的这些资产属于**被仿冒的厂商**，列为线索会向无关企业发函。
    verdict 三态；措辞刻意克制——样本自身只能证明「被重签名」，**永远证不了「注入了什么」**
    （那需要与官方同版本包逐文件差分），故 Finding 不得出现「后门 / 植入 / 注入」字样，有测试把守。

- **配置探测预案（`meta["config_probe_plan"]`）**：把 `api_surface` 提取的配置接口路径 ×
  `asset_score` 靠前的后端域名拼成候选 URL，补上 config-chain 断掉的中间一环——此前有路径没 host、
  有下载能力没目标地址。**不做笛卡尔积**：host 取排序靠前的、总数封顶、**截断量如实上报**。
  passive（默认）只出预案、对目标零流量；authorized-active 才交给既有的下载解码链路。

### Fixed

- **★ 脱壳成功但结果没进主报告**：`unpack` 的回灌重分析产出的是**另一份** Report 对象（写成
  `unpacked_report.json`），而 `auto` 只收下路径、不替换手里的 report——于是 capture / merge /
  closure 与最终报告全都还在壳桩静态报告上跑：**步骤显示「脱壳成功」、报告里一条隐藏端点都没有**。
  现由 `unpack.run(on_reanalyzed=…)` 交出回灌后的 Report，`auto` 立为当前输入并写 `artifact_lineage`
  ——「脱壳成功」与「脱壳结果已成为当前输入」是两件事，必须分别可查。
  运行上下文（`online` / `mode` / `target_serial`）按白名单继承；`is_hardened` 这类**样本**结论不继承
  （脱壳后本就该重算）。★`online` 漏继承的后果是方向性的：`merge` 据它决定运行时线索要不要标
  「离线扫描，归属未查询」，一次 `--offline` 运行会把「压根没查」渲染成「查过」。

- **★ 基础设施分类依赖 YAML 键顺序**：`classify_network` 原为首个命中即返回，`Amazon CloudFront`
  撞上 cloud 的 `amazon` 就再也轮不到 cdn 的 `cloudfront`。误判方向是反的——CDN 边缘不触发
  `PUBLIC_CDN` 阻断、反落进「云 / IDC 自建托管」，**边缘节点被当成源站去调证**。
  改为按**类别专指度**裁决（不是关键字长度：实测中文形态直接反转，telecom 的「中国移动」长于
  cloud 的「移动云」，运营商系云被判成运营商、hosting 层整层落 None、调证方向从云商错指运营商）。
  ASCII 关键字加词边界（`Kingcore Electronics` 曾因含 `gcore` 被判 CDN，进而压掉可能的真源站）；
  通用英文品牌词换成专指形态（`limelight` → `limelight networks`）。

- **★ digest 完全不透 findings**：digest 是喂 AI agent 的低 token 消费面，此前只有 leads / closure /
  attribution / visibility——实测一个样本 **31 条 Finding 对消费方全不可见**，其中包括 HIGH 级结论，
  以及那条专为拦住「向被仿冒厂商发函」的重打包警示。现 findings 排在 visibility 与 leads 之间
  （顺序即研判次序：哪里没看见 → 看见了什么 → 该向谁调证），只列 CRITICAL/HIGH/MEDIUM 保住低 token，
  但**省略数与严重度分布一并输出**——静默丢弃会被读成「只有这些」。

- **★ 扫描截断只落日志**：实测一个 100MB 样本上 **11 个分析器同时截断 DEX 字符串扫描**，而 23 处
  调用里只有 1 处把这个事实写进 meta。截断是最隐蔽的可见性缺口——分析器「跑成功了」、状态全绿，
  只是没扫完，于是「未发现某接口」完全可能只是它排在截断线之后；而**日志不是数据面**，
  digest / closure / AI 都读不到。现共享 helper 把标记写进调用方 `result`（那是唯一能跨进程边界
  回来的东西），pipeline 按**或运算**合并而非覆盖（11 个都截断时，最后一个写 `False` 的会把事实
  整个抹掉），并记下是哪些分析器截断的。19 个读 DEX 的分析器全部上报。

### Changed

- **`closure.py`（1360 行）按职责拆成包**：targets（选靶）/ layers（五层组装）/ sources（富化源）/
  gates（验收），主流程与 re-export 面留在 `__init__`。生产行为不变（40 个顶层定义逐个比对
  函数体 AST，零差异；8 个模块常量零变化）。
  **两处有意的不兼容**：① 原模块「顺带导入」的名字（`os`/`ipaddress`/`Endpoint`/`ANALYSIS_*` 等）
  不再从包可见——它们本就不是本模块的 API；② 包级 monkeypatch 语义变化，打桩方向**分两类且相反**
  （被 `close_report` 直调的 patch 包、只在子模块互调的 patch 子模块），已在 `__init__` 顶部写明
  并有测试钉住分界。

- **容器级诱饵条目检测**：`packing` 分析器新增 `APK-CORE-NAME-DECOY-ENTRIES`——检出以 `/` 开头
  （ZIP 规范禁止的绝对路径）且首段恰为 `AndroidManifest.xml` / `classes.dex` / `resources.arsc`
  的条目，即精确冒充每个 APK 解析器必找的核心文件、意在让解析器撞上假条目。
  - **实测定标**：24 个真实样本中 7 个含此构造、共 411 条，首段无一例外只有那三种；端到端
    检出 7/7、误报 0/14。fxapk 自身经真样本验证不受影响（包名/清单/DEX 均正常解出）。
  - **提示的是下一步动作**：别用会落盘解压的工具直接展开该样本，绝对路径条目在不同工具下行为不一。
  - **不做家族归属**：实测各样本扩展名分布逐构建随机化，细粒度签名当不了家族键，故只报手法、
    不指名工具；明细写入 `meta["container_decoy_entries"]` 供跨样本比对。

- **DEX 字符串池不透明度（可信度信号）**：新增 `dex_obfuscation` 分析器（自动跑），度量字符串池中
  「结构性不可读」串的占比，命中产 `DEX-STRING-POOL-OPAQUE`。
  - **解决的是静默失明**：编译期字符串混淆器把 dex 字面量整体加密后，`endpoints` / `contacts` /
    `config_keys` 等依赖字符串池的分析器会集体抽空，报告于是干净地写着「未发现网络端点」——而真相是
    看不见。本 Finding 明说「此处的『未发现』不可解读为『不存在』」，并指向运行时取证。
  - **不指名任何工具、不产任何端点或线索**，只度量输入的可读性；画像恒写进 `meta["dex_string_pool"]`
    （不论是否命中），使「我们究竟看到了多少」可复核。
  - **假阳防线**：只认结构性不可读（控制字符 / 私用区 / 代理码位 / 近随机码位分布），
    **CJK・西里尔・阿拉伯・假名一律算可读内容**——中文 App 的非 ASCII 字符串不会被误判；
    另需样本量达标 + 「不透明占比高」与「可读占比低」双边同时成立才报，类型描述符与方法签名
    （恒存在、不随混淆消失）排除出统计以免稀释比例。

- **抗 fork 的内嵌 syscall 载荷检测**（re_toolkit）：认**手法本身**而非「是哪个库」——DEX 里存在长
  base64 文本、解码后不是任何已知容器格式（ELF / ZIP / PNG / 证书…）、且含**指令对齐**的 syscall
  编码，即产一条技术级命中并置 `anti_frida`。
  - **为什么这条抗 fork**：字面量锚点（包名 / 错误串 / 具体 base64 值）在 fork 改名、改措辞、重新
    编译后全部失效；但「把可执行的 syscall 桩当文本字面量塞进 DEX」是这套手法的**必要构造**——纯
    Java 进不了内核，必须先有机器码再 mmap 成 RWX 执行，改掉功能就没了。
  - **压假阳**：只用 4 字节定长指令集（arm64 / arm32 / riscv64 / mips）；排除容器魔数；候选串设最短
    长度、单载荷设 64KB 上限（真实 syscall 桩仅 1.8~3.4KB），大于 8KB 的载荷另要求 ≥2 处命中以抵消
    扫描位置增多带来的碰撞概率。x86 的 `0f 05` / `cd 80` 仅 1~2 字节、随机噪声里常见，**有意不作判据**，
    代价是纯 x86 载荷检不出（真实移动样本压倒性是 arm）。
  - **额度记账不静默**：候选数与累计解码量触顶一律 `warning`，使「本次未命中」与「没查完」可区分。
  - 上游七架构真实 shellcode 在「包名改光、错误串删光」的模拟 fork 下实测 5/7 命中。

- **`re_toolkit` 规则新增 `dex_strings` 字段**：匹配 DEX 字符串**内容**子串（大小写敏感，base64 载荷
  必须），命中记**强证据**——R8/ProGuard 只重命名符号、从不改字符串内容，故可扛住改名与重打包。
  据此给 LibcoreSyscall 补上七个架构的 shellcode base64 首段与三条本项目独有措辞的错误串
  （均于 2026-07-25 逐字节核实上游源码）。原有包名前缀**保留**：该库自带 consumer ProGuard keep 规则
  并由 R8 自动合并，正常引 AAR 的 App 里包名不会被改名。
  ★ 局限已记入规则注释：上述锚点**扛不住 DEX 字符串加密**；那种样本会由 `dex_obfuscation` 报
  `DEX-STRING-POOL-OPAQUE`，正确结论是「静态不可判定」而非「未使用」。

- **★ 未知壳的结构判据**：`packing` 新增 `PACK-UNIDENTIFIED-STUB-DEX`——DEX 只剩壳桩
  （字符串数远低于真实 App）且存在 App 自有 `.so` 时，即便**未命中任何厂商特征**也判「疑已加固」，
  并明说静态端点不完整、需脱壳或转运行时。
  - **解决的问题**：厂商识别靠 so 名/特征文件/包名等已知特征，遇未知壳或自研壳全部落空、报「未加固」
    ——而真相是 Java 侧几乎什么都没抽到，报告却让人以为静态结果完整。实测三个真样本正是如此：
    `classes.dex` 仅 1~3KB、DEX 字符串 15~57 条，却被判「未加固」。
  - **阈值有实测依据**：真实样本标定，加固样本 DEX 字符串 15~440 条、正常 App 12867~299356 条，
    相差 29 倍，故取 1000 有充足余量；端到端 **命中 8/8、正常 App 误报 0/9**，厂商已识别的 7 个不重复报。
  - **只报手法不认厂商**：不写 `packed`（那是厂商归属，写了会误导「向该厂商调证」），
    只置 `is_hardened` 与 `meta["hardening_structural"]`。
- **自带域名解析检测（取证可见性信号）**：新增 `dns_bypass` 分析器，检出 App 内含 DoH 客户端
  （RFC 8484 的 `application/dns-message` 线格式 / `/dns-query` 路径）或商用 HTTPDNS SDK，
  命中产 `APP-MANAGED-DNS-RESOLUTION`。
  - **解决的问题**：这类实现把 DNS 查询封进 HTTPS 发给指定解析器、**不经过系统 DNS**，于是
    PCAP 只看得到一条到解析器的 TLS 连接、看不到查了哪些域名，设备/网关 DNS 日志同样为空。
    Finding 明说「DNS 日志里没有某域名**不能**推出该 App 没访问过它」，并给出替代取证路径
    （TLS SNI / keylog 解密后的 Host 头 / 直接看连了哪些 IP）。
  - **是能力信号不是罪状**：商用 HTTPDNS 合法常见，实测 24 个真样本中 13 个具备该能力，
    故严重度定 LOW；仅出现公共解析器主机名（可能只是配置默认值）**不单独触发**。
  - **.so 全量扫而非采样**：共享的 .so 采样助手按头/中/尾窗口取样，会漏掉大库中段的标记
    ——实测采样版只命中 6 个、全量版命中 13 个。可见性信号漏检等于错误地告诉办案人
    「DNS 是可见的」，比误报更糟，故这里按字节全量搜（单库 64MB / 累计 256MB 上限，
    读前先查声明大小，触顶留日志）。

### Fixed

- **★ 调证清单不再被解析器 / 证书链基础设施和 URL 残片污染**：实测两案时发现调证清单里塞满公共
  DNS、STUN 与证书吊销列表，且闭环仅有的 6 个调证目标名额被以 `1.` 开头的解析器 IP 占满
  （纯静态报告上目标排序会塌缩成字典序），真候选 54 个一个没评估。三处修：`KNOWN_INFRA` 补公共
  DNS/DoH、STUN、CA/CRL/OCSP 域名；`noise_ips` 补公共解析器 IP；**URL 派生 host 现在也要求 TLD 可信**
  ——`.so` 的 ASCII 串被分块切分会留下 `http://www.hortcut` 这类残片，裸域名通道有 TLD 白名单挡着、
  URL 通道却没有。判据用 `_COMMON_TLDS`（含 top/cc/info/me/online 等真 C2 常用 TLD）而非更窄的
  `_SAFE_BARE_TLDS`，避免误杀真线索；另把 RFC 2606/6761 保留 TLD 收进白名单（永不解析、零误报风险）。
  - **不是新引入的缺陷**：相关代码来自首个提交，旧样本同样含此类残片，只是淹没在上百条端点里未被注意。
- **★ 一个垃圾条目不再判死整个样本**（「拒绝分析」式诱饵炸弹）：zip 炸弹前置拦截原本对**任意**
  声明超限的条目就拒绝整个 APK。但 androguard 急切解压的只有 `AndroidManifest.xml` /
  `resources.arsc` / `classes*.dex`——真实语料里 多个样本各塞了一对 `res/1.xml` + `assets/1.xml`，
  声明 1000MB、压缩仅 5.5MB（三样本参数完全一致，同一工具注入），它们不在急切解压之列，却让整个
  样本被判死、什么都分析不到，**攻击者用我们自己的防护达成了完全的分析拒绝**。
  改为只对核心条目 fail-fast，非核心超限条目 `warning` + 跳过（仍由 `read_file` 逐条闸拒读，
  绝不真解压，OOM 防护未削弱）。另新增 `APK-DENIAL-OF-ANALYSIS-BOMB` 把该构造作为反分析信号报出。
  - **实测**：最近 5 天样本从 2/4 可分析变为 **4/4**；此前被判死的样本现产出 119 端点 / 107 线索。
- **syscall 载荷扫描的候选饥饿与单候选超预算**：候选计数原在解码**前**自增、达上限即中断，海量无关
  长 base64 会把排在后面的真载荷**静默挤掉**；累计预算又在解码**后**才扣，单个巨串可先完成整体分配。
  改为解码前按 base64 长度预估大小、超单载荷上限直接跳过且不扣预算，累计预算改为解码前扣的硬上限。
- **字符串池不透明度把 emoji 判成混淆**：合成 emoji 用 ZWJ(U+200D) 连接、其 Unicode 类别正是 `Cf`，
  实测家庭 emoji 占比 43%、职业 emoji 33%，双双越过不可读阈值；而 emoji 又不计入「可读」，于是
  emoji 用得多的正常 App 会同时踩中两条判据被误报。改为 ZWJ 与变体选择符不计入不可读、emoji 与
  图形符号计为可读内容。
- **类型描述符判据误排普通文案**：原判据「首字符 `L`/`[`/`(` + 含 `;` 或 `)`」会把
  `Login failed; retry later`、`(optional) phone number`、`(点击重试)` 当成描述符排除，而被排除的串
  不进分母、反而抬高不透明占比。改为按 JVM 描述符完整语法匹配。
- **字符串池统计新增总字符量上限**：原条数上限约束不住「少量超长串」的对抗构造，触顶 `warning`。

## 1.2.0 — 2026-07-25

Theme: **功能收敛 + 结果可信度**。三条线：①**收敛**——移除从未真正落地或半弃用的支线
（iOS / webcheck / graph / track / intel），以及一个 12/12 全为误报的检测类型（contacts 手机号）；
②**修静默损坏**——一批「不报错但结果悄悄错」的缺陷（.env 加载 / 远程配置解码 / 子进程编码 /
CFB8 解密 / IOC 导出 / 富化器内存与 SSRF / 报告转义与脱敏）；③**家族取证**——新增 native 库家族
指纹与反查、算法下发通道枚举、端口归一化反推（静态×动态交叉校验）。

> ⚠ **含破坏性变更**（详见下方 Removed 各条的「对调用方影响」）：`fxapk graph` / `fxapk track`
> 子命令与 `--track/--no-track` 开关移除、`[graph]`/`[track]` extras 移除、`.ipa` 不再受理、
> webcheck 的 3 个环境变量不再读取、`report.meta["contacts"]` 不再有 `phone` 键。
>
> 贯穿本版的一条原则：**宁可漏，不可造**——静态/被动路径上，若某启发式能凭随机字节产出看似权威的
> 调证目标（IP / 域名 / 端点），一律不做。已评估并否决的方案记录在 `AGENTS.md` §6，含否决理由与
> 「前提何时才算变了」，避免被反复重提。

### Added

- **端口归一化反推 / 静态×动态交叉校验**（A2）：新增 `fxapk port-normalize` 与 `config/port_norm.py`。
  部分家族配置里存 raw 端口、运行时才按固定规则算真实端口；本命令把**解密所得的声明端口**与
  **fxapk 实测到的连接端口**（`endpoints[].enrichment.runtime.remote_endpoints`）按 IP 配对，在有界假设
  空间（identity / +常量 / +IP末段+常量）里反推能解释全部配对的最简变换，并给出支持与反例明细。
  不产生任何端点；同一 IP 多个实测端口判 `ambiguous` 不擅自选；配对不足或数据过于齐整（声明端口全同 /
  IP 末段全同）判 `degenerate` 拒给结论。声明端口由调用方提供，**不入仓**。
- **native 库家族指纹**（#234、#239）：新增 `native_fingerprint` 分析器，对 App 自有 `.so` 逐个算 sha256
  写入 `report.meta["native_lib_hashes"]`（同族样本核心 `.so` 常逐字节相同，是比签名证书更硬的家族锚点）。
  corpus 新增 `seen <sha> --by so_sha256` 家族反查与 `corpus shared-native` 跨样本共享库聚簇。
  读取前先查 zip 声明的解压后大小、超 64MB 直接跳过（不膨胀进内存）；同名多 ABI 变体各自哈希，不按 basename 塌缩。
- **算法下发通道枚举**（#235、#241）：新增 `fxapk config-channel` 与 `config/algo_channel.py`，按
  `MD5(前缀 + yyyyMMdd) + "." + 基域` 枚举**运行时算法生成**的配置子域候选（静态不存在、跑起来才拼，
  常规 URL 抽取认不出）。前缀/基域由调用方提供，模块内**不含任何具体前缀或域名**。日期临近年界时同时产
  相邻年候选，覆盖 Java `SimpleDateFormat("YYYYMMdd")` 大写 `YYYY` 的 locale 相关周年语义。
- **native 运行时取址占位 Finding**（#233、#240）：硬编码**非标准**回环地址（非 127.0.0.1）+ 存在 native 库
  → 产 `NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER`（低置信启发式）。此前这类 127.x 被"裸 IP 去噪"静默丢弃，
  丢掉了「真后端由 .so 运行时决定、127.x 只是本地代理占位」这一家族级架构信号。证据按实际来源
  （dex / manifest）标注。

### Removed

- **半弃用组件 graph / track / intel**：删除 `apkscan/graph/`（Kuzu 案件图谱串案）、`apkscan/track/`
  （flask 网页台账）、`apkscan/intel/`（未接线的 intel providers），及 `commands/graph.py` /
  `commands/track.py`。串案已转 corpus 反查 + 上下文关联；这三者「仍可跑但不再迭代」，留着只增维护面与
  可选依赖（kuzu / flask）。`config/string_graph.py`（jadx 串链降噪）与 `attribution/graph.py`（五层归因）
  是同名但**活跃**组件，保留不动。
  - **对调用方影响**：`fxapk graph ...` / `fxapk track` 子命令消失；`analyze` / 静态命令去掉
    `--track/--no-track` 开关（写报告后不再自动入台账/喂图谱——脚本传 `--no-track` 需移除该参数）；
    `pip install fxapk[graph]` / `fxapk[track]` extras 与 kuzu / flask 依赖移除；batch 不再喂图谱。
- **iOS IPA 支持**（#215）：工具收敛为**仅分析 Android APK**。删除 `core/ipa.py`、`core/macho.py`、
  `analyzers/ios_plist.py` 与 `core/loader.py` 的文件类型分流（CLI 直接 `load_apk`），pipeline 恒注入
  `apk` 能力、去掉 `ipa` 能力与 iOS 降级分支。IPA 路径从未超出静态 Info.plist / Mach-O 字符串提取、无真实用例。
  - **对调用方影响**：CLI 只收 APK——传 `.ipa` 报解析错误退出码 2；`ipa` 能力消失（`requires=["ipa"]`
    的分析器永不运行）；输出不再有「类型：IPA(iOS)/APK(Android)」行。
- **webcheck 富化器**（#214）：它是全仓**唯一 `active=True` 富化器**；其信号改由被动源 / PCAP 管线覆盖。
  `exposure.build_host_fingerprint` / `assess_tech_stack` 与 `forensic.classify_jurisdiction` 收敛掉
  webcheck 形参，attribution 不再读 webcheck 子键（保留 `signals["response_headers"]` 契约），selfcheck
  去掉 webcheck 组件。
  - **对调用方影响**：`FXAPK_WEBCHECK_URL` / `FXAPK_WEBCHECK_CHECKS` / `FXAPK_WEBCHECK_TIMEOUT` 三个环境
    变量不再读取；`--mode authorized-active` 当前不再放行任何「主动富化器」（模式门保留、fail-closed，
    未来新增主动富化器须显式 `active=True`），该模式现放行的是远程配置对象下载与 Telegram getMe 在线核验；
    上述 exposure/forensic helper 去掉第二个参数。

### Fixed

- **.env 加载**（#212、#213、#216）：未加引号值按首个「空白+`#`」剥行内注释（避免中文备注并入 key 后当
  HTTP 头触发 UnicodeEncodeError），空白判定用 `str.isspace()` 覆盖全角空格 U+3000 / NBSP；带行尾注释的
  引号值按**配对收尾引号**切分；改用 `utf-8-sig` 读并剥 BOM；非 UTF-8 文件从静默跳过改 **WARNING** 明示整份
  未加载；空占位行（`KEY=` 及引号空串 `KEY=""`）不再注入，以免高优先级 .env 的空值**静默掩蔽**低优先级
  文件里配好的真实值；注入以 debug 记「键名←来源文件」（不回显值）。新增 `tests/test_dotenv.py`。
  - **对调用方影响**：未加引号 `.env` 值在首个「空白+`#`」处截断（值若含字面 ` #` 须加引号）；空占位行不再
    把环境变量置空（要空串请用真实环境变量）。
- **远程配置 base64 解码**（#217）：判形前 strip 而解码用原文 + `validate=True`，带尾随换行 / MIME 76 列
  折行的 base64 配置会**静默解不开**（`decoded=False, chain=()`）。改为判形与解码共用同一份去空白的规范化文本。
- **子进程编码 / CFB8 解密 / 错误归类 / 不泄密诊断**（#218，六处，各配「无修复即失败」回归测试）：
  - `appcrypto._build_mode` 按段位构造 CFB8 / CFB128（此前忽略 `segment_size` 恒按 CFB128、把 `AES/CFB8`
    密文解成乱码；不支持的段位改为拒绝而非静默出错）；`cryptohook._norm_mode` 保留 CFB 尾随段位数字，使
    recipe 端到端携带段位。
  - `multisource._safe_error_type` 把 `UnicodeError` 归 `request_encoding_error`（此前落进 `ValueError`
    分支误报 `parse_error`）。
  - `case close` 失败日志补记末 5 帧调用位置（文件:行:函数），仍**不写异常消息**以防 provider 敏感响应片段入日志。
  - `jadx` / `pdf` 的 `subprocess.run` 显式 `encoding="utf-8", errors="replace"`，避免 GBK 默认编码的中文
    Windows 上读取线程崩溃、丢光 stderr。
  - **对调用方影响**：富化 `error_type` 新增取值 `request_encoding_error`（匹配该字段的脚本 / CI 需更新）；
    解密配方 `mode` 值可能从恒 `CFB` 变为 `CFB8` / `CFB128`（精确匹配 mode 串的消费方注意）。
- **IOC CSV 公式注入**（#219）：`report/ioc.py` 的 `write_csv` 在写入层对首字符为 `= + - @`、Tab、CR 的
  单元格前置单引号（IOC 值直接来自不可信样本，未转义会在 Excel/WPS 被当公式执行）；改为按 `IOC_COLUMNS`
  投影写入，任何拼行路径都无法绕过。
  - **对调用方影响**：如 `+86…` 联系号会写成 `'+86…`；机器精确匹配 `ioc.csv` 值的脚本，应**仅当**剥掉的首
    字符确为上述触发符时才剥一个前导单引号（合法值本身以 `'` 开头不受转义、不可无条件剥）；列 schema / 表头不变。

### Chore

- `.env.example` 增补 `FXAPK_DAYDAYMAP_KEY` / `FXAPK_DAYDAYMAP_KEY2` 槽位与 DayDayMap 调用要点（POST /
  标准而非 urlsafe base64 keyword / API-KEY 请求头 / 响应仅含请求 fields）+ 多账号轮换规则（KEY→KEY2，
  仅配额/限频错误才切换）+ IP 维度返回的 ICP 备案属该 IP 上共同托管站点、非 IP 持有人的语义差异（#210、#211）。
  DayDayMap 由 OneDrive 多源富化工具消费，主仓 `analyze` 不直接调用。

## 1.1.0 — 2026-07-19

Theme: **1.0.0 后的安全与精度加固**——一轮全项目审计 + 对抗式复审后的正确性 / 输出安全
修复，加上把静态密文候选从"高误报启发式"收敛成"高精度 + 可复核"。

### Added

- config-chain `string_graph`：补**字段常量密文召回**（类作用域，只走消费档、不跨方法误绑），
  覆盖"密文常量在类字段、解密在方法内"的混淆写法（#196）。

### Fixed

- **未信任输入的资源上限**：zip 解压 / 远程下载 / 富化 JSON 响应 / 分析器窗口读，均加硬帽，
  防畸形样本打爆内存 / CPU（#200）。
- **androguard 前置 zip 炸弹守卫** + PDF 渲染沙箱化 + case close 时保留 `network_attribution`
  附加视图（#201）。
- **case close / attribution 收尾**：闭环后刷新归因派生视图、清理陈旧目标标记；修三处
  case-close / attribution 缺口（#198、#202）。
- **动态 / 报告**：全项目审计挑出的正确性与输出安全问题（markdown 注入转义、pcap 解析
  边界、socket 归因时间戳）（#199）。

### Removed — 静态密文的 Tier A 确定性自动解密（`_stage_decrypt_candidates`）

跨多个样本实测：该阶段一次都没有真正执行过（`decrypt_candidates_auto` 恒为
`{"attempted":0,"reason":"no crypto_recipe"}`）。原因是结构性的而非偶然——密文候选来自
jadx 反编译的 **Java** 代码，而配方只从 **JS bundle** 逆出（`crypto_recipe` 仅扫
`assets/` `**/www/` 与 RN bundle），两者无文件、调用点或数据流关联；把 JS 侧的 AES 流量
密钥套到 Java 侧字符串混淆器的密文上，对 44 条真实候选实测 0/44 可解。

**对 agent / CI 调用方的影响**：`report.meta["decrypt_candidates_auto"]` 不再产出，
`source="config-decrypted"` 的端点不再出现，`meta["stage_status"]` 中不再有
`decrypt_candidates` 阶段。`schema_version` 不变——这两个 meta 键本就是条件性存在
（无候选时不写），消费方必须已能容忍缺失。

**保留不变**：`report.meta["decrypt_candidates"]` 待解密线索清单（供人工 / AI 恢复）、
`crypto_recipe` 配方提取、`appcrypto.decrypt_envelope`（解**运行时抓包**的
`{data,timestamp}` 信封——这才是它的设计用途）、以及远程配置链的下载 + 多层解码回灌。

### Changed — 静态密文候选降噪（`config/string_graph`）

跨 4 个静态可见样本，候选从 230 条压到 3 条（含全部 2 条真实自有密文），新增三道压制：
第三方库路径整文件丢弃；聚集 ≥5 条纯 hex 常量的密码学参数表文件整体丢弃（混淆器会改
BouncyCastle 的包名，但"一个类里躺着几十条定长 hex 常量"的形态改不掉）；算法
transformation 串、字符两两不同的字母表/置换表、顺序字节测试向量不再判为密文。

### Changed — 压制改为"打标不丢弃"，范围收窄（`config/string_graph`）

上一条的两道**文件级**压制，其判据都落在**样本可控的输入**上——源文件路径由包名决定，
hex 常量条数由字面量决定——而命中即静默返回 `[]`。对抗审计复现出两条规避路径：

- ProGuard `-repackageclasses`（或任意混淆器）把自有解密类重定位进 `com/google/android/gms/internal/`，
  同一个 `{Cipher.getInstance + 真密文}` 类在自有路径下出 1 条链、在第三方路径下出 0 条。
- 往含真密文的方法里掺 5 条裸 32 字符 hex 字面量，即可让该文件连同真密文一起被丢。

两条都改掉：压制不再丢弃候选，而是在 `StringChain.suppressed` 上打原因标
（`third-party` / `param-table`），由调用方决定不呈现；参数表规则的标记只落在**hex 链**上，
同文件里的 base64 密文链不再被牵连（参数表按定义全是 hex，规则解释不了非 hex 的那部分）。
`analyzers/jadx` 把压制量按原因计数写进 `report.meta["decrypt_candidates_suppressed"]`——
压制因此可计数、可复核，规避手法至少是可见的。

第三方路径保留一处早退：路径命中**且**全文无任何标准解密 API 迹象时不扫（真实 APK 里这是
绝大多数文件，是这条路径的性能前提）；代价是这些文件里仅靠 consumer 成立的弱档链不被计数。

**对 agent / CI 调用方的影响**：新增条件性 meta 键 `decrypt_candidates_suppressed`（无压制时不写）。
`decrypt_candidates` 的内容不变——14 个真实样本的呈现候选逐条一致（+0 −0），`schema_version` 不变。

## 1.0.0 — 2026-07-18

Theme: **PCAP-first 网络证据 + 五层基础设施归属 + 资产沉淀**——动态从"HTTP 代理式抓包"
转向零注入的 PCAP 底座解析；把"IP 归属"从扁平的所属公司升级为五层不塌缩的归因链；
把历次分析的 report.json 沉淀成可查询、可回归、可重建的语料库。

### New — config-chain（`apkscan/config`）：加密远程配置链

- 发现 App 引用的 OSS / CDN 配置对象（`REMOTE_CONFIG` 线索）；授权档（`--mode authorized-active`）
  获取并多层解码（gzip / base64 / AES / JSON），解出动态后端域名 / IP 池回灌五层归因，原始对象落盘留存。
- 控制链对象 `report.meta["control_chains"]`：APK → 配置对象 → 解密配置 → 域名 → IP → IDC 拼成单链。
- 后端资产加权排序 `report.meta["asset_scores"]`；corpus 按远程配置对象跨样本串案（`corpus shared-config` /
  `corpus seen --by config-object`）。
- 方法级 密文→解密 启发式绑定（`string_graph`）：混淆改名的解密 helper 也给出**待解密线索**
  `report.meta["decrypt_candidates"]`（完整密文 + 上下文，供人工 / AI 恢复）；配方已知时本地自动解密回灌
  （★该自动解密已在 1.1.0 移除，见上；待解密线索本身保留）。

### New — 五层基础设施归属（`core/attribution`）

- 每个域名 / IP 端点富化后组装成**五层不塌缩**归因链，写进 `endpoints[].enrichment["attribution"]`：
  `resource_holder`（IP 资源登记方，IP-RDAP）→ `origin_network`（BGP Origin ASN）→ `hosting_provider`
  （云 / IDC）→ `edge_provider`（CDN / WAF / 边缘代理，多信号加权指纹）→ `service_operator`
  （实际运营者，**恒 unknown，绝不从 ASN / RDAP 推断**）。域名按解析到的每个 IP 逐个产链（per-IP，不合并）。
- edge 指纹为多信号加权：`confirmed` 须 ≥2 个独立强信号（单一响应头可伪造，最多 `probable`），
  负证据（只命中公有云 ASN / 通用 X-Cache / nginx）抑制"租了公有云就当代理坐实"的误判。
- 新增 `ip_rdap` 富化器（`rdap.org/ip` 查网段登记方）填 `resource_holder`——仅认 RDAP `registrant` 实体，
  不拿 abuse / technical 联系人或域名注册方冒充 IP 资源持有方。
- 调证函（`fxapk letters`）新增「基础设施归属链」段，按落地 IP 分层展示，直接支撑"向谁调证"。

### New — 动态 PCAP-first 网络证据

- 零注入 PCAP 解析：TLS ClientHello 跨 TCP 段恢复 + SNI / ALPN 提取、QUIC v1 Initial 解密与 SNI 提取。
- socket 精确归因：TCP / UDP / IPv4 / IPv6、持续 socket 时间线、多 UID 候选时输出**歧义**而非硬猜一个。
- TLS Key Log + tshark 解密链路；HTTP/1.1 · HTTP/2 凭据（Authorization / Cookie）提取与脱敏。
- `floor-only` 模式不再误依赖 Frida；`doctor` 体检覆盖 PCAP 深度能力（QUIC 元数据 / 解密 / tshark 就绪度）；
  报告记录 `build_commit` 溯源。

### New — `fxapk corpus`（样本库）

- **`corpus add REPORT... [--case] [--corpus]`** —— 把一份/多份 report.json
  入库：报告原样字节存进 `reports/<sample_sha256>/<tool_version>_<ruleset_digest>.report.json`，
  并登记进 `manifest.jsonl` 派生索引。库内主键 = `(sample_sha256, tool_version,
  ruleset_digest)`：同样本同版本同规则重复入库**幂等跳过**，换版本/换规则则并存新报告
  （天然做跨版本回归基线）。旧报告缺 `sample_sha256` 时按内容派生 `nosha-` 占位身份、不塌缩。
- **`corpus seen VALUE [--by sample_sha256|package_name|sign_sha256]`** ——
  「见过没」反查；`--by sign_sha256` 按共享签名证书一击串案。
- **`corpus ls [--package|--case|--packer|--type]`** —— 过滤列举。
- **`corpus reindex`** —— 扫 `reports/` 全量重建 manifest（自愈索引；report.json 是唯一
  事实源，只从旧 manifest 继承人工 `case_id`）。
- **`corpus events SHA256`** —— 复用 `report_to_events` 把库内报告吐成 JSONL 喂 agent。
- 地基不引入任何新存储引擎/依赖（不复活图谱/SQLite 台账）；`manifest.jsonl` 是可重建缓存、
  非事实源。

### Safety

- 语料库含真实案件数据（IOC/案件号），根目录**必须**经 `--corpus` 或环境变量
  `FXAPK_CORPUS` 显式指向库外（OneDrive），二者皆缺即**拒跑**（exit 2），绝不默认 `./corpus`；
  且根目录若落在 git 工作树内一律拒跑（防案件数据随 `git add` 混进公开仓库）。
- CI 守卫 + `.gitignore` 覆盖真正的 PII 载荷 `*.report.json`（报告全文），而不仅是派生索引
  `manifest.jsonl` / `ioc_index.jsonl`——git 跟踪的文件里出现任一即 CI 红。
- **取证字节保真**：报告原样存证（`corpus add` 读侧 `read_bytes` + 原子写禁用换行翻译），
  落盘字节 == 原文；不同主键净化后落同一路径时，写盘前**拒绝覆盖**已入库的取证字节（路径碰撞守卫）。

## 0.9.0 — 2026-07-13

Theme: **result credibility, the passive/active network boundary, and
release hardening** — moving fxapk from "what it can detect" toward "why it
judged this, whether the run was complete, and which network behavior is
permitted". (33 commits since 0.8.0.)

### ⚠️ Behavior changes (read before upgrading automation)

- **`--mode passive|authorized-active` (default `passive`)** on `analyze`,
  `auto`, and `batch`. In the default passive mode, enrichers that send
  traffic to the **target** (the web-check active prober) are blocked at the
  pipeline layer, and the Telegram `getMe` probe is not sent. Pass
  `--mode authorized-active` to allow active probing — this requires
  explicit operator authorization. **If you relied on web-check enrichment,
  you must now pass `--mode authorized-active`.**
- **`--strict`** on `analyze`: non-zero exit when the analysis is
  incomplete — exit code **4** if a *critical* analyzer failed, **3**
  otherwise. Default (non-strict) is unchanged: best-effort, exit **0**.
- **Report schema** gained top-level fields — `schema_version` ("1.0"),
  `analysis_status` (`complete|partial|failed`), `completeness` (0..1),
  `critical_failures`, `skipped_analyzers` — and `meta` keys: `mode`,
  `tool_version`, `ruleset_digest`, `stage_status`, `active_enrichers_*`.
  Existing fields are unchanged; consumers should key off `schema_version`.

### Added

- **Passive/active network mode** enforced in code across config → pipeline
  gate → CLI, fail-closed to passive. `web-check` is the sole active
  enricher and is labelled as such; skipped/enabled active enrichers are
  recorded in `meta` for audit.
- **Report credibility layer**: `analysis_status`, `completeness`
  (capability/platform skips excluded from the denominator),
  `critical_failures`, and `ruleset_digest` (a stable, EOL-normalized
  sha256 over the rule files — reproducibility anchor) + `tool_version`.
- **Finding provenance**: central `analyzer` attribution (stamped in the
  pipeline, no per-analyzer churn) and a `confidence` axis orthogonal to
  severity; explicitly heuristic findings default to LOW confidence.
- **Staged pipeline execution** with per-stage `stage_status` and
  stage-level resilience — a crashing stage no longer aborts the whole run;
  an `analyze`-stage crash marks the report `failed`, other stage crashes at
  least `partial`.
- **Anti-forensic / hardening detection**: open-source packer & hardening
  toolchain signatures, native `.so` symbol/string scanning (rename-
  resistant), ELF PT_NOTE hijack + local high-entropy heuristics,
  Xposed/LSPosed module identity from manifest meta-data, and additional
  hook / anti-detection signatures.
- **Dynamic capture hardening**: out-of-band floor pcap automation, explicit
  frida hook-readiness signal, capture-mode flags (`both/floor-only/
  mitm-only`) + `--serial`, degraded status (no fake "done"), UID socket
  snapshot at the capture window.
- **CI release gates**: OS matrix (Linux / macOS / Windows), 80% coverage
  floor, wheel build + clean-install smoke test (`fxapk --version` + rules
  load from the wheel), and `pip-audit` over the isolated fxapk dependency
  tree.

### Fixed

- Zip-bomb declared-size guard applied to the **parallel** analysis path
  (previously serial-only).
- Connectivity probe no longer false-negatives behind restrictive networks
  — mixed domestic + foreign **numeric** anchors over TCP:443 (no DNS
  dependency, bounded latency).
- Manifest-bomb / manifest-poison parsing robustness (no crash on tag
  namespace; string-pool package-name fallback).
- Review follow-ups: unified effective config (analyzer vs pipeline), audit
  scoped to the project dependency tree.

### Changed

- `run()` refactored into a staged `_PipelineState` pipeline
  (behavior-preserving).

---

Earlier releases (≤ 0.8.0) predate this changelog; see the git history and
GitHub release notes.
