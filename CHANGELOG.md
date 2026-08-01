# Changelog

Notable changes to fxapk. Versioning is semantic; **behavior changes that
affect automated / CI / agent callers are called out explicitly**.

## Unreleased

### Fixed

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
`shared_build_environments`）实现完备、注释里写着"实测一个构建标识横跨 3 个案件"，
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
  - **实测**：语料库 40 份报告中 14 份 DEX 为壳桩，各阻断 6 条结论。最能说明问题的是同包对照：
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
  - **阈值有实测依据**：24 样本标定，加固样本 DEX 字符串 15~440 条、正常 App 12867~299356 条，
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
  `resources.arsc` / `classes*.dex`——真实语料里 3 个样本各塞了一对 `res/1.xml` + `assets/1.xml`，
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

跨 14 个真实样本实测：该阶段一次都没有真正执行过（`decrypt_candidates_auto` 恒为
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
