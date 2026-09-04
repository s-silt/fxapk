# AGENTS.md — fxapk 操作指南（给 AI agent）

本仓库是 **fxapk（apkscan）**：APK **调证取证分析 CLI**。你（agent）通过命令行驱动它对样本做
按能力门控的静态/动态证据采集 + 境外基础设施候选的被动归属，产出**仍需过证据门的线索（leads）**。本文件让你在新机
clone 后**直接知道怎么操作**。项目背景见 `README.md`；本文件只讲**怎么跑**。

> **本文件假定：一个 agent 独立跑完全程。** 没有第二个 agent 接力、没有外部私有目录兜底——
> 从体检、分析、动态取证到串案与结论，**全部由你一个人走完并自检**。凡本文提到的资料，
> 要么在本仓库内、要么由用户提供；**不要依赖任何仓库外的交接文件**（不存在就按本文所述原则自己做）。

> 设计取向：本项目由人直接跑源码 + agent 驱动，**不打包 exe/GUI**。密钥走项目根 `.env`（已 gitignore）。
> 输出刻意做成 **agent 友好**：核心调证信息进 `evidence_to_obtain`/`notes`/`report.meta`，并由 `digest` 命令压成低 token 摘要。

---

## 0.0 ★首次在一台新机器上驱动本工具：先把这三条告诉用户

**这三件事在对应命令的默认路径上会发生。**前两条可能在外部留下删不掉的记录、或改动那台设备；
第三条是安全方向的默认值，列在这里是免得你以为还要额外加参数。你在这台机器上第一次要跑
`analyze` / `doctor` / `auto` 之前，**先把对应那条如实讲给用户**，别默默跑掉：

| 默认行为 | 会发生什么 | 用户想避开时 |
|---|---|---|
| `analyze` **默认联网** | 会把筛选后的域名 / IP 交给 WHOIS、RDAP、备案或测绘等第三方服务；DNS 查询还可能被递归解析器和权威 DNS 观察到。默认富化不主动访问样本声明的业务 URL，但不能表述为“对目标零流量” | `--offline`；仅预演用 `--enrichment-dry-run` |
| `doctor` / `auto` **默认改设备** | `doctor` 可部署 frida-server、安装抓包 CA；有设备时 `auto` 会安装样本、尝试脱壳并运行原版基线。只有去壳版的重打包、重签名及替换安装受“原版基线不足 + 工具建议旁路 + 显式行为修改/Java 双门”约束 | `doctor --no-fix`；`auto` 只在已授权的专用测试机上跑，旁路另需显式参数 |
| `digest` **默认脱敏** | 钱包私钥 / 助记词、个人隐私数据、后端凭据在摘要里打码。**这是给你看的那份**——你读到的 digest 默认就是脱敏的 | 确需明文加 `--no-redact`（完整明文一直在本地 `report.json` 里） |

★第二条尤其要先问再做：`auto --fix` 会不可逆地改动那台设备。用户没有明确说「这是专用测试机 /
可以随便改」之前，别替他决定——先跑 `fxapk doctor --no-fix` 把现状报给他，让他定。

★第三条的方向别搞反：`digest` 现在**默认就开着脱敏**，你不需要额外加参数来保护高敏值；
反过来，当用户确实要看原值时才加 `--no-redact`，并且提醒他那份输出别再贴给第三方服务。

★但**别把它说成「已净化、可以安全外发」**——它是「默认开着有限范围的脱敏」，不是净化。
确切范围见下条。

★★**但脱敏只管 `digest` 这一条路，别把它当成整个工具的保护。**下面这些出口一律原样吐高敏值：
`fxapk jsonl` / `fxapk diff` / `fxapk lead show|restore|replay` /
`fxapk corpus events|ls|seen|shared-config|shared-native|shared-build-env|link-candidates` /
`fxapk probe-leads` / `fxapk pcap-leads`
（★这些都会把线索原值打到 stdout，运行时各自往 stderr 打一行提醒，看到了别忽略；corpus 那几条
经台账的 key_iocs 带出，而台账不按类别过滤高敏。★这份名单是人工维护的、必然滞后——判断方法是
问「它的 stdout 里会不会出现线索值」）、`fxapk export` 的 CSV、HTML / PDF
报告、生成的文书、`corpus` 存证、`batch` 生成的 `case_correlation.json`、以及 `report.json` 本身。核心生成的 HTML/PDF 是受控内部证据视图，
不是已脱敏的发布版或可直接外发的正式报告。你要把内容转给任何第三方服务时，
`digest` 才走有限范围的类别/PII 脱敏；另有几条**独立的安全投影**：
`corpus link-discover|link-explain|link-groups` 默认 `--evidence-values omit`，
`link-labels-validate|link-evaluate|link-readiness|link-train` 只输出聚合结果。前三条若显式改成
`--evidence-values raw` 就重新变成未脱敏出口并在 stderr 警告，别把 raw 结果发给第三方。

★脱敏本身也是尽力而为，确切的保证只有两条：高敏类别的**值**被打码；**线索自己的**自由文本里，
邮箱 / 手机号 / 身份证号 / 长数字串这类有固定形态的被抹掉。这之外一律原样——包括 findings 的
标题、visibility 与 closure 的说明文字、overseas_targets 整段。姓名、地址、境外号码没有稳定
形态，哪儿都抹不掉。**别对用户说「已经全部脱敏了」**，那是过度承诺。

---

## 0. 行为铁律：直接用 fxapk 跑，别空想 / 别手搓

你是来**驱动 fxapk 出结果**的，不是来手动逆向、读源码猜结论、或大段推演的。收到「分析这个 APK / 查这些线索 / 准备设备 / 为什么动态跑不起来」一类请求时——**先跑对应 fxapk 命令，再据产物决策**。命令产物（`report.json` / `digest` / `corpus` 台账）才是事实来源，不是你的推测。

按意图直接选一条执行（别在跑命令前就长篇分析）：

| 用户想要 | 直接执行 |
|---|---|
| 分析一个 APK（静态 + 联网富化） | `fxapk analyze <apk> --out out`（**默认联网**；不想外发域名 / IP 加 `--offline`）然后 `fxapk digest out/<名>.json` |
| 一把梭（有真机：体检→静态→尝试脱壳→原版基线抓包→合并→闭环；仅旁路门全部满足时去壳重打包并重抓） | `fxapk auto <apk> --fix --strict-case` |
| 已有报告补跑多源富化 + 五层闭环 | `fxapk case close <report.json>`（默认严格：partial=5、failed=6） |
| 批量整个文件夹 | `fxapk batch <dir>` |
| 准备真机环境 / 排查动态为什么跑不起来 | `fxapk doctor`（**默认就会动手修**；只想看现状用 `--no-fix`） |
| 真机脱壳 / 去壳重打包 / 抓包（单步） | `fxapk unpack <apk>` / `fxapk repackage <apk>` / `fxapk capture <pkg>` |
| 串案 / 资产沉淀 /「这值见过没」反查 | `fxapk corpus add <report.json...>`（历次报告入库、跨版本回归）；`fxapk corpus seen <值> [--by sign_sha256\|so_sha256]`（按共享签名证书或 native 库哈希反查）；`fxapk corpus link-candidates`（rules-v2 可解释候选，分数只是复核优先级）；`link-explain` / `link-groups`（默认匿名复核视图）；`link-evaluate` / `link-readiness`（只输出聚合评测/训练门）；`fxapk corpus shared-native`（共享 .so 簇）；`fxapk corpus ls` 过滤列举 |
| 反推配置端口的运行时归一化规则 | `fxapk port-normalize --declared <声明端口.json> --report <report.json>`（详见 §0.6.2） |

- 先用 `fxapk digest <report.json>` 做低 token 分流和定位；形成五层归因、调证结论或正式报告时，
  必须回查 canonical `report.json` 中对应的结构化字段与原始证据。`digest` 是摘要，不能替代证据核验。
- 命令失败/缺前置 → 看它打印的 `playbook`（每条是可直接复制的修复命令），照着修，**别自己另起炉灶手搓**。
- 只有当**没有**对应 fxapk 命令、或要改 fxapk 代码本身时，才进入"分析/开发"模式（见第 5 节）。

---

## 0.5 分析 APK：标准动作 + 调证重点 + 汇报模板（核心办案逻辑）

**主工具（操作机已装，优先用，别空跑外部付费源）**：`fxapk`（本仓库，APK 取证→端点/IP/标识符+富化+corpus 反查台账）。默认富化不直连目标业务服务，但会向第三方数据源提交域名/IP，DNS 查询还可能被解析服务或权威 DNS 观察；动态运行 APK 的自身流量另行发生，不受静态富化的 `--mode` 阻断。

**标准动作（先跑命令、据产物决策，别空想）**
1. 有设备优先 `fxapk auto <apk> --online --out out --strict-case`；纯静态则先 `fxapk analyze <apk> --online --out out`。
2. 对已有报告执行 `fxapk case close out/<名>.json`，把多源覆盖、五层归因和未闭环项写回原报告。
3. `fxapk digest out/<名>.json` 读紧凑摘要并定位重点；形成正式结论时，按相关目标回查
   canonical `report.json` 的结构化字段与原始证据，不能只凭摘要下结论。
4. 不手搓逆向、不逐步复述工具过程、不把整份 report 倒出来。

**调证重点优先级（本办案口径，覆盖工具默认的"高敏物证优先"）**
1. **可依法调证的后端服务器（第一优先）**：先证明端点属于 App 自有/疑似业务后端，再按辖区、承载关系和可达法律渠道确定调证对象。IP 资源持有者/起源 ASN、承载或 CDN 服务商、域名注册主体与 ICP 备案主体是不同角色：前两者可提供与其服务关系相符的资源、租户或日志记录；ICP 只证明备案/接入登记，不能当作云服务商，也不能据此向备案主体索取云租户或控制面日志。任何一层都不能单独证明端点由 App 运营；纯第三方 SDK、公共解析服务和共享 CDN 仍须排除。CDN 边缘不得写成 Origin 或运营者，但分发服务商可以是账户或租户、分发与绑定域名、回源配置、访问日志和控制面审计记录的调证对象；具体字段按服务商口径填写。
2. **运营基础设施（第二优先）**：后台入口(admin_panel)、自建 IM/C2、短信验证码转发、硬编码后端凭据 → 作为运营基础设施线索和调证标的；发现凭据不构成登录、修改或访问外部系统的授权。
3. **境外基础设施**：列出并做**被动归属**（RDAP/DNS/ASN/证书透明度 + 端口/技术栈作识别信号），把边缘、承载方、Origin 候选和运营者分层。是否调证取决于合法可达渠道，不得按境内/境外一刀切；未经授权不主动探测。
4. **资金与高敏物证**：默认降低展示优先级，但不是“死胡同”。核心 HTML/PDF、JSON 和文书属于受控内部证据视图，可能含原值；对外发布或普通流转的正式报告必须另做经审核的安全投影，以证据编号和哈希定位，未经明确授权不得带出原值。需要资金线或身份线时再按授权范围展开。

**即时汇报模板（限长，只用于进度摘要；不得代替正式报告）**
```
## <app名> 研判（sha256 前12位）
- 涉诈类型：<app_classification>
- 可调证后端（按优先级，≤6 条）：· <域名/IP> | 运行时关系<已证实/候选> | 资源持有/ASN<主体> | 承载/CDN<主体> | Origin/运营者<已证实/未确认> | 依法可触达对象：<向谁>，取<什么证据>
- 运营端线索：后台/自建IM/短信转发/后端凭据（有则列+调证落点）
- 境外/辖区未知基础设施候选：候选<N 条>，Shodan/CT 已画像<P 条>，未画像<U 条>；已画像项再列<Origin 候选 IP / ASN·org 归属 / 证书透明度子域 / 技术栈指纹>（按证据分层和合法渠道决定下一步）
- 下一步取证动作：<1-3 条可执行>
（钱包/收款/四方支付：默认不展开，除非要资金线）
```

**动态：PCAP-first 保底，明文优先被动解密，探针是可选旁路（非必做）**：`fxapk capture --mode floor-only`
可在不使用 Frida 的情况下采集 floor PCAP，但仍需 adb 可用、设备 root（su）与设备侧 tcpdump。它可拿到接入节点 / SNI /
QUIC Initial / socket 归因等被动证据；
默认 `capture` 与 `auto` 当前仍要求 Frida，不能把默认模式描述成可无 Frida 降级运行。但 `capture status=done`
只表示采集流程完成，不等于动态证据闭环：`case close` 只有同一公网业务候选同时满足目标 App 归因、
业务端点判定与双向载荷门，才把动态层判为 `complete`；归因不唯一、APK 身份未知或只有 modified-runtime
证据时最多为 `partial`；仅通道就绪或零业务流量为 `failed`。
已知反诈拦截页不计业务候选。要明文时优先走 TLS Key Log + tshark 解密、socket 归因。默认 `both`
使用 Frida/mitm；行为修改 shim 仍须同时给 `--allow-behavior-modification --antidetect java`，不能与抓包模式混为一谈。

> **探针库**：首批 8 个探针（`coldstart-config` / `objstore-config` / `native-ssl` / `tls-keylog` /
> `sms-forward-outbound` / `mqtt-xmpp-im` / `telegram-mtproto` / `push-c2-inbound`）已脱敏后随 wheel
> 内置于 `apkscan/dynamic/frida_probes/`，手动 `frida -U -f <包名> -l <探针>.js -q -o probe.log` 注入；
> 其余探针仍需自备。探针散落的 `[LEAD]` 行用 `fxapk probe-leads probe.log --into out/<样本>.json`
> 聚成调证台账并回灌进报告。
> ★**探针线索的 confidence 不再一律 HIGH**：它是 advice 的纯投影——单源探针 待核→LOW、建议调证→MEDIUM，
> **永不 HIGH**；只有 merge 阶段与静态/pcap 二次印证（同 category+value、值有干净网络锚点、原 advice 为
> 建议调证）才升 HIGH，仅升不降。即**探针来源的 HIGH 意味着"两源印证过"**，MEDIUM 只代表目前单源、不代表价值低。
> confidence 只影响 closure 排位与展示排序，不作硬门（硬门读 advice）。

**深度归因（拿到后端域名/IP/标识符后做服务器归因 + 调证报告）**：证据分级 + 对抗式核验 + **绝不编造**
（Shodan 等可实查的源据实查；无 key 的源只给"应向谁查什么"的语句，不臆造结果）+ 辖区驱动的调证优先级
+ 固定结构输出研判报告。**这些原则本身就是全部要求**——不需要额外手册；若用户另给了打法文档就照它，
没有就按此执行。

**禁止**：dump 全 report；手搓逆向；逐步复述工具过程；铺开"无需调证"的 SDK/CDN 噪音；把钱包/收款当重点。

---

## 0.6 工作流闭环：别做一半就当完成

分析一个样本**未走完闭环不算完成**。开工前先说清「这次要走到哪一步」；收工前逐条自检（动作见 §0.5 / 各命令）：

1. **静态**：`analyze` → `report.json` + `digest`，确有产出。
2. **动态**（有设备）：用 `capture --mode floor-only` 建立无需 Frida 的 floor PCAP 底座；它仍需设备、
   adb 可用、设备 root（su）与设备侧 tcpdump，默认 `capture`/`auto` 当前仍要求 Frida。闭环完成要求同一公网业务候选通过目标 App
   归因、业务端点和双向载荷门；未唯一归因、APK 身份未知或只有 modified-runtime 证据时最多为 `partial`，
   只有通道或零业务候选为 `failed`。要明文优先走**被动**解密（TLS keylog + tshark）。
   ★`capture` 每次只采一个窗口；`auto` 第一轮尝试安装并运行原版 APK 取得基线，安装身份不能确认时必须把
   `meta.capture_apk_identity.which` 标为 `unknown`。仅当第一轮有可读基线、判据建议旁路且调用方显式授权时，`auto` 才进入第二个**旁路轮**
   （去壳重打包，并请求启用已由双门授权的 Java 行为修改 shim）；只有实际注入行为修改 shim 的证据才标 `modified-runtime`
   （`runtime_variant` 字段的两个取值就是 `original-runtime` / `modified-runtime`，带后缀）。
   **旁路轮的观测不得单独结案**——诱导出来的行为不能当作样本自发行为。行为修改 shim 默认关，
   需 `--allow-behavior-modification` + `--antidetect java` **双授权门**（与 `--mode authorized-active` 正交、不继承）。
   ★`--antidetect` 目前**只接受 `off` / `java`**；`native` 是预留档、主仓暂无内置 native shim，**传入即报错**。
   第二遍只产 `runtime_report.json` + 主报告挂指针，不出完整渲染态对照报告。
3. **富化 / 判型**：每个「建议调证」端点判辖区 + 判前端/落地；覆盖情况必须读逐目标、逐来源回执，
   区分 `hit` / `no_record` / `failed` / `skipped` / `disabled`。命中少可能是真无记录，不能据命中数反推“源没跑全”。
4. **降噪**：剔反诈拦截页和大厂共享端点；CDN 边缘不能当落地机，但仍保留其分发关系与可调证记录类型。
5. **串案**：独特字值（appkey / 证书 / CNAME 模板）跨案自查。
6. **五层闭环（收工前必跑）**：`fxapk case close <report.json>`。逐目标核验 ①运行时业务证据；② IP 资源登记持有者；③ BGP 前缀/起源 ASN；④云/IDC/CDN/防红分发关系；⑤最终调证对象（向谁调、取什么）。CDN/边缘没有 Origin 必须保持 `partial`。
7. **状态验收**：只有 `report.meta.closure.status=complete` 才能称完成。`partial` / `failed` 必须原样汇报 `gaps` 和 `next_actions`，不能把“命令跑完”表述成“案件闭环”。自动流程用 `fxapk auto <apk> --strict-case`，退出码 `0/5/6` 分别对应 `complete/partial/failed`。

收工必说清 **做了什么 / 没做什么（为什么）/ 风险 / 下一步**——别把半程当终点、别自认为完成。

### 0.6.1 ★ 哪些自动跑、哪些必须你手动补（最常见的"以为跑全了"）

`analyze` / `auto` 会自动跑**能力满足的全部分析器**（`native_fingerprint`、`endpoints`、`crypto_recipe`、
`contacts`、`sms_forwarding` … 全在内，无需开关）。不写死数字：分析器数量随版本变（`discover_analyzers()`
是唯一真源），而且**并非每个都在每次运行里跑** —— 声明了 `requires` 的会按能力门控自动 skipped，
例如 `jadx` 要 PATH 上真有 jadx、三个 `web_*` 要有已落盘的网页证据。要看本次实际跑了哪些，
读报告的 `analyzer_status`（skipped 会如实带原因），别假定"跑完就是全跑了"。

**下面这些永远不会自动发生**——它们要么需要你提供工具拿不到的输入，要么是跨样本操作。
跑完 `analyze` 就收工 = 漏掉半个系统：

| 必须手动补 | 为什么不能自动 | 什么时候做 |
|---|---|---|
| `fxapk corpus add out/<名>.json` | 库根含案件数据，须显式 `--corpus`／`FXAPK_CORPUS` 指向**工作树外** | **每次分析完都做**，否则串案/家族反查没有数据 |
| `fxapk corpus seen <值> --by so_sha256` / `corpus shared-native` | 跨样本操作，要先有库 | 想召回家族候选，并结合其他独立锚点复核时 |
| `fxapk config-channel --prefix … --domain …` | 前缀常量与基域**要你自己从样本常量里判断**哪个是 | 报告显示配置下发但静态无 URL 时 |
| `fxapk port-normalize --declared … --report …` | 声明端口来自**你的解密结果**，工具自己拿不到 | 解出配置里的 raw 端口后 |

### 0.6.2 ★ 顺着报告里的信号继续走（别停在"命令跑完"）

报告里出现下列信号时，**它就是在告诉你下一步该干什么**，不是结论：

- **`NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER`（回环占位架构）**：样本把非标准回环地址（如 `127.0.x.x`）
  硬编码成后端地址 + 存在 native 库 → **别对这个 127.x 调证**（对内网空调证）。真后端由 `.so` 运行时
  经下发通道（DNS TXT / 远程配置 / OSS 对象）决定。转去：① 动态抓包拿实际连接的公网 `IP:端口`；
  ② 或逆向 `.so` 的下发通道解出配置。
- **`meta.native_lib_hashes` 有值**：核心 `.so` 的 sha256 可作高价值候选锚点。入库后用
  `corpus seen <sha> --by so_sha256` 召回共享该值的样本，再排除公共库、SDK、壳组件、构建产物和正版重打包继承；
  单个共享哈希不能直接认定同一家族或同一运营主体。
- **解出了配置里的 raw 端口**：先别当成真实端口。部分家族运行时按固定规则归一化（如
  `真实 = 声明 + IP末段 + 常量`）。用 `port-normalize` 把**你解密的声明端口**与**报告里的实测端口**
  （`endpoints[].enrichment.runtime.remote_endpoints`）配对反推该规则——规则一致是很强的家族证据，
  规则不一致只说明该归一化假设未获支持，不足以单独排除同源。配对不足或过于齐整时它会判
  `degenerate` 拒给结论，**别硬套**。
- **`DEX-STRING-POOL-OPAQUE`（字符串池疑被整体混淆）**：★ 这条是**关于报告本身可信度**的警告，不是样本
  的一条罪状。命中意味着 dex 字符串常量疑被编译期整体加密 → `endpoints` / `contacts` / `config_keys`
  这些全靠字符串池的分析器会集体抽空。**此时本报告里这些项的「未发现」不可解读为「不存在」**，
  别据此判样本干净。真实端点转运行时取：floor PCAP 拿实际连接的 IP:端口 + socket 归因。
  画像恒写进 `meta["dex_string_pool"]`（不论是否命中），可复核「我们究竟看到了多少」。
- **`APK-CORE-NAME-DECOY-ENTRIES`（冒充核心文件名的诱饵条目）**：压缩包里有以 `/` 开头、首段恰为
  `AndroidManifest.xml` / `classes.dex` / `resources.arsc` 的条目。ZIP 规范禁止绝对路径条目、构建工具
  也从不产生 → 人为构造，意在让解析器定位核心文件时撞上假条目。
  **直接影响你的下一步**：别用会**落盘解压**的工具直接展开该样本（apktool / unzip / 部分反编译器），
  绝对路径条目在不同工具下行为不一，可能写到预期外位置或直接报错中断；继续用内存读取方式分析。
  fxapk 自身已实测不受影响。该构造可作技术画像，但**不宜单独当家族锚点**——实测细节逐构建随机化。
- **闭环状态 `partial` / `failed`**：原样汇报 `gaps` 与 `next_actions`，绝不表述成"已闭环"。

---

## 1. 环境准备（新机 clone 后一次性）

```bash
# 需 Python >= 3.11
pip install -e .                 # 装运行期依赖 + 注册 fxapk / apkscan 命令
cp .env.example .env             # 创建本地密钥文件（已 gitignore，绝不入库）
#   然后编辑 .env 填入 key（见第 3 节；不填也能跑，仅缺对应富化能力）
fxapk selfcheck                  # 能力自检（稳定 JSON）：核心/版本/cryptography/jadx/adb/frida/
                                 #   mitmproxy/device/联网能力**总体**逐项 ok|missing|disabled|
                                 #   unreachable + 一句修复指引。★驱动前先跑它，别试错
                                 #   ★它**不逐个源检查 API Key**（只报 online-enrichment 总体）；
                                 #     哪个源真查着了看报告的 source_status
                                 #   设备侧（root/ABI/frida/mitmproxy/CA）另见 §1.5 的 `fxapk doctor`
git config core.hooksPath .githooks   # ★启用提交前泄漏扫描（改代码就必须开）
```

★ 最后那条不是可选项。hook 只看**已 staged 的新增行**，默认阻断疑似真实地址 / 凭据 / 无理由豁免，
**以及三条案件值判据：中文人名（「姓+名+案」形态）、联系方式（QQ / 微信 / Telegram）、二开包名**
（含随机化不透明段的反向域名形态）。这三条同为默认档阻断，且 **finding 值本身自动脱敏**——
公开仓库的 CI 日志同样公开，回显真值等于换个地方泄漏，所以看到告警要自己回到那一行看是什么。
**真是公开第三方库被误判**，正确做法是登记进 `rules/` 对应规则表（`bank_packages` / `sdks`），
不是加行内豁免——豁免是给「判据要求真值字面」的夹具用的，不是给误报用的。
放行单行需写理由（行内注释 `leak-scan:` `allow` `<理由>`，三段连写、中间只留空格），且**理由要逐条成立**：同一理由跨 ≥20 个新增行会触发
`bulk_exemption` 阻断（防「用一句话批量按掉护栏」）。CI 会对 PR diff 再扫一遍，`--no-verify` 绕不过。
★**自验档位要对得上 CI**：分支已经有 commit 时用 `leak-scan --base origin/master --strict`（＝CI 那条），
`--staged` 只扫当前暂存的 diff，改动一旦 commit（多 commit 分支 / amend 后）它就看不到、会给出虚假的「未发现」。
另：**说明性文字里别把豁免 token 连写成完整形态**（`leak-scan:` 紧跟 `allow`）——
扫描器的匹配是 `leak-scan:\s*allow`，在**任何**行见到就当成真豁免指令，
文档里照抄一次就会凭空多出一条理由为空的幽灵豁免（本节这两处即为此把 token 用反引号断开）。
**测试夹具优先使用文档保留地址和域名。**如果被测分支必须具备公网地址语义、厂商域边界或其他
保留值无法触发的性质，改用 mock 或可审计的合成夹具，并逐行说明必要性、通过严格泄漏扫描；不得拿真实案件值充当夹具。

命令两种等价调用方式：`fxapk <cmd> ...`（装好后）或 `python -m apkscan.cli <cmd> ...`（免装）。

---

## 1.5 真机取证机准备（Android，动态分析前置）

脱壳 / 抓包 / 去壳重打包都需要**已 root 的 Android 真机或模拟器**（frida-server 必须 root 跑）。**纯静态 `analyze` 不需要设备**。一次性配置：

1. **root**（以红米 K40＝代号 `alioth` 为例）：解锁 BL（登小米账号 + 插**任意 SIM**翻开关，翻完可拔；小米有强制等待期）→ 取**与当前 MIUI/HyperOS 版本完全一致的 boot.img** → Magisk「安装 → 修补文件」生成 `magisk_patched.img` → `fastboot flash boot magisk_patched.img`。给 **shell（adb）授予 su 权限**（doctor 的 root 判定就认 `adb shell su -c id` 出 uid=0）。
2. **一键体检 + 自愈**：`fxapk doctor`（默认即 `--fix`）—— 自动按设备 ABI（K40＝arm64-v8a）+ 主机 frida 版本**下载并部署 frida-server、起进程、把 mitmproxy CA 装进系统信任库**，逐项报 OK / 怎么修。这一步能修的都自动修，别手动逐个搞。
3. **装 APK 绕过 MIUI「USB 安装要插 SIM」闸**：root 后不用开"USB 安装"那个 SIM 限制开关，直接
   `adb push x.apk /data/local/tmp/ && adb shell su -c 'pm install -r -t /data/local/tmp/x.apk'`。
4. **验证**：`frida-ps -U` 能列出设备进程只证明枚举通道可用，不证明 frida-server 以 root 运行，
   也不证明 attach、Java bridge 或目标 hook 已就绪。先用 `fxapk doctor --no-fix` 做基础体检，再用真实 attach/hook smoke 验收所需能力。

常见坑：
- **frida-server 从 GitHub releases 下载**——PC 在国内无代理会失败/慢。解决：挂代理；或手动下 `frida-server-<主机frida版本>-android-<abi>.xz`（版本须与 PC `frida --version` 一致，doctor 已自动对齐版本号）push 到 `/data/local/tmp/frida-server` 自起。
- ★**Frida ≥17：GumJS 不再内置 Java bridge**。注入端一引用 `Java`，运行时就 send 一条 `frida:load-bridge`
  向宿主要源码——frida-tools 的 CLI/REPL 自带应答器，**Python API 没有**。症状极具迷惑性：
  会话建立、进程存活、命令不报错，但**所有 Java hook 静默失效、事件全空**。宿主侧应答已实现，
  `fxapk doctor` 也已加检测项（能否取到 frida-tools 的 `bridges/java.js`）；装齐 frida-tools 即可，
  真验收看 capture 报告里的 `frida_bridges` 状态，别只看「会话成功」。
- ★**frida-server 能被 `frida-ps` 列出 ≠ 它以 root 在跑**。实测踩过：启动命令的引号被 adb 拆开，
  它以 UID=2000 起来了，spawn/attach 一概失败，**现象酷似样本反 Frida**。doctor 已按 `/proc/<pid>/status`
  读真实 UID 判这一项。
- **mitmproxy CA** 仅 HTTPS 抓包要：先 `pip install mitmproxy` 跑一次 `mitmdump`（Ctrl-C 退）生成 `~/.mitmproxy`，再 `doctor --fix` 装系统证书。
- **boot.img 必须与当前 ROM 版本匹配**，否则 bootloop。
- 取证测试机建议用**一次性小米账号 + Magisk**，别登个人账号。

---

## 2. 标准分析流程（按能力门控）

```bash
# ① 跑分析 → 产出报告（默认联网富化；--offline 跳过所有联网富化）
fxapk analyze <sample.apk> --online --out out --fmt html,json
#   产物：out/<样本名>.json（完整报告） + out/<样本名>.html（人看）

# ② 把完整报告压成【紧凑调证摘要】供你（agent）低 token 初筛和定位
fxapk digest out/<样本名>.json
#   摘要：leads 按优先级排序（建议调证 > 待核 > 无需调证；高可信/C2 在前）+ 计数摘要。
#   高敏值（钱包私钥/助记词、后端凭据、个人隐私数据、加密配方）默认**已脱敏**——这条命令的输出
#   通常直接进你的上下文；默认档只是有限脱敏，不等于已经净化或可以直接外发。
#   ★ 确需明文原值（核对取证细节）时才显式关掉：fxapk digest out/<样本名>.json --no-redact
#     关掉之后那份输出别再贴给第三方服务；完整明文一直在本地 report.json 里，不受此开关影响。
```

其它常用：
- `fxapk auto <apk>`：静态 +（有设备则）动态一把梭。`fxapk batch <dir>`：批量。
- `fxapk analyze-web <证据目录>`：把**已落盘的网页证据**当一级输入（递归读 `.html` / `.body` /
  `.js` / `.headers`），产出与 `analyze` 同构的报告。**不联网重取**——证据是什么就分析什么。
  报告会对本次实际进入分析器的文件按 NFC 相对路径、字节数与逐文件 SHA-256 生成确定性
  `meta.evidence_manifest`，并把清单指纹写入 `meta.sample_sha256`；因此网页证据集可直接进入
  `fxapk case package`。同一路径的 Unicode 规范化碰撞会拒绝生成指纹，不能静默覆盖。
  网页专属分析器**按文件分别**记录静态跳转候选，不把不同文件里的跳转拼成一条未经观测的链
  （拼出来的链是推断，不是观测）。
- `fxapk enrich batch -t <目标清单> -o <输出目录>`：批量被动富化（每行一个 IP / 域名），产出
  CSV 回灌 + NDJSON 明细，可 `--resume` 续跑。★ `--dry-run` 是**默认值**：只逐源估算配额、
  零请求，确认预算后再 `--no-dry-run` 真跑。源不适用于该目标（如域名源拿到 IP）与查了没记录
  是**分开标注**的——工具失败 ≠ 阴性结果。
- `fxapk case close <report.json>`：对已有报告执行主目标选择、有限重富化、五层归因与严格验收；默认原地写回 JSON，并刷新已存在的同名 HTML。
- `fxapk unpack` / `fxapk capture`：真机脱壳 / 抓包。`unpack` 需要 frida；只有
  `capture --mode floor-only` 可在无 frida 时运行，但仍需 adb 可用、设备 root（su）与设备侧 tcpdump；默认 `capture` 与 `auto` 当前仍要求 frida；
  `analyze --dynamic` 会自动接力。
- `fxapk repackage <apk>`：脱壳后把**去壳版**重打包（zip 替 DEX + apksigner 重签）装回设备，使 capture 抓去壳版（绕壳反 frida）。需 apksigner/zipalign + 设备；`auto` 只有在原版基线已取得、旁路被建议、显式同时开启 `--allow-behavior-modification --antidetect java` 且未设置 `--no-repackage` 时才调用此步（重签必卸原包会清 app 数据）。能力边界：治不了 VMP/重 native/反模拟器壳，多数样本预期降级、capture 仍跑原版。
- `fxapk corpus`（**资产沉淀主线**）：`corpus add <report.json...>` 把历次报告入库——主键 `(sample_sha256, tool_version, ruleset_digest, evidence_surface)`，同样本、版本、规则和证据面才幂等跳过；换版本、规则或证据面可并存做**跨版本/证据面回归基线**。`corpus seen <值> [--by sample_sha256|package_name|sign_sha256|so_sha256]` 用签名证书或 native 库哈希召回候选；`corpus shared-native` 只列出被 ≥2 样本共享的 `.so` 组件。共享值本身不等于家族或主体结论，须排除公共库、SDK、壳、构建链和正版重打包继承；另有 `corpus ls`（过滤列举）/ `reindex`（自愈索引）/ `events`（吐 JSONL 喂 agent）。★库根须 `--corpus` 或环境变量 `FXAPK_CORPUS` 显式指向 **git 工作树外**（含真实数据），否则拒跑（exit 2）。
- `fxapk corpus link-candidates --corpus <库>`：按非弱技术锚的倒排索引召回并排序人工复核候选；
  `review_priority_score` 不是概率，不得据此认定同一运营主体。命令会原样输出样本、案件和证据值。
  同一 native SHA 若能在至少三个不同真实样本间一一匹配到三个不同 basename，会以
  `renamed-shared-component` 零分排除但
  保持可见；`nosha-*` 派生身份只进 `possible_duplicate_report`，不生成普通 pair；疑似正版重打包
  或显式纳入 quarantined revision 时封顶为人工复核档。超大锚桶或非法样本身份会把召回状态标为
  `partial`。旧 manifest 缺 `repack_identity_verdict` 时也会标 `partial` 并给出 `corpus reindex` 动作；
  先显式重建索引再信任 ownership cap。显式 `--model <工作树外.json>` 只重排规则已召回全集，
  不扩张候选、不突破 caps，且 artifact 的 rules policy/result/feature/normalization 任一版本不一致即拒绝。
- `fxapk corpus link-labels-validate --labels <工作树外.jsonl>` / `link-evaluate --corpus <库>
  --labels <工作树外.jsonl>`：严格校验追加式私有标签并离线评测。不同 family、不同案件或未标注
  都不会自动成为负例；只有显式 confirmed negative 进入负例分母。评测 stdout 只含聚合指标，
  不输出 SHA、案件号、IOC 或标签路径；当前结果必须标 `experimental`。`label_basis` 必须非空且取
  `independent-review` / `remote-config-review` / `native-binary-review` /
  `signing-certificate-review` / `build-root-review` / `ioc-review` /
  `rule-candidate-review`；与模型特征重叠的标签只供审计/发现，不进入晋级指标或训练。独立正负金标
  不足必须返回 `insufficient_independent_labels`，不能继续宣称 precision/可训练。
  `independent-review` 的活跃记录必须带非空 `evidence_ref`（不透明证据指针，只查形状不解析）
  与非空 `reason_codes`——独立性仍是自证断言，此义务只让它可事后审计；可选 `label_lineage`
  （`queue-internal`/`queue-external`）记录标签是否产自规则召回队列，供开放集召回评估区分血缘。
- `fxapk corpus link-discover --corpus <库> --labels <工作树外.jsonl>`：在已确认关系组内统计重复技术锚，
  默认 `omit` 原值且不自动改规则/写 corpus；`raw` 只供本地复核。
- `fxapk corpus link-explain <左SHA> <右SHA>` / `link-groups`：默认使用运行内样本别名；groups 只连
  真实候选边，A-B-C 不会伪造 A-C；输出精确 `transitive_only_pair_count`，只预览最多 100 对
  `transitive_only_pairs`，不物化大型连通分量的完整传递闭包。
- `fxapk corpus link-readiness ...` / `link-train ... --model-out <工作树外.json>`：默认门槛为 200 个
  独立标注样本、10 个独立正例组件、300 正例、600 负例、500 hard negative。未达门槛时训练在导入
  scikit-learn 前返回 `blocked` 且不落模型；两条命令共用 `--test-fraction` / `--seed`，门槛只检查
  train 分区。训练只用 train 拟合并冻结语料级预处理，正例按关系分量、负例按分量对等权；holdout
  只产聚合排序指标。达到门槛后才安装 `pip install 'fxapk[ml]'` 并本地训练。
- `fxapk config-channel --prefix <常量前缀> --domain <基域> [--path /x.txt] [--date YYYY-MM-DD] [--back N] [--fwd N]`：枚举
  `MD5(前缀 + yyyyMMdd) + "." + 基域` 这类**运行时算法生成**的配置下发子域候选。此类 URL 静态不存在（跑起来才拼），
  常规端点抽取认不出——但前缀常量、基域、MD5+日期格式都是可从样本里提取的静态事实。产出候选喂被动查询
  （passive DNS / 证书透明度）看哪个真解析过。**纯离线生成、绝不联网**;前缀与基域由你提供（案件/逆向所得，不入仓）。
- `fxapk port-normalize --declared <声明端口.json> --report <report.json> [--min-support N]`（**静态×动态交叉校验**）：
  部分家族配置里存的是 raw 端口，运行时再按固定规则算真实端口（如 `真实 = 声明 + IP末段 + 常量`）。本命令把
  **你解密所得的声明端口**（`{"IP": 端口}`，案件数据、只读不存）与 **fxapk 实测到的连接端口**
  （`endpoints[].enrichment.runtime.remote_endpoints`，pcap/socket 真观测）按 IP 配对，在有界假设空间里反推
  能解释**全部**配对的最简变换，并列出支持/反例明细。
  - ★ **不产生任何端点**：observed 侧全是实测值，输出是可证伪的变换假设。同一 IP 有多个实测端口 → 判
    `ambiguous` 不擅自挑（挑=替你猜）。
  - ★ **过拟合闸**：配对 < min-support、或声明端口全相同、或 IP 末段全相同 → 判 `degenerate` 拒给结论
    （少量配对下任何形式都能拟合，那正是被撤销的二进制提取的翻车机理，见 §6）。
  - 确认后可用 `predict_port` 由声明端口推真实端口——**推导值必须如实标注，绝不可当"实测/确认连接"**。

---

## 3. 境外或辖区未知的基础设施与 Origin 候选（联网富化，`--online` 时生效）

对「建议调证」的域名/IP 端点做**两遍富化**：不向目标业务服务发起 HTTP/TCP 主动探测；查询会把域名/IP 提交给第三方数据源，DNS 查询还可能被解析服务或权威 DNS 观察。
1. **第①遍·归属** → 形成基础设施辖区候选、登记与承载信号（国内/境外/未知）：rdap/whois/dns/asn/icp；这些结果不证明物理源站或运营者辖区。
2. **第②遍·境外基础设施与 Origin 候选**（仅**境外+未知**端点）：收集承载、边缘、Origin 候选和关联资产信号；任何单一来源都不能独立确认 Origin 或运营者。

| 开关（写进 `.env`） | 能力 | 性质 |
|---|---|---|
| `FXAPK_SHODAN_KEY` | Shodan 查第三方既有数据库：host/IP/ASN/org/country/开放端口/服务 banner/产品版本/关联主机名——提供基础设施与 Origin 候选信号，不能单源确认运营者 | 不直连目标业务服务；目标标识会提交给 Shodan |
| crt.sh（免 key，默认开） | 证书透明度/SAN 关联子域候选 → 供串并复核；共享证书和多租户关系须排除 | 被动 |

**技术栈指纹（`exposure`，纯映射·零网络·零 payload·默认开）**：把 shodan 已采集的被动 banner 映射到**技术栈/后台框架指纹**。相同框架十分常见，只能作为人工复核的弱候选信号，不能据此认定同一后端、家族或运营主体；不做漏洞方向研判、不利用。

**结果在哪看**：候选证据并进对应 Lead 的 `evidence_to_obtain`/`notes`（自动进 `digest`）。当前可见前缀包括
`基础设施候选归属：…`、`Shodan 开放端口 / 服务：…`、`技术栈/后台框架指纹（常见弱候选；不能据此认定同一后端、家族或运营者）：…`、`关联子域候选(crt.sh)：…`；这些是字段示例，不是主体结论。
结构化 `overseas_targets` 段每主机带 `tech_stack[]` / `related_subdomains[]` 字段供 agent 直读，
但它是 **profile-only** 投影：只列 Shodan 或 CT 已返回实质画像的主机，不是境外/辖区未知候选全表。
ASN-only、Shodan/CT 无记录/失败/未配置的最终高价值候选可能不在该列表；必须同时读 digest
的 `overseas_target_coverage` 与 `summary.overseas_candidate_hosts_total / overseas_profiled_hosts /
overseas_unprofiled_hosts`。其中辖区只用逐源状态许可的 DNS/ASN/Shodan payload 判定，
无可用信号保守记「未知」；分母只纳入最终/安全投影后仍为「建议调证」的
DOMAIN/IP，「已画像 0」绝不等于「候选 0」。

**取证原则（辖区分流）**：
- **境内基础设施**：先证明它与目标业务有关，再按角色分别处理：向资源持有/承载/CDN 服务商调其实际掌握的资源、租户、分发或日志字段；向备案系统/接入信息渠道核 ICP 主体与接入关系。不得把 ICP 备案主体写成云服务商或向其套用云控制面字段。
- **境外基础设施**：先做被动归属与角色分层；是否调证、保全或协查取决于合法可达渠道，不能因境外属性自动排除。
  - ★ 若解析 IP 全是 **CDN/反代**，它们是边缘节点而非 Origin。不得把边缘写成源站或运营者；
    但可向分发服务商依法调取账户或租户、分发与绑定域名、回源配置、访问日志和控制面审计记录；具体字段按服务商口径填写。

---

## 3.5 五层基础设施归属（`endpoints[].enrichment["attribution"]`）

对每个建议调证端点，富化后组装成**五层不塌缩**归因链：
`resource_holder`（IP 资源登记方，IP-RDAP）→ `origin_network`（BGP Origin ASN）→ `hosting_provider`（云 / IDC）→ `edge_provider`（CDN / WAF / 防红代理，多信号加权指纹）→ `service_operator`（实际运营者，**恒 unknown，绝不从 ASN / RDAP 推断**）。域名按解析到的每个 IP **逐个产链**（per-IP，不合并成一份）。

★核心纪律：**IP 落在某云厂商 ASN ≠ App 由该厂商运营**。每层带 `confidence` / `source`，查不到即 unknown；edge 的 `confirmed` 须 ≥2 个独立强信号（单一响应头可伪造，最多 `probable`），负证据（只命中公有云 ASN / 通用 X-Cache / nginx）抑制误判。`fxapk letters` 会把这条链渲染进调证函的「基础设施归属链」段，直接支撑"向谁调证"。

---

## 4. 读结果（给 agent 的要点）

### 4.0 ★★ 读线索**之前**先过两道闸（顺序不能反）

**① `visibility` —— 这次到底看见了什么**（`digest` 与报告里都有，**排在 leads 之前**）

它回答的不是"发现了什么"，而是"**基于本次实际看到的输入，哪些结论有资格下**"。加固样本的 DEX
常常只剩壳桩，此时报告里的「未发现网络端点 / 未发现通讯录窃取」说明的是**没看见**，不是不存在。

- `sources`：dex / native / resource / runtime 各自的可见性（`complete` / `partial`(扫描被截断) /
  `stub_only`(壳桩) / `opaque`(字符串被混淆) / `unavailable` / `unknown`）。
- `blocked_claims`：**无资格下的穷尽性结论**清单。看到它们时，对应的"未发现"一律不得写成"不存在"，
  也不得据此下"该样本干净"的判断。
- `next_actions`：怎么补——该 `fxapk unpack` 还是 `fxapk capture`，或授权后重跑取远程配置。
- **与 `analysis_status` 是两码事**：那个说的是**工具**跑没跑好，这个说的是**样本内容**看没看见。
  「分析器全成功 + DEX 是壳桩 + 六条结论没资格下」完全可以同时成立。

**② `repack_identity` —— 重打包身份倾向（不直接决定资产归属）**

该 verdict 只决定隔离和复核策略，不能批量给接口、域名或构建路径定归属：

| verdict | 身份研判 | 资产处理 |
|---|---|---|
| `self_built` | 疑似自建 | 逐资产排除公共 SDK、共享基础设施与壳组件后，才作为调证候选 |
| `repack_suspected` | **继承与新增范围未定** | 先隔离可能继承的资产；与官方同版本包差分后再判断哪些是新增或篡改 |
| `unknown` | 未定 | 先人工核 |

判为 `repack_suspected` 时，工具只声明「疑似被重签名」，**永远不会说「植入了什么」**——那必须与
官方同版本包逐文件差分才能认定。你也不要替它下这个结论。

**③ 顺带**：`findings` 段（排在 visibility 与 leads 之间）承载 leads 不表达的事实判断——
通讯录窃取接口、域名轮换机制、未知壳、重打包警示。只列 CRITICAL/HIGH/MEDIUM，
`counts.omitted` 会告诉你省了多少条。

### 4.1 线索与归属

- 一切以 **leads** 为中心：每条带 `category`/`value`/`subject`/`advice`(建议调证/待核/无需调证)/
  `where_to_request`/`evidence_to_obtain`/`notes`。**优先看 advice=建议调证 的**。
- **结构化境外基础设施画像**：原始画像存于 `report.meta["overseas_targets"]`；`digest`
  在顶层输出按最终/安全 Lead 作用域投影后的 `overseas_targets`，
  **按主机机器可读**——`[{host, ip, jurisdiction, asn, org, country, ports[],
  services[{port,product,version}], tech_stack[], related_subdomains[]}]`。要列候选主机端口、比较技术栈或
  汇总关联子域时可直接读这个段，但它仅是 Shodan/CT 已命中的 **profile-only** 列表；
  要判断是否还有 ASN-only 等未画像候选，必须先读 `overseas_target_coverage`。仅【境外+未知】
  路由候选进入该覆盖口径，其中每项仍须按来源强度和角色边界复核。
- `report.meta` 还含 `app_classification`(涉诈类型研判)、`sample_sha256`(检材指纹)、`enriched_target_count` 等。
- 先用 `digest` 做摘要分流和定位；形成正式结论时回查 `out/<样本名>.json` 中对应的结构化字段与原始证据。

---

## 5. 开发约定（改代码时）
- Python type hints；测试用 **pytest**（不要 unittest）。跑全套：`python -m pytest -q`；快跑（排除重型）：`python -m pytest -q -m "not slow"`。
  - `@pytest.mark.slow` 标记的真 spawn 端到端等价测试需本地 `*.apk` 样本（`FXAPK_TEST_APK` 或仓库内任一 `*.apk`），无样本自动 skip（CI 不挂）。
- 富化器（`apkscan/enrichers/*.py`）继承 `BaseEnricher`，自动发现；失败吞成 `EnrichmentResult(ok=False)`
  **不抛、不裸 except、不在 try 里 swallow log**。新增富化器标 `phase`（attribution / overseas）。
- **分析器并行**（`apkscan/core/pipeline.py` + `snapshot.py`）：android 多核默认走**进程池并行**（绕 GIL；把 ApkContext 物化成可 pickle 的 `SnapshotContext` 发各 worker）。worker 数按 `min(CPU, 分析器数, 可用内存可容纳数)` 封顶防 OOM，**Linux cgroup 感知**（容器里取 cgroup 限额而非宿主机内存）。逃生 / 调优开关（env）：
  - `FXAPK_NO_PARALLEL=1` 强制串行（排障/兼容）；`FXAPK_MAX_WORKERS=N` 钳死 worker 数（=1 即强制串行）。
  - `FXAPK_WORKER_BASE_MB` / `FXAPK_MEM_SAFETY`（0<v≤1）现场覆盖内存封顶的标定（单 worker 估算 / 安全系数）。
  - ★ 改并行或快照路径须守不变量 **「串行 == 并行 逐字节一致」**（由 slow 等价测试背书）；分析器输出须确定（跨进程 PYTHONHASHSEED 不同，set 派生的顺序要显式排序）。
- **合并前必过三关（本地）**：`python -m ruff check apkscan tests` + `python -m pyright apkscan` + `python -m pytest -q`——CI（`.github/workflows/ci.yml`）这三样都跑，**只跑 pytest/pyright 不够，ruff 必跑**（曾因一个未用 import F401 把 CI 刷红）。
- **CI 环境对齐**：CI 装的是 `pip install -e "."`。新增**可选依赖**必须进 `pyproject` 对应 extra（如 pcap 深度解析→`pcap`/`dynamic`），且 ci.yml 两个 job 都要装上它，否则 CI 缺包报 `ModuleNotFoundError`/pyright 解析失败。依赖某可选 extra 的测试在模块顶部 `pytest.importorskip("<pkg>")`，未装该 extra 的环境优雅跳过。
- **合并前等 CI 绿**：开 PR 后 `gh run watch <id> --exit-status` 等 CI 跑完再 `gh pr merge`——别本地绿就盲合（本地与 CI 环境/依赖/平台不一致，本地缺 ruff、CI 缺可选依赖都坑过）。
- commit：conventional commits OK，中文 OK；**不要** `--no-verify` / 不要 force push 到 master；未经指示不主动 commit。

## 6. 已评估否决的方案（**别再提，除非前提变了**）

以下都是**实现过、复审后撤掉**的，不是"还没做"。再提之前先看这里的否决理由是否已被推翻。

- **❌ 二进制紧凑端点数组提取**（`decode_config_blob` 里从剥不动的 leaf 抠 `[IPv4(4)+port(2)]` 连续记录）—— 曾为 #237，已 revert（#238）。
  - **否决理由 1（致命·假阳）**：逐记录判据"公网非噪音 IPv4 + 非零端口"会放行约 **85%** 的随机 6 字节。实测（20 万随机/密文样本）即便要求整段 `len % 6 == 0` 且 ≥5 条记录，**30 字节随机/密文 leaf 仍有约 47% 被判成"5 个端点 IP"**。抬阈值救不了——只要长度是 6 的倍数就照样凭空造 IP。**取证工具伪造 IP 证据 = 一票否决**。
  - **否决理由 2（够不到）**：解码 BFS 只剥 gzip/base64/AES，**没有**家族专属的 XOR/首次破解步骤（密钥是案件数据、不入仓）。真样本上该提取器拿到的是**密文**而非解密后的数组，所以它产出的 IP 必然是假的。曾经"6 条真明文全过"的验证是把**已解密明文**直接喂进去测的，集成管线永远产不出那份明文。
  - **前提何时才算变了**：解码链里真出现了能**独立验证**的端点数组格式（如带 magic/长度头/校验和），或有可信的非启发式判据。仅仅"提高最小记录数"不算。
- **❌ Brotli 剥层进解码 BFS** —— 曾在 `feat/decode-brotli-layer` 分支，未合并即弃。
  - **否决理由**：Python `brotli` 包的 `Decompressor` 只有 `process/is_finished/can_accept_more_data`，**没有 zlib 那样的 `max_length` 输出上限**。分块喂输入也**不能**限住峰值内存——单次 `process()` 就能吐出远超上限的输出（检查发生在分配之后）。另外增量流的完整性要另查 `is_finished()`，截断流会被当成功剥层。为一个边际收益的层留内存安全洞不值。
  - **另注**：真族样本里 brotli 出现在 RSA 解密**之后**，而 RSA 私钥/首次破解不入仓，所以这一层在仓内管线上本就够不到。
  - **前提何时才算变了**：换用能限定输出上限的 brotli 绑定（或自带有界解压的实现），且能同时查流完整性。

> 通则：**宁可漏，不可造。** 静态/被动路径上，"看起来像"不等于"是"——启发式若能凭随机字节产出**看似权威的调证目标**（IP / 域名 / 端点），一律不做。
