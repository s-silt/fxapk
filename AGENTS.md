# AGENTS.md — fxapk 操作指南（给 AI agent）

本仓库是 **fxapk（apkscan）**：APK **调证取证分析 CLI**。你（agent）通过命令行驱动它对样本做
全套静态/动态分析 + 境外源站 IP 被动归属，产出**可直接使用的线索（leads）**。本文件让你在新机
clone 后**直接知道怎么操作**。项目背景见 `README.md`；本文件只讲**怎么跑**。

> **本文件假定：一个 agent 独立跑完全程。** 没有第二个 agent 接力、没有外部私有目录兜底——
> 从体检、分析、动态取证到串案与结论，**全部由你一个人走完并自检**。凡本文提到的资料，
> 要么在本仓库内、要么由用户提供；**不要依赖任何仓库外的交接文件**（不存在就按本文所述原则自己做）。

> 设计取向：本项目由人直接跑源码 + agent 驱动，**不打包 exe/GUI**。密钥走项目根 `.env`（已 gitignore）。
> 输出刻意做成 **agent 友好**：核心调证信息进 `evidence_to_obtain`/`notes`/`report.meta`，并由 `digest` 命令压成低 token 摘要。

---

## 0.0 ★首次在一台新机器上驱动本工具：先把这三条告诉用户

**这三件事不加任何参数就会发生。**前两条会在外部留下删不掉的记录、或不可逆地改动那台设备；
第三条是安全方向的默认值，列在这里是免得你以为还要额外加参数。你在这台机器上第一次要跑
`analyze` / `doctor` / `auto` 之前，**先把对应那条如实讲给用户**，别默默跑掉：

| 默认行为 | 会发生什么 | 用户想避开时 |
|---|---|---|
| `analyze` **默认联网** | 不碰目标服务器，但会把样本里的域名 / IP 拿去查公开数据库（WHOIS / RDAP / 备案 / 测绘平台）。查询记录留在那些平台上——**这等于向第三方平台披露你正在分析的对象** | `--offline` |
| `doctor` / `auto` **默认改设备** | 部署 frida-server、装抓包 CA；`auto` 还可能脱壳、重打包重签名、**卸载原应用并清空其数据**、安装并运行待分析样本 | `doctor --no-fix`；`auto` 只在专用测试机上跑 |
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
报告、生成的文书、`corpus` 存证、以及 `report.json` 本身。你要把内容转给任何第三方服务时，
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
| 一把梭（有真机：体检→静态→脱壳→去壳重打包→抓包→合并→闭环） | `fxapk auto <apk> --fix --strict-case` |
| 已有报告补跑多源富化 + 五层闭环 | `fxapk case close <report.json>`（默认严格：partial=5、failed=6） |
| 批量整个文件夹 | `fxapk batch <dir>` |
| 准备真机环境 / 排查动态为什么跑不起来 | `fxapk doctor`（**默认就会动手修**；只想看现状用 `--no-fix`） |
| 真机脱壳 / 去壳重打包 / 抓包（单步） | `fxapk unpack <apk>` / `fxapk repackage <apk>` / `fxapk capture <pkg>` |
| 串案 / 资产沉淀 /「这值见过没」反查 | `fxapk corpus add <report.json...>`（历次报告入库、跨版本回归）；`fxapk corpus seen <值> [--by sign_sha256\|so_sha256]`（按共享签名证书或 native 库哈希反查）；`fxapk corpus link-candidates`（rules-v2 可解释候选，分数只是复核优先级）；`link-explain` / `link-groups`（默认匿名复核视图）；`link-evaluate` / `link-readiness`（只输出聚合评测/训练门）；`fxapk corpus shared-native`（共享 .so 簇）；`fxapk corpus ls` 过滤列举 |
| 反推配置端口的运行时归一化规则 | `fxapk port-normalize --declared <声明端口.json> --report <report.json>`（详见 §0.6.2） |

- 决策只读 `fxapk digest <report.json>`（低 token、已按"建议调证 > 待核"排序）；要细节再读 `out/<名>.json` 全量。
- 命令失败/缺前置 → 看它打印的 `playbook`（每条是可直接复制的修复命令），照着修，**别自己另起炉灶手搓**。
- 只有当**没有**对应 fxapk 命令、或要改 fxapk 代码本身时，才进入"分析/开发"模式（见第 5 节）。

---

## 0.5 分析 APK：标准动作 + 调证重点 + 汇报模板（核心办案逻辑）

**主工具（操作机已装，优先用，别空跑外部付费源）**：`fxapk`（本仓库，APK 取证→端点/IP/标识符+富化+corpus 反查台账）。富化全被动（rdap/whois/dns/asn/icp/shodan 等），对目标零主动流量。

**标准动作（先跑命令、据产物决策，别空想）**
1. 有设备优先 `fxapk auto <apk> --online --out out --strict-case`；纯静态则先 `fxapk analyze <apk> --online --out out`。
2. 对已有报告执行 `fxapk case close out/<名>.json`，把多源覆盖、五层归因和未闭环项写回原报告。
3. `fxapk digest out/<名>.json` 读紧凑摘要；仅在核对五层原始证据时翻 `report.json` 全量。
4. 不手搓逆向、不逐步复述工具过程、不把整份 report 倒出来。

**调证重点优先级（本办案口径，覆盖工具默认的"高敏物证优先"）**
1. **可依法调证的后端服务器（第一优先）**：后端域名/IP，**登记主体在国内**（阿里云/腾讯云/华为云/电信·联通·移动/国内 IDC/有 ICP）→ 向该境内云·IDC·ICP 调租户实名 + 访问/登录日志。★ **纠偏**：fxapk 会把命中云/CDN 关键字的端点标「无需调证」折叠——但**只要 ASN/ICP 登记主体是国内提供商就不能忽略**，主动从 `endpoints[].enrichment` 的 asn/icp（org/isp 含 阿里云/Aliyun/腾讯/Tencent/华为/电信/联通/移动/ChinaNet，或归属国=中国大陆）捞出来列为调证目标。区分：App 自有/疑似后端要调；纯第三方 SDK/公共 CDN 共享域名（百度地图/umeng/个推下发）即便国内也是噪音。
2. **运营基础设施（第二优先）**：后台入口(admin_panel)、自建 IM/C2、短信验证码转发、硬编码后端凭据 → 可登录取证的运营端。
3. **境外服务器**：列出并做**被动 IP 归属**（RDAP/DNS/ASN/证书透明度 + 端口/技术栈作识别信号）、穿透 CDN 定位真实源站；不调证、不主动探测。
4. **降级、不再当重点**：钱包私钥/助记词、收款/四方支付——本口径下是死胡同。报告**保留但不高亮、digest 不排前、不作汇报重点**；仅用户明确要资金线时才展开。

**汇报模板（固定、限长、只产可办案信息）**
```
## <app名> 研判（sha256 前12位）
- 涉诈类型：<app_classification>
- 可调证后端（按优先级，≤6 条）：· <域名/IP> | 登记主体<国内云/IDC/ICP> | 调证落点：<向谁>，取<什么证据>
- 运营端线索：后台/自建IM/短信转发/后端凭据（有则列+调证落点）
- 境外 IP 归属 + 独特标识（被动）：<N 条>，<真实源站 IP / ASN·org 归属 / 证书透明度子域 / 技术栈指纹>（不调证，穿透 CDN 定位源站）
- 下一步取证动作：<1-3 条可执行>
（钱包/收款/四方支付：默认不展开，除非要资金线）
```

**动态：PCAP-first 保底，明文优先被动解密，探针是可选旁路（非必做）**：动态已转向**零注入 PCAP 底座**——`fxapk capture/auto` 起 floor PCAP，拿到接入节点 / SNI / QUIC Initial / socket 归因等被动证据即算**有观测产出**（不再以"抓到明文"为唯一成功标准）。但 `capture status=done` 只表示采集流程完成，不等于案件动态证据闭环：`case close` 只有观测到公网业务候选且能通过 socket/UID 归到目标 App 才把动态层判为 `complete`；有业务候选但归因不唯一为 `partial`；仅通道就绪或零业务流量为 `failed`。已知反诈拦截页不计业务候选。要明文时**优先走被动链路**：TLS Key Log + tshark 解密、socket 归因把流量落到进程 / UID / PID。Frida / native hook 降为**可选旁路**，仅当被动手段确实不够、且在 `--mode authorized-active` 授权下按需用。

**深度归因（拿到后端域名/IP/标识符后做服务器归因 + 调证报告）**：证据分级 + 对抗式核验 + **绝不编造**
（Shodan 等可实查的源据实查；无 key 的源只给"应向谁查什么"的语句，不臆造结果）+ 辖区驱动的调证优先级
+ 固定结构输出研判报告。**这些原则本身就是全部要求**——不需要额外手册；若用户另给了打法文档就照它，
没有就按此执行。

**禁止**：dump 全 report；手搓逆向；逐步复述工具过程；铺开"无需调证"的 SDK/CDN 噪音；把钱包/收款当重点。

---

## 0.6 工作流闭环：别做一半就当完成

分析一个样本**未走完闭环不算完成**。开工前先说清「这次要走到哪一步」；收工前逐条自检（动作见 §0.5 / 各命令）：

1. **静态**：`analyze` → `report.json` + `digest`，确有产出。
2. **动态**（有设备）：floor PCAP 保底；闭环完成要求 ≥1 个公网业务候选且明确归到目标 App。未唯一归因只能 `partial`，只有通道或零业务候选为 `failed`。要明文优先走**被动**解密（TLS keylog + tshark）。
3. **富化 / 判型**：每个「建议调证」端点判辖区 + 判前端/落地；富化源命中太少 = 源没跑全，别据残缺证据下结论。
4. **降噪**：剔反诈拦截页 / 大厂共享 / CDN 边缘，别当落地机。
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
| `fxapk corpus seen <值> --by so_sha256` / `corpus shared-native` | 跨样本操作，要先有库 | 想确认"这个样本属于哪个家族"时 |
| `fxapk config-channel --prefix … --domain …` | 前缀常量与基域**要你自己从样本常量里判断**哪个是 | 报告显示配置下发但静态无 URL 时 |
| `fxapk port-normalize --declared … --report …` | 声明端口来自**你的解密结果**，工具自己拿不到 | 解出配置里的 raw 端口后 |

### 0.6.2 ★ 顺着报告里的信号继续走（别停在"命令跑完"）

报告里出现下列信号时，**它就是在告诉你下一步该干什么**，不是结论：

- **`NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER`（回环占位架构）**：样本把非标准回环地址（如 `127.0.x.x`）
  硬编码成后端地址 + 存在 native 库 → **别对这个 127.x 调证**（对内网空调证）。真后端由 `.so` 运行时
  经下发通道（DNS TXT / 远程配置 / OSS 对象）决定。转去：① 动态抓包拿实际连接的公网 `IP:端口`；
  ② 或逆向 `.so` 的下发通道解出配置。
- **`meta.native_lib_hashes` 有值**：核心 `.so` 的 sha256 是**比签名证书更硬的家族锚点**（同族常逐字节
  相同）。入库后用 `corpus seen <sha> --by so_sha256` 一击拉出全家族样本。
- **解出了配置里的 raw 端口**：先别当成真实端口。部分家族运行时按固定规则归一化（如
  `真实 = 声明 + IP末段 + 常量`）。用 `port-normalize` 把**你解密的声明端口**与**报告里的实测端口**
  （`endpoints[].enrichment.runtime.remote_endpoints`）配对反推该规则——规则一致是很强的家族证据，
  规则不一致说明不是同一支。配对不足或过于齐整时它会判 `degenerate` 拒给结论，**别硬套**。
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

★ 最后那条不是可选项。hook 只看**已 staged 的新增行**，默认阻断疑似真实地址 / 凭据 / 无理由豁免；
放行单行需写理由（行内 `leak-scan: allow <理由>`）。CI 会对 PR diff 再扫一遍，`--no-verify` 绕不过。
**测试夹具一律用文档保留段**（`192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24` /
`2001:db8::/32` / `example.com`）——真实值一旦推上远端不可撤销，改写历史也删不掉平台缓存。

命令两种等价调用方式：`fxapk <cmd> ...`（装好后）或 `python -m apkscan.cli <cmd> ...`（免装）。

---

## 1.5 真机取证机准备（Android，动态分析前置）

脱壳 / 抓包 / 去壳重打包都需要**已 root 的 Android 真机或模拟器**（frida-server 必须 root 跑）。**纯静态 `analyze` 不需要设备**。一次性配置：

1. **root**（以红米 K40＝代号 `alioth` 为例）：解锁 BL（登小米账号 + 插**任意 SIM**翻开关，翻完可拔；小米有强制等待期）→ 取**与当前 MIUI/HyperOS 版本完全一致的 boot.img** → Magisk「安装 → 修补文件」生成 `magisk_patched.img` → `fastboot flash boot magisk_patched.img`。给 **shell（adb）授予 su 权限**（doctor 的 root 判定就认 `adb shell su -c id` 出 uid=0）。
2. **一键体检 + 自愈**：`fxapk doctor`（默认即 `--fix`）—— 自动按设备 ABI（K40＝arm64-v8a）+ 主机 frida 版本**下载并部署 frida-server、起进程、把 mitmproxy CA 装进系统信任库**，逐项报 OK / 怎么修。这一步能修的都自动修，别手动逐个搞。
3. **装 APK 绕过 MIUI「USB 安装要插 SIM」闸**：root 后不用开"USB 安装"那个 SIM 限制开关，直接
   `adb push x.apk /data/local/tmp/ && adb shell su -c 'pm install -r -t /data/local/tmp/x.apk'`。
4. **验证**：`frida-ps -U` 能列出设备进程 = frida 通；`fxapk doctor --no-fix`（纯体检、什么都不改）全绿即可开跑 `fxapk auto`。

常见坑：
- **frida-server 从 GitHub releases 下载**——PC 在国内无代理会失败/慢。解决：挂代理；或手动下 `frida-server-<主机frida版本>-android-<abi>.xz`（版本须与 PC `frida --version` 一致，doctor 已自动对齐版本号）push 到 `/data/local/tmp/frida-server` 自起。
- **mitmproxy CA** 仅 HTTPS 抓包要：先 `pip install mitmproxy` 跑一次 `mitmdump`（Ctrl-C 退）生成 `~/.mitmproxy`，再 `doctor --fix` 装系统证书。
- **boot.img 必须与当前 ROM 版本匹配**，否则 bootloop。
- 取证测试机建议用**一次性小米账号 + Magisk**，别登个人账号。

---

## 2. 全套分析（核心流程）

```bash
# ① 跑分析 → 产出报告（默认联网富化；--offline 跳过所有联网富化）
fxapk analyze <sample.apk> --online --out out --fmt html,json
#   产物：out/<样本名>.json（完整报告） + out/<样本名>.html（人看）

# ② 把完整报告压成【紧凑调证摘要】供你（agent）低 token 消费、直接决策
fxapk digest out/<样本名>.json
#   摘要：leads 按优先级排序（建议调证 > 待核 > 无需调证；高可信/C2 在前）+ 计数摘要。
#   高敏值（钱包私钥/助记词、后端凭据、个人隐私数据、加密配方）默认**已脱敏**——这条命令的输出
#   通常直接进你的上下文，安全的那一档就是默认档。
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
- `fxapk unpack` / `fxapk capture`：真机脱壳 / 抓包（需 adb 设备 + frida；`analyze --dynamic` 会自动接力）。
- `fxapk repackage <apk>`：脱壳后把**去壳版**重打包（zip 替 DEX + apksigner 重签）装回设备，使 capture 抓去壳版（绕壳反 frida）。需 apksigner/zipalign + 设备；auto 默认含此步（`--no-repackage` 关；重签必卸原包会清 app 数据）。能力边界：治不了 VMP/重 native/反模拟器壳，多数样本预期降级、capture 仍跑原版。
- `fxapk corpus`（**资产沉淀主线**）：`corpus add <report.json...>` 把历次报告入库——主键 `(sample_sha256, tool_version, ruleset_digest)`，同版本同规则幂等跳过、换版本并存做**跨版本回归基线**；`corpus seen <值> [--by sample_sha256|package_name|sign_sha256|so_sha256]`「这值见过没」反查（`--by sign_sha256` 按共享签名证书一击串案；`--by so_sha256` 按 native 库哈希一击拉全家族——同族核心 `.so` 常逐字节相同，比签名更硬）；`corpus shared-native` 列出被 ≥2 样本共享的 `.so`（家族簇）；另有 `corpus ls`（过滤列举）/ `reindex`（自愈索引）/ `events`（吐 JSONL 喂 agent）。★库根须 `--corpus` 或环境变量 `FXAPK_CORPUS` 显式指向 **git 工作树外**（含真实案件数据），否则拒跑（exit 2）。
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

## 3. 境外源站 IP 被动归属（联网富化，`--online` 时生效）

对「建议调证」的域名/IP 端点做**两遍富化**（全程被动、对目标零流量，绝不主动探测 / 攻击）：
1. **第①遍·归属** → 判服务器**辖区**（国内/境外/未知）：rdap/whois/dns/asn/icp。
2. **第②遍·境外源站被动归属**（仅**境外+未知**端点）：识别"这是不是真源站、归属哪、跟哪些资产关联"。

| 开关（写进 `.env`） | 能力 | 性质 |
|---|---|---|
| `FXAPK_SHODAN_KEY` | Shodan 被动查库：host/IP/ASN/org/country/开放端口/服务 banner/产品版本/关联主机名——判断是否真源站、归属哪家 | 被动·对目标零流量 |
| crt.sh（免 key，默认开） | 证书透明度关联子域 → 提取独特标识、串案 | 被动 |

**技术栈指纹（`exposure`，纯映射·零网络·零 payload·默认开）**：把 shodan 已采集的被动 banner 映射到**技术栈/后台框架指纹**（PHP/Laravel/ThinkPHP/Spring/致远/泛微/通达OA…），作为**同后台=疑同团伙的串案信号**——**仅识别、只用于串并**，不做漏洞方向研判、不利用。

**结果在哪看**：境外归属证据并进对应 Lead 的 `evidence_to_obtain`/`notes`（自动进 `digest`），例如
`Shodan 归属：ASN4134 / 80(nginx 1.18) …`、`技术栈/后台指纹（仅识别·串案用）：PHP、Jeecg-Boot…`、`关联子域(crt.sh)：…建议并簇串案`。
结构化 `overseas_targets` 段每主机带 `tech_stack[]` / `related_subdomains[]` 字段供 agent 直读。

**取证原则（辖区分流）**：
- **国内服务器** → 走「调证」：向境内云厂商/IDC/ICP 依法调取日志/租户实名。
- **境外服务器** → **不走调证**：目标是**被动定位真实源站服务器 IP + 提取独特标识**（ASN/org 归属、证书透明度子域、技术栈指纹），供后续依授权途径处置，**不主动探测、不攻击**。
  - ★ 若解析 IP 全是 **CDN/反代（如 Cloudflare）** → 那是边缘节点**非源站**：取证落点会提示
    「先被动穿透 CDN 定位真实源站 IP（历史 DNS/证书透明度 SAN/源站泄露/错配/邮件头），再做归属」。**别向 CDN 调证。**

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

**② `repack_identity` —— 这是自研马甲包，还是正版被重打包**

两种形态的**接口 / 域名 / 构建路径归属完全相反**：

| verdict | 这些资产属于谁 | 能否作线索 |
|---|---|---|
| `self_built` | 团伙自建 | 可以 |
| `repack_suspected` | **被仿冒的正版厂商** | **不可以**——列进清单＝向无关企业发函 |
| `unknown` | 未定 | 先人工核 |

判为 `repack_suspected` 时，工具只声明「疑似被重签名」，**永远不会说「植入了什么」**——那必须与
官方同版本包逐文件差分才能认定。你也不要替它下这个结论。

**③ 顺带**：`findings` 段（排在 visibility 与 leads 之间）承载 leads 不表达的事实判断——
通讯录窃取接口、域名轮换机制、未知壳、重打包警示。只列 CRITICAL/HIGH/MEDIUM，
`counts.omitted` 会告诉你省了多少条。

### 4.1 线索与归属

- 一切以 **leads** 为中心：每条带 `category`/`value`/`subject`/`advice`(建议调证/待核/无需调证)/
  `where_to_request`/`evidence_to_obtain`/`notes`。**优先看 advice=建议调证 的**。
- **结构化境外源站归属**：`digest` 输出含顶层 `overseas_targets`（也在 `report.meta["overseas_targets"]`），
  **按主机机器可读**——`[{host, ip, jurisdiction, asn, org, country, ports[],
  services[{port,product,version}], tech_stack[], related_subdomains[]}]`。要"列所有源站开放端口"
  "按技术栈指纹比对疑同团伙""汇总关联子域串案"时**直接读这个段**，别去解析 evidence 的自然语言串。
  仅【境外+未知】主机入此段（国内走调证不在此列）。
- `report.meta` 还含 `app_classification`(涉诈类型研判)、`sample_sha256`(检材指纹)、`enriched_target_count` 等。
- 先 `digest` 拿摘要决策；要细节再读 `out/<样本名>.json` 全量（`endpoints[].enrichment` 有富化原始数据）。

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
