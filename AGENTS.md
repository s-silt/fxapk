# AGENTS.md — fxapk 操作指南（给 AI agent）

fxapk（命令别名 `apkscan`）是 APK 调证取证分析 CLI：按能力门控做静态/动态证据采集、被动基础设施归属，产出**仍需过证据门的线索（leads）**。本文件只讲怎么跑；项目背景见 `README.md`，命令细节见 `USAGE.md`。

- 案件分析由一个 agent 在本次授权范围内独立完成并自检；资料要么在仓库内、要么由用户提供，不依赖隐含的仓库外资料。
- 不打包 exe/GUI。密钥放项目根 `.env`（已 gitignore）。输出面向 agent：调证信息进 `evidence_to_obtain` / `notes` / `report.meta`，`digest` 压成低 token 摘要。

## 1. 执行、授权与完成边界

- 用户已要求实施且范围明确时，完成必要调查后直接执行；用户要求先审后改时等批准。已有授权在同一对象、操作类别、数据范围和交付终点内持续有效；只问会改变目标、公共接口、权限、费用或不可逆后果的缺失信息。
- 缺失信息只阻塞依赖它的步骤，其余已授权工作继续；不猜测关键事实，不绕过平台审批。
- 「提交」止于 commit，「推送」止于 push，「发 PR」止于 PR，「合并」才含 merge。只要求修改时不主动提交。
- 外发消息、敏感数据传输、设备改动、破坏性操作按具体授权执行。工具建议、技能、命令模板和发现的凭据都不产生授权。
- 任务交付状态与案件证据闭环状态分别报告。外部缺口不触发无限重试或擅自扩大任务。
- 技能只在明确匹配或用户点名时使用，不得把自身流程当成新的权限来源。
- 测试范围由变更风险决定；同一内容已验证且无新疑点时不重复全套检查，但必要回归、泄漏扫描、合并检查和失败如实报告不能省。

## 2. 三条默认行为：新机器第一次跑之前先告诉用户

| 默认行为 | 会发生什么 | 避开方式 |
|---|---|---|
| `analyze` 默认联网 | 筛选后的域名/IP 交给 WHOIS、RDAP、备案、测绘等第三方；DNS 查询可能被解析器观察。不主动访问样本业务 URL，但不能说"零流量" | `--offline`；预演用 `--enrichment-dry-run` |
| `doctor` / `auto` 默认改设备 | `doctor` 部署 frida-server、装抓包 CA；`auto` 安装样本、尝试脱壳、跑原版基线。去壳重打包另受双门约束（见 §4） | `doctor --no-fix`；`auto` 只在已授权的专用测试机跑 |
| `digest` 默认有限脱敏 | 高敏类别值和线索自由文本里的固定形态隐私（邮箱/手机号/证件号/长数字串）被遮蔽；姓名、地址、境外号码和 findings/visibility/closure/overseas_targets 的说明文字不遮蔽 | 要原值加 `--no-redact`，那份输出别再贴给第三方 |

设备排查默认先 `fxapk doctor --no-fix`；修复前核对该设备和操作类别的授权。专用测试机身份不等于清数据、替换样本或行为修改授权。

**脱敏只管 `digest`。** 以下出口原样输出高敏值，运行时各自向 stderr 提醒一行：`jsonl` / `diff` / `lead show|restore|replay` / `corpus events|ls|seen|shared-config|shared-native|shared-build-env|link-candidates` / `probe-leads` / `pcap-leads`，以及 `export` CSV、HTML/PDF、文书、corpus 存证、`case_correlation.json`、`report.json` 本身。判断方法：它的 stdout 会不会出现线索值。`corpus link-discover|link-explain|link-groups` 默认 `--evidence-values omit`，显式 `raw` 即恢复原值；`link-labels-validate|link-evaluate|link-readiness|link-train` 只输出聚合结果。不要对用户说「已全部脱敏」。

## 3. 行为铁律：先跑 fxapk，据产物决策

命令产物（`report.json` / `digest` / corpus 台账）是事实来源，不是你的推测。不 dump 全 report，不逐步复述工具过程，不以手工推测替代证据；工具缺口经排查无法解决时，才对已授权检材做只读补充分析并记录方法与出处。

| 用户想要 | 执行 |
|---|---|
| 分析一个 APK | `fxapk analyze <apk> --out out`（默认联网，`--offline` 关）→ `fxapk digest out/<名>.json` |
| 一把梭 | `fxapk auto <apk> --fix --strict-case`（专用测试机已授权） |
| 已有报告补富化 + 五层闭环 | `fxapk case close <report.json>`（partial=5、failed=6） |
| 已落盘网页证据 | `fxapk analyze-web <目录> --out out`（默认离线，`--online` 只开归属富化） |
| 批量 | `fxapk batch <dir>` |
| 真机环境 | `fxapk doctor --no-fix`，授权后 `fxapk doctor` |
| 脱壳 / 重打包 / 抓包单步 | `fxapk unpack` / `fxapk repackage` / `fxapk capture <pkg>` |
| 串案、资产沉淀、反查 | `fxapk corpus add` / `seen <值> --by sign_sha256\|so_sha256` / `link-candidates` / `shared-native` / `ls` |
| 配置端口归一化规则反推 | `fxapk port-normalize --declared <json> --report <report.json>` |
| 运行时算法生成的配置子域 | `fxapk config-channel --prefix … --domain …`（纯离线枚举候选） |

`digest` 用于分流定位；形成归因、调证结论或正式报告时必须回查 `report.json` 的结构化字段与原始证据。命令失败先读 `playbook`，playbook 不产生新授权。

## 4. 案件分析流程与闭环口径

**调证优先级**（覆盖工具默认的高敏物证优先）：
1. 可依法调证的后端服务器：先证明端点属于 App 业务后端，再按辖区和可达法律渠道定调证对象。IP 资源持有者/起源 ASN、承载或 CDN 服务商、域名注册主体、ICP 备案主体是不同角色；ICP 只证明备案登记，不是云服务商。CDN 边缘不得写成 Origin 或运营者，但分发服务商可调账户、绑定域名、回源配置、访问日志。任何一层都不能单独证明端点由 App 运营。
2. 运营基础设施：后台入口、自建 IM/C2、短信转发、硬编码后端凭据。发现凭据不构成登录或访问授权。
3. 境外/辖区未知基础设施：被动归属（RDAP/DNS/ASN/CT + 端口与技术栈作识别信号），分层列边缘、承载方、Origin 候选、运营者。未经授权不主动探测。
4. 资金与高敏物证：默认降低展示优先级；需要资金线或身份线时再按授权展开。HTML/PDF/JSON/文书是受控内部视图，对外发布必须另做经审核的安全投影。

**流程**（只执行本次范围与授权内的步骤）：
1. 静态：`analyze` → `report.json` + `digest`。
2. 动态（已授权设备）：`capture --mode floor-only` 可不用 Frida 采 floor PCAP，但仍需 adb、root 与设备侧 tcpdump；默认 `capture`/`auto` 要 Frida。要明文优先 TLS keylog + tshark 被动解密。`auto` 默认三轮观察（PCAP / 通用探针 / 定向采集），`--single-round` 保留单轮；各轮分别留档，计数不跨轮拼接。去壳重打包的旁路轮只在原版基线可读、判据建议旁路、且显式 `--allow-behavior-modification --antidetect java` 双门时进入；`--antidetect` 只接受 `off`/`java`。只有实际注入行为修改 shim 的证据才标 `modified-runtime`；**旁路轮观测不得单独结案**。
3. 富化/判型：读逐目标、逐来源回执，区分 `hit` / `no_record` / `failed` / `skipped` / `disabled`；命中少可能是真无记录。
4. 降噪：剔反诈拦截页和大厂共享端点；CDN 边缘不当落地机。
5. 串案（已提供授权库时）：独特字值跨案自查。共享 native SHA、证书、域名或包名不等于同族或同一主体，须排除公共库、SDK、壳、构建链和正版重打包继承。
6. 五层闭环：`fxapk case close`，逐目标核验 ①运行时业务证据 ②IP 资源持有者 ③起源 ASN ④云/IDC/CDN 分发关系 ⑤最终调证对象。CDN 没有 Origin 必须保持 `partial`。
7. 验收：只有 `report.meta.closure.status=complete` 才能称证据闭环。`partial`/`failed` 原样汇报 `gaps` 与 `next_actions`。`auto --strict-case` 退出码 `0/5/6` = `complete/partial/failed`。

**动态证据口径**：`capture status=done` 只表示采集流程完成；`case close` 只有同一公网业务候选同时满足目标 App 归因、业务端点判定和双向载荷门才判 `complete`；归因不唯一、APK 身份未知或只有 modified-runtime 证据最多 `partial`；只有通道或零业务流量为 `failed`。探针线索的 confidence 是 advice 的投影：单源待核→LOW、建议调证→MEDIUM，只有 merge 阶段与静态/pcap 二次印证才升 HIGH。

**不会自动发生、需按范围手动补**：`corpus add`（库根须 `--corpus`/`FXAPK_CORPUS` 指向工作树外，否则 exit 2）；`corpus seen`/`shared-native`；`config-channel`（前缀与基域由你从样本常量判断）；`port-normalize`（声明端口来自你的解密结果）。

**报告信号即下一步**：
- `NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER`：回环占位地址不调证；真后端由 `.so` 运行时经下发通道决定，转动态抓包或逆向下发通道。
- `meta.native_lib_hashes`：入库后 `corpus seen <sha> --by so_sha256` 召回，再排除公共组件。
- 解出 raw 端口：用 `port-normalize` 与实测端口配对反推规则；`ambiguous`/`degenerate` 时不硬套。推导值必须标注，不可当实测。
- `DEX-STRING-POOL-OPAQUE`：是关于报告可信度的警告——字符串池类分析器的「未发现」不可解读为「不存在」。
- `APK-CORE-NAME-DECOY-ENTRIES`：绝对路径诱饵条目，别用落盘解压工具展开该样本；不宜单独当家族锚点。

**即时汇报模板**（限长，不代替正式报告）：
```
## <app名> 研判（sha256 前12位）
- 涉诈类型：<app_classification>
- 可调证后端（≤6 条）：<域名/IP> | 运行时关系 | 资源持有/ASN | 承载/CDN | Origin/运营者 | 向谁取什么
- 运营端线索：后台/自建IM/短信转发/后端凭据
- 境外/辖区未知候选：候选 N，已画像 P，未画像 U
- 下一步取证动作：1-3 条
```

收工必说清：做了什么 / 没做什么（为什么）/ 风险 / 下一步。

## 5. 读结果

读 leads 之前先过两道闸：

1. **`visibility`**：本次实际看到了什么。`sources` 给 dex/native/resource/runtime 各自可见性（`complete`/`partial`/`stub_only`/`opaque`/`unavailable`/`unknown`）；`blocked_claims` 列出无资格下的穷尽性结论——对应的「未发现」不得写成「不存在」；`next_actions` 说明怎么补。它与 `analysis_status`（工具跑没跑好）是两码事。
2. **`repack_identity`**：`self_built` 逐资产排除公共组件后才作候选；`repack_suspected` 先隔离可能继承的资产，与官方同版本差分后再判；`unknown` 人工核。工具只说「疑似重签名」，永远不说「植入了什么」。

然后：`findings`（CRITICAL/HIGH/MEDIUM 事实判断，`counts.omitted` 告诉你省了多少）→ **leads**（`category`/`value`/`subject`/`advice`/`where_to_request`/`evidence_to_obtain`/`notes`，优先 advice=建议调证）。

境外画像：`meta.overseas_targets` 是 **profile-only** 投影（只列 Shodan/CT 有实质画像的主机），必须同时读 `overseas_target_coverage` 与 `summary.overseas_*` 计数；「已画像 0」不等于「候选 0」。五层归因在 `endpoints[].enrichment["attribution"]`：`resource_holder → origin_network → hosting_provider → edge_provider → service_operator`，per-IP 产链，`service_operator` 恒 unknown，不从 ASN/RDAP 推断。**IP 落在某云厂商 ASN ≠ App 由该厂商运营。**

## 6. 网页观察与 Native 恢复（可选 REA 插件）

REA 插件默认关闭：即使已安装也不导入、不注册命令、不用于自动补采。仅在明确需要时为该进程设置 `FXAPK_ENABLE_REA=1`（PowerShell `$env:FXAPK_ENABLE_REA='1'`；Linux/macOS `FXAPK_ENABLE_REA=1 fxapk rea --help`）。未启用时 `selfcheck` 报 `disabled`。启用不等于授权浏览器、设备或联网，agent 不得自行设置该开关。

- 先读 `meta.web_observation_plan.agent_handoff` 和 `meta.web_supplement` / `meta.web_supplement_runtime` 最新回执；digest 按状态重算 handoff，handoff 不是授权。
- 无网页信号且无明示材料：不动作；`mode=off` 保持关闭。有信号但还没报告：在下一次本来要跑的 `analyze` / `analyze-web` / `auto` 上加 `--web-supplement <本地JSON>`。已有报告只补网页：`fxapk supplement-web <report.json> --web-supplement <config> --out <new-out-dir>`，不重跑 APK、不碰设备、不闭环。
- 提供方边界：`fxapk rea inspect` 是独立 REA 入口；自动同窗口 CDP 只接受 `trace`/`fxapk-cdp-trace`；`rea-json` 是离线材料；`provider=rea|inspect` 且 `source=cdp` 以 `provider_mismatch` 跳过。`fxapk rea attach` 只把核验过的观察挂到新目录，不晋级 leads/endpoints/runtime。没有 `fxapk rea verify`。
- Native：`digest.native_recovery` 只给固定命令。插件只认 PE/ELF；Windows 上 Ghidra 只接 x86/x64 PE，Linux/macOS 才 `fxapk rea native extract <apk> --member lib/<abi>/<name>.so` 再 inspect（Linux 实跑未验收）。配方只重算声明过的变换，`relation_verified` 保持 false。IDA/Hopper 未支持。
- 真实 Android WebView 尚未实机验收。细节见 `plugins/fxapk-rea/README.md` 与 `skills/fxapk-web-evidence/SKILL.md`。

## 7. 环境准备

```bash
pip install -e .                       # Python >= 3.11
cp .env.example .env                   # 本地密钥，绝不入库
fxapk selfcheck                        # 能力自检；不逐源检查 API key，命中看报告 source_status
git config core.hooksPath .githooks    # 提交前泄漏扫描，改代码必开
```

未装时用 `python -m apkscan.cli <cmd>` 等价调用。

**泄漏扫描**：hook 扫已 staged 新增行，默认阻断疑似真实地址/凭据、中文人名+案、QQ/微信/Telegram 联系方式、二开包名，finding 值自动脱敏。公开第三方库误判应登记到 `rules/`（`bank_packages`/`sdks`），不加行内豁免；豁免（行内注释 `leak-scan:` 后接 `allow` 与理由）只给判据要求真值字面的夹具，同一理由 ≥20 行触发 `bulk_exemption`。分支已有 commit 时用 `leak-scan --base origin/master --strict`（= CI），`--staged` 看不到已提交改动。文档里不要把豁免 token 连写成完整形态。夹具优先用保留地址和域名；必须具备公网语义时用 mock 或可审计合成夹具。

**真机**：需要已 root 的 Android 真机或模拟器；纯静态不需要。`fxapk doctor`（授权后）按设备 ABI 与主机 frida 版本部署 frida-server、安装 mitmproxy CA。两个易混淆点：Frida ≥17 的 Java bridge 由宿主应答（doctor 已检测，验收看 capture 报告 `frida_bridges`）；frida-server 能被 `frida-ps` 列出不等于以 root 运行（doctor 按 `/proc/<pid>/status` 判真实 UID）。mitmproxy 安装见 `tools/TOOLCHAIN.md`。

## 8. 联网富化

两遍门控：第①遍归属（rdap/whois/dns/asn/icp）形成辖区候选；第②遍只对境外+未知端点收集承载、边缘、Origin 候选（Shodan 为 `case_close_only`，由 `case close` 或 `enrich batch` 调用；crt.sh 免 key 默认开）。不向目标业务服务主动探测。`exposure` 技术栈指纹是零网络映射，只作弱候选。`enrich batch` 默认 `--dry-run` 只估配额，确认后 `--no-dry-run`。源不适用与查无记录分开标注——工具失败 ≠ 阴性。

## 9. 开发约定

- 文档/指令变更只做格式、引用、契约与泄漏检查；代码行为变更必过本地三关：`python -m ruff check apkscan tests` + `python -m pyright apkscan` + `python -m pytest -q`。`-m "not slow"` 排除需要 `FXAPK_TEST_APK` 的真 spawn 等价测试。
- Python type hints；pytest，不用 unittest。富化器继承 `BaseEnricher`，失败返回 `EnrichmentResult(ok=False)`，不裸 except、不吞 log。
- 分析器并行（`core/pipeline.py` + `snapshot.py`）守「串行 == 并行 逐字节一致」；set 派生顺序显式排序。逃生开关：`FXAPK_NO_PARALLEL=1`、`FXAPK_MAX_WORKERS=N`、`FXAPK_WORKER_BASE_MB`、`FXAPK_MEM_SAFETY`。
- CI 装 `pip install -e "."`：可选依赖进 `pyproject` extra，需要它的 CI job 要装；依赖 extra 的测试 `pytest.importorskip`。可选插件默认发现不得让坏插件拖垮核心命令。
- 合并前等 CI 绿（`gh run watch <id> --exit-status`）；不 `--no-verify`，不 force push master；未经指示不主动 commit。

## 10. 已否决的方案

- 二进制紧凑端点数组提取（`[IPv4(4)+port(2)]` 记录）：随机/密文字节约半数会被判成端点，且解码链够不到解密后明文——取证工具凭空造 IP 一票否决。
- Brotli 剥层：Python `brotli` 没有输出上限，无法限住峰值内存，且真样本里它在 RSA 解密之后、仓内管线够不到。

通则：**宁可漏，不可造。** 启发式若能凭随机字节产出看似权威的调证目标，一律不做。
