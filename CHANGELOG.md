# Changelog

Notable changes to fxapk. Versioning is semantic; **behavior changes that
affect automated / CI / agent callers are called out explicitly**.

## Unreleased — 待发布（拟 1.2.0）

Theme: **1.1.0 之后的功能收敛 + 静默损坏类修复**——移除从未真正落地的 iOS 与 webcheck 两条支线，
并修一批「不报错但结果悄悄错」的缺陷（.env 加载 / 远程配置解码 / 子进程编码 / CFB8 解密 / IOC 导出）。

### Removed

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
