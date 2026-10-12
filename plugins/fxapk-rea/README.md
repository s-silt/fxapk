# fxapk-rea

可选 REA 网页观察插件，版本 0.1.0。要求 Python 3.11+、fxapk 1.18.1+。
提供 `fxapk rea capabilities`、`inspect`、`import`，以及可选的 `trace`。没有 auto/capture/case close 钩子。核心收到 `--web-supplement` 时，按入口白名单调用本插件的 `run_supplement`；那不是本插件自己注册的 auto 或 case close。
核心源码须包含 `rea` 注册项；旧版 1.18.1 的白名单可能尚无该项，请使用本插件对应的核心修订。

## 安装

在仓库根目录、现有 fxapk Python 环境执行：

```powershell
python -m pip install -e .
python -m pip install -e ./plugins/fxapk-rea
fxapk rea --help
```

离线 import 不需要 Node、REA 或浏览器。在线观察目前只验收 REA **6.4.0**；其他版本拒绝执行，需核对契约后更新支持列表。
`trace` 不依赖 Node 或 REA。它使用可选 extra `trace`（`websockets>=13.1,<14`），采集时才导入。未安装该 extra 时，`import`、`inspect`、`attach` 和 `trace --help` 仍可使用；真正采集失败，稳定原因是 `trace_dependency_missing`。换一台机器复跑 trace：Python 3.11+、调用方已经启动并打开页面的 Chrome（数字回环 HTTP CDP），以及这个 extra。三者缺一，采集不会假装成功。REA `inspect` 另要本机 Node 与 REA 6.4.0，不能用 Chrome 加 `[trace]` 代替。

```powershell
python -m pip install -e "./plugins/fxapk-rea[trace]"
```
Node 和 Chrome 系浏览器另行准备；插件不会安装/更新软件、注册全局 MCP 或启动浏览器。
Windows 请将 `--rea` 指向安装包的 `scripts/rea.mjs`，可用 `--node` 指定 Node；不执行 `.cmd`/`.bat` 或 npx 下载命令。
Unix 可传本地可执行 REA 启动器；未传时查找 PATH 的 `rea`。

## 自动补采

`analyze`、`analyze-web`、`auto` 接受 `--web-supplement <本地JSON>`。已有报告用 `fxapk supplement-web <report.json> --web-supplement <config> --out <new-out-dir>`，只补网页材料，不重跑 APK、不碰设备、不做闭环。未装插件时这条命令的 `--help` 仍可看；执行时给出稳定不可用，不假装已经采集。fxapk 按配置和本机能力调度本插件，把解析增量放进报告。调用方不必先手工跑齐 `capabilities` / `inspect` / `trace` / `import` / `attach`。`inspect` 仍是独立的 REA 入口。同窗口实时采集只接受 `trace` / `fxapk-cdp-trace`，不是 REA inspect。`provider=rea` 或 `inspect` 且 `source=cdp` 会以 `provider_mismatch` 跳过，不会改成 trace。`bundle` 在核验回执前不能当成已选 REA 引擎。本插件没有新的 case close。

配置可以带严格布尔 `related_targets`，默认 false。显式 true 时，即使 `exact_origins` 只有一个，也允许采集该 exact origin 上的 Dedicated Worker 和 OOPIF。多个 `exact_origins` 仍按原规则打开相关 target，不会把未列出的 origin 加进授权。`navigate`、`click_selector`、`pause_related_start` 不是这份配置的字段。要这些动作，先在已授权的 `fxapk rea trace` 上显式传入 `--navigate` / `--click-selector` / `--pause-related-start`，再把产出的 bundle 交给 `supplement-web`。自动主路径不会代填这些开关。不采集 service worker 或 shared worker，也不自动打开 WebView 调试或把流量写成 App 归因。

`source=bundle` 或 `source=rea-json` 做离线校验。REA 6.4.0 的完整 CLI JSON 可以直接作为 `rea-json`。`source=cdp` 还要配置里的 `authorized=true`、数字回环 `endpoint`、`target` 和 exact `exact_origins`。缺这些不改设备，也不把授权写成已经连接。`live_cdp` 只跟随插件实际返回的布尔值。

CDP/trace 的 `scripts/<sha256>.js` 是 CDP `sourceText` 按 UTF-8 编码后的字节，不是该 URL 的原始 HTTP 响应体。本插件可选安装，与 Android UI 插件无关。计划字段和 `not_applicable` / `pending` 的差别见仓库 [AGENTS.md](../../AGENTS.md) 的网页补采段。真实 Android WebView 尚未实机验收。低信任候选进入现有解析器：新候选为待核 / LOW，证据范围为 `batch_reference`（`EvidenceScope.BATCH_REFERENCE`）。同值旧线索保持原等级。不自动走第三方富化或案件闭环。动态单轮/三轮是否回填，以该次报告里的 `meta.web_supplement` 与 `meta.web_supplement_runtime` 为准。

## Native 地址恢复

只读，不跑样本，不闭环。当前只识别 PE 与 ELF，没有 Mach-O，也不从 IPA 抽切片。Ghidra 在 Windows 上只收 x86/x64 原生 PE，不能拿抽出的 Android `.so` 去 inspect。Linux 和 macOS 上结构合法的 ELF 交给 Ghidra 的门是开的，Linux 实跑尚未验收。IDA 与 Hopper 不因名字出现在允许列表里就被当成可用。`--toolchain` 的 `ghidra` / `java` 只写入这一次子进程环境（`GHIDRA_INSTALL_DIR`、`JAVA_HOME`），不改全局配置。文件里的 `node` 键当前不读取；node 用 `--node` 显式传入，或接到运行时已有的 node 字段。`capabilities` 调 REA `providers --format json --full-output`，按 `analysis_provider_candidates[].provider.id` 和 `availability.status` 选择；省略 `--provider` 得到 `listed`，解析成功本身不是 `ok`。`doctor.healthy` 不是这个判断。

单文件读取上限 64MiB。`address-to-file-offset` 返回的 `file_offset` 是文件偏移。`read-bytes --length` 是有界观察。两者都不进入 recover。配方的连接运算有标识个数和展开字节上限，终止转换必须是最后一步。字节对上只说明声明过的变换重算成功，不是所有静态算法都能自动破解。`relation_verified` 仍是 false。

Windows（PE，不要接 Android `.so`）：

```powershell
fxapk rea native capabilities --provider ghidra --rea C:/tools/rea/scripts/rea.mjs --node C:/tools/node.exe --toolchain C:/tools/local-toolchain.json
fxapk rea native inspect C:/samples/native-x64.exe --provider ghidra --operation function --query decode_host --rea C:/tools/rea/scripts/rea.mjs --node C:/tools/node.exe --toolchain C:/tools/local-toolchain.json --out out/native-inspect-01
fxapk rea native inspect C:/samples/native-x64.exe --provider ghidra --operation address-to-file-offset --query 0x1000 --rea C:/tools/rea/scripts/rea.mjs --node C:/tools/node.exe --toolchain C:/tools/local-toolchain.json --out out/native-map-01
fxapk rea native recover out/native-inspect-01 --recipe recipe.json --out out/native-recovery-01
fxapk rea native attach out/native-recovery-01 --report out/app.json --out out/app-native-01
```

Linux / macOS（ELF；实跑未验收）：

```bash
fxapk rea native extract app.apk --member lib/arm64-v8a/libsample.so --out out/native-extract-01
fxapk rea native inspect out/native-extract-01/binary.bin --provider ghidra --operation function --query decode_host --rea /opt/rea/scripts/rea.mjs --node /usr/bin/node --toolchain /opt/local-toolchain.json --out out/native-inspect-01
```

`local-toolchain.json` 可以含 `node`、`ghidra`、`java` 路径，但当前只用 `ghidra` 和 `java`。attach 会重算身份和内容摘要，并复制有界的 `native_recovery_input`、native recovery 文件和网页观察附件。PCAP 等未搬运类型仍只在 `source_artifact_base`。

## 命令

```powershell
fxapk rea capabilities --rea C:/tools/rea/node_modules/rea-agents/scripts/rea.mjs

fxapk rea inspect --rea C:/tools/rea/node_modules/rea-agents/scripts/rea.mjs --endpoint http://127.0.0.1:9222 --target TARGET_ID --origin https://example.test --observation-ms 10000 --out out/rea-observation-01

fxapk rea import ./saved-rea-output.json --out out/rea-import-01

fxapk rea trace --endpoint http://127.0.0.1:9222 --target TARGET_ID --origin http://127.0.0.1:8765 --observation-ms 10000 --out out/cdp-trace-01

fxapk rea attach --bundle out/cdp-trace-01 --report D:/evidence/sample-report.json --out D:/evidence/sample-report-web --context-record D:/evidence/context-record.json
```

没有 `fxapk rea verify`。手工 `attach` 在写入新报告目录时核验。`--web-supplement` 是另一条校验并解析入口：通过后把增量送进同一次主报告的现有解析器，不靠 `attach`。

```powershell
fxapk rea capabilities --provider trace
fxapk rea capabilities --provider attach
```

默认 `capabilities` 仍只探测本机 REA，浏览器为 `not_probed`。`--provider trace` 只检查 `websockets` 能否导入以及版本是否在 `>=13.1,<14`，浏览器仍是 `not_probed`，不启动浏览器、不联网。`--provider attach` 报告离线 `offline_available`。`status=ok` 只表示本地前置满足，不是实测。

`capabilities` 检查本地 REA 启动和版本，明确将浏览器标为 `not_probed`；inspect 的 available 只表示本地运行条件通过，不证明页面/CDP 可用。

`inspect` 连接调用方已准备的 **数字回环 HTTP CDP 地址**，显式绑定 target ID 和单个 exact origin。该浏览器的网页访问及业务动作须在授权范围内。这条 REA 命令只观察，不导航、不点击、不读取 Cookie/存储值、不抓取 source map。它没有 trace 的跨 frame、worker 或 parentId 桥。
默认保留脚本原文和 JSON 字段结构；控制台文字须加 `--console-text`，可访问性文字不采集。
origin 过滤限制 REA 证据采集范围，**不是网页流量防火墙**，不能阻止浏览器自身联网。
target ID 可用 REA 的 `list-browser-targets` 查询。观察窗口从 REA 实际附加开始，不从 fxapk 进程启动开始；版本探测存在启动延迟。需保留独立动作记录，不能仅凭运行时长猜测已开始观察。

`trace` 是独立提供方 `fxapk-cdp-trace`，不是 `capabilities` / `inspect` / `import` 的完成态，也不读取 REA 版本或 REA 记录。它只附着调用方已经打开的数字回环 HTTP CDP。先校验端点、target 和 exact origin，再 claim 输出目录。HTTP 发现禁止代理和重定向，浏览器 WebSocket 必须是同一主机和端口上的 `/devtools/browser/`。只附着给出的 page target，启用 Page、Runtime、Debugger、Network，并把 async stack depth 设为 32。`ready.json` 只在这些命令都 ACK、顶层 frame 树属于该 origin、且已经看到同一 origin 的执行上下文之后写出。没有这份回执就表示还没开始记录。它表示本次附着已开始记录，不保证之后的事件一定送达。

附着发生在浏览器和页面已经启动之后，观察不到附着前的脚本解析和请求。默认不导航、不点击、不执行页面业务脚本、不设断点、不恢复别人暂停的 debugger，也不关闭浏览器。结束时只 detach 自己附着的 session。顶层 frame 离开 exact origin 时，采集以稳定原因 `top_frame_origin_rejected` 失败，不把新的站外 URL 写入产物。origin 过滤只决定持久化范围，不是流量防火墙。

显式选项才产生动作，默认保持关闭：

- `--navigate <同源 URL>`：观察 ready 之后做一次同源导航。origin 不一致则失败，原因 `navigate_origin_rejected`。
- `--click-selector <顶层 DOM 选择器>`：选择器解析失败则整次失败，原因 `click_selector_failed`。不注入脚本，不断点。
- `--related-targets`：才附着已选 page 的后代里、URL 的 exact origin 与给定 origin 相同的 iframe 和 Dedicated Worker。默认关闭时这些子 target 不进入采集。shared / service worker 仍然拒绝。OOPIF 要显式打开该开关，并且 origin 必须是精确相同的那一个，不能为了收进子 frame 放宽 origin。

动作记录保留种类、ACK 和时间。请求只落在候选窗口里。`click_attribution_verified` 仍是 false。ACK 不是完整的点击因果。

下面两个开关已经实现，默认都是 false，并且都必须同时带 `--related-targets`：

- `--related-origin`：可重复。每个值是 exact origin，最多 8 个，加在页面 origin 之外。不带 `--related-targets` 时失败，原因 `related_origin_requires_related_targets`。
- `--pause-related-start`：只暂停本次相关 target 里 `waitingForDebugger` 的启动，并在继续前对自己的会话调用 `Runtime.runIfWaitingForDebugger`。成功和失败都写入 `capture.startup_interventions`（带 `ack`）。失败不是成功采集。不带 `--related-targets` 时失败，原因 `pause_related_start_requires_related_targets`。

所有显式开关默认关闭。关闭时不导航、不点击、不附着相关 target，也不恢复别人暂停的 debugger。一旦打开 `--pause-related-start`，自己的等待恢复会出现在 startup interventions 里。REA 的 `inspect` / `import` 仍然没有这条跨 frame、worker 或 parentId 桥。

子 session 的 scriptId、requestId、contextId 按各自 session 保存，不能和主 session 的同号记录合并。`Page.frameDetached` 与 context 销毁留在原件里，用来结束该 frame 或 context 的寿命。worker 没有 frame 时保留 `worker_target_id`，`frame_id` 为空，并带 `loader_unknown`；覆盖仍是 `partial`，不把它写成 page frame。

跨 frame 的异步祖先用祖先自己的 frame、loader 和 epoch 核对，不用请求所在 frame 冒充祖先。缺偏移或 frame 未知仍然拒绝配对。非零 `startLine` / `startColumn` 只在依据明确时按 CDP 的 UTF-16 代码单元换算，并认 LF、CR、CRLF、U+2028、U+2029。`parentId` 用有界的 `Debugger.getStackTrace` 补取：缓存、去环、限深、限次数，debuggerId 必须落到对应 session。补到的栈和原始响应都留 JSON Pointer。浏览器没有 parentId 时不编造，缺口保持 `unresolved_parent_id`。这些都只属于 trace。REA provider 没有同等桥。

原始包上限 256 KiB（`256 * 1024` 字节）。事件最多 1024 条，源码最多 64 份。单份源码上限是 `48 * 1024` 个字符，不是 48 KiB。源码写入包内时还要受整包 256 KiB 的 UTF-8 字节预算约束。JSON 记账含逗号和空格。async stack depth 固定 32。采集按单条 JSON 增量记账，上一条源码计入预算后才取下一条。超限整次失败，留下仍是合法 JSON 的已筛选部分原件，并在 `capture.stopped_reason` 记录原因；不按字节截断，也不把这份原件当成完整成功采集。失败的命令回包不会继续取源码。只有 `Debugger.getScriptSource` 的命令错误记为 `source_unavailable`。`trace_limit`、`trace_oversize`、`trace_deadline`、`top_frame_origin_rejected` 和 CDP 传输失败会结束采集并关闭自己的 socket，不写成功的 observation。清理自己的 detach 或 socket 失败时同样不能记成功。落盘事件只保留投影所需字段，不是完整 CDP 协议。请求头、Cookie、postData 和站外 URL 在写入前丢掉。相对路径和 `sourceURL` 可以保留，但不表示那是一次网络下载。选定的 session 和 origin 对每条事件都生效，包括启动阶段和等待命令回包的时候。

`import` 只读取本地完整 CLI JSON（REA `--format json --full-output`），核验 provider/operation、target/origin 绑定、窗口、脚本内容哈希和大小。可加 `--expected-sha256` 核验输入原件哈希。成功的离线 import 在回执上写 `acquisition.kind=offline_import`，只表示这份记录来自本地文件导入。`project` 本身不写获取模式。`--expected-sha256` 只做可选字节核对，回执不因此增加 `expected_sha256_checked`，也不把认证、APK 身份、点击或闭环改成 true。
`inspect` 成功时写 `acquisition.kind=local_cdp_observation`，不会被离线导入的 kind 覆盖。
所有输出必须使用新目录，拒绝覆盖已有目录、文件或符号链接。不存在的父目录会创建。离线 import 在创建输出目录之前校验原始 JSON；inspect 先 claim 输出目录，再校验 REA 运行时输出。inspect 校验失败会保留 marker，且不产生成功的 `observation.json`。claim 之后的执行失败，或发布中途写脚本/回执失败，保留 marker 以及已经写出的原始字节，不写成功的 `observation.json`，也不删除已经留下的字节。

## 产物与状态

- `rea-original.json`：REA 输入/采集输出的原始字节；不会重排或改写。
- `cdp-trace-original.json`：`trace` 的筛选字段包，schema `fxapk-cdp-trace/1`，producer `fxapk-cdp-trace`。`capture.debugger_enabled` 与 `async_call_stack_depth` 记录本次附着实际启用的 Debugger 和 depth 32。它不是完整原始协议。
- `trace` 的 `observation.json` 使用 schema `fxapk-cdp-trace-observation/1`。请求身份按事件发生时的 session、该跳自己的 frame/context 寿命、`loaderId` 和 `scriptParsed` 序号绑定，不用最终映射回写旧请求。每一跳保留自己的栈和原件 JSON Pointer（`cdp-trace-original.json#/events/...`、`#/sources/...`，parent 补取另有原始响应指针）。回执同时带上 capture 的 target、session、origin、工具版本和实际启用的 Debugger/depth。真正的 parent 组才把 `async_parent_present` 记为 true；没补到的 `parentId` 仍是 `unresolved_parent_id`。默认不采集 OOPIF / worker，缺口里保留 `oopif_worker_unsupported`。显式 `--related-targets` 且子 target 通过 exact-origin 准入后，才去掉这一条缺口；service worker 与附着前历史仍不因此消失。内联脚本只有偏移依据明确时才按 UTF-16 换算，缺偏移不猜测。覆盖保持 `partial`。`provenance_authenticated`、`target_app_attribution_verified`、`click_attribution_verified`、`closure_evaluated` 均为 false。身份桥不是通用点击证明。不要把这些 trace 字段写成 REA inspect 的能力。
- `scripts/<sha256>.js`：REA 提供方源码字符串按 UTF-8 编码后的字节，`representation` 为 `rea_source_text_utf8`。它不是该 URL 的原始 HTTP 响应体。CDP/trace 路径上的同名脚本同样是 CDP `sourceText` 的 UTF-8，不是原始 HTTP 响应体。文件名只来自这些 UTF-8 字节的 SHA-256。`rea-original.json` 仍是输入原字节，不因源码重编码而改写。
- `observation.json`：`rea-web-observation/1` 规范化记录、原件 JSON Pointer、哈希、观察窗口及缺口。`coverage.limitations_refs` 只指向原件里真实存在的 `data.limitations` 或 `data.normalized_result.limitations`。键存在且值为 null 或空列表仍然出指针；键不存在不出悬空指针。指针根固定为 `rea-original.json#/`。
- 网页观察方法见仓库技能 [skills/fxapk-web-evidence/SKILL.md](../../skills/fxapk-web-evidence/SKILL.md)。它是仓库内可读资源，不表示插件已把技能装进每个客户端。
- `fxapk-rea-bundle.json`：目录创建后、任何原始 JSON / 脚本 / execution 产物之前写入的本地 bundle 标记。它只声明“这是未验证的外部观察目录”，不认证来源。失败或只写出部分产物时标记仍然留着，入口据此拒绝把该目录当直接案件证据；不会为了失败而删除已留下的原始字节。
- inspect 另存 `execution/stdout.bin`、`execution/stderr.bin` 和 `execution.json`；失败时尽力写 `failure.json`。

退出码 0 / `status=ok` 只表示采集/导入处理成功。`coverage.status` 保持 `partial`：当前入口不保留原始网络正文，不提供逐请求时间，不验证 APK 身份，也不证明点击因果或案件闭环。终端只输出计数、哈希和稳定原因码；完整原值在本地产物中，不属于已脱敏报告。

控制台事件按 REA 原始时间戳与窗口标为 `inside` / `outside` / `unknown`；日志缺时间或旧日志重放不会当作本轮点击。该分类仍依赖提供方时钟，不是跨进程高精度因果证明。
请求的 `observed_at` 为 null，`raw_body_available=false`；不将 body shapes 填成 HAR 正文。provider v2 没有请求侧的 frame/script 身份，未知的额外 JSON 字段也不会被升成身份。只有 `initiator.type=script`、同一 URL 恰好一条脚本记录（含缺源码行）、该记录的 `frame_id` 唯一且 origin 与 URL 一致、并且发起者的 0 基行号和 UTF-16 代码单元列号落在捕获源码内时，才写入 `candidate_script_path`。此时 `script_path` 仍为 null，`binding` 为 `url_candidate_unverified`，`frame_identity_verified` 为 false，并保留缺口 `initiator_frame_identity_unverified`。这是坐标核对过的 URL 候选，不是已验证绑定。类型、源码、frame 或坐标不成立时，`candidate_script_path` 同样为 null。JavaScript 行终止符只认 LF、CR、CRLF、U+2028 和 U+2029。脚本 URL 与 frame 页面 URL 相同的内联脚本没有已证实的坐标基准：缺少偏移、非零偏移、残缺偏移，或 `start_line`/`startLine` 与条目/`source` 声明不一致，都不猜测减法，也不给出候选。只有全部声明都明确是 0,0 时才继续做捕获源码上的坐标核对，结果仍然只是未验证 URL 候选。
脚本产物的 `sha256` 只覆盖上述 UTF-8 源码字节。`cdp_hash` 与这份 UTF-8 是否同一表示没有已证实契约，因此 `cdp_hash_relation` 保持 `unverified`；哈希相等也不把 `provenance_authenticated` 设为 true。`target_app_attribution_verified`、`click_attribution_verified`、`closure_evaluated` 均为 false。

## 挂到报告

`fxapk rea attach` 离线运行。它读取一份已经发布的 REA 或 trace 观察目录，重读 raw、回执和每一份 `scripts/<sha256>.js`，对照 manifest 与哈希。失败包、篡改、链接或路径逃逸、重复 JSON 键、超量都拒绝，不写出成功报告。通过后只在**新的** `--out` 目录复制核验过的原件，并发布 `report.json`、`report.digest.json`、`report.html`。原报告不覆盖。`report.json` 保留原报告里未知字段，只增加 `meta.web_observations`。digest 与 HTML 走核心渲染，不把 URL、源码或自由文本抄进默认摘要。

旧的已挂观察会按原件哈希再验一遍。同一哈希不静默再计一条。把整个新目录挪到别处后，观察指针仍是 `external_observations/<sha256>/` 这种相对路径。文件哈希核验不是采集来源认证。`provenance_authenticated` 保持 false。不新增 endpoints 或 leads，不改 closure / runtime。`analyze-web` 和案件直接证据入口仍拒绝这些观察目录；attach 不绕过那条拒收。核心不导入本插件时，已写入的 `web_observations` 仍可由核心 digest / HTML / PDF 渲染。

可选 `--context-record` 是本地声明，schema 固定为 `fxapk-web-context/1`。必填只有 `schema_version`、`sample_sha256`、`target_id`、`origin`。`sample_sha256` 必须等于报告样本哈希；`target_id` 与 `origin` 必须等于该 bundle。可选字段只有 `package_name`、`process_id`、`webview_target_id`、`recorded_at`。多一个键就拒绝。声明匹配只表示文件对得上，`authentication` 记为 `declared`，`target_app_attribution_verified` 仍是 false。

```powershell
$sampleSha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
$contextObject = [ordered]@{
  schema_version = "fxapk-web-context/1"
  sample_sha256 = $sampleSha
  target_id = "SYNTHETIC-TARGET"
  origin = "http://127.0.0.1:8765"
}
$json = $contextObject | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText("D:\evidence\context-record.json", $json, [System.Text.UTF8Encoding]::new($false))
```

`$sampleSha` 必须换成该报告真实的 `sample_sha256`。示例里的 64 个 `a` 只说明字段形状。`origin` 与 `target_id` 必须与该 bundle 一致。

## 合成夹具

`tools/rea_trace_fixture.py` 已在仓库内。它只绑定 `127.0.0.1`，不启动浏览器。`--out` 必须尚不存在，命令自己创建该目录；不要求事先准备一份被忽略的 `out/` 实验树。父目录须已存在。模式在 URL 查询串：`/?mode=direct|crossframe|worker|oopif|inline|decoy`。请求日志追加写入 `server.jsonl`，失败行保留，不删日志。

```powershell
python tools/rea_trace_fixture.py --out .\fixture-run
```

标准输出一行 JSON：`origin`、`secondary_origin`、`pid`。页面用浏览器打开 `origin` 加 `/?mode=direct`。停进程后日志仍留在 `--out`。

`analyze-web` 和案件包的直接证据入口会拒绝可识别的 REA bundle，也会拒绝 producer 为 `fxapk-cdp-trace` 的原始包和观察回执（含改名和 gzip）。单独的传统命令 `trace` 与 `import` 不会自动进入报告；只有显式 `attach` 会为这些手工观察写新报告目录，而且只增加 `meta.web_observations`。自动补采 `--web-supplement` 另是校验并解析入口：`bundle` / `rea-json` 或已授权 CDP 通过后，把待核 / LOW / `batch_reference` 候选写入同一次主报告，不把观察目录交给上述直接证据入口。当前/旧版回执、完整原始信封，以及它们祖先链上的 `scripts/`、`execution/` 和嵌套文件同样拒绝。祖先同时看词法路径和解析后的物理路径，直到文件系统根；链长超过硬上限则拒绝，不截断后放行。目录联接不能把 bundle 标记藏到另一条词法路径后面。文件链接会同时检查词法路径和解析目标的内容；链接解析或读取失败则拒绝。普通非 REA 文件及其内容不是契约的别名仍可进入。证据根上的保留名 `fxapk-rea-bundle.json` 即使只是空目录、链接或非普通文件也会拒绝，不依赖遍历是否发现了别的普通文件。该保留名只要存在就拒绝，内容损坏或元数据读失败也一样；这不扩大到任意 `observation.json`。可导入的原始信封按 16 MiB 上限整份识别，不依赖字段顺序。同一次网页载入或案件包校验共用一个识别读取预算。它的默认值是 96 MiB，和网页正文合计上限数字相同，但是独立开关；改正文上限不会改变识别预算。按实际读到的字节计费。gzip 成功输出按实际长度计入；某次解压调用失败时，除了已经返回的字节，再保守计入该次调用的有界输出额度，因为 zlib 丢掉的输出长度不可知，且该额度已有上限。用尽即拒绝，不按文件把预算清零。案件包校验一旦碰到识别预算用尽，立即返回失败，不再识别、哈希或做后续完整性检查。识别看契约字段，不是“凡是 observation.json 或 .js 都拒绝”。这个边界挡不住把裸脚本拷走并删掉来源标记，也不声称能防止故意剥离来源。被拒绝的文件不会自动改判成 batch reference。

## 资源和失败边界

原始 JSON/stdout 上限 16 MiB，stderr 上限 64 KiB，数组/对象成员上限 4096，JSON 深度上限 48，总节点上限 100000。流在达到限额时截断并使执行失败，不将截断结果作为成功观察。
观察窗口最大 60 秒，执行另有 30 秒启动/收尾预算，版本探测限时 15 秒；底层进程树清理有独立预算。
插件复用核心 owned-process 管理，超时、残留子进程、未证实的进程树所有权均不能记为成功。不会关闭调用方原本的浏览器。
本地产物包含源码、URL 和可能的明文日志。使用受控输出目录；Windows ACL 继承父目录，不承诺通过 POSIX mode 实现账户隔离。

## 验证

```powershell
python -m pytest -q tests/test_rea_plugin.py tests/test_rea_runtime.py tests/test_plugin_registry.py
python -m ruff check apkscan tests plugins/fxapk-rea/src
python -m pyright apkscan plugins/fxapk-rea/src
```

CI 使用合成输入与 Python 子进程测试，不要求下载 REA 或浏览器。真实合成网页 smoke 的原件保留在本地实验目录，不进入公开仓库。

MIT；REA、Node、浏览器及各依赖遵循各自许可。
