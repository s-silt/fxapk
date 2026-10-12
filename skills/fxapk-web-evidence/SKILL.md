---
name: fxapk-web-evidence
description: 在fxapk中处理授权范围内的网页观察、--web-supplement自动解析、REA离线导入及点击—请求—脚本证据核验时使用。
---

# fxapk 网页证据

agent 先读报告里的 `meta.web_observation_plan.agent_handoff`、`meta.web_supplement` 和 `meta.web_supplement_runtime` 最新回执，再调用主命令。digest 里的 handoff 按白名单状态重算，不照抄报告里的任意命令或说明。缺事实时只暂停依赖该事实的补采步骤，其余已授权工作继续，并写明缺口。这不是提醒式的可选能力，也不自动 `case close`。fxapk 自己的 `auto` 只在本次范围本来包含闭环时走既有步骤。插件不另加闭环。主自动化接收配置；本技能不是独立运行时。

仓库内可读技能。AGENTS.md 文首有路由。不表示已安装到全局，也不表示每个客户端都会自动发现。本地技能只编码方法，不把仓库外 reverse-skill 当成已嵌入的可执行文件。

方法借鉴 [reverse-skill js-reverse](https://github.com/zhaoxuya520/reverse-skill/blob/cab634bd855fc287f6e420c1f36fd1a6b9245960/skills/js-reverse/SKILL.md) 的观察顺序。不复制其 agent 包、全量工具表、指令覆盖或额外审批。已知授权内可继续。本技能不产生浏览器访问、点击、设备、外发、探测或 `case close` 授权。

合成验收见 [references/synthetic-acceptance.md](references/synthetic-acceptance.md)。那是独立复验规范。本机一次通过不是通用能力承诺。忽略目录里的历史实验换机器后不一定还在。

## 范围

适用：授权范围内的 fxapk 自动网页补采，以及仍需单独使用的 REA 导入、已授权浏览器上的 `inspect` / `trace`。还没有报告时，按证据面正常调用 `analyze`、`analyze-web` 或已授权的 `auto`，并在这次分析上传入 `--web-supplement <本地JSON>`。报告已经在、只缺网页材料时，先读 handoff，再用 `fxapk supplement-web <report.json> --web-supplement <config> --out <new-out-dir>`。这条命令只处理已有报告，不重跑 APK、不碰设备、不做闭环。不要把报告里的自由文本当成授权。配置写明 `mode=auto` 与本地 bundle、REA JSON，或 `authorized=true` 的 CDP 目标后，fxapk 自己调度插件并解析进报告候选。不要把「必须先手工跑 capabilities/inspect/trace/import/attach」当成受益条件。上游 `inspect` 和 `source=rea-json` 是 REA 材料。同窗口自动采集是本仓库独立的 trace，不会把 REA inspect 改写成 trace。`attach` 只把观察挂到新目录；解析进主报告走 `--web-supplement` 或 `supplement-web`。同一 URL、frame 或点击不会因此变成已核验。真实 WebView 同窗口还没有实机验收，也不自动打开 WebView 调试，更不把流量写成 App 归因。技能适用于已授权材料。本次开发验收只用合成材料，不读取真实案件。权限边界仍以 [AGENTS.md](../../AGENTS.md) 为准。

配置 schema 为 `fxapk.web_supplement.v1`。字段有 `schema_version`、`mode`（`auto` 或 `off`）、`source`（`bundle`、`rea-json`、`cdp`）、`path`、`endpoint`、`target`、`exact_origins`（最多 8 个 exact origin）、`provider`（空、`rea`、`inspect`、`trace`、`fxapk-cdp-trace`）、`observation_ms`（0 到 60000）、`authorized`，以及可选的严格布尔 `related_targets`（默认 false）。`navigate`、`click_selector`、`pause_related_start` 不是配置字段，字符串 `"false"`、数字和 null 也不能充当 `related_targets`。未知字段、重复 JSON 键、链接和超过 65536 字节拒绝。`path` 不能写成 http(s) 或 ws(s) URL。显式 `related_targets=true` 时，只有一个 exact origin 也可以采集该 origin 上的 Dedicated Worker 和 OOPIF。多个 `exact_origins` 仍会打开相关 target 采集，不会扩大授权 origin。service worker 和 shared worker 不在范围内。

这些动作只属于单独的已授权 `fxapk rea trace`：`--navigate`、`--click-selector`、`--pause-related-start`。自动主路径不声称支持这些开关。需要它们时，先用显式参数采集，再把该 bundle 交给 `supplement-web`。

| 情形 | 怎么做 |
| --- | --- |
| 普通 APK，无网页信号或 `mode=off` | 不补采，不建议把 mode 打开 |
| 普通 HTML / HAR | `fxapk analyze-web`，不走 REA import |
| 已保存的 REA JSON | `source=rea-json`，或单独 `fxapk rea import`。这是上游 REA 材料 |
| 已核验 bundle | `source=bundle`，核验前提供方未知 |
| 已有报告，只补网页 | `fxapk supplement-web <report.json> --web-supplement <config> --out <new-out-dir>` |
| 现场单个 CDP target | 配置 `source=cdp` 且授权完整。缺插件或目标时停在该步并保留稳定原因 |
| 相关 target，含同源 Worker | `related_targets=true`，或沿用多个 exact origin 的既有行为。不含 service/shared worker |
| 动态单轮 / 多轮 | 看该次 `meta.web_supplement` 与 `meta.web_supplement_runtime`。失败不自动重试；已有成功回执保留，同时能看见最新失败 |
| 失败或重复 | 读最新回执。重复 raw 不当成新采集。不要把错误原文改写成 digest 命令 |
| 缺插件或目标 | 插件不可用、依赖缺失、目标缺失各自保持稳定原因。未装插件时 `supplement-web --help` 仍可看 |
| 真实 Android | 尚未实机验收。不承诺自动 WebView 调试或 App 归因 |

不给这份配置，且没有 `platform=web` 或 WebView 信号时，计划是 `not_applicable`，reason 为 `no_config`，gaps 为空。有网页信号但还没有配置时是 `pending` / `no_config`，不执行。已经写好 `mode=auto` 才进入自动运行：`bundle` 与 `rea-json` 用本地 `path` 做离线校验后解析；`cdp` 必须 `authorized` 为 true，并且同时给出回环 `endpoint`、`target` 和至少一个 `exact_origins`。只有授权、缺端点或 origin 时是 `cdp_not_authorized` 或 `cdp_target_missing`，不表示已经连接。`mode=off` 不执行。有信号但配置里没有本地材料、也没有完整 CDP 目标时是 `material_missing`，status 为 `skipped`。

REA 6.4.0 的完整 CLI JSON 可以用 `source=rea-json` 直接自动解析。`fxapk rea inspect` 仍是独立入口。同窗口调度的是插件 trace，不是上游 REA inspect。ready 以 provider 写出的 `ready.json` 为准。缺 CDP 目标则 skipped，不改设备。`scripts/<sha256>.js` 是 CDP `sourceText` 的 UTF-8 编码，不是该 URL 的原始 HTTP 响应体。新机可选 `pip install -e ./plugins/fxapk-rea`，与 Android UI 插件独立；trace 另装该目录的 `[trace]` extra。静态和动态补采把低信任候选送进现有解析器，来源 `external-web-observation`，新候选为待核 / LOW / `batch_reference`，同值旧线索保持原等级。不自动提交第三方富化，也不自动改变案件闭环。`live_cdp` 只采纳插件返回的 true。动态单轮或三轮有没有回填，看该次报告的 `meta.web_supplement` 与 `meta.web_supplement_runtime`。

不适用：把网页候选当成案件闭环、设备改动或密钥操作。普通 HTML / HAR 仍走已有 `fxapk analyze-web`。配置了 `--web-supplement` 时，解析增量进入同一次主报告。

REA 命令是这三条：

- `fxapk rea capabilities`
- `fxapk rea inspect`
- `fxapk rea import`

另有可选命令 `fxapk rea trace`。它是独立提供方 `fxapk-cdp-trace`，走插件 extra `trace`，不依赖 Node/REA，也不把上面三条变成它的前置。手工观察进报告用 `fxapk rea attach`，只挂 `meta.web_observations`。自动解析是另一条：`--web-supplement` 校验后把增量送进现有解析器，新候选为待核 / LOW / `batch_reference`。没有 `fxapk rea verify`。`fxapk rea capabilities --provider trace` 与 `--provider attach` 只查本地前置：trace 看 `websockets` 能否导入及版本 `>=13.1,<14`，attach 报告 `offline_available`。两者浏览器都是 `not_probed`，不启动、不联网。`status=ok` 不是实测。缺 REA 不影响 `attach` 和 `trace --help`。

没有 `fxapk jshook`、`fxapk rea analyze` 或其他未实现子命令。缺工具就停在对应采集，不把缺的能力写成可用。未安装 `websockets` 时 `trace --help` 仍可用，采集失败且原因稳定为 `trace_dependency_missing`。`trace` 成功前必须写出 `ready.json`。回执用原件 JSON Pointer。附着前历史仍然看不到。跨 frame 祖先、非零 UTF-16 偏移和有界 parent 补取只属于 trace，不属于 REA。worker 与 OOPIF 默认不收。

## 能力路由

要增强同一次 fxapk 主分析，优先按 `agent_handoff` 准备 `--web-supplement` 配置，由 fxapk 内部调度。下面的独立命令用于单独观察、离线材料转换或仅挂附件，不要求依次执行，也不能代替主报告解析验收。

1. 已有 REA 完整 CLI JSON：直接 `fxapk rea import`。离线 import 不依赖本机 REA 或 Node，也不把 `capabilities` 成功当作必须前置。import 只搬入已有 REA 证据，不产生新的浏览器观察。
2. 已授权且需要现场观察：先跑 `capabilities`，只做本地启动检查（本地 REA 版本；浏览器恒为 `not_probed`）。`inspect=available` 只说明本地启动条件通过。通过后再跑 `inspect`。
3. 普通 HTML / HAR 走 `fxapk analyze-web`，不走 `rea import`。
4. 已授权且要直接记录 CDP 请求身份时，用 `fxapk rea trace`。它不替代 `inspect`，也不读取 REA 记录。先由调用方启动浏览器并打开页面，再运行 `trace`。换机条件是 Python 3.11+、该 Chrome、以及 `fxapk-rea[trace]`。`ready.json` 表示 Page/Runtime/Debugger/Network 与 async depth 32 已 ACK，顶层 frame 属于给定 origin，且已经看到该 origin 的执行上下文。这不是后续事件必达的保证。附着前的脚本和请求不在包里。
5. 要把已经单独采集的观察挂进报告：`fxapk rea attach --bundle <目录> --report <原报告> --out <新目录>`。新目录里才有 `report.json`、`report.digest.json`、`report.html`。然后照常 `fxapk digest`。attach 重核 raw、回执、脚本和 manifest。不覆盖原报告，只挂观察，不晋级 leads / endpoints / runtime，不跑 `case close`。要解析增量时走主路径 `--web-supplement`，不把 attach 当成那条解析入口。

`inspect` 不点击、不导航、不启动浏览器，也没有跨 frame 或 worker 桥。`trace` 默认不点击、不导航、不附着相关 target，不启动或关闭浏览器，不恢复其他暂停的 debugger。显式 `--navigate` 只接受同源 URL；显式 `--click-selector` 只点顶层选择器。两者都要求 CDP ACK。ACK 不是完整点击因果，`click_attribution_verified` 仍为 false。`--related-targets` 默认关闭；打开后也只收 exact origin 相同的 iframe 和 Dedicated Worker。`--related-origin` 与 `--pause-related-start` 已实现，默认都是 false，并且都要求 `--related-targets`。`--related-origin` 是可重复的 exact origin，最多 8 个。`--pause-related-start` 只恢复自己暂停、且正在 waitingForDebugger 的相关 target，结果写入 startup interventions。所有显式开关默认关闭；一旦暂停自己的等待目标，干预记录可见。origin 过滤是采集范围，不是流量防火墙。单独的 inspect、trace、import 不会自动写报告或做案件闭环。REA 旧 provider 仍然没有逐请求 frame/context 桥。

断点或注入是干预，单独记录。不与无断点观察、独立 CDP oracle 拼成一次运行。oracle 多出来的字段不能补成 provider 证据。

jshook 只是仓库外的手工对照。当前 fxapk 没有它的 import，也没有自动 adapter。

## 命令

下面是可解析的 PowerShell 变量示例，不是可直接整段执行的流程。调用前把每一项改成本次已授权的实际值。每个输出目录必须尚不存在，两条命令各用自己的目录。示例域名是保留名 `example.test`，端点是回环。不要对示例发起真实联网。

Windows 的 `--rea` 指向安装包里的 JS 启动器 `rea.mjs`，由 Node 执行。运行时拒绝 `.cmd` / `.bat`。细节见 [插件 README](../../plugins/fxapk-rea/README.md)。

```powershell
$reaLauncher = "D:\tools\rea\node_modules\rea-agents\scripts\rea.mjs"
$savedReaJson = "D:\evidence\rea-cli.json"
$newOutput = "D:\evidence\rea-import-01"
$authorizedTarget = "TARGET"
$expectedSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

fxapk rea import $savedReaJson --out $newOutput
fxapk rea import $savedReaJson --out "D:\evidence\rea-import-checked" --expected-sha256 $expectedSha256
fxapk rea capabilities --rea $reaLauncher
fxapk rea capabilities --provider trace
fxapk rea capabilities --provider attach
fxapk rea inspect --rea $reaLauncher --endpoint "http://127.0.0.1:9222" --target $authorizedTarget --origin "https://example.test" --observation-ms 10000 --out "D:\evidence\rea-inspect-01"
fxapk rea trace --endpoint "http://127.0.0.1:9222" --target $authorizedTarget --origin "http://127.0.0.1:8765" --observation-ms 10000 --out "D:\evidence\cdp-trace-01"
fxapk rea attach --bundle "D:\evidence\cdp-trace-01" --report "D:\evidence\sample-report.json" --out "D:\evidence\sample-report-web" --context-record "D:\evidence\context-record.json"
fxapk digest "D:\evidence\sample-report-web\report.json"
```

context-record 只声明身份。下面四个键必须与报告和 bundle 一致。`authentication` 由 attach 写成 `declared`，不要在文件里自填认证通过。

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

`$sampleSha` 换成报告里的样本哈希。64 个 `a` 只是形状示例。`target_id` 与 `origin` 换成该 bundle 的值。

合成页用仓库夹具，不依赖事先建好的忽略目录：

```powershell
python tools/rea_trace_fixture.py --out "D:\evidence\fixture-run"
```

进程打出 `origin` 后，浏览器打开 `http://127.0.0.1:<端口>/?mode=direct`。`mode` 还可为 `crossframe`、`worker`、`oopif`、`inline`、`decoy`。

## Observe / Capture

一次采集只覆盖工具实际写出的作用域。按真实字段记录，缺失写 `unknown`，不补造：

`target`、`session`、`frame`、`context`、`script`、`request`、`navigation`、`epoch`。

不能用 URL、时间接近、`window.name` 或 body 标签证明身份。

异步从 parent 到点击的链若缺一跳，覆盖保持 `partial`。动态脚本要核对插入或加载来源，以及异步祖先；只拿到文本不算点击链完成。`eval` 的 `sourceURL` 是声明名，不能单独证明网络来源。

源码 UTF-8 文本哈希、CDP 的 UTF-16 坐标、网络原始字节是三种表示。正文 shape 不是 payload。信任前保留原件哈希和 JSON Pointer。trace 单份源码先按 `48 * 1024` 个字符拒绝，再把 UTF-8 字节算进整包 `256 * 1024` 字节。字符上限不是 48 KiB。事件 1024、源码份数 64、观察 60 秒这些既有上限仍在。

trace 的跨 frame 祖先按该祖先自己的 frame、loader 和 epoch 记。非零行列在依据明确时按 UTF-16 代码单元换算。`parentId` 来自有界 `Debugger.getStackTrace`，并保留原响应指针。worker 没有 frame 时保留 worker 身份，覆盖保持 partial。这些句子只描述 trace。REA import/inspect 没有这条桥。

分开陈述：工具是否成功、证据覆盖、归属是否证实、案件是否闭环。`status=ok` 不是闭环。当前入口的 `coverage.status` 保持 `partial`。认证、APK 身份、点击归因、闭环保持 false。`tool_version` 在离线 import 为 null；inspect 成功才写入本地 REA 版本。

离线 import 写 `acquisition.kind=offline_import`。纯投影不写获取模式。inspect 写 `local_cdp_observation`。

`coverage.limitations_refs` 只指向原件里真实存在的键。值为 null 或空列表仍算存在。不存在的键不出指针。

## 原件与事件定位

保留 `rea-original.json` 的原始字节和 SHA-256。回执里的 `source_ref` / `limitations_refs` 用 `rea-original.json#/` 下的 JSON Pointer 回到原件。指针解不开就当缺口，不改原文去凑。

离线 import 的原始 JSON 校验失败发生在创建目录之前。`inspect` 先 claim 输出目录，再校验运行输出；该步失败保留 marker，没有成功的 `observation.json`。claim 之后执行失败，或发布时写脚本/回执失败：同样保留 marker 和已写出的原件，不删除已有字节。fxapk 这条路径可以留下 `failure.json` 和诊断。外部 collector 没有该 marker 时，记录它自己的失败和清理格式。清理要核对本次拥有的进程和端口。不要靠删除、重命名或剥离来源绕过 H1 拒收。

## 归因边

对每条声称的边单独核验，缺关联就留空或 `unknown`：

1. 请求 initiator 类型是否为 script。
2. 同一 URL 是否恰好一条脚本记录。
3. 该记录的 frame 是否唯一，origin 是否与 URL 一致。
4. 0 基行号和 UTF-16 列号是否落在捕获源码内。
5. 父 frame、导航 epoch、点击是否都有记录。缺 parent→点击则整段为 partial。
6. 动态插入要核对插入或加载来源和异步祖先。`eval` 的 `//# sourceURL` 是声明名，不能单独证明网络来源。

满足坐标核对时，现有投影最多给 `candidate_script_path`，`binding=url_candidate_unverified`，`frame_identity_verified=false`。这不是已验证绑定。

请求 hop 的 `frame_id` 是请求身份。异步脚本所在 frame 单独记 `script_frame_id`。`observed_identity_bridge=false` 时脚本仍可作候选，不写成已验证链接，也不合成 App 归属。覆盖缺口只保留白名单代码（如 `loader_unknown`、`oopif_worker_unsupported`、`related_target_uncovered`）；`executed` 与 `coverage=partial` 可以同时成立。`worker_not_stopped` 是进程/环境问题，不是 `inspect_input` 或 `config_rejected`。已授权 CDP 若静态路径拿掉且动态没有开始，回执是 `cdp_deferred` / `not_executed`，不是 `no_web_signal`。`mode=off` 保持关闭。

## 交付缺口

REA bundle 不能直接交给 `fxapk analyze-web` 或案件直接证据入口。核心会拒收带 marker、旧回执或可识别信封的目录。拒收不会自动改判 `batch_reference`，也不会自动写 `report.json`。

交付时写明：做了哪条命令、原件哈希、看见的边、没看见的作用域、为什么停。未过证据门不称案件闭环。

人工复核可抄 [references/synthetic-acceptance.md](references/synthetic-acceptance.md) 的记录模板。填完模板不是新的机器收据，也不是闭环。
