# fxapk-rea

可选 REA 网页观察与 Native 地址恢复插件，版本 0.1.1。要求 Python 3.11+、fxapk 1.19.0+。

**默认关闭**：即使已安装，也不会被 fxapk 导入、注册命令或用于自动补采。仅在明确需要时为该进程设置 `FXAPK_ENABLE_REA=1`（PowerShell `$env:FXAPK_ENABLE_REA='1'`；Linux/macOS `FXAPK_ENABLE_REA=1 fxapk rea --help`）。未启用时核心命令照常可用，`selfcheck` 对已安装的 REA 报 `disabled`。启用不等于授权浏览器、设备或联网操作，agent 不得自行设置该开关。

提供 `fxapk rea capabilities | inspect | import | trace | attach | native ...`。没有 auto / capture / case close 钩子；核心收到 `--web-supplement` 时按入口白名单调用本插件的 `run_supplement`。

## 安装

正式附件安装：先从所选 GitHub Release 下载核心与 REA wheel，按该发行的
`SHA256SUMS.txt` 校验，在独立 Python 虚拟环境安装核心，再执行
`python -m pip install ./fxapk_rea-0.1.1-py3-none-any.whl`。
需要 trace 时使用
`python -m pip install "./fxapk_rea-0.1.1-py3-none-any.whl[trace]"`。
附件不是完整离线依赖包，安装可能下载声明依赖；安装后仍默认关闭。
插件源码采用 MIT 许可（见 `LICENSE`），第三方工具与依赖遵循各自许可。

从源码开发安装：

```powershell
python -m pip install -e .
python -m pip install -e ./plugins/fxapk-rea          # 基础：import / inspect / attach / native
python -m pip install -e "./plugins/fxapk-rea[trace]"  # 加 trace（websockets>=13.1,<14）
$env:FXAPK_ENABLE_REA='1'
fxapk rea --help
```

- 离线 `import` 不需要 Node、REA 或浏览器。在线 `inspect` 支持 REA **6.4.0 / 6.7.0**，其他版本拒绝执行；旧版可用于回退。
- `trace` 不依赖 Node 或 REA，只依赖 `[trace]` extra 和调用方已启动并打开页面的 Chrome（数字回环 HTTP CDP）。缺 extra 时 `--help` 仍可用，采集失败原因为 `trace_dependency_missing`。
- Node 与浏览器另行准备；插件不安装软件、不注册全局 MCP、不启动浏览器。Windows 把 `--rea` 指向安装包的 `scripts/rea.mjs`，可用 `--node` 指定 Node；不执行 `.cmd`/`.bat` 或 npx 下载。

## 两条入口：手工采集 + attach，或自动补采

**手工**：`import` / `inspect` / `trace` 只采集到观察目录；`attach` 把核验过的观察挂进新目录的 `meta.web_observations`。不自动闭环，不把观察晋级成 leads、endpoints 或 runtime。

**自动补采**：`analyze` / `analyze-web` / `auto` 加 `--web-supplement <本地JSON>`；已有报告用 `fxapk supplement-web <report.json> --web-supplement <config> --out <new-out-dir>`（只读报告，不重跑 APK、不碰设备、不闭环）。fxapk 按配置和本机能力调度本插件，低信任候选以待核 / LOW / `batch_reference` 进入现有解析器；同值旧线索保持原等级，不自动富化。

- `source=bundle` 与 `source=rea-json`（REA 6.4.0 / 6.7.0 的 `inspect_web_page` 完整 CLI JSON）做离线校验。`source=cdp` 还需 `authorized=true`、数字回环 `endpoint`、`target` 和 exact `exact_origins`。
- 同窗口实时采集只接受 `trace` / `fxapk-cdp-trace`。`provider=rea|inspect` 且 `source=cdp` 以 `provider_mismatch` 跳过，不改写成 trace。`inspect` 始终是独立入口。
- 配置可带严格布尔 `related_targets`（默认 false）。`navigate`、`click_selector`、`pause_related_start` 不是配置字段：需要时先在授权的 `fxapk rea trace` 显式传参，再把 bundle 交给 `supplement-web`。
- 是否回填以报告里的 `meta.web_supplement` / `meta.web_supplement_runtime` 为准。真实 Android WebView 尚未实机验收。

## 命令

```powershell
fxapk rea capabilities --rea C:/tools/rea/scripts/rea.mjs
fxapk rea capabilities --provider trace      # 只查 websockets 版本
fxapk rea capabilities --provider attach     # 只查离线可用
fxapk rea inspect --rea C:/tools/rea/scripts/rea.mjs --endpoint http://127.0.0.1:9222 --target TARGET_ID --origin https://example.test --observation-ms 10000 --out out/rea-observation-01
fxapk rea import ./saved-rea-output.json --out out/rea-import-01 [--expected-sha256 <hex>]
fxapk rea trace --endpoint http://127.0.0.1:9222 --target TARGET_ID --origin http://127.0.0.1:8765 --observation-ms 10000 --out out/cdp-trace-01
fxapk rea attach --bundle out/cdp-trace-01 --report D:/evidence/sample-report.json --out D:/evidence/sample-report-web [--context-record ctx.json]
```

没有 `fxapk rea verify`；attach 在写新目录时核验。

**capabilities**：只查本地前置，浏览器恒 `not_probed`；`status=ok` 不是实测。

**inspect**：连接调用方准备的数字回环 CDP，绑定 target ID 与单个 exact origin。只观察：不导航、不点击、不读 Cookie/存储、不抓 source map，没有 trace 的跨 frame / worker / parentId 桥。控制台文字须 `--console-text`。origin 过滤只限制证据采集范围，不是流量防火墙。target ID 可用 REA `list-browser-targets` 查询。观察窗口从 REA 实际附加开始。

验收时保持 inspect 观察期间的文档不变；不要在启动子进程后用整页刷新制造请求。同源刷新也会触发 `target_changed`，适配层随后重试的新窗口可能开始于加载完成之后，得到 `status=ok`、零请求。应核对 `execution.json` 的 `navigation_retry`、保留的首轮输出以及最终 `capture_window`；零请求只描述最终窗口，不代表页面没有发过请求。验证页面导航请求用 `trace --navigate`；验证 inspect 可用同一文档内已授权的操作，诊断用静态资源 GET 须单独标注，不能计作业务流程成功。inspect 没有对调用方公开的 ready 回执，固定等待时间不能充当就绪确认。

**trace**（独立提供方 `fxapk-cdp-trace`）：只附着给出的 page target，启用 Page / Runtime / Debugger / Network，async stack depth 32。`ready.json` 在命令全部 ACK、顶层 frame 属于该 origin、且看到同 origin 执行上下文后才写出，表示已开始记录，不保证之后事件送达。观察不到附着前的脚本解析和请求。顶层 frame 离开 exact origin 时以 `top_frame_origin_rejected` 失败。结束只 detach 自己的 session，不关浏览器。显式开关（默认全关）：

| 开关 | 作用 | 失败原因 |
|---|---|---|
| `--navigate <同源 URL>` | ready 后做一次同源导航 | `navigate_origin_rejected` |
| `--click-selector <选择器>` | 顶层 DOM 一次点击，不注入脚本 | `click_selector_failed` |
| `--related-targets` | 附着同 exact origin 的 iframe / Dedicated Worker（OOPIF 也要此开关）；shared / service worker 仍拒绝 | — |
| `--related-origin <origin>` | 可重复，最多 8 个 exact origin；须同时带 `--related-targets` | `related_origin_requires_related_targets` |
| `--pause-related-start` | 只恢复自己附着的相关 target 的 `waitingForDebugger`，记入 `capture.startup_interventions` | `pause_related_start_requires_related_targets` |

动作记录保留种类、ACK 和时间；`click_attribution_verified` 仍为 false。子 session 的 scriptId / requestId / contextId 按 session 分别保存，不与主 session 合并。跨 frame 异步祖先按祖先自己的 frame、loader 和 epoch 核对；`parentId` 用有界的 `Debugger.getStackTrace` 补取，补不到保持 `unresolved_parent_id`，不编造。

**import**：读本地 REA 完整 CLI JSON（`--format json --full-output`），核验 provider / operation、target / origin 绑定、窗口、脚本哈希与大小。成功时 `acquisition.kind=offline_import`；inspect 成功时为 `local_cdp_observation`。

所有命令输出到**新目录**，拒绝覆盖已有目录、文件或符号链接。失败时保留 marker 与已写出的原始字节，不写成功的 `observation.json`。

## 限额

| 项 | 上限 |
|---|---|
| 原始包（采集、导入、挂载、补采共用） | 1 MiB |
| 事件 / 源码份数 | 1024 / 64 |
| 单份源码 | 48 × 1024 字符；累计源码 JSON 另限 128 KiB |
| 命令数 | 128（含清理命令预留） |
| REA 原始 JSON / stdout；stderr | 16 MiB；64 KiB |
| JSON 成员 / 深度 / 总节点 | 4096 / 48 / 100000 |
| 观察窗口；启动/收尾；版本探测 | 60 s；30 s；15 s |
| native 单文件读取 | 64 MiB |

Chrome 明确报告脚本 length 超限时不取源码、记 `source_unavailable`，不终止其余观察。其他预算超限整次失败：保留仍是合法 JSON 的已筛选原件，`capture.stopped_reason` 记原因（`trace_limit` / `trace_oversize` / `trace_deadline` / `top_frame_origin_rejected` / 传输失败），不写成功的 observation。落盘事件只保留投影所需字段；请求头、Cookie、postData 与站外 URL 写入前丢弃。

## 产物

- `rea-original.json` / `cdp-trace-original.json`：原始字节（REA）或筛选字段包（trace，schema `fxapk-cdp-trace/1`），不重排、不改写。
- `observation.json`：`rea-web-observation/1` 或 `fxapk-cdp-trace-observation/1` 规范化记录，含原件 JSON Pointer、哈希、观察窗口与缺口。`coverage.status` 保持 `partial`；`provenance_authenticated`、`target_app_attribution_verified`、`click_attribution_verified`、`closure_evaluated` 均为 false。
- `scripts/<sha256>.js`：源码字符串按 UTF-8 编码的字节，不是该 URL 的原始 HTTP 响应体；文件名来自这些字节的 SHA-256。`cdp_hash_relation` 保持 `unverified`。
- `fxapk-rea-bundle.json`：目录创建后立即写入的标记，声明"这是未验证的外部观察目录"。`analyze-web` 与案件直接证据入口据此拒绝该目录（含改名、gzip、祖先链上的嵌套文件）；只有显式 `attach` 或 `--web-supplement` 能让它进报告。
- inspect 另存 `execution/stdout.bin`、`execution/stderr.bin`、`execution.json`，失败时 `failure.json`。

请求的 `observed_at` 为 null、`raw_body_available=false`。只有 `initiator.type=script`、同 URL 恰一条脚本记录、frame 唯一且 origin 一致、发起者行列号落在捕获源码内时，才写 `candidate_script_path`（`binding=url_candidate_unverified`，`frame_identity_verified=false`）；内联脚本缺偏移或偏移不一致时不猜测。

退出码 0 / `status=ok` 只表示处理成功。终端只输出计数、哈希和稳定原因码；完整原值在本地产物中，不属于已脱敏报告。

## attach

离线读取已发布的观察目录，重读 raw、回执和每份 `scripts/<sha256>.js`，对照 manifest 与哈希。篡改、链接或路径逃逸、重复 JSON 键、超量、失败包都拒绝。通过后只在新的 `--out` 目录复制核验过的原件，并发布 `report.json`、`report.digest.json`、`report.html`；原报告不覆盖，`report.json` 保留未知字段、只增加 `meta.web_observations`。已挂的旧观察（含上一轮解析进报告的 `external_observations/<sha>/`）按哈希再验一遍并一同搬运，缺失、损坏或链接即拒绝；同一哈希不重复计数。不新增 endpoints / leads，不改 closure / runtime。

可选 `--context-record` 是本地声明（schema `fxapk-web-context/1`），必填 `schema_version`、`sample_sha256`、`target_id`、`origin`，可选 `package_name`、`process_id`、`webview_target_id`、`recorded_at`，多一个键即拒绝。匹配只表示文件对得上，`authentication=declared`，归因仍未验证。

## Native 地址恢复

只读，不跑样本，不闭环。只识别 PE 与 ELF（无 Mach-O，不抽 IPA）。Windows 上 Ghidra 只收 x86/x64 原生 PE，不要拿 Android `.so` 去 inspect；Linux/macOS 上 `fxapk rea native extract` 抽出单个 `lib/<abi>/<name>.so` 再 inspect（Linux 实跑未验收）。IDA / Hopper 未支持。`--toolchain` 文件只读取 `ghidra` / `java`（写入该次子进程的 `GHIDRA_INSTALL_DIR` / `JAVA_HOME`），`node` 键不用，node 用 `--node`。

```powershell
fxapk rea native capabilities --provider ghidra --rea <rea.mjs> --node <node> --toolchain <local-toolchain.json>
fxapk rea native inspect <binary> --provider ghidra --operation function|address-to-file-offset|read-bytes --query <q> --rea <rea.mjs> --node <node> --toolchain <json> --out out/native-inspect-01
fxapk rea native recover out/native-inspect-01 --recipe recipe.json --out out/native-recovery-01
fxapk rea native attach out/native-recovery-01 --report out/app.json --out out/app-native-01
```

`address-to-file-offset` 返回文件偏移（不是虚拟地址）；`read-bytes --length` 只是有界观察；两者都不自动进入 recover。配方必须显式文件偏移和期望字节，只重算声明过的变换，终止转换是最后一步；字节对上也只说明声明的变换重算成功，`relation_verified` 保持 false。attach 搬运 `native_recovery_input`、native recovery 文件与网页观察附件；PCAP 等未搬运类型仍只指向 `source_artifact_base`。

## REA 6.4.0 / 6.7.0 导航兼容修复

`python -m fxapk_rea.rea_compat --root <rea-agents包目录> --apply`（不带 `--apply` 只核验）。按包版本分别核验 6.4.0 / 6.7.0 源文件与补丁哈希，未知修改拒绝覆盖，可重复执行；普通采集不修改依赖。`capabilities` 与 `execution.json` 记录实际补丁 ID 与源码 SHA-256。

6.7.0 的被动 `inspect_web_page` 仍使用 `rea-cdp-browser/2`，完整原件与 completeness 保留；target 的 `attached=null` 原样保留为未知。上游场景捕获的 limits/event families 合同属于不同 operation，不纳入本插件的被动 inspect 支持声明。

已销毁脚本的明确 CDP `-32000` 错误记作 `script_sources/provider_unavailable`，保留其他证据。inspect 返回导航导致的 `target_changed` 且进程完整退出时，只允许对原 target/origin 再开一次观察窗口（`new_observation_window_after_navigation`）；首轮原件与回执保留，不混合文档，第二次仍变化则失败。

## 合成夹具与验证

`tools/rea_trace_fixture.py` 只绑定 `127.0.0.1`，不启动浏览器；`--out` 须不存在、父目录须存在。模式在查询串：`/?mode=direct|crossframe|worker|oopif|inline|decoy`。

```powershell
python tools/rea_trace_fixture.py --out .\fixture-run
python -m pytest -q tests/test_rea_plugin.py tests/test_rea_runtime.py tests/test_plugin_registry.py
python -m ruff check apkscan tests plugins/fxapk-rea/src
python -m pyright apkscan plugins/fxapk-rea/src
```

CI 使用合成输入，不下载 REA 或浏览器。本地产物包含源码、URL 和可能的明文日志，请使用受控输出目录。MIT；REA、Node、浏览器及各依赖遵循各自许可。网页观察方法见 [skills/fxapk-web-evidence/SKILL.md](../../skills/fxapk-web-evidence/SKILL.md)。
