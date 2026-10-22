---
name: fxapk-web-evidence
description: 在fxapk中处理授权范围内的网页观察、--web-supplement自动解析、REA离线导入及点击—请求—脚本证据核验时使用。
---

# fxapk 网页证据

REA 插件默认关闭：即使已安装也不导入、不注册命令、不用于自动补采。仅在明确需要时为该进程设置 `FXAPK_ENABLE_REA=1`（PowerShell `$env:FXAPK_ENABLE_REA='1'`）。未启用时 `selfcheck` 报 `disabled`。启用不等于授权浏览器、设备或联网，agent 不得自行设置该开关。

本技能只编码方法，不是独立运行时，不产生浏览器访问、点击、设备、外发、探测或 `case close` 授权。权限边界以 [AGENTS.md](../../AGENTS.md) 为准；命令与限额见 [插件 README](../../plugins/fxapk-rea/README.md)；合成验收见 [references/synthetic-acceptance.md](references/synthetic-acceptance.md)。观察顺序借鉴 [reverse-skill js-reverse](https://github.com/zhaoxuya520/reverse-skill/blob/cab634bd855fc287f6e420c1f36fd1a6b9245960/skills/js-reverse/SKILL.md)，不复制其 agent 包、工具表或额外审批。

## 先读报告，再选路径

先读 `meta.web_observation_plan.agent_handoff`，以及 `meta.web_supplement` / `meta.web_supplement_runtime` 最新回执。digest 里的 handoff 按白名单状态重算，不照抄报告自由文本；handoff 不是授权。缺事实时只暂停依赖它的补采步骤，其余已授权工作继续，并写明缺口。

| 情形 | 怎么做 |
| --- | --- |
| 无网页信号或 `mode=off` | 不补采，不建议把 mode 打开 |
| 普通 HTML / HAR | `fxapk analyze-web`，不走 REA |
| 还没有报告 | 在本来要跑的 `analyze` / `analyze-web` / `auto` 上加 `--web-supplement <本地JSON>` |
| 已有报告，只补网页 | `fxapk supplement-web <report.json> --web-supplement <config> --out <new-out-dir>`（不重跑 APK、不碰设备、不闭环） |
| 已保存的 REA 6.4.0 / 6.7.0 的 inspect_web_page 完整 CLI JSON | `source=rea-json`，或单独 `fxapk rea import` |
| 已核验 bundle | `source=bundle`；核验前提供方未知 |
| 现场单个 CDP target | `source=cdp` 且授权完整；缺插件或目标时停在该步并保留稳定原因 |
| 相关 target（同源 Worker / OOPIF） | `related_targets=true`；不含 service / shared worker |
| 真实 Android WebView | 尚未实机验收，不承诺自动 WebView 调试或 App 归因 |

计划状态：无配置且无 `platform=web` / WebView 信号 → `not_applicable` / `no_config`；有信号无配置 → `pending` / `no_config`，不执行；`mode=auto` 才运行。`cdp` 只给授权缺端点或 origin → `cdp_not_authorized` / `cdp_target_missing`，不表示已连接；有信号但既无本地材料也无完整 CDP 目标 → `skipped` / `material_missing`。失败不自动重试，已有成功回执保留。

**配置** schema `fxapk.web_supplement.v1`：`schema_version`、`mode`（`auto`/`off`）、`source`（`bundle`/`rea-json`/`cdp`）、`path`、`endpoint`、`target`、`exact_origins`（≤8）、`provider`（空/`rea`/`inspect`/`trace`/`fxapk-cdp-trace`）、`observation_ms`（0–60000）、`authorized`、可选严格布尔 `related_targets`。未知字段、重复键、链接、超过 65536 字节、`path` 写成 URL 都拒绝。`navigate` / `click_selector` / `pause_related_start` 不是配置字段：需要时先在授权的 `fxapk rea trace` 显式传参，再把 bundle 交给 `supplement-web`。

**提供方边界**：`inspect` 是独立 REA 入口；同窗口自动采集只接受 `trace` / `fxapk-cdp-trace`；`provider=rea|inspect` 且 `source=cdp` 以 `provider_mismatch` 跳过。`attach` 只把观察挂到新目录的 `meta.web_observations`；解析进主报告走 `--web-supplement` / `supplement-web`，来源 `external-web-observation`，新候选为待核 / LOW / `batch_reference`，同值旧线索保持原等级，不自动富化、不改闭环。没有 `fxapk rea verify`、`fxapk jshook`、`fxapk rea analyze`。

## 手工命令

独立命令用于单独观察、离线材料转换或仅挂附件，不要求依次执行，也不能代替主报告解析。

1. 已有 REA 完整 CLI JSON：`fxapk rea import`，不依赖本机 REA / Node。
2. 已授权现场观察：`capabilities`（只查本地启动条件，浏览器恒 `not_probed`）→ `inspect`。inspect 不点击、不导航、不启动浏览器，没有跨 frame / worker 桥。
3. 已授权且要直接记录 CDP 请求身份：`fxapk rea trace`。调用方先启动 Chrome 并打开页面。`ready.json` 表示 Page/Runtime/Debugger/Network 已 ACK、顶层 frame 属于给定 origin、且看到该 origin 的执行上下文；附着前的脚本和请求不在包里。默认不点击、不导航、不附着相关 target；显式开关见插件 README。
4. 挂进报告：`fxapk rea attach --bundle <目录> --report <原报告> --out <新目录>`，再照常 `fxapk digest`。不覆盖原报告，不晋级 leads / endpoints / runtime。

示例（PowerShell 变量，调用前改成本次已授权的实际值；每个输出目录须不存在；示例域名 `example.test` 和回环端点不要真实联网）：

```powershell
$reaLauncher = "D:\tools\rea\node_modules\rea-agents\scripts\rea.mjs"
$authorizedTarget = "TARGET"
fxapk rea import "D:\evidence\rea-cli.json" --out "D:\evidence\rea-import-01" [--expected-sha256 <hex>]
fxapk rea capabilities --rea $reaLauncher
fxapk rea inspect --rea $reaLauncher --endpoint "http://127.0.0.1:9222" --target $authorizedTarget --origin "https://example.test" --observation-ms 10000 --out "D:\evidence\rea-inspect-01"
fxapk rea trace --endpoint "http://127.0.0.1:9222" --target $authorizedTarget --origin "http://127.0.0.1:8765" --observation-ms 10000 --out "D:\evidence\cdp-trace-01"
fxapk rea attach --bundle "D:\evidence\cdp-trace-01" --report "D:\evidence\sample-report.json" --out "D:\evidence\sample-report-web" --context-record "D:\evidence\context-record.json"
fxapk digest "D:\evidence\sample-report-web\report.json"
```

context-record（`fxapk-web-context/1`）只声明身份：`schema_version`、`sample_sha256`、`target_id`、`origin` 必须与报告和 bundle 一致；`authentication` 由 attach 写成 `declared`，不要自填认证通过。

合成页：`python tools/rea_trace_fixture.py --out "D:\evidence\fixture-run"`，浏览器打开 `http://127.0.0.1:<端口>/?mode=direct|crossframe|worker|oopif|inline|decoy`。

## 观察与核验

一次采集只覆盖工具实际写出的作用域：`target`、`session`、`frame`、`context`、`script`、`request`、`navigation`、`epoch`。缺失写 `unknown`，不补造。不能用 URL、时间接近、`window.name` 或 body 标签证明身份。

源码 UTF-8 文本哈希、CDP 的 UTF-16 坐标、网络原始字节是三种表示；正文 shape 不是 payload。信任前保留原件哈希和 JSON Pointer（`rea-original.json#/` 或 `cdp-trace-original.json#/`）；指针解不开就当缺口，不改原文去凑。

对每条声称的归因边单独核验，缺关联就留空或 `unknown`：

1. 请求 initiator 类型是否为 script。
2. 同一 URL 是否恰好一条脚本记录。
3. 该记录的 frame 是否唯一，origin 是否与 URL 一致。
4. 0 基行号和 UTF-16 列号是否落在捕获源码内。
5. 父 frame、导航 epoch、点击是否都有记录；缺 parent→点击则整段 `partial`。
6. 动态插入要核对插入/加载来源和异步祖先；`eval` 的 `//# sourceURL` 是声明名，不能单独证明网络来源。

满足坐标核对时，投影最多给 `candidate_script_path`（`binding=url_candidate_unverified`，`frame_identity_verified=false`），不是已验证绑定。跨 frame 祖先、UTF-16 偏移换算和有界 `parentId` 补取只属于 trace；REA import / inspect 没有这条桥。断点或注入是干预，单独记录，不与无断点观察拼成一次运行。

分开陈述四件事：工具是否成功、证据覆盖、归属是否证实、案件是否闭环。`status=ok` 不是闭环；`coverage.status` 保持 `partial`；认证、APK 身份、点击归因、闭环保持 false。覆盖缺口只用白名单代码（`loader_unknown`、`oopif_worker_unsupported`、`related_target_uncovered` 等）；`executed` 与 `coverage=partial` 可同时成立。已授权 CDP 若动态没有开始，回执是 `cdp_deferred` / `not_executed`，不是 `no_web_signal`。

## 交付

REA bundle 不能直接交给 `fxapk analyze-web` 或案件直接证据入口；核心会拒收带 marker、旧回执或可识别信封的目录，拒收不自动改判 `batch_reference`。不要靠删除、重命名或剥离来源绕过拒收。

交付时写明：做了哪条命令、原件哈希、看见的边、没看见的作用域、为什么停。未过证据门不称案件闭环。人工复核可抄 [references/synthetic-acceptance.md](references/synthetic-acceptance.md) 的记录模板；填完模板不是新的机器收据。

REA 6.4.0 / 6.7.0 导航兼容修复：`python -m fxapk_rea.rea_compat --root <rea-agents包目录> --apply`，按版本分别哈希钉定、未知修改拒绝；失效源码记 `provider_unavailable`；inspect 只在安全退出后对原目标重开一次新窗口，首轮原件保留，第二轮仍失败则如实失败。
