# 合成验收矩阵

独立复验规范。用保留域名和回环构造页面。不依赖某一台机器上的历史实验目录。一次人工通过只说明该次记录，不是 fxapk 的通用能力承诺。

本文件不是 fxapk 机器收据，也不是 `observation.json` 的新格式。填完模板不等于闭环。

## 三种取证面

这三种面是取证设计，不是当前 fxapk 子命令。`fxapk rea import` 只搬入已有 REA 证据，不产生新的浏览器观察。当前没有 `jshook` import。原始新鲜动作和 oracle 的关系不能填回 REA 能力。

`fxapk rea trace` 是另一条可选提供方，不是上表三种面的完成态，也不是 `capabilities` / `inspect` / `import` 的第四种完成态。它在已启动的回环浏览器上附着一个 target。默认不导航、不点击、不收 worker/OOPIF。显式 `--navigate` / `--click-selector` / `--pause-related-start` 只在这条单独命令上生效，自动主路径和 `supplement-web` 配置不会代填。点击因果仍为 false。显式 `--related-targets` 或配置里的严格布尔 `related_targets=true` 才允许 exact origin 相同的 iframe 与 Dedicated Worker；只有一个 exact origin 时也要这个显式 true。多个 exact origin 仍沿用相关 target 采集。默认仍拒绝。shared / service worker 继续拒绝。worker 没有 frame 时保留 worker 身份，覆盖保持 partial。已有报告只补网页用 `fxapk supplement-web <report.json> --web-supplement <config> --out <new-out-dir>`，不重跑 APK。`trace_oversize`、`trace_deadline`、`source_unavailable`、发布冲突和 `trace_cleanup_failed` 保持各自稳定原因；是否已经开始采集只看本目录的 bundle marker 与 `ready.json`。失败不自动重试。

跨 frame 祖先按该跳自己的 frame、loader、epoch 核对。非零偏移按 UTF-16 换算。`parentId` 只接受有界 `Debugger.getStackTrace` 的原响应，并保留指针。子 session 的 scriptId / requestId / contextId 与主 session 重号时必须分开，不能并成一条。`frameDetached` 结束对应寿命。附着前历史仍然没有。REA inspect 仍然没有逐请求 frame/context 桥，也不要把它写成拥有这些 trace 能力。

`ready.json` 只说明附着和初始上下文已就绪。单份源码上限是 `48 * 1024` 字符，UTF-8 还受整包 `256 * 1024` 字节约束。事件 1024、源码 64 份、观察最多 60 秒保持不变。超限失败并留下合法的部分原件。没有独立的 `verify` 命令。`attach` 重核 raw、回执、脚本和 manifest，写到新的报告目录，再走普通 digest / HTML。核心没有安装本插件时，已写入的 `web_observations` 仍可渲染。搬目录后用相对路径 `external_observations/<sha256>/`。context-record 只是 declared。篡改、旧包与新包不一致、声明样本或 origin 对不上，都不得出成功报告。

仓库夹具是 `python tools/rea_trace_fixture.py --out <尚不存在的目录>`。不要求忽略用的 out 目录事先存在。模式为 `/?mode=direct|crossframe|worker|oopif|inline|decoy`。`server.jsonl` 只追加。失败请求保留在日志里，验收时不得删掉失败行。换机要有 Python 3.11+、调用方自己的 Chrome，以及 `fxapk-rea[trace]`。缺 extra 时期望稳定失败 `trace_dependency_missing`。REA inspect 还要 Node 与 REA 6.4.0。

| 面 | 含义 | 记录要求 |
|---|---|---|
| provider passive | 已有 REA 原件，或其后的离线 `import` | 另一次运行的字段留在那次原件里 |
| breakpoint intervention | 断点或注入。单独一次运行 | 与无断点观察分开留档 |
| 独立 CDP oracle | 单独的浏览器和会话。记录实际 Debugger、async depth 等配置 | 额外字段留在 oracle 原件，不写入 provider 证据 |

每次运行单独留原件、哈希、窗口，以及该工具自己的失败或清理记录。

## 页面情景

| 情景 | 要分开记录的对象 | 通过条件 | 反例 |
|---|---|---|---|
| direct | 一个 frame、一个 `app.js`、一次明确动作后的一个请求 | 同一运行内，可信动作记录与该请求 initiator 调用栈、脚本执行上下文相互对应。坐标或文本单独只证明源码候选。关联不齐为 partial，不强行证明点击 | 只凭 URL 相同、只凭坐标或文本、或只凭 click 记录 / `isTrusted` |
| 同 URL 双 frame | 父页也加载 `app.js` 时共三个 scriptId。两个案例分开：各用一次新采集，只点击一个子 frame | 保留浏览器 ID 作用域和导航周期。REA 没有逐请求 frame/context 桥；关联不齐时该案例为 partial | 写成三次点击，或按本表猜通过 |
| setTimeout + Promise | 点击后 `setTimeout` 再 `Promise.then` 里发请求 | 异步链每跳都有事件；缺 parent→点击则为 partial | 用时间接近补上缺失的点击 |
| dynamic script | `createElement('script')` 插入 | 核对插入或加载来源和异步祖先。只拿到文本不算点击链完成。下载来源未知则 `unknown` | 把脚本文本当成响应原始字节 |
| eval / sourceURL | `eval` 且带 `sourceURL` | `sourceURL` 是声明名，不是下载证明，不能单独证明网络来源。点击链要靠执行来源和异步祖先建立。坐标或文本单独只证明源码候选。关联不齐为 partial，不强行证明点击 | 用 sourceURL 字符串当网络来源，或只凭文本存在 |
| 与点击独立的一次性定时器 decoy | 同窗口两次请求：真点击分支，以及与点击独立的一次性定时器 | 只有真点击分支可归因。decoy 留在窗口内并标为独立分支 | 用不受控 `setInterval` 打断随后的静置观察，或因同窗口就算点击导致 |
| 多 session 重号 | 主 session 与子 session 使用相同 scriptId、requestId 或 contextId | 记录按 session 分开。重号不合并、不互相覆盖 | 用编号相同就把两条记成一次执行 |
| detach | `Page.frameDetached` 或 context 销毁之后的事件 | 寿命在 detach 处结束。之后的同号 ID 是新寿命或拒绝 | 用 detach 前的 frame 解释之后的请求 |
| worker / OOPIF 默认 | 不传 `--related-targets` | 子 target 不进入成功采集。缺口保留 worker/OOPIF 未收 | 默认运行却写成已观察 worker |
| worker / OOPIF 显式 | `--related-targets`，子 URL 的 exact origin 与给定 origin 相同 | iframe 与 Dedicated Worker 可进入。shared / service worker 仍拒绝。无 frame 的 worker 保留 worker 身份且 coverage 为 partial | 为了收进子 frame 而改用另一个 origin，或把 worker 写成 page frame |
| 显式动作 | `--navigate` 同源 URL，或 `--click-selector` 顶层选择器 | 原件有动作与 ACK。`click_attribution_verified` 仍为 false | 把 ACK 写成点击因果，或默认命令却去导航 |
| attach 旧包与新包 | 已挂过的观察再 attach，以及另一份新 bundle | 旧原件按哈希再验。同哈希不静默加一条。新 bundle 进新的 out 目录 | 覆盖原报告，或第二次不读旧脚本字节 |
| tamper | 改 raw、回执或 `scripts/*.js` 之一 | attach 失败，没有成功的新报告 | 只改一处仍发布 status=ok |
| 搬目录 | 整个 attach 输出目录换位置 | `external_observations/<sha256>/` 仍能对上复制的原件 | 只在旧绝对路径上才认原件 |
| 核心无插件 | 未安装 fxapk-rea 时读已挂报告 | 核心 digest / HTML 仍渲染计数、缺口和相对路径 | 渲染时去 import 插件，或把观察升成 leads |

观察顺序固定为三段：无动作基线观察、一次明确动作观察、随后静置再观察。旧 console 可以在后段重放并单独标出。`started_at` 之前的时间戳按工具真实分类记录，不把那段叫做负窗口。REA 没有逐请求时间，不能宣称做了逐请求跨时钟排序。click 记录或 `isTrusted` 单独仍不证明请求因果。

每个情景记录：

- 原件 SHA-256，以及脚本 UTF-8 源码 SHA-256。两者可以不同。
- 请求数。
- script ID 与 context / frame 关联。没有则空或 `unknown`。
- 失败记录用该工具自己的格式。fxapk 路径可有 marker 且成功回执不存在。合成夹具的 `server.jsonl` 保留 4xx/失败请求，验收不得删除这些行。外部 collector 没有 marker 时，记下它自己的失败和清理格式。清理要核对本次拥有的进程和端口。
- 错 frame：同 URL 另一 frame 的点击不得占用本 frame 的边。两个子 frame 是两次新采集。
- 改源码且保留原 hash：必须拒绝。源码和 hash 一起伪造时，hash 自洽不认证来源，需要独立原件锚点。
- 伪造异步祖先：与原始事件逐字段对照。只看 JSON 内部一致不够。对不上的边为空或 `unknown`，覆盖保持 partial。

## 人工复核记录

方法：

版本（fxapk / REA，没有就写 unknown）：

范围（target / session / frame / context / script / request / navigation / epoch）：

证据路径与原件 hash：

观察到的边（每条：请求、script ID、frame、坐标、窗口）：

缺口：

下一步：

停止条件：

不存在的关联留空或 `unknown`。此模板不是 fxapk 新机器收据。模板填完也不表示案件闭环。
