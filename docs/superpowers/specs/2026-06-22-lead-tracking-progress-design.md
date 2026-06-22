# 线索追踪 + 办案进度（混合存储 + 局域网网页）设计 spec

> 状态：经 brainstorm 逐项确认，实现就绪待用户过目。
> 决策快照：两级追踪（APK + 线索）；混合存储（JSON 台账权威源 + 自动喂图谱）；本地/LAN 网页（flask，可选 extra）；状态预设词表 + 自定义；台账 `~/.apkscan/tracking.json`（仓库外，git pull 永不覆盖）；LAN 暴露自动令牌鉴权。

## 1. 目标与背景

现状：图谱库（Kuzu）只在手动 `fxapk graph ingest` 时用、日常闲置；线索（Lead）只在单次报告里，无跨次的「办案进度」追踪。

要做：**跟踪每个 APK 发现的线索 + 可手动加/改办案进度**，并让闲置的图谱真正用起来。进度通过**本地/局域网网页**查看与编辑。

范围：①追踪台账（数据层）②analyze/auto 自动入账 + 自动喂图谱 ③flask 网页（查看/编辑/LAN 共享）。不改报告/分析器产出本身。

## 2. 数据模型（两级，JSON 台账为权威源）

台账文件（默认 `~/.apkscan/tracking.json`，见 §6）。结构：

```json
{
  "version": 1,
  "apks": {
    "<sha256>": {
      "package": "com.x", "label": "杀猪盘", "report_path": "...",
      "apk_status": "待处理", "apk_notes": "",
      "first_seen": "ISO8601", "updated_at": "ISO8601",
      "leads": {
        "<lead_key>": {
          "category": "DOMAIN", "value": "*.hcrsex.com", "subject": "...",
          "status": "待办", "notes": "",
          "history": [{"at": "ISO8601", "text": "已出函至XX注册商"}],
          "first_seen": "ISO8601", "updated_at": "ISO8601"
        }
      }
    }
  }
}
```

- `lead_key = f"{category}:{value}"`（稳定、可复现；同一线索跨多次分析归一）。
- 状态为自由字符串；UI 提供**预设下拉 + 自定义输入**。预设：
  - APK 级：`待处理 / 调查中 / 已移送 / 已结案`
  - 线索级：`待办 / 已出函 / 已收数据 / 无果 / 不调证`
- `history[]`：带时间戳的进展条目，手动追加，留痕（永不自动删改）。

## 3. 台账模块 `apkscan/track/ledger.py`

`TrackingLedger`（仿 `dynamic/ledger.AnalyzedLedger`：JSON、原子落盘、坏文件当空 + logging、**绝不抛**）。

关键方法：
- `upsert_report(report, report_path) -> None`：从 Report 取 sha256/package/label/leads，upsert 进台账。**合并规则（核心）**：APK/线索已存在时**保留人工改过的 `*_status`/`*_notes`/`history`**，只刷新分析派生字段（subject/value/report_path/updated_at）；新线索默认 `status="待办"`；**消失的旧线索不删**（保留办案痕迹，标 `updated_at` 不变即可）。
- `set_apk(sha256, *, status?, notes?) -> bool`、`set_lead(sha256, lead_key, *, status?, notes?) -> bool`：手动改（单字段，最小化覆盖面）。
- `add_history(sha256, lead_key, text) -> bool`：追加一条进展。
- `load()/all()`：读全量给网页。
- 并发：进程内 `threading.Lock` + 读改写后 `os.replace` 原子落盘；网页按**单条** POST 更新（不整盘覆盖），把丢更新面缩到同字段同刻 last-write-wins（局域网小团队足够，**不引入 filelock 跨进程锁**）。

## 4. 自动入账 + 自动喂图谱

- `analyze`（cli.py，写报告后）与 `auto`（auto.py，静态步骤后）调 `track.ledger.upsert_report(report, path)`——**默认开，可 `--no-track` 关**。失败 best-effort：记 warning、绝不影响主流程/报告产出。
- 同时调现有图谱 ingest（`apkscan/graph/ingest.py`）把 APK/实体喂进 Kuzu——**仅当 kuzu 可用**（可选 extra；不可用静默跳过 + 一次性 debug 提示），让闲置图谱随分析自然积累、支撑跨案串案。
- 补刀命令 `fxapk track ingest <report.json...>`：把历史报告回填进台账（+图谱），便于存量数据补登。

## 5. 网页（flask，可选 extra）

- 命令 `fxapk track [--host 127.0.0.1] [--port 8787] [--ledger PATH] [--no-auth]`：起 flask 服务，打印访问网址（含令牌）。flask 缺失 → 打印 `pip install -e .[track]` 提示并退出（仿 graph extra 缺失范式），不崩。
- 路由：
  - `GET /` → jinja2 渲染单页（已有 jinja2 依赖）：按 APK 列出（含 apk_status 概览）→ 展开线索表格 → 状态下拉(预设+自定义)/备注框/「加一条进展」。
  - `GET /api/tracking` → 全量台账 JSON。
  - `POST /api/apk` `{sha256,status?,notes?}` → set_apk。
  - `POST /api/lead` `{sha256,lead_key,status?,notes?}` → set_lead。
  - `POST /api/history` `{sha256,lead_key,text}` → add_history。
- **绑定与鉴权**（LAN 共享安全）：
  - 默认 `--host 127.0.0.1`（仅本机）。LAN 共享用 `--host 0.0.0.0`（或具体网卡 IP）。
  - **绑定到非 loopback 时自动启用令牌**：启动生成随机 token，URL 带 `?token=...` 打印；每个请求校验 token（query 或 `X-Track-Token` 头），不符 401。`--no-auth` 显式关闭（可信封闭内网）。loopback 默认不强制（本机自用）。
  - 台账含受害人 PII / 高敏线索 → 这是合规红线，默认不裸奔。
  - flask 开发服务器 `threaded=True` 支撑多人并发只读 + 偶发编辑；不上生产 WSGI（局域网取证小团队足够，spec 注明非公网部署）。
- 并发：见 §3，按条 POST + 锁 + 原子写。

## 6. 台账位置与「git pull 不覆盖」

- 默认 `~/.apkscan/tracking.json`（用户主目录，**仓库之外**）：
  - 真**全局**（不随 cwd 变，跨所有案件一份，配合图谱跨案）。
  - **git 永远碰不到** → `git pull` / `git clean -fdx` / 重新 clone 都不会覆盖或删除（满足「之后从 github 拉取更新不会覆盖」的最强保证）。
  - 与可清理的缓存目录 `.apkscan_cache/`（cwd 相对、放可再生缓存）分开，避免清缓存误删办案数据。
- `--ledger PATH` 与 `FXAPK_TRACKING_DB` env 可覆盖位置。首次访问 `mkdir(parents=True, exist_ok=True)`。

## 7. 错误处理（铁律）

- 台账读：坏 JSON / IO 失败 → 当空 + logging，绝不抛、绝不阻断分析主流程。
- 台账写：临时文件 + `os.replace` 原子落盘；写失败记 error、不破坏既有文件。
- 自动入账失败：warning，不影响报告产出（best-effort 旁路）。
- 图谱喂入失败 / kuzu 缺失：debug/warning，静默降级（图谱是可选增强）。
- 网页：异常返结构化 JSON 错误 + 状态码，服务不崩；包名/路径来自样本不可信，`device.is_valid_package` 校验后才入账/展示。

## 8. 测试（pytest，不开真浏览器/不联网）

- ledger：upsert 合并**保留人工改的 status/notes/history**、新线索默认待办、旧线索不删、lead_key 稳定、坏文件当空不抛、原子写、并发锁。
- 自动入账：analyze/auto 后台账有该 APK+leads；`--no-track` 关闭；入账失败不影响报告。
- 图谱喂入：kuzu 缺失静默跳过、可用时被调用（mock graph ingest）。
- 网页：flask `test_client` 跑 GET/POST 各路由、令牌鉴权（非 loopback 必带 token、--no-auth 放行）、单条更新落台账、坏入参 4xx；flask 缺失时 `track` 命令优雅退出（mock import 失败）。

## 9. 不做范围 / 已知限制

- 不做多用户账号体系/审计日志（令牌是单一共享密钥，封闭内网用；非公网部署）。
- 不做实时协同（多人同改同字段 last-write-wins；按条 POST 已最小化冲突）。
- 不改报告/分析器产出；不把进度写回 report.json（台账是独立权威源）。
- 不上生产级 WSGI/HTTPS（局域网取证小团队场景；如需公网另案）。

## 10. 依赖与打包

- `pyproject.toml` 新增可选 extra：`track = ["flask"]`（核心 7 依赖不变）。并发用进程内 `threading.Lock` + `os.replace` 原子写，**不引入 filelock**（保持依赖精简）。
- 新增包 `apkscan/track/`（`__init__.py`/`ledger.py`/`web.py`/`templates/track.html`）。
