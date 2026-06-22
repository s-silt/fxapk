# 图谱只入强档 + 网页可增删图谱/手动加线索 设计 spec

> 状态：经 brainstorm 逐项确认，实现就绪待用户过目。
> 决策快照：图谱入图只留**强档**；网页**结构化增删**图谱（加实体+连边 / 全局删实体 / 断单边，**不做原始 Cypher 写入**）；网页可**手动添加线索**进追踪台账；CLI 加 rm-entity/unlink + 一次性 prune-weak。**线索追踪状态逻辑不变**（仅多手动加入口）。

## 1. 目标与背景

图谱（Kuzu）此前对 `extract_fingerprints()` 的**每个**指纹都入图——含中档 `uni_appid`/`firebase_project`（易被无关 app 共用）→ 串案噪音。本设计：①入图只留**强档**降噪；②网页能像改数据库一样**增删**图谱节点/边，把漏网噪音手动清；③网页能**手动补线索**（自动没抠到的，人工加进台账跟进）。

## 2. 入图只留强档（`apkscan/graph/ingest.py`）

`ingest_report` 在 `for fp in extract_fingerprints(...)` 循环里加一道过滤：

```python
from apkscan.graph.weight import is_strong
...
for fp in extract_fingerprints(report_dict):
    kind = str(fp.kind)
    if not is_strong(kind):       # 只入强档（sign/c2/wallet_secret/crypto_addr/admin_host/im_server/telegram_bot）
        continue
    ...
    store.upsert_entity(kind, value)
    store.link(sha, kind, value, weight=get_weight(kind))
```

- 影响 analyze/auto 自动入图（autoingest）与 `fxapk graph ingest` 两条路（都过 `ingest_report`）。
- 丢弃中档 `uni_appid`/`firebase_project`。已在图里的旧中档实体由第 6 节 `prune-weak` 一次性清。
- `is_strong` 是 `weight.py` 现成配置（调档无须改本逻辑）。

## 3. 图谱删除 / 读（`apkscan/graph/store.py` + `query.py`）

`GraphStore` 新增（参数化查询防注入；绝不抛——失败记 logging 返 0/False）：

- `delete_entity(kind: str, value: str) -> int`：删该实体及其所有 OBSERVED 边。Kuzu 删除语义：**先删边再删节点**（不依赖 DETACH DELETE 是否支持）：
  ```
  MATCH (:Apk)-[r:OBSERVED]->(e:Entity {id: $id}) DELETE r
  MATCH (e:Entity {id: $id}) DELETE e
  ```
  `id = f"{kind}:{value}"`。返回删除的实体数（0/1）。
- `unlink(apk_sha256: str, kind: str, value: str) -> int`：只删这一条边：
  ```
  MATCH (a:Apk {sha256: $sha})-[r:OBSERVED]->(e:Entity {id: $id}) DELETE r
  ```
  返回删除边数。
- 读：复用现成 `query.query_link(sha256)`（该 APK 的实体 + 共用它的其它 APK）供网页图谱面板。
- 加（网页"加实体+连边"）：复用现成 `upsert_entity` + `link`（weight 用 `get_weight(kind)`）。

`prune_weak(store) -> int`（放 `query.py` 或 `ingest.py`）：枚举所有实体，对 `not is_strong(kind)` 的逐个 `delete_entity`，返回清理数（一次性清存量中档噪音）。

## 4. 台账加手动线索（`apkscan/track/ledger.py`）

`TrackingLedger` 新增（绝不抛）：

- `add_lead(sha256, category, value, *, subject="", status=_DEFAULT_LEAD_STATUS, notes="") -> bool`：
  - APK 不在台账 → 建最小 APK 壳（`apk_status` 默认、package/label 空）。
  - `lead_key = make_lead_key(category, value)`：已存在 → 返回 False（已跟踪，不覆盖）；不存在 → 建线索，**标 `manual: true`**，`first_seen/updated_at` 置当前。
  - 手动线索与自动入账线索同结构、可改状态/备注/进展；重分析 upsert 若命中同 key 走既有合并（保留人工 status/notes/history）。
- 不自动喂图谱（本轮决策：手动线索只进台账；要入图谱用第 3 节网页"加实体"或 CLI）。

## 5. 网页（`apkscan/track/web.py` + `templates/track.html`）

在现有 track 网页（线索+进度面板）基础上新增，沿用现有令牌鉴权 + 按条 POST + 结构化 JSON 错误：

**线索面板**：每个 APK 加「+ 添加线索」表单（category 下拉[LeadCategory] / value / subject / 初始状态 / 备注）→ `POST /api/lead/add` → `ledger.add_lead`。

**图谱面板**（每个 APK 一块，需 kuzu）：
- `GET /api/graph?sha256=` → `query_link(sha256)`：列该 APK 的强档实体 + 每个实体「还被哪些 APK 共用」。
- 每实体两个按钮：**全局删除该实体**（`POST /api/graph/delete_entity {kind,value}`）/ **断开本 APK 这条边**（`POST /api/graph/unlink {sha256,kind,value}`）。
- 「+ 加实体并连到本 APK」表单（kind / value）→ `POST /api/graph/entity {sha256,kind,value}` → `upsert_entity`+`link`。
- **kuzu 未装** → 这些路由返回 `{"ok":false,"error":"图谱未启用（pip install fxapk[graph]）"}`，面板显示提示，不报错、不影响线索面板。

所有图谱/线索写路由：`value`/`sha256` 经校验（sha256 hex；图谱写经 store 参数化查询防注入），坏入参 4xx。

## 6. CLI（`apkscan/cli.py` 的 `graph` 子命令组）

- `fxapk graph rm-entity <kind> <value>` → `store.delete_entity`，打印删除数。
- `fxapk graph unlink <sha256> <kind> <value>` → `store.unlink`。
- `fxapk graph prune-weak` → `prune_weak(store)`，打印清理数（一次性清存量非强档噪音）。
- 均需 `fxapk[graph]`；缺 kuzu 时与现有 graph 命令同款优雅提示。

## 7. 错误处理

- 图谱可选（kuzu）：store 删除/prune 与 web 图谱路由在 kuzu 缺失/查询异常时返 0/`{ok:false}` + logging，**绝不抛**、不连累线索面板与主流程。
- `add_lead` 绝不抛（台账层铁律）。
- 图谱写全走 `store.query_rows(..., params=...)` 参数化（value 来自样本/人工输入不可信，防 Cypher 注入）。
- 网页异常返结构化 JSON（沿用现有 400/401/404/500 handler）。

## 8. 测试（pytest，mock，不碰真 kuzu/浏览器）

- ingest：构造含强档+中档指纹的 report，断言入图**只链强档**、中档被丢（mock store 记 link 调用）。
- store：`delete_entity`/`unlink`/`prune_weak` 发出正确参数化 Cypher（mock 连接捕获 query+params）；kuzu 缺失返 0 不抛。
- ledger：`add_lead` 建手动线索（标 manual）、APK 不存在时建壳、重复 key 返 False；不破坏现有 upsert 合并。
- web：`/api/lead/add`、`/api/graph`、`/api/graph/entity|delete_entity|unlink` 各路由（mock ledger/store/query_link）；kuzu 缺失图谱路由优雅降级；坏入参 4xx；令牌鉴权。
- CLI：`graph rm-entity/unlink/prune-weak`（mock store）+ 缺 kuzu 优雅退出。

## 9. 不做范围

- 不做网页原始 Cypher 写入控制台（只读 `graph cypher` CLI 保留）。
- 不做网页"整个 APK 节点移除"（本轮只删实体/断边）。
- 线索追踪**状态机/进度逻辑不变**；手动线索不自动入图谱。
- 不动 `extract_fingerprints` 的抽取集（只在 ingest 端按 is_strong 过滤）。
