# fxapk Kuzu 案件图谱串案地基 · 设计规格

- 日期：2026-06-20
- 状态：已审批，待实施
- 一句话目标：让 fxapk 把每一次分析过的 APK 及其强指纹持久化进本地 Kuzu 属性图谱，供 Codex agent 跨样本串并案件，成为「广度 / 深度 / 规模化 / 落地性」路线图里规模化（Epic C）的第一块地基。

---

## 2. 背景与定位

### 2.1 现状缺口

`apkscan/dynamic/correlate.py` 已经实现了**单批次内**的团伙聚类：批量跑完后，`correlate()` 把当批每个样本的强指纹（签名证书 / C2 域名 / uni AppID / 收款地址 / Firebase 工程 / Telegram bot token）建倒排索引，用并查集把共享指纹的样本连成簇，写出 `case_correlation.json`。

但这套聚类是**进程内、批次内、无记忆**的：

- 上一批分析的 50 个 APK 跑完即忘，下一批的样本无法和它们碰撞。
- 三个月前办过的一个换皮包，今天来了一个新包共用同一签名证书 —— 现有流程完全看不到这条线。
- 办案最缺的「串并」恰恰是**跨时间、跨批次**的横向关联，而这正是当前缺的。

### 2.2 为何「图谱串案」是第一块地基

路线图四个方向（A 广度 / B 深度 / C 规模化 / D 落地性）里，**规模化（C）**的核心诉求是「分析过的样本越多，串并能力越强」。这要求一个**持久化、可累积、可跨批次查询**的关联存储。本 spec 就是这个存储：一个本地 Kuzu 属性图，把「APK ↔ 强指纹 ↔ APK」的关系永久沉淀下来。它一旦落地：

- A 期新增线索类型 → 只注册新 `kind` + 权重即可入图（零 DDL 迁移，见 §4）。
- B 期深度评分 → 在图上叠时序 / 路径权重即可。
- D 期落地 → CLI + 稳定 JSON 已经是 Codex / 卷宗可直接消费的接口。

所以它是后续三个方向共同依赖的底座，排在第一。

### 2.3 消费者是 Codex（agent 层），fxapk 是确定性工具层

明确分层：

- **fxapk = 确定性工具层**：负责「把 report 摄入图谱」「按 sha256 拉关联」「跑簇」「执行原始 Cypher」这类**确定性、可复现、无智能**的操作。输入相同 → 输出相同。
- **Codex = agent 层（消费者）**：负责「这两个簇是不是同一团伙」「这条资金线该怎么追」这类**需要推理、需要上下文**的判断。Codex 通过 fxapk 的 CLI（现在）和 MCP（预留）调用工具层。

因此本 spec 的接口设计原则是：**CLI + 稳定 JSON 打底（a），MCP 预留（b）**。所有 `graph` 子命令默认输出结构稳定、键名 snake_case、可被程序解析的 JSON；`graph cypher` 提供原始 Cypher 逃生口，为将来包一层 MCP server 留好通道。

---

## 3. 锁定约束

以下约束在审批时已锁定，实施不得偏离：

| # | 约束 | 含义 |
|---|------|------|
| C1 | 本地图谱 DB 为中心，以串案为目的 | 嵌入式 Kuzu，无远程服务，无网络依赖 |
| C2 | 不打包 exe、不做 GUI | 纯 pip 库 + CLI；本 spec **不**碰 PyInstaller / GUI |
| C3 | 消费者是 Codex（agent 层） | fxapk 是确定性工具层 |
| C4 | CLI + 稳定 JSON 打底，MCP 预留 | 六命令默认 JSON 输出；`graph cypher` 为 MCP 留口 |
| C5 | 环境常态：Windows + 离线 | whois / DNS 不可用；Kuzu 嵌入式无需联网，契合 |
| C6 | 真机动态：rooted MuMu | 本 spec 不直接涉及，但摄入的 report 来自动态分析产物 |
| C7 | 通用 Entity 建模，零 DDL 迁移 | 不为每个 kind 建表，新 kind 只是新行 |
| C8 | `extract_fingerprints` 是唯一连边真相源 | 摄入不得另起一套指纹抽取逻辑 |
| C9 | kuzu 懒加载，缺失绝不拖垮其它命令 | 项目铁律，见 §9 |
| C10 | 单写者 | Kuzu ACID 单写者，`threading.Lock` 守护，锁冲突清晰提示 |

---

## 4. 数据模型（Kuzu 通用 Entity 属性图）

### 4.1 钉死版本

- **Kuzu `0.11.3`**（2025-10-10 发布，为 0.11.x 末版，KuzuDB 项目在此版后归档；API 稳定，无后续破坏性变更）。
- PyPI 提供 cp310/cp311/cp312/cp313/cp314 多平台 wheel，**Windows cp312 wheel 已在 Windows 11 实测可装可跑**；无第三方依赖（`Requires: [empty]`）。
- pyproject 中固定为 `kuzu==0.11.3`（精确钉版，避免未来主版本破坏 schema API）。

### 4.2 建模决策：通用 Entity 而非每 kind 一表

把所有强指纹统一为一类 `Entity` 节点，用复合主键 `id = "{kind}:{value}"` 区分类型；**不**为 `sign` / `c2` / `crypto_addr` 各建一张节点表。理由：

- **零 DDL 迁移**：A 期新增线索类型（如 `apk_icon_hash`、`wallet_chain`）时，只需在 `weight.py` 注册新 `kind` + 权重，摄入时多产生几行 `kind` 前缀不同的 `Entity` —— **不动 schema、不迁移、不停机**。
- **Codex 查询统一**：所有关联走同一条 `(Apk)-[:OBSERVED]->(Entity)` 模式，Codex 无须为每种线索写不同 Cypher。
- **代价可接受**：单表 `Entity` 需要在 `(kind, value)` / `id` 上有索引（PK 自带），规模化到万级节点时性能可控（见 §12 风险）。

### 4.3 节点与边

```
节点 Apk:
  sha256       STRING PRIMARY KEY    -- 样本内容 sha256（去重主键，与 ledger 一致）
  package      STRING                -- 包名
  label        STRING                -- 应用显示名
  analyzed_at  STRING                -- 最近一次分析/摄入时间（ISO8601）
  report_path  STRING                -- 主 report.json 落盘路径（溯源）
  sign_sha256  STRING                -- 签名证书 sha256（冗余存，便于直接查）
  sign_subject STRING                -- 签名证书 subject

节点 Entity:
  id           STRING PRIMARY KEY    -- "{kind}:{value}"，如 "sign:deadbeef..."
  kind         STRING                -- sign|c2|uni_appid|crypto_addr|firebase_project|telegram_bot|...
  value        STRING                -- 指纹原值
  first_seen   STRING                -- 首次观测时间（ISO8601）
  last_seen    STRING                -- 最近观测时间（ISO8601）
  weight       DOUBLE                -- 该 kind 的强弱权重（冗余自 weight.py，便于排序）

边 OBSERVED  (Apk)-[:OBSERVED]->(Entity):
  weight       DOUBLE                -- 连边权重（= Entity 的 kind 权重，冗余便于 ORDER BY）
```

### 4.4 DDL 片段（幂等）

放在 `apkscan/graph/schema.py`。**所有 CREATE 用 `IF NOT EXISTS` 守护**，重复执行不报错（实测幂等）：

```cypher
CREATE NODE TABLE IF NOT EXISTS Apk(
    sha256 STRING,
    package STRING,
    label STRING,
    analyzed_at STRING,
    report_path STRING,
    sign_sha256 STRING,
    sign_subject STRING,
    PRIMARY KEY (sha256)
);

CREATE NODE TABLE IF NOT EXISTS Entity(
    id STRING,
    kind STRING,
    value STRING,
    first_seen STRING,
    last_seen STRING,
    weight DOUBLE,
    PRIMARY KEY (id)
);

CREATE REL TABLE IF NOT EXISTS OBSERVED(
    FROM Apk TO Entity,
    weight DOUBLE
);
```

> 注意（来自实测风险）：`IF NOT EXISTS` 并非对所有 DDL 构造都受支持。`ensure_schema()` 必须把每条 CREATE 包在 try/except 里，把「已存在」类异常当作预期、log 后吞掉、**不重抛**（见 §9）。CI 测试必须验证 schema 二次初始化不抛（`test_schema_ddl_idempotency`）。

### 4.5 串案语义

- **link（一跳关联）**：两个 `Apk` 共享 ≥1 个 `Entity`，即 `(a1)-[:OBSERVED]->(e)<-[:OBSERVED]-(a2)`。按共享 `Entity` 的权重排名。
- **cluster（团伙簇）**：`Apk-Entity-Apk` 形成的连通分量。语义上等价于 `correlate.py` 的并查集结果，但数据来自**持久图谱（跨批次累积）**而非单批内存。给出簇成员 + 并案依据（哪些指纹连起来的）+ 置信分（见 §7）。

---

## 5. 摄入流程

### 5.1 唯一连边真相源：复用 `extract_fingerprints`

摄入**绝不**另写指纹抽取逻辑，统一调用既有函数（约束 C8）。已确认签名（`apkscan/dynamic/correlate.py:49`）：

```python
from apkscan.dynamic.correlate import extract_fingerprints, Fingerprint

def extract_fingerprints(report: dict) -> set[Fingerprint]: ...

@dataclass(frozen=True)
class Fingerprint:
    kind: str   # sign|c2|uni_appid|crypto_addr|firebase_project|telegram_bot
    value: str
```

该函数已经：从 `meta` 抽 `sign_sha256`（排除 "android debug" 调试证书）/ `uni_appid` / `firebase_project_id` / `crypto_addresses[]` / `telegram_bot_tokens[]`，从 `leads[]` 抽 `is_c2=True` 的 value，且**绝不抛**。摄入直接消费它的输出，保证图谱里的边和 `correlate.py` 的簇逻辑**指纹口径完全一致**。

### 5.2 `ingest_report`（单份报告 → 图）

`apkscan/graph/ingest.py`：

```python
def ingest_report(report_dict: dict, store: GraphStore, report_path: str = "") -> None:
    """把一份 report.json 解析出的 dict 摄入图谱。绝不抛（坏报告 log+跳过）。"""
```

流程：

1. **抽 APK 元信息**：`sha256`（必需；缺失/空 → log warning 跳过整份）、`package`、`label`、`sign_sha256`、`sign_subject`、`report_path`。元信息键名以现有 report 的 `meta` 结构为准（`meta.sample_sha256` / `meta.package_name` / `meta.sign_sha256` / `meta.sign_subject` / `meta.app_label` 等，实施时按实际 report schema 对齐）。
2. **抽指纹**：`fps = extract_fingerprints(report_dict)`。
3. **upsert APK 节点**：`store.upsert_apk(...)`，`analyzed_at` 置为当前时间。
4. **逐指纹 upsert Entity + 连边**：对每个 `Fingerprint(kind, value)`：
   - `eid = store.upsert_entity(kind, value)`（`first_seen` 首次写、`last_seen` 每次更新、`weight` 取自 `weight.get_weight(kind)`）。
   - `store.link(sha256, kind, value, weight=get_weight(kind))`。
5. **异常隔离**：整个函数包在 try/except，捕获后 log warning（带上 report_path / sha256），**continue 不重抛**（与 `correlate.py` 的 `correlate()` 既有 try/except 隔离精神一致）。

### 5.3 幂等 MERGE（重摄不产重复）

所有写操作用 Cypher `MERGE`，保证幂等（实测验证）：

```cypher
-- upsert Apk：同 sha256 二次 MERGE 只更新，不产生重复节点（COUNT=1）
MERGE (a:Apk {sha256: $sha256})
SET a.package=$package, a.label=$label, a.analyzed_at=$analyzed_at,
    a.report_path=$report_path, a.sign_sha256=$sign_sha256, a.sign_subject=$sign_subject;

-- upsert Entity：id="{kind}:{value}" 作 PK；first_seen 仅在新建时写
MERGE (e:Entity {id: $id})
ON CREATE SET e.kind=$kind, e.value=$value, e.first_seen=$now, e.last_seen=$now, e.weight=$weight
ON MATCH  SET e.last_seen=$now, e.weight=$weight;

-- upsert 边：同 (a,e) 二次 MERGE 不产生重复边（COUNT=1）
MATCH (a:Apk {sha256: $sha256}), (e:Entity {id: $eid})
MERGE (a)-[r:OBSERVED]->(e)
SET r.weight=$weight;
```

> 幂等性质（约束 C8 / §10 验收）：同一 `sha256` 重摄 → APK 节点 COUNT 不变，仅 `last_seen` / `analyzed_at` 推进；`Entity` 不重复；`OBSERVED` 边不重复。

> Kuzu API 关键点（来自实测，实施必须遵守）：
> - `kuzu.Database(file_path)` 接受的是**文件路径字符串**，不是目录；`kuzu.Connection(db)` 是正确构造（**无** `db.connect()`）。
> - 参数占位符是 `$name`（**不是** `?` 或 `:name`），参数以 dict 传：`conn.execute(query, {"sha256": "abc"})`。
> - `conn.execute()` 返回 `QueryResult`（**不是** list）；取数用 `.get_all()` / `.get_next()`（**不是** `.fetchAll()/.fetchOne()`）；行是 tuple，按位置索引。
> - 转 dict：`conn.execute(q).rows_as_dict().get_all()` → `list[dict]`（键为列名如 `a.sha256`）。`.rows_as_dict()` 本身仍返回 `QueryResult`，必须再 `.get_all()`。
> - `conn.close()` + `db.close()` 必须在 finally / 上下文管理器里显式调用，否则连接残留会锁库。

### 5.4 batch 自动摄入

在 `apkscan/dynamic/batch.py` 的 `run_folder()` 中，**`_run_correlation(analyzed, out_dir)` 返回后（现 L197）、构造 `summary` dict 前（现 L199）**插入自动摄入钩子（约 8 行）：

```python
# L197 之后，L199 之前：
try:
    from apkscan.graph import GraphStore, ingest_batch
    # DB 锚定 out_dir，与 ledger（<out_dir>/.apkscan_cache/analyzed.json，batch.py:128）同根
    store = GraphStore(Path(out_dir) / ".apkscan_cache" / "cases.kuzu")
    res = ingest_batch(analyzed, store)   # 传 analyzed 列表（精确主报告路径），不盲 glob
    store.close()
    logger.info("[batch] 图谱摄入：成功 %s / 失败 %s", res["ingested"], res["failed"])
except ImportError:
    logger.info("[batch] 未安装 kuzu，跳过图谱摄入（pip install kuzu==0.11.3 启用）")
except Exception:
    logger.warning("[batch] 图谱摄入失败（非致命，已隔离）", exc_info=True)
```

要点：

- **DB 与 ledger 同根**：钩子显式把 DB 路径锚定到 `Path(out_dir)/.apkscan_cache/cases.kuzu`，与 `_run_folder` 的 ledger（`<out_dir>/.apkscan_cache/analyzed.json`，batch.py:128）落在**同一目录**。**绝不**用无参 `GraphStore()`（无参默认相对 cwd，见 §5.6）——否则当用户以相对 `out_dir` 在不同 cwd 多次跑批量时，DB 会被分裂成多个互不串案的库，直接违背「跨批次累积」的核心目标（约束 C1）。
- 摄入是**纯副作用**，`run_folder()` 返回的 dict **结构不变**（向后兼容；既有 `clusters` 键仍来自 `_run_correlation` / `case_correlation.json`，摄入不修改返回值，见 §5.5）。
- **GUI 入口零回归**：本钩子位于 `_run_correlation` 之后、`summary` 构造之前，不触碰 `on_progress` 进度回调链路；GUI 经 `run_folder(on_progress=...)` 调用时进度回调与返回结构均不受影响（§13 含对应验收项）。
- batch 现在按 APK 串行分析 → 摄入在同进程串行执行，无并发问题。
- kuzu 缺失 → info 级 log 跳过，batch 仍成功（约束 C9）。

`ingest_batch` 签名（**接受 `analyzed` 列表，复用 batch 既有精确主报告定位，不裸 glob**）：

```python
def ingest_batch(analyzed: list[dict], store: GraphStore) -> dict:
    """逐条遍历 batch 的 analyzed 列表，用 _load_main_report(entry["report_paths"])
    定位每包主报告（<base>.json，已排除 runtime_report.json），逐份 ingest_report。
    返回 {"ingested": int, "failed": int, "errors": list[str]}。"""
```

定位主报告的铁律（与真实代码对齐）：

- **复用 batch 既有定位逻辑**：直接消费 `analyzed[].report_paths` + `apkscan.dynamic.batch._load_main_report`（batch.py:46），**不**对 per-app 目录裸 `*.json` glob。裸 glob 会把 `runtime_report.json` / `case_correlation.json` / `evidence_manifest` 等非主报告一并误摄。
- 主报告文件名是 `<base>.json` 且**显式排除 `runtime_report.json`**（`_load_main_report` 已实现此口径），**不是**固定的 `report.json`。
- per-app 目录命名为 `<apk.stem>__<sha8>`（`apk.stem` 去扩展名，batch.py:158），不是 `<apk>__<sha8>`。
- APK 去重主键以 report 内 `meta.sample_sha256` 为准（缺键容错，见 §5.2）。

### 5.5 `case_correlation.json` 向后兼容

- batch 的 `_run_correlation()` **仍照旧写** `case_correlation.json` 到磁盘（不动现有行为）。
- 图谱摄入排在它之后，两份产物并存。
- 语义上：**图谱成为新的串案真相源**（跨批次），`case_correlation.json` 退化为单批次缓存 / 导出格式。`graph cluster` 命令的输出即「从图谱再生的 case_correlation」，跨批次、更全。
- 未来 Epic B 可把 `_run_correlation` 的写盘改为从 `graph cluster` 再生 —— 本 spec **不做**这步替换，只保证兼容。

### 5.6 DB 位置约定

DB 文件名统一为 `cases.kuzu`，落在某个 `.apkscan_cache/` 目录下；但**该目录的锚点随入口而异**，两条入口的默认路径解析规则写死如下：

| 入口 | DB 默认路径 | 锚点 | 与 ledger 关系 |
|------|-------------|------|----------------|
| **批量场景**（batch 自动摄入，§5.4） | `Path(out_dir)/.apkscan_cache/cases.kuzu` | **`out_dir`**（与 ledger `<out_dir>/.apkscan_cache/analyzed.json` 同根） | **同目录** |
| **单命令场景**（`graph ingest/link/...` 无 `--db`） | `Path.cwd()/.apkscan_cache/cases.kuzu` | **cwd** | 无 ledger 概念 |

要点：

- **批量场景必须锚定 `out_dir`**：batch 钩子显式传 `GraphStore(Path(out_dir)/'.apkscan_cache'/'cases.kuzu')`，保证同一次批量的 ledger 与图谱 DB 落在同一目录、跨批次累积不分裂（约束 C1，§5.4 已固化）。
- **单命令场景锚定 cwd**：`GraphStore(db_path="")` 无参时默认相对 cwd 取 `.apkscan_cache/cases.kuzu`；CLI `--db` 显式覆盖。
- 两类入口下 `.apkscan_cache/` 均已被 `.gitignore` 覆盖（`.gitignore:9`），自动忽略，无需新增条目。
- 注意 §4.1 实测风险：Kuzu `Database()` 接受**文件路径**。`cases.kuzu` 作为路径名（Kuzu 会在该路径下管理其存储）；实施时以 `kuzu.Database(str(path))` 传入，并在测试里验证 Windows 路径（反斜杠）经 `Path` 抽象后可用。
- 首次打开自动 `ensure_schema`（幂等），无需独立 init 命令。

---

## 6. CLI / JSON 接口（六命令）

六命令一句话职责对照（消除 `link` 与 `query` 口径混淆——两者底层 Cypher 形态接近，但入参与语义不同）：

| 命令 | 入参 | 一句话职责 |
|------|------|-----------|
| `ingest` | 单份 report / 目录 | 把报告摄入图谱（写） |
| `link` | **`<sha256>`** | 按 APK 查邻接——拉出与该 APK 共享强实体的其它 APK |
| `query` | **`--kind --value`** | 按实体反查——列出所有观测到该实体的 APK |
| `cluster` | `[--min-shared N]` | 跑全图团伙簇（连通分量）+ 并案依据 + 置信分 |
| `stats` | —— | 图谱体检：apk/entity/edge 计数 + 按 kind 分布 |
| `cypher` | `"<raw Cypher>"` | 原始 Cypher 逃生口（预留 MCP，自负其责，详见 §6.6 / §9） |

> `link`（按 sha256 邻接）与 `query`（按 kind/value 反查）是两个不同入口：前者「这个 APK 还和谁串」，后者「这条线索都出现在哪些 APK」。正文 §2.3 / §3 中「按 sha256 拉关联」对应 `link`，「按实体反查」对应 `query`，「跑簇」对应 `cluster`，「执行原始 Cypher」对应 `cypher`。

在 `apkscan/cli.py` 注册子应用（沿用现有 `typer.Typer` 模式，约 L26 `app` 定义后）：

```python
graph_app = typer.Typer(help="本地图谱串案：摄入报告 → 关联线索 → 团伙聚类")
app.add_typer(graph_app, name="graph")
```

每个命令统一行为：(1) 懒导入 `apkscan.graph`；(2) 捕获 `ImportError` → 打印 `请安装：pip install kuzu==0.11.3` 并 `exit 1`；(3) 实例化 `GraphStore(--db 或默认)`；(4) 执行并 `print(json.dumps(result, indent=2, ensure_ascii=False))`；(5) 整体 try/except → 友好错误 + `exit 1`；(6) finally 关闭 store。

所有命令默认输出**稳定 JSON**（键 snake_case，排序稳定，与 export/letters 命令一致风格）。

### 6.1 `graph ingest <report.json|目录> [--db PATH]`

摄入单份报告或整个目录。目录摄入时复用 `_load_main_report` 口径定位每包主报告（`<base>.json`，排除 `runtime_report.json` 等产物，见 §5.4），per-app 目录命名为 `<apk.stem>__<sha8>`。

输入：`fxapk graph ingest ./out/evilapp__deadbeef/evilapp.json`

输出：
```json
{
  "ingested": 1,
  "failed": 0,
  "errors": [],
  "db": ".apkscan_cache/cases.kuzu"
}
```

### 6.2 `graph link <sha256> [--db PATH]`

拉出与指定 APK 共享强实体的所有 APK，按共享实体权重排名。

底层 Cypher：
```cypher
MATCH (a1:Apk {sha256: $sha256})-[:OBSERVED]->(e:Entity)<-[:OBSERVED]-(a2:Apk)
WHERE a2.sha256 <> a1.sha256
RETURN DISTINCT a2.sha256, a2.package, e.kind, e.value, e.weight
ORDER BY e.weight DESC;
```

输入：`fxapk graph link deadbeefcafe...`

输出：
```json
{
  "apk": {"sha256": "deadbeefcafe...", "package": "com.evil.app", "label": "ETH钱包"},
  "related": [
    {
      "sha256": "feedface...",
      "package": "com.evil.app2",
      "shared_entities": [
        {"kind": "sign", "value": "abc123...", "weight": 10.0},
        {"kind": "c2", "value": "evil.example.com", "weight": 10.0}
      ],
      "strong_shared_count": 2,
      "strong_weight_sum": 20.0
    }
  ]
}
```

### 6.3 `graph query --kind <KIND> --value <VALUE> [--db PATH]`

反查：给定一个实体，列出所有观测到它的 APK。

底层 Cypher：
```cypher
MATCH (a:Apk)-[:OBSERVED]->(e:Entity {id: $entity_id})
RETURN a.sha256, a.package, a.label, e.kind, e.value;
```
（`entity_id = f"{kind}:{value}"`）

输入：`fxapk graph query --kind sign --value abc123...`

输出：
```json
{
  "entity": {"kind": "sign", "value": "abc123...", "weight": 10.0},
  "apks": [
    {"sha256": "deadbeef...", "package": "com.evil.app", "label": "ETH钱包"},
    {"sha256": "feedface...", "package": "com.evil.app2", "label": "USDT理财"}
  ],
  "count": 2
}
```

### 6.4 `graph cluster [--min-shared N] [--db PATH]`

跑全图团伙簇（连通分量），给簇成员 + 并案依据 + 置信分。`--min-shared` 过滤共享实体数低于 N 的弱关联（默认 1）。取代 `case_correlation.json` 成为跨批次串案输出。

底层（成对碰撞，用 `a1.sha256 < a2.sha256` 去对称，再在 Python 侧并查集成簇 / 或用 Cypher 多跳；置信分计算见 §7）：
```cypher
MATCH (a1:Apk)-[:OBSERVED]->(e:Entity)<-[:OBSERVED]-(a2:Apk)
WHERE a1.sha256 < a2.sha256
RETURN a1.sha256, a2.sha256,
       COUNT(DISTINCT e.id) AS shared_count,
       COLLECT(DISTINCT e.kind) AS shared_kinds,
       SUM(e.weight) AS weight_sum;
```

输入：`fxapk graph cluster --min-shared 1`

输出：
```json
{
  "clusters": [
    {
      "cluster_id": 1,
      "members": ["deadbeef...", "feedface..."],
      "shared": [
        {"kind": "sign", "value": "abc123...", "weight": 10.0}
      ],
      "confidence": 0.87,
      "rationale": {
        "strong_kind_count": 1,
        "strong_weight_sum": 10.0,
        "shared_entity_count": 1
      }
    }
  ],
  "cluster_count": 1,
  "min_shared": 1
}
```

> `confidence` 的语义保证（消费侧务必只依赖此口径）：**同一次 `graph cluster` 查询内，confidence 单调可比、可用于簇间排序**；其**绝对值不稳定、无跨查询/跨版本语义**（归一化方式可能随调参变化）。示例里的 `0.87` 仅为占位，**不构成对绝对值的承诺**。需要稳定可解释依据时，读 `rationale`（强 kind 数 / 强权重和 / 共享实体数）而非 confidence 绝对值。

### 6.5 `graph stats [--db PATH]`

图谱体检。

底层：`MATCH (a:Apk) RETURN COUNT(a)`；`MATCH (e:Entity) RETURN e.kind, COUNT(*)`；`MATCH ()-[r:OBSERVED]->() RETURN COUNT(r)`。

输入：`fxapk graph stats`

输出：
```json
{
  "apk_count": 128,
  "entity_count": 540,
  "edge_count": 612,
  "entities_by_kind": {
    "sign": 96, "c2": 210, "crypto_addr": 130,
    "uni_appid": 60, "firebase_project": 24, "telegram_bot": 20
  },
  "db": ".apkscan_cache/cases.kuzu"
}
```

### 6.6 `graph cypher "<MATCH...>" [--db PATH]`

原始 Cypher 逃生口（为 MCP 预留，高级用法，**仅供只读探查**）。Python 层**不做语义解析 / 校验**，经 `GraphStore` 的**同一连接**（即同一 `threading.Lock` 守护，不绕过 C10）执行 `conn.execute(raw)`，结果以 JSON 数组返回；语法 / 执行异常 → 友好 JSON 错误 + `exit 1`（见 §9）。help 文案标注「原始 Cypher 逃生口（预留 MCP，仅供只读探查；写操作自负其责，请优先用 `ingest`）」。

输入：`fxapk graph cypher "MATCH (a:Apk)-[r:OBSERVED]->(e:Entity) RETURN COUNT(r) AS edges"`

输出：
```json
[
  {"edges": 612}
]
```

---

## 7. 置信 / 权重模型

### 7.1 kind 强弱分档

`apkscan/graph/weight.py`：

```python
WEIGHT_CONFIG: dict[str, dict] = {
    "sign":             {"weight": 10.0, "strength": "strong"},
    "c2":               {"weight": 10.0, "strength": "strong"},
    "crypto_addr":      {"weight":  9.0, "strength": "strong"},
    "telegram_bot":     {"weight":  8.0, "strength": "strong"},
    "firebase_project": {"weight":  5.0, "strength": "medium"},
    "uni_appid":        {"weight":  5.0, "strength": "medium"},
}

def get_weight(kind: str) -> float:
    return WEIGHT_CONFIG.get(kind, {}).get("weight", 1.0)   # 未注册 kind 默认 1.0，绝不崩

def is_strong(kind: str) -> bool:
    return WEIGHT_CONFIG.get(kind, {}).get("strength") == "strong"
```

设计要点：

- 强档：`sign` / `c2` / `crypto_addr` / `telegram_bot`（高区分度，几乎不会被无关包共用；调试证书已在 `extract_fingerprints` 上游排除）。`favicon` 类强指标待 A 期接入时即插入强档。
- 中档：`firebase_project` / `uni_appid`（前端工程级，区分度中等）。
- **未注册 kind 默认权重 1.0、非 strong** —— A 期新 kind 即使忘了注册也不会崩，只是排名靠后（约束 C7 的安全垫）。
- `WEIGHT_CONFIG` 是**配置而非代码逻辑**，调权重无须改 schema、无须迁移。

### 7.2 link / cluster 排名

- **link**：related APK 按「共享强实体权重和」降序，平手按「不同强 kind 数」降序。
- **cluster 置信分**：综合「共享强实体权重和」+「不同强 kind 种类数」（多种不同强指纹同时命中 → 置信更高，单一指纹偶合可能性大）。给一个归一化到 `[0,1]` 的 `confidence`，并附 `rationale`（强 kind 数 / 强权重和 / 共享实体数）让 Codex / 办案人可复核。具体归一化公式实施时确定，但**必须从 `weight.py` 读权重**而非硬编码（便于调参，见 §10 测试）。
- **confidence 的契约（实施与消费两侧均须遵守）**：仅保证「**同一次查询内单调可比、可用于簇间排序**」；**绝对值不稳定、不跨查询/跨版本承诺**。因此 T5 验收只断言**相对序**（强实体簇 confidence > 中实体簇），不断言任何绝对值；§6.4 示例中的具体数值仅为占位。需要稳定绝对依据的消费侧改读 `rationale`。

> 高级时序评分（first_seen / last_seen 衰减、活跃度加权）留 Epic C 正篇，本 spec **不做**。

---

## 8. 复用与重构（对接 correlate / batch / ledger）

| 既有件 | 对接方式 | 是否改动 |
|--------|----------|----------|
| `apkscan/dynamic/correlate.py` `extract_fingerprints(report)->set[Fingerprint]` | 摄入唯一连边真相源，`graph.ingest` 直接 import 调用 | **不改**（保持单一真相源） |
| `apkscan/dynamic/correlate.py` `Fingerprint` dataclass | `ingest` 复用其 `(kind, value)` | 不改 |
| `apkscan/dynamic/batch.py` `run_folder()` | L197 后插自动摄入钩子（§5.4），返回 dict 不变 | **改**（+8 行） |
| `apkscan/dynamic/batch.py` `_run_correlation()` | 照旧写 `case_correlation.json`，图谱排其后 | 不改 |
| `apkscan/dynamic/batch.py` `_load_main_report()` | `ingest_batch` 复用它定位每包主报告（`<base>.json`，排除 `runtime_report.json`），不裸 glob | 不改（import 复用） |
| `apkscan/dynamic/ledger.py` | 借鉴 `.apkscan_cache/` 目录约定；批量场景 DB 锚定 `out_dir` 与 `analyzed.json` 同目录（§5.6） | 不改 |
| `apkscan/cli.py` | 注册 `graph` 子应用 + 六命令（§6） | **改** |

**新建包 `apkscan/graph/`（7 文件）**：

| 文件 | 职责 |
|------|------|
| `__init__.py` | 包标记 + 公开 API 导出（`GraphStore`, `ingest_report`, `ingest_batch`, `query_link`, `query_by_kind`, `query_clusters`, `query_stats`, `query_cypher`）。kuzu 缺失时不阻塞其它命令的导入 |
| `schema.py` | `SCHEMA_DEFINITION`（§4.4 DDL）+ `ensure_schema(db)`（幂等、捕异常不重抛） |
| `store.py` | `GraphStore` 类：懒初始化 DB、`threading.Lock` 单写者、`upsert_apk` / `upsert_entity` / `link` / `query_cypher` / `close`（§5.3 MERGE） |
| `ingest.py` | `ingest_report` / `ingest_batch`（§5.2 / §5.4），import `extract_fingerprints`；`ingest_batch` 复用 `batch._load_main_report` 定位主报告 |
| `query.py` | `query_link` / `query_by_kind` / `query_clusters` / `query_stats` + 排名辅助（§6 / §7） |
| `weight.py` | `WEIGHT_CONFIG` / `get_weight` / `is_strong`（§7.1） |
| —（测试见 §10） | `tests/test_graph.py` |

`GraphStore` 关键签名：

```python
class GraphStore:
    def __init__(self, db_path: str | Path = "") -> None: ...      # 懒初始化，默认 .apkscan_cache/cases.kuzu
    def _ensure_open(self): ...                                     # 懒 import kuzu + 建路径 + ensure_schema
    def upsert_apk(self, sha256: str, package: str = "", label: str = "",
                   sign_sha256: str = "", sign_subject: str = "",
                   report_path: str = "") -> None: ...
    def upsert_entity(self, kind: str, value: str) -> str: ...      # 返回 entity id
    def link(self, apk_sha256: str, entity_kind: str, entity_value: str,
             weight: float = 1.0) -> None: ...
    def query_cypher(self, q: str) -> list[dict]: ...
    def close(self) -> None: ...                                    # conn.close() + db.close()
```

---

## 9. 错误处理（项目铁律）

| 场景 | 处理 |
|------|------|
| **kuzu 未安装** | 懒 import（仅 `graph` 命令 / batch 自动摄入触发）。`graph` 命令捕 `ImportError` → 打印 `请安装：pip install kuzu==0.11.3` + `exit 1`；batch 自动摄入捕 `ImportError` → info log 跳过、batch 仍成功。**核心命令（analyze/auto/batch 本体）无条件可用，绝不被 kuzu 缺失拖垮**（约束 C9）。 |
| **坏 report.json** | `ingest_report` 整体 try/except：缺 `sha256` / 缺 `meta` / `leads` 非 list / 指纹值非字符串 → log warning（带文件名/sha256）后**跳过该份、continue，不抛**；好的照常摄入。 |
| **schema 二次初始化** | `ensure_schema` 每条 DDL 用 `IF NOT EXISTS` + try/except 兜底，「已存在」当预期 log 后吞，不重抛。 |
| **DB 锁冲突（单写者）** | `GraphStore` 所有写操作 `threading.Lock` 守护；Kuzu ACID 单写者。锁/打开失败 → log error + 抛带上下文异常（提示「DB 可能被另一进程占用，或上次批量未正常关闭连接」），调用方（batch）捕获并 log，不致命。 |
| **`graph cypher` 执行失败** | 语法错误 / 执行异常 → 捕获后输出**友好 JSON 错误**（`{"error": "...", "query": "..."}`）+ `exit 1`，不打印裸 traceback。 |
| **`graph cypher` 写操作绕过单写者** | raw cypher 经 `GraphStore` 的**同一连接**执行，因此自然走同一 `threading.Lock` 守护，不另开连接绕过 C10。但 raw cypher 不做语义校验，help 文案须明确「**仅供只读探查**；写操作自负其责，请优先用 `ingest`」，避免误用裸写绕开摄入幂等/校验路径。 |
| **连接生命周期** | `conn.close()` + `db.close()` 必须在 finally / 上下文管理器执行，否则残留连接锁库导致后续进程开不了。batch 钩子、CLI 命令都在 finally 关 store。 |
| **日志铁律** | try/except 内**绝不静默吞**（与全局 Python 规范一致）：要么 `logger.warning/exception` 记，要么带上下文重抛。 |

---

## 10. 测试计划（pytest / Windows / 零环境）

`tests/test_graph.py`。每个测试用 `tmp_path` 建独立 DB 目录，测后清理（注意 Windows：删 `tmp_path` 前先 `store.close()` 释放文件句柄，否则句柄残留导致清理失败）。合成 report dict 按 `correlate.py` 的 `meta`/`leads[]` 结构构造，零真机、零联网、零外部设备。kuzu 用 `pytest.importorskip("kuzu")` 在文件头守护（CI 装 `.[graph]` 后正常跑）。

| # | 用例 | Arrange / Act / Assert |
|---|------|------------------------|
| T1 | `test_schema_ddl_idempotency` | 同 `db_path` 建两次 `GraphStore`（DDL 跑两遍）→ 断言两次都不抛、schema 可用。 |
| T2 | `test_ingest_upsert_dedup` | 摄入 APK_A（含 `sign:CERT`）→ 记 Entity/边数 → 同 sha256 重摄一次 → 断言 Entity count 不变、OBSERVED 边 count 不变、`last_seen` 推进（≥ 前值）、APK 节点 COUNT=1。 |
| T3 | `test_extract_fingerprints_to_entity_mapping` | 构造含全 6 kind（sign/c2/uni_appid/crypto_addr/firebase_project/telegram_bot）的 report → 摄入 → 查 Entity → 断言每个 `Fingerprint(kind,value)` 都映射到一个 `Entity(kind=该kind, value=该值)`，共 6 行，kind 口径与 `extract_fingerprints` 输出一致。 |
| T4 | `test_link_query_cluster_synthetic_3apk` | 合成 3 包 fixture：APK_A(sign=SHARED) + APK_B(sign=SHARED) + APK_C(sign=UNIQUE)，全摄入 → `graph link(A)` 返回 B（经共享 sign）；`graph query(kind=sign,value=SHARED)` 返回 {A,B}；`graph cluster()` 返回 1 簇 {A,B}（shared 含 `sign:SHARED`）+ C 孤立不入簇。 |
| T5 | `test_confidence_ranking_strong_vs_medium` | 簇1 共享强 kind `sign`（1 强实体）；簇2 共享中 kind `uni_appid`+`firebase_project`（2 中实体）→ `graph cluster()` → 断言簇1 confidence > 簇2（只断言相对序，不断言绝对值，见 §7.2）。权重**从 `weight.py` 读**算期望值（不硬编码），允许调参不改测试。 |
| T6 | `test_bad_corrupt_report_never_throws` | 分别摄入：缺 `meta`、`meta=None`、指纹值非字符串、`leads` 非 list 的坏 report → 断言不抛、捕获到 WARNING 级日志（含 "skip"/"跳过" 类标记）、DB 仍一致；同批好 report 仍入图。 |
| T7 | `test_kuzu_not_installed_graceful` | monkeypatch 让 `import kuzu` 抛 `ModuleNotFoundError` → 直接调用 `graph ingest/link/cluster` 命令函数 → 断言 `exit code 1` + 输出含 `pip install kuzu`；再用 `CliRunner` 跑非 graph 命令（如 analyze/batch）→ 断言 `exit 0` 不受影响。注意隔离 import（conftest 清 `sys.modules` 缓存，避免 import 异常被缓存污染后续测试）。 |

CI（`.github/workflows/ci.yml`，**两个 job 各有一处 `pip install -e .`，均须改**）：

- **test job**（L45）：`pip install -e .` 改为 `pip install -e .[graph]`（拉 kuzu，否则 `tests/test_graph.py` 被 `importorskip` 跳过，等于没测）。
- **lint job**（L22）：`pip install -e .` **同样改为** `pip install -e .[graph]`。原因：lint job 在 L27 跑 `pyright apkscan`，新增的 `apkscan/graph/` 会 `import kuzu`；若 lint job 不装 kuzu，pyright basic 模式会报 `reportMissingImports`（注意：这是 `reportMissingImports`，不是已关掉的 `reportMissingModuleSource`），导致 lint job 直接挂。
  - 备选（任选其一即可）：若不想给 lint job 装 kuzu，则在 `apkscan/graph/` 内对 kuzu 用 `if TYPE_CHECKING:` 守护 import + 运行期懒 import，并在裸 `import kuzu` 处加 `# type: ignore[import-not-found]`。**推荐直接改 lint job 装 `.[graph]`**（更简单、与 store 懒加载行为一致）。
- 矩阵保持 Python 3.11 + 3.12（已有，无须改）。
- pytest 自动发现 `tests/test_graph.py`。
- 风险提醒：现有 CI 跑 `ubuntu-latest`，graph 测试须在 Linux 通过才能合入；**Windows wheel 可装性须在合入前本地离线验证**（见 §12）。可选增设 Windows 测试 job 兜底。

---

## 11. 范围边界

### IN（本 spec 做）

- Kuzu store（`GraphStore` + 懒初始化 + 单写者锁 + close）。
- 通用 Entity schema（§4 DDL，幂等）+ 钉版 `kuzu==0.11.3`。
- 摄入（`ingest_report` / `ingest_batch`，复用 `extract_fingerprints`，幂等 MERGE）。
- 六命令：`graph ingest` / `link` / `query` / `cluster` / `stats` / `cypher`（默认稳定 JSON）。
- 基础权重模型（`weight.py`，强/中分档 + 默认兜底）+ link/cluster 排名 + cluster 置信分。
- batch 自动摄入钩子（§5.4）。
- `case_correlation.json` 向后兼容（并存，不替换写盘）。
- 测试（T1–T7）+ deps（`pyproject` optional `graph`）+ CI（**lint + test 两个 job 均改 `.[graph]`**，§10）+ gitignore（已覆盖，确认）。

### OUT（不做，留后续）

- **A 期新 kind**（favicon / 钱包链 / icon hash 等）—— 届时只注册 `kind`+权重即插，本 spec 不预实现。
- **STIX / 标准威胁情报格式导出** —— 留后续。
- **MCP server 实体** —— 本 spec 只**预留** `graph cypher` 逃生口与稳定 JSON，不实现 MCP server。
- **高级时序评分**（first_seen/last_seen 衰减、活跃度加权）—— 留 Epic C 正篇。
- **GUI / exe 移除** —— 明确声明：GUI/exe 的清理是**独立清理任务，不并进本 spec**（约束 C2 只是说本 spec 不新增 GUI/exe，不负责删除既有的）。
- **把 `_run_correlation` 写盘改为从 `graph cluster` 再生** —— 留 Epic B。
- **batch 并行化下的摄入重构** —— 当前 batch 串行，无需；将来并行化时再把摄入移进 per-APK 钩子。

---

## 12. 风险与缓解

| 风险 | 缓解 |
|------|------|
| **Kuzu Windows 离线 wheel 可装性** | 0.11.3 已实测 Windows 11 cp312 可装可跑、无第三方依赖。缓解：合入前在**离线 Windows 环境**用缓存 wheel `pip install kuzu==0.11.3` 验证一次；CI 若仅 Linux，须本地补 Windows 烟测。 |
| **Kuzu 版本飘移破坏 schema API** | 精确钉版 `kuzu==0.11.3`（0.11.x 末版、项目已归档，无后续破坏）。不写 `>=`。 |
| **`Database()` 接受文件路径而非目录** | 实施严格按 `kuzu.Database(str(path))` 传路径；测试覆盖 Windows 反斜杠路径经 `Path` 抽象。 |
| **参数语法 / Result API 误用** | 文档化铁律（§5.3）：`$name` 不是 `?`；`QueryResult` 必 `.get_all()/.get_next()`，不可直接索引；`.rows_as_dict()` 后须再 `.get_all()`。测试以实际 API 断言。 |
| **单写者 / Windows NTFS 锁语义** | `threading.Lock` 守护所有写；所有读写后 finally `close()`；锁冲突给清晰提示。测试覆盖「同路径二次开/关」。 |
| **schema `IF NOT EXISTS` 并非全 DDL 支持** | `ensure_schema` 每条 DDL try/except 兜底，「已存在」当预期。T1 验证幂等。 |
| **大图性能（万级节点）** | 单 `Entity` 表 + PK 索引。规模化到千 APK × 10 实体 = 万级时若慢，加 `Entity(kind,value)` 索引；可在 CI 加 100 包 fixture 的 cluster 基准。Epic C 再正式调优，本 spec 不预优化。 |
| **连接残留锁库** | batch 钩子、CLI、测试全在 finally `store.close()`；测试清理前显式 close（Windows 句柄）。 |
| **未注册 kind 崩溃** | `get_weight` 默认 1.0、`is_strong` 默认 False，未注册 kind 不崩只降权（§7.1）。 |
| **权重为经验值、可能误判** | 权重是**配置非代码**（`weight.py`），调参无须迁移；T5 从配置读期望值，调权不改测试。Epic C 可加 `--weight-profile`。 |
| **report 元信息键名对齐** | 摄入抽 `meta.*` 时以实际 report schema 为准，缺键容错（默认空串/跳过），不假设键存在。 |

---

## 13. 验收标准（可勾验清单）

- [ ] `pip install -e .[graph]` 在 Windows 离线环境成功装上 `kuzu==0.11.3`。
- [ ] `apkscan/graph/` 包齐 7 文件（`__init__/schema/store/ingest/query/weight` + 测试）。
- [ ] 未装 kuzu 时：`fxapk analyze` / `fxapk batch` / `fxapk auto` 正常运行、零报错（约束 C9）。
- [ ] 未装 kuzu 时：`fxapk graph stats` 打印 `pip install kuzu==0.11.3` 提示并 `exit 1`。
- [ ] `fxapk graph ingest <report.json>` 输出 `{"ingested":1,...}` 形态 JSON。
- [ ] 同一 report 摄入两次：APK / Entity / OBSERVED 计数均不变，仅 `last_seen` 推进（幂等）。
- [ ] `fxapk graph link <sha256>` 返回共享强实体的关联 APK，按权重降序。
- [ ] `fxapk graph query --kind sign --value <X>` 反查出所有观测该实体的 APK。
- [ ] `fxapk graph cluster` 输出簇 + 并案依据 + 置信分；强实体簇置信 > 中实体簇。
- [ ] `fxapk graph stats` 输出 apk/entity/edge 计数 + 按 kind 分布。
- [ ] `fxapk graph cypher "<MATCH...>"` 原样执行并返回 JSON 数组；语法/执行错误 → 友好 JSON 错误 + `exit 1`（非裸 traceback）。
- [ ] batch 跑完自动摄入：图谱里出现该批 APK 与实体；`run_folder()` 返回 dict 结构不变。
- [ ] **批量后 DB 与 ledger 同目录**：`<out_dir>/.apkscan_cache/cases.kuzu` 与 `<out_dir>/.apkscan_cache/analyzed.json` 同根存在（断言不分裂、跨批次累积落同一库）。
- [ ] **GUI 入口零回归**：以 `run_folder(on_progress=非 None)` 跑通批量，自动摄入不影响进度回调触发与返回 dict 结构（或 §10 增一条 `on_progress` 回调存活断言）。
- [ ] `case_correlation.json` 仍照常写盘（向后兼容）。
- [ ] 摄入坏 report.json：log warning + 跳过、不抛、好报告仍入图。
- [ ] schema 二次初始化不抛（幂等）。
- [ ] 摄入指纹与 `extract_fingerprints(report)` 输出 kind 口径完全一致（无另起逻辑）。
- [ ] DB 默认落 `.apkscan_cache/cases.kuzu`，`--db` 可覆盖，且已被 `.gitignore` 忽略。
- [ ] `tests/test_graph.py` 的 T1–T7 全绿，CI 在 Python 3.11 + 3.12 通过。
- [ ] CI lint job 与 test job **均**改装 `.[graph]`；装 `.[graph]` 后 `pyright apkscan` 零错误（无 `reportMissingImports`）。
- [ ] 全程无 GUI / exe 改动（约束 C2；仅在 batch 内部插摄入钩子，不触碰 `apkscan/gui` 与 `on_progress` 回调链路）。