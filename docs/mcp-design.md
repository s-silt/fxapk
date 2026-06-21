# fxapk MCP 服务器 · 设计分析

- 日期：2026-06-21
- 状态：分析 / 设计（未实施）
- 目标：分析如何把 fxapk 做成 MCP（Model Context Protocol）服务器，让 Codex / Claude 等 agent
  **原生 tool-call** 调用 fxapk 的分析与图谱串案能力，而非 shell 出 CLI 再解析 stdout。

> 这是「CLI + 稳定 JSON 打底（a）、MCP 预留（b）」里 (b) 的落地分析。结论先行：**fxapk 现状离
> MCP 很近**——核心能力早已是「纯函数 / 稳定 JSON 产出」，MCP 服务器只是一层薄壳，**不重写业务、
> 不新增分析逻辑**，估算 ~1 个 PR（1 文件 + 打包 extra + 测试）。

---

## 1. 为什么做 MCP（动机）

当前 Codex 用 fxapk 的方式：`subprocess` 跑 `fxapk graph link <sha>` / `fxapk digest x.json`，
再解析 stdout JSON。可用，但：

- agent 要自己拼命令、管路径、解析输出、处理退出码；
- 没有机器可读的「工具清单 + 入参 schema」，agent 靠文档/试错发现能力；
- 多步编排（analyze → digest → graph ingest → cluster）全靠 agent 串 shell。

MCP 把每个能力暴露成带 **JSON Schema 的 tool**，agent 自动发现、类型校验、原生调用，输出直接是
结构化对象。对「Codex 驱动 fxapk」这一既定消费模型是顺滑升级。

---

## 2. 暴露哪些工具（capability → MCP tool）

fxapk 的能力**已经是 JSON-friendly 纯函数 / 命令**，逐一映射：

| MCP tool | 包装的现有实现 | 入参 | 产出 |
|---|---|---|---|
| `analyze_apk` | `core.loader.load_app` + `core.pipeline.run` + `report.json.to_dict` | `{apk_path, online, out_dir?}` | report dict（或直接 digest，见下） |
| `digest_report` | `report.digest.build_digest` | `{report_path}` 或 `{report}` | 紧凑调证摘要（优先级排序线索 + 计数） |
| `graph_ingest` | `graph.ingest_report` / `ingest_batch` + `GraphStore` | `{report_path \| dir, db?}` | `{ingested, failed, db}` |
| `graph_link` | `graph.query_link` | `{sha256, db?}` | 关联 APK + 共享强实体 |
| `graph_query` | `graph.query_by_kind` | `{kind, value, db?}` | 命中该实体的 APK |
| `graph_cluster` | `graph.query_clusters` | `{min_shared?, db?}` | 团伙簇 + 并案依据 + 置信分 |
| `graph_stats` | `graph.query_stats` | `{db?}` | 节点/边/各 kind 计数 |
| `graph_cypher` | `GraphStore.query_cypher` | `{query, db?}` | 原始 Cypher 行（只读探查） |
| `export_ioc` | `report.ioc.leads_to_ioc_rows` | `{report_path}` | IOC 行（CSV/数组） |
| `build_letters` | `report.letters.build_letters` | `{report_path}` | 调证函草稿 |

**关键点**：`graph.query_*` 与 `build_digest` **本就返回 JSON-able dict**（CLI 命令只是 `json.dumps`
它们）。MCP tool 直接 `return` 这些 dict——零适配。这正是 (a) 阶段「CLI+JSON 打底」预留 (b) 的回报。

最小可用集（MVP）：`analyze_apk`、`digest_report`、`graph_ingest`、`graph_link`、`graph_cluster`、
`graph_query`、`graph_stats`。其余按需补。

---

## 3. 架构：薄壳复用，不碰业务

```
Codex / Claude ── MCP(stdio) ──> fxapk-mcp 服务器
                                   │  每个 @tool 仅做：参数校验 → 调既有纯函数/命令实现 → 返回 dict
                                   └─ 复用 core.pipeline / graph.* / report.digest|ioc|letters（零重写）
```

- **传输**：`stdio`（本地）。Codex / Claude Code 以子进程方式拉起 `fxapk-mcp`，最贴合「本地工具层」。
  （HTTP/SSE 传输留给远程多客户端场景，本期不需要。）
- **SDK**：官方 `mcp` Python SDK（`FastMCP`）。`pip install fxapk[mcp]` 引入，**可选依赖**，不进核心
  运行期 deps（与 `[graph]` 同模式）。
- **入口**：`pyproject` 加 `fxapk-mcp = "apkscan.mcp.server:main"`（或 `fxapk mcp` 子命令）。
- **新增代码**：仅 `apkscan/mcp/server.py` 一个文件（+ `__init__`）。业务全在既有模块。

---

## 4. 骨架（FastMCP，示意）

```python
# apkscan/mcp/server.py  —— 薄壳，复用既有实现
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fxapk")

@mcp.tool()
def digest_report(report_path: str) -> dict:
    """读 report.json，返回按优先级排序的紧凑调证摘要。"""
    import json
    from apkscan.report.digest import build_digest
    return build_digest(json.loads(open(report_path, encoding="utf-8").read()))

@mcp.tool()
def graph_link(sha256: str, db: str = "") -> dict:
    """拉出与该 APK 共享强实体的关联 APK（团伙串案）。"""
    from apkscan.graph import GraphStore, query_link
    with GraphStore(db) as store:        # 复用既有纯函数，零重写
        return query_link(store, sha256)

@mcp.tool()
def analyze_apk(apk_path: str, online: bool = True, out_dir: str = "out") -> dict:
    """静态分析 APK/IPA，返回紧凑调证摘要（大报告落盘，摘要回 agent）。"""
    import anyio
    from apkscan.report.digest import build_digest
    def _run() -> dict:
        from apkscan.core.loader import load_app
        from apkscan.core import pipeline
        from apkscan.report import json as rjson
        ctx = load_app(apk_path)
        report = pipeline.run(ctx, ...)      # 既有管线
        d = rjson.to_dict(report)
        # 落盘完整报告 + 回紧凑 digest（控 token）
        return build_digest(d)
    return await anyio.to_thread.run_sync(_run)   # analyze 是 CPU 密集同步 → 丢线程，不堵事件循环

def main() -> None:
    mcp.run()   # stdio
```

要点：
- `analyze_apk` **回 digest 而非完整 report**（完整报告落盘，路径附在结果里）——控 token，对齐 §2 的
  digest 设计；agent 要细节再 `digest_report`/读文件。
- analyze 是 **CPU 密集同步**（androguard 纯 Python 独占 GIL）→ 必须 `to_thread` 丢线程池，否则堵塞
  MCP 事件循环（这与 GUI 当年「分析跑子进程避免饿死 tkinter」是同一教训）。

---

## 5. 需要处理的点（风险 / 决策）

| 点 | 处理 |
|---|---|
| **长耗时 analyze** | `to_thread` 跑；大样本可能数十秒。MCP 客户端需容忍长 tool 调用；或先返回 task id + 轮询（MVP 先同步） |
| **图谱单写者** | `GraphStore` 单写者 + `threading.Lock`；MCP 并发 tool 调用时 `graph_ingest` 串行化（每调用开/关 store，或全局单 store + 锁） |
| **db 路径** | tool 入参 `db` 可选；默认 `.apkscan_cache/cases.kuzu`（与 CLI/batch 同约定），让 Codex 跨 analyze 累积同一图 |
| **可选依赖缺失** | `mcp` / `kuzu` 未装 → 入口给清晰提示（同 `[graph]` 模式），不崩 |
| **错误** | tool 内 try/except → 返回 `{"error": ...}`（MCP 工具错误语义），不抛裸异常 |
| **安全/合规** | MCP 服务器本地运行，只暴露**分析/查询**（被动），无攻击能力；与现有合规边界一致 |
| **并发/有状态** | FastMCP 默认单进程；图谱 store 生命周期：每 tool 调用开/关（简单、无状态泄漏）vs 长驻单 store（快但需锁）——MVP 用前者 |

---

## 6. 落地步骤（约 1 PR）

1. `pyproject`：加 `mcp = ["mcp>=1.0"]` 可选 extra + `fxapk-mcp` 入口（或 `fxapk mcp` 子命令）。
2. `apkscan/mcp/server.py`：FastMCP + 上述 7 个 MVP tool（全是薄壳调既有实现）。
3. 测试：直接单测各 tool 函数（它们就是包装器，断言转发到既有实现 + 返回结构）；MCP 协议层可加一个
   `mcp` 在场时的 smoke（importorskip("mcp")）。
4. README + 一段 Codex/Claude 客户端配置示例（`.mcp.json` / `claude mcp add`）。
5. CI：`lint`/`test` job 装 `.[graph,mcp]`（与 `[graph]` 同处理，pyright 能解析 `mcp`）。

**为什么便宜**：fxapk 这一路「CLI + 稳定 JSON 打底」的设计（graph query 纯函数返回 dict、digest
纯函数、pipeline 可程序化调用）就是为 (b) 预留的——MCP 服务器无需触碰任何业务逻辑，只把它们登记成
带 schema 的 tool。

---

## 7. 结论

做成 MCP 是**低成本、高契合**的下一步：一层薄壳暴露既有能力，让 Codex 从「拼 shell 命令」升级到
「原生 tool-call + schema 自发现」。建议实现 §2 的 MVP 工具集，`analyze_apk` 回 digest 控 token，
analyze 走线程，图谱 store 每调用开关。可作为独立 PR 落地（与本仓 `[graph]` 可选依赖同模式）。
