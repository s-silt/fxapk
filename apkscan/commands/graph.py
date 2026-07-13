"""图谱串案 CLI 子命令（``graph_app``）。

从 cli.py 物理拆出（纯搬移、逻辑不变）：本地 Kuzu 图谱的摄入 / 关联 / 团伙聚类等只读命令。
``graph_app`` 由 cli.py `app.add_typer(graph_app, name="graph")` 挂到主 app——add_typer 留 cli.py
以引用主 app、避免本模块反向 import cli 造成循环。
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path

import typer

logger = logging.getLogger(__name__)


graph_app = typer.Typer(
    add_completion=False,
    help="本地图谱串案：摄入报告 → 关联线索 → 团伙聚类（默认输出稳定 JSON）。",
)

_KUZU_HINT = "未安装图谱依赖，请安装：pip install kuzu==0.11.3"


def _graph_print(obj: object) -> None:
    """统一打印稳定 JSON（UTF-8、缩进 2）。"""
    import json as _json

    typer.echo(_json.dumps(obj, ensure_ascii=False, indent=2))


@contextmanager
def _graph_session(db: str):
    """打开 GraphStore + 统一收尾/错误处理。

    kuzu 缺失（ImportError，含 ModuleNotFoundError）→ 提示安装 + exit 1；其它异常 → 友好
    提示 + exit 1（非 traceback）；无论成败 finally 必 close（释放连接、不锁库）。
    """
    from apkscan.graph import GraphStore

    store = GraphStore(db) if db else GraphStore()
    try:
        yield store
    except typer.Exit:
        raise
    except ImportError:
        typer.echo(_KUZU_HINT, err=True)
        raise typer.Exit(code=1) from None
    except Exception as exc:  # noqa: BLE001 - 转友好提示而非 traceback
        logger.exception("[cli] graph 操作异常")
        typer.echo(f"错误：图谱操作失败：{exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        store.close()


@graph_app.command("ingest")
def graph_ingest(
    path: Path = typer.Argument(..., exists=True, help="report.json 文件或批量输出目录。"),
    db: str = typer.Option("", "--db", help="图谱 DB 路径（默认 .apkscan_cache/cases.kuzu）。"),
) -> None:
    """把一份 report.json 或整个批量目录摄入图谱（幂等）。"""
    import json as _json

    from apkscan.graph import ingest_batch, ingest_report

    with _graph_session(db) as store:
        if path.is_dir():
            analyzed: list[dict] = []
            subdirs = [d for d in path.iterdir() if d.is_dir()]
            for d in subdirs or [path]:
                jsons = [str(p) for p in d.glob("*.json")]
                if jsons:
                    analyzed.append({"apk": d.name, "report_paths": jsons})
            result = ingest_batch(analyzed, store)
        else:
            rep = _json.loads(path.read_text(encoding="utf-8"))
            ok = ingest_report(rep, store, report_path=str(path))
            result = {"ingested": int(ok), "failed": int(not ok), "errors": []}
        result["db"] = str(store.db_path)
        _graph_print(result)


@graph_app.command("link")
def graph_link(
    sha256: str = typer.Argument(..., help="目标 APK 的内容 sha256。"),
    db: str = typer.Option("", "--db", help="图谱 DB 路径。"),
) -> None:
    """拉出与该 APK 共享强实体的其它 APK（按权重排名）。"""
    from apkscan.graph import query_link

    with _graph_session(db) as store:
        _graph_print(query_link(store, sha256))


@graph_app.command("query")
def graph_query(
    kind: str = typer.Option(..., "--kind", help="实体类型，如 sign/c2/crypto_addr。"),
    value: str = typer.Option(..., "--value", help="实体值。"),
    db: str = typer.Option("", "--db", help="图谱 DB 路径。"),
) -> None:
    """反查：列出所有观测到该实体的 APK。"""
    from apkscan.graph import query_by_kind

    with _graph_session(db) as store:
        _graph_print(query_by_kind(store, kind, value))


@graph_app.command("cluster")
def graph_cluster(
    min_shared: int = typer.Option(1, "--min-shared", help="过滤共享不同实体数低于 N 的弱关联。"),
    db: str = typer.Option("", "--db", help="图谱 DB 路径。"),
) -> None:
    """跑全图团伙簇（连通分量）+ 并案依据 + 置信分。"""
    from apkscan.graph import query_clusters

    with _graph_session(db) as store:
        _graph_print(query_clusters(store, min_shared))


@graph_app.command("stats")
def graph_stats(
    db: str = typer.Option("", "--db", help="图谱 DB 路径。"),
) -> None:
    """图谱体检：apk/entity/edge 计数 + 按 kind 分布。"""
    from apkscan.graph import query_stats

    with _graph_session(db) as store:
        _graph_print(query_stats(store))


@graph_app.command("cypher")
def graph_cypher(
    query: str = typer.Argument(..., help="原始 Cypher（仅供只读探查；写操作请用 ingest）。"),
    db: str = typer.Option("", "--db", help="图谱 DB 路径。"),
) -> None:
    """原始 Cypher 只读逃生口（供 agent 自定义图谱查询）。语法/执行错误 → 友好 JSON 错误 + exit 1。"""
    with _graph_session(db) as store:
        try:
            rows = store.query_cypher(query)
        except (ImportError, typer.Exit):
            raise
        except Exception as exc:  # noqa: BLE001 - 友好 JSON 错误而非 traceback
            _graph_print({"error": str(exc), "query": query})
            raise typer.Exit(code=1) from exc
        _graph_print(rows)


@graph_app.command("rm-entity")
def graph_rm_entity(
    kind: str = typer.Argument(..., help="实体类型，如 sign/c2/crypto_addr。"),
    value: str = typer.Argument(..., help="实体值。"),
    db: str = typer.Option("", "--db", help="图谱 DB 路径。"),
) -> None:
    """全局删除一个实体及其所有 OBSERVED 边（参数化防注入）。打印删除数。"""
    with _graph_session(db) as store:
        store.ensure_ready()  # 先探活：kuzu 缺失 → _graph_session 给统一安装提示
        n = store.delete_entity(kind, value)
        _graph_print({"deleted": n, "kind": kind, "value": value, "db": str(store.db_path)})


@graph_app.command("unlink")
def graph_unlink(
    sha256: str = typer.Argument(..., help="APK 内容 sha256。"),
    kind: str = typer.Argument(..., help="实体类型。"),
    value: str = typer.Argument(..., help="实体值。"),
    db: str = typer.Option("", "--db", help="图谱 DB 路径。"),
) -> None:
    """只断该 APK 与某实体的这条边（不动节点）。打印删除边数。"""
    with _graph_session(db) as store:
        store.ensure_ready()  # 先探活：kuzu 缺失 → _graph_session 给统一安装提示
        n = store.unlink(sha256, kind, value)
        _graph_print(
            {"removed": n, "sha256": sha256, "kind": kind, "value": value, "db": str(store.db_path)}
        )


@graph_app.command("prune-weak")
def graph_prune_weak(
    db: str = typer.Option("", "--db", help="图谱 DB 路径。"),
) -> None:
    """一次性清存量非强档噪音实体（not is_strong）。打印清理数。"""
    from apkscan.graph import prune_weak

    with _graph_session(db) as store:
        store.ensure_ready()  # 先探活：kuzu 缺失 → _graph_session 给统一安装提示
        n = prune_weak(store)
        _graph_print({"pruned": n, "db": str(store.db_path)})
