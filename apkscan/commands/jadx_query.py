"""``fxapk jadx`` 只读查询子命令（P2-D1）：usage / callpath。

消费已建立的 JADX 持久索引，**绝不跑 jadx、绝不启动任何子进程**——纯 load + 内存查询。
输出一律 JSON：load 三态原样透出（ok/miss/unavailable，exit 0，机器可判）；参数语法
错误才非零退出。空结果显式输出并带「空≠不存在/不可达」caveat；reason 一律过稳定码
语法闸，路径与异常文本绝不进输出。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import typer

from apkscan.core.jadx_callpath import CallPath, CallPathEdge, CallPathLimits, trace_callpath
from apkscan.core.jadx_index import (
    CacheMiss,
    CacheUnavailable,
    JadxIndexError,
    JadxIndexStore,
    LoadedIndex,
    UsageHit,
    find_value_usage,
)

_JADX_INDEX_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")

jadx_app = typer.Typer(
    add_completion=False,
    help="消费已建立的 JADX 持久索引，执行只读查询（绝不反编译）。",
)


def _stable_reason(value: object) -> str:
    """将缓存/异常原因收敛为不泄露路径和异常文本的稳定 code。"""
    if not isinstance(value, str):
        return "index_unavailable"
    lowered = value.lower()
    if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", lowered):
        return lowered
    return "index_unavailable"


def _reason_from_exception(exc: BaseException) -> str:
    """仅提取显式 code；绝不把异常文本透出到 CLI 输出。"""
    return _stable_reason(getattr(exc, "code", None))


def _validate_index_key(index_key: str) -> str:
    """key 语法校验必须早于 JadxIndexStore 构造——非法 key 不触碰文件系统。"""
    if not isinstance(index_key, str) or _JADX_INDEX_KEY_RE.fullmatch(index_key) is None:
        raise typer.BadParameter(
            "jadx index key 必须是 64 位小写十六进制",
            param_hint="--jadx-index",
        )
    return index_key


def _load_index(
    cache_root: Path, index_key: str
) -> tuple[LoadedIndex | None, dict[str, object] | None]:
    """加载索引并把非成功状态投影为 CLI JSON：(LoadedIndex, None) 或 (None, status 记录)。"""
    try:
        store = JadxIndexStore(cache_root)
        loaded = store.load_index(index_key)
    except JadxIndexError as exc:
        return None, {"status": "unavailable", "reason": _reason_from_exception(exc)}
    except Exception:  # noqa: BLE001 - 只读消费面，未知异常不泄露实现细节
        return None, {"status": "unavailable", "reason": "index_unavailable"}
    if isinstance(loaded, CacheMiss):
        return None, {"status": "miss", "reason": _stable_reason(loaded.reason)}
    if isinstance(loaded, CacheUnavailable):
        return None, {"status": "unavailable", "reason": _stable_reason(loaded.reason)}
    if not isinstance(loaded, LoadedIndex):
        return None, {"status": "unavailable", "reason": "index_unavailable"}
    return loaded, None


def _emit(payload: dict[str, object]) -> None:
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


def _usage_hit_record(hit: UsageHit) -> dict[str, object]:
    """UsageHit → 输出形态（不用 asdict：避免未来新增字段被无审查地递归暴露）。"""
    return {
        "path": hit.relative_path,
        "line": hit.line,
        "column": hit.column,
        "value_digest": hit.value_digest,
        "lineage": hit.lineage.to_record(),
        "class_context": hit.class_context,
        "method_context": hit.method_context,
        "ownership": hit.ownership,
    }


def _edge_record(edge: CallPathEdge) -> dict[str, object]:
    return {
        "caller": edge.caller,
        "callee": edge.callee,
        "caller_path": edge.caller_path,
        "line": edge.line,
        "resolution": edge.resolution,
    }


def _path_record(path: CallPath) -> dict[str, object]:
    return {"nodes": list(path.nodes), "edges": [_edge_record(e) for e in path.edges]}


@jadx_app.command("usage")
def jadx_usage(
    value: str = typer.Argument(..., help="要查询的字符串值。"),
    jadx_cache_root: Path = typer.Option(
        ..., "--jadx-cache-root", help="jadx 持久索引 cache 目录。"
    ),
    jadx_index: str = typer.Option(
        ..., "--jadx-index", help="索引 key（64 位小写 hex）。"
    ),
) -> None:
    """查询字符串值在已建索引中的使用位置（find_value_usage）。"""
    index_key = _validate_index_key(jadx_index)
    index, error = _load_index(jadx_cache_root, index_key)
    if error is not None or index is None:
        _emit(error or {"status": "unavailable", "reason": "index_unavailable"})
        return
    try:
        hits = find_value_usage(index, value)
    except JadxIndexError as exc:
        _emit({"status": "unavailable", "reason": _reason_from_exception(exc)})
        return
    except Exception:  # noqa: BLE001
        _emit({"status": "unavailable", "reason": "index_unavailable"})
        return
    records = [_usage_hit_record(hit) for hit in hits]
    caveats: list[dict[str, str]] = []
    if not records:
        caveats.append({
            "code": "empty_is_not_absence",
            "text": "空结果仅表示在索引覆盖范围内未观察到该值，绝不表示该值不存在。",
        })
    _emit({
        "status": "ok",
        "coverage": index.coverage,
        "hits": records,
        "caveats": caveats,
    })


@jadx_app.command("callpath")
def jadx_callpath(
    source: str = typer.Argument(..., help="源端点，如 Alpha#start/0。"),
    target: str = typer.Argument(..., help="目标端点，如 Alpha#target/0。"),
    jadx_cache_root: Path = typer.Option(
        ..., "--jadx-cache-root", help="jadx 持久索引 cache 目录。"
    ),
    jadx_index: str = typer.Option(
        ..., "--jadx-index", help="索引 key（64 位小写 hex）。"
    ),
) -> None:
    """查询已建索引中的静态调用路径（trace_callpath，bounded）。"""
    index_key = _validate_index_key(jadx_index)
    index, error = _load_index(jadx_cache_root, index_key)
    if error is not None or index is None:
        _emit(error or {"status": "unavailable", "reason": "index_unavailable"})
        return
    limits = CallPathLimits()
    try:
        paths = trace_callpath(index, source, target, limits=limits)
    except JadxIndexError as exc:
        _emit({"status": "unavailable", "reason": _reason_from_exception(exc)})
        return
    except Exception:  # noqa: BLE001
        _emit({"status": "unavailable", "reason": "index_unavailable"})
        return
    records = [_path_record(path) for path in paths]
    caveats: list[dict[str, str]] = []
    if not records:
        caveats.append({
            "code": "no_path_is_not_unreachable",
            "text": "空路径仅表示在索引覆盖与 bounded 查询限制内未观察到路径，绝不表示目标不可达。",
        })
    _emit({
        "status": "ok",
        "coverage": index.coverage,
        "paths": records,
        "limits": {
            "max_depth": limits.max_depth,
            "max_paths": limits.max_paths,
            "max_visited": limits.max_visited,
        },
        "caveats": caveats,
    })
