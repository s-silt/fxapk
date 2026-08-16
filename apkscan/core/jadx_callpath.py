"""JADX 结构索引上的有界静态调用路径查询（P1-B）。

在 schema 1.2 的 structure 段上做确定性 BFS：按简单名解析调用边（index 全局
唯一候选 → "unique"，多候选 → "ambiguous"，刻意过近似）。反射 / JNI / 动态
分发 / `new` 构造边均不可见——**查不到路径绝不等于不可达**，阴性一律不产出。
路径上每条边都带 caller 文件与调用行，可定位可复核。
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass

from apkscan.core.jadx_index import (
    REASON_MALFORMED,
    JadxIndexError,
    LoadedIndex,
    _normalize_safe_relative_path,
)

#: 端点形态：完整 "cls#name/arity" 或省 arity 的 "cls#name"（全 arity 匹配）。
_METHOD_ID_RE = re.compile(r"^([^#]+)#([^/]+)(?:/([0-9]+))?$")
_MAX_ENDPOINT_LEN = 4096


@dataclass(frozen=True, slots=True)
class CallPathLimits:
    max_depth: int = 16
    max_paths: int = 8
    max_visited: int = 100_000

    def __post_init__(self) -> None:
        for name in ("max_depth", "max_paths", "max_visited"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise JadxIndexError(REASON_MALFORMED, f"$.limits.{name}")


@dataclass(frozen=True, slots=True)
class CallPathEdge:
    caller: str
    callee: str
    caller_path: str
    line: int
    resolution: str

    def __post_init__(self) -> None:
        if not isinstance(self.caller, str) or not self.caller:
            raise JadxIndexError(REASON_MALFORMED, "$.caller")
        if not isinstance(self.callee, str) or not self.callee:
            raise JadxIndexError(REASON_MALFORMED, "$.callee")
        _normalize_safe_relative_path(self.caller_path, "$.caller_path")
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise JadxIndexError(REASON_MALFORMED, "$.line")
        if self.resolution not in ("unique", "ambiguous"):
            raise JadxIndexError(REASON_MALFORMED, "$.resolution")


@dataclass(frozen=True, slots=True)
class CallPath:
    nodes: tuple[str, ...]
    edges: tuple[CallPathEdge, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.nodes, tuple) or len(self.nodes) < 2:
            raise JadxIndexError(REASON_MALFORMED, "$.nodes")
        if not isinstance(self.edges, tuple) or len(self.edges) != len(self.nodes) - 1:
            raise JadxIndexError(REASON_MALFORMED, "$.edges")


def _parse_endpoint(value: object) -> tuple[str, str, int | None] | None:
    if not isinstance(value, str) or not value or len(value) > _MAX_ENDPOINT_LEN:
        return None
    match = _METHOD_ID_RE.fullmatch(value)
    if match is None:
        return None
    arity = int(match.group(3)) if match.group(3) is not None else None
    return match.group(1), match.group(2), arity


def _index_methods(
    index: LoadedIndex,
) -> tuple[dict[str, tuple[str, list[object]]], dict[str, list[str]]]:
    """跨全部 shard 建方法表：id -> (caller 文件, calls)；简单名 -> 候选 id 列表。

    ★形状异常 fail-closed（对齐 find_value_usage）：坏结构当场揭穿，不许静默跳过。
    ★同一方法 id 的重复：同 shard 内的擦除重载与跨 shard 的重复类（多 dex 脱壳
    dump 常态，schema 1.2 起合法）同语义——确定性合并出边，绝不静默后者覆盖。
    合并必须与 shard 枚举序无关：caller 文件取全部声明中字典序最小的路径；
    calls 多重集本身无序（BFS 扩展前按 (callee, line) 排序）。
    """
    methods: dict[str, tuple[str, list[object]]] = {}
    by_name: dict[str, list[str]] = {}
    for si, shard in enumerate(index.shards):
        if not isinstance(shard, Mapping):
            raise JadxIndexError(REASON_MALFORMED, f"$.shards[{si}]")
        structure = shard.get("structure")
        if not isinstance(structure, Mapping) or set(structure) != {"classes"}:
            raise JadxIndexError(REASON_MALFORMED, f"$.shards[{si}].structure")
        classes = structure["classes"]
        if not isinstance(classes, list):
            raise JadxIndexError(REASON_MALFORMED, f"$.shards[{si}].structure.classes")
        for cls in classes:
            if not isinstance(cls, Mapping) or set(cls) != {"name", "path", "methods"}:
                raise JadxIndexError(REASON_MALFORMED, f"$.shards[{si}].structure.classes")
            name = cls["name"]
            rel = cls["path"]
            raw_methods = cls["methods"]
            if (
                not isinstance(name, str)
                or not isinstance(rel, str)
                or not isinstance(raw_methods, list)
            ):
                raise JadxIndexError(REASON_MALFORMED, f"$.shards[{si}].structure.classes")
            for method in raw_methods:
                if not isinstance(method, Mapping) or set(method) != {
                    "name",
                    "arity",
                    "start_line",
                    "end_line",
                    "body_digest",
                    "calls",
                }:
                    raise JadxIndexError(REASON_MALFORMED, f"$.shards[{si}].structure")
                mn = method["name"]
                arity = method["arity"]
                calls = method["calls"]
                if (
                    not isinstance(mn, str)
                    or isinstance(arity, bool)
                    or not isinstance(arity, int)
                    or not isinstance(calls, list)
                ):
                    raise JadxIndexError(REASON_MALFORMED, f"$.shards[{si}].structure")
                ident = f"{name}#{mn}/{arity}"
                existing = methods.get(ident)
                if existing is not None:
                    merged = list(existing[1]) + list(calls)
                    methods[ident] = (min(existing[0], rel), merged)
                    continue
                methods[ident] = (rel, calls)
                by_name.setdefault(mn, []).append(ident)
    for candidates in by_name.values():
        candidates.sort()
    return methods, by_name


def _match_endpoints(
    methods: dict[str, tuple[str, list[object]]], parts: tuple[str, str, int | None]
) -> list[str]:
    cls, name, arity = parts
    if arity is not None:
        ident = f"{cls}#{name}/{arity}"
        return [ident] if ident in methods else []
    prefix = f"{cls}#{name}/"
    return sorted(ident for ident in methods if ident.startswith(prefix))


def trace_callpath(
    index: LoadedIndex,
    source: str,
    target: str,
    *,
    limits: CallPathLimits = CallPathLimits(),
) -> tuple[CallPath, ...]:
    """source 到 target 的静态调用路径（最短优先、字典序定序、bounded）。

    未知端点 / 坏形态输入 / source==target → 空结果；空结果不是「不可达」。
    """
    if not isinstance(index, LoadedIndex) or not isinstance(limits, CallPathLimits):
        return ()
    source_parts = _parse_endpoint(source)
    target_parts = _parse_endpoint(target)
    if source_parts is None or target_parts is None or source == target:
        return ()

    methods, by_name = _index_methods(index)
    starts = _match_endpoints(methods, source_parts)
    ends = set(_match_endpoints(methods, target_parts))
    if not starts or not ends:
        return ()

    queue: deque[tuple[str, tuple[str, ...], tuple[CallPathEdge, ...]]] = deque(
        (node, (node,), ()) for node in starts
    )
    seen_sequences: set[tuple[str, ...]] = set()
    found: list[CallPath] = []
    visited = 0
    while queue and len(found) < limits.max_paths and visited < limits.max_visited:
        node, nodes, edges = queue.popleft()
        visited += 1
        if node in ends and len(nodes) > 1:
            if nodes not in seen_sequences:
                seen_sequences.add(nodes)
                found.append(CallPath(nodes=nodes, edges=edges))
            continue
        if len(edges) >= limits.max_depth:
            continue
        caller_path, calls = methods[node]
        expanded: list[tuple[str, int, str]] = []
        for call in calls:
            if not isinstance(call, Mapping) or set(call) != {"callee", "line"}:
                raise JadxIndexError(REASON_MALFORMED, "$.calls")
            callee = call["callee"]
            line = call["line"]
            if (
                not isinstance(callee, str)
                or isinstance(line, bool)
                or not isinstance(line, int)
                or line < 1
            ):
                raise JadxIndexError(REASON_MALFORMED, "$.calls")
            candidates = by_name.get(callee, [])
            resolution = "unique" if len(candidates) == 1 else "ambiguous"
            for candidate in candidates:
                expanded.append((candidate, line, resolution))
        for candidate, line, resolution in sorted(expanded, key=lambda e: (e[0], e[1])):
            # 路径内不回访节点：环自然终止，路径保持简单路径语义。
            if candidate in nodes:
                continue
            edge = CallPathEdge(
                caller=node,
                callee=candidate,
                caller_path=caller_path,
                line=line,
                resolution=resolution,
            )
            queue.append((candidate, (*nodes, candidate), (*edges, edge)))
    found.sort(key=lambda path: (len(path.nodes), path.nodes))
    return tuple(found)


__all__ = [
    "CallPath",
    "CallPathEdge",
    "CallPathLimits",
    "trace_callpath",
]
