"""JADX 结构索引上的有界静态调用路径查询（P1-B）。

在持久索引的 structure 段上做确定性 BFS：调用边分为 name_unique、ambiguous 与
not_in_index 三态。name_unique 只表示简单名候选在索引覆盖内全局唯一，不是方法绑定；
not_in_index 只表示索引里没有该名字的可解析 body，不专指动态调用，只进入 gaps，绝不
表示不可达。路径上每条边都带 caller 文件、调用行与位置 scope，可定位可复核。
"""

from __future__ import annotations

import heapq
import itertools
import re
from collections import deque
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from apkscan.core.jadx_index import (
    REASON_MALFORMED,
    JadxIndexError,
    LoadedIndex,
    _IDENTIFIER_RE,
    _MAX_PERSISTED_IDENTIFIER,
    _QUALIFIED_CLASS_RE,
    _normalize_safe_relative_path,
    _valid_call_qualifier,
    _valid_call_scope,
)

#: 端点形态：完整 "cls#name/arity" 或省 arity 的 "cls#name"（全 arity 匹配）。
_METHOD_ID_RE = re.compile(r"^([^#]+)#([^/]+)(?:/([0-9]+))?$")
_MAX_ENDPOINT_LEN = 4096
_REASON_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SCOPE_RANK = {"method": 0, "nested_type": 1, "lambda": 2, "unknown": 3}


@dataclass(frozen=True, slots=True)
class CallPathLimits:
    max_depth: int = 16
    max_paths: int = 8
    max_visited: int = 100_000
    #: None 保持与 master 一致的全候选展开；显式整数才启用确定性 fanout 截断。
    max_fanout: int | None = None
    max_gaps: int = 64

    def __post_init__(self) -> None:
        for name in (
            "max_depth",
            "max_paths",
            "max_visited",
            "max_gaps",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise JadxIndexError(REASON_MALFORMED, f"$.limits.{name}")
        if self.max_fanout is not None and (
            isinstance(self.max_fanout, bool)
            or not isinstance(self.max_fanout, int)
            or self.max_fanout < 0
        ):
            raise JadxIndexError(REASON_MALFORMED, "$.limits.max_fanout")


@dataclass(frozen=True, slots=True)
class CallPathEdge:
    caller: str
    callee: str
    caller_path: str
    line: int
    resolution: str
    scope: str

    def __post_init__(self) -> None:
        if not isinstance(self.caller, str) or not self.caller:
            raise JadxIndexError(REASON_MALFORMED, "$.caller")
        if not isinstance(self.callee, str) or not self.callee:
            raise JadxIndexError(REASON_MALFORMED, "$.callee")
        _normalize_safe_relative_path(self.caller_path, "$.caller_path")
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise JadxIndexError(REASON_MALFORMED, "$.line")
        if self.resolution not in ("name_unique", "ambiguous", "not_in_index"):
            raise JadxIndexError(REASON_MALFORMED, "$.resolution")
        if not _valid_call_scope(self.scope):
            raise JadxIndexError(REASON_MALFORMED, "$.scope")


@dataclass(frozen=True, slots=True)
class CallPath:
    nodes: tuple[str, ...]
    edges: tuple[CallPathEdge, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.nodes, tuple) or len(self.nodes) < 2:
            raise JadxIndexError(REASON_MALFORMED, "$.nodes")
        if not isinstance(self.edges, tuple) or len(self.edges) != len(self.nodes) - 1:
            raise JadxIndexError(REASON_MALFORMED, "$.edges")
        if any(
            not isinstance(edge, CallPathEdge) or edge.resolution == "not_in_index"
            for edge in self.edges
        ):
            raise JadxIndexError(REASON_MALFORMED, "$.edges")


@dataclass(frozen=True, slots=True)
class CallPathTrace:
    """有界调用路径查询结果及其覆盖/截断边界。

    ``name_unique`` 仅表示简单名候选在索引覆盖内全局唯一，不是方法绑定；
    ``not_in_index`` 仅表示索引里没有该名字的可解析 body，绝不表示不可达，也不专指
    动态调用。
    """

    paths: tuple[CallPath, ...]
    gaps: tuple[CallPathEdge, ...]
    coverage: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.paths, tuple) or any(
            not isinstance(path, CallPath) for path in self.paths
        ):
            raise JadxIndexError(REASON_MALFORMED, "$.trace.paths")
        if not isinstance(self.gaps, tuple):
            raise JadxIndexError(REASON_MALFORMED, "$.trace.gaps")
        previous_gap: tuple[str, str, str, int, str] | None = None
        for gap in self.gaps:
            if not isinstance(gap, CallPathEdge) or gap.resolution != "not_in_index":
                raise JadxIndexError(REASON_MALFORMED, "$.trace.gaps")
            key = (gap.caller, gap.callee, gap.caller_path, gap.line, gap.scope)
            if previous_gap is not None and key <= previous_gap:
                raise JadxIndexError(REASON_MALFORMED, "$.trace.gaps")
            previous_gap = key
        if self.coverage not in ("complete", "partial"):
            raise JadxIndexError(REASON_MALFORMED, "$.trace.coverage")
        if not isinstance(self.reason_codes, tuple):
            raise JadxIndexError(REASON_MALFORMED, "$.trace.reason_codes")
        previous_reason: str | None = None
        for reason in self.reason_codes:
            if (
                not isinstance(reason, str)
                or _REASON_CODE_RE.fullmatch(reason) is None
                or (previous_reason is not None and reason <= previous_reason)
            ):
                raise JadxIndexError(REASON_MALFORMED, "$.trace.reason_codes")
            previous_reason = reason


def _parse_endpoint(value: object) -> tuple[str, str, int | None] | None:
    if not isinstance(value, str) or not value or len(value) > _MAX_ENDPOINT_LEN:
        return None
    match = _METHOD_ID_RE.fullmatch(value)
    if match is None:
        return None
    cls = match.group(1)
    name = match.group(2)
    if _QUALIFIED_CLASS_RE.fullmatch(cls) is None or (
        name != "<init>" and _IDENTIFIER_RE.fullmatch(name) is None
    ):
        return None
    arity = int(match.group(3)) if match.group(3) is not None else None
    return cls, name, arity


def _index_methods(
    index: LoadedIndex,
) -> tuple[dict[str, tuple[str, list[object]]], dict[str, list[str]]]:
    """跨全部 shard 建方法表：id -> (caller 文件, calls)；简单名 -> 候选 id 列表。

    ★形状异常 fail-closed（对齐 find_value_usage）：坏结构当场揭穿，不许静默跳过。
    ★同一方法 id 的重复：同 shard 内的擦除重载与跨 shard 的重复类（多 dex 脱壳
    dump 常态，schema 1.2 起合法）同语义——确定性合并出边，绝不静默后者覆盖。
    合并必须与 shard 枚举序无关：caller 文件取全部声明中字典序最小的路径；
    calls 多重集本身无序（BFS 扩展前按 (line, callee, qualifier, scope) 排序）。
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


def _expansion_stream(
    candidates: list[str],
    fanout: int | None,
    nodes: tuple[str, ...],
    line: int,
    resolution: str,
    scope: str,
) -> Iterator[tuple[str, int, str, str]]:
    """单个调用点的候选流（按候选身份字典序，即 expansion_key 递增）。

    ``fanout`` 为显式 ``max_fanout`` 时只走候选表前缀（与 master 的 ``candidates[:max_fanout]``
    同一前缀），用 ``islice`` 惰性截断、不复制列表——预算耗尽时本流至多被拉取一次，不该为它
    先分配 calls × max_fanout 个引用。路径内不回访节点：环自然终止，路径保持简单路径语义；
    ★过滤必须发生在预算选取之前：若先取前 remaining 项再过滤，环候选会白占名额、把本应入列
    的非环候选挤掉，与 master「完整排序后跳过」不再等价。每条流在产出一项前至多跳过
    ``len(nodes)``（≤ max_depth + 1）个环候选。
    """
    for candidate in itertools.islice(candidates, fanout):
        if candidate in nodes:
            continue
        yield candidate, line, resolution, scope


def trace_callpath(
    index: LoadedIndex,
    source: str,
    target: str,
    *,
    limits: CallPathLimits = CallPathLimits(),
) -> CallPathTrace:
    """source 到 target 的静态调用路径（最短优先、字典序定序、bounded）。

    未知端点 / 坏形态输入 / source==target → 带稳定 reason 的空结果；
    空结果与 gap 都不是「不可达」。

    ``name_unique`` 仅表示简单名候选在索引覆盖内全局唯一，不是方法绑定；
    ``not_in_index`` 仅表示索引里没有该名字的可解析 body，绝不表示不可达，也不专指
    动态调用。调用点的 ``qualifier`` 与 ``scope`` 照常记录。scope 不参与候选解析与
    resolution 判定，但参与 gap 身份与确定性排序：同行同名不同 scope 的调用点是两条
    gap，各占一个 ``max_gaps`` 预算位。

    因此 ``class C extends Base``、C 声明 ``foo/1``、Base 声明 ``foo/2`` 的跨 arity
    构型会保留全部简单名候选并标为 ambiguous，不再产生 owner 收窄导致的假唯一结论。
    代价是：即使本类自调用只有一个本类候选，只要索引中其他类存在同简单名方法，也会
    诚实降级为 ambiguous。

    **入列预算（资源边界，零语义变化）**：队列是纯 FIFO、出队总次数 ≤ ``max_visited``，
    故全局入列序号（初始 starts 计入）> ``max_visited`` 的项永远不会被出队——只入列前
    ``max_visited`` 项、其余丢弃并计数（``dropped``），循环结束后按 master 循环头的检查
    顺序补偿 reason：``dropped > 0`` 意味着 master 此刻队列非空、会先查 ``paths_limited``
    再查 ``visited_limited``。单节点的展开是各调用点候选流的稳定 k 路归并
    （``heapq.merge``，同 key 按调用点序出队，逐项等于 master 的稳定 ``sorted(expanded, key)``），
    只拉取前 remaining+1 项：单节点代价 O(calls + (remaining+1)·log calls)，外加每条流在
    产出前至多跳过 ≤ max_depth+1 个环候选；不为候选表做任何复制。每个出队节点的 calls
    校验、gap 登记、``fanout_limited`` 登记与 ``caller_path`` 校验与预算无关、一律照常执行：
    paths / gaps / reason_codes / 异常行为与无预算版本逐字节相同
    （tests/test_jadx_callpath_budget.py 以 master 实测指纹与内嵌参考实现钉住）。
    """
    if not isinstance(index, LoadedIndex):
        raise JadxIndexError(REASON_MALFORMED, "$.index")
    if not isinstance(limits, CallPathLimits):
        raise JadxIndexError(REASON_MALFORMED, "$.limits")

    def result(
        paths: tuple[CallPath, ...] = (),
        gaps: tuple[CallPathEdge, ...] = (),
        reasons: tuple[str, ...] = (),
    ) -> CallPathTrace:
        return CallPathTrace(
            paths=paths,
            gaps=gaps,
            coverage=index.coverage,
            reason_codes=reasons,
        )

    def expansion_key(
        entry: tuple[str, int, str, str],
    ) -> tuple[str, int, int]:
        return entry[0], entry[1], _SCOPE_RANK[entry[3]]

    source_parts = _parse_endpoint(source)
    target_parts = _parse_endpoint(target)
    if source_parts is None or target_parts is None or source == target:
        return result(reasons=("malformed_query",))

    methods, by_name = _index_methods(index)
    starts = _match_endpoints(methods, source_parts)
    ends = set(_match_endpoints(methods, target_parts))
    if not starts or not ends:
        return result(reasons=("endpoint_unmatched",))

    queue: deque[tuple[str, tuple[str, ...], tuple[CallPathEdge, ...]]] = deque()
    for position, node in enumerate(starts):
        if position >= limits.max_visited:
            break
        queue.append((node, (node,), ()))

    enqueued = len(queue)
    dropped = len(starts) - enqueued
    seen_sequences: set[tuple[str, ...]] = set()
    found: list[CallPath] = []
    gaps_by_key: dict[tuple[str, str, str, int, str], CallPathEdge] = {}
    reasons: set[str] = set()
    visited = 0

    while queue:
        if len(found) >= limits.max_paths:
            reasons.add("paths_limited")
            break
        if visited >= limits.max_visited:
            # 入列预算使正常控制流不再能到达此分支；保留作防御性预算检查。
            reasons.add("visited_limited")
            break

        node, nodes, edges = queue.popleft()
        visited += 1
        if node in ends and len(nodes) > 1:
            if nodes not in seen_sequences:
                seen_sequences.add(nodes)
                found.append(CallPath(nodes=nodes, edges=edges))
            continue
        if len(edges) >= limits.max_depth:
            if methods[node][1]:
                reasons.add("depth_limited")
            continue

        caller_path, calls = methods[node]
        validated_calls: list[tuple[int, str, str, str]] = []
        for call in calls:
            if not isinstance(call, Mapping) or set(call) != {
                "callee",
                "line",
                "qualifier",
                "scope",
            }:
                raise JadxIndexError(REASON_MALFORMED, "$.calls")
            callee = call["callee"]
            line = call["line"]
            qualifier = call["qualifier"]
            scope = call["scope"]
            if (
                not isinstance(callee, str)
                or len(callee) > _MAX_PERSISTED_IDENTIFIER
                or _IDENTIFIER_RE.fullmatch(callee) is None
                or isinstance(line, bool)
                or not isinstance(line, int)
                or line < 1
                or not _valid_call_qualifier(qualifier)
                or not _valid_call_scope(scope)
            ):
                raise JadxIndexError(REASON_MALFORMED, "$.calls")
            assert isinstance(qualifier, str) and isinstance(scope, str)
            validated_calls.append((line, callee, qualifier, scope))

        ordered_calls = sorted(validated_calls)
        for line, callee, _qualifier, scope in ordered_calls:
            candidates = by_name.get(callee, ())
            if not candidates:
                gap = CallPathEdge(
                    caller=node,
                    callee=callee,
                    caller_path=caller_path,
                    line=line,
                    resolution="not_in_index",
                    scope=scope,
                )
                key = (
                    gap.caller,
                    gap.callee,
                    gap.caller_path,
                    gap.line,
                    gap.scope,
                )
                if key not in gaps_by_key:
                    if len(gaps_by_key) >= limits.max_gaps:
                        reasons.add("gaps_limited")
                    else:
                        gaps_by_key[key] = gap
                continue
            if limits.max_fanout is not None and len(candidates) > limits.max_fanout:
                reasons.add("fanout_limited")

        # 每个调用点一条候选流：候选表已按身份字典序排好，同一调用点的 line/scope 固定，
        # 故单条流按 expansion_key 严格递增；各流按 ordered_calls 顺序参加**稳定** k 路归并
        # （heapq.merge 同 key 按流序出队），结果与 master 的 sorted(expanded, key)（稳定
        # 排序、构造序＝调用点序×候选序）逐项相同。只取前 remaining+1 项：前 remaining 项
        # 入列、第 remaining+1 项存在即判溢出——单节点代价 O(calls + (remaining+1)·log calls)，
        # 不再随 calls × candidates 线性增长（预算耗尽前最后一个大扇出节点也不例外）。
        streams: list[Iterator[tuple[str, int, str, str]]] = []
        for line, callee, _qualifier, scope in ordered_calls:
            candidates = by_name.get(callee, ())
            if not candidates:
                continue
            resolution = "name_unique" if len(candidates) == 1 else "ambiguous"
            streams.append(
                _expansion_stream(candidates, limits.max_fanout, nodes, line, resolution, scope)
            )

        remaining = limits.max_visited - enqueued
        taken = list(itertools.islice(heapq.merge(*streams, key=expansion_key), remaining + 1))
        if len(taken) > remaining:
            # dropped 仅以 >0 参与判定：它意味着 master 的总入列数已超过 max_visited。
            dropped += 1
            # master 会为所有幸存候选构造 CallPathEdge；即使候选被预算丢弃，
            # 也必须保留 caller_path 的 fail-closed 异常面。
            _normalize_safe_relative_path(caller_path, "$.caller_path")

        for candidate, line, resolution, scope in taken[:remaining]:
            edge = CallPathEdge(
                caller=node,
                callee=candidate,
                caller_path=caller_path,
                line=line,
                resolution=resolution,
                scope=scope,
            )
            queue.append(
                (
                    candidate,
                    (*nodes, candidate),
                    (*edges, edge),
                )
            )
            enqueued += 1

    if dropped > 0 and len(found) >= limits.max_paths:
        reasons.add("paths_limited")
    if visited >= limits.max_visited:
        # 即便本次展开恰好耗尽队列，达到 visited 帽也必须显式披露预算边界。
        reasons.add("visited_limited")
    found.sort(key=lambda path: (len(path.nodes), path.nodes))
    ordered_gaps = tuple(gaps_by_key[key] for key in sorted(gaps_by_key))
    return result(
        paths=tuple(found),
        gaps=ordered_gaps,
        reasons=tuple(sorted(reasons)),
    )


__all__ = [
    "CallPath",
    "CallPathEdge",
    "CallPathLimits",
    "CallPathTrace",
    "trace_callpath",
]
