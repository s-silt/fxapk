"""trace_callpath 入列预算：队列占用以 max_visited 封顶，且输出与 master 逐字节等价。

背景：BFS 每出队一个节点就把 ``calls × candidates`` 全部入列（每项复制整条路径元组），
``max_visited`` 只限**出队**；合成夹具（10 候选 × 10 调用点 × 深度 3）实测
``max_visited=1000`` 时队列峰值 58,503、``max_visited=10`` 时 820。真实混淆样本单方法
调用点上限 256、单简单名候选最大 3038 → 单节点可入列约 78 万项，100k 次出队前内存即耗尽。

修法不加旋钮（``CallPathLimits`` 字段集被 test_scope_never_gates_expansion_or_adds_limits
锁死）：队列是纯 FIFO，出队总次数 ≤ ``max_visited``，故全局入列序号 > ``max_visited`` 的项
永远不会被出队——丢弃它们不改变任何可观测输出。本文件三类锁：

1. **oracle 等价（真索引路径）**：两个合成夹具 × 8 组端点 × 2112 组限额（含 max_visited=0 /
   max_paths=0 / max_fanout=0 等角例），把 ``CallPathTrace`` 的**全部**可观测字段（路径节点序与
   每条边的六元组、gap 六元组、coverage、reason_codes）序列化后的 canonical JSON 指纹必须与在
   master ``4d86455``（改动前）实测捕获的指纹逐字节一致。指纹由脚本在改动前的代码上生成、非手写。
2. **参考实现对等（伪造索引 + 随机 fuzz）**：本文件内嵌 master 的 BFS 原文作为参考实现，
   在对抗复核给出的反例构型与随机小图上逐例比较 ``CallPathTrace``/异常——覆盖真索引夹具
   到不了的形态（畸形 caller_path 的异常面、环过滤、省 arity 多起点等）。
3. **资源边界**（无修复即红）：队列长度峰值不得超过 ``max_visited``。
"""

from __future__ import annotations

import collections
import hashlib
import json
import random
from collections import deque
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

from apkscan.core import jadx_callpath as jcp
from apkscan.core.jadx_callpath import (
    _SCOPE_RANK,
    CallPath,
    CallPathEdge,
    CallPathLimits,
    CallPathTrace,
    _index_methods,
    _match_endpoints,
    _parse_endpoint,
    trace_callpath,
)
from apkscan.core.jadx_index import (
    _IDENTIFIER_RE,
    _MAX_PERSISTED_IDENTIFIER,
    REASON_MALFORMED,
    JadxIndexError,
    LoadedIndex,
    _valid_call_qualifier,
    _valid_call_scope,
)
from tests.test_jadx_callpath import _build_single_tree_index

# ---------------------------------------------------------------------------
# 合成夹具（与 oracle 生成脚本逐字一致；改动任何字符都会让指纹失配）
# ---------------------------------------------------------------------------


def _fanout_files(n_cand: int, k_calls: int) -> dict[str, str]:
    """``S#go`` → 简单名 ``a`` 的 n_cand 个候选，每个候选再发 k_calls 次 ``a()`` 后调 ``z()``。

    ``u()`` 不在索引 → not_in_index gap；``a()`` 两次 → 同名多候选 ambiguous。
    """
    files: dict[str, str] = {}
    for i in range(n_cand):
        body = "".join("        a();\n" for _ in range(k_calls))
        files[f"com/p/C{i}.java"] = (
            "package com.p;\n\npublic class C%d {\n    void a() {\n%s        z();\n    }\n}\n"
            % (i, body)
        )
    files["com/p/S.java"] = (
        "package com.p;\n\npublic class S {\n    void z() {\n    }\n"
        "    void go() {\n        a();\n        u();\n        a();\n    }\n}\n"
    )
    return files


#: 同行双调用（同 key 重复入列）+「第 max_visited 次出队恰是终点命中」构型。
_F2: dict[str, str] = {
    "com/q/S.java": (
        "package com.q;\n\npublic class S {\n    void go() {\n        a(); b();\n"
        "        a();\n    }\n    void t() {\n    }\n}\n"
    ),
    "com/q/A.java": "package com.q;\n\npublic class A {\n    void a() {\n        t();\n    }\n}\n",
    "com/q/B.java": (
        "package com.q;\n\npublic class B {\n    void b() {\n        t();\n        a();\n    }\n}\n"
    ),
}

_FIXTURES: dict[str, dict[str, str]] = {
    "fanout_4x3": _fanout_files(4, 3),
    "f2": _F2,
}

#: 限额网格：11 × 4 × 4 × 4 × 3 = 2112 组，覆盖 0 值角例（含 max_fanout=0）与默认值。
_GRID: list[dict[str, int | None]] = [
    {"max_visited": mv, "max_paths": mp, "max_depth": md, "max_fanout": mf, "max_gaps": mg}
    for mv in (0, 1, 2, 3, 4, 5, 6, 7, 8, 13, 100_000)
    for mp in (0, 1, 2, 8)
    for md in (1, 2, 3, 16)
    for mf in (None, 0, 1, 2)
    for mg in (0, 1, 64)
]

#: master 4d86455 上实测捕获的 canonical 输出指纹：(夹具, source, target) → sha256。
#: 端点覆盖：多候选目标、省 arity 起点、中途起点、终点即直接候选。
_ORACLE_SHA256: dict[tuple[str, str, str], str] = {
    ("fanout_4x3", "com.p.S#go/0", "com.p.S#z/0"): (
        "68c77e5973a02ecd63cea169eb4e58c88b867396b6470d8a695f44ebf38debd9"
    ),
    ("fanout_4x3", "com.p.S#go/0", "com.p.C0#a/0"): (
        "0980ff34d4891937af09ff002b4ce06d9f17921d594d584860c37f0579359fe5"
    ),
    ("fanout_4x3", "com.p.S#go", "com.p.S#z/0"): (
        "68c77e5973a02ecd63cea169eb4e58c88b867396b6470d8a695f44ebf38debd9"
    ),
    ("fanout_4x3", "com.p.C1#a/0", "com.p.S#z/0"): (
        "0ef5e6c8bd15b02cf278d3eb424e885cc30db804fd3bc8deddd64fb0a7add1ae"
    ),
    ("f2", "com.q.S#go/0", "com.q.S#t/0"): (
        "d874c600600ce9809560d6872ff32918f79395fe089828aed417fc5c552964c2"
    ),
    ("f2", "com.q.S#go/0", "com.q.A#a/0"): (
        "7a48db47d35a1f25e601449dbb13e3c921680859b1e742891e750cdb9fa9bb96"
    ),
    ("f2", "com.q.S#go/0", "com.q.B#b/0"): (
        "6abbbffdc43c244730bffc0fc522c0edb72c7cec4472e8a7a38e08b1be938f9e"
    ),
    ("f2", "com.q.B#b/0", "com.q.S#t/0"): (
        "022fa924d6f3c765b3f3f98c5e541469c3434f311ce1e26aa79d0955662edf03"
    ),
}


def _edge_row(edge: CallPathEdge) -> list[object]:
    return [edge.caller, edge.callee, edge.caller_path, edge.line, edge.resolution, edge.scope]


def _rows(loaded: LoadedIndex, source: str, target: str) -> list[dict[str, object]]:
    """把 CallPathTrace **全部**可观测字段序列化：路径的节点序与每条边的六元组、gap 六元组、
    coverage、reason_codes——只哈希节点序会让「统一改所有边的 line」这类语义变化逃过指纹。"""
    rows: list[dict[str, object]] = []
    for lim in _GRID:
        trace = trace_callpath(loaded, source, target, limits=CallPathLimits(**lim))  # type: ignore[arg-type]
        rows.append(
            {
                "limits": lim,
                "paths": [
                    {"nodes": list(p.nodes), "edges": [_edge_row(e) for e in p.edges]}
                    for p in trace.paths
                ],
                "gaps": [_edge_row(g) for g in trace.gaps],
                "coverage": trace.coverage,
                "reasons": list(trace.reason_codes),
            }
        )
    return rows


def _fingerprint(rows: list[dict[str, object]]) -> str:
    canon = json.dumps(rows, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 1. oracle 等价（真索引路径）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(_FIXTURES))
def test_outputs_match_master_oracle(tmp_path: Path, name: str) -> None:
    """夹具 × 端点对 × 2112 组限额的完整 CallPathTrace 序列化与 master 实测指纹逐字节一致。"""
    loaded = _build_single_tree_index(tmp_path / name, _FIXTURES[name])
    pairs = [(s, t) for (n, s, t) in _ORACLE_SHA256 if n == name]
    assert pairs, "每个夹具至少一组端点"
    for source, target in pairs:
        got = _fingerprint(_rows(loaded, source, target))
        assert got == _ORACLE_SHA256[(name, source, target)], (name, source, target)


def test_grid_covers_zero_and_default_limits() -> None:
    """网格本身的覆盖面锁：0 值角例与默认值都在（否则 oracle 等价只是看起来全面）。"""
    assert any(g["max_visited"] == 0 and g["max_paths"] == 0 for g in _GRID), (
        "必须含 max_visited=0 且 max_paths=0 的角例"
    )
    assert {
        "max_visited": 100_000,
        "max_paths": 8,
        "max_depth": 16,
        "max_fanout": None,
        "max_gaps": 64,
    } in _GRID, "必须含默认限额"
    assert any(g["max_fanout"] == 0 for g in _GRID), "必须含 max_fanout=0（只登记 reason 不展开）"
    assert len(_GRID) == 2112


def test_corner_reasons_are_readable(tmp_path: Path) -> None:
    """指纹之外的可读角例（与 oracle 同源，便于人读）：

    (a) max_visited=0 且 max_paths=0 且 starts 非空 → {paths_limited, visited_limited}
        （循环头先查 paths 再查 visited，两条都到）；
    (b) 第 max_visited 次出队恰是终点命中且令 found==max_paths、且仍有未出队项 →
        同样 {paths_limited, visited_limited}，路径照常返回。
    """
    loaded = _build_single_tree_index(tmp_path / "f2", _F2)
    source, target = "com.q.S#go/0", "com.q.S#t/0"
    a = trace_callpath(loaded, source, target, limits=CallPathLimits(max_visited=0, max_paths=0))
    assert a.paths == () and a.gaps == ()
    assert a.reason_codes == ("paths_limited", "visited_limited")
    b = trace_callpath(
        loaded, source, target, limits=CallPathLimits(max_visited=5, max_paths=1, max_depth=2)
    )
    assert [p.nodes for p in b.paths] == [("com.q.S#go/0", "com.q.A#a/0", "com.q.S#t/0")]
    assert b.reason_codes == ("paths_limited", "visited_limited")


# ---------------------------------------------------------------------------
# 2. 参考实现对等：内嵌 master 4d86455 的 BFS 原文（仅改名），伪造索引 + 随机 fuzz 逐例比较
# ---------------------------------------------------------------------------

_DIGEST = "0" * 64


def _forge_index(
    classes: Mapping[str, Mapping[str, list[tuple[str, int, str, str]]]],
    paths: Mapping[str, str] | None = None,
) -> LoadedIndex:
    """直接伪造 LoadedIndex（不经 store 校验）：{cls: {"name/arity": [(callee, line, qualifier, scope)]}}。"""
    out: list[dict[str, object]] = []
    for cls, methods in classes.items():
        ms: list[dict[str, object]] = []
        for ident, calls in methods.items():
            mn, ar = ident.split("/")
            ms.append(
                {
                    "name": mn,
                    "arity": int(ar),
                    "start_line": 1,
                    "end_line": 2,
                    "body_digest": _DIGEST,
                    "calls": [
                        {"callee": c, "line": ln, "qualifier": q, "scope": s}
                        for c, ln, q, s in calls
                    ],
                }
            )
        out.append(
            {
                "name": cls,
                "path": (paths or {}).get(cls, cls.replace(".", "/") + ".java"),
                "methods": ms,
            }
        )
    shard = {"structure": {"classes": out}}
    return LoadedIndex(
        manifest=None,  # type: ignore[arg-type]
        shard_locators=("s0",),
        coverage="complete",
        shards=(shard,),
    )


def _master_trace_callpath(
    index: LoadedIndex,
    source: str,
    target: str,
    *,
    limits: CallPathLimits = CallPathLimits(),
) -> CallPathTrace:
    """master 4d86455 的 trace_callpath 原文（参考实现；只改函数名）。"""
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

    source_parts = _parse_endpoint(source)
    target_parts = _parse_endpoint(target)
    if source_parts is None or target_parts is None or source == target:
        return result(reasons=("malformed_query",))
    methods, by_name = _index_methods(index)
    starts = _match_endpoints(methods, source_parts)
    ends = set(_match_endpoints(methods, target_parts))
    if not starts or not ends:
        return result(reasons=("endpoint_unmatched",))

    queue: deque[tuple[str, tuple[str, ...], tuple[CallPathEdge, ...]]] = deque(
        (node, (node,), ()) for node in starts
    )
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
        expanded: list[tuple[str, int, str, str]] = []
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

        for line, callee, _qualifier, scope in sorted(validated_calls):
            candidates = list(by_name.get(callee, ()))
            if not candidates:
                gap = CallPathEdge(
                    caller=node,
                    callee=callee,
                    caller_path=caller_path,
                    line=line,
                    resolution="not_in_index",
                    scope=scope,
                )
                key = (gap.caller, gap.callee, gap.caller_path, gap.line, gap.scope)
                if key not in gaps_by_key:
                    if len(gaps_by_key) >= limits.max_gaps:
                        reasons.add("gaps_limited")
                    else:
                        gaps_by_key[key] = gap
                continue
            resolution = "name_unique" if len(candidates) == 1 else "ambiguous"
            if limits.max_fanout is not None and len(candidates) > limits.max_fanout:
                candidates = candidates[: limits.max_fanout]
                reasons.add("fanout_limited")
            for candidate in candidates:
                expanded.append((candidate, line, resolution, scope))
        for candidate, line, resolution, scope in sorted(
            expanded, key=lambda e: (e[0], e[1], _SCOPE_RANK[e[3]])
        ):
            if candidate in nodes:
                continue
            edge = CallPathEdge(
                caller=node,
                callee=candidate,
                caller_path=caller_path,
                line=line,
                resolution=resolution,
                scope=scope,
            )
            queue.append((candidate, (*nodes, candidate), (*edges, edge)))
    if visited >= limits.max_visited:
        reasons.add("visited_limited")
    found.sort(key=lambda path: (len(path.nodes), path.nodes))
    ordered_gaps = tuple(gaps_by_key[key] for key in sorted(gaps_by_key))
    return result(tuple(found), ordered_gaps, tuple(sorted(reasons)))


def _outcome(
    fn: object, index: LoadedIndex, source: str, target: str, limits: CallPathLimits
) -> tuple[str, object]:
    """把「正常返回」与「结构化异常」折成可比较的值。"""
    assert callable(fn)
    try:
        return ("ok", fn(index, source, target, limits=limits))
    except JadxIndexError as exc:
        return ("raise", (exc.code, str(exc)))


def _same_as_master(index: LoadedIndex, source: str, target: str, limits: CallPathLimits) -> None:
    got = _outcome(trace_callpath, index, source, target, limits)
    want = _outcome(_master_trace_callpath, index, source, target, limits)
    assert got == want, (source, target, limits, got, want)


_CALL = ("", "method")


def test_counterexample_nsmallest_truncation_must_count_as_dropped() -> None:
    """对抗复核反例 1：a→{b,c}，目标 b，max_visited=2、max_paths=1。

    master：第 2 次出队命中 b、found==max_paths，此时队列仍有 c → 循环头 paths_limited +
    后置 visited_limited。预算版若只按「入列前检查」计 dropped，截断发生在选取阶段、计数恒 0，
    paths_limited 会丢——必须按「幸存候选 − 剩余预算」计。
    """
    idx = _forge_index({"X": {"a/0": [("b", 1, *_CALL), ("c", 2, *_CALL)], "b/0": [], "c/0": []}})
    lim = CallPathLimits(max_visited=2, max_paths=1)
    _same_as_master(idx, "X#a/0", "X#b/0", lim)
    assert trace_callpath(idx, "X#a/0", "X#b/0", limits=lim).reason_codes == (
        "paths_limited",
        "visited_limited",
    )


def test_counterexample_zero_remaining_still_counts_survivors() -> None:
    """对抗复核反例 2：a→{b,e}，b→c，目标 e，max_visited=3、max_paths=1。

    出队 b 时预算已耗尽，但 master 仍会把 c 入列；预算版 remaining==0 也必须过滤并计数幸存
    候选，否则 paths_limited 丢失。
    """
    idx = _forge_index(
        {
            "X": {
                "a/0": [("b", 1, *_CALL), ("e", 2, *_CALL)],
                "b/0": [("c", 1, *_CALL)],
                "c/0": [],
                "e/0": [],
            }
        }
    )
    lim = CallPathLimits(max_visited=3, max_paths=1)
    _same_as_master(idx, "X#a/0", "X#e/0", lim)
    assert trace_callpath(idx, "X#a/0", "X#e/0", limits=lim).reason_codes == (
        "paths_limited",
        "visited_limited",
    )


def test_cycle_filtered_candidates_do_not_fake_paths_limited() -> None:
    """环过滤：a→{b,e}，b→a，目标 e，max_visited=3、max_paths=1。

    出队 b 时唯一候选 a 已在路径上被过滤 → master 不入列 → 只有 visited_limited。
    预算版不得把「有候选」误当「有溢出」而补 paths_limited（只数幸存者）。
    """
    idx = _forge_index(
        {"X": {"a/0": [("b", 1, *_CALL), ("e", 2, *_CALL)], "b/0": [("a", 1, *_CALL)], "e/0": []}}
    )
    lim = CallPathLimits(max_visited=3, max_paths=1)
    _same_as_master(idx, "X#a/0", "X#e/0", lim)
    assert trace_callpath(idx, "X#a/0", "X#e/0", limits=lim).reason_codes == ("visited_limited",)


def test_malformed_caller_path_still_raises_when_budget_exhausted() -> None:
    """异常面：master 对**每个**幸存候选都构造 CallPathEdge（校验 caller_path）；预算版不再为
    越界项构造边，但必须保留同一道 fail-closed——伪造索引里 Q 的 path 畸形、Q#b 出队时预算已尽、
    仍有幸存候选 → 两边都要抛 JadxIndexError（不得静默返回 visited_limited）。
    """
    idx = _forge_index(
        {
            "P": {"a/0": [("b", 1, *_CALL)]},
            "Q": {"b/0": [("c", 1, *_CALL)]},
            "R": {"c/0": []},
        },
        paths={"Q": "/abs/Q.java"},
    )
    lim = CallPathLimits(max_visited=2, max_paths=8)
    _same_as_master(idx, "P#a/0", "R#c/0", lim)
    with pytest.raises(JadxIndexError):
        trace_callpath(idx, "P#a/0", "R#c/0", limits=lim)


@pytest.mark.parametrize(
    ("limits", "expected"),
    [
        (CallPathLimits(max_visited=0, max_paths=0), ("paths_limited", "visited_limited")),
        (CallPathLimits(max_visited=0, max_paths=1), ("visited_limited",)),
        (CallPathLimits(max_visited=5, max_paths=0), ("paths_limited",)),
    ],
)
def test_zero_limit_reason_combinations(limits: CallPathLimits, expected: tuple[str, ...]) -> None:
    idx = _forge_index({"X": {"a/0": [("b", 1, *_CALL)], "b/0": []}})
    _same_as_master(idx, "X#a/0", "X#b/0", limits)
    assert trace_callpath(idx, "X#a/0", "X#b/0", limits=limits).reason_codes == expected


def test_many_starts_truncation_triggers_paths_limited_via_dropped() -> None:
    """省 arity 起点匹配 3 个重载、max_visited=1、max_paths=0：starts 截断产生的 dropped 也要让
    paths_limited 出现（master 循环头在队列非空时先查 paths）。"""
    idx = _forge_index(
        {
            "X": {
                "go/0": [("t", 1, *_CALL)],
                "go/1": [("t", 1, *_CALL)],
                "go/2": [("t", 1, *_CALL)],
                "t/0": [],
            }
        }
    )
    lim = CallPathLimits(max_visited=1, max_paths=0)
    _same_as_master(idx, "X#go", "X#t/0", lim)
    assert trace_callpath(idx, "X#go", "X#t/0", limits=lim).reason_codes == ("paths_limited",)


def test_exact_exhaustion_without_drop_does_not_fake_paths_limited() -> None:
    """dropped==0 但 visited==max_visited 且 found>=max_paths（队列恰好耗尽）→ 仅 visited_limited。"""
    idx = _forge_index({"X": {"a/0": [("b", 1, *_CALL)], "b/0": []}})
    lim = CallPathLimits(max_visited=2, max_paths=1)
    _same_as_master(idx, "X#a/0", "X#b/0", lim)
    assert trace_callpath(idx, "X#a/0", "X#b/0", limits=lim).reason_codes == ("visited_limited",)


def test_random_small_graphs_match_master_reference() -> None:
    """随机小图 × 随机限额（含 max_fanout/max_gaps/省 arity 端点/四种 scope/重复调用点），
    逐例比较新实现与内嵌 master 参考实现的返回值或异常。"""
    rng = random.Random(20260821)
    scopes = ["method", "nested_type", "lambda", "unknown"]
    quals = ["", "this", "<expr>", "x"]
    compared = 0
    for _trial in range(1500):
        ncls = rng.randint(1, 3)
        names = ["m%d" % i for i in range(rng.randint(2, 5))]
        classes: dict[str, dict[str, list[tuple[str, int, str, str]]]] = {}
        for ci in range(ncls):
            ms: dict[str, list[tuple[str, int, str, str]]] = {}
            for n in names:
                if rng.random() < 0.7:
                    # 少量畸形调用点（line=0 / 非法 scope）：两边都必须在**同一个**出队节点上
                    # 抛 JadxIndexError（未出队节点的 calls 两边都不校验）。
                    calls = [
                        (
                            rng.choice(names + ["u1", "u2"]),
                            rng.randint(1, 4) if rng.random() < 0.95 else 0,
                            rng.choice(quals),
                            rng.choice(scopes) if rng.random() < 0.97 else "bad_scope",
                        )
                        for _ in range(rng.randint(0, 4))
                    ]
                    ms[f"{n}/{rng.choice([0, 1])}"] = calls
            if ms:
                classes[f"c{ci}.K"] = ms
        idx = _forge_index(classes)
        methods, _by_name = _index_methods(idx)
        idents = sorted(methods)
        if len(idents) < 2:
            continue
        src = rng.choice(idents)
        dst = rng.choice(idents)
        if rng.random() < 0.3:
            src = src.rsplit("/", 1)[0]  # 省 arity 起点
        lim = CallPathLimits(
            max_depth=rng.choice([0, 1, 2, 3, 16]),
            max_paths=rng.choice([0, 1, 2, 8]),
            max_visited=rng.choice([0, 1, 2, 3, 4, 6, 9, 100_000]),
            max_fanout=rng.choice([None, 0, 1, 2]),
            max_gaps=rng.choice([0, 1, 64]),
        )
        _same_as_master(idx, src, dst, lim)
        compared += 1
    assert compared > 1000


# ---------------------------------------------------------------------------
# 3. 资源边界：队列峰值 ≤ max_visited（无修复即红）
# ---------------------------------------------------------------------------


class _RecordingDeque(collections.deque):  # type: ignore[type-arg]
    peak = 0

    def append(self, item: object) -> None:
        super().append(item)
        _RecordingDeque.peak = max(_RecordingDeque.peak, len(self))


def test_queue_peak_never_exceeds_max_visited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★无修复即红：BFS 队列长度峰值必须 ≤ max_visited。

    夹具 10 候选 × 10 调用点 × 深度 3；master 上 max_visited=10 时队列峰值 820、
    max_visited=1000 时 58,503——入列量与出队帽脱钩，真实样本（256 调用点 × 3038 候选）
    单节点即可入列数十万项。
    """
    monkeypatch.setattr(jcp, "deque", _RecordingDeque)
    loaded = _build_single_tree_index(tmp_path, _fanout_files(10, 10))
    for max_visited in (0, 1, 10, 1000):
        _RecordingDeque.peak = 0
        trace = trace_callpath(
            loaded,
            "com.p.S#go/0",
            "com.p.S#z/0",
            limits=CallPathLimits(max_visited=max_visited, max_depth=3),
        )
        assert _RecordingDeque.peak <= max_visited, (
            f"max_visited={max_visited}: 队列峰值 {_RecordingDeque.peak} 超出出队帽"
        )
        if max_visited >= 1000:
            assert trace.paths, "预算内仍须找到路径（预算不是召回削减）"


def test_starts_respect_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """省 arity 端点可匹配多个起点；起点入列同样受预算约束（队列峰值 ≤ max_visited）。"""
    monkeypatch.setattr(jcp, "deque", _RecordingDeque)
    files = {
        "com/s/M.java": (
            "package com.s;\n\npublic class M {\n"
            "    void go() {\n        t();\n    }\n"
            "    void go(int a) {\n        t();\n    }\n"
            "    void go(int a, int b) {\n        t();\n    }\n"
            "    void t() {\n    }\n}\n"
        ),
    }
    loaded = _build_single_tree_index(tmp_path, files)
    _RecordingDeque.peak = 0
    trace = trace_callpath(
        loaded, "com.s.M#go", "com.s.M#t/0", limits=CallPathLimits(max_visited=1)
    )
    assert _RecordingDeque.peak <= 1
    assert trace.paths == ()
    assert "visited_limited" in trace.reason_codes


def test_expansion_work_is_bounded_by_budget_not_fanout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★CPU 边界（codex 复审 P2）：单节点展开只能拉取「剩余预算 + 1」个幸存候选加上每条候选流
    的首项（k 路归并初始化），不得随 calls × candidates 线性增长——否则预算耗尽前最后一个
    大扇出节点仍要扫完全部候选（真样本 256 × 3038 ≈ 78 万项）。

    夹具 10 候选 × 10 调用点：每个 C_i#a 有 11 条候选流（10 次 a() + 1 次 z()），master 式
    全量展开每节点产 101 项；归并式每节点 ≤ 11（流首项）+ remaining + 1。
    """
    pulled = {"n": 0}
    original = jcp._expansion_stream

    def counting_stream(*args: object, **kwargs: object) -> Iterator[tuple[str, int, str, str]]:
        for item in original(*args, **kwargs):  # type: ignore[arg-type]
            pulled["n"] += 1
            yield item

    monkeypatch.setattr(jcp, "_expansion_stream", counting_stream)
    loaded = _build_single_tree_index(tmp_path, _fanout_files(10, 10))
    for max_fanout in (None, 3):
        for max_visited in (1, 4, 10):
            pulled["n"] = 0
            trace_callpath(
                loaded,
                "com.p.S#go/0",
                "com.p.S#z/0",
                limits=CallPathLimits(max_visited=max_visited, max_depth=3, max_fanout=max_fanout),
            )
            # 每个出队节点最多 11 条流首项 + (remaining + 1) ≤ 11 + max_visited + 1。
            bound = max_visited * (11 + max_visited + 1)
            assert pulled["n"] <= bound, (
                f"max_visited={max_visited} max_fanout={max_fanout}: 拉取 {pulled['n']} > {bound}"
            )
