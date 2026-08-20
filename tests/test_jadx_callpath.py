"""P1-B trace_callpath：确定性 BFS 路径查询 + ledger 投影（阴性绝不产观察）。

先于实现编写（红态契约；导入 apkscan.core.jadx_callpath 在实现落地前收集即失败）。
行号断言基于手工数行的合成源码。设计见
docs/superpowers/specs/2026-08-16-p1b-jadx-callpath-design.md。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from apkscan.core import jadx_callpath as jcp
from apkscan.core import judgment_ledger as jl
from apkscan.core import recognition_contract as rc
from apkscan.core.jadx_callpath import (
    CallPath,
    CallPathEdge,
    CallPathLimits,
    trace_callpath,
)
from apkscan.core.jadx_index import (
    INDEX_SCHEMA_VERSION,
    DexInput,
    DexRole,
    IndexBuildResult,
    IndexBuildState,
    JadxIndexError,
    JadxIndexManifest,
    JadxIndexStore,
    Limits,
    LoadedIndex,
    build_key_material,
    derive_index_key,
    scan_java_sources,
    verify_dex_inputs,
)
from apkscan.core.jadx_index_ledger import (
    CallPathQueryResult,
    IndexQueryState,
    append_jadx_callpath_projection,
    append_jadx_query_projection,
)
from tests.recognition_fixtures import (
    FIXED_TIME,
    append_record,
    make_action_ledger,
    make_actor,
    make_authorization,
)

_OPTS = "sha256:" + "a" * 64


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _java_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


APP_JAVA = (
    "package com.a;\n"
    "\n"
    "public class App {\n"
    "    public void onCreate() {\n"
    "        Helper h = new Helper();\n"
    '        h.fetch("https://cfg.example/api");\n'
    "    }\n"
    "}\n"
)

HELPER_JAVA = (
    "package com.b;\n"
    "\n"
    "public class Helper {\n"
    "    public String fetch(String url) {\n"
    "        return Net.get(url);\n"
    "    }\n"
    "}\n"
)

NET_JAVA = (
    "package com.c;\n"
    "\n"
    "public class Net {\n"
    "    public static String get(String url) {\n"
    "        return raw(url);\n"
    "    }\n"
    "\n"
    "    private static String raw(String url) {\n"
    "        return url;\n"
    "    }\n"
    "}\n"
)


def _build_two_dex_index(tmp_path: Path) -> LoadedIndex:
    """apk_dex shard：App+Helper；extra_dex shard：Net——跨 dex 路径的地基。"""
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "classes.dex").write_bytes(b"dex-main")
    (src / "extra.dex").write_bytes(b"dex-extra")
    inputs = [
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="classes.dex",
            relative_path="classes.dex",
            declared_digest=_digest(b"dex-main"),
        ),
        DexInput(
            role=DexRole.EXTRA_DEX,
            ordinal=0,
            source_label="extra.dex",
            relative_path="extra.dex",
            declared_digest=_digest(b"dex-extra"),
        ),
    ]
    lineage = verify_dex_inputs(src, inputs)
    key = derive_index_key(lineage, "1.5.2", _OPTS)
    material = build_key_material(lineage, "1.5.2", _OPTS)
    manifest = JadxIndexManifest(
        index_key=key,
        key_material=material,
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )

    main_root = tmp_path / "out-main"
    extra_root = tmp_path / "out-extra"
    _java_tree(main_root, {"com/a/App.java": APP_JAVA, "com/b/Helper.java": HELPER_JAVA})
    _java_tree(extra_root, {"com/c/Net.java": NET_JAVA})
    by_role = {lin.role: lin for lin in lineage}
    scans = {
        by_role[DexRole.APK_DEX]: scan_java_sources(
            main_root, [], lineage=by_role[DexRole.APK_DEX], limits=Limits()
        ),
        by_role[DexRole.EXTRA_DEX]: scan_java_sources(
            extra_root, [], lineage=by_role[DexRole.EXTRA_DEX], limits=Limits()
        ),
    }
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(src, manifest, scan=scans)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.BUILT
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    return loaded


def _build_single_tree_index(
    tmp_path: Path, files: dict[str, str], *, limits: Limits = Limits()
) -> LoadedIndex:
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "classes.dex").write_bytes(b"dex-0")
    inputs = [
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="classes.dex",
            relative_path="classes.dex",
            declared_digest=_digest(b"dex-0"),
        )
    ]
    lineage = verify_dex_inputs(src, inputs)
    key = derive_index_key(lineage, "1.5.2", _OPTS)
    manifest = JadxIndexManifest(
        index_key=key,
        key_material=build_key_material(lineage, "1.5.2", _OPTS),
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )
    out = tmp_path / "out"
    _java_tree(out, files)
    scan = scan_java_sources(out, [], lineage=lineage[0], limits=limits)
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(src, manifest, scan=scan)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.BUILT
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    return loaded


# ---------------------------------------------------------------------------
# trace_callpath：查询语义
# ---------------------------------------------------------------------------


def test_trace_multihop_path_across_dex_shards(tmp_path: Path) -> None:
    """★核心断言：跨 shard（apk_dex → extra_dex）的三跳路径，确定性且带边定位。"""
    loaded = _build_two_dex_index(tmp_path)
    trace = trace_callpath(loaded, "com.a.App#onCreate/0", "com.c.Net#raw/1")
    paths = trace.paths
    assert len(paths) == 1
    assert trace.gaps == ()
    (path,) = paths
    assert path.nodes == (
        "com.a.App#onCreate/0",
        "com.b.Helper#fetch/1",
        "com.c.Net#get/1",
        "com.c.Net#raw/1",
    )
    assert len(path.edges) == 3
    assert [(e.caller_path, e.line) for e in path.edges] == [
        ("com/a/App.java", 6),
        ("com/b/Helper.java", 5),
        ("com/c/Net.java", 5),
    ]
    assert all(e.resolution == "name_unique" for e in path.edges)


def test_generic_param_endpoint_resolves_at_true_arity(tmp_path: Path) -> None:
    """★P1-A 真入口锁：泛型参数方法的端点按真实 arity 可达。

    旧的 `split(",")` 计数把 `Map<String, String> m` 记成 2 个参数，方法身份变成
    `handle/2`，于是按真实 arity 查 `handle/1` 得空——空结果在本模块语义里是
    「未观察到」而非「不可达」，假阴性因此不会被任何现有断言揭穿。这条用例把
    修复钉在 trace_callpath 真入口上：单测 `_declared_arity` 测不到这层接线。
    """
    loaded = _build_single_tree_index(
        tmp_path,
        {
            "com/a/A.java": (
                "package com.a;\n"
                "public class A {\n"
                "    public void start() {\n"
                "        handle(cfg);\n"
                "    }\n"
                "    public void handle(Map<String, String> m) {\n"
                "    }\n"
                "}\n"
            )
        },
    )
    paths = trace_callpath(loaded, "com.a.A#start/0", "com.a.A#handle/1").paths
    assert len(paths) == 1
    (path,) = paths
    assert path.nodes == ("com.a.A#start/0", "com.a.A#handle/1")
    assert [(e.caller_path, e.line) for e in path.edges] == [("com/a/A.java", 4)]
    # 旧 buggy 计数下该方法会被登记成 arity=2；修复后这个端点必须不存在。
    assert trace_callpath(loaded, "com.a.A#start/0", "com.a.A#handle/2").paths == ()


def test_trace_accepts_arityless_endpoint_form(tmp_path: Path) -> None:
    loaded = _build_two_dex_index(tmp_path)
    paths = trace_callpath(loaded, "com.a.App#onCreate", "com.c.Net#get/1").paths
    assert len(paths) == 1
    assert paths[0].nodes[0] == "com.a.App#onCreate/0"
    assert paths[0].nodes[-1] == "com.c.Net#get/1"


def test_trace_negative_and_malformed_inputs_return_empty(tmp_path: Path) -> None:
    loaded = _build_two_dex_index(tmp_path)
    # 逆向不可达（静态图无 raw→onCreate 边）。
    assert trace_callpath(loaded, "com.c.Net#raw/1", "com.a.App#onCreate/0").paths == ()
    # 未知端点 / 空串 / 超长 / source==target。
    assert trace_callpath(loaded, "com.zz.Gone#x/0", "com.c.Net#raw/1").paths == ()
    assert trace_callpath(loaded, "", "com.c.Net#raw/1").paths == ()
    assert trace_callpath(loaded, "com.a.App#onCreate/0", "").paths == ()
    assert trace_callpath(loaded, "A" * 5000, "com.c.Net#raw/1").paths == ()
    assert trace_callpath(loaded, "com.c.Net#raw/1", "com.c.Net#raw/1").paths == ()


def test_trace_respects_depth_limit(tmp_path: Path) -> None:
    loaded = _build_two_dex_index(tmp_path)
    limited = trace_callpath(
        loaded,
        "com.a.App#onCreate/0",
        "com.c.Net#raw/1",
        limits=CallPathLimits(max_depth=2),
    )
    assert limited.paths == ()
    assert "depth_limited" in limited.reason_codes


def test_trace_marks_ambiguous_name_resolution(tmp_path: Path) -> None:
    """同名方法多候选 → 每条候选边都是一条路径，resolution=ambiguous，序确定。"""
    files = {
        "com/p/A.java": (
            "package com.p;\n"
            "\n"
            "public class A {\n"
            "    void parse(String s) {\n"
            "    }\n"
            "}\n"
        ),
        "com/p/B.java": (
            "package com.p;\n"
            "\n"
            "public class B {\n"
            "    void parse(String s) {\n"
            "    }\n"
            "}\n"
        ),
        "com/p/C.java": (
            "package com.p;\n"
            "\n"
            "public class C {\n"
            "    void go() {\n"
            '        parse("x");\n'
            "    }\n"
            "}\n"
        ),
    }
    loaded = _build_single_tree_index(tmp_path, files)
    to_a = trace_callpath(loaded, "com.p.C#go/0", "com.p.A#parse/1")
    to_b = trace_callpath(loaded, "com.p.C#go/0", "com.p.B#parse/1")
    assert len(to_a.paths) == 1 and len(to_b.paths) == 1
    assert to_a.paths[0].edges[0].resolution == "ambiguous"
    assert to_b.paths[0].edges[0].resolution == "ambiguous"
    assert (
        to_a.paths[0].edges[0].line == 5
        and to_a.paths[0].edges[0].caller_path == "com/p/C.java"
    )


def test_trace_terminates_on_cycles(tmp_path: Path) -> None:
    files = {
        "com/q/R.java": (
            "package com.q;\n"
            "\n"
            "public class R {\n"
            "    void a() {\n"
            "        b();\n"
            "    }\n"
            "\n"
            "    void b() {\n"
            "        a();\n"
            "        c();\n"
            "    }\n"
            "\n"
            "    void c() {\n"
            "    }\n"
            "}\n"
        ),
    }
    loaded = _build_single_tree_index(tmp_path, files)
    paths = trace_callpath(loaded, "com.q.R#a/0", "com.q.R#c/0").paths
    assert len(paths) >= 1
    assert paths[0].nodes == ("com.q.R#a/0", "com.q.R#b/0", "com.q.R#c/0")


def test_trace_fail_closed_on_malformed_structure(tmp_path: Path) -> None:
    """★伪造 shard 结构（call 缺 line）→ 当场揭穿，不许静默跳过。"""
    loaded = _build_two_dex_index(tmp_path)
    bad_shard = dict(loaded.shards[0])
    bad_shard["structure"] = {
        "classes": [
            {
                "name": "com.x.Bad",
                "path": "com/a/App.java",
                "methods": [
                    {
                        "name": "m",
                        "arity": 0,
                        "start_line": 1,
                        "end_line": 2,
                        "body_digest": _digest(b"m"),
                        "calls": [{"callee": "n"}],  # 缺 line
                    }
                ],
            }
        ]
    }
    forged = LoadedIndex(
        manifest=loaded.manifest,
        shard_locators=loaded.shard_locators,
        coverage=loaded.coverage,
        shards=(bad_shard, *loaded.shards[1:]),
    )
    with pytest.raises(JadxIndexError) as exc:
        trace_callpath(forged, "com.x.Bad#m/0", "com.c.Net#raw/1")
    assert exc.value.code == "malformed"


# ---------------------------------------------------------------------------
# CallPath / CallPathEdge 契约
# ---------------------------------------------------------------------------


def _edge(**overrides: object) -> CallPathEdge:
    base: dict[str, object] = {
        "caller": "com.a.App#onCreate/0",
        "callee": "com.b.Helper#fetch/1",
        "caller_path": "com/a/App.java",
        "line": 6,
        "resolution": "name_unique",
        "scope": "method",
    }
    return CallPathEdge(**{**base, **overrides})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"line": 0},
        {"resolution": "maybe"},
        {"resolution": "resolved"},
        {"resolution": "unresolved_dynamic"},
        {"scope": "weird"},
        {"caller_path": "/abs/App.java"},
        {"caller": ""},
    ],
)
def test_edge_validation_rejects_bad_fields(overrides: dict) -> None:
    with pytest.raises(JadxIndexError):
        _edge(**overrides)


def test_callpath_requires_matching_nodes_and_edges() -> None:
    edge = _edge()
    with pytest.raises(JadxIndexError):
        CallPath(nodes=("com.a.App#onCreate/0",), edges=())
    with pytest.raises(JadxIndexError):
        CallPath(
            nodes=("com.a.App#onCreate/0", "com.b.Helper#fetch/1"),
            edges=(edge, edge),
        )


# ---------------------------------------------------------------------------
# ledger 投影：callpath 版状态矩阵与事件链合法性
# ---------------------------------------------------------------------------


def _authorized_ledger(action_type: str) -> tuple[tuple[jl.LedgerEvent, ...], str]:
    events = make_action_ledger(action_type=action_type)
    action = events[-1].payload
    assert isinstance(action, rc.NextAction)
    events = append_record(
        events,
        jl.EventType.ACTION_AUTHORIZED,
        make_authorization(action_id=action.action_id),
    )
    return events, action.action_id


def _path() -> CallPath:
    return CallPath(
        nodes=("com.a.App#onCreate/0", "com.b.Helper#fetch/1"),
        edges=(_edge(),),
    )


def _result(
    state: IndexQueryState,
    *,
    coverage: str | None = "complete",
    paths: tuple[CallPath, ...] = (),
) -> CallPathQueryResult:
    return CallPathQueryResult(
        state=state,
        coverage=coverage,
        paths=paths,
        manifest_digest="sha256:" + "a" * 64,
        shard_digests=("sha256:" + "b" * 64,),
        reason_codes=("test",),
    )


def _observation_count(events: tuple[jl.LedgerEvent, ...]) -> int:
    return sum(1 for e in events if e.event_type is jl.EventType.OBSERVATION_ADDED)


def test_callpath_hit_projection_appends_path_observation() -> None:
    events, action_id = _authorized_ledger("jadx-callpath-query")
    before_obs = _observation_count(events)
    out = append_jadx_callpath_projection(
        events,
        action_id=action_id,
        result=_result(IndexQueryState.HIT, paths=(_path(),)),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    projection = jl.replay(out)
    outcome = projection.outcomes[-1]
    assert outcome.status is rc.OutcomeStatus.COMPLETE
    (cov,) = outcome.coverage_assertions
    assert cov.source is rc.CoverageSource.JADX_INDEX
    assert cov.status is rc.CoverageStatus.COMPLETE
    assert _observation_count(out) == before_obs + 1

    # replay 投影的 observations 不保证追加序——按类型过滤，不取 [-1]。
    (obs,) = [o for o in projection.observations if o.observation_type == "jadx_callpath"]
    # OBSERVED 而非 DERIVED：契约规定 DERIVED 必须携带非空 input_observation_ids
    # （推导可追溯），P1-B 不为单条边落独立观察——设计据此修正。
    assert obs.strength is rc.ObservationStrength.OBSERVED
    assert obs.input_observation_ids == ()
    assert obs.ownership is rc.OwnershipValue.UNKNOWN
    assert obs.origin_outcome_id == outcome.outcome_id
    # 观察值是路径的 digest 形态 token，绝不携带原始标识符序列。
    assert obs.value.kind is rc.ObservationValueKind.CATEGORICAL
    categorical = obs.value.categorical
    assert categorical is not None
    assert categorical.startswith("sha256.") and len(categorical) == 71
    # 每条边一个 LINE_RANGE 定位符。
    assert len(obs.source_refs) == len(_path().edges)
    locator = obs.source_refs[0]
    assert locator.kind is rc.LocatorKind.LINE_RANGE
    assert locator.value == "com/a/App.java" and locator.start == 6 and locator.end == 6
    # anchor 的 schema 引用跟随常量，不是写死的字面量。
    assert outcome.output_anchors
    assert all(a.schema_version_ref == INDEX_SCHEMA_VERSION for a in outcome.output_anchors)


def test_callpath_two_paths_two_distinct_observations() -> None:
    events, action_id = _authorized_ledger("jadx-callpath-query")
    other = CallPath(
        nodes=("com.a.App#onCreate/0", "com.c.Net#get/1"),
        edges=(_edge(callee="com.c.Net#get/1"),),
    )
    out = append_jadx_callpath_projection(
        events,
        action_id=action_id,
        result=_result(IndexQueryState.HIT, paths=(_path(), other)),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    observations = [
        o for o in jl.replay(out).observations if o.observation_type == "jadx_callpath"
    ]
    assert len(observations) == 2
    values = {obs.value.categorical for obs in observations}
    assert len(values) == 2  # 不同路径 → 不同 digest


def _project_single_path_categorical(resolution: str, scope: str) -> str | None:
    """投影一条单边路径，返回其 jadx_callpath 观察的 categorical digest。"""
    events, action_id = _authorized_ledger("jadx-callpath-query")
    path = CallPath(
        nodes=("com.a.App#onCreate/0", "com.b.Helper#fetch/1"),
        edges=(_edge(resolution=resolution, scope=scope),),
    )
    out = append_jadx_callpath_projection(
        events,
        action_id=action_id,
        result=_result(IndexQueryState.HIT, paths=(path,)),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    (obs,) = [
        o for o in jl.replay(out).observations if o.observation_type == "jadx_callpath"
    ]
    return obs.value.categorical


def test_callpath_observation_value_distinguishes_resolution_and_scope() -> None:
    """★红态契约（P1-2b：诚实命名不得在账本层被丢弃）：观察载荷现状只编
    nodes + 逐边 (caller_path, line)，resolution 与 scope 在 ledger 一层全部
    丢失——name_unique 的直接边链与 ambiguous 的嵌套体候选链会入账成**同一个**
    categorical digest、同为 OBSERVED。消费方从账本上永远无法区分「观察到的
    调用表达式链」与「启发式候选链」，三态诚实化在账本层归零。

    契约只钉可区分性：仅 resolution 不同、或仅 scope 不同的两条路径，观察值
    必须不同。载荷具体形状（逐边编入 resolution/scope）由实现规格约定；
    OBSERVED 强度维持既有论证（源码注释）——前提正是载荷如实携带判据状态。"""
    base = _project_single_path_categorical("name_unique", "method")
    assert base is not None
    assert base != _project_single_path_categorical("ambiguous", "method"), (
        "resolution 未进观察载荷：候选链与唯一名链在账本上不可区分"
    )
    assert base != _project_single_path_categorical("name_unique", "nested_type"), (
        "scope 未进观察载荷：嵌套体边与直接边在账本上不可区分"
    )


def test_callpath_empty_result_never_observes() -> None:
    """★「没找到静态路径」不是「不可达」——HIT 空结果也绝不产观察。"""
    events, action_id = _authorized_ledger("jadx-callpath-query")
    before_obs = _observation_count(events)
    out = append_jadx_callpath_projection(
        events,
        action_id=action_id,
        result=_result(IndexQueryState.HIT, paths=()),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    assert _observation_count(out) == before_obs
    assert jl.replay(out).outcomes[-1].status is rc.OutcomeStatus.COMPLETE


@pytest.mark.parametrize(
    "state",
    [
        IndexQueryState.MISS,
        IndexQueryState.CORRUPT,
        IndexQueryState.DRIFT,
        IndexQueryState.TIMEOUT_EMPTY,
        IndexQueryState.FAILED,
        IndexQueryState.UNAVAILABLE,
    ],
)
def test_callpath_negative_states_with_paths_never_observe(state: IndexQueryState) -> None:
    events, action_id = _authorized_ledger("jadx-callpath-query")
    before_obs = _observation_count(events)
    out = append_jadx_callpath_projection(
        events,
        action_id=action_id,
        result=_result(state, coverage=None, paths=(_path(),)),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    assert _observation_count(out) == before_obs
    assert jl.replay(out).outcomes[-1].status is rc.OutcomeStatus.FAILED


def test_callpath_wrong_action_type_rejected_both_directions() -> None:
    """usage 动作不能投 callpath，callpath 动作也不能投 usage——双向回归锁。"""
    usage_events, usage_action = _authorized_ledger("jadx-usage-query")
    with pytest.raises(JadxIndexError) as exc:
        append_jadx_callpath_projection(
            usage_events,
            action_id=usage_action,
            result=_result(IndexQueryState.HIT, paths=(_path(),)),
            actor=make_actor(),
            occurred_at=FIXED_TIME,
        )
    assert exc.value.code == "wrong_action_type"

    callpath_events, callpath_action = _authorized_ledger("jadx-callpath-query")
    from apkscan.core.jadx_index_ledger import IndexQueryResult

    with pytest.raises(JadxIndexError) as exc:
        append_jadx_query_projection(
            callpath_events,
            action_id=callpath_action,
            result=IndexQueryResult(
                state=IndexQueryState.HIT,
                coverage="complete",
                hits=(),
            ),
            actor=make_actor(),
            occurred_at=FIXED_TIME,
        )
    assert exc.value.code == "wrong_action_type"


def test_callpath_detached_and_unauthorized_rejected() -> None:
    events, _ = _authorized_ledger("jadx-callpath-query")
    with pytest.raises(JadxIndexError) as exc:
        append_jadx_callpath_projection(
            events,
            action_id="action-sha256:" + "9" * 64,
            result=_result(IndexQueryState.HIT, paths=(_path(),)),
            actor=make_actor(),
            occurred_at=FIXED_TIME,
        )
    assert exc.value.code == "detached_action"

    proposed_only = make_action_ledger(action_type="jadx-callpath-query")
    action = proposed_only[-1].payload
    assert isinstance(action, rc.NextAction)
    with pytest.raises(JadxIndexError) as exc:
        append_jadx_callpath_projection(
            proposed_only,
            action_id=action.action_id,
            result=_result(IndexQueryState.HIT, paths=(_path(),)),
            actor=make_actor(),
            occurred_at=FIXED_TIME,
        )
    assert exc.value.code == "action_not_authorized"


def test_callpath_result_validates_paths_tuple() -> None:
    with pytest.raises(JadxIndexError) as exc:
        CallPathQueryResult(
            state=IndexQueryState.HIT,
            coverage="complete",
            paths=("not-a-path",),  # type: ignore[arg-type]
        )
    assert exc.value.code == "invalid_query_paths"


# ---------------------------------------------------------------------------
# codex 复审补锁：跨 shard 重复 id、shard 序无关、零上限、同行重复调用、重复 digest 锚
# ---------------------------------------------------------------------------


def _build_two_dex_index_with(
    tmp_path: Path, files_main: dict[str, str], files_extra: dict[str, str]
) -> LoadedIndex:
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "classes.dex").write_bytes(b"dex-main")
    (src / "extra.dex").write_bytes(b"dex-extra")
    inputs = [
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="classes.dex",
            relative_path="classes.dex",
            declared_digest=_digest(b"dex-main"),
        ),
        DexInput(
            role=DexRole.EXTRA_DEX,
            ordinal=0,
            source_label="extra.dex",
            relative_path="extra.dex",
            declared_digest=_digest(b"dex-extra"),
        ),
    ]
    lineage = verify_dex_inputs(src, inputs)
    manifest = JadxIndexManifest(
        index_key=derive_index_key(lineage, "1.5.2", _OPTS),
        key_material=build_key_material(lineage, "1.5.2", _OPTS),
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )
    main_root = tmp_path / "out-main"
    extra_root = tmp_path / "out-extra"
    _java_tree(main_root, files_main)
    _java_tree(extra_root, files_extra)
    by_role = {lin.role: lin for lin in lineage}
    scans = {
        by_role[DexRole.APK_DEX]: scan_java_sources(
            main_root, [], lineage=by_role[DexRole.APK_DEX], limits=Limits()
        ),
        by_role[DexRole.EXTRA_DEX]: scan_java_sources(
            extra_root, [], lineage=by_role[DexRole.EXTRA_DEX], limits=Limits()
        ),
    }
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(src, manifest, scan=scans)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.BUILT
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    return loaded


def test_duplicate_method_id_across_shards_merges(tmp_path: Path) -> None:
    """★schema 1.2：跨 shard 重复类（多 dex 脱壳 dump 常态）不再 fail-closed——
    同 ident 确定性合并出边（与同 shard 擦除重载同语义），路径照常可寻。"""
    loaded = _build_two_dex_index_with(
        tmp_path,
        {"com/a/App.java": APP_JAVA, "com/b/Helper.java": HELPER_JAVA},
        {"com/a/App.java": APP_JAVA},  # extra dex 重复同一类
    )
    paths = trace_callpath(
        loaded, "com.a.App#onCreate/0", "com.b.Helper#fetch/1"
    ).paths
    assert len(paths) == 1
    assert paths[0].nodes == ("com.a.App#onCreate/0", "com.b.Helper#fetch/1")


def test_cross_shard_merge_unions_out_edges(tmp_path: Path) -> None:
    """合并语义锁：两个 shard 的同 ident 各带不同出边——合并后两边都可达。

    突变敏感：实现若「后者覆盖」则 alpha 不可达，若「前者独占」则 beta 不可达。"""
    loaded = _build_two_dex_index_with(
        tmp_path,
        {
            "com/m/M.java": (
                "package com.m;\n"
                "\n"
                "public class M {\n"
                "    void run() {\n"
                "        alpha();\n"
                "    }\n"
                "}\n"
            ),
            "com/m/A.java": (
                "package com.m;\n"
                "\n"
                "public class A {\n"
                "    void alpha() {\n"
                "    }\n"
                "}\n"
            ),
        },
        {
            "com/m/M.java": (
                "package com.m;\n"
                "\n"
                "public class M {\n"
                "    void run() {\n"
                "        beta();\n"
                "    }\n"
                "}\n"
            ),
            "com/m/B.java": (
                "package com.m;\n"
                "\n"
                "public class B {\n"
                "    void beta() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    to_alpha = trace_callpath(loaded, "com.m.M#run/0", "com.m.A#alpha/0")
    to_beta = trace_callpath(loaded, "com.m.M#run/0", "com.m.B#beta/0")
    assert len(to_alpha.paths) == 1 and len(to_beta.paths) == 1


def test_duplicate_ident_merge_independent_of_shard_order(tmp_path: Path) -> None:
    """★codex 复审 P1 回归锁：重复 ident 落在不同路径时，合并输出（含
    caller_path）必须与 shard 枚举序无关——caller 文件取字典序最小的声明路径。"""
    loaded = _build_two_dex_index_with(
        tmp_path,
        {
            "com/m/M.java": (
                "package com.m;\n"
                "\n"
                "public class M {\n"
                "    void run() {\n"
                "        alpha();\n"
                "    }\n"
                "}\n"
            ),
            "com/m/A.java": (
                "package com.m;\n"
                "\n"
                "public class A {\n"
                "    void alpha() {\n"
                "    }\n"
                "}\n"
            ),
        },
        {
            # 同限定名重复类落在不同相对路径（脱壳 dump 去重后缀形态）。
            "dup/com/m/M.java": (
                "package com.m;\n"
                "\n"
                "public class M {\n"
                "    void run() {\n"
                "        beta();\n"
                "    }\n"
                "}\n"
            ),
            "com/m/B.java": (
                "package com.m;\n"
                "\n"
                "public class B {\n"
                "    void beta() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    reversed_index = LoadedIndex(
        manifest=loaded.manifest,
        shard_locators=tuple(reversed(loaded.shard_locators)),
        coverage=loaded.coverage,
        shards=tuple(reversed(loaded.shards)),
    )
    for target in ("com.m.A#alpha/0", "com.m.B#beta/0"):
        forward = trace_callpath(loaded, "com.m.M#run/0", target)
        backward = trace_callpath(reversed_index, "com.m.M#run/0", target)
        assert forward == backward and len(forward.paths) == 1
        (edge,) = forward.paths[0].edges
        assert edge.caller_path == "com/m/M.java"  # 字典序最小的声明路径


def test_trace_results_independent_of_shard_order(tmp_path: Path) -> None:
    loaded = _build_two_dex_index(tmp_path)
    reversed_index = LoadedIndex(
        manifest=loaded.manifest,
        shard_locators=tuple(reversed(loaded.shard_locators)),
        coverage=loaded.coverage,
        shards=tuple(reversed(loaded.shards)),
    )
    forward = trace_callpath(loaded, "com.a.App#onCreate/0", "com.c.Net#raw/1")
    backward = trace_callpath(reversed_index, "com.a.App#onCreate/0", "com.c.Net#raw/1")
    assert forward == backward and len(forward.paths) == 1


def test_zero_limits_yield_empty(tmp_path: Path) -> None:
    loaded = _build_two_dex_index(tmp_path)
    source, target = "com.a.App#onCreate/0", "com.c.Net#raw/1"
    depth = trace_callpath(loaded, source, target, limits=CallPathLimits(max_depth=0))
    paths = trace_callpath(loaded, source, target, limits=CallPathLimits(max_paths=0))
    visited = trace_callpath(loaded, source, target, limits=CallPathLimits(max_visited=0))
    assert depth.paths == () and "depth_limited" in depth.reason_codes
    assert paths.paths == () and "paths_limited" in paths.reason_codes
    assert visited.paths == () and "visited_limited" in visited.reason_codes


def test_same_line_double_call_yields_single_deduped_path(tmp_path: Path) -> None:
    dup_call = (
        "package com.m;\n"
        "\n"
        "public class D {\n"
        "    void go() {\n"
        "        add(one(), one());\n"
        "    }\n"
        "\n"
        "    int one() {\n"
        "        return 1;\n"
        "    }\n"
        "\n"
        "    int add(int a, int b) {\n"
        "        return a + b;\n"
        "    }\n"
        "}\n"
    )
    loaded = _build_single_tree_index(tmp_path, {"com/m/D.java": dup_call})
    paths = trace_callpath(loaded, "com.m.D#go/0", "com.m.D#one/0").paths
    assert len(paths) == 1  # 同行两次同名调用 → 节点序列去重后只有一条路径
    assert paths[0].edges[0].resolution == "name_unique"


def test_duplicate_shard_digests_produce_distinct_anchors() -> None:
    """相同 digest 的多个 shard 锚以 logical_id 区分——不触发 canonical tuple 重复拒绝。"""
    events, action_id = _authorized_ledger("jadx-callpath-query")
    out = append_jadx_callpath_projection(
        events,
        action_id=action_id,
        result=CallPathQueryResult(
            state=IndexQueryState.HIT,
            coverage="complete",
            paths=(_path(),),
            manifest_digest="sha256:" + "a" * 64,
            shard_digests=("sha256:" + "b" * 64, "sha256:" + "b" * 64),
            reason_codes=("test",),
        ),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    outcome = jl.replay(out).outcomes[-1]
    assert len(outcome.output_anchors) == 3
    assert len({a.anchor_id for a in outcome.output_anchors}) == 3


def test_same_arity_overloads_collapse_not_reject(tmp_path: Path) -> None:
    """★同类内擦除后同 arity 的重载是合法 Java：塌缩节点合并两个重载的出边，
    绝不因 id 撞车拒绝（跨 shard 重复才拒绝）。"""
    overloads = (
        "package com.n;\n"
        "\n"
        "public class O {\n"
        "    void go(int x) {\n"
        "        alpha();\n"
        "    }\n"
        "\n"
        "    void go(String s) {\n"
        "        beta();\n"
        "    }\n"
        "\n"
        "    void alpha() {\n"
        "    }\n"
        "\n"
        "    void beta() {\n"
        "    }\n"
        "}\n"
    )
    loaded = _build_single_tree_index(tmp_path, {"com/n/O.java": overloads})
    to_alpha = trace_callpath(loaded, "com.n.O#go/1", "com.n.O#alpha/0")
    to_beta = trace_callpath(loaded, "com.n.O#go/1", "com.n.O#beta/0")
    assert len(to_alpha.paths) == 1 and len(to_beta.paths) == 1


# ---------------------------------------------------------------------------
# resolution 三态（name_unique / ambiguous / not_in_index，schema 1.4 起）。红态契约。
#
# 本节钉住的契约：
# - trace_callpath 返回 CallPathTrace(paths, gaps, coverage, reason_codes)；
# - 边 resolution ∈ {"name_unique","ambiguous","not_in_index"}——名字只描述
#   判据（简单名候选数 1 / >1 / 0），不声称绑定；"unique"/"resolved"/
#   "unresolved_dynamic" 全部退役被拒；
# - 边另带 scope（method/nested_type/lambda/unknown）：纯标注，不门控扩展
#   （契约见 test_jadx_resolution_criteria.py）；
# - owner 不参与解析（裁决摘除 narrowing）：qualifier/scope 照常提取落盘，但
#   语义候选集恒为 by_name 原始集合，resolution 恒按原始候选集判（唯一→
#   name_unique，多候选→ambiguous）；owner 也不得影响 max_fanout 截断——
#   「own 排前面再截断」会间接裁掉真实继承候选，同属禁区；
# - 索引查无此名的调用点 = not_in_index 边，进 gaps（路径中止为 gap），
#   绝不解读为「不可达」，也不专指动态调用；
# - 超限（depth/visited/fanout/gaps/paths）以稳定 reason code 显式声明，
#   绝不静默把截断伪装成穷尽。
# ---------------------------------------------------------------------------


def _edge_tuple(edge: CallPathEdge) -> list[object]:
    # scope 经 getattr 读取：落地前无此字段时红态以 AssertionError 呈现，
    # 落地后与直接属性访问等价，断言强度不变。
    return [
        edge.caller,
        edge.callee,
        edge.caller_path,
        edge.line,
        edge.resolution,
        getattr(edge, "scope", None),
    ]


def _trace_canonical_bytes(trace: object) -> bytes:
    """CallPathTrace 的确定性序列化（shard 序 / hashseed 无关性断言用）。"""
    record = {
        "paths": [
            {"nodes": list(p.nodes), "edges": [_edge_tuple(e) for e in p.edges]}
            for p in trace.paths  # type: ignore[attr-defined]
        ],
        "gaps": [_edge_tuple(e) for e in trace.gaps],  # type: ignore[attr-defined]
        "coverage": trace.coverage,  # type: ignore[attr-defined]
        "reason_codes": list(trace.reason_codes),  # type: ignore[attr-defined]
    }
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")


def test_globally_unique_name_edge_yields_path(tmp_path: Path) -> None:
    """全局唯一简单名 → 单条路径，resolution=name_unique；无 gap、无截断 code。"""
    loaded = _build_single_tree_index(
        tmp_path,
        {
            "com/r1/Caller.java": (
                "package com.r1;\n"
                "\n"
                "public class Caller {\n"
                "    void go() {\n"
                "        w.pull();\n"
                "    }\n"
                "}\n"
            ),
            "com/r1/Worker.java": (
                "package com.r1;\n"
                "\n"
                "public class Worker {\n"
                "    void pull() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    trace = trace_callpath(loaded, "com.r1.Caller#go/0", "com.r1.Worker#pull/0")
    assert len(trace.paths) == 1
    (path,) = trace.paths
    assert path.nodes == ("com.r1.Caller#go/0", "com.r1.Worker#pull/0")
    (edge,) = path.edges
    assert edge.resolution == "name_unique"
    assert getattr(edge, "scope", None) == "method"
    assert (edge.caller_path, edge.line) == ("com/r1/Caller.java", 5)
    assert trace.gaps == ()
    assert trace.reason_codes == ()
    assert trace.coverage == "complete"


def test_self_call_expands_full_name_candidate_set(tmp_path: Path) -> None:
    """★裁决契约（owner narrowing 摘除）：无 qualifier 的本类自调用不再收窄
    候选——语义候选集恒为 by_name 原始集合，resolution 恒按原始候选集判。
    本类声明同名方法只是候选之一：同简单名的其他类照样展开（真边不丢），
    两条边一律 ambiguous。qualifier/scope 仍照常提取落盘，只是不驱动 narrowing。"""
    loaded = _build_single_tree_index(
        tmp_path,
        {
            "com/o1/A.java": (
                "package com.o1;\n"
                "\n"
                "public class A {\n"
                "    void go() {\n"
                "        parse();\n"
                "    }\n"
                "\n"
                "    void parse() {\n"
                "    }\n"
                "}\n"
            ),
            "com/o1/B.java": (
                "package com.o1;\n"
                "\n"
                "public class B {\n"
                "    void parse() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    to_own = trace_callpath(loaded, "com.o1.A#go/0", "com.o1.A#parse/0")
    to_other = trace_callpath(loaded, "com.o1.A#go/0", "com.o1.B#parse/0")
    for trace in (to_own, to_other):
        assert len(trace.paths) == 1
        (edge,) = trace.paths[0].edges
        assert edge.resolution == "ambiguous"
        assert (edge.caller_path, edge.line) == ("com/o1/A.java", 5)
        assert trace.gaps == ()
        assert trace.reason_codes == ()


def test_inherited_cross_arity_true_edge_survives_self_call(tmp_path: Path) -> None:
    """★裁决核心防线（C/Base 构型）：C extends Base，C 声明 foo/1、Base 声明
    foo/2，C 体内无限定调 foo(x, y)——JLS 绑定是继承来的 Base#foo/2。文本层
    不建继承层次，唯一诚实输出是保留全体简单名候选并标 ambiguous；owner 收窄
    在此构型会判出假的唯一名边并丢掉真边（同构型下 master 两态判 ambiguous 且
    保真边，即净新增假阳——故摘除）。"""
    loaded = _build_single_tree_index(
        tmp_path,
        {
            "com/o3/Base.java": (
                "package com.o3;\n"
                "\n"
                "public class Base {\n"
                "    void foo(int a, int b) {\n"
                "    }\n"
                "}\n"
            ),
            "com/o3/C.java": (
                "package com.o3;\n"
                "\n"
                "public class C extends Base {\n"
                "    void go() {\n"
                "        foo(x, y);\n"
                "    }\n"
                "\n"
                "    void foo(String s) {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    to_base = trace_callpath(loaded, "com.o3.C#go/0", "com.o3.Base#foo/2")
    to_self = trace_callpath(loaded, "com.o3.C#go/0", "com.o3.C#foo/1")
    for trace in (to_base, to_self):
        assert len(trace.paths) == 1
        (edge,) = trace.paths[0].edges
        assert edge.resolution == "ambiguous"
        assert (edge.caller_path, edge.line) == ("com/o3/C.java", 5)
        assert trace.gaps == ()
        assert trace.reason_codes == ()


def test_owner_guard_nested_type_scope_stays_ambiguous(tmp_path: Path) -> None:
    """★造假防线：匿名类体内的无 qualifier 调用（scope=nested_type）绑定目标
    不可静态确定——即便外层类恰好声明同名方法，也必须回退全局歧义，绝不
    伪装成唯一名匹配（那会产出看似权威的错误边）。"""
    loaded = _build_single_tree_index(
        tmp_path,
        {
            "com/o2/C.java": (
                "package com.o2;\n"
                "\n"
                "public class C {\n"
                "    void go() {\n"
                "        Runnable r = new Runnable() {\n"
                "            public void run() {\n"
                "                parse();\n"
                "            }\n"
                "        };\n"
                "    }\n"
                "\n"
                "    void parse() {\n"
                "    }\n"
                "}\n"
            ),
            "com/o2/D.java": (
                "package com.o2;\n"
                "\n"
                "public class D {\n"
                "    void parse() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    to_c = trace_callpath(loaded, "com.o2.C#go/0", "com.o2.C#parse/0")
    to_d = trace_callpath(loaded, "com.o2.C#go/0", "com.o2.D#parse/0")
    for trace in (to_c, to_d):
        assert len(trace.paths) == 1
        (edge,) = trace.paths[0].edges
        assert edge.resolution == "ambiguous"
        assert (edge.caller_path, edge.line) == ("com/o2/C.java", 7)
        # ★红态契约（纠正误钉）：`public void run() {` 是匿名类方法**声明**，
        # 不是调用点——此前把它钉成「必须如实成为 gap」，等于把伪观测包装成
        # 诚实披露。声明剔除落地后它既不成边也不成 gap，此处必须空。
        assert trace.gaps == ()


def test_ambiguous_when_multiple_owners_unknown(tmp_path: Path) -> None:
    """标识符 qualifier（变量接收者）owner 不可判 → 全体候选展开、标 ambiguous；
    即便 caller 自己的类也声明同名方法，也不得触发本类限定（x 可能是任何类型）。"""
    loaded = _build_single_tree_index(
        tmp_path,
        {
            "com/p1/K.java": (
                "package com.p1;\n"
                "\n"
                "public class K {\n"
                "    void go() {\n"
                "        x.parse();\n"
                "    }\n"
                "}\n"
            ),
            "com/p1/K2.java": (
                "package com.p1;\n"
                "\n"
                "public class K2 {\n"
                "    void go() {\n"
                "        x.parse();\n"
                "    }\n"
                "\n"
                "    void parse() {\n"
                "    }\n"
                "}\n"
            ),
            "com/p1/A.java": (
                "package com.p1;\n"
                "\n"
                "public class A {\n"
                "    void parse() {\n"
                "    }\n"
                "}\n"
            ),
            "com/p1/B.java": (
                "package com.p1;\n"
                "\n"
                "public class B {\n"
                "    void parse() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    for source, target in (
        ("com.p1.K#go/0", "com.p1.A#parse/0"),
        ("com.p1.K#go/0", "com.p1.B#parse/0"),
        ("com.p1.K2#go/0", "com.p1.K2#parse/0"),
        ("com.p1.K2#go/0", "com.p1.A#parse/0"),
    ):
        trace = trace_callpath(loaded, source, target)
        assert len(trace.paths) == 1, (source, target)
        (edge,) = trace.paths[0].edges
        assert edge.resolution == "ambiguous", (source, target)


def test_ambiguous_edges_are_labeled_not_dropped(tmp_path: Path) -> None:
    """歧义边逐候选展开：路径条数 == 候选数，全部带 ambiguous 标签；
    绝不静默择一、绝不静默丢弃、也绝不落进 gaps。"""
    files = {
        "com/q1/M.java": (
            "package com.q1;\n"
            "\n"
            "public class M {\n"
            "    void go() {\n"
            "        t.handle(v);\n"
            "    }\n"
            "}\n"
        ),
    }
    for cls in ("A", "B", "C"):
        files[f"com/q1/{cls}.java"] = (
            "package com.q1;\n"
            "\n"
            f"public class {cls} {{\n"
            "    void handle(String s) {\n"
            "    }\n"
            "}\n"
        )
    loaded = _build_single_tree_index(tmp_path, files)
    expanded = 0
    for cls in ("A", "B", "C"):
        trace = trace_callpath(loaded, "com.q1.M#go/0", f"com.q1.{cls}#handle/1")
        assert len(trace.paths) == 1, cls
        (edge,) = trace.paths[0].edges
        assert edge.resolution == "ambiguous"
        assert trace.gaps == ()
        assert trace.reason_codes == ()
        expanded += len(trace.paths)
    assert expanded == 3  # 候选展开数 == 歧义边计数


def test_self_call_overloads_expand_across_declaring_classes(tmp_path: Path) -> None:
    """本类自调用 + 重载：候选集不因 owner 收窄——S 的两个重载与外类 T 的
    同名方法全部展开、全部 ambiguous（调用点实参个数不参与判定，见规格
    非目标；文本层不做绑定判定，不声称任何候选是 JLS 绑定）。"""
    loaded = _build_single_tree_index(
        tmp_path,
        {
            "com/s1/S.java": (
                "package com.s1;\n"
                "\n"
                "public class S {\n"
                "    void go() {\n"
                "        handle(v);\n"
                "    }\n"
                "\n"
                "    void handle(int x) {\n"
                "    }\n"
                "\n"
                "    void handle(int x, int y) {\n"
                "    }\n"
                "}\n"
            ),
            "com/s1/T.java": (
                "package com.s1;\n"
                "\n"
                "public class T {\n"
                "    void handle(int x) {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    for target in ("com.s1.S#handle/1", "com.s1.S#handle/2", "com.s1.T#handle/1"):
        trace = trace_callpath(loaded, "com.s1.S#go/0", target)
        assert len(trace.paths) == 1, target
        assert trace.paths[0].edges[0].resolution == "ambiguous", target
        assert trace.gaps == ()
        assert trace.reason_codes == ()


def test_not_in_index_boundary_is_gap_not_absence(tmp_path: Path) -> None:
    """★索引查无此名的调用点（反射 invoke / JNI / 框架方法同一形态：索引里
    没有可解析的 body）→ not_in_index gap。查不到路径 + 有 gap ⇒
    「未观察到」，绝不是「不可达」。"""
    loaded = _build_single_tree_index(
        tmp_path,
        {
            "com/g1/R.java": (
                "package com.g1;\n"
                "\n"
                "public class R {\n"
                "    void go() {\n"
                "        step();\n"
                "    }\n"
                "\n"
                "    void step() {\n"
                "        m.invoke(this);\n"
                "    }\n"
                "}\n"
            ),
            "com/g1/Z.java": (
                "package com.g1;\n"
                "\n"
                "public class Z {\n"
                "    void far() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    trace = trace_callpath(loaded, "com.g1.R#go/0", "com.g1.Z#far/0")
    assert trace.paths == ()
    assert [_edge_tuple(g) for g in trace.gaps] == [
        ["com.g1.R#step/0", "invoke", "com/g1/R.java", 9, "not_in_index", "method"]
    ]
    assert trace.reason_codes == ()

    # 目标节点命中即中止、不展开：其体内的动态调用不进本次 gaps（语义钉死）。
    to_step = trace_callpath(loaded, "com.g1.R#go/0", "com.g1.R#step/0")
    assert len(to_step.paths) == 1
    assert to_step.paths[0].edges[0].resolution == "name_unique"
    assert to_step.gaps == ()


def test_depth_limit_bounds_paths_without_claiming_unreachable(tmp_path: Path) -> None:
    files = {
        "com/d1/W.java": (
            "package com.d1;\n"
            "\n"
            "public class W {\n"
            "    void a() {\n"
            "        b();\n"
            "    }\n"
            "\n"
            "    void b() {\n"
            "        c();\n"
            "    }\n"
            "\n"
            "    void c() {\n"
            "        d();\n"
            "    }\n"
            "\n"
            "    void d() {\n"
            "    }\n"
            "}\n"
        ),
    }
    loaded = _build_single_tree_index(tmp_path, files)
    full = trace_callpath(loaded, "com.d1.W#a/0", "com.d1.W#d/0")
    assert len(full.paths) == 1 and len(full.paths[0].edges) == 3

    cut = trace_callpath(
        loaded, "com.d1.W#a/0", "com.d1.W#d/0", limits=CallPathLimits(max_depth=2)
    )
    assert cut.paths == ()
    assert "depth_limited" in cut.reason_codes  # 截断必须自报，绝不冒充穷尽
    assert cut.gaps == ()


def test_visited_and_frontier_caps_are_respected(tmp_path: Path) -> None:
    """visited 帽与 gap 帽：撞帽 → 空结果/截断结果 + 对应稳定 code。"""
    loaded = _build_single_tree_index(
        tmp_path,
        {
            "com/d2/G.java": (
                "package com.d2;\n"
                "\n"
                "public class G {\n"
                "    void go() {\n"
                "        u1();\n"
                "        u2();\n"
                "        u3();\n"
                "    }\n"
                "\n"
                "    void sink() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    # 默认限额：三个未知 callee 全量成 gap，确定性排序。
    trace = trace_callpath(loaded, "com.d2.G#go/0", "com.d2.G#sink/0")
    assert trace.paths == ()
    assert [g.callee for g in trace.gaps] == ["u1", "u2", "u3"]
    assert all(g.resolution == "not_in_index" for g in trace.gaps)

    # gap 帽：确定性保留最先遍历到的 u1，且显式自报 gaps_limited。
    capped = trace_callpath(
        loaded, "com.d2.G#go/0", "com.d2.G#sink/0", limits=CallPathLimits(max_gaps=1)
    )
    assert [g.callee for g in capped.gaps] == ["u1"]
    assert "gaps_limited" in capped.reason_codes

    # visited 帽：源节点即耗尽 → 空结果 + visited_limited。
    starved = trace_callpath(
        loaded, "com.d2.G#go/0", "com.d2.G#sink/0", limits=CallPathLimits(max_visited=1)
    )
    assert starved.paths == ()
    assert "visited_limited" in starved.reason_codes


def test_ambiguous_fanout_capped_deterministically(tmp_path: Path) -> None:
    """单调用点候选数超 max_fanout → 按 ident 字典序确定性保留前 N，
    并显式自报 fanout_limited；被裁掉的候选查不到路径不是「不可达」。

    ★范围声明（第二轮复审修正）：本测试与下一条只钉**显式收紧限额时**的截断
    机制（确定性、披露、owner 无关），不背书默认档位——默认 max_fanout=32
    相对 master（全候选展开）是真实召回回归，由 test_jadx_recall_baseline 的
    默认限额对等契约钉红，处置方式待人裁决。"""
    files = {
        "com/f1/M.java": (
            "package com.f1;\n"
            "\n"
            "public class M {\n"
            "    void go() {\n"
            "        x.pick();\n"
            "    }\n"
            "}\n"
        ),
    }
    for cls in ("C1", "C2", "C3", "C4"):
        files[f"com/f1/{cls}.java"] = (
            "package com.f1;\n"
            "\n"
            f"public class {cls} {{\n"
            "    void pick() {\n"
            "    }\n"
            "}\n"
        )
    loaded = _build_single_tree_index(tmp_path, files)

    # 默认限额下四个候选全可达（对照组）。
    assert len(trace_callpath(loaded, "com.f1.M#go/0", "com.f1.C4#pick/0").paths) == 1

    limits = CallPathLimits(max_fanout=2)
    kept = trace_callpath(loaded, "com.f1.M#go/0", "com.f1.C1#pick/0", limits=limits)
    assert len(kept.paths) == 1
    assert kept.paths[0].edges[0].resolution == "ambiguous"
    assert "fanout_limited" in kept.reason_codes

    dropped = trace_callpath(loaded, "com.f1.M#go/0", "com.f1.C4#pick/0", limits=limits)
    assert dropped.paths == ()
    assert "fanout_limited" in dropped.reason_codes


def test_fanout_truncation_is_owner_independent(tmp_path: Path) -> None:
    """★不变量（防下一切片踩坑）：max_fanout 截断恒按全体简单名候选的 ident
    字典序保前 N，owner 不得给自家候选任何存活特权。夹具刻意让 caller 自己的
    类（Zz）字典序排最后：
    - 「own 排前面再截断」会保 Zz、裁 Cb——被「Cb 可达 ∧ Zz#hit 不可达」双向拒绝；
    - 声明该名的 caller（Zz）与不声明的 caller（Nn）截断行为必须完全一致；
    - 截断不升格 resolution：max_fanout=1 只剩一条边仍是 ambiguous
      （resolution 恒按原始候选集判，绝不按截断后的存活数重判）。

    ★范围声明（第二轮复审修正）：全程显式传小 max_fanout——钉的是截断**机制**
    的不变量，不是「默认档位截断合理」；默认档位的召回底线归
    test_jadx_recall_baseline 管。"""
    files = {
        "com/fo1/Zz.java": (
            "package com.fo1;\n"
            "\n"
            "public class Zz {\n"
            "    void go() {\n"
            "        hit();\n"
            "    }\n"
            "\n"
            "    void hit() {\n"
            "    }\n"
            "}\n"
        ),
        "com/fo1/Nn.java": (
            "package com.fo1;\n"
            "\n"
            "public class Nn {\n"
            "    void go() {\n"
            "        hit();\n"
            "    }\n"
            "}\n"
        ),
    }
    for cls in ("Ca", "Cb"):
        files[f"com/fo1/{cls}.java"] = (
            "package com.fo1;\n"
            "\n"
            f"public class {cls} {{\n"
            "    void hit() {\n"
            "    }\n"
            "}\n"
        )
    loaded = _build_single_tree_index(tmp_path, files)
    limits = CallPathLimits(max_fanout=2)
    for caller in ("com.fo1.Zz#go/0", "com.fo1.Nn#go/0"):
        # 全候选 [Ca, Cb, Zz] 截断成 [Ca, Cb]：与 caller 是谁无关。
        for target in ("com.fo1.Ca#hit/0", "com.fo1.Cb#hit/0"):
            kept = trace_callpath(loaded, caller, target, limits=limits)
            assert len(kept.paths) == 1, (caller, target)
            assert kept.paths[0].edges[0].resolution == "ambiguous", (caller, target)
            assert "fanout_limited" in kept.reason_codes, (caller, target)
        cut_own = trace_callpath(loaded, caller, "com.fo1.Zz#hit/0", limits=limits)
        assert cut_own.paths == (), caller
        assert "fanout_limited" in cut_own.reason_codes, caller

        solo = trace_callpath(
            loaded, caller, "com.fo1.Ca#hit/0", limits=CallPathLimits(max_fanout=1)
        )
        assert len(solo.paths) == 1, caller
        assert solo.paths[0].edges[0].resolution == "ambiguous", caller
        assert "fanout_limited" in solo.reason_codes, caller


def test_partial_coverage_manifest_marks_result_partial(tmp_path: Path) -> None:
    """manifest coverage=partial（扫描截断）必须原样传染到查询结果。"""
    loaded = _build_single_tree_index(
        tmp_path,
        {
            "a/AA.java": (
                "package a;\n"
                "\n"
                "public class AA {\n"
                "    void go() {\n"
                "        step();\n"
                "    }\n"
                "\n"
                "    void step() {\n"
                "    }\n"
                "}\n"
            ),
            "z/ZZ.java": (
                "package z;\n"
                "\n"
                "public class ZZ {\n"
                "    void zz() {\n"
                "    }\n"
                "}\n"
            ),
        },
        limits=Limits(max_files=1),  # 只扫得到字典序靠前的 a/AA.java
    )
    assert loaded.coverage == "partial"
    trace = trace_callpath(loaded, "a.AA#go/0", "a.AA#step/0")
    assert len(trace.paths) == 1
    assert trace.coverage == "partial"


def test_resolution_output_is_byte_identical_across_shard_enumeration_order(
    tmp_path: Path,
) -> None:
    """含歧义边与 gap 的完整结果（paths+gaps+coverage+reason_codes）必须与
    shard 枚举序无关——逐字节一致。"""
    loaded = _build_two_dex_index_with(
        tmp_path,
        {
            "com/x1/M.java": (
                "package com.x1;\n"
                "\n"
                "public class M {\n"
                "    void go() {\n"
                "        t.handle(v);\n"
                "        u1();\n"
                "    }\n"
                "}\n"
            ),
            "com/x1/A.java": (
                "package com.x1;\n"
                "\n"
                "public class A {\n"
                "    void handle(String s) {\n"
                "    }\n"
                "}\n"
            ),
        },
        {
            "com/x1/B.java": (
                "package com.x1;\n"
                "\n"
                "public class B {\n"
                "    void handle(String s) {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    reversed_index = LoadedIndex(
        manifest=loaded.manifest,
        shard_locators=tuple(reversed(loaded.shard_locators)),
        coverage=loaded.coverage,
        shards=tuple(reversed(loaded.shards)),
    )
    for target in ("com.x1.A#handle/1", "com.x1.A#handle"):
        forward = trace_callpath(loaded, "com.x1.M#go/0", target)
        backward = trace_callpath(reversed_index, "com.x1.M#go/0", target)
        assert _trace_canonical_bytes(forward) == _trace_canonical_bytes(backward)
        assert len(forward.paths) == 1
        assert [g.callee for g in forward.gaps] == ["u1"]


def test_tristate_edge_validation_and_paths_never_contain_gaps() -> None:
    """三态取值域钉死："unique"/"resolved"/"unresolved_dynamic" 退役必须被拒；
    not_in_index 边只许进 gaps，绝不许出现在 CallPath 里（路径不能穿越
    索引外边界）。"""
    unique_name = _edge(resolution="name_unique")
    assert unique_name.resolution == "name_unique"
    absent = _edge(resolution="not_in_index", callee="invoke")
    for retired in ("unique", "resolved", "unresolved_dynamic"):
        with pytest.raises(JadxIndexError):
            _edge(resolution=retired)
    with pytest.raises(JadxIndexError):
        CallPath(nodes=("com.a.App#onCreate/0", "invoke"), edges=(absent,))

    trace_cls = jcp.CallPathTrace
    with pytest.raises(JadxIndexError):
        trace_cls(paths=(), gaps=(unique_name,), coverage="complete", reason_codes=())
    with pytest.raises(JadxIndexError):
        trace_cls(paths=(), gaps=(), coverage="total", reason_codes=())
    with pytest.raises(JadxIndexError):
        trace_cls(paths=(), gaps=(), coverage="complete", reason_codes=("Bad Code!",))
    ok = trace_cls(
        paths=(), gaps=(absent,), coverage="partial", reason_codes=("gaps_limited",)
    )
    assert ok.gaps[0].resolution == "not_in_index"
