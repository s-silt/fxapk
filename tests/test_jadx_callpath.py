"""P1-B trace_callpath：确定性 BFS 路径查询 + ledger 投影（阴性绝不产观察）。

先于实现编写（红态契约；导入 apkscan.core.jadx_callpath 在实现落地前收集即失败）。
行号断言基于手工数行的合成源码。设计见
docs/superpowers/specs/2026-08-16-p1b-jadx-callpath-design.md。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

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


def _build_single_tree_index(tmp_path: Path, files: dict[str, str]) -> LoadedIndex:
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
    scan = scan_java_sources(out, [], lineage=lineage[0], limits=Limits())
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
    paths = trace_callpath(loaded, "com.a.App#onCreate/0", "com.c.Net#raw/1")
    assert len(paths) == 1
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
    assert all(e.resolution == "unique" for e in path.edges)


def test_trace_accepts_arityless_endpoint_form(tmp_path: Path) -> None:
    loaded = _build_two_dex_index(tmp_path)
    paths = trace_callpath(loaded, "com.a.App#onCreate", "com.c.Net#get/1")
    assert len(paths) == 1
    assert paths[0].nodes[0] == "com.a.App#onCreate/0"
    assert paths[0].nodes[-1] == "com.c.Net#get/1"


def test_trace_negative_and_malformed_inputs_return_empty(tmp_path: Path) -> None:
    loaded = _build_two_dex_index(tmp_path)
    # 逆向不可达（静态图无 raw→onCreate 边）。
    assert trace_callpath(loaded, "com.c.Net#raw/1", "com.a.App#onCreate/0") == ()
    # 未知端点 / 空串 / 超长 / source==target。
    assert trace_callpath(loaded, "com.zz.Gone#x/0", "com.c.Net#raw/1") == ()
    assert trace_callpath(loaded, "", "com.c.Net#raw/1") == ()
    assert trace_callpath(loaded, "com.a.App#onCreate/0", "") == ()
    assert trace_callpath(loaded, "A" * 5000, "com.c.Net#raw/1") == ()
    assert trace_callpath(loaded, "com.c.Net#raw/1", "com.c.Net#raw/1") == ()


def test_trace_respects_depth_limit(tmp_path: Path) -> None:
    loaded = _build_two_dex_index(tmp_path)
    limited = trace_callpath(
        loaded,
        "com.a.App#onCreate/0",
        "com.c.Net#raw/1",
        limits=CallPathLimits(max_depth=2),
    )
    assert limited == ()


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
    assert len(to_a) == 1 and len(to_b) == 1
    assert to_a[0].edges[0].resolution == "ambiguous"
    assert to_b[0].edges[0].resolution == "ambiguous"
    assert to_a[0].edges[0].line == 5 and to_a[0].edges[0].caller_path == "com/p/C.java"


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
    paths = trace_callpath(loaded, "com.q.R#a/0", "com.q.R#c/0")
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
        "resolution": "unique",
    }
    return CallPathEdge(**{**base, **overrides})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"line": 0},
        {"resolution": "maybe"},
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
