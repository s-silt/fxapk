"""resolution 三态改名 + 调用点 scope 标注 + 提取器 fail-closed。红态契约。

规格：scratchpad `jadx-resolution-rename-and-scope-annotation-spec.md`（本轮）。
钉住的契约：

- 三态名字只许描述判据：`name_unique`（简单名在索引里恰一候选）/ `ambiguous`
  （多候选）/ `not_in_index`（查无此名——不专指动态调用）。退役名
  `resolved` / `unique` / `unresolved_dynamic` 必须被拒。
- `CallPathEdge` 带必填 `scope`（method / nested_type / lambda / unknown）：
  **绝不门控扩展/候选解析**——嵌套体内的边照常成路径（Android 的关键逻辑就在
  回调体里，排除即召回塌方）；CLI 以 caveat 说明穿越边不等于直接执行。
  ★精确边界（第二轮复审修正）：scope 不是纯装饰，它进入 gap 身份与确定性
  排序（见 dual_scope 两条测试）；「不门控」只承诺 resolution/候选集不看 scope。
- 提取器六缺陷修复方向 = 修准标注、判不准标不可判定（unknown / <unknown>），
  **任何情况下不因判不准而丢调用点**；记录集变化只许两类且都是删伪：
  「构造器类型名被伪造成普通方法调用」（`new X(...)` 不是边是既有文档化限制）
  与「方法/构造器**声明行**被伪造成调用点」（第二轮复审新增红态，文本可判定
  绝非调用表达式才准删，判据与剔除清单见 test_jadx_recall_baseline）。

先于实现编写：实现落地前须为**正确原因**红（AssertionError / AttributeError /
构造缺 scope 字段的 TypeError / DID NOT RAISE），绝不允许 SyntaxError /
ImportError / collection error。其中两条召回锁（reachability_preserved 系）
现在就是绿的，实现后必须保持绿。夹具全合成，无案件值。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.jadx_callpath import (
    CallPathEdge,
    CallPathLimits,
    trace_callpath,
)
from apkscan.core.jadx_index import (
    DexInput,
    DexLineage,
    DexRole,
    IndexBuildResult,
    IndexBuildState,
    JadxIndexError,
    JadxIndexManifest,
    JadxIndexStore,
    Limits,
    LoadedIndex,
    _valid_call_qualifier,
    _valid_call_scope,
    build_key_material,
    derive_index_key,
    scan_java_sources,
    verify_dex_inputs,
)

runner = CliRunner()

_OPTS = "sha256:" + "c" * 64
_LINEAGE = DexLineage(DexRole.APK_DEX, 0, "classes.dex", "sha256:" + "1" * 64)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _java_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _build_index(
    tmp_path: Path, files: dict[str, str]
) -> tuple[JadxIndexStore, str, LoadedIndex]:
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "classes.dex").write_bytes(b"dex-crit")
    inputs = [
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="classes.dex",
            relative_path="classes.dex",
            declared_digest=_digest(b"dex-crit"),
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
    return store, key, loaded


def _scan_calls(tmp_path: Path, source: str) -> dict[str, list[dict[str, object]]]:
    """单文件夹具 → {方法名: calls 列表}（scan_java_sources 真入口）。"""
    root = tmp_path / "java"
    _java_tree(root, {"com/t/T.java": source})
    scan = scan_java_sources(root, [], lineage=_LINEAGE, limits=Limits())
    assert scan.coverage == "complete"
    (cls,) = scan.structure
    return {
        str(dict(m)["name"]): [dict(c) for c in dict(m)["calls"]]  # type: ignore[union-attr]
        for m in cls["methods"]  # type: ignore[union-attr]
    }


def _run_cli(args: list[str]) -> tuple[int, dict | None]:
    result = runner.invoke(cli.app, args)
    try:
        return result.exit_code, json.loads(result.stdout)
    except ValueError:
        return result.exit_code, None


def _scope_of(edge: CallPathEdge) -> object:
    """scope 字段读取（落地前无此字段：getattr 让红态以 AssertionError 呈现，
    落地后与直接属性访问等价，断言强度不变）。"""
    return getattr(edge, "scope", None)


#: 匿名类体内调用 sink 的可达性夹具（召回锁与 scope 标注共用）。
_JAVA_ANON = {
    "com/cr/R.java": (
        "package com.cr;\n"
        "\n"
        "public class R {\n"
        "    void go() {\n"
        "        Runnable r = new Runnable() {\n"
        "            public void run() {\n"
        "                sink();\n"
        "            }\n"
        "        };\n"
        "    }\n"
        "\n"
        "    void direct() {\n"
        "        step();\n"
        "    }\n"
        "\n"
        "    void step() {\n"
        "    }\n"
        "}\n"
    ),
    "com/cr/S.java": (
        "package com.cr;\n"
        "\n"
        "public class S {\n"
        "    void sink() {\n"
        "        onward();\n"
        "    }\n"
        "\n"
        "    void onward() {\n"
        "    }\n"
        "}\n"
    ),
}


# ---------------------------------------------------------------------------
# 三态改名：名字只许描述判据
# ---------------------------------------------------------------------------


def test_unique_name_criterion_is_named_name_unique(tmp_path: Path) -> None:
    """恰一候选 → resolution="name_unique"。名字声称的只有「简单名在索引覆盖
    内唯一」这一件事，不是 JLS 绑定（判据本身没变，变的是不再用 "resolved"
    这个声称绑定的词）。"""
    _, _, loaded = _build_index(
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
    (edge,) = trace.paths[0].edges
    assert edge.resolution == "name_unique"


def test_absent_name_criterion_is_named_not_in_index(tmp_path: Path) -> None:
    """索引查无此简单名 → gap，resolution="not_in_index"。旧名
    unresolved_dynamic 声称了「动态边界」，实际判据只是「索引里没有」——
    成因包括 JDK/框架方法、被逐行正则漏掉的声明、反射目标等，名字不许挑
    其中一种成因来讲。"""
    _, _, loaded = _build_index(
        tmp_path,
        {
            "com/g2/R.java": (
                "package com.g2;\n"
                "\n"
                "public class R {\n"
                "    void go() {\n"
                "        m.invoke(this);\n"
                "    }\n"
                "}\n"
            ),
            "com/g2/Z.java": (
                "package com.g2;\n"
                "\n"
                "public class Z {\n"
                "    void far() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    trace = trace_callpath(loaded, "com.g2.R#go/0", "com.g2.Z#far/0")
    assert trace.paths == ()
    (gap,) = trace.gaps
    assert gap.callee == "invoke"
    assert gap.resolution == "not_in_index"


def test_crossline_method_decl_miss_surfaces_as_not_in_index(tmp_path: Path) -> None:
    """跨行方法声明不入索引（既有文档化限制）→ 对它的调用成 gap。该 gap 与
    动态调用毫无关系，正是 "not_in_index" 只说可观测事实的理由。"""
    _, _, loaded = _build_index(
        tmp_path,
        {
            "com/g3/T.java": (
                "package com.g3;\n"
                "\n"
                "public class T {\n"
                "    void deep(\n"
                "        int a) {\n"
                "        body();\n"
                "    }\n"
                "\n"
                "    void go() {\n"
                "        deep(1);\n"
                "    }\n"
                "\n"
                "    void far() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    trace = trace_callpath(loaded, "com.g3.T#go/0", "com.g3.T#far/0")
    assert trace.paths == ()
    assert [g.callee for g in trace.gaps] == ["deep"]
    assert trace.gaps[0].resolution == "not_in_index"


def test_retired_resolution_names_are_rejected() -> None:
    """★取值域钉死：resolved / unique / unresolved_dynamic 全部退役，构造即拒
    ——防旧值从任何生产方静默流回。新域 = name_unique / ambiguous /
    not_in_index，且 scope 为必填字段（无默认——默认 "method" 等于替忘写的
    生产方伪造直接执行）。"""

    def edge(**overrides: object) -> CallPathEdge:
        base: dict[str, object] = {
            "caller": "com.a.A#go/0",
            "callee": "com.b.B#hit/0",
            "caller_path": "com/a/A.java",
            "line": 5,
            "resolution": "name_unique",
            "scope": "method",
        }
        return CallPathEdge(**{**base, **overrides})  # type: ignore[arg-type]

    assert edge().resolution == "name_unique"
    assert edge(resolution="ambiguous").resolution == "ambiguous"
    assert edge(resolution="not_in_index").resolution == "not_in_index"
    for retired in ("resolved", "unique", "unresolved_dynamic"):
        with pytest.raises(JadxIndexError):
            edge(resolution=retired)
    for bad_scope in ("", "weird", "nested"):
        with pytest.raises(JadxIndexError):
            edge(scope=bad_scope)
    with pytest.raises(TypeError):
        CallPathEdge(  # type: ignore[call-arg]
            caller="com.a.A#go/0",
            callee="com.b.B#hit/0",
            caller_path="com/a/A.java",
            line=5,
            resolution="name_unique",
        )


def test_reflective_invoke_reachability_preserved(tmp_path: Path) -> None:
    """★召回锁（现在绿、实现后必须仍绿）：`m.invoke(...)` 撞上索引里唯一的
    同名方法 → 边照常存在、路径照常可查。改名修的是标签的诚实度，不许顺手
    把边删掉——名字匹配本来就是本模块声明的判据。"""
    _, _, loaded = _build_index(
        tmp_path,
        {
            "com/rf/R.java": (
                "package com.rf;\n"
                "\n"
                "public class R {\n"
                "    void go() {\n"
                "        m.invoke(this);\n"
                "    }\n"
                "}\n"
            ),
            "com/rf/H.java": (
                "package com.rf;\n"
                "\n"
                "public class H {\n"
                "    void invoke(Object o) {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    trace = trace_callpath(loaded, "com.rf.R#go/0", "com.rf.H#invoke/1")
    assert len(trace.paths) == 1
    assert trace.paths[0].nodes == ("com.rf.R#go/0", "com.rf.H#invoke/1")
    assert trace.gaps == ()


def test_reflective_invoke_edge_claims_name_uniqueness_only(tmp_path: Path) -> None:
    """上一条构型里的边必须标 "name_unique"——它对绑定不置一词；qualifier
    （"m"）照常落盘留给下一步消费，本轮不据此改判。"""
    _, _, loaded = _build_index(
        tmp_path,
        {
            "com/rf2/R.java": (
                "package com.rf2;\n"
                "\n"
                "public class R {\n"
                "    void go() {\n"
                "        m.invoke(this);\n"
                "    }\n"
                "}\n"
            ),
            "com/rf2/H.java": (
                "package com.rf2;\n"
                "\n"
                "public class H {\n"
                "    void invoke(Object o) {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    trace = trace_callpath(loaded, "com.rf2.R#go/0", "com.rf2.H#invoke/1")
    (edge,) = trace.paths[0].edges
    assert edge.resolution == "name_unique"


# ---------------------------------------------------------------------------
# scope 标注：边保留、可穿越，只加标注
# ---------------------------------------------------------------------------


def test_nested_body_reachability_is_preserved(tmp_path: Path) -> None:
    """★召回锁（现在绿、实现后必须仍绿）：匿名类体内的调用照常成边、照常
    多跳穿越。Android 关键逻辑大量在回调体内——把嵌套体排除出扩展会让
    「onCreate 到网络 sink」这类查询系统性空手而归，是负优化，禁止。"""
    _, _, loaded = _build_index(tmp_path, _JAVA_ANON)
    direct = trace_callpath(loaded, "com.cr.R#go/0", "com.cr.S#sink/0")
    assert len(direct.paths) == 1
    assert direct.paths[0].nodes == ("com.cr.R#go/0", "com.cr.S#sink/0")

    # 穿越嵌套体继续多跳：go → (匿名体) sink → onward。
    two_hop = trace_callpath(loaded, "com.cr.R#go/0", "com.cr.S#onward/0")
    assert len(two_hop.paths) == 1
    assert two_hop.paths[0].nodes == (
        "com.cr.R#go/0",
        "com.cr.S#sink/0",
        "com.cr.S#onward/0",
    )


def test_nested_body_edge_carries_nested_type_scope(tmp_path: Path) -> None:
    """嵌套体内的边带 scope="nested_type"：不冒充直接执行（单纯调用 go 不
    必然跑匿名体），同时线索原样保留。直接语句边带 scope="method"。"""
    _, _, loaded = _build_index(tmp_path, _JAVA_ANON)
    nested = trace_callpath(loaded, "com.cr.R#go/0", "com.cr.S#sink/0")
    (edge,) = nested.paths[0].edges
    assert edge.resolution == "name_unique"
    assert _scope_of(edge) == "nested_type"

    plain = trace_callpath(loaded, "com.cr.R#direct/0", "com.cr.R#step/0")
    (edge,) = plain.paths[0].edges
    assert _scope_of(edge) == "method"
    # 第二跳（sink 体内的直接语句）恒为 method——scope 是逐边事实。
    two_hop = trace_callpath(loaded, "com.cr.R#go/0", "com.cr.S#onward/0")
    assert [_scope_of(e) for e in two_hop.paths[0].edges] == ["nested_type", "method"]


def test_lambda_body_edge_is_traversable_with_lambda_scope(tmp_path: Path) -> None:
    """lambda 体内的调用：边照常成路径，scope="lambda"。"""
    _, _, loaded = _build_index(
        tmp_path,
        {
            "com/lb/L.java": (
                "package com.lb;\n"
                "\n"
                "public class L {\n"
                "    void go() {\n"
                "        Runnable r = () -> sink();\n"
                "    }\n"
                "}\n"
            ),
            "com/lb/S.java": (
                "package com.lb;\n"
                "\n"
                "public class S {\n"
                "    void sink() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    trace = trace_callpath(loaded, "com.lb.L#go/0", "com.lb.S#sink/0")
    assert len(trace.paths) == 1
    (edge,) = trace.paths[0].edges
    assert edge.resolution == "name_unique"
    assert _scope_of(edge) == "lambda"


def test_gap_records_carry_site_scope(tmp_path: Path) -> None:
    """gap 也带 scope：嵌套体内查无此名的调用点标 nested_type，直接语句的
    标 method——边界披露连位置类别一起给足。"""
    _, _, loaded = _build_index(
        tmp_path,
        {
            "com/gs/R.java": (
                "package com.gs;\n"
                "\n"
                "public class R {\n"
                "    void go() {\n"
                "        u1();\n"
                "        Runnable r = new Runnable() {\n"
                "            public void run() {\n"
                "                u2();\n"
                "            }\n"
                "        };\n"
                "    }\n"
                "\n"
                "    void far() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    trace = trace_callpath(loaded, "com.gs.R#go/0", "com.gs.R#far/0")
    assert trace.paths == ()
    by_callee = {g.callee: g for g in trace.gaps}
    # ★红态契约（纠正误钉）：`public void run() {` 是方法声明不是调用点，
    # 声明剔除落地后不得再以 gap 现身——伪观测连「诚实披露」的资格都没有。
    # gap 的 scope 语义由真实调用点（u1 直接语句 / u2 匿名体内）承载。
    assert set(by_callee) == {"u1", "u2"}
    assert _scope_of(by_callee["u1"]) == "method"
    assert _scope_of(by_callee["u2"]) == "nested_type"
    assert all(g.resolution == "not_in_index" for g in trace.gaps)


def test_same_line_dual_scope_prefers_direct_edge_and_splits_gaps(
    tmp_path: Path,
) -> None:
    """同一行同名调用点一处直接、一处 lambda 体内：
    - 路径去重后存活的代表边必须是 scope="method"（更强的真实声明优先，
      rank 序确定）；
    - gap 去重键含 scope → 两个真实调用点诚实分列为两条 gap。"""
    _, _, loaded = _build_index(
        tmp_path,
        {
            "com/ds/D.java": (
                "package com.ds;\n"
                "\n"
                "public class D {\n"
                "    void go() {\n"
                "        run(g(), () -> g());\n"
                "    }\n"
                "\n"
                "    void g() {\n"
                "    }\n"
                "\n"
                "    void go2() {\n"
                "        use(u1(), () -> u1());\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    to_g = trace_callpath(loaded, "com.ds.D#go/0", "com.ds.D#g/0")
    assert len(to_g.paths) == 1
    (edge,) = to_g.paths[0].edges
    assert _scope_of(edge) == "method"

    to_far = trace_callpath(loaded, "com.ds.D#go2/0", "com.ds.D#g/0")
    assert to_far.paths == ()
    gap_keys = [(g.callee, _scope_of(g)) for g in to_far.gaps]
    assert gap_keys == [("u1", "lambda"), ("u1", "method"), ("use", "method")]


def test_dual_scope_gap_sites_consume_distinct_gap_budget(tmp_path: Path) -> None:
    """★钉现状为契约（P2-3 复核结论）：scope 参与 gap **身份**——同一行同名
    的直接调用点与 lambda 体内调用点是两处真实文本观测，各占一个 max_gaps
    预算位；预算紧时后续 gap 被挤出并以 gaps_limited 显式披露，预算够时全量
    保留。代价（双位占用）与收益（不静默合并两处语义不同的观测）是刻意取舍；
    若要改成「同行同名合并记一条」，属语义变更，须显式改本契约。"""
    _, _, loaded = _build_index(
        tmp_path,
        {
            "com/gb/G.java": (
                "package com.gb;\n"
                "\n"
                "public class G {\n"
                "    void go() {\n"
                "        pass(() -> miss()); miss();\n"
                "        late();\n"
                "    }\n"
                "\n"
                "    void pass(Runnable r) {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    tight = trace_callpath(
        loaded, "com.gb.G#go/0", "com.gb.G#pass/1", limits=CallPathLimits(max_gaps=2)
    )
    assert [(g.callee, g.line, _scope_of(g)) for g in tight.gaps] == [
        ("miss", 5, "lambda"),
        ("miss", 5, "method"),
    ]
    assert "gaps_limited" in tight.reason_codes

    roomy = trace_callpath(
        loaded, "com.gb.G#go/0", "com.gb.G#pass/1", limits=CallPathLimits(max_gaps=3)
    )
    assert [(g.callee, g.line, _scope_of(g)) for g in roomy.gaps] == [
        ("late", 6, "method"),
        ("miss", 5, "lambda"),
        ("miss", 5, "method"),
    ]
    assert "gaps_limited" not in roomy.reason_codes


def test_scope_never_gates_expansion_or_adds_limits() -> None:
    """★不变量（P2-3 复核后的精确表述）：scope 不参与**候选解析**——resolution
    判定与候选集恒与 scope 无关，也不许为嵌套边增设新限额旋钮。但 scope 并非
    纯装饰：它进入 gap 身份（去重键）与确定性排序，预算内保留哪些观测因此会
    受 scope 影响——那部分行为由 test_same_line_dual_scope_prefers_direct_edge
    _and_splits_gaps 与 test_dual_scope_gap_sites_consume_distinct_gap_budget
    钉住。本条只锁旋钮面不扩张、scope 不进截断/候选判定。"""
    assert set(CallPathLimits.__dataclass_fields__) == {
        "max_depth",
        "max_paths",
        "max_visited",
        "max_fanout",
        "max_gaps",
    }


def test_cli_surfaces_scope_and_nested_execution_caveat(tmp_path: Path) -> None:
    """CLI：边记录带 "scope"；返回路径含嵌套体内边时追加稳定 caveat
    nested_edge_is_not_direct_execution；纯直接边结果不带该 caveat。"""
    store, key, _ = _build_index(tmp_path, _JAVA_ANON)
    code, data = _run_cli(
        [
            "jadx",
            "callpath",
            "com.cr.R#go/0",
            "com.cr.S#sink/0",
            "--jadx-cache-root",
            str(store.cache_root),
            "--jadx-index",
            key,
        ]
    )
    assert code == 0 and data is not None and data["status"] == "ok"
    (path,) = data["paths"]
    (edge,) = path["edges"]
    assert edge["scope"] == "nested_type"
    assert edge["resolution"] == "name_unique"
    codes = [c["code"] for c in data["caveats"]]
    assert "nested_edge_is_not_direct_execution" in codes

    code, data = _run_cli(
        [
            "jadx",
            "callpath",
            "com.cr.R#direct/0",
            "com.cr.R#step/0",
            "--jadx-cache-root",
            str(store.cache_root),
            "--jadx-index",
            key,
        ]
    )
    assert code == 0 and data is not None and data["status"] == "ok"
    (path,) = data["paths"]
    (edge,) = path["edges"]
    assert edge["scope"] == "method"
    codes = [c["code"] for c in data["caveats"]]
    assert "nested_edge_is_not_direct_execution" not in codes


def test_cli_switch_rule_path_has_no_nested_execution_caveat(tmp_path: Path) -> None:
    """★红态契约（P2-4 CLI 面）：路径唯一边落在 switch rule 分支体内时不得出现
    nested_edge_is_not_direct_execution caveat——switch 分支体随 switch 语句
    **同步执行**，「该边的执行取决于嵌套体何时被调用」的话术用在这里是反向
    误导（把同步边说成延迟边）。现状把一切 `->` 当 lambda，故此条为红。"""
    store, key, _ = _build_index(
        tmp_path,
        {
            "com/sw/W.java": (
                "package com.sw;\n"
                "\n"
                "public class W {\n"
                "    void go(int x) {\n"
                "        switch (x) {\n"
                "            case 1 -> sink();\n"
                "            default -> other();\n"
                "        }\n"
                "    }\n"
                "\n"
                "    void sink() {\n"
                "    }\n"
                "\n"
                "    void other() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    code, data = _run_cli(
        [
            "jadx",
            "callpath",
            "com.sw.W#go/1",
            "com.sw.W#sink/0",
            "--jadx-cache-root",
            str(store.cache_root),
            "--jadx-index",
            key,
        ]
    )
    assert code == 0 and data is not None and data["status"] == "ok"
    (path,) = data["paths"]
    (edge,) = path["edges"]
    assert edge["scope"] == "method"
    codes = [c["code"] for c in data["caveats"]]
    assert "nested_edge_is_not_direct_execution" not in codes


# ---------------------------------------------------------------------------
# 提取器状态机：六缺陷逐条（scan_java_sources 真入口）
# ---------------------------------------------------------------------------


def test_lambda_bodies_scoped_lambda_expr_and_block(tmp_path: Path) -> None:
    """缺陷 (a)：lambda 无状态建模。表达式体与块体都必须标 scope="lambda"；
    lambda 语句之后与同语句其他实参里的直接调用保持 method。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.la;\n"
            "public class L {\n"
            "    void go() {\n"
            "        Runnable a = () -> sink();\n"
            "        list.each(x -> { deep(); }, other());\n"
            "        after();\n"
            "    }\n"
            "    void sink() {\n"
            "    }\n"
            "}\n"
        ),
    )
    assert calls["go"] == [
        {"callee": "sink", "line": 4, "qualifier": "", "scope": "lambda"},
        {"callee": "deep", "line": 5, "qualifier": "", "scope": "lambda"},
        {"callee": "each", "line": 5, "qualifier": "list", "scope": "method"},
        {"callee": "other", "line": 5, "qualifier": "", "scope": "method"},
        {"callee": "after", "line": 6, "qualifier": "", "scope": "method"},
    ]


def test_new_in_condition_keeps_direct_scope(tmp_path: Path) -> None:
    """缺陷 (b)：`if (new Foo().ok()) { sink(); }`——if 块不是类型体。
    new 表达式随条件闭括号终结，sink 是直接语句，必须 scope="method"
    （现状误标 nested_type：低估真实直接边，等消费方读 scope 时就成反向
    误导）。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.nc;\n"
            "public class C {\n"
            "    void go() {\n"
            "        if (new Foo().ok()) {\n"
            "            sink();\n"
            "        }\n"
            "        after();\n"
            "    }\n"
            "}\n"
        ),
    )
    assert calls["go"] == [
        {"callee": "ok", "line": 4, "qualifier": "<expr>", "scope": "method"},
        {"callee": "sink", "line": 5, "qualifier": "", "scope": "method"},
        {"callee": "after", "line": 7, "qualifier": "", "scope": "method"},
    ]


def test_switch_rule_arrow_bodies_are_not_lambda_scope(tmp_path: Path) -> None:
    """★红态契约（P2-4）：switch rule 的 `->`（case/default 箭头）不是 lambda。
    分支体随 switch 语句**同步执行**，没有「嵌套体何时被调用」的延迟语义；
    现状把一切 `->` 一律记 scope="lambda"，属反向误导标注（把同步执行边说成
    延迟边，CLI 还会追加错误 caveat）。表达式体与块体都必须是 scope="method"
    （所在外层 scope 的原值）；真 lambda（参数箭头）不受影响、colon 形态 switch
    照旧 method。判不准 case/default 归属时按既有纪律标 unknown，不许猜 lambda。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.t;\n"
            "public class T {\n"
            "    void go(int x) {\n"
            "        Runnable r = () -> lam();\n"
            "        switch (x) {\n"
            "            case 1 -> arm();\n"
            "            case 2 -> {\n"
            "                armBlock();\n"
            "            }\n"
            "            default -> fallback();\n"
            "        }\n"
            "        switch (x) {\n"
            "            case 1:\n"
            "                colon();\n"
            "                break;\n"
            "        }\n"
            "        after();\n"
            "    }\n"
            "}\n"
        ),
    )
    assert calls["go"] == [
        {"callee": "lam", "line": 4, "qualifier": "", "scope": "lambda"},
        {"callee": "arm", "line": 6, "qualifier": "", "scope": "method"},
        {"callee": "armBlock", "line": 8, "qualifier": "", "scope": "method"},
        {"callee": "fallback", "line": 10, "qualifier": "", "scope": "method"},
        {"callee": "colon", "line": 14, "qualifier": "", "scope": "method"},
        {"callee": "after", "line": 17, "qualifier": "", "scope": "method"},
    ]


def test_array_initializer_calls_are_direct_scope(tmp_path: Path) -> None:
    """缺陷 (c)：数组初始化器 `new T[]{ ... }` 急切求值，体内调用是直接执行
    ——scope="method"；初始化器里嵌套的匿名类体仍是 nested_type。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.ar;\n"
            "public class A {\n"
            "    void go() {\n"
            "        Object[] xs = new Object[]{ make() };\n"
            "        Runnable[] rs = new Runnable[]"
            "{ new Runnable() { public void run() { inner(); } } };\n"
            "        after();\n"
            "    }\n"
            "}\n"
        ),
    )
    # ★红态（纠正误钉）：`public void run() {` 是声明、不再入 calls；
    # 匿名体内真实调用 inner 保留 nested_type。
    assert calls["go"] == [
        {"callee": "make", "line": 4, "qualifier": "", "scope": "method"},
        {"callee": "inner", "line": 5, "qualifier": "", "scope": "nested_type"},
        {"callee": "after", "line": 6, "qualifier": "", "scope": "method"},
    ]


def test_crossline_local_class_body_is_nested_type(tmp_path: Path) -> None:
    """缺陷 (d)：`class Local` 与 `{` 分行时局部类体必须仍是 nested_type
    （现状整个体被标 method——把只在局部类被用到时才执行的调用冒充成
    外层方法的直接语句）。局部类照旧不入索引（既有文档化限制不动）。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.lc;\n"
            "public class T {\n"
            "    void go() {\n"
            "        class Local\n"
            "        {\n"
            "            void inner() {\n"
            "                body();\n"
            "            }\n"
            "        }\n"
            "        after();\n"
            "    }\n"
            "}\n"
        ),
    )
    # ★红态（纠正误钉）：`void inner() {` 是局部类**方法声明**、不再入 calls；
    # 局部类体内真实调用 body 保留 nested_type，语句后回 method。
    assert calls["go"] == [
        {"callee": "body", "line": 7, "qualifier": "", "scope": "nested_type"},
        {"callee": "after", "line": 10, "qualifier": "", "scope": "method"},
    ]


def test_dot_continuation_qualifier_reads_across_lines(tmp_path: Path) -> None:
    """缺陷 (e)：跨行点续行。`obj.` 换行 `send()` 现状产 qualifier=""——
    把限定调用冒充成无限定自调用，是危险方向；`obj` 换行 `.send()` 现状产
    <expr>。两种形态都必须回溯到真实接收者 "obj"；多段链仍 <expr>。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.qx;\n"
            "public class Q {\n"
            "    void go() {\n"
            "        obj.\n"
            "        send(1);\n"
            "        recv\n"
            "        .next(2);\n"
            "        a.b.\n"
            "        tail(3);\n"
            "    }\n"
            "}\n"
        ),
    )
    assert calls["go"] == [
        {"callee": "send", "line": 5, "qualifier": "obj", "scope": "method"},
        {"callee": "next", "line": 7, "qualifier": "recv", "scope": "method"},
        {"callee": "tail", "line": 9, "qualifier": "<expr>", "scope": "method"},
    ]


def test_keyword_before_dot_is_expression_receiver(tmp_path: Path) -> None:
    """缺陷 (e) 姊妹构型：接收者是被清理掉的字面量时（`return "cfg".trim()`），
    回溯撞到的 `return` 是语句关键字、不可能是接收者标识符——必须归
    <expr>，不许把关键字当 qualifier 落盘（现状产 qualifier="return"）。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.kw;\n"
            "public class K {\n"
            "    String q() {\n"
            '        return "cfg".trim();\n'
            "    }\n"
            "}\n"
        ),
    )
    assert calls["q"] == [
        {"callee": "trim", "line": 4, "qualifier": "<expr>", "scope": "method"},
    ]


def test_new_type_names_never_recorded_as_calls(tmp_path: Path) -> None:
    """缺陷 (f)：`new` 的类型名不是调用点。跨行 `new\\nFoo()` 与限定
    `new com.a.Foo()` 现状都把 Foo 伪造成普通方法调用（假边/假 gap）——
    必须由状态机抑制；构造实参、数组长度表达式、构造结果上的链式调用
    这些**真实执行**的调用点必须原样保留。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.nf;\n"
            "public class N {\n"
            "    void go() {\n"
            "        Foo f = new\n"
            "        Foo();\n"
            "        Object g = new com.a.Foo();\n"
            "        int[] zs = new int[size()];\n"
            "        Foo h = new Foo(bar());\n"
            "        new Foo().after();\n"
            "    }\n"
            "}\n"
        ),
    )
    assert calls["go"] == [
        {"callee": "size", "line": 7, "qualifier": "", "scope": "method"},
        {"callee": "bar", "line": 8, "qualifier": "", "scope": "method"},
        {"callee": "after", "line": 9, "qualifier": "<expr>", "scope": "method"},
    ]


def test_brace_desync_marks_scope_unknown_not_guessed(tmp_path: Path) -> None:
    """fail-closed 落点：花括号失配（rel_depth 落到负值）后状态机已失去
    位置感——其后调用点 scope 一律 "unknown"（粘滞到方法末），照常记录、
    照常参与解析。判不准就说判不准，但绝不因此丢调用点。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.dy;\n"
            "public class D {\n"
            "    void go() {\n"
            "        x();\n"
            "        } y(); {\n"
            "        z();\n"
            "    }\n"
            "}\n"
        ),
    )
    assert calls["go"] == [
        {"callee": "x", "line": 4, "qualifier": "", "scope": "method"},
        {"callee": "y", "line": 5, "qualifier": "", "scope": "unknown"},
        {"callee": "z", "line": 6, "qualifier": "", "scope": "unknown"},
    ]


def test_scope_and_qualifier_value_domains(tmp_path: Path) -> None:
    """取值域单一来源锁：scope 四值、qualifier 字面量加 <unknown>；域外值
    照旧拒收。（1.4 未合并进 master，域是本分支的 schema 形状决策，不 bump。）"""
    for scope in ("method", "nested_type", "lambda", "unknown"):
        assert _valid_call_scope(scope), scope
    for bad in ("", "weird", "nested", "Method"):
        assert not _valid_call_scope(bad), bad
    for qualifier in ("", "this", "super", "<expr>", "<unknown>", "h"):
        assert _valid_call_qualifier(qualifier), qualifier
    for bad in ("bad token!", "<what>", "a.b"):
        assert not _valid_call_qualifier(bad), bad

    # 消费面同源校验：域外 scope 的 shard 必须被 trace fail-closed 揭穿。
    _, _, loaded = _build_index(
        tmp_path,
        {
            "com/vd/V.java": (
                "package com.vd;\n"
                "\n"
                "public class V {\n"
                "    void go() {\n"
                "        step();\n"
                "    }\n"
                "\n"
                "    void step() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    bad_shard = dict(loaded.shards[0])
    bad_shard["structure"] = {
        "classes": [
            {
                "name": "com.vd.V",
                "path": "com/vd/V.java",
                "methods": [
                    {
                        "name": "go",
                        "arity": 0,
                        "start_line": 4,
                        "end_line": 6,
                        "body_digest": _digest(b"go"),
                        "calls": [
                            {
                                "callee": "step",
                                "line": 5,
                                "qualifier": "",
                                "scope": "nested",
                            }
                        ],
                    },
                    {
                        "name": "step",
                        "arity": 0,
                        "start_line": 8,
                        "end_line": 9,
                        "body_digest": _digest(b"step"),
                        "calls": [],
                    },
                ],
            }
        ]
    }
    forged = LoadedIndex(
        manifest=loaded.manifest,
        shard_locators=loaded.shard_locators,
        coverage=loaded.coverage,
        shards=(bad_shard,),
    )
    with pytest.raises(JadxIndexError) as exc:
        trace_callpath(forged, "com.vd.V#go/0", "com.vd.V#step/0")
    assert exc.value.code == "malformed"


# ---------------------------------------------------------------------------
# 第三轮复审新增契约：record 识别 + 注解使用剔除（红态）与反过杀守卫
# ---------------------------------------------------------------------------


def _scan_structure(
    tmp_path: Path, source: str
) -> dict[str, dict[str, list[dict[str, object]]]]:
    """单文件夹具 → {类限定名: {"name/arity": calls}}（多类形态，含局部类型条目）。"""
    root = tmp_path / "java"
    _java_tree(root, {"com/t/T.java": source})
    scan = scan_java_sources(root, [], lineage=_LINEAGE, limits=Limits())
    assert scan.coverage == "complete"
    table: dict[str, dict[str, list[dict[str, object]]]] = {}
    for cls in scan.structure:
        methods: dict[str, list[dict[str, object]]] = {}
        for method in cls["methods"]:  # type: ignore[index]
            record = dict(method)  # type: ignore[arg-type]
            methods[f"{record['name']}/{record['arity']}"] = [
                dict(c) for c in record["calls"]  # type: ignore[union-attr]
            ]
        table[str(cls["name"])] = methods  # type: ignore[index]
    return table


def test_local_record_body_parity_with_enum(tmp_path: Path) -> None:
    """★红态契约（第三轮复审 P1-b）：局部 `record` 必须与同构局部 `enum`
    完全同构处理。现状 `record` 不在类型识别集里：record 体内调用被标
    scope="method"（把「只在 record 被用到时才执行」冒充成外层方法的直接
    语句，CLI 随之漏发嵌套执行 caveat——这是分支新增 scope 字段的错误值，
    master 无此字段无从错）；且 record 自身的类条目/方法（`T$Rec#r/0`）
    整个不入索引（对照 `T$E#e/0` 在）。两处都要修：record 头（`record 名(
    形参)…{`，形参括号是与 record 作普通标识符区分的判据）与
    class/interface/enum 同待遇。实测对照见 round-3 探针（branch/master 双跑）。"""
    structure = _scan_structure(
        tmp_path,
        (
            "package com.t;\n"
            "public class T {\n"
            "    void outer() {\n"
            "        record Rec(int x) {\n"
            "            void r() {\n"
            "                sinkRec();\n"
            "            }\n"
            "        }\n"
            "        enum E {\n"
            "            A;\n"
            "            void e() {\n"
            "                sinkEnum();\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "\n"
            "    void sinkRec() {\n"
            "    }\n"
            "\n"
            "    void sinkEnum() {\n"
            "    }\n"
            "}\n"
        ),
    )
    # record 体内调用与 enum 同构：外层方法记 nested_type（声明行 r/e 已剔）。
    assert structure["com.t.T"]["outer/0"] == [
        {"callee": "sinkRec", "line": 6, "qualifier": "", "scope": "nested_type"},
        {"callee": "sinkEnum", "line": 12, "qualifier": "", "scope": "nested_type"},
    ]
    # record 类条目与方法双归属：与 enum 完全同构，不许半识别。
    assert set(structure) == {"com.t.T", "com.t.T$Rec", "com.t.T$E"}
    assert structure["com.t.T$Rec"] == {
        "r/0": [{"callee": "sinkRec", "line": 6, "qualifier": "", "scope": "method"}]
    }
    assert structure["com.t.T$E"] == {
        "e/0": [{"callee": "sinkEnum", "line": 12, "qualifier": "", "scope": "method"}]
    }


def test_record_as_plain_identifier_stays_a_call_site(tmp_path: Path) -> None:
    """反过杀守卫（record 识别落地前后都必须绿）：`record` 是上下文关键字，
    dex 世界里完全可以是方法名。`record(1);` 是真实调用点、必须照常入
    calls 且 scope 不受影响——record 头识别必须以「名字 + 形参括号」为判据，
    不许见 `record` 就开类型 scope。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.t;\n"
            "public class T {\n"
            "    void go() {\n"
            "        record(1);\n"
            "        after();\n"
            "    }\n"
            "\n"
            "    void record(int x) {\n"
            "    }\n"
            "\n"
            "    void after() {\n"
            "    }\n"
            "}\n"
        ),
    )
    assert calls["go"] == [
        {"callee": "record", "line": 4, "qualifier": "", "scope": "method"},
        {"callee": "after", "line": 5, "qualifier": "", "scope": "method"},
    ]


def test_annotation_usage_is_not_a_call_site(tmp_path: Path) -> None:
    """★红态契约（第三轮复审 P1-a）：`@Ident(...)` 是注解使用不是调用。
    判据 sound：合法 Java 中 `@ Ident (` 只能是注解使用，绝无调用形态——
    左邻 `@` 即剔，方法注解与形参注解一并覆盖。master 同样记这两条伪边
    （round-3 探针实证），本契约是相对 master 的纯精度改进；残留的
    跨行 abstract 泛型无体声明（左邻 `>`、右邻 `;`）属文档化边界，判据
    不 sound 不强修（round-2 已明令禁用角括号判据）。同体真实调用与
    匿名类外语句必须原样保留。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.t;\n"
            "public class T {\n"
            "    void go() {\n"
            "        Runnable r = new Runnable() {\n"
            "            @Anno(v = 1)\n"
            "            public void run() {\n"
            "                real();\n"
            "            }\n"
            "\n"
            "            public void g(@Size(max = 1) String x) {\n"
            "            }\n"
            "        };\n"
            "        after();\n"
            "    }\n"
            "\n"
            "    void real() {\n"
            "    }\n"
            "\n"
            "    void after() {\n"
            "    }\n"
            "}\n"
        ),
    )
    assert calls["go"] == [
        {"callee": "real", "line": 7, "qualifier": "", "scope": "nested_type"},
        {"callee": "after", "line": 13, "qualifier": "", "scope": "method"},
    ]


def test_qualified_annotation_usage_is_not_a_call_site(tmp_path: Path) -> None:
    """★红态契约（第四轮复审 N2）：限定名注解 `@pkg.Anno(...)` 同样不是调用。
    现状 `is_annotation_site` 只认**直接**左邻 `@`——`@com.x.Anno(` 里 `Anno`
    的左邻是 `.`，仍被记成调用点（qualifier 还会被算成 `<expr>`/包段名）。
    jadx 反混淆输出真实存在该形态（87MB 真样本 `@a.InterfaceC0158a(` 109 处；
    混淆包名 + import 冲突时 jadx 会写限定名）。判据 sound：合法 Java 中
    `@` 后跟点链标识符再开 `(` 只能是注解使用，调用表达式无此形态；点链回溯
    **只服务注解证明**——链头不是 `@` 时不作任何剔除证据（fail-open 保留
    记录），真实限定调用不受影响（见下一条守卫）。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.t;\n"
            "public class T {\n"
            "    void go() {\n"
            "        Runnable r = new Runnable() {\n"
            "            @com.x.Anno(v = 1)\n"
            "            public void run() {\n"
            "                real();\n"
            "            }\n"
            "        };\n"
            "        after();\n"
            "    }\n"
            "\n"
            "    void real() {\n"
            "    }\n"
            "\n"
            "    void after() {\n"
            "    }\n"
            "}\n"
        ),
    )
    assert calls["go"] == [
        {"callee": "real", "line": 7, "qualifier": "", "scope": "nested_type"},
        {"callee": "after", "line": 10, "qualifier": "", "scope": "method"},
    ]


def test_qualified_call_chain_survives_annotation_rule(tmp_path: Path) -> None:
    """反过杀守卫（限定名注解剔除落地前后都必须绿）：`util.log.d(1);` 是真实
    限定调用、`this.self();` 是 this 限定调用——点链回溯发现链头不是 `@` 时
    必须保留记录。注解剔除只许剔「链头左邻是 `@`」的命中，别的一律不动。"""
    calls = _scan_calls(
        tmp_path,
        (
            "package com.t;\n"
            "public class T {\n"
            "    void go() {\n"
            "        util.log.d(1);\n"
            "        this.self();\n"
            "    }\n"
            "\n"
            "    void self() {\n"
            "    }\n"
            "}\n"
        ),
    )
    assert calls["go"] == [
        {"callee": "d", "line": 4, "qualifier": "<expr>", "scope": "method"},
        {"callee": "self", "line": 5, "qualifier": "this", "scope": "method"},
    ]
