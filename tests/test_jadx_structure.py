"""P1-B 结构层：schema 1.1、确定性 bounded 结构提取、发布/加载 fail-closed 校验。

先于实现编写（红态契约）。行号断言基于手工数行的合成 JADX 风格源码——
改 fixture 必须同步重数行号。设计见
docs/superpowers/specs/2026-08-16-p1b-jadx-callpath-design.md。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable

from apkscan.core.jadx_index import (
    CacheMiss,
    DexInput,
    DexLineage,
    DexRole,
    IndexBuildResult,
    IndexBuildState,
    JadxIndexManifest,
    JadxIndexStore,
    Limits,
    LoadedIndex,
    build_key_material,
    derive_index_key,
    scan_java_sources,
    verify_dex_inputs,
)
from apkscan.core.recognition_codec import canonical_json_v1, parse_json_v1

_OPTS = "sha256:" + "a" * 64


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _java_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _lin() -> DexLineage:
    return DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"dex"))


def _make_manifest(tmp_path: Path) -> JadxIndexManifest:
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
    material = build_key_material(lineage, "1.5.2", _OPTS)
    return JadxIndexManifest(
        index_key=key,
        key_material=material,
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )


APP_JAVA = (
    "package com.a;\n"
    "\n"
    "public class App {\n"
    "    public void onCreate() {\n"
    "        Helper h = new Helper();\n"
    '        h.fetch("https://cfg.example/api");\n'
    "    }\n"
    "\n"
    "    public void unused(int x) {\n"
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


# ---------------------------------------------------------------------------
# schema 演进锁：已并入单一真源，本文件不再钉版本字面量
# ---------------------------------------------------------------------------
# 本文件曾有自己的 `assert INDEX_SCHEMA_VERSION == "X.Y"` 演进锁，与
# test_jadx_resolution_migration.py 的锁重复钉同一常量——1.4→1.5、1.5→1.6
# 两轮 bump 都恰好漏掉这里（红是能红，但每轮都得全仓库考古才找齐钉点）。
# 锁已收敛为单一真源：
#   test_jadx_resolution_migration.py::test_index_schema_version_bumped_to_1_6
# （含完整版本演进史与 bump 检查单）。


# ---------------------------------------------------------------------------
# 结构提取：类 / 方法 / 调用点
# ---------------------------------------------------------------------------


def _classes_of(structure: tuple, name: str) -> dict:
    match = [c for c in structure if c["name"] == name]
    assert len(match) == 1, f"class {name} not found exactly once: {structure!r}"
    return dict(match[0])


def test_extracts_classes_methods_and_call_sites(tmp_path: Path) -> None:
    src = tmp_path / "java"
    _java_tree(src, {"com/a/App.java": APP_JAVA})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())
    assert result.coverage == "complete"
    app = _classes_of(result.structure, "com.a.App")
    assert app["path"] == "com/a/App.java"
    assert set(app.keys()) == {"name", "path", "methods"}

    methods = [dict(m) for m in app["methods"]]
    assert [(m["name"], m["arity"], m["start_line"], m["end_line"]) for m in methods] == [
        ("onCreate", 0, 4, 7),
        ("unused", 1, 9, 10),
    ]
    for m in methods:
        assert set(m.keys()) == {
            "name",
            "arity",
            "start_line",
            "end_line",
            "body_digest",
            "calls",
        }
        assert m["body_digest"].startswith("sha256:") and len(m["body_digest"]) == 71

    # onCreate：只有 fetch 一个调用点；``new Helper(...)`` 不是 P1-B 的边。
    assert [dict(c) for c in methods[0]["calls"]] == [
        {"callee": "fetch", "line": 6, "qualifier": "h", "scope": "method"}
    ]
    assert list(methods[1]["calls"]) == []


def test_extracts_nested_class_with_dollar_name(tmp_path: Path) -> None:
    outer = (
        "package com.d;\n"
        "\n"
        "public class Outer {\n"
        "    public void go() {\n"
        "        run();\n"
        "    }\n"
        "\n"
        "    class Inner {\n"
        "        void run() {\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    src = tmp_path / "java"
    _java_tree(src, {"com/d/Outer.java": outer})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())
    names = [c["name"] for c in result.structure]
    assert names == ["com.d.Outer", "com.d.Outer$Inner"]
    outer_cls = _classes_of(result.structure, "com.d.Outer")
    assert [(m["name"], m["start_line"], m["end_line"]) for m in outer_cls["methods"]] == [
        ("go", 4, 6)
    ]
    inner_cls = _classes_of(result.structure, "com.d.Outer$Inner")
    assert [(m["name"], m["start_line"], m["end_line"]) for m in inner_cls["methods"]] == [
        ("run", 9, 10)
    ]


def test_constructor_recorded_as_init(tmp_path: Path) -> None:
    boot = (
        "package com.e;\n"
        "\n"
        "public class Boot {\n"
        "    public Boot(int mode) {\n"
        "        init(mode);\n"
        "    }\n"
        "\n"
        "    private void init(int mode) {\n"
        "    }\n"
        "}\n"
    )
    src = tmp_path / "java"
    _java_tree(src, {"com/e/Boot.java": boot})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())
    boot_cls = _classes_of(result.structure, "com.e.Boot")
    assert [(m["name"], m["arity"], m["start_line"], m["end_line"]) for m in boot_cls["methods"]] == [
        ("<init>", 1, 4, 6),
        ("init", 1, 8, 9),
    ]
    assert [dict(c) for c in boot_cls["methods"][0]["calls"]] == [
        {"callee": "init", "line": 5, "qualifier": "", "scope": "method"}
    ]


def test_keywords_and_string_literals_are_not_call_sites(tmp_path: Path) -> None:
    guard = (
        "package com.f;\n"
        "\n"
        "public class Guard {\n"
        "    public void check(int x) {\n"
        "        if (x > 0) {\n"
        '            log("fake(1) call");\n'
        "        }\n"
        "        return;\n"
        "    }\n"
        "\n"
        "    private void log(String s) {\n"
        "    }\n"
        "}\n"
    )
    src = tmp_path / "java"
    _java_tree(src, {"com/f/Guard.java": guard})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())
    guard_cls = _classes_of(result.structure, "com.f.Guard")
    check = dict(guard_cls["methods"][0])
    assert check["name"] == "check"
    callees = [dict(c)["callee"] for c in check["calls"]]
    assert callees == ["log"]  # 无 if / return / fake（字符串字面量内不算调用点）


def test_body_digest_is_whitespace_normalized(tmp_path: Path) -> None:
    """同名同体但缩进不同 → 同 digest；语句变了 → digest 变。"""
    p_java = (
        "package com.g;\n"
        "\n"
        "public class P {\n"
        "    void ping() {\n"
        "        state = 1;\n"
        "    }\n"
        "}\n"
    )
    q_java = (
        "package com.g;\n"
        "\n"
        "public class Q {\n"
        "            void ping() {\n"
        "                state = 1;\n"
        "            }\n"
        "}\n"
    )
    r_java = (
        "package com.g;\n"
        "\n"
        "public class R {\n"
        "    void ping() {\n"
        "        state = 2;\n"
        "    }\n"
        "}\n"
    )
    src = tmp_path / "java"
    _java_tree(src, {"com/g/P.java": p_java, "com/g/Q.java": q_java, "com/g/R.java": r_java})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())

    def _ping_digest(cls_name: str) -> str:
        cls = _classes_of(result.structure, cls_name)
        (method,) = [dict(m) for m in cls["methods"]]
        assert method["name"] == "ping"
        return str(method["body_digest"])

    assert _ping_digest("com.g.P") == _ping_digest("com.g.Q")
    assert _ping_digest("com.g.P") != _ping_digest("com.g.R")


def test_structure_is_deterministic_across_creation_order(tmp_path: Path) -> None:
    files = {"com/a/App.java": APP_JAVA, "com/b/Helper.java": HELPER_JAVA}
    a_root = tmp_path / "a"
    b_root = tmp_path / "b"
    _java_tree(a_root, files)
    _java_tree(b_root, dict(reversed(list(files.items()))))
    ra = scan_java_sources(a_root, [], lineage=_lin(), limits=Limits())
    rb = scan_java_sources(b_root, [], lineage=_lin(), limits=Limits())
    assert ra.structure == rb.structure
    assert canonical_json_v1(list(ra.structure)) == canonical_json_v1(list(rb.structure))
    # 类名升序（canonical 序，load 校验同款）。
    names = [c["name"] for c in ra.structure]
    assert names == sorted(names)


def test_structure_limits_mark_partial(tmp_path: Path) -> None:
    two_methods = (
        "package com.h;\n"
        "\n"
        "public class Two {\n"
        "    void first() {\n"
        "    }\n"
        "\n"
        "    void second() {\n"
        "    }\n"
        "}\n"
    )
    src = tmp_path / "java"
    _java_tree(src, {"com/h/Two.java": two_methods})
    limited = scan_java_sources(
        src, [], lineage=_lin(), limits=Limits(max_methods_per_class=1)
    )
    assert limited.structure_limit_hit is True
    assert limited.coverage == "partial"
    two_cls = _classes_of(limited.structure, "com.h.Two")
    assert [m["name"] for m in two_cls["methods"]] == ["first"]


# ---------------------------------------------------------------------------
# 发布 / 加载：structure 随 shard 落盘并被 fail-closed 校验
# ---------------------------------------------------------------------------


def _built_with_structure(tmp_path: Path) -> tuple[JadxIndexStore, JadxIndexManifest]:
    manifest = _make_manifest(tmp_path)
    src = tmp_path / "java"
    _java_tree(src, {"com/a/App.java": APP_JAVA, "com/b/Helper.java": HELPER_JAVA})
    scan = scan_java_sources(src, [], lineage=manifest.dex_lineage[0], limits=Limits())
    assert len(scan.structure) == 2
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(tmp_path / "src", manifest, scan=scan)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.BUILT
    return store, manifest


def test_structure_roundtrips_through_store(tmp_path: Path) -> None:
    store, manifest = _built_with_structure(tmp_path)
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    (shard,) = loaded.shards
    structure = shard["structure"]
    assert isinstance(structure, dict) and set(structure) == {"classes"}
    names = [c["name"] for c in structure["classes"]]
    assert names == ["com.a.App", "com.b.Helper"]


def _rewrite_shard(
    tmp_path: Path,
    manifest: JadxIndexManifest,
    mutate: Callable[[dict], None],
) -> None:
    """篡改 shard 内容并把 manifest 的 shard digest / aggregate 补齐——
    让加载走到结构校验，而不是先被 shard_digest_mismatch 拦下。"""
    index_dir = tmp_path / "cache" / manifest.index_key
    shard_path = next((index_dir / "shards").glob("*.json"))
    shard_value = parse_json_v1(shard_path.read_bytes().decode("utf-8"))
    assert isinstance(shard_value, dict)
    mutate(shard_value)
    new_bytes = canonical_json_v1(shard_value)
    shard_path.unlink()
    shard_path.write_bytes(new_bytes)

    manifest_path = index_dir / "manifest.json"
    manifest_value = parse_json_v1(manifest_path.read_bytes().decode("utf-8"))
    assert isinstance(manifest_value, dict)
    new_digest = hashlib.sha256(new_bytes).hexdigest()
    refs = manifest_value["shard_refs"]
    assert isinstance(refs, list) and len(refs) == 1
    refs[0]["digest"] = new_digest
    manifest_value["aggregate_digest"] = hashlib.sha256(
        "".join(sorted(ref["digest"] for ref in refs)).encode("ascii")
    ).hexdigest()
    manifest_path.unlink()
    manifest_path.write_bytes(canonical_json_v1(manifest_value))


def test_load_rejects_missing_structure_key(tmp_path: Path) -> None:
    store, manifest = _built_with_structure(tmp_path)

    def _drop(shard: dict) -> None:
        del shard["structure"]

    _rewrite_shard(tmp_path, manifest, _drop)
    miss = store.load_index(manifest.index_key)
    assert isinstance(miss, CacheMiss) and miss.reason == "malformed"


def test_load_rejects_duplicate_class_identity(tmp_path: Path) -> None:
    """完全相同的 (name, path) 重复仍是形状违规——身份放宽到 path 级不放走精确重复。"""
    store, manifest = _built_with_structure(tmp_path)

    def _dup(shard: dict) -> None:
        classes = shard["structure"]["classes"]
        classes.append(dict(classes[0]))
        classes.sort(key=lambda c: (str(c["name"]), str(c["path"])))

    _rewrite_shard(tmp_path, manifest, _dup)
    miss = store.load_index(manifest.index_key)
    assert isinstance(miss, CacheMiss) and miss.reason == "duplicate_structure"


def test_load_rejects_unsorted_classes(tmp_path: Path) -> None:
    store, manifest = _built_with_structure(tmp_path)

    def _swap(shard: dict) -> None:
        classes = shard["structure"]["classes"]
        classes.reverse()

    _rewrite_shard(tmp_path, manifest, _swap)
    miss = store.load_index(manifest.index_key)
    assert isinstance(miss, CacheMiss) and miss.reason == "malformed"


def test_load_rejects_class_path_outside_files(tmp_path: Path) -> None:
    store, manifest = _built_with_structure(tmp_path)

    def _reroute(shard: dict) -> None:
        shard["structure"]["classes"][0]["path"] = "com/zzz/Nope.java"

    _rewrite_shard(tmp_path, manifest, _reroute)
    miss = store.load_index(manifest.index_key)
    assert isinstance(miss, CacheMiss) and miss.reason == "malformed"


def test_load_rejects_legacy_1_0_manifest_as_schema_drift(tmp_path: Path) -> None:
    """1.0 工件的回归锁：既有漂移机制必须把旧 schema 拒成可重建的 CacheMiss。"""
    store, manifest = _built_with_structure(tmp_path)
    manifest_path = tmp_path / "cache" / manifest.index_key / "manifest.json"
    value = parse_json_v1(manifest_path.read_bytes().decode("utf-8"))
    assert isinstance(value, dict)
    value["index_schema_version"] = "1.0"
    value["key_material"]["index_schema_version"] = "1.0"
    manifest_path.unlink()
    manifest_path.write_bytes(canonical_json_v1(value))
    miss = store.load_index(manifest.index_key)
    assert isinstance(miss, CacheMiss) and miss.reason == "schema_drift"


# ---------------------------------------------------------------------------
# 混淆形态（schema 1.2 身份修复锁）：不同路径同名类必须可发布可加载
# ---------------------------------------------------------------------------

#: 脱壳 dump 常见形态：反编译产物无 package 声明，混淆名跨目录塌缩成同一简单名。
OBF_RUN_JAVA = "class a {\n    void run() {\n        go();\n    }\n}\n"
OBF_GO_JAVA = "class a {\n    void go() {\n    }\n}\n"


def _built_with_duplicate_names(
    tmp_path: Path,
) -> tuple[JadxIndexStore, JadxIndexManifest]:
    manifest = _make_manifest(tmp_path)
    src = tmp_path / "java"
    _java_tree(src, {"p000/a.java": OBF_RUN_JAVA, "p001/a.java": OBF_GO_JAVA})
    scan = scan_java_sources(src, [], lineage=manifest.dex_lineage[0], limits=Limits())
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(tmp_path / "src", manifest, scan=scan)
    assert isinstance(result, IndexBuildResult)
    assert result.state == IndexBuildState.BUILT, result.diagnostics
    return store, manifest


def test_build_accepts_duplicate_simple_names_without_package(tmp_path: Path) -> None:
    """★真样本混淆锁（2026-08-16 e2e 实证）：不同路径同名类必须 BUILT 且可往返。

    旧身份（仅 name）让带脱壳 dump 的真实混淆样本索引整体 FAILED——
    发布闸门与 load 校验的身份都必须是 (name, path)。"""
    store, manifest = _built_with_duplicate_names(tmp_path)
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    (shard,) = loaded.shards
    structure = shard["structure"]
    assert isinstance(structure, dict)
    assert [(c["name"], c["path"]) for c in structure["classes"]] == [
        ("a", "p000/a.java"),
        ("a", "p001/a.java"),
    ]


def test_build_accepts_duplicate_qualified_names_across_paths(tmp_path: Path) -> None:
    """多 dex 脱壳 dump 的重复类形态：同限定名不同相对路径 → BUILT。"""
    manifest = _make_manifest(tmp_path)
    src = tmp_path / "java"
    _java_tree(
        src,
        {
            "com/x/a.java": "package com.x;\n\nclass a {\n    void run() {\n    }\n}\n",
            "dup/com/x/a.java": "package com.x;\n\nclass a {\n    void go() {\n    }\n}\n",
        },
    )
    scan = scan_java_sources(src, [], lineage=manifest.dex_lineage[0], limits=Limits())
    assert [(c["name"], c["path"]) for c in scan.structure] == [
        ("com.x.a", "com/x/a.java"),
        ("com.x.a", "dup/com/x/a.java"),
    ]
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(tmp_path / "src", manifest, scan=scan)
    assert isinstance(result, IndexBuildResult)
    assert result.state == IndexBuildState.BUILT, result.diagnostics


def test_build_deduplicates_same_identity_in_one_file_as_partial(tmp_path: Path) -> None:
    """扫描层保留首个同身份声明并降级；存储层仍拒绝外部注入的重复结构。"""
    manifest = _make_manifest(tmp_path)
    src = tmp_path / "java"
    _java_tree(src, {"p000/a.java": "class a {\n}\n\nclass a {\n}\n"})
    scan = scan_java_sources(src, [], lineage=manifest.dex_lineage[0], limits=Limits())
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(tmp_path / "src", manifest, scan=scan)
    assert isinstance(result, IndexBuildResult)
    assert result.state == IndexBuildState.BUILT
    assert result.coverage == "partial"
    assert [(item["name"], item["path"]) for item in scan.structure] == [
        ("a", "p000/a.java")
    ]


def test_load_rejects_same_name_paths_out_of_order(tmp_path: Path) -> None:
    """同名类按 path 二级升序是 canonical 序的一部分；失序 → malformed。"""
    store, manifest = _built_with_duplicate_names(tmp_path)

    def _swap(shard: dict) -> None:
        shard["structure"]["classes"].reverse()

    _rewrite_shard(tmp_path, manifest, _swap)
    miss = store.load_index(manifest.index_key)
    assert isinstance(miss, CacheMiss) and miss.reason == "malformed"


# ---------------------------------------------------------------------------
# codex 复审补锁：注释/字符字面量的括号、截断方法、签名形态
# ---------------------------------------------------------------------------


def test_braces_in_comments_and_char_literals_do_not_break_spans(tmp_path: Path) -> None:
    """★JADX 输出满是 /* renamed from: */ 注释——注释与字符字面量里的括号绝不参与配平。"""
    noisy = (
        "package com.i;\n"
        "\n"
        "/* renamed from: a {\n"
        " * } */\n"
        "public class Noisy {\n"
        "    void f() {\n"
        "        char c = '}';\n"
        "        // { open in line comment\n"
        "        step();\n"
        "    }\n"
        "\n"
        "    void step() {\n"
        "    }\n"
        "}\n"
    )
    src = tmp_path / "java"
    _java_tree(src, {"com/i/Noisy.java": noisy})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())
    cls = _classes_of(result.structure, "com.i.Noisy")
    assert [(m["name"], m["start_line"], m["end_line"]) for m in cls["methods"]] == [
        ("f", 6, 10),
        ("step", 12, 13),
    ]
    f_method = dict(cls["methods"][0])
    assert [dict(c) for c in f_method["calls"]] == [
        {"callee": "step", "line": 9, "qualifier": "", "scope": "method"}
    ]


def test_truncated_method_without_closing_brace_locked(tmp_path: Path) -> None:
    """闭括号缺失（截断/畸形文件）→ end_line 退回签名行、calls 为空——锁死降级形态。"""
    cut = "package com.j;\n\npublic class Cut {\n    void f() {\n        step(\n"
    src = tmp_path / "java"
    _java_tree(src, {"com/j/Cut.java": cut})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())
    cls = _classes_of(result.structure, "com.j.Cut")
    (method,) = [dict(m) for m in cls["methods"]]
    assert method["name"] == "f"
    assert method["end_line"] == method["start_line"] == 4
    assert list(method["calls"]) == []


def test_generic_array_returns_and_annotations(tmp_path: Path) -> None:
    generic = (
        "package com.k;\n"
        "\n"
        "public class G {\n"
        "    @Override\n"
        "    public Map<String, String> pairs(int n) {\n"
        "        return null;\n"
        "    }\n"
        "\n"
        "    int[] arr() {\n"
        "        return null;\n"
        "    }\n"
        "}\n"
    )
    src = tmp_path / "java"
    _java_tree(src, {"com/k/G.java": generic})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())
    cls = _classes_of(result.structure, "com.k.G")
    assert [(m["name"], m["arity"], m["start_line"], m["end_line"]) for m in cls["methods"]] == [
        ("pairs", 1, 5, 7),
        ("arr", 0, 9, 11),
    ]


def test_multiline_signature_skipped_not_fatal(tmp_path: Path) -> None:
    """跨行签名是文档化的启发式盲区：跳过该方法、不崩溃、不影响其它方法。"""
    broken = (
        "package com.l;\n"
        "\n"
        "public class M {\n"
        "    void ok() {\n"
        "    }\n"
        "\n"
        "    void broken(\n"
        "        int a) {\n"
        "    }\n"
        "}\n"
    )
    src = tmp_path / "java"
    _java_tree(src, {"com/l/M.java": broken})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())
    cls = _classes_of(result.structure, "com.l.M")
    assert [m["name"] for m in cls["methods"]] == ["ok"]


def test_escaped_quotes_with_braces_do_not_break_spans(tmp_path: Path) -> None:
    """转义引号里的括号（"\\"}{" 与 '\''）绝不参与配平。"""
    esc = (
        "package com.o;\n"
        "\n"
        "public class Esc {\n"
        "    void f() {\n"
        '        String s = "\\"}{";\n'
        "        char q = '\\'';\n"
        "        step();\n"
        "    }\n"
        "\n"
        "    void step() {\n"
        "    }\n"
        "}\n"
    )
    src = tmp_path / "java"
    _java_tree(src, {"com/o/Esc.java": esc})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())
    cls = _classes_of(result.structure, "com.o.Esc")
    assert [(m["name"], m["start_line"], m["end_line"]) for m in cls["methods"]] == [
        ("f", 4, 8),
        ("step", 10, 11),
    ]
    assert [dict(c) for c in dict(cls["methods"][0])["calls"]] == [
        {"callee": "step", "line": 7, "qualifier": "", "scope": "method"}
    ]


def test_sanitizer_preserves_line_count() -> None:
    """★清理前后行数恒等是行号定位的地基契约——含跨行块注释与未闭合字符串。"""
    from apkscan.core.jadx_index import _sanitize_java_source

    samples = [
        "a\n/* x\n y */\nint c = 1; // t\n",
        '"unterminated\nnext line\n',
        "/* never closed\nstill comment\n",
        "",
        "no newline at all",
    ]
    for text in samples:
        assert len(_sanitize_java_source(text)) == len(text.splitlines())


def test_body_digest_uses_original_lines_not_sanitized(tmp_path: Path) -> None:
    """★digest 基于原始行：体内注释参与摘要——若误用清理行，注释会被抹平导致同 digest。"""
    with_comment = (
        "package com.q1;\n"
        "\n"
        "public class W {\n"
        "    void f() {\n"
        "        // marker {\n"
        "        x = 1;\n"
        "    }\n"
        "}\n"
    )
    without_comment = (
        "package com.q2;\n"
        "\n"
        "public class V {\n"
        "    void f() {\n"
        "        x = 1;\n"
        "    }\n"
        "}\n"
    )
    src = tmp_path / "java"
    _java_tree(src, {"com/q1/W.java": with_comment, "com/q2/V.java": without_comment})
    result = scan_java_sources(src, [], lineage=_lin(), limits=Limits())
    digest_w = dict(_classes_of(result.structure, "com.q1.W")["methods"][0])["body_digest"]
    digest_v = dict(_classes_of(result.structure, "com.q2.V")["methods"][0])["body_digest"]
    assert digest_w != digest_v
