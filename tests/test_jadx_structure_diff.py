"""P1-C 结构 diff：三分类、重载多重集、absence_claimable 封锁、fail-closed、确定性。

先于实现编写（红态契约；导入 apkscan.core.jadx_structure_diff 在实现落地前收集即失败）。
设计见本地 docs/superpowers/specs/2026-08-16-p1c-structure-diff-design.md（不入 git）。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from apkscan.core.jadx_index import (
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
from apkscan.core.jadx_structure_diff import (
    ChangedMethod,
    MethodRegion,
    StructuralDiff,
    diff_index_structure,
)

_OPTS = "sha256:" + "a" * 64


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _java_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _build_index(
    tmp_path: Path,
    tag: str,
    files: dict[str, str],
    *,
    limits: Limits | None = None,
) -> LoadedIndex:
    """走真入口（store.build_index + load_index）构建带结构的单 dex 索引。"""
    base = tmp_path / tag
    src = base / "src"
    src.mkdir(parents=True, exist_ok=True)
    payload = f"dex-{tag}".encode()
    (src / "classes.dex").write_bytes(payload)
    inputs = [
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="classes.dex",
            relative_path="classes.dex",
            declared_digest=_digest(payload),
        )
    ]
    lineage = verify_dex_inputs(src, inputs)
    manifest = JadxIndexManifest(
        index_key=derive_index_key(lineage, "1.5.2", _OPTS),
        key_material=build_key_material(lineage, "1.5.2", _OPTS),
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )
    out = base / "out"
    _java_tree(out, files)
    scan = scan_java_sources(out, [], lineage=lineage[0], limits=limits or Limits())
    store = JadxIndexStore(base / "cache")
    result = store.build_index(src, manifest, scan=scan)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.BUILT
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    return loaded


W_LEFT = (
    "package com.a;\n"
    "\n"
    "public class W {\n"
    "    void f() {\n"
    "        x = 1;\n"
    "    }\n"
    "\n"
    "    void g() {\n"
    "    }\n"
    "\n"
    "    void same() {\n"
    "        y = 9;\n"
    "    }\n"
    "}\n"
)

W_RIGHT = (
    "package com.a;\n"
    "\n"
    "public class W {\n"
    "    void f() {\n"
    "        x = 2;\n"
    "    }\n"
    "\n"
    "    void h() {\n"
    "    }\n"
    "\n"
    "    void same() {\n"
    "        y = 9;\n"
    "    }\n"
    "}\n"
)

B_JAVA = "package com.b;\n\npublic class B {\n    void only() {\n    }\n}\n"
C_JAVA = "package com.c;\n\npublic class C {\n    void fresh() {\n    }\n}\n"


# ---------------------------------------------------------------------------
# 三分类语义
# ---------------------------------------------------------------------------


def test_identical_indexes_all_unchanged(tmp_path: Path) -> None:
    loaded = _build_index(tmp_path, "l", {"com/a/W.java": W_LEFT, "com/b/B.java": B_JAVA})
    diff = diff_index_structure(loaded, loaded)
    assert isinstance(diff, StructuralDiff)
    assert diff.added_classes == () and diff.removed_classes == ()
    assert diff.added_methods == () and diff.removed_methods == ()
    assert diff.changed_methods == ()
    assert diff.unchanged_methods == 4  # W#f/g/same + B#only
    assert diff.left_coverage == diff.right_coverage == "complete"
    assert diff.absence_claimable is True


def test_added_removed_changed_three_way(tmp_path: Path) -> None:
    """★核心断言：类级增删、方法级增删、同身份不同 digest 的 changed 各归其位。"""
    left = _build_index(tmp_path, "l", {"com/a/W.java": W_LEFT, "com/b/B.java": B_JAVA})
    right = _build_index(tmp_path, "r", {"com/a/W.java": W_RIGHT, "com/c/C.java": C_JAVA})
    diff = diff_index_structure(left, right)

    assert diff.added_classes == ("com.c.C",)
    assert diff.removed_classes == ("com.b.B",)

    assert [(m.class_name, m.method) for m in diff.added_methods] == [("com.a.W", "h/0")]
    assert [(m.class_name, m.method) for m in diff.removed_methods] == [("com.a.W", "g/0")]
    added = diff.added_methods[0]
    assert added.path == "com/a/W.java" and added.start_line == 8 and added.end_line == 9
    assert added.body_digest.startswith("sha256:")

    (changed,) = diff.changed_methods
    assert isinstance(changed, ChangedMethod)
    assert (changed.class_name, changed.method) == ("com.a.W", "f/0")
    (left_region,) = changed.left_regions
    (right_region,) = changed.right_regions
    assert left_region.body_digest != right_region.body_digest

    assert diff.unchanged_methods == 1  # W#same
    assert diff.absence_claimable is True


def test_class_level_add_remove_not_double_counted(tmp_path: Path) -> None:
    """类级 added/removed 的方法不再进 method 级列表。"""
    left = _build_index(tmp_path, "l", {"com/b/B.java": B_JAVA})
    right = _build_index(tmp_path, "r", {"com/c/C.java": C_JAVA})
    diff = diff_index_structure(left, right)
    assert diff.added_classes == ("com.c.C",) and diff.removed_classes == ("com.b.B",)
    assert diff.added_methods == () and diff.removed_methods == ()
    assert diff.changed_methods == () and diff.unchanged_methods == 0


def test_overload_multiset_comparison(tmp_path: Path) -> None:
    """同身份多声明按 body_digest 多重集比较；不等时两侧 region 全列。"""
    o_left = (
        "package com.n;\n"
        "\n"
        "public class O {\n"
        "    void go(int x) {\n"
        "        a = 1;\n"
        "    }\n"
        "\n"
        "    void go(String s) {\n"
        "        b = 2;\n"
        "    }\n"
        "}\n"
    )
    o_right = o_left.replace("b = 2;", "b = 3;")
    left = _build_index(tmp_path, "l", {"com/n/O.java": o_left})
    right = _build_index(tmp_path, "r", {"com/n/O.java": o_right})
    diff = diff_index_structure(left, right)
    (changed,) = diff.changed_methods
    assert (changed.class_name, changed.method) == ("com.n.O", "go/1")
    assert len(changed.left_regions) == 2 and len(changed.right_regions) == 2
    assert diff.unchanged_methods == 0

    # 多重集相等（即使声明顺序/行号有别）→ unchanged。
    same = diff_index_structure(left, left)
    assert same.changed_methods == () and same.unchanged_methods == 1


# ---------------------------------------------------------------------------
# absence_claimable 封锁
# ---------------------------------------------------------------------------


def test_partial_coverage_blocks_absence_claims(tmp_path: Path) -> None:
    """★任一侧 partial → absence_claimable=False；观察到的差异仍如实列出。"""
    left = _build_index(
        tmp_path,
        "l",
        {"com/a/W.java": W_LEFT, "com/b/B.java": B_JAVA},
        limits=Limits(max_files=1),  # 只扫到一个文件 → partial
    )
    right = _build_index(tmp_path, "r", {"com/a/W.java": W_RIGHT, "com/c/C.java": C_JAVA})
    assert left.coverage == "partial"
    diff = diff_index_structure(left, right)
    assert diff.left_coverage == "partial" and diff.right_coverage == "complete"
    assert diff.absence_claimable is False
    # 两侧都观察到的差异（如 changed）不受封锁影响地列出。
    assert diff.added_classes or diff.removed_classes or diff.changed_methods


# ---------------------------------------------------------------------------
# fail-closed 与确定性
# ---------------------------------------------------------------------------


def test_malformed_structure_fail_closed(tmp_path: Path) -> None:
    loaded = _build_index(tmp_path, "l", {"com/b/B.java": B_JAVA})
    bad_shard = dict(loaded.shards[0])
    bad_shard["structure"] = {"classes": [{"name": "com.x.Bad"}]}  # 缺 path/methods
    forged = LoadedIndex(
        manifest=loaded.manifest,
        shard_locators=loaded.shard_locators,
        coverage=loaded.coverage,
        shards=(bad_shard,),
    )
    with pytest.raises(JadxIndexError) as exc:
        diff_index_structure(forged, loaded)
    assert exc.value.code == "malformed"


def test_cross_shard_duplicate_class_rejected(tmp_path: Path) -> None:
    """单侧索引内跨 shard 重复类 → duplicate_structure（与 trace_callpath 同语义）。"""
    loaded = _build_index(tmp_path, "l", {"com/b/B.java": B_JAVA})
    (shard,) = loaded.shards
    forged = LoadedIndex(
        manifest=loaded.manifest,
        shard_locators=loaded.shard_locators + loaded.shard_locators,
        coverage=loaded.coverage,
        shards=(shard, dict(shard)),  # 同一类出现在两个 shard
    )
    with pytest.raises(JadxIndexError) as exc:
        diff_index_structure(forged, loaded)
    assert exc.value.code == "duplicate_structure"


def test_diff_independent_of_shard_order(tmp_path: Path) -> None:
    left = _build_index(tmp_path, "l", {"com/a/W.java": W_LEFT, "com/b/B.java": B_JAVA})
    right = _build_index(tmp_path, "r", {"com/a/W.java": W_RIGHT, "com/c/C.java": C_JAVA})
    reversed_left = LoadedIndex(
        manifest=left.manifest,
        shard_locators=tuple(reversed(left.shard_locators)),
        coverage=left.coverage,
        shards=tuple(reversed(left.shards)),
    )
    assert diff_index_structure(left, right) == diff_index_structure(reversed_left, right)


# ---------------------------------------------------------------------------
# MethodRegion 契约
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"path": "/abs/W.java"},
        {"start_line": 0},
        {"end_line": 3},  # < start_line
        {"body_digest": "md5:" + "a" * 64},
        {"class_name": ""},
    ],
)
def test_method_region_validation(overrides: dict) -> None:
    base: dict[str, object] = {
        "class_name": "com.a.W",
        "method": "f/0",
        "path": "com/a/W.java",
        "start_line": 4,
        "end_line": 6,
        "body_digest": _digest(b"body"),
    }
    with pytest.raises(JadxIndexError):
        MethodRegion(**{**base, **overrides})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# codex 复审补锁：与 load 侧同强度的 fail-closed、多重集边界
# ---------------------------------------------------------------------------


def _forge(loaded: LoadedIndex, mutate) -> LoadedIndex:  # type: ignore[no-untyped-def]
    import copy

    shard = copy.deepcopy(dict(loaded.shards[0]))
    mutate(shard)
    return LoadedIndex(
        manifest=loaded.manifest,
        shard_locators=loaded.shard_locators,
        coverage=loaded.coverage,
        shards=(shard,),
    )


def test_same_shard_duplicate_class_rejected(tmp_path: Path) -> None:
    loaded = _build_index(tmp_path, "l", {"com/b/B.java": B_JAVA})

    def _dup(shard: dict) -> None:
        classes = shard["structure"]["classes"]
        classes.append(copy_class := dict(classes[0]))
        assert copy_class["name"] == classes[0]["name"]

    forged = _forge(loaded, _dup)
    with pytest.raises(JadxIndexError) as exc:
        diff_index_structure(forged, loaded)
    assert exc.value.code == "duplicate_structure"


def test_duplicate_method_triple_rejected(tmp_path: Path) -> None:
    loaded = _build_index(tmp_path, "l", {"com/b/B.java": B_JAVA})

    def _dup(shard: dict) -> None:
        methods = shard["structure"]["classes"][0]["methods"]
        methods.append(dict(methods[0]))

    forged = _forge(loaded, _dup)
    with pytest.raises(JadxIndexError) as exc:
        diff_index_structure(forged, loaded)
    assert exc.value.code == "duplicate_structure"


def test_bad_class_name_and_disorder_rejected(tmp_path: Path) -> None:
    loaded = _build_index(tmp_path, "l", {"com/b/B.java": B_JAVA})

    def _bad_name(shard: dict) -> None:
        shard["structure"]["classes"][0]["name"] = "com..Bad"

    with pytest.raises(JadxIndexError) as exc:
        diff_index_structure(_forge(loaded, _bad_name), loaded)
    assert exc.value.code == "malformed"

    def _disorder(shard: dict) -> None:
        first = shard["structure"]["classes"][0]
        earlier = dict(first)
        earlier["name"] = "aaa.First"
        shard["structure"]["classes"] = [first, earlier]  # 降序 → 乱序

    with pytest.raises(JadxIndexError) as exc:
        diff_index_structure(_forge(loaded, _disorder), loaded)
    assert exc.value.code == "malformed"


def test_class_path_outside_files_rejected(tmp_path: Path) -> None:
    loaded = _build_index(tmp_path, "l", {"com/b/B.java": B_JAVA})

    def _reroute(shard: dict) -> None:
        shard["structure"]["classes"][0]["path"] = "com/zzz/N.java"

    with pytest.raises(JadxIndexError) as exc:
        diff_index_structure(_forge(loaded, _reroute), loaded)
    assert exc.value.code == "malformed"


def test_multiset_equal_digests_different_lines_unchanged(tmp_path: Path) -> None:
    """digest 多重集相同（声明顺序/行号不同）→ unchanged；[A,A] vs [A,B] → changed。"""
    two_same_sig = (
        "package com.r;\n"
        "\n"
        "public class T {\n"
        "    void go(int x) {\n"
        "        k = 1;\n"
        "    }\n"
        "\n"
        "    void go(String s) {\n"
        "        k = 1;\n"
        "    }\n"
        "}\n"
    )
    # 右侧对调两个声明的顺序（行号变、digest 多重集不变）。
    swapped = (
        "package com.r;\n"
        "\n"
        "public class T {\n"
        "    void go(String s) {\n"
        "        k = 1;\n"
        "    }\n"
        "\n"
        "    void go(int x) {\n"
        "        k = 1;\n"
        "    }\n"
        "}\n"
    )
    left = _build_index(tmp_path, "l", {"com/r/T.java": two_same_sig})
    right = _build_index(tmp_path, "r", {"com/r/T.java": swapped})
    diff = diff_index_structure(left, right)
    assert diff.changed_methods == () and diff.unchanged_methods == 1

    # [A,A] vs [A,B]：完全同签名的两个声明，一侧改其中一个 body → changed。
    dup_decl = (
        "package com.s;\n"
        "\n"
        "public class U {\n"
        "    void go(int x) {\n"
        "        k = 1;\n"
        "    }\n"
        "\n"
        "    void go(int x) {\n"
        "        k = 1;\n"
        "    }\n"
        "}\n"
    )
    dup_changed = dup_decl.replace("k = 1;\n    }\n}", "k = 2;\n    }\n}")
    aa = _build_index(tmp_path, "aa", {"com/s/U.java": dup_decl})
    ab = _build_index(tmp_path, "ab", {"com/s/U.java": dup_changed})
    diff2 = diff_index_structure(aa, ab)
    (changed,) = diff2.changed_methods
    assert (changed.class_name, changed.method) == ("com.s.U", "go/1")
    assert len(changed.left_regions) == 2 and len(changed.right_regions) == 2
