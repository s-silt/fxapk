"""P1-C：usage 命中的类/方法归属（class_context / method_context）。

这两个字段一直在 `UsageHit` 上、也一直被 `fxapk jadx usage` 的 JSON 输出透传，
但 `find_value_usage` 从不给它们赋值——输出里恒为 null，且没有任何测试断言过。
本片把它们填实：用 structure 段里 method 的行号区间反查 posting 所在的方法。

反查是 fail-closed 的：**恰好一个区间包含该行才归属**，0 个（字段初始化器/静态块
——class 段没有行号区间，无法单独定类）或 ≥2 个（区间重叠）一律留 None，绝不猜。
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

from apkscan.core.jadx_index import (
    DexInput,
    DexRole,
    JadxIndexManifest,
    JadxIndexStore,
    Limits,
    LoadedIndex,
    build_key_material,
    derive_index_key,
    find_value_usage,
    scan_java_sources,
    verify_dex_inputs,
)

# CGNAT 段：全球可路由字面但绝非真实案件值，两边都不需要豁免。
_TARGET = "https://100.64.0.1/x"
_OPTS = "sha256:" + "f" * 64


def _build_index(
    tmp_path: Path, files: dict[str, str], values: list[str]
) -> LoadedIndex:
    """建一个含 postings 的索引并 load 回来。

    ★不能复用 test_jadx_callpath 的 helper：那个把 values 传成空列表，建出的索引
    没有 postings，find_value_usage 恒返回空。
    """
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    dex = src / "classes.dex"
    dex.write_bytes(b"dex-usage-ctx")
    inputs = [
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="classes.dex",
            relative_path="classes.dex",
            declared_digest="sha256:" + hashlib.sha256(dex.read_bytes()).hexdigest(),
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
    for relative, text in files.items():
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
    scan = scan_java_sources(out, values, lineage=lineage[0], limits=Limits())
    store = JadxIndexStore(tmp_path / "cache")
    store.build_index(src, manifest, scan=scan)
    loaded = store.load_index(key)
    assert isinstance(loaded, LoadedIndex)
    return loaded


def _replace_first_shard(index: LoadedIndex, shard: dict[str, object]) -> LoadedIndex:
    return replace(index, shards=(shard,))


def test_usage_hit_gets_class_and_method_context(tmp_path: Path) -> None:
    """★真入口锁：命中落在方法体内时，补上 类名 与 name/arity。"""
    index = _build_index(
        tmp_path,
        {
            "com/a/A.java": (
                "package com.a;\n"
                "public class A {\n"
                "    public void handle(String value) {\n"
                f'        String target = "{_TARGET}";\n'
                "    }\n"
                "}\n"
            )
        },
        [_TARGET],
    )
    hits = find_value_usage(index, _TARGET)
    assert len(hits) == 1
    assert hits[0].class_context == "com.a.A"
    assert hits[0].method_context == "handle/1"


def test_usage_outside_any_method_leaves_context_none(tmp_path: Path) -> None:
    """字段初始化器：命中照常产生，但两个 context 留 None（class 段无行号区间，不猜）。"""
    index = _build_index(
        tmp_path,
        {
            "com/a/A.java": (
                "package com.a;\n"
                "public class A {\n"
                f'    private String target = "{_TARGET}";\n'
                "    public void handle(String value) {\n"
                "        value.length();\n"
                "    }\n"
                "}\n"
            )
        },
        [_TARGET],
    )
    hits = find_value_usage(index, _TARGET)
    assert len(hits) == 1
    assert hits[0].class_context is None
    assert hits[0].method_context is None


def test_ambiguous_ranges_leave_context_none(tmp_path: Path) -> None:
    """区间重叠一律拒绝归属（保守到「恰好一个」，不取最内层）。

    真实提取器产不出重叠区间（成员方法只在类深度+1 识别，局部/匿名类的方法根本
    不进 structure），所以这里手工构造 shard——structure 是从磁盘读进来的，
    能写 cache 的攻击者就能造重叠，防御分支不能依赖「提取器不会产生」这个前提。
    """
    index = _build_index(
        tmp_path,
        {
            "com/a/A.java": (
                "package com.a;\n"
                "public class A {\n"
                f'    public void handle(String v) {{ String x = "{_TARGET}"; }}\n'
                "}\n"
            )
        },
        [_TARGET],
    )
    original = find_value_usage(index, _TARGET)
    assert len(original) == 1
    line = original[0].line

    shard = dict(index.shards[0])
    shard["structure"] = {
        "classes": [
            {
                "name": "com.a.A",
                "path": "com/a/A.java",
                "methods": [
                    {"name": "a", "arity": 0, "start_line": line - 1, "end_line": line + 5},
                    {"name": "b", "arity": 1, "start_line": line - 1, "end_line": line + 1},
                ],
            }
        ]
    }
    hits = find_value_usage(_replace_first_shard(index, shard), _TARGET)
    assert len(hits) == 1
    assert hits[0].class_context is None
    assert hits[0].method_context is None


def test_context_enrichment_never_changes_hit_set(tmp_path: Path) -> None:
    """★命中集合一字不增不减：补 context 不是制造或吞掉观察。"""
    index = _build_index(
        tmp_path,
        {
            "com/a/A.java": (
                "package com.a;\n"
                "public class A {\n"
                f'    private String field = "{_TARGET}";\n'
                "    public void handle(String value) {\n"
                f'        String first = "{_TARGET}";\n'
                "    }\n"
                "}\n"
            )
        },
        [_TARGET],
    )
    digest = "sha256:" + hashlib.sha256(_TARGET.encode("utf-8")).hexdigest()
    expected = sorted(
        (posting["path"], posting["line"], posting["column"])
        for shard in index.shards
        for posting in shard["postings"]  # type: ignore[union-attr]
        if posting["value_digest"] == digest
    )
    hits = find_value_usage(index, _TARGET)
    assert sorted((h.relative_path, h.line, h.column) for h in hits) == expected


def test_missing_structure_section_degrades_to_none(tmp_path: Path) -> None:
    """structure 段缺失时降级为无归属，绝不因此丢掉命中或抛异常。"""
    index = _build_index(
        tmp_path,
        {
            "com/a/A.java": (
                "package com.a;\n"
                "public class A {\n"
                f'    public void handle(String v) {{ String x = "{_TARGET}"; }}\n'
                "}\n"
            )
        },
        [_TARGET],
    )
    shard = dict(index.shards[0])
    shard.pop("structure", None)
    hits = find_value_usage(_replace_first_shard(index, shard), _TARGET)
    assert len(hits) == 1
    assert hits[0].class_context is None
    assert hits[0].method_context is None
