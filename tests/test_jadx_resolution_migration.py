"""JADX resolution 三态：schema 1.3 → 1.4 → 1.5 → 1.6 迁移。红态契约。

范围：INDEX_SCHEMA_VERSION bump（1.4：calls 记录形状扩展 {callee,line} →
{callee,line,qualifier,scope}；1.5：声明剔除与 scope 状态机修复；1.6（第三轮
复审两修复，红态）：注解使用剔除 + 局部 record 识别——内容语义变、
形状不变）、旧索引 fail-closed 迁移（schema drift 必须 CacheMiss，绝不静默当
现行 schema 消费）、reason 只透稳定 code、建索引与查询输出的确定性
（串行==并行、跨 PYTHONHASHSEED）。

先于实现编写：实现落地前须为**正确原因**红（AssertionError / AttributeError /
DID NOT RAISE / 明确的 schema 拒绝），绝不允许 SyntaxError / ImportError /
collection error。夹具一律用合成标识符与文档保留值，绝无案件值。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.jadx_callpath import trace_callpath
from apkscan.core.jadx_index import (
    INDEX_SCHEMA_VERSION,
    CacheMiss,
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
    _validate_shard_structure,
    build_key_material,
    derive_index_key,
    scan_java_sources,
    verify_dex_inputs,
)
from apkscan.core.recognition_codec import canonical_json_v1, parse_json_v1

runner = CliRunner()

_REPO_ROOT = Path(__file__).resolve().parents[1]
_OPTS = "sha256:" + "ab" * 32
_LINEAGE = DexLineage(DexRole.APK_DEX, 0, "classes.dex", "sha256:" + "0" * 64)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


#: 最小自环夹具：start → target（无 package，类名即 Alpha）。
_JAVA_ALPHA = {
    "com/x/Alpha.java": (
        "class Alpha {\n"
        "    void start() {\n"
        "        target();\n"
        "    }\n"
        "    void target() {\n"
        "    }\n"
        "}\n"
    ),
}

#: gap 夹具：step 里的 m.invoke(...) 在索引里查无此名 → not_in_index gap。
_JAVA_GAP = {
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
}

#: 跨 shard 歧义 + gap 夹具（确定性测试共用）。
_JAVA_AMBIG_MAIN = {
    "com/h/M.java": (
        "package com.h;\n"
        "\n"
        "public class M {\n"
        "    void go() {\n"
        "        t.handle(v);\n"
        "        u1();\n"
        "    }\n"
        "}\n"
    ),
    "com/h/A.java": (
        "package com.h;\n"
        "\n"
        "public class A {\n"
        "    void handle(String s) {\n"
        "    }\n"
        "}\n"
    ),
}
_JAVA_AMBIG_EXTRA = {
    "com/h/B.java": (
        "package com.h;\n"
        "\n"
        "public class B {\n"
        "    void handle(String s) {\n"
        "    }\n"
        "}\n"
    ),
    "com/h/Z.java": (
        "package com.h;\n"
        "\n"
        "public class Z {\n"
        "    void far() {\n"
        "    }\n"
        "}\n"
    ),
}


def _build_index(
    tmp_path: Path, java_files: dict[str, str], *, subdir: str
) -> tuple[JadxIndexStore, str]:
    """单 dex 索引：返回 (store, index_key)。"""
    work = tmp_path / subdir
    src = work / "src"
    src.mkdir(parents=True)
    (src / "classes.dex").write_bytes(b"dex-mig")
    lineage = verify_dex_inputs(
        src,
        [
            DexInput(
                role=DexRole.APK_DEX,
                ordinal=0,
                source_label="classes.dex",
                relative_path="classes.dex",
                declared_digest=_digest(b"dex-mig"),
            )
        ],
    )
    key = derive_index_key(lineage, "1.5.2", _OPTS)
    manifest = JadxIndexManifest(
        index_key=key,
        key_material=build_key_material(lineage, "1.5.2", _OPTS),
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )
    java_root = work / "java"
    _write_tree(java_root, java_files)
    scan = scan_java_sources(java_root, [], lineage=lineage[0], limits=Limits())
    store = JadxIndexStore(work / "cache")
    built = store.build_index(src, manifest, scan=scan)
    assert isinstance(built, IndexBuildResult) and built.state == IndexBuildState.BUILT
    return store, key


def _build_two_dex(
    tmp_path: Path, *, subdir: str, reverse_scans: bool
) -> tuple[JadxIndexStore, str]:
    """双 dex 索引；reverse_scans 翻转 scans 映射的提供顺序（模拟并行归集到达序）。"""
    work = tmp_path / subdir
    src = work / "src"
    src.mkdir(parents=True)
    (src / "classes.dex").write_bytes(b"dex-main")
    (src / "extra.dex").write_bytes(b"dex-extra")
    lineage = verify_dex_inputs(
        src,
        [
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
        ],
    )
    key = derive_index_key(lineage, "1.5.2", _OPTS)
    manifest = JadxIndexManifest(
        index_key=key,
        key_material=build_key_material(lineage, "1.5.2", _OPTS),
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )
    main_root = work / "out-main"
    extra_root = work / "out-extra"
    _write_tree(main_root, _JAVA_AMBIG_MAIN)
    _write_tree(extra_root, _JAVA_AMBIG_EXTRA)
    by_role = {lin.role: lin for lin in lineage}
    pairs = [
        (
            by_role[DexRole.APK_DEX],
            scan_java_sources(
                main_root, [], lineage=by_role[DexRole.APK_DEX], limits=Limits()
            ),
        ),
        (
            by_role[DexRole.EXTRA_DEX],
            scan_java_sources(
                extra_root, [], lineage=by_role[DexRole.EXTRA_DEX], limits=Limits()
            ),
        ),
    ]
    if reverse_scans:
        pairs.reverse()
    store = JadxIndexStore(work / "cache")
    built = store.build_index(src, manifest, scan=dict(pairs))
    assert isinstance(built, IndexBuildResult) and built.state == IndexBuildState.BUILT
    return store, key


def _rewrite_schema_version(cache_root: Path, index_key: str, version: str) -> None:
    """把已落盘 manifest 的 schema 版本改写为 version（canonical 重编码）——
    构造「旧 schema 工件」夹具；load 侧的版本闸必须先于 key 复核揭穿它。"""
    manifest_path = cache_root / index_key / "manifest.json"
    value = parse_json_v1(manifest_path.read_bytes().decode("utf-8"))
    assert isinstance(value, dict)
    value["index_schema_version"] = version
    material = value["key_material"]
    assert isinstance(material, dict)
    material["index_schema_version"] = version
    manifest_path.write_bytes(canonical_json_v1(value))


def _run_cli(args: list[str]) -> tuple[int, dict | None, str]:
    result = runner.invoke(cli.app, args)
    raw = result.stdout
    try:
        return result.exit_code, json.loads(raw), raw
    except ValueError:
        return result.exit_code, None, raw


# ---------------------------------------------------------------------------
# schema bump 与旧索引 fail-closed 迁移
# ---------------------------------------------------------------------------


def test_index_schema_version_bumped_to_1_6() -> None:
    """★schema 演进锁（全仓库单一真源——test_jadx_structure.py 的重复锁已并入此处）。

    版本演进史：
    1.1→1.2：结构身份 name 改 (name, path)——混淆样本不同路径同名类合法。
    1.2→1.3：arity 按尖括号深度 0 的逗号计数——泛型实参逗号不再误算成参数
    分隔符（不改字段集、仍必须 bump 的首个先例）。
    1.3→1.4：calls 记录形状扩成 {callee,line,qualifier,scope}，trace 输出三态
    resolution——形状变了必须 bump，否则同一 index_key 下的旧 shard 会以 1.3
    形状撞上新消费侧的 fail-closed 校验（或更糟：被静默容忍）。
    1.4→1.5：声明剔除（`public void run() {` 这类方法声明不再被误记为调用边）
    与嵌套 new 的 scope 状态机修复。calls 形状不变——bump 的理由是缓存内容：
    schema 版本参与 key material，是「提取语义变了、旧工件不可信」唯一的
    失效开关。
    1.5→1.6：注解使用剔除（`@Anno(v=1)` / 形参注解的注解名不再入 calls——
    记录集收缩）+ 局部 record 识别（scope method→nested_type 纠正、record
    类条目/方法首次入索引——classes 集扩张）。同样是形状不变、内容语义变：
    不 bump，1.5 工件里的注解伪边与错标 scope 会被静默当好数据消费。
    更早的工件按既有漂移机制拒收（版本同时进 key material 与 load 校验）。

    ★bump 检查单（1.4→1.5、1.5→1.6 两轮都漏过分散钉点，故收敛于此）——
    全仓库需要同步的版本字面量只有三处：
      1) 生产 apkscan/core/jadx_index.py 的 INDEX_SCHEMA_VERSION；
      2) 本锁的期望字面量（连同函数名后缀，并在上方演进史补一行理由）；
      3) test_jadx_index.py::test_key_fixed_vector 的固定向量——必须独立复算
         （手工构造 key material 复算 sha256，并用旧 schema 值逐字节复现前代
         向量以自证配方未变），绝不抄实现输出。
    其余断言一律引用 INDEX_SCHEMA_VERSION 符号（接线检查，非版本钉点），
    不入清单。每轮另新增旧版拒收契约（test_vXX_index_rejected_…）——那钉的
    是旧版本号，不随后续 bump 腐坏。"""
    assert INDEX_SCHEMA_VERSION == "1.6"


def test_v13_index_rejected_as_schema_drift_after_bump(tmp_path: Path) -> None:
    """1.3 工件在现行代码下 load → CacheMiss(schema_drift)，无迁移代码、只重建。"""
    store, key = _build_index(tmp_path, _JAVA_ALPHA, subdir="one")
    loaded_before = store.load_index(key)
    assert isinstance(loaded_before, LoadedIndex)

    _rewrite_schema_version(store.cache_root, key, "1.3")
    miss = store.load_index(key)
    assert isinstance(miss, CacheMiss)
    assert miss.reason == "schema_drift"


def test_v14_index_rejected_as_schema_drift_after_bump(tmp_path: Path) -> None:
    """★1.4 工件在现行代码下 load → CacheMiss(schema_drift)。这正是 1.4→1.5
    bump 的靶子人群：1.4 工件的 calls 形状与 1.5 完全同形，任何结构校验都
    揭不穿「伪造声明边 / 错标 scope」的旧内容，唯一能挡住它的就是版本闸。"""
    store, key = _build_index(tmp_path, _JAVA_ALPHA, subdir="one")
    _rewrite_schema_version(store.cache_root, key, "1.4")
    miss = store.load_index(key)
    assert isinstance(miss, CacheMiss)
    assert miss.reason == "schema_drift"


def test_v15_index_rejected_as_schema_drift_after_bump(tmp_path: Path) -> None:
    """★红态契约（1.5→1.6 bump 落地后转绿）：1.5 工件在 1.6 代码下 load →
    CacheMiss(schema_drift)。1.5 工件与 1.6 同形，但仍含注解伪边
    （`@Anno(v=1)` 被记成调用）与 record 体错标 scope="method" 的记录、且缺
    record 类条目——结构校验揭不穿，唯一能挡住它的就是版本闸。"""
    store, key = _build_index(tmp_path, _JAVA_ALPHA, subdir="one")
    _rewrite_schema_version(store.cache_root, key, "1.5")
    miss = store.load_index(key)
    assert isinstance(miss, CacheMiss)
    assert miss.reason == "schema_drift"


def test_stale_v13_index_never_returns_stale_arity_or_resolution(tmp_path: Path) -> None:
    """★schema 版本参与 key material：现行代码派生的 key 与任何旧版 key
    必然不同（旧工件寻址不到）；即便直接按旧目录加载，也必须 CacheMiss——
    不存在任何「旧 arity / 旧 resolution / 伪造声明边 / 注解伪边 / record
    错标 scope 被静默当现行数据消费」的通路。（key material 断言取符号
    INDEX_SCHEMA_VERSION：这是「manifest 持久化了现行版本」的接线检查，
    不是版本钉点——钉点唯一真源在 test_index_schema_version_bumped_to_1_6。）"""
    store, key = _build_index(tmp_path, _JAVA_ALPHA, subdir="one")
    manifest_value = parse_json_v1(
        (store.cache_root / key / "manifest.json").read_bytes().decode("utf-8")
    )
    assert isinstance(manifest_value, dict)
    material = manifest_value["key_material"]
    assert isinstance(material, dict)
    assert material["index_schema_version"] == INDEX_SCHEMA_VERSION

    _rewrite_schema_version(store.cache_root, key, "1.3")
    stale = store.load_index(key)
    assert not isinstance(stale, LoadedIndex)
    assert isinstance(stale, CacheMiss) and stale.reason == "schema_drift"


def test_migration_reason_is_stable_code_only(tmp_path: Path) -> None:
    """★CLI 真入口：1.3 缓存 → {"status":"miss","reason":"schema_drift"}，
    reason 只透稳定 code——不泄字段坐标、异常文本或主机路径。"""
    store, key = _build_index(tmp_path, _JAVA_ALPHA, subdir="one")
    _rewrite_schema_version(store.cache_root, key, "1.3")
    code, data, raw = _run_cli(
        [
            "jadx",
            "callpath",
            "Alpha#start/0",
            "Alpha#target/0",
            "--jadx-cache-root",
            str(store.cache_root),
            "--jadx-index",
            key,
        ]
    )
    assert code == 0 and data is not None
    assert data == {"status": "miss", "reason": "schema_drift"}
    assert re.fullmatch(r"[a-z][a-z0-9_]*", data["reason"]) is not None
    assert "$." not in raw
    assert "Traceback" not in raw
    assert str(store.cache_root) not in raw


# ---------------------------------------------------------------------------
# calls 记录形状：1.4 起的产出与消费侧双向 fail-closed
# ---------------------------------------------------------------------------


def _reshape_calls_to_v13(shard: Mapping[str, object]) -> dict[str, object]:
    """把 shard 里的 calls 记录裁回 1.3 形状 {callee,line}（其余字段原样）。"""
    out = dict(shard)
    structure = out["structure"]
    assert isinstance(structure, Mapping)
    classes_out: list[dict[str, object]] = []
    classes = structure["classes"]
    assert isinstance(classes, list)
    for cls in classes:
        assert isinstance(cls, Mapping)
        cls_out = dict(cls)
        methods_out: list[dict[str, object]] = []
        methods = cls_out["methods"]
        assert isinstance(methods, list)
        for method in methods:
            assert isinstance(method, Mapping)
            method_out = dict(method)
            calls = method_out["calls"]
            assert isinstance(calls, list)
            method_out["calls"] = [
                {"callee": dict(c)["callee"], "line": dict(c)["line"]} for c in calls
            ]
            methods_out.append(method_out)
        cls_out["methods"] = methods_out
        classes_out.append(cls_out)
    out["structure"] = {"classes": classes_out}
    return out


def test_calls_record_shape_change_is_schema_gated(tmp_path: Path) -> None:
    """★1.3 形状的 calls 记录绝不许被 1.4 起的消费侧接受：trace 与 load 校验
    都必须 fail-closed 揭穿（malformed），不许静默按旧语义消费。"""
    store, key = _build_index(tmp_path, _JAVA_ALPHA, subdir="one")
    loaded = store.load_index(key)
    assert isinstance(loaded, LoadedIndex)
    forged = LoadedIndex(
        manifest=loaded.manifest,
        shard_locators=loaded.shard_locators,
        coverage=loaded.coverage,
        shards=tuple(_reshape_calls_to_v13(s) for s in loaded.shards),
    )
    with pytest.raises(JadxIndexError) as exc:
        trace_callpath(forged, "Alpha#start/0", "Alpha#target/0")
    assert exc.value.code == "malformed"

    # load 侧同款闸：1.3 形状的 call 记录过不了当前 schema 的结构校验。
    v13_shard = {
        "structure": {
            "classes": [
                {
                    "name": "com.t.T",
                    "path": "com/t/T.java",
                    "methods": [
                        {
                            "name": "m",
                            "arity": 0,
                            "start_line": 1,
                            "end_line": 3,
                            "body_digest": _digest(b"m"),
                            "calls": [{"callee": "n", "line": 2}],
                        }
                    ],
                }
            ]
        }
    }
    with pytest.raises(JadxIndexError) as exc:
        _validate_shard_structure(v13_shard, {"com/t/T.java"})
    assert exc.value.code == "malformed"


def test_calls_qualifier_and_scope_values_fail_closed(tmp_path: Path) -> None:
    """qualifier / scope 的取值域校验不得放宽：形状对但值非法 → malformed。
    （此守卫在 1.3 下靠形状闸已成立，1.4/1.5 下必须继续成立——防实现放宽。）"""
    store, key = _build_index(tmp_path, _JAVA_ALPHA, subdir="one")
    loaded = store.load_index(key)
    assert isinstance(loaded, LoadedIndex)
    bad_calls: list[dict[str, object]] = [
        {"callee": "n", "line": 2, "qualifier": "bad token!", "scope": "method"},
        {"callee": "n", "line": 2, "qualifier": "", "scope": "weird"},
    ]
    for bad_call in bad_calls:
        bad_shard = dict(loaded.shards[0])
        bad_shard["structure"] = {
            "classes": [
                {
                    "name": "com.t.Bad",
                    "path": "com/x/Alpha.java",
                    "methods": [
                        {
                            "name": "m",
                            "arity": 0,
                            "start_line": 1,
                            "end_line": 2,
                            "body_digest": _digest(b"m"),
                            "calls": [bad_call],
                        }
                    ],
                },
                {
                    "name": "com.t.Sink",
                    "path": "com/x/Alpha.java",
                    "methods": [
                        {
                            "name": "s",
                            "arity": 0,
                            "start_line": 3,
                            "end_line": 4,
                            "body_digest": _digest(b"s"),
                            "calls": [],
                        }
                    ],
                },
            ]
        }
        forged = LoadedIndex(
            manifest=loaded.manifest,
            shard_locators=loaded.shard_locators,
            coverage=loaded.coverage,
            shards=(bad_shard,),
        )
        with pytest.raises(JadxIndexError) as exc:
            trace_callpath(forged, "com.t.Bad#m/0", "com.t.Sink#s/0")
        assert exc.value.code == "malformed", bad_call


def test_scan_emits_qualifier_and_scope_fields(tmp_path: Path) -> None:
    """★真入口 scan_java_sources：calls 记录逐字段钉死（形状 1.4 起、期望内容
    为 1.5 声明剔除后语义）。qualifier 只记
    文本可确证的接收者形态（""/this/super/单标识符/<expr>），scope 标记调用点
    是否落在方法体内联的类型体（匿名类等）里——那是 owner 限定的禁区。"""
    java_root = tmp_path / "java"
    _write_tree(
        java_root,
        {
            "com/v/V.java": (
                "package com.v;\n"
                "\n"
                "public class V {\n"
                "    void a() {\n"
                "        local();\n"
                "        this.self();\n"
                "        h.fetch();\n"
                "        Net.get();\n"
                "        a.b.deep();\n"
                "        chain().next();\n"
                "        super.sup();\n"
                "    }\n"
                "\n"
                "    void b() {\n"
                "        Runnable r = new Runnable() {\n"
                "            public void run() {\n"
                "                inner();\n"
                "            }\n"
                "        };\n"
                "        after();\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    scan = scan_java_sources(java_root, [], lineage=_LINEAGE, limits=Limits())
    assert scan.coverage == "complete"
    (cls,) = scan.structure
    methods = {
        str(dict(m)["name"]): dict(m)
        for m in cls["methods"]  # type: ignore[union-attr]
    }
    assert [dict(c) for c in methods["a"]["calls"]] == [  # type: ignore[union-attr]
        {"callee": "local", "line": 5, "qualifier": "", "scope": "method"},
        {"callee": "self", "line": 6, "qualifier": "this", "scope": "method"},
        {"callee": "fetch", "line": 7, "qualifier": "h", "scope": "method"},
        {"callee": "get", "line": 8, "qualifier": "Net", "scope": "method"},
        {"callee": "deep", "line": 9, "qualifier": "<expr>", "scope": "method"},
        {"callee": "chain", "line": 10, "qualifier": "", "scope": "method"},
        {"callee": "next", "line": 10, "qualifier": "<expr>", "scope": "method"},
        {"callee": "sup", "line": 11, "qualifier": "super", "scope": "method"},
    ]
    # ★红态契约（纠正误钉）：`public void run() {` 是匿名类**方法声明**，不是
    # 调用表达式——此前把它钉进期望列表等于把伪边当契约。声明剔除落地后，
    # b 的调用记录只剩真实调用点；匿名体内真实调用（inner）原样保留。
    assert [dict(c) for c in methods["b"]["calls"]] == [  # type: ignore[union-attr]
        {"callee": "inner", "line": 17, "qualifier": "", "scope": "nested_type"},
        {"callee": "after", "line": 20, "qualifier": "", "scope": "method"},
    ]


def test_scan_nested_new_in_anonymous_ctor_args_stays_nested_type(
    tmp_path: Path,
) -> None:
    """★红线钉桩（复审实测发现，落盘时红——修好 scope 状态机后转绿）：匿名类
    构造实参里含**完整闭合的嵌套 new**（`new Foo(new Bar()) { … }`）时，内层
    new 会把 pending_paren 重置为 0，外层实参的闭括号把它推成 -1，匿名体的
    `{` 因 pending_paren != 0 漏判内联类型体 → 体内调用被记成 scope="method"。
    scope="method" 正是「直接执行」标注，失效方向是反保守（把嵌套体调用
    冒充直接边），不是保守漏，必须修。常见构型 `new Thread(new Runnable() { … })`
    （嵌套 new 未闭合即开体）不受影响，由上一条测试钉住。"""
    java_root = tmp_path / "java"
    _write_tree(
        java_root,
        {
            "com/w/W.java": (
                "package com.w;\n"
                "\n"
                "public class W {\n"
                "    void m() {\n"
                "        new Foo(new Bar()) {\n"
                "            void h() {\n"
                "                helper();\n"
                "            }\n"
                "        };\n"
                "        after();\n"
                "    }\n"
                "\n"
                "    void helper() {\n"
                "    }\n"
                "}\n"
            ),
        },
    )
    scan = scan_java_sources(java_root, [], lineage=_LINEAGE, limits=Limits())
    assert scan.coverage == "complete"
    (cls,) = scan.structure
    methods = {
        str(dict(m)["name"]): dict(m)
        for m in cls["methods"]  # type: ignore[union-attr]
    }
    # ★红态契约（纠正误钉）：`void h() {` 是方法**声明**，此前以「已知怪癖」
    # 名义钉进期望——怪癖不是契约，声明剔除落地后它必须消失。本测试真正要锁
    # 的 scope 语义由真实调用点（helper）承载：匿名体内 nested_type，匿名语句
    # 结束后回到 method，断言强度不降。
    assert [dict(c) for c in methods["m"]["calls"]] == [  # type: ignore[union-attr]
        {"callee": "helper", "line": 7, "qualifier": "", "scope": "nested_type"},
        {"callee": "after", "line": 10, "qualifier": "", "scope": "method"},
    ]


# ---------------------------------------------------------------------------
# CLI 消费面：gaps / reason_codes 透出，caveat 不变量保持
# ---------------------------------------------------------------------------


def test_cli_callpath_surfaces_gaps_reason_codes_and_caveat(tmp_path: Path) -> None:
    store, key = _build_index(tmp_path, _JAVA_GAP, subdir="gap")
    code, data, _ = _run_cli(
        [
            "jadx",
            "callpath",
            "com.g1.R#go/0",
            "com.g1.Z#far/0",
            "--jadx-cache-root",
            str(store.cache_root),
            "--jadx-index",
            key,
        ]
    )
    assert code == 0 and data is not None
    assert data["status"] == "ok"
    assert data["paths"] == []
    assert "gaps" in data, "not_in_index 边界必须透出到 CLI"
    assert data["gaps"] == [
        {
            "caller": "com.g1.R#step/0",
            "callee": "invoke",
            "caller_path": "com/g1/R.java",
            "line": 9,
            "resolution": "not_in_index",
            "scope": "method",
        }
    ]
    assert data.get("reason_codes") == []
    # ★不变量：no_path_is_not_unreachable caveat 不得删。
    codes = [c["code"] for c in data["caveats"]]
    assert "no_path_is_not_unreachable" in codes
    assert set(data["limits"]) == {
        "max_depth",
        "max_paths",
        "max_visited",
        "max_fanout",
        "max_gaps",
    }


# ---------------------------------------------------------------------------
# 确定性：串行 == 并行、跨 PYTHONHASHSEED 逐字节一致
# ---------------------------------------------------------------------------


def test_serial_equals_parallel_for_index_build(tmp_path: Path) -> None:
    """scan 输入的提供顺序（模拟并行归集的任意到达序）不得影响落盘工件字节
    与查询输出——「串行 == 并行 逐字节一致」在本切片的对应物。"""
    store_a, key_a = _build_two_dex(tmp_path, subdir="a", reverse_scans=False)
    store_b, key_b = _build_two_dex(tmp_path, subdir="b", reverse_scans=True)
    assert key_a == key_b

    manifest_a = (store_a.cache_root / key_a / "manifest.json").read_bytes()
    manifest_b = (store_b.cache_root / key_b / "manifest.json").read_bytes()
    assert manifest_a == manifest_b
    shards_a = sorted(p.name for p in (store_a.cache_root / key_a / "shards").iterdir())
    shards_b = sorted(p.name for p in (store_b.cache_root / key_b / "shards").iterdir())
    assert shards_a == shards_b
    for name in shards_a:
        assert (store_a.cache_root / key_a / "shards" / name).read_bytes() == (
            store_b.cache_root / key_b / "shards" / name
        ).read_bytes()

    loaded_a = store_a.load_index(key_a)
    loaded_b = store_b.load_index(key_b)
    assert isinstance(loaded_a, LoadedIndex) and isinstance(loaded_b, LoadedIndex)
    trace_a = trace_callpath(loaded_a, "com.h.M#go/0", "com.h.A#handle/1")
    trace_b = trace_callpath(loaded_b, "com.h.M#go/0", "com.h.A#handle/1")
    assert trace_a == trace_b
    assert len(trace_a.paths) == 1
    assert trace_a.paths[0].edges[0].resolution == "ambiguous"
    assert [g.callee for g in trace_a.gaps] == ["u1"]
    assert trace_a.reason_codes == ()


_SCRIPT = '''\
import hashlib
import json
import os
import sys
from pathlib import Path

from apkscan.core.jadx_callpath import trace_callpath
from apkscan.core.jadx_index import (
    DexInput,
    DexRole,
    IndexBuildResult,
    JadxIndexManifest,
    JadxIndexStore,
    Limits,
    LoadedIndex,
    build_key_material,
    derive_index_key,
    scan_java_sources,
    verify_dex_inputs,
)

JAVA = {
    "com/h/M.java": "package com.h;\\n\\npublic class M {\\n    void go() {\\n        t.handle(v);\\n        u1();\\n    }\\n}\\n",
    "com/h/A.java": "package com.h;\\n\\npublic class A {\\n    void handle(String s) {\\n    }\\n}\\n",
    "com/h/B.java": "package com.h;\\n\\npublic class B {\\n    void handle(String s) {\\n    }\\n}\\n",
    "com/h/Z.java": "package com.h;\\n\\npublic class Z {\\n    void far() {\\n    }\\n}\\n",
}


def edge(e):
    # getattr 兼容 scope 落地前后两种边形状：本探针只做同版本跨种子字节比对，
    # 宽容读取不弱化该锁，且 scope 落地后自动纳入确定性覆盖。
    return [e.caller, e.callee, e.caller_path, e.line, e.resolution,
            getattr(e, "scope", None)]


def trace_record(trace):
    return {
        "paths": [
            {"nodes": list(p.nodes), "edges": [edge(e) for e in p.edges]}
            for p in trace.paths
        ],
        "gaps": [edge(e) for e in trace.gaps],
        "coverage": trace.coverage,
        "reason_codes": list(trace.reason_codes),
    }


def main():
    # ★自证前提：父进程必须真把定制 env 传进来。若这里失败，说明测试侧
    # subprocess.run 没传 env=env——那正是这条测试历史上假绿的原因。
    expected_seed = sys.argv[2]
    actual_seed = os.environ.get("PYTHONHASHSEED")
    assert actual_seed == expected_seed, (
        f"PYTHONHASHSEED 未传入子进程: {actual_seed!r} != {expected_seed!r}"
    )
    work = Path(sys.argv[1])
    src = work / "src"
    src.mkdir(parents=True)
    (src / "classes.dex").write_bytes(b"dex-seed")
    digest = "sha256:" + hashlib.sha256(b"dex-seed").hexdigest()
    lineage = verify_dex_inputs(
        src,
        [
            DexInput(
                role=DexRole.APK_DEX,
                ordinal=0,
                source_label="classes.dex",
                relative_path="classes.dex",
                declared_digest=digest,
            )
        ],
    )
    opts = "sha256:" + "a" * 64
    key = derive_index_key(lineage, "1.5.2", opts)
    manifest = JadxIndexManifest(
        index_key=key,
        key_material=build_key_material(lineage, "1.5.2", opts),
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=opts,
    )
    java_root = work / "java"
    for rel, content in JAVA.items():
        target = java_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    scan = scan_java_sources(java_root, [], lineage=lineage[0], limits=Limits())
    store = JadxIndexStore(work / "cache")
    built = store.build_index(src, manifest, scan=scan)
    assert isinstance(built, IndexBuildResult), built
    loaded = store.load_index(key)
    assert isinstance(loaded, LoadedIndex), loaded
    record = {
        "index_key": key,
        "to_far": trace_record(trace_callpath(loaded, "com.h.M#go/0", "com.h.Z#far/0")),
        "to_handle": trace_record(
            trace_callpath(loaded, "com.h.M#go/0", "com.h.A#handle/1")
        ),
    }
    sys.stdout.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def test_output_stable_under_pythonhashseed(tmp_path: Path) -> None:
    """★跨进程 PYTHONHASHSEED 不同，建索引 + trace 的完整输出（含 gaps 与
    reason_codes）必须逐字节一致——set/dict 派生顺序必须被显式排序钉死。"""
    script = tmp_path / "probe_trace.py"
    script.write_text(_SCRIPT, encoding="utf-8")
    outputs: list[bytes] = []
    for seed, name in (("0", "run0"), ("1", "run1")):
        work = tmp_path / name
        work.mkdir()
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONPATH"] = str(_REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, str(script), str(work), seed],
            capture_output=True,
            timeout=120,
            check=False,
            env=env,
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")[-2000:]
        assert proc.stdout, "探针必须有输出"
        outputs.append(proc.stdout)
    assert outputs[0] == outputs[1]
