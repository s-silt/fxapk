"""P1-A jadx_index S1（契约与身份层）：类型契约、DEX 复算校验、key 派生。

对应 plan Task 1 + Task 2。每条拒绝断言精确到 reason code——「拒了」和「为对的理由拒了」
是两回事；S2/S3（发布/加载/查询/ledger 投影）的测试随后续切片补充。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from apkscan.core.jadx_index import (
    INDEX_SCHEMA_VERSION,
    CacheMiss,
    CacheUnavailable,
    DexInput,
    DexLineage,
    DexRole,
    JadxIndexError,
    JadxIndexManifest,
    UsageHit,
    build_key_material,
    derive_index_key,
    derive_shard_key,
    verify_dex_inputs,
)
from apkscan.core.recognition_codec import canonical_json_v1

_OPTS = "sha256:" + "a" * 64


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write_dex(root: Path, rel: str, data: bytes) -> DexInput:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return DexInput(
        role=DexRole.APK_DEX,
        ordinal=0,
        source_label=rel,
        relative_path=rel,
        declared_digest=_digest(data),
    )


def _code_of(excinfo: pytest.ExceptionInfo[JadxIndexError]) -> str:
    return excinfo.value.code


# ---------------------------------------------------------------------------
# Task 1：类型契约
# ---------------------------------------------------------------------------


def test_lineage_record_contains_no_path_material() -> None:
    """★序列化 lineage 只含 role/ordinal/label/digest——绝无文件系统路径。"""
    lin = DexLineage(DexRole.EXTRA_DEX, 3, "unpack-1", _digest(b"x"))
    record = lin.to_record()
    assert set(record) == {"role", "ordinal", "source_label", "digest"}
    encoded = canonical_json_v1(record).decode("utf-8")
    assert "\\\\" not in encoded and ":/" not in encoded


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"ordinal": -1}, "invalid_ordinal"),
        ({"ordinal": True}, "invalid_ordinal"),
        ({"source_label": ""}, "invalid_source_label"),
        ({"declared_digest": "sha256:XYZ"}, "invalid_digest"),
        ({"declared_digest": "md5:" + "a" * 64}, "invalid_digest"),
        ({"declared_digest": "sha256:" + "A" * 64}, "invalid_digest"),
    ],
)
def test_dex_input_field_validation(kwargs: dict, code: str) -> None:
    base = {
        "role": DexRole.APK_DEX,
        "ordinal": 0,
        "source_label": "classes.dex",
        "relative_path": "classes.dex",
        "declared_digest": _digest(b"x"),
    }
    with pytest.raises(JadxIndexError) as exc:
        DexInput(**{**base, **kwargs})
    assert _code_of(exc) == code


@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        "/abs/classes.dex",
        "C:evil.dex",
        "C:/evil.dex",
        "//unc/share/x.dex",
        "a/../b.dex",
        "./x.dex",
        "a//b.dex",
        "a\\b.dex",
        "trailing/",
    ],
)
def test_dex_input_rejects_unsafe_relative_paths(bad_path: str) -> None:
    with pytest.raises(JadxIndexError) as exc:
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="x",
            relative_path=bad_path,
            declared_digest=_digest(b"x"),
        )
    assert _code_of(exc) == "invalid_relative_path"


def test_manifest_requires_valid_options_digest() -> None:
    """★回归锁（接线修正）：options_digest 必填且必须是 sha256 语法——
    不存在"看起来合法"的默认值可以静默通过。"""
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    key = derive_index_key([lin], "1.5.2", _OPTS)
    material = build_key_material([lin], "1.5.2", _OPTS)
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key=key,
            key_material=material,
            dex_lineage=(lin,),
            jadx_version="1.5.2",
            options_digest=INDEX_SCHEMA_VERSION,  # 恰是曾经的坏默认值
        )
    assert _code_of(exc) == "invalid_digest"


def test_manifest_rejects_unknown_key_material_keys() -> None:
    """★codex 复审必须项：key_material 未知键是不影响身份的自由载荷通道，两侧拒绝。"""
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    key = derive_index_key([lin], "1.5.2", _OPTS)
    material = dict(build_key_material([lin], "1.5.2", _OPTS))
    material["smuggled"] = "payload"
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key=key,
            key_material=material,
            dex_lineage=(lin,),
            jadx_version="1.5.2",
            options_digest=_OPTS,
        )
    assert _code_of(exc) == "invalid_key_material"


def test_manifest_rejects_schema_drift() -> None:
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    key = derive_index_key([lin], "1.5.2", _OPTS)
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key=key,
            key_material=build_key_material([lin], "1.5.2", _OPTS),
            dex_lineage=(lin,),
            jadx_version="1.5.2",
            options_digest=_OPTS,
            index_schema_version="9.9",
        )
    assert _code_of(exc) == "schema_drift"


def test_cache_results_are_distinct_types() -> None:
    """CacheMiss（内容层）与 CacheUnavailable（环境层）是不同类型，不可互换。"""
    assert CacheMiss("absent") != CacheUnavailable("absent")
    assert not isinstance(CacheMiss("absent"), CacheUnavailable)
    assert not isinstance(CacheUnavailable("io_error"), CacheMiss)


def test_usage_hit_contract() -> None:
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    hit = UsageHit("a/b.java", 1, 1, _digest(b"v"), lin)
    assert hit.ownership == "unknown"
    for bad in (
        {"line": 0},
        {"column": 0},
        {"line": True},
        {"ownership": "suspect_first_party"},
        {"relative_path": "../escape.java"},
    ):
        with pytest.raises(JadxIndexError):
            UsageHit(
                **{
                    **{
                        "relative_path": "a/b.java",
                        "line": 1,
                        "column": 1,
                        "value_digest": _digest(b"v"),
                        "lineage": lin,
                    },
                    **bad,
                }
            )


# ---------------------------------------------------------------------------
# Task 2：DEX 复算校验
# ---------------------------------------------------------------------------


def test_verify_recomputes_and_accepts_true_digest(tmp_path: Path) -> None:
    inp = _write_dex(tmp_path, "classes.dex", b"dex-bytes-1")
    (lineage,) = verify_dex_inputs(tmp_path, [inp])
    assert lineage.digest == _digest(b"dex-bytes-1")


def test_verify_rejects_forged_declared_digest(tmp_path: Path) -> None:
    """★declared digest 是待验证义务：字节被换掉必须拒绝，绝不信任声明。"""
    inp = _write_dex(tmp_path, "classes.dex", b"original")
    (tmp_path / "classes.dex").write_bytes(b"tampered")
    with pytest.raises(JadxIndexError) as exc:
        verify_dex_inputs(tmp_path, [inp])
    assert _code_of(exc) == "digest_mismatch"


def test_verify_rejects_missing_and_non_regular(tmp_path: Path) -> None:
    inp = _write_dex(tmp_path, "classes.dex", b"x")
    (tmp_path / "classes.dex").unlink()
    with pytest.raises(JadxIndexError) as exc:
        verify_dex_inputs(tmp_path, [inp])
    assert _code_of(exc) == "mapped_file_missing"

    dir_input = DexInput(
        role=DexRole.APK_DEX,
        ordinal=1,
        source_label="d",
        relative_path="subdir",
        declared_digest=_digest(b"x"),
    )
    (tmp_path / "subdir").mkdir()
    with pytest.raises(JadxIndexError) as exc:
        verify_dex_inputs(tmp_path, [dir_input])
    assert _code_of(exc) == "mapped_file_not_regular"


def test_verify_rejects_duplicate_identical_lineage(tmp_path: Path) -> None:
    a = _write_dex(tmp_path, "same.dex", b"bytes")
    with pytest.raises(JadxIndexError) as exc:
        verify_dex_inputs(tmp_path, [a, a])
    # 同一路径先撞归一化冲突（同键即拒），语义都是 fail-closed。
    assert _code_of(exc) in {"duplicate_lineage", "normalization_conflict"}


def test_equal_bytes_distinct_lineage_kept_and_key_differs(tmp_path: Path) -> None:
    """★相同字节、不同逻辑来源：两条 lineage 都保留，且 key 不与单条混淆。"""
    data = b"identical-dex-bytes"
    a = _write_dex(tmp_path, "a/classes.dex", data)
    b_ = DexInput(
        role=DexRole.EXTRA_DEX,
        ordinal=0,
        source_label="unpacked",
        relative_path="b/classes.dex",
        declared_digest=_digest(data),
    )
    (tmp_path / "b").mkdir()
    (tmp_path / "b/classes.dex").write_bytes(data)
    lineages = verify_dex_inputs(tmp_path, [a, b_])
    assert len(lineages) == 2
    key_both = derive_index_key(lineages, "1.5.2", _OPTS)
    key_single = derive_index_key(lineages[:1], "1.5.2", _OPTS)
    assert key_both != key_single


def test_nfc_casefold_collision_rejected(tmp_path: Path) -> None:
    """★大小写折叠后同键的两个输入必须显式拒绝，不许静默去重。"""
    a = _write_dex(tmp_path, "dir/Classes.dex", b"one")
    b_ = DexInput(
        role=DexRole.EXTRA_DEX,
        ordinal=1,
        source_label="lower",
        relative_path="dir/classes.dex",
        declared_digest=_digest(b"two"),
    )
    with pytest.raises(JadxIndexError) as exc:
        verify_dex_inputs(tmp_path, [a, b_])
    assert _code_of(exc) == "normalization_conflict"


def test_source_root_must_be_absolute_existing_dir(tmp_path: Path) -> None:
    inp = _write_dex(tmp_path, "classes.dex", b"x")
    with pytest.raises(JadxIndexError) as exc:
        verify_dex_inputs("relative/root", [inp])
    assert _code_of(exc) == "invalid_source_root"
    with pytest.raises(JadxIndexError) as exc:
        verify_dex_inputs(tmp_path / "nope", [inp])
    assert _code_of(exc) == "invalid_source_root"


# ---------------------------------------------------------------------------
# Task 2：key 派生
# ---------------------------------------------------------------------------


def _lineages() -> list[DexLineage]:
    return [
        DexLineage(DexRole.EXTRA_DEX, 1, "b", _digest(b"2")),
        DexLineage(DexRole.APK_DEX, 0, "a", _digest(b"1")),
    ]


def test_key_is_insertion_order_independent() -> None:
    fwd = derive_index_key(_lineages(), "1.5.2", _OPTS)
    rev = derive_index_key(list(reversed(_lineages())), "1.5.2", _OPTS)
    assert fwd == rev
    assert len(fwd) == 64 and fwd == fwd.lower()


def test_key_changes_on_every_drift_dimension() -> None:
    base = derive_index_key(_lineages(), "1.5.2", _OPTS)
    assert derive_index_key(_lineages()[:1], "1.5.2", _OPTS) != base
    assert derive_index_key(_lineages(), "1.5.3", _OPTS) != base
    other_opts = "sha256:" + "b" * 64
    assert derive_index_key(_lineages(), "1.5.2", other_opts) != base
    with pytest.raises(JadxIndexError) as exc:
        derive_index_key(_lineages(), "1.5.2", _OPTS, index_schema_version="2.0")
    assert _code_of(exc) == "schema_drift"


def test_key_material_rejects_duplicate_lineage() -> None:
    dup = _lineages() + [_lineages()[0]]
    with pytest.raises(JadxIndexError) as exc:
        build_key_material(dup, "1.5.2", _OPTS)
    assert _code_of(exc) == "duplicate_lineage"


def test_shard_key_domain_separated_from_index_key() -> None:
    (lin,) = [_lineages()[1]]
    idx = derive_index_key([lin], "1.5.2", _OPTS)
    shard = derive_shard_key(lin, "1.5.2", _OPTS)
    assert idx != shard and len(shard) == 64


def test_key_fixed_vector() -> None:
    """★锁死一个规范向量：canonical_json_v1 编码或域分离前缀的任何漂移都在这里变红。
    期望值为字面量——绝不与实现共享推导逻辑（假绿教训）。"""
    lin = DexLineage(
        DexRole.APK_DEX,
        0,
        "classes.dex",
        "sha256:" + "0" * 64,
    )
    key = derive_index_key([lin], "9.9.9", "sha256:" + "f" * 64)
    material = build_key_material([lin], "9.9.9", "sha256:" + "f" * 64)
    # 材料本身可 JSON 往返（canonical_json_v1 拒 NaN/Inf/重复键的前提下）。
    json.loads(canonical_json_v1(material))
    assert key == "ebe1f5fded4666108898e45ac7500aa951aabd5f2a0cb1589e7dbacc456c3f7d"


# ---------------------------------------------------------------------------
# Task 3：存储层——cache root 安全
# ---------------------------------------------------------------------------

from apkscan.core.jadx_index import (  # noqa: E402
    IndexBuildResult,
    IndexBuildState,
    JadxIndexStore,
    LoadedIndex,
)


def _make_manifest(tmp_path: Path, n_dex: int = 1) -> JadxIndexManifest:
    inputs = [
        _write_dex(tmp_path / "src", f"classes{i or ''}.dex", b"dex-%d" % i) for i in range(n_dex)
    ]
    fixed = [
        DexInput(
            role=inp.role,
            ordinal=i,
            source_label=inp.source_label,
            relative_path=inp.relative_path,
            declared_digest=inp.declared_digest,
        )
        for i, inp in enumerate(inputs)
    ]
    lineage = verify_dex_inputs(tmp_path / "src", fixed)
    key = derive_index_key(lineage, "1.5.2", _OPTS)
    material = build_key_material(lineage, "1.5.2", _OPTS)
    return JadxIndexManifest(
        index_key=key,
        key_material=material,
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )


@pytest.mark.parametrize(
    "bad_root",
    ["", "relative/cache", "file:///c:/cache", "//server/share/cache", "C:relative"],
)
def test_store_rejects_unsafe_cache_root(bad_root: str) -> None:
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexStore(bad_root)
    assert _code_of(exc) == "invalid_cache_root"


def test_store_rejects_protected_root_overlap(tmp_path: Path) -> None:
    """cache root 等于/位于/包含保护根（含大小写别名）→ 一律拒绝。"""
    protected = tmp_path / "Evidence"
    protected.mkdir()
    cache_inside = protected / "cache"
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexStore(cache_inside, protected_roots=[protected])
    assert _code_of(exc) == "protected_root_overlap"
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexStore(tmp_path, protected_roots=[protected])
    assert _code_of(exc) == "protected_root_overlap"
    # 大小写折叠别名同样拦截（Windows 大小写不敏感文件系统的现实）。
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexStore(str(protected).upper(), protected_roots=[str(protected).lower()])
    assert _code_of(exc) == "protected_root_overlap"


def test_store_accepts_disjoint_roots(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    other = tmp_path / "evidence"
    other.mkdir()
    store = JadxIndexStore(cache, protected_roots=[other])
    assert store.cache_root == cache.resolve()


# ---------------------------------------------------------------------------
# Task 3：build → load 往返、幂等与崩溃恢复
# ---------------------------------------------------------------------------


def test_build_then_load_roundtrip(tmp_path: Path) -> None:
    manifest = _make_manifest(tmp_path, n_dex=2)
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(tmp_path / "src", manifest)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.BUILT
    assert result.manifest is not None and len(result.manifest.shard_refs) == 2

    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    assert loaded.manifest.index_key == manifest.index_key
    assert loaded.manifest.dex_lineage == manifest.dex_lineage
    assert len(loaded.shards) == 2
    assert loaded.coverage == "complete"


def test_rebuild_is_reused_and_immutable(tmp_path: Path) -> None:
    manifest = _make_manifest(tmp_path)
    store = JadxIndexStore(tmp_path / "cache")
    first = store.build_index(tmp_path / "src", manifest)
    assert isinstance(first, IndexBuildResult)
    manifest_path = tmp_path / "cache" / manifest.index_key / "manifest.json"
    before = manifest_path.read_bytes()
    second = store.build_index(tmp_path / "src", manifest)
    assert isinstance(second, IndexBuildResult) and second.state == IndexBuildState.REUSED
    assert manifest_path.read_bytes() == before  # 绝不改写既有产物


def test_crash_before_manifest_recovers(tmp_path: Path) -> None:
    """shard 已发布、manifest 未发布（模拟崩溃）：load=absent、重跑 build 补齐。"""
    manifest = _make_manifest(tmp_path)
    store = JadxIndexStore(tmp_path / "cache")
    built = store.build_index(tmp_path / "src", manifest)
    assert isinstance(built, IndexBuildResult)
    manifest_path = tmp_path / "cache" / manifest.index_key / "manifest.json"
    manifest_path.unlink()  # 抹掉 manifest = 崩溃前状态
    assert isinstance(store.load_index(manifest.index_key), CacheMiss)
    recovered = store.build_index(tmp_path / "src", manifest)
    assert isinstance(recovered, IndexBuildResult) and recovered.state == IndexBuildState.BUILT
    assert isinstance(store.load_index(manifest.index_key), LoadedIndex)


# ---------------------------------------------------------------------------
# Task 3：fail-closed 加载校验链
# ---------------------------------------------------------------------------


def _built_store(tmp_path: Path) -> tuple[JadxIndexStore, JadxIndexManifest]:
    manifest = _make_manifest(tmp_path)
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(tmp_path / "src", manifest)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.BUILT
    return store, manifest


def test_load_malformed_key_and_absent(tmp_path: Path) -> None:
    store = JadxIndexStore(tmp_path / "cache")
    miss = store.load_index("not-a-key")
    assert isinstance(miss, CacheMiss) and miss.reason == "malformed"
    miss = store.load_index("0" * 64)
    assert isinstance(miss, CacheMiss) and miss.reason == "absent"


def test_load_rejects_tampered_manifest_bytes(tmp_path: Path) -> None:
    store, manifest = _built_store(tmp_path)
    path = tmp_path / "cache" / manifest.index_key / "manifest.json"
    raw = path.read_bytes()
    path.write_bytes(raw.replace(b'"complete"', b'"COMPLETE"', 1))
    miss = store.load_index(manifest.index_key)
    assert isinstance(miss, CacheMiss)  # canonical 自证或字段校验，两者都 fail-closed


def test_load_rejects_tampered_aggregate_digest(tmp_path: Path) -> None:
    """★aggregate 复验：manifest 内 shard digest 集合的锚被改写必须揭穿。"""
    store, manifest = _built_store(tmp_path)
    path = tmp_path / "cache" / manifest.index_key / "manifest.json"
    raw = path.read_bytes()
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    old_aggregate = loaded.manifest.aggregate_digest.encode("ascii")
    new_aggregate = ("e" * 64).encode("ascii")
    tampered = raw.replace(old_aggregate, new_aggregate, 1)
    assert tampered != raw
    path.unlink()
    path.write_bytes(tampered)
    miss = store.load_index(manifest.index_key)
    assert isinstance(miss, CacheMiss) and miss.reason == "malformed"


def test_load_rejects_tampered_shard_bytes(tmp_path: Path) -> None:
    store, manifest = _built_store(tmp_path)
    shard_dir = tmp_path / "cache" / manifest.index_key / "shards"
    shard_path = next(shard_dir.glob("*.json"))
    shard_path.write_bytes(shard_path.read_bytes() + b" ")
    miss = store.load_index(manifest.index_key)
    assert isinstance(miss, CacheMiss) and miss.reason == "shard_digest_mismatch"


def test_load_rejects_key_mismatch_via_copied_dir(tmp_path: Path) -> None:
    """把 A 的整个索引目录复制成另一个 key 的目录名——re-derive 必须揭穿。"""
    import shutil

    store, manifest = _built_store(tmp_path)
    src_dir = tmp_path / "cache" / manifest.index_key
    fake_key = "f" * 64
    shutil.copytree(src_dir, tmp_path / "cache" / fake_key)
    miss = store.load_index(fake_key)
    assert isinstance(miss, CacheMiss) and miss.reason == "key_mismatch"


def test_shard_conflict_fails_build(tmp_path: Path) -> None:
    """同 shard 路径已有不同内容：cache_conflict → build FAILED 带诊断，不覆盖。"""
    manifest = _make_manifest(tmp_path)
    store = JadxIndexStore(tmp_path / "cache")
    shard_key = derive_shard_key(manifest.dex_lineage[0], "1.5.2", _OPTS)
    shard_path = tmp_path / "cache" / manifest.index_key / "shards" / f"{shard_key}.json"
    shard_path.parent.mkdir(parents=True)
    shard_path.write_bytes(b'{"poisoned": true}')
    result = store.build_index(tmp_path / "src", manifest)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.FAILED
    assert any("cache_conflict" in d for d in result.diagnostics)
    assert shard_path.read_bytes() == b'{"poisoned": true}'  # 原物未被覆盖


def test_symlinked_index_dir_rejected(tmp_path: Path) -> None:
    """索引目录若是符号链接（指向 cache 外）→ path escape。无权限建链则 skip。"""
    store = JadxIndexStore(tmp_path / "cache")
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "cache").mkdir(exist_ok=True)
    link = tmp_path / "cache" / ("a" * 64)
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("no symlink privilege on this host")
    result = store.load_index("a" * 64)
    assert isinstance(result, CacheMiss) and result.reason == "path_escape"


# ---------------------------------------------------------------------------
# Task 4：查询层——确定性枚举、bounded postings、find_value_usage
# ---------------------------------------------------------------------------

from apkscan.core.jadx_index import (  # noqa: E402
    Limits,
    find_value_usage,
    scan_java_sources,
)


def _java_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _lin() -> DexLineage:
    return DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"dex"))


def test_scan_produces_bounded_postings_no_raw_value(tmp_path: Path) -> None:
    src = tmp_path / "java"
    _java_tree(src, {"com/a/App.java": 'x = "needle-value";\ny = "needle-value";\n'})
    result = scan_java_sources(src, ["needle-value"], lineage=_lin(), limits=Limits())
    assert result.coverage == "complete"
    assert result.files == ("com/a/App.java",)
    assert len(result.postings) == 2
    first = result.postings[0]
    assert first["line"] == 1 and first["column"] == 6  # 1-based
    # ★postings 只带 digest，绝无原值。
    assert all("needle-value" not in str(p.values()) for p in result.postings)
    expected = "sha256:" + hashlib.sha256(b"needle-value").hexdigest()
    assert first["value_digest"] == expected


def test_scan_is_deterministic_across_creation_order(tmp_path: Path) -> None:
    """同一文件集不同创建顺序 → 逐字节相同的 files/postings 序列。"""
    files = {f"p{i}/F{i}.java": f'v = "acme-{i % 3}";\n' for i in range(12)}
    a_root = tmp_path / "a"
    b_root = tmp_path / "b"
    _java_tree(a_root, files)
    _java_tree(b_root, dict(reversed(list(files.items()))))
    values = ["acme-0", "acme-1", "acme-2"]
    ra = scan_java_sources(a_root, values, lineage=_lin(), limits=Limits())
    rb = scan_java_sources(b_root, values, lineage=_lin(), limits=Limits())
    assert ra.files == rb.files
    assert ra.postings == rb.postings


def test_scan_limit_and_truncation_yield_partial(tmp_path: Path) -> None:
    src = tmp_path / "java"
    _java_tree(src, {f"f{i}.java": "x = 1;\n" for i in range(4)})
    limited = scan_java_sources(src, ["x"], lineage=_lin(), limits=Limits(max_files=2))
    assert limited.scan_limit_hit and limited.coverage == "partial"
    assert limited.files_total == 4 and limited.scanned == 2

    big = tmp_path / "big"
    _java_tree(big, {"Big.java": "A" * 100 + "\n"})
    truncated = scan_java_sources(big, ["A"], lineage=_lin(), limits=Limits(max_file_bytes=10))
    assert truncated.truncated == 1 and truncated.coverage == "partial"


def test_build_with_scan_roundtrip_query(tmp_path: Path) -> None:
    """★端到端：扫描 → build(scan=) → load → find_value_usage 命中。"""
    manifest = _make_manifest(tmp_path)
    src = tmp_path / "java"
    _java_tree(src, {"com/x/C.java": 'u = "https://cfg-host.example/api";\n'})
    scan = scan_java_sources(
        src,
        ["https://cfg-host.example/api"],
        lineage=manifest.dex_lineage[0],
        limits=Limits(),
    )
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(tmp_path / "src", manifest, scan=scan)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.BUILT

    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    hits = find_value_usage(loaded, "https://cfg-host.example/api")
    assert len(hits) == 1
    assert hits[0].relative_path == "com/x/C.java" and hits[0].line == 1
    assert hits[0].ownership == "unknown"
    # 未命中值与超长值 → 空结果，不抛。
    assert find_value_usage(loaded, "absent-value") == ()
    assert find_value_usage(loaded, "A" * 5000) == ()


def test_partial_scan_infects_manifest_coverage(tmp_path: Path) -> None:
    manifest = _make_manifest(tmp_path)
    src = tmp_path / "java"
    _java_tree(src, {f"f{i}.java": "x = 1;\n" for i in range(3)})
    scan = scan_java_sources(
        src, ["x"], lineage=manifest.dex_lineage[0], limits=Limits(max_files=1)
    )
    assert scan.coverage == "partial"
    store = JadxIndexStore(tmp_path / "cache")
    result = store.build_index(tmp_path / "src", manifest, scan=scan)
    assert isinstance(result, IndexBuildResult)
    assert result.coverage == "partial"
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex) and loaded.coverage == "partial"


def test_find_value_usage_fail_closed_on_malformed_posting(tmp_path: Path) -> None:
    """★shard 内坏 posting（缺字段）必须当场揭穿，不许静默跳过。"""
    manifest = _make_manifest(tmp_path)
    store = JadxIndexStore(tmp_path / "cache")
    built = store.build_index(tmp_path / "src", manifest)
    assert isinstance(built, IndexBuildResult)
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    bad_shard = dict(loaded.shards[0]) if loaded.shards else {}
    bad_shard["postings"] = [{"path": "a.java", "line": 1}]  # 缺 column/value_digest
    forged = LoadedIndex(
        manifest=loaded.manifest,
        shard_locators=loaded.shard_locators,
        coverage=loaded.coverage,
        shards=(bad_shard,),
    )
    with pytest.raises(JadxIndexError) as exc:
        find_value_usage(forged, "anything")
    assert _code_of(exc) == "malformed"
