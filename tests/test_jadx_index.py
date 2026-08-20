"""P1-A jadx_index S1（契约与身份层）：类型契约、DEX 复算校验、key 派生。

对应 plan Task 1 + Task 2。每条拒绝断言精确到 reason code——「拒了」和「为对的理由拒了」
是两回事；S2/S3（发布/加载/查询/ledger 投影）的测试随后续切片补充。
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
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


def test_manifest_rejects_stale_key_with_new_options_digest() -> None:
    """★P1-D codex 复审必须项：「旧 key + 新 options_digest」的不一致 manifest
    构造即拒——否则它可凭旧 key 走 build_index 复用分支，拿旧 structure 数据
    冒充新配置的产物（生产路径先派生后构造所以不触发，但存储层必须独立 fail-closed）。"""
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    stale_key = derive_index_key([lin], "1.5.2", _OPTS)
    new_opts = "sha256:" + "b" * 64
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key=stale_key,
            key_material=build_key_material([lin], "1.5.2", new_opts),
            dex_lineage=(lin,),
            jadx_version="1.5.2",
            options_digest=new_opts,
        )
    assert _code_of(exc) == "key_mismatch"
    assert exc.value.field_path == "$.index_key"


def test_manifest_rejects_fabricated_index_key() -> None:
    """64-hex 语法合法但编造的 index_key 同样拒绝——语法校验挡不住假 key。"""
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key="f" * 64,
            key_material=build_key_material([lin], "1.5.2", _OPTS),
            dex_lineage=(lin,),
            jadx_version="1.5.2",
            options_digest=_OPTS,
        )
    assert _code_of(exc) == "key_mismatch"


def test_manifest_rejects_key_material_identity_mismatch() -> None:
    """★P1 复审必须项：key_material 是身份的持久化副本，内容与顶层字段不一致即拒——
    矛盾 manifest 一旦落盘 load 恒 CacheMiss，create-only 发布还会把 key 槽位毒化成死件。"""
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    key = derive_index_key([lin], "1.5.2", _OPTS)
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key=key,
            key_material=build_key_material([lin], "1.5.2", "sha256:" + "b" * 64),
            dex_lineage=(lin,),
            jadx_version="1.5.2",
            options_digest=_OPTS,
        )
    assert _code_of(exc) == "key_material_mismatch"
    assert exc.value.field_path == "$.key_material"


def test_manifest_snapshots_key_material_against_mutation() -> None:
    """★P1 复审必须项：frozen 是浅冻结——构造后篡改调用方 dict（含内层 lineage 记录）
    不得影响 manifest，否则先构造合法对象再改 material 就绕过了全部校验。"""
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    key = derive_index_key([lin], "1.5.2", _OPTS)
    material = build_key_material([lin], "1.5.2", _OPTS)
    manifest = JadxIndexManifest(
        index_key=key,
        key_material=material,
        dex_lineage=(lin,),
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )
    material["options_digest"] = "sha256:" + "b" * 64  # 顶层篡改
    records = material["dex_lineage"]
    assert isinstance(records, list)
    first = records[0]
    assert isinstance(first, dict)
    first["digest"] = _digest(b"tampered")  # 内层篡改（浅拷贝防不住这层）
    assert manifest.key_material == build_key_material([lin], "1.5.2", _OPTS)


def test_manifest_normalizes_pathological_key_material() -> None:
    """遍历即炸的自定义 Mapping 归一为结构化拒绝——契约层的拒绝合同是
    JadxIndexError，不许裸抛调用方容器自带的异常。"""

    class _Booby(Mapping[str, object]):
        def __getitem__(self, key: str) -> object:
            raise RuntimeError("boom")

        def __iter__(self) -> Iterator[str]:
            raise RuntimeError("boom")

        def __len__(self) -> int:
            return 4

    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    key = derive_index_key([lin], "1.5.2", _OPTS)
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key=key,
            key_material=_Booby(),
            dex_lineage=(lin,),
            jadx_version="1.5.2",
            options_digest=_OPTS,
        )
    assert _code_of(exc) == "invalid_key_material"


def test_manifest_normalizes_cyclic_key_material() -> None:
    """自引用的 key_material 在 canonical 编码阶段炸 RecursionError——同样归一为
    结构化拒绝，不裸抛。"""
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    key = derive_index_key([lin], "1.5.2", _OPTS)
    material: dict[str, object] = dict(build_key_material([lin], "1.5.2", _OPTS))
    material["dex_lineage"] = [material]  # 循环引用
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key=key,
            key_material=material,
            dex_lineage=(lin,),
            jadx_version="1.5.2",
            options_digest=_OPTS,
        )
    assert _code_of(exc) == "invalid_key_material"


def test_manifest_rejects_non_lineage_elements() -> None:
    """dex_lineage 元素必须是 DexLineage：否则身份重算走不到，拒绝就不再是
    结构化的 JadxIndexError。"""
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    key = derive_index_key([lin], "1.5.2", _OPTS)
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key=key,
            key_material=build_key_material([lin], "1.5.2", _OPTS),
            dex_lineage=(lin.to_record(),),  # type: ignore[arg-type]  # dict 冒充
            jadx_version="1.5.2",
            options_digest=_OPTS,
        )
    assert _code_of(exc) == "lineage_must_be_tuple"


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
    期望值为字面量——绝不与实现共享推导逻辑（假绿教训）。本测试是 schema bump
    检查单的第 3 项（清单见 test_jadx_resolution_migration.py::
    test_index_schema_version_bumped_to_1_6），bump 时向量必须重新独立复算。
    schema 1.0 时代的向量是 ebe1f5fd…3f7d，1.1 时代是 1b8e523f…76cb，1.2（类身份
    (name, path) 化）时代是 977adae6…de6c，1.3（arity 泛型感知计数）时代是
    1cea741b…c45e，1.4（calls 扩 qualifier/scope 四字段）时代是 70f5a03c…c29c，
    1.5（声明剔除）时代是 2b6f801e…f2b1；schema 参与 key material，1.6（注解
    使用剔除 + 局部 record 识别——内容语义 bump、形状不变）后向量合法更替为
    下值。1.6 值的独立性论证（非复制实现输出）：手工按「material 形状 +
    canonical_json_v1 + 前缀 fxapk.jadx.index/key/v1\\0 + sha256」复算，
    schema="1.4" / "1.5" 输入分别逐字节复现 70f5…c29c 与 2b6f…f2b1
    （证明派生规则未变、唯一变的 key material 输入是 index_schema_version），
    schema="1.6" 输入得下值。"""
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
    assert key == "acd01fa5c853194cf05fb05706abc8c0ecc6cf47f1da6e6517c9820973499f05"


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


def _giant_method_tree(root: Path, n_calls: int) -> None:
    calls = "\n".join("foo();" for _ in range(n_calls))
    _java_tree(
        root,
        {
            "com/x/C.java": (
                "package com.x;\n"
                "class C {\n"
                "    void giant() {\n"
                f"        {calls}\n"
                "    }\n"
                "    void foo() {}\n"
                "}\n"
            )
        },
    )


def test_giant_method_keeps_structure_partial(tmp_path: Path) -> None:
    """P1-D 诚实边界锁：文件全扫完（不撞 max_files）时，超大方法仍须因
    calls_cap（单方法调用点数上限，**精确 256**）保持 partial——P1-D 只调 max_files，
    刻意不碰 max_calls_per_method。精确锁边界值：256 恰好达界 complete、257 触界
    partial 且 calls 截断在 256——若有人把 cap 从 256 悄悄放宽到任何更大值，
    257 侧断言必红（codex 复审：只断言「300 → partial」锁不住 cap 具体值）。"""
    at_cap = tmp_path / "at-cap"
    _giant_method_tree(at_cap, 256)
    ok = scan_java_sources(at_cap, [], lineage=_lin(), limits=Limits(max_files=100))
    assert ok.scan_limit_hit is False and ok.coverage == "complete"

    over_cap = tmp_path / "over-cap"
    _giant_method_tree(over_cap, 257)
    scan = scan_java_sources(over_cap, [], lineage=_lin(), limits=Limits(max_files=100))
    assert scan.scan_limit_hit is False  # 没撞文件上限
    assert scan.coverage == "partial"  # 因 calls_cap 不完整
    (cls,) = [c for c in scan.structure if c["name"] == "com.x.C"]
    giant = next(m for m in cls["methods"] if m["name"] == "giant")  # type: ignore[union-attr]
    assert len(giant["calls"]) == 256  # 截断点精确在 cap


def test_total_byte_budget_stops_scan_honestly(tmp_path: Path) -> None:
    """★聚合读取预算：max_files × max_file_bytes 的理论积（调大 max_files 后约
    47GiB）不能成为敌对样本可实际兑现的读取量。累计读取触顶即停、剩余文件不扫，
    coverage 诚实降 partial，且可与文件数上限（scan_limit_hit）、单文件截断
    （truncated）、读失败（read_failed）区分：scanned < files_total 而三者皆零。"""
    src = tmp_path / "java"
    body = "x = 1;\n" * 40  # 每文件约 280 字节
    _java_tree(src, {f"com/x/F{i}.java": body for i in range(6)})

    capped = scan_java_sources(
        src, [], lineage=_lin(), limits=Limits(max_files=100, max_total_bytes=300)
    )
    assert capped.coverage == "partial"
    assert capped.scan_limit_hit is False
    assert capped.read_failed == 0 and capped.truncated == 0
    assert 0 < capped.scanned < capped.files_total  # 预算触顶提前停

    unlimited = scan_java_sources(src, [], lineage=_lin(), limits=Limits(max_files=100))
    assert unlimited.coverage == "complete"  # 默认预算远大于真实产物，不误伤
    assert unlimited.scanned == unlimited.files_total


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
