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
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key=key,
            key_material={},
            dex_lineage=(lin,),
            jadx_version="1.5.2",
            options_digest=INDEX_SCHEMA_VERSION,  # 恰是曾经的坏默认值
        )
    assert _code_of(exc) == "invalid_digest"


def test_manifest_rejects_schema_drift() -> None:
    lin = DexLineage(DexRole.APK_DEX, 0, "classes.dex", _digest(b"x"))
    key = derive_index_key([lin], "1.5.2", _OPTS)
    with pytest.raises(JadxIndexError) as exc:
        JadxIndexManifest(
            index_key=key,
            key_material={},
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
