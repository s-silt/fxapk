"""P5-A split-manifest 红态测试（契约见 docs/superpowers/specs/2026-08-17-p5a-split-manifest-design.md）。

夹具值全部合成：sha 用重复十六进制字节，case 用 case-* 占位。
"""

from __future__ import annotations

import hashlib
import json

import pytest

from apkscan.core.recognition_labels import (
    RecognitionLabelRecord,
    RecognitionLabelSet,
)
from apkscan.core.recognition_training import (
    SplitConfig,
    SplitManifestError,
    build_split_manifest,
    encode_split_manifest,
    load_split_manifest,
)

SHA_A = "aa" * 32
SHA_B = "bb" * 32
SHA_C = "cc" * 32
SHA_D = "dd" * 32
LABELS_DIGEST = "ab" * 32

SPLIT_NAMES = frozenset(
    {
        "train",
        "calibration",
        "test_temporal_seen",
        "test_unseen_family",
        "test_adversarial",
    }
)

_seq = iter(range(1, 10_000))


def _record(kind: str, status: str = "confirmed", **fields: object) -> RecognitionLabelRecord:
    return RecognitionLabelRecord(
        kind=kind,
        schema_version="1.0",
        record_id=f"rec-{next(_seq):04d}",
        status=status,
        layer="silver",
        author_kind="human",
        label_basis=(),
        evidence_ref=None,
        label_lineage="unspecified",
        confidence=None,
        supersedes=None,
        reason_codes=(),
        **fields,  # type: ignore[arg-type]
    )


def _family(sha: str, family_id: str, status: str = "confirmed") -> RecognitionLabelRecord:
    return _record(
        "family_assignment",
        status=status,
        sample_sha256=sha,
        level="product_line",
        family_id=family_id,
    )


def _relation(
    left: str, right: str, relation: str = "positive", status: str = "confirmed"
) -> RecognitionLabelRecord:
    return _record(
        "relation_judgment",
        status=status,
        left_sha256=left,
        right_sha256=right,
        relation=relation,
        relation_subtype="binary_lineage",
    )


def _label_set(*records: RecognitionLabelRecord) -> RecognitionLabelSet:
    active = tuple(r for r in records if r.status not in {"superseded", "rejected"})
    effective = tuple(r for r in active if r.status == "confirmed")
    return RecognitionLabelSet(
        records=tuple(records),
        active=active,
        effective=effective,
        kind_counts=(),
        status_counts=(),
        layer_counts=(),
    )


def _row(sha: str, *case_ids: str, record_state: str = "active") -> dict:
    return {
        "sample_sha256": sha,
        "tool_version": "1.6.1",
        "ruleset_digest": "rules-v2",
        "evidence_surface": "static",
        "case_ids": list(case_ids),
        "record_state": record_state,
        "record_state_reason": None,
        "ingest_sequence": None,
    }


def _config(**over: object) -> SplitConfig:
    base: dict = {
        "cutoff_date": "2026-01-01",
        "unseen_families": (),
        "adversarial_samples": (),
        "calibration_samples": (),
        "derivations": (),
        "policy_version": "split-v1",
        "labels_digest": LABELS_DIGEST,
        "catalog_revision": "rev-1",
    }
    base.update(over)
    return SplitConfig(**base)  # type: ignore[arg-type]


TIME = {
    "case-early": "2025-11-15",
    "case-mid": "2025-12-20",
    "case-late": "2026-03-01",
}


def _build(rows, label_set=None, time_table=TIME, **config_over):
    return build_split_manifest(
        rows,
        label_set if label_set is not None else _label_set(),
        time_table,
        _config(**config_over),
    )


def _units(manifest):
    for name in SPLIT_NAMES:
        for unit in manifest.splits[name]:
            yield name, unit


def _split_of(manifest, sha: str) -> str:
    hits = [name for name, unit in _units(manifest) if sha in unit.members]
    assert len(hits) == 1, f"{sha[:8]} 命中 {hits}"
    return hits[0]


def _unit_of(manifest, sha: str):
    for _, unit in _units(manifest):
        if sha in unit.members:
            return unit
    raise AssertionError(f"{sha[:8]} 不在任何单位")


# ---------------------------------------------------------------- 闭包（T1-T5）


def test_same_case_merges_and_unrelated_stays_apart() -> None:
    manifest = _build(
        [_row(SHA_A, "case-early"), _row(SHA_B, "case-early"), _row(SHA_C, "case-mid")]
    )
    assert _unit_of(manifest, SHA_A) is _unit_of(manifest, SHA_B)
    assert set(_unit_of(manifest, SHA_A).members) == {SHA_A, SHA_B}
    assert set(_unit_of(manifest, SHA_C).members) == {SHA_C}


def test_confirmed_positive_relation_merges_negative_and_unknown_do_not() -> None:
    rows = [_row(SHA_A, "case-early"), _row(SHA_B, "case-mid"), _row(SHA_C, "case-mid2")]
    time = {**TIME, "case-mid2": "2025-12-21"}
    merged = _build(rows, _label_set(_relation(SHA_A, SHA_B, "positive")), time_table=time)
    assert _unit_of(merged, SHA_A) is _unit_of(merged, SHA_B)
    for verdict in ("negative", "unknown"):
        apart = _build(rows, _label_set(_relation(SHA_A, SHA_B, verdict)), time_table=time)
        assert _unit_of(apart, SHA_A) is not _unit_of(apart, SHA_B)


def test_non_effective_labels_never_merge() -> None:
    rows = [_row(SHA_A, "case-early"), _row(SHA_B, "case-mid")]
    for status in ("proposed", "rejected", "superseded"):
        manifest = _build(rows, _label_set(_relation(SHA_A, SHA_B, status=status)))
        assert _unit_of(manifest, SHA_A) is not _unit_of(manifest, SHA_B)
        manifest = _build(
            rows,
            _label_set(
                _family(SHA_A, "fam-x", status=status), _family(SHA_B, "fam-x", status=status)
            ),
        )
        assert _unit_of(manifest, SHA_A) is not _unit_of(manifest, SHA_B)


def test_confirmed_family_merges_but_reserved_ids_do_not() -> None:
    rows = [_row(SHA_A, "case-early"), _row(SHA_B, "case-mid")]
    merged = _build(rows, _label_set(_family(SHA_A, "fam-x"), _family(SHA_B, "fam-x")))
    assert _unit_of(merged, SHA_A) is _unit_of(merged, SHA_B)
    for reserved in ("unknown", "abstain"):
        apart = _build(rows, _label_set(_family(SHA_A, reserved), _family(SHA_B, reserved)))
        assert _unit_of(apart, SHA_A) is not _unit_of(apart, SHA_B)


def test_explicit_derivation_pair_merges() -> None:
    manifest = _build(
        [_row(SHA_A, "case-early"), _row(SHA_B, "case-mid")],
        derivations=((SHA_A, SHA_B),),
    )
    assert _unit_of(manifest, SHA_A) is _unit_of(manifest, SHA_B)


# ---------------------------------------------------------- 切分不变量（T6-T9）


def test_five_splits_exist_and_partition_is_exact() -> None:
    manifest = _build(
        [_row(SHA_A, "case-early"), _row(SHA_B, "case-mid"), _row(SHA_C, "case-late")]
    )
    assert set(manifest.splits) == SPLIT_NAMES
    seen: list[str] = []
    for _, unit in _units(manifest):
        seen.extend(unit.members)
    assert sorted(seen) == sorted({SHA_A, SHA_B, SHA_C})


def test_unseen_family_is_isolated_and_adversarial_capture_rejects() -> None:
    rows = [_row(SHA_A, "case-early"), _row(SHA_B, "case-mid"), _row(SHA_C, "case-late")]
    labels = _label_set(_family(SHA_A, "fam-u"), _family(SHA_B, "fam-u"))
    manifest = _build(rows, labels, unseen_families=("fam-u",))
    assert _split_of(manifest, SHA_A) == "test_unseen_family"
    assert _split_of(manifest, SHA_B) == "test_unseen_family"
    for name in SPLIT_NAMES - {"test_unseen_family"}:
        assert all("fam-u" not in unit.family_ids for unit in manifest.splits[name])
    with pytest.raises(SplitManifestError) as exc:
        _build(rows, labels, unseen_families=("fam-u",), adversarial_samples=(SHA_A,))
    assert exc.value.reason_code == "unseen_isolation_violation"


def test_adversarial_takes_whole_unit_and_never_trains() -> None:
    manifest = _build(
        [_row(SHA_A, "case-early"), _row(SHA_B, "case-early")],
        adversarial_samples=(SHA_A,),
    )
    assert _split_of(manifest, SHA_A) == "test_adversarial"
    assert _split_of(manifest, SHA_B) == "test_adversarial"
    for name in ("train", "calibration"):
        assert manifest.splits[name] == ()


def test_unit_spanning_cutoff_leaves_train_by_max_rule() -> None:
    manifest = _build(
        [_row(SHA_A, "case-early"), _row(SHA_B, "case-late")],
        _label_set(_relation(SHA_A, SHA_B, "positive")),
    )
    assert _split_of(manifest, SHA_A) == "test_temporal_seen"
    assert _split_of(manifest, SHA_B) == "test_temporal_seen"


# ------------------------------------------------------- fail-closed（T10、T14）


def test_missing_case_time_rejects_with_case_list() -> None:
    with pytest.raises(SplitManifestError) as exc:
        _build([_row(SHA_A, "case-unlisted")])
    assert exc.value.reason_code == "time_missing"
    assert "case-unlisted" in str(exc.value)


def test_calibration_sample_after_cutoff_rejects() -> None:
    with pytest.raises(SplitManifestError) as exc:
        _build([_row(SHA_A, "case-late")], calibration_samples=(SHA_A,))
    assert exc.value.reason_code == "calibration_conflict"


def test_calibration_sample_before_cutoff_lands_in_calibration() -> None:
    manifest = _build(
        [_row(SHA_A, "case-early"), _row(SHA_B, "case-mid")],
        calibration_samples=(SHA_A,),
    )
    assert _split_of(manifest, SHA_A) == "calibration"
    assert _split_of(manifest, SHA_B) == "train"


# ------------------------------------------------- 确定性与冻结（T11-T13）


def test_build_is_deterministic_under_input_reordering() -> None:
    rows = [_row(SHA_A, "case-early"), _row(SHA_B, "case-mid"), _row(SHA_C, "case-late")]
    labels = (_family(SHA_A, "fam-x"), _family(SHA_B, "fam-x"))
    one = _build(list(rows), _label_set(*labels))
    other = _build(list(reversed(rows)), _label_set(*reversed(labels)))
    assert encode_split_manifest(one) == encode_split_manifest(other)


def test_tampered_manifest_is_rejected_fail_closed() -> None:
    text = encode_split_manifest(_build([_row(SHA_A, "case-early")]))
    assert load_split_manifest(text) is not None
    tampered = text.replace(LABELS_DIGEST, "e" + LABELS_DIGEST[1:], 1)
    assert tampered != text
    with pytest.raises(SplitManifestError) as exc:
        load_split_manifest(tampered)
    assert exc.value.reason_code == "digest_mismatch"


def test_unknown_schema_version_is_rejected_even_with_valid_digest() -> None:
    text = encode_split_manifest(_build([_row(SHA_A, "case-early")]))
    payload = json.loads(text)
    payload["schema_version"] = "9.9"
    payload.pop("manifest_digest")
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    payload["manifest_digest"] = hashlib.sha256(
        ("fxapk-split-manifest-v1\n" + canonical).encode("utf-8")
    ).hexdigest()
    retagged = (
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        + "\n"
    )
    with pytest.raises(SplitManifestError) as exc:
        load_split_manifest(retagged)
    assert exc.value.reason_code == "schema_unknown"


def test_empty_inputs_produce_honest_empty_manifest_roundtrip() -> None:
    manifest = _build([], time_table={})
    assert set(manifest.splits) == SPLIT_NAMES
    assert all(manifest.splits[name] == () for name in SPLIT_NAMES)
    text = encode_split_manifest(manifest)
    assert encode_split_manifest(load_split_manifest(text)) == text


def test_unknown_policy_version_is_rejected() -> None:
    with pytest.raises(SplitManifestError) as exc:
        _build([_row(SHA_A, "case-early")], policy_version="split-v0")
    assert exc.value.reason_code == "policy_unknown"
