"""P4-A 红态契约：apkscan/core/recognition_labels.py（多任务标签契约）。

核心不变量（设计见本地 P4 v2 spec §1/§6）：
- 五种记录 kind、closed-world 字段集、严格 JSONL；
- author_kind=model ⇒ status=proposed 且 layer=silver（模型无权晋级/无权写 gold）；
- same_operator 确认下界 = author_kind=human + independent-review + evidence_ref
  ——这是机器最低门槛，不是「人工程序已完成」的证明；
- active（未废弃，含 proposed）与 effective（仅 confirmed，唯一可消费面）双投影；
- record_id 全文件唯一（跨 kind）；supersedes 单值同 kind、禁自指、目标须 superseded 态、
  至多一个后继；文件顺序无要求；
- reanalysis_outcome 只记 coverage 事实，绝不携带 family/relation/clue 语义。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkscan.core import recognition_labels as rlabels

HEX_A = "a" * 64
HEX_B = "b" * 64


def _common(**over):
    record = {
        "kind": "family_assignment",
        "schema_version": "1.0",
        "record_id": "rec-0001",
        "status": "confirmed",
        "layer": "silver",
        "author_kind": "human",
        "label_basis": ["independent-review"],
        "evidence_ref": "bundle:2026/fixture-0001",
        "label_lineage": "unspecified",
        "confidence": 0.9,
        "supersedes": None,
        "reason_codes": ["fixture-reason"],
    }
    record.update(over)
    return record


def _family(**over):
    record = _common(
        sample_sha256=HEX_A,
        level="platform_family",
        family_id="fixture-family",
    )
    record.update(over)
    return record


def _relation(**over):
    record = _common(
        kind="relation_judgment",
        record_id="rec-rel-0001",
        left_sha256=HEX_A,
        right_sha256=HEX_B,
        relation="positive",
        relation_subtype="binary_lineage",
    )
    record.pop("sample_sha256", None)
    record.update(over)
    return record


def _clue(**over):
    record = _common(
        kind="clue_judgment",
        record_id="rec-clue-0001",
        clue_ref="clue:fixture/0001",
        verdict="valid",
        ownership="suspect_first_party",
    )
    record.update(over)
    return record


def _ownership(**over):
    record = _common(
        kind="ownership_judgment",
        record_id="rec-own-0001",
        sample_sha256=HEX_A,
        observation_ref="observation:fixture/0001",
        ownership="inherited_third_party",
    )
    record.update(over)
    return record


def _outcome(**over):
    record = _common(
        kind="reanalysis_outcome",
        record_id="rec-out-0001",
        request_id="action-sha256:" + "c" * 64,
        outcome="obtained",
        obtained_observation_types=["jadx_value_usage"],
        coverage_reason_codes=[],
    )
    record.update(over)
    return record


def _write(tmp_path: Path, *records) -> Path:
    path = tmp_path / "labels.jsonl"
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
    )
    return path


def _load(tmp_path: Path, *records):
    return rlabels.load_recognition_labels(_write(tmp_path, *records))


def _error(tmp_path: Path, *records) -> rlabels.RecognitionLabelValidationError:
    with pytest.raises(rlabels.RecognitionLabelValidationError) as exc:
        _load(tmp_path, *records)
    return exc.value


# ---------------------------------------------------------------- 装载与 closed-world


def test_loads_all_five_kinds(tmp_path):
    label_set = _load(
        tmp_path, _family(), _relation(), _clue(), _ownership(), _outcome()
    )
    assert label_set.record_count == 5
    kinds = dict(label_set.kind_counts)
    assert kinds == {
        "family_assignment": 1,
        "relation_judgment": 1,
        "clue_judgment": 1,
        "ownership_judgment": 1,
        "reanalysis_outcome": 1,
    }


def test_empty_file_is_valid_and_empty(tmp_path):
    path = tmp_path / "labels.jsonl"
    path.write_text("", encoding="utf-8")
    label_set = rlabels.load_recognition_labels(path)
    assert label_set.record_count == 0
    assert label_set.active == ()
    assert label_set.effective == ()


def test_unknown_kind_and_unknown_key_fail_closed(tmp_path):
    assert _error(tmp_path, _family(kind="pair_judgment")).code == "kind_unknown"
    error = _error(tmp_path, _family(surprise=True))
    assert error.code == "field_set_mismatch"
    assert error.line == 1


def test_missing_field_fails_closed(tmp_path):
    record = _family()
    record.pop("evidence_ref")
    assert _error(tmp_path, record).code == "field_set_mismatch"


def test_error_carries_first_offending_line(tmp_path):
    error = _error(tmp_path, _family(), _relation(relation="both"))
    assert error.line == 2


# ---------------------------------------------------------------- 模型写入边界


def test_model_author_must_stay_proposed(tmp_path):
    assert (
        _error(tmp_path, _family(author_kind="model", status="confirmed")).code
        == "model_status_forbidden"
    )


def test_model_author_must_stay_in_silver(tmp_path):
    record = _family(
        author_kind="model",
        status="proposed",
        layer="gold_internal",
        label_lineage="queue-internal",
    )
    assert _error(tmp_path, record).code == "model_layer_forbidden"


def test_model_proposed_silver_is_legal_but_not_effective(tmp_path):
    label_set = _load(tmp_path, _family(author_kind="model", status="proposed"))
    assert len(label_set.active) == 1
    assert label_set.effective == ()  # proposed 绝不进可消费面


# ---------------------------------------------------------------- same_operator 机器下界


def test_same_operator_confirmed_requires_full_floor(tmp_path):
    base = dict(
        relation_subtype="same_operator",
        status="confirmed",
        label_lineage="queue-external",
    )
    ok = _relation(**base)
    assert _load(tmp_path, ok).record_count == 1

    assert (
        _error(tmp_path, _relation(**base, author_kind="system")).code
        == "same_operator_confirmation_floor"
    )
    assert (
        _error(tmp_path, _relation(**base, label_basis=["ioc-review"])).code
        == "same_operator_confirmation_floor"
    )
    assert (
        _error(tmp_path, _relation(**base, evidence_ref=None)).code
        == "same_operator_confirmation_floor"
    )


def test_same_operator_proposed_needs_no_floor(tmp_path):
    record = _relation(
        relation_subtype="same_operator",
        status="proposed",
        author_kind="system",
        label_basis=["rule-candidate-review"],
        evidence_ref=None,
    )
    assert _load(tmp_path, record).record_count == 1


# ---------------------------------------------------------------- 分层与 lineage


def test_gold_layers_bind_lineage(tmp_path):
    assert (
        _error(
            tmp_path,
            _family(layer="gold_internal", label_lineage="queue-external"),
        ).code
        == "layer_lineage_mismatch"
    )
    assert (
        _error(
            tmp_path,
            _family(layer="gold_external", label_lineage="queue-internal"),
        ).code
        == "layer_lineage_mismatch"
    )
    ok = _family(layer="gold_external", label_lineage="queue-external")
    assert _load(tmp_path, ok).record_count == 1


# ---------------------------------------------------------------- record_id / supersedes 状态机


def test_record_id_must_be_globally_unique_across_kinds(tmp_path):
    assert (
        _error(tmp_path, _family(), _clue(record_id="rec-0001")).code
        == "record_id_duplicate"
    )


def test_supersedes_target_must_exist_same_kind_no_self(tmp_path):
    assert (
        _error(tmp_path, _family(supersedes="rec-missing")).code
        == "supersedes_unknown_target"
    )
    assert (
        _error(tmp_path, _family(supersedes="rec-0001")).code
        == "supersedes_self_reference"
    )
    cross = _clue(record_id="rec-x", supersedes="rec-0001")
    assert _error(tmp_path, _family(status="superseded"), cross).code == (
        "supersedes_kind_mismatch"
    )


def test_supersedes_target_status_must_be_superseded(tmp_path):
    old = _family(record_id="rec-old", status="confirmed")
    new = _family(record_id="rec-new", supersedes="rec-old")
    assert _error(tmp_path, old, new).code == "supersedes_target_not_superseded"


def test_supersedes_allows_out_of_order_lines_and_single_successor(tmp_path):
    new = _family(record_id="rec-new", supersedes="rec-old")
    old = _family(record_id="rec-old", status="superseded")
    label_set = _load(tmp_path, new, old)  # 后继在前：两遍装载必须放行
    assert label_set.record_count == 2

    rival = _family(record_id="rec-rival", supersedes="rec-old")
    assert _error(tmp_path, new, old, rival).code == "supersedes_multiple_successors"


# ---------------------------------------------------------------- 自然键与多标签


def test_duplicate_active_natural_key_rejected(tmp_path):
    twin = _family(record_id="rec-0002")
    assert _error(tmp_path, _family(), twin).code == "natural_key_conflict"


def test_multi_family_per_level_is_legal(tmp_path):
    second = _family(record_id="rec-0002", family_id="another-family")
    label_set = _load(tmp_path, _family(), second)
    assert len(label_set.effective) == 2  # 同层多族并存＝母设计的多标签开放集


def test_revision_via_supersedes_keeps_single_active(tmp_path):
    old = _family(record_id="rec-old", status="superseded")
    new = _family(record_id="rec-new", supersedes="rec-old")
    label_set = _load(tmp_path, old, new)
    active_ids = {record.record_id for record in label_set.active}
    assert active_ids == {"rec-new"}


# ---------------------------------------------------------------- 值域


def test_sha_fields_must_be_64_hex(tmp_path):
    assert _error(tmp_path, _family(sample_sha256="XYZ")).code == "sha256_invalid"
    assert (
        _error(tmp_path, _relation(left_sha256="f" * 63)).code == "sha256_invalid"
    )


def test_relation_pair_must_be_canonically_ordered(tmp_path):
    swapped = _relation(left_sha256=HEX_B, right_sha256=HEX_A)
    assert _error(tmp_path, swapped).code == "pair_order_invalid"


def test_relation_subtype_covers_master_eight_and_rejects_others(tmp_path):
    for subtype in (
        "exact_artifact_identity",
        "product_line_reuse",
        "technical_link_relevant",
    ):
        record = _relation(record_id=f"rec-{subtype[:8]}", relation_subtype=subtype)
        assert _load(tmp_path, record).record_count == 1
    assert (
        _error(tmp_path, _relation(relation_subtype="same_campaign")).code
        == "relation_subtype_unknown"
    )


def test_confidence_rejects_bool_and_out_of_range(tmp_path):
    assert _error(tmp_path, _family(confidence=True)).code == "confidence_invalid"
    assert _error(tmp_path, _family(confidence=1.5)).code == "confidence_invalid"
    ok = _family(confidence=None)
    assert _load(tmp_path, ok).record_count == 1


def test_family_id_reserved_words_rejected(tmp_path):
    for reserved in ("unknown", "abstain"):
        assert (
            _error(tmp_path, _family(family_id=reserved)).code
            == "family_id_reserved"
        )


def test_ownership_vocabulary_enforced(tmp_path):
    assert (
        _error(tmp_path, _ownership(ownership="first-party")).code
        == "ownership_invalid"
    )
    assert (
        _error(tmp_path, _clue(verdict="maybe")).code == "verdict_invalid"
    )


# ---------------------------------------------------------------- reanalysis_outcome 边界


def test_outcome_vocabulary(tmp_path):
    for outcome in ("obtained", "partial", "not_obtained"):
        record = _outcome(record_id=f"rec-{outcome}", outcome=outcome)
        assert _load(tmp_path, record).record_count == 1
    assert _error(tmp_path, _outcome(outcome="failed")).code == "outcome_invalid"


def test_outcome_carries_no_label_semantics(tmp_path):
    # closed-world 已挡未知键；这里锁死最危险的三个语义字段名。
    for forbidden in ("family_id", "relation", "verdict"):
        record = _outcome(**{forbidden: "x"})
        error = _error(tmp_path, record)
        assert error.code == "field_set_mismatch"


# ---------------------------------------------------------------- codex 复审补锁


def test_first_offending_line_wins_across_passes(tmp_path):
    # 行 2 是跨记录违规（record_id 重复）、行 3 是行内违规：必须报行 2。
    dup = _family(record_id="rec-0001", family_id="second-family")
    bad = _relation(relation="both")
    error = _error(tmp_path, _family(), dup, bad)
    assert error.code == "record_id_duplicate"
    assert error.line == 2


def test_supersedes_two_node_cycle_rejected(tmp_path):
    a = _family(record_id="rec-a", status="superseded", supersedes="rec-b")
    b = _family(
        record_id="rec-b",
        status="superseded",
        supersedes="rec-a",
        family_id="second-family",
    )
    error = _error(tmp_path, a, b)
    assert error.code == "supersedes_cycle"
    assert error.line == 2


def test_supersedes_long_cycle_rejected_and_legal_chain_passes(tmp_path):
    a = _family(record_id="rec-a", status="superseded", supersedes="rec-b")
    b = _family(
        record_id="rec-b", status="superseded", supersedes="rec-c",
        family_id="family-b",
    )
    c = _family(
        record_id="rec-c", status="superseded", supersedes="rec-a",
        family_id="family-c",
    )
    assert _error(tmp_path, a, b, c).code == "supersedes_cycle"

    oldest = _family(record_id="rec-1", status="superseded")
    middle = _family(record_id="rec-2", status="superseded", supersedes="rec-1")
    newest = _family(record_id="rec-3", supersedes="rec-2")
    label_set = _load(tmp_path, oldest, middle, newest)
    assert {record.record_id for record in label_set.active} == {"rec-3"}


def test_label_basis_controlled_vocabulary(tmp_path):
    assert _error(tmp_path, _family(label_basis=[])).code == "label_basis_invalid"
    assert (
        _error(tmp_path, _family(label_basis=["not/a controlled basis"])).code
        == "label_basis_invalid"
    )
    assert (
        _error(
            tmp_path,
            _family(label_basis=["ioc-review", "ioc-review"]),
        ).code
        == "label_basis_invalid"
    )


def test_evidence_ref_placeholder_rejected(tmp_path):
    assert (
        _error(tmp_path, _family(evidence_ref="placeholder")).code
        == "evidence_ref_invalid"
    )


def test_reason_codes_reject_duplicates_and_bad_tokens(tmp_path):
    assert (
        _error(tmp_path, _family(reason_codes=["x", "x"])).code
        == "reason_codes_invalid"
    )
    assert (
        _error(tmp_path, _family(reason_codes=["bad token"])).code
        == "reason_codes_invalid"
    )


def test_validate_recognition_label_single_record_api():
    rlabels.validate_recognition_label(_family())
    with pytest.raises(rlabels.RecognitionLabelValidationError) as exc:
        rlabels.validate_recognition_label(_family(family_id="unknown"))
    assert exc.value.code == "family_id_reserved"
    assert exc.value.line == 1
