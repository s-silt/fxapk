"""与原件矛盾的 exact xref 必须拒绝；没有原件时只能标成未本地核验。"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

from apkscan.core.dex_query import (
    DexQueryError,
    DexQueryLimits,
    _canonical_text,
    _receipt_from_worker,
    import_receipt,
    inventory_dex_members,
    query_apk,
)
from tests.fixtures.dex_query.dexgen import (
    DexClassSpec,
    DexMethodSpec,
    ExpectedHit,
    build_dex,
    sample_classes,
    zip_bytes,
)
from tests.test_dex_query_inventory import _raw_zip

_WORKER = [sys.executable, "tests/fixtures/dex_query/fake_worker.py"]
_VALUE = "api.example.invalid"
_OTHER = "other.example.invalid"
_LIMITS = DexQueryLimits(timeout_sec=20, memory_bytes=256 * 1024 * 1024)


def _case_report(sample: str) -> dict[str, object]:
    return {
        "package_name": "example.invalid",
        "schema_version": "1.2",
        "endpoints": [],
        "findings": [],
        "analyzer_status": [],
        "meta": {
            "sample_sha256": sample,
            "closure": {"status": "partial", "gaps": ["keep"]},
        },
        "leads": [
            {
                "category": "DOMAIN",
                "value": _VALUE,
                "advice": "建议调证",
                "confidence": "HIGH",
                "is_runtime_seen": True,
                "is_runtime_contact": True,
                "notes": "dynamic-observed",
                "source_refs": [
                    {
                        "source": "runtime",
                        "location": "socket",
                        "snippet": "observed",
                        "scope": "case_evidence",
                    }
                ],
            }
        ],
    }


def _write_report(path: Path, sample: str) -> None:
    path.write_text(json.dumps(_case_report(sample)), encoding="utf-8")


def _resign(receipt: dict[str, object]) -> None:
    members = receipt["members"]
    assert isinstance(members, list)
    hit = members[0]["hits"][0]
    body = {key: value for key, value in hit.items() if key != "evidence_sha256"}
    hit["evidence_sha256"] = hashlib.sha256(_canonical_text(body)).hexdigest()
    naked = {key: value for key, value in receipt.items() if key != "receipt_id"}
    receipt["receipt_id"] = hashlib.sha256(_canonical_text(naked)).hexdigest()


def _two_method_receipt(tmp_path: Path) -> tuple[Path, dict[str, object], ExpectedHit, ExpectedHit]:
    """A 引用 _VALUE，B 引用另一个值。回执按 dexgen 坐标组装，fake_worker 不认识这个形状。"""
    dex = build_dex((
        DexClassSpec("Lexample/invalid/Trust;", (
            DexMethodSpec("hasValue", (), "Ljava/lang/String;", _VALUE),
            DexMethodSpec("otherValue", (), "Ljava/lang/String;", _OTHER),
        )),
    ))
    good, bad = dex.hits
    assert good.string == _VALUE
    assert bad.string == _OTHER
    apk = tmp_path / "synthetic.apk"
    apk.write_bytes(zip_bytes([("classes.dex", dex.data)]))
    members, skipped, truncated = inventory_dex_members(apk)
    member = members[0]
    hit = {
        "value_sha256": hashlib.sha256(_VALUE.encode("utf-8")).hexdigest(),
        "descriptor": good.descriptor,
        "offset": good.code_unit_offset,
        "offset_unit": "code_units",
        "file_offset": good.file_offset,
        "precision": "exact",
    }
    receipt = _receipt_from_worker(
        {"members": [{
            "name": member.name,
            "ordinal": member.ordinal,
            "sha256": member.sha256,
            "status": "hit",
            "precision": "exact",
            "truncated": False,
            "hits": [hit],
        }]},
        hashlib.sha256(apk.read_bytes()).hexdigest(),
        [_VALUE],
        members,
        skipped,
        truncated,
        DexQueryLimits(),
    )
    return apk, receipt, good, bad


def _store(path: Path, receipt: dict[str, object]) -> None:
    path.write_bytes(_canonical_text(receipt))


def _static_snippets(report: dict[str, object]) -> list[str]:
    snippets: list[str] = []
    leads = report["leads"]
    assert isinstance(leads, list)
    for lead in leads:
        refs = lead["source_refs"]
        for ref in refs:
            if ref.get("source") == "static-dex-xref":
                snippets.append(str(ref["snippet"]))
    return snippets


def _assert_runtime_kept(report: dict[str, object]) -> None:
    assert report["meta"]["closure"] == {"status": "partial", "gaps": ["keep"]}
    leads = {item["value"]: item for item in report["leads"]}
    kept = leads[_VALUE]
    assert kept["advice"] == "建议调证"
    assert kept["confidence"] == "HIGH"
    assert kept["is_runtime_seen"] is True
    assert kept["is_runtime_contact"] is True
    assert kept["notes"] == "dynamic-observed"
    assert kept["source_refs"][0]["source"] == "runtime"
    assert kept["source_refs"][0]["snippet"] == "observed"


@pytest.mark.skipif(sys.platform == "darwin", reason="RLIMIT_AS not enforceable on macOS; dex worker memory limit unavailable")
def test_query_apk_import_marks_xref_verified(tmp_path: Path) -> None:
    dex = build_dex(sample_classes(_VALUE))
    apk = tmp_path / "app.apk"
    apk.write_bytes(zip_bytes([("classes.dex", dex.data)]))
    receipt_path = tmp_path / "receipt.json"
    receipt = query_apk(apk, [_VALUE], worker_argv=_WORKER, limits=_LIMITS, out=receipt_path)
    report_path = tmp_path / "report.json"
    _write_report(report_path, receipt["apk_sha256"])
    out = tmp_path / "imported"
    result = import_receipt(receipt_path, report_path, out, apk=apk)
    assert result["status"] == "imported"
    merged = json.loads((out / "report.json").read_text(encoding="utf-8"))
    summary = merged["meta"]["dex_query"]["receipts"][0]
    assert summary["xref_verified"] is True
    assert summary["xref_verification"] == "verified_against_apk"
    snippets = _static_snippets(merged)
    assert snippets
    assert all("xref=verified" in item for item in snippets)
    _assert_runtime_kept(merged)


def test_descriptor_of_other_method_is_rejected(tmp_path: Path) -> None:
    apk, receipt, _good, bad = _two_method_receipt(tmp_path)
    mutated = copy.deepcopy(receipt)
    mutated["members"][0]["hits"][0]["descriptor"] = bad.descriptor
    _resign(mutated)
    receipt_path = tmp_path / "wrong-descriptor.json"
    _store(receipt_path, mutated)
    report_path = tmp_path / "report.json"
    _write_report(report_path, mutated["apk_sha256"])
    out = tmp_path / "imported"
    with pytest.raises(DexQueryError) as caught:
        import_receipt(receipt_path, report_path, out, apk=apk)
    assert caught.value.reason == "xref_mismatch"
    assert not out.exists()


def test_file_offset_of_other_method_is_rejected(tmp_path: Path) -> None:
    apk, receipt, _good, bad = _two_method_receipt(tmp_path)
    mutated = copy.deepcopy(receipt)
    mutated["members"][0]["hits"][0]["file_offset"] = bad.file_offset
    _resign(mutated)
    receipt_path = tmp_path / "wrong-offset.json"
    _store(receipt_path, mutated)
    report_path = tmp_path / "report.json"
    _write_report(report_path, mutated["apk_sha256"])
    out = tmp_path / "imported"
    with pytest.raises(DexQueryError) as caught:
        import_receipt(receipt_path, report_path, out, apk=apk)
    assert caught.value.reason == "xref_mismatch"
    assert not out.exists()


def test_tampered_receipts_without_apk_stay_unverified(tmp_path: Path) -> None:
    apk, receipt, _good, bad = _two_method_receipt(tmp_path)
    report_path = tmp_path / "report.json"
    _write_report(report_path, str(receipt["apk_sha256"]))
    mutations = {
        "descriptor": ("descriptor", bad.descriptor),
        "file_offset": ("file_offset", bad.file_offset),
    }
    for name, (field, value) in mutations.items():
        mutated = copy.deepcopy(receipt)
        mutated["members"][0]["hits"][0][field] = value
        _resign(mutated)
        receipt_path = tmp_path / f"{name}.json"
        _store(receipt_path, mutated)
        out = tmp_path / name
        result = import_receipt(receipt_path, report_path, out)
        assert result["status"] == "imported"
        merged = json.loads((out / "report.json").read_text(encoding="utf-8"))
        summary = merged["meta"]["dex_query"]["receipts"][0]
        assert summary["xref_verified"] is False
        assert summary["xref_verification"] == "not_verified_locally"
        snippets = _static_snippets(merged)
        assert snippets
        assert all("xref=unverified" in item for item in snippets)
        _assert_runtime_kept(merged)


def test_absolute_compiler_paths_are_not_relative_attachment_claims():
    from apkscan.core.dex_query import _reject_unknown_claims

    _reject_unknown_claims({"meta": {"build_paths": [{"path": "/app/compiler/source.go"}]}}, set())
    with pytest.raises(DexQueryError, match="path_escape"):
        _reject_unknown_claims({"meta": {"attachment": {"path": "../dex-query/escape.json"}}}, set())


def _hit(descriptor: str, offset: int, file_offset: int) -> dict[str, object]:
    return {
        "value_sha256": hashlib.sha256(_VALUE.encode("utf-8")).hexdigest(),
        "descriptor": descriptor,
        "offset": offset,
        "offset_unit": "code_units",
        "file_offset": file_offset,
        "precision": "exact",
    }


def _apk_receipt(tmp_path: Path, name: str, data: bytes, hits: list[dict[str, object]]):
    apk = tmp_path / f"{name}.apk"
    apk.write_bytes(zip_bytes([("classes.dex", data)]))
    members, skipped, truncated = inventory_dex_members(apk)
    member = members[0]
    receipt = _receipt_from_worker(
        {"members": [{
            "name": member.name,
            "ordinal": member.ordinal,
            "sha256": member.sha256,
            "status": "hit",
            "precision": "exact",
            "truncated": False,
            "hits": hits,
        }]},
        hashlib.sha256(apk.read_bytes()).hexdigest(),
        [_VALUE],
        members,
        skipped,
        truncated,
        _LIMITS,
    )
    return apk, receipt


def _import_case(tmp_path: Path, name: str, apk: Path, receipt: dict[str, object], *, with_apk: bool):
    receipt_path = tmp_path / f"{name}.json"
    _store(receipt_path, receipt)
    report_path = tmp_path / f"{name}-report.json"
    _write_report(report_path, str(receipt["apk_sha256"]))
    out = tmp_path / name
    if with_apk:
        return import_receipt(receipt_path, report_path, out, apk=apk), out
    return import_receipt(receipt_path, report_path, out), out


def test_operand_lookalike_is_xref_mismatch_and_unverified_without_apk(tmp_path: Path) -> None:
    dex = build_dex(sample_classes(_VALUE))
    hit = dex.hits[0]
    index = dex.strings.index(_VALUE)
    data = bytearray(dex.data)
    data[hit.file_offset:hit.file_offset + 6] = struct.pack("<HHH", 0x0013, 0x001A, index)
    claimed = _hit(hit.descriptor, hit.code_unit_offset + 1, hit.file_offset + 2)
    apk, receipt = _apk_receipt(tmp_path, "operand", bytes(data), [claimed])
    out = tmp_path / "operand"
    with pytest.raises(DexQueryError) as caught:
        _import_case(tmp_path, "operand", apk, receipt, with_apk=True)
    assert caught.value.reason == "xref_mismatch"
    assert not out.exists()
    result, unverified = _import_case(tmp_path, "operand-plain", apk, receipt, with_apk=False)
    assert result["status"] == "imported"
    merged = json.loads((unverified / "report.json").read_text(encoding="utf-8"))
    summary = merged["meta"]["dex_query"]["receipts"][0]
    assert summary["xref_verified"] is False
    assert summary["xref_verification"] == "not_verified_locally"


def test_jumbo_const_string_at_instruction_boundary_verifies(tmp_path: Path) -> None:
    dex = build_dex(sample_classes(_VALUE))
    hit = dex.hits[0]
    index = dex.strings.index(_VALUE)
    data = bytearray(dex.data)
    data[hit.file_offset:hit.file_offset + 6] = struct.pack("<HI", 0x001B, index)
    claimed = _hit(hit.descriptor, hit.code_unit_offset, hit.file_offset)
    apk, receipt = _apk_receipt(tmp_path, "jumbo", bytes(data), [claimed])
    result, out = _import_case(tmp_path, "jumbo-out", apk, receipt, with_apk=True)
    assert result["status"] == "imported"
    merged = json.loads((out / "report.json").read_text(encoding="utf-8"))
    summary = merged["meta"]["dex_query"]["receipts"][0]
    assert summary["xref_verified"] is True
    assert summary["xref_verification"] == "verified_against_apk"
    assert all("xref=verified" in item for item in _static_snippets(merged))


@pytest.mark.parametrize("word", [0x0073, 0x0100, 0x0200, 0x0300])
def test_malformed_method_stays_unverified_while_other_method_matches(
    tmp_path: Path, word: int,
) -> None:
    dex = build_dex(sample_classes(_VALUE))
    bad, good = dex.hits
    index = dex.strings.index(_VALUE)
    data = bytearray(dex.data)
    data[bad.file_offset:bad.file_offset + 6] = struct.pack("<HHH", word, 0x001A, index)
    hits = [
        _hit(bad.descriptor, bad.code_unit_offset + 1, bad.file_offset + 2),
        _hit(good.descriptor, good.code_unit_offset, good.file_offset),
    ]
    apk, receipt = _apk_receipt(tmp_path, f"malformed-{word:04x}", bytes(data), hits)
    result, out = _import_case(tmp_path, f"malformed-out-{word:04x}", apk, receipt, with_apk=True)
    assert result["status"] == "imported"
    merged = json.loads((out / "report.json").read_text(encoding="utf-8"))
    summary = merged["meta"]["dex_query"]["receipts"][0]
    assert summary["xref_verified"] is False
    assert summary["xref_verification"] == "parse_unavailable"
    by_location = {
        ref["location"]: ref["snippet"]
        for lead in merged["leads"]
        for ref in lead["source_refs"]
        if ref.get("source") == "static-dex-xref"
    }
    good_key = f"classes.dex!{good.descriptor}@code_units:{good.code_unit_offset}"
    bad_key = f"classes.dex!{bad.descriptor}@code_units:{bad.code_unit_offset + 1}"
    assert "xref=verified" in by_location[good_key]
    assert "xref=unverified" in by_location[bad_key]


@pytest.mark.parametrize(
    ("insns", "width", "wanted", "found"),
    [
        (struct.pack("<HHH", 0x0000, 0x001A, 7), 1, {0, 1}, {1: 7}),
        (struct.pack("<HHHH", 0x0013, 0x001A, 0x001A, 9), 2, {1, 2}, {2: 9}),
        (struct.pack("<HHHHHH", 0x0003, 0x001B, 0x0000, 0x001B, 4, 0), 3, {1, 3}, {3: 4}),
        (struct.pack("<HHHHHH", 0x00FA, 0x001A, 0x001B, 0x0000, 0x001A, 3), 4, {1, 2, 4}, {4: 3}),
        (struct.pack("<HHHHHHH", 0x0018, 0x001A, 0, 0, 0, 0x001A, 5), 5, {1, 5}, {5: 5}),
        (
            struct.pack("<HHHHHH", 0x0100, 1, 0x001A, 0, 0, 0) + struct.pack("<HH", 0x001A, 11),
            6,
            {2, 6},
            {6: 11},
        ),
        (
            struct.pack("<HHHHHH", 0x0200, 1, 0x001B, 0, 0, 0) + struct.pack("<HI", 0x001B, 12),
            6,
            {2, 6},
            {6: 12},
        ),
        (
            struct.pack("<HHIH", 0x0300, 2, 1, 0x001A) + struct.pack("<HH", 0x001A, 8),
            5,
            {4, 5},
            {5: 8},
        ),
    ],
)
def test_instruction_width_ignores_operand_and_payload_lookalikes(
    insns: bytes, width: int, wanted: set[int], found: dict[int, int],
) -> None:
    from apkscan.core.dex_query import _const_string_indexes, _instruction_width

    assert _instruction_width(insns, 0) == width
    assert _const_string_indexes(insns, wanted) == found


def test_unknown_and_truncated_payloads_are_not_guessed_as_one_unit() -> None:
    from apkscan.core.dex_query import _DexParseError, _instruction_width

    with pytest.raises(_DexParseError):
        _instruction_width(struct.pack("<H", 0x0073), 0)
    with pytest.raises(_DexParseError):
        _instruction_width(struct.pack("<HHH", 0x0100, 1, 0), 0)
    with pytest.raises(_DexParseError):
        _instruction_width(struct.pack("<HHI", 0x0300, 3, 1), 0)


@pytest.mark.skipif(sys.platform == "darwin", reason="RLIMIT_AS not enforceable on macOS; dex worker memory limit unavailable")
def test_directory_before_dex_uses_inventory_ordinal(tmp_path: Path) -> None:
    dex = build_dex(sample_classes(_VALUE))
    apk = tmp_path / "directories.apk"
    apk.write_bytes(_raw_zip([
        ("assets/", 0, b"", 0),
        ("assets/empty/", 0, b"", 0),
        ("classes.dex", 0, dex.data, len(dex.data)),
    ]))
    members, _skipped, _truncated = inventory_dex_members(apk)
    assert [item.name for item in members] == ["classes.dex"]
    assert members[0].sha256 == dex.sha256
    receipt_path = tmp_path / "receipt.json"
    receipt = query_apk(apk, [_VALUE], worker_argv=_WORKER, limits=_LIMITS, out=receipt_path)
    assert receipt["members"][0]["ordinal"] == members[0].ordinal
    assert receipt["members"][0]["name"] == members[0].name
    report_path = tmp_path / "report.json"
    _write_report(report_path, receipt["apk_sha256"])
    out = tmp_path / "imported"
    result = import_receipt(receipt_path, report_path, out, apk=apk)
    assert result["status"] == "imported"
    merged = json.loads((out / "report.json").read_text(encoding="utf-8"))
    summary = merged["meta"]["dex_query"]["receipts"][0]
    assert summary["xref_verified"] is True
    assert summary["members"][0]["ordinal"] == members[0].ordinal


def _uleb(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def _shared_string_dex(count: int, text_len: int) -> bytes:
    blob = _uleb(text_len) + b"A" * text_len + b"\x00"
    ids_off = 0x70
    data_off = ids_off + 4 * count
    size = data_off + len(blob)
    data = bytearray(size)
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 32, size)
    struct.pack_into("<I", data, 36, 0x70)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<I", data, 56, count)
    struct.pack_into("<I", data, 60, ids_off)
    for index in range(count):
        struct.pack_into("<I", data, ids_off + 4 * index, data_off)
    data[data_off:] = blob
    return bytes(data)


def _descriptor_bomb_dex(count: int, text_len: int) -> bytes:
    strings = [b"L" + b"A" * text_len + b";", b"m", b"V", b"V"]
    blob = b"".join(_uleb(len(item)) + item + b"\x00" for item in strings)
    ids_off = 0x70
    types_off = ids_off + 4 * len(strings)
    protos_off = types_off + 4 * 2
    methods_off = protos_off + 12
    data_off = methods_off + 8 * count
    size = data_off + len(blob)
    data = bytearray(size)
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 32, size)
    struct.pack_into("<I", data, 36, 0x70)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<I", data, 56, len(strings))
    struct.pack_into("<I", data, 60, ids_off)
    struct.pack_into("<I", data, 64, 2)
    struct.pack_into("<I", data, 68, types_off)
    struct.pack_into("<I", data, 72, 1)
    struct.pack_into("<I", data, 76, protos_off)
    struct.pack_into("<I", data, 88, count)
    struct.pack_into("<I", data, 92, methods_off)
    cursor = data_off
    for index, item in enumerate(strings):
        struct.pack_into("<I", data, ids_off + 4 * index, cursor)
        cursor += len(_uleb(len(item))) + len(item) + 1
    struct.pack_into("<I", data, types_off, 0)
    struct.pack_into("<I", data, types_off + 4, 2)
    struct.pack_into("<III", data, protos_off, 3, 1, 0)
    for index in range(count):
        struct.pack_into("<HHI", data, methods_off + 8 * index, 0, 0, 1)
    data[data_off:] = blob
    return bytes(data)


def test_shared_string_offsets_and_descriptor_fanout_stay_bounded(tmp_path: Path) -> None:
    from apkscan.core.dex_query import _DexParseError, _parse_dex, _verify_xref_hits

    data = _shared_string_dex(2000, 64 * 1024)
    with pytest.raises(_DexParseError):
        _parse_dex(data)

    apk = tmp_path / "shared.apk"
    apk.write_bytes(zip_bytes([("classes.dex", data)], compress=False))
    members, _skipped, _truncated = inventory_dex_members(apk)
    receipt = {
        "members": [{
            "name": members[0].name,
            "ordinal": members[0].ordinal,
            "sha256": members[0].sha256,
            "status": "hit",
            "hits": [],
        }],
    }
    check = _verify_xref_hits(apk.read_bytes(), receipt)
    assert check.verified is False
    assert check.status == "parse_unavailable"

    with pytest.raises(_DexParseError):
        _parse_dex(_descriptor_bomb_dex(2000, 64 * 1024))
    assert _parse_dex(build_dex(sample_classes(_VALUE)).data).methods


def test_only_partial_hits_yield_no_exact_hits(tmp_path: Path) -> None:
    dex = build_dex(sample_classes(_VALUE))
    claimed = _hit(dex.hits[0].descriptor, dex.hits[0].code_unit_offset, dex.hits[0].file_offset)
    apk, receipt = _apk_receipt(tmp_path, "partial-only", dex.data, [claimed])
    receipt["members"][0]["hits"][0]["precision"] = "partial"
    _resign(receipt)
    receipt_path = tmp_path / "partial-only.json"
    _store(receipt_path, receipt)
    report_path = tmp_path / "partial-only-report.json"
    _write_report(report_path, str(receipt["apk_sha256"]))
    out = tmp_path / "partial-imported"
    result = import_receipt(receipt_path, report_path, out, apk=apk)
    assert result["status"] == "imported"
    merged = json.loads((out / "report.json").read_text(encoding="utf-8"))
    summary = merged["meta"]["dex_query"]["receipts"][0]
    assert summary["xref_verified"] is False
    assert summary["xref_verification"] == "no_exact_hits"
    snippets = _static_snippets(merged)
    assert snippets
    assert all("xref=unverified" in item for item in snippets)
