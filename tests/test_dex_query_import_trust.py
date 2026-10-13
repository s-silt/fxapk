"""与原件矛盾的 exact xref 必须拒绝；没有原件时只能标成未本地核验。"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import tracemalloc
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


def _param_fanout_dex(
    proto_count: int,
    param_count: int,
    text_len: int,
    method_count: int,
    *,
    param_string: bytes | None = None,
    pad: int = 0,
    same_name: bool = False,
) -> bytes:
    """proto_count 个 proto 共享同一份 param_count 项 type_list；参数类型名长 text_len。"""
    big = (
        param_string
        if param_string is not None
        else b"I" if text_len == 1 else b"L" + b"A" * (text_len - 2) + b";"
    )
    names = [f"m{i}".encode() for i in range(max(method_count, 1))]
    strings = [b"LA;", b"V", big, *names]
    string_blob = b"".join(_uleb(len(item)) + item + b"\x00" for item in strings)
    ids_off = 0x70
    types_off = ids_off + 4 * len(strings)
    protos_off = types_off + 4 * 3
    methods_off = protos_off + 12 * proto_count
    data_off = methods_off + 8 * method_count
    list_off = data_off + len(string_blob)
    list_off += (4 - list_off % 4) % 4
    size = list_off + 4 + 2 * param_count
    data = bytearray(size + pad)
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 32, size + pad)
    struct.pack_into("<I", data, 36, 0x70)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<I", data, 56, len(strings))
    struct.pack_into("<I", data, 60, ids_off)
    struct.pack_into("<I", data, 64, 3)
    struct.pack_into("<I", data, 68, types_off)
    struct.pack_into("<I", data, 72, proto_count)
    struct.pack_into("<I", data, 76, protos_off)
    if method_count:
        struct.pack_into("<I", data, 88, method_count)
        struct.pack_into("<I", data, 92, methods_off)
    cursor = data_off
    for index, item in enumerate(strings):
        struct.pack_into("<I", data, ids_off + 4 * index, cursor)
        cursor += len(_uleb(len(item))) + len(item) + 1
    for index, string_idx in enumerate((0, 1, 2)):
        struct.pack_into("<I", data, types_off + 4 * index, string_idx)
    for index in range(proto_count):
        struct.pack_into("<III", data, protos_off + 12 * index, 1, 1, list_off)
    for index in range(method_count):
        name_idx = 3 if same_name else 3 + index
        struct.pack_into("<HHI", data, methods_off + 8 * index, 0, 0, name_idx)
    struct.pack_into("<I", data, list_off, param_count)
    for index in range(param_count):
        struct.pack_into("<H", data, list_off + 4 + 2 * index, 2)
    data[data_off:data_off + len(string_blob)] = string_blob
    return bytes(data)


def _shared_code_dex(method_count: int, insns_len: int) -> bytes:
    """method_count 个 direct 方法共享同一个 code_off 的 code_item。"""
    strings = [b"LA;", b"V"] + [f"m{i:04d}".encode() for i in range(method_count)]
    string_blob = b"".join(_uleb(len(item)) + item + b"\x00" for item in strings)
    ids_off = 0x70
    types_off = ids_off + 4 * len(strings)
    protos_off = types_off + 4 * 2
    methods_off = protos_off + 12
    class_defs_off = methods_off + 8 * method_count
    data_off = class_defs_off + 32
    code_off = data_off + len(string_blob)
    code_off += (4 - code_off % 4) % 4
    class_data_off = code_off + 16 + insns_len
    class_data = _uleb(0) + _uleb(0) + _uleb(method_count) + _uleb(0)
    for index in range(method_count):
        class_data += _uleb(0 if index == 0 else 1) + _uleb(1) + _uleb(code_off)
    size = class_data_off + len(class_data)
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
    struct.pack_into("<I", data, 88, method_count)
    struct.pack_into("<I", data, 92, methods_off)
    struct.pack_into("<I", data, 96, 1)
    struct.pack_into("<I", data, 100, class_defs_off)
    cursor = data_off
    for index, item in enumerate(strings):
        struct.pack_into("<I", data, ids_off + 4 * index, cursor)
        cursor += len(_uleb(len(item))) + len(item) + 1
    struct.pack_into("<I", data, types_off, 0)
    struct.pack_into("<I", data, types_off + 4, 1)
    struct.pack_into("<III", data, protos_off, 1, 1, 0)
    for index in range(method_count):
        struct.pack_into("<HHI", data, methods_off + 8 * index, 0, 0, 2 + index)
    struct.pack_into("<I", data, class_defs_off, 0)
    struct.pack_into("<I", data, class_defs_off + 8, 1)
    struct.pack_into("<I", data, class_defs_off + 24, class_data_off)
    struct.pack_into("<HHHHII", data, code_off, 1, 0, 0, 0, 0, insns_len // 2)
    data[data_off:data_off + len(string_blob)] = string_blob
    data[class_data_off:class_data_off + len(class_data)] = class_data
    return bytes(data)


def _parse_peak(data: bytes) -> tuple[object, int]:
    from apkscan.core.dex_query import _DexParseError, _parse_dex

    tracemalloc.start()
    try:
        try:
            parsed: object = _parse_dex(data)
        except _DexParseError:
            parsed = None
        _current, peak = tracemalloc.get_traced_memory()
        return parsed, peak
    finally:
        tracemalloc.stop()


def test_descriptor_budget_blocks_fanout_before_allocating() -> None:
    """4096 个参数全部指向一个 ~4KiB 类型名：descriptor 展开 ~16 MiB，必须在 join 前拒。"""
    from apkscan.core.dex_query import _DexParseError, _parse_dex

    data = _param_fanout_dex(proto_count=1, param_count=4096, text_len=4096, method_count=1)
    tracemalloc.start()
    try:
        with pytest.raises(_DexParseError):
            _parse_dex(data)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4 * 1024 * 1024


def test_shared_type_list_expands_once_under_budget() -> None:
    """2000 个 proto 共享一份 2000 项 type_list：去重展开计入预算一次，正常解析。"""
    data = _param_fanout_dex(proto_count=2000, param_count=2000, text_len=8, method_count=0)
    parsed, peak = _parse_peak(data)
    assert parsed is not None
    assert peak < 4 * 1024 * 1024


def test_methods_sharing_one_code_item_share_insns_bytes() -> None:
    """1000 个方法指向同一 16 KiB code_item：不重切，insns 是同一对象。"""
    data = _shared_code_dex(1000, 16 * 1024)
    parsed, peak = _parse_peak(data)
    assert parsed is not None
    assert peak < 2 * 1024 * 1024
    methods = parsed.methods  # type: ignore[union-attr]
    first = methods["LA;->m0000()V"]
    last = methods["LA;->m0999()V"]
    assert first.insns is last.insns


def test_empty_type_descriptor_is_rejected() -> None:
    """类型表项指向空字符串：合法 DEX 不存在，直接拒。"""
    from apkscan.core.dex_query import _DexParseError, _parse_dex

    data = _param_fanout_dex(1, 4000, 8, 4000, param_string=b"")
    with pytest.raises(_DexParseError):
        _parse_dex(data)


def test_shared_proto_params_join_once_within_time_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """4000 个方法共享一份 4000 参数 proto：params 文本只 join 一次。"""
    import time

    import apkscan.core.dex_query as dex_query
    from apkscan.core.dex_query import _parse_dex

    joins: list[int] = []
    real_join = getattr(dex_query, "_join_params", None)

    def spy(*args: object) -> object:
        joins.append(1)
        assert real_join is not None
        return real_join(*args)

    monkeypatch.setattr(dex_query, "_join_params", spy, raising=False)
    data = _param_fanout_dex(1, 4000, 1, 4000, pad=2 * 1024 * 1024)
    start = time.perf_counter()
    parsed = _parse_dex(data)
    elapsed = time.perf_counter() - start
    assert parsed is not None
    assert len(joins) == 1
    assert elapsed < 1.0


def _shared_classdata_dex(classdef_count: int, field_count: int) -> bytes:
    """classdef_count 个 class_def 共享同一份含 field_count 个零 ULEB 字段的 class_data。"""
    strings = [b"LA;", b"V"]
    string_blob = b"".join(_uleb(len(item)) + item + b"\x00" for item in strings)
    ids_off = 0x70
    types_off = ids_off + 4 * len(strings)
    class_defs_off = types_off + 4
    data_off = class_defs_off + 32 * classdef_count
    class_data_off = data_off + len(string_blob)
    class_data_off += (4 - class_data_off % 4) % 4
    class_data = (
        _uleb(field_count) + _uleb(0) + _uleb(0) + _uleb(0)
        + b"\x00" * (2 * field_count + 16)
    )
    size = class_data_off + len(class_data)
    data = bytearray(size)
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 32, size)
    struct.pack_into("<I", data, 36, 0x70)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<I", data, 56, len(strings))
    struct.pack_into("<I", data, 60, ids_off)
    struct.pack_into("<I", data, 64, 1)
    struct.pack_into("<I", data, 68, types_off)
    struct.pack_into("<I", data, 96, classdef_count)
    struct.pack_into("<I", data, 100, class_defs_off)
    cursor = data_off
    for index, item in enumerate(strings):
        struct.pack_into("<I", data, ids_off + 4 * index, cursor)
        cursor += len(_uleb(len(item))) + len(item) + 1
    struct.pack_into("<I", data, types_off, 0)
    for index in range(classdef_count):
        struct.pack_into("<I", data, class_defs_off + 32 * index, 0)
        struct.pack_into("<I", data, class_defs_off + 32 * index + 24, class_data_off)
    data[data_off:data_off + len(string_blob)] = string_blob
    data[class_data_off:class_data_off + len(class_data)] = class_data
    return bytes(data)


def _overlapping_classdata_dex(starts: int) -> bytes:
    """class_data 区为重复 \\x7f\\x00\\x00\\x00 模式：每 4 字节起点解出 (127,0,0,0)+127 field。"""
    strings = [b"LA;", b"V"]
    string_blob = b"".join(_uleb(len(item)) + item + b"\x00" for item in strings)
    ids_off = 0x70
    types_off = ids_off + 4 * len(strings)
    class_defs_off = types_off + 4
    data_off = class_defs_off + 32 * starts
    region_off = data_off + len(string_blob)
    region_off += (4 - region_off % 4) % 4
    region = b"\x7f\x00\x00\x00" * (starts + 300)
    size = region_off + len(region)
    data = bytearray(size)
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 32, size)
    struct.pack_into("<I", data, 36, 0x70)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<I", data, 56, len(strings))
    struct.pack_into("<I", data, 60, ids_off)
    struct.pack_into("<I", data, 64, 1)
    struct.pack_into("<I", data, 68, types_off)
    struct.pack_into("<I", data, 96, starts)
    struct.pack_into("<I", data, 100, class_defs_off)
    cursor = data_off
    for index, item in enumerate(strings):
        struct.pack_into("<I", data, ids_off + 4 * index, cursor)
        cursor += len(_uleb(len(item))) + len(item) + 1
    struct.pack_into("<I", data, types_off, 0)
    for index in range(starts):
        struct.pack_into("<I", data, class_defs_off + 32 * index, 0)
        struct.pack_into(
            "<I", data, class_defs_off + 32 * index + 24, region_off + 4 * index,
        )
    data[data_off:data_off + len(string_blob)] = string_blob
    data[region_off:region_off + len(region)] = region
    return bytes(data)


def test_class_defs_sharing_one_class_data_parse_once() -> None:
    """1000 个 class_def 指向同一 class_data：seen 去重后只解析一次。"""
    import time

    from apkscan.core.dex_query import _parse_dex

    data = _shared_classdata_dex(1000, 1000)
    start = time.perf_counter()
    parsed = _parse_dex(data)
    assert time.perf_counter() - start < 0.5
    assert parsed is not None


def test_overlapping_class_data_entries_hit_cumulative_budget() -> None:
    """重叠 class_data 起点让累计 field 数超过 2*limit：fail closed。"""
    from apkscan.core.dex_query import _DexParseError, _parse_dex

    data = _overlapping_classdata_dex(64)
    with pytest.raises(_DexParseError):
        _parse_dex(data)


def _shared_method_defs_dex(classdef_count: int) -> bytes:
    """classdef_count 个 class_def 各有独立 class_data，但都声明同一个 method。"""
    strings = [b"LA;", b"m", b"V"]
    string_blob = b"".join(_uleb(len(item)) + item + b"\x00" for item in strings)
    ids_off = 0x70
    types_off = ids_off + 4 * len(strings)
    protos_off = types_off + 4 * 2
    methods_off = protos_off + 12
    class_defs_off = methods_off + 8
    data_off = class_defs_off + 32 * classdef_count
    code_off = data_off + len(string_blob)
    code_off += (4 - code_off % 4) % 4
    insns_len = 4
    entry = b"\x00\x00\x01\x00" + b"\x00\x01" + _uleb(code_off)
    region_off = code_off + 16 + insns_len
    size = region_off + len(entry) * classdef_count
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
    struct.pack_into("<I", data, 88, 1)
    struct.pack_into("<I", data, 92, methods_off)
    struct.pack_into("<I", data, 96, classdef_count)
    struct.pack_into("<I", data, 100, class_defs_off)
    cursor = data_off
    for index, item in enumerate(strings):
        struct.pack_into("<I", data, ids_off + 4 * index, cursor)
        cursor += len(_uleb(len(item))) + len(item) + 1
    struct.pack_into("<I", data, types_off, 0)
    struct.pack_into("<I", data, types_off + 4, 2)
    struct.pack_into("<III", data, protos_off, 2, 1, 0)
    struct.pack_into("<HHI", data, methods_off, 0, 0, 1)
    for index in range(classdef_count):
        struct.pack_into("<I", data, class_defs_off + 32 * index, 0)
        struct.pack_into("<I", data, class_defs_off + 32 * index + 8, 1)
        struct.pack_into(
            "<I", data, class_defs_off + 32 * index + 24, region_off + len(entry) * index,
        )
    struct.pack_into("<HHHHII", data, code_off, 1, 0, 0, 0, 0, insns_len // 2)
    data[data_off:data_off + len(string_blob)] = string_blob
    for index in range(classdef_count):
        start = region_off + len(entry) * index
        data[start:start + len(entry)] = entry
    return bytes(data)


def test_duplicate_method_ids_descriptors_are_rejected() -> None:
    """两个 method_ids 展开出同一 descriptor：合法 DEX method_ids 唯一，直接拒。"""
    from apkscan.core.dex_query import _DexParseError, _parse_dex

    data = _param_fanout_dex(1, 8, 8, 2, same_name=True)
    with pytest.raises(_DexParseError):
        _parse_dex(data)


def test_distinct_class_data_reusing_unique_descriptor_stays_fast() -> None:
    """2000 份独立 class_data 都声明 method 0：descriptor 同对象，dict 走身份快路径。"""
    import time

    from apkscan.core.dex_query import _parse_dex

    data = _shared_method_defs_dex(2000)
    start = time.perf_counter()
    parsed = _parse_dex(data)
    assert time.perf_counter() - start < 0.5
    assert parsed is not None
    assert len(parsed.methods) == 1  # type: ignore[union-attr]


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


def _receipt_dir(root: Path, count: int, payload: bytes) -> dict[str, object]:
    dex_dir = root / "dex-query"
    dex_dir.mkdir()
    receipts = []
    for index in range(count):
        receipt_id = f"{index:064x}"
        (dex_dir / f"{receipt_id}.json").write_bytes(payload)
        receipts.append({
            "receipt_id": receipt_id,
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    return {"dex_query": {"receipts": receipts}}


def test_collect_receipt_files_refuses_more_than_64(tmp_path: Path) -> None:
    from apkscan.core.dex_query import collect_receipt_files

    meta = _receipt_dir(tmp_path, 65, b'{"ok":true}')
    with pytest.raises(DexQueryError) as excinfo:
        collect_receipt_files(tmp_path, meta)
    assert excinfo.value.reason == "dex_receipt_oversize"


def test_collect_receipt_files_byte_budget_is_cumulative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import apkscan.core.dex_query as dex_query
    from apkscan.core.dex_query import collect_receipt_files

    monkeypatch.setattr(
        dex_query, "DexQueryLimits", lambda: DexQueryLimits(input_bytes=20)
    )
    meta = _receipt_dir(tmp_path, 2, b"0123456789abcde")
    with pytest.raises(DexQueryError) as excinfo:
        collect_receipt_files(tmp_path, meta)
    assert excinfo.value.reason == "dex_receipt_oversize"


def test_read_relative_uses_bounded_stream_and_stats_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import apkscan.core.dex_query as dex_query

    dex_dir = tmp_path / "dex-query"
    dex_dir.mkdir()
    receipt_id = "a" * 64
    payload = b'{"ok":true}'
    (dex_dir / f"{receipt_id}.json").write_bytes(payload)
    calls: list[int] = []
    real_read_limited = dex_query.read_limited

    def spy(stream, max_bytes):  # noqa: ANN001, ANN202
        calls.append(max_bytes)
        return real_read_limited(stream, max_bytes)

    monkeypatch.setattr(dex_query, "read_limited", spy)
    blob = dex_query._read_relative(tmp_path, f"dex-query/{receipt_id}.json", 64)
    assert blob == payload
    assert calls == [64]

    oversized = "b" * 64
    (dex_dir / f"{oversized}.json").write_bytes(b"x" * 128)
    with pytest.raises(DexQueryError) as excinfo:
        dex_query._read_relative(tmp_path, f"dex-query/{oversized}.json", 64)
    assert excinfo.value.reason == "oversize"
    assert calls == [64]


def test_collect_receipt_files_stat_size_lie_still_hits_byte_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """stat 报 5B 但实际读 15B（竞态/虚报）：按剩余预算读，越界仍 dex_receipt_oversize。"""
    import os

    import apkscan.core.dex_query as dex_query
    from apkscan.core.dex_query import collect_receipt_files

    monkeypatch.setattr(
        dex_query, "DexQueryLimits", lambda: DexQueryLimits(input_bytes=20)
    )
    meta = _receipt_dir(tmp_path, 2, b"0123456789abcde")
    real_stat = Path.stat

    def fake_stat(self: Path, *args: object, **kwargs: object) -> os.stat_result:
        result = real_stat(self, *args, **kwargs)
        if self.suffix == ".json":
            fields = list(result)
            fields[6] = 5
            return os.stat_result(tuple(fields))
        return result

    monkeypatch.setattr(Path, "stat", fake_stat)
    with pytest.raises(DexQueryError) as excinfo:
        collect_receipt_files(tmp_path, meta)
    assert excinfo.value.reason == "dex_receipt_oversize"
