"""与原件矛盾的 exact xref 必须拒绝；没有原件时只能标成未本地核验。"""

from __future__ import annotations

import copy
import hashlib
import json
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
