"""M2/M4/M5 反例。坏定位不能标 exact，伪造回执不能导入，哈希和清单共用一份快照。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from apkscan.core.dex_query import (
    DexQueryError,
    DexQueryLimits,
    _clean_hits,
    _stable_snapshot,
    import_receipt,
    query_apk,
)
from tests.fixtures.dex_query.dexgen import build_dex, sample_classes, zip_bytes

_WORKER = ["python", "tests/fixtures/dex_query/fake_worker.py"]


def test_invalid_locator_is_not_exact() -> None:
    value = "api.example.invalid"
    hit = _clean_hits(
        [{
            "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
            "descriptor": "",
            "offset": -1,
            "offset_unit": "code_units",
            "file_offset": True,
            "precision": "exact",
        }],
        200,
    )[0]
    assert hit["precision"] != "exact"
    assert hit["descriptor"] is None
    assert hit["offset"] is None
    assert hit["file_offset"] is None


def test_import_rejects_unexecuted_forged_receipt(tmp_path: Path) -> None:
    blob = b"synthetic-member-A"
    apk = tmp_path / "synthetic.zip"
    apk.write_bytes(zip_bytes([("classes.dex", blob)]))
    member_sha = hashlib.sha256(blob).hexdigest()
    values = ["api.example.invalid"]
    from apkscan.core import dex_query as dq

    actual, _skipped, _truncated = dq.inventory_dex_bytes(apk.read_bytes())
    forged = dq._receipt_from_worker(
        {"members": [{
            "name": actual[0].name,
            "ordinal": actual[0].ordinal,
            "sha256": member_sha,
            "status": "hit",
            "precision": "exact",
            "hits": [{
                "value_sha256": hashlib.sha256(values[0].encode()).hexdigest(),
                "descriptor": "",
                "offset": -1,
                "offset_unit": "code_units",
                "file_offset": True,
                "precision": "exact",
            }],
        }]},
        hashlib.sha256(apk.read_bytes()).hexdigest(),
        values,
        actual,
        [],
        False,
        DexQueryLimits(),
    )
    forged["provider_version"] = "wrong-version"
    forged["provider_revision"] = "wrong-revision"
    forged["engine_executed"] = False
    forged["query_summary_sha256"] = "b" * 64
    forged["members"][0]["name"] = "not-in-apk.dex"
    forged["members"][0]["ordinal"] = 999
    forged["receipt_id"] = hashlib.sha256(
        dq._canonical_text({key: value for key, value in forged.items() if key != "receipt_id"})
    ).hexdigest()
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(dq._canonical_text(forged))
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps({"meta": {"sample_sha256": forged["apk_sha256"]}, "leads": []}),
        encoding="utf-8",
    )
    out = tmp_path / "imported"
    with pytest.raises(DexQueryError) as caught:
        import_receipt(receipt_path, report_path, out, apk=apk)
    assert caught.value.reason in {
        "engine_not_executed",
        "provider_version_mismatch",
        "identity_mismatch",
        "invalid_type",
    }
    assert not out.exists()


def test_snapshot_rejects_a_changed_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"abc")
    real_stat = Path.stat
    calls = {"n": 0}

    def stat(self: Path, *args: object, **kwargs: object) -> object:
        calls["n"] += 1
        result = real_stat(self, *args, **kwargs)
        if self == path and calls["n"] >= 2:
            return type("Changed", (), {"st_size": result.st_size + 1})()
        return result

    monkeypatch.setattr(Path, "stat", stat)
    with pytest.raises(DexQueryError) as caught:
        _stable_snapshot(path, 100)
    assert caught.value.reason == "input_rejected"


def test_query_does_not_hash_and_inventory_separately(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = build_dex(sample_classes("api.example.invalid"))
    apk = tmp_path / "app.apk"
    apk.write_bytes(zip_bytes([("classes.dex", sample.data), ("classes2.dex", sample.data)]))

    def boom(path: Path, limit: int) -> str:
        raise AssertionError("hash and inventory must share one snapshot")

    monkeypatch.setattr("apkscan.core.dex_query._sha256_file", boom)
    receipt = query_apk(
        apk,
        ["api.example.invalid"],
        worker_argv=[__import__("sys").executable, "tests/fixtures/dex_query/fake_worker.py"],
        limits=DexQueryLimits(timeout_sec=20, memory_bytes=256 * 1024 * 1024),
    )
    assert receipt["apk_sha256"] == hashlib.sha256(apk.read_bytes()).hexdigest()
    assert [item["name"] for item in receipt["members"]] == ["classes.dex", "classes2.dex"]
    assert receipt["members"][0]["sha256"] == receipt["members"][1]["sha256"] == sample.sha256
