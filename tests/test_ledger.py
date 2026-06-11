"""批量分析去重台账（apkscan.dynamic.ledger）测试。

台账按 APK 内容 sha256 去重：同内容改名也跳过；坏文件当空处理绝不抛；每次 record
原子落盘（mid-batch 崩了已分析的不丢）。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from apkscan.dynamic.ledger import AnalyzedLedger, apk_sha256


def test_apk_sha256_matches_hashlib(tmp_path: Path) -> None:
    f = tmp_path / "x.apk"
    data = b"PK\x03\x04 some apk bytes" * 1000  # 跨多个读块
    f.write_bytes(data)
    assert apk_sha256(str(f)) == hashlib.sha256(data).hexdigest()


def test_unknown_sha_not_analyzed(tmp_path: Path) -> None:
    led = AnalyzedLedger(tmp_path / "analyzed.json")
    assert led.is_analyzed("deadbeef") is False


def test_record_then_analyzed(tmp_path: Path) -> None:
    led = AnalyzedLedger(tmp_path / "analyzed.json")
    led.record("abc123", apk_name="x.apk", report_dir="out/x", status="done")
    assert led.is_analyzed("abc123") is True


def test_persists_across_instances(tmp_path: Path) -> None:
    p = tmp_path / "analyzed.json"
    AnalyzedLedger(p).record("abc123", apk_name="x.apk", report_dir="out/x", status="done")
    assert AnalyzedLedger(p).is_analyzed("abc123") is True


def test_record_metadata_retrievable(tmp_path: Path) -> None:
    p = tmp_path / "analyzed.json"
    AnalyzedLedger(p).record("abc123", apk_name="x.apk", report_dir="out/x", status="done")
    entry = AnalyzedLedger(p).get("abc123")
    assert entry is not None
    assert entry["apk_name"] == "x.apk"
    assert entry["report_dir"] == "out/x"
    assert entry["status"] == "done"


def test_corrupt_ledger_treated_as_empty_and_recoverable(tmp_path: Path) -> None:
    p = tmp_path / "analyzed.json"
    p.write_text("{ this is not valid json", encoding="utf-8")
    led = AnalyzedLedger(p)  # 不抛
    assert led.is_analyzed("anything") is False
    led.record("abc", apk_name="a", report_dir="d", status="done")  # 覆盖坏文件
    assert AnalyzedLedger(p).is_analyzed("abc") is True


def test_record_creates_parent_dir(tmp_path: Path) -> None:
    p = tmp_path / "nested" / ".apkscan_cache" / "analyzed.json"
    AnalyzedLedger(p).record("abc", apk_name="a", report_dir="d", status="done")
    assert p.is_file()
