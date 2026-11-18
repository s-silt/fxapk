"""Characterize the offline runtime-report identity gate before merging evidence."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from fxapk.core import integrity
from fxapk.dynamic.auto import _verified_merge_namespace


def test_verified_namespace_binds_exact_runtime_bytes(tmp_path: Path) -> None:
    path = tmp_path / "runtime.json"
    data = b'{"synthetic": true}'
    path.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    records = [
        {"runtime_report_path": "unrelated.json", "runtime_report_sha256": "0" * 64},
        {"runtime_report_path": str(path), "runtime_report_sha256": expected},
    ]
    assert _verified_merge_namespace(str(path), records) == f"capture:{expected}"
    path.write_bytes(data + b" ")
    assert _verified_merge_namespace(str(path), records) is None
    path.unlink()
    assert _verified_merge_namespace(str(path), records) is None


def test_missing_first_recorded_digest_does_not_read_or_choose_later_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def should_not_read(_path: str) -> str:
        pytest.fail("should not read unbound material")

    monkeypatch.setattr(integrity, "sha256_file", should_not_read)
    records = [
        {"runtime_report_path": "synthetic.json", "runtime_report_sha256": None},
        {"runtime_report_path": "synthetic.json", "runtime_report_sha256": "a" * 64},
    ]
    assert _verified_merge_namespace("synthetic.json", records) is None
    assert _verified_merge_namespace("missing.json", records) is None
