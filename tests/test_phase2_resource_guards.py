"""Synthetic-only read bounds and atomic publication regressions."""
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from apkscan.core.phase2.inventory import _read_json_bounded
from apkscan.core.phase2.link import write_gate_receipt


def test_json_read_is_bounded_even_if_file_grows_after_stat():
    sizes = []

    class RecordingStream(io.BytesIO):
        def read(self, size=-1):
            sizes.append(size)
            return super().read(size)

    class GrowingFile:
        def is_symlink(self):
            return False

        def stat(self):
            return SimpleNamespace(st_size=1)

        def open(self, mode):
            assert mode == "rb"
            return RecordingStream(b'"' + b'x' * 1000 + b'"')

    with pytest.raises(OverflowError, match="while reading"):
        _read_json_bounded(GrowingFile(), 16, 8)
    assert sizes == [17]


def test_receipt_writer_preserves_fixed_tmp_and_exact_json(tmp_path: Path):
    path = tmp_path / "gate-receipt.json"
    old_tmp = path.with_name(path.name + ".tmp")
    old_tmp.write_text("unrelated CANARY", encoding="utf-8")
    receipt = {"schema_version": "synthetic", "result": "BLOCKED", "notes": "合成"}
    write_gate_receipt(path, receipt)
    assert path.read_bytes() == (
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    assert old_tmp.read_text() == "unrelated CANARY"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["gate-receipt.json", "gate-receipt.json.tmp"]


def test_json_reader_exact_byte_boundary(tmp_path: Path):
    path = tmp_path / "synthetic.json"
    raw = b'{"ok":true}'
    path.write_bytes(raw)
    assert _read_json_bounded(path, len(raw), 8) == ({"ok": True}, raw)
    with pytest.raises(OverflowError):
        _read_json_bounded(path, len(raw) - 1, 8)


@pytest.mark.parametrize("raw", [b'{"x":NaN}\n', b'{"x":1e999}\n', b'[]\n'])
def test_clue_jsonl_rejects_nonfinite_and_nonobject(tmp_path: Path, raw: bytes):
    from apkscan.core.phase2.inventory import load_clue_records
    path = tmp_path / "clues.jsonl"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        load_clue_records(path)


def test_clue_jsonl_enforces_real_byte_limit(tmp_path: Path):
    from apkscan.core.phase2.inventory import load_clue_records
    path = tmp_path / "clues.jsonl"
    raw = b'{"synthetic":true}\n'
    path.write_bytes(raw)
    assert load_clue_records(path, max_bytes=len(raw)) == [{"synthetic": True}]
    with pytest.raises(ValueError):
        load_clue_records(path, max_bytes=len(raw) - 1)


def test_inventory_small_json_does_not_allocate_report_budget():
    reads = []
    class Stream(io.BytesIO):
        def read(self, size=-1):
            reads.append(size)
            return super().read(size)
    class SmallFile:
        def is_symlink(self):
            return False
        def stat(self):
            return SimpleNamespace(st_size=2)
        def open(self, mode):
            return Stream(b"{}")
    assert _read_json_bounded(SmallFile(), 128 * 1024 * 1024, 64) == ({}, b"{}")
    assert max(reads) <= 65536
