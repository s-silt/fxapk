""".so 流式三窗读（codex 全库审计 P1）：大 .so 字符串扫描不整解压进内存，只取 head/mid/tail 三窗。"""

from __future__ import annotations

import zipfile
from pathlib import Path

from apkscan.analyzers import _common


def _make_apk(tmp_path: Path, entry: str, body: bytes) -> str:
    p = tmp_path / "app.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr(entry, body)
    return str(p)


def test_read_so_windows_matches_sample_so(tmp_path: Path) -> None:
    """流式三窗读的窗口口径与整读 _sample_so 完全一致（>3窗时取 head/mid/tail）。"""
    window = 16
    body = b"HEADmark" + b"a" * 100 + b"MIDmark!" + b"b" * 100 + b"TAILmark"  # 224B > 3*16
    entry = "lib/arm64-v8a/libx.so"
    apk = _make_apk(tmp_path, entry, body)

    got = _common._read_so_windows(apk, entry, window)
    assert got == _common._sample_so(body, window)  # 与整读采样等价
    assert got is not None and b"HEADmark" in got and b"TAILmark" in got  # 覆盖首尾


def test_read_so_windows_small_file_returns_full(tmp_path: Path) -> None:
    """≤3 窗的小 .so 直接全读（与 _sample_so 对小文件返回 data 等价）。"""
    body = b"tiny native lib content"
    entry = "lib/x/libs.so"
    apk = _make_apk(tmp_path, entry, body)
    assert _common._read_so_windows(apk, entry, 1024) == body


def test_read_so_windows_missing_entry_returns_none(tmp_path: Path) -> None:
    """缺失条目 / 坏 zip → None（调用方回退整读+采样，绝不炸）。"""
    apk = _make_apk(tmp_path, "lib/x/a.so", b"x" * 100)
    assert _common._read_so_windows(apk, "lib/x/does-not-exist.so", 16) is None
    assert _common._read_so_windows(str(tmp_path / "no-such.apk"), "a.so", 16) is None
