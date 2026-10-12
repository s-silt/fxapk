"""DEX 成员清点：非标准位置不能漏，坏路径、重复、CRC 和炸弹在解压前拒绝。"""

from __future__ import annotations

import struct
import zlib

import pytest

from apkscan.core.dex_query import DexQueryError, DexQueryLimits, inventory_dex_members
from tests.fixtures.dex_query.dexgen import (
    build_dex,
    declared_bomb,
    flip_central_crc,
    sample_classes,
    zip_bytes,
)


def _raw_zip(entries: list[tuple[str, int, bytes, int]]) -> bytes:
    """entries: (name, method, payload, declared_uncompressed)。method 0 原样，8 视为已压缩字节。"""
    local_parts: list[bytes] = []
    central_parts: list[bytes] = []
    offset = 0
    for name, method, payload, declared in entries:
        raw_name = name.encode("utf-8")
        crc = zlib.crc32(payload if method == 0 else b"") & 0xFFFFFFFF
        local = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50, 20, 0, method, 0, 0, crc, len(payload), declared, len(raw_name), 0,
        ) + raw_name + payload
        central = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50, 20, 20, 0, method, 0, 0, crc, len(payload), declared,
            len(raw_name), 0, 0, 0, 0, 0, offset,
        ) + raw_name
        local_parts.append(local)
        central_parts.append(central)
        offset += len(local)
    local_blob = b"".join(local_parts)
    central_blob = b"".join(central_parts)
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central_blob), len(local_blob), 0,
    )
    return local_blob + central_blob + eocd


def test_inventory_keeps_every_dex_member_and_rejects_a_declared_bomb(tmp_path) -> None:
    built = build_dex(sample_classes())
    archive = tmp_path / "members.apk"
    archive.write_bytes(zip_bytes([
        ("classes.dex", built.data),
        ("classes2.dex", built.data),
        ("extra.dex", built.data),
        ("assets/payload.dex", built.data),
        ("res/note.txt", b"not-a-dex"),
    ]))
    members, skipped, truncated = inventory_dex_members(archive)
    assert [item.name for item in members] == [
        "classes.dex",
        "classes2.dex",
        "extra.dex",
        "assets/payload.dex",
    ]
    assert [item.sha256 for item in members] == [built.sha256] * 4
    assert {item.role for item in members} == {"original"}
    assert skipped == []
    assert truncated is False

    bomb = tmp_path / "bomb.apk"
    bomb.write_bytes(declared_bomb())
    with pytest.raises(DexQueryError) as caught:
        inventory_dex_members(bomb)
    assert caught.value.reason == "zip_bomb"


def test_inventory_rejects_crc_path_and_duplicate_before_using_the_member(tmp_path) -> None:
    built = build_dex(sample_classes())
    flipped = tmp_path / "crc.apk"
    flipped.write_bytes(flip_central_crc(zip_bytes([("classes.dex", built.data)], compress=False)))
    with pytest.raises(DexQueryError) as crc_error:
        inventory_dex_members(flipped)
    assert crc_error.value.reason == "crc_mismatch"

    escaped = tmp_path / "path.apk"
    escaped.write_bytes(_raw_zip([("../classes.dex", 0, built.data, len(built.data))]))
    with pytest.raises(DexQueryError) as path_error:
        inventory_dex_members(escaped)
    assert path_error.value.reason == "path_rejected"

    duplicated = tmp_path / "dup.apk"
    duplicated.write_bytes(_raw_zip([
        ("classes.dex", 0, built.data, len(built.data)),
        ("classes.dex", 0, built.data, len(built.data)),
    ]))
    with pytest.raises(DexQueryError) as duplicate_error:
        inventory_dex_members(duplicated)
    assert duplicate_error.value.reason == "duplicate_member"


def test_member_cap_skips_later_dex_without_inflating_it(tmp_path) -> None:
    built = build_dex(sample_classes())
    garbage = b"not-deflate"
    archive = tmp_path / "capped.apk"
    archive.write_bytes(_raw_zip([
        ("classes.dex", 0, built.data, len(built.data)),
        ("assets/payload.dex", 8, garbage, 32),
    ]))
    members, skipped, truncated = inventory_dex_members(
        archive, DexQueryLimits(max_dex_members=1),
    )
    assert [item.name for item in members] == ["classes.dex"]
    assert skipped == [{
        "ordinal": 1,
        "name": "assets/payload.dex",
        "status": "skipped",
        "reason": "oversize",
    }]
    assert truncated is True
