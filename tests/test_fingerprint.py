"""mmh3 / favicon_hash 纯函数单测 —— 锁死实现对齐权威 MurmurHash3 x86_32 向量。

最关键：favicon hash 错一位，丢给 FOFA/Shodan 的查询串就是废线索。故这里硬编码
公开可核验的权威向量断言；favicon_hash 还要验证 base64.encodebytes（RFC2045 每 76
字符插 \\n）口径，证明用的是 encodebytes 而非 b64encode。
"""

from __future__ import annotations

import base64

from apkscan.dynamic.fingerprint import favicon_hash, mmh3_x86_32


# ---------------------------------------------------------------------------
# MurmurHash3 x86_32 权威向量（seed=0，有符号 32-bit）
# ---------------------------------------------------------------------------
#
# 这些值与 Python `mmh3.hash(s)`（C 实现）一致，是公认参考口径：
#   mmh3.hash("")      == 0
#   mmh3.hash("foo")   == -156908512
#   mmh3.hash("hello") == 613153351
#   mmh3.hash("Hello, world!") == -1070186941
# 任意一条对不上即纯实现写错，必须修到对齐。


def test_empty_bytes_is_zero() -> None:
    assert mmh3_x86_32(b"") == 0


def test_vector_foo() -> None:
    assert mmh3_x86_32(b"foo") == -156908512


def test_vector_hello() -> None:
    assert mmh3_x86_32(b"hello") == 613153351


def test_vector_hello_world() -> None:
    assert mmh3_x86_32(b"Hello, world!") == -1070186941


def test_seed_changes_hash() -> None:
    # 不同 seed 必给出不同结果（seed 真正进入算法，而非被忽略）。
    assert mmh3_x86_32(b"foo", seed=0) != mmh3_x86_32(b"foo", seed=1)


def test_result_is_signed_32bit() -> None:
    # 返回值落在有符号 32-bit 区间。
    for data in (b"", b"foo", b"hello", b"a" * 100):
        h = mmh3_x86_32(data)
        assert -(2**31) <= h <= 2**31 - 1


def test_tail_lengths_all_branches() -> None:
    # 覆盖 tail 处理的 0/1/2/3 字节分支：长度 4k、4k+1、4k+2、4k+3 都不应抛。
    for n in (4, 5, 6, 7, 8, 9, 10, 11):
        h = mmh3_x86_32(b"x" * n)
        assert isinstance(h, int)


# ---------------------------------------------------------------------------
# favicon_hash —— base64.encodebytes 口径（经典踩坑点）
# ---------------------------------------------------------------------------


def test_favicon_hash_uses_encodebytes_not_b64encode() -> None:
    # 用一段够长（>76 字节，触发换行）的固定 bytes。
    raw = bytes(range(256)) * 4  # 1024 字节，encodebytes 会插多处 \n

    expected = mmh3_x86_32(base64.encodebytes(raw))
    assert favicon_hash(raw) == expected

    # 与无换行的 b64encode 口径必须不同（证明确实用了 encodebytes）。
    wrong = mmh3_x86_32(base64.b64encode(raw))
    assert favicon_hash(raw) != wrong

    # 直接断言 encodebytes 确实插了换行（前提成立）。
    assert b"\n" in base64.encodebytes(raw)
    assert b"\n" not in base64.b64encode(raw)


def test_favicon_hash_empty() -> None:
    # encodebytes(b"") == b""，favicon_hash(b"") == mmh3("") == 0。
    assert base64.encodebytes(b"") == b""
    assert favicon_hash(b"") == 0


def test_favicon_hash_short_input_no_newline_still_matches() -> None:
    # 短输入（<76 base64 字符，无换行）也必须走 encodebytes 口径。
    raw = b"abc"
    assert favicon_hash(raw) == mmh3_x86_32(base64.encodebytes(raw))
