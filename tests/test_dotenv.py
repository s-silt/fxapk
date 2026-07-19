"""``core/dotenv`` 行解析测试——重点是**行内注释**与引号的交互。

背景：一个真实的 .env 里写成 ``FXAPK_X_KEY=<32位密钥>  # 可选：备用 Key``，注释被并进了值，
62 字符含中文的"密钥"塞进 HTTP 头直接 UnicodeEncodeError。行内注释必须剥，但引号内的 ``#``
是值的一部分、不能剥。
"""

from __future__ import annotations

import os

from apkscan.core.dotenv import _parse_line, load_dotenv


def test_plain_key_value() -> None:
    assert _parse_line("FXAPK_A=abc123") == ("FXAPK_A", "abc123")


def test_export_prefix_and_whitespace() -> None:
    assert _parse_line("  export FXAPK_A = abc123  ") == ("FXAPK_A", "abc123")


def test_full_line_comment_and_blank_rejected() -> None:
    assert _parse_line("# 整行注释") is None
    assert _parse_line("   ") is None
    assert _parse_line("NO_EQUALS_SIGN") is None


def test_inline_comment_stripped() -> None:
    """★核心回归：空白 + ``#`` 起注释，值不得把注释吞进来。"""
    assert _parse_line("FXAPK_A=abc123  # 可选：备用 Key") == ("FXAPK_A", "abc123")
    assert _parse_line("FXAPK_A=abc123\t# tab 分隔的注释") == ("FXAPK_A", "abc123")
    # 多个 # 时取最早的分隔位
    assert _parse_line("FXAPK_A=abc # 一 # 二") == ("FXAPK_A", "abc")


def test_hash_without_leading_space_is_part_of_value() -> None:
    """``abc#def`` 里的 ``#`` 无前导空白 → 是值的一部分，不能截断（密钥可能含 #）。"""
    assert _parse_line("FXAPK_A=abc#def") == ("FXAPK_A", "abc#def")


def test_quoted_value_keeps_hash_verbatim() -> None:
    """引号内 ``#`` 不是注释：剥引号后原样保留，不做行内注释处理。"""
    assert _parse_line('FXAPK_A="abc # still value"') == ("FXAPK_A", "abc # still value")
    assert _parse_line("FXAPK_A='abc # still value'") == ("FXAPK_A", "abc # still value")


def test_inline_comment_keeps_key_ascii_safe(tmp_path, monkeypatch) -> None:
    """端到端：带中文行内注释的 .env 注入后，值仍是纯 ASCII 的密钥本体。

    这正是踩过的坑——若注释被并入，值含中文，后续当 HTTP 头用会 UnicodeEncodeError。
    """
    env = tmp_path / ".env"
    env.write_text("FXAPK_TEST_INLINE=deadbeefcafe0123  # 可选：备用 Key；主 Key 未配置时使用\n",
                   encoding="utf-8")
    monkeypatch.delenv("FXAPK_TEST_INLINE", raising=False)
    monkeypatch.chdir(tmp_path)
    assert load_dotenv(env) >= 1
    val = os.environ["FXAPK_TEST_INLINE"]
    assert val == "deadbeefcafe0123"
    assert val.isascii()
    val.encode("latin-1")  # HTTP 头编码：注释若被并入这里会抛
