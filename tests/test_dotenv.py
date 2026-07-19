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


def test_quoted_value_with_inline_comment() -> None:
    """★引号 + 行内注释:按**配对收尾引号**切,其后是注释。

    早先的实现用 ``val[0] == val[-1]`` 判引号包裹,而带注释时末字符属注释 → 判不出,
    于是把字面引号留在值里;更糟的是引号内含 ``# `` 时会从**引号内部**切断。
    """
    assert _parse_line('FXAPK_A="abc"  # 注释') == ("FXAPK_A", "abc")
    assert _parse_line("FXAPK_A='abc'  # 注释") == ("FXAPK_A", "abc")
    # 引号内的 # 属于值,不能被当注释切断
    assert _parse_line('FXAPK_A="a # b"  # 真注释') == ("FXAPK_A", "a # b")


def test_unclosed_quote_falls_back() -> None:
    """引号未闭合 → 不猜,退化为按未加引号处理。"""
    assert _parse_line('FXAPK_A="unclosed') == ("FXAPK_A", '"unclosed')


def test_bom_does_not_corrupt_first_key(tmp_path, monkeypatch) -> None:
    """★BOM:编辑器存的 .env 常带 BOM,用 utf-8 读会让首个键名变成 ``\ufeffFXAPK_...``——
    "注入成功 1 条"但真实键查不到,且零告警。"""
    env = tmp_path / ".env"
    env.write_bytes("﻿FXAPK_TEST_BOM=abc123\n".encode("utf-8"))
    monkeypatch.delenv("FXAPK_TEST_BOM", raising=False)
    assert load_dotenv(env) == 1
    assert os.environ.get("FXAPK_TEST_BOM") == "abc123"
    assert not [k for k in os.environ if k.startswith("﻿")]


def test_non_utf8_file_warns_not_silent(tmp_path, caplog) -> None:
    """★非 UTF-8(如 GBK):整份文件被丢弃、所有密钥消失。必须 WARNING 可见,
    否则症状是"所有源都说没配密钥",离病根极远。"""
    env = tmp_path / ".env"
    env.write_bytes("FXAPK_TEST_GBK=abc123  # 中文注释\n".encode("gbk"))
    with caplog.at_level("WARNING"):
        assert load_dotenv(env) == 0
    assert any("UTF-8" in r.message for r in caplog.records), "非 UTF-8 必须给 WARNING"
