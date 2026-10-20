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
    env.write_text("FXAPK_VT_KEY=deadbeefcafe0123  # 可选：备用 Key；主 Key 未配置时使用\n",
                   encoding="utf-8")
    monkeypatch.delenv("FXAPK_VT_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    assert load_dotenv(env) >= 1
    val = os.environ["FXAPK_VT_KEY"]
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
    env.write_bytes("﻿FXAPK_OTX_KEY=abc123\n".encode("utf-8"))
    monkeypatch.delenv("FXAPK_OTX_KEY", raising=False)
    assert load_dotenv(env) == 1
    assert os.environ.get("FXAPK_OTX_KEY") == "abc123"
    assert not [k for k in os.environ if k.startswith("﻿")]


def test_fullwidth_space_and_nbsp_start_comment() -> None:
    """★全角空格 U+3000 / NBSP U+00A0 + ``#`` 也起注释——从中文文档粘贴的注释常带这类空白，
    只认 ``" #"``/``"\\t#"`` 会把注释整个并进密钥。"""
    assert _parse_line("FXAPK_A=abc123　# 全角空格注释") == ("FXAPK_A", "abc123")
    assert _parse_line("FXAPK_A=abc123\xa0# NBSP 注释") == ("FXAPK_A", "abc123")
    # 无前导空白的 # 仍是值的一部分（语义不变）。
    assert _parse_line("FXAPK_A=abc#def") == ("FXAPK_A", "abc#def")


def test_empty_placeholder_does_not_mask_lower_priority(tmp_path, monkeypatch) -> None:
    """★空占位不掩蔽：仓库根 .env 里同一键先有空占位行、再有真实值行，最终取真实值。"""
    from apkscan.core import dotenv as dotenv_mod

    monkeypatch.setattr(dotenv_mod, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(dotenv_mod, "_USER_ENV", tmp_path / "absent-user.env")
    (tmp_path / ".env").write_text("FXAPK_VT_KEY=\nFXAPK_VT_KEY=realvalue\n", encoding="utf-8")
    monkeypatch.delenv("FXAPK_VT_KEY", raising=False)
    assert load_dotenv() >= 1
    assert os.environ["FXAPK_VT_KEY"] == "realvalue"


def test_injection_logs_source_file(tmp_path, monkeypatch, caplog) -> None:
    """注入时记「键名 ← 来源文件」（debug 级、绝不回显值）——多 .env 并存时排障第一问。"""
    env = tmp_path / ".env"
    env.write_text("FXAPK_OTX_KEY=abc123\n", encoding="utf-8")
    monkeypatch.delenv("FXAPK_OTX_KEY", raising=False)
    with caplog.at_level("DEBUG", logger="apkscan.core.dotenv"):
        assert load_dotenv(env) == 1
    hits = [r.message for r in caplog.records if "FXAPK_OTX_KEY" in r.message]
    assert hits and any(str(env) in m for m in hits)
    assert not any("abc123" in m for m in hits), "日志绝不回显密钥值"


def test_non_utf8_file_warns_not_silent(tmp_path, caplog) -> None:
    """★非 UTF-8(如 GBK):整份文件被丢弃、所有密钥消失。必须 WARNING 可见,
    否则症状是"所有源都说没配密钥",离病根极远。"""
    env = tmp_path / ".env"
    env.write_bytes("FXAPK_URLSCAN_KEY=abc123  # 中文注释\n".encode("gbk"))
    with caplog.at_level("WARNING"):
        assert load_dotenv(env) == 0
    assert any("UTF-8" in r.message for r in caplog.records), "非 UTF-8 必须给 WARNING"


def test_hostile_cwd_env_is_not_loaded(tmp_path, monkeypatch) -> None:
    """证据目录（cwd）里的 .env 不是查找源，攻击者放的键不得进入环境。"""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / ".env").write_text(
        "FXAPK_TOOLCHAIN_FILE=evil-toolchain\n"
        "FXAPK_ENABLE_REA=1\n"
        "FXAPK_VT_KEY=evil-vt-key\n",
        encoding="utf-8",
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    for key in ("FXAPK_TOOLCHAIN_FILE", "FXAPK_ENABLE_REA", "FXAPK_VT_KEY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(evidence)
    from apkscan.core import dotenv as dotenv_mod

    monkeypatch.setattr(dotenv_mod, "_REPO_ROOT", repo)
    monkeypatch.setattr(dotenv_mod, "_USER_ENV", tmp_path / "absent-user.env")
    assert load_dotenv() == 0
    assert "FXAPK_TOOLCHAIN_FILE" not in os.environ
    assert "FXAPK_ENABLE_REA" not in os.environ
    assert "FXAPK_VT_KEY" not in os.environ


def test_user_env_is_second_trusted_location(tmp_path, monkeypatch) -> None:
    """仓库根没有 .env 时读用户级 ``~/.fxapk/.env``；cwd 与非白名单键都不注入。"""
    from apkscan.core import dotenv as dotenv_mod

    repo = tmp_path / "repo"
    repo.mkdir()
    user_env = tmp_path / "home" / ".fxapk" / ".env"
    user_env.parent.mkdir(parents=True)
    user_env.write_text(
        "FXAPK_VT_KEY=user-vt-key\n"
        "FXAPK_TOOLCHAIN_FILE=user-toolchain\n",
        encoding="utf-8",
    )
    hostile = tmp_path / "evidence"
    hostile.mkdir()
    (hostile / ".env").write_text(
        "FXAPK_TOOLCHAIN_FILE=evil-toolchain\n"
        "FXAPK_ENABLE_REA=1\n"
        "FXAPK_VT_KEY=evil-vt-key\n",
        encoding="utf-8",
    )
    for key in ("FXAPK_TOOLCHAIN_FILE", "FXAPK_ENABLE_REA", "FXAPK_VT_KEY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(hostile)
    monkeypatch.setattr(dotenv_mod, "_REPO_ROOT", repo)
    monkeypatch.setattr(dotenv_mod, "_USER_ENV", user_env)
    assert load_dotenv() == 1
    assert os.environ["FXAPK_VT_KEY"] == "user-vt-key"
    assert "FXAPK_TOOLCHAIN_FILE" not in os.environ
    assert "FXAPK_ENABLE_REA" not in os.environ


def test_explicit_dotenv_rejects_execution_path_and_gate_keys(tmp_path, monkeypatch, caplog) -> None:
    """显式路径仍只注入白名单键；执行路径 / 安全门 / 数据根被拒，告警只列键名。"""
    env = tmp_path / ".env"
    planted = {
        "PATH": "evil-path-value",
        "JAVA_HOME": "evil-java-home",
        "FXAPK_TOOLCHAIN_FILE": "evil-toolchain",
        "FXAPK_TCPDUMP_BIN": "evil-tcpdump",
        "FXAPK_ENABLE_REA": "1",
        "FXAPK_HANDOFF_ROOT": "evil-handoff-root",
        "FXAPK_CORPUS": "evil-corpus-root",
        "FXAPK_VT_KEY": "vt-key-body",
    }
    env.write_text("".join(f"{key}={val}\n" for key, val in planted.items()), encoding="utf-8")
    for key in planted:
        monkeypatch.delenv(key, raising=False)
    rejected = (
        "FXAPK_CORPUS",
        "FXAPK_ENABLE_REA",
        "FXAPK_HANDOFF_ROOT",
        "FXAPK_TCPDUMP_BIN",
        "FXAPK_TOOLCHAIN_FILE",
        "JAVA_HOME",
        "PATH",
    )
    with caplog.at_level("WARNING", logger="apkscan.core.dotenv"):
        assert load_dotenv(env) == 1
    assert os.environ["FXAPK_VT_KEY"] == "vt-key-body"
    for key in rejected:
        assert key not in os.environ
    warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    text = warnings[0]
    assert ", ".join(rejected) in text
    assert str(env) in text
    for val in planted.values():
        if val == "1":
            assert "FXAPK_ENABLE_REA=1" not in text
            continue
        assert val not in text


def test_hostile_dotenv_does_not_open_rea_gate(tmp_path, monkeypatch) -> None:
    """REA 门的判据是 ``FXAPK_ENABLE_REA == '1'``（plugins/registry.py）。.env 不得打开它。"""
    env = tmp_path / ".env"
    env.write_text("FXAPK_ENABLE_REA=1\n", encoding="utf-8")
    monkeypatch.delenv("FXAPK_ENABLE_REA", raising=False)
    assert load_dotenv(env) == 0
    assert os.environ.get("FXAPK_ENABLE_REA") != "1"
