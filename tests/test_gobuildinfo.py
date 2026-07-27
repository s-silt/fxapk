"""Go buildinfo 解析 + 注入凭据的脱敏。

★这一层的安全红线与别处不同：``-ldflags -X`` 注入的值可能是活体私钥（实测样本里就是
一份可用的 RSA 私钥）。那是能解控制面流量的凭据，把它写进 report.json 等于把凭据分发
出去——本地留存也不行。所以不是"digest --redact 时遮蔽"，是**在解析处就不留原值**。
"""

from __future__ import annotations

import base64
import hashlib
import json

from apkscan.core.gobuildinfo import (
    _INFO_END,
    _INFO_START,
    fingerprint_embedded_secret,
    parse_go_buildinfo,
)

_FAKE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + "\n".join(["QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 2] * 20)
    + "\n-----END RSA PRIVATE KEY-----\n"
)
_FAKE_B64 = base64.b64encode(_FAKE_PEM.encode()).decode()


def _make_blob(modinfo: str) -> bytes:
    return b"\x00\x00go1.25.0\x00" + _INFO_START + modinfo.encode() + _INFO_END + b"\x00"


def test_parses_version_module_replace_and_deps() -> None:
    info = parse_go_buildinfo(_make_blob(
        "path\tgobind/gobind\n"
        "mod\tgobind\t(devel)\n"
        "dep\tgithub.com/example/lib\tv1.2.3\th1:abc\n"
        "=>\tD:\\workspace\\project\n"
        "build\t-buildmode=c-shared\n"
    ))
    assert info is not None
    assert info.go_version == "go1.25.0"
    assert info.main_path == "gobind/gobind"
    assert "gobind" in info.main_module
    assert info.replaces == ["D:\\workspace\\project"]
    assert any("github.com/example/lib" in d for d in info.deps)
    assert info.build_settings["-buildmode"] == "c-shared"


def test_injected_private_key_never_appears_in_output() -> None:
    """★核心红线：注入值原样不得出现在返回结构的任何角落。"""
    modinfo = (
        "path\tgobind/gobind\n"
        f'build\t-ldflags="-X example/sdk.EmbeddedPrivateKeyB64={_FAKE_B64}"\n'
    )
    info = parse_go_buildinfo(_make_blob(modinfo))
    assert info is not None

    blob = json.dumps({
        "replaces": info.replaces, "deps": info.deps,
        "build_settings": info.build_settings, "ldflags_x": info.ldflags_x,
    }, ensure_ascii=False)

    # 用真实注入值本身去查，而不是猜特征——base64 形态不含 "BEGIN RSA PRIVATE KEY"，
    # 只查明文特征会漏掉 build_settings 里那份完整原值（实测踩过）。
    assert _FAKE_B64 not in blob, "完整原值泄露"
    assert _FAKE_B64[:64] not in blob, "原值前缀泄露"
    assert "BEGIN RSA PRIVATE KEY" not in blob


def test_ldflags_setting_itself_is_redacted() -> None:
    """★同一个值在 build_settings 的 -ldflags 命令行里还有一份——那条也要抹。"""
    info = parse_go_buildinfo(_make_blob(
        f'build\t-ldflags="-X example/sdk.KeyB64={_FAKE_B64}"\n'
    ))
    assert info is not None
    ldflags = info.build_settings.get("-ldflags", "")
    assert _FAKE_B64 not in ldflags
    assert "<redacted:" in ldflags


def test_fingerprint_carries_enough_to_match_across_samples() -> None:
    """指纹要足以跨样本比对同一份凭据，同时不泄露内容。"""
    fp = fingerprint_embedded_secret("sdk.EmbeddedPrivateKeyB64", _FAKE_B64)
    assert fp["kind"] == "private_key_pem_base64"
    assert fp["length"] == len(_FAKE_B64)
    assert fp["sha256"] == hashlib.sha256(_FAKE_B64.encode()).hexdigest()
    assert fp["decoded_sha256"] == hashlib.sha256(_FAKE_PEM.encode()).hexdigest()
    assert "value" not in fp, "敏感值不得带 value 字段"


def test_non_sensitive_injection_keeps_value() -> None:
    """版本号这类注入留明文才有用——不能一刀切全抹。"""
    info = parse_go_buildinfo(_make_blob(
        'build\t-ldflags="-X main.BuildVersion=1.4.2"\n'
    ))
    assert info is not None
    entry = next(x for x in info.ldflags_x if x["var"] == "main.BuildVersion")
    assert entry["value"] == "1.4.2"
    assert info.build_settings["-ldflags"].count("1.4.2") == 1


def test_sensitive_by_variable_name_even_when_value_is_opaque() -> None:
    info = parse_go_buildinfo(_make_blob(
        'build\t-ldflags="-X main.ApiToken=zzzz1111"\n'
    ))
    assert info is not None
    entry = next(x for x in info.ldflags_x if x["var"] == "main.ApiToken")
    assert entry["kind"] == "sensitive_by_name"
    assert "value" not in entry
    assert "zzzz1111" not in info.build_settings["-ldflags"]


def test_non_go_binary_returns_none() -> None:
    assert parse_go_buildinfo(b"\x7fELF" + b"\x00" * 512) is None


def test_oversized_modinfo_is_bounded() -> None:
    """超大 modinfo 不解析——但仍把 Go 版本带出来（廉价且有用）。"""
    info = parse_go_buildinfo(_make_blob("build\tx=" + "A" * 200_000 + "\n"))
    assert info is not None
    assert info.go_version == "go1.25.0"
    assert not info.build_settings


def test_never_raises_on_garbage() -> None:
    for blob in (b"", b"go1.25.0", _INFO_START, _INFO_END + _INFO_START,
                 _INFO_START + b"\xff\xfe" * 100 + _INFO_END):
        parse_go_buildinfo(blob)  # 不抛即通过
