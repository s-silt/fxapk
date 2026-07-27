"""资源投毒路径：目录名恰好叫 strings.xml 的畸形条目不得被送进 XML parser。

★真样本回归：脱壳 DEX 回灌时见过成批的
``res/values/strings.xml/<畸形 Unicode 路径>.png`` 与 ``.../*.xml``。
原判据是子串匹配（``"res/values/strings.xml" in path``），于是每个投毒文件都进了
XML parser，刷出几十屏 ExpatError traceback，而汇总仍写 ``config_keys 抠出 N 条``、
``ran=35 skipped=0 error=0`` —— 既刷屏，又把"部分输入不可解析"这个事实盖掉了。
"""

from __future__ import annotations

from typing import Any

import pytest

from apkscan.analyzers.config_keys import ConfigKeysAnalyzer, _match_extra_config


class _Ctx:
    """最小 AnalysisContext 替身：只实现本分析器要用的两个方法。"""

    platform = "android"
    manifest_xml = ""

    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files
        self.reads: list[str] = []

    def list_files(self) -> list[str]:
        return list(self._files)

    def read_file(self, path: str) -> bytes:
        self.reads.append(path)
        return self._files[path]

    def dex_strings(self) -> list[str]:
        return []


@pytest.mark.parametrize(
    "path",
    [
        "res/values/strings.xml/﻿‮́.png",
        "res/values/strings.xml/nested/evil.xml",
        "res/values/strings.xml.bak",
        "res/values/strings.xmlx",
        "assets/data/dcloud_control.xml/evil.png",
        "res/values/strings.xml/",
        "res/values//strings.xml",
        "res/values/../values/strings.xml",
    ],
)
def test_poisoned_paths_do_not_match(path: str) -> None:
    assert _match_extra_config(path) is None, path


@pytest.mark.parametrize(
    "path",
    [
        "res/values/strings.xml",
        "RES/VALUES/STRINGS.XML",
        "assets/data/dcloud_control.xml",
        "assets/data/dcloud_uniplugins.json",
        "base/res/values/strings.xml",
    ],
)
def test_real_config_paths_still_match(path: str) -> None:
    assert _match_extra_config(path) is not None, path


def test_poisoned_entries_are_never_read() -> None:
    """★最关键的一条：投毒文件连读都不该读，更不该进 parser。"""
    ctx = _Ctx({
        "res/values/strings.xml": b'<resources><string name="APPKEY">k1</string></resources>',
        "res/values/strings.xml/‮́.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 32,
        "res/values/strings.xml/evil.xml": b"<<<not xml at all",
    })
    analyzer = ConfigKeysAnalyzer()
    errors: dict[str, int] = {}
    keys = analyzer._from_extra_files(ctx, errors)  # type: ignore[arg-type]

    assert ctx.reads == ["res/values/strings.xml"], f"只该读真配置文件，实读 {ctx.reads}"
    assert errors == {}, "真配置文件解析正常，不该有输入错误"
    assert any(k.name == "APPKEY" for k in keys)


def test_parse_errors_are_aggregated_into_meta() -> None:
    """真配置文件本身坏掉时，错误要按类型计数进 meta，而不是只落一坨 traceback。"""
    ctx = _Ctx({"res/values/strings.xml": b"<resources><string name=unclosed"})
    result = ConfigKeysAnalyzer().analyze(ctx)  # type: ignore[arg-type]

    errors = result.meta.get("config_keys_input_errors")
    assert isinstance(errors, dict) and errors, "输入错误必须出现在 meta 里"
    assert sum(errors.values()) == 1
    assert "ExpatError" in errors


def test_clean_run_leaves_no_input_error_key() -> None:
    """没有错误时不要写空字段——"存在但为空"和"没有"读起来是两回事。"""
    ctx = _Ctx({
        "res/values/strings.xml": b'<resources><string name="A">v</string></resources>',
    })
    result = ConfigKeysAnalyzer().analyze(ctx)  # type: ignore[arg-type]
    assert "config_keys_input_errors" not in result.meta


def test_analyzer_does_not_crash_on_poisoned_only(monkeypatch: Any) -> None:
    ctx = _Ctx({f"res/values/strings.xml/{i}.png": b"\x00\x01" for i in range(20)})
    result = ConfigKeysAnalyzer().analyze(ctx)  # type: ignore[arg-type]
    assert result.error is None
    assert "config_keys_input_errors" not in result.meta
