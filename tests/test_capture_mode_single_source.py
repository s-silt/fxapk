"""capture 模式与 antidetect 档位的单一事实源。

此前 cli.py、capture.py、capabilities.py 各写一份取值集合，只靠注释「与…对齐」维持一致；
cli 的 --mode 报错文案就因此漏了 no-proxy。本测试把那句注释换成会红的检查。
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fxapk import cli
from fxapk.dynamic import capabilities, capture

_ROOT = Path(__file__).resolve().parents[1]
_GUARDED_FILES = ("fxapk/cli.py", "fxapk/dynamic/capture.py")
_GUARDED_SETS = (
    frozenset(capabilities.CAPTURE_MODES),
    frozenset(capabilities.ANTIDETECT_MODES),
)


def _literal_string_collections(source: str) -> list[tuple[int, frozenset[str]]]:
    """返回源码里所有纯字符串字面量 tuple/set/list 及其行号。"""
    found: list[tuple[int, frozenset[str]]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Tuple, ast.Set, ast.List)) and len(node.elts) >= 2:
            values = [e.value for e in node.elts if isinstance(e, ast.Constant)]
            if len(values) == len(node.elts) and all(isinstance(v, str) for v in values):
                found.append((node.lineno, frozenset(values)))
    return found


def test_capture_runtime_uses_capabilities_constants() -> None:
    assert capture._CAPTURE_MODES == frozenset(capabilities.CAPTURE_MODES)
    assert capture._ANTIDETECT_MODES == frozenset(capabilities.ANTIDETECT_MODES)


@pytest.mark.parametrize("rel_path", _GUARDED_FILES)
def test_no_hardcoded_copy_of_mode_sets(rel_path: str) -> None:
    source = (_ROOT / rel_path).read_text(encoding="utf-8")
    copies = [
        (line, sorted(values))
        for line, values in _literal_string_collections(source)
        if values in _GUARDED_SETS
    ]
    assert not copies, (
        f"{rel_path} 手写了取值集合 {copies}；改用 fxapk.dynamic.capabilities "
        "的 CAPTURE_MODES / ANTIDETECT_MODES"
    )


def test_scanner_detects_hardcoded_copy() -> None:
    """扫描器自检：手写副本必须被认出来，否则上一条测试会假绿。"""
    src = 'if antidetect not in ("off", "java"):\n    pass\nX = {"both", "floor-only", "mitm-only", "no-proxy"}\n'
    hits = {values for _, values in _literal_string_collections(src)}
    assert set(_GUARDED_SETS) <= hits


def test_capture_cli_mode_error_lists_every_supported_mode() -> None:
    res = CliRunner().invoke(cli.app, ["capture", "com.example.synthetic", "--mode", "bogus"])
    assert res.exit_code == 2
    for mode in capabilities.CAPTURE_MODES:
        assert mode in res.output


@pytest.mark.parametrize("command", ["capture", "auto"])
def test_cli_rejects_unsupported_antidetect(command: str, tmp_path: Path) -> None:
    if command == "capture":
        target = "com.example.synthetic"
    else:
        apk = tmp_path / "synthetic.apk"
        apk.write_bytes(b"PK\x05\x06" + b"\x00" * 18)  # 空 ZIP；校验在加载 APK 之前
        target = str(apk)
    res = CliRunner().invoke(cli.app, [command, target, "--antidetect", "native"])
    assert res.exit_code == 2
    assert "--antidetect 取值非法" in res.output  # 防止因别的参数错误以 2 退出而假绿
    assert " / ".join(capabilities.ANTIDETECT_MODES) in res.output
