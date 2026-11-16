"""名字只有 fxapk：命令、导入包都不再提供 apkscan，给用户的命令提示也不能写 apkscan。"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

from typer.main import get_command

from fxapk import cli

_ROOT = Path(__file__).resolve().parents[1]


def test_only_fxapk_console_script_is_registered() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert set(project["scripts"]) == {"fxapk"}


def test_apkscan_import_package_is_gone() -> None:
    import importlib.util

    assert importlib.util.find_spec("apkscan") is None
    setuptools = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]
    assert setuptools["packages"]["find"]["include"] == ["fxapk*"]
    assert not (_ROOT / "apkscan").exists()


def _subcommands() -> set[str]:
    group = get_command(cli.app)
    return set(getattr(group, "commands", {}))


def _string_fragments(source: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append((node.lineno, node.value))
    return out


def _alias_hint_pattern(subcommands: set[str]) -> re.Pattern[str]:
    names = "|".join(sorted(map(re.escape, subcommands)))
    return re.compile(rf"(?<![\w./-])apkscan\s+(?:{names})\b")


def test_no_user_facing_apkscan_command_hint() -> None:
    pattern = _alias_hint_pattern(_subcommands())
    hits = [
        f"{path.relative_to(_ROOT).as_posix()}:{line}"
        for path in sorted((_ROOT / "fxapk").rglob("*.py"))
        for line, text in _string_fragments(path.read_text(encoding="utf-8"))
        if pattern.search(text)
    ]
    assert not hits, f"字符串里仍提示用户运行 apkscan 别名：{hits}"


def test_hint_scanner_detects_alias_and_ignores_module_path() -> None:
    pattern = _alias_hint_pattern({"analyze", "leak-scan"})
    assert pattern.search("apkscan analyze <apk> --extra-dex <dir>")
    assert pattern.search('f"apkscan analyze {apk}"'.split('"')[1])
    assert not pattern.search("python -m fxapk.cli analyze x")
    assert not pattern.search("leak-scan --path apkscan --path tests")
    assert {"analyze", "digest", "capture"} <= _subcommands()
