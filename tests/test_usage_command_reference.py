"""Core public top-level registration must have entries in both command tables.

Nested commands, optional plugins, hidden aliases and prose/example parity are
outside this contract. Inspect registration only; never execute a command.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import click
import pytest

_ROOT = Path(__file__).resolve().parents[1]


def table_commands(text: str, heading: str) -> set[str]:
    marker = f"## {heading}\n"
    if text.count(marker) != 1:
        raise ValueError("expected one command-reference section")
    section = text.split(marker, 1)[1].split("\n## ", 1)[0]
    rows = "\n".join(line for line in section.splitlines() if line.startswith("|"))
    return set(re.findall(r"`fxapk ([a-z][a-z0-9-]*)(?=[ `])", rows))


def public_commands(group: click.Group) -> set[str]:
    return {name for name, command in group.commands.items() if not command.hidden}


@pytest.fixture(scope="module")
def registered_core_commands() -> set[str]:
    # Fresh process avoids changing the CLI singleton used by other tests.
    # Disable only optional registrations; use the real core Typer -> Click tree.
    script = '''
import json
import fxapk.plugins.registry as registry
registry.register_plugin_clis = lambda app: []
from typer.main import get_command
from fxapk.cli import app
from tests.test_usage_command_reference import public_commands
print(json.dumps(sorted(public_commands(get_command(app)))))
'''
    env = dict(os.environ)
    for name in ("PYTHONPATH", "FXHX_API_KEY", "CLIPROXYAPI_API_KEY"):
        env.pop(name, None)
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=_ROOT, env=env,
        capture_output=True, text=True, check=True, timeout=30,
    )
    names = set(json.loads(result.stdout))
    assert {"letters", "probe-target", "addressing-evaluate"} <= names
    return names


@pytest.mark.parametrize("filename,heading", [("USAGE.md", "命令表"), ("USAGE.en.md", "Command table")])
def test_public_core_commands_have_reference_entries(filename, heading, registered_core_commands):
    names = table_commands((_ROOT / filename).read_text(encoding="utf-8"), heading)
    assert not (missing := registered_core_commands - names), f"{filename}: missing entries {sorted(missing)}"


def test_only_reference_table_entries_count():
    text = '''## Command table
Prose mentions `fxapk letters`.
| Goal | Command |
| Evaluate | `fxapk addressing-evaluate manifest.json` |
## Examples
| Example | `fxapk probe-target --help` |
'''
    assert table_commands(text, "Command table") == {"addressing-evaluate"}


def test_missing_reference_heading_is_an_error():
    with pytest.raises(ValueError):
        table_commands("| Command | `fxapk letters` |", "Command table")


def test_public_command_scope_excludes_hidden_but_includes_groups():
    group = click.Group()
    group.add_command(click.Command("visible"))
    group.add_command(click.Command("compat", hidden=True))
    nested = click.Group("group")
    nested.add_command(click.Command("nested"))
    group.add_command(nested)
    assert public_commands(group) == {"visible", "group"}
