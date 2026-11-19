"""Fresh-process CLI cold-start and mixed optional-plugin lifecycle smoke tests."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_RUNTIME_ENV_KEYS = (
    "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
    "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "VIRTUAL_ENV",
)
_SCRIPT = r'''
import importlib.abc
import importlib.metadata
import json
import sys
from types import SimpleNamespace
import typer
from fxapk.plugins.contracts import PLUGIN_API_VERSION

mode, failure, *cli_args = sys.argv[1:]
MARKER = "synthetic-exception-detail-not-a-status"
blocked_http: list[str] = []
selected_groups: list[str | None] = []
calls = {
    "broken_load": 0, "broken_factory": 0, "broken_register": 0,
    "healthy_register": 0, "smoke_ran": 0, "rea_load": 0,
}

class NoHTTPImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "fxapk.config.fetch" or fullname.split(".")[0] == "requests":
            blocked_http.append(fullname)
            raise AssertionError(f"Forbidden HTTP import during CLI cold start: {fullname}")

def broken_register(_app: object) -> None:
    calls["broken_register"] += 1
    raise RuntimeError(MARKER)

def broken_factory() -> object:
    calls["broken_factory"] += 1
    if failure == "factory_dependency":
        raise ModuleNotFoundError(MARKER)
    if failure == "factory_failure":
        raise RuntimeError(MARKER)
    return SimpleNamespace(name="android_ui", api_version=PLUGIN_API_VERSION, register_cli=broken_register)

def broken_load():
    calls["broken_load"] += 1
    if failure == "load_dependency":
        raise ModuleNotFoundError(MARKER)
    return broken_factory

def healthy_register(app: typer.Typer) -> None:
    calls["healthy_register"] += 1
    if mode == "unregistered_noop":
        return
    sub = typer.Typer()
    @sub.callback()
    def _cb() -> None:
        pass
    @sub.command("smoke")
    def _smoke(tag: str = typer.Option(..., "--tag")) -> None:
        calls["smoke_ran"] += 1
        typer.echo(f"flutter-smoke:{tag}")
    app.add_typer(sub, name="flutter")

def healthy_load():
    api_ver = "999" if mode == "bad_api_version" else PLUGIN_API_VERSION
    return lambda: SimpleNamespace(name="flutter", api_version=api_ver, register_cli=healthy_register)

def rea_load():
    calls["rea_load"] += 1
    raise AssertionError("rea entry point must not load without FXAPK_ENABLE_REA=1")

entries = [
    SimpleNamespace(
        name="flutter", value="fxapk_flutter.plugin:plugin_factory",
        dist=SimpleNamespace(metadata={"Name": "fxapk-flutter"}), load=healthy_load,
    ),
    SimpleNamespace(
        name="rea", value="fxapk_rea.plugin:plugin_factory",
        dist=SimpleNamespace(metadata={"Name": "fxapk-rea"}), load=rea_load,
    ),
]
if failure != "absent":
    entries.append(SimpleNamespace(
        name="android_ui", value="fxapk_android_ui.plugin:plugin_factory",
        dist=SimpleNamespace(metadata={"Name": "fxapk-android-ui"}), load=broken_load,
    ))

class Entries:
    def select(self, **kwargs):
        group = kwargs.get("group")
        selected_groups.append(group)
        return list(entries) if group == "fxapk.plugins" else []

importlib.metadata.entry_points = lambda: Entries()
sys.meta_path.insert(0, NoHTTPImports())
def block_network(event, _args):
    if event.startswith("socket."):
        raise AssertionError(f"Network operation attempted: {event}")

sys.addaudithook(block_network)
from fxapk import cli
from fxapk.core import dotenv

# Only this synthetic callback is exercised; it never needs credentials. Avoid reading parent .env files.
dotenv._candidate_paths = lambda _path: []
sys.argv = ["fxapk", *cli_args]
exit_code = 0
try:
    cli.main()
except SystemExit as exc:
    exit_code = 0 if exc.code is None else int(exc.code)

assert "fxapk.plugins" in selected_groups
assert not blocked_http
assert "requests" not in sys.modules
assert "fxapk.config.fetch" not in sys.modules
statuses = cli._PLUGIN_CLI_STATUS
assert MARKER not in json.dumps(statuses)
expected = [
    {
        "name": "flutter",
        "status": "unavailable" if mode == "bad_api_version" else "ok",
        "reason": "ValueError" if mode == "bad_api_version" else "",
    },
    {"name": "rea", "status": "disabled", "reason": "rea_opt_in_required"},
]
if failure != "absent":
    reason = "ModuleNotFoundError" if failure.endswith("_dependency") else "RuntimeError"
    expected.insert(0, {"name": "android_ui", "status": "unavailable", "reason": reason})
assert statuses == expected
assert calls == {
    "broken_load": int(failure != "absent"),
    "broken_factory": int(failure not in ("absent", "load_dependency")),
    "broken_register": int(failure == "register_failure"),
    "healthy_register": int(mode != "bad_api_version"),
    "smoke_ran": int(mode == "healthy_registered" and cli_args[:2] == ["flutter", "smoke"]),
    "rea_load": 0,
}
raise SystemExit(exit_code)
'''


def _run_cli_subprocess(tmp_path: Path, mode: str, failure: str, cli_args: list[str]) -> subprocess.CompletedProcess[str]:
    env = {k: v for k in _RUNTIME_ENV_KEYS if (v := os.environ.get(k)) is not None}
    for key in ("HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"):
        env[key] = str(tmp_path)
    env["PYTHONPATH"] = str(_ROOT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONIOENCODING"] = "utf-8:strict"
    env["NO_COLOR"] = "1"
    return subprocess.run(
        [sys.executable, "-B", "-c", _SCRIPT, mode, failure, *cli_args],
        cwd=tmp_path, env=env, input="", capture_output=True, text=True, encoding="utf-8", timeout=30,
    )


@pytest.mark.parametrize("cli_args", [["--version"], ["flutter", "smoke", "--tag", "synthetic-ok"]])
@pytest.mark.parametrize("failure", ["absent", "load_dependency", "factory_dependency", "factory_failure", "register_failure"])
def test_fresh_cli_keeps_stable_stdout_and_healthy_sibling_when_peer_fails(
    tmp_path: Path, cli_args: list[str], failure: str,
) -> None:
    baseline = _run_cli_subprocess(tmp_path, "healthy_registered", "absent", cli_args)
    assert baseline.returncode == 0, baseline.stderr
    result = _run_cli_subprocess(tmp_path, "healthy_registered", failure, cli_args)
    assert result.returncode == 0, result.stderr
    assert result.stdout == baseline.stdout
    assert "synthetic-exception-detail-not-a-status" not in result.stdout
    assert "Traceback" not in result.stdout
    if cli_args == ["--version"]:
        assert result.stdout.strip() != ""
    else:
        assert result.stdout == "flutter-smoke:synthetic-ok\n"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("mode", ["unregistered_noop", "bad_api_version"])
def test_negative_controls_reject_observe_only_or_incompatible_registration(tmp_path: Path, mode: str) -> None:
    result = _run_cli_subprocess(tmp_path, mode, "load_dependency", ["flutter", "smoke", "--tag", "synthetic-ok"])
    assert result.returncode == 2, result.stderr
    assert "No such command" in result.stderr
    assert "AssertionError" not in result.stderr
    assert result.stdout == ""
    assert list(tmp_path.iterdir()) == []
