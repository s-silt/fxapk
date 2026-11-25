"""Check the offline CLI contract of installed fxapk wheels; does not build or publish.

Create a fresh venv for each mode. Pass the exact paths of the core and,
for registered mode, the three plugin wheels directly to pip (not package
names found through an index). For example, install from a local wheelhouse::

    /path/to/venv/bin/python -m pip install --no-index --find-links /path/to/wheelhouse CORE.whl UI.whl FLUTTER.whl REA.whl

Then run from outside the checkout with the same venv Python::

    /path/to/venv/bin/python -I /path/to/checkout/tools/release_plugin_smoke.py \
        --expect-version 2.0.6 registered

Use separate environments for "core" and "registered". The REA probe tests local
registration only; it never changes the CLI opt-in setting. This complements
dependency checks and the existing core release smoke.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from importlib.metadata import Distribution, EntryPoint, distribution, entry_points
from pathlib import Path

GROUP = "fxapk.plugins"
REGISTERED = {
    "android_ui": ("fxapk-android-ui", "fxapk_android_ui.plugin:plugin_factory"),
    "flutter": ("fxapk-flutter", "fxapk_flutter.plugin:plugin_factory"),
    "rea": ("fxapk-rea", "fxapk_rea.plugin:plugin_factory"),
}


class SmokeFailure(Exception):
    """A failed check, with a stable diagnostic independent of machine paths."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise SmokeFailure(code)


def validate_registry(entries: list[EntryPoint], mode: str) -> None:
    wanted = REGISTERED if mode == "registered" else {}
    require(
        len(entries) == len(wanted) and {entry.name for entry in entries} == set(wanted),
        "unexpected_plugin_entries",
    )
    for entry in entries:
        owner = entry.dist
        if owner is None:
            raise SmokeFailure("plugin_distribution_missing")
        name = re.sub(r"[-_.]+", "-", (owner.metadata["Name"] or "").lower())
        require((name, entry.value) == wanted[entry.name], "unexpected_plugin_target")
        require_local_wheel(owner)


def run_installed(argv: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    # Retain OS runtime settings, but not project flags, Python import paths or user config.
    env = {
        key: value for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "LANG", "LC_ALL"}
    }
    for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        env[key] = str(root)
    env.update(PYTHONUTF8="1", NO_COLOR="1")
    try:
        return subprocess.run(
            argv, cwd=root, env=env, capture_output=True,
            text=True, encoding="utf-8", timeout=30, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SmokeFailure("cli_timeout") from exc
    except (OSError, UnicodeError) as exc:
        raise SmokeFailure("cli_unavailable") from exc


def run_cli(args: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    exe = Path(sys.executable).parent / ("fxapk.exe" if os.name == "nt" else "fxapk")
    return run_installed([str(exe), *args], root)


_REA_PROBE = r"""
import sys

attempted = False

def audit(event, args):
    global attempted
    if event == "import" and args[0].split(".")[0] == "fxapk_rea":
        attempted = True

sys.addaudithook(audit)
sys.argv = ["fxapk", "rea", "--help"]
try:
    from fxapk.cli import main
    main()
finally:
    # importlib-based entry loaders may not fire the Python import audit event.
    if attempted or any(name.split(".")[0] == "fxapk_rea" for name in sys.modules):
        sys.stderr.write("rea_default_import_detected\n")
"""

def check_rea_default(root: Path) -> None:
    probe = run_installed([sys.executable, "-I", "-c", _REA_PROBE], root)
    require("rea_default_import_detected" not in probe.stderr, "rea_imported_by_default")
    require(probe.returncode == 2 and "No such command 'rea'" in probe.stderr, "rea_not_disabled")


# Test only local command registration, without turning on REA in the core CLI.
# A sentinel is added so Typer cannot flatten the REA group into a single command.
_REA_REGISTRATION = """
from contextlib import redirect_stderr, redirect_stdout
from importlib.metadata import entry_points
from io import StringIO
import sys

try:
    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        import typer
        from fxapk.plugins.contracts import PLUGIN_API_VERSION

        entry = entry_points(group="fxapk.plugins", name="rea")["rea"]
        plugin = entry.load()()
        if plugin.name != "rea" or plugin.api_version != PLUGIN_API_VERSION:
            raise ValueError("rea_plugin_contract")
        app = typer.Typer()
        @app.command()
        def sentinel():
            pass
        plugin.register_cli(app)
        command = typer.main.get_command(app)
        context = command.make_context("fxapk", ["rea", "--help"], resilient_parsing=True)
        group = command.get_command(context, "rea")
        if group is None or "attach" not in group.commands:
            raise ValueError("rea_commands_missing")
except Exception:
    sys.exit(1)
print("rea_registration_ok")
"""


def check_rea_registration(root: Path) -> None:
    proc = run_installed([sys.executable, "-I", "-c", _REA_REGISTRATION], root)
    require(proc.returncode == 0 and proc.stdout.strip() == "rea_registration_ok",
            "rea_registration_failed")


def flutter_check(root: Path, *, valid: bool) -> None:
    case = "flutter_valid" if valid else "flutter_invalid"
    fixture = root / f"{case}.json"
    fixture.write_text(
        json.dumps({"schema_version": "fxapk-flutter-toolchain/1", "entries": []} if valid else {}),
        encoding="utf-8",
    )
    proc = run_cli(["flutter", "capabilities", "--toolchain", str(fixture)], root)
    require(proc.returncode == (0 if valid else 1), case + "_exit")
    try:
        receipt = json.loads(proc.stdout)
    except ValueError as exc:
        raise SmokeFailure(case + "_receipt") from exc
    require(
        isinstance(receipt, dict)
        and receipt.get("status") == ("configured" if valid else "unavailable")
        and receipt.get("execution_verified") is False
        and ((type(receipt.get("entries")) is int and receipt["entries"] == 0) if valid
             else receipt.get("reason") == "invalid_toolchain"),
        case + "_receipt",
    )


def require_local_wheel(dist: Distribution) -> None:
    raw_origin = dist.read_text("direct_url.json")
    try:
        origin = json.loads(raw_origin) if raw_origin else None
    except ValueError as exc:
        raise SmokeFailure("local_wheel_required") from exc
    require(
        isinstance(origin, dict)
        and isinstance(origin.get("archive_info"), dict)
        and "dir_info" not in origin
        and isinstance(origin.get("url"), str)
        and origin["url"].startswith("file://")
        and origin["url"].endswith(".whl"),
        "local_wheel_required",
    )


def smoke(mode: str, expect_version: str, root: Path, checks: list[str]) -> None:
    require(bool(sys.flags.isolated) and sys.prefix != sys.base_prefix, "wheel_venv_required")
    core = distribution("fxapk")
    require_local_wheel(core)
    entries = list(entry_points(group=GROUP))
    validate_registry(entries, mode)
    checks.append("entry_point_inventory")
    ver = run_cli(["--version"], root)
    require(
        core.version == expect_version and ver.returncode == 0
        and ver.stdout.strip() == f"fxapk {expect_version}",
        "version",
    )
    checks.append("installed_version")
    if mode == "registered":
        for entry in entries:
            try:
                factory = entry.load()
            except Exception as exc:  # Third-party plugin boundary: never expose its traceback.
                raise SmokeFailure("plugin_load_failed") from exc
            require(callable(factory), "plugin_factory_not_callable")
        checks.append("entry_point_loading")
        ui = run_cli(["ui", "--help"], root)
        require(ui.returncode == 0 and "capabilities" in ui.stdout, "ui_help")
        checks.append("ui_help")
    check_rea_default(root)
    checks.append("rea_default_off")
    if mode == "registered":
        check_rea_registration(root)
        checks.append("rea_registration_offline")
        for valid in (True, False):
            flutter_check(root, valid=valid)
            checks.append("flutter_valid" if valid else "flutter_invalid")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["core", "registered"])
    parser.add_argument("--expect-version", required=True)
    ns = parser.parse_args(argv)
    checks: list[str] = []
    reason: str | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="fxapk-plugin-smoke-") as tmp:
            smoke(ns.mode, ns.expect_version, Path(tmp), checks)
    except SmokeFailure as exc:
        reason = str(exc)
    except (OSError, ImportError) as exc:
        reason = type(exc).__name__
    print(json.dumps({
        "schema": "fxapk-release-plugin-smoke/1",
        "mode": ns.mode,
        "expected_version": ns.expect_version,
        "status": "passed" if reason is None else "failed",
        "checks": checks,
        "reason": reason,
    }, sort_keys=True))
    return int(reason is not None)


if __name__ == "__main__":
    raise SystemExit(main())
