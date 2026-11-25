"""Offline checks of the installed-wheel smoke test's failure contracts."""
from __future__ import annotations

import json
import subprocess
from importlib.metadata import Distribution, EntryPoint
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import release_plugin_smoke as smoke

# Independent literals: an accidental change in the checker must not update its fixtures.
ENTRIES = {
    "android_ui": ("fxapk-android-ui", "fxapk_android_ui.plugin:plugin_factory"),
    "flutter": ("fxapk-flutter", "fxapk_flutter.plugin:plugin_factory"),
    "rea": ("fxapk-rea", "fxapk_rea.plugin:plugin_factory"),
}


def entry(root: Path, name: str, owner: str, target: str, *, editable: bool = False) -> EntryPoint:
    info = root / f"{owner.replace('-', '_')}-1.0.dist-info"
    info.mkdir(exist_ok=True)
    (info / "METADATA").write_text(f"Name: {owner}\nVersion: 1.0\n", encoding="utf-8")
    (info / "entry_points.txt").write_text(f"[{smoke.GROUP}]\n{name} = {target}\n", encoding="utf-8")
    origin = {"url": "file:///synthetic/sample.whl", "archive_info": {}}
    if editable:
        origin = {"url": "file:///synthetic/source", "dir_info": {"editable": True}}
    (info / "direct_url.json").write_text(json.dumps(origin), encoding="utf-8")
    return Distribution.at(info).entry_points[name]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("missing", "unexpected_plugin_entries"),
        ("duplicate", "unexpected_plugin_entries"),
        ("owner", "unexpected_plugin_target"),
        ("target", "unexpected_plugin_target"),
        ("editable", "local_wheel_required"),
        ("extra_core", "unexpected_plugin_entries"),
    ],
)
def test_registry_rejects_wrong_install(tmp_path: Path, change: str, reason: str) -> None:
    entries = [
        entry(tmp_path, name, owner, target if change != "target" or name != "flutter" else "wrong:factory",
              editable=change == "editable" and name == "flutter")
        if change != "owner" or name != "flutter"
        else entry(tmp_path, name, "wrong-flutter", target)
        for name, (owner, target) in ENTRIES.items()
    ]
    if change == "missing":
        entries.pop()
    if change == "duplicate":
        entries[-1] = entries[0]
    with pytest.raises(smoke.SmokeFailure, match=f"^{reason}$"):
        smoke.validate_registry(entries, "core" if change == "extra_core" else "registered")


def test_registry_accepts_supported_modes(tmp_path: Path) -> None:
    smoke.validate_registry([], "core")
    smoke.validate_registry([
        entry(tmp_path, name, owner, target)
        for name, (owner, target) in ENTRIES.items()
    ], "registered")


@pytest.mark.parametrize("value", [False, "0", None])
def test_flutter_count_is_not_coerced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    payload = json.dumps({"status": "configured", "execution_verified": False, "entries": value})
    monkeypatch.setattr(smoke, "run_cli", lambda args, root: subprocess.CompletedProcess(args, 0, payload))
    with pytest.raises(smoke.SmokeFailure, match="flutter_valid_receipt"):
        smoke.flutter_check(tmp_path, valid=True)


@pytest.mark.parametrize("broken", [False, True])
def test_main_checks_installed_registry_and_sanitizes_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], broken: bool,
) -> None:
    entries = [entry(tmp_path, name, owner, target) for name, (owner, target) in ENTRIES.items()]
    monkeypatch.setattr(smoke, "entry_points", lambda *, group: entries if group == "fxapk.plugins" else [])
    monkeypatch.setattr(smoke, "distribution", lambda name: SimpleNamespace(version="2.0.6"))
    require_wheel = smoke.require_local_wheel
    monkeypatch.setattr(smoke, "require_local_wheel", lambda dist: (
        require_wheel(dist) if isinstance(dist, Distribution) else None
    ))
    monkeypatch.setattr(smoke, "sys", SimpleNamespace(flags=SimpleNamespace(isolated=1),
                     prefix="venv", base_prefix="base", executable="test-python"))
    monkeypatch.setattr(smoke, "flutter_check", lambda root, *, valid: None)

    def load(self: EntryPoint) -> object:
        if broken and self.name == "flutter":
            raise RuntimeError("synthetic private diagnostic")
        return lambda: None

    def run_cli(args: list[str], root: Path) -> subprocess.CompletedProcess[str]:
        stdout = "fxapk 2.0.6" if args == ["--version"] else "capabilities"
        return subprocess.CompletedProcess(args, 0, stdout, "")

    def run_installed(argv: list[str], root: Path) -> subprocess.CompletedProcess[str]:
        if "rea_registration_ok" in argv[-1]:
            return subprocess.CompletedProcess(argv, 0, "rea_registration_ok", "")
        return subprocess.CompletedProcess(argv, 2, "", "No such command 'rea'")

    monkeypatch.setattr(EntryPoint, "load", load)
    monkeypatch.setattr(smoke, "run_cli", run_cli)
    monkeypatch.setattr(smoke, "run_installed", run_installed)
    rc = smoke.main(["registered", "--expect-version", "2.0.6"])
    captured = capsys.readouterr()
    assert not captured.err
    assert "synthetic private diagnostic" not in captured.out
    receipt = json.loads(captured.out)
    assert rc == (1 if broken else 0)
    assert receipt["status"] == ("failed" if broken else "passed")
    assert receipt["reason"] == ("plugin_load_failed" if broken else None)
    if not broken:
        assert receipt["checks"] == [
            "entry_point_inventory", "installed_version", "entry_point_loading",
            "ui_help", "rea_default_off", "rea_registration_offline", "flutter_valid", "flutter_invalid",
        ]


def test_default_off_rejects_hidden_import(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def result(argv: list[str], root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 2, "", "No such command 'rea'\nrea_default_import_detected")

    monkeypatch.setattr(smoke, "run_installed", result)
    with pytest.raises(smoke.SmokeFailure, match="^rea_imported_by_default$"):
        smoke.check_rea_default(tmp_path)


def test_registration_failure_is_not_an_optional_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def result(argv: list[str], root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, "", "synthetic registration failure")

    monkeypatch.setattr(smoke, "run_installed", result)
    with pytest.raises(smoke.SmokeFailure, match="^rea_registration_failed$"):
        smoke.check_rea_registration(tmp_path)
