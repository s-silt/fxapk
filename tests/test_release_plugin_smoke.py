"""Offline checks of the installed-wheel smoke test's failure contracts."""
from __future__ import annotations

import json
import subprocess
from importlib.metadata import Distribution, EntryPoint
from pathlib import Path

import pytest

from tools import release_plugin_smoke as smoke


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
        for name, (owner, target) in smoke.REGISTERED.items()
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
        for name, (owner, target) in smoke.REGISTERED.items()
    ], "registered")


@pytest.mark.parametrize("value", [False, "0", None])
def test_flutter_count_is_not_coerced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    payload = json.dumps({"status": "configured", "execution_verified": False, "entries": value})
    monkeypatch.setattr(smoke, "run_cli", lambda args, root: subprocess.CompletedProcess(args, 0, payload))
    with pytest.raises(smoke.SmokeFailure, match="flutter_valid_receipt"):
        smoke.flutter_check(tmp_path, valid=True)
