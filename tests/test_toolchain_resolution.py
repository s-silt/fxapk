"""Regression coverage for mixed host/venv versions and stale explicit tool paths."""
import json
import os
from pathlib import Path

import pytest

from apkscan.core import tools
from apkscan.dynamic import tshark_backend


def configure(monkeypatch, tmp_path, data):
    config = tmp_path / "tools.json"
    config.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(tools, "_toolchain_file", lambda: config)
    return config


def test_current_environment_beats_system_path(monkeypatch, tmp_path):
    local = tmp_path / ("frida.exe" if os.name == "nt" else "frida")
    local.write_bytes(b"placeholder")
    local.chmod(0o755)
    monkeypatch.setattr(tools, "_python_scripts_dir", lambda: tmp_path)
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/system/frida")
    assert tools.frida_invocation("frida") == [str(local)]
    assert tools.has_frida()


@pytest.mark.parametrize("name", ["frida", "frida-dexdump", "mitmdump"])
def test_missing_local_script_preserves_path_fallback(monkeypatch, name):
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/system/tool")
    assert tools.frida_invocation(name) == ["/system/tool"]


@pytest.mark.real_adb_path
def test_native_and_python_explicit_paths_are_used(monkeypatch, tmp_path):
    native = str(tmp_path / "native.exe")
    configure(monkeypatch, tmp_path, {"schema": 1, "tools": dict.fromkeys(
        ["adb", "jadx", "frida", "tshark"], native
    )})
    monkeypatch.setattr(tools.shutil, "which", lambda name: native if name == native else "/stale/tool")
    assert tools.adb_path() == native
    assert tools.resolve_jadx() == ([native], {})
    assert tools.frida_invocation("frida") == [native]
    assert tshark_backend.has_tshark()
    assert tools.executable_path("tshark") == native


@pytest.mark.parametrize("data", [
    {"schema": 1, "tools": {"jadx": "relative/tool"}},
    {"schema": 1, "tools": {"jadx": []}},
    {"schema": 2, "tools": {}},
    {"schema": 1, "tools": []},
    [],
])
def test_invalid_config_never_uses_stale_path_or_addon(monkeypatch, tmp_path, data):
    configure(monkeypatch, tmp_path, data)
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/stale/jadx")
    monkeypatch.setattr(tools, "jadx_addon_dir", lambda: pytest.fail("unexpected addon fallback"))
    assert tools.resolve_jadx() is None


def test_missing_configured_binary_does_not_fall_back(monkeypatch, tmp_path):
    selected = str(tmp_path / "missing.exe")
    configure(monkeypatch, tmp_path, {"schema": 1, "tools": {"frida": selected}})
    monkeypatch.setattr(tools.shutil, "which", lambda name: None if name == selected else "/stale/frida")
    assert not tools.frida_invocation("frida")
    assert not tools.has_frida()


def test_malformed_config_and_missing_explicit_file_fail_closed(monkeypatch, tmp_path):
    config = configure(monkeypatch, tmp_path, {})
    config.write_text("{invalid", encoding="utf-8")
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/stale/tool")
    assert tools.executable_path("tshark") == ""
    config.unlink()
    monkeypatch.setenv("FXAPK_TOOLCHAIN_FILE", str(config))
    assert tools.executable_path("tshark") == ""


def test_config_override_location(monkeypatch, tmp_path):
    # Test the real location function, which the suite normally isolates.
    import importlib.util
    spec = importlib.util.spec_from_file_location("toolchain_location_test", Path(tools.__file__))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    selected = tmp_path / "selection.json"
    monkeypatch.setenv("FXAPK_TOOLCHAIN_FILE", str(selected))
    assert module._toolchain_file() == selected


def test_doctor_and_backend_share_tshark_selection(monkeypatch):
    from apkscan.dynamic import doctor
    monkeypatch.setattr(tools, "executable_path", lambda _: "")
    assert not tshark_backend.has_tshark()
    item = next(x for x in doctor._check_pcap_capabilities() if x["name"] == doctor._NAME_TSHARK)
    assert not item["ok"]


def test_default_config_directory_fails_closed(monkeypatch, tmp_path):
    config = tmp_path / "fxapk-tools.json"
    config.mkdir()
    monkeypatch.setattr(tools, "_toolchain_file", lambda: config)
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/stale/tool")
    assert tools.executable_path("tshark") == ""


@pytest.mark.parametrize("schema", [True, "1", 1.0])
def test_schema_requires_integer_one(monkeypatch, tmp_path, schema):
    configure(monkeypatch, tmp_path, {"schema": schema, "tools": {}})
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/stale/tool")
    assert tools.executable_path("tshark") == ""


def test_relative_config_override_fails_closed(monkeypatch, tmp_path, caplog):
    configure(monkeypatch, tmp_path, {"schema": 1, "tools": {}})
    monkeypatch.setenv("FXAPK_TOOLCHAIN_FILE", "tools.json")
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/stale/tool")
    assert tools.executable_path("tshark") == ""
    assert "Invalid toolchain selection" in caplog.text


def test_explicit_config_beats_valid_local_script(monkeypatch, tmp_path):
    local = tmp_path / ("frida.exe" if os.name == "nt" else "frida")
    local.write_bytes(b"placeholder")
    local.chmod(0o755)
    selected = str(tmp_path / "configured-frida.exe")
    configure(monkeypatch, tmp_path, {"schema": 1, "tools": {"frida": selected}})
    monkeypatch.setattr(tools, "_python_scripts_dir", lambda: tmp_path)
    monkeypatch.setattr(tools.shutil, "which", lambda name: selected if name == selected else "/stale/tool")
    assert tools.executable_path("frida") == selected


@pytest.mark.parametrize("on_path", ["/system/frida", None])
def test_frozen_ignores_config_and_scripts(monkeypatch, on_path):
    monkeypatch.setattr(tools, "frozen", lambda: True)
    monkeypatch.setattr(tools, "_toolchain_file", lambda: pytest.fail("unexpected config read"))
    monkeypatch.setattr(tools, "_python_scripts_dir", lambda: pytest.fail("unexpected scripts lookup"))
    monkeypatch.setattr(tools.shutil, "which", lambda _: on_path)
    assert tools.executable_path("frida") == (on_path or "")


def test_oversized_config_fails_closed(monkeypatch, tmp_path):
    config = configure(monkeypatch, tmp_path, {"schema": 1, "tools": {}})
    config.write_text(config.read_text(encoding="utf-8").ljust(65537), encoding="utf-8")
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/stale/tool")
    assert tools.executable_path("tshark") == ""
