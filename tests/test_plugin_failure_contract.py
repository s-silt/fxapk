"""Synthetic optional-plugin failures remain distinct without blocking healthy peers."""
from __future__ import annotations

from collections.abc import Callable
import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from fxapk import selfcheck
from fxapk.plugins import registry


@pytest.mark.parametrize("consumer", ["discovery", "registration", "selfcheck"])
@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        ("absent", None),
        ("load_dependency", "ModuleNotFoundError"),
        ("factory_dependency", "ModuleNotFoundError"),
        ("factory_failure", "RuntimeError"),
    ],
)
def test_optional_plugin_failure_contract(monkeypatch: pytest.MonkeyPatch, consumer: str, failure: str, reason: str | None) -> None:
    calls = {"load": 0, "factory": 0, "healthy_register": 0}
    marker = "synthetic-exception-detail-not-a-status"

    def healthy_register(_app: object) -> None:
        calls["healthy_register"] += 1

    healthy = SimpleNamespace(name="flutter", api_version="1", register_cli=healthy_register)

    def broken_factory() -> None:
        calls["factory"] += 1
        if failure == "factory_dependency":
            raise ModuleNotFoundError(marker)
        raise RuntimeError(marker)

    def broken_load() -> Callable[[], None]:
        calls["load"] += 1
        if failure == "load_dependency":
            raise ModuleNotFoundError(marker)
        return broken_factory

    entries = [SimpleNamespace(
        name="flutter", value="fxapk_flutter.plugin:plugin_factory",
        dist=SimpleNamespace(metadata={"Name": "fxapk-flutter"}), load=lambda: lambda: healthy,
    )]
    if failure != "absent":
        entries.append(SimpleNamespace(
            name="android_ui", value="fxapk_android_ui.plugin:plugin_factory",
            dist=SimpleNamespace(metadata={"Name": "fxapk-android-ui"}), load=broken_load,
        ))
    monkeypatch.setattr(registry, "_entry_points", lambda: entries)

    if consumer == "selfcheck":
        # Only the plugin diagnostic wiring is real; no tool, credential or network probes.
        core_registry = ModuleType("fxapk.core.registry")
        monkeypatch.setattr(core_registry, "detect_capabilities", lambda **_kwargs: set(), raising=False)
        monkeypatch.setitem(sys.modules, "fxapk.core.registry", core_registry)
        monkeypatch.setattr(selfcheck, "build_version_component", lambda: {
            "name": "version", "category": "core", "status": "ok", "detail": "synthetic", "fix": "",
        })
        monkeypatch.setattr(selfcheck, "build_credential_components", lambda: [])
        monkeypatch.setattr(selfcheck, "_OPTIONAL_DEPS", ())
        result = selfcheck.run_selfcheck(online=False, probe_network=False)
        statuses = [
            {"name": c["name"].removeprefix("plugin:"), "status": c["status"],
             "reason": "" if c["status"] == "ok" else c["detail"]}
            for c in result["components"] if c["category"] == "plugin"
        ]
        assert result["summary"].get("unavailable", 0) == (reason is not None)
    elif consumer == "registration":
        statuses = registry.register_plugin_clis(object())
    else:
        plugins, statuses = registry.discover_plugins()
        assert plugins == [healthy]

    expected = [{"name": "flutter", "status": "ok", "reason": ""}]
    if reason is not None:
        expected.insert(0, {"name": "android_ui", "status": "unavailable", "reason": reason})
    assert statuses == expected
    # Exception class is structured output; it does not identify which phase failed.
    assert marker not in json.dumps(statuses)
    assert calls == {
        "load": int(failure != "absent"),
        "factory": int(failure.startswith("factory_")),
        "healthy_register": int(consumer == "registration"),
    }
