from __future__ import annotations

from types import SimpleNamespace

import pytest

from apkscan.plugins import registry


def test_discovery_ignores_unlisted_entry_point(monkeypatch) -> None:
    entry = SimpleNamespace(name="unexpected", load=lambda: None)
    monkeypatch.setattr(registry, "_entry_points", lambda: [entry])

    plugins, statuses = registry.discover_plugins()

    assert plugins == []
    assert statuses == []


def test_discovery_isolates_bad_plugin(monkeypatch) -> None:
    def broken():
        raise RuntimeError("bad plugin")

    entry = SimpleNamespace(
        name="android_ui",
        value="fxapk_android_ui.plugin:plugin_factory",
        dist=SimpleNamespace(metadata={"Name": "fxapk-android-ui"}),
        load=lambda: broken,
    )
    monkeypatch.setattr(registry, "_entry_points", lambda: [entry])

    plugins, statuses = registry.discover_plugins()

    assert plugins == []
    assert statuses == [{"name": "android_ui", "status": "unavailable", "reason": "RuntimeError"}]


def _trusted_entry(*, distribution="fxapk-android-ui", value="fxapk_android_ui.plugin:plugin_factory", loaded=None):
    plugin = SimpleNamespace(name="android_ui", api_version="1", register_cli=lambda app: None)

    def load():
        if loaded is not None:
            loaded.append(True)
        return lambda: plugin

    return SimpleNamespace(
        name="android_ui", value=value,
        dist=SimpleNamespace(metadata={"Name": distribution}), load=load,
    )


@pytest.mark.parametrize(
    ("distribution", "value", "reason"),
    [
        ("unrelated-distribution", "fxapk_android_ui.plugin:plugin_factory", "plugin_distribution_untrusted"),
        ("fxapk-android-ui", "unrelated.module:factory", "plugin_entry_point_untrusted"),
    ],
)
def test_discovery_rejects_spoofed_plugin_before_import(monkeypatch, distribution, value, reason):
    loaded = []
    entry = _trusted_entry(distribution=distribution, value=value, loaded=loaded)
    monkeypatch.setattr(registry, "_entry_points", lambda: [entry])

    plugins, statuses = registry.discover_plugins()

    assert plugins == []
    assert loaded == []
    assert statuses == [{"name": "android_ui", "status": "unavailable", "reason": reason}]


@pytest.mark.parametrize("reverse", [False, True])
def test_discovery_rejects_duplicate_name_without_loading_either(monkeypatch, reverse):
    loaded = []
    entries = [_trusted_entry(loaded=loaded), _trusted_entry(distribution="unrelated-distribution", loaded=loaded)]
    monkeypatch.setattr(registry, "_entry_points", lambda: list(reversed(entries)) if reverse else entries)

    plugins, statuses = registry.discover_plugins()

    assert plugins == []
    assert loaded == []
    assert statuses == [{"name": "android_ui", "status": "unavailable", "reason": "duplicate_plugin_entry_point"}]


def test_discovery_accepts_exact_entry_from_normalized_trusted_distribution(monkeypatch):
    loaded = []
    entry = _trusted_entry(distribution="FxApk_Android_UI", loaded=loaded)
    monkeypatch.setattr(registry, "_entry_points", lambda: [entry])

    plugins, statuses = registry.discover_plugins()

    assert len(plugins) == 1
    assert loaded == [True]
    assert statuses == [{"name": "android_ui", "status": "ok", "reason": ""}]
