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


def _rea_entry(load, *, distribution: str = "fxapk-rea", value: str = "fxapk_rea.plugin:plugin_factory"):
    return SimpleNamespace(
        name="rea",
        value=value,
        dist=SimpleNamespace(metadata={"Name": distribution}),
        load=load,
    )


def _set_rea_optin(monkeypatch, optin: str | None) -> None:
    if optin is None:
        monkeypatch.delenv("FXAPK_ENABLE_REA", raising=False)
    else:
        monkeypatch.setenv("FXAPK_ENABLE_REA", optin)


@pytest.mark.parametrize("optin", [None, "", "0", "false", "true", "yes", " 1 "])
def test_rea_disabled_unless_exact_opt_in(monkeypatch, optin: str | None) -> None:
    def fake_load():
        pytest.fail("disabled plugin imported")

    monkeypatch.setattr(registry, "_entry_points", lambda: [_rea_entry(fake_load)])
    _set_rea_optin(monkeypatch, optin)

    plugins, statuses = registry.discover_plugins()

    assert plugins == []
    assert statuses == [{"name": "rea", "status": "disabled", "reason": "rea_opt_in_required"}]


def test_rea_exact_opt_in_loads_stub_once(monkeypatch) -> None:
    calls: list[bool] = []
    plugin = SimpleNamespace(name="rea", api_version="1", register_cli=lambda app: None)

    def fake_load():
        calls.append(True)
        return lambda: plugin

    monkeypatch.setattr(registry, "_entry_points", lambda: [_rea_entry(fake_load)])
    monkeypatch.setenv("FXAPK_ENABLE_REA", "1")

    plugins, statuses = registry.discover_plugins()

    assert calls == [True]
    assert plugins == [plugin]
    assert statuses == [{"name": "rea", "status": "ok", "reason": ""}]


def test_enabled_rea_rejects_spoofed_distribution_without_load(monkeypatch) -> None:
    loaded: list[bool] = []

    def fake_load():
        loaded.append(True)
        return lambda: SimpleNamespace(name="rea", api_version="1", register_cli=lambda app: None)

    entry = _rea_entry(fake_load, distribution="unrelated-distribution")
    monkeypatch.setattr(registry, "_entry_points", lambda: [entry])
    monkeypatch.setenv("FXAPK_ENABLE_REA", "1")

    plugins, statuses = registry.discover_plugins()

    assert plugins == []
    assert loaded == []
    assert statuses == [{"name": "rea", "status": "unavailable", "reason": "plugin_distribution_untrusted"}]


@pytest.mark.parametrize("reverse", [False, True])
def test_enabled_rea_rejects_duplicate_entries_without_load(monkeypatch, reverse: bool) -> None:
    loaded: list[bool] = []

    def fake_load():
        loaded.append(True)
        return lambda: SimpleNamespace(name="rea", api_version="1", register_cli=lambda app: None)

    entries = [
        _rea_entry(fake_load),
        _rea_entry(fake_load, distribution="unrelated-distribution"),
    ]
    monkeypatch.setattr(registry, "_entry_points", lambda: list(reversed(entries)) if reverse else entries)
    monkeypatch.setenv("FXAPK_ENABLE_REA", "1")

    plugins, statuses = registry.discover_plugins()

    assert plugins == []
    assert loaded == []
    assert statuses == [{"name": "rea", "status": "unavailable", "reason": "duplicate_plugin_entry_point"}]


def test_disabled_rea_leaves_android_ui_loaded(monkeypatch) -> None:
    rea_loaded: list[bool] = []
    android_loaded: list[bool] = []

    def fake_load():
        rea_loaded.append(True)
        pytest.fail("disabled plugin imported")

    entries = [_trusted_entry(loaded=android_loaded), _rea_entry(fake_load)]
    monkeypatch.setattr(registry, "_entry_points", lambda: entries)
    monkeypatch.delenv("FXAPK_ENABLE_REA", raising=False)

    plugins, statuses = registry.discover_plugins()

    assert rea_loaded == []
    assert android_loaded == [True]
    assert [plugin.name for plugin in plugins] == ["android_ui"]
    assert statuses == [
        {"name": "android_ui", "status": "ok", "reason": ""},
        {"name": "rea", "status": "disabled", "reason": "rea_opt_in_required"},
    ]


@pytest.mark.parametrize("optin", [None, "1"])
def test_register_plugin_clis_and_web_supplement_share_rea_opt_in(monkeypatch, optin: str | None) -> None:
    import typer
    from typer.testing import CliRunner

    from apkscan.core.web_supplement import _plugin

    calls = {"load": 0, "register": 0, "run": 0}

    def register_cli(app: typer.Typer) -> None:
        calls["register"] += 1
        group = typer.Typer()

        @group.command("capabilities")
        def capabilities() -> None:
            return None

        app.add_typer(group, name="rea")

    plugin = SimpleNamespace(
        name="rea",
        api_version="1",
        register_cli=register_cli,
        run_supplement=lambda _payload: calls.__setitem__("run", calls["run"] + 1),
    )

    def fake_load():
        calls["load"] += 1
        return lambda: plugin

    monkeypatch.setattr(registry, "_entry_points", lambda: [_rea_entry(fake_load)])
    _set_rea_optin(monkeypatch, optin)

    app = typer.Typer(add_completion=False)

    @app.command("core")
    def core_command() -> None:
        return None

    registry.register_plugin_clis(app)
    runner = CliRunner()
    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    assert "core" in help_result.stdout
    rea_result = runner.invoke(app, ["rea", "capabilities"])
    if optin == "1":
        assert rea_result.exit_code == 0
        assert calls == {"load": 1, "register": 1, "run": 0}
    else:
        assert rea_result.exit_code == 2
        assert calls == {"load": 0, "register": 0, "run": 0}
        assert _plugin() == (None, "plugin_unavailable")
        assert calls == {"load": 0, "register": 0, "run": 0}
