"""Optional plugin discovery with strict failure isolation."""
from __future__ import annotations

import importlib.metadata
import logging
import re
from collections import Counter
from collections.abc import Iterable
from typing import Any

from apkscan.plugins.contracts import PLUGIN_API_VERSION

logger = logging.getLogger(__name__)

_ENTRYPOINT_GROUP = "fxapk.plugins"
_ALLOWED = {
    "android_ui": ("fxapk-android-ui", "fxapk_android_ui.plugin:plugin_factory"),
}


def _entry_points() -> Iterable[importlib.metadata.EntryPoint]:
    discovered = importlib.metadata.entry_points()
    if hasattr(discovered, "select"):
        return discovered.select(group=_ENTRYPOINT_GROUP)
    return discovered.get(_ENTRYPOINT_GROUP, ())


def discover_plugins() -> tuple[list[Any], list[dict[str, str]]]:
    """Load known optional plugins without letting one affect core commands."""
    plugins: list[Any] = []
    statuses: list[dict[str, str]] = []
    try:
        entries = sorted(_entry_points(), key=lambda item: item.name)
    except Exception:
        logger.exception("[plugins] entry-point discovery failed")
        return [], [{"name": "plugins", "status": "unavailable", "reason": "discovery_failed"}]

    counts = Counter(entry.name for entry in entries if entry.name in _ALLOWED)
    seen: set[str] = set()
    for entry in entries:
        if entry.name not in _ALLOWED or entry.name in seen:
            continue
        seen.add(entry.name)
        if counts[entry.name] != 1:
            statuses.append({"name": entry.name, "status": "unavailable", "reason": "duplicate_plugin_entry_point"})
            continue
        try:
            distribution, expected_entry = _ALLOWED[entry.name]
            metadata = getattr(getattr(entry, "dist", None), "metadata", {})
            name = metadata.get("Name", "")
            normalized = re.sub(r"[-_.]+", "-", name).lower() if isinstance(name, str) else ""
            if normalized != distribution:
                statuses.append({"name": entry.name, "status": "unavailable", "reason": "plugin_distribution_untrusted"})
                continue
            if entry.value != expected_entry:
                statuses.append({"name": entry.name, "status": "unavailable", "reason": "plugin_entry_point_untrusted"})
                continue
            factory = entry.load()
            plugin = factory()
            if getattr(plugin, "name", "") != entry.name:
                raise ValueError("plugin_name_mismatch")
            if getattr(plugin, "api_version", "") != PLUGIN_API_VERSION:
                raise ValueError("plugin_api_version_unsupported")
            if not callable(getattr(plugin, "register_cli", None)):
                raise ValueError("plugin_register_cli_missing")
            plugins.append(plugin)
            statuses.append({"name": entry.name, "status": "ok", "reason": ""})
        except Exception as exc:  # noqa: BLE001 - external plugin must never break fxapk
            logger.exception("[plugins] failed loading %s", entry.name)
            statuses.append({"name": entry.name, "status": "unavailable", "reason": type(exc).__name__})
    return plugins, statuses


def register_plugin_clis(app: Any) -> list[dict[str, str]]:
    """Register optional command groups and return their discovery state."""
    plugins, statuses = discover_plugins()
    for plugin in plugins:
        try:
            plugin.register_cli(app)
        except Exception as exc:  # noqa: BLE001 - command registration is optional
            logger.exception("[plugins] failed registering CLI for %s", plugin.name)
            statuses = [
                {**status, "status": "unavailable", "reason": type(exc).__name__}
                if status["name"] == plugin.name else status
                for status in statuses
            ]
    return statuses
