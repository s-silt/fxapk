"""Optional static Flutter stage. Core does not import the implementation package."""

from __future__ import annotations

import logging
from typing import Any

from apkscan.core.models import Endpoint
from apkscan.plugins.registry import discover_plugins

logger = logging.getLogger(__name__)

META_WRITE_OWNER = "core.flutter_analysis"
META_WRITE_CATEGORIES = {"flutter_analysis": "coverage"}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)


def run_flutter_stage(state: Any) -> None:
    mode = state.config.flutter
    if mode not in {"auto", "off", "required"}:
        raise ValueError("invalid_flutter_mode")
    if state.platform != "android":
        return
    framework = state.meta.get("app_framework", {})
    own = framework.get("own_code_libs", []) if isinstance(framework, dict) else []
    identified = isinstance(framework, dict) and framework.get("identified") and (framework.get("name") == "flutter" or "libapp.so" in own)
    if not identified and mode != "required":
        return
    metadata: dict[str, Any] = {"schema_version": "fxapk-flutter/1", "status": "skipped",
                                "reason": "disabled" if mode == "off" else "not_flutter", "runtime_observed": False}
    if identified and mode != "off":
        plugins, statuses = discover_plugins()
        plugin = next((p for p in plugins if p.name == "flutter"), None)
        if plugin is None:
            status = next((s for s in statuses if s["name"] == "flutter"), {})
            metadata.update(status="unavailable", reason=status.get("reason") or "plugin_not_installed")
        else:
            try:
                result = plugin.run_static({"apk": state.ctx.apk_path, "out_dir": state.config.out_dir,
                                            "toolchain": state.config.flutter_toolchain, "timeout": state.config.flutter_timeout})
                metadata = result["metadata"]
                endpoints = result["endpoints"]
                if not isinstance(metadata, dict) or metadata.get("status") not in {"ok", "failed", "partial", "unavailable"}:
                    raise ValueError("invalid_flutter_result")
                if not isinstance(endpoints, list) or not all(isinstance(e, Endpoint) for e in endpoints):
                    raise ValueError("invalid_flutter_endpoints")
                state.endpoints.extend(endpoints)
            except Exception as exc:  # noqa: BLE001 - optional plugin failure must preserve other analyzers
                logger.warning("Flutter plugin execution failed (%s)", type(exc).__name__)
                metadata = {"schema_version": "fxapk-flutter/1", "status": "failed", "reason": "plugin_execution_failed", "runtime_observed": False}
    state.meta["flutter_analysis"] = metadata
    if mode != "off":
        state.analyzer_status.append({"name": "flutter", "status": "ran" if metadata["status"] == "ok" else "error", "reason": metadata.get("reason", "")})
