"""Bounded host-side aggregation for bundled Frida observer coverage receipts."""

from __future__ import annotations

import importlib.resources
from typing import Any

FAMILIES = (
    "crypto",
    "jsbridge",
    "sensitive_api",
    "okhttp",
    "sqlcipher",
    "clipboard",
    "accessibility",
)
_OPTIONAL_FAMILIES = ("config_body", "config_consumer")
_HOOKS = {
    "config_body": frozenset({"body_bytes", "response", "events"}),
    "config_consumer": frozenset({"body_origin", "string_origin", "json_origin", "field_read", "socket_argument", "events"}),
    "crypto": frozenset(
        {"cipher_init", "cipher_final", "secret_key", "iv_spec", "mac_init", "webview_load_url", "events"}
    ),
    "jsbridge": frozenset({"add_interface", "dsbridge_call", "events"}),
    "sensitive_api": frozenset({"sensitive_api", "events"}),
    "okhttp": frozenset({"execute", "proceed", "events"}),
    "sqlcipher": frozenset({"cipher_open", "sqlite_open", "events"}),
    "clipboard": frozenset({"primary_clip", "get_text", "coerce_text", "events"}),
    "accessibility": frozenset(
        {"event_package", "node_package", "dispatch_gesture", "global_action", "screencapture", "events"}
    ),
}
_REGISTRATION_STATUSES = frozenset(
    {"installed", "unsupported", "partial", "installation_failed"}
)
_REASONS = frozenset(
    {"java_unavailable", "api_unavailable", "registration_failed"}
)
_STATUS_MESSAGES = 256


def load_bootstrap() -> str:
    resource = importlib.resources.files("apkscan.dynamic") / "frida_js" / "probe_coverage.js"
    return resource.read_bytes().decode("utf-8")


def new_probe_state(
    *,
    package: str,
    requested_hooks: tuple[str, ...] | None,
    frida_requested: bool,
    pass_tag: str | None,
    sample_sha256: str | None,
) -> dict[str, Any]:
    requested = list(FAMILIES if requested_hooks is None else requested_hooks)
    return {
        "schema_version": 1,
        "frida_requested": bool(frida_requested),
        "requested_package": package or None,
        "requested_package_source": "caller_requested" if package else "not_provided",
        "observed_pid": None,
        "observed_pid_source": "not_provided",
        "observed_uid": None,
        "observed_uid_source": "not_provided",
        "pass_tag": pass_tag or None,
        "pass_tag_source": "caller_declared" if pass_tag else "not_provided",
        "round": None,
        "round_source": "not_provided",
        "sample_sha256": sample_sha256 or None,
        "sample_sha256_source": "caller_declared" if sample_sha256 else "not_provided",
        "target_app_attribution_verified": False,
        "script_sha256": None,
        "script_sha256_source": "not_provided",
        "requested_hooks": requested,
        "java_bridge_ready": None,
        "families": {
            family: {
                "registration_status": (
                    "not_requested"
                    if not frida_requested or family not in requested
                    else "unknown"
                ),
                "triggered_hooks": [],
                "trigger_status": "unknown",
                "dropped_observation": False,
                "dropped_count_lower_bound": 0,
                "drop_count_semantics": "lower_bound",
                "truncation_known": False,
                "event_completeness": "not_attested",
                "reasons": [],
            }
            for family in (*FAMILIES, *(name for name in _OPTIONAL_FAMILIES if name in requested))
        },
        "status_messages_seen": 0,
    }


def record_status(state: dict[str, Any], payload: Any) -> None:
    if not isinstance(payload, dict) or payload.get("type") != "apkscan-probe-status":
        return
    seen = state.get("status_messages_seen", 0)
    if type(seen) is not int or seen >= _STATUS_MESSAGES:
        return
    state["status_messages_seen"] = seen + 1
    family, status = payload.get("family"), payload.get("status")
    if not isinstance(family, str) or not isinstance(status, str):
        return
    if family == "java_bridge":
        if status == "ready":
            state["java_bridge_ready"] = True
        elif status == "java_unavailable":
            state["java_bridge_ready"] = False
        return
    if family not in _HOOKS or family not in state["families"] or status not in {
        *_REGISTRATION_STATUSES,
        "triggered",
        "dropped",
        "truncated",
        "api_unavailable",
        "registration_failed",
    }:
        return
    family_state = state["families"][family]
    hook = payload.get("hook")
    if hook is not None and (not isinstance(hook, str) or hook not in _HOOKS[family]):
        return
    reason = payload.get("reason")
    if isinstance(reason, str) and reason in _REASONS and reason not in family_state["reasons"]:
        if len(family_state["reasons"]) < 128:
            family_state["reasons"].append(reason)
    if status in _REGISTRATION_STATUSES:
        family_state["registration_status"] = status
    elif status == "triggered" and hook is not None:
        if hook not in family_state["triggered_hooks"] and len(family_state["triggered_hooks"]) < 128:
            family_state["triggered_hooks"].append(hook)
    elif status == "dropped":
        family_state["dropped_observation"] = True
        if type(payload.get("dropped_count_lower_bound")) is int and payload.get(
            "dropped_count_lower_bound"
        ) == 1:
            family_state["dropped_count_lower_bound"] = max(
                1, family_state["dropped_count_lower_bound"]
            )
    elif status == "truncated":
        family_state["truncation_known"] = True
        family_state["event_completeness"] = "not_attested"


def note_sink_drop(state: dict[str, Any], family: str, events: list[dict[str, Any]]) -> None:
    if family not in _HOOKS or family not in state["families"]:
        return
    if any(isinstance(event, dict) and event.get("_capped") for event in events):
        family_state = state["families"][family]
        family_state["dropped_observation"] = True
        family_state["dropped_count_lower_bound"] = max(
            1, family_state["dropped_count_lower_bound"]
        )


def finalize_probe_state(
    state: dict[str, Any], *, observed_pid: int | None, observed_uid: int | None
) -> dict[str, Any]:
    state["observed_pid"] = observed_pid
    state["observed_uid"] = observed_uid
    state["observed_pid_source"] = "frida_spawn" if observed_pid is not None else "not_provided"
    state["observed_uid_source"] = (
        "floor_pcap_attribution" if observed_uid is not None else "not_provided"
    )
    requested = state.get("requested_hooks", [])
    installed: list[str] = []
    for family in state["families"]:
        item = state["families"][family]
        if family not in requested:
            item["registration_status"] = "not_requested"
            item["trigger_status"] = "unknown"
            continue
        if item["registration_status"] == "installed":
            installed.append(family)
            item["trigger_status"] = (
                "observed" if item["triggered_hooks"] else "installed_no_observation"
            )
        else:
            item["trigger_status"] = "observed" if item["triggered_hooks"] else "unknown"
    coverage = {
        key: value
        for key, value in state.items()
        if key not in {"families", "status_messages_seen"}
    }
    coverage["installed_hooks"] = installed
    coverage["families"] = state["families"]
    return coverage
