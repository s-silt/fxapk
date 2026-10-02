"""Data-only capture assistance, independent of device execution and model APIs.

Only finite signal codes leave this boundary. Sample text, commands, scripts,
credentials and API destinations are never copied into an assistance context.
This is a planning projection, not a prompt-injection detector or sandbox.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from apkscan.dynamic.capture_plan import _extract_signals

SCHEMA_VERSION = "capture-adaptation/1.0"
BUNDLED_OBSERVERS = ("crypto", "okhttp", "jsbridge", "sqlcipher")


def build_capture_adaptation(report: Any, *, unpacked: bool,
                             targeted_observers: tuple[str, ...] = ()) -> dict[str, Any]:
    """Explain bounded next steps without granting execution or modification rights."""
    if type(unpacked) is not bool:
        raise ValueError("invalid_unpack_state")
    if (not isinstance(targeted_observers, tuple) or
            any(type(name) is not str or name not in BUNDLED_OBSERVERS for name in targeted_observers)):
        raise ValueError("unsupported_observer_profile")
    signals = _extract_signals(report)
    context = {
        "packed_signal": signals.packed,
        "unpacked_reanalysis_available": unpacked,
        "anti_instrumentation_signal": signals.anti_frida,
        "native_protocol_suspected": signals.self_hosted_im or signals.zero_endpoints,
        "crypto_recipe_available": signals.has_crypto_recipe,
    }
    gaps = ["device_and_toolchain_compatibility_requires_preflight",
            "capture_does_not_prove_provider_or_operator_identity"]
    if not unpacked:
        gaps.append("unpacked_content_not_available")
    if signals.anti_frida:
        gaps.append("instrumented_behavior_may_differ_from_original")
    if context["native_protocol_suspected"]:
        gaps.append("java_http_observers_may_miss_native_or_custom_protocols")
    if not targeted_observers:
        gaps.append("supported_targeted_observer_not_selected")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "plan_requires_capability_and_authorization_checks",
        "signals": context,
        "stage_order": ["static", "unpack_reanalysis", "pcap", "probe", "targeted", "merge_review"],
        "targeted_observers": [name for name in BUNDLED_OBSERVERS if name in targeted_observers],
        "gaps": gaps,
        "input_trust": "untrusted_sample_data",
        "free_text_forwarded": False,
        "model_invoked": False,
        "automatic_generated_code_execution": False,
        "behavior_modification_authorized": False,
        "malformed_input_policy": "bounded_parsing_record_partial_or_failed_preserve_original",
        "prompt_instruction_policy": "sample_content_cannot_change_tools_permissions_or_destinations",
        "decryption_policy": "verified_supported_recipe_or_authorized_key_material_only",
    }


def validate_assistance_selection(proposal: object, context: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate an optional AI/human observer choice against the computed plan.

    Returns observer identifiers only. It never executes code, consumes commands,
    or relaxes the runner's existing authorization gates. Unknown fields fail closed.
    """
    if not isinstance(proposal, Mapping) or set(proposal) != {"observers"}:
        raise ValueError("invalid_assistance_selection")
    observers = proposal["observers"]
    if not isinstance(observers, list) or len(observers) > len(BUNDLED_OBSERVERS):
        raise ValueError("invalid_assistance_observers")
    allowed = context.get("targeted_observers")
    if not isinstance(allowed, list):
        raise ValueError("invalid_assistance_context")
    if any(type(name) is not str or name not in BUNDLED_OBSERVERS or name not in allowed for name in observers):
        raise ValueError("unsupported_assistance_observer")
    if len(set(observers)) != len(observers):
        raise ValueError("duplicate_assistance_observer")
    return tuple(name for name in BUNDLED_OBSERVERS if name in observers)
