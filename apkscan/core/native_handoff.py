"""Digest handoff for native address recovery. Core does not launch a provider."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from apkscan.core.infra import ADVICE_SKIP, classify_domain, classify_ip

_FINDINGS = frozenset(
    {
        "NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER",
        "NATIVE-OBFUSCATION-SUSPECTED",
        "NATIVE-CONFIG-CHANNEL",
    }
)
_CHECK = "fxapk rea native capabilities --provider ghidra --rea <rea.mjs> --node <node> --toolchain <local-toolchain.json>"
_COMMANDS = [
    "plugin formats: PE and ELF only; no Mach-O and no IPA slice extraction",
    "Windows Ghidra: x86/x64 native PE only. Do not extract an Android .so and inspect it with a Windows toolchain.",
    "fxapk rea native inspect <windows-x86_64.pe> --provider ghidra --operation function --query <name-or-address> --rea <rea.mjs> --node <node> --toolchain <local-toolchain.json> --out <new-dir>",
    "Linux/macOS ELF is structural only and the live Ghidra run is unverified: fxapk rea native extract <apk> --member lib/<abi>/<name>.so --out <new-dir>",
    "fxapk rea native inspect <linux-elf-binary.bin> --provider ghidra --operation address-to-file-offset --query <address> --rea <rea.mjs> --node <node> --toolchain <local-toolchain.json> --out <new-dir>",
    "fxapk rea native inspect <binary> --provider ghidra --operation read-bytes --query <address> --length <1-4096> --rea <rea.mjs> --node <node> --toolchain <local-toolchain.json> --out <new-dir>",
    _CHECK,
    "--toolchain node is unused; pass node with --node or the existing node field",
    "recipe replays declared file-offset bytes only; it does not break every static algorithm",
    "fxapk rea native recover <inspect-bundle> --recipe <recipe.json> --out <new-dir>",
    "fxapk rea native attach <recovery-bundle> --report <report.json> --out <new-dir>",
    "attach copies native recovery and web observation attachments; PCAP and other unmoved types stay at source_artifact_base",
]


def _url_host(value: str) -> str:
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return ""
    return host or ""


def _non_business_address(value: str) -> bool:
    """SDK hosts and private or non-routable addresses do not prove a business backend."""
    if classify_domain(value)[0] == ADVICE_SKIP:
        return True
    return classify_ip(value)[0] == ADVICE_SKIP


def _business_endpoint(item: object) -> bool:
    """External, batch, and SDK endpoints do not close a native addressing gap."""
    if not isinstance(item, dict):
        return False
    kind = str(item.get("kind", "")).lower()
    value = item.get("value")
    if kind not in {"domain", "ip", "url"} or not value or not isinstance(value, str):
        return False
    if kind == "url":
        host = _url_host(value)
        if not host or _non_business_address(host):
            return False
    elif kind == "domain" and _non_business_address(value):
        return False
    elif kind == "ip" and classify_ip(value)[0] == ADVICE_SKIP:
        return False
    refs = item.get("evidences")
    if not isinstance(refs, list) or not refs:
        refs = item.get("source_refs")
    if not isinstance(refs, list) or not refs:
        return True
    indirect = True
    for ref in refs:
        source = ""
        scope = ""
        if isinstance(ref, dict):
            source = str(ref.get("source") or "")
            scope = str(ref.get("scope") or "")
        else:
            source = str(getattr(ref, "source", "") or "")
            scope = str(getattr(ref, "scope", "") or "")
        folded = source.strip().casefold()
        if folded in {"external-web-observation", "sdk"} or scope.strip().casefold() == "batch_reference":
            continue
        indirect = False
    return not indirect


def project_native_handoff(report: object) -> dict[str, Any] | None:
    """Fixed command templates. Raw endpoint values are not placed in argv text."""
    if not isinstance(report, dict):
        return None
    raw_meta = report.get("meta")
    meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    reasons: list[str] = []
    findings = report.get("findings")
    if isinstance(findings, list):
        for item in findings:
            if isinstance(item, dict) and item.get("id") in _FINDINGS:
                reasons.append(str(item["id"]))
    if isinstance(meta.get("native_obfuscation"), dict):
        reasons.append("native_obfuscation")
    if isinstance(meta.get("native_config_channel"), dict):
        reasons.append("native_config_channel")
    hashes = meta.get("native_lib_hashes")
    hashed = isinstance(hashes, list) and any(
        isinstance(item, dict) and isinstance(item.get("sha256"), str) and len(item["sha256"]) == 64
        for item in hashes
    )
    raw_endpoints = report.get("endpoints")
    endpoints = raw_endpoints if isinstance(raw_endpoints, list) else []
    has_network = any(_business_endpoint(item) for item in endpoints)
    if isinstance(findings, list) and hashed and any(
        isinstance(item, dict) and item.get("id") == "DEX-STRING-POOL-OPAQUE" for item in findings
    ):
        reasons.append("dex_string_pool_opaque")
    if hashed and not has_network:
        reasons.append("native_hash_endpoint_gap")
    history = meta.get("native_recovery")
    candidates = 0
    if isinstance(history, list):
        candidates = sum(1 for item in history if isinstance(item, dict))
        if candidates:
            reasons.append("native_recovery_history")
    if not reasons:
        return None
    if candidates:
        stage = "awaiting_review"
    else:
        stage = "capabilities"
    return {
        "schema_version": "fxapk-native-handoff/1",
        "stage": stage,
        "reasons": reasons,
        "native_tool_missing": "not_probed",
        "native_tool_status": "not_probed",
        "check_command": _CHECK,
        "windows_ghidra_p0": "x86_x64_native_pe_only",
        "android_elf_on_windows": "unsupported",
        "linux_ghidra_elf_live_run": "unverified",
        "closure_evaluated": False,
        "relation_verified": False,
        "runtime_observed": False,
        "auto_execute": False,
        "web_only": False,
        "commands": list(_COMMANDS),
    }


_HISTORY_BOOLS = ("relation_verified", "runtime_observed", "closure_evaluated")
_HISTORY_LABEL = "analyst_reconstruction"


def align_native_history_item(item: dict[str, Any], result: dict[str, Any]) -> None:
    """Reject history flags that contradict a verified recovery result.

    Absent flags are filled only on this in-memory item, and only from a result
    whose own flags are already the canonical false reconstruction. The caller
    writes a new directory and does not rewrite the source report. Unknown
    fields on the item are left in place.
    """
    if not isinstance(result, dict):
        raise ValueError("result_mismatch")
    candidate = result.get("candidate")
    if not isinstance(candidate, dict):
        raise ValueError("result_mismatch")
    for key in _HISTORY_BOOLS:
        if result.get(key) is not False or candidate.get(key) is not False:
            raise ValueError("result_mismatch")
        if key not in item:
            item[key] = False
        elif item[key] is not False:
            raise ValueError("result_mismatch")
    if candidate.get("label") != _HISTORY_LABEL:
        raise ValueError("result_mismatch")
    if "label" in result and result.get("label") != _HISTORY_LABEL:
        raise ValueError("result_mismatch")
    if "label" not in item:
        item["label"] = _HISTORY_LABEL
    elif item.get("label") != _HISTORY_LABEL:
        raise ValueError("result_mismatch")


def _explicit_history_conflict(record: object) -> bool:
    """A present flag or label that is not the canonical reconstruction."""
    if not isinstance(record, dict):
        return False
    if any(key in record and record.get(key) is not False for key in _HISTORY_BOOLS):
        return True
    return "label" in record and record.get("label") != _HISTORY_LABEL


def _history_identity_conflict(item: dict[str, Any], result: object) -> bool:
    """Present result identity must match the history item. Absent fields stay absent."""
    if not isinstance(result, dict):
        return False
    return any(
        key in result and result.get(key) != item.get(key)
        for key in ("content_digest", "binary_sha256")
    )


def reconcile_native_history_item(item: dict[str, Any], result: object) -> None:
    """Apply canonical flag checks when the retained result is a verified receipt.

    A history copy that has no candidate receipt keeps absent flags absent.
    Present contradictory flags or labels on the result or its candidate are
    rejected even when the candidate is missing or not canonical. Present
    content or binary identity must match the history item.
    """
    if isinstance(result, dict):
        candidate = result.get("candidate")
        if (
            _explicit_history_conflict(result)
            or _explicit_history_conflict(candidate)
            or _history_identity_conflict(item, result)
        ):
            raise ValueError("result_mismatch")
        if isinstance(candidate, dict) and candidate.get("label") == _HISTORY_LABEL and all(
            result.get(key) is False and candidate.get(key) is False for key in _HISTORY_BOOLS
        ) and ("label" not in result or result.get("label") == _HISTORY_LABEL):
            align_native_history_item(item, result)
            return
    for key in _HISTORY_BOOLS:
        if isinstance(item, dict) and key in item and item[key] is not False:
            raise ValueError("result_mismatch")
    if isinstance(item, dict) and "label" in item and item.get("label") != _HISTORY_LABEL:
        raise ValueError("result_mismatch")
