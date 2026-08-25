"""Canonical per-provider enrichment outcome contract.

New report-facing writers use ``provider -> {status, ...}`` entries.  Readers remain
compatible with the historical compact ``provider -> "status"`` ledger shape and
with the more detailed status words used by the local companion enrichers.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any

SOURCE_STATUS_HIT = "hit"
SOURCE_STATUS_NO_RECORD = "no_record"
SOURCE_STATUS_FAILED = "failed"
SOURCE_STATUS_SKIPPED = "skipped"
SOURCE_STATUS_DISABLED = "disabled"

SOURCE_STATUSES = frozenset(
    {
        SOURCE_STATUS_HIT,
        SOURCE_STATUS_NO_RECORD,
        SOURCE_STATUS_FAILED,
        SOURCE_STATUS_SKIPPED,
        SOURCE_STATUS_DISABLED,
    }
)
ANSWERED_SOURCE_STATUSES = frozenset({SOURCE_STATUS_HIT, SOURCE_STATUS_NO_RECORD})

_DETAILED_FAILURES = frozenset(
    {
        "timeout",
        "rate_limited",
        "quota_insufficient",
        "maintenance",
        "auth_failed",
        "provider_error",
    }
)
_SKIPPED_REASONS = {
    "not_applicable": "not_applicable",
    "skipped-budget": "budget_exhausted",
    "skipped_budget": "budget_exhausted",
    "budget_exhausted": "budget_exhausted",
}
_DISABLED_REASONS = {
    "disabled_by_default": "disabled_by_default",
    "credential_not_configured": "credential_not_configured",
}
_OPTIONAL_FIELDS = ("error_type", "reason")
_LEGACY_PROVIDER_KEYS = frozenset(
    {
        "abuseipdb",
        "asn",
        "censys",
        "certs",
        "dns",
        "fofa",
        "hunter",
        "icp",
        "ip_rdap",
        "otx",
        "quake",
        "rdap",
        "ripestat_bgp",
        "shodan",
        "spamhaus",
        "urlscan",
        "virustotal",
        "whois",
        "zoomeye",
    }
)
_MISSING = object()


def normalize_source_status(value: object) -> dict[str, Any]:
    """Return one canonical ``{status, ...}`` source outcome.

    Unknown or malformed values fail closed.  Granular local failure words remain
    available as ``error_type`` instead of becoming extra top-level status values.
    """

    metadata: dict[str, str] = {}
    raw_status: object = value
    if isinstance(value, Mapping):
        raw_status = value.get("status", value.get("_status"))
        for key in _OPTIONAL_FIELDS:
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                metadata[key] = item

    status = str(raw_status or "").strip()
    if status in SOURCE_STATUSES:
        return {"status": status, **metadata}
    if status in _DETAILED_FAILURES:
        metadata.setdefault("error_type", status)
        return {"status": SOURCE_STATUS_FAILED, **metadata}
    if status in _SKIPPED_REASONS:
        metadata.setdefault("reason", _SKIPPED_REASONS[status])
        return {"status": SOURCE_STATUS_SKIPPED, **metadata}
    if status in _DISABLED_REASONS:
        metadata.setdefault("reason", _DISABLED_REASONS[status])
        return {"status": SOURCE_STATUS_DISABLED, **metadata}

    metadata.setdefault("error_type", "invalid_status")
    if status:
        metadata.setdefault("reason", f"legacy_status:{status}")
    else:
        metadata.setdefault("reason", "missing_status")
    return {"status": SOURCE_STATUS_FAILED, **metadata}


def normalize_source_status_map(value: object) -> dict[str, dict[str, Any]]:
    """Normalize a provider-keyed status mapping in deterministic order."""

    if not isinstance(value, Mapping):
        return {}
    return {
        str(provider): normalize_source_status(item)
        for provider, item in sorted(value.items(), key=lambda pair: str(pair[0]))
    }


def _legacy_provider_status(payload: Mapping[object, object]) -> dict[str, Any]:
    """Infer one historical provider outcome without mutating its payload.

    This mirrors the pre-contract writer's observable rules solely for migrating
    reports that have no ``source_status`` key at all.  It is never used to fill
    a provider omitted from an explicit status map.
    """

    marker = payload.get("_source_status", _MISSING)
    if marker is _MISSING:
        marker = payload.get("_status", _MISSING)
    error_type = payload.get("_error_type")
    if marker is not _MISSING:
        if not isinstance(marker, str):
            return {"status": SOURCE_STATUS_FAILED, "error_type": "invalid_source_status"}
        legacy: dict[str, object] = {"status": marker}
        if isinstance(error_type, str) and error_type.strip():
            legacy["error_type"] = error_type.strip()
        return normalize_source_status(legacy)

    error = str(payload.get("error") or "")
    note = str(payload.get("note") or "")
    folded = f"{error} {note}".lower()
    if error:
        if any(token in folded for token in ("无记录", "无结果", "not found", "no record", "404")):
            return {"status": SOURCE_STATUS_NO_RECORD}
        return {
            "status": SOURCE_STATUS_FAILED,
            "error_type": error.split(":", 1)[0][:80] or "provider_error",
        }
    if not any(
        value not in (None, "", [], {})
        for key, value in payload.items()
        if key != "note" and not (isinstance(key, str) and key.startswith("_"))
    ):
        return {"status": SOURCE_STATUS_NO_RECORD}
    return {"status": SOURCE_STATUS_HIT}


def _legacy_source_status_map(value: Mapping[object, object]) -> dict[str, dict[str, Any]]:
    """Derive canonical outcomes for provider payloads in a status-less legacy node."""

    return {
        provider: _legacy_provider_status(payload)
        for provider in sorted(_LEGACY_PROVIDER_KEYS)
        if isinstance((payload := value.get(provider)), Mapping)
    }


def canonicalize_enrichment_source_status(enrichment: object) -> None:
    """Canonicalize one enrichment tree, including per-resolved-IP children."""

    canonicalize_source_status_tree(enrichment)


def canonicalize_source_status_tree(
    value: object, _seen: set[int] | None = None
) -> None:
    """Canonicalize every ``source_status`` mapping in a nested report tree.

    Closure projections live under ``meta`` rather than typed endpoints, so an
    endpoint-only traversal leaks legacy strings at public serialization
    boundaries.  The identity guard also makes this defensive for malformed
    in-memory trees containing cycles.
    """

    if not isinstance(value, (MutableMapping, list, tuple)):
        return
    seen = _seen if _seen is not None else set()
    identity = id(value)
    if identity in seen:
        return
    seen.add(identity)
    if isinstance(value, MutableMapping):
        if "source_status" not in value:
            legacy_statuses = _legacy_source_status_map(value)
            if legacy_statuses:
                value["source_status"] = legacy_statuses
        else:
            value["source_status"] = normalize_source_status_map(value.get("source_status"))
        for key, child in tuple(value.items()):
            if key != "source_status":
                canonicalize_source_status_tree(child, seen)
    else:
        for child in value:
            canonicalize_source_status_tree(child, seen)


def canonicalize_report_source_status(report: object) -> None:
    """Canonicalize every endpoint status tree on a typed report in place."""

    endpoints = getattr(report, "endpoints", ())
    if not isinstance(endpoints, (list, tuple)):
        return
    for endpoint in endpoints:
        canonicalize_enrichment_source_status(getattr(endpoint, "enrichment", None))
    canonicalize_source_status_tree(getattr(report, "meta", None))


def source_status_value(value: object) -> str:
    """Return the five-state status value from any supported historical shape."""

    return str(normalize_source_status(value)["status"])


def is_answered_source_status(value: object) -> bool:
    """Whether the provider supplied a positive result or an explicit no-record answer."""

    return source_status_value(value) in ANSWERED_SOURCE_STATUSES


def provider_payload_if_hit(enrichment: object, provider: str) -> dict[str, Any]:
    """Return a provider payload only when its outcome licenses positive data.

    A report with no ``source_status`` key at all predates the outcome contract,
    so its provider mappings remain readable.  Once the key exists it is
    authoritative: the map and provider entry must exist and normalize to
    ``hit``.  Failed, no-record, skipped, disabled, unknown, or malformed
    outcomes cannot make stale payload bytes look like fresh evidence.
    """

    if not isinstance(enrichment, Mapping):
        return {}
    payload = enrichment.get(provider)
    if not isinstance(payload, Mapping):
        return {}
    if "source_status" not in enrichment:
        if _legacy_provider_status(payload).get("status") != SOURCE_STATUS_HIT:
            return {}
        return {
            key: item
            for key, item in payload.items()
            if not (isinstance(key, str) and key.startswith("_"))
        }
    status_map = enrichment.get("source_status")
    if not isinstance(status_map, Mapping) or provider not in status_map:
        return {}
    if source_status_value(status_map.get(provider)) != SOURCE_STATUS_HIT:
        return {}
    return {
        key: item
        for key, item in payload.items()
        if not (isinstance(key, str) and key.startswith("_"))
    }
