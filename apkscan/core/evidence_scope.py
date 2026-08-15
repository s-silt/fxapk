"""Scope-aware projection helpers for raw ``report.json`` dictionaries.

Typed report loading applies the same safety rule through
``quarantine_reference_only_leads``.  Some deliberately lightweight outputs
consume JSON dictionaries directly, however, so they must not trust cached
``advice``/``is_c2``/runtime booleans that can outlive or contradict the
nested Evidence scopes.

The helpers in this module never mutate their input.  A batch reference or a
legacy/malformed scope remains visible as a reference, but cannot independently
be presented as current-case investigative evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from apkscan.core import infra
from apkscan.core.models import (
    ADVICE_INVESTIGATE,
    ADVICE_REVIEW,
    DOWNGRADE_EVIDENCE_SCOPE,
    OBSERVED_CONTACT_SOURCES,
    EvidenceScope,
)

EVIDENCE_SCOPE_DOWNGRADE_NOTE = (
    "仅由批量/跨案参考或旧版未声明作用域的材料支撑；可作复核线索，"
    "但不能单独作为当前案件调证或闭环依据"
)
_EMPTY_CLOSURE_GAP = "闭环声明为 complete，但未记录任何有效闭环目标"
_EMPTY_CLOSURE_ACTION = "重新执行 case close 生成非空目标并补当前案件直接证据"
_MISSING_CLOSURE_ACTION = (
    "为缺证目标补采 case_evidence（运行时或静态原始证据）后重新执行 case close"
)


def _scope(value: object) -> str:
    if isinstance(value, EvidenceScope):
        return value.value
    # Persisted enum values are exact protocol tokens.  Trimming here would
    # turn malformed ``" case_evidence "`` into direct evidence on raw-output
    # paths while typed loading correctly quarantines it.
    return value if isinstance(value, str) else ""


def serialized_case_evidence_refs(
    item: Mapping[str, object], field: str,
) -> list[dict[str, Any]]:
    """Return explicit current-case Evidence dictionaries from ``field``."""
    raw = item.get(field)
    if not isinstance(raw, list):
        return []
    return [
        dict(ref)
        for ref in raw
        if isinstance(ref, Mapping)
        and _scope(ref.get("scope")) == EvidenceScope.CASE_EVIDENCE.value
    ]


def serialized_has_case_evidence(item: Mapping[str, object], field: str) -> bool:
    """Whether ``item[field]`` contains at least one explicit direct Evidence."""
    return bool(serialized_case_evidence_refs(item, field))


def _network_key(kind: object, value: object) -> tuple[str, str] | None:
    # DOMAIN Leads and domain Endpoints intentionally differ only by case.
    # Whitespace is not part of either enum and must not be trimmed into a
    # valid decision key on raw-report paths.
    normalized_kind = kind.lower() if isinstance(kind, str) else ""
    if normalized_kind not in {"domain", "ip"}:
        return None
    try:
        return normalized_kind, infra.match_key(normalized_kind, str(value or ""))
    except (TypeError, ValueError):
        # Bad raw input must fail closed rather than crash an output command.
        return None


def serialized_lead_case_evidence_refs(
    report: Mapping[str, object], lead: Mapping[str, object]
) -> list[dict[str, Any]]:
    """Direct refs supporting a Lead, including a same-value network Endpoint.

    A Lead's own ``source_refs`` are authoritative for every category.  DOMAIN
    and IP leads may additionally inherit direct refs from an Endpoint with the
    same normalized ``(kind, value)``.  This mirrors the typed closure/lead
    qualification rule and preserves the valid case+batch scenario.
    """
    refs = serialized_case_evidence_refs(lead, "source_refs")
    wanted = _network_key(lead.get("category"), lead.get("value"))
    if wanted is None:
        return refs
    raw_endpoints = report.get("endpoints")
    if not isinstance(raw_endpoints, list):
        return refs
    seen = {
        (
            str(ref.get("source", "")),
            str(ref.get("location", "")),
            str(ref.get("snippet", "")),
            str(ref.get("scope", "")),
        )
        for ref in refs
    }
    for endpoint in raw_endpoints:
        if not isinstance(endpoint, Mapping):
            continue
        if _network_key(endpoint.get("kind"), endpoint.get("value")) != wanted:
            continue
        for ref in serialized_case_evidence_refs(endpoint, "evidences"):
            key = (
                str(ref.get("source", "")),
                str(ref.get("location", "")),
                str(ref.get("snippet", "")),
                str(ref.get("scope", "")),
            )
            if key not in seen:
                refs.append(ref)
                seen.add(key)
    return refs


def serialized_lead_has_case_evidence(
    report: Mapping[str, object], lead: Mapping[str, object]
) -> bool:
    """Whether a raw Lead has direct current-case support."""
    return bool(serialized_lead_case_evidence_refs(report, lead))


def project_serialized_lead(
    report: Mapping[str, object], lead: Mapping[str, object]
) -> dict[str, Any]:
    """Return a non-mutating, scope-qualified Lead projection for outputs."""
    projected: dict[str, Any] = dict(lead)
    direct_refs = serialized_lead_case_evidence_refs(report, lead)
    if direct_refs:
        # Decision outputs cite only the refs that licensed the decision.  In
        # the same-value Endpoint case this also carries the Endpoint evidence
        # into the projected Lead without touching the raw report.
        projected["source_refs"] = direct_refs
        sources = [str(ref.get("source", "")) for ref in direct_refs]
        projected["is_c2"] = (
            isinstance(projected.get("category"), str)
            and str(projected.get("category", "")).upper() in {"DOMAIN", "IP"}
            and projected.get("advice") == ADVICE_INVESTIGATE
        )
        projected["is_runtime_seen"] = any(source.startswith("runtime") for source in sources)
        projected["is_runtime_contact"] = any(
            source in OBSERVED_CONTACT_SOURCES for source in sources
        )
        return projected

    if projected.get("advice") == ADVICE_INVESTIGATE:
        projected["advice"] = ADVICE_REVIEW
    projected["is_c2"] = False
    projected["is_runtime_seen"] = False
    projected["is_runtime_contact"] = False
    raw_downgrades = projected.get("downgrades")
    downgrades = dict(raw_downgrades) if isinstance(raw_downgrades, Mapping) else {}
    downgrades[DOWNGRADE_EVIDENCE_SCOPE] = EVIDENCE_SCOPE_DOWNGRADE_NOTE
    projected["downgrades"] = downgrades
    return projected


def project_serialized_leads(report: object) -> list[dict[str, Any]]:
    """Project every well-formed Lead in a raw report without mutating it."""
    if not isinstance(report, Mapping):
        return []
    raw_leads = report.get("leads")
    if not isinstance(raw_leads, list):
        return []
    return [
        project_serialized_lead(report, lead)
        for lead in raw_leads
        if isinstance(lead, Mapping)
    ]


def _serialized_direct_network_keys(
    report: Mapping[str, object],
) -> set[tuple[str, str]]:
    """Return normalized network values supported by direct case evidence."""
    keys: set[tuple[str, str]] = set()
    raw_endpoints = report.get("endpoints")
    for endpoint in raw_endpoints if isinstance(raw_endpoints, list) else []:
        if not isinstance(endpoint, Mapping) or not serialized_has_case_evidence(
            endpoint, "evidences"
        ):
            continue
        key = _network_key(endpoint.get("kind"), endpoint.get("value"))
        if key is not None:
            keys.add(key)
    raw_leads = report.get("leads")
    for lead in raw_leads if isinstance(raw_leads, list) else []:
        if not isinstance(lead, Mapping) or not serialized_has_case_evidence(
            lead, "source_refs"
        ):
            continue
        key = _network_key(lead.get("category"), lead.get("value"))
        if key is not None:
            keys.add(key)
    return keys


def _append_unique_text(target: dict[str, Any], field: str, value: str) -> None:
    raw = target.get(field)
    items = [str(item) for item in raw] if isinstance(raw, list) else []
    if value not in items:
        items.append(value)
    target[field] = items


def project_serialized_closure(report: object) -> dict[str, Any]:
    """Return a non-mutating, scope-safe closure projection.

    Existing states are never upgraded.  A serialized ``complete`` claim is
    retained only when it carries a non-empty target inventory and every
    target has matching current-case evidence.  Missing inventory is a failed
    closure; partial target support is a partial closure.
    """
    if not isinstance(report, Mapping):
        return {}
    raw_meta = report.get("meta")
    raw_closure = raw_meta.get("closure") if isinstance(raw_meta, Mapping) else None
    if not isinstance(raw_closure, Mapping):
        return {}
    projected: dict[str, Any] = deepcopy(dict(raw_closure))
    raw_status = projected.get("status")
    if not isinstance(raw_status, str) or raw_status.strip() != "complete":
        return projected
    projected["status"] = "complete"

    raw_targets = projected.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        projected["status"] = "failed"
        _append_unique_text(projected, "gaps", _EMPTY_CLOSURE_GAP)
        _append_unique_text(projected, "next_actions", _EMPTY_CLOSURE_ACTION)
        return projected

    direct = _serialized_direct_network_keys(report)
    missing: list[str] = []
    for index, target in enumerate(raw_targets):
        if not isinstance(target, Mapping):
            missing.append(f"target[{index}]")
            continue
        key = _network_key(target.get("kind"), target.get("value"))
        if key is None:
            missing.append(f"target[{index}]")
            continue
        if key not in direct:
            missing.append(f"{key[0]}:{key[1]}")
    if missing:
        projected["status"] = "partial"
        _append_unique_text(
            projected,
            "gaps",
            "闭环目标缺少当前案件直接证据：" + ", ".join(missing),
        )
        _append_unique_text(projected, "next_actions", _MISSING_CLOSURE_ACTION)
    return projected


__all__ = [
    "EVIDENCE_SCOPE_DOWNGRADE_NOTE",
    "project_serialized_lead",
    "project_serialized_leads",
    "project_serialized_closure",
    "serialized_case_evidence_refs",
    "serialized_has_case_evidence",
    "serialized_lead_case_evidence_refs",
    "serialized_lead_has_case_evidence",
]
