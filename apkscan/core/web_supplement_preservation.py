"""Shared evidence union and cumulative web-supplement projection.

Attempts are immutable inputs. The canonical ``web_supplement`` value is only a
projection over those attempts, so a later failure cannot drop an earlier hash,
path, relation, or count.
"""

from __future__ import annotations

import copy
import ipaddress
import json
from typing import Any
from urllib.parse import urlsplit

from apkscan.core.infra import match_key
from apkscan.core.models import (
    SUPERSEDED_EVIDENCE_SOURCES,
    EvidenceScope,
    Lead,
    LeadCategory,
)

META_WRITE_OWNER = "core.web_supplement_preservation"
META_WRITE_CATEGORIES = {
    "web_supplement": "coverage",
}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)

_ATTEMPT_DROP = frozenset({"attempts", "latest_status", "latest_reason"})
_COUNT_KEYS = ("endpoints", "config_leads", "relations", "scripts")


def _field(evidence: object, name: str, default: object = "") -> object:
    if isinstance(evidence, dict):
        return evidence.get(name, default)
    return getattr(evidence, name, default)


def evidence_key(evidence: object) -> tuple[str, str, str, str, object]:
    """Identity is source, location, snippet, scope, and observed_at."""
    scope = _field(evidence, "scope", "")
    if isinstance(scope, EvidenceScope):
        scope_text = scope.value
    else:
        scope_text = str(scope or "")
    return (
        str(_field(evidence, "source", "")),
        str(_field(evidence, "location", "")),
        str(_field(evidence, "snippet", "")),
        scope_text,
        _field(evidence, "observed_at", None),
    )


def union_evidence(existing: list[Any], incoming: list[Any]) -> None:
    """Append unseen evidence after revoking superseded observations.

    Supersession is decided on the combined multiset, so one incoming batch can
    drop a stale row that arrives beside its replacement. ``incoming`` itself is
    not rewritten.
    """
    incoming_rows = list(incoming)
    blocked: dict[tuple[str, str, str], set[str]] = {}
    for item in [*existing, *incoming_rows]:
        source = str(_field(item, "source", ""))
        identity = evidence_key(item)[1:4]
        for newer, older in SUPERSEDED_EVIDENCE_SOURCES.items():
            if source == newer:
                blocked.setdefault(identity, set()).update(older)

    def _current(item: Any) -> bool:
        source = str(_field(item, "source", ""))
        return source not in blocked.get(evidence_key(item)[1:4], set())

    kept = [item for item in existing if _current(item)]
    seen = {evidence_key(item) for item in kept}
    staged: list[Any] = []
    for item in incoming_rows:
        if not _current(item):
            continue
        key = evidence_key(item)
        if key in seen:
            continue
        seen.add(key)
        staged.append(item)
    existing[:] = kept
    existing.extend(staged)


def union_text(existing: list[str], incoming: list[str]) -> None:
    seen = {item for item in existing if isinstance(item, str)}
    staged: list[str] = []
    for item in incoming:
        if isinstance(item, str) and item not in seen:
            seen.add(item)
            staged.append(item)
    existing.extend(staged)


def _lead_match_keys(category: LeadCategory, value: str) -> set[tuple[str, str]]:
    label = category.value
    return {(label, match_key(label, value))}


def _endpoint_match_keys(kind: str, value: str) -> set[tuple[str, str]]:
    """Pair DOMAIN/IP leads with the same host, including a URL-only endpoint."""
    normalized = kind.strip().lower()
    if normalized == "domain":
        return {("DOMAIN", match_key("DOMAIN", value))}
    if normalized == "ip":
        return {("IP", match_key("IP", value))}
    if normalized != "url":
        return set()
    keys = {("DOMAIN", match_key("DOMAIN", value))}
    host = urlsplit(value if "://" in value else f"//{value}").hostname or ""
    if not host:
        return keys
    try:
        ipaddress.ip_address(host)
    except ValueError:
        keys.add(("DOMAIN", match_key("DOMAIN", host)))
    else:
        keys.add(("IP", match_key("IP", host)))
    return keys


def sync_domain_leads(endpoints: list[Any], leads: list[Lead]) -> None:
    """Copy endpoint evidence onto an existing DOMAIN or IP lead with the same host.

    Advice and confidence stay on the lead. Evidence objects keep their own scope.
    """
    matched: dict[tuple[str, str], list[Lead]] = {}
    for lead in leads:
        if lead.category not in (LeadCategory.DOMAIN, LeadCategory.IP):
            continue
        if not isinstance(lead.value, str):
            continue
        for key in _lead_match_keys(lead.category, lead.value):
            matched.setdefault(key, []).append(lead)
    for endpoint in endpoints:
        kind = str(getattr(endpoint, "kind", "") or "")
        value = getattr(endpoint, "value", None)
        if not isinstance(value, str):
            continue
        evidences = list(getattr(endpoint, "evidences", []) or [])
        targets: list[Lead] = []
        seen: set[int] = set()
        for key in _endpoint_match_keys(kind, value):
            for lead in matched.get(key, []):
                if id(lead) in seen:
                    continue
                seen.add(id(lead))
                targets.append(lead)
        for lead in targets:
            union_evidence(lead.source_refs, evidences)


def _strip_attempt(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in record.items()
        if key not in _ATTEMPT_DROP
    }


def _fingerprint(record: dict[str, Any]) -> str:
    return json.dumps(_strip_attempt(record), ensure_ascii=False, sort_keys=True, default=str)


def load_attempts(meta: dict[str, Any]) -> list[dict[str, Any]]:
    """Return stored attempts. A legacy canonical record is migrated once.

    A projection is never appended as another attempt.
    """
    current = meta.get("web_supplement")
    if not isinstance(current, dict):
        return []
    attempts = current.get("attempts")
    if isinstance(attempts, list):
        return [copy.deepcopy(item) for item in attempts if isinstance(item, dict)]
    if "status" in current:
        return [_strip_attempt(current)]
    return []


def _hashes(attempt: dict[str, Any]) -> list[str]:
    raw = attempt.get("raw_sha256")
    found: list[str] = []
    if isinstance(raw, str) and raw:
        found.append(raw)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and item and item not in found:
                found.append(item)
    return found


def _paths(attempt: dict[str, Any]) -> list[str]:
    found: list[str] = []
    raw = attempt.get("relative_paths")
    if isinstance(raw, list):
        found.extend(item for item in raw if isinstance(item, str) and item)
    published = attempt.get("published_path")
    if isinstance(published, str) and published:
        found.append(published)
    return found


def _relations(attempt: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("relations", "relation_records"):
        raw = attempt.get(key)
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
    return []


def project_attempts(attempts: list[dict[str, Any]], *, round_id: str) -> dict[str, Any]:
    """Deterministic cumulative projection. Counts the first success per raw hash."""
    from apkscan.core.web_supplement import _record

    totals = {key: 0 for key in _COUNT_KEYS}
    hashes: list[str] = []
    paths: list[str] = []
    relations: list[dict[str, Any]] = []
    seen_relations: set[str] = set()
    counted: set[str] = set()
    status = "failed"
    reason = "parse_failed"
    provider = ""
    live = False
    coverage: dict[str, Any] = {}
    for attempt in attempts:
        item_status = str(attempt.get("status") or "")
        item_reason = str(attempt.get("reason") or "")
        if item_status == "executed":
            status, reason = "executed", "executed"
        elif status != "executed" and item_status:
            status, reason = item_status, item_reason or reason
        provider = str(attempt.get("provider") or provider)
        boundary = attempt.get("boundary")
        if isinstance(boundary, dict):
            live = live or boundary.get("live_cdp") is True
        live = live or attempt.get("live_cdp") is True
        from apkscan.core.web_observation_plan import clean_coverage

        coverage = clean_coverage(attempt.get("coverage")) if "coverage" in attempt else {}
        for rel in _relations(attempt):
            token = json.dumps(rel, ensure_ascii=False, sort_keys=True, default=str)
            if token not in seen_relations:
                seen_relations.add(token)
                relations.append(rel)
        for path in _paths(attempt):
            if path not in paths:
                paths.append(path)
        if item_status != "executed" or item_reason == "duplicate_raw":
            continue
        fresh = [item for item in _hashes(attempt) if item not in counted]
        if _hashes(attempt) and not fresh:
            continue
        counted.update(fresh)
        for item in fresh:
            hashes.append(item)
        raw_counts = attempt.get("parse_counts")
        counts = raw_counts if isinstance(raw_counts, dict) else {}
        for key in _COUNT_KEYS:
            number = counts.get(key, 0)
            if isinstance(number, int) and not isinstance(number, bool) and number > 0:
                totals[key] += number
    plan = {"execute": status == "executed", "status": status, "reason": reason, "provider": provider}
    record = _record(
        plan,
        status=status,
        reason=reason,
        provider=provider,
        parse_counts=totals,
        round_id=round_id,
        raw_sha256=hashes,
        relative_paths=paths,
        relations=relations,
        live_cdp=live,
        coverage=coverage or None,
    )
    record["attempts"] = [copy.deepcopy(item) for item in attempts]
    if attempts:
        record["latest_status"] = str(attempts[-1].get("status") or "")
        record["latest_reason"] = str(attempts[-1].get("reason") or "")
    else:
        record["latest_status"] = status
        record["latest_reason"] = reason
    return record


def commit_supplement(meta: dict[str, Any], attempt: dict[str, Any], *, round_id: str = "") -> None:
    attempts = load_attempts(meta)
    stripped = _strip_attempt(attempt)
    token = _fingerprint(stripped)
    if all(_fingerprint(item) != token for item in attempts):
        attempts.append(stripped)
    chosen = round_id or str(stripped.get("round_id") or "")
    meta["web_supplement"] = project_attempts(attempts, round_id=chosen)


def publish_runtime_projection(
    meta: dict[str, Any],
    rounds: list[dict[str, Any]],
    *,
    round_id: str,
) -> None:
    from apkscan.core.web_supplement import _record

    attempts = load_attempts(meta)
    known = {_fingerprint(item) for item in attempts}
    for item in rounds:
        if not isinstance(item, dict):
            continue
        raw = item.get("raw_sha256")
        hashes = [raw] if isinstance(raw, str) and raw else raw if isinstance(raw, list) else []
        published = item.get("published_path")
        paths = [published] if isinstance(published, str) and published else []
        extra_paths = item.get("relative_paths")
        if isinstance(extra_paths, list):
            paths.extend(path for path in extra_paths if isinstance(path, str))
        status = str(item.get("status") or "failed")
        reason = str(item.get("reason") or status)
        raw = item.get("parse_counts")
        raw_counts = raw if isinstance(raw, dict) else {}
        counts = {key: 0 for key in _COUNT_KEYS}
        for key in _COUNT_KEYS:
            number = raw_counts.get(key, 0)
            if isinstance(number, int) and not isinstance(number, bool) and number >= 0:
                counts[key] = number
        plan = {
            "execute": status == "executed",
            "status": status,
            "reason": reason,
            "provider": str(item.get("provider") or ""),
        }
        attempt = _record(
            plan,
            status=status,
            reason=reason,
            provider=str(item.get("provider") or ""),
            parse_counts=counts,
            round_id=str(item.get("round_id") or ""),
            raw_sha256=[one for one in hashes if isinstance(one, str) and one],
            relative_paths=paths,
            relations=_relations(item),
            live_cdp=item.get("live_cdp") is True,
            coverage=item.get("coverage"),
        )
        token = _fingerprint(attempt)
        if token in known:
            continue
        known.add(token)
        attempts.append(attempt)
    meta["web_supplement"] = project_attempts(attempts, round_id=round_id)
