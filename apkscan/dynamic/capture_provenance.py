"""Scoped capture coordinates and whole-observation runtime projection.

The scope is task-local and always reset. Legacy single-round merges are unchanged.
"""
from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from typing import Any, Iterator

from apkscan.core.models import (
    Evidence,
    EvidenceScope,
    LeadCategory,
    OBSERVED_CONTACT_SOURCES,
    Report,
    revoke_superseded_evidence,
)

_OBSERVATION_BUDGET = 12000
_OVERFLOW_REASON = "runtime_observation_budget_exceeded"

META_WRITE_OWNER = "dynamic.capture_provenance"
META_WRITE_CATEGORIES = {
    "runtime_observations": "record",
    "runtime_observation_overflow": "coverage",
}
META_WRITE_KEYS = frozenset(META_WRITE_CATEGORIES)

_scope: ContextVar[tuple[str | None, bool]] = ContextVar('capture_provenance', default=(None, False))


@contextmanager
def capture_scope(namespace: str | None, *, verified: bool = False) -> Iterator[None]:
    token = _scope.set((namespace, verified))
    try:
        yield
    finally:
        _scope.reset(token)


def scoped_evidence(*args: Any, **kwargs: Any) -> Evidence:
    evidence = Evidence(*args, **kwargs)
    namespace, verified = _scope.get()
    if namespace and not verified and evidence.source in OBSERVED_CONTACT_SOURCES:
        evidence.source = "runtime-derived"
    if namespace and not evidence.location.startswith(namespace + '::'):
        evidence.location = namespace + '::' + evidence.location
    return evidence


def validate_ledger(report: Report) -> None:
    ledger = report.meta.get('runtime_observations', [])
    if (not isinstance(ledger, list) or len(ledger) > 12000
            or report.meta.get('runtime_observations_truncated')):
        raise ValueError('invalid_runtime_observation_ledger')
    for row in ledger:
        if (not isinstance(row, dict) or not isinstance(row.get('capture_ref'), str)
                or not isinstance(row.get('kind'), str) or not isinstance(row.get('value'), str)
                or not isinstance(row.get('runtime'), dict) or type(row.get('eligible')) is not bool
                or not isinstance(row.get('contact_evidence_refs'), list)
                or any(not isinstance(ref, str) for ref in row['contact_evidence_refs'])):
            raise ValueError('invalid_runtime_observation_ledger')
        if row['eligible'] and (not row['contact_evidence_refs'] or any(
                not ref.startswith(row['capture_ref'] + '::') for ref in row['contact_evidence_refs'])):
            raise ValueError('unbound_runtime_observation_refs')


def retain_observations(report: Report, endpoints: list) -> None:
    namespace, verified = _scope.get()
    if not namespace:
        return
    ledger = report.meta.setdefault('runtime_observations', [])
    if not isinstance(ledger, list):
        raise ValueError('invalid_runtime_observation_ledger')
    pending: list[dict] = []
    # Whole-row signatures match dict equality (including 1 == 1.0 == True) without
    # scanning the growing pending list. Identity of retained rows stays the same.
    seen = {_observation_signature(item) for item in ledger if isinstance(item, dict)}
    for endpoint in endpoints:
        runtime = endpoint.enrichment.get('runtime')
        if not isinstance(runtime, dict) or not runtime:
            continue
        refs = sorted({ev.location for ev in endpoint.evidences
                       if ev.scope is EvidenceScope.CASE_EVIDENCE
                       and ev.source in OBSERVED_CONTACT_SOURCES
                       and ev.location.startswith(namespace + '::')})
        row = {'capture_ref': namespace, 'kind': endpoint.kind, 'value': endpoint.value,
               'runtime': deepcopy(runtime), 'contact_evidence_refs': refs,
               'eligible': verified and bool(refs) and runtime.get('variant', 'original-runtime') == 'original-runtime'}
        signature = _observation_signature(row)
        if signature in seen:
            continue
        seen.add(signature)
        pending.append(row)
    if not pending:
        return
    if len(ledger) + len(pending) > _OBSERVATION_BUDGET:
        _reject_observation_overflow(report, ledger, pending)
        raise ValueError(_OVERFLOW_REASON)
    ledger.extend(pending)


def project_observations(report: Report) -> None:
    namespace, _ = _scope.get()
    if not namespace:
        return
    ledger = report.meta.get('runtime_observations', [])
    affected = _overflow_affected(report)
    # A legacy truncated ledger does not name the omitted targets, so none of its
    # rows can be treated as a complete contact history.
    legacy_truncated = bool(report.meta.get("runtime_observations_truncated"))
    indexed: dict[tuple[str, str], list] = defaultdict(list)
    for row in ledger:
        indexed[(row['kind'], row['value'])].append(row)
    for ep in report.endpoints:
        rows = indexed.get((ep.kind, ep.value), [])
        if not rows:
            continue
        # Inconsistent re-use of an artifact identity is a conflict, not a refresh.
        refs: dict[str, list] = {}
        for row in rows:
            if row['contact_evidence_refs']:
                refs.setdefault(row['capture_ref'], []).append(row)
        conflicts = {ref for ref, group in refs.items()
                     if any(item['runtime'] != group[0]['runtime'] for item in group[1:])}
        candidates = [row for row in rows if row['eligible'] and row['capture_ref'] not in conflicts]
        if candidates:
            def rank(row: dict) -> tuple:
                runtime = row['runtime']
                return (int(runtime.get('target_attributed') is True),
                        int(runtime.get('has_payload') is True), row['capture_ref'])
            selected = max(candidates, key=rank)
            ep.enrichment['runtime'] = deepcopy(selected['runtime'])
            ep.enrichment['runtime']['selected_observation_ref'] = selected['capture_ref']
            ep.enrichment['runtime']['selected_evidence_refs'] = list(selected['contact_evidence_refs'])
        else:
            # Raw values remain in the ledger; no identity-unknown row grants contact proof.
            runtime = deepcopy(rows[0]['runtime'])
            runtime['target_attributed'] = None
            runtime['sequence_identity_unconfirmed'] = True
            ep.enrichment['runtime'] = runtime
        if conflicts:
            ep.enrichment['runtime_observation_conflicts'] = sorted(conflicts)
        if ((ep.kind, ep.value) in affected or legacy_truncated) and isinstance(
                ep.enrichment.get('runtime'), dict):
            # An omitted same-target row may disagree; keep ledger history and drop the claim.
            # Legacy truncation omits unknown targets, so every projected row stays unconfirmed.
            ep.enrichment['runtime']['target_attributed'] = None
            ep.enrichment['runtime']['sequence_identity_unconfirmed'] = True
            if (ep.kind, ep.value) in affected:
                _apply_overflow_conflicts(report, ep)


def append_capture_ref(report: Report, category: object, value: str, evidence: Evidence) -> bool:
    """Add a distinct reference to an existing lead without changing its verdict.

    A capture namespace is optional. Legacy callers still union distinct evidence
    and do not append a second lead for the same category and value.
    """
    for lead in report.leads:
        if lead.category == category and lead.value == value:
            if evidence not in lead.source_refs:
                lead.source_refs.append(evidence)
            return True
    return False


def _network_key(kind: str, value: str) -> tuple[str, str] | None:
    from apkscan.core.infra import match_key

    normalized = match_key(kind, value).strip().lower().rstrip(".")
    return (kind, normalized) if normalized else None


def _lead_network_key(lead: Any) -> tuple[str, str] | None:
    category = getattr(lead, "category", None)
    if isinstance(category, LeadCategory):
        name = category.value
    else:
        name = str(getattr(category, "value", category) or "")
    name = name.rsplit(".", 1)[-1].upper()
    if name not in {LeadCategory.DOMAIN.value, LeadCategory.IP.value}:
        return None
    return _network_key(name.lower(), str(getattr(lead, "value", "")))


def _endpoint_network_key(endpoint: Any) -> tuple[str, str] | None:
    kind = str(getattr(endpoint, "kind", "") or "")
    value = str(getattr(endpoint, "value", "") or "")
    if kind in {"domain", "ip"}:
        return _network_key(kind, value)
    if kind != "url":
        return None
    host = _host_of_url(value)
    if not host:
        return None
    from ipaddress import ip_address

    try:
        ip_address(host)
    except ValueError:
        return _network_key("domain", host)
    return _network_key("ip", host)


def _host_of_url(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def _overflow_record(report: Report) -> dict:
    overflow = report.meta.get("runtime_observation_overflow")
    return overflow if isinstance(overflow, dict) else {}


def _overflow_affected(report: Report) -> set[tuple[str, str]]:
    affected: set[tuple[str, str]] = set()
    for item in _overflow_record(report).get("affected_targets") or []:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            affected.add((str(item[0]), str(item[1])))
    return affected


def _overflow_conflict_refs(report: Report) -> list[str]:
    refs = _overflow_record(report).get("conflict_refs") or []
    return sorted({ref for ref in refs if isinstance(ref, str)})


def _apply_overflow_conflicts(report: Report, endpoint: Any) -> None:
    refs = _overflow_conflict_refs(report)
    if not refs:
        return
    current = endpoint.enrichment.get("runtime_observation_conflicts")
    merged = set(refs)
    if isinstance(current, list):
        merged.update(item for item in current if isinstance(item, str))
    endpoint.enrichment["runtime_observation_conflicts"] = sorted(merged)


def _reject_observation_overflow(report: Report, ledger: list, pending: list[dict]) -> None:
    """Refuse the batch before any ledger append.

    Unrelated rows leave previously validated observations in place. A same-target
    row that cannot be stored may contradict them, so only that target loses the
    contact claim; its earlier ledger rows stay as history.
    """
    stored: dict[tuple[str, str], list] = defaultdict(list)
    for row in ledger:
        if isinstance(row, dict):
            stored[(str(row.get("kind")), str(row.get("value")))].append(row.get("runtime"))
    affected: set[tuple[str, str]] = _overflow_affected(report)
    conflict_refs: set[str] = set(_overflow_conflict_refs(report))
    batch_affected: set[tuple[str, str]] = set()
    batch_conflicts: set[str] = set()
    for row in pending:
        key = (str(row.get("kind")), str(row.get("value")))
        priors = stored.get(key, [])
        if priors and any(prior != row.get("runtime") for prior in priors):
            affected.add(key)
            batch_affected.add(key)
            ref = row.get("capture_ref")
            if isinstance(ref, str):
                conflict_refs.add(ref)
                batch_conflicts.add(ref)
    prior = _overflow_record(report)
    omitted = len(pending)
    prior_count = prior.get("omitted_count")
    if type(prior_count) is int:
        omitted += prior_count
    receipts = [item for item in prior.get("rejections") or [] if isinstance(item, dict)]
    receipts.append({
        "omitted_count": len(pending),
        "affected_targets": sorted([list(key) for key in batch_affected]),
        "conflict_refs": sorted(batch_conflicts),
    })
    report.meta["runtime_observation_overflow"] = {
        "status": "rejected",
        "reason": _OVERFLOW_REASON,
        "omitted_count": omitted,
        "affected_targets": sorted([list(key) for key in affected]),
        "conflict_refs": sorted(conflict_refs),
        "rejections": receipts,
    }
    for endpoint in report.endpoints:
        key = (getattr(endpoint, "kind", None), getattr(endpoint, "value", None))
        if key not in affected:
            continue
        runtime = endpoint.enrichment.get("runtime")
        if isinstance(runtime, dict):
            runtime = deepcopy(runtime)
            runtime["target_attributed"] = None
            runtime["sequence_identity_unconfirmed"] = True
            endpoint.enrichment["runtime"] = runtime
        if conflict_refs:
            endpoint.enrichment["runtime_observation_conflicts"] = sorted(conflict_refs)


def _observation_signature(row: dict) -> tuple:
    """Equality signature for one ledger row.

    Matches ``dict``/``list`` equality, including ``True == 1 == 1.0``, so membership
    does not depend on scanning ``pending``.
    """
    return _freeze(row)


def _freeze(value: object) -> tuple:
    if isinstance(value, dict):
        items = tuple(sorted(
            ((_freeze(key), _freeze(item)) for key, item in value.items()),
            key=repr,
        ))
        return ("dict", items)
    if isinstance(value, list):
        return ("list", tuple(_freeze(item) for item in value))
    if isinstance(value, str):
        return ("str", value)
    if value is None:
        return ("none",)
    if isinstance(value, bool):
        return ("num", int(value))
    if isinstance(value, int):
        return ("num", value)
    if isinstance(value, float):
        if value == value and value != float("inf") and value != float("-inf"):
            as_int = int(value)
            if as_int == value:
                return ("num", as_int)
        return ("float", value)
    return ("other", type(value).__name__, repr(value))


def _legitimate_ref(evidence: Evidence, namespace: str | None) -> bool:
    if not str(evidence.source).startswith("runtime"):
        return False
    if namespace and not str(evidence.location).startswith(namespace + "::"):
        return False
    return True


def sync_endpoint_refs(report: Report, endpoints: list) -> None:
    """Copy runtime evidence onto the existing DOMAIN/IP lead for the same host.

    Legacy merges have no capture namespace and still propagate. Verdict fields stay
    untouched. A revoked runtime-pcap identity is not appended back beside the
    source that superseded it.
    """
    namespace, _ = _scope.get()
    by_key: dict[tuple[str, str], Any] = {}
    for lead in report.leads:
        key = _lead_network_key(lead)
        if key is not None and key not in by_key:
            by_key[key] = lead
    for endpoint in endpoints:
        lead = by_key.get(_endpoint_network_key(endpoint) or ("", ""))
        if lead is None:
            continue
        incoming = [ev for ev in endpoint.evidences if _legitimate_ref(ev, namespace)]
        if not incoming:
            continue
        filtered = list(incoming)
        revoke_superseded_evidence(filtered, filtered)
        # Existing derived refs supersede a later stale pcap with the same
        # location/snippet/scope. Identity ignores timestamp; both objects stay intact.
        revoke_superseded_evidence(filtered, lead.source_refs)
        revoke_superseded_evidence(lead.source_refs, filtered)
        for evidence in filtered:
            if evidence not in lead.source_refs:
                lead.source_refs.append(evidence)
