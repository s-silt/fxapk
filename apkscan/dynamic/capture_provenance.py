"""Scoped capture coordinates and whole-observation runtime projection.

The scope is task-local and always reset. Legacy single-round merges are unchanged.
"""
from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from typing import Any, Iterator

from apkscan.core.models import Evidence, EvidenceScope, OBSERVED_CONTACT_SOURCES, Report

META_WRITE_OWNER = "dynamic.capture_provenance"
META_WRITE_CATEGORIES = {"runtime_observations": "record", "runtime_observations_truncated": "coverage"}
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
        if row in ledger:
            continue
        if len(ledger) >= 12000:
            report.meta['runtime_observations_truncated'] = True
            continue
        ledger.append(row)


def project_observations(report: Report) -> None:
    namespace, _ = _scope.get()
    if not namespace:
        return
    ledger = report.meta.get('runtime_observations', [])
    if report.meta.get('runtime_observations_truncated'):
        for ep in report.endpoints:
            if isinstance(ep.enrichment.get('runtime'), dict):
                ep.enrichment['runtime']['sequence_identity_unconfirmed'] = True
                ep.enrichment['runtime']['target_attributed'] = None
        return
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


def append_capture_ref(report: Report, category: object, value: str, evidence: Evidence) -> bool:
    """Add a distinct round reference to an existing lead without changing its verdict."""
    if not _scope.get()[0]:
        return False
    for lead in report.leads:
        if lead.category == category and lead.value == value:
            if evidence not in lead.source_refs:
                lead.source_refs.append(evidence)
            return True
    return False


def sync_endpoint_refs(report: Report, endpoints: list) -> None:
    namespace, _ = _scope.get()
    if not namespace:
        return
    by_value = {(lead.category.value.lower(), lead.value): lead for lead in report.leads}
    for endpoint in endpoints:
        lead = by_value.get((endpoint.kind, endpoint.value))
        if lead is not None:
            for evidence in endpoint.evidences:
                if evidence.location.startswith(namespace + '::') and evidence not in lead.source_refs:
                    lead.source_refs.append(evidence)
