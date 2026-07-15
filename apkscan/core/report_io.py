"""Shared report.json loading and atomic persistence helpers."""

from __future__ import annotations

import json
import logging
from dataclasses import fields
from pathlib import Path
from typing import Mapping

from apkscan.core.models import (
    ANALYSIS_STATUS_COMPLETE,
    REPORT_SCHEMA_VERSION,
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    Lead,
    LeadCategory,
    Report,
    Severity,
)
from apkscan.report import json as report_json

logger = logging.getLogger(__name__)

_EXTENSIONS_META_KEY = "_report_top_level_extensions"
_REPORT_FIELDS = frozenset(field.name for field in fields(Report))


def _evidence_from_dict(value: object) -> Evidence:
    if not isinstance(value, Mapping):
        return Evidence(source="", location="")
    observed = value.get("observed_at")
    return Evidence(
        source=str(value.get("source", "")),
        location=str(value.get("location", "")),
        snippet=str(value.get("snippet", "")),
        observed_at=observed if isinstance(observed, (int, float)) else None,
    )


def _string_list(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _evidences(value: object) -> list[Evidence]:
    return [_evidence_from_dict(item) for item in value] if isinstance(value, list) else []


def _confidence(value: object) -> Confidence:
    try:
        return Confidence(str(value or Confidence.MEDIUM.value))
    except ValueError:
        return Confidence.MEDIUM


def _severity(value: object) -> Severity:
    try:
        return Severity(str(value or Severity.INFO.value))
    except ValueError:
        return Severity.INFO


def report_from_dict(payload: Mapping[str, object]) -> Report:
    """Reconstruct a :class:`Report` without dropping health or extension data."""
    leads: list[Lead] = []
    raw_leads = payload.get("leads")
    for item in raw_leads if isinstance(raw_leads, list) else []:
        if not isinstance(item, Mapping):
            continue
        try:
            category = LeadCategory(str(item.get("category", "")))
        except ValueError:
            logger.warning("Unknown LeadCategory in report.json; skipping: %s", item.get("category"))
            continue
        subject = item.get("subject")
        where = item.get("where_to_request")
        leads.append(
            Lead(
                category=category,
                value=str(item.get("value", "")),
                subject=str(subject) if subject is not None else None,
                where_to_request=str(where) if where is not None else None,
                evidence_to_obtain=_string_list(item.get("evidence_to_obtain")),
                confidence=_confidence(item.get("confidence")),
                source_refs=_evidences(item.get("source_refs")),
                notes=str(item.get("notes", "")),
                advice=str(item.get("advice", "")),
            )
        )

    endpoints: list[Endpoint] = []
    raw_endpoints = payload.get("endpoints")
    for item in raw_endpoints if isinstance(raw_endpoints, list) else []:
        if not isinstance(item, Mapping):
            continue
        enrichment = item.get("enrichment")
        endpoints.append(
            Endpoint(
                value=str(item.get("value", "")),
                kind=str(item.get("kind", "")),
                evidences=_evidences(item.get("evidences")),
                is_cleartext=bool(item.get("is_cleartext", False)),
                is_private=bool(item.get("is_private", False)),
                is_suspicious=bool(item.get("is_suspicious", False)),
                enrichment=dict(enrichment) if isinstance(enrichment, Mapping) else {},
            )
        )

    findings: list[Finding] = []
    raw_findings = payload.get("findings")
    for item in raw_findings if isinstance(raw_findings, list) else []:
        if not isinstance(item, Mapping):
            continue
        findings.append(
            Finding(
                id=str(item.get("id", "")),
                title=str(item.get("title", "")),
                severity=_severity(item.get("severity")),
                category=str(item.get("category", "")),
                description=str(item.get("description", "")),
                recommendation=str(item.get("recommendation", "")),
                evidences=_evidences(item.get("evidences")),
                references=_string_list(item.get("references")),
                analyzer=str(item.get("analyzer", "")),
                confidence=_confidence(item.get("confidence")),
                kind=str(item.get("kind", "inference")),
            )
        )

    raw_meta = payload.get("meta")
    meta = dict(raw_meta) if isinstance(raw_meta, Mapping) else {}
    extensions = {str(key): value for key, value in payload.items() if key not in _REPORT_FIELDS}
    if extensions:
        existing = meta.get(_EXTENSIONS_META_KEY)
        merged = dict(existing) if isinstance(existing, Mapping) else {}
        merged.update(extensions)
        meta[_EXTENSIONS_META_KEY] = merged

    raw_analyzers = payload.get("analyzer_status")
    raw_enrichers = payload.get("enricher_status")
    completeness = payload.get("completeness", 1.0)
    return Report(
        package_name=str(payload.get("package_name", "")),
        meta=meta,
        leads=leads,
        endpoints=endpoints,
        findings=findings,
        analyzer_status=[dict(item) for item in raw_analyzers if isinstance(item, Mapping)]
        if isinstance(raw_analyzers, list)
        else [],
        enricher_status=[dict(item) for item in raw_enrichers if isinstance(item, Mapping)]
        if isinstance(raw_enrichers, list)
        else [],
        schema_version=str(payload.get("schema_version", REPORT_SCHEMA_VERSION)),
        analysis_status=str(payload.get("analysis_status", ANALYSIS_STATUS_COMPLETE)),
        completeness=float(completeness) if isinstance(completeness, (int, float)) else 1.0,
        critical_failures=_string_list(payload.get("critical_failures")),
        skipped_analyzers=_string_list(payload.get("skipped_analyzers")),
    )


def load_report(path: str | Path) -> Report:
    """Load a UTF-8 report JSON object and reconstruct its typed model."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("report root must be an object")
    return report_from_dict(payload)


def write_report(
    report: Report,
    path: str | Path,
    *,
    render_existing_html: bool = True,
) -> list[str]:
    """Atomically replace report JSON and refresh an existing sibling HTML report."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = report_json.to_dict(report)
    meta = payload.get("meta")
    extensions = meta.pop(_EXTENSIONS_META_KEY, {}) if isinstance(meta, dict) else {}
    if isinstance(extensions, Mapping):
        payload.update({str(key): value for key, value in extensions.items() if key not in payload})

    temporary = target.with_suffix(target.suffix + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(target)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)

    written = [str(target)]
    html_path = target.with_suffix(".html")
    if render_existing_html and html_path.is_file():
        from apkscan.report import html as report_html

        report_html.render(report, str(html_path))
        written.append(str(html_path))
    return written


__all__ = ["load_report", "report_from_dict", "write_report"]
