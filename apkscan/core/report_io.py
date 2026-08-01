"""Shared report.json loading and atomic persistence helpers."""

from __future__ import annotations

import json
import logging
from dataclasses import fields
from pathlib import Path
from typing import Mapping

from apkscan.core import infra
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

#: ``Lead.base_advice`` 的合法取值。磁盘上的报告可能被手改或被别的工具写坏，读进来的初始档
#: 必须落在这个集合里——否则一个没人认识的字符串会被当成档位一路写进 ``advice``。
_VALID_ADVICE: frozenset[str] = frozenset({
    infra.ADVICE_INVESTIGATE, infra.ADVICE_REVIEW, infra.ADVICE_SKIP,
})
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


def _base_advice(value: object) -> str | None:
    """读 ``Lead.base_advice``：只认**合法档位取值**，其余（含缺失 / null / 乱码）一律 ``None``。

    ★保留「没有」这个状态：``None`` 表示这条线索的初始档不可考（旧报告），与「初始档恰好
      是空串」不是一回事，也不该被悄悄抹平成后者。

    ★只收白名单里的取值、**不做 ``str()`` 硬转**：这份数据来自磁盘，可能被手改或被别的工具
      写坏。放一个 ``"{'bad': 1}"`` 进来，它会被 :func:`models.recompute_advice` 当成初始档
      写进 ``advice``，而一致性校验还判它自洽——凭空造出一个没人认识的档位。
      非法值当作「来源不可考」处理：档位原样沿用报告里的 advice，行为等同旧报告，安全。
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text not in _VALID_ADVICE:
        if text:
            logger.warning("report.json 里的 base_advice 取值非法，按来源不可考处理：%r", text)
        return None
    return text


def _str_mapping(value: object) -> dict[str, str]:
    """读一个 ``{str: str}`` 映射；非映射 / 非字符串键值一律丢弃，绝不抛。

    ★值也必须是真字符串、不做 ``str()`` 硬转：嵌套对象被转成 ``"{'a': 1}"`` 这种字面后，
      看着像一条正常的抑制说明，实则是坏数据混进了判定输入。
    """
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, str] = {}
    for key, item in value.items():
        if not (isinstance(key, str) and key.strip()):
            continue
        if not isinstance(item, str):
            continue
        out[key.strip()] = item
    return out


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
                # ★必须往返：closure/letters 都从磁盘上的 report.json 走，丢了这个字段
                #   等于形态存疑的保留意见在 `case close` / `letters` 那一步凭空消失。
                shape_uncertain=bool(item.get("shape_uncertain", False)),
                # 同上：letters 靠它渲染「别发给被冒用的那家公司」的警示，丢了警示就消失。
                sni_masquerade=_string_list(item.get("sni_masquerade")),
                # ★档位的可撤销来源。旧报告没有这两个字段：``base_advice`` 保持 None（如实
                #   表达「这条的初始档不可考」），``downgrades`` 为空。此时 advice 原样沿用，
                #   行为与改动前逐字一致；但也**不会**有人据此自动解除抑制——因为没有 base
                #   就算不出该恢复到哪一档，:func:`models.effective_advice` 会返回空串。
                base_advice=_base_advice(item.get("base_advice")),
                downgrades=_str_mapping(item.get("downgrades")),
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
