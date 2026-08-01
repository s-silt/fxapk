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
    VALID_ADVICE,
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


def _advice_or_none(value: object, field_name: str) -> str | None:
    """读一个**档位锚点字段**：只认合法取值，其余（含缺失 / null / 乱码）一律 ``None``。

    ``base_advice`` 与 ``legacy_effective_advice`` 共用——两者取值域相同，坏数据的后果也相同。

    ★保留「没有」这个状态：``None`` 表示这个锚点不可考（旧报告），与「锚点恰好是空串」不是
      一回事，也不该被悄悄抹平成后者。

    ★只收白名单里的取值、**不做 ``str()`` 硬转**：这份数据来自磁盘，可能被手改或被别的工具
      写坏。放一个 ``"{'bad': 1}"`` 进来，它会被 :func:`models.recompute_advice` 当成锚点
      写进 ``advice``，而一致性校验还判它自洽——凭空造出一个没人认识的档位。
      非法值当作「不可考」处理：档位原样沿用报告里的 advice，行为等同旧报告，安全。
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text not in VALID_ADVICE:
        if text:
            logger.warning("report.json 里的 %s 取值非法，按不可考处理：%r", field_name, text)
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
        base_advice = _advice_or_none(item.get("base_advice"), "base_advice")
        legacy_advice = _advice_or_none(item.get("legacy_effective_advice"), "legacy_effective_advice")
        if base_advice is not None and legacy_advice is not None:
            # 眼下两者互斥：有判据结论就不会去拍迁移快照，所以同时出现说明这条被手改过、或
            # 经过了某个我们还不知道的写路径。**不丢弃任何一个**：计算上由
            # models.effective_advice 让 base 优先，快照原样往返留档，供人事后核对。
            #
            # ★下一刀要重审这段文案：一旦开始给旧 lead **补算** base_advice，「两个锚点并存」
            #   就成了迁移期的正常过渡态，那时再说「被手改」就不对了，得按当时的迁移策略改写。
            logger.warning(
                "report.json 的 lead %r 同时带 base_advice 与 legacy_effective_advice；"
                "按 base_advice 计算档位，快照原样保留：%r / %r",
                item.get("value"), base_advice, legacy_advice,
            )
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
                # ★档位的可撤销来源。旧报告没有这三个字段：两个锚点保持 None（如实表达「不可
                #   考」），``downgrades`` 为空。此时 advice 原样沿用，行为与改动前逐字一致；
                #   也不会有人据此自动解除抑制——两个锚点都没有时 models.effective_advice 返回
                #   空串，算不出该恢复到哪一档。要等它被 apply_downgrade 碰过、拍下迁移快照，
                #   才具备撤销能力。
                base_advice=base_advice,
                downgrades=_str_mapping(item.get("downgrades")),
                legacy_effective_advice=legacy_advice,
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
