"""把分析报告摊成 JSONL 事件流（供 AI agent / 脚本逐条流式消费）。

一行一个 JSON 对象：先 1 条 ``meta`` 头（身份 / 完整度 / 可复现锚点），再每条**线索**（lead，核心
调证产出）与**发现**（finding，带 confidence/kind/analyzer 溯源）各一个事件。让 Claude/GPT 等按
confidence/kind 加权、逐条串案、生成文书，而不必先解析整份嵌套报告。纯 dict 入、纯 list 出，可离线测。
"""

from __future__ import annotations


def _meta_event(report: dict) -> dict:
    m = report.get("meta")
    meta = m if isinstance(m, dict) else {}
    return {
        "type": "meta",
        "package": meta.get("package_name") or report.get("package_name"),
        "sample_sha256": meta.get("sample_sha256"),
        "version_name": meta.get("version_name"),
        "version_code": meta.get("version_code"),
        "mode": meta.get("mode"),
        "analysis_status": report.get("analysis_status"),
        "completeness": report.get("completeness"),
        "schema_version": report.get("schema_version"),
        "tool_version": meta.get("tool_version"),
        "ruleset_digest": meta.get("ruleset_digest"),
    }


def _lead_event(lead: dict) -> dict:
    return {
        "type": "lead",
        "category": lead.get("category"),
        "value": lead.get("value"),
        "subject": lead.get("subject"),
        "confidence": lead.get("confidence"),
        "advice": lead.get("advice"),
        "where_to_request": lead.get("where_to_request"),
        "evidence_to_obtain": lead.get("evidence_to_obtain") if isinstance(
            lead.get("evidence_to_obtain"), list) else [],
    }


def _finding_event(f: dict) -> dict:
    return {
        "type": "finding",
        "id": f.get("id"),
        "title": f.get("title"),
        "severity": f.get("severity"),
        "confidence": f.get("confidence"),
        "kind": f.get("kind"),
        "analyzer": f.get("analyzer"),
        "category": f.get("category"),
        "evidence": f.get("evidences") if isinstance(f.get("evidences"), list) else [],
    }


def report_to_events(report: object) -> list[dict]:
    """report dict → JSONL 事件列表：``meta`` 头 + 每条 lead + 每条 finding。绝不抛（非 dict → 仅 meta）。

    保留溯源字段（lead.confidence/advice；finding.id/analyzer/confidence/kind）让每个事件自解释，
    可被 agent 直接加权 / 分流 / 归因，无需回读整份报告。
    """
    r = report if isinstance(report, dict) else {}
    events: list[dict] = [_meta_event(r)]
    leads = r.get("leads")
    if isinstance(leads, list):
        events.extend(_lead_event(x) for x in leads if isinstance(x, dict))
    findings = r.get("findings")
    if isinstance(findings, list):
        events.extend(_finding_event(x) for x in findings if isinstance(x, dict))
    return events
