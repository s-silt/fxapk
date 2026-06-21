"""把 report.json 压成 **AI agent（agent-agnostic）/ 程序友好** 的紧凑摘要（compact digest）。

report.json 完整但冗长（端点全表 / 技术附录 / 富化原始数据），AI agent（Codex）逐字解析既费
token 又难抓重点。本模块抽出**可办案化的核心**：按优先级排序的调证线索 + 计数摘要，键名稳定、
结构扁平，供低 token 消费、直接决策。纯函数（report dict → digest dict），绝不抛。
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from apkscan.core.redact import redact_value

# 排序优先级：建议调证 > 待核 > 无需调证；同档高可信在前；C2 在前。
_ADVICE_RANK = {"建议调证": 0, "待核": 1, "无需调证": 2}
_CONF_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _lead_sort_key(lead: dict[str, Any]) -> tuple[int, int, int, str]:
    return (
        _ADVICE_RANK.get(str(lead.get("advice") or ""), 3),
        _CONF_RANK.get(str(lead.get("confidence") or ""), 3),
        0 if lead.get("is_c2") else 1,
        str(lead.get("category") or ""),
    )


def _compact_lead(lead: dict[str, Any], redact: bool) -> dict[str, Any]:
    """单条线索压成扁平稳定字段（去掉 source_refs 等冗长内部结构）。

    redact=True（默认）：高敏类别（钱包私钥/凭据/受害人 PII）的 value 脱敏——明文只留本地完整报告，
    不进 agent 上下文。
    """
    category = lead.get("category")
    value = lead.get("value")
    if redact:
        value = redact_value(category, value)
    return {
        "category": category,
        "value": value,
        "subject": lead.get("subject"),
        "advice": lead.get("advice"),
        "confidence": lead.get("confidence"),
        "is_c2": bool(lead.get("is_c2")),
        "is_runtime_seen": bool(lead.get("is_runtime_seen")),
        "where_to_request": lead.get("where_to_request"),
        "evidence_to_obtain": lead.get("evidence_to_obtain") or [],
        "notes": lead.get("notes") or "",
    }


def build_digest(report: object, *, redact: bool = True) -> dict[str, Any]:
    """report.json 解析出的对象 → 紧凑摘要 dict（线索按优先级排序）。绝不抛。

    redact=True（默认）：高敏类别（钱包私钥/凭据/受害人 PII）的 value 脱敏，明文只留本地完整报告，
    不进 agent 上下文（隐私安全）。--raw / redact=False 关闭脱敏。
    """
    if not isinstance(report, dict):
        return {"error": "report 非 dict", "leads": []}
    raw_meta = report.get("meta")
    meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    leads = [lead for lead in (report.get("leads") or []) if isinstance(lead, dict)]
    leads_sorted = sorted(leads, key=_lead_sort_key)

    by_advice = Counter(str(lead.get("advice") or "未研判") for lead in leads)
    by_category = Counter(str(lead.get("category") or "?") for lead in leads)

    return {
        "package": meta.get("package_name") or report.get("package_name"),
        "sha256": meta.get("sample_sha256"),
        "app_classification": meta.get("app_classification"),
        "summary": {
            "total_leads": len(leads),
            "by_advice": dict(by_advice),
            "by_category": dict(by_category),
            "comm_sessions": len(meta.get("comm_sessions") or []),
        },
        "leads": [_compact_lead(lead, redact) for lead in leads_sorted],
    }
