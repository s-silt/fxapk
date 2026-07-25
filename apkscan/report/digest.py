"""把 report.json 压成 **AI agent（agent-agnostic）/ 程序友好** 的紧凑摘要（compact digest）。

report.json 完整但冗长（端点全表 / 技术附录 / 富化原始数据），AI agent（Codex）逐字解析既费
token 又难抓重点。本模块抽出**可办案化的核心**：按优先级排序的调证线索 + 计数摘要，键名稳定、
结构扁平，供低 token 消费、直接决策。纯函数（report dict → digest dict），绝不抛。
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from apkscan.core.redact import redact_value, scrub_pii

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


def _scrub_field(text: object, flag: list[bool]) -> object:
    """redact 模式下对单个自由文本字段抹结构化 PII；命中即置 flag。None 保持 None（不改结构）。"""
    if text is None:
        return None
    scrubbed, hit = scrub_pii(text)
    if hit:
        flag[0] = True
    return scrubbed


def _compact_lead(lead: dict[str, Any], redact: bool, pii_flag: list[bool]) -> dict[str, Any]:
    """单条线索压成扁平稳定字段（去掉 source_refs 等冗长内部结构）。

    redact=True（可选）：高敏类别（钱包私钥/凭据/受害人 PII/加密配方）的 value 按类别脱敏；
    并对 subject/notes/where_to_request/evidence_to_obtain 等**自由文本**兜底抹结构化 PII
    （不依赖类别标注是否正确，防受害人手机号/证件号绕过脱敏进云端 agent，codex C1）。默认 False。
    """
    category = lead.get("category")
    value = lead.get("value")
    subject = lead.get("subject")
    where = lead.get("where_to_request")
    notes = lead.get("notes") or ""
    evidence = lead.get("evidence_to_obtain") or []
    if redact:
        value = redact_value(category, value)
        subject = _scrub_field(subject, pii_flag)
        where = _scrub_field(where, pii_flag)
        notes = _scrub_field(notes, pii_flag)
        evidence = [_scrub_field(item, pii_flag) for item in evidence]
    return {
        "category": category,
        "value": value,
        "subject": subject,
        "advice": lead.get("advice"),
        "confidence": lead.get("confidence"),
        "is_c2": bool(lead.get("is_c2")),
        # 宽口径「动态侧出现」；严一档的「observed-contact 真接触」另给 is_runtime_contact，
        # 供下游筛选/研判分层——勿把仅 is_runtime_seen（含手编 runtime-derived）当「实连/确认 C2」。
        "is_runtime_seen": bool(lead.get("is_runtime_seen")),
        "is_runtime_contact": bool(lead.get("is_runtime_contact")),
        "where_to_request": where,
        "evidence_to_obtain": evidence,
        "notes": notes,
    }


#: role display order for the network_attribution digest block (behavioral-deception
#: and origin findings first; edge last as it is closest to a mere resource fact).
_ROLE_RANK = {
    "cloaking_edge_node": 0,
    "origin_candidate": 1,
    "domestic_relay_candidate": 2,
    "edge_candidate": 3,
}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _neg_score(value: object) -> float:
    """Negated score for a descending sort. A non-numeric / bool score (only
    reachable from a hand-edited or version-skewed report.json) sorts as 0 so the
    digest degrades rather than raising on the one arithmetic use of the field."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return -float(value)


def _compact_network_attribution(raw: Any) -> dict[str, Any] | None:
    """Low-token projection of meta['network_attribution']: graph counts + the
    ELIGIBLE role candidates only (ineligible are counted, not listed). Defensive
    — any malformed shape degrades to an empty block; never raises, never the raw graph."""
    if not isinstance(raw, dict):
        return None
    graph = raw.get("graph")
    graph = graph if isinstance(graph, dict) else {}

    candidates: list[dict[str, Any]] = []
    eligible = ineligible = 0
    by_role: Counter = Counter()
    for endpoint in _list(raw.get("endpoints")):
        if not isinstance(endpoint, dict):
            continue
        for ipv in _list(endpoint.get("ips")):
            if not isinstance(ipv, dict):
                continue
            for role in _list(ipv.get("roles")):
                if not isinstance(role, dict):
                    continue
                if role.get("eligible"):
                    eligible += 1
                    by_role[str(role.get("role"))] += 1
                    candidates.append({
                        "endpoint": endpoint.get("endpoint"),
                        "kind": endpoint.get("kind"),  # domain / ip（对齐设计 schema role_candidates 字段）
                        "ip": ipv.get("ip"),
                        "role": role.get("role"),
                        "score": role.get("score"),
                        "confidence": role.get("confidence"),
                    })
                else:
                    ineligible += 1
    candidates.sort(
        key=lambda c: (_ROLE_RANK.get(str(c.get("role")), 99), _neg_score(c.get("score")), str(c.get("ip")))
    )
    return {
        "counts": {
            "nodes": len(_list(graph.get("nodes"))),
            "edges": len(_list(graph.get("edges"))),
            "issues": len(_list(graph.get("issues"))),
            "eligible": eligible,
            "ineligible": ineligible,
            "by_role": dict(by_role),
        },
        "role_candidates": candidates[:10],
    }


def build_digest(report: object, *, redact: bool = False) -> dict[str, Any]:
    """report.json 解析出的对象 → 紧凑摘要 dict（线索按优先级排序）。绝不抛。

    redact=False（默认）：原样输出——取证查看需要看到钱包私钥/凭据等实际值。
    redact=True（`fxapk digest --redact`，喂云端 agent 时）：高敏类别 value 脱敏，明文只留本地完整报告。
    """
    if not isinstance(report, dict):
        return {"error": "report 非 dict", "leads": []}
    raw_meta = report.get("meta")
    meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    leads = [lead for lead in (report.get("leads") or []) if isinstance(lead, dict)]
    leads_sorted = sorted(leads, key=_lead_sort_key)
    pii_flag = [False]  # 单元素可变标记：任一 lead 自由文本抹掉 PII 即置 True（见 _compact_lead）

    by_advice = Counter(str(lead.get("advice") or "未研判") for lead in leads)
    by_category = Counter(str(lead.get("category") or "?") for lead in leads)

    # 结构化境外源站段（被动定位的海外后端/控制者：IP 归属/ASN/开放端口/服务 banner/技术栈/关联子域，
    # 按主机聚合，机器可读）。由 pipeline 写入 meta["overseas_targets"]，已做辖区门控（仅国外+未知）；
    # 此处原样透传供 agent 直查——纯被动 OSINT 定位，对目标零流量。
    overseas_targets = meta.get("overseas_targets")
    overseas_targets = overseas_targets if isinstance(overseas_targets, list) else []

    raw_closure = meta.get("closure")
    closure = raw_closure if isinstance(raw_closure, dict) else {}
    closure_targets = closure.get("targets")
    compact_closure = {
        "status": closure.get("status"),
        "target_count": len(closure_targets) if isinstance(closure_targets, list) else 0,
        "gaps": [str(item) for item in closure.get("gaps", [])]
        if isinstance(closure.get("gaps"), list)
        else [],
        "next_actions": [str(item) for item in closure.get("next_actions", [])]
        if isinstance(closure.get("next_actions"), list)
        else [],
        "source_summary": closure.get("source_summary")
        if isinstance(closure.get("source_summary"), dict)
        else {},
    }

    network_attribution = _compact_network_attribution(meta.get("network_attribution"))
    role_candidate_count = (
        network_attribution["counts"].get("eligible", 0)
        if isinstance(network_attribution, dict)
        else 0
    )

    digest: dict[str, Any] = {
        "package": meta.get("package_name") or report.get("package_name"),
        "sha256": meta.get("sample_sha256"),
        "app_classification": meta.get("app_classification"),
        "summary": {
            "total_leads": len(leads),
            "by_advice": dict(by_advice),
            "by_category": dict(by_category),
            "comm_sessions": len(meta.get("comm_sessions") or []),
            "overseas_target_hosts": len(overseas_targets),
            "attributed_role_candidates": role_candidate_count,
        },
        "leads": [_compact_lead(lead, redact, pii_flag) for lead in leads_sorted],
        "overseas_targets": overseas_targets,
        "closure": compact_closure,
    }
    if network_attribution is not None:
        digest["network_attribution"] = network_attribution
    # ★告警（codex C1）：redact 模式下自由文本命中并抹掉了结构化 PII → 显式标记，不静默
    #   （提醒操作者上游把受害人 PII 写进了 subject/notes 等自由文本，脱敏虽已兜底但源头应修）。
    if redact and pii_flag[0]:
        digest["redaction_warning"] = "自由文本字段命中并抹除了结构化 PII（手机号/证件号/邮箱/卡号）；上游不应把受害人 PII 写入自由文本"
    return digest
