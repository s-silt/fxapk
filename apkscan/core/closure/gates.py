"""闭环验收：动态采集质量门（``evaluate_capture_quality``）与总闭环判定（``evaluate_closure``）。

为什么这样切：验收层只消费"已组装好的 targets 结构 + report.meta"，产出 complete/partial/failed
判定与 gaps/next_actions，不做任何富化与组装，因此对 targets/layers/sources 零依赖，只依赖
共享底座 ``_shared``（layers 会反过来复用这里的 ``_non_negative_int``，方向是 layers → gates，无环）。
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from apkscan.core.models import (
    ANALYSIS_STATUS_COMPLETE,
    ANALYSIS_STATUS_FAILED,
    Report,
)

from apkscan.core.closure._shared import (
    CLOSURE_COMPLETE,
    CLOSURE_FAILED,
    CLOSURE_PARTIAL,
    SOURCE_STATUSES,
    _mapping,
)


def _non_negative_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return max(0, int(value))
    return 0


def evaluate_capture_quality(meta: Mapping[str, object]) -> dict[str, object]:
    """Separate channel readiness from target-attributed business evidence."""
    raw = _mapping(meta.get("quality"))
    raw.update({key: value for key, value in meta.items() if key not in raw})

    attribution = _mapping(raw.get("pcap_app_attribution"))
    attributed = sum(
        1
        for item in attribution.values()
        if isinstance(item, Mapping) and item.get("is_target_app") is True
    )
    target_count = _non_negative_int(raw.get("target_attributed_count")) or attributed
    business_count = _non_negative_int(raw.get("business_candidate_count"))
    if business_count == 0:
        business_count = _non_negative_int(raw.get("endpoint_total"))
    packet_count = _non_negative_int(raw.get("packet_count"))
    pcap_valid = bool(raw.get("pcap_valid")) and packet_count > 0
    channel_ready = bool(
        raw.get("channel_ready")
        or raw.get("mitm_channel_ok")
        or raw.get("floor_started")
    )

    floor_parse_status = str(raw.get("floor_parse_status") or "ok")
    floor_parse_failed = floor_parse_status not in ("ok", "absent", "")

    # 双向业务证据：出站与入站均有应用层载荷的、且归因到目标 App 的对端数量。
    # ★为什么必须单列：单向流量（DNS query、SYN-only、发出去没人应）证明不了"与后端通信过"，
    #   而闭环 complete 的含义正是"拿到了真实通信去向"。实测两案上，目标 UID 只向公共解析器
    #   发过 DNS query（入站 0B），却被判 complete —— 人工结论是动态未闭环。
    # ★字段缺失（老 runtime_report / 未提供该统计）时按 0 处理，即 fail-closed 降级为 partial：
    #   宁可把已闭环说成未闭环（多跑一次采集），不可把未闭环说成已闭环（据以结案）。
    bidirectional_count = _non_negative_int(raw.get("bidirectional_business_count"))

    if target_count > 0 and business_count > 0 and bidirectional_count > 0:
        status = CLOSURE_COMPLETE
        reason = "target-attributed public business candidate observed with bidirectional payload"
    elif target_count > 0 and business_count > 0:
        status = CLOSURE_PARTIAL
        reason = (
            "target-attributed candidate observed but no bidirectional payload "
            "(one-way traffic does not establish a reached backend)"
        )
    elif business_count > 0:
        status = CLOSURE_PARTIAL
        reason = "public business candidate observed without unique target attribution"
    elif floor_parse_failed:
        # floor pcap 解析/采集失败：空结果**不代表零流量**——与「真实零业务流量」显式区分，提示重抓而非结案。
        status = CLOSURE_FAILED
        reason = f"floor pcap parse failed ({floor_parse_status}); empty result does not imply zero traffic"
    else:
        status = CLOSURE_FAILED
        reason = "no target business candidate observed"

    return {
        "channel_ready": channel_ready,
        "pcap_valid": pcap_valid,
        "packet_count": packet_count,
        "business_candidate_count": business_count,
        "target_attributed_count": target_count,
        "bidirectional_business_count": bidirectional_count,
        # 分侧计数原样透传：双向证据来自 floor 实测还是 mitm 代理，读报告的人要分得清。
        "bidirectional_floor_count": _non_negative_int(raw.get("bidirectional_floor_count")),
        "bidirectional_mitm_count": _non_negative_int(raw.get("bidirectional_mitm_count")),
        # 因基础设施判据被排除的对端数（公共解析器上的 DNS 等）。单列出来，
        # 免得"排除了噪音"与"本来就没流量"在读报告时长得一样。
        "infrastructure_excluded_count": _non_negative_int(raw.get("infrastructure_excluded_count")),
        "dynamic_status": status,
        "reason": reason,
        "floor_parse_status": floor_parse_status,
    }


def _capture_meta(report: Report) -> dict[str, Any]:
    for key in ("capture_quality", "runtime_capture_quality", "capture_signals"):
        value = report.meta.get(key)
        if isinstance(value, Mapping):
            return dict(value)
    return {}


def _source_summary(targets: Sequence[Mapping[str, object]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for target in targets:
        sources = target.get("source_status")
        if not isinstance(sources, Mapping):
            continue
        for item in sources.values():
            if isinstance(item, Mapping):
                counts[str(item.get("status", "failed"))] += 1
    return {status: counts.get(status, 0) for status in sorted(SOURCE_STATUSES)}


def _visibility_check(
    report: Report, targets: Sequence[Mapping[str, object]], gaps: list[str]
) -> dict[str, object]:
    """证据可见性对闭环的影响 —— **按主张相关性**，不是全局封顶。

    可见性求值（``core.visibility``）说的是「哪些输入没看见」。它对闭环的影响取决于**目标从哪来**：

    - 目标由运行时唯一归因确认（pcap 实测连接 + socket/UID 归到本 app）→ DEX 看不看得见都不影响
      这个目标本身。硬把闭环降级会把真实、可办案的动态证据一起拖下水，这正是要避免的。
    - 目标全靠静态提取，而静态输入不可见 → 目标集合可能压根不全（真 C2 藏在看不见的 DEX 里），
      此时说「闭环完成」站不住，记 gap。

    两种情况都写进 checks 供人核；只有后者进 gaps（进 gaps 即封顶 partial）。
    """
    from apkscan.core import visibility as _vis

    assessment = report.meta.get("visibility")
    if not isinstance(assessment, dict):
        return {
            "id": "evidence_visibility",
            "status": "not_applicable",
            "reason": "no visibility assessment in report (older analysis)",
            "evidence_refs": [],
        }
    if not _vis.blocks_claim(assessment, "static_endpoint_exhaustive"):
        return {
            "id": "evidence_visibility",
            "status": "pass",
            "reason": "static inputs were fully visible",
            "evidence_refs": [],
        }

    blind = sorted(
        src for src, info in (assessment.get("sources") or {}).items()
        if isinstance(info, dict)
        and info.get("visibility") not in (_vis.VIS_COMPLETE, _vis.VIS_UNKNOWN)
    )
    runtime_backed = [
        t for t in targets
        if isinstance(_mapping(t.get("runtime")).get("status"), str)
        and _mapping(t.get("runtime")).get("status") == CLOSURE_COMPLETE
    ]
    detail = f"static inputs not fully visible ({', '.join(blind) or 'unspecified'})"

    if runtime_backed and len(runtime_backed) == len(list(targets)):
        # 全部目标都有运行时唯一归因：这些目标本身不受静态盲区影响，只是「有没有漏掉别的目标」存疑。
        # 记 warn 不记 gap —— 不为一个穷尽性疑问把已坐实的动态证据降级。
        return {
            "id": "evidence_visibility",
            "status": "warn",
            "reason": (
                f"{detail}; all selected targets are runtime-attributed, so they stand, "
                "but the target set may be incomplete"
            ),
            "evidence_refs": [],
        }

    gaps.append(f"target set may be incomplete: {detail}")
    return {
        "id": "evidence_visibility",
        "status": "warn",
        "reason": f"{detail}; targets rely on static extraction",
        "evidence_refs": [],
    }


def evaluate_closure(
    report: Report,
    targets: Sequence[Mapping[str, object]],
    *,
    require_dynamic: bool | None,
    target_selection: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Calculate complete/partial/failed from explicit static, dynamic, and target gates."""
    checks: list[dict[str, object]] = []
    gaps: list[str] = []
    fatal = False

    if report.critical_failures or report.analysis_status == ANALYSIS_STATUS_FAILED:
        fatal = True
        checks.append(
            {
                "id": "static_health",
                "status": "fail",
                "reason": "critical static analysis failure",
                "evidence_refs": list(report.critical_failures),
            }
        )
        gaps.append("static analysis has critical failures")
    elif report.analysis_status != ANALYSIS_STATUS_COMPLETE:
        checks.append(
            {"id": "static_health", "status": "warn", "reason": "static analysis is partial", "evidence_refs": []}
        )
        gaps.append("static analysis is partial")
    else:
        checks.append(
            {"id": "static_health", "status": "pass", "reason": "static analysis completed", "evidence_refs": []}
        )

    dynamic_required = require_dynamic
    if dynamic_required is None:
        dynamic_required = bool(report.meta.get("runtime_merged") or _capture_meta(report))
    if dynamic_required:
        quality = evaluate_capture_quality(_capture_meta(report))
        dynamic_status = quality["dynamic_status"]
        check_status = "pass" if dynamic_status == CLOSURE_COMPLETE else "warn"
        if dynamic_status == CLOSURE_FAILED:
            check_status = "fail"
            fatal = True
        checks.append(
            {
                "id": "dynamic_evidence",
                "status": check_status,
                "reason": quality["reason"],
                "evidence_refs": [],
            }
        )
        if dynamic_status != CLOSURE_COMPLETE:
            gaps.append(str(quality["reason"]))
    else:
        checks.append(
            {
                "id": "dynamic_evidence",
                "status": "not_applicable",
                "reason": "dynamic evidence was not required",
                "evidence_refs": [],
            }
        )

    if not targets:
        fatal = True
        gaps.append("no investigation target selected")
    for target in targets:
        value = str(target.get("value", "target"))
        if target.get("status") != CLOSURE_COMPLETE:
            gaps.append(f"{value}: five-layer attribution is incomplete")
        origin = target.get("origin")
        if isinstance(origin, Mapping) and origin.get("required") is True and origin.get("status") != CLOSURE_COMPLETE:
            gaps.append(f"{value}: Origin is missing behind edge/CDN")
        sources = target.get("source_status")
        if isinstance(sources, Mapping):
            failed_sources = [
                str(name)
                for name, item in sources.items()
                if isinstance(item, Mapping)
                and (
                    item.get("status") == "failed"
                    or (
                        item.get("status") == "skipped"
                        and item.get("reason") != "active_mode_blocked"
                    )
                )
            ]
            if failed_sources:
                gaps.append(f"{value}: source lookup incomplete ({', '.join(sorted(failed_sources))})")

    checks.append(_visibility_check(report, targets, gaps))

    selection = _mapping(target_selection)
    truncated = _non_negative_int(selection.get("truncated"))
    if truncated > 0:
        dropped = selection.get("dropped")
        dropped_values = [str(value) for value in dropped] if isinstance(dropped, (list, tuple)) else []
        detail = f" ({', '.join(dropped_values)})" if dropped_values else ""
        gaps.append(
            f"investigation target list truncated: {truncated} advisable candidate(s) beyond "
            f"max_targets={_non_negative_int(selection.get('limit'))} not evaluated{detail}"
        )

    gaps = list(dict.fromkeys(gaps))
    if fatal:
        status = CLOSURE_FAILED
    elif gaps:
        status = CLOSURE_PARTIAL
    else:
        status = CLOSURE_COMPLETE
    return {
        "schema_version": "1.0",
        "status": status,
        "checks": checks,
        "targets": [dict(target) for target in targets],
        "source_summary": _source_summary(targets),
        "target_selection": dict(selection),
        "gaps": gaps,
        "next_actions": [f"Resolve closure gap: {gap}" for gap in gaps],
    }
