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
from apkscan.core.runtime_inventory import derive_capture_quality, read_inventory


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
    #   而闭环 complete 的含义正是"拿到了真实通信去向"。实测多份真样本上，目标 UID 只向公共解析器
    #   发过 DNS query（入站 0B），却被判 complete —— 人工结论是动态未闭环。
    # ★字段缺失（老 runtime_report / 未提供该统计）时按 0 处理，即 fail-closed 降级为 partial：
    #   宁可把已闭环说成未闭环（多跑一次采集），不可把未闭环说成已闭环（据以结案）。
    bidirectional_count = _non_negative_int(raw.get("bidirectional_business_count"))
    # ★★ 归因与双向必须落在**同一个端点**上。分别判断两个汇总值 > 0 是不够的：
    #    代理是整机级的，于是「目标 App 有个单向端点 A」＋「无关背景端点 B 有完整往返」
    #    会让两个计数各自 > 0，凑出一个目标 App 其实从未收到过应答的 complete。
    #    capture 侧因此单列 bidirectional_target_count（floor 侧已归因且 established +
    #    mitm 侧能对上已归因端点的），门控只认它。
    target_bidirectional = _non_negative_int(raw.get("bidirectional_target_count"))
    if not target_bidirectional:
        # 兼容早于该字段的 runtime_report：floor 侧计数的口径本就是「归因到目标 **且**
        # 双向有载荷」，即同一端点上两个条件都成立，与新字段语义一致，可安全回退。
        # 注意**不能**回退到 bidirectional_business_count——那个含未归因的 mitm 端点，
        # 正是本次要堵的洞；两者都缺时按 0 → partial（fail-closed）。
        target_bidirectional = _non_negative_int(raw.get("bidirectional_floor_count"))

    # ★P0-a：行为修改 shim 注入轮（modified-runtime）的观测是**被我方诱导**出来的，不得据以主张
    #   「已掌握运行时实连去向」。封顶 PARTIAL——否则本门产出的 complete 会与端点侧的 runtime-modified
    #   降钉、报告告警自相矛盾（机器可读字段与证据档位打架），且本门确实参与总闭环 checks。
    modified_runtime = str(raw.get("runtime_variant") or "") == "modified-runtime"
    # ★P0-c：运行 APK 身份不可确认（装原包失败——最常见是此前旁路轮的去壳重打包版仍在设备上），
    #   则这一轮抓到的流量**未必出自本次要分析的样本**。它与 modified-runtime 同样不足以独立结案：
    #   只标注不门控是无效的——机器消费方只读这里，HTML 告警约束不了它们。
    identity_unconfirmed = str(raw.get("capture_apk_identity_which") or "") == "unknown"
    if identity_unconfirmed and target_count > 0 and business_count > 0:
        status = CLOSURE_PARTIAL
        reason = (
            "running APK identity unconfirmed (install of the original APK failed; a leftover "
            "repackaged build may still be on the device); evidence cannot be attributed to this sample"
        )
    elif modified_runtime and target_count > 0 and business_count > 0:
        status = CLOSURE_PARTIAL
        reason = (
            "runtime evidence captured under behavior-modification shim (modified-runtime); "
            "induced observation cannot independently establish a reached backend"
        )
    elif target_count > 0 and business_count > 0 and target_bidirectional > 0:
        status = CLOSURE_COMPLETE
        reason = "target-attributed endpoint observed with bidirectional payload on that same endpoint"
    elif target_count > 0 and business_count > 0 and bidirectional_count > 0:
        # 有双向载荷，但它不属于任何一个归因到目标 App 的端点——多半是整机代理抓到的旁人流量。
        status = CLOSURE_PARTIAL
        reason = (
            "bidirectional payload present but not on a target-attributed endpoint "
            "(the proxy captures whole-device traffic); attribution and bidirectionality "
            "must hold on the same endpoint"
        )
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
        # 门控实际消费的那个计数要出现在结果里——否则读报告的人看到 complete/partial
        # 却查不到判据（信号必须接线：gate 消费 + 报告可见）。
        "bidirectional_target_count": target_bidirectional,
        "bidirectional_business_count": bidirectional_count,
        # 分侧计数原样透传：双向证据来自 floor 实测还是 mitm 代理，读报告的人要分得清。
        "bidirectional_floor_count": _non_negative_int(raw.get("bidirectional_floor_count")),
        "bidirectional_mitm_count": _non_negative_int(raw.get("bidirectional_mitm_count")),
        "bidirectional_mitm_attributed_count": _non_negative_int(
            raw.get("bidirectional_mitm_attributed_count")
        ),
        # 因基础设施判据被排除的对端数（公共解析器上的 DNS 等）。单列出来，
        # 免得"排除了噪音"与"本来就没流量"在读报告时长得一样。
        "infrastructure_excluded_count": _non_negative_int(raw.get("infrastructure_excluded_count")),
        # ★P0-a：variant 必须原样透传进结果——闭环门读的是 report.meta['capture_quality']（即本返回体），
        #   不透传则二次求值时判据丢失、modified 封顶守卫成为空接线（信号必须接线：gate 消费 + 报告可见）。
        "runtime_variant": str(raw.get("runtime_variant") or "original-runtime"),
        # 同理透传身份判据：闭环门读的是 report.meta['capture_quality']（即本返回体），不透传则
        # 二次求值时"身份不可确认"这一档丢失、守卫成空接线。
        "capture_apk_identity_which": str(raw.get("capture_apk_identity_which") or "original"),
        "dynamic_status": status,
        "reason": reason,
        "floor_parse_status": floor_parse_status,
    }


def _capture_meta(report: Report) -> dict[str, Any]:
    """取采集质量输入：优先真采集（floor/mitm），其次从运行时回灌清单派生。

    ★为什么要有回灌这一路：只走 ``pcap-leads`` / ``probe-leads`` 回灌的报告没有
      ``capture_quality``（那是 floor/mitm 真采集才写的），于是这里返回 ``{}`` →
      ``business_count=0`` → 动态闭环判 **failed**。而实际上报告里明明有已观测的业务候选
      端点，正确结论是 **partial**（观测到了去向，只是做不了唯一归因）。
      回灌清单此前**没有任何生产消费方**，这个函数就是那个消费方。

    ★顺序不能反：真采集的统计口径更完整（含双向载荷、UID 归因），有它就不该被回灌的
      派生值覆盖。回灌只在真采集缺位时兜底，且 :func:`derive_capture_quality` 保证
      ``target_attributed_count=0``、不补 ``bidirectional_*`` —— 上限 partial，绝不抬成 complete。
    """
    for key in ("capture_quality", "runtime_capture_quality", "capture_signals"):
        value = report.meta.get(key)
        if isinstance(value, Mapping):
            return dict(value)
    return dict(derive_capture_quality(read_inventory(report.meta)))


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

    # ★只看 static_endpoint_exhaustive **这条主张实际依赖的**源，不要全局扫。
    #   全局扫会把 runtime=unavailable（纯静态分析的正常状态、与静态穷尽性无关）
    #   也算成"静态盲区"，于是每份没跑动态的报告都被记 gap 封顶 partial——
    #   与本函数开头声明的「按主张相关性，不是全局封顶」相悖。
    # 「确证不可见」与「未评估」再分开：都不足以支撑穷尽性主张，
    #   但只有前者是本次分析实测到的缺口，该把闭环封顶 partial。
    _claim = _mapping((assessment.get("claims") or {}).get("static_endpoint_exhaustive"))
    blind = sorted(str(s) for s in (_claim.get("missing_sources") or []))
    unassessed = sorted(str(s) for s in (_claim.get("unassessed_sources") or []))
    if not blind:
        # 仅因某一维从未评估而被阻：如实说明，但不为此把整份报告降级——
        # 与上面「目标全由运行时归因」那条豁免同构。★但也**不能**再说
        # "static inputs were fully visible"：那对一个没评估过的维度是错误陈述。
        return {
            "id": "evidence_visibility",
            "status": "warn",
            "reason": (
                f"static inputs not assessed for: {', '.join(unassessed) or 'unspecified'}; "
                "exhaustiveness claims withheld, but no confirmed blind spot"
            ),
            "evidence_refs": [],
        }
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
