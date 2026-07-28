"""Deterministic case-closure gates over static, runtime, and attribution evidence."""

# closure 原为单文件模块（apkscan/core/closure.py），按职责拆为包：
#   _shared —— 共享常量 / ClosureConfig / _mapping（无包内依赖的底座，杜绝循环导入）
#   targets —— 目标选择与排序（含 FOFA 命名行解析、runtime 信号读取）
#   layers  —— 五层组装（单目标 + 域名逐 IP 聚合）
#   sources —— 富化源判定与解析 IP 逐 IP 富化（唯一改写 enrichment 的一侧）
#   gates   —— 验收（采集质量门 + 总闭环判定）
# 主流程 close_report 与派生视图刷新留在本文件；下方 re-export 保留原模块**自己定义**的属性面
# （含下划线内部名），既有 `from apkscan.core.closure import X` / `closure_module._x` 用法不变。
#
# ★两处有意的不兼容，别当遗漏补回来：
#   1) 原模块"顺带导入"的名字（os / ipaddress / Counter / dataclass / Any / Endpoint /
#      ANALYSIS_* 等）不再从包可见。它们本就不是本模块的 API——从别人模块借 import 是坏习惯，
#      补回来等于把它固化成契约。实测全仓零处这样用。
#   2) 包级 monkeypatch 的语义变了：拆分前 patch 包属性能改到所有调用点（同一个模块全局），
#      现在子模块内部的互调看的是子模块自己的命名空间。这是拆包的必然后果，无法靠 re-export
#      消除（re-export 只是静态对象绑定）。故本次重构的准确说法是「生产代码路径行为不变」，
#      而非笼统的「零行为改变」——打桩语义确实变了，见下方分类。
# ★ monkeypatch 打哪里：**分两类，方向相反**。打错一边不会报错，只是 patch 静默失效——
#   测试照样绿却已经不测原来那件事，比拆崩更难发现（崩了看得见）。判据是「谁在调用它」：
#
#   1) 被本文件的 close_report 直接调用的 —— patch **包**（apkscan.core.closure.<名>）。
#      本文件把它们 from-import 进了自己的命名空间，调用时按本模块全局名解析，
#      patch 子模块属性改不到这里。属此类：_select_targets_with_stats、assemble_target_closure、
#      _ensure_source_status_coverage、_enrich_resolved_ips、_set_attribution、evaluate_closure。
#
#   2) 只在子模块内部被互相调用的 —— patch **定义它的子模块**（如 closure.sources.<名>）。
#      调用点在子模块自己的命名空间里，patch 包属性够不着。属此类：_normalized_public_ip、
#      _resolved_ips、_is_known_intercept_ip、_normalize_source_status、_runtime_info、
#      evaluate_capture_quality。
#
#   拿不准就现场验：patch 后把替身换成会让断言必然失败的值，跑一遍确认测试**真的会红**。
#   光看绿不算数——那正是静默失效的表现。

from __future__ import annotations

import logging
from typing import Mapping, Sequence

from apkscan.core.models import Report

from apkscan.core.closure._shared import (
    CLOSURE_COMPLETE as CLOSURE_COMPLETE,
    CLOSURE_FAILED as CLOSURE_FAILED,
    CLOSURE_PARTIAL as CLOSURE_PARTIAL,
    LAYER_NAMES as LAYER_NAMES,
    SOURCE_STATUSES as SOURCE_STATUSES,
    ClosureConfig as ClosureConfig,
    _mapping as _mapping,
)
from apkscan.core.closure.gates import (
    _capture_meta as _capture_meta,
    _non_negative_int as _non_negative_int,
    _source_summary as _source_summary,
    _visibility_check as _visibility_check,
    evaluate_capture_quality as evaluate_capture_quality,
    evaluate_closure as evaluate_closure,
)
from apkscan.core.closure.layers import (
    _aggregate_layer as _aggregate_layer,
    _aggregate_source_status as _aggregate_source_status,
    _attribution_for_endpoint as _attribution_for_endpoint,
    _bgp_layer as _bgp_layer,
    _edge_provider as _edge_provider,
    _hosting_layer as _hosting_layer,
    _layer as _layer,
    _normalize_source_status as _normalize_source_status,
    _origin_status as _origin_status,
    _passive_hosting_evidence as _passive_hosting_evidence,
    _registration_layer as _registration_layer,
    _request_layer as _request_layer,
    _runtime_layer as _runtime_layer,
    _single_target_closure as _single_target_closure,
    assemble_target_closure as assemble_target_closure,
)
from apkscan.core.closure.sources import (
    _MAX_RESOLVED_IPS_PER_TARGET as _MAX_RESOLVED_IPS_PER_TARGET,
    _enrich_resolved_ips as _enrich_resolved_ips,
    _enrichers_to_run as _enrichers_to_run,
    _ensure_source_status_coverage as _ensure_source_status_coverage,
    _is_known_intercept_ip as _is_known_intercept_ip,
    _normalized_public_ip as _normalized_public_ip,
    _resolved_ips as _resolved_ips,
    _set_attribution as _set_attribution,
    _source_is_configured as _source_is_configured,
    _source_is_terminal as _source_is_terminal,
)
from apkscan.core.closure.targets import (
    _FOFA_FIELDS as _FOFA_FIELDS,
    _parse_fofa_row as _parse_fofa_row,
    _runtime_info as _runtime_info,
    _select_targets_with_stats as _select_targets_with_stats,
    _target_rank as _target_rank,
    select_targets as select_targets,
)

# 原单文件模块的 module-level logger：保持 ``closure.logger`` 属性面与 logger 名不变
# （真正使用它的 _parse_fofa_row 已随迁 targets.py，用各自模块的 child logger）。
logger = logging.getLogger(__name__)


def _update_target_leads(report: Report, targets: Sequence[Mapping[str, object]]) -> None:
    by_key = {(str(target.get("kind")), str(target.get("value")).lower()): target for target in targets}
    marker = "[case-close]"
    for lead in report.leads:
        kind = "domain" if lead.category.value == "DOMAIN" else "ip" if lead.category.value == "IP" else ""
        if not kind:
            continue  # 非 DOMAIN/IP 线索：从不贴 case-close marker，不碰
        # 先清本线索所有旧 [case-close] 注记——含上一轮更大 max_targets 时给现已被截断/未选的 lead 写的陈旧状态
        # （codex 审计 P1-1 B 面：否则缩小上限后 dropped lead 会残留与本轮 closure 不一致的旧状态）。
        retained = [line for line in lead.notes.splitlines() if not line.startswith(marker)]
        target = by_key.get((kind, lead.value.lower()))
        if target is None:
            lead.notes = "\n".join(line for line in retained if line).strip()  # 本轮未评估：只清旧 marker
            continue
        layers = target.get("layers")
        request = layers.get("request_target") if isinstance(layers, Mapping) else None
        evidence = request.get("evidence") if isinstance(request, Mapping) else None
        if isinstance(evidence, Mapping):
            provider = evidence.get("provider")
            if provider:
                lead.where_to_request = str(provider)
            fields = evidence.get("evidence_fields")
            if isinstance(fields, list):
                for field in fields:
                    text = str(field)
                    if text and text not in lead.evidence_to_obtain:
                        lead.evidence_to_obtain.append(text)
        raw_gaps = target.get("gaps")
        gaps = [str(gap) for gap in raw_gaps] if isinstance(raw_gaps, list) else []
        summary = f"{marker} status={target.get('status')}; gaps={','.join(gaps) or 'none'}"
        retained.append(summary)
        lead.notes = "\n".join(line for line in retained if line).strip()


#: 会影响可见性判定的原始信号键。旧报告（分析于 visibility 层落地之前）虽无 ``visibility``
#: 快照，但这些键早已在 meta 里——据此可补算，不必重跑分析。
_VISIBILITY_INPUT_KEYS: tuple[str, ...] = (
    "dex_available", "dex_scanned", "dex_strings_truncated", "dex_string_pool",
    "is_hardened", "hardening_structural", "extra_dex_visibility",
    "native_obfuscation", "artifact_lineage",
    "uni_encrypted", "crypto_recipe", "resource_files_scanned",
    "resource_files_read_failed", "resource_listing_failed",
    "runtime_merged", "capture_quality", "capture_signals",
)


def _refresh_visibility(report: Report) -> None:
    """结案前重算证据可见性 —— 快照是派生视图，不是证据。

    三档，逐档保守：

    - **已有快照** → 无条件重算。分析期算完之后，动态合并还会往 meta 里写
      ``runtime_merged`` / ``capture_quality``；不重算就会出现「已成功抓包，
      报告却说未做运行时观测、建议去抓包」。重算幂等。
    - **无快照但有原始信号** → 补算。否则存量加壳报告会从 gates 的 ``not_applicable``
      分支旁路而过，拿到 complete —— 加壳样本本该触发的「目标集可能不全」封顶完全落空。
    - **连信号键都没有** → 不写。「没有信号」不等于「已确认完整」，凭空造一份
      ``dex=complete`` 的快照正是本层要防的那类误读；留给 gates 的 not_applicable 兜底。

    assess 自带兜底、绝不抛；此处再包一层，重算失败也不影响结案主流程。
    """
    from apkscan.core import visibility as _visibility

    meta = report.meta if isinstance(report.meta, dict) else {}
    has_snapshot = isinstance(meta.get("visibility"), dict)
    if not has_snapshot and not any(k in meta for k in _VISIBILITY_INPUT_KEYS):
        return
    try:
        report.meta["visibility"] = _visibility.assess({"meta": meta})
    except Exception:  # noqa: BLE001 - 重算失败不得中断结案
        logger.exception("[closure] 可见性重求值失败，沿用原快照")


def close_report(
    report: Report,
    config: ClosureConfig,
    *,
    enrichers: Sequence[object] | None = None,
) -> dict[str, object]:
    """Run bounded re-enrichment, five-layer assembly, and write ``meta.closure``."""
    # 见 _refresh_visibility 的说明：结案前必须让可见性视图与 meta 现状一致。
    from apkscan.core.enrichment import enrich_selected_targets
    from apkscan.core.registry import discover_enrichers

    selected, target_selection = _select_targets_with_stats(report, config.max_targets)
    available = list(enrichers) if enrichers is not None else list(discover_enrichers())
    typed_enrichers = [enricher for enricher in available if hasattr(enricher, "enrich")]
    for endpoint in selected:
        pending = _enrichers_to_run(
            endpoint,
            typed_enrichers,
            mode=config.mode,
            refresh=config.refresh,
        )
        if config.online and pending:
            enrich_selected_targets(
                [endpoint],
                pending,  # type: ignore[arg-type]
                mode=config.mode,
                include_case_close=True,
            )
        _ensure_source_status_coverage(endpoint, typed_enrichers, config)
        if endpoint.kind == "domain":
            _enrich_resolved_ips(endpoint, typed_enrichers, config)
        # 顶层归因在逐 IP 富化之后再建，才能吸收 resolved_ip_enrichment（P1-3：否则文书/摘要读顶层恒 unknown）。
        _set_attribution(endpoint)

    _refresh_visibility(report)
    targets = [assemble_target_closure(endpoint) for endpoint in selected]
    closure = evaluate_closure(
        report, targets, require_dynamic=config.require_dynamic, target_selection=target_selection
    )
    report.meta["closure"] = closure
    _refresh_derived_views(report, online=config.online)
    _update_target_leads(report, targets)
    return closure


def _populate_network_attribution(report: Report) -> None:
    """Assemble the additive network_attribution view from the (now refreshed) endpoint
    facts. View-only, passive; its own guard so it never sinks case closure nor mutates
    the returned closure. On failure a minimal deterministic error marker is recorded."""
    import logging

    try:
        from apkscan.attribution.assemble import build_network_attribution

        artifact_id = str(report.meta.get("sample_sha256") or "") or f"pkg:{report.package_name or 'unknown'}"
        blob = build_network_attribution(report.endpoints, artifact_id=artifact_id, phase="close")
        if blob is not None:
            report.meta["network_attribution"] = blob
    except Exception as exc:  # noqa: BLE001 - view-only; a failure never fails case closure
        logging.getLogger(__name__).warning("network_attribution 组装失败：%s", type(exc).__name__)
        # close 期重组失败不得覆盖 analyze 期已有的有效视图——保留旧视图、只在其上附 close_error；
        # 无旧视图才写纯错误标记（否则会损失展示证据，见 codex 审计 P2）。
        existing = report.meta.get("network_attribution")
        if isinstance(existing, dict):
            existing["close_error"] = type(exc).__name__
        else:
            report.meta["network_attribution"] = {"phase": "close", "error": type(exc).__name__}


def _refresh_derived_views(report: Report, *, online: bool) -> None:
    """close 重建选中端点 attribution 后，重跑依赖 attribution 的派生视图——否则它们停留在 analyze 期而陈旧
    （codex 审计"已知边界"）。全 view-only、各自 try/except、绝不 sink closure；空产物不覆盖既有有效视图。"""
    import logging

    log = logging.getLogger(__name__)
    # ① fronting-cluster：close 的单端点 _set_attribution 重建冲掉了 analyze 期写进端点 edge_provider 的
    #   cluster_id，须对全报告重聚类恢复（codex 具体点名的 correctness 回归）。
    try:
        from apkscan.core.attribution import cluster_fronting

        all_ips = [
            ipv
            for ep in report.endpoints
            for ipv in ((ep.enrichment.get("attribution") or {}).get("ips") or [])
            if isinstance(ipv, dict)
        ]
        cluster_fronting(all_ips)
    except Exception:  # noqa: BLE001 — 聚类失败不得拖累 closure
        log.debug("[closure] close 后 fronting-cluster 重聚类失败，跳过", exc_info=True)
    # ② network_attribution（沿用既有逻辑，含失败保留旧视图）。
    _populate_network_attribution(report)
    # ③ control_chains（远程配置对象→配方→解码→后端→五层归因；仅非空才覆盖，空不清既有）。
    try:
        from apkscan.config.chain import build_control_chains

        chains = build_control_chains(
            report.meta.get("remote_config_artifacts"), report.meta.get("crypto_recipe"), report.endpoints
        )
        if chains:
            report.meta["control_chains"] = chains
    except Exception:  # noqa: BLE001
        log.debug("[closure] close 后 control_chains 刷新失败，跳过", exc_info=True)
    # ④ asset_scores（后端资产按分排序；仅非空才覆盖）。
    try:
        from apkscan.config.asset_score import rank_assets

        scores = rank_assets(report.endpoints)
        if scores:
            report.meta["asset_scores"] = [
                {"value": s.value, "kind": s.kind, "score": s.score, "reasons": list(s.reasons)} for s in scores
            ]
    except Exception:  # noqa: BLE001
        log.debug("[closure] close 后 asset_scores 刷新失败，跳过", exc_info=True)
    # ⑤ overseas_targets（境外被动定位结构化；与 analyze 期同门控——仅联网富化后有内容）。
    if online:
        try:
            from apkscan.core.leads import _build_overseas_targets

            report.meta["overseas_targets"] = _build_overseas_targets(report.endpoints)
        except Exception:  # noqa: BLE001
            log.debug("[closure] close 后 overseas_targets 刷新失败，跳过", exc_info=True)


__all__ = [
    "CLOSURE_COMPLETE",
    "CLOSURE_FAILED",
    "CLOSURE_PARTIAL",
    "LAYER_NAMES",
    "SOURCE_STATUSES",
    "ClosureConfig",
    "assemble_target_closure",
    "close_report",
    "evaluate_capture_quality",
    "evaluate_closure",
    "select_targets",
]
