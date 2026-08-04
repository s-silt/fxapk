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

from apkscan.core import infra
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
META_WRITE_OWNER = "core.closure"
META_WRITE_KEYS = frozenset({
    "asset_scores", "closure", "control_chains", "network_attribution", "overseas_targets", "visibility",
})

logger = logging.getLogger(__name__)


def _update_target_leads(report: Report, targets: Sequence[Mapping[str, object]]) -> None:
    # ★两侧都走 infra.match_key（IP 剥 :port/proto）。此前这里用裸 .lower()，而选目标那侧
    #   早就剥了端口——于是一个 pcap 实测后端能被选成闭环目标、却在回写时匹配不上自己的 Lead，
    #   拿不到 where_to_request / evidence_to_obtain，连 [case-close] 状态都不落。
    by_key = {
        (str(target.get("kind")), infra.match_key(str(target.get("kind")), str(target.get("value")))): target
        for target in targets
    }
    marker = "[case-close]"
    for lead in report.leads:
        kind = "domain" if lead.category.value == "DOMAIN" else "ip" if lead.category.value == "IP" else ""
        if not kind:
            continue  # 非 DOMAIN/IP 线索：从不贴 case-close marker，不碰
        # 先清本线索所有旧 [case-close] 注记——含上一轮更大 max_targets 时给现已被截断/未选的 lead 写的陈旧状态
        # （codex 审计 P1-1 B 面：否则缩小上限后 dropped lead 会残留与本轮 closure 不一致的旧状态）。
        retained = [line for line in lead.notes.splitlines() if not line.startswith(marker)]
        target = by_key.get((kind, infra.match_key(kind, lead.value)))
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

    ★重算必须是**信息保持**的：先前记下的「确证盲区」不得因为原始信号不在 meta 里而消失。
    动态合并只会往 meta 里加信号，所以正常管线的重算总是等价或更强；但一份在工具体外被裁剪过
    的 report.json（手编、第三方产、人工"精简"）可能只剩快照。对它重算等于从零重推，加壳样本
    的 ``dex=stub_only`` 会退成"没有记录"，「目标集可能不全」的封顶随之凭空消失——这正是
    「未发现」被读成「已穷尽」。故重算后逐维做一次保守回填，见 :func:`_preserve_confirmed_gaps`。

    assess 自带兜底、绝不抛；此处再包一层，重算失败也不影响结案主流程。
    """
    if isinstance(report.meta, dict):
        refresh_visibility_snapshot(report.meta)


def refresh_visibility_snapshot(meta: dict) -> None:
    """在 ``meta`` 上**就地**重算 visibility 快照。逻辑与语义见 :func:`_refresh_visibility`。

    ★**任何往 report.json 写 meta 的路径都该调它**，不只结案。快照是派生视图：写方往 meta 里
      追加了新信号却不重算，报告就会自相矛盾——实测过一份「``runtime_merged=True``、23 个运行时
      端点、27 条活体确认线索，而快照仍写着『未做运行时观测（纯静态分析）』」的报告，因为
      ``pcap-leads --into`` 只写信号、没刷快照。**判据是对的，落盘的东西是旧的。**

    ★这类缺口测试很容易漏掉：既有测试断言的是 ``visibility.assess(payload)``（**现场重算**），
      判据永远正确，而产物永远陈旧，测试全绿。所以另有一条结构性测试直接比对
      「存下的快照 == 对该 payload 现场重算的结果」，将来新增的写方忘了刷新会被它照出来。
    """
    from apkscan.core import visibility as _visibility

    previous = meta.get("visibility")
    has_snapshot = isinstance(previous, dict)
    if not has_snapshot and not _visibility.input_keys_seen(meta):
        return
    try:
        fresh = _visibility.assess({"meta": meta})
        if has_snapshot:
            fresh = _preserve_confirmed_gaps(previous, fresh, meta)  # type: ignore[arg-type]
        meta["visibility"] = fresh
    except Exception:  # noqa: BLE001 - 重算失败不得中断调用方主流程
        logger.exception("[closure] 可见性重求值失败，沿用原快照")


def _preserve_confirmed_gaps(previous: dict, fresh: dict, meta: dict) -> dict:
    """某一维的原始信号已不在 meta 里时，沿用旧快照对该维的判定，并重推主张资格。

    ★判据是「**旧快照见过的输入是否仍全部在场**」，不是「新值是什么」。信号从不会自己消失：
      正常管线只往 meta 里加东西，动态合并更是如此。只要旧 ``inputs_seen`` 里的任一键不见了，
      就说明这份 report.json 在工具体外被裁剪过（手编 / 第三方产 / 人工"精简"）。此时对它
      重算不是刷新，是拿残缺输入重新推理——加壳样本的 ``dex=stub_only`` 会退成"完整可见"，
      「目标集可能不全」的封顶随之无声消失，正是「未发现」被读成「已穷尽」。

    只在旧值属**确证盲区**（``INSUFFICIENT``）时回填：那是本次分析实测到的缺口，丢了就是丢证据。
    旧值本就是 complete/unknown 的维度照常跟随重算——那里没有要保护的信息。

    新快照由 :func:`visibility.assess` 逐维记录 ``inputs_seen``。这里检查
    ``old_inputs - current_inputs``，而不只检查「当前是真子集」：删除旧键的同时新增另一个键，
    仍然发生了信息丢失，不能借新增键把旧盲区冲掉。合法升级只新增信号，旧集合必为当前集合子集。

    旧报告没有 ``inputs_seen`` 时无法可靠区分部分裁剪与合法新增，继续沿用旧兼容口径：
    该维输入全不在才回填。这样不会把历史 ``runtime=unavailable`` 快照冻结住，妨碍新增
    ``capture_quality`` 后的正常升级；完整保护需用当前版本重新分析生成带溯源的新快照。
    """
    from apkscan.core import visibility as _visibility

    old_sources = previous.get("sources")
    new_sources = fresh.get("sources")
    if not (isinstance(old_sources, dict) and isinstance(new_sources, dict)):
        return fresh

    restored = False
    restored_legacy_source = False
    for name, new_info in new_sources.items():
        old_info = old_sources.get(name)
        if not (isinstance(old_info, dict) and isinstance(new_info, dict)):
            continue
        if old_info.get("visibility") not in _visibility.INSUFFICIENT:
            continue
        old_seen_raw = old_info.get("inputs_seen")
        new_seen_raw = new_info.get("inputs_seen")
        if isinstance(old_seen_raw, list) and isinstance(new_seen_raw, list):
            old_seen = {str(key) for key in old_seen_raw}
            current_seen = {str(key) for key in new_seen_raw}
            should_restore = bool(old_seen - current_seen)
        else:
            # 旧 schema 无法识别「部分裁剪」；保留此前兼容行为，避免拦死合法 runtime 升级。
            should_restore = not _visibility.input_keys_seen(meta, name)
        if not should_restore:
            continue
        why = [str(w) for w in (old_info.get("why") or [])]
        marker = "★沿用先前快照：支撑该判定的原始信号已不在 meta 中（报告疑经裁剪）"
        if marker not in why:
            why.append(marker)
        new_sources[name] = {**old_info, "why": why}
        restored = True
        restored_legacy_source = restored_legacy_source or not isinstance(old_seen_raw, list)

    if restored:
        # 源回填后，主张、说明和补救动作都必须重推，否则机器字段与人读建议自相矛盾。
        fresh = _visibility.reassess_derived(fresh, meta)
        if restored_legacy_source:
            # 无 inputs_seen 的旧源无法满足 1.1 的逐维 provenance 契约，不能冒充新 schema。
            fresh["schema_version"] = "1.0"
    return fresh


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
    _sync_passive_dns_evidence(report, selected)
    return closure


def _sync_passive_dns_evidence(report: Report, endpoints: Sequence[object]) -> None:
    """把结案期富化拿到的被动 DNS 历史补进对应线索的取证要项。

    ★为什么单开这一步：线索是在 ``analyze`` 阶段建的，那时富化已经跑过，历史落点顺着
    ``build_endpoint_leads`` 自然进了线索。但结案会**再富化一轮**（选中的目标、常常是首次联网），
    这一轮的产物只落在 ``endpoint.enrichment`` 里——:func:`_update_target_leads` 只回写
    ``where_to_request`` 与五层证据字段，不重算这条。不补这一步，联网结案拿到的历史落点
    就停在报告的 endpoints 段里，进不了文书。

    只补 ``evidence_to_obtain``（文书渲染读它）；幂等，重复结案不会堆重复行。绝不抛。
    """
    from apkscan.core.leads import _passive_dns_note

    by_key = {}
    for endpoint in endpoints:
        kind = str(getattr(endpoint, "kind", ""))
        if kind not in ("domain", "ip"):
            continue
        try:
            note = _passive_dns_note(getattr(endpoint, "enrichment", {}) or {})
        except Exception:  # noqa: BLE001 — 补注记失败不得让结案失败
            logger.debug("被动 DNS 注记生成失败：%s", getattr(endpoint, "value", "?"), exc_info=True)
            continue
        if note:
            by_key[(kind, infra.match_key(kind, str(getattr(endpoint, "value", ""))))] = note

    if not by_key:
        return
    for lead in report.leads:
        kind = "domain" if lead.category.value == "DOMAIN" else "ip" if lead.category.value == "IP" else ""
        if not kind:
            continue
        note = by_key.get((kind, infra.match_key(kind, lead.value)))
        # 旧注记按前缀清掉再写：历史落点会随富化更新，留着两版会让人不知道该信哪个。
        if note is None:
            continue
        lead.evidence_to_obtain[:] = [
            line for line in lead.evidence_to_obtain if not str(line).startswith("历史解析（被动 DNS")
        ]
        lead.evidence_to_obtain.append(note)


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
