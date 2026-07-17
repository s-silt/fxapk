"""分析流水线：跑分析器 → 富化端点 → 聚合 → 生成 Lead → 组装 Report。

错误处理铁律：单分析器/富化器异常一律 try/except 记录到结果 + logging.exception，
绝不裸 pass、绝不让单点故障中断整条流水线。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING


from apkscan.analyzers.classify import classify_app
from apkscan.core import infra
from apkscan.core.attribution import build_endpoint_attribution
from apkscan.core.models import (
    ANALYSIS_MODE_AUTHORIZED_ACTIVE,
    ANALYSIS_MODE_PASSIVE,
    ANALYSIS_STATUS_COMPLETE,
    ANALYSIS_STATUS_FAILED,
    ANALYSIS_STATUS_PARTIAL,
    AnalysisConfig,
    Endpoint,
    Evidence,
    Report,
)
from apkscan.core.registry import (
    detect_capabilities,
    discover_analyzers,
    discover_enrichers,
    ruleset_digest,
)

# 端点 → Lead 生成已物理拆到 apkscan/core/leads.py（纯搬移）；在此 re-export 供 stage 调用，
# 并保持既有 `pipeline.build_endpoint_leads` 等测试访问路径不变。
from apkscan.core.leads import (
    _apply_default_advice,
    _build_overseas_targets,
    build_endpoint_leads,
)

# 联网富化执行已物理拆到 apkscan/core/enrichment.py（纯搬移）；在此 re-export 供 _stage_enrich 调用，
# 并保持既有 `pipeline._run_enrichment` / `pipeline.ENRICH_MAX_WORKERS` 等测试访问路径不变。
from apkscan.core.enrichment import (
    ENRICH_MAX_WORKERS,  # noqa: F401 — re-export：保 pipeline.ENRICH_MAX_WORKERS 测试访问路径
    _enrich_endpoints,  # noqa: F401 — re-export：保 pipeline._enrich_endpoints 测试访问路径
    _enrichment_targets,
    _mode_gate,  # noqa: F401 - compatibility re-export
    _run_enrichment,  # noqa: F401 - compatibility re-export
    enrich_selected_targets,
)

# 分析器进程池并行 + 内存封顶决策已物理拆到 apkscan/core/parallel.py（纯搬移）；_stage_run_analyzers
# 经 _analyze_eligible 调用本簇。并行/内存机器的 monkeypatch 测试现打补丁到 parallel.* 命名空间。
from apkscan.core.parallel import _analyze_eligible

if TYPE_CHECKING:
    from collections.abc import Callable

    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)



#: **关键**分析器：其失败即报告核心不可信（身份 + 网络调证线索）。--strict 据此非零退出。
#: 保守取最小集——manifest（包名/权限/SDK/加固）与 endpoints（域名/IP 调证线索的核心提取）；
#: 其余是特性分析器，失败只降级、不使整份报告无效。按需增删。
_CRITICAL_ANALYZERS: frozenset[str] = frozenset({"manifest", "endpoints"})


def _tool_version() -> str:
    """当前 fxapk 版本（写进 report.meta，供审计 / 可复现）。取不到 → "unknown"（不抛）。"""
    try:
        from apkscan import __version__

        return __version__
    except Exception:  # noqa: BLE001 — 版本读取绝不得影响主流程
        logger.debug("读取 __version__ 失败", exc_info=True)
        return "unknown"


def _analysis_health(analyzer_status: list[dict]) -> tuple[str, float, list[str], list[str]]:
    """据 analyzer_status 聚合分析完整度，返回 (status, completeness, critical_failures, skipped)。

    - completeness = 成功跑完 ÷ (成功 + 报错)（能力/平台跳过的**不计入分母**——环境门控非故障，
      否则装了越多可选工具分母越大、completeness 越低，误导）。无任何可跑分析器 → 1.0。
    - status：无报错=complete；有报错但仍有成功=partial；有报错且零成功=failed。
    - critical_failures：报错分析器 ∩ _CRITICAL_ANALYZERS。
    - skipped：被跳过的分析器名（仅信息性）。
    """
    errored = [s.get("name", "") for s in analyzer_status if s.get("status") == "error"]
    ran = [s.get("name", "") for s in analyzer_status if s.get("status") == "ran"]
    skipped = [s.get("name", "") for s in analyzer_status if s.get("status") == "skipped"]
    eligible = len(ran) + len(errored)
    completeness = 1.0 if eligible == 0 else round(len(ran) / eligible, 4)
    if not errored:
        status = ANALYSIS_STATUS_COMPLETE
    elif ran:
        status = ANALYSIS_STATUS_PARTIAL
    else:
        status = ANALYSIS_STATUS_FAILED
    critical = sorted(n for n in errored if n in _CRITICAL_ANALYZERS)
    return status, completeness, critical, skipped


@dataclass
class _PipelineState:
    """一次 pipeline 运行的可变累积态：各 ``_stage_*`` 就地读写，run() 末尾据此组装 Report。

    引入它是为把原先 run() 里一长串内联阶段拆成命名清晰的 stage 函数（**纯结构、行为逐字不变**），
    让阶段边界显式、并为后续「每阶段状态/指标/超时」留骨架。字段与 Report 的对应产出一一对应。
    """

    ctx: "AnalysisContext"
    config: AnalysisConfig
    platform: str
    capabilities: set[str]
    meta: dict = field(default_factory=dict)
    leads: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    analyzer_status: list[dict] = field(default_factory=list)
    enricher_status: list[dict] = field(default_factory=list)
    #: 每个 pipeline 阶段的执行状态：{name, status: ran|error, error?}。阶段级故障不中断流水线
    #: （延续「绝不让单点故障中断整条流水线」到阶段粒度），记于此供报告审计 + 反馈 analysis_status。
    stage_status: list[dict] = field(default_factory=list)
    analysis_status: str = ANALYSIS_STATUS_COMPLETE
    completeness: float = 1.0
    critical_failures: list = field(default_factory=list)
    skipped_analyzers: list = field(default_factory=list)


def _canonicalize_ctx_config(ctx: "AnalysisContext", config: AnalysisConfig) -> None:
    """规范化「有效配置」为单一来源：分析器读 ``ctx.config``，而 pipeline 门控 / 报告标注读 ``config``
    参数——二者本应同一对象（load_app 传入同一 config），但程序化调用方可能传入不一致的两个，导致
    分析器的主动探测门控（如 contacts getMe 读 ctx.config.mode）与报告标注的 mode 分叉，出现「报告
    标 passive 但分析器按 authorized-active 主动探测」的错配。以 pipeline 的 config 为准对齐 ctx。"""
    if getattr(ctx, "config", None) is not config:
        try:
            ctx.config = config  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 — 只读上下文兜底：无法对齐则不阻断，仅记 debug
            logger.debug("无法规范化 ctx.config（只读上下文？）", exc_info=True)


def _init_pipeline_state(ctx: "AnalysisContext", config: AnalysisConfig) -> _PipelineState:
    """探测能力 + 平台并播种 meta，返回初始累积态。

    平台能力：让 requires=["apk"] 的 Android 专属 analyzer 在 IPA 上自动 skipped、requires=["ipa"]
    的 iOS analyzer 在 APK 上 skipped（复用既有 requires 门控）。meta 播种 package_name/platform +
    网络模式留痕（passive / authorized-active，供报告审计声明是否纯被动）。"""
    capabilities = detect_capabilities(online=config.online)
    platform = getattr(ctx, "platform", "android")
    capabilities.add("apk" if platform == "android" else "ipa")
    meta: dict = {"package_name": ctx.package_name, "platform": platform}
    meta["mode"] = getattr(config, "mode", ANALYSIS_MODE_PASSIVE)
    return _PipelineState(
        ctx=ctx, config=config, platform=platform, capabilities=capabilities, meta=meta
    )


def _stage_run_analyzers(state: _PipelineState) -> None:
    """跑分析器（android 多核走进程池并行，否则串行；按 requires 门控）→ **按发现顺序聚合**
    endpoints/leads/findings/meta + 记 status + finding 溯源盖章 → 端点按 value 去重。

    去重必须在富化与 build_endpoint_leads 之前，避免重复 DOMAIN/IP Lead 与重复富化查询。
    """
    ctx = state.ctx
    capabilities = state.capabilities
    meta = state.meta
    discovered = discover_analyzers()
    eligible: list[tuple[str, object]] = []  # (name, analyzer)，requires 已满足，发现顺序
    for analyzer in discovered:
        name = getattr(analyzer, "name", "") or analyzer.__class__.__name__
        missing = [cap for cap in (getattr(analyzer, "requires", []) or []) if cap not in capabilities]
        if not missing:
            eligible.append((name, analyzer))

    # 执行（并行或串行），得 name → (result, error)。
    results_map = {
        name: (result, error) for name, result, error in _analyze_eligible(ctx, eligible)
    }

    # 按发现顺序聚合 + 记 status（与串行行为一致）。
    for analyzer in discovered:
        name = getattr(analyzer, "name", "") or analyzer.__class__.__name__
        requires = list(getattr(analyzer, "requires", []) or [])
        missing = [cap for cap in requires if cap not in capabilities]
        if missing:
            reason = f"缺少能力：{', '.join(missing)}"
            logger.info("跳过分析器 %s：%s", name, reason)
            state.analyzer_status.append({"name": name, "status": "skipped", "reason": reason})
            continue

        result, error = results_map.get(name, (None, "分析器未返回结果"))
        if error is not None:
            logger.warning("分析器执行异常：%s（%s）", name, error)
            state.analyzer_status.append({"name": name, "status": "error", "reason": error})
            continue
        if result is None:
            logger.warning("分析器 %s 返回 None，按空结果处理", name)
            state.analyzer_status.append(
                {"name": name, "status": "error", "reason": "analyze 返回 None"}
            )
            continue

        state.endpoints.extend(result.endpoints)
        state.leads.extend(result.leads)
        # 溯源：集中给每条 finding 盖上产出它的分析器名（此处 analyzer 归属仍在；一旦 extend 进
        # report.findings 就丢了）。分析器已自标更细来源的不覆盖。
        for finding in result.findings:
            if not finding.analyzer:
                finding.analyzer = name
        state.findings.extend(result.findings)
        if result.meta:
            # 同名 meta key 冲突时记 warning，避免后跑分析器静默覆盖前者的结果。
            for k, v in result.meta.items():
                if k in meta and meta[k] != v:
                    logger.warning(
                        "meta key 冲突，分析器 %s 覆盖了 %r：%r → %r", name, k, meta[k], v
                    )
            meta.update(result.meta)

        if result.error:
            logger.warning("分析器 %s 自报错误：%s", name, result.error)
            state.analyzer_status.append(
                {"name": name, "status": "error", "reason": result.error}
            )
        else:
            state.analyzer_status.append({"name": name, "status": "ran", "reason": ""})

    # 端点按 value 去重合并（不同分析器可能产出同一 value 的 Endpoint）。
    state.endpoints = _dedup_endpoints(state.endpoints)


def _stage_degradation_flags(state: _PipelineState) -> None:
    """把上下文的降级标志显式带入 meta，避免"未采集"被静默当成"采集为空"。"""
    ctx = state.ctx
    meta = state.meta
    if getattr(ctx, "dex_available", True) is False:
        if state.platform == "ios":
            # iOS 本就无 DEX，不是"加固"——H5 端点在 www JS 资源里命中，这不是降级告警。
            meta["dex_parse_failed"] = False
        else:
            meta["dex_parse_failed"] = True
            logger.warning("DEX 不可用（加固/无 dex），静态端点/SDK/支付线索严重不完整")
    if getattr(ctx, "apk_validation_ok", True) is False:
        meta["apk_validation_warning"] = "APK 合法性校验异常，分析结果可能不可靠（详见日志）"


def _stage_enrich(state: _PipelineState) -> None:
    """联网富化（两遍）——**只对"高度可疑"端点（建议调证）查**，不再有一个查一个。

    判据：infra 分级为"建议调证"（疑似 App 自有服务/C2）的域名/IP 才查；已知第三方基础设施/SDK/CDN
    （无需调证）、私网/回环/行情代码（待核）一律跳过。★ 两遍富化（见 _run_enrichment）：①归属定辖区
    → ②境外被动取证仅对【国外+未知】端点跑。主动/被动模式硬隔离：passive（默认）屏蔽会**向目标发
    流量**的主动富化器（active=True，如 webcheck），authorized-active 才放行；被屏蔽/放行项记入 meta
    供审计。offline → 仅记跳过标志。"""
    config = state.config
    meta = state.meta
    if not config.online:
        meta["enrichment_skipped_offline"] = True
        logger.info("offline 模式：跳过全部富化器（归属信息未查询，非查无结果）")
        return

    targets = _enrichment_targets(state.endpoints)
    discovered = [
        enricher
        for enricher in discover_enrichers()
        if not getattr(enricher, "case_close_only", False)
    ]
    mode = getattr(config, "mode", ANALYSIS_MODE_PASSIVE)
    active_enrichers = [e for e in discovered if getattr(e, "active", False)]
    if mode == ANALYSIS_MODE_AUTHORIZED_ACTIVE:
        if active_enrichers:
            names = [getattr(e, "name", "") or type(e).__name__ for e in active_enrichers]
            meta["active_enrichers_enabled"] = names
            logger.warning(
                "authorized-active 模式：放行 %d 个**主动**富化器（将向目标发起 live 探测，"
                "请确认已获授权）：%s",
                len(names),
                names,
            )
    elif active_enrichers:
        names = [getattr(e, "name", "") or type(e).__name__ for e in active_enrichers]
        meta["active_enrichers_skipped_passive_mode"] = names
        logger.info(
            "passive 模式：已屏蔽 %d 个主动富化器（对目标发流量）：%s；如确需主动探测请显式"
            " --mode authorized-active",
            len(names),
            names,
        )
    state.enricher_status = enrich_selected_targets(
        targets,
        discovered,
        mode=mode,
        include_case_close=False,
    )
    meta["enriched_target_count"] = len(targets)
    net_eps = sum(1 for ep in state.endpoints if ep.kind in ("domain", "ip"))
    logger.info(
        "联网富化：仅对 %d 个高度可疑端点（建议调证）查归属，跳过其余 %d 个域名/IP（infra/已知/私网）",
        len(targets),
        max(0, net_eps - len(targets)),
    )


def _stage_attribution(state: _PipelineState) -> None:
    """把富化好的 enrichment 映射成**五层不塌缩**基础设施归因，写入 ``endpoint.enrichment['attribution']``。

    ★必须在 enrich 之后（此时 asn/dns 子键已填）、build_leads 之前。域名按解析到的每个 IP 逐条产五层
    （per-IP，不合并）。build_endpoint_attribution 绝不抛；无归属信号的端点不写该键（不塞空归因）。
    """
    for ep in state.endpoints:
        try:
            att = build_endpoint_attribution(ep.kind, ep.value, ep.enrichment)
        except Exception:  # noqa: BLE001 — 防御纵深：单端点归因失败不得拖累其它端点/整个阶段
            logger.debug("端点归因失败，跳过：%s", ep.value, exc_info=True)
            continue
        if att is not None:
            ep.enrichment["attribution"] = att


def _stage_build_leads(state: _PipelineState) -> None:
    """端点 → DOMAIN/IP Lead（分析器本身不产 DOMAIN/IP Lead，统一在此生成；advice 已在
    build_endpoint_leads 内按 infra 分级赋值）+ advice 兜底（分析器未自带研判建议时按线索类别给默认值，
    避免报告出现空白"是否调证"列；已自带 advice 的不覆盖）。"""
    state.leads.extend(build_endpoint_leads(state.endpoints, online=state.config.online))
    _apply_default_advice(state.leads)


def _stage_overseas_targets(state: _PipelineState) -> None:
    """结构化境外目标段（按主机聚合 shodan/certs 的被动定位信号，机器可读）：供 digest/HTML/Codex
    直接查询/聚合/交叉比对，免去从 evidence 自然语言串里解析。仅联网富化后有内容。"""
    if state.config.online:
        state.meta["overseas_targets"] = _build_overseas_targets(state.endpoints)


def _stage_credibility(state: _PipelineState) -> None:
    """结果可信度地基：据 analyzer_status 聚合完整度 + 记录工具版本 / 规则摘要（可复现锚点）。"""
    (
        state.analysis_status,
        state.completeness,
        state.critical_failures,
        state.skipped_analyzers,
    ) = _analysis_health(state.analyzer_status)
    state.meta["tool_version"] = _tool_version()
    state.meta["ruleset_digest"] = ruleset_digest()


def _stage_network_attribution(state: _PipelineState) -> None:
    """附加视图：把**已收集的端点事实**组装成基础设施归因图谱 + 角色候选（PR3-PR8）。纯被动、
    不新增网络/富化/文件 I/O、不反哺闭环/线索/退出码；仅写 meta["network_attribution"]。云/ASN/CDN
    归属只是资源事实、非运营者指控。无可归因端点则省略该键。"""
    from apkscan.attribution.assemble import build_network_attribution

    artifact_id = str(state.meta.get("sample_sha256") or "") or f"pkg:{state.ctx.package_name or 'unknown'}"
    blob = build_network_attribution(state.endpoints, artifact_id=artifact_id, phase="analyze")
    if blob is not None:
        state.meta["network_attribution"] = blob


def _assemble_report(state: _PipelineState) -> Report:
    """据累积态组装 Report（字段一一对应）。"""
    return Report(
        package_name=state.ctx.package_name,
        meta=state.meta,
        leads=state.leads,
        endpoints=state.endpoints,
        findings=state.findings,
        analyzer_status=state.analyzer_status,
        enricher_status=state.enricher_status,
        analysis_status=state.analysis_status,
        completeness=state.completeness,
        critical_failures=state.critical_failures,
        skipped_analyzers=state.skipped_analyzers,
    )


def _run_stage(state: _PipelineState, name: str, fn: "Callable[[_PipelineState], None]") -> None:
    """跑一个 pipeline 阶段并捕获异常：把 ``{name, status, error?}`` 记入 ``state.stage_status``，
    **绝不让单阶段故障中断整条流水线**（把模块「单点故障不中断流水线」的铁律从分析器/富化器粒度
    延伸到阶段粒度：一个阶段崩了，其余阶段照跑、仍产出部分报告，而非整个分析炸掉丢全部产出）。

    计时只记 log、**不入报告**（timing 非确定，入报告会破坏串行==并行逐字节一致的不变量）。
    """
    t0 = time.perf_counter()
    try:
        fn(state)
        entry: dict = {"name": name, "status": "ran"}
    except Exception as exc:  # noqa: BLE001 — 阶段级兜底：记录后继续，绝不炸整条流水线
        logger.exception("pipeline 阶段异常：%s", name)
        entry = {"name": name, "status": "error", "error": f"{type(exc).__name__}: {exc}"}
    logger.info(
        "pipeline 阶段 %s：%s（%dms）", name, entry["status"], int((time.perf_counter() - t0) * 1000)
    )
    state.stage_status.append(entry)


# 附加/纯视图阶段：故障只记入 stage_status 供审计，**不反哺 analysis_status / --strict 退出码**。
# network_attribution 是纯被动附加视图（见 _stage_network_attribution docstring 与设计 spec Boundaries：
# PR9 不 create/mutate 任何 Lead/advice/exit code），其组装故障不该污染 --strict 门禁——与 closure.py 里
# close 阶段同一视图已自带 guard、不下沉 case closure 的既定语义对齐（只有 analyze 侧接线漏了这层豁免）。
# 故障仍完整记录于 meta.stage_status（保留 error 审计痕迹），仅切断降级传导。
_ADDITIVE_STAGES: frozenset[str] = frozenset({"network_attribution"})


def _apply_stage_failures(state: _PipelineState) -> None:
    """阶段级故障反馈 ``analysis_status`` / ``completeness``，让 --strict / 完整度也能反映阶段崩溃
    （而非只看分析器）：``analyze`` 阶段崩 → failed **且 completeness 归零**（analyze 崩时
    analyzer_status 为空、_analysis_health 会按"无可跑→1.0"算出误导性的满完整度，须校正）；其它阶段崩
    → 至少 partial（分析器已跑完，completeness 仍如实反映分析器层，partial 表征后续阶段故障）。
    ★``_ADDITIVE_STAGES``（附加/纯视图阶段，如 network_attribution）例外：其故障只记 stage_status、
    不参与降级判定，避免纯被动视图的组装故障污染 analysis_status / --strict 退出码。不上调已判 failed 的结果。"""
    errored = [
        s["name"]
        for s in state.stage_status
        if s.get("status") == "error" and s["name"] not in _ADDITIVE_STAGES
    ]
    if not errored:
        return
    if "analyze" in errored:
        state.analysis_status = ANALYSIS_STATUS_FAILED
        state.completeness = 0.0  # analyze 崩 → 无分析器完成，完整度归零（校正 eligible=0 的假 1.0）
    elif state.analysis_status == ANALYSIS_STATUS_COMPLETE:
        state.analysis_status = ANALYSIS_STATUS_PARTIAL


def run(ctx: "AnalysisContext", config: AnalysisConfig) -> Report:
    """执行完整流水线，返回 Report。

    结构为一串按序执行的 stage（见各 ``_stage_*``），共享 ``_PipelineState`` 累积态，每个核心阶段
    经 ``_run_stage`` 执行——**阶段级故障被捕获记入 stage_status、不中断后续**，并反馈 analysis_status。
    各阶段业务逻辑与历史内联实现逐字一致（结构重构），仅新增阶段边界的状态捕获与韧性。
    """
    _canonicalize_ctx_config(ctx, config)
    state = _init_pipeline_state(ctx, config)
    _run_stage(state, "analyze", _stage_run_analyzers)              # 分析器执行 + 聚合 + 端点去重
    _run_stage(state, "degradation_flags", _stage_degradation_flags)  # 降级标志入 meta
    _run_stage(state, "enrich", _stage_enrich)                     # 联网富化（两遍，主动/被动硬隔离）
    _run_stage(state, "attribution", _stage_attribution)           # 五层不塌缩基础设施归因（per-IP）
    _run_stage(state, "build_leads", _stage_build_leads)           # 端点 → Lead + advice 兜底
    _run_stage(state, "overseas_targets", _stage_overseas_targets)  # 境外目标结构化段
    _run_stage(state, "credibility", _stage_credibility)           # 完整度 / 工具版本 / 规则摘要
    _run_stage(state, "network_attribution", _stage_network_attribution)  # 附加：基础设施归因图谱 + 角色候选（被动）
    _apply_stage_failures(state)          # 阶段级故障反馈 analysis_status
    state.meta["stage_status"] = state.stage_status
    report = _assemble_report(state)
    # App 类型聚合分类（在所有分析器跑完 + build_endpoint_leads 之后调用一次）：聚合现成
    # meta/leads/endpoints/findings 信号加权定类，并据类型**追加**针对性调证 Lead（只追加、不改已有
    # Lead）。已自带 try/except 兜底、属组装后增强，不纳入核心阶段状态。
    classify_app(report)
    return report


# ---------------------------------------------------------------------------
# 分析器执行：android 多核走进程池并行（绕 GIL），否则/失败串行。结果按发现顺序聚合。
# ---------------------------------------------------------------------------

#: 逃生开关：设 FXAPK_NO_PARALLEL 强制串行（排障 / 兼容）。


def _dedup_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """按 value 去重合并端点（不同分析器可能产出同一 value 的 Endpoint）。

    合并规则：
    - evidences：按 (source, location, snippet) 去重后并集（保持首次出现顺序）。
    - is_cleartext / is_private / is_suspicious：取并集（任一为 True 即 True）。
    - enrichment：浅合并（后者补充先者缺的键，已有键不覆盖）。
    - kind：以首次出现为准（同一 value 一般同 kind）。

    保持端点首次出现的相对顺序，便于报告稳定。
    """
    merged: dict[str, Endpoint] = {}
    for ep in endpoints:
        existing = merged.get(ep.value)
        if existing is None:
            # 拷贝一份，避免就地修改分析器产出的对象。
            merged[ep.value] = Endpoint(
                value=ep.value,
                kind=ep.kind,
                evidences=list(ep.evidences),
                is_cleartext=ep.is_cleartext,
                is_private=ep.is_private,
                is_suspicious=ep.is_suspicious,
                enrichment=dict(ep.enrichment),
            )
            continue

        existing.evidences.extend(ep.evidences)
        existing.is_cleartext = existing.is_cleartext or ep.is_cleartext
        existing.is_private = existing.is_private or ep.is_private
        existing.is_suspicious = existing.is_suspicious or ep.is_suspicious
        for key, val in ep.enrichment.items():
            if key == "tier":
                # C1：域名来源可信度档特殊处理——多来源取最可信档（app > library-file
                #   > bulk-string），避免"既来自 app 文件又来自 library 文件"被错降。
                existing.enrichment["tier"] = infra.best_tier(
                    existing.enrichment.get("tier"), val
                )
                continue
            existing.enrichment.setdefault(key, val)

    # evidences 去重（保持顺序）。
    for ep in merged.values():
        seen: set[tuple[str, str, str]] = set()
        deduped: list[Evidence] = []
        for ev in ep.evidences:
            key = (ev.source, ev.location, ev.snippet)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(ev)
        ep.evidences = deduped

    return list(merged.values())
