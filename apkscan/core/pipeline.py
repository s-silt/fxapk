"""分析流水线：跑分析器 → 富化端点 → 聚合 → 生成 Lead → 组装 Report。

错误处理铁律：单分析器/富化器异常一律 try/except 记录到结果 + logging.exception，
绝不裸 pass、绝不让单点故障中断整条流水线。
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import pickle
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import psutil

from apkscan.analyzers.classify import classify_app
from apkscan.core import exposure, forensic, infra
from apkscan.core.models import (
    ANALYSIS_MODE_AUTHORIZED_ACTIVE,
    ANALYSIS_MODE_PASSIVE,
    ANALYSIS_STATUS_COMPLETE,
    ANALYSIS_STATUS_FAILED,
    ANALYSIS_STATUS_PARTIAL,
    AnalysisConfig,
    Confidence,
    Endpoint,
    Evidence,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.core.registry import (
    BaseEnricher,
    detect_capabilities,
    discover_analyzers,
    discover_enrichers,
    ruleset_digest,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

#: 富化并发度：按端点并发跑富化器（I/O 密集，瓶颈是 whois/rdap 的 ~30s 超时串行累加）。
#: 默认 8 个 worker。每个端点由单一 worker 串行跑其匹配的全部富化器，故同一 ep.enrichment
#: 无并发写竞争；只有跨端点共享的 provider 统计需加锁聚合。
ENRICH_MAX_WORKERS = 8


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
    discovered = discover_enrichers()
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
    state.enricher_status = _run_enrichment(targets, discovered, gate=_mode_gate(mode))
    meta["enriched_target_count"] = len(targets)
    net_eps = sum(1 for ep in state.endpoints if ep.kind in ("domain", "ip"))
    logger.info(
        "联网富化：仅对 %d 个高度可疑端点（建议调证）查归属，跳过其余 %d 个域名/IP（infra/已知/私网）",
        len(targets),
        max(0, net_eps - len(targets)),
    )


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


def _apply_stage_failures(state: _PipelineState) -> None:
    """阶段级故障反馈 ``analysis_status`` / ``completeness``，让 --strict / 完整度也能反映阶段崩溃
    （而非只看分析器）：``analyze`` 阶段崩 → failed **且 completeness 归零**（analyze 崩时
    analyzer_status 为空、_analysis_health 会按"无可跑→1.0"算出误导性的满完整度，须校正）；其它阶段崩
    → 至少 partial（分析器已跑完，completeness 仍如实反映分析器层，partial 表征后续阶段故障）。
    不上调已判 failed 的结果。"""
    errored = [s["name"] for s in state.stage_status if s.get("status") == "error"]
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
    _run_stage(state, "build_leads", _stage_build_leads)           # 端点 → Lead + advice 兜底
    _run_stage(state, "overseas_targets", _stage_overseas_targets)  # 境外目标结构化段
    _run_stage(state, "credibility", _stage_credibility)           # 完整度 / 工具版本 / 规则摘要
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
_ENV_NO_PARALLEL = "FXAPK_NO_PARALLEL"

#: worker 进程级状态（spawn 后由 initializer 填充）。
_WORKER_STATE: dict = {}

# ---- worker 数内存封顶常量 ----
_ENV_MAX_WORKERS = "FXAPK_MAX_WORKERS"  # 运维强制覆盖最终 worker 数
_ENV_WORKER_BASE_MB = "FXAPK_WORKER_BASE_MB"  # 覆盖 _WORKER_BASE_BYTES（单位 MB）
_ENV_MEM_SAFETY = "FXAPK_MEM_SAFETY"  # 覆盖 _MEM_SAFETY（0<v<=1）
#: 单 worker 常驻基线（**不含快照**）：实测常驻 ~128MB 含 ~11.5MB 快照拷贝，剔除快照得 ~116MB，
#: 加 ~50MB 分析瞬时余量 ≈ 170MB。快照由 _SNAPSHOT_FACTOR*snapshot_size 单独叠加，勿在此重复计入。
_WORKER_BASE_BYTES = 170 * 1024 * 1024
#: snapshot pickle 体积→实际占用的放大系数：每 worker unpickle 后 dex_strings(12 万 str) 在堆里物化
#: 为 pickle 字节的 2~3 倍，同一份快照又在父侧 queue-feeder 并发缓冲。2.0 同时近似覆盖两者，偏保守。
_SNAPSHOT_FACTOR = 2.0
#: 父进程预留：决策时 avail 已扣父进程当前常驻，但决策之后父侧仍增长（W 份 pickle 缓冲 + W 个
#: AnalyzerResult 物化 + dedup/富化/classify 聚合）。实测并行净增属父侧部分，保守留 256MB。
_PARENT_RESERVE_BYTES = 256 * 1024 * 1024
#: 只用预算的 60%，给 OS/其他进程/spawn import 风暴/unpickle 双持留余量。按 Windows ullAvailPhys 标定。
_MEM_SAFETY = 0.6
#: psutil 查询运行时异常时的保守上限（psutil 已为核心依赖，此路径罕见）。取 min(cpu_cap, 4)。
_FIXED_FALLBACK_CAP = 4
#: 快照 pickle 体积超此值，worker 数再砍半（_SNAPSHOT_FACTOR 已线性吸收，此为病态大快照硬降档）。
_SNAPSHOT_TIER_THRESHOLD = 40 * 1024 * 1024

#: _decide_workers 的 env_n 哨兵：区分"未提供（自行读 env）"与"读到 env=None（未设置）"。
_UNSET = object()


def _parse_int_env(name: str) -> int | None:
    """读正整数 env：未设/空串→None（静默，未设置是正常态）；非整数或<=0→None+warning。"""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return None
    try:
        n = int(raw)
    except ValueError:
        logger.warning("%s=%r 非整数，忽略", name, raw)
        return None
    if n <= 0:
        logger.warning("%s=%r 非正整数，忽略", name, raw)
        return None
    return n


def _parse_float_env(name: str, *, lo: float, hi: float) -> float | None:
    """读 (lo, hi] 区间浮点 env：未设/空串→None；非浮点或越界→None+warning。"""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return None
    try:
        v = float(raw)
    except ValueError:
        logger.warning("%s=%r 非浮点，忽略", name, raw)
        return None
    if not (lo < v <= hi):
        logger.warning("%s=%r 越界 (%s, %s]，忽略", name, raw, lo, hi)
        return None
    return v


def _worker_base_bytes() -> int:
    """单 worker 基线字节数（FXAPK_WORKER_BASE_MB 可覆盖，现场纠偏阀）。"""
    mb = _parse_int_env(_ENV_WORKER_BASE_MB)
    return mb * 1024 * 1024 if mb is not None else _WORKER_BASE_BYTES


def _mem_safety() -> float:
    """内存安全系数（FXAPK_MEM_SAFETY 可覆盖）。"""
    v = _parse_float_env(_ENV_MEM_SAFETY, lo=0.0, hi=1.0)
    return v if v is not None else _MEM_SAFETY


def _read_cgroup_file(path: str) -> str:
    """读 cgroup 文件首行（抽出便于测试 monkeypatch）。"""
    with open(path) as f:
        return f.read().strip()


def _cgroup_limit_bytes() -> int | None:
    """cgroup 内存硬上限；未设限 / 非 cgroup / 读失败 → None。"""
    try:
        v2_max = "/sys/fs/cgroup/memory.max"
        if os.path.exists(v2_max):  # cgroup v2
            raw = _read_cgroup_file(v2_max)
            if raw == "max":
                return None  # 未设限
            return int(raw)
        v1_limit = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
        if os.path.exists(v1_limit):  # cgroup v1
            limit = int(_read_cgroup_file(v1_limit))
            # 未设限哨兵：接近 2^63 的大数（经典 0x7FFFFFFFFFFFF000）或 >= 物理内存。
            if limit >= 2**62 or limit >= psutil.virtual_memory().total:
                return None
            return limit
    except Exception:  # noqa: BLE001 — 上限读失败 → None（回退 psutil，绝不炸决策）
        logger.debug("读取 cgroup 内存上限失败", exc_info=True)
    return None


def _cgroup_usage_bytes() -> int | None:
    """cgroup 当前用量；读失败 → None。"""
    try:
        v2_cur = "/sys/fs/cgroup/memory.current"
        if os.path.exists(v2_cur):
            return int(_read_cgroup_file(v2_cur))
        v1_usage = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
        if os.path.exists(v1_usage):
            return int(_read_cgroup_file(v1_usage))
    except Exception:  # noqa: BLE001 — 用量读失败 → None（由调用方保守按整个 limit 处理）
        logger.debug("读取 cgroup 内存用量失败", exc_info=True)
    return None


def _cgroup_available_bytes() -> int | None:
    """Linux cgroup 内存剩余 (limit - usage)；非 Linux / 未设限 / 上限读失败 → None。

    ★安全回退：上限已知但用量读失败时返回**上限本身**（保守按整个 limit 估），绝不退回宿主机内存
    ——否则容器里会按宿主机几十 GB 算 worker 数、撞穿 cgroup limit 被 OOMKilled（SIGKILL 无回退机会），
    正是本特性要防的场景。仅当上限本身都读不到（无 cgroup / 解析失败）才返回 None 退回 psutil。
    """
    if not sys.platform.startswith("linux"):
        return None
    limit = _cgroup_limit_bytes()
    if limit is None:
        return None
    usage = _cgroup_usage_bytes()
    if usage is None:
        return limit  # 用量未知 → 保守按整个 limit（仍受容器上限约束，远安全于退回宿主机）
    return max(0, limit - usage)


def _available_bytes() -> int:
    """可用内存：Windows=psutil.available；Linux 取 min(psutil.available, cgroup 剩余)——容器里
    psutil.available 读宿主机内存、与 cgroup limit 无关，不取 min 会撞穿 limit 被 OOMKilled。"""
    avail = psutil.virtual_memory().available
    cg = _cgroup_available_bytes()
    return min(avail, cg) if cg is not None else avail


def _decide_workers(snapshot_size: int, name_count: int, env_n: object = _UNSET) -> int:
    """据 CPU / 可用内存 / env 决定进程池 worker 数。纯计算、绝不抛（异常→保守兜底）。返回 >=1，
    调用方对 <=1 回退串行。env_n 缺省自行读 FXAPK_MAX_WORKERS（便于单测）；_analyze_parallel 传入
    避免重复解析/重复 warning。详见 specs/2026-06-22-parallel-worker-memory-cap-design.md。"""
    cpu_cap = max(1, min(name_count, os.cpu_count() or 2))
    n = _parse_max_workers_env() if env_n is _UNSET else env_n

    # (1) env 强制覆盖。
    if n is not None:
        return max(1, min(cpu_cap, n))  # type: ignore[arg-type]

    # (2) 按可用内存封顶。
    try:
        avail = _available_bytes()
        per_worker = _worker_base_bytes() + int(_SNAPSHOT_FACTOR * snapshot_size)
        budget = max(0, avail - _PARENT_RESERVE_BYTES)
        mem_cap = int(budget * _mem_safety() / per_worker) if per_worker > 0 else cpu_cap
        workers = min(cpu_cap, max(1, mem_cap))
        if 1 < workers < cpu_cap:
            logger.info(
                "内存受限：worker %d→%d（可用 %dMB，单 worker 估 %dMB）",
                cpu_cap, workers, avail // (1024 * 1024), per_worker // (1024 * 1024),
            )
        # 快照超阈再砍一档（病态大快照硬降档；_SNAPSHOT_FACTOR 已线性吸收，此为额外保守）。
        if snapshot_size > _SNAPSHOT_TIER_THRESHOLD and workers > 1:
            halved = max(1, workers // 2)
            logger.info(
                "快照体积 %d 字节超阈 %d，worker 再压一档 %d→%d",
                snapshot_size, _SNAPSHOT_TIER_THRESHOLD, workers, halved,
            )
            workers = halved
        return max(1, workers)
    except Exception:  # noqa: BLE001 — 内存探测失败不得炸并行决策；保守兜底（不向上冒泡）
        cap = max(1, min(cpu_cap, _FIXED_FALLBACK_CAP))
        logger.warning("psutil 查询可用内存失败，worker 用固定兜底 %d", cap)
        return cap


def _parse_max_workers_env() -> int | None:
    """读 FXAPK_MAX_WORKERS（运维强制覆盖最终 worker 数）。"""
    return _parse_int_env(_ENV_MAX_WORKERS)


def _sizeof_pickle(snapshot: object) -> int:
    """快照 pickle 体积（字节）——与父侧真实 IPC 序列化口径一致，作内存封顶公式输入。"""
    try:
        return len(pickle.dumps(snapshot))
    except Exception:  # noqa: BLE001 — 体积估算失败按 0（退化为仅 base 估算，绝不炸）
        logger.debug("快照 pickle 体积估算失败，按 0 处理", exc_info=True)
        return 0


def _worker_init(snapshot: object) -> None:
    """进程池 worker 初始化：配置日志 + 缓存快照 + 发现分析器（每 worker 一次，不含 androguard 重导入）。"""
    # spawn 的 worker 是全新进程，不继承主进程 cli 的 logging 配置——不配则分析器内
    # logger.info/warning/exception 走 root 兜底 handler（无时间戳、格式不一致、INFO 被丢）。
    # 取证工具的审计日志是关键证据，同一 APK 不能因走并行/串行而产出详尽程度不同的日志。
    # 与 cli.basicConfig 同口径（level/format 一致），保证两路日志一致。
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _WORKER_STATE["snapshot"] = snapshot
    _WORKER_STATE["analyzers"] = {
        (getattr(a, "name", "") or a.__class__.__name__): a for a in discover_analyzers()
    }


def _worker_analyze(name: str) -> tuple:
    """worker 内跑一个分析器，返回 (name, result|None, error|None)。结果须可 pickle。"""
    snap = _WORKER_STATE.get("snapshot")
    analyzer = (_WORKER_STATE.get("analyzers") or {}).get(name)
    if analyzer is None:
        return (name, None, "worker 未发现该分析器")
    try:
        return (name, analyzer.analyze(snap), None)
    except Exception as exc:  # noqa: BLE001 — 单分析器失败不炸 worker，回传错误
        # 错误处理铁律：记完整堆栈（与串行 _analyze_serial 同口径）。worker 已在 _worker_init
        # 配好日志，logger.exception 把 traceback 落到 worker stderr（继承主控台）；否则并行路只
        # 回一行 "ValueError: ..." 无堆栈，崩溃分析器排障从"看堆栈"退化成"盲猜"。
        logger.exception("分析器执行异常：%s", name)
        return (name, None, f"{type(exc).__name__}: {exc}")


def _should_parallelize(ctx: object, eligible: list) -> bool:
    """是否走进程池并行：android + 多核 + 足够多分析器 + 有 apk_path（惰性兜底需要）+ 未禁用。"""
    if os.environ.get(_ENV_NO_PARALLEL):
        return False
    if getattr(ctx, "platform", "android") != "android":
        return False  # IPA 等 read_file 语义不同 → 串行
    if (os.cpu_count() or 1) < 2 or len(eligible) < 3:
        return False  # 单核 / 分析器太少不值进程开销
    if not getattr(ctx, "apk_path", ""):
        return False  # 无 apk_path 无法在 worker 惰性兜底非文本 read_file
    return True


def _analyze_serial(ctx: object, eligible: list) -> list[tuple]:
    """串行跑（无 androguard pickle 开销；并行不适用/失败时的回退）。"""
    out: list[tuple] = []
    for name, analyzer in eligible:
        try:
            out.append((name, analyzer.analyze(ctx), None))
        except Exception as exc:  # noqa: BLE001 — 单点故障不中断流水线
            logger.exception("分析器执行异常：%s", name)
            out.append((name, None, f"{type(exc).__name__}: {exc}"))
    return out


#: 整批并行分析的总超时预算（秒）。防病态输入（如构造触发正则灾难性回溯的字符串）让某个分析器
#: 的 worker 无限期卡住、拖住整批结果永久不返回。固定值而非按分析器数线性放大——各分析器都是
#: 纯内存扫描（dex 字符串/manifest 正则，无网络 IO），正常情况下全部跑完通常数秒内，120s 是几十倍
#: 安全余量。注意 map_async().get(timeout) 的语义是「从 get() 起整批累计等待」而非逐个 task 各自计时。
_BATCH_TIMEOUT_SECONDS = 120.0


def _run_pool(snapshot: object, names: list[str], workers: int) -> list[tuple]:
    """纯建池 + map（不含内存决策）。map_async(...).get() 保序。真 spawn 等价测试直接调本函数以
    绕过 _decide_workers，保证它永远真 spawn（否则低 RAM 机上等价测试会因回退串行而 serial==serial 假绿）。

    超时防护：单个分析器卡死不应让整批并行结果永久挂起。超过 _BATCH_TIMEOUT_SECONDS → 放弃等待
    并抛 TimeoutError，外层 `_analyze_eligible` 的 except Exception 捕获后回退串行逐个执行（至少能
    继续产出结果、定位是哪个分析器卡死）。

    ★ 用 ``multiprocessing.Pool`` 而非 ``concurrent.futures.ProcessPoolExecutor``：前者的 with
    __exit__ 调 ``terminate()`` **强杀 worker 进程**，故超时后墙钟被真正 bound 住；后者 __exit__ 是
    ``shutdown(wait=True)``，超时抛出后反而挂住等卡死 worker 跑完，令超时形同虚设（实测：worker 卡死
    5s、超时压到 1s 时，ProcessPoolExecutor 版总耗时仍 5s，multiprocessing.Pool 版 1s）。
    """
    with multiprocessing.Pool(
        processes=workers, initializer=_worker_init, initargs=(snapshot,)
    ) as pool:
        try:
            return pool.map_async(_worker_analyze, names).get(timeout=_BATCH_TIMEOUT_SECONDS)
        except multiprocessing.TimeoutError as exc:
            logger.warning(
                "并行分析批次超时（%d 个分析器，预算 %.0fs）：疑似病态输入导致某分析器卡死，"
                "强杀 worker、放弃本批结果，回退串行逐个执行（会更慢但能继续产出）",
                len(names),
                _BATCH_TIMEOUT_SECONDS,
            )
            # with 退出时 multiprocessing.Pool.__exit__ → terminate() 强杀仍在跑的 worker，墙钟被真正
            # bound 住。归一到内置 TimeoutError，保持外层 _analyze_eligible 的 except 契约不变。
            raise TimeoutError(str(exc)) from exc


def _analyze_parallel(ctx: object, eligible: list) -> list[tuple]:
    """进程池并行跑（snapshot 发各 worker，绕 GIL 在多核真并行）。worker 数按 CPU+可用内存封顶；<=1 回退串行。

    执行顺序契约（钉死，勿打乱）：env 前置短路 → build_snapshot → _decide_workers →
    workers<=1 回退串行（**不发**『并行执行』INFO，否则审计日志说进程池却走了串行）→ 否则发 INFO + 建池。
    """
    from apkscan.core.snapshot import build_snapshot

    names = [name for name, _ in eligible]
    cpu_cap = max(1, min(len(names), os.cpu_count() or 2))
    # env 强制串行的廉价前置：FXAPK_MAX_WORKERS 使最终 <=1 → 在 build_snapshot 之前就回退，省 ~689ms。
    env_n = _parse_max_workers_env()
    if env_n is not None and min(cpu_cap, env_n) <= 1:
        logger.debug("FXAPK_MAX_WORKERS=%d → 回退串行", env_n)
        return _analyze_serial(ctx, eligible)

    snapshot = build_snapshot(ctx)
    workers = _decide_workers(_sizeof_pickle(snapshot), len(names), env_n=env_n)
    if workers <= 1:
        logger.debug("内存封顶后 workers<=1 → 回退串行（avail 不足 / 容器受限）")
        return _analyze_serial(ctx, eligible)
    logger.info("分析器并行执行：%d 个（进程池，%d worker）", len(names), workers)
    return _run_pool(snapshot, names, workers)


def _analyze_eligible(ctx: object, eligible: list) -> list[tuple]:
    """跑一组（已过 requires）分析器，返回 [(name, result, error)]。并行不适用/失败 → 串行回退。"""
    if _should_parallelize(ctx, eligible):
        try:
            return _analyze_parallel(ctx, eligible)
        except Exception:  # noqa: BLE001 — 并行整体失败（spawn/pickle 等）→ 回退串行，绝不漏分析
            logger.exception("分析器并行执行失败，回退串行")
    return _analyze_serial(ctx, eligible)


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


def _enrichment_targets(endpoints: list[Endpoint]) -> list[Endpoint]:
    """筛出"高度可疑"端点（域名/IP 且 infra 分级为"建议调证"）作为联网富化目标。

    只对疑似 App 自有服务/C2 的域名/IP 查 WHOIS/ICP/ASN；已知第三方基础设施/SDK/CDN
    （无需调证）、私网/回环 IP / 行情代码伪域名（待核）都不查。这正是"最后只对高度可疑的查、
    而不是有一个查一个"：省时（网络受限不被 infra 域名拖死、不误查 127.0.0.1）+ 聚焦调证。
    """
    targets: list[Endpoint] = []
    for ep in endpoints:
        if ep.kind not in ("domain", "ip"):
            continue  # 非 domain/ip 本就不被 WHOIS/ICP/ASN 路由
        advice, _reason = infra.classify_domain(ep.value)
        if advice == infra.ADVICE_INVESTIGATE:
            targets.append(ep)
    return targets


def _enrich_endpoints(
    endpoints: list[Endpoint],
    enrichers: list[BaseEnricher],
    *,
    gate: "Callable[[Endpoint, BaseEnricher], bool] | None" = None,
) -> list[dict]:
    """对每个端点按 applies_to 跑匹配的富化器，结果写入 endpoint.enrichment[provider]。

    ``gate``（可选）：额外的 (端点, 富化器)→bool 谓词，返回 False 则跳过该富化器（不计入统计）。
    不传则对匹配 applies_to 的富化器全跑（向后兼容；本仓当前富化器全部为被动，对目标零流量）。

    按端点并发（``ThreadPoolExecutor``，worker 数 = ``ENRICH_MAX_WORKERS``）：富化是
    I/O 密集（whois/rdap 单次可达 ~30s 超时），串行双重循环单包可达 7 分钟，按端点并发
    把这些超时叠在一起跑而非顺序累加。

    并发不变量：
    - 每个端点由**单一** worker 串行跑其匹配的全部富化器 → 同一 ``ep.enrichment``
      无并发写竞争；端点之间互不共享 enrichment dict。
    - ``endpoints`` 列表**原地不动、顺序不变**（只就地写 ``ep.enrichment``，绝不重排）。
    - 跨端点共享的 provider 统计用锁聚合，``attempted/ok/failed/typical_error`` 准确。
    - ip-api 免费档限速由 ``_ipinfo`` 内部的进程级线程安全限速器担保（asn 单查走 45/min·1.4s 闸、
      dns 批量走 /batch 15/min·4.0s 独立闸）——并发下仍是全局闸，本层只管并发分发。

    返回每个富化器的聚合状态 [{provider, attempted, ok, failed, typical_error}]，
    使富化器层的系统性失败（如某 provider 全部失败）在报告里透明可见，
    而非打散进各 endpoint 难以察觉。
    """
    stats: dict[str, dict] = {}
    stats_lock = threading.Lock()

    if endpoints:
        # max_workers 不超过端点数，避免端点少时空建大量线程。
        workers = max(1, min(ENRICH_MAX_WORKERS, len(endpoints)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="enrich") as pool:
            # list() 强制求值 → 任一 worker 内未捕获异常会在此重抛（_run_enrichers_on_endpoint
            # 内部已逐 enrich try/except，正常不会到这；这里是兜底，不让异常被 executor 静默吞掉）。
            list(pool.map(
                lambda ep: _run_enrichers_on_endpoint(ep, enrichers, stats, stats_lock, gate),
                endpoints,
            ))

    return list(stats.values())


def _stat(stats: dict[str, dict], provider: str) -> dict:
    """取/建某 provider 的统计条目（调用方须持 stats 的锁）。"""
    return stats.setdefault(
        provider,
        {"provider": provider, "attempted": 0, "ok": 0, "failed": 0, "typical_error": None},
    )


def _run_enrichers_on_endpoint(
    ep: Endpoint,
    enrichers: list[BaseEnricher],
    stats: dict[str, dict],
    stats_lock: threading.Lock,
    gate: "Callable[[Endpoint, BaseEnricher], bool] | None" = None,
) -> None:
    """对单个端点**串行**跑匹配的富化器（applies_to + gate 过滤），就地写 ep.enrichment + 聚合 stats。

    在单一 worker 内调用：同一 ep.enrichment 无并发写竞争；跨端点共享的 stats 用锁聚合。
    """
    for enricher in enrichers:
        applies_to = list(getattr(enricher, "applies_to", []) or [])
        if ep.kind not in applies_to:
            continue
        if gate is not None and not gate(ep, enricher):
            continue  # 门控谓词返回 False：跳过该富化器，不计统计
        provider = getattr(enricher, "name", "") or enricher.__class__.__name__

        with stats_lock:
            _stat(stats, provider)["attempted"] += 1

        try:
            result = enricher.enrich(ep)
        except Exception:  # noqa: BLE001 - 富化失败不阻塞主流程
            logger.exception("富化器执行异常：provider=%s endpoint=%s", provider, ep.value)
            ep.enrichment[provider] = {"ok": False, "error": "富化器异常"}
            with stats_lock:
                _note_fail(_stat(stats, provider), "富化器异常")
            continue

        if result is None:
            logger.warning("富化器 %s 返回 None：%s", provider, ep.value)
            ep.enrichment[provider] = {"ok": False, "error": "enrich 返回 None"}
            with stats_lock:
                _note_fail(_stat(stats, provider), "enrich 返回 None")
            continue

        data = dict(result.data)
        has_values = any(v not in (None, "", [], {}) for v in data.values())
        with stats_lock:
            st = _stat(stats, provider)
            if result.ok and has_values:
                st["ok"] += 1
            elif result.ok and not has_values:
                # 成功但零信息：显式标注，避免与"查到了"在报告里视觉混淆。
                data.setdefault("note", "查询无结果")
                _note_fail(st, "查询无结果")
            else:
                if result.error:
                    data.setdefault("error", result.error)
                _note_fail(st, result.error or "富化失败")
        ep.enrichment[provider] = data


def _note_fail(st: dict, msg: str) -> None:
    """记一次失败到 provider 统计（调用方须持 stats_lock）。"""
    st["failed"] += 1
    if not st["typical_error"]:
        st["typical_error"] = msg


# overseas 阶段的组内顺序（确定性排序；shodan/certs 均被动、互不依赖，固定序保证串行==并行逐字节一致）。
_OVERSEAS_ORDER = {"shodan": 0, "certs": 1}


def _enricher_phase(enricher: BaseEnricher) -> str:
    """富化器阶段（缺失/空 → 默认 attribution，兼容未标 phase 的旧富化器）。"""
    return getattr(enricher, "phase", "attribution") or "attribution"


def _classify_endpoint_jurisdiction(ep: Endpoint) -> str:
    """据第①遍归属富化结果判该端点服务器辖区（国内/国外/未知）。绝不抛（失败→未知，保守）。"""
    e = ep.enrichment
    try:
        return forensic.classify_jurisdiction(
            ep.value,
            icp=e.get("icp"),
            rdap=e.get("rdap"),
            whois=e.get("whois"),
            dns=e.get("dns"),
            asn=e.get("asn"),
            webcheck=e.get("webcheck"),
        )
    except Exception:  # noqa: BLE001 — 辖区判定失败不得炸主流程；保守判未知（宁可漏归类也不误标辖区）
        logger.debug("辖区判定失败，按未知处理：%s", ep.value, exc_info=True)
        return forensic.JURIS_UNKNOWN


def _mode_gate(mode: str) -> "Callable[[Endpoint, BaseEnricher], bool]":
    """按网络模式生成富化器门控谓词（防御纵深：真正在**调用点**拦，任何富化路径都过此闸）。

    - ``authorized-active``：全放行（含 active=True 的主动富化器）。
    - 其它（含默认 ``passive`` 及任何非法值 → 保守当被动）：只放行被动富化器（active 为假）。
    """
    if mode == ANALYSIS_MODE_AUTHORIZED_ACTIVE:
        return lambda _ep, _e: True
    return lambda _ep, enricher: not getattr(enricher, "active", False)


def _run_enrichment(
    targets: list[Endpoint],
    enrichers: list[BaseEnricher],
    gate: "Callable[[Endpoint, BaseEnricher], bool] | None" = None,
) -> list[dict]:
    """两遍富化编排（**单遍并发·每端点内两阶段**，无跨端点栅栏）：
    每个端点在自己的 worker 里串行跑 ①归属(attribution) → 定辖区 → ②境外被动取证(overseas)，
    端点之间互不等待——慢端点（如 30s WHOIS 超时）不再阻塞其它端点的第②阶段（去掉旧版两遍之间的栅栏）。

    第②遍只对【国外 + 未知】端点跑（境内走调证、不做境外取证）；overseas 富化器全部**被动**
    （shodan/certs 读公开库，对目标零流量）。辖区结果仅为 worker 内局部变量，**绝不写入 ep.enrichment**
    （避免 ``_jurisdiction`` 等内部键泄漏进 report.json）。

    ``gate=None`` **fail-closed**：缺省按 passive 门控（拦 active 富化器）。这样任何调用方（现在或
    将来）漏传 gate 都得到**安全**行为，绝不会静默把 webcheck 等主动富化器放进被动运行。要全放行须
    显式传 ``gate=_mode_gate("authorized-active")``。
    """
    if gate is None:
        gate = _mode_gate(ANALYSIS_MODE_PASSIVE)
    attribution = [e for e in enrichers if _enricher_phase(e) == "attribution"]
    overseas = sorted(
        (e for e in enrichers if _enricher_phase(e) == "overseas"),
        key=lambda e: _OVERSEAS_ORDER.get(getattr(e, "name", ""), 0),
    )

    stats: dict[str, dict] = {}
    stats_lock = threading.Lock()

    def _enrich_one_two_phase(ep: Endpoint) -> None:
        # ① 归属富化。
        _run_enrichers_on_endpoint(ep, attribution, stats, stats_lock, gate)
        if not overseas:
            return
        # 定辖区（worker 内局部，绝不写回 ep.enrichment）。
        juris = _classify_endpoint_jurisdiction(ep)
        if juris not in (forensic.JURIS_FOREIGN, forensic.JURIS_UNKNOWN):
            return  # 境内：走调证、不做境外被动取证

        # ② 境外被动取证富化（同 worker 内串行，组内顺序由 overseas 排序保证确定性）。
        _run_enrichers_on_endpoint(ep, overseas, stats, stats_lock, gate)

    if targets:
        workers = max(1, min(ENRICH_MAX_WORKERS, len(targets)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="enrich") as pool:
            list(pool.map(_enrich_one_two_phase, targets))

    return list(stats.values())


def build_endpoint_leads(endpoints: list[Endpoint], online: bool = True) -> list[Lead]:
    """把（已富化的）domain/IP 端点转成 DOMAIN/IP Lead。

    - domain 的归属优先级：icp > rdap（RDAP/whois 兜底）> whois；dns 托管 IP/ASN 入 evidence/notes。
    - IP 的 where_to_request 用 asn 结果。
    URL 端点不直接产 Lead（其归属取决于其 domain/ip 部分）。

    online=False 时在 Lead.notes 标明"离线扫描，归属未查询"，让报告能区分
    "查过查不到" 与 "压根没查"。
    """
    leads: list[Lead] = []
    for ep in endpoints:
        if ep.kind == "domain":
            leads.append(_domain_lead(ep, online))
        elif ep.kind == "ip":
            leads.append(_ip_lead(ep, online))
    return leads


# 结构化境外目标聚合的展示上限（防个别巨型主机塞爆 meta；完整原始数据仍在 endpoints[].enrichment）。
_OT_MAX_SUBDOMAINS = 50


def _as_dict(value: object) -> dict:
    """value 是 dict 则返回之，否则空 dict（兼容缺字段 / 坏结构）。"""
    return value if isinstance(value, dict) else {}


def _build_overseas_targets(endpoints: list[Endpoint]) -> list[dict]:
    """把各端点的境外被动富化(shodan/certs)聚合成**结构化、按主机**的列表，写 report.meta["overseas_targets"]。

    供 digest / HTML / Codex **机器可读**地查询/聚合/交叉比对（源站归属/端口/服务/技术栈/关联子域），
    免去从 evidence_to_obtain 的自然语言串里解析。全程被动 OSINT，对目标零流量。辖区门控与渲染层
    同口径：只收【国外 + 未知】主机，境内主机不进（境内走调证）。绝不抛（坏字段安全跳过）。

    每条结构（契约 D）：{host, ip, jurisdiction, asn, org, country, ports[],
    services[{port, product, version}], tech_stack[], related_subdomains[]}
    ——不含 cves / exposed_paths / active_probed。
    """
    out: list[dict] = []
    for ep in endpoints:
        if ep.kind not in ("domain", "ip"):
            continue
        e = _as_dict(ep.enrichment)
        shodan = _as_dict(e.get("shodan"))
        certs = _as_dict(e.get("certs"))
        asn = _as_dict(e.get("asn"))
        if not (shodan or certs):
            continue

        try:
            juris = forensic.classify_jurisdiction(
                ep.value,
                icp=e.get("icp"), rdap=e.get("rdap"), whois=e.get("whois"),
                dns=e.get("dns"), asn=e.get("asn"), webcheck=e.get("webcheck"), shodan=shodan,
            )
        except Exception:  # noqa: BLE001 — 辖区判定失败不得炸主流程；保守判未知
            logger.debug("[overseas_targets] 辖区判定失败：%s", ep.value, exc_info=True)
            juris = forensic.JURIS_UNKNOWN
        if juris == forensic.JURIS_DOMESTIC:
            continue  # 境内不呈现境外目标（与渲染层一致）

        entry: dict[str, object] = {"host": ep.value, "jurisdiction": juris}

        # 源站被动归属（shodan 优先，IP 端点用自身值兜底，asn 富化再兜底）：识别真实源站、归属哪。
        ip = shodan.get("ip") or (ep.value if ep.kind == "ip" else "") or asn.get("ip")
        if ip:
            entry["ip"] = ip
        asn_no = shodan.get("asn") or asn.get("asn")
        if asn_no:
            entry["asn"] = asn_no
        org = shodan.get("org") or shodan.get("isp") or asn.get("org") or asn.get("isp")
        if org:
            entry["org"] = org
        country = shodan.get("country") or asn.get("country")
        if country:
            entry["country"] = country

        # 端口（shodan 被动扫库）。
        ports = sorted({p for p in (shodan.get("ports") or []) if isinstance(p, int)})
        if ports:
            entry["ports"] = ports

        # 服务指纹（shodan：port/product/version）。
        services: list[dict] = []
        for s in shodan.get("services") or []:
            if isinstance(s, dict) and s.get("port") is not None:
                svc: dict[str, object] = {"port": s.get("port")}
                if s.get("product"):
                    svc["product"] = s.get("product")
                if s.get("version"):
                    svc["version"] = s.get("version")
                services.append(svc)
        if services:
            entry["services"] = services

        # 技术栈/后台框架指纹（被动 banner → 同后台疑同团伙串案）。
        tech = exposure.assess_tech_stack(shodan, e.get("webcheck"))
        if tech:
            entry["tech_stack"] = tech

        # 关联子域（crt.sh CT 日志 + shodan 关联主机名；去重，疑同团伙 → 并簇串案）。
        subs = [h for h in (certs.get("related_hostnames") or []) if isinstance(h, str)]
        for h in shodan.get("hostnames") or []:
            if isinstance(h, str) and h not in subs:
                subs.append(h)
        if subs:
            entry["related_subdomains"] = subs[:_OT_MAX_SUBDOMAINS]

        # 仅在确实有实质内容时收（光 host/jurisdiction 无意义）。
        if len(entry) > 2:
            out.append(entry)
    return out


# advice 兜底：未自带研判建议的 Lead 按类别给默认值。
# DOMAIN/IP 不在此表（其 advice 已由 build_endpoint_leads 按 infra 分级赋值）。
_DEFAULT_ADVICE_BY_CATEGORY: dict[LeadCategory, str] = {
    LeadCategory.CRYPTO_RECIPE: infra.ADVICE_INVESTIGATE,
    LeadCategory.SDK_SERVICE: infra.ADVICE_INVESTIGATE,
    LeadCategory.PAYMENT: infra.ADVICE_INVESTIGATE,
    LeadCategory.CONFIG_KEY: infra.ADVICE_INVESTIGATE,
    LeadCategory.PACKER: infra.ADVICE_INVESTIGATE,
    LeadCategory.CONTACT: infra.ADVICE_INVESTIGATE,
    LeadCategory.SIGNING: infra.ADVICE_REVIEW,
    # 以下分析器均按证据档自带 advice；此处仅兜底未研判项（默认待核，绝不默认建议调证）。
    LeadCategory.ADMIN_PANEL: infra.ADVICE_REVIEW,
    LeadCategory.FOURTH_PARTY_PAYMENT: infra.ADVICE_REVIEW,
    LeadCategory.SMS_FORWARDING: infra.ADVICE_REVIEW,
    LeadCategory.CARD_MERCHANT: infra.ADVICE_REVIEW,
    LeadCategory.SELF_HOSTED_IM: infra.ADVICE_REVIEW,
    LeadCategory.WALLET_SECRET: infra.ADVICE_INVESTIGATE,
    LeadCategory.BACKEND_CREDENTIAL: infra.ADVICE_INVESTIGATE,
}


def _apply_default_advice(leads: list[Lead]) -> None:
    """给未自带 advice 的 Lead 按类别填默认研判建议（就地修改，不覆盖已有值）。"""
    for lead in leads:
        if lead.advice:  # 分析器/构造器已研判，尊重之。
            continue
        default = _DEFAULT_ADVICE_BY_CATEGORY.get(lead.category)
        if default:
            lead.advice = default


# 离线扫描时附加到归属为空的端点 Lead 的说明。
_OFFLINE_NOTE = "离线扫描：未做 WHOIS/ICP/ASN 归属查询，归属待联网或人工核（非查无结果）"


def _apply_forensic(
    advice: str, host: str, evidence_to_obtain: list[str], notes: str, **enr: object
) -> str:
    """对「建议调证」的后端 Lead 按服务器辖区追加取证路径（国内调证 / 国外取证）。

    就地向 evidence_to_obtain 追加路径证据，返回带辖区标签的 notes。非建议调证（infra/私网/
    待核）不标——只给真后端分流。绝不抛（forensic 为纯函数）。
    """
    if advice != infra.ADVICE_INVESTIGATE:
        return notes
    juris = forensic.classify_jurisdiction(host, **enr)
    fp = forensic.forensic_path(juris)
    evidence_to_obtain.extend(fp.evidence)

    # 海外取证第一步：解析 IP 全为 CDN/反代时，提示先用公开情报被动穿透 CDN 定位真实源站 IP。
    # 放在源站定位之前——给随后的 Shodan 端口/服务加上下文（那是 CDN 边缘端口、非源站）。
    if juris == forensic.JURIS_FOREIGN:
        evidence_to_obtain.extend(
            forensic.render_origin_hint(enr.get("dns"), enr.get("asn"))
        )

    # ★ 境外被动取证证据按**最终辖区**门控（与两遍富化同口径，落到渲染层）：仅【国外 + 未知】渲染；
    #   国内（含 shodan country 把国外/未知翻成国内的情形）：一概不渲染——避免一条最终标
    #   「国内·可调证」的 Lead 上挂着境外取证痕迹（合规呈现自相矛盾、不可审计）。全程被动 OSINT。
    if juris in (forensic.JURIS_FOREIGN, forensic.JURIS_UNKNOWN):
        # 境外源站被动定位（Shodan）：源站归属(IP/ASN/geo) + 开放端口/服务指纹 + 关联主机名（串案）。
        evidence_to_obtain.extend(forensic.render_overseas_targets(enr.get("shodan")))
        # 证书透明度（被动 crt.sh）：CT 日志关联子域（含历史/影子子域），疑同团伙基础设施→并簇串案。
        evidence_to_obtain.extend(forensic.render_related_subdomains(enr.get("certs")))
        # 技术栈/后台框架指纹（被动 banner，shodan/webcheck）：仅识别 → 同后台疑同团伙串案，不研判漏洞。
        _tech = exposure.assess_tech_stack(enr.get("shodan"), enr.get("webcheck"))
        evidence_to_obtain.extend(forensic.render_tech_stack(_tech))
    return f"{notes}；{fp.label}" if notes else fp.label


def _domain_lead(ep: Endpoint, online: bool = True) -> Lead:
    icp = ep.enrichment.get("icp") or {}
    rdap = ep.enrichment.get("rdap") or {}
    whois = ep.enrichment.get("whois") or {}
    dns = ep.enrichment.get("dns") or {}

    # 归属优先级：icp（中国备案实名）> rdap（RDAP/whois 兜底）> whois（独立，已基本不再路由）。
    subject = (
        icp.get("subject")
        or rdap.get("registrant")
        or rdap.get("org")
        or whois.get("registrant")
        or whois.get("org")
    )
    where = None
    evidence_to_obtain: list[str] = []
    enriched = bool(icp or rdap or whois or dns)

    rdap_registrar = rdap.get("registrar")
    whois_registrar = whois.get("registrar")

    if icp.get("subject") or icp.get("license_no"):
        where = "工信部 ICP 备案系统 / 备案服务商"
        if icp.get("license_no"):
            evidence_to_obtain.append(f"ICP 备案号 {icp.get('license_no')} 主体实名信息")
        else:
            evidence_to_obtain.append("ICP 备案主体实名信息")
    elif rdap_registrar:
        where = f"域名注册商：{rdap_registrar}"
        evidence_to_obtain.append("RDAP/WHOIS 注册人/注册邮箱/注册时间")
    elif whois_registrar:
        where = f"域名注册商：{whois_registrar}"
        evidence_to_obtain.append("WHOIS 注册人/注册邮箱/注册时间")
    else:
        where = "域名注册商 / ICP 备案系统（需人工核）"
        evidence_to_obtain.append("RDAP / WHOIS / ICP 备案主体信息")

    confidence = Confidence.HIGH if subject else Confidence.MEDIUM

    # infra 分级：命中已知基础设施→无需调证；私网/无效→待核；否则→建议调证。
    advice, _reason = infra.classify_domain(ep.value)
    notes = _endpoint_notes(ep, online, enriched)

    # dns 富化：把当前解析 IP / 托管 ASN 体现为调证落点（向云厂商调租户/访问日志）。
    hosting_note = _dns_hosting_note(dns)
    if hosting_note:
        evidence_to_obtain.append(hosting_note)
        notes = f"{notes}；{hosting_note}" if notes else hosting_note

    # C1：域名来源可信度档降可信。当端点仅见于第三方库文件/超大字符串表（tier=
    #   library-file / bulk-string）且 classify 仍判"建议调证"（即非已知 infra/
    #   library-embedded、非私网）时，把 advice 降为"待核"并标低可信。★ 绝不降为"无需
    #   调证"（避免误杀真 C2）；已是 infra/私网档的不动（app tier 的真 C2 不受影响）。
    #   用 infra.effective_advice 统一判据（与目标筛选同口径，防判据漂移）。
    tier = ep.enrichment.get("tier")
    if advice == infra.ADVICE_INVESTIGATE and infra.effective_advice(ep.value, tier) != infra.ADVICE_INVESTIGATE:
        advice = infra.ADVICE_REVIEW
        confidence = Confidence.LOW
        tier_note = "仅见于第三方库文件/超大字符串表，疑似库内置，低可信"
        notes = f"{notes}；{tier_note}" if notes else tier_note

    notes = _apply_forensic(
        advice, ep.value, evidence_to_obtain, notes,
        icp=icp, rdap=rdap, whois=whois, dns=dns,
        webcheck=ep.enrichment.get("webcheck"), shodan=ep.enrichment.get("shodan"),
        certs=ep.enrichment.get("certs"),
    )
    return Lead(
        category=LeadCategory.DOMAIN,
        value=ep.value,
        subject=subject,
        where_to_request=where,
        evidence_to_obtain=evidence_to_obtain,
        confidence=confidence,
        source_refs=list(ep.evidences),
        notes=notes,
        advice=advice,
    )


def _ip_lead(ep: Endpoint, online: bool = True) -> Lead:
    asn = ep.enrichment.get("asn") or {}

    subject = asn.get("org") or asn.get("isp") or asn.get("asn")
    where = None
    evidence_to_obtain: list[str] = []
    enriched = bool(asn)

    if subject:
        where = f"云厂商 / IDC：{subject}"
        evidence_to_obtain.append("该 IP 在涉案时间段的租户/实名/访问日志")
    else:
        where = "云厂商 / IDC（需人工核 ASN 归属）"
        evidence_to_obtain.append("ASN 归属及租户信息")

    confidence = Confidence.HIGH if subject else Confidence.MEDIUM

    # IP 研判：内网/回环（端点已标 is_private）无需调证；公网 IP 默认建议调证。
    advice = infra.ADVICE_SKIP if ep.is_private else infra.ADVICE_INVESTIGATE

    notes = _apply_forensic(
        advice, ep.value, evidence_to_obtain, _endpoint_notes(ep, online, enriched),
        asn=asn, webcheck=ep.enrichment.get("webcheck"), shodan=ep.enrichment.get("shodan"),
        certs=ep.enrichment.get("certs"),
    )
    return Lead(
        category=LeadCategory.IP,
        value=ep.value,
        subject=subject,
        where_to_request=where,
        evidence_to_obtain=evidence_to_obtain,
        confidence=confidence,
        source_refs=list(ep.evidences),
        notes=notes,
        advice=advice,
    )


def _dns_hosting_note(dns: dict) -> str:
    """把 dns 富化的解析 IP / 托管 ASN 压成一句调证落点说明（无数据 → 空串）。

    形如「当前解析 IP 45.76.1.1(AS20473 Vultr), 45.76.1.2(AS20473 Vultr)→向云厂商调租户/访问日志」。
    """
    ips = dns.get("ips") or []
    hosting = dns.get("hosting") or []
    if not ips and not hosting:
        return ""

    by_ip: dict[str, dict] = {}
    for h in hosting:
        if isinstance(h, dict) and h.get("ip"):
            by_ip[h["ip"]] = h

    parts: list[str] = []
    # 以 hosting 的 IP 优先（带 ASN/org），再补只在 ips 里出现的裸 IP。
    seen: set[str] = set()
    for ip in ips:
        seen.add(ip)
        h = by_ip.get(ip)
        org_or_asn = ""
        if h:
            org_or_asn = h.get("asn") or h.get("org") or ""
        parts.append(f"{ip}({org_or_asn})" if org_or_asn else ip)
    for ip, h in by_ip.items():
        if ip in seen:
            continue
        org_or_asn = h.get("asn") or h.get("org") or ""
        parts.append(f"{ip}({org_or_asn})" if org_or_asn else ip)

    if not parts:
        return ""
    return f"当前解析 IP {', '.join(parts)}→向云厂商/IDC 调该 IP 在涉案时段的租户/访问日志"


def _endpoint_notes(ep: Endpoint, online: bool = True, enriched: bool = False) -> str:
    flags: list[str] = []
    if ep.is_cleartext:
        flags.append("明文传输")
    if ep.is_private:
        flags.append("内网/回环")
    if ep.is_suspicious:
        flags.append("可疑")
    # 离线且本端点未做归属富化 → 明确标注，避免"没查"被误读为"查不到"。
    if not online and not enriched:
        flags.append(_OFFLINE_NOTE)
    return "；".join(flags)
