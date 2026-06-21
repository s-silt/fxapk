"""分析流水线：跑分析器 → 富化端点 → 聚合 → 生成 Lead → 组装 Report。

错误处理铁律：单分析器/富化器异常一律 try/except 记录到结果 + logging.exception，
绝不裸 pass、绝不让单点故障中断整条流水线。
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from apkscan.analyzers.classify import classify_app
from apkscan.core import forensic, infra
from apkscan.core.models import (
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
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

#: 富化并发度：按端点并发跑富化器（I/O 密集，瓶颈是 whois/rdap 的 ~30s 超时串行累加）。
#: 默认 8 个 worker。每个端点由单一 worker 串行跑其匹配的全部富化器，故同一 ep.enrichment
#: 无并发写竞争；只有跨端点共享的 provider 统计需加锁聚合。
ENRICH_MAX_WORKERS = 8


def run(ctx: "AnalysisContext", config: AnalysisConfig) -> Report:
    """执行完整流水线，返回 Report。"""
    capabilities = detect_capabilities(online=config.online)
    # 平台能力：让 requires=["apk"] 的 Android 专属 analyzer 在 IPA 上自动 skipped、
    # requires=["ipa"] 的 iOS analyzer 在 APK 上 skipped（复用既有 requires 门控，pipeline 主体不变）。
    platform = getattr(ctx, "platform", "android")
    capabilities.add("apk" if platform == "android" else "ipa")

    leads: list[Lead] = []
    endpoints: list[Endpoint] = []
    findings: list = []
    meta: dict = {"package_name": ctx.package_name, "platform": platform}
    analyzer_status: list[dict] = []

    # 1) 跑分析器（逐个 try/except；requires 不满足→skipped）
    for analyzer in discover_analyzers():
        name = getattr(analyzer, "name", "") or analyzer.__class__.__name__
        requires = list(getattr(analyzer, "requires", []) or [])

        missing = [cap for cap in requires if cap not in capabilities]
        if missing:
            reason = f"缺少能力：{', '.join(missing)}"
            logger.info("跳过分析器 %s：%s", name, reason)
            analyzer_status.append({"name": name, "status": "skipped", "reason": reason})
            continue

        try:
            result = analyzer.analyze(ctx)
        except Exception as exc:  # noqa: BLE001 - 单点故障不得中断流水线
            logger.exception("分析器执行异常：%s", name)
            analyzer_status.append({"name": name, "status": "error", "reason": str(exc)})
            continue

        if result is None:
            logger.warning("分析器 %s 返回 None，按空结果处理", name)
            analyzer_status.append(
                {"name": name, "status": "error", "reason": "analyze 返回 None"}
            )
            continue

        # 2) 聚合 endpoints/leads/findings/meta
        endpoints.extend(result.endpoints)
        leads.extend(result.leads)
        findings.extend(result.findings)
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
            analyzer_status.append(
                {"name": name, "status": "error", "reason": result.error}
            )
        else:
            analyzer_status.append({"name": name, "status": "ran", "reason": ""})

    # 2.4) 端点按 value 去重合并（不同分析器可能产出同一 value 的 Endpoint）。
    # 必须在富化与 build_endpoint_leads 之前，避免重复 DOMAIN/IP Lead 与重复富化查询。
    endpoints = _dedup_endpoints(endpoints)

    # 2.5) 把上下文的降级标志显式带入报告，避免"未采集"被静默当成"采集为空"。
    if getattr(ctx, "dex_available", True) is False:
        if platform == "ios":
            # iOS 本就无 DEX，不是"加固"——H5 端点在 www JS 资源里命中，这不是降级告警。
            meta["dex_parse_failed"] = False
        else:
            meta["dex_parse_failed"] = True
            logger.warning("DEX 不可用（加固/无 dex），静态端点/SDK/支付线索严重不完整")
    if getattr(ctx, "apk_validation_ok", True) is False:
        meta["apk_validation_warning"] = "APK 合法性校验异常，分析结果可能不可靠（详见日志）"

    # 3) 联网富化（两遍）——**只对"高度可疑"端点（建议调证）查**，不再有一个查一个。
    #    判据：infra 分级为"建议调证"（疑似 App 自有服务/C2）的域名/IP 才查；已知第三方基础设施/
    #    SDK/CDN（无需调证）、私网/回环/行情代码（待核）一律跳过。省时 + 聚焦调证。
    #    ★ 两遍富化（见 _run_enrichment）：①归属(rdap/whois/dns/asn/icp/webcheck)定辖区 →
    #      ②攻击面(shodan/recon/cve/certs)仅对【国外+未知】跑；主动探测(recon)仅对【国外】跑。
    enricher_status: list[dict] = []
    if config.online:
        targets = _enrichment_targets(endpoints)
        enricher_status = _run_enrichment(targets, discover_enrichers())
        meta["enriched_target_count"] = len(targets)
        net_eps = sum(1 for ep in endpoints if ep.kind in ("domain", "ip"))
        logger.info(
            "联网富化：仅对 %d 个高度可疑端点（建议调证）查归属，跳过其余 %d 个域名/IP（infra/已知/私网）",
            len(targets),
            max(0, net_eps - len(targets)),
        )
    else:
        meta["enrichment_skipped_offline"] = True
        logger.info("offline 模式：跳过全部富化器（归属信息未查询，非查无结果）")

    # 4) 端点 → DOMAIN/IP Lead（分析器本身不产 DOMAIN/IP Lead，统一在此生成）
    #    DOMAIN/IP Lead 的 advice 已在 build_endpoint_leads 内按 infra 分级赋值。
    leads.extend(build_endpoint_leads(endpoints, online=config.online))

    # 4.5) advice 兜底：分析器若未自带研判建议，按线索类别给默认值，
    #      避免报告里出现空白的"是否调证"列。已自带 advice 的不覆盖。
    _apply_default_advice(leads)

    # 5) 组装 Report
    report = Report(
        package_name=ctx.package_name,
        meta=meta,
        leads=leads,
        endpoints=endpoints,
        findings=findings,
        analyzer_status=analyzer_status,
        enricher_status=enricher_status,
    )

    # 6) App 类型聚合分类（在所有分析器跑完 + build_endpoint_leads 之后调用一次）。
    #    聚合 report 现成 meta/leads/endpoints/findings 信号，加权定类，并据类型**追加**
    #    针对性调证 Lead（只追加、不改已有 Lead）。classify_app 整体 try/except 兜底，
    #    分类失败时 report 原样返回，绝不炸流水线。
    classify_app(report)

    return report


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
    两遍富化用它把"主动探测（active=True）"门控到仅国外端点；不传则全跑（向后兼容）。

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

    def _stat(provider: str) -> dict:
        # 在 stats_lock 内调用。
        return stats.setdefault(
            provider,
            {"provider": provider, "attempted": 0, "ok": 0, "failed": 0, "typical_error": None},
        )

    def _enrich_one(ep: Endpoint) -> None:
        """对单个端点跑其匹配的全部富化器（在单一 worker 内串行）。"""
        for enricher in enrichers:
            applies_to = list(getattr(enricher, "applies_to", []) or [])
            if ep.kind not in applies_to:
                continue
            if gate is not None and not gate(ep, enricher):
                continue  # 两遍富化门控：如主动探测仅国外（非国外端点跳过该富化器，不计统计）
            provider = getattr(enricher, "name", "") or enricher.__class__.__name__

            with stats_lock:
                st = _stat(provider)
                st["attempted"] += 1

            try:
                result = enricher.enrich(ep)
            except Exception:  # noqa: BLE001 - 富化失败不阻塞主流程
                logger.exception("富化器执行异常：provider=%s endpoint=%s", provider, ep.value)
                ep.enrichment[provider] = {"ok": False, "error": "富化器异常"}
                with stats_lock:
                    _note_fail(_stat(provider), "富化器异常")
                continue

            if result is None:
                logger.warning("富化器 %s 返回 None：%s", provider, ep.value)
                ep.enrichment[provider] = {"ok": False, "error": "enrich 返回 None"}
                with stats_lock:
                    _note_fail(_stat(provider), "enrich 返回 None")
                continue

            data = dict(result.data)
            has_values = any(v not in (None, "", [], {}) for v in data.values())
            with stats_lock:
                st = _stat(provider)
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

    if endpoints:
        # max_workers 不超过端点数，避免端点少时空建大量线程。
        workers = max(1, min(ENRICH_MAX_WORKERS, len(endpoints)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="enrich") as pool:
            # list() 强制求值 → 任一 worker 内未捕获异常会在此重抛（_enrich_one 内部已逐
            # enrich try/except，正常不会到这；这里是兜底，不让异常被 executor 静默吞掉）。
            list(pool.map(_enrich_one, endpoints))

    return list(stats.values())


def _note_fail(st: dict, msg: str) -> None:
    """记一次失败到 provider 统计（调用方须持 stats_lock）。"""
    st["failed"] += 1
    if not st["typical_error"]:
        st["typical_error"] = msg


# attack_surface 阶段的组内顺序：cve 依赖同端点 shodan/recon 写入的指纹，故排在它们之后。
_ATTACK_SURFACE_ORDER = {"shodan": 0, "recon": 0, "certs": 0, "cve": 1}


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
    except Exception:  # noqa: BLE001 — 辖区判定失败不得炸主流程；保守判未知（不触发主动探测）
        logger.debug("辖区判定失败，按未知处理：%s", ep.value, exc_info=True)
        return forensic.JURIS_UNKNOWN


def _run_enrichment(targets: list[Endpoint], enrichers: list[BaseEnricher]) -> list[dict]:
    """两遍富化编排：①归属(attribution) → 定辖区 → ②攻击面(attack_surface)。

    第②遍只对【国外 + 未知】端点跑（境内服务器走调证路径、不做攻击面取证）；其中 **active=True
    的主动探测（recon）再收紧到仅【国外】**（未知辖区不主动触达，最保守）。辖区结果仅暂存于本函数
    局部 dict（按 id(ep)），**绝不写入 ep.enrichment**——避免 ``_jurisdiction`` 等内部键泄漏进
    report.json 被下游误当 provider。
    """
    attribution = [e for e in enrichers if _enricher_phase(e) == "attribution"]
    attack_surface = sorted(
        (e for e in enrichers if _enricher_phase(e) == "attack_surface"),
        key=lambda e: _ATTACK_SURFACE_ORDER.get(getattr(e, "name", ""), 0),
    )

    # 第①遍：归属富化（沿用既有并发/缓存/统计机制）。
    stats = _enrich_endpoints(targets, attribution)
    if not attack_surface:
        return stats

    # 定辖区（本地 dict，绝不写回 ep.enrichment）。
    juris: dict[int, str] = {id(ep): _classify_endpoint_jurisdiction(ep) for ep in targets}

    # 第②遍目标：国外 + 未知（被动攻击面）；主动探测再收紧到仅国外（见 gate）。
    phase2_targets = [
        ep
        for ep in targets
        if juris[id(ep)] in (forensic.JURIS_FOREIGN, forensic.JURIS_UNKNOWN)
    ]
    if not phase2_targets:
        return stats

    def _gate(ep: Endpoint, enricher: BaseEnricher) -> bool:
        # 主动探测（active=True）仅对【国外 + 最终建议调证】端点放行；被动攻击面对【国外+未知】均放行。
        # ★ tier 判据：库内置档（library-file/bulk-string）端点最终被判"待核"（见 _domain_lead C1），
        #   即便辖区=国外也绝不主动探测——与最终 Lead 研判同口径，消除判据漂移（合规红线）。
        if getattr(enricher, "active", False):
            return (
                juris[id(ep)] == forensic.JURIS_FOREIGN
                and infra.effective_advice(ep.value, ep.enrichment.get("tier"))
                == infra.ADVICE_INVESTIGATE
            )
        return True

    stats += _enrich_endpoints(phase2_targets, attack_surface, gate=_gate)
    return stats


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

    # ★ 攻击面/主动探测证据按**最终辖区**门控（与两遍富化 gate 同口径，落到渲染层）：
    #   - 被动攻击面（Shodan/CVE/crt.sh）：仅【国外+未知】渲染；
    #   - 主动探测（recon）：仅【国外】渲染；
    #   - 国内（含 shodan country 把国外/未知翻成国内的情形）：一概不渲染——避免一条最终标
    #     「国内·可调证」的 Lead 上挂着对它的攻击面/主动侦查痕迹（合规呈现自相矛盾、不可审计）。
    if juris in (forensic.JURIS_FOREIGN, forensic.JURIS_UNKNOWN):
        # Shodan 攻击面（被动）：开放端口/服务指纹/已知漏洞方向/关联主机。
        evidence_to_obtain.extend(forensic.render_attack_surface(enr.get("shodan")))
        # CVE 补查（被动 NVD）：补 Shodan 未覆盖指纹的已知漏洞方向（带 CVSS），仅情报方向、非利用。
        evidence_to_obtain.extend(forensic.render_cve_surface(enr.get("cve")))
        # 证书透明度（被动 crt.sh）：CT 日志关联子域（含历史/影子子域），疑同团伙基础设施→并簇串案。
        evidence_to_obtain.extend(forensic.render_related_subdomains(enr.get("certs")))
    if juris == forensic.JURIS_FOREIGN:
        # 主动探测（recon，opt-in/已授权）：实时侦查的开放端口/TLS证书/HTTP指纹/暴露后台路径。
        evidence_to_obtain.extend(forensic.render_active_recon(enr.get("recon")))
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
    #   用 infra.effective_advice 统一判据（与目标筛选/主动探测门控同口径，防判据漂移）。
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
        recon=ep.enrichment.get("recon"), cve=ep.enrichment.get("cve"),
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
        recon=ep.enrichment.get("recon"), cve=ep.enrichment.get("cve"),
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
