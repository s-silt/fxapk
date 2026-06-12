"""分析流水线：跑分析器 → 富化端点 → 聚合 → 生成 Lead → 组装 Report。

错误处理铁律：单分析器/富化器异常一律 try/except 记录到结果 + logging.exception，
绝不裸 pass、绝不让单点故障中断整条流水线。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkscan.analyzers.classify import classify_app
from apkscan.core import infra
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
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)


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

    # 3) 联网富化（按 applies_to 路由）——**只对"高度可疑"端点查归属**，不再有一个查一个。
    #    判据：infra 分级为"建议调证"（疑似 App 自有服务/C2）的域名/IP 才查 WHOIS/ICP/ASN；
    #    已知第三方基础设施/SDK/CDN（无需调证）、私网/回环/行情代码（待核）一律跳过。
    #    既省时（网络受限时不被一堆 infra/google 域名拖死、也不再误查 127.0.0.1）、又聚焦调证
    #    （WHOIS 归属对真 C2 才有意义，对 google 没意义）。
    enricher_status: list[dict] = []
    if config.online:
        targets = _enrichment_targets(endpoints)
        enricher_status = _enrich_endpoints(targets, discover_enrichers())
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
    endpoints: list[Endpoint], enrichers: list[BaseEnricher]
) -> list[dict]:
    """对每个端点按 applies_to 跑匹配的富化器，结果写入 endpoint.enrichment[provider]。

    返回每个富化器的聚合状态 [{provider, attempted, ok, failed, typical_error}]，
    使富化器层的系统性失败（如某 provider 全部失败）在报告里透明可见，
    而非打散进各 endpoint 难以察觉。
    """
    stats: dict[str, dict] = {}

    def _stat(provider: str) -> dict:
        return stats.setdefault(
            provider,
            {"provider": provider, "attempted": 0, "ok": 0, "failed": 0, "typical_error": None},
        )

    def _note_fail(st: dict, msg: str) -> None:
        st["failed"] += 1
        if not st["typical_error"]:
            st["typical_error"] = msg

    for ep in endpoints:
        for enricher in enrichers:
            applies_to = list(getattr(enricher, "applies_to", []) or [])
            if ep.kind not in applies_to:
                continue
            provider = getattr(enricher, "name", "") or enricher.__class__.__name__
            st = _stat(provider)
            st["attempted"] += 1

            try:
                result = enricher.enrich(ep)
            except Exception:  # noqa: BLE001 - 富化失败不阻塞主流程
                logger.exception("富化器执行异常：provider=%s endpoint=%s", provider, ep.value)
                ep.enrichment[provider] = {"ok": False, "error": "富化器异常"}
                _note_fail(st, "富化器异常")
                continue

            if result is None:
                logger.warning("富化器 %s 返回 None：%s", provider, ep.value)
                ep.enrichment[provider] = {"ok": False, "error": "enrich 返回 None"}
                _note_fail(st, "enrich 返回 None")
                continue

            data = dict(result.data)
            has_values = any(v not in (None, "", [], {}) for v in data.values())
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

    return list(stats.values())


def build_endpoint_leads(endpoints: list[Endpoint], online: bool = True) -> list[Lead]:
    """把（已富化的）domain/IP 端点转成 DOMAIN/IP Lead。

    - domain 的 where_to_request 优先用 icp 结果，其次 whois。
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


def _domain_lead(ep: Endpoint, online: bool = True) -> Lead:
    icp = ep.enrichment.get("icp") or {}
    whois = ep.enrichment.get("whois") or {}

    subject = icp.get("subject") or whois.get("registrant") or whois.get("org")
    where = None
    evidence_to_obtain: list[str] = []
    enriched = bool(icp or whois)

    if icp.get("subject") or icp.get("license_no"):
        where = "工信部 ICP 备案系统 / 备案服务商"
        if icp.get("license_no"):
            evidence_to_obtain.append(f"ICP 备案号 {icp.get('license_no')} 主体实名信息")
        else:
            evidence_to_obtain.append("ICP 备案主体实名信息")
    elif whois.get("registrar"):
        where = f"域名注册商：{whois.get('registrar')}"
        evidence_to_obtain.append("WHOIS 注册人/注册邮箱/注册时间")
    else:
        where = "域名注册商 / ICP 备案系统（需人工核）"
        evidence_to_obtain.append("WHOIS / ICP 备案主体信息")

    confidence = Confidence.HIGH if subject else Confidence.MEDIUM

    # infra 分级：命中已知基础设施→无需调证；私网/无效→待核；否则→建议调证。
    advice, _reason = infra.classify_domain(ep.value)
    notes = _endpoint_notes(ep, online, enriched)

    # C1：域名来源可信度档降可信。当端点仅见于第三方库文件/超大字符串表（tier=
    #   library-file / bulk-string）且 classify 仍判"建议调证"（即非已知 infra/
    #   library-embedded、非私网）时，把 advice 降为"待核"并标低可信。★ 绝不降为"无需
    #   调证"（避免误杀真 C2）；已是 infra/私网档的不动（app tier 的真 C2 不受影响）。
    tier = ep.enrichment.get("tier")
    if tier in (infra.TIER_LIBRARY_FILE, infra.TIER_BULK_STRING) and advice == infra.ADVICE_INVESTIGATE:
        advice = infra.ADVICE_REVIEW
        confidence = Confidence.LOW
        tier_note = "仅见于第三方库文件/超大字符串表，疑似库内置，低可信"
        notes = f"{notes}；{tier_note}" if notes else tier_note

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

    return Lead(
        category=LeadCategory.IP,
        value=ep.value,
        subject=subject,
        where_to_request=where,
        evidence_to_obtain=evidence_to_obtain,
        confidence=confidence,
        source_refs=list(ep.evidences),
        notes=_endpoint_notes(ep, online, enriched),
        advice=advice,
    )


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
