"""端点 → 调证 Lead 生成：DOMAIN/IP Lead 构建、advice 兜底、结构化境外目标聚合。

从 pipeline.py 物理拆出（纯搬移、逻辑不变）：这一簇把（已富化的）端点转成可落地的 DOMAIN/IP
Lead、按类别补默认研判 advice、并把境外被动富化信号聚合成结构化 overseas_targets 段。pipeline 只
在 stage 里调用 build_endpoint_leads / _apply_default_advice / _build_overseas_targets。
"""

from __future__ import annotations

import logging

from apkscan.core import exposure, forensic, infra
from apkscan.core.models import Confidence, Endpoint, Lead, LeadCategory

logger = logging.getLogger(__name__)


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
