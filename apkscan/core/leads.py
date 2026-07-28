"""端点 → 调证 Lead 生成：DOMAIN/IP Lead 构建、advice 兜底、结构化境外目标聚合。

从 pipeline.py 物理拆出（纯搬移、逻辑不变）：这一簇把（已富化的）端点转成可落地的 DOMAIN/IP
Lead、按类别补默认研判 advice、并把境外被动富化信号聚合成结构化 overseas_targets 段。pipeline 只
在 stage 里调用 build_endpoint_leads / _apply_default_advice / _build_overseas_targets。
"""

from __future__ import annotations

import logging

from apkscan.core import exposure, forensic, infra
from apkscan.core.attribution import classify_network
from apkscan.core.models import (
    OBSERVED_CONTACT_SOURCES,
    Confidence,
    Endpoint,
    Lead,
    LeadCategory,
)
from apkscan.network.categories import CAT_CLOUD, CAT_HOSTING_RESELLER, CAT_IDC

logger = logging.getLogger(__name__)


def build_endpoint_leads(endpoints: list[Endpoint], online: bool = True) -> list[Lead]:
    """把（已富化的）domain/IP 端点转成 DOMAIN/IP Lead。

    - domain 的归属优先级：icp > rdap（RDAP/whois 兜底）> whois；dns 托管 IP/ASN 入 evidence/notes。
    - IP 的 where_to_request 用 asn 结果。
    URL 端点不直接产 Lead（其归属取决于其 domain/ip 部分）。

    online=False 时在 Lead.notes 标明"离线扫描，归属未查询"，让报告能区分
    "查过查不到" 与 "压根没查"。
    """
    # 样本内的低段位 IPv4 兄弟池：成簇（1.3.1.1 / 1.3.1.6 / 1.4.1.14）是版本号的主要产生形态，
    # 用来压住 classify_ip 的托管佐证豁免。全样本一次算好，逐端点只做减法。
    low_octet_pool = {
        infra._strip_port_suffix(ep.value)
        for ep in endpoints
        if ep.kind == "ip" and infra.is_low_octet_ipv4(ep.value)
    }
    leads: list[Lead] = []
    for ep in endpoints:
        if ep.kind == "domain":
            leads.append(_domain_lead(ep, online))
        elif ep.kind == "ip":
            leads.append(_ip_lead(ep, online, low_octet_pool=low_octet_pool))
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
                dns=e.get("dns"), asn=e.get("asn"), shodan=shodan,
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
        tech = exposure.assess_tech_stack(shodan)
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


#: 与 ``analyzers/repack_identity.VERDICT_REPACK_SUSPECTED`` 同值。
#: 这里刻意写字面量而不 import：core 层不该反向依赖 analyzers（分层倒置）。
#: 两处一致性由 tests 里的一条断言钉住——改了一边另一边会红。
_VERDICT_REPACK_SUSPECTED = "repack_suspected"

_REPACK_QUARANTINE_NOTE = (
    "疑似正版应用重打包：该端点可能属被仿冒的正版厂商，在与官方同版本包差分核实前"
    "按疑似正版资产隔离（建议调证→待核）；差分确认属注入后可人工恢复"
)


def apply_repack_quarantine(leads: list[Lead], meta: dict) -> list[str]:
    """样本判为「正版重打包」时，把其网络端点从调证出口隔离。返回被隔离的值。

    **为什么必须机制化，而不能只发一条警告**：自研马甲包与正版重打包件的接口 / 域名
    **归属完全相反**——后者属于被仿冒的正版厂商。而 ``advice == "建议调证"`` 是四个输出口
    的共同闸门：closure 目标选择、letters 调证函套打、``ioc --only-investigate`` 导出、
    HTML 的「C2/主控域名」红标区块。只要这一个字段不变，被仿冒厂商的官方域名就会一路走到
    自动生成的调证函草稿里，全靠人工在几十条 finding 中读到一条 MEDIUM 警告才能拦下。
    实测发生过同型错误：正版钱包的 156 条接口被整体错归为团伙资产。

    **为什么是降档而不是删除**：重打包件里**确实可能**被注入了真的 C2，只是无法只凭本包
    区分「原厂自带」与「注入」——那需要与官方同版本包做差分。删掉会漏掉真注入的；
    留在「建议调证」会误伤正版厂商。故降为「待核」并写明理由，把判断交还给人，
    人工差分核实后可改回。同理**绝不降到「无需调证」**——那等于替人下了"与本案无关"的结论。

    幂等：已被降档的（advice 不再是「建议调证」）不会二次处理，故运行时回灌路径重复调用安全。
    """
    rid = meta.get("repack_identity") if isinstance(meta, dict) else None
    if not (isinstance(rid, dict) and rid.get("verdict") == _VERDICT_REPACK_SUSPECTED):
        return []
    quarantined: list[str] = []
    for lead in leads:
        if lead.category not in (LeadCategory.DOMAIN, LeadCategory.IP):
            continue
        if lead.advice != infra.ADVICE_INVESTIGATE:
            continue
        lead.advice = infra.ADVICE_REVIEW
        lead.confidence = Confidence.LOW
        lead.notes = (
            f"{lead.notes}；{_REPACK_QUARANTINE_NOTE}" if lead.notes
            else _REPACK_QUARANTINE_NOTE
        )
        quarantined.append(lead.value)
    return quarantined


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
        # 技术栈/后台框架指纹（被动 banner，shodan）：仅识别 → 同后台疑同团伙串案，不研判漏洞。
        _tech = exposure.assess_tech_stack(enr.get("shodan"))
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
        shodan=ep.enrichment.get("shodan"),
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


#: ASN 归属被判为这几类时，算「这个地址落在租户可查的托管段上」——用作低段位裸 IP 的升级佐证。
#: ★刻意不含 CDN / security_proxy：CDN 边缘本就不该当源站进调证函（见线索清单约定）。
_TENANT_HOSTING_CATEGORIES = frozenset({CAT_CLOUD, CAT_HOSTING_RESELLER, CAT_IDC})


def _is_tenant_hosting_asn(asn: dict) -> bool:
    """ASN 富化结果是否指向「租户可查的托管段」（云 / IDC / 托管转售）。

    只在 :func:`infra.classify_ip` 的低段位豁免里当**佐证之一**用，不单独构成任何结论：
    绝大多数全球 IP 都有 ASN，光"有数据"没有区分度。
    """
    if not isinstance(asn, dict):
        return False
    org = asn.get("org") or asn.get("isp") or ""
    asn_no = str(asn.get("asn") or "") or None
    return classify_network(str(org), asn_no) in _TENANT_HOSTING_CATEGORIES


def _ip_lead(
    ep: Endpoint, online: bool = True, *, low_octet_pool: set[str] | None = None
) -> Lead:
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

    # IP 研判：内网/回环（端点已标 is_private）无需调证；其余交 classify_ip 分级——
    # 点分四段字面未必是地址，实测语料里版本号与 ASN.1 OID 大量以 confidence=HIGH
    # 混进"建议调证"，把闭环预算与外部富化额度吃光。判据用得着证据片段来判断
    # 这个字面在样本里是否当地址使用（带端口 / 在 URL 里），故把 snippet 拼给它。
    ip_reason = ""
    if ep.is_private:
        advice = infra.ADVICE_SKIP
    else:
        # ★全量扫证据、不截前 N 条：带端口/URL 的那条可能排在任何位置，
        #   漏看一条就可能把真实后端降成待核。snippet 有长度上限，全量拼接开销可控。
        context = " ".join((ev.snippet or "") for ev in ep.evidences)
        bare = infra._strip_port_suffix(ep.value)
        advice, ip_reason = infra.classify_ip(
            ep.value,
            context=context,
            # ★用 OBSERVED_CONTACT_SOURCES 而非 startswith("runtime")：后者会把
            #   runtime-derived（手编/回灌，只证明"出现在 runtime 报告里"）与解密派生值
            #   也当成实连证据。豁免形态判据这种事，必须用严格口径，与 attribution 侧同源。
            runtime_observed=any(
                str(ev.source) in OBSERVED_CONTACT_SOURCES for ev in ep.evidences
            ),
            # 低段位裸 IP 的定向豁免佐证：ASN 落托管段 + 样本内无同形态编号序列。
            hosting_attributed=_is_tenant_hosting_asn(asn),
            low_octet_siblings=len((low_octet_pool or set()) - {bare}),
        )

    endpoint_notes = _endpoint_notes(ep, online, enriched)
    # 靠外部佐证把低段位裸 IP 捞回"建议调证"时，把保留意见落进 notes——办案人发函前该看到
    # 「这个值的形态本身存疑，是 ASN 佐证把它升回来的」，而不是只看到一条干净的调证条目。
    if advice == infra.ADVICE_INVESTIGATE and "四段值偏低" in ip_reason:
        endpoint_notes = f"{endpoint_notes}；{ip_reason}" if endpoint_notes else ip_reason

    notes = _apply_forensic(
        advice, ep.value, evidence_to_obtain, endpoint_notes,
        asn=asn, shodan=ep.enrichment.get("shodan"),
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
