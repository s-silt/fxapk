"""端点 → 调证 Lead 生成：DOMAIN/IP Lead 构建、advice 兜底、结构化境外目标聚合。

从 pipeline.py 物理拆出（纯搬移、逻辑不变）：这一簇把（已富化的）端点转成可落地的 DOMAIN/IP
Lead、按类别补默认研判 advice、并把境外被动富化信号聚合成结构化 overseas_targets 段。pipeline 只
在 stage 里调用 build_endpoint_leads / _apply_default_advice / _build_overseas_targets。
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Mapping

from apkscan.core import appframework, exposure, forensic, infra
from apkscan.core.attribution import classify_network, tenant_distribution_edge
from apkscan.core.restore import is_restored, restore_index
from apkscan.core.models import (
    DOWNGRADE_EVIDENCE_SCOPE,
    DOWNGRADE_REPACK_IDENTITY,
    DOWNGRADE_SNI_MASQUERADE,
    DOWNGRADE_SOURCE_TIER,
    OBSERVED_CONTACT_SOURCES,
    SNI_MASQUERADE_KEY,
    Confidence,
    Endpoint,
    EvidenceScope,
    Lead,
    LeadCategory,
    apply_downgrade,
    has_case_evidence,
)
from apkscan.network.categories import CAT_CLOUD, CAT_HOSTING_RESELLER, CAT_IDC
from apkscan.core.source_status import provider_payload_if_hit

logger = logging.getLogger(__name__)

_EVIDENCE_SCOPE_NOTE = (
    "仅由批量/跨案参考或旧版未声明作用域的材料支撑；可作复核线索，"
    "但不能单独作为当前案件调证或闭环依据"
)


def _apply_evidence_scope(lead: Lead, endpoint: Endpoint) -> None:
    """参考材料可见但不升级：无当前案件直接证据时结构化降到待核。"""
    if not has_case_evidence(endpoint.evidences):
        apply_downgrade(lead, DOWNGRADE_EVIDENCE_SCOPE, _EVIDENCE_SCOPE_NOTE)


def quarantine_reference_only_leads(lead_items: list[Lead], endpoints: list[Endpoint]) -> None:
    """给载入的旧/外部报告补作用域闸；无直接案件证据的 Lead 一律降档。

    所有类别都可由自身 ``source_refs`` 取得资格；仅 DOMAIN/IP 还能由同值 Endpoint
    的直接证据兜底。不能给其它类别套用网络端点的值关联，否则同字面但不同语义的
    PAYMENT/CONTACT 等会被错误升级。
    """
    direct: set[tuple[str, str]] = {
        (ep.kind, infra.match_key(ep.kind, ep.value))
        for ep in endpoints
        if ep.kind in {"domain", "ip"} and has_case_evidence(ep.evidences)
    }
    for lead in lead_items:
        if has_case_evidence(lead.source_refs):
            continue
        if lead.category in {LeadCategory.DOMAIN, LeadCategory.IP}:
            kind = lead.category.value.lower()
            key = (kind, infra.match_key(kind, lead.value))
            if key in direct:
                continue
        apply_downgrade(lead, DOWNGRADE_EVIDENCE_SCOPE, _EVIDENCE_SCOPE_NOTE)


def build_endpoint_leads(
    endpoints: list[Endpoint],
    online: bool = True,
    *,
    sibling_pool: set[str] | None = None,
    framework: appframework.AppFramework | None = None,
) -> list[Lead]:
    """把（已富化的）domain/IP 端点转成 DOMAIN/IP Lead。

    - domain 的归属优先级：icp > rdap（RDAP/whois 兜底）> whois；dns 托管 IP/ASN 入 evidence/notes。
    - IP 的 where_to_request 用 asn 结果。
    URL 端点不直接产 Lead（其归属取决于其 domain/ip 部分）。

    online=False 时在 Lead.notes 标明"离线扫描，归属未查询"，让报告能区分
    "查过查不到" 与 "压根没查"。

    ``framework`` 由调用方从 ``report.meta['app_framework']`` 复原后传入（见
    :func:`apkscan.core.appframework.framework_from_meta`）。给了就按该样本的实际框架
    判断哪个 .so 装着本应用代码；不给则退回全局并集这一宽口径。
    """
    # 样本内的低段位 IPv4 兄弟池：成簇（1.3.1.1 / 1.3.1.6 / 1.4.1.14）是版本号的主要产生形态，  # leak-scan: allow 判据说明所举的版本号/序号形态例子，非网络地址
    # 用来压住 classify_ip 的托管佐证豁免。全样本一次算好，逐端点只做减法。
    #
    # ★``sibling_pool`` 由调用方传入**全样本**的池。动态回灌只把新增端点交给本函数，若就地
    #   从 endpoints 自算，静态侧已成簇的兄弟就不在池里，新回灌的同形态值会被当孤值放行。
    low_octet_pool = sibling_pool if sibling_pool is not None else {
        infra._strip_port_suffix(ep.value)
        for ep in endpoints
        if ep.kind == "ip" and infra.is_low_octet_ipv4(ep.value)
    }
    # 哪些 native 库能被认出是「第三方 SDK 的二进制」——供 IP 侧判断裸地址是不是 SDK 内置常量。
    # ★同样要全样本一次算好：判据要看的是"这个库里还有没有该 SDK 自己的域名"，
    #   而域名端点与 IP 端点是两条独立记录，逐端点看不出来。
    vendor_libs = _vendor_sdk_libraries(endpoints, framework=framework)
    leads: list[Lead] = []
    for ep in endpoints:
        if ep.kind == "domain":
            leads.append(_domain_lead(ep, online))
        elif ep.kind == "ip":
            leads.append(_ip_lead(ep, online, low_octet_pool=low_octet_pool, vendor_libs=vendor_libs))
    return leads


#: 一个 native 库里要出现几个**已知第三方基础设施域名**，才算认出它是厂商 SDK 的二进制。
#: 取 2 而不是 1：单个已知域名太容易被自带 .so 的样本顺手写进去（随手塞一个众所周知的
#: 大厂域名就能让同文件里的真后端地址降档），两个以上才构成"这确实是那家 SDK 的库"的形态。
_VENDOR_SDK_MIN_KNOWN_DOMAINS = 2

# 应用**自身**业务代码的编译产物（Flutter 的 libapp.so、Unity 的 libil2cpp.so 等）必须排除在
# 厂商库判定之外：整个应用的业务代码都在这类文件里，引用一堆第三方域名是常态（地图、头像、
# CDN、文档链接都写在业务代码里），"带 ≥2 个已知基础设施域名"这条形态判据必然命中，于是
# **同一文件里本应用的真后端会被一并降成待核**。实测踩过：一份 Flutter 样本的自建服务器与其
# 已确认的 C2 同处业务代码容器，却被判成"疑为该 SDK 内置常量"。
#
# 判据与各框架的产物命名是 :mod:`apkscan.core.appframework` 的单一真源，此处只调用它。


def _native_lib_of(location: object) -> str:
    """证据位置指向 native 库时返回其文件名（小写），否则空串。

    ``lib/arm64-v8a/libDingRtc.so`` 与 ``lib/armeabi-v7a/libDingRtc.so`` 折到同一个名字：
    多 ABI 是同一个库的多份拷贝，不该被当成两个来源。
    """
    loc = str(location or "").replace("\\", "/").lower()
    if not loc.endswith(".so"):
        return ""
    return loc.rsplit("/", 1)[-1]


def _vendor_sdk_libraries(
    endpoints: list[Endpoint], *, framework: appframework.AppFramework | None = None
) -> set[str]:
    """找出「带着 ≥2 个已知第三方基础设施域名」的 native 库文件名集合。

    ★应用自身业务代码的编译产物先行排除：它们必然携带多个第三方域名，不排除就会把
    本 App 的真后端一并降档。给了 ``framework``（该样本实际识别出的框架）就按它精确判，
    否则退回全局并集这一宽口径——两者的差别在于：Unity 样本里一个真叫 ``libapp.so``
    的第三方库，精确口径下不会被当成本应用代码而免检。
    """
    per_lib: dict[str, set[str]] = {}
    for ep in endpoints:
        if ep.kind != "domain" or not infra.is_known_infra(ep.value):
            continue
        for ev in ep.evidences:
            lib = _native_lib_of(ev.location)
            if lib and not appframework.is_app_own_code(lib, framework):
                per_lib.setdefault(lib, set()).add(ep.value.lower())
    return {lib for lib, doms in per_lib.items() if len(doms) >= _VENDOR_SDK_MIN_KNOWN_DOMAINS}


def _vendor_sdk_constant(ep: Endpoint, vendor_libs: set[str]) -> str:
    """该端点是否**只**出现在某一个已认出的厂商 SDK 库内；是则返回库名，否则空串。

    要求"全部证据同属一个库"：只要还有别的来源（dex 串、资源、运行时），这个地址就不只是
    SDK 常量，判据不适用——宁可留在原来的出口里。
    """
    libs = {_native_lib_of(ev.location) for ev in ep.evidences}
    if len(libs) != 1:
        return ""
    lib = libs.pop()
    return lib if lib and lib in vendor_libs else ""


# 结构化境外目标聚合的展示上限（防个别巨型主机塞爆 meta；完整原始数据仍在 endpoints[].enrichment）。
_OT_MAX_SUBDOMAINS = 50


def _as_dict(value: object) -> dict:
    """value 是 dict 则返回之，否则空 dict（兼容缺字段 / 坏结构）。"""
    return value if isinstance(value, dict) else {}


def _endpoint_parts(endpoint: object) -> tuple[str, str, dict]:
    """容错取出 Endpoint 或已序列化 endpoint 的分类、值与富化块。"""
    if isinstance(endpoint, Endpoint):
        return endpoint.kind, endpoint.value, _as_dict(endpoint.enrichment)
    if isinstance(endpoint, Mapping):
        return (
            str(endpoint.get("kind") or ""),
            str(endpoint.get("value") or ""),
            _as_dict(endpoint.get("enrichment")),
        )
    return "", "", {}


def _is_overseas_routing_candidate(kind: str, value: str, enrichment: dict) -> bool:
    """是否属于两阶段富化的高价值 domain/IP 候选。

    与 ``core.enrichment._enrichment_targets`` 共用同一组公共判据，但不反向导入该编排模块，
    避免 leads/enrichment 循环依赖。这个门使「未画像数」不会把已知 SDK/CDN 和私网噪音全数进去。
    """
    if kind == "domain":
        return infra.effective_advice(value, enrichment.get("tier")) == infra.ADVICE_INVESTIGATE
    if kind == "ip":
        advice, _reason = infra.classify_ip(value)
        return advice == infra.ADVICE_INVESTIGATE
    return False


def _lead_network_key(lead: object) -> tuple[str, str] | None:
    """取最终 Lead 的 domain/IP 匹配键；非最高档或坏结构返回 None。"""
    if isinstance(lead, Lead):
        category: object = lead.category
        value = lead.value
        advice = lead.advice
    elif isinstance(lead, Mapping):
        category = lead.get("category")
        value = str(lead.get("value") or "")
        advice = lead.get("advice")
    else:
        return None
    if advice != infra.ADVICE_INVESTIGATE or not value:
        return None

    if isinstance(category, LeadCategory):
        category_name = category.value
    elif isinstance(category, Mapping):
        category_name = str(
            category.get("_value_")
            or category.get("value")
            or category.get("_name_")
            or category.get("name")
            or ""
        )
    else:
        category_name = str(category or "")
    category_name = category_name.rsplit(".", 1)[-1].upper()
    if category_name not in {LeadCategory.DOMAIN.value, LeadCategory.IP.value}:
        return None
    kind = category_name.lower()
    normalized = infra.match_key(kind, value).strip().lower().rstrip(".")
    return (kind, normalized) if normalized else None


def _final_network_target_keys(final_leads: object) -> set[tuple[str, str]] | None:
    """最终/安全投影 Lead 中的最高档网络标的；None 表示旧报告未提供 leads。"""
    if not isinstance(final_leads, (list, tuple)):
        return None
    return {
        key
        for lead in final_leads
        if (key := _lead_network_key(lead)) is not None
    }


def _project_overseas_profiles(
    profiled_targets: object,
    final_leads: object,
) -> list[dict]:
    """profile-only 列表按最终 DOMAIN/IP 调证标的做不变更原数据的展示投影。"""
    target_items = profiled_targets if isinstance(profiled_targets, (list, tuple)) else []
    final_keys = _final_network_target_keys(final_leads)
    allowed_values = {value for _kind, value in final_keys} if final_keys is not None else None
    projected: list[dict] = []
    for target in target_items:
        if not isinstance(target, Mapping):
            continue
        host = str(target.get("host") or "").strip().lower().rstrip(".")
        if not host or (allowed_values is not None and host not in allowed_values):
            continue
        projected.append(dict(target))
    return projected


def _supported_jurisdiction(value: str, enrichment: dict) -> str:
    """只用结果协议许可的 DNS/ASN/Shodan hit 判基础设施辖区。"""
    try:
        return forensic.classify_jurisdiction(
            value,
            dns=provider_payload_if_hit(enrichment, "dns"),
            asn=provider_payload_if_hit(enrichment, "asn"),
            shodan=provider_payload_if_hit(enrichment, "shodan"),
        )
    except Exception:  # noqa: BLE001 — 覆盖统计不得中断报告；保守记未知
        logger.debug("[overseas_targets] 辖区判定失败：%s", value, exc_info=True)
        return forensic.JURIS_UNKNOWN


def _overseas_target_coverage(
    endpoints: object,
    profiled_targets: object,
    final_leads: object = None,
) -> dict[str, object]:
    """统计境外/辖区未知候选与 Shodan/CT 画像之间的覆盖缺口。

    ``overseas_targets`` 从设计上就是 **profile-only**：只收 Shodan 或证书透明度
    已返回实质画像的主机。因此候选全集需独立从 endpoint 路由面计算：先以
    最终/安全投影后 ``advice=建议调证`` 的 DOMAIN/IP Lead 值限定分母，再严格只读 ``source_status=hit``
    许可的 DNS/ASN/Shodan payload 判辖区。没有可用归属信号的路由候选保守记为
    「未知」，不会因 Shodan/CT 无记录或失败而从覆盖分母消失。

    返回仅含聚合计数，不增加新的原值导出面。旧报告若只有 profile 列表而缺
    leads/endpoints，profile 主机仍并入分母，保证 ``profiled <= total``。
    """
    candidate_jurisdiction: dict[str, str] = {}
    final_keys = _final_network_target_keys(final_leads)
    endpoint_items = endpoints if isinstance(endpoints, (list, tuple)) else []
    for endpoint in endpoint_items:
        kind, value, enrichment = _endpoint_parts(endpoint)
        endpoint_key = (
            kind,
            infra.match_key(kind, value).strip().lower().rstrip("."),
        )
        if not value:
            continue
        if final_keys is not None:
            if endpoint_key not in final_keys:
                continue
        elif not _is_overseas_routing_candidate(kind, value, enrichment):
            continue
        jurisdiction = _supported_jurisdiction(value, enrichment)
        if jurisdiction == forensic.JURIS_DOMESTIC:
            continue
        candidate_jurisdiction[endpoint_key[1]] = jurisdiction

    profiled_hosts: set[str] = set()
    target_items = _project_overseas_profiles(profiled_targets, final_leads)
    for target in target_items:
        if not isinstance(target, Mapping):
            continue
        host = str(target.get("host") or "").strip().lower().rstrip(".")
        if not host:
            continue
        profiled_hosts.add(host)
        candidate_jurisdiction.setdefault(
            host,
            str(target.get("jurisdiction") or forensic.JURIS_UNKNOWN),
        )

    candidate_hosts = set(candidate_jurisdiction)
    profiled_in_scope = candidate_hosts & profiled_hosts
    by_jurisdiction = {
        forensic.JURIS_FOREIGN: sum(
            value == forensic.JURIS_FOREIGN for value in candidate_jurisdiction.values()
        ),
        forensic.JURIS_UNKNOWN: sum(
            value != forensic.JURIS_FOREIGN for value in candidate_jurisdiction.values()
        ),
    }
    return {
        "scope": "profile-only",
        "candidate_hosts_total": len(candidate_hosts),
        "profiled_hosts": len(profiled_in_scope),
        "unprofiled_hosts": len(candidate_hosts - profiled_in_scope),
        "by_jurisdiction": by_jurisdiction,
        "note": (
            "overseas_targets 只列 Shodan/CT 已返回实质画像的主机，不是境外/"
            "辖区未知候选全表；profiled_hosts=0 不表示没有候选。候选分母只纳入"
            "最终/安全投影后仍为建议调证的 DOMAIN/IP，辖区只读状态许可的 "
            "DNS/ASN/Shodan payload。"
        ),
    }


def _build_overseas_targets(endpoints: list[Endpoint]) -> list[dict]:
    """把各端点已命中的 Shodan/CT 画像聚合成**结构化、按主机**的列表。

    供 digest / HTML / Codex **机器可读**地查询/聚合/交叉比对（候选归属/端口/服务/技术栈/关联子域），
    免去从 evidence_to_obtain 的自然语言串里解析。字段只形成基础设施候选，不能单独确认 Origin、家族
    或运营者。该列表是 **profile-only 投影**，不是境外/辖区未知候选全表；只有
    ASN/DNS 归属或 Shodan/CT 无记录的候选不会入列表，它们由
    :func:`_overseas_target_coverage` 计入未画像分母。辖区门控只收【国外 + 未知】主机。
    绝不抛（坏字段安全跳过）。

    每条结构（契约 D）：{host, ip, jurisdiction, asn, org, country, ports[],
    services[{port, product, version}], tech_stack[], related_subdomains[]}
    ——不含 cves / exposed_paths / active_probed。
    """
    out: list[dict] = []
    for ep in endpoints:
        if ep.kind not in ("domain", "ip"):
            continue
        e = _as_dict(ep.enrichment)
        shodan = provider_payload_if_hit(e, "shodan")
        certs = provider_payload_if_hit(e, "certs")
        asn = provider_payload_if_hit(e, "asn")
        if not (shodan or certs):
            continue

        juris = _supported_jurisdiction(ep.value, e)
        if juris == forensic.JURIS_DOMESTIC:
            continue  # 境内不呈现境外目标（与渲染层一致）

        entry: dict[str, object] = {"host": ep.value, "jurisdiction": juris}

        # 基础设施候选归属（shodan 优先，IP 端点用自身值兜底，asn 富化再兜底）。
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

        # 技术栈/后台框架指纹：常见弱候选，须由独立锚点复核。
        tech = exposure.assess_tech_stack(shodan)
        if tech:
            entry["tech_stack"] = tech

        # 关联子域候选（crt.sh CT 日志 + shodan 关联主机名；去重，不代表控制关系）。
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

    幂等：:func:`models.apply_downgrade` 对同一来源 id 只更新说明并返回 ``False``，故运行时
    回灌路径重复调用安全，返回值里也不会出现重复。

    ★判的是 :attr:`Lead.base_advice`（判据链结论）而**不是**当前 ``advice``：一条 base 为最高档
      （``ADVICE_INVESTIGATE``）、但已被来源档或伪装 SNI 压成待核的线索，照样要记上本条抑制。
      旧写法看当前档位、发现已是待核就跳过，于是这条线索的账上没有重打包这一笔——将来撤销那条
      来源时，档位就会错误地弹回最高档，被仿冒厂商的域名重新走进出口。那正是本机制要防的。
      代价是审计块 ``repack_quarantine.values`` 会比旧版大，但它记的本就是「被本机制压过的值」，
      语义一致。

    ★不再压 ``confidence``、也不再把理由拼进 ``notes``：前者是证据强度（隔离撤销后证据并不会
      因此变强或变弱，把各自的 HIGH/MEDIUM 一把塌缩成 LOW 是不可逆的信息销毁），后者混进
      notes 就没法在撤销时精确删掉自己那句（见 :attr:`models.Lead.downgrades` 注释）。理由现在
      存进 downgrades 的值里。
    """
    rid = meta.get("repack_identity") if isinstance(meta, dict) else None
    if not (isinstance(rid, dict) and rid.get("verdict") == _VERDICT_REPACK_SUSPECTED):
        return []
    # 人工已核实放行的不再复压。没有这道门，「换版本重跑一次」就把上一次的人工核实抹掉——
    # 而重跑是常态，等于人工恢复永远白做。墓碑按 (类别, 值, 来源) 精确匹配：同一条线索被别的
    # 来源压着的部分不受影响。
    restored = restore_index(meta if isinstance(meta, dict) else None)
    quarantined: list[str] = []
    for lead in leads:
        if lead.category not in (LeadCategory.DOMAIN, LeadCategory.IP):
            continue
        base = lead.base_advice if lead.base_advice is not None else lead.advice
        if base != infra.ADVICE_INVESTIGATE:
            continue
        if is_restored(restored, lead.category.value, lead.value, DOWNGRADE_REPACK_IDENTITY):
            continue
        if apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, _REPACK_QUARANTINE_NOTE):
            quarantined.append(lead.value)
    return quarantined


#: 配置值里取 host 用的形态：``key=<scheme>://host[:port]/...`` 或 ``key=host:port``。
#: 只认这两种；取不出 host 就当"这条配置里没有地址"，行为逐字不变。
_CONFIG_VALUE_HOST_RE = re.compile(
    r"=\s*(?:[a-z][a-z0-9+.\-]*://)?(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._\-]+)(?::\d{1,5})?(?:[/?#]|$)"
)


def _config_value_unroutable_host(value: str) -> str:
    """配置值里的地址是否**不可对外查询**（本机 / 私网 / 保留段）；是则返回那个 host。

    ★为什么要按值分档：``CONFIG_KEY`` 原先不看值一律兜到最高档出口，于是
    ``baseURL=https://localhost:60267`` 这种也进去了——本机地址没有对外查询对象，
    名额却被它占着。

    ★判据刻意只认两种形态：字面 ``localhost``，或**能解析成 IP 且非全球可路由**。
      绝不用"无点即无效"那条口径——渠道 SDK 的 APP_KEY、``AES_KEY=0123…``、
      ``debug=true`` 这些值都是无点单串，那样会把整类真线索一起降掉。
    """
    m = _CONFIG_VALUE_HOST_RE.search(str(value or ""))
    if m is None:
        return ""
    host = m.group("host").strip("[]").rstrip(".").lower()
    if not host:
        return ""
    if host == "localhost" or host.endswith(".localhost"):
        return host
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return ""  # 不是 IP 字面 —— 域名与随机串一律不碰
    return host if not addr.is_global else ""


def _apply_default_advice(leads: list[Lead]) -> None:
    """给未自带 advice 的 Lead 按类别填默认研判建议（就地修改，不覆盖已有值）。"""
    for lead in leads:
        if lead.advice:  # 分析器/构造器已研判，尊重之。
            continue
        default = _DEFAULT_ADVICE_BY_CATEGORY.get(lead.category)
        if not default:
            continue
        if lead.category == LeadCategory.CONFIG_KEY and default == infra.ADVICE_INVESTIGATE:
            local = _config_value_unroutable_host(lead.value)
            if local:
                # ★只降待核、绝不判 SKIP：开发者本机调试端口残留本身是构建环境痕迹，
                #   有情报价值，必须留在清单上让人看见。
                lead.advice = infra.ADVICE_REVIEW
                note = f"配置值指向不可对外查询的地址（{local}：本机/私网/保留段）；作构建环境痕迹留待人工核"
                lead.notes = f"{lead.notes}；{note}" if lead.notes else note
                continue
        lead.advice = default


# 离线扫描时附加到归属为空的端点 Lead 的说明。
_OFFLINE_NOTE = "离线扫描：未做 WHOIS/ICP/ASN 归属查询，归属待联网或人工核（非查无结果）"



def _apply_forensic(
    advice: str, host: str, evidence_to_obtain: list[str], notes: str, **enr: object
) -> str:
    """对「建议调证」的后端 Lead 按基础设施辖区候选追加分层取证路径。

    就地向 evidence_to_obtain 追加路径证据，返回带辖区标签的 notes。非建议调证（infra/私网/
    待核）不标——只给真后端分流。绝不抛（forensic 为纯函数）。
    """
    if advice != infra.ADVICE_INVESTIGATE:
        return notes
    juris = forensic.classify_jurisdiction(host, **enr)
    fp = forensic.forensic_path(juris)
    evidence_to_obtain.extend(fp.evidence)

    # CDN/反代边界不因辖区改变：任何边缘都不能写成 Origin，并应列出分发侧依法调证字段。
    evidence_to_obtain.extend(
        forensic.render_origin_hint(enr.get("dns"), enr.get("asn"))
    )

    # ★ 境外候选证据按**最终辖区**门控（与两遍富化同口径，落到渲染层）：仅【国外 + 未知】渲染；
    #   国内（含 shodan country 把国外/未知翻成国内的情形）：一概不渲染——避免一条最终标
    #   「国内·评估依法调证」的 Lead 上挂着境外候选富化痕迹（呈现自相矛盾、不可审计）。
    if juris in (forensic.JURIS_FOREIGN, forensic.JURIS_UNKNOWN):
        # 境外基础设施候选（Shodan）：归属(IP/ASN/geo) + 端口/服务记录 + 关联主机名候选。
        evidence_to_obtain.extend(forensic.render_overseas_targets(enr.get("shodan")))
        # 证书透明度（crt.sh）：CT 日志关联子域候选；共享证书/多租户须排除。
        evidence_to_obtain.extend(forensic.render_related_subdomains(enr.get("certs")))
        # 技术栈/后台框架指纹（Shodan banner）：仅作弱候选，不研判漏洞。
        _tech = exposure.assess_tech_stack(enr.get("shodan"))
        evidence_to_obtain.extend(forensic.render_tech_stack(_tech))
    return f"{notes}；{fp.label}" if notes else fp.label


def _domain_lead(ep: Endpoint, online: bool = True) -> Lead:
    icp = provider_payload_if_hit(ep.enrichment, "icp")
    rdap = provider_payload_if_hit(ep.enrichment, "rdap")
    whois = provider_payload_if_hit(ep.enrichment, "whois")
    dns = provider_payload_if_hit(ep.enrichment, "dns")
    shodan = provider_payload_if_hit(ep.enrichment, "shodan")
    certs = provider_payload_if_hit(ep.enrichment, "certs")

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
            evidence_to_obtain.append(
                f"ICP 备案号 {icp.get('license_no')} 的备案主体与接入信息（登记关系，不等于 App 运营关系）"
            )
        else:
            evidence_to_obtain.append("ICP 备案主体与接入信息（登记关系，不等于 App 运营关系）")
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
    advice, cls_reason = infra.classify_domain(ep.value)
    distribution_edge = tenant_distribution_edge(ep.value, dns)
    cdn = forensic.cdn_vendor(dns)
    if distribution_edge is not None:
        provider = str(distribution_edge.get("request_target") or "")
        distribution_domain = str(distribution_edge.get("distribution_domain") or "")
        custom_hostname = str(distribution_edge.get("custom_hostname") or "")
        where = f"CDN / 分发服务商：{provider}"
        cname_evidence = (
            f"DNS CNAME 将自定义域名 {custom_hostname} 指向完整分发域名 "
            f"{distribution_domain}；"
            if custom_hostname
            else f"根据完整分发域名 {distribution_domain} "
        )
        evidence_to_obtain.append(
            f"{cname_evidence}检索对应 CloudFront Distribution；"
            "依法调取 AWS 账号、Distribution ID/配置、Alternate Domain Names、Origin 及 "
            "OAC/OAI、访问日志、CloudTrail 与关联 AWS 资源；边缘地址不得写成 Origin"
        )
    elif cdn:
        request_provider = (
            "Amazon Web Services, Inc."
            if "cloudfront" in cdn.casefold()
            else f"{cdn}（需核实法定主体）"
        )
        distribution_target = f"CDN / 分发服务商候选：{request_provider}"
        where = f"{where}；{distribution_target}" if where else distribution_target
    notes = _endpoint_notes(ep, online, enriched)
    if subject:
        registration_boundary = "主体字段来自域名备案/注册记录，仅表示登记关系，不等于 App 运营者"
        notes = f"{notes}；{registration_boundary}" if notes else registration_boundary

    # 对象存储桶模板：判据链把它降到待核，而**降档的理由必须跟到线索上**——否则出口只看得到
    # 一条没有来由的「待核」，读的人无从知道「这是个桶名占位符、下一步该去取运行时真桶名」。
    # ★窄门：只搬运这一类的理由，不把全部 REVIEW 域名的 reason 一律拼进 notes——那是另一件
    #   事（爆炸半径大得多），本刀不夹带。IP 侧早有同款先例（降待核的理由跟到线索上）。
    if advice == infra.ADVICE_REVIEW and infra.tenant_bucket_template(ep.value) is not None:
        notes = f"{notes}；{cls_reason}" if notes else cls_reason

    # DNS 富化：把当前解析 IP / 托管 ASN 作为解析时点候选呈现，不直接把解析 IP 当租户落点。
    hosting_note = _dns_hosting_note(dns)
    if hosting_note:
        evidence_to_obtain.append(hosting_note)
        notes = f"{notes}；{hosting_note}" if notes else hosting_note

    # 被动 DNS 历史：与上面的"当前解析"并列。★同时进 evidence_to_obtain 与 notes——
    #   文书渲染读的是前者，notes 在文书全文里不呈现，只写 notes 等于读的人看不到。
    pdns_note = _passive_dns_note(ep.enrichment)
    if pdns_note:
        evidence_to_obtain.append(pdns_note)
        notes = f"{notes}；{pdns_note}" if notes else pdns_note

    # C1：域名来源可信度档降可信。当端点仅见于第三方库文件/超大字符串表（tier=
    #   library-file / bulk-string）且 classify 仍判"建议调证"（即非已知 infra/
    #   library-embedded、非私网）时，把 advice 降为"待核"并标低可信。★ 绝不降为"无需
    #   调证"（避免误杀真 C2）；已是 infra/私网档的不动（app tier 的真 C2 不受影响）。
    #   用 infra.effective_advice 统一判据（与目标筛选同口径，防判据漂移）。
    tier = ep.enrichment.get("tier")
    # ★与 IP 侧（:func:`_ip_lead`）同口径的实连豁免：真连过的域名不因"它也出现在某个
    #   库文件/超大字符串表里"降档。此前只有 IP 侧有这条，域名侧带 runtime-pcap 实连
    #   证据照样被压待核——`is_runtime_contact` 徽标标着实连、advice 却是待核，出口自相
    #   矛盾，且 runtime-first 的闭环候选被 advice 门挡掉。口径同样必须是严格的
    #   OBSERVED_CONTACT_SOURCES（runtime-derived 只证明"出现在 runtime 报告里"，不豁免）。
    domain_runtime_observed = any(
        ev.scope is EvidenceScope.CASE_EVIDENCE and str(ev.source) in OBSERVED_CONTACT_SOURCES
        for ev in ep.evidences
    )
    tier_suppressed = (
        advice == infra.ADVICE_INVESTIGATE
        and not domain_runtime_observed
        and infra.effective_advice(ep.value, tier) != infra.ADVICE_INVESTIGATE
    )
    tier_note = "仅见于第三方库文件/超大字符串表，疑似库内置，低可信"
    if tier_suppressed:
        # ★这里的 LOW **留在判据链里**（不随降档走）：它编码的是「这条端点的静态出处只有
        #   库文件/超大字符串表」这一**证据强度**事实，撤销降档之后该事实依然成立。其余三个
        #   位点的 LOW 则跟着降档一起去掉——那些是当年没有结构化降档记录时，借 confidence
        #   当可见标记的历史代偿，现在 downgrades 就是那个标记。
        confidence = Confidence.LOW

    # 伪装 SNI：该域名只在**非标准 TLS 端口**上作为 SNI 出现过（判据见
    # ``dynamic.pcap_ingest.sni_camouflage_carriers``，事实随 Endpoint 一起传过来）。
    #
    # ★这是本项目最重的那类误判的入口：非标端口上的 ClientHello 写着谁，证明不了这台机器归谁
    #   运营——自建协议借知名域名的名义混入背景流量是常见手法。此处若照常判
    #   ``ADVICE_INVESTIGATE``，出口就会为被冒用域名套打出一份指向其持有方的文书，把无关第三方
    #   列成了标的。实测（1.4.0）已真的对两个知名服务各生成了一份。
    #
    # ★只降到 ``ADVICE_REVIEW``、不判 ``ADVICE_SKIP``：样本作者完全可以注册一个知名域名的近似域
    #   自用，一律排除会把真 C2 藏起来。降档关掉自动套打，同时留在清单里供人核。
    masq_carriers = _sni_masquerade_carriers(ep)
    masq_note = (
        f"⚠ 该域名仅作为 SNI 出现在非标准 TLS 端口（{'、'.join(masq_carriers)}）上——"
        "标准端口之外，ClientHello 里的 SNI 不构成「该域名运营方即此端点运营方」的证据，"
        "系伪装的可能性高。★标的应是承载它的 IP:端口，**不是**该域名的持有方；"
        "如确需以此域名为标的，须先人工核实证书 / Host 与之一致。"
    ) if masq_carriers else ""

    # ★构造提前到抑制之前：``apply_downgrade`` 要有 Lead 对象才能记账。``advice`` 此刻还是
    #   判据链的结论，正好同时作为 ``base_advice`` 封存；随后的档位一律由 helper 算出。
    lead = Lead(
        category=LeadCategory.DOMAIN,
        value=ep.value,
        subject=subject,
        where_to_request=where,
        evidence_to_obtain=evidence_to_obtain,
        confidence=confidence,
        source_refs=list(ep.evidences),
        notes=notes,
        advice=advice,
        base_advice=advice,
        # 被冒用的域名，其 Lead 的标的**就是**被借用的那个名字——故填自身。方向与 IP 侧
        # （「本连接借用了谁」）相反，字段语义一致：这条线索上出现的这些名字，其持有方与
        # 本案无关，不得作为受文机关。★必须结构化：那段说明在合并与出口两处都会丢。
        sni_masquerade=[ep.value] if masq_carriers else [],
    )
    if tier_suppressed:
        apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, tier_note)
    if masq_carriers:
        apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, masq_note)
    _apply_evidence_scope(lead, ep)

    # ★必须读**压完之后**的 lead.advice：_apply_forensic 只对最高档就地追加取证路径，
    #   传压之前的档位会让被抑制的线索多出一段取证路径——与旧行为相反。旧代码此处传的是被
    #   降档语句改写过的局部变量，等价于压完之后的值，这里保持一致。
    #   （evidence_to_obtain 是同一个 list 对象，就地追加对上面构造的 lead 同样可见。）
    lead.notes = _apply_forensic(
        lead.advice, ep.value, evidence_to_obtain, lead.notes,
        icp=icp, rdap=rdap, whois=whois, dns=dns,
        shodan=shodan,
        certs=certs,
    )
    return lead


def _sni_masquerade_carriers(ep: Endpoint) -> list[str]:
    """取端点上「只在非标端口作 SNI 出现」的承载端点列表；没有 / 结构不符 → 空列表。绝不抛。"""
    raw = ep.enrichment.get(SNI_MASQUERADE_KEY)
    if not isinstance(raw, dict):
        return []
    carriers = raw.get("carriers")
    if not isinstance(carriers, list):
        return []
    return [str(c).strip() for c in carriers if str(c).strip()]


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


#: IP 侧 tier 降档的记账说明。与域名侧措辞对齐，但点明「公共节点」这一 IP 特有的实际形态
#: （第三方库硬编码的 RPC/DNS/时间服务节点），让读线索的人知道该核什么。
_IP_TIER_NOTE = "仅见于第三方库文件/超大字符串表，疑似库内置的公共节点，低可信"


def _ip_lead(
    ep: Endpoint,
    online: bool = True,
    *,
    low_octet_pool: set[str] | None = None,
    vendor_libs: set[str] | None = None,
) -> Lead:
    asn = provider_payload_if_hit(ep.enrichment, "asn")
    shodan = provider_payload_if_hit(ep.enrichment, "shodan")
    certs = provider_payload_if_hit(ep.enrichment, "certs")

    subject = asn.get("org") or asn.get("isp") or asn.get("asn")
    where = None
    evidence_to_obtain: list[str] = []
    enriched = bool(asn)

    cdn = forensic.cdn_vendor(None, asn)
    if cdn:
        where = f"CDN / 分发服务商：{subject or cdn}"
        evidence_to_obtain.append(
            "核实该边缘 IP 的分发服务关系，依法调取账户/租户、分发与绑定域名、回源配置、访问日志及控制面审计记录；边缘 IP 不得写成 Origin"
        )
    elif subject:
        where = f"云厂商 / IDC：{subject}"
        evidence_to_obtain.append(
            "核实资源持有与实际承载角色后，依法调取该 IP 在涉案时段的租户/实名/访问日志"
        )
    else:
        where = "云厂商 / IDC（需人工核 ASN 归属）"
        evidence_to_obtain.append("ASN 归属及租户信息")

    confidence = Confidence.HIGH if subject else Confidence.MEDIUM

    # IP 研判：内网/回环（端点已标 is_private）无需调证；其余交 classify_ip 分级——
    # 点分四段字面未必是地址，实测语料里版本号与 ASN.1 OID 大量以 confidence=HIGH
    # 混进"建议调证"，把闭环预算与外部富化额度吃光。判据用得着证据片段来判断
    # 这个字面在样本里是否当地址使用（带端口 / 在 URL 里），故把 snippet 拼给它。
    ip_reason = ""
    # ★用 OBSERVED_CONTACT_SOURCES 而非 startswith("runtime")：后者会把
    #   runtime-derived（手编/回灌，只证明"出现在 runtime 报告里"）与解密派生值
    #   也当成实连证据。豁免形态判据这种事，必须用严格口径，与 attribution 侧同源。
    #   ★提取成变量：classify_ip 与下面的 tier 降档共用同一口径——真连过的 IP 两处都豁免。
    runtime_observed = any(
        ev.scope is EvidenceScope.CASE_EVIDENCE and str(ev.source) in OBSERVED_CONTACT_SOURCES
        for ev in ep.evidences
    )
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
            runtime_observed=runtime_observed,
            # 低段位裸 IP 的定向豁免佐证：ASN 落托管段 + 样本内无同形态编号序列。
            hosting_attributed=_is_tenant_hosting_asn(asn),
            low_octet_siblings=len((low_octet_pool or set()) - {bare}),
            # 全部证据都在某厂商 SDK 的 .so 内（该文件同时带着该 SDK 自有域名）→ 降待核。
            vendor_sdk_binary=_vendor_sdk_constant(ep, vendor_libs or set()),
        )

    endpoint_notes = _endpoint_notes(ep, online, enriched)
    # 被动 DNS 历史：对 IP 而言是"这台机器上历史挂过哪些域名"——既是落点佐证，也是跨样本
    # 并簇的线索。与域名侧同样两处都写（文书读 evidence_to_obtain，不读 notes）。
    ip_pdns_note = _passive_dns_note(ep.enrichment)
    if ip_pdns_note:
        evidence_to_obtain.append(ip_pdns_note)
        endpoint_notes = f"{endpoint_notes}；{ip_pdns_note}" if endpoint_notes else ip_pdns_note

    # 靠外部佐证把低段位裸 IP 捞回"建议调证"时，保留意见必须**结构化**地跟着走。
    # ★曾只把这句话拼进 notes 并声称"办案人发函前看得到"——实际 letters 全文不渲染 notes，
    #   于是发出去的是一封干净的、HIGH 置信度、指名某云厂商的调证函，没有半点存疑提示。
    shape_uncertain = advice == infra.ADVICE_INVESTIGATE and "四段值偏低" in ip_reason
    if shape_uncertain:
        endpoint_notes = f"{endpoint_notes}；{ip_reason}" if endpoint_notes else ip_reason
        # 形态存疑的值不许以 HIGH 示人：HIGH 是"这确实是个地址"的断言，而此处恰恰不确定。
        # subject（ASN org）非空只说明"这个数字解释成 IP 后落在谁的网段"，不是地址性的证据。
        confidence = Confidence.MEDIUM
    elif advice == infra.ADVICE_REVIEW and ip_reason:
        # 降待核的理由必须跟到线索上。★不写就只剩一个没有出处的"待核"：人既不知道为什么
        #   被降、也不知道该核什么，等于把判据的结论藏起来——降噪的账要算得回来。
        endpoint_notes = f"{endpoint_notes}；{ip_reason}" if endpoint_notes else ip_reason

    # C1（IP 侧）：来源可信度档降可信，与 :func:`_domain_lead` 同口径。第三方库文件里
    #   硬编码的公共节点 IP（如 web3 库自带的以太坊 RPC 节点）此前整类以最高档进调证出口，
    #   把闭环主目标占满、真实站点被挤到候选尾部——实测一次占掉前 6 个目标里的全部 6 个。
    #
    # ★与域名侧的两处**有意差别**：
    #   1. 不走 ``infra.effective_advice``——那是域名接口。IP 的档由 ``classify_ip`` 判，
    #      故这里只读 tier 本身，判据不跨类借用（见 test_pipeline 里那条设计锁）。
    #   2. 只降 Lead 的 advice，**不动 enrichment 侧**（``_enrichment_targets`` 照旧富化
    #      降档后的 IP）。降到待核不是排除，是留给人核；人核时手里得有 ASN/RDAP 结果。
    #      这正是那条设计锁担心的「该核查的 IP 却没有富化结果」，两边由此不再打架。
    #
    # ★``runtime_observed`` 同样豁免：真连过的对端不因"它也出现在某个库文件里"降档。
    #   与 ``classify_ip`` 的形态豁免共用一个口径，故上面提取成了变量。
    tier = ep.enrichment.get("tier")
    ip_tier_suppressed = (
        advice == infra.ADVICE_INVESTIGATE
        and not runtime_observed
        and tier in (infra.TIER_LIBRARY_FILE, infra.TIER_BULK_STRING)
    )
    if ip_tier_suppressed:
        # 与域名侧一致：LOW 编码的是"静态出处只有库文件/超大字符串表"这一证据强度事实，
        # 撤销降档后该事实依然成立，故留在判据链里、不随降档走。
        confidence = Confidence.LOW

    # ★Lead 构造提前到降档之前（与 _domain_lead 同）：apply_downgrade 要有 Lead 才能记账，
    #   此刻的 advice 正好同时作为 base_advice 封存，随后的档位一律由 helper 算出。
    lead = Lead(
        category=LeadCategory.IP,
        value=ep.value,
        subject=subject,
        where_to_request=where,
        evidence_to_obtain=evidence_to_obtain,
        confidence=confidence,
        source_refs=list(ep.evidences),
        notes=endpoint_notes,
        advice=advice,
        base_advice=advice,
        shape_uncertain=shape_uncertain,
    )
    if ip_tier_suppressed:
        apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, _IP_TIER_NOTE)
    _apply_evidence_scope(lead, ep)

    # ★必须读**压完之后**的 lead.advice：_apply_forensic 只对最高档就地追加取证路径。
    #   （evidence_to_obtain 是同一个 list 对象，就地追加对上面构造的 lead 同样可见。）
    lead.notes = _apply_forensic(
        lead.advice, ep.value, evidence_to_obtain, lead.notes,
        asn=asn, shodan=shodan,
        certs=certs,
    )
    return lead


#: 被动 DNS 历史的来源富化器（各自把归一后的记录写在 ``enrichment[<name>]["passive_dns"]``）。
_PASSIVE_DNS_SOURCES = ("virustotal", "otx")

#: 一条 note 里最多列几条历史解析。全量可达数十条，写进文书只会把人淹掉；
#: 完整明细仍在 ``endpoints[].enrichment[<源>]["passive_dns"]``。
_PASSIVE_DNS_NOTE_MAX = 8


def _passive_dns_records(enrichment: dict) -> list[dict]:
    """汇总各源的被动 DNS 记录，按对端值去重（多源命中同一值时合并来源）。"""
    merged: dict[str, dict] = {}
    for source in _PASSIVE_DNS_SOURCES:
        block = provider_payload_if_hit(enrichment, source)
        for record in block.get("passive_dns") or []:
            if not isinstance(record, dict):
                continue
            value = str(record.get("value") or "").strip()
            if not value:
                continue
            existing = merged.get(value)
            if existing is None:
                merged[value] = {**record, "sources": [source]}
            elif source not in existing["sources"]:
                existing["sources"].append(source)
                # 时间窗取更全的那份：先到的源可能只给了一半。
                for key in ("first_seen", "last_seen", "record_type"):
                    if not existing.get(key) and record.get(key):
                        existing[key] = record[key]
    return list(merged.values())


def _passive_dns_note(enrichment: dict) -> str:
    """把被动 DNS 历史压成一句可读的落点说明（无数据 → 空串）。

    ★与 :func:`_dns_hosting_note` 的"当前解析"是**两件事**，必须并列呈现而不是二选一：
      涉案域名换 IP 很快，取证时点解析到的往往已经不是案发时点那台机器——可能是换过的机器，
      也可能是被拦截后指向的拦截页。只写当前解析，等于把发函落点押在一个未必相关的地址上。
    """
    records = _passive_dns_records(enrichment)
    if not records:
        return ""

    def _window(record: dict) -> str:
        first, last = record.get("first_seen"), record.get("last_seen")
        if first and last and first != last:
            return f"{first}→{last}"
        return f"至 {last}" if last else (f"自 {first}" if first else "时间未知")

    # 有 last_seen 的排前面且倒序：最近的落点通常最相关；无时间的沉底但不丢。
    ordered = sorted(records, key=lambda r: (str(r.get("last_seen") or ""),), reverse=True)
    shown = ordered[:_PASSIVE_DNS_NOTE_MAX]
    parts = [f"{r['value']}({_window(r)})" for r in shown]
    more = f"，另有 {len(ordered) - len(shown)} 条见报告明细" if len(ordered) > len(shown) else ""
    sources = sorted({s for r in records for s in r.get("sources", [])})
    return (
        f"历史解析（被动 DNS，来源 {'/'.join(sources)}）：{'、'.join(parts)}{more}"
        "——取证时点的解析未必是案发时点的落点，发函前请按案发日核对时间窗"
    )


def _dns_hosting_note(dns: dict) -> str:
    """把 DNS 富化的解析 IP / 托管 ASN 压成一句角色中立的候选说明（无数据 → 空串）。

    当前解析只证明解析时点的基础设施关系；必须先区分资源持有、承载、CDN 边缘和 Origin，
    不能直接把共享边缘 IP 当作 App 租户落点。
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
    return (
        f"当前解析 IP {', '.join(parts)}，仅为解析时点的基础设施/承载候选；"
        "须先核实资源持有、承载、CDN 边缘与 Origin 角色，再确定相应调证对象和字段"
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
