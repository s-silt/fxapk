"""基础设施辖区候选分流 + 取证路径（纯函数，零第三方依赖）。

默认有网（消费者 Codex 在联网环境），辖区只以富化得到的基础设施归属国作候选信号：

- **国内基础设施候选**：先确认 App 关系与资源持有、承载、分发、Origin、运营者各层角色，再评估依法调证。
- **境外基础设施候选**：区分边缘、承载和 Origin 候选，并按可用法律渠道评估调证或协作；不得一刀切排除。
- **辖区未定**：先补登记与承载信号，再按证据强度和合法渠道分流。

基础设施判据只读 DNS 托管、IP ASN 与 Shodan 归属；国内外信号冲突或没有信号均返回未知。
ICP、域名后缀和域名 RDAP/WHOIS 只描述备案/注册关系，不驱动承载辖区。该值不证明物理 Origin、
App 运营者或其实际辖区。
"""

from __future__ import annotations

from dataclasses import dataclass

from apkscan.core.attribution import classify_network
from apkscan.network.categories import CAT_CDN, CAT_SECURITY_PROXY

JURIS_DOMESTIC = "国内"
JURIS_FOREIGN = "国外"
JURIS_UNKNOWN = "未知"


def _country_is_domestic(country: str) -> bool:
    """基础设施归属是否明确指向中国大陆；港澳台常见长名称不得误吞。"""
    c = (country or "").strip().casefold()
    non_mainland_markers = (
        "hong kong", "hongkong", "香港",
        "macao", "macau", "澳门", "澳門",
        "taiwan", "台湾", "臺灣",
    )
    if any(marker in c for marker in non_mainland_markers):
        return False
    return c in {"cn", "chn", "china", "prc", "people's republic of china", "中国", "中国大陆"} or c.startswith(
        ("china,", "china ", "mainland china")
    )


def _country_signal(country: str) -> str | None:
    """把归属国字段归一为国内/国外信号；占位或未分配值不作国外证据。"""
    normalized = (country or "").strip().casefold()
    if normalized in {
        "", "-", "?", "n/a", "na", "none", "null", "unknown", "unknown country",
        "not available", "not applicable", "undetermined", "undisclosed", "unspecified",
        "unassigned", "private", "reserved", "xx", "zz",
    }:
        return None
    return JURIS_DOMESTIC if _country_is_domestic(normalized) else JURIS_FOREIGN


def _infrastructure_countries(*dicts: object) -> list[str]:
    """从 DNS/ASN/Shodan 富化抽出基础设施归属国，不混入域名登记国。"""
    out: list[str] = []
    for d in dicts:
        if not isinstance(d, dict):
            continue
        for key in ("country", "country_code"):
            v = d.get(key)
            if v:
                out.append(str(v))
        for h in d.get("hosting") or []:
            if isinstance(h, dict) and h.get("country"):
                out.append(str(h["country"]))
    return out


def classify_jurisdiction(
    host: str,
    *,
    icp: object = None,
    rdap: object = None,
    whois: object = None,
    dns: object = None,
    asn: object = None,
    shodan: object = None,
    certs: object = None,
) -> str:
    """据 DNS/ASN/Shodan 归属判基础设施辖区候选。返回 国内 / 国外 / 未知。绝不抛。

    归属国信号只来自 DNS 托管、ASN 与 Shodan 主机记录。ICP、域名后缀、域名 RDAP/WHOIS
    反映备案或注册关系，不能证明承载位置，因此不参与本判定；基础设施信号冲突时返回未知，
    让后续候选富化继续执行而不是被错误门控。

    ``certs``（crt.sh 关联子域）目前不携带归属国信号（仅关联主机名），故不参与辖区判定；作为
    参数接受是为兼容 pipeline ``_apply_forensic`` 的统一 ``**enr`` 透传（避免 TypeError）。
    """
    _ = (host, icp, rdap, whois, certs)  # 登记/证书字段不参与基础设施辖区判定。
    signals = [_country_signal(c) for c in _infrastructure_countries(dns, asn, shodan)]
    domestic = [signal for signal in signals if signal == JURIS_DOMESTIC]
    foreign = [signal for signal in signals if signal == JURIS_FOREIGN]
    if domestic and foreign:
        return JURIS_UNKNOWN
    if domestic:
        return JURIS_DOMESTIC
    if foreign:
        return JURIS_FOREIGN
    return JURIS_UNKNOWN


@dataclass(frozen=True)
class ForensicPath:
    """辖区对应的取证路径：展示标签 + 追加证据清单 + 一句说明。"""

    jurisdiction: str
    label: str
    evidence: tuple[str, ...]
    note: str


_PATHS = {
    JURIS_DOMESTIC: ForensicPath(
        JURIS_DOMESTIC,
        "国内基础设施候选·评估依法调证",
        (
            "先核实 App 与端点的业务关系，并区分资源持有者、ASN、承载/CDN、Origin 与运营者；再向依法可触达的服务商调取与其角色相符的租户实名、配置、访问或控制面日志",
        ),
        "国内基础设施候选：DNS 托管、IP ASN 或 Shodan 归属不等于 App 运营关系；ICP/域名登记另层记录，须分层核实后依法调证",
    ),
    JURIS_FOREIGN: ForensicPath(
        JURIS_FOREIGN,
        "境外基础设施候选·评估依法协作",
        (
            "利用第三方既有数据区分资源登记、承载、CDN 边缘和 Origin 候选；历史 DNS、证书和扫描库结果均不能单独确认 Origin 或运营者",
            "按服务商所在地、可用法律渠道和证据保全需求评估依法调证或协作；技术栈、证书与关联主机名仅作弱候选，须由独立锚点复核",
        ),
        "境外基础设施信号：分层记录登记、承载、边缘与 Origin 候选，并评估依法可达的调证或协作渠道",
    ),
    JURIS_UNKNOWN: ForensicPath(
        JURIS_UNKNOWN,
        "辖区未定",
        (
            "补充 DNS 托管、IP ASN 或 Shodan 基础设施信号并处理冲突；WHOIS、域名 RDAP 与 ICP 仅另记注册/备案关系，再按角色证据和合法渠道分流",
        ),
        "辖区未定：登记或承载归属尚不足，不能据此认定 Origin、运营者或其辖区",
    ),
}


def forensic_path(jurisdiction: str) -> ForensicPath:
    """取辖区对应的取证路径；未知辖区兜底。"""
    return _PATHS.get(jurisdiction, _PATHS[JURIS_UNKNOWN])


#: CNAME 链里的 CDN **完整服务商控制后缀**。不能用 ``cloudflare`` / ``akamai`` 这类
#: 无点品牌词匹配倒数标签：攻击者可注册 ``cloudflare.<任意后缀>``，从而把普通域伪装成 CDN。
#: 这里只做标签边界的完整 suffix 匹配；名单宁可保守漏报，也不能因品牌词出现在攻击者域里误归因。
_CDN_CNAME_SUFFIXES = (
    "w.kunlungr.com", "alicdn.com", "dnsv1.com", "cdntip.com", "qcloudcdn.com",  # leak-scan: allow 公开 CDN 后缀规则，非案件 IOC
    "volccdn.com", "volcgslb.com", "wscdns.com", "cdn20.com", "lxdns.com",  # leak-scan: allow 公开 CDN 后缀规则，非案件 IOC
    "chinacache.net", "bsgslb.cn", "bsclink.cn", "upyun.com", "upaiyun.com",  # leak-scan: allow 公开 CDN 后缀规则，非案件 IOC
    "qiniucdn.com", "qbox.me", "ksyuncdn.com", "cloudflare.net", "cloudfront.net",  # leak-scan: allow 公开 CDN 后缀规则，非案件 IOC
    "akamai.net", "akamaiedge.net", "akamaized.net", "edgekey.net", "edgesuite.net",  # leak-scan: allow 公开 CDN 后缀规则，非案件 IOC
    "fastly.net", "fastlylb.net", "cdn77.org", "b-cdn.net", "gcdn.co",  # leak-scan: allow 公开 CDN 后缀规则，非案件 IOC
)

#: 响应头里的 CDN 边缘信号（键或值命中即判边缘）。国内 CDN 常见：aliyun WAF/CDN 的 acw_tc
#: cookie、via: ens-cache（阿里 ENS）、x-swift-*（阿里/淘系 Swift 缓存）、x-ser（网宿）；通用：
#: x-cache / x-cdn / cf-ray / x-akamai-* 等。键统一转小写匹配。
_CDN_HEADER_KEY_MARKERS = (
    "x-swift-savetime", "x-swift-cachetime", "x-cache", "x-cache-lookup", "x-cdn",
    "x-ser", "cf-ray", "x-akamai-transformed", "eagleid", "x-hcs-proxy-type",
    "ali-swift-global-savetime", "x-tengine-error",
)

#: 响应头**值**里的 CDN 边缘信号子串（针对 Via / Set-Cookie 等值命中即判边缘）。
_CDN_HEADER_VALUE_MARKERS = (
    "acw_tc", "ens-cache", "ali-swift", "kunlun", "cache.51cdn", "wscache",
    "cloudflare", "cloudfront", "akamai", "fastly", "varnish", "yunjiasu",
)


def _hosting_units(*dicts: object) -> list[tuple[str, str]]:
    """把 dns(hosting[]) 与 asn 富化归一成 [(匹配用 blob, 展示用 org)]，**每个解析 IP / ASN 归属一条**。

    blob = org+isp+asn 合并（供 CDN 标记子串匹配，避免纯编号 asn 拉低判定）；org 取最具名字段供展示。
    """
    units: list[tuple[str, str]] = []
    for d in dicts:
        if not isinstance(d, dict):
            continue
        sources = list(d.get("hosting") or [])
        # asn 富化本身（IP 端点无 hosting，归属直接在顶层）也算一条。
        if any(d.get(k) for k in ("org", "isp", "asn")):
            sources.append(d)
        for h in sources:
            if not isinstance(h, dict):
                continue
            blob = " ".join(str(h.get(k) or "") for k in ("org", "isp", "asn"))
            if blob.strip():
                org = str(h.get("org") or h.get("isp") or h.get("asn") or "")
                units.append((blob, org))
    return units


def _cname_cdn_marker(dns: object) -> str | None:
    """DNS 富化里的 CNAME 链是否指向已知 CDN；命中返回完整后缀（供展示），否则 None。

    诈骗后端常把 A 记录藏在 CDN 调度域名之后：解析 IP 归属看似普通 IDC，但 CNAME 直指
    ``*.w.kunlungr.com`` / ``*.alicdn.com`` 等——这是最可靠的边缘信号之一。
    """
    if not isinstance(dns, dict):
        return None
    chain = dns.get("cname")
    names: list[str] = []
    if isinstance(chain, str):
        names = [chain]
    elif isinstance(chain, list):
        names = [str(c) for c in chain if c]
    for name in names:
        low = name.strip().lower().rstrip(".")
        for suffix in _CDN_CNAME_SUFFIXES:
            normalized = suffix.strip().lower().rstrip(".")
            if low == normalized or low.endswith("." + normalized):
                return suffix
    return None


def _header_cdn_signal(dns: object) -> bool:
    """DNS 富化里的响应头是否带 CDN 边缘信号（键或值命中即真）。

    国内 CDN 常见：acw_tc cookie、via: ens-cache（阿里 ENS）、x-swift-*（阿里/淘系缓存）、
    x-ser（网宿）等；通用 x-cache / cf-ray 等。键统一小写比对，值做子串包含。
    """
    if not isinstance(dns, dict):
        return False
    headers = dns.get("headers")
    if not isinstance(headers, dict):
        return False
    for key, value in headers.items():
        low_key = str(key).lower()
        if any(m in low_key for m in _CDN_HEADER_KEY_MARKERS):
            return True
        low_val = str(value).lower()
        if any(m in low_val for m in _CDN_HEADER_VALUE_MARKERS):
            return True
    return False


def cdn_vendor(dns: object = None, asn: object = None) -> str | None:
    """判断当前解析结果是否形成反代型 CDN 边缘候选；命中返回厂商名，否则 None。

    三路信号：
    1. 解析 IP / ASN 归属**全部**由统一 provider 规则分类为 CDN 或安全反向代理；
    2. DNS CNAME 链按域名标签/后缀边界命中 CDN 调度标记；
    3. 响应头带 CDN 边缘信号（acw_tc / via: ens-cache / x-swift-* / x-cache / x-ser 等）。

    第 1 路是较强候选；边界正确的已知 CDN CNAME 单源也应保留为分发关系候选，
    因为目标可能已下线或不返回厂商响应头。单个响应头不足以成立，避免通用
    ``X-Cache`` 或可伪造头部触发候选；它只能与部分 CDN org 信号交叉时补强候选。

    命中只表示当前解析结果须按 CDN/反代候选处理；未经分发配置、历史 DNS 或其他
    独立证据核实，不得直接把当前 IP 写成 Origin 或运营者地址。仅 org 全 CDN 时按 org
    取厂商名；否则退到 CNAME 标记。绝不抛。
    """
    units = _hosting_units(dns, asn)
    org_vendor: str | None = None
    all_cdn = bool(units)
    for blob, org in units:
        if classify_network(blob) not in {CAT_CDN, CAT_SECURITY_PROXY}:
            all_cdn = False  # 有非 CDN 归属 → 不算全 CDN（该 IP 可能就是源站）
        elif org_vendor is None:
            org_vendor = org.split(",")[0].strip() or org
    if all_cdn and org_vendor:
        return org_vendor

    # org 未全命中：边界正确的 CNAME 保留为分发关系候选。响应头只作旁证；
    # 单个头可伪造且跨厂商通用，不能独立返回厂商。
    cname_marker = _cname_cdn_marker(dns)
    if cname_marker:
        return org_vendor or cname_marker
    if org_vendor and _header_cdn_signal(dns):
        return org_vendor
    return None


def render_origin_hint(dns: object = None, asn: object = None) -> list[str]:
    """解析 IP 全为反代型 CDN 时，渲一条边缘与 Origin 候选边界证据行。

    非全 CDN / 无信号 → 空列表。绝不抛。第三方历史数据只能产生 Origin 候选；同时提示可依法向
    分发服务商调取账户、分发、绑定域名、回源配置、访问日志和控制面审计记录，不主动探测目标业务服务。
    """
    vendor = cdn_vendor(dns, asn)
    if not vendor:
        return []
    return [
        f"⚠ 检测到符合候选判据的 CDN/反代边缘信号（{vendor}），当前解析结果不得未经核实写成 Origin 或运营者地址。"
        "历史 DNS、证书透明度 SAN 或邮件发信头只能形成 Origin 候选，须排除共享和多租户关系并继续核实；"
        "同时评估依法向分发服务商调取账户/租户、分发与绑定域名、回源配置、访问日志及控制面审计记录（不主动探测目标业务服务）"
    ]


# 境外基础设施候选渲染的展示上限（防个别巨型主机刷屏；完整数据仍在 report.json 的 enrichment 里）。
_MAX_PORTS_SHOWN = 12
_MAX_HOSTS_SHOWN = 8

# crt.sh 关联子域渲染上限（同上，防刷屏；完整列表仍在 report.json 的 enrichment["certs"] 里）。
_MAX_RELATED_HOSTS_SHOWN = 12


def render_overseas_targets(shodan: object) -> list[str]:
    """把 Shodan 第三方既有数据渲成「境外基础设施候选」证据行。

    不直接连接目标业务服务，但会把目标标识提交给 Shodan。结果只描述其数据库中的基础设施归属、
    端口、服务和关联主机名，可能过期；不能单独确认 Origin、App 家族或运营者。**不含漏洞方向、不含利用**。

    无数据 / 非 dict / 仅"查无记录"标记 → 返回空列表。绝不抛（纯函数，坏字段安全跳过）。
    输出形如：
      - 基础设施候选归属：IP 192.0.2.4 AS64500 ExampleCorp US
      - Shodan 开放端口 / 服务：80(Apache httpd 2.4.7) 22(OpenSSH 6.6.1p1) 6379
      - Shodan 关联主机名：a.example b.example（同一数据库记录的关联候选；须排除共享/多租户并以独立锚点复核）
    """
    if not isinstance(shodan, dict):
        return []
    lines: list[str] = []

    # 1) 基础设施候选归属（IP / ASN / 归属国 / org），不据此认定 Origin 或运营者。
    org = shodan.get("org") or shodan.get("isp")
    attrib = " ".join(
        str(x) for x in (
            f"IP {shodan.get('ip')}" if shodan.get("ip") else "",
            str(shodan.get("asn")) if shodan.get("asn") else "",
            str(org) if org else "",
            str(shodan.get("country")) if shodan.get("country") else "",
        ) if x
    ).strip()
    if attrib:
        lines.append("基础设施候选归属：" + attrib)

    # 2) 第三方数据库中的端口 + 服务指纹（product/version 标在端口后，可能过期）。
    svc_by_port: dict[object, dict] = {}
    for svc in shodan.get("services") or []:
        if isinstance(svc, dict) and svc.get("port") is not None:
            svc_by_port[svc["port"]] = svc
    ports = [p for p in (shodan.get("ports") or []) if isinstance(p, int)]
    if not ports:
        ports = sorted(p for p in svc_by_port if isinstance(p, int))
    if ports:
        parts: list[str] = []
        for p in ports[:_MAX_PORTS_SHOWN]:
            svc = svc_by_port.get(p) or {}
            label = " ".join(
                str(x) for x in (svc.get("product"), svc.get("version")) if x
            ).strip()
            parts.append(f"{p}({label})" if label else str(p))
        more = f" 等共 {len(ports)} 个" if len(ports) > _MAX_PORTS_SHOWN else ""
        lines.append("Shodan 开放端口 / 服务：" + " ".join(parts) + more)

    # 3) 同一 Shodan 记录的关联主机名候选，不能单独证明同源或同主体。
    hostnames = [h for h in (shodan.get("hostnames") or []) if isinstance(h, str)]
    if hostnames:
        shown = " ".join(hostnames[:_MAX_HOSTS_SHOWN])
        more = f" 等共 {len(hostnames)} 个" if len(hostnames) > _MAX_HOSTS_SHOWN else ""
        lines.append(
            f"Shodan 关联主机名：{shown}{more}（同一数据库记录的关联候选；共享和多租户关系未排除，须由独立锚点复核）"
        )

    return lines


def render_related_subdomains(certs: object) -> list[str]:
    """把 crt.sh 证书透明度结果渲成「关联子域候选」取证证据行。

    与 Shodan ``hostnames`` 互补：CT 日志记录历史和当前证书名称，但共享证书、通配证书及多租户
    均可能造成关联；结果只能作候选，须由独立锚点复核。查询会把域名提交给 crt.sh。

    无数据 / 非 dict / 无关联主机名 → 返回空列表。绝不抛（纯函数，坏字段安全跳过）。
    输出形如：
      - 关联子域候选(crt.sh)：api.example pay.example admin.example 等共 N 个（共享证书/多租户未排除，须由独立锚点复核）
    """
    if not isinstance(certs, dict):
        return []
    hosts = [h for h in (certs.get("related_hostnames") or []) if isinstance(h, str)]
    if not hosts:
        return []
    total = certs.get("hostname_total")
    total = total if isinstance(total, int) and total >= len(hosts) else len(hosts)
    shown = " ".join(hosts[:_MAX_RELATED_HOSTS_SHOWN])
    more = f" 等共 {total} 个" if total > _MAX_RELATED_HOSTS_SHOWN else ""
    return [
        f"关联子域候选(crt.sh)：{shown}{more}（证书名称关联；共享证书、通配证书和多租户关系未排除，须由独立锚点复核）"
    ]


# 技术栈/后台指纹渲染上限。
_MAX_STACK_SHOWN = 10


def render_tech_stack(tech_stack: object) -> list[str]:
    """把识别到的**技术栈/后台框架**渲成弱候选证据行（**不研判漏洞、不含利用方向**）。

    无数据 / 非 list → 空列表。绝不抛（坏字段安全跳过）。
    """
    if not isinstance(tech_stack, list):
        return []
    names: list[str] = []
    notes: list[str] = []
    for t in tech_stack[:_MAX_STACK_SHOWN]:
        if isinstance(t, dict) and t.get("name"):
            names.append(str(t["name"]))
            if t.get("note"):
                notes.append(f"· {t['name']}：{t['note']}")
    if not names:
        return []
    return [
        "技术栈/后台框架指纹（常见弱候选；不能据此认定同一后端、家族或运营者）：" + "、".join(names),
        *notes,
    ]
