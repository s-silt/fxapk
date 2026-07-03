"""服务器辖区分流 + 取证路径（纯函数，零第三方依赖）。

默认有网（消费者 Codex 在联网环境），辖区以**富化归属国**为主信号、域名启发式兜底：

- **国内服务器 → 调证路径**：向境内云厂商 / IDC / 工信部 ICP 调取访问日志、登录记录、租户实名。
- **国外服务器 → 取证路径**：难直接调证；以**被动定位真实源站 IP**（穿透 CDN）、结合技术栈 /
  后台框架指纹并簇串案为目标（**全程被动 OSINT，绝不主动探测 / 攻击 / 扫描**）。
- **辖区未定 → 先定归属再分流**。

判据优先级：ICP 备案存在 → 国内（ICP 仅境内）；host .cn/.gov.cn → 国内；富化归属国含中国大陆
→ 国内；有归属国信号且非大陆 → 国外（含港澳台 / 境外，均难直接调证）；无任何信号 → 未知。
"""

from __future__ import annotations

from dataclasses import dataclass

JURIS_DOMESTIC = "国内"
JURIS_FOREIGN = "国外"
JURIS_UNKNOWN = "未知"


def _country_is_domestic(country: str) -> bool:
    """归属国是否为中国大陆（港澳台按境外/难直接调处理，故不计入）。"""
    c = (country or "").strip().lower()
    return c == "cn" or "china" in c or "中国" in c


def _countries(*dicts: object) -> list[str]:
    """从富化 dict（rdap/whois/dns/asn）抽出所有归属国字符串。"""
    out: list[str] = []
    for d in dicts:
        if not isinstance(d, dict):
            continue
        for key in ("country", "registrant_country", "country_code"):
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
    webcheck: object = None,
    shodan: object = None,
    certs: object = None,
) -> str:
    """据富化归属国 + 域名启发式判服务器辖区。返回 国内 / 国外 / 未知。绝不抛。

    归属国信号来源：rdap/whois 注册国、dns 托管 country、asn 归属国、web-check ``location``
    归一化的 ``country``、Shodan 主机归属国（见 enrichers/shodan）。ICP 备案 / .cn 直判国内。

    ``certs``（crt.sh 关联子域）目前不携带归属国信号（仅关联主机名），故不参与辖区判定；作为
    参数接受是为兼容 pipeline ``_apply_forensic`` 的统一 ``**enr`` 透传（避免 TypeError）。
    """
    _ = certs  # 当前不参与判定（无 country 字段）；显式消费以示有意忽略。
    if isinstance(icp, dict) and (icp.get("subject") or icp.get("license_no")):
        return JURIS_DOMESTIC
    h = (host or "").lower().strip().rstrip(".")
    if h.endswith(".cn") or h.endswith(".gov.cn") or h.endswith(".中国"):
        return JURIS_DOMESTIC
    countries = _countries(rdap, whois, dns, asn, webcheck, shodan)
    if any(_country_is_domestic(c) for c in countries):
        return JURIS_DOMESTIC
    if countries:
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
        "国内服务器·可调证",
        ("向境内云厂商 / IDC / 工信部 ICP 备案系统调取该服务器访问日志、登录记录与租户实名",),
        "国内服务器：依法调证路径——向境内云厂商 / IDC / ICP 调取访问、登录日志与租户实名",
    ),
    JURIS_FOREIGN: ForensicPath(
        JURIS_FOREIGN,
        "国外服务器·被动定位（不调证、不攻击）",
        (
            "海外不走调证：以**被动定位真实源站 IP**（公开情报穿透 CDN）+ 提取归属标识为目标，供依授权途径处置",
            "结合该服务器的技术栈 / 后台框架指纹与关联主机名并簇串案（全程被动 OSINT，不主动探测 / 不攻击）",
        ),
        "国外服务器：不走调证——被动定位真实源站 IP + 提取归属标识（ASN/org、证书透明度子域、技术栈指纹）",
    ),
    JURIS_UNKNOWN: ForensicPath(
        JURIS_UNKNOWN,
        "辖区未定",
        ("先据 whois 注册国 / IP ASN 归属国确定服务器辖区，再分流（国内调证 / 国外取证）",),
        "辖区未定：先定服务器归属国，再分流——国内走调证、国外走取证",
    ),
}


def forensic_path(jurisdiction: str) -> ForensicPath:
    """取辖区对应的取证路径；未知辖区兜底。"""
    return _PATHS.get(jurisdiction, _PATHS[JURIS_UNKNOWN])


#: 已知 CDN / 反向代理 / WAF 厂商标记（org / ASN 字符串里命中即判该 IP 为边缘节点、非真实源站）。
#: 只收**会隐藏源站**的反代型 CDN；纯托管云（AWS EC2 / GCP / Azure 裸机）不在此列——那些 IP 可能就是源站。
#: 含西方主流 + 国内主流（网宿 wangsu / 白山 baishan / 阿里 alicdn·kunlun / 腾讯 tcdn·dnsv1 /
#: 字节 volccdn / 华为 hwcdn / 百度 bdydns / 又拍 upyun / 七牛 qiniu / 金山 ksyun 等）——诈骗后端
#: 常挂国内 CDN 隐藏源站，漏国内 CDN 会把边缘 IP 误当源站。
_CDN_ORG_MARKERS = (
    # 西方主流
    "cloudflare", "akamai", "fastly", "incapsula", "imperva", "sucuri",
    "stackpath", "cdn77", "bunny", "gcore", "g-core", "edgio", "limelight",
    "cloudfront", "keycdn", "section.io", "ddos-guard", "qrator",
    # 国内主流
    "wangsu", "chinanetcenter", "baishan", "alicdn", "kunlun", "aliyun cdn",
    "tcdn", "dnsv1", "cdntip", "volccdn", "volcgslb", "hwcdn", "huaweicloud cdn",
    "bdydns", "yunjiasu", "upyun", "upaiyun", "qiniu", "qbox", "ksyun", "kingsoft cloud cdn",
)

#: CNAME 链里的国内/西方 CDN 域名后缀标记（诈骗后端常把 A 记录藏在 CDN 的 CNAME 之后，
#: 解析 IP 归属看似普通 IDC，但 CNAME 直指 CDN 调度域名——这是最可靠的边缘信号之一）。
_CDN_CNAME_MARKERS = (
    "kunlun", "alicdn", "aliyuncs", "w.kunlungr.com", "tcdn", "dnsv1", "cdntip",
    "qcloud", "volccdn", "volcgslb", "wangsu", "wscdns", "cdn20", "lxdns", "chinacache",
    "baishan", "bsgslb", "bsclink", "upyun", "upaiyun", "qiniu", "qbox", "ksyuncdn",
    "cloudflare", "akamai", "akamaized", "edgekey", "fastly", "cdn77", "bunnycdn", "gcdn",
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
    """DNS 富化里的 CNAME 链是否指向已知 CDN；命中返回命中的标记（供展示），否则 None。

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
        low = name.lower()
        for marker in _CDN_CNAME_MARKERS:
            if marker in low:
                return marker
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
    """判断当前解析结果是否落在反代型 CDN 边缘（隐藏源站）；命中返回厂商名，否则 None。

    三路信号（任一命中即判边缘，因国内 CDN 边缘 IP 常伪装成普通 IDC，单看 IP 归属会漏判）：
    1. 解析 IP / ASN 归属**全部**命中已知 CDN org/asn 标记（含西方 + 国内主流）；
    2. DNS CNAME 链指向已知 CDN 调度域名（即便 IP 归属看似普通 IDC）；
    3. 响应头带 CDN 边缘信号（acw_tc / via: ens-cache / x-swift-* / x-cache / x-ser 等）。

    命中 ⇒ 当前解析 IP 是边缘节点、**不是真实源站**——海外取证须先穿透 CDN 定位源站。
    仅 org 全 CDN 时按 org 取厂商名；否则退到 CNAME 标记 / 通用「CDN」。绝不抛。
    """
    units = _hosting_units(dns, asn)
    org_vendor: str | None = None
    all_cdn = bool(units)
    for blob, org in units:
        low = blob.lower()
        if not any(m in low for m in _CDN_ORG_MARKERS):
            all_cdn = False  # 有非 CDN 归属 → 不算全 CDN（该 IP 可能就是源站）
        elif org_vendor is None:
            org_vendor = org.split(",")[0].strip() or org
    if all_cdn and org_vendor:
        return org_vendor

    # org 未全命中：退到 CNAME / 响应头旁证（国内 CDN 边缘 IP 常伪装普通 IDC）。
    cname_marker = _cname_cdn_marker(dns)
    if cname_marker:
        return org_vendor or cname_marker
    if _header_cdn_signal(dns):
        return org_vendor or "CDN"
    return None


def render_origin_hint(dns: object = None, asn: object = None) -> list[str]:
    """解析 IP 全为反代型 CDN 时，渲一条「用公开情报被动定位真实源站 IP」取证证据行。

    非全 CDN / 无信号 → 空列表。绝不抛。境外只做被动定位：CDN 是边缘节点非源站，
    用公开情报（历史 DNS / 证书透明度 / 邮件发信头）穿透找源站 IP，不主动攻击。
    """
    vendor = cdn_vendor(dns, asn)
    if not vendor:
        return []
    return [
        f"⚠ 解析 IP 均为 CDN/反代（{vendor}），是边缘节点**非真实源站** → 境外不走调证："
        "用公开情报被动穿透 CDN 定位真实源站 IP（历史 DNS 解析 / 证书透明度 SAN / 邮件发信头），"
        "得到源站 IP 供归属研判与并簇串案（只做被动定位，不主动攻击）"
    ]


# 境外源站被动定位渲染的展示上限（防个别巨型主机刷屏；完整数据仍在 report.json 的 enrichment 里）。
_MAX_PORTS_SHOWN = 12
_MAX_HOSTS_SHOWN = 8

# crt.sh 关联子域渲染上限（同上，防刷屏；完整列表仍在 report.json 的 enrichment["certs"] 里）。
_MAX_RELATED_HOSTS_SHOWN = 12


def render_overseas_targets(shodan: object) -> list[str]:
    """把 Shodan 被动富化渲成「境外源站被动定位」取证证据行（海外取证：先被动定位真实源站）。

    仅做**被动定位与识别**，对目标零流量：源站归属（IP / ASN / 归属国 / org）+ 开放端口与服务
    指纹（识别这是不是真源站、跑什么服务）+ 关联主机名（同源站其它域名，疑同团伙 → 并簇串案）。
    **不含漏洞方向、不含利用**。

    无数据 / 非 dict / 仅"查无记录"标记 → 返回空列表。绝不抛（纯函数，坏字段安全跳过）。
    输出形如：
      - 源站被动归属：IP 1.2.3.4 AS12345 EvilCorp US
      - Shodan 开放端口 / 服务：80(Apache httpd 2.4.7) 22(OpenSSH 6.6.1p1) 6379
      - Shodan 关联主机名：a.com b.com（同源站其它域名，疑同团伙基础设施，建议并簇串案）
    """
    if not isinstance(shodan, dict):
        return []
    lines: list[str] = []

    # 1) 源站被动归属（IP / ASN / 归属国 / org）——识别真实源站、归属哪（对目标零流量）。
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
        lines.append("源站被动归属：" + attrib)

    # 2) 端口 + 服务指纹（product/version 标在端口后）——识别真源站跑的服务。
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

    # 3) 关联主机名（串案：同源站其它域名，疑同团伙基础设施）。
    hostnames = [h for h in (shodan.get("hostnames") or []) if isinstance(h, str)]
    if hostnames:
        shown = " ".join(hostnames[:_MAX_HOSTS_SHOWN])
        more = f" 等共 {len(hostnames)} 个" if len(hostnames) > _MAX_HOSTS_SHOWN else ""
        lines.append(
            f"Shodan 关联主机名：{shown}{more}（同源站其它域名，疑同团伙基础设施，建议并簇串案）"
        )

    return lines


def render_related_subdomains(certs: object) -> list[str]:
    """把 crt.sh 证书透明度结果渲成「关联子域(串案)」取证证据行。

    与 Shodan ``hostnames`` 互补：CT 日志覆盖该域名**历史 + 当前**被签过证的全部子域（含 DNS 已
    撤的影子子域），疑同团伙基础设施——建议并簇串案。全程被动 OSINT（读 crt.sh 公开库），对目标零流量。

    无数据 / 非 dict / 无关联主机名 → 返回空列表。绝不抛（纯函数，坏字段安全跳过）。
    输出形如：
      - 关联子域(crt.sh)：api.evil.com pay.evil.com admin.evil.com 等共 N 个（CT 日志关联，疑同团伙基础设施，建议并簇串案）
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
        f"关联子域(crt.sh)：{shown}{more}（CT 日志关联，疑同团伙基础设施，建议并簇串案）"
    ]


# 技术栈/后台指纹渲染上限。
_MAX_STACK_SHOWN = 10


def render_tech_stack(tech_stack: object) -> list[str]:
    """把识别到的**技术栈/后台框架**渲成证据行（仅识别 + 串案；**不研判漏洞、不含利用方向**）。

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
        "技术栈/后台框架指纹（仅识别·同后台疑同团伙 → 并簇串案）：" + "、".join(names),
        *notes,
    ]
