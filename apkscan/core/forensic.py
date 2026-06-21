"""服务器辖区分流 + 取证路径（纯函数，零第三方依赖）。

默认有网（消费者 Codex 在联网环境），辖区以**富化归属国**为主信号、域名启发式兜底：

- **国内服务器 → 调证路径**：向境内云厂商 / IDC / 工信部 ICP 调取访问日志、登录记录、租户实名。
- **国外服务器 → 取证路径**：难直接调证；以拿到服务器**镜像 / 磁盘与日志**为目标，结合已识别的
  后台 / 管理端、技术栈已知漏洞方向、暴露的敏感路径研判（**被动情报指引，非主动攻击 / 扫描**）。
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
    recon: object = None,
    cve: object = None,
    certs: object = None,
) -> str:
    """据富化归属国 + 域名启发式判服务器辖区。返回 国内 / 国外 / 未知。绝不抛。

    归属国信号来源：rdap/whois 注册国、dns 托管 country、asn 归属国、web-check ``location``
    归一化的 ``country``、Shodan 主机归属国（见 enrichers/shodan）。ICP 备案 / .cn 直判国内。

    ``recon``（主动探测结果）/ ``cve``（CVE 方向补查）/ ``certs``（crt.sh 关联子域）目前不携带
    归属国信号（仅暴露面 / 漏洞方向 / 关联主机名），故不参与辖区判定；作为参数接受是为兼容
    pipeline ``_apply_forensic`` 的统一 ``**enr`` 透传（避免 TypeError）。
    """
    _ = (recon, cve, certs)  # 当前不参与判定（无 country 字段）；显式消费以示有意忽略。
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
        "国外服务器·取证为主",
        (
            "国外难直接调证：以获取服务器镜像 / 磁盘与访问日志为目标",
            "结合该服务器已识别的后台 / 管理端、技术栈已知漏洞方向、暴露的敏感路径研判（被动情报，非主动攻击）",
        ),
        "国外服务器：难直接调证——转取证路径，以拿到服务器镜像 / 磁盘与日志为目标",
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


# 攻击面渲染的展示上限（防个别巨型主机刷屏；完整数据仍在 report.json 的 enrichment 里）。
_MAX_PORTS_SHOWN = 12
_MAX_VULNS_SHOWN = 8
_MAX_HOSTS_SHOWN = 8

# 主动探测渲染上限（同上，防刷屏）。
_MAX_RECON_PORTS_SHOWN = 16
_MAX_RECON_PATHS_SHOWN = 12

# CVE 补查渲染上限（同上，防刷屏；完整列表仍在 report.json 的 enrichment["cve"] 里）。
_MAX_CVES_SHOWN = 10

# crt.sh 关联子域渲染上限（同上，防刷屏；完整列表仍在 report.json 的 enrichment["certs"] 里）。
_MAX_RELATED_HOSTS_SHOWN = 12


def render_attack_surface(shodan: object) -> list[str]:
    """把 Shodan 富化结果渲成「服务器攻击面」取证证据行（国外取证路径价值最高）。

    无数据 / 非 dict / 仅"查无记录"标记 → 返回空列表。绝不抛（纯函数，坏字段安全跳过）。
    输出形如：
      - Shodan 暴露面：80(Apache httpd 2.4.7) 22(OpenSSH 6.6.1p1) 6379
      - Shodan 已知漏洞方向(CPE→CVE 情报，非利用)：CVE-2021-44790、… 等共 N 个
      - Shodan 关联主机名：a.com b.com（疑同团伙基础设施，建议并簇串案）
    """
    if not isinstance(shodan, dict):
        return []
    lines: list[str] = []

    # 1) 端口 + 服务指纹（product/version 标在端口后）。
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
        lines.append("Shodan 暴露面：" + " ".join(parts) + more)

    # 2) 已知漏洞方向（Shodan 现成 CPE→CVE；情报方向，非利用）。
    vulns = [v for v in (shodan.get("vulns") or []) if isinstance(v, str)]
    if vulns:
        total = shodan.get("vuln_total")
        total = total if isinstance(total, int) and total >= len(vulns) else len(vulns)
        shown = "、".join(vulns[:_MAX_VULNS_SHOWN])
        more = f" 等共 {total} 个" if total > _MAX_VULNS_SHOWN else ""
        lines.append(f"Shodan 已知漏洞方向(CPE→CVE 情报，非利用)：{shown}{more}")

    # 3) 关联主机名（串案：疑同团伙基础设施）。
    hostnames = [h for h in (shodan.get("hostnames") or []) if isinstance(h, str)]
    if hostnames:
        shown = " ".join(hostnames[:_MAX_HOSTS_SHOWN])
        more = f" 等共 {len(hostnames)} 个" if len(hostnames) > _MAX_HOSTS_SHOWN else ""
        lines.append(f"Shodan 关联主机名：{shown}{more}（疑同团伙基础设施，建议并簇串案）")

    return lines


def render_active_recon(recon: object) -> list[str]:
    """把**主动探测**（recon enricher）结果渲成取证证据行，统一标注「主动探测·已授权」。

    与 ``render_attack_surface``（被动 Shodan）区分：主动探测是对授权目标的**实时侦查**结果
    （开放端口 / TLS 证书主体 / HTTP 指纹 / 暴露后台路径），证明力更强、时点更新。每行都带
    「主动探测·已授权」前缀，让报告明确这是主动行为（与被动情报区分、可审计）。

    无数据 / 非 dict / 无任何探测命中 → 返回空列表。绝不抛（纯函数，坏字段安全跳过）。
    输出形如：
      - 主动探测·已授权 开放端口：22(SSH) 80(HTTP) 6379(Redis) …
      - 主动探测·已授权 HTTP 指纹：80 200 Server=nginx 标题「XX管理后台」
      - 主动探测·已授权 TLS 证书：443 CN=evil.com 颁发者=Let's Encrypt
      - 主动探测·已授权 暴露后台路径：/admin(200) /druid(200) /actuator(401) …
    """
    if not isinstance(recon, dict):
        return []
    prefix = "主动探测·已授权"
    lines: list[str] = []

    # 1) 开放端口 + 服务名。
    services = recon.get("services") or []
    svc_name: dict[object, str] = {}
    for s in services:
        if isinstance(s, dict) and s.get("port") is not None:
            svc_name[s["port"]] = str(s.get("service") or "")
    open_ports = [p for p in (recon.get("open_ports") or []) if isinstance(p, int)]
    if open_ports:
        parts: list[str] = []
        for p in open_ports[:_MAX_RECON_PORTS_SHOWN]:
            name = svc_name.get(p, "")
            parts.append(f"{p}({name})" if name else str(p))
        more = f" 等共 {len(open_ports)} 个" if len(open_ports) > _MAX_RECON_PORTS_SHOWN else ""
        lines.append(f"{prefix} 开放端口：" + " ".join(parts) + more)

    # 2) HTTP 指纹（Server / X-Powered-By / 标题 / 状态码）。
    for h in recon.get("http") or []:
        if not isinstance(h, dict):
            continue
        port = h.get("port")
        status = h.get("status")
        bits: list[str] = []
        if h.get("server"):
            bits.append(f"Server={h['server']}")
        if h.get("x_powered_by"):
            bits.append(f"X-Powered-By={h['x_powered_by']}")
        if h.get("title"):
            bits.append(f"标题「{h['title']}」")
        # 状态行解析失败（status=0/None，如端口上跑的是 SSH/Redis 等非 HTTP 服务）且无任何有效指纹 →
        # 跳过该行（'…HTTP 指纹：80 0' 既无信息量又会误导办案人，绝不渲染）。
        valid_status = isinstance(status, int) and status > 0
        if not valid_status and not bits:
            continue
        head = f"{prefix} HTTP 指纹：{port}"
        if valid_status:
            head += f" {status}"
        tail = (" " + " ".join(bits)) if bits else ""
        lines.append((head + tail).rstrip())

    # 3) TLS 证书（CN/SAN/issuer/有效期）。
    tls = recon.get("tls") or {}
    if isinstance(tls, dict):
        for port, cert in tls.items():
            if not isinstance(cert, dict):
                continue
            bits = []
            if cert.get("subject"):
                bits.append(f"主体={cert['subject']}")
            if cert.get("issuer"):
                bits.append(f"颁发者={cert['issuer']}")
            if cert.get("not_after"):
                bits.append(f"有效期至={cert['not_after']}")
            san = cert.get("san")
            if isinstance(san, list) and san:
                bits.append("SAN=" + " ".join(str(s) for s in san[:6]))
            if bits:
                lines.append(f"{prefix} TLS 证书：{port} " + " ".join(bits))

    # 4) 暴露后台路径（只状态码+标题，证明入口存在）。
    paths = [p for p in (recon.get("exposed_paths") or []) if isinstance(p, dict)]
    if paths:
        parts = []
        for p in paths[:_MAX_RECON_PATHS_SHOWN]:
            label = str(p.get("path", ""))
            status = p.get("status")
            title = p.get("title")
            seg = f"{label}({status})" if status is not None else label
            if title:
                seg += f"「{title}」"
            parts.append(seg)
        more = f" 等共 {len(paths)} 个" if len(paths) > _MAX_RECON_PATHS_SHOWN else ""
        lines.append(f"{prefix} 暴露后台路径：" + " ".join(parts) + more)

    return lines


def render_cve_surface(cve: object) -> list[str]:
    """把 CVE 补查（cve enricher / NVD）结果渲成「已知漏洞方向」取证证据行。

    与 ``render_attack_surface`` 的 Shodan ``vulns`` 互补：本行来自对 Shodan 未覆盖 CPE/指纹的
    NVD 在线补查，带 CVSS/severity，**仅情报方向、非利用、不含 exploit**。复用 Shodan 已覆盖的
    CVE 会标 ``(印证Shodan)``。无数据 / 非 dict / 无 CVE → 返回空列表。绝不抛（坏字段安全跳过）。

    输出形如：
      - NVD 补查·已知漏洞方向(指纹→CVE 情报，非利用)：CVE-2021-44790(9.8 CRITICAL) CVE-2017-15715(8.1 HIGH) … 等共 N 个
    """
    if not isinstance(cve, dict):
        return []
    rows = [r for r in (cve.get("cves") or []) if isinstance(r, dict)]
    if not rows:
        return []

    parts: list[str] = []
    for r in rows[:_MAX_CVES_SHOWN]:
        cid = r.get("id")
        if not isinstance(cid, str):
            continue
        score = r.get("cvss")
        sev = r.get("severity")
        tag_bits = " ".join(
            str(x) for x in (score if isinstance(score, (int, float)) else None, sev) if x
        ).strip()
        seg = f"{cid}({tag_bits})" if tag_bits else cid
        if r.get("reused_from_shodan"):
            seg += "(印证Shodan)"
        parts.append(seg)

    if not parts:
        return []
    total = cve.get("cve_total")
    total = total if isinstance(total, int) and total >= len(rows) else len(rows)
    more = f" 等共 {total} 个" if total > _MAX_CVES_SHOWN else ""
    return ["NVD 补查·已知漏洞方向(指纹→CVE 情报，非利用)：" + " ".join(parts) + more]


def render_related_subdomains(certs: object) -> list[str]:
    """把 crt.sh 证书透明度结果渲成「关联子域(串案)」取证证据行。

    与 Shodan ``hostnames`` 互补：CT 日志覆盖该域名**历史 + 当前**被签过证的全部子域（含 DNS 已
    撤的影子子域），疑同团伙基础设施——建议并簇串案（也可作为主动探测的额外目标，由 recon 自身门控决定）。

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
