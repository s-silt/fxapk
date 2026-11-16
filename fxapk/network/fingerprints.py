"""网络事实的纯规范化与稳定指纹工具。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import urllib.parse

__all__ = [
    "DNS_SERVICE_PORTS",
    "KNOWN_INTERCEPT_IPS",
    "AUTHORITATIVE_DNS_HOSTS",
    "PUBLIC_DNS_RESOLVERS",
    "is_authoritative_dns_host",
    "is_infrastructure_endpoint",
    "is_known_intercept_ip",
    "is_public_dns_resolver",
    "normalize_authority",
    "normalize_domain",
    "normalize_ip",
    "parse_asn",
    "sanitize_absolute_url",
    "sanitize_http_path",
    "stable_digest",
]

_MAX_DOMAIN_LENGTH = 253
_MAX_LABEL_LENGTH = 63
_DEFAULT_PORTS = {"http": 80, "https": 443}

#: Known non-business interception nodes. A domestically-blocked fraud domain resolves
#: to an anti-fraud interception page IP — never a real serving/landing host — so it must
#: be excluded from attribution (never surfaced as "the domain's serving IP"). Shared by
#: the pcap ingest (drop as a runtime endpoint) and the attribution bridge (mint no edge).
#: 收录门槛：必须有**主动观测**证据（自签/ISP 证书 + 拦截提示页 + 业务 API 403 这一组
#: 形态同时成立），而不是"某个涉案域名解析到过它"。后者只能说明该域名被拦了，
#: 拿它当收录依据会把运营商的正常业务地址一起吃进来。
#:
#: ★为什么只能是名单、不能做成通用形态判据：判"是不是拦截页"要看响应内容，
#: 而本模块跑在静态/被动侧，拿不到页面。形态判据的位置在主动探测那一侧。
KNOWN_INTERCEPT_IPS: frozenset[str] = frozenset({
    # 中国移动上海。
    "183.192.65.101",
    # 中国电信山东（RDAP netname=CHINANET-SD，本方复核）。
    # 拦截形态由 codex-1 于 2026-08-04 主动探测确认：自签 IDCISP 证书、首页反诈提示、
    # 业务 API 403。★本方只复核了 RDAP 归属，页面形态未独立复现。
    "182.43.124.7",
})


def is_known_intercept_ip(value: str) -> bool:
    """Whether ``value`` is a known interception page IP, not a business server.

    ★先规范化再比：IPv4-mapped IPv6（``::ffff:183.192.65.101``）与压缩写法都折回同一形式，
    防拦截节点被 ``::ffff:...`` 等写法绕过（绕过后会被运行时行为信号误升为中继/边缘候选）。坏输入 → False。"""
    if not isinstance(value, str):
        return False
    if value in KNOWN_INTERCEPT_IPS:
        return True
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    canonical = str(mapped) if mapped is not None else addr.compressed
    return canonical in KNOWN_INTERCEPT_IPS


#: DNS 服务端口：明文 53、DoT 853、mDNS 5353。DoH 走 443 与业务流量同端口，
#: 靠端口分不出来，故本判据不覆盖 DoH（DoH 的排除只能靠域名侧的 infra 名单）。
DNS_SERVICE_PORTS: frozenset[int] = frozenset({53, 853, 5353})

#: 公共递归解析器。这些地址是**基础设施**：App 向它们发 DNS query 只说明"App 在解析域名"，
#: 不说明"App 与业务后端通信"，因此不得计入业务候选、更不得据以判动态闭环。
#:
#: ★为什么只列名单、不把「凡 53 端口皆排除」当判据：团伙自建的 DNS/DoH 服务器同样在 53 端口，
#:   而那是**真线索**（自建解析器往往就架在控制面同一台机器上）。按 IP 名单排除，能保证
#:   未知的 53 端口对端仍被当作业务候选留给人工核 —— 宁可多留噪音，不可丢真节点。
PUBLIC_DNS_RESOLVERS: frozenset[str] = frozenset({
    # 中国大陆
    "223.5.5.5", "223.6.6.6",                       # 阿里 AliDNS
    "114.114.114.114", "114.114.115.115",           # 114DNS
    "119.29.29.29", "182.254.116.116",              # 腾讯 DNSPod
    "1.12.12.12", "120.53.53.53",                   # 腾讯 DNSPod（新段，实测语料里出现）
    "180.76.76.76",                                 # 百度
    "117.50.10.10", "52.80.66.66",                  # OneDNS
    "1.2.4.8", "210.2.4.8",                         # CNNIC sDNS
    "101.226.4.6", "218.30.118.6",                  # DNS 派
    "123.125.81.6", "140.207.198.6",
    # 国际
    "8.8.8.8", "8.8.4.4",                           # Google
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.1.1.3",     # Cloudflare（.2/.3 为其家庭过滤档）
    "9.9.9.9", "149.112.112.112",                   # Quad9
    "208.67.222.222", "208.67.220.220",             # OpenDNS
    "8.26.56.26", "8.20.247.20",                    # Comodo
    "64.6.64.6", "64.6.65.6",                       # Verisign
    "77.88.8.8", "77.88.8.1",                       # Yandex
    "94.140.14.14", "94.140.15.15",                 # AdGuard
    "76.76.2.0", "76.76.10.0",                      # Control D
    "185.228.168.9", "185.228.169.9",               # CleanBrowsing
    # ★以下为同一批服务商的**过滤档 / 家庭档**地址与几家区域解析器。名单原先只收了各家的
    #   默认档，于是同一个服务商的另一档地址照旧被判「建议核查」。实测某第三方库把整份
    #   公共解析器清单编进 DEX，一个样本就贡献 20 余条这类地址。
    "185.228.168.168", "185.228.169.168",           # CleanBrowsing 家庭过滤档
    "208.67.222.123", "208.67.220.123",             # OpenDNS FamilyShield
    "77.88.8.88", "77.88.8.2",                      # Yandex 安全档 / 家庭档
    "199.85.126.10", "199.85.127.10",               # Norton ConnectSafe（服务已下线，地址仍在各清单里）
    "209.244.0.3", "209.244.0.4",                   # Level3 / CenturyLink
    "216.146.35.35", "216.146.36.36",               # Dyn
    "195.46.39.39",                                 # SafeDNS
    "168.95.1.1", "168.95.192.1",                   # 中華電信 HiNet
    "80.80.80.80", "80.80.81.81",                   # Freenom World
})

#: 域名托管商的**权威** DNS 主机（不是递归解析器）。样本里出现同样是 DNS 库的引导/测试
#: 数据，向托管商查这些地址与本案无关。
#:
#: ★只列**实测见过**的地址，不按网段整段放行：Route53 的 NS 确实占着一个公开的 /21，
#:   但本仓没有可离线核对的官方前缀表，按整段放行等于凭记忆替人下结论。
#:   再遇到新地址就加一行——这条路慢，但每一行都可核。
AUTHORITATIVE_DNS_HOSTS: frozenset[str] = frozenset({
    # AWS Route53 的 ns-*.awsdns-*.* 主机
    "205.251.193.186", "205.251.194.188", "205.251.197.22", "205.251.199.99",
})


def is_authoritative_dns_host(value: str) -> bool:
    """``value`` 是否为已知的域名托管商权威 DNS 主机（非业务节点）。

    与 :func:`is_public_dns_resolver` 同口径：先折回 IPv4-mapped IPv6 再比。坏输入 → False。
    """
    if not isinstance(value, str):
        return False
    if value in AUTHORITATIVE_DNS_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped is not None and str(mapped) in AUTHORITATIVE_DNS_HOSTS


def is_public_dns_resolver(value: str) -> bool:
    """``value`` 是否为已知公共递归解析器（非业务节点）。

    与 :func:`is_known_intercept_ip` 同样先规范化 IPv4-mapped IPv6 再比，
    免得 ``::ffff:223.5.5.5`` 这类写法绕过名单。坏输入 → False。
    """
    if not isinstance(value, str):
        return False
    if value in PUBLIC_DNS_RESOLVERS:
        return True
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    canonical = str(mapped) if mapped is not None else addr.compressed
    return canonical in PUBLIC_DNS_RESOLVERS


def is_infrastructure_endpoint(ip: str, port: object) -> bool:
    """该 (ip, port) 是否为**基础设施**对端 —— 观测到它不构成业务通信证据。

    当前判据：已知公共解析器 + DNS 服务端口。两个条件都要满足 ——
    单看端口会误杀团伙自建 DNS，单看 IP 会漏掉"公共解析器同时提供别的服务"这种理论情形
    （实践中不存在，但两条件与的写法让判据的含义留在代码里）。
    """
    if not is_public_dns_resolver(ip):
        return False
    if isinstance(port, bool):          # bool 是 int 的子类，先挡掉
        return False
    if isinstance(port, int):
        return port in DNS_SERVICE_PORTS
    if isinstance(port, str):
        try:
            return int(port) in DNS_SERVICE_PORTS
        except ValueError:
            return False
    return False


def _require_string(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not value:
        raise ValueError(f"{name} must not be empty")
    return value


_ASN_MIN, _ASN_MAX = 1, 4_294_967_294  # 合法 32-bit ASN 范围（RFC 6996/7300 私有段不在此另判）


def parse_asn(value: object) -> tuple[int | None, str | None]:
    """★共享数据契约：严格解析 ASN——仅接受纯整数或**完整匹配** ``AS?<digits>[ <org>]`` 的字符串，校验 32-bit 范围。

    返回 ``(asn_num, org_tail)``；畸形（``-123 x`` / ``1.5 x`` / ``garbage123`` / 越界 / 超长数字串）→ ``(None, None)``。
    绝不用 ``re.search`` 从中间抠数字冒充高置信归属；★绝不抛（超长数字串按位数在 ``int()`` 前拒，避开 CPython
    4300 位限制）。core/attribution（五层）与 attribution/assemble（角色）共用此一份，消除两处口径漂移。"""
    if isinstance(value, bool) or value is None:  # bool 是 int 子类，须排除
        return None, None
    if isinstance(value, int):
        n, org_tail = value, None
    else:
        m = re.match(r"^\s*(?:AS)?(\d+)(?:\s+(.*))?$", str(value), re.IGNORECASE)
        if not m or len(m.group(1)) > 10:  # 合法 ASN ≤ 10 位；超长直接拒，避免 int() 触达 4300 位限制抛
            return None, None
        n = int(m.group(1))
        org_tail = (m.group(2) or "").strip() or None
    return (n, org_tail) if _ASN_MIN <= n <= _ASN_MAX else (None, None)


def normalize_ip(value: str) -> str:
    """返回 IPv4/IPv6 字面量的压缩规范形式。"""
    raw = _require_string("IP address", value)
    if raw != raw.strip():
        raise ValueError("IP address must not contain surrounding whitespace")
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc


def normalize_domain(value: str) -> str:
    """返回小写 IDNA 域名；去掉尾点并拒绝 IP 字面量。"""
    raw = _require_string("domain", value)
    if any(char.isspace() for char in raw):
        raise ValueError(f"whitespace not allowed in domain: {value!r}")
    stripped = raw.rstrip(".")
    if not stripped:
        raise ValueError("domain must contain at least one label")
    try:
        ipaddress.ip_address(stripped)
    except ValueError:
        pass
    else:
        raise ValueError(f"IP literal is not a domain: {value!r}")

    labels: list[str] = []
    for label in stripped.split("."):
        if not label:
            raise ValueError(f"empty label in domain: {value!r}")
        try:
            encoded = label.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(f"invalid domain label: {label!r}") from exc
        if not encoded or len(encoded) > _MAX_LABEL_LENGTH:
            raise ValueError(f"invalid domain label: {label!r}")
        labels.append(encoded)

    normalized = ".".join(labels)
    if len(normalized) > _MAX_DOMAIN_LENGTH:
        raise ValueError(f"domain too long: {value!r}")
    return normalized


def _parse_port(value: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError(f"invalid port: {value!r}")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return port


def normalize_authority(value: str) -> tuple[str, str, int | None, bool]:
    """返回 ``(authority, host, port, is_ip)``，支持括号 IPv6。"""
    raw = _require_string("authority", value)
    if any(char.isspace() for char in raw):
        raise ValueError(f"whitespace not allowed in authority: {value!r}")
    if "@" in raw:
        raise ValueError("userinfo is not allowed in an authority")
    if any(char in raw for char in "/?#"):
        raise ValueError("path, query, or fragment is not allowed in an authority")

    port_text: str | None
    if raw.startswith("["):
        closing = raw.find("]")
        if closing < 0:
            raise ValueError(f"unterminated IPv6 authority: {value!r}")
        host_raw = raw[1:closing]
        remainder = raw[closing + 1 :]
        if remainder and not remainder.startswith(":"):
            raise ValueError(f"invalid suffix after IPv6 authority: {value!r}")
        port_text = remainder[1:] if remainder else None
        try:
            host = ipaddress.IPv6Address(host_raw).compressed
        except ValueError as exc:
            raise ValueError(f"invalid IPv6 authority: {value!r}") from exc
        rendered_host = f"[{host}]"
        is_ip = True
    else:
        if raw.count(":") > 1:
            raise ValueError("IPv6 authorities must use brackets")
        if ":" in raw:
            host_raw, port_text = raw.split(":", 1)
        else:
            host_raw, port_text = raw, None
        if not host_raw:
            raise ValueError("authority host must not be empty")
        try:
            host = ipaddress.IPv4Address(host_raw).compressed
            is_ip = True
        except ValueError:
            host = normalize_domain(host_raw)
            is_ip = False
        rendered_host = host

    port = _parse_port(port_text) if port_text is not None else None
    authority = rendered_host if port is None else f"{rendered_host}:{port}"
    return authority, host, port, is_ip


def sanitize_http_path(value: str) -> str:
    """返回去掉 query/fragment/authority 的 origin-form 路径。"""
    if not isinstance(value, str):
        raise TypeError("HTTP path must be a string")
    parsed = urllib.parse.urlsplit(value)
    path = parsed.path or "/"
    return path if path.startswith("/") else f"/{path}"


def sanitize_absolute_url(value: str) -> str:
    """规范化 HTTP(S) URL，并移除 query、fragment 与默认端口。"""
    raw = _require_string("URL", value)
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError("URL scheme must be http or https")
    if not parsed.netloc:
        raise ValueError("absolute URL must contain an authority")
    _authority, host, port, is_ip = normalize_authority(parsed.netloc)
    rendered_host = f"[{host}]" if is_ip and ":" in host else host
    netloc = (
        rendered_host
        if port is None or port == _DEFAULT_PORTS[scheme]
        else f"{rendered_host}:{port}"
    )
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return urllib.parse.urlunsplit((scheme, netloc, path, "", ""))


def stable_digest(namespace: str, payload: object) -> str:
    """对命名空间和规范 JSON 计算完整 SHA-256 十六进制摘要。"""
    clean_namespace = _require_string("namespace", namespace).strip()
    if not clean_namespace:
        raise ValueError("namespace must not be blank")
    try:
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("payload is not canonical-JSON serializable") from exc
    digest = hashlib.sha256()
    digest.update(clean_namespace.encode("utf-8"))
    digest.update(b"\0")
    digest.update(canonical.encode("utf-8"))
    return digest.hexdigest()
