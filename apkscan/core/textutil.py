"""文本 / URL / host / IP 解析与标量工具 —— 端点类分析器共享的纯函数实现。

以 analyzers/endpoints.py 的最完整实现为基准抽出，供 endpoints / js_bundle 等
分析器复用，消除逐字重复的本地副本。这里全部是纯函数（无状态、无副作用），
行为与原 endpoints.py 私有实现逐字一致。

约束：
- 纯标准库，禁止 import androguard / 任何分析器。
- 全程 type hints。
"""

from __future__ import annotations

import ipaddress
import re


def as_str_list(value: object) -> list[str]:
    """把规则字段规整为 str 列表（容忍 None / 非 list / 含非 str 元素）。"""
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def truncate(text: str, limit: int) -> str:
    """超过 limit 截断并追加省略号；否则原样返回。"""
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def strip_url_tail(url: str) -> str:
    """去掉 URL 尾部常见标点噪音（句号、逗号、引号、闭合括号等）。"""
    url = url.strip()
    # 去尾部成对/标点
    while url and url[-1] in ".,;:'\")]}>" + "”’、，。；":
        # 闭合括号若有对应开括号则保留
        if url[-1] == ")" and url.count("(") > url.count(")"):
            break
        if url[-1] == "]" and url.count("[") > url.count("]"):
            break
        url = url[:-1]
    return url


def host_from_url(url: str) -> str:
    """从 URL 取 host（去 scheme / userinfo / port / path）。失败返回空。"""
    try:
        after = url.split("://", 1)[1]
    except IndexError:
        return ""
    # 截到 path/query/fragment 之前
    for sep in ("/", "?", "#"):
        idx = after.find(sep)
        if idx != -1:
            after = after[:idx]
    # 去 userinfo
    if "@" in after:
        after = after.rsplit("@", 1)[1]
    # 去端口（IPv6 不在本期范围，按简单规则去 :port）
    if after.startswith("["):  # IPv6 字面量
        end = after.find("]")
        if end != -1:
            return after[: end + 1]
    if ":" in after:
        after = after.split(":", 1)[0]
    return after.strip().rstrip(".").lower()


def is_noise_bare_ip(ip_str: str) -> bool:
    """裸 IP 是否为版本号/网络地址/保留段噪音（C4 降噪）。

    仅作用于"裸 IP"——URL host 内的 IP 仍走 host 通道不受此限（URL 形式的私网/示例
    IP 仍产端点，与现状一致）。判为噪音的情形：
    - 首段或末段为 0（1.0.0.0 / 3.2.16.0 / 0.0.0.0 等版本串/网络地址）。
    - bogon / 保留 / 示例段（用 ipaddress 判定，比手写段更稳）：私网(RFC1918) /
      回环(127/8) / 链路本地(169.254/16) / 保留 / 多播 / 未指定。这类裸 IP 无调证价值。
    注意：TEST-NET（192.0.2/24 等 RFC5737 文档示例段）不被 ipaddress 判为 is_reserved，
    故由调用方的 noise_ips denylist 或 host 通道处理；本函数不强行覆盖。
    """
    octets = ip_str.split(".")
    if len(octets) != 4:
        return False
    if octets[0] == "0" or octets[-1] == "0":
        return True
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def parse_ipv4(ip_str: str) -> ipaddress.IPv4Address | None:
    """严格解析 IPv4（每段 0-255）。非法返回 None。"""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return None
    for p in parts:
        if not p.isdigit() or len(p) > 3:
            return None
        if int(p) > 255:
            return None
    try:
        return ipaddress.IPv4Address(ip_str)
    except ValueError:
        return None


def ip_is_private(ip: ipaddress.IPv4Address) -> bool:
    """RFC1918 / 回环 / 链路本地 / 0.0.0.0 / 保留 / 多播 → 私网。"""
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_multicast
    )


def host_is_private(host: str) -> bool:
    """host 本身若是 IPv4 字面量且私网 → True；否则按本机别名 / .local 等判定。"""
    ip = parse_ipv4(host)
    if ip is not None:
        return ip_is_private(ip)
    # 常见局域网/本机别名
    if host in ("localhost", "localhost.localdomain"):
        return True
    if host.endswith(".local") or host.endswith(".lan") or host.endswith(".internal"):
        return True
    return False


def valid_url_host(host: str) -> bool:
    """URL 的 host 是否像真实主机：IPv4 字面量 / 含点且末段为 2+ 字母 / 本机别名。

    用于剔除 http://%s、http://config、http://bi 这类来自格式串/代码的伪 URL。
    """
    host = host.strip().rstrip(".")
    if not host:
        return False
    if parse_ipv4(host) is not None:
        return True
    if host in ("localhost", "localhost.localdomain"):
        return True
    if "." not in host:
        return False
    last = host.rsplit(".", 1)[-1]
    return last.isalpha() and 2 <= len(last) <= 24


def looks_keyish(value: str) -> bool:
    """值是否“像密钥”：纯十六进制 / 含 Base64 特征字符 / 字母数字混合。"""
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return True
    if any(c in value for c in "+/="):
        return True
    if any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
        return True
    return False
