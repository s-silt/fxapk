"""测试专用的**文档保留**地址常量，以及「把保留地址当公网候选」的定向放行补丁。

为什么需要这一层
----------------

夹具经常需要一个语义上是「公网业务后端」的地址：判据要它被判公网，端点/闭环/富化
的断言才有意义。但 :mod:`ipaddress` 把 RFC 5737 / RFC 3849 的文档段一律判为
private/reserved，于是这类夹具历史上走了一条错路——挑一段 ``is_global`` 为真的**真实
可路由**地址，再在运行时按段拼装（``".".join((...))``），躲开按字面量正则工作的提交前
泄漏扫描（``core/leakscan.py``）。

那条路必须封掉，理由不是洁癖：

1. **它把门禁变成了摆设。** 拼接模板一旦存在，任何真实 IOC 都能用同一手法写进仓库，
   而扫描器永远看不见。护栏的价值等于它最容易被绕过的那条缝。
2. **它写进仓库的是真地址。** 那种写法之所以"能用"，恰恰因为地址落在全球可路由段而
   不是文档段——``is_global`` 为真正说明它**不是**合成值。
3. **注释还把手法教给了下一个人。** 原注释逐字说明了「写成字面量会被拦下，故拼接」。

正确做法：地址一律用文档保留段（源码里就是**字面量**，扫描器看得见、也确认它无害），
「需要被判公网」这件事**改由定向 patch 分类器表达**——语义写在代码里，而不是靠挑一个
碰巧可路由的真地址来偷偷满足。

放行范围刻意收窄
----------------

:func:`treat_doc_addresses_as_public` 只对**显式列出**的文档地址返回「公网」，其余地址
一律落回真实判据。故 ``192.168.10.233`` / ``127.0.0.1`` 这些夹具里的本机侧地址仍被判私网，
「私网不产接入节点」「本机地址不入端点」这类断言不会被补丁悄悄抽空。
"""

from __future__ import annotations

import ipaddress

import pytest

from apkscan.dynamic import pcap_ingest, probe_ingest

__all__ = [
    "DOC_BACKEND_IP",
    "DOC_DOMAIN",
    "DOC_IPV6",
    "DOC_SECOND_IP",
    "DOC_STATIC_NOISE_IP",
    "DOC_THIRD_IP",
    "is_documentation_address",
    "public_and_non_public_probe_cases",
    "restore_real_address_calipers",
    "treat_doc_addresses_as_public",
]

#: 真实判据的引用，在**任何** patch 之前于导入期捕获。
#: 不能在 patch 之后再去读模块属性——那时读到的就是 patch 本身，
#: 「撤掉补丁」会变成「换一个补丁」，真判据漂移也就测不出来了。
_REAL_IS_NOISE_BARE_IP = probe_ingest.is_noise_bare_ip
_REAL_IP_PUBLIC = pcap_ingest._ip_public
_REAL_IPV6_IS_REPORTABLE = probe_ingest._ipv6_is_reportable

#: RFC 5737 TEST-NET-2 / TEST-NET-3 与 RFC 3849 文档段里的几个占位值。
#: 末段刻意都不为 0：``is_noise_bare_ip`` 把「末段为 0」判成网络地址/版本号噪音。
DOC_BACKEND_IP = "198.51.100.7"
DOC_SECOND_IP = "198.51.100.20"
DOC_THIRD_IP = "198.51.100.31"
DOC_STATIC_NOISE_IP = "203.0.113.11"
DOC_IPV6 = "2001:db8::1"

#: RFC 6761 保留给文档/测试的域名后缀。本仓库夹具用 ``*.example.test`` 当合成公网域名。
DOC_DOMAIN = "api.example.test"

#: 文档保留网段（RFC 5737 + RFC 3849）。放行判据只认落在这些段里的地址。
_DOC_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def is_documentation_address(value: str) -> bool:
    """``value`` 是否为 RFC 5737 / RFC 3849 文档保留地址。非法输入返回 False。"""
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(addr in net for net in _DOC_NETWORKS)


def treat_doc_addresses_as_public(
    monkeypatch: pytest.MonkeyPatch, *addresses: str, **_: object
) -> None:
    """把**列出的**文档地址定向放行成「公网候选」，其余地址仍走真实判据。

    同时打三处，因为三条运行时路径各用一个判据函数，而它们的产出会取**并集**：

    - ``probe_ingest.is_noise_bare_ip``：探针日志的 IPv4 路径（裸 IP 与 URL host 共用）；
    - ``probe_ingest._ipv6_is_reportable``：探针日志的 IPv6 路径（裸 v6 / ``[v6]:port`` /
      URL 里的 v6 都走它；它**不**经过 ``is_noise_bare_ip``，只打前者会让 RFC 3849
      夹具永远判不出公网，v6 断言全成假绿）；
    - ``pcap_ingest._ip_public``：pcap 路径（判哪端是远端、是否产接入节点）。

    只打一处会让各路径口径不一致，夹具就会在「同一后端被算两次」这类缺陷上假绿。

    传入非文档地址直接 :func:`pytest.fail` —— 本工具的用途是放行**合成占位值**，
    不是给真实公网地址开后门。
    """
    allowed = frozenset(addresses)
    for value in sorted(allowed):
        if not is_documentation_address(value):
            pytest.fail(
                f"treat_doc_addresses_as_public 只放行文档保留地址，收到 {value!r}；"
                "夹具请改用 RFC 5737 / RFC 3849 段，不要放行真实公网地址。"
            )

    # v6 按 ``ipaddress`` 的规范压缩形比对：``2001:DB8::0:1`` 与 ``2001:db8::1`` 是同一个
    # 地址的两种写法，按原串比对会让其中一种写法悄悄落回真实判据（→ 判私网 → 假绿）。
    allowed_v6 = frozenset(
        ipaddress.ip_address(value).compressed
        for value in allowed
        if ipaddress.ip_address(value).version == 6
    )

    real_is_noise = probe_ingest.is_noise_bare_ip
    real_ip_public = pcap_ingest._ip_public
    real_ipv6_reportable = probe_ingest._ipv6_is_reportable

    def _is_noise_bare_ip(value: str) -> bool:
        # 放行 = 「不是噪音」，故返回 False；其余一律落回真实判据。
        if value in allowed:
            return False
        return real_is_noise(value)

    def _ip_public(value: str) -> bool:
        if value in allowed:
            return True
        return real_ip_public(value)

    def _ipv6_is_reportable(addr: "ipaddress.IPv6Address") -> bool:
        if addr.compressed in allowed_v6:
            return True
        return real_ipv6_reportable(addr)

    monkeypatch.setattr(probe_ingest, "is_noise_bare_ip", _is_noise_bare_ip)
    monkeypatch.setattr(probe_ingest, "_ipv6_is_reportable", _ipv6_is_reportable)
    monkeypatch.setattr(pcap_ingest, "_ip_public", _ip_public)


def restore_real_address_calipers(monkeypatch: pytest.MonkeyPatch) -> None:
    """撤掉放行补丁，把各侧判据恢复成真实实现。

    比对「各条路径口径是否一致」时必须先撤补丁，否则比的是**补丁 vs 补丁**，
    真判据一旦漂移也测不出来。

    恢复用的是**导入期**捕获的引用（见 :data:`_REAL_IP_PUBLIC`）。绝不能改成读当前模块
    属性、或探测 ``__wrapped__`` 再回退到当前值——补丁已经在位时那等于把补丁自己装回去，
    「撤销」静默变成 no-op。
    """
    monkeypatch.setattr(probe_ingest, "is_noise_bare_ip", _REAL_IS_NOISE_BARE_IP)
    monkeypatch.setattr(probe_ingest, "_ipv6_is_reportable", _REAL_IPV6_IS_REPORTABLE)
    monkeypatch.setattr(pcap_ingest, "_ip_public", _REAL_IP_PUBLIC)


def public_and_non_public_probe_cases() -> tuple[tuple[str, bool], ...]:
    """口径比对用的 ``(地址, 是否应判公网)`` 取样。

    全部是保留/私网/回环地址，故**不含**任何真实公网字面量；「应判公网」那一档由调用方
    用 :func:`treat_doc_addresses_as_public` 放行后再断言，从而两个方向都测到。
    """
    return (
        ("127.0.0.1", False),
        ("192.168.1.9", False),
        ("10.0.0.5", False),
        ("169.254.1.1", False),
        ("0.0.0.0", False),
        ("172.16.5.4", False),
    )
