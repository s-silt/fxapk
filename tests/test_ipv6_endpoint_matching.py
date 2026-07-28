"""IPv6 端点在「Lead 值带端口 ↔ Endpoint 裸地址」这条链上的匹配。

背景（codex 二轮 P1）：运行时 Lead 的值形如 ``<addr>:<port>/<proto>``，而 Endpoint 一律裸地址。
IPv4 靠 ``infra._strip_port_suffix`` 剥端口对上；IPv6 此前**整条断掉**——裸拼出来的
``2001:db8::1:443/tcp`` 冒号太多，剥端口的判据（``count(":") == 1``）直接放弃，于是 target 选择、
closure 回写、letters 归属链三处同时匹配不上。

修法分两头：
- 生产侧改用 RFC 3986 括号形态 ``[2001:db8::1]:443/tcp``（``pcap_ingest.format_peer``），从此无歧义；
- 消费侧既认括号形态，也用 ``/proto`` 尾缀给**旧产物**里的无括号拼接消歧。

★最要紧的不变量是「裸 IPv6 绝不能被剥」：``2001:db8::1`` 的末段 ``1`` 本身就是合法端口号，
  剥一刀就得到 ``2001:db8:``，地址直接毁掉。
"""

from __future__ import annotations

from apkscan.core import infra
from apkscan.dynamic import pcap_ingest

_V6 = "2001:db8::1"
_V6_FULL = "2606:4700:4700::1111"


# ---------------------------------------------------------------------------
# 生产侧：拼出来的字面必须无歧义
# ---------------------------------------------------------------------------


def test_format_peer_brackets_ipv6_only() -> None:
    assert pcap_ingest.format_peer("8.138.102.85", 31861, "tcp") == "8.138.102.85:31861/tcp"
    assert pcap_ingest.format_peer(_V6, 443, "tcp") == "[2001:db8::1]:443/tcp"
    # 不带 proto 的形态（remote_endpoints 用）同样加括号
    assert pcap_ingest.format_peer(_V6, 443) == "[2001:db8::1]:443"
    assert pcap_ingest.format_peer("1.2.3.4", 80) == "1.2.3.4:80"


def test_runtime_lead_for_ipv6_uses_bracket_form() -> None:
    """★端到端：pcap 产出的 IPv6 Lead 值必须是括号形态，否则下游一律匹配不上。"""
    flows = [
        pcap_ingest.Flow(proto="tcp", src_ip="192.168.10.233", src_port=45678,
                         dst_ip=_V6_FULL, dst_port=8443, packets=20,
                         payload_bytes=1500, flags={"syn"}),
        pcap_ingest.Flow(proto="tcp", src_ip=_V6_FULL, src_port=8443,
                         dst_ip="192.168.10.233", dst_port=45678, packets=18,
                         payload_bytes=900, flags={"synack"}),
    ]
    leads = pcap_ingest.to_report_leads(pcap_ingest.PcapSummary(flows=flows))
    ip_leads = [ld for ld in leads if ld.category.value == "IP"]
    assert any(ld.value == f"[{_V6_FULL}]:8443/tcp" for ld in ip_leads), \
        f"IPv6 Lead 没用括号形态：{[ld.value for ld in ip_leads]}"


# ---------------------------------------------------------------------------
# 消费侧：归一化
# ---------------------------------------------------------------------------


def test_bracket_form_strips_to_bare_ipv6() -> None:
    assert infra.match_key("IP", f"[{_V6}]:443/tcp") == _V6
    assert infra.match_key("IP", f"[{_V6}]:443") == _V6
    assert infra.match_key("IP", f"[{_V6}]") == _V6


def test_bare_ipv6_is_never_stripped() -> None:
    """★核心不变量：裸 IPv6 一刀都不能剥。

    ``2001:db8::1`` 末段是 ``1``、``...::1111`` 末段是 ``1111``，都是合法端口号——
    按"末段是数字就当端口"去剥，会把地址剁成 ``2001:db8:``，之后一切匹配都是错的。
    """
    for bare in (_V6, _V6_FULL, "fe80::1", "::1", "2001:db8:85a3::8a2e:370:7334"):
        assert infra.match_key("IP", bare) == bare, f"裸 IPv6 {bare} 被剥了端口"


def test_legacy_unbracketed_ipv6_is_disambiguated_by_proto_suffix() -> None:
    """旧产物里的 ``2001:db8::1:443/tcp`` 靠 ``/proto`` 尾缀消歧——那个后缀只由拼过端口的路径产生。"""
    assert infra.match_key("IP", f"{_V6}:443/tcp") == _V6
    assert infra.match_key("IP", f"{_V6_FULL}:8443/udp") == _V6_FULL
    # 没有 /proto 尾缀就没有消歧依据 → 保守不动（当成裸地址）
    assert infra.match_key("IP", f"{_V6}:443") == f"{_V6}:443"


def test_ipv4_behaviour_unchanged() -> None:
    """IPv4 与域名侧的既有行为一字不改。"""
    assert infra.match_key("IP", "8.138.102.85:31861/tcp") == "8.138.102.85"
    assert infra.match_key("IP", "223.5.5.5:53/udp") == "223.5.5.5"
    assert infra.match_key("IP", "8.138.102.85") == "8.138.102.85"
    assert infra.match_key("DOMAIN", "Pay.X.com") == "pay.x.com"
    # 非 IP 字面（OID 形态）不受影响
    assert infra.match_key("IP", "1.3.101.112.1") == "1.3.101.112.1"


def test_malformed_bracket_is_not_guessed() -> None:
    """只有左括号的坏字面不猜，原样返回——宁可匹配不上，也不要造一个错地址出来。"""
    assert infra.match_key("IP", "[2001:db8::1:443/tcp") == "[2001:db8::1:443"


# ---------------------------------------------------------------------------
# 三个消费面：确认归一化真的接上了
# ---------------------------------------------------------------------------


def test_remote_endpoints_roundtrip_through_the_shared_parser() -> None:
    """★格式化与解析必须是一对：写方 format_hostport、读方 split_hostport，全仓只此一份。

    上一轮的回归就出在这里——pcap 侧改成了括号形态，attribution 侧还在本地
    ``rpartition(":")``，于是拿到 ``"[2606:...]"`` 解析不出地址，IPv6 的运行时归因边**静默**丢光。
    """
    for ip, port in ((_V6, 443), (_V6_FULL, 8443), ("8.138.102.85", 31861), ("::1", 80)):
        wire = infra.format_hostport(ip, port)
        assert infra.split_hostport(wire) == (ip, port), f"{wire} 无法还原回 ({ip}, {port})"

    # 旧产物的裸拼形态也要能解析（下游读到的历史报告里就是这个）
    assert infra.split_hostport("8.138.102.85:31861") == ("8.138.102.85", 31861)
    # 坏形状一律 None，绝不猜
    for bad in ("", "no-colon", "[2001:db8::1:443", "1.2.3.4:0", "1.2.3.4:99999",
                "1.2.3.4:abc", "not-an-ip:80", None, 123):
        assert infra.split_hostport(bad) is None, f"{bad!r} 不该被解析成端点"


def test_ipv6_runtime_endpoint_reaches_attribution() -> None:
    """★入口级链路：pcap 回灌 → runtime.remote_endpoints → attribution 解析出 IPv6 落地 IP。

    这条才是能逮住"格式改了但消费方没跟上"的测试。上一轮我只测到 match_key 与 letters，
    attribution 那一环没走，于是自己引入的回归自己没发现——由 codex 复审指出。
    """
    from apkscan.attribution import assemble

    flows = [
        pcap_ingest.Flow(proto="tcp", src_ip="192.168.10.233", src_port=45678,
                         dst_ip=_V6_FULL, dst_port=8443, packets=20,
                         payload_bytes=1500, flags={"syn"}, sni={"api.example.test"}),
        pcap_ingest.Flow(proto="tcp", src_ip=_V6_FULL, src_port=8443,
                         dst_ip="192.168.10.233", dst_port=45678, packets=18,
                         payload_bytes=900, flags={"synack"}),
    ]
    eps = pcap_ingest._runtime_endpoint_dicts(pcap_ingest.PcapSummary(flows=flows))
    rt = next(e for e in eps if e["value"] == _V6_FULL)["enrichment"]["runtime"]

    assert rt["remote_endpoints"] == [f"[{_V6_FULL}]:8443"], "回灌写出的不是括号形态"
    # attribution 侧必须能从同一个字面里取回裸 IPv6
    assert assemble._ip_from_hostport(rt["remote_endpoints"][0]) == _V6_FULL, \
        "attribution 解析不出 IPv6 落地 IP —— 运行时归因边会被静默丢掉"


def test_ipv6_lead_reaches_the_letter_attribution_chain() -> None:
    """★letters 侧：括号形态的 IPv6 Lead 要能关联上裸 IPv6 Endpoint 的五层归属链。"""
    from apkscan.report import letters

    layer = {
        "ip": _V6_FULL,
        "resource_holder": {"name": "EXAMPLE-V6-NET", "confidence": "high"},
        "origin_network": {"asn": 64500, "organization": "Example", "category": "cloud",
                           "confidence": "high"},
        "hosting_provider": {"name": "Example", "role": "cloud_host", "confidence": "medium"},
        "edge_provider": {"name": None, "role": None, "tier": None},
        "service_operator": {"name": None, "confidence": "unknown"},
    }
    report = {
        "leads": [{
            "category": "IP", "value": f"[{_V6_FULL}]:8443/tcp", "subject": "某科技有限公司",
            "where_to_request": "云服务商", "advice": "建议调证",
            "evidence_to_obtain": ["租户实名"],
            "source_refs": [{"evidence_id": "E1"}],
        }],
        "endpoints": [{
            "value": _V6_FULL, "kind": "ip",
            "enrichment": {"attribution": {"endpoint": _V6_FULL, "kind": "ip", "ips": [layer]}},
        }],
    }
    out = letters.build_letters(report)
    assert len(out) == 1
    assert "基础设施归属链" in out[0]["body_md"], "IPv6 标的没关联上归属链"
    assert out[0]["attribution"]["ips"][0]["ip"] == _V6_FULL
