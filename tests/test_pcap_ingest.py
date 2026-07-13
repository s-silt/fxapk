"""apkscan.dynamic.pcap_ingest 的单测。

pcap_ingest 吃一个**带外抓的 pcap**（网关 tcpdump / PCAPdroid 免 root 导出），即使 TLS 解不开、
是 MTProto/native 自建协议，也从裸包里抽出 **接入节点 IP:port + TLS SNI + DNS 查询**，按 LeadCategory
聚成调证线索 / 回灌 report.json——把"解不开也能办案：带外拿接入节点 IP=穿透锚点"变成一条命令。

测试：纯标准库 pcap 解析（craft 真实格式字节）+ 线索映射 + 台账 + report.json 追加。
"""

from __future__ import annotations

import json
import struct

import pytest

from apkscan.core.models import Confidence, LeadCategory
from apkscan.dynamic import pcap_ingest


# ---------- 按 pcap/Ethernet/IP/TCP/UDP/TLS/DNS 规范 craft 最小有效字节 ----------
def _eth(payload: bytes, ethertype: int) -> bytes:
    return b"\x11\x22\x33\x44\x55\x66" + b"\xaa\xbb\xcc\xdd\xee\xff" + struct.pack("!H", ethertype) + payload


def _ipv4(payload: bytes, proto: int, src: str, dst: str) -> bytes:
    import socket

    total = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return hdr + payload


def _tcp(payload: bytes, sport: int, dport: int) -> bytes:
    # data offset 5 (20B), flags PSH+ACK
    hdr = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, (5 << 4), 0x18, 65535, 0, 0)
    return hdr + payload


def _udp(payload: bytes, sport: int, dport: int) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tls_client_hello(sni: str) -> bytes:
    """最小可解析的 TLS ClientHello（含 SNI 扩展）。"""
    sni_b = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(sni_b)) + sni_b  # type=host_name(0) + len + name
    snl = struct.pack("!H", len(server_name)) + server_name        # server_name_list
    sni_ext = struct.pack("!HH", 0x0000, len(snl)) + snl           # ext type=0 + len + body
    exts = sni_ext
    body = (
        b"\x03\x03"                       # client version TLS1.2
        + b"\x00" * 32                    # random
        + b"\x00"                         # session id len 0
        + struct.pack("!H", 2) + b"\x13\x01"  # cipher suites len + 1 suite
        + b"\x01\x00"                     # compression methods len 1 + null
        + struct.pack("!H", len(exts)) + exts
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body   # type=1 + 3-byte len + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def _dns_query(qname: str) -> bytes:
    q = b"".join(struct.pack("!B", len(p)) + p.encode() for p in qname.split(".")) + b"\x00"
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + q + struct.pack("!HH", 1, 1)  # qtype A, qclass IN


def _ipv6(payload: bytes, proto: int, src: str, dst: str) -> bytes:
    import socket

    hdr = (
        struct.pack("!IHBB", 0x60000000, len(payload), proto, 64)
        + socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, dst)
    )
    return hdr + payload


def _tcp_flags(payload: bytes, sport: int, dport: int, flags: int) -> bytes:
    """带指定 TCP 标志的 TCP 段（0x02=SYN、0x12=SYN+ACK、0x18=PSH+ACK、0x04=RST）。"""
    hdr = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, (5 << 4), flags, 65535, 0, 0)
    return hdr + payload


def _dns_response_txt(qname: str, txt: str, rcode: int = 0) -> bytes:
    """最小 DNS 应答（QR=1，1 问 1 答，答为 TXT）——模拟 ClientCore 经 DNS TXT 下发配置。"""
    q = b"".join(struct.pack("!B", len(p)) + p.encode() for p in qname.split(".")) + b"\x00"
    header = struct.pack("!HHHHHH", 0x4321, 0x8000 | (rcode & 0x0F), 1, 1, 0, 0)  # QR=1 + rcode
    question = q + struct.pack("!HH", 16, 1)  # qtype TXT(16) + IN
    txt_b = txt.encode()
    rdata = struct.pack("!B", len(txt_b)) + txt_b  # TXT rdata：长度前缀字符串
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 300, len(rdata)) + rdata  # name 指针→问题段
    return header + question + answer


def _pcap(packets: list[bytes], linktype: int = 1) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, pkt in enumerate(packets):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(pkt), len(pkt)) + pkt
    return out


def _sample_pcap() -> bytes:
    p_tls = _eth(_ipv4(_tcp(_tls_client_hello("evil-c2.example.com"), 50000, 443), 6, "10.0.0.2", "203.0.113.9"), 0x0800)
    p_dns = _eth(_ipv4(_udp(_dns_query("tracker.example.org"), 40000, 53), 17, "10.0.0.2", "10.0.0.1"), 0x0800)
    p_native = _eth(_ipv4(_tcp(b"\x00\x01\x02", 50001, 30113), 6, "10.0.0.2", "106.53.21.146"), 0x0800)
    return _pcap([p_tls, p_dns, p_native])


# ======================================================================
# A. 纯标准库 pcap 解析
# ======================================================================


def test_parse_extracts_tls_sni() -> None:
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    snis = {s for f in summary.flows for s in f.sni}
    assert "evil-c2.example.com" in snis


def test_parse_extracts_native_endpoint_ip_port() -> None:
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    peers = {(f.dst_ip, f.dst_port) for f in summary.flows}
    assert ("106.53.21.146", 30113) in peers  # native 接入节点(无 TLS 也抓到)
    assert ("203.0.113.9", 443) in peers


def test_parse_extracts_dns_query() -> None:
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    assert "tracker.example.org" in summary.dns_queries


def test_parse_bad_bytes_returns_empty_not_crash() -> None:
    assert pcap_ingest.parse_pcap_bytes(b"not a pcap").flows == []


# ======================================================================
# B. 线索映射
# ======================================================================


def test_to_leads_native_ip_is_穿透_lead() -> None:
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    leads = pcap_ingest.to_report_leads(summary)
    ip_leads = [l for l in leads if l.category == LeadCategory.IP]
    assert any("106.53.21.146" in l.value and "30113" in l.value for l in ip_leads)
    # 公网接入节点默认建议调证、source=runtime-pcap
    node = next(l for l in ip_leads if "106.53.21.146" in l.value)
    assert node.source_refs and node.source_refs[0].source.startswith("runtime")
    assert node.advice == "建议调证"


def test_to_leads_sni_and_dns_become_domain_leads() -> None:
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    leads = pcap_ingest.to_report_leads(summary)
    dom = {l.value for l in leads if l.category == LeadCategory.DOMAIN}
    assert "evil-c2.example.com" in dom  # 来自 SNI
    assert "tracker.example.org" in dom  # 来自 DNS


def test_private_ip_filtered_out() -> None:
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    leads = pcap_ingest.to_report_leads(summary)
    # 10.0.0.1(DNS 服务器，私网)不应作为 IP 接入节点线索
    assert not any("10.0.0.1" in l.value for l in leads if l.category == LeadCategory.IP)


def test_build_ledger_md_has_sections() -> None:
    md = pcap_ingest.build_ledger_md(pcap_ingest.parse_pcap_bytes(_sample_pcap()))
    assert "调证台账" in md or "接入节点" in md
    assert "106.53.21.146" in md
    assert "向" in md  # where_to_request


def test_merge_into_report_json_appends(tmp_path) -> None:
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": []}, ensure_ascii=False), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    added = pcap_ingest.merge_into_report_json(str(p), summary)
    assert added > 0
    out = json.loads(p.read_text(encoding="utf-8"))
    assert len(out["leads"]) == added
    assert any("106.53.21.146" in str(l.get("value", "")) for l in out["leads"])


# ======================================================================
# C. 原子写：写中途失败不留半截坏 JSON
# ======================================================================


def test_merge_atomic_keeps_old_content_when_write_fails(tmp_path, monkeypatch) -> None:
    """回灌写盘中途抛异常 → report.json 保持旧内容完整、绝不留半截坏 JSON。"""
    p = tmp_path / "report.json"
    original = {"leads": [{"category": "DOMAIN", "value": "已存在.example", "advice": "建议调证"}]}
    p.write_text(json.dumps(original, ensure_ascii=False, indent=2), encoding="utf-8")

    # 让原子写在替换目标文件前爆掉（模拟磁盘满 / 进程被杀）。
    def boom(*_a, **_k):
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(pcap_ingest.atomic_write_text.__module__ + ".Path.write_text", boom, raising=True)

    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    added = pcap_ingest.merge_into_report_json(str(p), summary)
    assert added == 0  # 写失败保底返 0
    # 关键：原文件仍是可解析的完整旧内容，未被半截覆盖
    reloaded = json.loads(p.read_text(encoding="utf-8"))
    assert reloaded == original


# ======================================================================
# D. runtime 确认合并（非 dedup 丢弃）
# ======================================================================


def test_merge_runtime_confirms_existing_static_domain(tmp_path) -> None:
    """静态已有 DOMAIN=evil-c2.example.com，回灌 runtime 观测同 domain → 合并为活体确认。"""
    p = tmp_path / "report.json"
    static_lead = {
        "category": "DOMAIN",
        "value": "evil-c2.example.com",
        "advice": "建议调证",
        "source_refs": [{"source": "dex", "location": "com/x/Api", "snippet": "静态硬编码"}],
        "is_runtime_seen": False,
    }
    p.write_text(json.dumps({"leads": [static_lead]}, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    pcap_ingest.merge_into_report_json(str(p), summary)

    out = json.loads(p.read_text(encoding="utf-8"))
    merged = next(l for l in out["leads"] if l.get("value") == "evil-c2.example.com")
    # 同键未被 continue 丢弃：runtime source_ref 已并入、升为活体确认
    sources = [str(ev.get("source", "")) for ev in merged.get("source_refs", [])]
    assert any(s.startswith("runtime") for s in sources)
    assert any(s == "dex" for s in sources)  # 原静态证据保留
    assert merged.get("is_runtime_seen") is True


def test_merge_runtime_no_dup_lead_for_existing_key(tmp_path) -> None:
    """命中已存在键不新增一条重复 lead（合并进原 lead 而非 append）。"""
    p = tmp_path / "report.json"
    static_lead = {"category": "DOMAIN", "value": "evil-c2.example.com", "advice": "建议调证"}
    p.write_text(json.dumps({"leads": [static_lead]}, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    pcap_ingest.merge_into_report_json(str(p), summary)
    out = json.loads(p.read_text(encoding="utf-8"))
    same = [l for l in out["leads"] if l.get("value") == "evil-c2.example.com"]
    assert len(same) == 1


# ======================================================================
# E. Evidence.observed_at 回灌落库
# ======================================================================


def test_observed_at_populated_for_ip_lead() -> None:
    """IP 接入节点线索的 runtime Evidence 带 observed_at（来自 Flow.first_ts）。"""
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    leads = pcap_ingest.to_report_leads(summary)
    node = next(l for l in leads if l.category == LeadCategory.IP and "106.53.21.146" in l.value)
    ev = node.source_refs[0]
    assert ev.observed_at is not None
    # native 包是第 3 个（index 2），pcap ts = 1700000000 + 2
    assert ev.observed_at == pytest.approx(1700000002.0)


def test_observed_at_落库_into_report_json(tmp_path) -> None:
    """回灌后 observed_at 落进 report.json。"""
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": []}, ensure_ascii=False), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    pcap_ingest.merge_into_report_json(str(p), summary)
    out = json.loads(p.read_text(encoding="utf-8"))
    node = next(l for l in out["leads"] if "106.53.21.146" in str(l.get("value", "")))
    assert node["source_refs"][0].get("observed_at") is not None


def test_iter_frames_nanosecond_pcap_timestamp() -> None:
    """★ 回归（codex review P2）：纳秒精度 pcap（magic a1b23c4d / 4d3cb2a1）的小数字段
    须按 1e9 还原，不能一律 /1e6——否则 observed_at 偏移最多近千秒，和设备/网关日志对不上。"""

    def _one_packet_pcap(magic: bytes, endian: str, ts_sec: int, ts_frac: int) -> bytes:
        payload = b"\x00" * 14  # 占位帧，内容不影响时间戳解析
        gh = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 1)  # linktype=1
        rec = struct.pack(endian + "IIII", ts_sec, ts_frac, len(payload), len(payload))
        return gh + rec + payload

    # 纳秒 magic：500_000_000 ns = 0.5s → ts 应为 1000.5（修前误 /1e6 会得 1500.0）。
    ns = _one_packet_pcap(b"\xa1\xb2\x3c\x4d", ">", 1000, 500_000_000)
    assert list(pcap_ingest._iter_frames(ns))[0][0] == pytest.approx(1000.5)
    # 微秒 magic：500_000 µs = 0.5s → 同为 1000.5（这条一直对，作对照）。
    us = _one_packet_pcap(b"\xa1\xb2\xc3\xd4", ">", 1000, 500_000)
    assert list(pcap_ingest._iter_frames(us))[0][0] == pytest.approx(1000.5)
    # 小端纳秒 magic 也走 1e9。
    le = _one_packet_pcap(b"\x4d\x3c\xb2\xa1", "<", 2000, 250_000_000)
    assert list(pcap_ingest._iter_frames(le))[0][0] == pytest.approx(2000.25)


def test_strip_link_sll2_linktype_276() -> None:
    """★ 回归（codex review P2）：`tcpdump -i any` 在新版 libpcap 下写 SLL2（linktype 276）；
    _strip_link 须能剥它（20 字节头，EtherType 在 offset 0、IP 载荷从 offset 20 起），
    否则设备侧 floor.pcap 被接受为产物却解析出 0 条流（pcap-leads 拿不到接入节点）。"""
    ip_payload = b"IPPKT-PLACEHOLDER"
    # SLL2 头：protocol(EtherType, 2B, BE) + 18B 其余头 = 20B。
    frame = struct.pack("!H", 0x0800) + b"\x00" * 18 + ip_payload
    et, payload = pcap_ingest._strip_link(276, frame)
    assert et == 0x0800 and payload == ip_payload
    # IPv6 EtherType + 太短的 SLL2 帧的安全边界。
    assert pcap_ingest._strip_link(276, struct.pack("!H", 0x86DD) + b"\x00" * 18 + b"x")[0] == 0x86DD
    assert pcap_ingest._strip_link(276, b"\x08\x00\x00") == (None, b"")


# ======================================================================
# F. P0-1 远端聚合分级（established / syn_only）+ P0-2 DNS 结构化
# ======================================================================


def test_pcap_syn_only_is_pending_not_high_confidence() -> None:
    """★ P0-1：仅 SYN、无 SYN-ACK、无载荷的连接尝试 → state=syn_only、advice=待核、非 HIGH——
    不能把 ClientCore 轮询/容灾池的 SYN-only 节点写成"实测接入节点/建议调证"。"""
    syn = _eth(_ipv4(_tcp_flags(b"", 55555, 9466, 0x02), 6, "10.0.0.2", "45.202.1.235"), 0x0800)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([syn]))
    node = next(r for r in pcap_ingest.remote_endpoints(summary) if r.ip == "45.202.1.235")
    assert node.state == "syn_only"
    assert node.out_bytes == 0 and node.in_bytes == 0
    lead = next(
        l for l in pcap_ingest.to_report_leads(summary)
        if l.category == LeadCategory.IP and "45.202.1.235" in l.value
    )
    assert lead.advice == "待核"
    assert lead.confidence != Confidence.HIGH


def test_pcap_aggregates_remote_endpoint_across_five_tuples() -> None:
    """★ P0-1：同一远端的 本机→远端(出载荷) + 远端→本机(SYN-ACK+入载荷) 两条 5 元组聚成一个远端，
    双向载荷 → established；out/in 字节与 connection_count 正确累计。"""
    out1 = _eth(_ipv4(_tcp_flags(b"A" * 100, 50000, 7689, 0x18), 6, "10.0.0.2", "47.98.207.14"), 0x0800)
    synack = _eth(_ipv4(_tcp_flags(b"", 7689, 50000, 0x12), 6, "47.98.207.14", "10.0.0.2"), 0x0800)
    in1 = _eth(_ipv4(_tcp_flags(b"B" * 70, 7689, 50000, 0x18), 6, "47.98.207.14", "10.0.0.2"), 0x0800)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([out1, synack, in1]))
    node = next(
        r for r in pcap_ingest.remote_endpoints(summary) if r.ip == "47.98.207.14" and r.port == 7689
    )
    assert node.state == "established"
    assert node.out_bytes == 100
    assert node.in_bytes == 70
    assert node.connection_count == 1
    lead = next(
        l for l in pcap_ingest.to_report_leads(summary)
        if l.category == LeadCategory.IP and "47.98.207.14" in l.value
    )
    assert lead.advice == "建议调证" and lead.confidence == Confidence.HIGH


def test_pcap_dns_txt_answer_is_preserved() -> None:
    """★ P0-2：DNS TXT 应答（ClientCore 配置下发通道）须结构化保留 qtype=16/rcode/answer value，
    不能只留 qname——徐康案 TXT 内容要能直接进报告。"""
    resp = _eth(
        _ipv4(_udp(_dns_response_txt("7nf15vxk.yqdgtbq2xm.uk", "Io59QrTjne3mq19Yoc"), 53, 40000),
              17, "10.0.0.1", "10.0.0.2"),
        0x0800,
    )
    summary = pcap_ingest.parse_pcap_bytes(_pcap([resp]))
    rec = next(r for r in summary.dns_records if r.qname == "7nf15vxk.yqdgtbq2xm.uk")
    assert rec.qtype == 16 and rec.rcode == 0
    assert any(a["type"] == 16 and "Io59QrTjne3mq19Yoc" in a["value"] for a in rec.answers)
    led = pcap_ingest.to_ledger_dict(summary)
    assert any(r["qtype"] == 16 for r in led["dns_records"])
    assert "7nf15vxk.yqdgtbq2xm.uk" in summary.dns_queries  # 向后兼容仍保留 qname


def test_runtime_endpoints_filters_syn_only_no_payload() -> None:
    """★ 复审#1：to_runtime_endpoints（自动并入主报告）过滤无载荷 SYN-only 节点——不让它绕过
    态分级、走下游默认公网 IP"建议调证"；有载荷节点保留；SYN-only 仍在 pcap 台账作待核。"""
    syn = _eth(_ipv4(_tcp_flags(b"", 55555, 9466, 0x02), 6, "10.0.0.2", "45.202.1.235"), 0x0800)
    data = _eth(_ipv4(_tcp_flags(b"X" * 50, 50001, 30113, 0x18), 6, "10.0.0.2", "106.53.21.146"), 0x0800)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([syn, data]))
    ip_vals = {e.value for e in pcap_ingest.to_runtime_endpoints(summary) if e.kind == "ip"}
    assert "45.202.1.235" not in ip_vals  # SYN-only 无载荷 → 自动并入过滤
    assert "106.53.21.146" in ip_vals  # 有载荷 → 保留
    syn_lead = next(
        l for l in pcap_ingest.to_report_leads(summary)
        if l.category == LeadCategory.IP and "45.202.1.235" in l.value
    )
    assert syn_lead.advice == "待核"  # pcap 台账仍留作待核（不静默丢弃）


def test_fanzha_interception_node_excluded() -> None:
    """★ Codex fengzhixin 案抓包交接 §6：反诈拦截节点（183.192.65.101）即便有双向载荷（拦截页
    返回），也标『无需调证·反诈拦截』、不升入 runtime 端点（会污染归因）；业务接入节点正常保留。"""
    fanzha, biz = "183.192.65.101", "43.230.113.177"
    # fanzha：双向载荷（拦截页会回数据）——本应被"反诈拦截"排除，而非因"有载荷"被当业务后端保留。
    out1 = _eth(_ipv4(_tcp_flags(b"GET /", 50001, 443, 0x18), 6, "10.0.0.2", fanzha), 0x0800)
    in1 = _eth(_ipv4(_tcp_flags(b"HTTP 302", 443, 50001, 0x18), 6, fanzha, "10.0.0.2"), 0x0800)
    biz = _eth(_ipv4(_tcp_flags(b"X" * 40, 50002, 443, 0x18), 6, "10.0.0.2", biz), 0x0800)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([out1, in1, biz]))

    ip_vals = {e.value for e in pcap_ingest.to_runtime_endpoints(summary) if e.kind == "ip"}
    assert "183.192.65.101" not in ip_vals  # 反诈拦截节点排除，绝不升 runtime 端点污染归因
    assert "43.230.113.177" in ip_vals  # 业务接入节点正常保留

    fz_lead = next(
        l for l in pcap_ingest.to_report_leads(summary)
        if l.category == LeadCategory.IP and "183.192.65.101" in l.value
    )
    assert fz_lead.advice == "无需调证"  # 台账仍留（作拦截证据），但标『无需调证·反诈拦截』
    assert "反诈拦截" in (fz_lead.notes or "")


def test_udp_payload_counts_as_evidence() -> None:
    """★ 复审#2：UDP 载荷计入 payload_bytes——UDP C2/QUIC/HTTP3 真载荷不被误降为待核。"""
    udp = _eth(_ipv4(_udp(b"\x00" * 40, 50000, 8443), 17, "10.0.0.2", "8.8.8.8"), 0x0800)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([udp]))
    node = next(r for r in pcap_ingest.remote_endpoints(summary) if r.ip == "8.8.8.8")
    assert node.out_bytes == 40 and node.has_payload
    lead = next(
        l for l in pcap_ingest.to_report_leads(summary)
        if l.category == LeadCategory.IP and "8.8.8.8" in l.value
    )
    assert lead.advice == "建议调证"


def test_public_to_public_ipv6_not_dropped() -> None:
    """★ 复审#3：两端都公网（移动网 IPv6 GUA 直连）不丢弃——SYN 方向判远端。"""
    syn = _eth(_ipv6(_tcp_flags(b"", 40000, 443, 0x02), 6, "2409:8a00::1", "2606:4700::1111"), 0x86DD)
    dat = _eth(_ipv6(_tcp_flags(b"Z" * 30, 40000, 443, 0x18), 6, "2409:8a00::1", "2606:4700::1111"), 0x86DD)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([syn, dat]))
    ips = {r.ip for r in pcap_ingest.remote_endpoints(summary)}
    assert "2606:4700::1111" in ips  # 远端保留（未丢连接）
    assert "2409:8a00::1" not in ips  # 本机端不作远端


def test_to_runtime_endpoints_from_pcap() -> None:
    """★ floor 自动并入的基础：pcap summary → runtime Endpoint（公网 IP + SNI/DNS 域名，
    source=runtime-pcap），供 capture 并进 runtime_report.endpoints 走下游 asn/infra 分级。"""
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    eps = pcap_ingest.to_runtime_endpoints(summary)
    assert eps  # 非空
    assert all(e.evidences and e.evidences[0].source == "runtime-pcap" for e in eps)
    ip_vals = {e.value for e in eps if e.kind == "ip"}
    assert "106.53.21.146" in ip_vals  # 公网接入节点作 IP 端点
    # 私网/回环不作接入节点。
    assert not any(
        e.value.startswith(("192.168.", "127.", "10.")) for e in eps if e.kind == "ip"
    )
