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


def _big_client_hello(sni: str, pad: int = 2000) -> bytes:
    """跨段用大 ClientHello：SNI 之外塞一个 padding 扩展(0x0015)使 record 超 MSS、必然跨 TCP 段。"""
    sni_b = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(sni_b)) + sni_b
    snl = struct.pack("!H", len(server_name)) + server_name
    sni_ext = struct.pack("!HH", 0x0000, len(snl)) + snl
    pad_ext = struct.pack("!HH", 0x0015, pad) + b"\x00" * pad  # TLS padding 扩展
    exts = sni_ext + pad_ext
    body = (
        b"\x03\x03" + b"\x00" * 32 + b"\x00"
        + struct.pack("!H", 2) + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(exts)) + exts
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _tcp_seq(payload: bytes, sport: int, dport: int, seq: int, flags: int = 0x18) -> bytes:
    """带真实 seq 的 TCP 段（现有 _tcp/_tcp_flags 硬编码 seq=0，跨段重组用例必须带序列号）。"""
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, (5 << 4), flags, 65535, 0, 0)
    return hdr + payload


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


# --- ClientHello 跨段重组（P0 PCAP-first）------------------------------------


def _split_ch_pcap(segments: list[tuple[int, bytes]], src="10.0.0.2", dst="203.0.113.9",
                   sport=50000, dport=443) -> bytes:
    """把 (seq, payload) 段列表按同一五元组封成 pcap（跨段 ClientHello 重组用）。"""
    frames = [
        _eth(_ipv4(_tcp_seq(payload, sport, dport, seq), 6, src, dst), 0x0800)
        for seq, payload in segments
    ]
    return _pcap(frames)


def _flow_sni_ja3(summary, ip="203.0.113.9"):  # type: ignore[no-untyped-def]
    f = next(fl for fl in summary.flows if fl.dst_ip == ip)
    return f.sni, f.ja3


def test_client_hello_split_two_segments() -> None:
    """核心：现代大 ClientHello 跨 2 个 TCP 段（Chrome/Cronet PQ key_share 超 MSS）→ 重组后 SNI/JA3 不丢，
    且 JA3 与对完整 record 直接解析所得**一致**（正确性，而非仅存在）。"""
    rec = _big_client_hello("split.evil-c2.com")
    seg1, seg2 = rec[:1400], rec[1400:]
    summary = pcap_ingest.parse_pcap_bytes(_split_ch_pcap([(1000, seg1), (1000 + len(seg1), seg2)]))
    sni, ja3 = _flow_sni_ja3(summary)
    exp_sni, exp_ja3 = pcap_ingest._parse_client_hello(rec)
    assert "split.evil-c2.com" in sni and exp_sni in sni
    assert ja3 == {exp_ja3}  # 重组后 JA3 == 完整 record 的 JA3


def test_split_hello_retransmission_and_overlap() -> None:
    """锚段重传（幂等）+ 尾段 100B 重叠（first-writer-wins）→ 仍正确解出。"""
    rec = _big_client_hello("retx.evil-c2.com")
    seg1, seg2 = rec[:1400], rec[1300:]  # seg2 与 seg1 重叠 100B
    summary = pcap_ingest.parse_pcap_bytes(
        _split_ch_pcap([(1000, seg1), (1000, seg1), (1000 + 1300, seg2)])  # seg1 重传一次
    )
    sni, _ja3 = _flow_sni_ja3(summary)
    assert "retx.evil-c2.com" in sni


def test_split_hello_gap_salvages_sni_but_no_wrong_ja3() -> None:
    """★关键回归：缺中段（gap 永不闭合）→ SNI 靠 salvage 从锚段 best-effort 捞回（与旧 best-effort
    一致，SNI 在靠前的锚段内），但 **JA3 弃掉**——绝不产出截断算错的 JA3。parse_pcap_bytes 不崩。"""
    rec = _big_client_hello("gap.evil-c2.com")
    seg1, seg3 = rec[:1000], rec[2000:]  # 缺 [1000:2000]
    summary = pcap_ingest.parse_pcap_bytes(
        _split_ch_pcap([(1000, seg1), (1000 + 2000, seg3)])
    )
    sni, ja3 = _flow_sni_ja3(summary)
    assert "gap.evil-c2.com" in sni  # SNI 捞回（高价值、与旧行为一致）
    assert not ja3  # 但 JA3 弃：绝不产出截断算错的 JA3（关键回归保护）


def test_four_tuple_reuse_syn_resets_stitch() -> None:
    """★复审 #1/#5：四元组复用——连接 A 留下不完整 stitch，连接 B（纯 SYN 后）完整单段 CH 仍解出，
    不被旧 stitch 引流丢弃（守住"不破坏现有单段行为"）。"""
    incomplete = _big_client_hello("stale-A.com")[:1200]  # 连接 A：锚段但永不闭合
    fresh = _big_client_hello("reused-B.com")             # 连接 B：完整单段 CH
    seg_a = _eth(_ipv4(_tcp_seq(incomplete, 50000, 443, 1000), 6, "10.0.0.2", "203.0.113.9"), 0x0800)
    syn_b = _eth(_ipv4(_tcp_seq(b"", 50000, 443, 900000000, flags=0x02), 6, "10.0.0.2", "203.0.113.9"), 0x0800)
    ch_b = _eth(_ipv4(_tcp_seq(fresh, 50000, 443, 900000001), 6, "10.0.0.2", "203.0.113.9"), 0x0800)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([seg_a, syn_b, ch_b]))
    sni, _ = _flow_sni_ja3(summary)
    assert "reused-B.com" in sni  # 复用元组上新连接的完整单段 CH 未被旧 stitch 吞掉


def test_snaplen_truncation_salvages_sni() -> None:
    """★复审 #2：snaplen 截断（record 头声明的长度 > 实捕字节，永不凑齐）→ 仍从缓冲 best-effort 捞回
    SNI（旧代码本能捞出，是本模块目标场景），JA3 弃。"""
    rec = _big_client_hello("snaplen.evil-c2.com")
    # 只喂一个"看似跨段"的锚段（rec_len 声明大、实捕仅 600B、无续段）——模拟 tcpdump -s 截断
    truncated = rec[:600]
    summary = pcap_ingest.parse_pcap_bytes(_split_ch_pcap([(1000, truncated)]))
    sni, ja3 = _flow_sni_ja3(summary)
    assert "snaplen.evil-c2.com" in sni and not ja3


def test_empty_segment_does_not_block_ooo() -> None:
    """★复审 #6：空载荷段（纯 ACK）不得以 first-writer-wins 占住未来偏移、挡掉随后到达的真数据。"""
    asm = pcap_ingest._HelloReassembler()
    key = ("10.0.0.2", 50000, "1.2.3.4", 443)
    rec = _big_client_hello("empty-seg.com")
    seg1, seg2 = rec[:1400], rec[1400:]
    asm.feed(key, 1000, seg1, len(seg1))               # 锚段
    asm.feed(key, 1000 + 1400, b"", 100)               # 空段落在续段偏移 → 不得占坑
    r = asm.feed(key, 1000 + 1400, seg2, len(seg1) + len(seg2))  # 真续段补上 → 应完成
    assert r is not None and r[0] == "empty-seg.com"


def test_single_packet_big_hello_fast_path_identical() -> None:
    """完整大 CH 落单段 → 走快路径，SNI/JA3 与直接解析完整 record 一致（现有行为不变）。"""
    rec = _big_client_hello("single.evil-c2.com")
    summary = pcap_ingest.parse_pcap_bytes(_split_ch_pcap([(1000, rec)]))
    sni, ja3 = _flow_sni_ja3(summary)
    exp_sni, exp_ja3 = pcap_ingest._parse_client_hello(rec)
    assert exp_sni in sni and ja3 == {exp_ja3}


def test_ipv6_split_hello() -> None:
    """IPv6 链路上跨段 ClientHello 同样重组（方向键含 IPv6 文本地址）。"""
    rec = _big_client_hello("v6.evil-c2.com")
    seg1, seg2 = rec[:1400], rec[1400:]
    frames = [
        _eth(_ipv6(_tcp_seq(seg1, 40000, 443, 5000), 6, "2409:8a00::1", "2606:4700::1111"), 0x86DD),
        _eth(_ipv6(_tcp_seq(seg2, 40000, 443, 5000 + len(seg1)), 6, "2409:8a00::1", "2606:4700::1111"), 0x86DD),
    ]
    summary = pcap_ingest.parse_pcap_bytes(_pcap(frames))
    f = next(fl for fl in summary.flows if fl.dst_ip == "2606:4700::1111")
    assert "v6.evil-c2.com" in f.sni


def test_seq_wraparound_split() -> None:
    """seq 32 位回绕处劈段 → 相对偏移 mod 2^32 仍正确，SNI 解出。"""
    rec = _big_client_hello("wrap.evil-c2.com")
    seg1, seg2 = rec[:1400], rec[1400:]
    base = (0xFFFFFFFF - 200) & 0xFFFFFFFF  # 锚段后即回绕
    summary = pcap_ingest.parse_pcap_bytes(
        _split_ch_pcap([(base, seg1), ((base + len(seg1)) & 0xFFFFFFFF, seg2)])
    )
    sni, _ = _flow_sni_ja3(summary)
    assert "wrap.evil-c2.com" in sni


def _incomplete_anchor(rec_len: int = 2000) -> bytes:
    """声称 rec_len 但只给约 16 字节的 client_hello 锚段（跨段、永不闭合）。"""
    return b"\x16\x03\x01" + struct.pack("!H", rec_len) + b"\x01" + b"\x00" * 12


def test_reassembler_conn_flood_bounded() -> None:
    """白盒：10000 个不同方向键的不完整锚段 → pending≤512、done≤4096，不崩不 OOM。"""
    asm = pcap_ingest._HelloReassembler()
    anchor = _incomplete_anchor()
    for i in range(10000):
        key = (f"10.0.{i // 256}.{i % 256}", 50000, "1.2.3.4", 443)
        asm.feed(key, 1000, anchor, len(anchor))
    assert len(asm.pending) <= pcap_ingest._MAX_PENDING
    assert len(asm.done) <= pcap_ingest._MAX_DONE


def test_huge_rec_len_rejected() -> None:
    """白盒：锚段声称 rec_len=0xFFFF(>16384) → 拒锚、不建 pending。"""
    asm = pcap_ingest._HelloReassembler()
    key = ("10.0.0.2", 50000, "1.2.3.4", 443)
    assert asm.feed(key, 1000, _incomplete_anchor(0xFFFF), 100) is None
    assert key not in asm.pending


def test_chunk_flood_bounded_and_killed() -> None:
    """白盒：单连接喂大量乱序小碎段 → 上限触发判死记 done，不崩不 OOM。"""
    asm = pcap_ingest._HelloReassembler()
    key = ("10.0.0.2", 50000, "1.2.3.4", 443)
    asm.feed(key, 1000, _incomplete_anchor(), len(_incomplete_anchor()))  # 先锚
    for i in range(500):  # 大量喂段 → pkts 上限判死
        asm.feed(key, 1000 + 5000 + i * 7, b"\x00" * 3, 100)
    assert key in asm.done and key not in asm.pending


def test_server_flight_not_buffered() -> None:
    """白盒：0x16 但 handshake type=0x02(ServerHello) 跨段 → 锚门拒，pending 不建（大证书链不占内存）。"""
    asm = pcap_ingest._HelloReassembler()
    key = ("1.2.3.4", 443, "10.0.0.2", 50000)
    server = b"\x16\x03\x03" + struct.pack("!H", 3000) + b"\x02" + b"\x00" * 12  # type=2
    assert asm.feed(key, 1000, server, len(server)) is None
    assert key not in asm.pending


def test_midstream_ciphertext_not_anchored() -> None:
    """白盒：某方向累计载荷已 >64KiB 后才现 0x16 段 → 锚窗判定为长流密文伪锚，不建 stitch。"""
    asm = pcap_ingest._HelloReassembler()
    key = ("10.0.0.2", 50000, "1.2.3.4", 443)
    fake = _incomplete_anchor()
    assert asm.feed(key, 1000, fake, 70 * 1024) is None  # flow_payload_bytes 远超 64KiB 锚窗
    assert key not in asm.pending


# --- QUIC（HTTP/3）长包头元数据（P0，纯 stdlib、零解密）----------------------


def _quic_long_header(version: int = 0x00000001, dcid: bytes = bytes(range(8)),
                      scid: bytes = b"\xaa\xbb\xcc", ptype: int = 0) -> bytes:
    """构造 QUIC v1 长包头（RFC 9000 §17.2）：首字节 11|type|.. + version + CID 长度/CID + 占位尾。"""
    b0 = 0xC0 | ((ptype & 0x03) << 4)
    return (bytes([b0]) + struct.pack("!I", version) + bytes([len(dcid)]) + dcid
            + bytes([len(scid)]) + scid + b"\x00" * 24)  # token/length/pn/payload 占位（PR1 不解析）


def _quic_pcap(payload: bytes, dst: str = "45.202.1.235", dport: int = 443) -> bytes:
    return _pcap([_eth(_ipv4(_udp(payload, 51000, dport), 17, "10.0.0.2", dst), 0x0800)])


def test_quic_long_header_metadata_extracted() -> None:
    """QUIC Initial 长包头 → version/DCID/SCID 明文抽取，落 Flow + 远端聚合 + lead snippet（h3 归因）。"""
    summary = pcap_ingest.parse_pcap_bytes(_quic_pcap(_quic_long_header()))
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")
    assert "00000001" in f.quic_versions
    assert bytes(range(8)).hex() in f.quic_dcids and "aabbcc" in f.quic_scids
    lead = next(l for l in pcap_ingest.to_report_leads(summary)
                if l.category == LeadCategory.IP and "45.202.1.235" in l.value)
    assert "QUIC=00000001" in lead.source_refs[0].snippet
    led = pcap_ingest.to_ledger_dict(summary)
    assert any("00000001" in e["quic_versions"] for e in led["remote_endpoints"])


def test_quic_dcid_survives_ip_migration_correlation() -> None:
    """同一 QUIC 连接 ID 出现在不同五元组（IP 迁移/NAT 重绑）→ 各 Flow 都记录该 DCID（供跨流关联，
    五元组聚合做不到的能力）。"""
    dcid = b"\xde\xad\xbe\xef\x11\x22"
    s1 = pcap_ingest.parse_pcap_bytes(_quic_pcap(_quic_long_header(dcid=dcid), dst="45.202.1.235"))
    s2 = pcap_ingest.parse_pcap_bytes(_quic_pcap(_quic_long_header(dcid=dcid), dst="106.53.21.146"))
    assert dcid.hex() in s1.flows[0].quic_dcids
    assert dcid.hex() in s2.flows[0].quic_dcids


def test_non_quic_udp_not_tagged() -> None:
    """随机 UDP / 非 QUIC 版本 → 不误标 QUIC（挡假阳）。"""
    s1 = pcap_ingest.parse_pcap_bytes(_quic_pcap(b"\x00 random udp payload not quic"))
    assert all(not fl.quic_versions for fl in s1.flows)
    s2 = pcap_ingest.parse_pcap_bytes(_quic_pcap(_quic_long_header(version=0x12345678)))
    assert all(not fl.quic_versions for fl in s2.flows)  # 长包头位对但 version 不像 QUIC → 不认


def test_quic_malformed_header_no_crash() -> None:
    """畸形 QUIC 头（超长 CID len / 截断 / 空）→ 不崩、不误标。"""
    assert pcap_ingest._parse_quic_long_header(b"\xc0\x00\x00\x00\x01\xff") is None  # dcid_len=255>20
    assert pcap_ingest._parse_quic_long_header(b"\xc0\x00\x00\x00\x01") is None       # 截断（无 CID）
    assert pcap_ingest._parse_quic_long_header(b"") is None
    pcap_ingest.parse_pcap_bytes(_quic_pcap(b"\xc0\x00\x00\x00\x01\x14" + b"\x00" * 2))  # 端到端不崩


def test_quic_probe_does_not_break_dns() -> None:
    """QUIC 探测挂在 UDP 分支，真 DNS（53）仍走原路径解出（内容优先派发：非 QUIC 才当 DNS）。"""
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    assert "tracker.example.org" in summary.dns_queries


def test_quic_over_udp53_still_detected() -> None:
    """★复审 #2：QUIC 伪装到 UDP/53（防火墙常放行）仍被抽 QUIC 元数据，不因端口=53 被当 DNS 漏掉。"""
    summary = pcap_ingest.parse_pcap_bytes(_quic_pcap(_quic_long_header(), dport=53))
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")
    assert "00000001" in f.quic_versions
    # 且不把 QUIC 字节误当 DNS 查询污染 dns_queries
    assert summary.dns_queries == set()


def test_ntp_style_zerofill_not_quic() -> None:
    """★复审 #1/#3：NTP/SNTP 风格全零填充包（首字节 0xE3/0xDB + 全零）不因 vneg(0) 被误标 QUIC。"""
    assert pcap_ingest._parse_quic_long_header(bytes([0xE3]) + bytes(47)) is None
    assert pcap_ingest._parse_quic_long_header(bytes([0xDB]) + bytes(47)) is None
    # version=0 的 vneg 也不再收（无 h3 增量）
    assert pcap_ingest._parse_quic_long_header(
        b"\xc0\x00\x00\x00\x00\x08" + bytes(range(8)) + b"\x03\xaa\xbb\xcc"
    ) is None


# --- QUIC Initial 解密 → ClientHello SNI/ALPN（P0/②b，RFC 9001）---------------


def _enc_varint(v: int) -> bytes:
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack("!H", v | 0x4000)
    if v < 2**30:
        return struct.pack("!I", v | 0x80000000)
    return struct.pack("!Q", v | 0xC000000000000000)


def _tls_ch_alpn(sni: str, alpn: bytes = b"h3") -> bytes:
    """裸 handshake ClientHello（含 SNI + ALPN 扩展）——供 QUIC CRYPTO 承载。"""
    sni_b = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(sni_b)) + sni_b
    snl = struct.pack("!H", len(server_name)) + server_name
    sni_ext = struct.pack("!HH", 0x0000, len(snl)) + snl
    alpn_list = struct.pack("!H", len(alpn) + 1) + bytes([len(alpn)]) + alpn
    alpn_ext = struct.pack("!HH", 0x0010, len(alpn_list)) + alpn_list
    exts = sni_ext + alpn_ext
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01"
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


def _build_quic_initial(dcid: bytes, crypto_frames: bytes, scid: bytes = b"\xaa\xbb", pn: int = 0,
                        key_dcid: bytes | None = None) -> bytes:
    """独立实现 RFC 9001 加密造一个合法 client Initial（作 round-trip 的独立对照，不调生产解密码）。

    key_dcid 给定时用它派生密钥、而包头 DCID 仍是 dcid——模拟 RFC 9001 §5.2/9000 §7.2：客户端收到
    服务端首包后把 DCID 切成服务端 SCID，但 Initial 密钥仍由**原始** DCID 派生。
    """
    import struct as _s

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, iv, hp = pcap_ingest._quic_client_initial_keys(key_dcid or dcid, {})  # 生产密钥派生（已对 RFC 向量验证）
    plaintext = crypto_frames
    pnl = 4
    length = pnl + len(plaintext) + 16
    hdr = (bytes([0xC0 | (pnl - 1)]) + _s.pack("!I", 1) + bytes([len(dcid)]) + dcid
           + bytes([len(scid)]) + scid + _enc_varint(0) + _enc_varint(length))
    pn_bytes = _s.pack("!I", pn)[-pnl:]
    header_with_pn = hdr + pn_bytes
    nonce = bytes(x ^ y for x, y in zip(iv, b"\x00" * (12 - pnl) + pn_bytes))
    ct = AESGCM(key).encrypt(nonce, plaintext, header_with_pn)
    packet = bytearray(header_with_pn + ct)
    pn_off = len(hdr)
    sample = bytes(packet[pn_off + 4 : pn_off + 4 + 16])
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)[:5]
    packet[0] ^= mask[0] & 0x0F
    for i in range(pnl):
        packet[pn_off + i] ^= mask[1 + i]
    return bytes(packet)


def test_quic_key_derivation_matches_rfc9001_a1() -> None:
    """★外部正确性锚：RFC 9001 §A.1 官方向量——DCID 0x8394c8f03e515708 派生的 iv/hp 逐字节吻合。"""
    pytest.importorskip("cryptography")
    keys = pcap_ingest._quic_client_initial_keys(bytes.fromhex("8394c8f03e515708"), {})
    assert keys is not None
    _key, iv, hp = keys
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


def test_quic_initial_decrypt_yields_sni_and_alpn() -> None:
    """QUIC v1 Initial 解密 → CRYPTO 重组 → ClientHello 的 SNI/ALPN 落 Flow（QUIC 全密文时唯一线索）。"""
    pytest.importorskip("cryptography")
    dcid = bytes.fromhex("8394c8f03e515708")
    ch = _tls_ch_alpn("quic-c2.evil.com", b"h3")
    frame = b"\x06" + _enc_varint(0) + _enc_varint(len(ch)) + ch  # CRYPTO frame at offset 0
    pkt = _build_quic_initial(dcid, frame)
    summary = pcap_ingest.parse_pcap_bytes(_quic_pcap(pkt))
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")
    assert "quic-c2.evil.com" in f.sni  # QUIC SNI 解出，与 TCP「SNI 不丢」对等
    assert "h3" in f.alpn
    lead = next(l for l in pcap_ingest.to_report_leads(summary)
                if l.category == LeadCategory.IP and "45.202.1.235" in l.value)
    assert "quic-c2.evil.com" in lead.source_refs[0].snippet and "ALPN=h3" in lead.source_refs[0].snippet


def test_quic_initial_multi_packet_crypto_reassembly() -> None:
    """ClientHello 跨 2 个 Initial 包（CRYPTO 分 offset 0 / N）→ 按 DCID 重组后 SNI 解出。"""
    pytest.importorskip("cryptography")
    dcid = bytes.fromhex("0102030405060708")
    ch = _tls_ch_alpn("split-quic.evil.com")
    cut = len(ch) // 2
    f1 = b"\x06" + _enc_varint(0) + _enc_varint(cut) + ch[:cut]
    f2 = b"\x06" + _enc_varint(cut) + _enc_varint(len(ch) - cut) + ch[cut:]
    p1 = _build_quic_initial(dcid, f1, pn=0)
    p2 = _build_quic_initial(dcid, f2, pn=1)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([
        _eth(_ipv4(_udp(p1, 51000, 443), 17, "10.0.0.2", "45.202.1.235"), 0x0800),
        _eth(_ipv4(_udp(p2, 51000, 443), 17, "10.0.0.2", "45.202.1.235"), 0x0800),
    ]))
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")
    assert "split-quic.evil.com" in f.sni


def test_quic_initial_aead_failure_no_sni_no_crash() -> None:
    """AEAD tag 被破坏（服务端包/坏包）→ 解密失败静默降级：无 SNI、仍落 QUIC 元数据、不崩。"""
    pytest.importorskip("cryptography")
    dcid = bytes.fromhex("8394c8f03e515708")
    ch = _tls_ch_alpn("nope.evil.com")
    frame = b"\x06" + _enc_varint(0) + _enc_varint(len(ch)) + ch
    pkt = bytearray(_build_quic_initial(dcid, frame))
    pkt[-1] ^= 0xFF  # 破坏 AEAD tag
    summary = pcap_ingest.parse_pcap_bytes(_quic_pcap(bytes(pkt)))
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")
    assert not f.sni  # 解密失败 → 无 SNI
    assert "00000001" in f.quic_versions  # 但元数据仍落（QUIC 存在性不丢）


def test_quic_malformed_initial_no_crash() -> None:
    """畸形 Initial（截断/坏 varint）→ 解密路径绝不抛。"""
    qdec = pcap_ingest._QuicDecryptor()
    fk = ("10.0.0.2", 51000, "1.2.3.4", 443)
    assert pcap_ingest._decrypt_quic_initial(b"\xc0\x00\x00\x00\x01\x08" + bytes(4), qdec, fk) is None
    assert pcap_ingest._decrypt_quic_initial(b"", qdec, fk) is None
    pcap_ingest.parse_pcap_bytes(_quic_pcap(b"\xc0\x00\x00\x00\x01\x14" + b"\xff" * 60))  # 不崩


def test_quic_dcid_switch_keeps_original_keys() -> None:
    """★复审 #A（RFC 9001 §5.2 / 9000 §7.2）：服务端回包后客户端把 DCID 切成服务端 SCID 重传尾段 CRYPTO，
    但密钥仍由**原始** DCID 派生 → 候选序 + 按流分桶后仍解出 SNI（旧 per-packet DCID 会必然失败）。"""
    pytest.importorskip("cryptography")
    d0 = bytes.fromhex("8394c8f03e515708")  # 客户端原始 DCID
    ssid = bytes.fromhex("cafebabe")          # 服务端 SCID（切换后包头 DCID）
    ch = _tls_ch_alpn("dcid-switch.evil.com")
    cut = len(ch) // 2
    f1 = b"\x06" + _enc_varint(0) + _enc_varint(cut) + ch[:cut]
    f2 = b"\x06" + _enc_varint(cut) + _enc_varint(len(ch) - cut) + ch[cut:]
    p1 = _build_quic_initial(d0, f1, pn=0)                      # 首包：头 DCID=D0、密钥 D0
    p2 = _build_quic_initial(ssid, f2, pn=1, key_dcid=d0)       # 切换后重传：头 DCID=S、密钥仍 D0
    summary = pcap_ingest.parse_pcap_bytes(_pcap([
        _eth(_ipv4(_udp(p1, 51000, 443), 17, "10.0.0.2", "45.202.1.235"), 0x0800),
        _eth(_ipv4(_udp(p2, 51000, 443), 17, "10.0.0.2", "45.202.1.235"), 0x0800),
    ]))
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")
    assert "dcid-switch.evil.com" in f.sni


def test_quic_key_cache_bounded() -> None:
    """★复审 #B：唯一 DCID 洪水 → 密钥缓存 FIFO 有界（≤ _MAX_QUIC_KEYS），绝不无界 OOM。"""
    pytest.importorskip("cryptography")
    cache: dict = {}
    for i in range(pcap_ingest._MAX_QUIC_KEYS + 200):
        pcap_ingest._quic_client_initial_keys(struct.pack("!Q", i), cache)
    assert len(cache) <= pcap_ingest._MAX_QUIC_KEYS
