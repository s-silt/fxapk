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
    p_native = _eth(_ipv4(_tcp(b"\x00\x01\x02", 50001, 30113), 6, "10.0.0.2", "106.53.21.146"), 0x0800)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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
    assert ("106.53.21.146", 30113) in peers  # native 接入节点(无 TLS 也抓到)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert ("203.0.113.9", 443) in peers


def test_parse_extracts_dns_query() -> None:
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    assert "tracker.example.org" in summary.dns_queries


def test_parse_bad_bytes_returns_empty_not_crash() -> None:
    assert pcap_ingest.parse_pcap_bytes(b"not a pcap").flows == []


# --- IP 层长度裁剪：抓包工具的帧尾元数据不得被读成应用载荷 ------------------


def test_ipv4_payload_truncated_at_total_length() -> None:
    """★真样本回归：PCAPdroid 的 dump_extensions 在 IP 数据之后追加 UID/包名元数据。

    帧尾那段字节若继续喂给 TCP/TLS 解析，碰上 0x16 开头就被读成 ClientHello，
    解出的 SNI 会被绑到真实的业务连接上——实测样本的目标后端 30124/30139
    因此挂上了 zhihu.com / bilibili.com。
    """
    # 真实业务连接：一个**无应用载荷**的 ACK 包（PCAPdroid 对每个包都追加元数据，
    # 包括纯 ACK——此时追加区就成了 TCP 头之后的第一段字节，正对上 TLS 解析的入口）。
    real = _tcp(b"", 50001, 30124)
    ip_packet = _ipv4(real, 6, "10.0.0.2", "198.51.100.53")
    trailer = _tls_client_hello("static.zhihu.com") + b"\x00com.example.app\x00"
    frame = _eth(ip_packet + trailer, 0x0800)

    summary = pcap_ingest.parse_pcap_bytes(_pcap([frame]))
    peers = {(f.dst_ip, f.dst_port) for f in summary.flows}
    assert ("198.51.100.53", 30124) in peers, "真实连接必须保留"
    snis = {s for f in summary.flows for s in f.sni}
    assert "static.zhihu.com" not in snis, "帧尾元数据不得被读成 SNI"
    assert not snis, f"该连接不该有任何 SNI，实得 {snis}"


def test_ipv4_payload_byte_count_excludes_trailer() -> None:
    """字节计数也不能把帧尾元数据算进去——它会虚高业务流量、误导闭环判定。"""
    real = _tcp(b"\xaa" * 16, 50001, 30124)
    frame = _eth(
        _ipv4(real, 6, "10.0.0.2", "198.51.100.53") + b"\xff" * 512, 0x0800
    )
    summary = pcap_ingest.parse_pcap_bytes(_pcap([frame]))
    flow = next(f for f in summary.flows if f.dst_port == 30124)
    assert flow.payload_bytes == 16, f"应只算 IP total_length 内的 16 字节，实得 {flow.payload_bytes}"


def test_ipv6_payload_truncated_at_payload_length() -> None:
    real = _tcp(b"", 50002, 30139)
    trailer = _tls_client_hello("www.bilibili.com")
    frame = _eth(
        _ipv6(real, 6, "2001:db8::2", "2001:db8::1") + trailer, 0x86DD
    )
    summary = pcap_ingest.parse_pcap_bytes(_pcap([frame]))
    snis = {s for f in summary.flows for s in f.sni}
    assert "www.bilibili.com" not in snis
    assert not snis


def test_ipv4_trailer_does_not_forge_dns_records() -> None:
    """帧尾元数据同样不得被读成 DNS —— 伪域名会直接进线索清单。

    构造成真到 53 端口的空 UDP 包：不裁剪时 trailer 就是 DNS 解析看到的第一段字节。
    """
    real = _udp(b"", 40000, 53)
    trailer = _dns_query("static.zhihu.com")
    frame = _eth(_ipv4(real, 17, "10.0.0.2", "198.51.100.53") + trailer, 0x0800)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([frame]))
    assert "static.zhihu.com" not in summary.dns_queries


def test_normal_tls_sni_still_extracted_after_truncation() -> None:
    """★裁剪不得损召回：没有帧尾元数据的普通 443 TLS，SNI 照常提取。"""
    frame = _eth(
        _ipv4(_tcp(_tls_client_hello("bucket.oss-accelerate.aliyuncs.com"), 50003, 443),
              6, "10.0.0.2", "198.51.100.45"),
        0x0800,
    )
    summary = pcap_ingest.parse_pcap_bytes(_pcap([frame]))
    snis = {s for f in summary.flows for s in f.sni}
    assert "bucket.oss-accelerate.aliyuncs.com" in snis


def test_bogus_total_length_falls_back_to_actual_bytes() -> None:
    """total_length 坏掉（大于实际字节）时退回按实际切——不能因一个坏字段把整包丢了。"""
    real = _tcp(_tls_client_hello("real-c2.example.com"), 50004, 443)
    ip_packet = bytearray(_ipv4(real, 6, "10.0.0.2", "198.51.100.43"))
    struct.pack_into("!H", ip_packet, 2, 65535)  # total_length 谎报 65535
    summary = pcap_ingest.parse_pcap_bytes(_pcap([_eth(bytes(ip_packet), 0x0800)]))
    snis = {s for f in summary.flows for s in f.sni}
    assert "real-c2.example.com" in snis


# ======================================================================
# B. 线索映射
# ======================================================================


def test_to_leads_native_ip_is_穿透_lead() -> None:
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    leads = pcap_ingest.to_report_leads(summary)
    ip_leads = [l for l in leads if l.category == LeadCategory.IP]
    assert any("106.53.21.146" in l.value and "30113" in l.value for l in ip_leads)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    # 公网接入节点默认建议调证、source=runtime-pcap
    node = next(l for l in ip_leads if "106.53.21.146" in l.value)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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
    assert "106.53.21.146" in md  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert "向" in md  # where_to_request


def test_merge_into_report_json_appends(tmp_path) -> None:
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": []}, ensure_ascii=False), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    added = pcap_ingest.merge_into_report_json(str(p), summary)
    assert added > 0
    out = json.loads(p.read_text(encoding="utf-8"))
    assert len(out["leads"]) == added
    assert any("106.53.21.146" in str(l.get("value", "")) for l in out["leads"])  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点


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
    node = next(l for l in leads if l.category == LeadCategory.IP and "106.53.21.146" in l.value)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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
    node = next(l for l in out["leads"] if "106.53.21.146" in str(l.get("value", "")))  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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


def test_parse_status_distinguishes_failure_from_zero_traffic(tmp_path) -> None:
    """★回归（codex 全库审计 P1）：坏 magic / 读失败 与「真实零业务流量」要能区分——空 flows 不都等于零流量，
    否则 pcap-leads/closure 把采集失败误判成"抓到零业务流量"。"""
    bad = pcap_ingest.parse_pcap_bytes(b"not a pcap at all")
    assert bad.parse_status == "unparseable" and bad.flows == [] and bad.error
    empty_ok = pcap_ingest.parse_pcap_bytes(_pcap([]))  # 合法但零包的经典 pcap（仅全局头）
    assert empty_ok.parse_status == "ok" and empty_ok.flows == []
    missing = pcap_ingest.parse_pcap(str(tmp_path / "no-such-file.pcap"))  # 读失败（文件不存在）
    assert missing.parse_status == "read_error" and missing.error
    # 出口透出：JSON 台账带 parse_status（程序化消费者据此判），MD 台账带告警。
    assert pcap_ingest.to_ledger_dict(bad)["parse_status"] == "unparseable"
    assert "解析未成功" in pcap_ingest.build_ledger_md(bad)


def _pcapng_one_epb(endian: str, tsresol: int, ts64: int, frame: bytes = b"\x00" * 14, if_id: int = 0) -> bytes:
    """一个 pcapng section：SHB + IDB(if_tsresol) + 单条 EPB(64bit 时间戳)。endian: '<' 或 '>'。"""
    def block(btype: int, body: bytes) -> bytes:
        body = body + b"\x00" * ((4 - len(body) % 4) % 4)
        blen = 12 + len(body)
        return struct.pack(endian + "II", btype, blen) + body + struct.pack(endian + "I", blen)

    shb = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb_opts = struct.pack(endian + "HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3 + struct.pack(endian + "HH", 0, 0)
    idb = block(0x00000001, struct.pack(endian + "HHI", 1, 0, 0xFFFF) + idb_opts)
    epb_body = struct.pack(endian + "IIIII", if_id, (ts64 >> 32) & 0xFFFFFFFF, ts64 & 0xFFFFFFFF, len(frame), len(frame)) + frame
    epb = block(0x00000006, epb_body)
    return shb + idb + epb


def test_parse_status_flags_truncated_header() -> None:
    """★回归（codex 复核 P1）：有效 magic 但连全局头都放不下 = 截断文件，标 unparseable，不当「零流量」。"""
    trunc = pcap_ingest.parse_pcap_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 10)  # 经典 magic，仅 14B < 24
    assert trunc.parse_status == "unparseable" and trunc.error


def test_parse_status_flags_mid_file_truncation() -> None:
    """★回归（codex 第3轮复核）：有效全局头但某记录声明字节数超出实际（文件中途截断）→ 标 truncated，
    不当 ok 零/完整流量——操作员据此知道要重抓（而非误判抓到零业务流量）。"""
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # 经典 pcap 全局头（24B）
    rec = struct.pack("<IIII", 1_700_000_000, 0, 1000, 1000) + b"\x00" * 4  # 记录头声明 incl=1000，实际只跟 4B
    summ = pcap_ingest.parse_pcap_bytes(header + rec)
    assert summ.parse_status == "truncated" and summ.error


def test_iter_pcapng_rejects_out_of_range_interface_id() -> None:
    """★回归（codex 复核 P1）：非法 EPB interface_id 越界须跳过该块，不借用接口 0 的 linktype/tsresol 误解。"""
    ng = _pcapng_one_epb(">", 6, 1_000_000_000, if_id=5)  # 只声明 1 个接口(0)，if_id=5 越界
    assert list(pcap_ingest._iter_frames(ng)) == []  # 越界 EPB 被跳过、不产帧（修前会借接口0）


def test_build_ledger_md_escapes_error_field() -> None:
    """★回归（codex 复核 P1，修 #2 时自引入的注入面）：失败态 error 可能含路径/异常串，markdown 台账须转义。"""
    summ = pcap_ingest.PcapSummary(parse_status="read_error", error="x` <img src=x onerror=alert(1)> `")
    md = pcap_ingest.build_ledger_md(summ)
    assert "<img" not in md.replace("\\<img", "")  # 无裸 <img
    assert "\\`" in md  # 反引号被转义


def test_iter_pcapng_respects_if_tsresol_nanoseconds() -> None:
    """★回归（codex 全库审计 P1）：pcapng EPB 时间戳须按 IDB 的 if_tsresol 还原，不能一律 /1e6——
    纳秒(if_tsresol=9)会被放大 1000×，与 socket 时间线成假「已知冲突」把五元组归因误降级。"""
    ns = _pcapng_one_epb(">", 9, 1_000_500_000_000)  # 1000.5s in ns，tsresol=9→/1e9
    assert list(pcap_ingest._iter_frames(ns))[0][0] == pytest.approx(1000.5)
    us = _pcapng_one_epb(">", 6, 1_000_500_000)  # 1000.5s in µs，tsresol=6→/1e6（对照，修前也对）
    assert list(pcap_ingest._iter_frames(us))[0][0] == pytest.approx(1000.5)
    le_ns = _pcapng_one_epb("<", 9, 2_000_250_000_000)  # 小端纳秒
    assert list(pcap_ingest._iter_frames(le_ns))[0][0] == pytest.approx(2000.25)


def test_iter_pcapng_multi_section_different_endian() -> None:
    """★回归（codex 全库审计 P1）：pcapng 允许多 section 用不同字节序；须每遇 SHB 重定字节序，
    否则异序的后续 section 被误解或直接停止解析、其流量静默丢失。"""
    be = _pcapng_one_epb(">", 6, 1_000_000_000)  # 大端 section（1000.0s）
    le = _pcapng_one_epb("<", 6, 2_000_000_000)  # 小端 section（2000.0s）
    frames = list(pcap_ingest._iter_frames(be + le))
    assert len(frames) == 2  # 两 section 的帧都要在（修前只出第一段）
    assert frames[0][0] == pytest.approx(1000.0)
    assert frames[1][0] == pytest.approx(2000.0)


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
    syn = _eth(_ipv4(_tcp_flags(b"", 55555, 9466, 0x02), 6, "10.0.0.2", "45.202.1.235"), 0x0800)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    summary = pcap_ingest.parse_pcap_bytes(_pcap([syn]))
    node = next(r for r in pcap_ingest.remote_endpoints(summary) if r.ip == "45.202.1.235")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert node.state == "syn_only"
    assert node.out_bytes == 0 and node.in_bytes == 0
    lead = next(
        l for l in pcap_ingest.to_report_leads(summary)
        if l.category == LeadCategory.IP and "45.202.1.235" in l.value  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    )
    assert lead.advice == "待核"
    assert lead.confidence != Confidence.HIGH


def test_pcap_aggregates_remote_endpoint_across_five_tuples() -> None:
    """★ P0-1：同一远端的 本机→远端(出载荷) + 远端→本机(SYN-ACK+入载荷) 两条 5 元组聚成一个远端，
    双向载荷 → established；out/in 字节与 connection_count 正确累计。"""
    out1 = _eth(_ipv4(_tcp_flags(b"A" * 100, 50000, 7689, 0x18), 6, "10.0.0.2", "100.64.7.14"), 0x0800)
    synack = _eth(_ipv4(_tcp_flags(b"", 7689, 50000, 0x12), 6, "100.64.7.14", "10.0.0.2"), 0x0800)
    in1 = _eth(_ipv4(_tcp_flags(b"B" * 70, 7689, 50000, 0x18), 6, "100.64.7.14", "10.0.0.2"), 0x0800)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([out1, synack, in1]))
    node = next(
        r for r in pcap_ingest.remote_endpoints(summary) if r.ip == "100.64.7.14" and r.port == 7689
    )
    assert node.state == "established"
    assert node.out_bytes == 100
    assert node.in_bytes == 70
    assert node.connection_count == 1
    lead = next(
        l for l in pcap_ingest.to_report_leads(summary)
        if l.category == LeadCategory.IP and "100.64.7.14" in l.value
    )
    assert lead.advice == "建议调证" and lead.confidence == Confidence.HIGH


def test_pcap_dns_txt_answer_is_preserved() -> None:
    """★ P0-2：DNS TXT 应答（ClientCore 配置下发通道）须结构化保留 qtype=16/rcode/answer value，
    不能只留 qname——某案 TXT 内容要能直接进报告。"""
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


def test_dns_over_tcp_reaches_summary_through_parse_pcap() -> None:
    """★ 走 parse_pcap 真入口：TCP/53 上的 DNS 必须进 summary。

    只测 `_iter_tcp_dns_messages` 锁不住接线——TCP 分支里那个 `if` 若从未被写上，
    切分函数的单测照样全绿，而报告里一条 DNS 都没有。实测一份在手采集正是走
    223.5.5.5 的 TCP/53；此前解出 0 条，报告显示"未观测到 DNS"，
    与"确实没查过域名"无法区分。
    """
    qname = "config.example.test"
    msg = _dns_query(qname)
    # RFC 1035 §4.2.2：DNS over TCP 报文前置 2 字节长度
    seg = struct.pack("!H", len(msg)) + msg
    pkt = _eth(_ipv4(_tcp(seg, 50100, 53), 6, "10.0.0.2", "10.0.0.1"), 0x0800)

    summary = pcap_ingest.parse_pcap_bytes(_pcap([pkt]))

    assert qname in summary.dns_queries, f"TCP/53 的查询名未进 summary：{summary.dns_queries}"
    rec = next(r for r in summary.dns_records if r.qname == qname)
    assert rec.qtype == 1


def test_dns_over_tcp_answer_is_structured() -> None:
    """TCP 上的应答同样要结构化保留（TXT 下发通道超 512 字节就会走 TCP）。"""
    qname = "7nf15vxk.example.test"
    msg = _dns_response_txt(qname, "Io59QrTjne3mq19Yoc")
    seg = struct.pack("!H", len(msg)) + msg
    pkt = _eth(_ipv4(_tcp(seg, 53, 50101), 6, "10.0.0.1", "10.0.0.2"), 0x0800)

    summary = pcap_ingest.parse_pcap_bytes(_pcap([pkt]))

    rec = next(r for r in summary.dns_records if r.qname == qname)
    assert rec.qtype == 16 and rec.rcode == 0
    assert any(a["type"] == 16 and "Io59QrTjne3mq19Yoc" in a["value"] for a in rec.answers)


def test_intercept_exclusion_is_reported_separately_from_no_payload() -> None:
    """反诈拦截节点的排除必须**单列**统计，不能混进「无载荷」里。

    ★这条排除是全仓降噪纪律里唯一直接判「无需调证」的通道，且命中与否取决于一份人工维护的
      常量名单。此前它与无载荷共用一个计数、日志只提无载荷，于是「有个端点被当拦截节点吞了」
      在报告里完全看不出来——名单若哪天收错（某 IP 改作普通业务地址并被后端租用），
      静默丢弃会让人永远发现不了。
    """
    from apkscan.network.fingerprints import KNOWN_INTERCEPT_IPS

    intercept = sorted(KNOWN_INTERCEPT_IPS)[0]
    # 拦截节点带**双向载荷**：证明它不是靠「无载荷」那条判据被滤掉的
    hit = _eth(_ipv4(_tcp_flags(b"Y" * 60, 50002, 443, 0x18), 6, "10.0.0.2", intercept), 0x0800)
    syn = _eth(_ipv4(_tcp_flags(b"", 55555, 9466, 0x02), 6, "10.0.0.2", "45.202.1.235"), 0x0800)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    data = _eth(_ipv4(_tcp_flags(b"X" * 50, 50001, 30113, 0x18), 6, "10.0.0.2", "106.53.21.146"), 0x0800)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    summary = pcap_ingest.parse_pcap_bytes(_pcap([hit, syn, data]))

    stats: dict[str, object] = {}
    eps = pcap_ingest.to_runtime_endpoints(summary, stats=stats)
    ip_vals = {e.value for e in eps if e.kind == "ip"}

    assert intercept not in ip_vals, "拦截节点仍被升为 runtime 端点"
    assert stats["intercept_excluded"] == [intercept], (
        f"拦截节点的排除没有单列出来：{stats}"
    )
    assert stats["no_payload_dropped"] == 1, (
        f"拦截节点被混进了「无载荷」计数：{stats}——两类判据性质不同，合在一起数等于把后者藏起来"
    )
    assert "106.53.21.146" in ip_vals  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点


def test_intercept_exclusion_stats_absent_when_not_requested() -> None:
    """不传 stats 时行为逐字不变——既有 20+ 处调用点零改动。"""
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    assert pcap_ingest.to_runtime_endpoints(summary) == pcap_ingest.to_runtime_endpoints(
        summary, stats={}
    )


def test_runtime_endpoints_filters_syn_only_no_payload() -> None:
    """★ 复审#1：to_runtime_endpoints（自动并入主报告）过滤无载荷 SYN-only 节点——不让它绕过
    态分级、走下游默认公网 IP"建议调证"；有载荷节点保留；SYN-only 仍在 pcap 台账作待核。"""
    syn = _eth(_ipv4(_tcp_flags(b"", 55555, 9466, 0x02), 6, "10.0.0.2", "45.202.1.235"), 0x0800)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    data = _eth(_ipv4(_tcp_flags(b"X" * 50, 50001, 30113, 0x18), 6, "10.0.0.2", "106.53.21.146"), 0x0800)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    summary = pcap_ingest.parse_pcap_bytes(_pcap([syn, data]))
    ip_vals = {e.value for e in pcap_ingest.to_runtime_endpoints(summary) if e.kind == "ip"}
    assert "45.202.1.235" not in ip_vals  # SYN-only 无载荷 → 自动并入过滤  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert "106.53.21.146" in ip_vals  # 有载荷 → 保留  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    syn_lead = next(
        l for l in pcap_ingest.to_report_leads(summary)
        if l.category == LeadCategory.IP and "45.202.1.235" in l.value  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    )
    assert syn_lead.advice == "待核"  # pcap 台账仍留作待核（不静默丢弃）


def test_fanzha_interception_node_excluded() -> None:
    """★ Codex fengzhixin 案抓包交接 §6：反诈拦截节点（183.192.65.101）即便有双向载荷（拦截页
    返回），也标『无需调证·反诈拦截』、不升入 runtime 端点（会污染归因）；业务接入节点正常保留。"""
    fanzha, biz = "183.192.65.101", "100.64.113.177"
    # fanzha：双向载荷（拦截页会回数据）——本应被"反诈拦截"排除，而非因"有载荷"被当业务后端保留。
    out1 = _eth(_ipv4(_tcp_flags(b"GET /", 50001, 443, 0x18), 6, "10.0.0.2", fanzha), 0x0800)
    in1 = _eth(_ipv4(_tcp_flags(b"HTTP 302", 443, 50001, 0x18), 6, fanzha, "10.0.0.2"), 0x0800)
    biz = _eth(_ipv4(_tcp_flags(b"X" * 40, 50002, 443, 0x18), 6, "10.0.0.2", biz), 0x0800)
    summary = pcap_ingest.parse_pcap_bytes(_pcap([out1, in1, biz]))

    ip_vals = {e.value for e in pcap_ingest.to_runtime_endpoints(summary) if e.kind == "ip"}
    assert "183.192.65.101" not in ip_vals  # 反诈拦截节点排除，绝不升 runtime 端点污染归因
    assert "100.64.113.177" in ip_vals  # 业务接入节点正常保留

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
    syn = _eth(_ipv6(_tcp_flags(b"", 40000, 443, 0x02), 6, "2001:db8:9::1", "2606:4700::1111"), 0x86DD)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    dat = _eth(_ipv6(_tcp_flags(b"Z" * 30, 40000, 443, 0x18), 6, "2001:db8:9::1", "2606:4700::1111"), 0x86DD)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    summary = pcap_ingest.parse_pcap_bytes(_pcap([syn, dat]))
    ips = {r.ip for r in pcap_ingest.remote_endpoints(summary)}
    assert "2606:4700::1111" in ips  # 远端保留（未丢连接）  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert "2001:db8:9::1" not in ips  # 本机端不作远端


# ======================================================================
# UID 归因回灌（Codex 8.6 交接问题 1）
#
# 现象：capture 的 runtime_report.json 已把某端点标 target_attributed=true/confirmed，
# 而同一份采集经 `pcap-leads --into` 回灌后写出「runtime 确认 0 条」——
# 同一事实两个结论，且回灌那条是把「已确认」降成「没确认」的方向。
# ======================================================================


def _attr_key(summary) -> str:  # type: ignore[no-untyped-def]
    """夹具里第一个远端的归因表键（``proto/ip:port``）。

    ★从 summary 派生、不写死端口：夹具端口一改，写死的键会静默不命中，
      测试照样"通过"（因为断言的是"没有归因字段"）——那是最坏的假绿。
    """
    r = pcap_ingest.remote_endpoints(summary)[0]
    return f"{r.proto}/{r.ip}:{r.port}"


def _attr_of(report_path, ip: str) -> dict:
    """从 report.json 取某 IP 端点的 runtime 块。"""
    data = json.loads(report_path.read_text(encoding="utf-8"))
    for ep in data.get("endpoints", []):
        if ep.get("value") == ip:
            return (ep.get("enrichment") or {}).get("runtime") or {}
    return {}


def test_no_socket_snapshot_writes_no_attribution_field(tmp_path) -> None:
    """★没给快照时**一个归因字段都不写**——绝不填 target_attributed=False。

    「没做归因」和「做了、结论是不属目标」是两件事：前者是不知道，后者是证据。
    往缺失里填 False 就是把不知道写成了否定，而否定会让真后端被当噪音滤掉。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": [], "endpoints": [], "meta": {}}), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    pcap_ingest.merge_into_report_json(str(p), summary)  # 不传 app_attr
    rt = _attr_of(p, "106.53.21.146")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert rt, "端点本身应当写进去了"
    for key in ("target_attributed", "attribution", "target_among_candidates"):
        assert key not in rt, f"未归因时不该出现 {key}"
    inv = (json.loads(p.read_text(encoding="utf-8")).get("meta") or {}).get(
        "runtime_merged_inventory") or {}
    assert inv.get("uid_attributed") is False


def test_socket_attribution_reaches_report(tmp_path) -> None:
    """给了归因表 → 端点带 target_attributed，且 meta 两处都跟着走。"""
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": [], "endpoints": [], "meta": {}}), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    # 键格式与 capture 的 capture_signals["pcap_app_attribution"] 一致
    app_attr = {
        _attr_key(summary): {
            "attribution": "confirmed", "is_target_app": True,
            "score": 0.95, "target_uid_among_candidates": True, "uid": 10255,
        }
    }
    pcap_ingest.merge_into_report_json(str(p), summary, app_attr)
    rt = _attr_of(p, "106.53.21.146")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert rt["target_attributed"] is True
    assert rt["attribution"] == ["confirmed"]
    assert rt["attribution_score"] == 0.95
    assert rt["target_among_candidates"] is True
    meta = json.loads(p.read_text(encoding="utf-8"))["meta"]
    # ★闭环门控读 uid_attributed，报告读 capture_signals——两处都要有，否则归因做了也不算数
    assert meta["runtime_merged_inventory"]["uid_attributed"] is True
    assert meta["capture_signals"]["pcap_app_attribution"] == app_attr


def test_attribution_not_target_is_recorded_as_false_not_missing(tmp_path) -> None:
    """做了归因、结论是「不属目标」→ 明确写 False（这是证据，与"没做"不同）。"""
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": [], "endpoints": [], "meta": {}}), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    app_attr = {
        _attr_key(summary): {
            "attribution": "confirmed", "is_target_app": False, "uid": 1000,
        }
    }
    pcap_ingest.merge_into_report_json(str(p), summary, app_attr)
    rt = _attr_of(p, "106.53.21.146")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert rt["target_attributed"] is False
    assert rt["attribution"] == ["confirmed"]


def test_target_attributed_count_is_real_not_endpoint_total(tmp_path) -> None:
    """★★本刀自查抓到的核心问题：``target_attributed_count`` 必须是**真实归目标条数**。

    ``derive_capture_quality`` 曾写成 ``endpoints if uid_attributed else 0``——
    把「做过归因」读成「全部端点都归到目标了」。pcap 回灌恒 uid_attributed=False 时
    不暴露，一旦回灌能真做归因就是重大误报：某真实样本实测 33 个接入节点仅 1 个属目标，
    其余是设备自带推送等背景噪音，那个写法会把它们全报成"目标 app 已确认通信"。

    这里构造「有归因表、但该端点不属目标」，断言计数是 0 而不是端点数。
    """
    from apkscan.core import runtime_inventory as inv

    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": [], "endpoints": [], "meta": {}}), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    pcap_ingest.merge_into_report_json(str(p), summary, {
        _attr_key(summary): {"attribution": "confirmed", "is_target_app": False, "uid": 1000},
    })
    inventory = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]
    assert inventory["uid_attributed"] is True, "做过归因"
    assert inventory["remote_endpoints"] >= 1, "端点是有的"
    assert inventory["target_attributed"] == 0, "但没有一个属目标"
    q = inv.derive_capture_quality(inventory)
    assert q["target_attributed_count"] == 0, (
        "★归因结论是「不属目标」，却被计成已归因——这会把背景噪音写成目标资产")
    assert q["business_candidate_count"] >= 1


def test_target_attributed_count_counts_only_the_real_ones(tmp_path) -> None:
    """归目标的算 1 个，不属目标的不算——两者同时存在时也要分得清。"""
    from apkscan.core import runtime_inventory as inv

    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": [], "endpoints": [], "meta": {}}), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    pcap_ingest.merge_into_report_json(str(p), summary, {
        _attr_key(summary): {"attribution": "confirmed", "is_target_app": True, "uid": 10255},
    })
    inventory = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]
    assert inventory["target_attributed"] == 1
    assert inv.derive_capture_quality(inventory)["target_attributed_count"] == 1


def test_no_attribution_keeps_count_zero(tmp_path) -> None:
    """没做归因 → 恒 0（既有语义，闭环上限 partial）。"""
    from apkscan.core import runtime_inventory as inv

    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": [], "endpoints": [], "meta": {}}), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    pcap_ingest.merge_into_report_json(str(p), summary)
    inventory = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]
    assert inventory["uid_attributed"] is False
    assert inv.derive_capture_quality(inventory)["target_attributed_count"] == 0


def test_unattributed_endpoint_gets_no_false_positive(tmp_path) -> None:
    """归因表里没有这个远端 → 不写字段（不能因为"表在"就给所有端点填 False）。"""
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": [], "endpoints": [], "meta": {}}), encoding="utf-8")
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    pcap_ingest.merge_into_report_json(
        str(p), summary, {"tcp/198.51.100.7:443": {"attribution": "confirmed",
                                                   "is_target_app": True}})
    rt = _attr_of(p, "106.53.21.146")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert "target_attributed" not in rt


def test_to_runtime_endpoints_from_pcap() -> None:
    """★ floor 自动并入的基础：pcap summary → runtime Endpoint（公网 IP + SNI/DNS 域名，
    source=runtime-pcap），供 capture 并进 runtime_report.endpoints 走下游 asn/infra 分级。"""
    summary = pcap_ingest.parse_pcap_bytes(_sample_pcap())
    eps = pcap_ingest.to_runtime_endpoints(summary)
    assert eps  # 非空
    assert all(e.evidences and e.evidences[0].source == "runtime-pcap" for e in eps)
    ip_vals = {e.value for e in eps if e.kind == "ip"}
    assert "106.53.21.146" in ip_vals  # 公网接入节点作 IP 端点  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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
        _eth(_ipv6(_tcp_seq(seg1, 40000, 443, 5000), 6, "2001:db8:9::1", "2606:4700::1111"), 0x86DD),  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
        _eth(_ipv6(_tcp_seq(seg2, 40000, 443, 5000 + len(seg1)), 6, "2001:db8:9::1", "2606:4700::1111"), 0x86DD),  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    ]
    summary = pcap_ingest.parse_pcap_bytes(_pcap(frames))
    f = next(fl for fl in summary.flows if fl.dst_ip == "2606:4700::1111")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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


def _quic_pcap(payload: bytes, dst: str = "45.202.1.235", dport: int = 443) -> bytes:  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    return _pcap([_eth(_ipv4(_udp(payload, 51000, dport), 17, "10.0.0.2", dst), 0x0800)])


def test_quic_long_header_metadata_extracted() -> None:
    """QUIC Initial 长包头 → version/DCID/SCID 明文抽取，落 Flow + 远端聚合 + lead snippet（h3 归因）。"""
    summary = pcap_ingest.parse_pcap_bytes(_quic_pcap(_quic_long_header()))
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert "00000001" in f.quic_versions
    assert bytes(range(8)).hex() in f.quic_dcids and "aabbcc" in f.quic_scids
    lead = next(l for l in pcap_ingest.to_report_leads(summary)
                if l.category == LeadCategory.IP and "45.202.1.235" in l.value)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert "QUIC=00000001" in lead.source_refs[0].snippet
    led = pcap_ingest.to_ledger_dict(summary)
    assert any("00000001" in e["quic_versions"] for e in led["remote_endpoints"])


def test_quic_dcid_survives_ip_migration_correlation() -> None:
    """同一 QUIC 连接 ID 出现在不同五元组（IP 迁移/NAT 重绑）→ 各 Flow 都记录该 DCID（供跨流关联，
    五元组聚合做不到的能力）。"""
    dcid = b"\xde\xad\xbe\xef\x11\x22"
    s1 = pcap_ingest.parse_pcap_bytes(_quic_pcap(_quic_long_header(dcid=dcid), dst="45.202.1.235"))  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    s2 = pcap_ingest.parse_pcap_bytes(_quic_pcap(_quic_long_header(dcid=dcid), dst="106.53.21.146"))  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert "quic-c2.evil.com" in f.sni  # QUIC SNI 解出，与 TCP「SNI 不丢」对等
    assert "h3" in f.alpn
    lead = next(l for l in pcap_ingest.to_report_leads(summary)
                if l.category == LeadCategory.IP and "45.202.1.235" in l.value)  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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
        _eth(_ipv4(_udp(p1, 51000, 443), 17, "10.0.0.2", "45.202.1.235"), 0x0800),  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
        _eth(_ipv4(_udp(p2, 51000, 443), 17, "10.0.0.2", "45.202.1.235"), 0x0800),  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    ]))
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
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
        _eth(_ipv4(_udp(p1, 51000, 443), 17, "10.0.0.2", "45.202.1.235"), 0x0800),  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
        _eth(_ipv4(_udp(p2, 51000, 443), 17, "10.0.0.2", "45.202.1.235"), 0x0800),  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    ]))
    f = next(fl for fl in summary.flows if fl.dst_ip == "45.202.1.235")  # leak-scan: allow pcap 远端/接入节点夹具，_ip_public 要判它是公网远端才会产出 runtime 端点
    assert "dcid-switch.evil.com" in f.sni


def test_quic_key_cache_bounded() -> None:
    """★复审 #B：唯一 DCID 洪水 → 密钥缓存 FIFO 有界（≤ _MAX_QUIC_KEYS），绝不无界 OOM。"""
    pytest.importorskip("cryptography")
    cache: dict = {}
    for i in range(pcap_ingest._MAX_QUIC_KEYS + 200):
        pcap_ingest._quic_client_initial_keys(struct.pack("!Q", i), cache)
    assert len(cache) <= pcap_ingest._MAX_QUIC_KEYS


def test_remote_endpoints_exposes_per_connection_local_port_and_window(monkeypatch) -> None:
    """★A2：remote_endpoints 暴露每本机端口一条连接观测（本地端口 + 两方向时间区间并集），供五元组归因。"""
    monkeypatch.setattr(pcap_ingest, "_ip_public", lambda v: v == "1.2.3.4")
    summary = pcap_ingest.PcapSummary(flows=[
        pcap_ingest.Flow("tcp", "10.0.0.2", 50002, "1.2.3.4", 443, packets=2, payload_bytes=80, first_ts=1.0, last_ts=2.0),   # 出站
        pcap_ingest.Flow("tcp", "1.2.3.4", 443, "10.0.0.2", 50002, packets=3, payload_bytes=200, first_ts=1.1, last_ts=2.5),  # 入站反向
    ])
    res = {(r.ip, r.port): r for r in pcap_ingest.remote_endpoints(summary)}
    re = res[("1.2.3.4", 443)]
    assert len(re.connections) == 1
    c = re.connections[0]
    assert c.local_port == 50002                   # 本机临时端口（出站 src_port = 入站 dst_port）
    assert c.first_ts == 1.0 and c.last_ts == 2.5  # 两方向时间区间并集

def test_ingest_and_advice_calibers_differ_on_purpose() -> None:
    """摄取层与出口层对"公网"的判据**有意不同**，这条锁住的是分工本身。

    ``_ip_public`` 问的是"这是不是一个可上报的远端"（并集口径，与 probe 侧对齐）；
    ``infra.classify_ip`` 问的是"值不值得调证"。CGNAT 正踩在两者的缝上：
    它确实是远端（该被摄取），但运营商级 NAT 没有可调证的租户（不该进调证出口）。

    ★谁要是把 ``_ip_public`` "顺手"改成 ``is_global``，这条会红——那不是笔误，
      是会破坏 pcap/probe 并集口径的改动，须连同 probe 侧一起重新设计。
    """
    from apkscan.core import infra

    cgnat = "100.64.7.14"
    assert pcap_ingest._ip_public(cgnat) is True, "摄取层：CGNAT 是远端，应被收下"
    assert infra.classify_ip(cgnat)[0] == infra.ADVICE_SKIP, "出口层：CGNAT 无调证对象"

    # 对照：私网在两层都不该被当远端 / 调证对象——分歧只在 CGNAT 这一档上
    assert pcap_ingest._ip_public("10.0.0.5") is False
    assert infra.classify_ip("10.0.0.5")[0] == infra.ADVICE_SKIP

    # ★这里**不放**"真公网"对照组：要一个 is_global=True 的字面就得引入
    #   192.88.99.x 那类依赖标准库特殊段分类的地址，而那正是另一项待清理的债
    #   （见任务「测试夹具不再依赖 ipaddress 的特殊段分类偶然性」）。
    #   本条锁的是"两层判据在 CGNAT 上有意分歧"，不需要第三组数据。
