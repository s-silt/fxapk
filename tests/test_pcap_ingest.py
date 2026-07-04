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

from apkscan.core.models import LeadCategory
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
