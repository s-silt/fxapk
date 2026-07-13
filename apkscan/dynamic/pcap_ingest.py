"""apkscan.dynamic.pcap_ingest — 带外 pcap → 接入节点/SNI/DNS 调证线索（纯标准库解析，零依赖）。

针对反分析涉诈 App：即便 TLS 解不开、走 MTProto/native 自建协议（普通抓包 endpoint=0），
只要有一份**带外抓的 pcap**（网关 tcpdump / PCAPdroid 免 root 导出 / Wireshark），就能从裸包抽出
**真实接入节点 IP:port + TLS SNI + DNS 查询 + JA3 指纹**，按 LeadCategory 聚成调证线索 / 回灌
``report.json``——把"解不开也能办案：带外拿接入节点 IP=穿透锚点"变成一条命令。

为什么纯标准库：fxapk 主打"零环境"（不强求 dpkt/scapy/pyshark/tshark）；这里只需 IP:port/SNI/DNS，
用 ``struct`` 手解经典 pcap 足够。支持 Ethernet/RAW-IP/Linux-SLL 链路、IPv4/IPv6、TCP/UDP，以及
pcapng 的 Enhanced Packet Block（best-effort）。**绝不抛**：坏包/坏文件逐条跳过 + logging。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from apkscan.core import infra
from apkscan.core.atomic import atomic_write_text
from apkscan.core.models import (
    Confidence,
    Endpoint,
    Evidence,
    Lead,
    LeadCategory,
    merge_runtime_into_lead_dict,
)

logger = logging.getLogger(__name__)

_SOURCE = "runtime-pcap"

# TLS GREASE 值（JA3 计算须剔除）：0x0a0a, 0x1a1a, …, 0xfafa。
_GREASE = {(b << 8) | b for b in range(0x0A, 0x100, 0x10)}


@dataclass
class Flow:
    """一条按 5 元组聚合的流（方向：src→dst）。"""

    proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: int = 0
    bytes_: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    sni: set[str] = field(default_factory=set)
    ja3: set[str] = field(default_factory=set)
    flags: set[str] = field(default_factory=set)  # 本方向见到的 TCP 标志：syn/ack/synack/rst/fin/psh
    payload_bytes: int = 0  # 本方向 L4 应用层载荷累计字节（TCP：TCP 头之后）


@dataclass
class DnsRecord:
    """一条 DNS 查询/应答的结构化证据——保留 QTYPE/RCODE/answers，供 TXT 配置下发通道等直接入报告。"""

    qname: str
    qtype: int
    rcode: int
    txid: int = 0
    answers: list[dict] = field(default_factory=list)  # [{"type": int, "value": str, "ttl": int}]
    ts: float = 0.0


# TCP 连接态分级（远端聚合后据双向载荷/握手标志判定；与 Codex 交接 P0-1 口径一致）。
STATE_ESTABLISHED = "established"  # 双向均有应用层载荷 —— 已通信的真接入节点
STATE_SYN_ONLY = "syn_only"  # 仅本机 SYN、无 SYN-ACK、无任何载荷 —— 连接尝试/待核
STATE_RESET = "reset"  # 见 RST 且无载荷 —— 连接被拒/待核
STATE_UNKNOWN = "unknown"  # 其它（单向载荷、握手无数据等）

# 已知反诈拦截节点（Codex fengzhixin 案抓包交接 §6）：涉诈域名被拦后解析至此的拦截页 IP——非业务
# 接入/落地机。即便有双向载荷（拦截页会回数据）也必须与待核业务接入池严格区分、勿据此调证。
_KNOWN_FANZHA = frozenset({"183.192.65.101"})


@dataclass
class RemoteEndpoint:
    """按公网远端 (ip:port/proto) 跨多条 5 元组聚合的接入节点——分级 established/syn_only/reset/unknown。"""

    ip: str
    port: int
    proto: str
    out_bytes: int = 0  # 本机→远端 应用层载荷
    in_bytes: int = 0  # 远端→本机 应用层载荷
    packets: int = 0
    connection_count: int = 0  # 不同本机源端口数（连接尝试次数）
    flags: set[str] = field(default_factory=set)
    sni: set[str] = field(default_factory=set)
    ja3: set[str] = field(default_factory=set)
    first_ts: float = 0.0
    last_ts: float = 0.0
    state: str = STATE_UNKNOWN

    @property
    def has_payload(self) -> bool:
        return self.out_bytes > 0 or self.in_bytes > 0


@dataclass
class PcapSummary:
    flows: list[Flow] = field(default_factory=list)
    dns_queries: set[str] = field(default_factory=set)
    dns_records: list[DnsRecord] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 解析入口
# ---------------------------------------------------------------------------


def parse_pcap(path: str) -> PcapSummary:
    """读 pcap 文件并解析；文件缺失/坏 → 空 summary（不抛）。"""
    try:
        data = Path(path).read_bytes()
    except OSError:
        logger.exception("[pcap] 读取 pcap 失败：%s", path)
        return PcapSummary()
    return parse_pcap_bytes(data)


def parse_pcap_bytes(data: bytes) -> PcapSummary:
    """解析 pcap/pcapng 字节，聚合出 flows + DNS 查询。绝不抛。"""
    summ = PcapSummary()
    flows: dict[tuple, Flow] = {}
    try:
        for ts, linktype, frame in _iter_frames(data):
            try:
                _process_frame(ts, linktype, frame, flows, summ)
            except Exception:  # noqa: BLE001 - 单包坏不影响其余
                logger.debug("[pcap] 跳过坏包", exc_info=True)
    except Exception:  # noqa: BLE001 - 整体解析异常也不抛
        logger.exception("[pcap] 解析异常")
    summ.flows = list(flows.values())
    return summ


# ---------------------------------------------------------------------------
# 帧迭代：经典 pcap + pcapng（best-effort）
# ---------------------------------------------------------------------------


def _iter_frames(data: bytes) -> Iterator[tuple[float, int, bytes]]:
    if len(data) < 24:
        return
    magic = data[:4]
    # 经典 pcap 有微秒(a1b2c3d4 / d4c3b2a1)与纳秒(a1b23c4d / 4d3cb2a1)两种精度魔数,
    # 小数字段除数不同:µs→1e6、ns→1e9。混用会让 observed_at 偏移最多近千秒。
    if magic == b"\xa1\xb2\xc3\xd4":
        endian, frac_div = ">", 1e6
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, frac_div = ">", 1e9
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian, frac_div = "<", 1e6
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, frac_div = "<", 1e9
    elif magic == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng(data)
        return
    else:
        logger.info("[pcap] 非 pcap/pcapng（magic=%s），跳过", magic.hex())
        return
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    n = len(data)
    while off + 16 <= n:
        ts_sec, ts_usec_or_nsec, incl, _orig = struct.unpack(endian + "IIII", data[off : off + 16])
        off += 16
        if incl < 0 or off + incl > n:
            break
        frame = data[off : off + incl]
        off += incl
        yield (float(ts_sec) + ts_usec_or_nsec / frac_div, linktype, frame)


def _iter_pcapng(data: bytes) -> Iterator[tuple[float, int, bytes]]:
    """最小 pcapng：跟踪 IDB 的 linktype，产出 Enhanced/Simple Packet Block 的帧。"""
    n = len(data)
    if n < 12:
        return
    # SHB 的 byte-order magic 在 offset 8（0x1A2B3C4D）。
    endian = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    linktypes: list[int] = []
    off = 0
    while off + 8 <= n:
        btype, blen = struct.unpack(endian + "II", data[off : off + 8])
        if blen < 12 or off + blen > n:
            break
        body = data[off + 8 : off + blen - 4]
        if btype == 0x00000001:  # IDB
            if len(body) >= 2:
                linktypes.append(struct.unpack(endian + "H", body[:2])[0])
        elif btype == 0x00000006:  # EPB: interface_id(4) ts_hi(4) ts_lo(4) caplen(4) origlen(4) data
            if len(body) >= 20:
                if_id, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
                frame = body[20 : 20 + caplen]
                lt = linktypes[if_id] if if_id < len(linktypes) else (linktypes[0] if linktypes else 1)
                ts = ((ts_hi << 32) | ts_lo) / 1e6
                yield (ts, lt, frame)
        elif btype == 0x00000003:  # Simple Packet Block
            lt = linktypes[0] if linktypes else 1
            if len(body) >= 4:
                yield (0.0, lt, body[4:])
        off += blen


# ---------------------------------------------------------------------------
# 链路层 → IP → L4
# ---------------------------------------------------------------------------


def _strip_link(linktype: int, frame: bytes) -> tuple[int | None, bytes]:
    """剥链路层，返回 (ethertype, ip_payload)。ethertype 0x0800=IPv4 0x86dd=IPv6。"""
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None, b""
        et = struct.unpack("!H", frame[12:14])[0]
        payload = frame[14:]
        while et == 0x8100 and len(payload) >= 4:  # 802.1Q VLAN
            et = struct.unpack("!H", payload[2:4])[0]
            payload = payload[4:]
        return et, payload
    if linktype in (101, 12, 14):  # RAW IP
        if not frame:
            return None, b""
        ver = frame[0] >> 4
        return (0x0800 if ver == 4 else 0x86DD if ver == 6 else None), frame
    if linktype == 113:  # Linux SLL（v1，16 字节头）
        if len(frame) < 16:
            return None, b""
        return struct.unpack("!H", frame[14:16])[0], frame[16:]
    if linktype == 276:  # Linux SLL2（-i any 在 libpcap>=1.10 / tcpdump>=4.99 下的产物，20 字节头）
        if len(frame) < 20:
            return None, b""
        # SLL2：protocol(EtherType) 在头部 offset 0，IP 载荷从 offset 20 起。
        return struct.unpack("!H", frame[0:2])[0], frame[20:]
    if linktype == 0:  # BSD loopback
        if len(frame) < 4:
            return None, b""
        fam = struct.unpack("=I", frame[:4])[0]
        return (0x0800 if fam == 2 else 0x86DD), frame[4:]
    return None, b""


def _parse_ipv4(b: bytes) -> tuple[int, str, str, bytes] | None:
    if len(b) < 20:
        return None
    ihl = (b[0] & 0x0F) * 4
    if ihl < 20 or len(b) < ihl:
        return None
    return b[9], socket.inet_ntoa(b[12:16]), socket.inet_ntoa(b[16:20]), b[ihl:]


def _parse_ipv6(b: bytes) -> tuple[int, str, str, bytes] | None:
    if len(b) < 40:
        return None
    src = socket.inet_ntop(socket.AF_INET6, b[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, b[24:40])
    return b[6], src, dst, b[40:]  # next-header；扩展头从简（非 6/17 即跳过）


def _parse_tcp(b: bytes) -> tuple[int, int, int, bytes] | None:
    if len(b) < 20:
        return None
    sport, dport = struct.unpack("!HH", b[:4])
    flags = b[13]  # TCP 标志字节（FIN/SYN/RST/PSH/ACK…）
    off = (b[12] >> 4) * 4
    if off < 20 or len(b) < off:
        return sport, dport, flags, b""
    return sport, dport, flags, b[off:]


def _parse_udp(b: bytes) -> tuple[int, int, bytes] | None:
    if len(b) < 8:
        return None
    sport, dport = struct.unpack("!HH", b[:4])
    return sport, dport, b[8:]


def _process_frame(ts: float, linktype: int, frame: bytes, flows: dict, summ: PcapSummary) -> None:
    et, ipp = _strip_link(linktype, frame)
    if not ipp:
        return
    if et == 0x0800:
        info = _parse_ipv4(ipp)
    elif et == 0x86DD:
        info = _parse_ipv6(ipp)
    else:
        return
    if info is None:
        return
    proto_num, src_ip, dst_ip, l4 = info
    tcp_flags = 0
    if proto_num == 6:
        tcp_parsed = _parse_tcp(l4)
        if tcp_parsed is None:
            return
        sport, dport, tcp_flags, app = tcp_parsed
        proto = "tcp"
    elif proto_num == 17:
        udp_parsed = _parse_udp(l4)
        if udp_parsed is None:
            return
        sport, dport, app = udp_parsed
        proto = "udp"
    else:
        return
    key = (proto, src_ip, sport, dst_ip, dport)
    f = flows.get(key)
    if f is None:
        f = Flow(proto, src_ip, sport, dst_ip, dport, first_ts=ts)
        flows[key] = f
    f.packets += 1
    f.bytes_ += len(frame)
    f.last_ts = ts
    f.payload_bytes += len(app)  # TCP/UDP 均计 L4 应用层载荷（UDP C2/QUIC 只有 UDP 载荷也算有载荷）
    if proto_num == 6:
        for name, bit in (("fin", 0x01), ("syn", 0x02), ("rst", 0x04), ("psh", 0x08), ("ack", 0x10)):
            if tcp_flags & bit:
                f.flags.add(name)
        if (tcp_flags & 0x02) and (tcp_flags & 0x10):  # SYN+ACK = 本流方向为"远端→本机"的握手应答
            f.flags.add("synack")
        if app[:1] == b"\x16":  # TLS handshake record
            sni, ja3 = _parse_client_hello(app)
            if sni:
                f.sni.add(sni)
            if ja3:
                f.ja3.add(ja3)
    if proto_num == 17 and (dport == 53 or sport == 53):
        qn = _parse_dns_qname(app)
        if qn:
            summ.dns_queries.add(qn)
        rec = _parse_dns(app, ts)
        if rec is not None:
            summ.dns_records.append(rec)


# ---------------------------------------------------------------------------
# TLS ClientHello（SNI + JA3）/ DNS
# ---------------------------------------------------------------------------


def _u16_list(b: bytes) -> list[int]:
    return [struct.unpack("!H", b[i : i + 2])[0] for i in range(0, len(b) - 1, 2)]


def _parse_sni_ext(ev: bytes) -> str | None:
    if len(ev) < 5:
        return None
    p = 2  # 跳 server_name_list 长度
    while p + 3 <= len(ev):
        ntype = ev[p]
        nlen = struct.unpack("!H", ev[p + 1 : p + 3])[0]
        name = ev[p + 3 : p + 3 + nlen]
        p += 3 + nlen
        if ntype == 0:  # host_name
            try:
                return name.decode("ascii")
            except UnicodeDecodeError:
                return name.decode("utf-8", "replace")
    return None


def _ja3(ver: int, ciphers: list[int], exts: list[int], curves: list[int], formats: list[int]) -> str:
    def j(lst: list[int]) -> str:
        return "-".join(str(x) for x in lst if x not in _GREASE)

    s = f"{ver},{j(ciphers)},{j(exts)},{j(curves)},{j(formats)}"
    return hashlib.md5(s.encode()).hexdigest()  # noqa: S324 - JA3 规范就是 md5，非安全用途


def _parse_client_hello(rec: bytes) -> tuple[str | None, str | None]:
    try:
        if len(rec) < 5 or rec[0] != 0x16:
            return None, None
        rec_len = struct.unpack("!H", rec[3:5])[0]
        hs = rec[5 : 5 + rec_len]
        if len(hs) < 4 or hs[0] != 0x01:  # client_hello
            return None, None
        hs_len = int.from_bytes(hs[1:4], "big")
        body = hs[4 : 4 + hs_len]
        p = 0
        client_ver = struct.unpack("!H", body[p : p + 2])[0]
        p += 2 + 32  # version + random
        sid_len = body[p]
        p += 1 + sid_len
        cs_len = struct.unpack("!H", body[p : p + 2])[0]
        p += 2
        ciphers = _u16_list(body[p : p + cs_len])
        p += cs_len
        comp_len = body[p]
        p += 1 + comp_len
        sni: str | None = None
        curves: list[int] = []
        formats: list[int] = []
        ext_types: list[int] = []
        if p + 2 <= len(body):
            ext_total = struct.unpack("!H", body[p : p + 2])[0]
            p += 2
            end = min(p + ext_total, len(body))
            while p + 4 <= end:
                et = struct.unpack("!H", body[p : p + 2])[0]
                el = struct.unpack("!H", body[p + 2 : p + 4])[0]
                ev = body[p + 4 : p + 4 + el]
                p += 4 + el
                ext_types.append(et)
                if et == 0x0000:
                    sni = _parse_sni_ext(ev)
                elif et == 0x000A and len(ev) >= 2:
                    curves = _u16_list(ev[2:])
                elif et == 0x000B and ev:
                    formats = list(ev[1:])
        return sni, _ja3(client_ver, ciphers, ext_types, curves, formats)
    except Exception:  # noqa: BLE001 - 解析坏 ClientHello 不抛
        return None, None


def _parse_dns_qname(b: bytes) -> str | None:
    if len(b) < 13:
        return None
    p = 12
    labels: list[str] = []
    while p < len(b):
        ln = b[p]
        if ln == 0:
            break
        if ln & 0xC0:  # 问题段里出现压缩指针（罕见）→ 放弃
            return None
        p += 1
        labels.append(b[p : p + ln].decode("ascii", "replace"))
        p += ln
        if len(labels) > 127:
            return None
    return ".".join(labels) if labels else None


def _read_name(msg: bytes, p: int) -> tuple[str, int]:
    """读 DNS 域名（支持 0xC0 压缩指针）；返回 (name, 指针后的偏移)。坏则返回 ("", p)。"""
    labels: list[str] = []
    jumped = False
    resume = p
    steps = 0
    while 0 <= p < len(msg):
        ln = msg[p]
        if ln == 0:
            p += 1
            break
        if ln & 0xC0 == 0xC0:  # 压缩指针
            if p + 1 >= len(msg):
                return "", resume
            ptr = ((ln & 0x3F) << 8) | msg[p + 1]
            if not jumped:
                resume = p + 2
            jumped = True
            p = ptr
            steps += 1
            if steps > 128:
                return ".".join(labels), resume
            continue
        p += 1
        labels.append(msg[p : p + ln].decode("ascii", "replace"))
        p += ln
        if len(labels) > 127:
            break
    return ".".join(labels), (resume if jumped else p)


def _decode_rdata(rtype: int, rdata: bytes, msg: bytes, rdata_off: int) -> str:
    """按 RR 类型解码 rdata → 可读值：A/AAAA=IP、CNAME/NS=域名、TXT=文本、其它=hex。绝不抛。"""
    try:
        if rtype == 1 and len(rdata) == 4:  # A
            return socket.inet_ntoa(rdata)
        if rtype == 28 and len(rdata) == 16:  # AAAA
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if rtype in (5, 2, 12):  # CNAME / NS / PTR（可能含压缩指针，须在整包里读）
            name, _ = _read_name(msg, rdata_off)
            return name
        if rtype == 16:  # TXT：一或多段 长度前缀字符串
            out: list[str] = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                i += 1
                out.append(rdata[i : i + ln].decode("ascii", "replace"))
                i += ln
            return "".join(out)
    except Exception:  # noqa: BLE001 - 单条 rdata 解码坏不抛
        return rdata.hex()
    return rdata.hex()


def _parse_dns(b: bytes, ts: float = 0.0) -> DnsRecord | None:
    """解析一条 DNS 报文（查询或应答）→ 结构化 DnsRecord（txid/qtype/rcode/answers）。绝不抛。

    保留 QTYPE/RCODE 与每条 answer 的 type/value/TTL——本案 TXT 配置下发通道(ClientCore 经
    DNS TXT 下发动态服务器 IP:端口)须能把 TXT 内容直接进报告，仅留 qname 会丢关键证据。
    """
    try:
        if len(b) < 12:
            return None
        txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", b[:12])
        if qd < 1:
            return None
        rcode = flags & 0x000F
        qname, p = _read_name(b, 12)
        if p + 4 > len(b):
            return None
        qtype, _qclass = struct.unpack("!HH", b[p : p + 4])
        p += 4
        # 跳过其余问题段（通常 qd==1）。
        for _ in range(qd - 1):
            _n, p = _read_name(b, p)
            p += 4
            if p > len(b):
                return DnsRecord(qname=qname, qtype=qtype, rcode=rcode, txid=txid, ts=ts)
        answers: list[dict] = []
        for _ in range(an):
            if p >= len(b):
                break
            _name, p = _read_name(b, p)
            if p + 10 > len(b):
                break
            rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", b[p : p + 10])
            p += 10
            rdata = b[p : p + rdlen]
            value = _decode_rdata(rtype, rdata, b, p)
            p += rdlen
            answers.append({"type": rtype, "value": value, "ttl": ttl})
        return DnsRecord(qname=qname, qtype=qtype, rcode=rcode, txid=txid, answers=answers, ts=ts)
    except Exception:  # noqa: BLE001 - 坏 DNS 报文不抛
        return None


# ---------------------------------------------------------------------------
# summary → Lead / 台账 / report.json
# ---------------------------------------------------------------------------


def _ip_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (
            a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved
        )
    except ValueError:
        return False


_IP_WHERE = "向云厂商 / IDC 调该 IP 的主机租户实名 + 入站连接日志（native/自建协议接入节点，穿透真源站锚点）。"
_DOMAIN_WHERE = "向注册商 / ICP 备案 / 云厂商调域名归属与租户实名。"


def _classify_state(re: "RemoteEndpoint") -> str:
    """据双向载荷 + 握手标志判连接态。双向载荷=established；仅 SYN 无应答无载荷=syn_only（待核）。"""
    if re.out_bytes > 0 and re.in_bytes > 0:
        return STATE_ESTABLISHED
    if re.has_payload:
        return STATE_UNKNOWN  # 单向有载荷：观测到数据但非双向（仍作线索，不降为待核）
    if "rst" in re.flags:
        return STATE_RESET
    if "syn" in re.flags and "synack" not in re.flags:
        return STATE_SYN_ONLY
    return STATE_UNKNOWN


def remote_endpoints(summary: PcapSummary) -> list[RemoteEndpoint]:
    """把 flows 按**公网远端** (ip:port/proto) 跨多条 5 元组聚合成接入节点，并分级连接态。

    本机↔远端两个方向（client→server / server→client）各自是一条 5 元组 Flow；此处按远端归并：
    - 本机→远端方向贡献 ``out_bytes`` + 本机侧标志（syn/rst）+ 连接尝试次数（不同本机源端口）;
    - 远端→本机方向贡献 ``in_bytes`` + 远端侧握手标志（synack）。
    仅公网远端入选（私网/回环远端跳过）。绝不抛。
    """
    agg: dict[tuple[str, str, int], RemoteEndpoint] = {}
    conn_src: dict[tuple[str, str, int], set[tuple[str, int]]] = {}

    def _touch(key: tuple[str, str, int], ip: str, port: int, proto: str) -> RemoteEndpoint:
        re = agg.get(key)
        if re is None:
            re = RemoteEndpoint(ip=ip, port=port, proto=proto)
            agg[key] = re
        return re

    for f in summary.flows:
        dst_pub = _ip_public(f.dst_ip)
        src_pub = _ip_public(f.src_ip)
        if dst_pub and not src_pub:
            remote_is_dst = True  # 本机(私)→远端(公)：出站
        elif src_pub and not dst_pub:
            remote_is_dst = False  # 远端(公)→本机(私)：入站
        elif dst_pub and src_pub:
            # 两端都公网（如移动网 IPv6 GUA 直连）——不丢弃：SYN 方向/端口启发式判哪端是远端。
            if "syn" in f.flags and "synack" not in f.flags:
                remote_is_dst = True  # 本机发起 SYN → dst 是远端
            elif "synack" in f.flags:
                remote_is_dst = False  # 见 SYN-ACK → src 是远端（服务端）
            else:
                remote_is_dst = f.dst_port <= f.src_port  # 端口小的一端更像服务端/远端
        else:
            continue  # 两端都私网：不产接入节点
        if remote_is_dst:  # 本机→远端：出站
            key = (f.proto, f.dst_ip, f.dst_port)
            re = _touch(key, f.dst_ip, f.dst_port, f.proto)
            re.out_bytes += f.payload_bytes
            re.flags |= {x for x in f.flags if x in ("syn", "rst", "fin", "ack", "psh")}
            re.sni |= f.sni
            re.ja3 |= f.ja3
            conn_src.setdefault(key, set()).add((f.src_ip, f.src_port))
        else:  # 远端→本机：入站
            key = (f.proto, f.src_ip, f.src_port)
            re = _touch(key, f.src_ip, f.src_port, f.proto)
            re.in_bytes += f.payload_bytes
            if "synack" in f.flags:
                re.flags.add("synack")
            if "rst" in f.flags:
                re.flags.add("rst")
            re.sni |= f.sni
            re.ja3 |= f.ja3
            conn_src.setdefault(key, set()).add((f.dst_ip, f.dst_port))  # 入站方向也计本机端口(P1)
        re.packets += f.packets
        if f.first_ts and (re.first_ts == 0.0 or f.first_ts < re.first_ts):
            re.first_ts = f.first_ts
        if f.last_ts > re.last_ts:
            re.last_ts = f.last_ts

    for key, re in agg.items():
        re.connection_count = len(conn_src.get(key, set()))
        re.state = _classify_state(re)
    return list(agg.values())


def to_report_leads(summary: PcapSummary) -> list[Lead]:
    """把 pcap summary 转成 report 的 Lead（公网接入节点 IP + SNI/DNS 域名，source=runtime-pcap）。"""
    leads: list[Lead] = []
    seen: set[tuple[str, str]] = set()

    for re in remote_endpoints(summary):
        value = f"{re.ip}:{re.port}/{re.proto}"
        key = (LeadCategory.IP.value, value)
        if key in seen:
            continue
        seen.add(key)
        ja3 = ("，JA3=" + "/".join(sorted(re.ja3))) if re.ja3 else ""
        sni = ("，SNI=" + "/".join(sorted(re.sni))) if re.sni else ""
        if re.ip in _KNOWN_FANZHA:
            # 反诈拦截节点即便有双向载荷（拦截页会回数据）也非业务接入/落地机——标『无需调证』，
            # 不静默丢（仍留台账作拦截证据），但严禁当接入节点升"建议调证"、污染归因。
            advice, confidence = infra.ADVICE_SKIP, Confidence.HIGH
            notes = "反诈拦截节点（涉诈域名被拦后解析至此的拦截页）——非业务接入/落地机，排除，勿据此调证。"
        elif re.has_payload:
            advice, confidence = infra.ADVICE_INVESTIGATE, Confidence.HIGH
            if re.state == STATE_ESTABLISHED:
                notes = "带外 pcap 实测接入节点（双向载荷=已通信后端）；凭此 IP 调证穿透真源站。"
            else:
                notes = "带外 pcap 观测到应用层载荷（单向，未见回程）；作接入节点调证。"
        else:
            advice, confidence = infra.ADVICE_REVIEW, Confidence.MEDIUM
            notes = (
                "带外 pcap 仅见连接尝试（SYN-only / 无双向载荷 / RST），待核——"
                "可能为 ClientCore 轮询/容灾池或背景噪音，勿当实测接入节点直接调证。"
            )
        leads.append(
            Lead(
                category=LeadCategory.IP,
                value=value,
                where_to_request=_IP_WHERE,
                confidence=confidence,
                advice=advice,
                source_refs=[
                    Evidence(
                        source=_SOURCE,
                        location="pcap",
                        snippet=(
                            f"->{value} state={re.state} out={re.out_bytes}B in={re.in_bytes}B "
                            f"conns={re.connection_count} pkts={re.packets}{sni}{ja3}"
                        )[:200],
                        observed_at=re.first_ts or None,  # 首包时间 → 观测时刻（0.0 视作未知留 None）
                    )
                ],
                notes=notes,
            )
        )

    domains: dict[str, str] = {}
    domain_ts: dict[str, float] = {}  # SNI 域名 → 承载它的最早 flow 首包时间（DNS 域名无 per-query ts，留空）
    for f in summary.flows:
        for s in f.sni:
            domains.setdefault(s, "TLS SNI")
            if f.first_ts and (s not in domain_ts or f.first_ts < domain_ts[s]):
                domain_ts[s] = f.first_ts
    for q in summary.dns_queries:
        domains.setdefault(q, "DNS 查询")
    for dom, src in domains.items():
        key = (LeadCategory.DOMAIN.value, dom)
        if key in seen:
            continue
        seen.add(key)
        try:
            advice, _reason = infra.classify_domain(dom)
        except Exception:  # noqa: BLE001 - 分级失败给默认
            advice = "建议调证"
        leads.append(
            Lead(
                category=LeadCategory.DOMAIN,
                value=dom,
                where_to_request=_DOMAIN_WHERE,
                confidence=Confidence.HIGH,
                advice=advice or "建议调证",
                source_refs=[
                    Evidence(
                        source=_SOURCE,
                        location="pcap",
                        snippet=f"{src}: {dom}",
                        observed_at=domain_ts.get(dom),  # SNI 域名带首包时间，DNS 域名留 None
                    )
                ],
                notes=f"带外 pcap 捕获（{src}）。",
            )
        )
    return leads


def to_runtime_endpoints(summary: PcapSummary) -> list[Endpoint]:
    """把 pcap summary 转成 runtime_report 的 ``Endpoint``（公网接入节点 IP + SNI/DNS 域名，
    ``source=runtime-pcap``）——供 capture 把带外 pcap 的接入节点【自动并入】``runtime_report.endpoints``，
    随后经 merge → asn 富化 → infra 归属分级（Google/云 IP 自动判为第三方基础设施并在报告里折叠）。

    与 :func:`to_report_leads` 同源（同样只收 public dst IP + SNI/DNS 域名），但产 ``Endpoint`` 而非
    ``Lead``；**此处不做噪音判定**——IP 侧交下游 asn/infra 分级，域名侧的 OS/GMS/连通性噪音由调用方
    （capture）按 host 名单折叠。绝不抛（坏 summary 退化为空列表由调用方兜底）。
    """
    endpoints: list[Endpoint] = []
    seen: set[str] = set()
    dropped = 0
    for re in remote_endpoints(summary):
        # ★反诈拦截节点排除（Codex fengzhixin 案抓包交接 §6）：涉诈域名被拦后解析至此的拦截页，即便
        #   有双向载荷也非业务接入/落地机，绝不升为 runtime 端点（会污染归因）；仍在 pcap 台账留证。
        if re.ip in _KNOWN_FANZHA:
            dropped += 1
            continue
        # ★自动并入护栏：无载荷（SYN-only/reset/仅握手）节点不升为主报告"公网 IP 建议调证"——
        # 下游 _ip_lead 对 pcap Endpoint 只按公私网给 advice、会绕过这里的态分级，故直接过滤；
        # 它们仍在 pcap 台账（to_report_leads）与原始 floor.pcap 中作"待核"，不静默丢弃。
        if not re.has_payload:
            dropped += 1
            continue
        if re.ip in seen:
            continue
        seen.add(re.ip)
        ja3 = ("，JA3=" + "/".join(sorted(re.ja3))) if re.ja3 else ""
        sni = ("，SNI=" + "/".join(sorted(re.sni))) if re.sni else ""
        endpoints.append(
            Endpoint(
                value=re.ip,
                kind="ip",
                evidences=[
                    Evidence(
                        source=_SOURCE,
                        location="pcap",
                        snippet=(
                            f"->{re.ip}:{re.port}/{re.proto} state={re.state} "
                            f"out={re.out_bytes}B in={re.in_bytes}B pkts={re.packets}{sni}{ja3}"
                        )[:200],
                        observed_at=re.first_ts or None,
                    )
                ],
            )
        )
    if dropped:
        logger.info(
            "[pcap] 自动并入过滤无载荷接入节点 %d 个（SYN-only/连接尝试，留 pcap 台账作待核，不升'建议调证'）",
            dropped,
        )
    # SNI / DNS 域名端点（DNS 域名无 per-query ts，留 None）。
    domain_ts: dict[str, float] = {}
    domains: dict[str, str] = {}
    for f in summary.flows:
        for s in f.sni:
            domains.setdefault(s, "TLS SNI")
            if f.first_ts and (s not in domain_ts or f.first_ts < domain_ts[s]):
                domain_ts[s] = f.first_ts
    for q in summary.dns_queries:
        domains.setdefault(q, "DNS 查询")
    for dom, src in domains.items():
        if dom in seen:
            continue
        seen.add(dom)
        endpoints.append(
            Endpoint(
                value=dom,
                kind="domain",
                evidences=[
                    Evidence(
                        source=_SOURCE,
                        location="pcap",
                        snippet=f"{src}: {dom}",
                        observed_at=domain_ts.get(dom),
                    )
                ],
            )
        )
    return endpoints


def build_ledger_md(summary: PcapSummary) -> str:
    """把 pcap 线索聚成调证台账（markdown），按 IP 接入节点 / 域名 分组。"""
    leads = to_report_leads(summary)
    ips = [l for l in leads if l.category == LeadCategory.IP]
    doms = [l for l in leads if l.category == LeadCategory.DOMAIN]
    lines: list[str] = [
        "# pcap 调证台账（带外抓包线索聚合）",
        "",
        f"接入节点 {len(ips)} 个、域名 {len(doms)} 个、DNS 查询 {len(summary.dns_queries)} 条。",
        "解不开密文也能办案：下列接入节点 IP/SNI 即穿透真源站的调证锚点。",
        "",
        "## 接入节点（IP:port）",
        "> 调证落点：" + _IP_WHERE,
        "",
    ]
    for l in ips:
        lines.append(f"- `{l.value}`  {l.source_refs[0].snippet if l.source_refs else ''}")
    lines.append("")
    lines.append("## 域名（TLS SNI / DNS）")
    lines.append("> 调证落点：" + _DOMAIN_WHERE)
    lines.append("")
    for l in doms:
        lines.append(f"- `{l.value}`  [{l.advice}]  {l.notes}")
    lines.append("")
    return "\n".join(lines)


def to_ledger_dict(summary: PcapSummary) -> dict[str, object]:
    leads = to_report_leads(summary)
    res = remote_endpoints(summary)
    endpoints = [
        {
            "value": f"{re.ip}:{re.port}/{re.proto}",
            "ip": re.ip,
            "port": re.port,
            "proto": re.proto,
            "state": re.state,  # established / syn_only / reset / unknown —— SYN-only 为连接尝试待核
            "out_bytes": re.out_bytes,
            "in_bytes": re.in_bytes,
            "packets": re.packets,
            "connection_count": re.connection_count,
            "sni": sorted(re.sni),
            "no_sni": not re.sni,
        }
        for re in res
    ]
    return {
        "endpoints": [
            {"value": l.value, "advice": l.advice, "snippet": (l.source_refs[0].snippet if l.source_refs else "")}
            for l in leads
            if l.category == LeadCategory.IP
        ],
        "remote_endpoints": endpoints,
        # 按累计字节 / 连接尝试次数排序的 Top（供研判先看谁通信最多、谁被反复拨号）。
        "top_bytes": sorted(
            endpoints, key=lambda e: e["out_bytes"] + e["in_bytes"], reverse=True
        )[:10],
        "top_connections": sorted(endpoints, key=lambda e: e["connection_count"], reverse=True)[:10],
        "domains": [{"value": l.value, "advice": l.advice} for l in leads if l.category == LeadCategory.DOMAIN],
        "dns_queries": sorted(summary.dns_queries),
        "dns_records": [
            {
                "qname": r.qname,
                "qtype": r.qtype,
                "rcode": r.rcode,
                "txid": r.txid,
                "answers": r.answers,
            }
            for r in summary.dns_records
        ],
    }


def merge_into_report_json(report_json_path: str, summary: PcapSummary) -> int:
    """把 pcap 线索合并进 report.json 的 ``leads``。绝不抛，失败返 0。

    - 新键（(category, value) 不存在）→ append，计入返回的 added。
    - 命中已存在键（如静态已抓到同 domain/ip）→ 不丢弃，把 runtime 证据并进原 lead、升为
      ``is_runtime_seen``（静态→活体确认），不计入 added。
    - 落盘走 :func:`atomic_write_text`：写中途失败绝不留半截坏 JSON（保底 return 0）。
    """
    try:
        from apkscan.report import json as report_json

        path = Path(report_json_path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            logger.warning("[pcap] report.json 顶层非 dict，跳过：%s", path)
            return 0
        existing = payload.get("leads")
        if not isinstance(existing, list):
            existing = []
            payload["leads"] = existing
        existing_by_key: dict[tuple[str, str], dict] = {
            (str(item.get("category")), str(item.get("value"))): item
            for item in existing
            if isinstance(item, dict)
        }
        added = 0
        confirmed = 0
        for lead in to_report_leads(summary):
            key = (lead.category.value, lead.value)
            lead_dict = report_json._to_jsonable(lead)
            hit = existing_by_key.get(key)
            if hit is not None:
                # 命中已存在键：不丢弃——把 runtime 证据并进原 lead、升为活体确认。
                if merge_runtime_into_lead_dict(hit, lead_dict):
                    confirmed += 1
                continue
            existing_by_key[key] = lead_dict
            existing.append(lead_dict)
            added += 1
        atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2))
        logger.info("[pcap] 追加 %d 条、runtime 确认 %d 条带外线索进 %s", added, confirmed, path)
        return added
    except (OSError, ValueError):
        logger.exception("[pcap] 读取/解析 report.json 失败：%s", report_json_path)
        return 0
    except Exception:  # noqa: BLE001 - 追加失败不抛
        logger.exception("[pcap] 追加进 report.json 异常：%s", report_json_path)
        return 0
