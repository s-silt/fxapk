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
from apkscan.core.models import Confidence, Evidence, Lead, LeadCategory

logger = logging.getLogger(__name__)

_SOURCE = "runtime-pcap"

# TLS GREASE 值（JA3 计算须剔除）：0x0a0a, 0x1a1a, …, 0xfafa。
_GREASE = {(b << 8) | b for b in range(0x0A, 0x100, 0x10)}


@dataclass
class Flow:
    """一条按 5 元组聚合的流。"""

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


@dataclass
class PcapSummary:
    flows: list[Flow] = field(default_factory=list)
    dns_queries: set[str] = field(default_factory=set)


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
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
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
        yield (float(ts_sec) + ts_usec_or_nsec / 1e6, linktype, frame)


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
    if linktype == 113:  # Linux SLL
        if len(frame) < 16:
            return None, b""
        return struct.unpack("!H", frame[14:16])[0], frame[16:]
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


def _parse_tcp(b: bytes) -> tuple[int, int, bytes] | None:
    if len(b) < 20:
        return None
    sport, dport = struct.unpack("!HH", b[:4])
    off = (b[12] >> 4) * 4
    if off < 20 or len(b) < off:
        return sport, dport, b""
    return sport, dport, b[off:]


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
    if proto_num == 6:
        l4info = _parse_tcp(l4)
        proto = "tcp"
    elif proto_num == 17:
        l4info = _parse_udp(l4)
        proto = "udp"
    else:
        return
    if l4info is None:
        return
    sport, dport, app = l4info
    key = (proto, src_ip, sport, dst_ip, dport)
    f = flows.get(key)
    if f is None:
        f = Flow(proto, src_ip, sport, dst_ip, dport, first_ts=ts)
        flows[key] = f
    f.packets += 1
    f.bytes_ += len(frame)
    f.last_ts = ts
    if proto_num == 6 and app[:1] == b"\x16":  # TLS handshake record
        sni, ja3 = _parse_client_hello(app)
        if sni:
            f.sni.add(sni)
        if ja3:
            f.ja3.add(ja3)
    if proto_num == 17 and (dport == 53 or sport == 53):
        qn = _parse_dns_qname(app)
        if qn:
            summ.dns_queries.add(qn)


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


def to_report_leads(summary: PcapSummary) -> list[Lead]:
    """把 pcap summary 转成 report 的 Lead（公网接入节点 IP + SNI/DNS 域名，source=runtime-pcap）。"""
    leads: list[Lead] = []
    seen: set[tuple[str, str]] = set()

    for f in summary.flows:
        if not _ip_public(f.dst_ip):
            continue
        value = f"{f.dst_ip}:{f.dst_port}/{f.proto}"
        key = (LeadCategory.IP.value, value)
        if key in seen:
            continue
        seen.add(key)
        ja3 = ("，JA3=" + "/".join(sorted(f.ja3))) if f.ja3 else ""
        sni = ("，SNI=" + "/".join(sorted(f.sni))) if f.sni else ""
        leads.append(
            Lead(
                category=LeadCategory.IP,
                value=value,
                where_to_request=_IP_WHERE,
                confidence=Confidence.HIGH,
                advice="建议调证",
                source_refs=[
                    Evidence(
                        source=_SOURCE,
                        location="pcap",
                        snippet=f"{f.src_ip}:{f.src_port}->{value} pkts={f.packets}{sni}{ja3}"[:200],
                    )
                ],
                notes="带外 pcap 实测接入节点；即便协议/密文解不开，也能凭此 IP 调证穿透真源站。",
            )
        )

    domains: dict[str, str] = {}
    for f in summary.flows:
        for s in f.sni:
            domains.setdefault(s, "TLS SNI")
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
                source_refs=[Evidence(source=_SOURCE, location="pcap", snippet=f"{src}: {dom}")],
                notes=f"带外 pcap 捕获（{src}）。",
            )
        )
    return leads


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
    return {
        "endpoints": [
            {"value": l.value, "advice": l.advice, "snippet": (l.source_refs[0].snippet if l.source_refs else "")}
            for l in leads
            if l.category == LeadCategory.IP
        ],
        "domains": [{"value": l.value, "advice": l.advice} for l in leads if l.category == LeadCategory.DOMAIN],
        "dns_queries": sorted(summary.dns_queries),
    }


def merge_into_report_json(report_json_path: str, summary: PcapSummary) -> int:
    """把 pcap 线索追加进 report.json 的 ``leads``（去重 by (category, value)）。绝不抛，失败返 0。"""
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
        existing_keys = {
            (str(item.get("category")), str(item.get("value")))
            for item in existing
            if isinstance(item, dict)
        }
        added = 0
        for lead in to_report_leads(summary):
            key = (lead.category.value, lead.value)
            if key in existing_keys:
                continue
            existing_keys.add(key)
            existing.append(report_json._to_jsonable(lead))
            added += 1
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("[pcap] 追加 %d 条带外线索进 %s", added, path)
        return added
    except (OSError, ValueError):
        logger.exception("[pcap] 读取/解析 report.json 失败：%s", report_json_path)
        return 0
    except Exception:  # noqa: BLE001 - 追加失败不抛
        logger.exception("[pcap] 追加进 report.json 异常：%s", report_json_path)
        return 0
