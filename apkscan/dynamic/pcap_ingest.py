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
from apkscan.network.fingerprints import KNOWN_INTERCEPT_IPS as _KNOWN_FANZHA
from apkscan.network.fingerprints import (  # noqa: F401 — public re-export (capture/closure/tests use pcap_ingest.is_known_intercept_ip)
    is_known_intercept_ip,
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
    # QUIC（HTTP/3）长包头明文元数据（RFC 9000 §17.2，纯 stdlib、无需解密）——供 h3 归因 + 按连接 ID
    # 跨 IP 迁移/NAT 重绑关联（五元组聚合做不到）。各 set 有 per-flow 上限（见 _MAX_QUIC_CIDS）。
    quic_versions: set[str] = field(default_factory=set)
    quic_dcids: set[str] = field(default_factory=set)
    quic_scids: set[str] = field(default_factory=set)
    alpn: set[str] = field(default_factory=set)  # ALPN 协商协议（h3/h2/http1.1）——QUIC Initial 解出


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
# 常量与判定已上移至 apkscan.network.fingerprints（供 pcap ingest 与归因桥接共用），此处经上方
# import 以 _KNOWN_FANZHA / is_known_intercept_ip 别名保留原有引用。


@dataclass
class ConnObs:
    """A2：一条本机↔远端连接的观测——本机临时端口 + pcap 流时间区间。供 socket_attr 五元组+时间窗归因
    把该远端消歧到具体 UID（floor pcap 帧时钟 = 设备时钟，可与设备侧 socket 观测区间直接比对）。"""

    local_port: int
    first_ts: float = 0.0
    last_ts: float = 0.0


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
    quic_versions: set[str] = field(default_factory=set)  # 该远端观测到的 QUIC 版本（h3 归因）
    alpn: set[str] = field(default_factory=set)  # ALPN 协商协议（h3/h2）——QUIC Initial 解出
    #: A2：每本机端口一条连接观测（本地端口 + 时间窗），供五元组归因消歧到 UID。connection_count 仍是
    #: 计数（可含同端口不同本机 IP），connections 按本地端口聚合两方向的时间区间。
    connections: list[ConnObs] = field(default_factory=list)

    @property
    def has_payload(self) -> bool:
        return self.out_bytes > 0 or self.in_bytes > 0


@dataclass
class PcapSummary:
    flows: list[Flow] = field(default_factory=list)
    dns_queries: set[str] = field(default_factory=set)
    dns_records: list[DnsRecord] = field(default_factory=list)
    #: 解析状态——让调用方区分「采集/解析失败」与「真实零业务流量」（二者过去都是空 flows）。
    #: ok=正常解析（flows 可为空=真零流量）；read_error=文件读失败；unparseable=非 pcap/pcapng（坏 magic/过短）；
    #: parse_error=解析中途异常。失败态时 flows 通常为空但**不代表**零流量，closure/pcap-leads 据此不误判。
    parse_status: str = "ok"
    error: str | None = None


# ---------------------------------------------------------------------------
# 解析入口
# ---------------------------------------------------------------------------


def _has_pcap_magic(data: bytes) -> bool:
    """前 4 字节是否 pcap/pcapng magic（经典 µs/ns 大小端 + pcapng SHB）。"""
    return len(data) >= 4 and data[:4] in (
        b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d", b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a",
    )


def parse_pcap(path: str) -> PcapSummary:
    """读 pcap 文件并解析；文件缺失/坏 → **带失败态**的 summary（不抛）。"""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        logger.exception("[pcap] 读取 pcap 失败：%s", path)
        return PcapSummary(parse_status="read_error", error=f"{type(exc).__name__}: {exc}")
    return parse_pcap_bytes(data)


def parse_pcap_bytes(data: bytes) -> PcapSummary:
    """解析 pcap/pcapng 字节，聚合出 flows + DNS 查询。绝不抛。失败态写 parse_status/error。"""
    summ = PcapSummary()
    if not _has_pcap_magic(data):
        # 坏 magic / 过短 = 非 pcap/pcapng：显式标失败，不与「合法零流量」混同（否则 pcap-leads 误判采集成功）。
        summ.parse_status = "unparseable"
        summ.error = f"unrecognized magic {data[:4].hex()}" if data else "empty input"
        return summ
    # 有效 magic 但连头都放不下 = 截断文件：也标失败，别当「零流量」（经典全局头 24B、pcapng 最小 SHB 28B）。
    min_len = 28 if data[:4] == b"\x0a\x0d\x0d\x0a" else 24
    if len(data) < min_len:
        summ.parse_status = "unparseable"
        summ.error = f"truncated header: {len(data)} bytes (< {min_len})"
        return summ
    flows: dict[tuple, Flow] = {}
    asm = _HelloReassembler()  # 每份 pcap 独立、无模块级态（并行分析器安全）
    qdec = _QuicDecryptor()    # QUIC Initial 解密态（密钥缓存 + CRYPTO 重组），同样每份 pcap 独立
    try:
        for ts, linktype, frame in _iter_frames(data):
            try:
                _process_frame(ts, linktype, frame, flows, summ, asm, qdec)
            except Exception:  # noqa: BLE001 - 单包坏不影响其余
                logger.debug("[pcap] 跳过坏包", exc_info=True)
    except Exception as exc:  # noqa: BLE001 - 整体解析异常也不抛
        logger.exception("[pcap] 解析异常")
        summ.parse_status = "parse_error"
        summ.error = f"{type(exc).__name__}: {exc}"
    # 收尾：对未凑齐的 stitch（snaplen 截断/丢续段）best-effort 捞 SNI 回填对应 Flow（复审 #2：
    # 恢复旧代码对截断 record 能捞出 SNI 的行为，弃 JA3 以不产出算错值）。
    asm.drain()
    for dkey, sni in asm.salvaged:
        f = flows.get(("tcp", *dkey))
        if f is not None:
            f.sni.add(sni)
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


def _pcapng_if_tsresol(idb_body: bytes, endian: str) -> float:
    """从 IDB 选项解析 if_tsresol(code 9) → 时间戳除数。缺省 1e6（微秒）。

    值字节 v：MSB=0 → 10^(v&0x7f) 秒的负幂（如 v=6→µs=1e6、v=9→ns=1e9）；MSB=1 → 2^(v&0x7f)。
    没有它就默认微秒——旧代码对所有 EPB 硬编码 /1e6，遇纳秒(if_tsresol=9)的 pcapng 会把时间戳放大 1000×，
    与 socket 时间线形成假「已知冲突」、把本应 confirmed 的五元组归因误降级。
    """
    # IDB body: linktype(2) reserved(2) snaplen(4) 之后是 options(TLV: code(2) len(2) value 4字节对齐)。
    opt = 8
    while opt + 4 <= len(idb_body):
        code, length = struct.unpack(endian + "HH", idb_body[opt : opt + 4])
        opt += 4
        if code == 0:  # opt_endofopt
            break
        if code == 9 and length >= 1:  # if_tsresol
            v = idb_body[opt]
            return float(2 ** (v & 0x7F)) if (v & 0x80) else float(10 ** (v & 0x7F))
        opt += (length + 3) & ~3  # 4 字节对齐
    return 1e6


def _iter_pcapng(data: bytes) -> Iterator[tuple[float, int, bytes]]:
    """最小 pcapng：按 section 跟踪字节序 + 每接口 linktype/if_tsresol，产出 Enhanced/Simple Packet Block 的帧。"""
    n = len(data)
    if n < 12:
        return
    endian = "<"  # 占位，遇首个 SHB 即按其 byte-order magic 重定
    linktypes: list[int] = []
    tsresols: list[float] = []
    off = 0
    while off + 8 <= n:
        # SHB 的 block type 0x0A0D0D0A 字节序无关（回文）——每遇 SHB 重定本 section 字节序 + 重置接口表
        # （pcapng 允许多 section 用不同字节序；旧代码只在首个 SHB 判一次，后续异序 section 被误解或停止）。
        if data[off : off + 4] == b"\x0a\x0d\x0d\x0a":
            if off + 12 > n:
                break
            endian = "<" if data[off + 8 : off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            linktypes = []
            tsresols = []
        btype, blen = struct.unpack(endian + "II", data[off : off + 8])
        if blen < 12 or off + blen > n:
            break
        body = data[off + 8 : off + blen - 4]
        if btype == 0x00000001:  # IDB: linktype(2) reserved(2) snaplen(4) options...
            if len(body) >= 2:
                linktypes.append(struct.unpack(endian + "H", body[:2])[0])
                tsresols.append(_pcapng_if_tsresol(body, endian))
        elif btype == 0x00000006:  # EPB: interface_id(4) ts_hi(4) ts_lo(4) caplen(4) origlen(4) data
            if len(body) >= 20:
                if_id, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
                # 非法 interface_id（越界或尚无 IDB）= malformed 块：跳过，不借用接口 0 的 linktype/tsresol 误解。
                # linktypes/tsresols 逐 IDB 成对追加，len 一致，故 if_id 合法即两者都可安全索引。
                if if_id < len(linktypes):
                    frame = body[20 : 20 + caplen]
                    yield (((ts_hi << 32) | ts_lo) / tsresols[if_id], linktypes[if_id], frame)
        elif btype == 0x00000003:  # Simple Packet Block：无时间戳 → 0.0（下游按 <=0 = 未知处理，不当真时刻）
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


def _parse_tcp(b: bytes) -> tuple[int, int, int, int, bytes] | None:
    if len(b) < 20:
        return None
    sport, dport = struct.unpack("!HH", b[:4])
    seq = struct.unpack("!I", b[4:8])[0]  # 序列号：跨段 TLS 握手重组用
    flags = b[13]  # TCP 标志字节（FIN/SYN/RST/PSH/ACK…）
    off = (b[12] >> 4) * 4
    if off < 20 or len(b) < off:
        return sport, dport, seq, flags, b""
    return sport, dport, seq, flags, b[off:]


def _parse_udp(b: bytes) -> tuple[int, int, bytes] | None:
    if len(b) < 8:
        return None
    sport, dport = struct.unpack("!HH", b[:4])
    return sport, dport, b[8:]


# ---------------------------------------------------------------------------
# QUIC（HTTP/3）长包头元数据（RFC 9000 §17.2）——纯 stdlib、零解密
# ---------------------------------------------------------------------------
# 现代 App 大量走 QUIC（UDP/443），mitm/frida 全看不到。长包头的 version/DCID/SCID 是**明文**，无需
# 任何密钥即可抽取：拿来做 h3 归因、按连接 ID 跨 IP 迁移/NAT 重绑关联（五元组做不到）、发现 QUIC-only
# 后端。★Initial 解密→SNI 是下一步（需惰性 cryptography），本层只做明文元数据、保住模块"零依赖"承诺。

_MAX_QUIC_CIDS = 8  # 每 Flow 各 QUIC set 上限（防海量连接 ID 撑内存）
#: 已知 QUIC 版本：v1(RFC 9000) / v2(RFC 9369)。★不收 vneg(0)：它由服务端在版本不匹配时回、无 h3 归因
#: 增量（同连接的客户端 Initial 是 v1、照样标 QUIC），且收录 0 会让 NTP 等全零填充协议包假阳（复审 #1/#3）。
_QUIC_KNOWN_VERSIONS = frozenset({0x00000001, 0x6B3343CF})


def _is_quic_version(v: int) -> bool:
    """v 是否像合法 QUIC 版本（挡随机 UDP 假阳）：已知版本 / draft(0xff0000xx) / GREASE(0x?a?a?a?a)。"""
    if v in _QUIC_KNOWN_VERSIONS:
        return True
    if (v & 0xFFFFFF00) == 0xFF000000:  # draft-ietf-quic-transport-xx
        return True
    return (v & 0x0F0F0F0F) == 0x0A0A0A0A  # GREASE（强制版本协商的保留版本）


def _parse_quic_long_header(app: bytes) -> tuple[str, str, str] | None:
    """解析 QUIC 长包头 → (version_hex, dcid_hex, scid_hex)；非 QUIC 长包头 → None。绝不抛。

    只读明文字段（version + 单字节 CID 长度 + CID）——token/length/包号/frame 是解密层的事（本层不碰）。
    """
    try:
        if len(app) < 7:
            return None
        if (app[0] & 0xC0) != 0xC0:  # QUIC 长包头恒 11xxxxxx（长包头位 0x80 + fixed bit 0x40）
            return None
        version = int.from_bytes(app[1:5], "big")
        if not _is_quic_version(version):  # 挡随机 UDP 假阳
            return None
        p = 5
        dcid_len = app[p]
        if dcid_len > 20 or p + 1 + dcid_len > len(app):  # RFC 9000：CID ≤ 20 字节
            return None
        p += 1
        dcid = app[p : p + dcid_len]
        p += dcid_len
        if p >= len(app):
            return None
        scid_len = app[p]
        if scid_len > 20 or p + 1 + scid_len > len(app):
            return None
        p += 1
        scid = app[p : p + scid_len]
        return f"{version:08x}", dcid.hex(), scid.hex()
    except Exception:  # noqa: BLE001 - 坏 QUIC 头不抛
        return None


def _ingest_quic(app: bytes, f: Flow, qdec: "_QuicDecryptor", flow_key: tuple) -> bool:
    """是 QUIC 长包头则抽元数据（+ v1 Initial 尝试解密→SNI/ALPN）填进 Flow、返回 True；否则 False
    （供调用方决定是否再当 DNS 解——内容优先派发）。"""
    meta = _parse_quic_long_header(app)
    if meta is None:
        return False
    version, dcid, scid = meta
    if len(f.quic_versions) < _MAX_QUIC_CIDS:
        f.quic_versions.add(version)
    if dcid and len(f.quic_dcids) < _MAX_QUIC_CIDS:
        f.quic_dcids.add(dcid)
    if scid and len(f.quic_scids) < _MAX_QUIC_CIDS:
        f.quic_scids.add(scid)
    # v1 Initial（type 位 00）且 cryptography 可用 → 解密取 ClientHello 的 SNI/ALPN（QUIC 全密文时唯一
    # 应用层线索，与 TCP「SNI 不丢」对等）。Initial 密钥仅依赖明文 DCID，无需任何会话密钥。
    if version == "00000001" and (app[0] & 0x30) == 0 and qdec.available:
        _ingest_quic_initial(app, f, qdec, flow_key)
    return True


# ---------------------------------------------------------------------------
# QUIC Initial 解密（RFC 9001）：Initial 密钥从公开 DCID 派生 → 去头保护 → AEAD → CRYPTO → ClientHello
# ---------------------------------------------------------------------------
# ★纯取证解析、零注入：Initial 密钥仅依赖**明文** DCID，无需任何会话密钥；1-RTT 应用数据不解（需会话
# 密钥）。cryptography 惰性引入（非 fxapk 声明依赖）——缺库则本层静默禁用、只落 QUIC 元数据，模块其余
# 保持零依赖、绝不抛。密钥派生已对 RFC 9001 §A.1 官方向量（iv/hp）逐字节验证。

_QUIC_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")  # RFC 9001 §5.2 v1
_MAX_QUIC_CRYPTO = 65536   # 单连接 CRYPTO 重组缓冲上限（真实 ClientHello <16KB，封 64KiB）
_MAX_QUIC_PENDING = 512    # 并发 CRYPTO 重组连接上限（超出 FIFO 淘汰最老）
_MAX_QUIC_DONE = 4096      # tombstone 上限
_MAX_QUIC_KEYS = 4096      # Initial 密钥缓存上限（DCID 明文可随时重派生，FIFO 淘汰无正确性代价；防无界 DoS）


def _quic_crypto_available() -> bool:
    """探 cryptography 是否可用（一次性，缺库则 QUIC 解密静默禁用、只落元数据）。"""
    try:
        import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _read_quic_varint(b: bytes, p: int) -> tuple[int, int] | None:
    """RFC 9000 §16 变长整数 → (value, new_offset)；越界 → None。"""
    if p >= len(b):
        return None
    ln = 1 << (b[p] >> 6)
    if p + ln > len(b):
        return None
    val = b[p] & 0x3F
    for i in range(1, ln):
        val = (val << 8) | b[p + i]
    return val, p + ln


def _quic_client_initial_keys(dcid: bytes, cache: dict) -> tuple[bytes, bytes, bytes] | None:
    """RFC 9001 §5.2：客户端原始 DCID → client Initial (key, iv, hp)。缺 cryptography / 失败 → None。缓存。"""
    if dcid in cache:
        return cache[dcid]
    keys: tuple[bytes, bytes, bytes] | None = None
    try:
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.hmac import HMAC
        from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

        def expand(secret: bytes, label: bytes, length: int) -> bytes:
            full = b"tls13 " + label  # RFC 8446 HKDF-Expand-Label 前缀
            info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
            return HKDFExpand(algorithm=SHA256(), length=length, info=info).derive(secret)

        h = HMAC(_QUIC_INITIAL_SALT, SHA256())
        h.update(dcid)
        cs = expand(h.finalize(), b"client in", 32)
        keys = (expand(cs, b"quic key", 16), expand(cs, b"quic iv", 12), expand(cs, b"quic hp", 16))
    except Exception:  # noqa: BLE001 - 密钥派生失败静默降级
        keys = None
    if len(cache) >= _MAX_QUIC_KEYS:
        cache.pop(next(iter(cache)), None)  # FIFO 淘汰最老（复审 #B：防唯一 DCID 洪水撑爆缓存）
    cache[dcid] = keys
    return keys


def _quic_try_decrypt(
    app: bytes, pn_off: int, length: int, keys: tuple[bytes, bytes, bytes]
) -> bytes | None:
    """用给定 (key,iv,hp) 对一个 v1 Initial 去头保护 + AES-128-GCM 解密 → 明文 frames；tag 不符 → None。"""
    try:
        key, iv, hp = keys
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        sample = app[pn_off + 4 : pn_off + 4 + 16]
        # ★AES-ECB 仅用于 RFC 9001 §5.4.1 规定的**头保护掩码**派生（对单个 16B sample 出 5B mask），
        #   非数据加密——QUIC 协议要求，勿按"ECB 泄露结构"误报。
        mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)[:5]  # noqa: S305
        first = app[0] ^ (mask[0] & 0x0F)
        pnl = (first & 0x03) + 1
        if pn_off + pnl > len(app):
            return None
        pn_bytes = bytes(app[pn_off + i] ^ mask[1 + i] for i in range(pnl))
        header = bytes([first]) + app[1:pn_off] + pn_bytes  # AAD = 去保护后的完整头
        ct = app[pn_off + pnl : pn_off + length]
        nonce = bytes(x ^ y for x, y in zip(iv, b"\x00" * (12 - pnl) + pn_bytes))
        return AESGCM(key).decrypt(nonce, ct, header)  # tag 不符则抛 → None（天然过滤坏包/错密钥）
    except Exception:  # noqa: BLE001
        return None


def _decrypt_quic_initial(
    app: bytes, qdec: "_QuicDecryptor", flow_key: tuple
) -> tuple[tuple, bytes] | None:
    """解 v1 Initial → (重组桶键=flow_key, 明文 frames)。AEAD 失败/非 v1/坏包 → None。绝不抛。

    ★RFC 9001 §5.2：整条连接的 Initial 密钥固定由客户端**首个** DCID 派生（DCID 切换后不变，仅 Retry
    重算）。故按候选序试：已记录的连接原始 DCID 优先（覆盖 §7.2 服务端回包后切 DCID 的重传），回退本包
    DCID（覆盖首包 / Retry 重派生）；某候选 AEAD 成功即记住它。重组按 flow_key 分桶（非 per-packet DCID，
    否则切换后同连接被劈成两桶永不凑齐，复审 #A）。
    """
    try:
        if len(app) < 7 or (app[0] & 0xC0) != 0xC0 or int.from_bytes(app[1:5], "big") != 1:
            return None
        p = 5
        dl = app[p]
        p += 1
        if dl > 20 or p + dl > len(app):
            return None
        dcid = app[p : p + dl]
        p += dl
        if p >= len(app):
            return None
        sl = app[p]
        p += 1
        if sl > 20 or p + sl > len(app):
            return None
        p += sl  # 跳 SCID
        tv = _read_quic_varint(app, p)  # token length
        if tv is None:
            return None
        token_len, p = tv
        p += token_len
        lv = _read_quic_varint(app, p)  # length（= 包号 + 载荷含 16B AEAD tag）
        if lv is None:
            return None
        length, p = lv
        pn_off = p
        if pn_off + 4 + 16 > len(app) or pn_off + length > len(app) or length < 20:
            return None
        prior = qdec.conn_dcid.get(flow_key)
        seen: set[bytes] = set()
        for cand in (prior, dcid):  # 连接原始 DCID 优先，回退本包 DCID
            if cand is None or cand in seen:
                continue
            seen.add(cand)
            keys = _quic_client_initial_keys(cand, qdec.key_cache)
            if keys is None:
                continue
            plain = _quic_try_decrypt(app, pn_off, length, keys)
            if plain is not None:
                if len(qdec.conn_dcid) >= _MAX_QUIC_PENDING:
                    qdec.conn_dcid.pop(next(iter(qdec.conn_dcid)), None)  # FIFO 有界
                qdec.conn_dcid[flow_key] = cand  # 记住成功的连接 DCID（Retry 回退成功时自动更新）
                return flow_key, plain
        return None
    except Exception:  # noqa: BLE001 - 解密失败（服务端包/非 v1/坏包/无 cryptography）静默 None
        return None


def _collect_crypto_frames(plain: bytes) -> dict[int, bytes]:
    """遍历 QUIC frame 收 CRYPTO(0x06) → {offset: data}。PADDING/PING 跳；未知 frame 停。绝不抛。"""
    chunks: dict[int, bytes] = {}
    try:
        p = 0
        n = len(plain)
        while p < n and len(chunks) < _MAX_OOO_CHUNKS:
            ft = plain[p]
            p += 1
            if ft in (0x00, 0x01):  # PADDING / PING
                continue
            if ft != 0x06:  # 其它 frame（ACK 等结构复杂）→ 停（Initial 里 CRYPTO 通常靠前）
                break
            ov = _read_quic_varint(plain, p)
            if ov is None:
                break
            off, p = ov
            lv = _read_quic_varint(plain, p)
            if lv is None:
                break
            clen, p = lv
            if p + clen > n or clen > _MAX_QUIC_CRYPTO:
                break
            chunks[off] = plain[p : p + clen]
            p += clen
    except Exception:  # noqa: BLE001 - 坏 frame 不抛
        return chunks
    return chunks


@dataclass
class _QuicCryptoState:
    """某 DCID 的 CRYPTO 流重组暂存：自 offset 0 起连续前缀 buf + 乱序段 ooo。"""

    buf: bytearray = field(default_factory=bytearray)
    ooo: dict[int, bytes] = field(default_factory=dict)
    ooo_bytes: int = 0
    needed: int | None = None


class _QuicCryptoReassembler:
    """按 DCID 重组跨 Initial 包/乱序的 CRYPTO 流 → 完整 ClientHello handshake。有界，绝不 OOM。"""

    def __init__(self) -> None:
        self.pending: dict[object, _QuicCryptoState] = {}
        self.done: dict[object, None] = {}

    def _kill(self, dcid: object) -> None:
        self.pending.pop(dcid, None)
        self.done[dcid] = None
        if len(self.done) > _MAX_QUIC_DONE:
            self.done.pop(next(iter(self.done)), None)

    def feed(self, dcid: object, chunks: dict[int, bytes]) -> bytes | None:
        """喂一个 Initial 解出的 CRYPTO 片段集；凑齐 ClientHello 返回其字节，否则 None。绝不抛。"""
        if not chunks or dcid in self.done:
            return None
        st = self.pending.get(dcid)
        if st is None:
            if len(self.pending) >= _MAX_QUIC_PENDING:
                self.pending.pop(next(iter(self.pending)), None)  # FIFO 淘汰最老
            st = _QuicCryptoState()
            self.pending[dcid] = st
        for off in sorted(chunks):
            self._place(st, off, chunks[off])
            if st.ooo_bytes + len(st.buf) > _MAX_QUIC_CRYPTO:
                self._kill(dcid)
                return None
        return self._try_complete(dcid, st)

    def _place(self, st: _QuicCryptoState, off: int, data: bytes) -> None:
        blen = len(st.buf)
        if off == blen:
            st.buf += data
            while len(st.buf) in st.ooo:  # 补洞
                seg = st.ooo.pop(len(st.buf))
                st.ooo_bytes -= len(seg)
                st.buf += seg
        elif off < blen:  # 重叠：first-writer-wins，掐已覆盖前缀
            extra = data[blen - off :]
            if extra:
                st.buf += extra
        elif off <= _MAX_QUIC_CRYPTO and data:  # 乱序超前段（空段不占坑）
            if off not in st.ooo and len(st.ooo) < _MAX_OOO_CHUNKS:
                st.ooo[off] = data
                st.ooo_bytes += len(data)

    def _try_complete(self, dcid: object, st: _QuicCryptoState) -> bytes | None:
        if st.needed is None and len(st.buf) >= 4:
            if st.buf[0] != 0x01:  # 非 client_hello → 弃
                self._kill(dcid)
                return None
            st.needed = 4 + int.from_bytes(bytes(st.buf[1:4]), "big")
            if st.needed > _MAX_QUIC_CRYPTO:
                self._kill(dcid)
                return None
        if st.needed is not None and len(st.buf) >= st.needed:
            hs = bytes(st.buf[: st.needed])
            self._kill(dcid)
            return hs
        return None


class _QuicDecryptor:
    """每份 pcap 一个：QUIC Initial 密钥缓存 + CRYPTO 重组器 + cryptography 可用性（无模块级态）。"""

    def __init__(self) -> None:
        self.key_cache: dict[bytes, tuple[bytes, bytes, bytes] | None] = {}
        self.conn_dcid: dict[tuple, bytes] = {}  # 客户端→服务端流键 → 连接原始 DCID（RFC 9001 §5.2）
        self.reasm = _QuicCryptoReassembler()
        self.available = _quic_crypto_available()


def _ingest_quic_initial(app: bytes, f: Flow, qdec: "_QuicDecryptor", flow_key: tuple) -> None:
    """解 v1 Initial → CRYPTO 重组 → ClientHello 的 SNI/ALPN 填 Flow。任何失败静默降级（仍有元数据）。"""
    try:
        dec = _decrypt_quic_initial(app, qdec, flow_key)
        if dec is None:
            return
        bucket, plain = dec
        hs = qdec.reasm.feed(bucket, _collect_crypto_frames(plain))
        if hs is None:
            return
        sni, _ja3v, alpn = _parse_hs_client_hello(hs)
        if sni:
            f.sni.add(sni)
        for a in alpn[:8]:
            f.alpn.add(a)
    except Exception:  # noqa: BLE001 - QUIC 解密任何异常不抛
        logger.debug("[pcap] QUIC Initial 处理异常（忽略）", exc_info=True)


def _process_frame(
    ts: float, linktype: int, frame: bytes, flows: dict, summ: PcapSummary,
    asm: _HelloReassembler, qdec: "_QuicDecryptor",
) -> None:
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
        sport, dport, seq, tcp_flags, app = tcp_parsed
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
        dkey = (src_ip, sport, dst_ip, dport)
        if (tcp_flags & 0x02) and not (tcp_flags & 0x10):
            # 纯 SYN = 新连接：四元组复用则清该方向旧 stitch/tombstone。否则残留态会把新连接完整落
            # 单段的 ClientHello 引流进重组、按随机 ISN 算错偏移丢弃 → 破坏现有单段解析（复审 #1/#5）。
            asm.reset(dkey)
        # TLS 握手 record：完整落在本段内 → 走今天原样快路径（现有用例字节级不变）；不完整或该方向
        # 已在跨段 stitch 中 → 交定向重组器凑齐 record 再解，让跨段 ClientHello 的 SNI/JA3 不丢。
        r: tuple[str | None, str | None] | None = None
        if app[:1] == b"\x16":
            rec_len = struct.unpack("!H", app[3:5])[0] if len(app) >= 5 else -1
            if rec_len >= 0 and len(app) >= 5 + rec_len and dkey not in asm.pending:
                r = _parse_client_hello(app)
            else:
                r = asm.feed(dkey, seq, app, f.payload_bytes)
        elif app and dkey in asm.pending:  # continuation 段（非 0x16、非空）→ 补洞（空段不入，复审 #6）
            r = asm.feed(dkey, seq, app, f.payload_bytes)
        if r is not None:
            sni, ja3 = r
            if sni:
                f.sni.add(sni)
            if ja3:
                f.ja3.add(ja3)
    if proto_num == 17 and app:
        # 内容优先派发：先看是不是 QUIC 长包头（严格 0xC0 门 + 版本白名单，真 DNS 命不中）——是则抽 QUIC
        # 元数据、**不**再当 DNS（哪怕在 UDP/53：反取证 C2 常把 QUIC 伪装到防火墙放行的 53，复审 #2）；
        # 否则若在 53 端口才当 DNS 解。
        if not _ingest_quic(app, f, qdec, (src_ip, sport, dst_ip, dport)) and (dport == 53 or sport == 53):
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


def _parse_alpn_ext(ev: bytes) -> list[str]:
    """解 ALPN 扩展（RFC 7301）ProtocolNameList → 协议名列表（如 ['h3','h2']）。绝不抛。"""
    out: list[str] = []
    try:
        if len(ev) < 2:
            return out
        total = struct.unpack("!H", ev[:2])[0]
        p = 2
        end = min(2 + total, len(ev))
        while p < end:
            ln = ev[p]
            p += 1
            if ln == 0 or p + ln > end:
                break
            name = ev[p : p + ln].decode("ascii", "replace")
            if name:
                out.append(name)
            p += ln
            if len(out) >= 16:
                break
    except Exception:  # noqa: BLE001 - 坏 ALPN 不抛
        return out
    return out


def _parse_hs_client_hello(hs: bytes) -> tuple[str | None, str | None, list[str]]:
    """解析**裸** TLS handshake ClientHello 消息（无 5 字节 record 头）→ (sni, ja3, alpn)。绝不抛。

    QUIC 的 CRYPTO 流里是裸 handshake（无 record 层）；TCP 侧剥掉 record 头后也复用此函数。
    """
    try:
        if len(hs) < 4 or hs[0] != 0x01:  # client_hello
            return None, None, []
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
        alpn: list[str] = []
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
                elif et == 0x0010:  # ALPN（h3/h2 归因）
                    alpn = _parse_alpn_ext(ev)
                elif et == 0x000A and len(ev) >= 2:
                    curves = _u16_list(ev[2:])
                elif et == 0x000B and ev:
                    formats = list(ev[1:])
        return sni, _ja3(client_ver, ciphers, ext_types, curves, formats), alpn
    except Exception:  # noqa: BLE001 - 解析坏 ClientHello 不抛
        return None, None, []


def _parse_client_hello(rec: bytes) -> tuple[str | None, str | None]:
    """TLS **record** 层 ClientHello → (sni, ja3)（剥 5 字节 record 头后复用 _parse_hs_client_hello）。"""
    try:
        if len(rec) < 5 or rec[0] != 0x16:
            return None, None
        rec_len = struct.unpack("!H", rec[3:5])[0]
        sni, ja3, _alpn = _parse_hs_client_hello(rec[5 : 5 + rec_len])
        return sni, ja3
    except Exception:  # noqa: BLE001 - 解析坏 record 不抛
        return None, None


# ---------------------------------------------------------------------------
# ClientHello 跨段重组（P0 PCAP-first）
# ---------------------------------------------------------------------------
# 现代 Chrome/Cronet 的 ClientHello 常带 post-quantum key_share，超 1460B MSS 跨 2 个 TCP 段 —— 今天
# 逐包解析必丢 SNI/JA3。定向重组器：只在某方向**首个** TLS record 是 client_hello 且跨段时开有界缓冲，
# 按 seq 拼到 record 完整再喂 _parse_client_hello。纯解析、状态有界、绝不抛/绝不 OOM，不动 Flow schema，
# 不碰五元组聚合 / _KNOWN_FANZHA / netstate。顺带修掉：现有 _parse_client_hello 对截断 record 会静默算
# **错** JA3（扩展区没读全就提前退出），凑齐才解析天然消除之。
# ★不做（P1/授权动态分析）：通用双向流重组、HTTP 明文、跨多 record 的握手分片、ServerHello、QUIC。

_MAX_HELLO_BUF = 5 + 16384       # 单 stitch 缓冲上限（TLS 明文 record 上限；buf+ooo 合并计费）
_MAX_OOO_CHUNKS = 64             # 单 stitch 乱序段数上限（防碎段洪水撑 dict）
_MAX_STITCH_PKTS = 256           # 单 stitch 喂段数上限（封死慢速滴灌占坑；MSS≥536 时最大 record ~31 段）
_MAX_PENDING = 512               # 并发 stitch 上限（超出按插入序 FIFO 淘汰最老）
_MAX_DONE = 4096                 # tombstone 上限（防百万连接 pcap 撑爆）
_ANCHOR_MAX_PAYLOAD = 64 * 1024  # 锚窗：某方向累计载荷超此不再当锚（握手只在连接头部，挡长流密文伪锚）


@dataclass
class _HelloState:
    """某方向 ClientHello 跨段重组的暂存态：自 first_seq 起的连续前缀 buf + 乱序段 ooo 补洞。"""

    first_seq: int
    buf: bytearray
    needed: int | None = None  # 5 + rec_len；锚段不足 5 字节读不到时暂 None
    ooo: dict[int, bytes] = field(default_factory=dict)  # 乱序段：相对偏移 → payload
    ooo_bytes: int = 0
    pkts: int = 0


class _HelloReassembler:
    """按方向四元组 (src_ip,sport,dst_ip,dport) 重组跨 TCP 段的 TLS ClientHello（每份 pcap 一个实例）。

    唯一入口 :meth:`feed`：完整落在单段内的 CH 不进这里（调用方走快路径）；只有 record 不完整、或该方向
    已在 stitch 时才进来。重叠段 **first-writer-wins**（取证口径：确定性优先；重传内容一致，构造性不一致
    重叠只让本连接解析失败、不外溢）。任一上限超出 → 判死该状态、退回今天的单段行为，绝不抛、绝不 OOM。
    """

    def __init__(self) -> None:
        self.pending: dict[tuple, _HelloState] = {}
        self.done: dict[tuple, None] = {}
        self.salvaged: list[tuple[tuple, str]] = []  # 判死/EOF 对截断缓冲 best-effort 捞出的 SNI

    def reset(self, key: tuple) -> None:
        """纯 SYN 见新连接 → 清该方向重组残留（四元组复用，旧 stitch/tombstone 必失效，复审 #1/#5）。"""
        self.pending.pop(key, None)
        self.done.pop(key, None)

    def _kill(self, key: tuple) -> None:
        """杀死某方向的 stitch 并落 tombstone（一方向只试一次；tombstone 有上限、满则 FIFO 丢最老）。"""
        self.pending.pop(key, None)
        self.done[key] = None
        if len(self.done) > _MAX_DONE:
            self.done.pop(next(iter(self.done)), None)

    def _salvage(self, key: tuple, st: _HelloState) -> None:
        """record 凑不齐（snaplen 截断/丢续段）前，对已缓冲字节 best-effort 捞 SNI（弃 JA3，避免算错）。"""
        try:
            sni, _ja3 = _parse_client_hello(bytes(st.buf))
        except Exception:  # noqa: BLE001 - 捞 SNI 失败不影响主流程
            sni = None
        if sni:
            self.salvaged.append((key, sni))

    def _abandon(self, key: tuple, st: _HelloState) -> None:
        """判死未完成的 stitch：先 best-effort 捞 SNI 再落 tombstone（超限/丢段路径用）。"""
        self._salvage(key, st)
        self._kill(key)

    def drain(self) -> None:
        """解析结束：对 pending 里所有未完成 stitch best-effort 捞 SNI（不再落 tombstone）。"""
        for key, st in list(self.pending.items()):
            self._salvage(key, st)
        self.pending.clear()

    def feed(
        self, key: tuple, seq: int, app: bytes, flow_payload_bytes: int
    ) -> tuple[str | None, str | None] | None:
        """喂一个 TCP 段。返回 (sni, ja3)（record 凑齐并解析）或 None（还没齐/判死/非 CH）。绝不抛。"""
        try:
            if key in self.done:
                return None  # tombstone 短路：防长流密文里的 0x16 反复重开
            st = self.pending.get(key)
            if st is None:
                return self._anchor(key, seq, app, flow_payload_bytes)
            return self._absorb(key, st, seq, app)
        except Exception:  # noqa: BLE001 - 重组坏包不抛（外层已双保险，这里再兜一层）
            logger.debug("[pcap] ClientHello 重组异常（弃该方向）", exc_info=True)
            self._kill(key)
            return None

    def _anchor(
        self, key: tuple, seq: int, app: bytes, flow_payload_bytes: int
    ) -> tuple[str | None, str | None] | None:
        """锚门：仅当本段是某方向首个 TLS client_hello record（且跨段放不下）才建 stitch。"""
        if len(app) < 2 or app[0] != 0x16 or app[1] != 0x03:
            return None
        # 锚窗：握手只发生在连接头部；本段之前该方向累计载荷已超阈值 → 长流密文伪 0x16，不锚。
        if flow_payload_bytes - len(app) > _ANCHOR_MAX_PAYLOAD:
            return None
        if len(app) >= 6 and app[5] != 0x01:  # 非 client_hello（ServerHello/证书等）从不缓冲
            return None
        needed: int | None = None
        if len(app) >= 5:
            rec_len = struct.unpack("!H", app[3:5])[0]
            if rec_len > 16384:
                return None
            needed = 5 + rec_len
        if len(self.pending) >= _MAX_PENDING:
            old_key = next(iter(self.pending))  # FIFO 淘汰最老 stitch（淘汰前 best-effort 捞 SNI）
            self._salvage(old_key, self.pending.pop(old_key))
        st = _HelloState(first_seq=seq, buf=bytearray(app), needed=needed, pkts=1)
        self.pending[key] = st
        return self._try_complete(key, st)

    def _absorb(
        self, key: tuple, st: _HelloState, seq: int, app: bytes
    ) -> tuple[str | None, str | None] | None:
        """吸收续段/重传/乱序段。"""
        st.pkts += 1
        if st.pkts > _MAX_STITCH_PKTS:
            self._abandon(key, st)
            return None
        rel = (seq - st.first_seq) & 0xFFFFFFFF  # mod 2^32 天然处理 seq 回绕
        self._place(st, rel, app)
        # 补洞：弹出所有起点已被 buf 覆盖/衔接的乱序段（≤ 而非 ==；重叠前缀由 _place 的 rel<blen 掐掉，
        # 否则 repacketize 重传使 buf 一步越过某 ooo key 时该段永不 drain → 记账泄漏/永久洞，复审 #3）。
        while st.ooo:
            k = min(st.ooo)
            if k > len(st.buf):
                break
            seg = st.ooo.pop(k)
            st.ooo_bytes -= len(seg)
            self._place(st, k, seg)
        # 先试完成：本次 feed 已凑齐则切 record 解析，绝不因补洞后总账越限把已完整的 CH 误杀（复审 #4）。
        r = self._try_complete(key, st)
        if r is None and st.ooo_bytes + len(st.buf) > _MAX_HELLO_BUF:
            self._abandon(key, st)
        return r

    def _place(self, st: _HelloState, rel: int, app: bytes) -> None:
        """把一段按相对偏移放入缓冲：contiguous 追加 / 重叠掐前缀 / 超前存 ooo / 窗外丢弃。"""
        blen = len(st.buf)
        if rel == blen:
            st.buf += app
        elif rel < blen:  # 重传/重叠：first-writer-wins，掐掉已覆盖前缀
            extra = app[blen - rel:]
            if extra:
                st.buf += extra
        elif rel <= _MAX_HELLO_BUF and app:  # 乱序超前段：暂存补洞（空段不占坑，否则挡真数据，复审 #6）
            if rel not in st.ooo and len(st.ooo) < _MAX_OOO_CHUNKS:
                st.ooo[rel] = app
                st.ooo_bytes += len(app)
        # rel > _MAX_HELLO_BUF：垃圾/窗外/回绕旧段 → 丢弃

    def _try_complete(
        self, key: tuple, st: _HelloState
    ) -> tuple[str | None, str | None] | None:
        """buf 够长即读 needed、凑齐即切完整 record 喂 _parse_client_hello（一方向只试一次）。"""
        if st.needed is None and len(st.buf) >= 5:
            rec_len = struct.unpack("!H", bytes(st.buf[3:5]))[0]
            if rec_len > 16384:
                self._kill(key)
                return None
            st.needed = 5 + rec_len
        if st.needed is not None and len(st.buf) >= st.needed:
            rec = bytes(st.buf[: st.needed])
            self._kill(key)  # 重协商/多 CH 不管：现实客户端 CH 是一个大 record 跨多段
            return _parse_client_hello(rec)
        return None


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
    #: A2：key → {本机端口: [first_ts, last_ts]}——按本机临时端口聚合两方向 Flow 的时间区间。
    conn_win: dict[tuple[str, str, int], dict[int, list[float]]] = {}

    def _touch(key: tuple[str, str, int], ip: str, port: int, proto: str) -> RemoteEndpoint:
        re = agg.get(key)
        if re is None:
            re = RemoteEndpoint(ip=ip, port=port, proto=proto)
            agg[key] = re
        return re

    def _touch_win(key: tuple[str, str, int], local_port: int, first_ts: float, last_ts: float) -> None:
        w = conn_win.setdefault(key, {}).get(local_port)
        if w is None:
            conn_win[key][local_port] = [first_ts, last_ts]
            return
        if first_ts and (w[0] == 0.0 or first_ts < w[0]):
            w[0] = first_ts
        if last_ts > w[1]:
            w[1] = last_ts

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
            _touch_win(key, f.src_port, f.first_ts, f.last_ts)  # 出站：本机端口 = src_port
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
            _touch_win(key, f.dst_port, f.first_ts, f.last_ts)  # 入站：本机端口 = dst_port
        re.packets += f.packets
        re.quic_versions |= f.quic_versions  # QUIC 版本聚合到远端（两方向共用）
        re.alpn |= f.alpn  # ALPN 聚合到远端
        if f.first_ts and (re.first_ts == 0.0 or f.first_ts < re.first_ts):
            re.first_ts = f.first_ts
        if f.last_ts > re.last_ts:
            re.last_ts = f.last_ts

    for key, re in agg.items():
        re.connection_count = len(conn_src.get(key, set()))
        re.connections = [
            ConnObs(local_port=p, first_ts=w[0], last_ts=w[1])
            for p, w in sorted(conn_win.get(key, {}).items())
        ]
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
        quic = ("，QUIC=" + "/".join(sorted(re.quic_versions))) if re.quic_versions else ""
        if re.alpn:
            quic += "，ALPN=" + "/".join(sorted(re.alpn))
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
                            f"conns={re.connection_count} pkts={re.packets}{sni}{ja3}{quic}"
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
        quic = ("，QUIC=" + "/".join(sorted(re.quic_versions))) if re.quic_versions else ""
        if re.alpn:
            quic += "，ALPN=" + "/".join(sorted(re.alpn))
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
                            f"out={re.out_bytes}B in={re.in_bytes}B pkts={re.packets}{sni}{ja3}{quic}"
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


#: markdown 结构/行内语法字符：嵌不可信字段前逐字符反斜杠转义（含反引号，堵逃逸 inline-code 注入 HTML/链接）。
#: 无正则实现——本模块把 `re` 用作 RemoteEndpoint 循环变量，不引入 re 模块避免撞名。
_MD_SPECIAL_CHARS = frozenset("\\`*_{}[]()#+-.!|>&<~")


def _md_escape(value: object) -> str:
    """markdown 台账里嵌可能含不可信内容的字段（如 error 里的文件路径/解析异常串）前转义：折叠空白 +
    反斜杠转义 markdown 结构/行内语法字符（含反引号），防被渲染成结构/链接或逃逸注入原始 HTML。"""
    collapsed = " ".join(str(value).split())  # 折叠所有空白（含换行）为单空格，堵伪造新行/标题
    return "".join("\\" + ch if ch in _MD_SPECIAL_CHARS else ch for ch in collapsed)


def build_ledger_md(summary: PcapSummary) -> str:
    """把 pcap 线索聚成调证台账（markdown），按 IP 接入节点 / 域名 分组。"""
    leads = to_report_leads(summary)
    ips = [l for l in leads if l.category == LeadCategory.IP]
    doms = [l for l in leads if l.category == LeadCategory.DOMAIN]
    lines: list[str] = [
        "# pcap 调证台账（带外抓包线索聚合）",
        "",
    ]
    if summary.parse_status != "ok":
        # error 可能含文件路径/解析异常串（潜在不可信）→ 转义后再嵌 markdown，别自己开注入面（同 probe-leads 的教训）。
        lines += [
            f"> ⚠ pcap 解析未成功（{_md_escape(summary.parse_status)}：{_md_escape(summary.error)}）——"
            "空结果**不代表零流量**，请核对 pcap 文件完整性/格式后重抓。",
            "",
        ]
    lines += [
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
            "quic_versions": sorted(re.quic_versions),  # h3 归因（明文长包头元数据）
            "alpn": sorted(re.alpn),  # ALPN 协商协议（QUIC Initial 解出，h3/h2）
        }
        for re in res
    ]
    return {
        # 解析状态先行：程序化消费者据此区分「解析/采集失败」与「真实零业务流量」（失败态空 endpoints 不当零流量）。
        "parse_status": summary.parse_status,
        "error": summary.error,
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
