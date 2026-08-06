"""把带外 pcap 的接入节点【自动绑定到目标 app】——消费 capture 抓的 ``uid_sockets.txt``（纯逻辑，离线可测）。

带外整机 tcpdump 抓的 pcap 是**全机**流量：接入节点 IP:port 里既有目标 app 的真后端，也有系统/其它 app 的
背景噪音。capture 侧已在抓包窗口末抓了一份 ``/proc/net/tcp{,6}`` 快照（``uid_sockets.txt``，含 uid 列 +
十六进制地址端口），但此前只是**原始产物、供人工比对**。本模块把它解析出来，按 (远端 IP, 远端 port) 匹配
pcap 接入节点 → 标出该连接属于哪个 UID、是否 == 目标 app UID，从而**自动区分真后端 vs 背景噪音**。

★纯 stdlib、纯函数、绝不抛：坏行/坏 hex 逐条跳过。设备侧「单次快照→持续时间线」的升级（补短连接）是
capture 侧后续工作；本层只做「解析 + 关联」这一离线可测的消费端。
"""

from __future__ import annotations

import json
import logging
import math
import re
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: /proc/net/tcp 状态码（十六进制）→ 可读名。**列全**：缺映射的状态会以原始 hex
#: 落进 ``SocketEntry.state``，让下游按名字判状态的逻辑（如残留识别）整类失效。
#: 实测遗漏过 ``04``/``05``（两种 FIN_WAIT），它们恰恰是判断连接是否已终止的关键。
_TCP_STATES = {
    "01": "established", "02": "syn_sent", "03": "syn_recv", "04": "fin_wait1",
    "05": "fin_wait2", "06": "time_wait", "07": "close", "08": "close_wait",
    "09": "last_ack", "0A": "listen", "0B": "closing",
}

#: 连接已终止或正在终止的状态。这些状态下 socket 可能已与创建它的进程解绑。
_CLOSING_STATES = frozenset({"time_wait", "fin_wait1", "fin_wait2",
                             "close", "last_ack", "closing"})


def is_orphan_record(entry: "SocketEntry") -> bool:
    """该 socket 记录是否为**无进程持有的残留**（不代表任何主体）。

    ★判据是 ``uid == 0`` **且** 处于终止态，两个条件缺一不可：

    - TCP 进入 TIME_WAIT 后连接已完全关闭，socket 由内核保留 2MSL 等待迟到报文，
      不再属于任何进程，``/proc/net/tcp`` 的 uid 列固定显示 0。FIN_WAIT/LAST_ACK
      等终止中的状态在进程已退出时同样会变成无主（orphan socket）。
    - 但**只看 uid==0 会误伤真正的 root 进程连接**（系统守护进程的 established 连接
      uid 就是 0），只看终止态又会误伤目标 app 自己正在关闭的连接。

    ★为什么要有这个判据：不排除这类记录，**任何反复重连的应用都会被自己的 TIME_WAIT
      残留判成归属歧义**——同一个远端上，活着的连接归目标 app、刚关闭的那批记为 uid=0，
      归因引擎看到两个 UID 就判 ambiguous。2026-08-06 实测：某样本 33 个接入节点里
      13 个因此被判歧义，其中包括通信量最大的两个业务节点，导致它们没有进入结论。

    ★注意 ``close_wait`` **不在**终止态集合里：那是对端已关闭、本端尚未关闭，
      socket 仍由进程持有（实测目标 app 自己就有 close_wait 记录），排除它会丢真证据。
    """
    return entry.uid == 0 and entry.state in _CLOSING_STATES


@dataclass
class SocketEntry:
    """一条内核 socket 表记录（/proc/net/tcp{,6} 一行）。"""

    proto: str  # tcp / tcp6
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str  # established / listen / ...（未知则原始 hex）
    uid: int
    process: str | None = None  # 由 ss -tunp 补（best-effort）
    pid: int | None = None
    #: A2：该 socket 被观测到的时间区间（socket_timeline 周期采样各时刻聚合的 min/max；窗口末快照无
    #: 时间 → None）。供 :func:`attribute_connections` 与 pcap 流的 [first_ts,last_ts] 做时间窗对齐——
    #: floor pcap（设备侧 tcpdump）与 socket 时间线（设备侧 /proc 采样）同设备时钟，可直接区间比较。
    first_ts: float | None = None
    last_ts: float | None = None


@dataclass
class UidSockets:
    """一份 uid_sockets.txt 的解析结果：目标 app UID + 全部 socket 记录 + 倒排索引（远端 / 本地端口连接）。"""

    target_uid: int | None = None
    package: str | None = None
    entries: list[SocketEntry] = field(default_factory=list)
    #: (remote_ip, remote_port) → 命中的 SocketEntry 列表（同远端可有多条连接）。
    by_remote: dict[tuple[str, int], list[SocketEntry]] = field(default_factory=dict)
    #: A2：(proto_family, local_port, remote_ip, remote_port) → SocketEntry 列表。本地临时端口精确定位单条
    #: 连接——同远端多 UID（CDN/网关）时用它把 pcap 流消歧到具体 UID（五元组归因核心）。proto 按 tcp/udp 族
    #: 归一入键：tcp/udp 本地端口空间独立可同号，须分族避免 UDP 流撞 TCP socket 误确证。
    by_conn: dict[tuple[str, int, str, int], list[SocketEntry]] = field(default_factory=dict)

    def owner_of(self, ip: str, port: int) -> SocketEntry | None:
        """按远端 (ip, port) 找拥有该连接的 socket 记录；优先返回目标 UID 的那条。无 → None。

        ★低层访问器（会偏向目标 UID）：归因请用 :func:`attribute_endpoints`——它对同一远端多 UID
        判 ambiguous、不默认强选目标（CDN/网关误归因）。owner_of 仅供需要"某条代表记录"的场景。
        """
        hits = self.by_remote.get((ip, port))
        if not hits:
            return None
        if self.target_uid is not None:
            for e in hits:
                if e.uid == self.target_uid:
                    return e
        return hits[0]


def _decode_proc_ipv4(hex_addr: str) -> str | None:
    """/proc/net/tcp 的 IPv4 十六进制地址（4 字节小端）→ 点分。坏 → None。"""
    if len(hex_addr) != 8:
        return None
    try:
        b = bytes.fromhex(hex_addr)
    except ValueError:
        return None
    return f"{b[3]}.{b[2]}.{b[1]}.{b[0]}"  # 小端存储 → 反转成网络序


def _decode_proc_ipv6(hex_addr: str) -> str | None:
    """/proc/net/tcp6 的 IPv6 十六进制地址（4 个 32 位字，每字小端）→ 压缩 IPv6。坏 → None。"""
    if len(hex_addr) != 32:
        return None
    try:
        raw = bytes.fromhex(hex_addr)
    except ValueError:
        return None
    netbytes = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))  # 每 32 位字内字节反转
    # ★IPv4-mapped（::ffff:a.b.c.d）归一化为点分：Android Java/OkHttp 默认 AF_INET6 双栈，目标 app 的
    #   IPv4 连接只现身 /proc/net/tcp6 且为 v4-mapped，而 pcap 侧是裸点分——不归一则主流量永不匹配（复审 #1）。
    if netbytes[:12] == b"\x00" * 10 + b"\xff\xff":
        return f"{netbytes[12]}.{netbytes[13]}.{netbytes[14]}.{netbytes[15]}"
    try:
        return socket.inet_ntop(socket.AF_INET6, netbytes)
    except (OSError, ValueError):
        return None


def _parse_proc_line(line: str, proto: str) -> SocketEntry | None:
    """解析 /proc/net/{tcp,tcp6,udp,udp6} 的一行数据 → SocketEntry。表头/坏行 → None。

    四者列格式一致（uid 在第 8 列、地址端口十六进制）；udp/udp6 的 st 列语义弱（多为 07 未连接），
    经 _TCP_STATES 未命中则原样保留。proto 以 "6" 结尾 → IPv6 解码（tcp6/udp6）。
    """
    parts = line.split()
    if len(parts) < 8 or ":" not in parts[1] or ":" not in parts[2]:
        return None  # 表头（sl local_address ...）或残行
    try:
        laddr, lport_h = parts[1].rsplit(":", 1)
        raddr, rport_h = parts[2].rsplit(":", 1)
        decode = _decode_proc_ipv6 if proto.endswith("6") else _decode_proc_ipv4
        lip = decode(laddr)
        rip = decode(raddr)
        if lip is None or rip is None:
            return None
        uid = int(parts[7])
        lport = int(lport_h, 16)  # ★端口转换须在 try 内：坏 hex（空/U+FFFD）逐行跳过、不逃逸（复审 #2/#3）
        rport = int(rport_h, 16)
    except (ValueError, IndexError):
        return None
    return SocketEntry(
        proto=proto,
        local_ip=lip,
        local_port=lport,
        remote_ip=rip,
        remote_port=rport,
        state=_TCP_STATES.get(parts[3].upper(), parts[3]),
        uid=uid,
    )


def _proto_family(proto: str) -> str:
    """把 proto 归一到族：``udp``/``udp6`` → ``"udp"``，其余（tcp/tcp6）→ ``"tcp"``。

    ★两点都是取证正确性刚需：①tcp↔tcp6（Android v4-mapped 主路径）须能互配，故不能按精确串匹配；
    ②tcp 与 udp 的本地端口空间**独立、可合法同号**（HTTPS/TCP-443 与 QUIC/UDP-443 常同连一个 CDN IP），
    故必须分族——否则一条 UDP 流会撞上同号 TCP socket 被误"confirmed"成目标（Fable 复审 P1-1）。
    """
    return "udp" if proto.lower().startswith("udp") else "tcp"


def _index_entry(res: UidSockets, e: SocketEntry) -> None:
    """把一条 SocketEntry 挂进两个倒排索引：by_remote（远端二元组）+ by_conn（proto族+本地端口+远端，A2 五元组消歧）。"""
    res.by_remote.setdefault((e.remote_ip, e.remote_port), []).append(e)
    res.by_conn.setdefault((_proto_family(e.proto), e.local_port, e.remote_ip, e.remote_port), []).append(e)


#: ss -tunp 的进程标注：``users:(("chrome",pid=1234,fd=56))``。
_SS_PROC_RE = re.compile(r'\(\("([^"]+)",pid=(\d+)')
#: ss 行里的 addr:port——方括号整体捕获（容纳带 %scope 的链路本地 IPv6，如 [fe80::1%wlan0]:443）。
_SS_ADDR_RE = re.compile(r"(\[[^\]]+\]|[0-9a-fA-F:.]+):(\d+)")


def parse_uid_sockets(text: str) -> UidSockets:
    """解析 capture 抓的 ``uid_sockets.txt`` → UidSockets（目标 UID + socket 记录 + 远端倒排）。绝不抛。

    识别 ``# package=.. uid=..`` 头、``## /proc/net/tcp`` / ``## /proc/net/tcp6`` 段（主数据源，含 uid）、
    以及 ``## ss -tunp`` 段（best-effort 补进程名/pid，按 (远端 ip,port) 回填到已有 /proc 记录）。
    """
    res = UidSockets()
    if not isinstance(text, str):
        return res
    section = ""
    ss_lines: list[str] = []  # ss 段常排在 /proc 之前，缓存到 /proc 全索引后再回填
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("# package="):
            m = re.search(r"package=(\S+)", s)
            if m:
                res.package = m.group(1)
            mu = re.search(r"uid=(\d+)", s)
            if mu:
                res.target_uid = int(mu.group(1))
            continue
        if s.startswith("## "):
            # 顺序要紧：/proc/net/tcp6 含子串 "tcp"、udp6 含 "udp"——先判带 6 的。
            if "/proc/net/udp6" in s:
                section = "udp6"
            elif "/proc/net/udp" in s:
                section = "udp"
            elif "tcp6" in s:
                section = "tcp6"
            elif "/proc/net/tcp" in s:
                section = "tcp"
            elif "ss " in s:
                section = "ss"
            else:
                section = ""
            continue
        if not s:
            continue
        if section in ("tcp", "tcp6", "udp", "udp6"):
            e = _parse_proc_line(s, section)
            if e is not None:
                res.entries.append(e)
                _index_entry(res, e)
        elif section == "ss":
            ss_lines.append(s)
    for s in ss_lines:  # /proc 索引已就绪，回填进程名/pid
        _apply_ss_line(s, res)
    return res


def _split_ip_port(value: object) -> tuple[str, int] | None:
    """拆 JSONL 的 ``ip:port`` / ``[ipv6]:port``。坏值返回 None。"""
    if not isinstance(value, str) or ":" not in value:
        return None
    ip, _, port_text = value.rpartition(":")
    ip = ip.strip().strip("[]")
    if not ip:
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not 0 <= port <= 65535:
        return None
    return ip, port


def parse_socket_timeline(text: str) -> UidSockets:
    """解析周期采样的 ``socket_timeline.jsonl``，合并全部时刻的 socket 观测。绝不抛。

    首行通常是 ``{type, package, target_uid}`` 元数据；其后每行是一条
    ``{ts, proto, uid, local, remote, state}`` 观测。坏 JSON 或坏字段逐行跳过。
    """
    res = UidSockets()
    if not isinstance(text, str):
        return res
    #: 同一 socket（proto+本地+远端+uid）跨时刻的多次观测聚成一条 entry，first_ts/last_ts 取 min/max
    #: 形成观测时间区间（A2 时间窗匹配所需）。多 state（syn_sent→established）也归并为一条。
    agg: dict[tuple[str, str, int, str, int, int], SocketEntry] = {}
    for line in text.splitlines():
        try:
            obj = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "meta":
            package = obj.get("package")
            target_uid = obj.get("target_uid")
            if isinstance(package, str) and package:
                res.package = package
            if isinstance(target_uid, int) and not isinstance(target_uid, bool):
                res.target_uid = target_uid
            continue

        local = _split_ip_port(obj.get("local"))
        remote = _split_ip_port(obj.get("remote"))
        uid = obj.get("uid")
        if local is None or remote is None or not isinstance(uid, int) or isinstance(uid, bool):
            continue
        process = obj.get("process")
        pid = obj.get("pid")
        raw_ts = obj.get("ts")
        ts = float(raw_ts) if isinstance(raw_ts, (int, float)) and not isinstance(raw_ts, bool) else None
        proto = str(obj.get("proto") or "tcp")
        key = (proto, local[0], local[1], remote[0], remote[1], uid)
        entry = agg.get(key)
        if entry is None:
            entry = SocketEntry(
                proto=proto,
                local_ip=local[0],
                local_port=local[1],
                remote_ip=remote[0],
                remote_port=remote[1],
                state=str(obj.get("state") or ""),
                uid=uid,
                process=process if isinstance(process, str) else None,
                pid=pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
                first_ts=ts,
                last_ts=ts,
            )
            agg[key] = entry
            res.entries.append(entry)
            _index_entry(res, entry)
        else:  # 同一 socket 的后续观测：扩时间区间 + 补齐缺失的 process/pid（宁全勿缺）
            _extend_ts(entry, ts, ts)
            if entry.process is None and isinstance(process, str):
                entry.process = process
            if entry.pid is None and isinstance(pid, int) and not isinstance(pid, bool):
                entry.pid = pid
    return res


def _extend_ts(entry: SocketEntry, first_ts: float | None, last_ts: float | None) -> None:
    """把一段观测时间区间并入 entry 的 [first_ts,last_ts]（None 侧忽略）。"""
    if first_ts is not None:
        entry.first_ts = first_ts if entry.first_ts is None else min(entry.first_ts, first_ts)
    if last_ts is not None:
        entry.last_ts = last_ts if entry.last_ts is None else max(entry.last_ts, last_ts)


def _norm_ss_ip(ip: str) -> str:
    """ss 地址归一化到与 /proc 解出的 IP 对齐：剥方括号 + %scope；v4-mapped ::ffff:a.b.c.d → 点分。"""
    ip = ip.strip("[]").split("%", 1)[0]
    if ip.lower().startswith("::ffff:") and "." in ip:
        ip = ip.rsplit(":", 1)[-1]
    return ip


def _apply_ss_line(line: str, res: UidSockets) -> None:
    """从一行 ss -tunp 抽 (进程名,pid) + 本端/远端 addr:port，按**四元组**精确回填到那一条 /proc 记录。绝不抛。

    ★codex 复审 P1：旧实现只按远端 (ip,port) 回填 → 同一远端被多 UID 连时，进程/pid 会被最后处理的 ss 行
    统一覆盖到所有候选记录（张冠李戴、污染 candidates[].process/pid）。改按 (local_ip,local_port,remote_ip,
    remote_port) 唯一定位那条 socket；无唯一对应则不回填（宁缺勿错）。
    """
    proc = _SS_PROC_RE.search(line)
    if proc is None:
        return
    addrs = _SS_ADDR_RE.findall(line)
    if len(addrs) < 2:
        return
    lip, lport_s = addrs[-2]  # ss 行倒数第二 = 本端（local）
    rip, rport_s = addrs[-1]  # 行末 = peer（远端）
    lip, rip = _norm_ss_ip(lip), _norm_ss_ip(rip)
    try:
        lport, rport = int(lport_s), int(rport_s)
    except ValueError:
        return
    for e in res.by_remote.get((rip, rport), []):
        if e.local_ip == lip and e.local_port == lport:  # 四元组唯一匹配 → 只回填这一条
            e.process = proc.group(1)
            e.pid = int(proc.group(2))


def merge_uid_sockets(*tables: UidSockets) -> UidSockets:
    """合并多份 UidSockets（去重、重建 by_remote），target_uid/package 取首个非空。绝不抛。

    ★codex 复审 P0：归因**必须含竞争 UID**。持续时间线（_SocketSampler）**只采目标 UID**——单用它做归因，
    目标与其它 UID 连同一远端时时间线只见目标 UID，会误判 confident、歧义失效。故须与**窗口末快照**（含全
    UID）合并：快照给竞争视图、时间线补目标短连。按 (proto,local,remote,uid) 五元组+uid 去重（同一 socket
    在时间线多时刻/快照里重复只记一次，避免 candidates 连接数虚高）。
    """
    out = UidSockets()
    seen: dict[tuple[str, str, int, str, int, int], SocketEntry] = {}
    for t in tables:
        if out.target_uid is None and t.target_uid is not None:
            out.target_uid = t.target_uid
        if not out.package and t.package:
            out.package = t.package
        for e in t.entries:
            key = (e.proto, e.local_ip, e.local_port, e.remote_ip, e.remote_port, e.uid)
            kept = seen.get(key)
            if kept is None:
                kept = replace(e)  # ★拷贝：下面会就地扩时间区间/补 process，绝不能改到输入表的 entry（保"纯函数"，Fable 复审 P2-2）
                seen[key] = kept
                out.entries.append(kept)
                _index_entry(out, kept)
            else:  # 同一 socket 跨源/跨时刻重复：并入时间区间 + 补缺失 process/pid，别让一源无时间戳丢掉另一源的
                _extend_ts(kept, e.first_ts, e.last_ts)
                if kept.process is None and e.process:
                    kept.process = e.process
                if kept.pid is None and e.pid is not None:
                    kept.pid = e.pid
    return out


def attribute_endpoints(
    endpoints: list[tuple[str, int]], sockets: UidSockets
) -> dict[tuple[str, int], dict]:
    """把 pcap 接入节点 (ip, port) 列表关联到 app。未匹配到 socket 记录的端点不入结果。绝不抛。

    ★复审加固：**只有远端 (ip,port)** 时不能默认强选目标 UID——CDN / 大型 API 网关 / 公有云上目标 app、
    系统 WebView、其它 app 常连**同一** remote:443。故按拥有该远端连接的**去重 UID 数**分两路：

    - 单一 UID → ``attribution="confident"``：``{uid, is_target_app, process, pid, attribution, matched_by}``。
    - ≥2 个 UID → ``attribution="ambiguous"``：``is_target_app=None``（仅远端无法定夺）+ ``candidates``
      （按连接数降序，各含 uid/connections/is_target_app/process/pid）+ ``target_uid_among_candidates``，
      **不把混连流量单独归给目标**。（五元组 proto+local:port + 时间窗可进一步消歧，属后续。）

    ``matched_by=["remote_ip_port"]``：当前仅按远端匹配；后续加五元组/时间窗时并入该列表。
    """
    out: dict[tuple[str, int], dict] = {}
    tgt = sockets.target_uid
    for ip, port in endpoints:
        raw = sockets.by_remote.get((ip, port))
        if not raw:
            continue
        # 与 attribute_connections 同一条判据：无主残留不参与 UID 竞争，
        # 否则应用自己刚关闭的连接会以 uid=0 冒充第二个主体。见 is_orphan_record。
        hits = [e for e in raw if not is_orphan_record(e)]
        if not hits:
            continue
        by_uid: dict[int, SocketEntry] = {}
        for e in hits:
            by_uid.setdefault(e.uid, e)  # 每 UID 留首条作代表（进程/pid）
        if len(by_uid) == 1:
            uid, e = next(iter(by_uid.items()))
            out[(ip, port)] = {
                "uid": uid,
                "is_target_app": tgt is not None and uid == tgt,
                "process": e.process,
                "pid": e.pid,
                "attribution": "confident",
                "matched_by": ["remote_ip_port"],
            }
        else:
            candidates = sorted(
                (
                    {
                        "uid": u,
                        "connections": sum(1 for e in hits if e.uid == u),
                        "is_target_app": tgt is not None and u == tgt,
                        "process": e.process,
                        "pid": e.pid,
                    }
                    for u, e in by_uid.items()
                ),
                key=lambda c: (-c["connections"], c["uid"]),
            )
            out[(ip, port)] = {
                "attribution": "ambiguous",
                "is_target_app": None,  # 仅远端无法定夺——不强选目标（复审：别把其它进程流量归给目标）
                "target_uid_among_candidates": tgt is not None and tgt in by_uid,
                "candidates": candidates,
                "matched_by": ["remote_ip_port"],
            }
    return out


# ---------------------------------------------------------------------------
# A2：五元组（本地临时端口）+ pcap 流时间窗归因，四级评分
# ---------------------------------------------------------------------------


@dataclass
class PcapConn:
    """pcap 侧一条本机→远端连接的观测：本地临时端口 + 流时间区间（floor pcap 帧时钟 = 设备时钟）。"""

    local_port: int
    first_ts: float | None = None
    last_ts: float | None = None


@dataclass
class PcapEndpoint:
    """pcap 侧一个远端接入节点 + 它的全部本机连接（供 A2 五元组+时间窗归因；由 pcap_ingest 侧构造）。"""

    remote_ip: str
    remote_port: int
    proto: str = "tcp"  # tcp / udp：按 _proto_family 归族参与匹配（tcp↔tcp6 互配、tcp/udp 分族防撞号误确证）
    conns: list[PcapConn] = field(default_factory=list)


#: 时间窗重叠默认容差（秒）：socket 采样时刻与 pcap 流首/末包时间的抖动 + 采样周期。
_TIME_TOLERANCE = 2.0


def _known_ts(v: float | None) -> float | None:
    """有效观测时刻：有限正数才算已知。None / <=0（0.0 是 pcap flow / pcapng SPB 的"未知"哨兵）/
    NaN / inf → None——避免把 epoch 0 之类的占位当真时刻，与真实 socket 时钟(约 1.7e9)误判「已知冲突」。"""
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 and math.isfinite(v) else None


def _ts_overlap(entry: SocketEntry, conn: PcapConn, tol: float) -> bool:
    """socket 观测区间与 pcap 流时间区间是否重叠（含容差）。任一侧时刻未知 → False（无法佐证，不否定）。"""
    e0, e1 = _known_ts(entry.first_ts), _known_ts(entry.last_ts)
    c0, c1 = _known_ts(conn.first_ts), _known_ts(conn.last_ts)
    if e0 is None or e1 is None or c0 is None or c1 is None:
        return False
    return (e1 + tol) >= c0 and (c1 + tol) >= e0


def _ts_known_conflict(entry: SocketEntry, conn: PcapConn, tol: float) -> bool:
    """socket 观测区间与 pcap 流区间是否**已知**不相交（两侧都有有效时间戳、加容差后仍不重叠）。

    任一侧时刻未知（None 或 <=0 哨兵）→ False（未知，不能据此否定）。仅当四个时间戳都有效且区间明确错开时
    才 True——这才是「已知冲突」，用于把「一条早期一次性 socket 观测凭临时端口复用被误确证为一条晚得多的
    pcap 流」从 confirmed 降级（本地临时端口会被后续连接复用，端口相同 + 时间已知错开 = 巧合，非同一连接）。
    """
    e0, e1 = _known_ts(entry.first_ts), _known_ts(entry.last_ts)
    c0, c1 = _known_ts(conn.first_ts), _known_ts(conn.last_ts)
    if e0 is None or e1 is None or c0 is None or c1 is None:
        return False
    return not ((e1 + tol) >= c0 and (c1 + tol) >= e0)


def attribute_connections(
    endpoints: list[PcapEndpoint],
    sockets: UidSockets,
    *,
    time_tolerance: float = _TIME_TOLERANCE,
) -> dict[tuple[str, str, int], dict]:
    """A2：用**五元组（本地临时端口）+ pcap 流时间窗**把 pcap 接入节点归因到 app/UID，四级评分。绝不抛。

    承接 :func:`attribute_endpoints`（仅远端二元组）：pcap 流带本机源端口 + 时间区间（``PcapEndpoint.conns``），
    与设备侧 socket 时间线（本地端口 + 观测时间区间）对齐，把同一远端多 UID（CDN/网关/公有云）的歧义
    尽量消解到具体连接。四级 ``attribution``：

    - ``confirmed``：某 pcap 连接的本地端口在 socket 表精确命中**单一** UID（time_window 命中再加分）——
      该连接由五元组唯一定位到该 UID。**socket 与 pcap 时间戳都在且区间已知不相交的匹配不算数**
      （本地临时端口会被后续连接复用，端口相同但时间已知错开 = 巧合，降级 probable/ambiguous）。
    - ``probable``：远端仅一个 UID 连、但无本地端口精确确证（如仅窗口末快照、pcap 无连接明细）。
    - ``ambiguous``：远端多 UID，本地端口/时间窗仍无法收敛到单一 winner——给带 ``score`` 的 candidates，不强选目标。
    - ``unattributed``：pcap 有该接入节点，但 socket 表无任何对应记录——**显式记录**而非静默丢弃。

    结果 dict 键 ``(proto_family, remote_ip, remote_port)``——含 proto 族，避免同 ip:port 的 tcp/udp 接入节点
    互相覆盖（Fable 复审 P1-2）。``score`` 为 0–1 置信度（ambiguous 为 None，分数在各 candidate 上）。
    """
    out: dict[tuple[str, str, int], dict] = {}
    tgt = sockets.target_uid
    for ep in endpoints:
        fam = _proto_family(ep.proto)
        key = (fam, ep.remote_ip, ep.remote_port)
        # 远端命中后按 proto 族过滤：tcp 接入节点只认 tcp/tcp6 socket、udp 只认 udp/udp6——tcp/udp 本地端口
        # 空间独立可同号，不分族会把别的 app 的 UDP 流撞进目标 TCP socket 误确证（Fable 复审 P1-1）。
        raw_hits = [e for e in (sockets.by_remote.get((ep.remote_ip, ep.remote_port)) or []) if _proto_family(e.proto) == fam]
        # ★先剔除无主残留（uid=0 且处于终止态），再谈"有几个 UID 在竞争"。
        #   不剔的话，目标 app 自己刚关闭的那批连接会以 uid=0 的身份成为"第二个候选"，
        #   把它自己的节点判成归属歧义——实测该误判吃掉了通信量最大的两个业务节点。
        #   残留数量单独记下来：它是"这个远端被反复连过"的旁证，不该静默丢弃。
        hits = [e for e in raw_hits if not is_orphan_record(e)]
        n_orphan = len(raw_hits) - len(hits)
        if not hits:
            out[key] = {"attribution": "unattributed", "is_target_app": None, "score": 0.0,
                        "matched_by": [],
                        **({"orphan_records": n_orphan} if n_orphan else {})}
            continue
        by_uid: dict[int, SocketEntry] = {}
        for e in hits:
            by_uid.setdefault(e.uid, e)
        target_among = tgt is not None and tgt in by_uid
        # ① 本地临时端口精确匹配：逐 pcap 连接用 by_conn（同 proto 族）定位 socket，按 UID 汇总时间命中。
        #   区分三态——「时间重叠」加分、「时间未知」不否定、「时间已知冲突」（端口复用巧合）不算有效确证。
        precise: dict[int, dict] = {}
        for conn in ep.conns:
            for e in sockets.by_conn.get((fam, conn.local_port, ep.remote_ip, ep.remote_port), []):
                if is_orphan_record(e):
                    continue      # 同上：残留记录不参与本地端口确证
                rec = precise.setdefault(e.uid, {"entry": e, "time_hits": 0, "nonconflict_hits": 0})
                if _ts_overlap(e, conn, time_tolerance):
                    rec["time_hits"] += 1
                    rec["nonconflict_hits"] += 1
                elif not _ts_known_conflict(e, conn, time_tolerance):
                    rec["nonconflict_hits"] += 1
        # 仅"时间重叠"或"时间未知"的本地端口匹配才算有效确证；某 UID 的全部匹配都是已知时间冲突 → 不得作 winner。
        precise_valid = {uid: rec for uid, rec in precise.items() if rec["nonconflict_hits"] > 0}
        if len(precise_valid) == 1:  # 本地端口唯一定位到单一 UID（且非已知时间冲突）→ confirmed
            uid, rec = next(iter(precise_valid.items()))
            e = rec["entry"]
            matched_by = ["remote_ip_port", "local_port"]
            score = 0.7
            if rec["time_hits"]:
                matched_by.append("time_window")
                score = 0.95
            out[key] = {
                "uid": uid,
                "is_target_app": tgt is not None and uid == tgt,
                "process": e.process,
                "pid": e.pid,
                "attribution": "confirmed",
                "score": score,
                # ★即便这条流确属某非目标 UID，也保留"目标 app 也连过该远端"的提示——否则下游按 is_target_app
                #   分拣会把"目标也连的真后端"整段当背景噪音丢掉（Fable 复审 P2-1 取证假阴性）。
                "target_uid_among_candidates": target_among,
                "matched_by": matched_by,
                **({"orphan_records": n_orphan} if n_orphan else {}),
            }
            continue
        # ② 无有效本地端口确证（无命中，或命中均为已知时间冲突）+ 远端仅一个 UID → probable。
        if not precise_valid and len(by_uid) == 1:
            uid, e = next(iter(by_uid.items()))
            out[key] = {
                "uid": uid,
                "is_target_app": tgt is not None and uid == tgt,
                "process": e.process,
                "pid": e.pid,
                "attribution": "probable",
                "score": 0.5,
                "matched_by": ["remote_ip_port"],
                **({"orphan_records": n_orphan} if n_orphan else {}),
            }
            continue
        # ③ 多 UID（含"多本地端口分属不同 UID"）→ ambiguous + 带 score 的 candidates，不强选目标。
        total = len(hits)
        candidates: list[dict] = []
        for u, e in by_uid.items():
            conns = sum(1 for h in hits if h.uid == u)
            rec = precise_valid.get(u)
            score = 0.2 + 0.2 * (conns / total if total else 0.0)
            if rec:
                score += 0.4
                if rec["time_hits"]:
                    score += 0.2
            candidates.append({
                "uid": u,
                "connections": conns,
                "is_target_app": tgt is not None and u == tgt,
                "process": e.process,
                "pid": e.pid,
                "score": round(min(score, 1.0), 2),
            })
        candidates.sort(key=lambda c: (-c["score"], -c["connections"], c["uid"]))
        matched_by = ["remote_ip_port"]
        if precise_valid:
            matched_by.append("local_port")
        out[key] = {
            "attribution": "ambiguous",
            "is_target_app": None,
            "target_uid_among_candidates": target_among,
            "candidates": candidates,
            "score": None,
            "matched_by": matched_by,
            **({"orphan_records": n_orphan} if n_orphan else {}),
        }
    return out


# ---------------------------------------------------------------------------
# 从 socket 快照文件直接归因一份 pcap —— capture 与 pcap-leads 的**共用入口**
# ---------------------------------------------------------------------------
def load_socket_tables(paths: "Sequence[Path | str]") -> tuple["UidSockets | None", list[str]]:
    """读若干 socket 快照/时间线文件 → 合并后的 :class:`UidSockets` + 实际用到的文件名。

    ★同时认两种格式：``socket_timeline``（``_SocketSampler`` 采样，只含目标 UID、补短连）
      与 ``uid_sockets.txt``（窗口末快照，含全 UID）。**两者要合并**——只用 target-only
      的时间线，同远端多 UID 时会误判成 confident（codex 复审 P0 的原结论）。

    解析不出记录的文件不计入。全都读不到 → ``(None, [])``。绝不抛。
    """
    parsed: list[UidSockets] = []
    names: list[str] = []
    for raw in paths or ():
        try:
            p = Path(raw)
            if not p.is_file():
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.warning("[socket_attr] socket 快照读取失败，跳过：%s", raw)
            continue
        # 时间线与快照的头部不同，两个解析器都试一遍，取解出记录多的那个——
        # 文件名不可靠（改名/复制很常见），按内容判才稳。
        best: UidSockets | None = None
        for fn in (parse_socket_timeline, parse_uid_sockets):
            try:
                got = fn(text)
            except Exception:  # noqa: BLE001 - 单个文件解析失败不阻断其余
                continue
            if got.entries and (best is None or len(got.entries) > len(best.entries)):
                best = got
        if best is not None:
            parsed.append(best)
            names.append(Path(raw).name)
    if not parsed:
        return None, []
    table = parsed[0] if len(parsed) == 1 else merge_uid_sockets(*parsed)
    return table, names


def attribute_remote_endpoints(remotes: "Sequence[Any]", table: "UidSockets") -> dict[str, dict]:
    """把 :class:`pcap_ingest.RemoteEndpoint` 列表归因到 UID → ``{"proto/ip:port": 归因}``。

    ★这是 capture 与 pcap-leads **唯一**的归因入口。抽出来是因为两条路径此前各写各的：
      capture 有这套、pcap-leads 压根没有，于是同一份 pcap 经 capture 得到
      ``target_attributed=true``、经 ``pcap-leads --into`` 却写出"runtime 确认 0 条"——
      **同一事实两个结论**，而回灌那条恰恰是把"已确认"降成"没确认"的方向。

    键格式 ``"proto/ip:port"`` 与 ``capture_signals["pcap_app_attribution"]`` 一致，
    下游（closure 门控、报告）不必区分数据是哪条路径来的。
    """
    eps = [
        PcapEndpoint(
            remote_ip=r.ip,
            remote_port=r.port,
            proto=r.proto,
            conns=[
                PcapConn(c.local_port, c.first_ts, c.last_ts)
                for c in getattr(r, "connections", []) or []
            ],
        )
        for r in remotes or ()
    ]
    if not eps:
        return {}
    attr = attribute_connections(eps, table)
    return {f"{proto}/{ip}:{port}": v for (proto, ip, port), v in attr.items()}


def attribution_counts(attr: "Mapping[str, Any]") -> dict[str, int]:
    """四级归因计数 + 归目标 app 的条数。供两条路径打同一句日志/回执。

    ★``is_target_app=None``（歧义/未归因）不得被当 falsy 归进"背景噪音"——
      三类不塌缩是本模块的既有纪律。
    """
    vals = [v for v in (attr or {}).values() if isinstance(v, Mapping)]
    out = {
        kind: sum(1 for v in vals if v.get("attribution") == kind)
        for kind in ("confirmed", "probable", "ambiguous", "unattributed")
    }
    out["total"] = len(vals)
    out["target_app"] = sum(1 for v in vals if v.get("is_target_app") is True)
    # 目标虽不是本条流的所有者、但也连过该远端——按 is_target_app 分拣会整段丢掉，单列出来。
    out["target_among_candidates"] = sum(
        1 for v in vals if v.get("target_uid_among_candidates") is True
    )
    return out
