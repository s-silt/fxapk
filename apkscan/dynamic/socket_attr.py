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
import re
import socket
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

#: /proc/net/tcp 状态码（十六进制）→ 可读名（只列关联用得上的）。
_TCP_STATES = {
    "01": "established", "02": "syn_sent", "03": "syn_recv", "06": "time_wait",
    "08": "close_wait", "0A": "listen",
}


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


@dataclass
class UidSockets:
    """一份 uid_sockets.txt 的解析结果：目标 app UID + 全部 socket 记录 + 远端倒排索引。"""

    target_uid: int | None = None
    package: str | None = None
    entries: list[SocketEntry] = field(default_factory=list)
    #: (remote_ip, remote_port) → 命中的 SocketEntry 列表（同远端可有多条连接）。
    by_remote: dict[tuple[str, int], list[SocketEntry]] = field(default_factory=dict)

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
                res.by_remote.setdefault((e.remote_ip, e.remote_port), []).append(e)
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
        entry = SocketEntry(
            proto=str(obj.get("proto") or "tcp"),
            local_ip=local[0],
            local_port=local[1],
            remote_ip=remote[0],
            remote_port=remote[1],
            state=str(obj.get("state") or ""),
            uid=uid,
            process=process if isinstance(process, str) else None,
            pid=pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
        )
        res.entries.append(entry)
        res.by_remote.setdefault((entry.remote_ip, entry.remote_port), []).append(entry)
    return res


def _apply_ss_line(line: str, res: UidSockets) -> None:
    """从一行 ss -tunp 抽 (进程名,pid) + 远端 addr:port，回填到已有 /proc 记录的 process/pid。绝不抛。"""
    proc = _SS_PROC_RE.search(line)
    if proc is None:
        return
    addrs = _SS_ADDR_RE.findall(line)
    if len(addrs) < 2:
        return
    rip, rport_s = addrs[-1]  # ss 行末通常是 peer（远端）地址
    rip = rip.strip("[]").split("%", 1)[0]  # 剥方括号 + %scope（/proc 解出的 IPv6 不带 scope，须对齐）
    if rip.lower().startswith("::ffff:") and "." in rip:  # v4-mapped 归一化（与 _decode_proc_ipv6 一致）
        rip = rip.rsplit(":", 1)[-1]
    try:
        rport = int(rport_s)
    except ValueError:
        return
    for e in res.by_remote.get((rip, rport), []):
        e.process = proc.group(1)
        e.pid = int(proc.group(2))


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
        hits = sockets.by_remote.get((ip, port))
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
