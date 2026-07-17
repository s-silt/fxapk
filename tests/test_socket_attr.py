"""把 pcap 接入节点绑定到 app UID（socket_attr）：解析 uid_sockets.txt + 关联，纯逻辑离线测。"""

from __future__ import annotations

from apkscan.dynamic import socket_attr

# 合成 uid_sockets.txt（capture 抓的格式）：目标 app uid=10234；
#   /proc/net/tcp 两条：1.2.3.4:443 属 uid 10234（真后端），8.8.8.8:53 属 uid 0（系统 DNS，噪音）。
_SAMPLE = """# package=com.fraud.app uid=10234

## ss -tunp（需 root 显进程/UID）
tcp ESTAB 0 0 10.0.2.15:43090 1.2.3.4:443 users:(("com.fraud.app",pid=5678,fd=90))

## /proc/net/tcp（uid 在第 8 列，地址/端口十六进制）
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0F02000A:A852 04030201:01BB 01 00000000:00000000 00:00000000 00000000 10234        0 111
   1: 0F02000A:A853 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 222

## /proc/net/tcp6（uid 在第 8 列）
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 333
"""


def test_decode_proc_ipv4() -> None:
    assert socket_attr._decode_proc_ipv4("04030201") == "1.2.3.4"  # 小端 → 反转
    assert socket_attr._decode_proc_ipv4("0F02000A") == "10.0.2.15"
    assert socket_attr._decode_proc_ipv4("zz") is None  # 坏 hex 不抛


def test_decode_proc_ipv6() -> None:
    # ::1（loopback）在 /proc/net/tcp6：每 32 位字小端；末字 01000000 → 反转 00000001。
    assert socket_attr._decode_proc_ipv6("00000000000000000000000001000000") == "::1"
    assert socket_attr._decode_proc_ipv6("bad") is None


def test_parse_uid_sockets() -> None:
    s = socket_attr.parse_uid_sockets(_SAMPLE)
    assert s.target_uid == 10234 and s.package == "com.fraud.app"
    assert len(s.entries) == 3  # 2 条 tcp + 1 条 tcp6
    e = s.owner_of("1.2.3.4", 443)
    assert e is not None and e.uid == 10234 and e.state == "established"
    assert e.process == "com.fraud.app" and e.pid == 5678  # ss 回填进程名/pid


def test_attribute_endpoints_binds_and_flags_target() -> None:
    s = socket_attr.parse_uid_sockets(_SAMPLE)
    attr = socket_attr.attribute_endpoints([("1.2.3.4", 443), ("8.8.8.8", 53), ("9.9.9.9", 443)], s)
    # 真后端：属目标 app
    assert attr[("1.2.3.4", 443)]["is_target_app"] is True
    assert attr[("1.2.3.4", 443)]["uid"] == 10234
    assert attr[("1.2.3.4", 443)]["process"] == "com.fraud.app"
    # 系统 DNS：非目标 app（背景噪音，据此过滤）
    assert attr[("8.8.8.8", 53)]["is_target_app"] is False and attr[("8.8.8.8", 53)]["uid"] == 0
    # 无 socket 记录的端点不入结果（未归因）
    assert ("9.9.9.9", 443) not in attr


def test_owner_prefers_target_uid_on_shared_remote() -> None:
    # 同一远端被目标 app 与系统各连一次 → owner_of 优先返回目标 UID 的那条。
    txt = (
        "# package=com.x uid=10001\n\n"
        "## /proc/net/tcp\n"
        "  sl  local_address rem_address st ...\n"
        "   0: 0100000A:1000 04030201:01BB 01 00000000:00000000 00:00000000 00000000     0 0 1\n"
        "   1: 0100000A:1001 04030201:01BB 01 00000000:00000000 00:00000000 00000000 10001 0 2\n"
    )
    s = socket_attr.parse_uid_sockets(txt)
    e = s.owner_of("1.2.3.4", 443)
    assert e is not None and e.uid == 10001  # 目标 UID 优先


def test_robust_bad_input() -> None:
    assert socket_attr.parse_uid_sockets("").entries == []
    assert socket_attr.parse_uid_sockets(None).entries == []  # type: ignore[arg-type]
    # 坏行 / 缺列 / 非 hex 逐条跳过，不抛
    junk = "## /proc/net/tcp\ngarbage line\n 0: nothex:1 also:2 01 x x x x x 5 0 1\n"
    assert socket_attr.parse_uid_sockets(junk).entries == []
    assert socket_attr.attribute_endpoints([("1.2.3.4", 443)], socket_attr.UidSockets()) == {}


def test_bad_port_hex_does_not_raise() -> None:
    """★复审 #2/#3：地址 hex 合法但端口坏（空 / 非 hex / U+FFFD）→ 逐行跳过、绝不抛（一行坏不清零全部）。"""
    for badport in (":", ":GGGG", ":01�B"):
        line = f"## /proc/net/tcp\n 0: 0100000A:1000 04030201{badport} 01 x x x x x 10001 0 1\n"
        assert socket_attr.parse_uid_sockets(line).entries == []  # 不抛
    # 同快照里坏行与好行并存 → 只丢坏行、好行照常归因
    mixed = (
        "# package=com.x uid=10001\n## /proc/net/tcp\n"
        "   0: 0100000A:1000 04030201: 01 00000000:00000000 00:00000000 00000000 10001 0 1\n"
        "   1: 0100000A:1001 08080808:01BB 01 00000000:00000000 00:00000000 00000000 10001 0 2\n"
    )
    s = socket_attr.parse_uid_sockets(mixed)
    assert len(s.entries) == 1 and s.owner_of("8.8.8.8", 443) is not None


def test_ipv4_mapped_v6_normalized_and_attributed() -> None:
    """★复审 #1（HIGH）：Android 双栈 → 目标 app IPv4 连接只现身 /proc/net/tcp6 的 v4-mapped 形式，
    须归一化为点分才能与 pcap 侧（裸点分）匹配、把主流量归因到目标 app。"""
    # ::ffff:1.2.3.4 的 /proc/net/tcp6 word-LE 十六进制（末 32 位字 04030201=小端 1.2.3.4）
    assert socket_attr._decode_proc_ipv6("0000000000000000FFFF000004030201") == "1.2.3.4"
    txt = (
        "# package=com.fraud.app uid=10234\n\n"
        "## ss -tunp\n"
        'tcp ESTAB 0 0 [::ffff:10.0.2.15]:43090 [::ffff:1.2.3.4]:443 users:(("com.fraud.app",pid=5678,fd=9))\n'
        "## /proc/net/tcp6（uid 在第 8 列）\n"
        "   0: 0000000000000000FFFF00000F02000A:A852 0000000000000000FFFF000004030201:01BB 01"
        " 00000000:00000000 00:00000000 00000000 10234 0 111\n"
    )
    s = socket_attr.parse_uid_sockets(txt)
    attr = socket_attr.attribute_endpoints([("1.2.3.4", 443)], s)
    assert attr[("1.2.3.4", 443)]["is_target_app"] is True  # 主流量归因到目标 app
    assert attr[("1.2.3.4", 443)]["process"] == "com.fraud.app"  # ss v4-mapped 回填也对齐


def test_scoped_ipv6_ss_backfill() -> None:
    """★复审 #4：ss 里带 %scope 的链路本地 IPv6 peer 正确解析 + 剥 scope，进程回填不断链。"""
    txt = (
        "# package=com.x uid=10001\n## /proc/net/tcp6\n"
        # fe80::1 的 word-LE 十六进制（首字节 fe80..0000、末字 01000000=小端 ::1 段）
        "   0: 000000000000000000000000000000FE:1000 010080FE00000000000000000100000A:01BB 01"
        " 00000000:00000000 00:00000000 00000000 10001 0 1\n"
        "## ss -tunp\n"
        'tcp ESTAB 0 0 [fe80::a]:39000 [fe80::1000:0:0:a01%wlan0]:443 users:(("chrome",pid=11,fd=2))\n'
    )
    s = socket_attr.parse_uid_sockets(txt)  # 不抛即可（scope 剥离逻辑走通）
    assert isinstance(s.entries, list)


def test_parse_socket_timeline_unions_observations_and_skips_bad_lines() -> None:
    """周期采样跨时刻合并远端；坏 JSON / 坏字段只跳过，不清空已有观测。"""
    text = "\n".join(
        [
            '{"type":"meta","package":"com.fraud.app","target_uid":10234}',
            '{"ts":1.0,"proto":"tcp","uid":10234,"local":"10.0.2.15:43090",'
            '"remote":"1.2.3.4:443","state":"established"}',
            "not-json",
            '{"ts":1.2,"proto":"tcp6","uid":10234,"local":"[::1]:43091",'
            '"remote":"[2001:db8::5]:8443","state":"syn_sent"}',
            '{"ts":1.3,"proto":"tcp","uid":"bad","local":"10.0.2.15:1",'
            '"remote":"9.9.9.9:443","state":"established"}',
        ]
    )

    sockets = socket_attr.parse_socket_timeline(text)

    assert sockets.package == "com.fraud.app"
    assert sockets.target_uid == 10234
    assert len(sockets.entries) == 2
    assert sockets.owner_of("1.2.3.4", 443) is not None
    ipv6 = sockets.owner_of("2001:db8::5", 8443)
    assert ipv6 is not None and ipv6.proto == "tcp6" and ipv6.state == "syn_sent"


def test_parse_socket_timeline_robust_bad_input() -> None:
    assert socket_attr.parse_socket_timeline("").entries == []
    assert socket_attr.parse_socket_timeline(None).entries == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ★外部复审：归因准确性——共享远端多 UID 标 ambiguous（不强选目标）+ UDP/udp6 归因（QUIC）
# ---------------------------------------------------------------------------
def test_attribute_endpoints_confident_single_uid_schema() -> None:
    """单一 UID 拥有该远端 → attribution=confident + matched_by=[remote_ip_port]，is_target_app 仍确定。"""
    s = socket_attr.parse_uid_sockets(_SAMPLE)
    a = socket_attr.attribute_endpoints([("1.2.3.4", 443)], s)[("1.2.3.4", 443)]
    assert a["attribution"] == "confident" and a["matched_by"] == ["remote_ip_port"]
    assert a["is_target_app"] is True and a["uid"] == 10234


def test_attribute_endpoints_ambiguous_on_shared_remote_multiuid() -> None:
    """★同一远端(CDN/大型网关/公有云)被目标 app 与其它进程各连 → 不默认强选目标，标 ambiguous + candidates。"""
    txt = (
        "# package=com.x uid=10001\n## /proc/net/tcp\n"
        "   0: 0100000A:1000 04030201:01BB 01 00000000:00000000 00:00000000 00000000     0 0 1\n"  # 系统 uid 0
        "   1: 0100000A:1001 04030201:01BB 01 00000000:00000000 00:00000000 00000000 10001 0 2\n"  # 目标
        "   2: 0100000A:1002 04030201:01BB 01 00000000:00000000 00:00000000 00000000 10001 0 3\n"  # 目标再一条
    )
    s = socket_attr.parse_uid_sockets(txt)
    a = socket_attr.attribute_endpoints([("1.2.3.4", 443)], s)[("1.2.3.4", 443)]
    assert a["attribution"] == "ambiguous"
    assert a["is_target_app"] is None  # ★仅远端无法定夺——不把混连流量归给目标
    assert a["target_uid_among_candidates"] is True
    assert {c["uid"] for c in a["candidates"]} == {0, 10001}
    assert a["candidates"][0]["uid"] == 10001 and a["candidates"][0]["connections"] == 2  # 连接数降序


def test_udp_section_parsed_and_attributed() -> None:
    """★/proc/net/udp 也解析（QUIC/HTTP3 = UDP）→ 给 UDP/443 流做 UID 归因（此前只覆盖 TCP）。"""
    txt = (
        "# package=com.q uid=10055\n## /proc/net/udp（uid 在第 8 列）\n"
        "  sl  local_address rem_address st ...\n"
        "   0: 0100000A:C000 04030201:01BB 07 00000000:00000000 00:00000000 00000000 10055 0 9\n"
    )
    s = socket_attr.parse_uid_sockets(txt)
    assert len(s.entries) == 1 and s.entries[0].proto == "udp"
    a = socket_attr.attribute_endpoints([("1.2.3.4", 443)], s)[("1.2.3.4", 443)]
    assert a["uid"] == 10055 and a["is_target_app"] is True and a["attribution"] == "confident"


def test_udp6_v4mapped_parsed_and_normalized() -> None:
    """/proc/net/udp6 的 v4-mapped 也按 tcp6 同法解码归一为点分。"""
    txt = (
        "# package=com.q uid=10055\n## /proc/net/udp6\n"
        "   0: 000000000000000000000000FFFF020F:C000 0000000000000000FFFF000004030201:01BB 07"
        " 00000000:00000000 00:00000000 00000000 10055 0 9\n"
    )
    s = socket_attr.parse_uid_sockets(txt)
    assert len(s.entries) == 1 and s.entries[0].proto == "udp6" and s.entries[0].remote_ip == "1.2.3.4"


# ---------------------------------------------------------------------------
# ★codex CLI 复核坐实的 P0/P1：merge(时间线+快照) 才能触发歧义；ss 回填按四元组不跨 UID
# ---------------------------------------------------------------------------
def test_merge_timeline_and_snapshot_enables_ambiguity() -> None:
    """★codex P0：target-only 时间线单用会误判 confident；与含竞争 UID 的末快照 merge 后才触发 ambiguity。"""
    tl = socket_attr.parse_socket_timeline(
        '{"type":"meta","package":"com.x","target_uid":10001}\n'
        '{"ts":1,"proto":"tcp","uid":10001,"local":"10.0.2.15:1000","remote":"1.2.3.4:443","state":"established"}\n'
    )
    snap = socket_attr.parse_uid_sockets(
        "# package=com.x uid=10001\n## /proc/net/tcp\n"
        "   0: 0F02000A:03E8 04030201:01BB 01 00000000:00000000 00:00000000 00000000 10001 0 1\n"
        "   1: 0F02000A:03E9 04030201:01BB 01 00000000:00000000 00:00000000 00000000     0 0 2\n"  # 系统 uid 0 竞争
    )
    only_tl = socket_attr.attribute_endpoints([("1.2.3.4", 443)], tl)[("1.2.3.4", 443)]
    assert only_tl["attribution"] == "confident"  # 单用 target-only 时间线看不到竞争 UID（codex 指出的失效）
    merged = socket_attr.merge_uid_sockets(tl, snap)
    a = socket_attr.attribute_endpoints([("1.2.3.4", 443)], merged)[("1.2.3.4", 443)]
    assert a["attribution"] == "ambiguous" and a["is_target_app"] is None  # merge 后见竞争 → 歧义
    assert {c["uid"] for c in a["candidates"]} == {0, 10001}


def test_merge_dedups_same_socket_across_tables() -> None:
    """merge 按五元组+uid 去重：同一 socket 在时间线多时刻/快照重复，连接数不虚高。"""
    tl = socket_attr.parse_socket_timeline(
        '{"type":"meta","package":"com.x","target_uid":10001}\n'
        '{"ts":1,"proto":"tcp","uid":10001,"local":"10.0.2.15:1000","remote":"1.2.3.4:443","state":"established"}\n'
        '{"ts":2,"proto":"tcp","uid":10001,"local":"10.0.2.15:1000","remote":"1.2.3.4:443","state":"established"}\n'
    )
    snap = socket_attr.parse_uid_sockets(
        "# package=com.x uid=10001\n## /proc/net/tcp\n"
        "   0: 0F02000A:03E8 04030201:01BB 01 00000000:00000000 00:00000000 00000000 10001 0 1\n"  # 同一 socket
    )
    merged = socket_attr.merge_uid_sockets(tl, snap)
    assert len(merged.by_remote[("1.2.3.4", 443)]) == 1  # 三处重复 → 去重成一条


def test_ss_backfill_by_four_tuple_not_across_uids() -> None:
    """★codex P1：同远端多 UID 时 ss 进程回填按四元组只落到匹配 local 的那条，不污染其它 UID 的记录。"""
    txt = (
        "# package=com.x uid=10001\n"
        "## ss -tunp\n"
        'tcp ESTAB 0 0 10.0.2.15:1001 1.2.3.4:443 users:(("com.x",pid=555,fd=9))\n'
        "## /proc/net/tcp\n"
        "   0: 0F02000A:03E8 04030201:01BB 01 00000000:00000000 00:00000000 00000000     0 0 1\n"  # local:1000 uid 0
        "   1: 0F02000A:03E9 04030201:01BB 01 00000000:00000000 00:00000000 00000000 10001 0 2\n"  # local:1001 uid 10001
    )
    s = socket_attr.parse_uid_sockets(txt)
    by_uid = {e.uid: e for e in s.by_remote[("1.2.3.4", 443)]}
    assert by_uid[10001].process == "com.x" and by_uid[10001].pid == 555  # 匹配 local:1001 → 回填
    assert by_uid[0].process is None and by_uid[0].pid is None  # 另一 UID（local:1000）不被污染


# ---------------------------------------------------------------------------
# ★A2：五元组（本地临时端口）+ pcap 流时间窗归因，四级评分 confirmed/probable/ambiguous/unattributed
# ---------------------------------------------------------------------------

# 同远端 1.2.3.4:443 被目标 uid 10234（本地端口 43090=0xA852）与系统 uid 0（本地端口 40000=0x9C40）各连一条。
_SHARED_REMOTE = (
    "# package=com.x uid=10234\n## /proc/net/tcp\n"
    "   0: 0F02000A:A852 04030201:01BB 01 00000000:00000000 00:00000000 00000000 10234 0 1\n"
    "   1: 0F02000A:9C40 04030201:01BB 01 00000000:00000000 00:00000000 00000000     0 0 2\n"
)


def _ep(ip: str, port: int, *conns: socket_attr.PcapConn) -> socket_attr.PcapEndpoint:
    return socket_attr.PcapEndpoint(remote_ip=ip, remote_port=port, conns=list(conns))


def test_attribute_connections_confirms_via_local_port_disambiguation() -> None:
    """★A2 核心：远端多 UID（旧 attribute_endpoints 判 ambiguous），但 pcap 流的本地临时端口精确命中
    目标 UID → confirmed（五元组把歧义消解到具体连接）。"""
    s = socket_attr.parse_uid_sockets(_SHARED_REMOTE)
    # 旧远端-only 归因：多 UID → ambiguous
    assert socket_attr.attribute_endpoints([("1.2.3.4", 443)], s)[("1.2.3.4", 443)]["attribution"] == "ambiguous"
    # A2：pcap 连接本地端口 43090 → 精确命中 uid 10234 → confirmed（结果键含 proto 族）
    a = socket_attr.attribute_connections([_ep("1.2.3.4", 443, socket_attr.PcapConn(43090))], s)[("tcp", "1.2.3.4", 443)]
    assert a["attribution"] == "confirmed" and a["uid"] == 10234 and a["is_target_app"] is True
    assert a["matched_by"] == ["remote_ip_port", "local_port"] and a["score"] == 0.7  # 无时间戳 → 未加时间窗分


def test_attribute_connections_time_window_boosts_score() -> None:
    """本地端口命中 + socket 观测时间区间与 pcap 流时间窗重叠 → confirmed + matched_by 含 time_window + score 升。"""
    s = socket_attr.parse_socket_timeline(
        '{"type":"meta","package":"com.x","target_uid":10234}\n'
        '{"ts":1.0,"proto":"tcp","uid":10234,"local":"10.0.2.15:43090","remote":"1.2.3.4:443","state":"syn_sent"}\n'
        '{"ts":3.0,"proto":"tcp","uid":10234,"local":"10.0.2.15:43090","remote":"1.2.3.4:443","state":"established"}\n'
    )
    a = socket_attr.attribute_connections(
        [_ep("1.2.3.4", 443, socket_attr.PcapConn(43090, first_ts=1.5, last_ts=2.5))], s
    )[("tcp", "1.2.3.4", 443)]
    assert a["attribution"] == "confirmed" and a["score"] == 0.95
    assert a["matched_by"] == ["remote_ip_port", "local_port", "time_window"]


def test_attribute_connections_time_window_miss_stays_local_only() -> None:
    """本地端口命中但时间窗不重叠（socket 观测远早于 pcap 流）→ 仍 confirmed（本地端口够强），但不加时间窗分。"""
    s = socket_attr.parse_socket_timeline(
        '{"type":"meta","package":"com.x","target_uid":10234}\n'
        '{"ts":1.0,"proto":"tcp","uid":10234,"local":"10.0.2.15:43090","remote":"1.2.3.4:443","state":"established"}\n'
    )
    a = socket_attr.attribute_connections(
        [_ep("1.2.3.4", 443, socket_attr.PcapConn(43090, first_ts=100.0, last_ts=200.0))], s
    )[("tcp", "1.2.3.4", 443)]
    assert a["attribution"] == "confirmed" and a["score"] == 0.7 and "time_window" not in a["matched_by"]


def test_attribute_connections_probable_single_remote_uid_no_local() -> None:
    """远端仅一个 UID、pcap 无本地端口明细（conns 为空）→ probable（远端唯一但未经本地端口确证）。"""
    s = socket_attr.parse_uid_sockets(_SAMPLE)  # 1.2.3.4:443 仅 uid 10234
    a = socket_attr.attribute_connections([_ep("1.2.3.4", 443)], s)[("tcp", "1.2.3.4", 443)]
    assert a["attribution"] == "probable" and a["uid"] == 10234 and a["is_target_app"] is True
    assert a["score"] == 0.5 and a["matched_by"] == ["remote_ip_port"]


def test_attribute_connections_ambiguous_when_local_port_unknown() -> None:
    """远端多 UID、pcap 本地端口对不上任何 socket → ambiguous + 带 score 的 candidates，不强选目标。"""
    s = socket_attr.parse_uid_sockets(_SHARED_REMOTE)
    a = socket_attr.attribute_connections([_ep("1.2.3.4", 443, socket_attr.PcapConn(59999))], s)[("tcp", "1.2.3.4", 443)]
    assert a["attribution"] == "ambiguous" and a["is_target_app"] is None
    assert a["target_uid_among_candidates"] is True
    assert {c["uid"] for c in a["candidates"]} == {0, 10234}
    assert all("score" in c for c in a["candidates"])  # 每候选带评分
    assert "local_port" not in a["matched_by"]  # 本地端口未命中 → 不标 local_port


def test_attribute_connections_unattributed_explicit() -> None:
    """pcap 有接入节点但 socket 表无对应记录 → 显式 unattributed 条目（不再静默丢弃）。"""
    s = socket_attr.parse_uid_sockets(_SAMPLE)
    a = socket_attr.attribute_connections([_ep("9.9.9.9", 443, socket_attr.PcapConn(50000))], s)[("tcp", "9.9.9.9", 443)]
    assert a["attribution"] == "unattributed" and a["is_target_app"] is None
    assert a["score"] == 0.0 and a["matched_by"] == []


def test_parse_socket_timeline_aggregates_ts_and_fills_by_conn() -> None:
    """同一 socket 多时刻观测聚成一条 entry + first_ts/last_ts 区间；by_conn 本地端口索引已填。"""
    s = socket_attr.parse_socket_timeline(
        '{"type":"meta","package":"com.x","target_uid":10234}\n'
        '{"ts":1.0,"proto":"tcp","uid":10234,"local":"10.0.2.15:43090","remote":"1.2.3.4:443","state":"syn_sent"}\n'
        '{"ts":3.0,"proto":"tcp","uid":10234,"local":"10.0.2.15:43090","remote":"1.2.3.4:443","state":"established"}\n'
    )
    assert len(s.entries) == 1  # 同 socket 多观测聚成一条
    e = s.entries[0]
    assert e.first_ts == 1.0 and e.last_ts == 3.0  # 区间取 min/max
    assert s.by_conn[("tcp", 43090, "1.2.3.4", 443)] == [e]  # (proto族,本地端口,远端) 索引已填


def test_ts_overlap_helper() -> None:
    """时间窗重叠判定：含容差、任一侧无时间戳 → False（不佐证也不否定）。"""
    e = socket_attr.SocketEntry("tcp", "10.0.0.1", 1, "1.2.3.4", 443, "established", 10234, first_ts=1.0, last_ts=3.0)
    assert socket_attr._ts_overlap(e, socket_attr.PcapConn(1, 2.0, 2.5), 2.0) is True   # 区间内
    assert socket_attr._ts_overlap(e, socket_attr.PcapConn(1, 4.5, 5.0), 2.0) is True   # 差 1.5 < 容差
    assert socket_attr._ts_overlap(e, socket_attr.PcapConn(1, 10.0, 11.0), 2.0) is False  # 远超容差
    assert socket_attr._ts_overlap(e, socket_attr.PcapConn(1, None, None), 2.0) is False  # 无 pcap 时间


def test_attribute_connections_udp_flow_does_not_confirm_via_tcp_socket() -> None:
    """★Fable 复审 P1-1：tcp/udp 本地端口空间独立可同号——一条 UDP 流不得撞上同号 TCP socket 被误 confirmed。"""
    s = socket_attr.parse_uid_sockets(_SAMPLE)  # 1.2.3.4:443 是目标 uid 10234 的 **TCP** socket，本地端口 43090
    # pcap 侧一条 **UDP** 流，本地端口恰好也 43090（合法同号，属别的 app 的 QUIC）
    a = socket_attr.attribute_connections(
        [socket_attr.PcapEndpoint("1.2.3.4", 443, proto="udp", conns=[socket_attr.PcapConn(43090)])], s
    )
    assert a[("udp", "1.2.3.4", 443)]["attribution"] == "unattributed"  # udp 无对应 socket → 不误确证成目标
    assert ("tcp", "1.2.3.4", 443) not in a  # 也没混进 tcp 结果


def test_attribute_connections_tcp_and_udp_same_ipport_do_not_overwrite() -> None:
    """★Fable 复审 P1-2：同 ip:port 的 tcp 与 udp 接入节点结果键含 proto 族，互不覆盖。"""
    s = socket_attr.parse_uid_sockets(_SAMPLE)  # tcp 1.2.3.4:443 → uid 10234
    a = socket_attr.attribute_connections(
        [
            socket_attr.PcapEndpoint("1.2.3.4", 443, proto="tcp", conns=[socket_attr.PcapConn(43090)]),
            socket_attr.PcapEndpoint("1.2.3.4", 443, proto="udp", conns=[socket_attr.PcapConn(50000)]),
        ],
        s,
    )
    assert a[("tcp", "1.2.3.4", 443)]["attribution"] == "confirmed"  # tcp 判决未被 udp 覆盖
    assert a[("udp", "1.2.3.4", 443)]["attribution"] == "unattributed"  # 两条独立并存


def test_attribute_connections_confirmed_nontarget_keeps_target_hint() -> None:
    """★Fable 复审 P2-1：某条流 confirmed 到非目标 UID，但"目标 app 也连过该远端"须保留提示，避免假阴性漏线索。"""
    s = socket_attr.parse_uid_sockets(_SHARED_REMOTE)  # 目标 10234(本地 43090) 与 uid 0(本地 40000) 都连 1.2.3.4:443
    # pcap 只覆盖到 uid 0 那条流（本地端口 40000=0x9C40）
    a = socket_attr.attribute_connections([_ep("1.2.3.4", 443, socket_attr.PcapConn(40000))], s)[("tcp", "1.2.3.4", 443)]
    assert a["attribution"] == "confirmed" and a["uid"] == 0 and a["is_target_app"] is False
    assert a["target_uid_among_candidates"] is True  # ★保留"目标也连过"提示（下游不至于整段当噪音丢）


def test_merge_uid_sockets_does_not_mutate_input_tables() -> None:
    """★Fable 复审 P2-2：merge 就地扩时间区间/补 process 时须拷贝，绝不改输入表的 entry（保纯函数）。"""
    tl = socket_attr.parse_socket_timeline(
        '{"type":"meta","package":"com.x","target_uid":10001}\n'
        '{"ts":1,"proto":"tcp","uid":10001,"local":"10.0.2.15:1000","remote":"1.2.3.4:443","state":"established"}\n'
    )
    snap = socket_attr.parse_uid_sockets(
        "# package=com.x uid=10001\n## ss -tunp\n"
        'tcp ESTAB 0 0 10.0.2.15:1000 1.2.3.4:443 users:(("com.x",pid=77,fd=9))\n'
        "## /proc/net/tcp\n"
        "   0: 0F02000A:03E8 04030201:01BB 01 00000000:00000000 00:00000000 00000000 10001 0 1\n"
    )
    merged = socket_attr.merge_uid_sockets(tl, snap)
    assert merged.entries[0].process == "com.x" and merged.entries[0].pid == 77  # 合并结果补上了进程
    assert tl.entries[0].process is None and tl.entries[0].pid is None  # ★输入表 entry 未被污染
    assert merged.entries[0] is not tl.entries[0]  # 是拷贝、非共享对象


def test_attribute_connections_tcp_pcap_matches_tcp6_vmapped_socket() -> None:
    """★proto 分族不误伤主路径：Android v4-mapped 目标连接只现身 /proc/net/tcp6（proto=tcp6），pcap 侧是
    裸点分 tcp——tcp/tcp6 同归 'tcp' 族，by_conn 仍能互配（分族只隔开 tcp↔udp，不隔 tcp↔tcp6）。"""
    txt = (  # tcp6 v4-mapped：local ::ffff:10.0.2.15:43090 / remote ::ffff:1.2.3.4:443 → 归一点分
        "# package=com.x uid=10234\n## /proc/net/tcp6\n"
        "   0: 0000000000000000FFFF00000F02000A:A852 0000000000000000FFFF000004030201:01BB 01"
        " 00000000:00000000 00:00000000 00000000 10234 0 1\n"
    )
    s = socket_attr.parse_uid_sockets(txt)
    assert s.entries[0].proto == "tcp6" and s.entries[0].remote_ip == "1.2.3.4" and s.entries[0].local_port == 43090
    a = socket_attr.attribute_connections(
        [socket_attr.PcapEndpoint("1.2.3.4", 443, proto="tcp", conns=[socket_attr.PcapConn(43090)])], s
    )[("tcp", "1.2.3.4", 443)]
    assert a["attribution"] == "confirmed" and a["uid"] == 10234  # tcp pcap 命中 tcp6 socket（同 tcp 族）
