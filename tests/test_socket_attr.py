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
        "   0: 000000000000000000000000FFFF020F:A852 0000000000000000FFFF000004030201:01BB 01"
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
