"""`pcap-leads --into` 回灌后，报告三个消费面必须说同一件事。

一份 report.json 有三个互不相干的消费面：调证函读 ``leads``、闭环排序读 ``endpoints``、
可见性读 ``meta``。回灌此前只更新第一面，于是同一份报告里：

- Lead 标着 ``is_runtime_contact=true``、notes 写"双向载荷=已通信后端"；
- 闭环主目标却挑满静态噪音，实测的真后端连候选都不是；
- digest 还写着 runtime ``unavailable``、"未做运行时观测"。

三处各自看都自洽，合起来自相矛盾。本文件从**回灌入口**驱动，逐面断言。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkscan.core import visibility
from apkscan.core.closure.targets import _select_targets_with_stats
from apkscan.core.report_io import report_from_dict
from apkscan.core import runtime_inventory
from apkscan.dynamic import pcap_ingest
from tests.doc_addresses import (
    DOC_BACKEND_IP,
    DOC_SECOND_IP,
    treat_doc_addresses_as_public,
)

#: 合成后端 IP —— 一律 RFC 5737 文档保留段的**字面量**（泄漏扫描看得见、也确认它无害）。
#:
#: 判据确实要求它被判为公网（否则"实测公网后端"的语义被抽掉，端点与闭环断言全部失去意义），
#: 但那件事由下面的 autouse fixture 定向表达，**不是**靠挑一个碰巧全球可路由的真地址
#: 再运行时拼装躲开扫描器——那样写进仓库的是真地址，且给任何真实 IOC 留了同一条缝。
_BACKEND_IP = DOC_BACKEND_IP
_TWO_PORT_IP = DOC_SECOND_IP


@pytest.fixture(autouse=True)
def _treat_documentation_ips_as_synthetic_public_backends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """把上面两个文档占位值定向放行成「公网」，其余地址仍走真实判据。

    故 ``192.168.10.233``（本机侧）与 ``192.168.10.1`` 仍被判私网，
    ``test_private_remote_is_not_merged`` 这类反向护栏不会被补丁抽空。
    """
    treat_doc_addresses_as_public(monkeypatch, _BACKEND_IP, _TWO_PORT_IP)

#: 静态侧的两条噪音（云段模板 IP + SDK 域名）——真实报告里这类占了绝大多数。
_STATIC = {
    "package_name": "com.test.app",
    "schema_version": "1.0",
    "meta": {"dex_available": True, "dex_scanned": True, "resource_files_scanned": 3},
    "leads": [
        {"category": "IP", "value": "106.11.35.1", "advice": "建议调证",  # leak-scan: allow pcap 回灌接线夹具，须被判公网远端才会并入 endpoints
         "confidence": "HIGH", "where_to_request": "云厂商", "evidence_to_obtain": ["租户"]},
        {"category": "DOMAIN", "value": "sdk.example.com", "advice": "建议调证",
         "confidence": "HIGH", "where_to_request": "注册商", "evidence_to_obtain": ["实名"]},
    ],
    "endpoints": [
        {"value": "106.11.35.1", "kind": "ip", "evidences": [{"source": "dex", "location": "a"}]},  # leak-scan: allow pcap 回灌接线夹具，须被判公网远端才会并入 endpoints
        {"value": "sdk.example.com", "kind": "domain",
         "evidences": [{"source": "dex", "location": "a"}]},
    ],
    "findings": [], "analyzer_status": [],
}


def _bidirectional_summary(ip: str = _BACKEND_IP, port: int = 31861) -> pcap_ingest.PcapSummary:
    """目标与 ip:port 有过双向载荷的 pcap（复刻周祥/戎子佳/范旻三案的强证据形态）。

    双向要两条流：本机→远端贡献 out_bytes，远端→本机贡献 in_bytes；两者都 >0 才判 established。
    """
    out = pcap_ingest.Flow(
        proto="tcp", src_ip="192.168.10.233", src_port=45678,
        dst_ip=ip, dst_port=port, packets=22, payload_bytes=5000, flags={"syn"},
    )
    back = pcap_ingest.Flow(
        proto="tcp", src_ip=ip, src_port=port,
        dst_ip="192.168.10.233", dst_port=45678,
        packets=18, payload_bytes=4000, flags={"synack"},
    )
    return pcap_ingest.PcapSummary(flows=[out, back])


def _two_port_summary(ip: str = _TWO_PORT_IP) -> pcap_ingest.PcapSummary:
    """同一 IP 上两个业务端口（复刻实测形态：一台机 5479 主通道 ＋ 8796 心跳通道）。

    实测三台后端各开两个端口，每台的两个端口一个流量大（约 1.7KB 上行）、
    一个流量小（约 250B 上行）——若合并时相互覆盖，稳定漏掉一半调证标的。
    """
    flows: list[pcap_ingest.Flow] = []
    for port, out_b, in_b, lport in ((5479, 1759, 546, 40001), (8796, 258, 447, 40002)):
        flows.append(pcap_ingest.Flow(
            proto="tcp", src_ip="192.168.10.233", src_port=lport,
            dst_ip=ip, dst_port=port, packets=20, payload_bytes=out_b, flags={"syn"},
        ))
        flows.append(pcap_ingest.Flow(
            proto="tcp", src_ip=ip, src_port=port,
            dst_ip="192.168.10.233", dst_port=lport,
            packets=17, payload_bytes=in_b, flags={"synack"},
        ))
    return pcap_ingest.PcapSummary(flows=flows)


def _merge(tmp_path: Path, summary: pcap_ingest.PcapSummary) -> dict:
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")
    pcap_ingest.merge_into_report_json(str(p), summary)
    return json.loads(p.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 面一：闭环主目标（codex P0-1）
# ---------------------------------------------------------------------------


def test_runtime_backend_becomes_a_closure_candidate(tmp_path: Path) -> None:
    """★实测双向通信的后端必须**先**进候选池，再谈排序。

    此前它根本不在 report.endpoints 里——排序排的是端点，而那个端点从没被创建过。
    退回 _runtime_endpoint_dicts 的接线，这里即红。
    """
    payload = _merge(tmp_path, _bidirectional_summary())

    ips = [e["value"] for e in payload["endpoints"] if e["kind"] == "ip"]
    assert _BACKEND_IP in ips, "回灌没把运行时端点写进 endpoints"

    ep = next(e for e in payload["endpoints"] if e["value"] == _BACKEND_IP)
    rt = ep["enrichment"]["runtime"]
    assert rt["has_payload"] is True
    assert rt["port"] == 31861, "端口要留在 runtime 富化里（调证函要写、同 IP 不同服务要分得开）"
    assert rt["state"] == pcap_ingest.STATE_ESTABLISHED


def test_runtime_backend_outranks_static_noise(tmp_path: Path) -> None:
    """★核心回归：真后端排在静态噪音之前，而不是被挤出 Top-N。

    实测三案里，动态证据已满足闭环门槛，closure 却仍判 partial、五层归属预算被噪音耗尽。
    """
    payload = _merge(tmp_path, _bidirectional_summary())
    rep = report_from_dict(payload)

    selected, _stats = _select_targets_with_stats(rep, max_targets=6)
    values = [e.value for e in selected]

    assert values[0] == _BACKEND_IP, f"实测后端应排第一，实得 {values}"
    assert "106.11.35.1" in values, "静态候选仍参选，只是让位"  # leak-scan: allow pcap 回灌接线夹具，须被判公网远端才会并入 endpoints


def test_runtime_backend_survives_a_tight_budget(tmp_path: Path) -> None:
    """★max_targets 截断时，让位的必须是静态噪音而不是实测后端。"""
    payload = _merge(tmp_path, _bidirectional_summary())
    rep = report_from_dict(payload)

    selected, stats = _select_targets_with_stats(rep, max_targets=1)

    assert [e.value for e in selected] == [_BACKEND_IP]
    assert stats["truncated"] == 2


def test_lead_port_suffix_matches_bare_ip_endpoint(tmp_path: Path) -> None:
    """★两侧值形状不同是设计使然，配对必须容得下：Lead 带 ``:port/proto``、Endpoint 是裸 IP。

    端口留在 Lead 上是因为调证函要写它；Endpoint 用裸 IP 是因为富化器与静态端点都按裸 IP 算。
    退回 _match_value 的剥端口，两边永远配不上，真后端又变回"连候选都不是"。
    """
    payload = _merge(tmp_path, _bidirectional_summary())
    lead = next(ld for ld in payload["leads"] if ld["value"].startswith(_BACKEND_IP))
    assert lead["value"] == f"{_BACKEND_IP}:31861/tcp", "Lead 侧保留端口"

    rep = report_from_dict(payload)
    selected, _ = _select_targets_with_stats(rep, max_targets=6)
    assert _BACKEND_IP in [e.value for e in selected]


# ---------------------------------------------------------------------------
# 面二：可见性（codex P0-2）
# ---------------------------------------------------------------------------


def test_runtime_visibility_stops_claiming_nothing_was_observed(tmp_path: Path) -> None:
    """★回灌之后不得再说"未做运行时观测、建议去抓包"——那与同一份报告里的 Lead 直接打架。"""
    payload = _merge(tmp_path, _bidirectional_summary())

    a = visibility.assess(payload)
    rt = a["sources"]["runtime"]
    assert rt["visibility"] != visibility.VIS_UNAVAILABLE
    assert not any("未做运行时观测" in w for w in rt["why"]), rt["why"]
    # 采集质量确实没评估过（pcap-leads 拿不到 capture_quality）→ partial 是诚实的档位
    assert rt["visibility"] == visibility.VIS_PARTIAL


def test_merge_records_that_uid_attribution_was_not_possible(tmp_path: Path) -> None:
    """★带外 pcap 抓的是**整机**流量，这条路径没有设备侧 socket 快照，做不了 UID 归因。

    不能因为"这是为目标抓的包"就默认把流量算作目标的。缺了就如实记下来，让下游看得见。
    """
    payload = _merge(tmp_path, _bidirectional_summary())

    inv = payload["meta"]["runtime_merged_inventory"]
    assert inv["uid_attributed"] is False
    assert inv["remote_endpoints"] == 1

    ep = next(e for e in payload["endpoints"] if e["value"] == _BACKEND_IP)
    assert "target_attributed" not in ep["enrichment"]["runtime"], (
        "没做归因就不能写这个字段——它会被闭环当成'已归因到目标'"
    )


# ---------------------------------------------------------------------------
# 反向护栏
# ---------------------------------------------------------------------------


def test_existing_static_endpoint_is_upgraded_not_duplicated(tmp_path: Path) -> None:
    """静态已知的 IP 这次被实测连上 → 并进原端点（升级），不另起一条。"""
    payload = _merge(tmp_path, _bidirectional_summary(ip="106.11.35.1", port=443))  # leak-scan: allow pcap 回灌接线夹具，须被判公网远端才会并入 endpoints

    hits = [e for e in payload["endpoints"] if e["value"] == "106.11.35.1"]  # leak-scan: allow pcap 回灌接线夹具，须被判公网远端才会并入 endpoints
    assert len(hits) == 1, "同一 IP 不得出现两条端点"
    assert hits[0]["enrichment"]["runtime"]["has_payload"] is True
    assert any(ev["source"] == "runtime-pcap" for ev in hits[0]["evidences"]), "runtime 证据要并进去"


def test_empty_capture_does_not_fake_runtime_observation(tmp_path: Path) -> None:
    """★零流量的 pcap 不得把 runtime 标成"观测过"——那是凭空造一次并不存在的采集。"""
    payload = _merge(tmp_path, pcap_ingest.PcapSummary(flows=[]))

    assert "runtime_merged" not in payload["meta"]
    a = visibility.assess(payload)
    assert a["sources"]["runtime"]["visibility"] == visibility.VIS_UNAVAILABLE


def test_private_remote_is_not_merged(tmp_path: Path) -> None:
    """私网远端不产接入节点（remote_endpoints 已过滤），端点侧同样不该冒出来。"""
    f = pcap_ingest.Flow(proto="tcp", src_ip="192.168.10.233", src_port=1,
                         dst_ip="192.168.10.1", dst_port=80, packets=4, payload_bytes=100)
    payload = _merge(tmp_path, pcap_ingest.PcapSummary(flows=[f]))

    assert "192.168.10.1" not in [e["value"] for e in payload["endpoints"]]


# ---------------------------------------------------------------------------
# 面四：同一 IP 多端口不得互相覆盖（codex P1-3）
# ---------------------------------------------------------------------------


def _runtime_of(payload: dict, ip: str) -> dict:
    ep = next(e for e in payload["endpoints"] if e["value"] == ip)
    return ep["enrichment"]["runtime"]


def test_multi_port_backend_keeps_every_port(tmp_path: Path) -> None:
    """★同一 IP 上的多个业务端口必须全部保留。

    端点的 value 是裸 IP，此前每个端口各产一条同 key 的 dict、合并时 ``{**old, **new}``
    把前一个端口的 runtime 整个压掉——报告里只剩最后一个端口。实测形态是
    「一台机两个端口、一主一心跳」，等于稳定漏掉一半调证标的。
    """
    payload = _merge(tmp_path, _two_port_summary())
    rt = _runtime_of(payload, _TWO_PORT_IP)

    assert sorted(rt["remote_endpoints"]) == [f"{_TWO_PORT_IP}:5479", f"{_TWO_PORT_IP}:8796"]
    assert sorted(rt["ports"]) == [5479, 8796]


def test_multi_port_counters_are_summed_not_overwritten(tmp_path: Path) -> None:
    """★字节与连接数按端口累加，不是被后一个端口覆盖。"""
    payload = _merge(tmp_path, _two_port_summary())
    rt = _runtime_of(payload, _TWO_PORT_IP)

    assert rt["out_bytes"] == 1759 + 258, "上行字节没有跨端口累加"
    assert rt["in_bytes"] == 546 + 447
    assert rt["has_payload"] is True


def test_representative_port_is_the_high_traffic_one(tmp_path: Path) -> None:
    """代表端口取流量最大的那个（主通道），不是最后并入的那个。

    实测形态是"一主一心跳"；心跳端口若当上代表值，展示与调证函会指向次要通道。
    """
    rt = _runtime_of(_merge(tmp_path, _two_port_summary()), _TWO_PORT_IP)
    assert rt["port"] == 5479, "代表端口指到了低流量的次要通道"


def test_cross_source_merge_keeps_the_high_traffic_representative_port() -> None:
    """跨来源合并同样按流量定代表端口——否则 docstring 承诺的规则只在单来源内成立。"""
    heavy = {"port": 5479, "out_bytes": 1759, "in_bytes": 546, "ports": [5479]}
    light = {"port": 8796, "out_bytes": 258, "in_bytes": 447, "ports": [8796]}

    assert pcap_ingest._merge_runtime_blocks(heavy, light)["port"] == 5479
    assert pcap_ingest._merge_runtime_blocks(light, heavy)["port"] == 5479


def test_cross_source_merge_does_not_clobber_target_attribution() -> None:
    """★pcap 路径做不了 UID 归因、从不写 target_attributed；合并不得把 capture 写的真归因冲掉。"""
    from_capture = {"target_attributed": True, "out_bytes": 10, "in_bytes": 10}
    from_pcap = {"out_bytes": 5, "in_bytes": 5, "ports": [443]}  # 无 target_attributed 键

    merged = pcap_ingest._merge_runtime_blocks(from_capture, from_pcap)
    assert merged["target_attributed"] is True, "capture 路径的 UID 归因被 pcap 合并冲掉了"


# ---------------------------------------------------------------------------
# 面五：重复导入同一份采集必须幂等（codex 二轮 P1）
# ---------------------------------------------------------------------------


def test_reimporting_the_same_pcap_does_not_double_count(tmp_path: Path) -> None:
    """★同一份 pcap 并两次，字节数与连接数不得翻倍。

    求和是跨端口累计所必需的语义，但重复导入时它变成凭空翻倍——而字节数正是闭环判
    「有无双向载荷」的输入，翻倍等于伪造观测强度。去掉幂等闸，本测试即红。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")
    summary = _two_port_summary()

    pcap_ingest.merge_into_report_json(str(p), summary)
    first = json.loads(p.read_text(encoding="utf-8"))
    rt_first = _runtime_of(first, _TWO_PORT_IP)
    out_once, conns_once = rt_first["out_bytes"], rt_first["connection_count"]

    pcap_ingest.merge_into_report_json(str(p), summary)  # 同一份再并一次
    second = json.loads(p.read_text(encoding="utf-8"))
    rt = _runtime_of(second, _TWO_PORT_IP)

    assert rt["out_bytes"] == out_once, "重复导入把上行字节数累加了"
    assert rt["connection_count"] == conns_once, "重复导入把连接数累加了"
    assert sorted(rt["ports"]) == [5479, 8796]
    ep = next(e for e in second["endpoints"] if e["value"] == _TWO_PORT_IP)
    sigs = [(e["source"], e["location"], e["snippet"]) for e in ep["evidences"]]
    assert len(sigs) == len(set(sigs)), "重复导入把同样的证据又追加了一遍"


def test_two_different_captures_still_accumulate(tmp_path: Path) -> None:
    """幂等闸按**内容**指纹判，两份不同的采集仍要正常累加——别把闸修成"只认第一次"。"""
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(p), _two_port_summary())
    before = _runtime_of(json.loads(p.read_text(encoding="utf-8")), _TWO_PORT_IP)["out_bytes"]

    # 第二份采集：同 IP 同端口，但字节数不同 → 是另一次观测，应当累加。
    other = pcap_ingest.PcapSummary(flows=[
        pcap_ingest.Flow(proto="tcp", src_ip="192.168.10.233", src_port=40009,
                         dst_ip=_TWO_PORT_IP, dst_port=5479, packets=9,
                         payload_bytes=777, flags={"syn"}),
        pcap_ingest.Flow(proto="tcp", src_ip=_TWO_PORT_IP, src_port=5479,
                         dst_ip="192.168.10.233", dst_port=40009, packets=8,
                         payload_bytes=333, flags={"synack"}),
    ])
    pcap_ingest.merge_into_report_json(str(p), other)
    after = _runtime_of(json.loads(p.read_text(encoding="utf-8")), _TWO_PORT_IP)["out_bytes"]

    assert after == before + 777, "不同的两份采集没有累加"


def _one_flow_pair(sni: set[str] | None = None, out_b: int = 1200, in_b: int = 800):
    """一对同端点的进出向 flow，统计量固定、只有 SNI 可变——用来单独考指纹的分辨力。"""
    return pcap_ingest.PcapSummary(flows=[
        pcap_ingest.Flow(proto="tcp", src_ip="192.168.10.233", src_port=41000,
                         dst_ip=_TWO_PORT_IP, dst_port=5479, packets=20,
                         payload_bytes=out_b, flags={"syn"}, sni=set(sni or ())),
        pcap_ingest.Flow(proto="tcp", src_ip=_TWO_PORT_IP, src_port=5479,
                         dst_ip="192.168.10.233", dst_port=41000, packets=17,
                         payload_bytes=in_b, flags={"synack"}),
    ])


def test_fingerprint_distinguishes_captures_that_differ_only_in_sni(tmp_path: Path) -> None:
    """★统计量完全相同、只是第二次多解出了 SNI —— 不得被幂等闸当成重复。

    此前指纹只收端点统计与 flows/DNS 计数，这两份采集指纹相同，于是端点侧被整体跳过：
    Lead 侧照常拿到 sni_masquerade，端点侧却连 runtime.sni 都没有，同一份报告两种说法
    （codex 二轮 P1）。上一版之所以测试还绿，是因为我恰好改了字节数——那是巧合，不是判据。
    """
    plain = _one_flow_pair()
    with_sni = _one_flow_pair({"player.mediastatic-cdn.com"})

    assert pcap_ingest.summary_merge_fingerprint(plain) != \
        pcap_ingest.summary_merge_fingerprint(with_sni), "只差 SNI 的两份采集指纹撞了"

    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")
    pcap_ingest.merge_into_report_json(str(p), plain)
    pcap_ingest.merge_into_report_json(str(p), with_sni)

    rt = _runtime_of(json.loads(p.read_text(encoding="utf-8")), _TWO_PORT_IP)
    assert rt["sni"] == ["player.mediastatic-cdn.com"], "第二次采集的 SNI 被幂等闸吞掉了"
    assert rt["sni_masquerade"] == ["player.mediastatic-cdn.com"], "端点侧没拿到伪装标记"


def test_merge_history_is_never_truncated(tmp_path: Path) -> None:
    """★并过很多份之后，最早那份重新导入仍不得累加计数。

    曾给这份名单加过 64 条上限来防 meta 膨胀，结果截尾让最老的采集"失忆"——再次导入时
    ``already=False``，字节数与连接数照样求和，凭空长出观测强度，正是这道闸要防的那件事
    被防膨胀措施自己放了回来（codex 三轮 P1）。取证工具**宁可漏、不可造**：多留几条哈希只是
    几 KB，伪造出来的"双向载荷"却会直接改变闭环结论。把截尾加回去，本测试即红。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")

    first = _one_flow_pair(out_b=1000, in_b=500)
    pcap_ingest.merge_into_report_json(str(p), first)
    baseline = _runtime_of(json.loads(p.read_text(encoding="utf-8")), _TWO_PORT_IP)["out_bytes"]

    # 再并 80 份互不相同的采集（每份字节数不同 → 指纹不同），把历史撑到远超任何合理上限
    for n in range(80):
        pcap_ingest.merge_into_report_json(str(p), _one_flow_pair(out_b=2000 + n, in_b=100 + n))
    after_many = _runtime_of(json.loads(p.read_text(encoding="utf-8")), _TWO_PORT_IP)["out_bytes"]

    # 现在把**最早**那份再并一次——它必须仍被认出来
    pcap_ingest.merge_into_report_json(str(p), first)
    final = json.loads(p.read_text(encoding="utf-8"))
    assert _runtime_of(final, _TWO_PORT_IP)["out_bytes"] == after_many, \
        "最早那份采集被历史截尾挤掉了，重并时又累加了一次"
    assert final["meta"]["runtime_pcap_merges"][0] == pcap_ingest.summary_merge_fingerprint(first), \
        "首条指纹不该被截掉"
    assert baseline < after_many  # 中间那批确实累加了（否则上面的断言恒真）


def test_dns_only_captures_still_get_their_leads(tmp_path: Path) -> None:
    """★DNS-only 采集的线索不受幂等闸影响——因为 Lead 合并在闸**外**。

    上一版这条测试断言的是「两份 DNS-only 采集指纹必须不同」，**前提就错了**：
    幂等闸只保护端点侧的累加，而 DNS 只产生 Lead，Lead 合并在闸外、自带证据签名去重。
    把 dns_queries 塞进指纹反而会让「端点贡献相同、只差 DNS」的两份采集绕过闸、
    把端点字节数再累加一遍（codex 四轮 P1）。

    所以该钉的不是指纹差异，而是**结果**：两份 DNS-only 采集的域名线索都要进报告。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(
        str(p), pcap_ingest.PcapSummary(dns_queries={"a.example.test"}))
    pcap_ingest.merge_into_report_json(
        str(p), pcap_ingest.PcapSummary(dns_queries={"b.example.test"}))

    values = {ld.get("value") for ld in json.loads(p.read_text(encoding="utf-8"))["leads"]}
    assert {"a.example.test", "b.example.test"} <= values, "第二份 DNS 采集的线索丢了"


def test_dns_only_capture_writes_runtime_meta(tmp_path: Path) -> None:
    """★纯 DNS 采集也是**真观测**，必须写 runtime meta。

    此前的写入条件是 ``fresh_eps or summary.flows``，纯 DNS 两者皆空 → 整个被挡在门外：
    不产生 inventory、``runtime_merged`` 不置 True，可见性一直说"未做运行时观测"。
    上一版那条 DNS 测试只查 Lead，**恰好绕过了这条路径**（codex 五轮 P1）。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(
        str(p), pcap_ingest.PcapSummary(dns_queries={"a.example.test"}))
    meta = json.loads(p.read_text(encoding="utf-8"))["meta"]

    assert meta.get("runtime_merged") is True, "纯 DNS 采集没被记成运行时观测"
    inv = meta["runtime_merged_inventory"]
    # ★精确值，不用 >=：_STATIC 里没有任何 runtime-pcap 域名线索，所以只能是 1。
    #   放宽成 >= 会同时放过「重复计数」和「把静态/capture 的线索也算进来」两类回归。
    assert inv["domain_leads"] == 1, "inventory 的域名线索数不对"
    assert inv["uid_attributed"] is False

    # 再并一份不同的 DNS 采集 → 计数要反映累计结果，而不是停在第一份
    pcap_ingest.merge_into_report_json(
        str(p), pcap_ingest.PcapSummary(dns_queries={"b.example.test"}))
    inv2 = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]
    assert inv2["domain_leads"] == 2, "第二份 DNS 采集没进 inventory"


def test_dns_only_merge_does_not_wipe_earlier_endpoint_inventory(tmp_path: Path) -> None:
    """★放宽写入条件的直接副作用：inventory 是覆盖写的。

    先并一份有端点的采集、再并一份纯 DNS 的，若 inventory 仍按「本次 summary 的快照」写，
    ``remote_endpoints`` 会被清零——报告里凭空少掉一个已观测的后端。故计数改为从 payload
    推导（天然幂等），而不是取本次快照。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(p), _bidirectional_summary())
    before = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]
    assert before["remote_endpoints"] == 1

    pcap_ingest.merge_into_report_json(
        str(p), pcap_ingest.PcapSummary(dns_queries={"a.example.test"}))
    after = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]

    assert after["remote_endpoints"] == 1, "纯 DNS 采集把之前那份的端点数清零了"
    assert after["domain_leads"] == 1


# --- inventory 的归属边界：只数本路径自己的贡献 -----------------------------

def _report_with(extra_endpoints=(), extra_leads=(), meta=None) -> dict:
    payload = json.loads(json.dumps(_STATIC))
    payload.setdefault("endpoints", []).extend(extra_endpoints)
    payload.setdefault("leads", []).extend(extra_leads)
    if meta:
        payload.setdefault("meta", {}).update(meta)
    return payload


def test_capture_endpoints_do_not_count_as_pcap_inventory(tmp_path: Path) -> None:
    """★capture 路径写的端点不得算进名为 *pcap* 的 inventory。

    按 ``source == "runtime-pcap"`` 钉边界是**不够的**：capture 直接调用
    ``pcap_ingest.to_runtime_endpoints()``，产出的也是 runtime-pcap 证据（正常生产路径，
    不是边角）。共享 schema 判不了归属，只能各自在 meta 里记账（codex 六轮 P1）。
    """
    p = tmp_path / "report.json"
    capture_ep = {
        "value": "198.51.100.77", "kind": "ip", "is_private": False,
        "evidences": [{"source": "runtime-pcap", "location": "pcap", "snippet": "capture 写的"}],
        "enrichment": {"runtime": {"remote_endpoints": ["198.51.100.77:443"]}},
    }
    p.write_text(json.dumps(_report_with(extra_endpoints=[capture_ep]), ensure_ascii=False),
                 encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(p), _bidirectional_summary())
    inv = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]

    assert inv["remote_endpoints"] == 1, "capture 的端点被算进了 pcap inventory"


def test_capture_domain_leads_do_not_count_as_pcap_inventory(tmp_path: Path) -> None:
    """同理：预先存在的 runtime-pcap 域名线索（capture 写的）不得算进本路径的 inventory。"""
    p = tmp_path / "report.json"
    capture_lead = {
        "category": "DOMAIN", "value": "cap.example.test", "advice": "待核",
        "confidence": "MEDIUM",
        "source_refs": [{"source": "runtime-pcap", "location": "pcap", "snippet": "capture 写的"}],
    }
    p.write_text(json.dumps(_report_with(extra_leads=[capture_lead]), ensure_ascii=False),
                 encoding="utf-8")

    pcap_ingest.merge_into_report_json(
        str(p), pcap_ingest.PcapSummary(dns_queries={"a.example.test"}))
    inv = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]

    assert inv["domain_leads"] == 1, "capture 的域名线索被算进了 pcap inventory"


def test_inventory_key_rename_migrates_and_clears_the_old_key(tmp_path: Path) -> None:
    """★清单**自身**的键名改过（``runtime_pcap_inventory`` → ``runtime_merged_inventory``）。

    改名要带迁移：旧报告的计数得跟过来；旧键还要清掉，否则两套形状长期并存、读方各读一套，
    而这份清单本来就有多个读方（闭环采集质量 / 可见性）。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_report_with(meta={"runtime_pcap_inventory": {
        "remote_endpoints": 4,
    }}), ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(p), _bidirectional_summary())
    meta = json.loads(p.read_text(encoding="utf-8"))["meta"]

    assert meta["runtime_merged_inventory"]["remote_endpoints"] == 4, "旧清单的计数没迁移过来"
    for stale in runtime_inventory.INVENTORY_META_ALIASES:
        assert stale not in meta, f"旧清单键 {stale} 没被清掉"
def test_old_report_parse_failure_survives_the_new_key(tmp_path: Path) -> None:
    """★旧报告只有 `parse_status`、没有后加的 `parse_degraded`——降级历史不得被抹掉。

    `bool(prev.get("parse_degraded"))` 对旧报告恒为 False，同时 `parse_status` 被本次的
    "ok" 覆盖，于是「这份报告曾经解析失败」彻底消失（codex 八轮 P1）。缺键时要从旧
    `parse_status` 反推。这是同一个元错误的第三次：修了兄弟键，又漏了这一个。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_report_with(meta={"runtime_pcap_inventory": {
        "parse_status": "parse_error",          # 旧 schema：没有 parse_degraded
    }}), ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(p), _bidirectional_summary())   # 本次解析正常
    inv = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]

    assert inv["parse_status"] == "ok"          # 最近一次确实成功
    assert inv["parse_degraded"] is True, "旧报告的解析失败历史被抹掉了"


def test_old_endpoint_and_domain_counts_do_not_regress(tmp_path: Path) -> None:
    """★旧报告有计数、却没有贡献集合（集合是后来才引入的）——不得被重置成本次的值数量。

    最初只给 `flows` 写了迁移，忘了 `remote_endpoints` 与 `dns_queries` 是同一次改名的兄弟：
    旧报告 `{remote_endpoints: 5, dns_queries: 7}` 并入一个端点一个域名后会写成 1、1
    （codex 七轮 P1）。取 max 作单调下界——不能相加，因为无从判断新旧是否重叠。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_report_with(meta={"runtime_pcap_inventory": {
        "remote_endpoints": 5, "dns_queries": 7,
    }}), ensure_ascii=False), encoding="utf-8")

    # 这份采集只贡献 1 个端点、0 个域名
    pcap_ingest.merge_into_report_json(str(p), _bidirectional_summary())
    inv = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]

    assert inv["remote_endpoints"] == 5, "旧端点计数被重置成本次贡献数"
    assert inv["domain_leads"] == 7, "旧 dns_queries 没迁移到 domain_leads"
    assert "dns_queries" not in inv, "旧键没被清掉"


def test_dropped_fields_do_not_come_back(tmp_path: Path) -> None:
    """★``flows_merged`` 已按「无消费方即删除」显式丢弃——旧报告带着它也不得复活。

    删字段和加字段一样要留痕：旧报告里真有这个键，读到时按表跳过。若某天有人为了"兼容"
    把它迁回来，清单又会多背一份没人读的计数——这正是当初整块清单没有任何生产消费方的成因。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(
        _report_with(meta={"runtime_pcap_inventory": {"flows": 7, "flows_merged": 9}}),
        ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(p), _bidirectional_summary())
    inv = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]

    for dropped in runtime_inventory.DROPPED_FIELDS:
        assert dropped not in inv, f"已丢弃的字段 {dropped} 又回到清单里了"
    # 丢弃必须写明理由，否则下一个维护者只能猜"这是不是漏迁移了"
    assert all(reason.strip() for reason in runtime_inventory.DROPPED_FIELDS.values())


def test_every_inventory_field_names_its_reader() -> None:
    """★清单的准入条件：**每个字段都要说清谁读它**。

    这份清单曾经整块没有任何生产消费方（全仓只有 writer 与测试读它），而写它的注释却说
    "消费方 closure/digest 看得出…"——注释自己在撒谎。填不出 reader 的字段不该存在，
    所以把这条准入条件做成测试，而不是留给复审时靠人记得问。
    """
    produced = set(runtime_inventory.build_inventory(
        {}, source="pcap", endpoint_values=(), domain_values=(), parse_status="ok"))
    declared = {f.name for f in runtime_inventory.INVENTORY_FIELDS}

    assert produced == declared, "实际写出的键与声明表不一致（漏声明或漏实现）"
    for field in runtime_inventory.INVENTORY_FIELDS:
        assert field.reader.strip(), f"{field.name} 没写明消费方"
def test_record_only_summary_does_not_fake_an_observation(tmp_path: Path) -> None:
    """★只有 dns_records、没有 flow/query 的采集不得声称"已观测"。

    这条路径根本不落盘 record（明细走 to_ledger_dict），拿它当凭据就会造出
    「runtime_merged=True 但报告里没有任何可审计证据」（codex 六轮 P1）。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")

    rec = pcap_ingest.DnsRecord(qname="x.example.test", qtype=1, rcode=0)
    pcap_ingest.merge_into_report_json(str(p), pcap_ingest.PcapSummary(dns_records=[rec]))
    meta = json.loads(p.read_text(encoding="utf-8")).get("meta", {})

    assert "runtime_merged" not in meta, "只有 record 就声称做过运行时观测"
    assert "runtime_pcap_inventory" not in meta


def test_parse_failure_is_not_erased_by_a_later_success(tmp_path: Path) -> None:
    """解析失败过这件事不该被下一次成功抹掉——覆盖写会让报告看起来一直是干净的。"""
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")

    bad = pcap_ingest.PcapSummary(flows=list(_bidirectional_summary().flows),
                                  parse_status="parse_error")
    pcap_ingest.merge_into_report_json(str(p), bad)
    assert json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]["parse_degraded"] is True

    pcap_ingest.merge_into_report_json(str(p), _two_port_summary())   # 这次解析正常
    inv = json.loads(p.read_text(encoding="utf-8"))["meta"]["runtime_merged_inventory"]
    assert inv["parse_degraded"] is True, "先前的解析失败被后一次成功抹掉了"


# --- 闸的边界：只保护端点侧的累加，不受闸外字段影响 -------------------------

def _pair_with(**kw):
    """同一组端点贡献，只改 Flow 上某个**不进 runtime 端点**的字段。"""
    base = dict(proto="tcp", packets=20, payload_bytes=1200)
    out = {**base, **kw}
    inb = {**base, "packets": 17, "payload_bytes": 800, **kw}
    return pcap_ingest.PcapSummary(flows=[
        pcap_ingest.Flow(src_ip="192.168.10.233", src_port=41000,
                         dst_ip=_TWO_PORT_IP, dst_port=5479, flags={"syn"}, **out),
        pcap_ingest.Flow(src_ip=_TWO_PORT_IP, src_port=5479,
                         dst_ip="192.168.10.233", dst_port=41000, flags={"synack"}, **inb),
    ])


def test_gate_ignores_fields_that_never_reach_the_endpoint(tmp_path: Path) -> None:
    """★端点贡献相同时，闸外字段的差异**不得**让端点计数再累加一遍。

    ``parse_status`` 是 meta 覆盖写、``ja3``/``alpn``/``quic`` 只进 Lead 证据——三者都不在
    ``_runtime_endpoint_dicts`` 写的端点里。把它们收进指纹，就会让「同一批端点、只差这些」
    的两份采集绕过闸，``out_bytes`` 翻倍。这是「扩大判据范围」引入的伪造（codex 四轮 P1）。
    """
    first = _pair_with()
    for label, second in (
        ("parse_status", pcap_ingest.PcapSummary(flows=list(first.flows), parse_status="parse_error")),
        ("ja3", _pair_with(ja3={"deadbeef"})),
        ("alpn", _pair_with(alpn={"h2"})),
        ("quic", _pair_with(quic_versions={"1"})),
    ):
        assert pcap_ingest.summary_merge_fingerprint(first) == \
            pcap_ingest.summary_merge_fingerprint(second), f"{label} 不该改变端点侧指纹"

        p = tmp_path / f"report_{label}.json"
        p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")
        pcap_ingest.merge_into_report_json(str(p), first)
        once = _runtime_of(json.loads(p.read_text(encoding="utf-8")), _TWO_PORT_IP)["out_bytes"]
        pcap_ingest.merge_into_report_json(str(p), second)
        twice = _runtime_of(json.loads(p.read_text(encoding="utf-8")), _TWO_PORT_IP)["out_bytes"]
        assert twice == once, f"只差 {label} 就让端点字节数累加了两次"


def test_gate_still_separates_real_endpoint_differences() -> None:
    """收窄之后不能矫枉过正：端点侧**真**有差异时，指纹仍必须分得开。"""
    base = _pair_with()
    assert pcap_ingest.summary_merge_fingerprint(base) != \
        pcap_ingest.summary_merge_fingerprint(_pair_with(payload_bytes=9999)), "字节数差异被吞了"
    assert pcap_ingest.summary_merge_fingerprint(base) != \
        pcap_ingest.summary_merge_fingerprint(_pair_with(sni={"player.example.test"})), "SNI 差异被吞了"
    # 同一份采集重复计算 → 指纹稳定（幂等闸成立的前提）
    assert pcap_ingest.summary_merge_fingerprint(base) == \
        pcap_ingest.summary_merge_fingerprint(_pair_with())


def test_merge_never_downgrades_state_or_proto() -> None:
    """★合并只应增加信息：已确证的 established / mixed 不得被后并入的弱观测冲掉。"""
    strong = {"state": "established", "proto": "mixed", "out_bytes": 100, "in_bytes": 100}
    weak = {"state": "syn_only", "proto": "tcp", "out_bytes": 1, "in_bytes": 0}

    merged = pcap_ingest._merge_runtime_blocks(strong, weak)
    assert merged["state"] == "established", "SYN-only 的补充采集把 established 降级了"
    assert merged["proto"] == "mixed", "只含 TCP 的补充采集把 mixed 退回 tcp 了"

    # 反向同理（谁先谁后都不该改变结论）
    merged2 = pcap_ingest._merge_runtime_blocks(weak, strong)
    assert merged2["state"] == "established"
    assert merged2["proto"] == "mixed"

    # 两种不同协议相遇 → 升 mixed（而非任一方胜出）
    assert pcap_ingest._merge_runtime_blocks(
        {"proto": "tcp"}, {"proto": "udp"}
    )["proto"] == "mixed"
    # reset 强于 syn_only（对端有反应），但弱于 established
    assert pcap_ingest._merge_runtime_blocks(
        {"state": "syn_only"}, {"state": "reset"}
    )["state"] == "reset"


def test_port_normalize_can_read_the_merged_endpoint(tmp_path: Path) -> None:
    """★接线锁：port-normalize 的数据源必须真的被生成。

    它读 ``endpoints[].enrichment["runtime"]["remote_endpoints"]``（``"ip:port"`` 形态）。
    该字段此前根本没被 pcap 回灌生成，文档宣称的「报告实测端口交叉校验」对这类报告不可用——
    只测端点建出来了，挡不住这种「字段名对不上、下游静默拿不到」。
    """
    from apkscan.config import port_norm

    payload = _merge(tmp_path, _two_port_summary())
    observed = port_norm.observed_ports_from_report(payload)

    assert observed.get(_TWO_PORT_IP) == {5479, 8796}


# ---------------------------------------------------------------------------
# 迁移期计数的两条边界（Fable 监督 WARN#2 指出的覆盖缺口）
#
# B-2 重构把清单的迁移逻辑集中进 core.runtime_inventory 时，我删掉了 4 条测试、只交代了 2 条。
# 另 2 条断言的行为**至今仍然存在**，只是失去了保护，这里按新 schema 补回：
#   1. 「升级已存在的静态端点」也要计入贡献集合（不能只记新增的那一半）；
#   2. 贡献集合长过迁移下界之后，计数要跟着集合走（单调下界只在迁移期兜底，不能永久卡住）。
# ---------------------------------------------------------------------------


def test_upgrading_an_existing_static_endpoint_still_counts(tmp_path: Path) -> None:
    """本次采集命中的是一个**已存在的静态端点**（升级而非新增）→ 仍要计入贡献集合。

    贡献集合若只记「新增的端点」，就会漏掉「升级已有端点」这一半：静态早已提取到的 IP
    这次被实测连上，恰恰是最强的那类证据，反而不计数。
    """
    p = tmp_path / "report.json"
    static_ep = {
        "value": _BACKEND_IP, "kind": "ip", "is_private": False,
        "evidences": [{"source": "dex", "location": "classes.dex", "snippet": "静态抓到的"}],
        "enrichment": {},
    }
    p.write_text(json.dumps(_report_with(extra_endpoints=[static_ep]), ensure_ascii=False),
                 encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(p), _bidirectional_summary())
    payload = json.loads(p.read_text(encoding="utf-8"))

    assert len([e for e in payload["endpoints"] if e["value"] == _BACKEND_IP]) == 1, "端点重复了"
    inventory = payload["meta"][runtime_inventory.INVENTORY_META_KEY]
    assert inventory["remote_endpoints"] == 1, "被升级的静态端点没计入贡献集合"


def test_counts_follow_the_set_once_it_overtakes_the_migrated_floor(tmp_path: Path) -> None:
    """单调下界**只在迁移期**兜底：贡献集合长过旧值之后，计数要跟着集合走。

    与 ``test_old_endpoint_and_domain_counts_do_not_regress`` 是同一机制的两个方向——
    那条防「旧计数被重置」，这条防「计数永久卡在旧下界上、后续采集白抓」。
    """
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_report_with(meta={
        runtime_inventory.INVENTORY_META_KEY: {"remote_endpoints": 1},
    }), ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(p), _bidirectional_summary())   # _BACKEND_IP
    pcap_ingest.merge_into_report_json(str(p), _two_port_summary())        # _TWO_PORT_IP
    payload = json.loads(p.read_text(encoding="utf-8"))

    inventory = payload["meta"][runtime_inventory.INVENTORY_META_KEY]
    assert inventory["remote_endpoints"] == 2, "集合已有两个 IP，计数还卡在旧的下界上"
    assert sorted(payload["meta"]["runtime_pcap_endpoint_values"]) == sorted(
        [_BACKEND_IP, _TWO_PORT_IP]
    )
