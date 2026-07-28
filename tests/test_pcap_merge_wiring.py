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

from apkscan.core import visibility
from apkscan.core.closure.targets import _select_targets_with_stats
from apkscan.core.report_io import report_from_dict
from apkscan.dynamic import pcap_ingest

#: 静态侧的两条噪音（云段模板 IP + SDK 域名）——真实报告里这类占了绝大多数。
_STATIC = {
    "package_name": "com.test.app",
    "schema_version": "1.0",
    "meta": {"dex_available": True, "dex_scanned": True, "resource_files_scanned": 3},
    "leads": [
        {"category": "IP", "value": "106.11.35.1", "advice": "建议调证",
         "confidence": "HIGH", "where_to_request": "云厂商", "evidence_to_obtain": ["租户"]},
        {"category": "DOMAIN", "value": "sdk.example.com", "advice": "建议调证",
         "confidence": "HIGH", "where_to_request": "注册商", "evidence_to_obtain": ["实名"]},
    ],
    "endpoints": [
        {"value": "106.11.35.1", "kind": "ip", "evidences": [{"source": "dex", "location": "a"}]},
        {"value": "sdk.example.com", "kind": "domain",
         "evidences": [{"source": "dex", "location": "a"}]},
    ],
    "findings": [], "analyzer_status": [],
}


def _bidirectional_summary(ip: str = "8.138.102.85", port: int = 31861) -> pcap_ingest.PcapSummary:
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


def _two_port_summary(ip: str = "8.163.60.2") -> pcap_ingest.PcapSummary:
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
    assert "8.138.102.85" in ips, "回灌没把运行时端点写进 endpoints"

    ep = next(e for e in payload["endpoints"] if e["value"] == "8.138.102.85")
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

    assert values[0] == "8.138.102.85", f"实测后端应排第一，实得 {values}"
    assert "106.11.35.1" in values, "静态候选仍参选，只是让位"


def test_runtime_backend_survives_a_tight_budget(tmp_path: Path) -> None:
    """★max_targets 截断时，让位的必须是静态噪音而不是实测后端。"""
    payload = _merge(tmp_path, _bidirectional_summary())
    rep = report_from_dict(payload)

    selected, stats = _select_targets_with_stats(rep, max_targets=1)

    assert [e.value for e in selected] == ["8.138.102.85"]
    assert stats["truncated"] == 2


def test_lead_port_suffix_matches_bare_ip_endpoint(tmp_path: Path) -> None:
    """★两侧值形状不同是设计使然，配对必须容得下：Lead 带 ``:port/proto``、Endpoint 是裸 IP。

    端口留在 Lead 上是因为调证函要写它；Endpoint 用裸 IP 是因为富化器与静态端点都按裸 IP 算。
    退回 _match_value 的剥端口，两边永远配不上，真后端又变回"连候选都不是"。
    """
    payload = _merge(tmp_path, _bidirectional_summary())
    lead = next(ld for ld in payload["leads"] if "8.138" in ld["value"])
    assert lead["value"] == "8.138.102.85:31861/tcp", "Lead 侧保留端口"

    rep = report_from_dict(payload)
    selected, _ = _select_targets_with_stats(rep, max_targets=6)
    assert "8.138.102.85" in [e.value for e in selected]


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

    inv = payload["meta"]["runtime_pcap_inventory"]
    assert inv["uid_attributed"] is False
    assert inv["remote_endpoints"] == 1

    ep = next(e for e in payload["endpoints"] if e["value"] == "8.138.102.85")
    assert "target_attributed" not in ep["enrichment"]["runtime"], (
        "没做归因就不能写这个字段——它会被闭环当成'已归因到目标'"
    )


# ---------------------------------------------------------------------------
# 反向护栏
# ---------------------------------------------------------------------------


def test_existing_static_endpoint_is_upgraded_not_duplicated(tmp_path: Path) -> None:
    """静态已知的 IP 这次被实测连上 → 并进原端点（升级），不另起一条。"""
    payload = _merge(tmp_path, _bidirectional_summary(ip="106.11.35.1", port=443))

    hits = [e for e in payload["endpoints"] if e["value"] == "106.11.35.1"]
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
    rt = _runtime_of(payload, "8.163.60.2")

    assert sorted(rt["remote_endpoints"]) == ["8.163.60.2:5479", "8.163.60.2:8796"]
    assert sorted(rt["ports"]) == [5479, 8796]


def test_multi_port_counters_are_summed_not_overwritten(tmp_path: Path) -> None:
    """★字节与连接数按端口累加，不是被后一个端口覆盖。"""
    payload = _merge(tmp_path, _two_port_summary())
    rt = _runtime_of(payload, "8.163.60.2")

    assert rt["out_bytes"] == 1759 + 258, "上行字节没有跨端口累加"
    assert rt["in_bytes"] == 546 + 447
    assert rt["has_payload"] is True


def test_representative_port_is_the_high_traffic_one(tmp_path: Path) -> None:
    """代表端口取流量最大的那个（主通道），不是最后并入的那个。

    实测形态是"一主一心跳"；心跳端口若当上代表值，展示与调证函会指向次要通道。
    """
    rt = _runtime_of(_merge(tmp_path, _two_port_summary()), "8.163.60.2")
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


def test_port_normalize_can_read_the_merged_endpoint(tmp_path: Path) -> None:
    """★接线锁：port-normalize 的数据源必须真的被生成。

    它读 ``endpoints[].enrichment["runtime"]["remote_endpoints"]``（``"ip:port"`` 形态）。
    该字段此前根本没被 pcap 回灌生成，文档宣称的「报告实测端口交叉校验」对这类报告不可用——
    只测端点建出来了，挡不住这种「字段名对不上、下游静默拿不到」。
    """
    from apkscan.config import port_norm

    payload = _merge(tmp_path, _two_port_summary())
    observed = port_norm.observed_ports_from_report(payload)

    assert observed.get("8.163.60.2") == {5479, 8796}
