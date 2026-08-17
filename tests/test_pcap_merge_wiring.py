"""`pcap-leads --into` 回灌后，报告三个消费面必须说同一件事。

一份 report.json 有三个互不相干的消费面：调证函读 ``leads``、闭环排序读 ``endpoints``、
可见性读 ``meta``。回灌此前只更新第一面，于是同一份报告里：

- Lead 标着 ``is_runtime_contact=true``、notes 写"双向载荷=已通信后端"；
- 闭环主目标却挑满静态噪音，实测的真后端连候选都不是；
- digest 还写着 runtime ``unavailable``、"未做运行时观测"。

三处各自看都自洽，合起来自相矛盾。本文件从**回灌入口**驱动，逐面断言。
"""

from __future__ import annotations

import struct

import json
from pathlib import Path

import pytest

from apkscan.core import visibility
from apkscan.core.closure.layers import _runtime_layer
from apkscan.core.closure.targets import _select_targets_with_stats
from apkscan.core.models import LeadCategory, Report
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
    "schema_version": "1.2",
    "meta": {"dex_available": True, "dex_scanned": True, "resource_files_scanned": 3},
    "leads": [
        {"category": "IP", "value": "106.11.35.1", "advice": "建议调证",  # leak-scan: allow pcap 回灌接线夹具，须被判公网远端才会并入 endpoints
         "confidence": "HIGH", "where_to_request": "云厂商", "evidence_to_obtain": ["租户"]},
        {"category": "DOMAIN", "value": "sdk.example.com", "advice": "建议调证",
         "confidence": "HIGH", "where_to_request": "注册商", "evidence_to_obtain": ["实名"]},
    ],
    "endpoints": [
        {"value": "106.11.35.1", "kind": "ip", "evidences": [{"source": "dex", "location": "a", "scope": "case_evidence"}]},  # leak-scan: allow pcap 回灌接线夹具，须被判公网远端才会并入 endpoints
        {"value": "sdk.example.com", "kind": "domain",
         "evidences": [{"source": "dex", "location": "a", "scope": "case_evidence"}]},
    ],
    "findings": [], "analyzer_status": [],
}


def _bidirectional_summary(ip: str = _BACKEND_IP, port: int = 31861) -> pcap_ingest.PcapSummary:
    """目标与 ip:port 有过双向载荷的 pcap（复刻三份在手样本共有的强证据形态）。

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

    实测多份真样本里，动态证据已满足闭环门槛，closure 却仍判 partial、五层归属预算被噪音耗尽。
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


def test_stored_visibility_snapshot_is_refreshed_not_left_stale(tmp_path: Path) -> None:
    """★落盘的快照必须等于对该 payload **现场重算**的结果——派生视图不许留旧值。

    上面那条测试断言的是 ``visibility.assess(payload)``，即**现场重算**：判据永远正确，
    而报告里存的 ``meta.visibility`` 可以一直是旧的，测试照样全绿。实测一份真实报告：
    ``runtime_merged=True``、23 个运行时端点、27 条活体确认线索，而存下的快照仍写着
    「未做运行时观测（纯静态分析）」——因为 ``pcap-leads --into`` 只写信号、不刷快照。

    ★这条测试的**结构性价值**在于它不针对某个写方：任何往 meta 写信号却忘了刷新派生视图的
      路径都会让它变红。「每个写方都要记得」靠不住，得让不变量自己可测。
    """
    payload = _merge(tmp_path, _bidirectional_summary())

    stored = payload["meta"]["visibility"]
    recomputed = visibility.assess(payload)
    assert stored == recomputed, (
        "落盘快照与现场重算不一致——写方往 meta 追加了信号却没重算派生视图"
    )
    # 顺带钉住这次的具体后果：不得再声称"未做运行时观测"
    assert stored["sources"]["runtime"]["visibility"] == visibility.VIS_PARTIAL


def test_empty_capture_leaves_visibility_snapshot_honest(tmp_path: Path) -> None:
    """反向：真·空采集刷新后仍是 ``unavailable``——刷新不得凭空造出运行时维。

    ★断言不带 `if`：曾写成 `if stored is not None:`，一旦刷新接线缺失、快照压根不存在，
      整条测试就一句都不跑、静默变成恒真（codex P2）。
    """
    payload = _merge(tmp_path, pcap_ingest.PcapSummary(flows=[]))

    stored = payload["meta"].get("visibility")
    assert stored is not None, "刷新没落盘快照（接线缺失时这条曾被条件断言静默跳过）"
    assert stored == visibility.assess(payload)
    assert stored["sources"]["runtime"]["visibility"] == visibility.VIS_UNAVAILABLE


def test_stale_snapshot_is_replaced_not_merely_created(tmp_path: Path) -> None:
    """★钉「替换已有陈旧快照」，而不只是「从无到有生成」。

    `_STATIC` 本身不带 `meta.visibility`，所以上面那条其实只验证了"生成"。真实场景是
    analyze 先存了一份 `runtime=unavailable`，回灌后必须被改写成 partial（codex P2）。
    """
    p = tmp_path / "report.json"
    stale = json.loads(json.dumps(_STATIC))
    stale.setdefault("meta", {})["visibility"] = {
        "sources": {"runtime": {"visibility": visibility.VIS_UNAVAILABLE,
                                "why": ["未做运行时观测（纯静态分析）"]}},
        "blocked_claims": [],
    }
    p.write_text(json.dumps(stale, ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(p), _bidirectional_summary())
    payload = json.loads(p.read_text(encoding="utf-8"))
    rt = payload["meta"]["visibility"]["sources"]["runtime"]

    assert rt["visibility"] == visibility.VIS_PARTIAL, "陈旧快照没被替换"
    assert not any("未做运行时观测" in w for w in rt["why"]), rt["why"]


def test_refresh_preserves_a_gap_when_its_inputs_were_stripped() -> None:
    """刷新必须是**信息保持**的：该维输入被裁掉时沿用旧盲区，别从零重推成"完整可见"。

    这是回灌无条件刷新的安全前提——若重算会丢盲区，那这条接线就成了新的「未发现被读成已穷尽」。

    当前快照会记录逐维 ``inputs_seen``；后续刷新只要发现旧键消失，就沿用旧盲区。
    旧 schema 没有该字段时仍按「该维输入全删」兼容，避免冻结合法 runtime 升级。
    """
    from apkscan.core.closure import refresh_visibility_snapshot

    hardened = {
        "dex_available": True, "dex_scanned": 1, "is_hardened": True,
        "hardening_structural": {"verdict": "hardened"}, "dex_string_pool": 0,
    }
    snap = visibility.assess({"meta": hardened})
    assert snap["sources"]["dex"]["visibility"] in visibility.INSUFFICIENT

    stripped: dict[str, object] = {"visibility": snap}   # 该维输入全被裁掉
    refresh_visibility_snapshot(stripped)

    after = stripped["visibility"]
    assert isinstance(after, dict)
    assert after["sources"]["dex"]["visibility"] in visibility.INSUFFICIENT, \
        "输入被裁掉后重算把确证盲区刷成了完整可见"
    for claim in ("no_contact_harvesting", "no_sms_interception"):
        assert claim in after["blocked_claims"], f"{claim} 被凭空解禁"


def test_refresh_preserves_gap_when_only_some_inputs_were_stripped() -> None:
    """只剩一个无害键也不能把加固盲区刷成 complete；旧 ``any()`` 判据会放过此案。"""
    from apkscan.core.closure import refresh_visibility_snapshot

    original = {
        "dex_available": True,
        "dex_scanned": 1,
        "dex_string_pool": 0,
        "is_hardened": True,
        "hardening_structural": {"verdict": "hardened"},
    }
    snapshot = visibility.assess({"meta": original})
    trimmed: dict[str, object] = {
        "dex_available": True,
        "visibility": snapshot,
    }

    refresh_visibility_snapshot(trimmed)

    after = trimmed["visibility"]
    assert isinstance(after, dict)
    assert after["sources"]["dex"]["visibility"] in visibility.INSUFFICIENT
    assert any(
        note.startswith("[dex]") and ("加固" in note or "壳" in note)
        for note in after["notes"]
    ), "回填源之后 notes 仍是裁剪输入重算出的新说明"
    assert any("unpack" in action for action in after["next_actions"]), \
        "回填 DEX 盲区后没有恢复对应补救动作"
    for claim in ("no_contact_harvesting", "no_sms_interception"):
        assert claim in after["blocked_claims"], f"{claim} 被凭空解禁"


def test_refresh_preserves_gap_when_old_input_disappears_as_new_one_is_added() -> None:
    """新键不能掩盖旧键丢失；只判断「当前是真子集」会漏掉这种混合变化。"""
    from apkscan.core.closure import refresh_visibility_snapshot

    original = {
        "dex_available": True,
        "is_hardened": True,
        "hardening_structural": {"verdict": "hardened"},
    }
    snapshot = visibility.assess({"meta": original})
    changed: dict[str, object] = {
        "dex_available": True,
        "extra_dex_visibility": {"requested": 1, "loaded": 1, "complete": True},
        "visibility": snapshot,
    }

    refresh_visibility_snapshot(changed)

    after = changed["visibility"]
    assert isinstance(after, dict)
    assert after["sources"]["dex"]["visibility"] in visibility.INSUFFICIENT
    assert "no_contact_harvesting" in after["blocked_claims"]


def test_legacy_snapshot_with_no_inputs_left_keeps_confirmed_gap() -> None:
    """1.0 快照无 provenance 时仍保留旧有的「该维输入全删才回填」兼容保护。"""
    from apkscan.core.closure import refresh_visibility_snapshot

    legacy = {
        "schema_version": "1.0",
        "sources": {
            "dex": {
                "visibility": visibility.VIS_STUB_ONLY,
                "why": ["旧报告已确认只看到壳桩"],
            },
        },
        "blocked_claims": ["no_contact_harvesting", "no_sms_interception"],
    }
    meta: dict[str, object] = {"visibility": legacy}

    refresh_visibility_snapshot(meta)

    after = meta["visibility"]
    assert isinstance(after, dict)
    assert after["schema_version"] == "1.0", "含无 provenance 旧源的快照不能冒充 1.1"
    assert after["sources"]["dex"]["visibility"] == visibility.VIS_STUB_ONLY
    assert "inputs_seen" not in after["sources"]["dex"]
    assert "no_contact_harvesting" in after["blocked_claims"]


def test_legacy_snapshot_does_not_freeze_a_valid_runtime_upgrade() -> None:
    """旧快照不知道原键集合；已有新 runtime 信号时必须允许刷新，不能一律保守回填。"""
    from apkscan.core.closure import refresh_visibility_snapshot

    legacy = {
        "schema_version": "1.0",
        "sources": {
            "runtime": {
                "visibility": visibility.VIS_UNAVAILABLE,
                "why": ["未做运行时观测（纯静态分析）"],
            },
        },
        "blocked_claims": ["runtime_contact_observed"],
    }
    meta: dict[str, object] = {
        "capture_quality": {"dynamic_status": "complete", "reason": "ok"},
        "visibility": legacy,
    }

    refresh_visibility_snapshot(meta)

    after = meta["visibility"]
    assert isinstance(after, dict)
    assert after["sources"]["runtime"]["visibility"] == visibility.VIS_COMPLETE
    assert "runtime_contact_observed" not in after["blocked_claims"]


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
    assert all(
        ev.get("scope") == "case_evidence"
        for ev in hits[0]["evidences"]
        if ev.get("source") == "runtime-pcap"
    )


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
def test_record_only_summary_is_auditable_runtime_observation(tmp_path: Path) -> None:
    """DNS answer 本身是可审计的运行时证据，即使没有 flow/query 集合也要落主报告。"""
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")

    rec = pcap_ingest.DnsRecord(
        qname="entry.example.test", qtype=1, rcode=0, txid=7, ts=1723305600.25,
        answers=[
            {"name": "entry.example.test", "type": 5,
             "value": "route.example.test", "ttl": 60},
            {"name": "route.example.test", "type": 5,
             "value": "origin.example.test", "ttl": 60},
            {"name": "origin.example.test", "type": 1,
             "value": "198.51.100.42", "ttl": 30},
        ],
    )
    pcap_ingest.merge_into_report_json(str(p), pcap_ingest.PcapSummary(dns_records=[rec]))
    payload = json.loads(p.read_text(encoding="utf-8"))
    meta = payload["meta"]

    assert meta["runtime_merged"] is True
    ep = next(e for e in payload["endpoints"] if e["value"] == "entry.example.test")
    dns = ep["enrichment"]["dns_runtime"]
    assert dns["ips"] == ["198.51.100.42"]
    assert dns["cname_edges"] == [
        {"from": "entry.example.test", "to": "route.example.test"},
        {"from": "route.example.test", "to": "origin.example.test"},
    ]
    assert dns["records"][0]["txid"] == 7
    assert dns["records"][0]["observed_at"] == 1723305600.25
    assert ep["evidences"][0]["scope"] == "case_evidence"


def test_dns_record_merge_is_idempotent_and_independent_of_flow_fingerprint(tmp_path: Path) -> None:
    """同一 record 重并不重复；纯 DNS 的后续不同答案也不能被空 flow 指纹挡住。"""
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")
    first = pcap_ingest.DnsRecord(
        qname="entry.example.test", qtype=1, rcode=0, txid=1, ts=1.0,
        answers=[{"name": "entry.example.test", "type": 1,
                  "value": "198.51.100.41", "ttl": 30}],
    )
    second = pcap_ingest.DnsRecord(
        qname="entry.example.test", qtype=1, rcode=0, txid=2, ts=2.0,
        answers=[{"name": "entry.example.test", "type": 1,
                  "value": "198.51.100.42", "ttl": 30}],
    )

    pcap_ingest.merge_into_report_json(str(p), pcap_ingest.PcapSummary(dns_records=[first]))
    pcap_ingest.merge_into_report_json(str(p), pcap_ingest.PcapSummary(dns_records=[first]))
    pcap_ingest.merge_into_report_json(str(p), pcap_ingest.PcapSummary(dns_records=[second]))
    payload = json.loads(p.read_text(encoding="utf-8"))
    ep = next(e for e in payload["endpoints"] if e["value"] == "entry.example.test")
    dns = ep["enrichment"]["dns_runtime"]

    assert dns["ips"] == ["198.51.100.41", "198.51.100.42"]
    assert len(dns["records"]) == 2


def test_cname_without_rr_owner_is_preserved_but_not_invented_as_an_edge(tmp_path: Path) -> None:
    """旧摘要缺 RR owner 时只能保留答案，不能擅自写成 qname→target。"""
    p = tmp_path / "report.json"
    p.write_text(json.dumps(_STATIC, ensure_ascii=False), encoding="utf-8")
    rec = pcap_ingest.DnsRecord(
        qname="entry.example.test", qtype=1, rcode=0, txid=9, ts=3.0,
        answers=[{"type": 5, "value": "origin.example.test", "ttl": 60}],
    )

    pcap_ingest.merge_into_report_json(str(p), pcap_ingest.PcapSummary(dns_records=[rec]))
    payload = json.loads(p.read_text(encoding="utf-8"))
    ep = next(e for e in payload["endpoints"] if e["value"] == "entry.example.test")
    dns = ep["enrichment"]["dns_runtime"]

    assert dns["records"][0]["answers"][0]["name"] == ""
    assert dns["cname_edges"] == [], "没有 RR owner 时不得补造 CNAME 边"


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


def test_endpoint_exclusions_survive_merge_into_main_report(tmp_path) -> None:
    """拦截节点排除必须活到**用户真正读的那份产物**：``report.meta.capture_signals``。

    ★链条是 ``runtime_report.capture_signals.endpoint_exclusions``
      → ``merge_capture_quality`` → ``report.meta.capture_signals.endpoint_exclusions``。
      capture 侧的测试只锁到 runtime_report.json 那一站，而 auto 流程里下游消费方拿到的是主报告。

    ★现在能保留是因为 ``merge_capture_quality`` 对 capture_signals 整体复制
      （``dict(raw_signals)``）；若哪天改成字段白名单而漏了这一项，排除记录就会在合并时
      静默蒸发——那正是这条链最初要修的「静默」本身。本条把最终落点钉住。
    """
    from apkscan.dynamic.merge import merge_capture_quality

    runtime = tmp_path / "runtime_report.json"
    runtime.write_text(
        json.dumps(
            {
                "capture_signals": {
                    "endpoint_total": 3,
                    "endpoint_exclusions": {"known_intercept_ips": ["203.0.113.77"]},
                }
            }
        ),
        encoding="utf-8",
    )
    report = Report(
        package_name="com.example.synthetic", meta={}, leads=[], endpoints=[], findings=[],
        analyzer_status=[{"name": "manifest", "status": "ran"}],
    )

    merge_capture_quality(report, str(runtime))

    merged = (report.meta.get("capture_signals") or {}).get("endpoint_exclusions") or {}
    assert merged.get("known_intercept_ips") == ["203.0.113.77"], (
        f"排除记录在合并进主报告时丢了：{report.meta.get('capture_signals')}"
    )


# ---------------------------------------------------------------------------
# 归因结论必须传导到证据来源标签（否则下游会把其他应用的流量当成本样本的实连）
# ---------------------------------------------------------------------------


def _one_flow_summary(dst_ip: str, dst_port: int = 30110):
    """一条有双向载荷的 TCP 流，足以产出 IP Lead 与 Endpoint。"""
    out = pcap_ingest.Flow(
        proto="tcp", src_ip="10.0.0.2", src_port=50000, dst_ip=dst_ip, dst_port=dst_port,
        packets=8, bytes_=800, payload_bytes=400, first_ts=1.0, last_ts=2.0,
        flags={"syn", "ack", "psh"},
    )
    back = pcap_ingest.Flow(
        proto="tcp", src_ip=dst_ip, src_port=dst_port, dst_ip="10.0.0.2", dst_port=50000,
        packets=8, bytes_=900, payload_bytes=500, first_ts=1.1, last_ts=2.1,
        flags={"synack", "ack", "psh"},
    )
    return pcap_ingest.PcapSummary(flows=[out, back])


def _attr(ip: str, *, is_target: object, port: int = 30110) -> dict:
    return {f"tcp/{ip}:{port}": {
        "attribution": "confirmed" if is_target is True else "unattributed",
        "is_target_app": is_target,
        "score": 0.95 if is_target is True else 0.0,
    }}


def test_unattributed_pcap_endpoint_is_not_observed_contact() -> None:
    """★ 归因判定「不属于目标应用」时，证据来源须降为非 observed-contact。

    2026-08-12 实证：同一次全设备抓包并入两个样本的报告后，工具已算出
    is_target_app=false 的流量，在报告中仍显示为「已抓到通信的确认 C2」——
    根因是来源标签不带归因结论。本用例锁住 producer 侧的降档。
    """
    ip = "100.64.9.9"
    summary = _one_flow_summary(ip)

    [lead] = [x for x in pcap_ingest.to_report_leads(summary, _attr(ip, is_target=False))
              if x.category is LeadCategory.IP]
    assert lead.is_runtime_seen is True, "仍应算运行时出现"
    assert lead.is_runtime_contact is False, "但不得算已确认接触"

    [ok] = [x for x in pcap_ingest.to_report_leads(summary, _attr(ip, is_target=True))
            if x.category is LeadCategory.IP]
    assert ok.is_runtime_contact is True, "归因确认时应保持 observed-contact"


def test_missing_attribution_table_does_not_downgrade() -> None:
    """反向：没做归因不等于已判定不是——缺信息不得反向降档。

    与 _attr_block「没有 socket 快照时一个字段都不写」同一条哲学。
    """
    ip = "100.64.9.10"
    summary = _one_flow_summary(ip)
    for attr in (None, {}, {"tcp/203.0.113.1:443": {"is_target_app": False}}):
        [lead] = [x for x in pcap_ingest.to_report_leads(summary, attr)
                  if x.category is LeadCategory.IP]
        assert lead.is_runtime_contact is True, f"未归因不应降档：{attr}"


def test_attribution_downgrade_reaches_report_json(tmp_path: Path) -> None:
    """★ 走 merge_into_report_json 真入口：降档必须落到 report.json 的证据里。

    只测 to_report_leads 锁不住接线——真入口若忘了把 app_attr 透传下去，
    上面两条照样全绿，而报告里仍是 runtime-pcap。
    """
    ip = "100.64.9.11"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(
        str(path), _one_flow_summary(ip), _attr(ip, is_target=False)
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    sources = {
        ev.get("source")
        for lead in payload["leads"] if ip in str(lead.get("value"))
        for ev in lead.get("source_refs") or []
    }
    assert sources == {"runtime-derived"}, f"真入口未透传归因结论：{sources}"

    # ★endpoints 与 leads 是**两条**生产线：leads 走 to_report_leads，endpoints 走
    #   _runtime_endpoint_dicts。只断言 leads 会漏掉后者——闭环排序、五层归属、外部富化
    #   全以 endpoints 为对象，它若仍是 runtime-pcap，降档等于只做了一半。
    ep_sources = {
        ev.get("source")
        for ep in payload["endpoints"] if ep.get("value") == ip
        for ev in ep.get("evidences") or []
    }
    assert ep_sources == {"runtime-derived"}, f"endpoints 侧未降档：{ep_sources}"


def _dns_query_bytes(name: str, txid: int = 0x1234) -> bytes:
    """一条最小 DNS 查询报文（A 记录）。"""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def test_dns_over_tcp_is_parsed() -> None:
    """★ DNS over TCP（RFC 1035 §4.2.2）必须解析：报文前有 2 字节长度前缀。

    此前 TCP 分支完全不解 DNS，走 TCP/53 的采集一条记录都出不来，
    报告显示"未观测到 DNS"——与"确实没查过域名"无法区分。应答超 512 字节被 TC
    截断后客户端就改走 TCP，部分系统解析器也直接用 TCP，不是罕见形态。
    """
    name = "config.example.test"
    msg = _dns_query_bytes(name)
    payload = struct.pack("!H", len(msg)) + msg
    flow = pcap_ingest.Flow(
        proto="tcp", src_ip="10.0.0.2", src_port=50100, dst_ip="100.64.9.40", dst_port=53,
        packets=1, bytes_=len(payload), payload_bytes=len(payload),
    )
    assert pcap_ingest._iter_tcp_dns_messages(payload) == [msg]
    assert pcap_ingest._parse_dns_qname(msg) == name
    del flow  # 形态参照，本用例只锁切分与解析


def test_tcp_dns_length_prefix_is_validated() -> None:
    """长度前缀可被伪造：声明长度越界或短于 DNS 头时整段放弃，不半解一条当证据。

    ★继续往下猜偏移就是在编报文——取证工具宁可漏、不可造。
    """
    msg = _dns_query_bytes("a.example.test")
    # 声明长度超出实际剩余
    assert pcap_ingest._iter_tcp_dns_messages(struct.pack("!H", len(msg) + 50) + msg) == []
    # 声明长度短于 DNS 头（12 字节）
    assert pcap_ingest._iter_tcp_dns_messages(struct.pack("!H", 5) + b"\x00" * 5) == []
    # 前一条完整、后一条越界 → 只收完整的那条
    good = struct.pack("!H", len(msg)) + msg
    assert pcap_ingest._iter_tcp_dns_messages(good + struct.pack("!H", 999) + b"\x00" * 4) == [msg]


def _sni_flow(dst_ip: str, dst_port: int, name: str, *, ts: float = 1.0):
    """一条带 SNI 的出方向 TLS 流。"""
    return pcap_ingest.Flow(
        proto="tcp", src_ip="10.0.0.2", src_port=50001, dst_ip=dst_ip, dst_port=dst_port,
        packets=6, bytes_=600, payload_bytes=300, first_ts=ts, last_ts=ts + 1,
        flags={"syn", "ack", "psh"}, sni={name},
    )


def _domain_lead(summary, attr, name: str):
    return next(
        x for x in pcap_ingest.to_report_leads(summary, attr)
        if x.category is LeadCategory.DOMAIN and x.value == name
    )


def test_domain_lead_follows_carrier_attribution() -> None:
    """★ 域名侧同样要跟归因走：承载它的连接全被判非目标时，不得算已确认接触。

    此前域名 Lead 固定钉 runtime-pcap，于是同一条被判非目标的连接，IP 侧降了档、
    它的 SNI 域名却仍渲染成「已抓到通信」——降档从旁路又漏了回去。
    """
    ip, name = "100.64.9.12", "api.example.com"
    summary = pcap_ingest.PcapSummary(flows=[_sni_flow(ip, 443, name)])

    assert _domain_lead(summary, _attr(ip, is_target=False, port=443), name).is_runtime_contact is False
    assert _domain_lead(summary, _attr(ip, is_target=True, port=443), name).is_runtime_contact is True


def test_domain_lead_keeps_contact_when_any_carrier_is_target() -> None:
    """多个承载端点时：只要有一个确属目标，该域名就仍是已确认接触。

    目标确实用这个名字连过——哪怕别的进程也连了同一个名字（公共 CDN 域名极常见）。
    """
    name = "cdn.example.com"
    mine, theirs = "100.64.9.13", "100.64.9.14"
    summary = pcap_ingest.PcapSummary(
        flows=[_sni_flow(mine, 443, name), _sni_flow(theirs, 443, name, ts=5.0)]
    )
    attr = {**_attr(mine, is_target=True, port=443), **_attr(theirs, is_target=False, port=443)}
    assert _domain_lead(summary, attr, name).is_runtime_contact is True


def test_domain_lead_not_downgraded_on_partial_attribution() -> None:
    """承载端点没被全部归因时维持原样——缺信息不反向降档，同 _endpoint_source 第 2 态。

    另锁 DNS 查询出来的域名：它没有承载连接，任何归因表都不该让它降档。
    """
    name, dns_name = "partial.example.com", "queried.example.com"
    known, unknown = "100.64.9.15", "100.64.9.16"
    summary = pcap_ingest.PcapSummary(
        flows=[_sni_flow(known, 443, name), _sni_flow(unknown, 443, name, ts=5.0)],
        dns_queries={dns_name},
    )
    attr = _attr(known, is_target=False, port=443)  # unknown 那条不在表内
    assert _domain_lead(summary, attr, name).is_runtime_contact is True
    assert _domain_lead(summary, attr, dns_name).is_runtime_contact is True


def test_same_ip_multi_port_attribution_is_order_independent() -> None:
    """★ 同 IP 多端口：IP 级归因不得由「哪个端口先被迭代到」决定。

    _attr_block 此前只在首次创建端点时调用一次，同一 IP 的 :443 属目标、:9000 属他进程时，
    结论随 flow 插入顺序摇摆。逐端口 evidence 则各标各的，不因 IP 级结论被抹平。
    """
    ip = "100.64.9.17"
    attr = {**_attr(ip, is_target=True, port=443), **_attr(ip, is_target=False, port=9000)}
    mine = _one_flow_summary(ip, 443).flows
    theirs = _one_flow_summary(ip, 9000).flows

    results = []
    for flows in (mine + theirs, theirs + mine):
        [ep] = pcap_ingest._runtime_endpoint_dicts(pcap_ingest.PcapSummary(flows=flows), attr)
        results.append(ep)
        assert {ev["source"] for ev in ep["evidences"]} == {"runtime-pcap", "runtime-derived"}, (
            "逐端口证据应各标各的来源"
        )
    assert [r["enrichment"]["runtime"]["target_attributed"] for r in results] == [True, True], (
        "任一端口确属目标即算被目标连过，且与 flow 顺序无关"
    )


def test_runtime_endpoints_multi_port_source_is_order_independent() -> None:
    """to_runtime_endpoints 按裸 IP 折叠，来源标签同样不得由首个端口决定。

    与上一条测的是**另一个函数**：这个按 IP 折叠、每 IP 只有一条证据，
    故只能按该 IP 全部端口聚合；上一条按端口逐条建证据。
    """
    ip = "100.64.9.18"
    attr = {**_attr(ip, is_target=True, port=443), **_attr(ip, is_target=False, port=9000)}
    mine = _one_flow_summary(ip, 443).flows
    theirs = _one_flow_summary(ip, 9000).flows

    for flows in (mine + theirs, theirs + mine):
        [ep] = [
            e for e in pcap_ingest.to_runtime_endpoints(
                pcap_ingest.PcapSummary(flows=flows), app_attr=attr
            ) if e.value == ip
        ]
        assert {ev.source for ev in ep.evidences} == {"runtime-pcap"}, (
            "任一端口确属目标即保留，且与 flow 顺序无关"
        )

    # 全部端口都判非目标 → 降档
    none_attr = {**_attr(ip, is_target=False, port=443), **_attr(ip, is_target=False, port=9000)}
    [ep] = [
        e for e in pcap_ingest.to_runtime_endpoints(
            pcap_ingest.PcapSummary(flows=mine + theirs), app_attr=none_attr
        ) if e.value == ip
    ]
    assert {ev.source for ev in ep.evidences} == {"runtime-derived"}


def test_inbound_clienthello_sni_is_attributed_to_the_real_remote() -> None:
    """★ 入站 ClientHello：承载键必须是**远端**，不能按 flow.dst 拼成本机地址。

    设备上的应用监听 TLS、外部节点主动连入时，ClientHello 在「公网源 → 本机目的」方向。
    若按 dst 拼键会得到本机地址，查归因表必落空 → 被当作"未完全归因"而保留 observed-contact
    ——保守的方向恰恰是本次要消除的过度断言。
    """
    remote_ip, name = "100.64.9.19", "inbound.example.com"
    inbound = pcap_ingest.Flow(
        proto="tcp", src_ip=remote_ip, src_port=44300, dst_ip="10.0.0.2", dst_port=8443,
        packets=6, bytes_=600, payload_bytes=300, first_ts=1.0, last_ts=2.0,
        flags={"syn", "psh"}, sni={name},
    )
    summary = pcap_ingest.PcapSummary(flows=[inbound])

    carriers = pcap_ingest._sni_carriers(summary)
    assert carriers[name] == {f"tcp/{remote_ip}:44300"}, f"承载键指向了本机：{carriers}"

    attr = _attr(remote_ip, is_target=False, port=44300)
    assert _domain_lead(summary, attr, name).is_runtime_contact is False


def test_later_attribution_revokes_earlier_observed_contact(tmp_path: Path) -> None:
    """★ 先无快照回灌、后补快照重跑：旧的 runtime-pcap 证据必须被撤销，不能与新的并存。

    证据去重签名含 source，两条只差来源的证据会各自留下；而 is_runtime_contact 是**存在
    量词**——只要旧的还在，降档就等于没发生。这是本次修复的真实逃逸路径。
    """
    ip = "100.64.9.22"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")

    # 第一次：没有 socket 快照，证据以 runtime-pcap 落盘
    pcap_ingest.merge_into_report_json(str(path), _one_flow_summary(ip), None)
    first = json.loads(path.read_text(encoding="utf-8"))
    assert {
        ev.get("source") for lead in first["leads"] if ip in str(lead.get("value"))
        for ev in lead.get("source_refs") or []
    } == {"runtime-pcap"}, "前置：首次回灌应为 runtime-pcap"

    # 第二次：补上快照，同一份 pcap 重跑，归因明确判非目标
    pcap_ingest.merge_into_report_json(str(path), _one_flow_summary(ip), _attr(ip, is_target=False))
    payload = json.loads(path.read_text(encoding="utf-8"))
    for lead in payload["leads"]:
        if ip not in str(lead.get("value")):
            continue
        sources = {ev.get("source") for ev in lead.get("source_refs") or []}
        assert sources == {"runtime-derived"}, f"旧证据未被撤销，contact 仍成立：{sources}"
        assert lead.get("is_runtime_contact") is False
    for ep in payload["endpoints"]:
        if ep.get("value") != ip:
            continue
        sources = {ev.get("source") for ev in ep.get("evidences") or []}
        assert sources == {"runtime-derived"}, f"端点侧旧证据未被撤销：{sources}"


def test_explicit_target_restores_contact_on_both_faces(tmp_path: Path) -> None:
    """★ 先降档、后**明确判定属于目标**时，两个消费面都要恢复——不能只恢复一面。

    ★这一条补的是与上一条相反的方向，而缺它曾漏掉一个真缺陷：
      ``_restamp_runtime_endpoint_evidence`` 里把"撤销"与"追加"耦合成
      ``if not revoke(...): continue``，于是降档（有取代关系、撤销数>0）走得通，
      而升档（本轮 incoming 全是 runtime-pcap、撤销数恒 0）被整条跳过——
      lead 面经 merge_runtime_into_lead_dict 恢复了 is_runtime_contact，
      endpoint 面却停在旧的降档证据上。**同一事实两个消费面相反结论**，
      而闭环排序读的正是 endpoint 面，已确认属目标的后端会继续被当降档处理。

    ★缺信息不翻案（下一条）与明确证据可翻案（本条）必须成对锁：
      只锁前者的话，把升档路径整个删掉也照样全绿。
    """
    ip = "100.64.9.24"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")

    # 第一轮：明确判非目标 → 两面都降档
    pcap_ingest.merge_into_report_json(str(path), _one_flow_summary(ip), _attr(ip, is_target=False))
    first = json.loads(path.read_text(encoding="utf-8"))
    assert {ev.get("source") for ep in first["endpoints"] if ep.get("value") == ip
            for ev in ep.get("evidences") or []} == {"runtime-derived"}, "前置：端点面先降档"

    # 第二轮：同一份 pcap，本轮归因明确判**属于**目标
    pcap_ingest.merge_into_report_json(str(path), _one_flow_summary(ip), _attr(ip, is_target=True))
    payload = json.loads(path.read_text(encoding="utf-8"))

    lead_sources = {
        ev.get("source") for lead in payload["leads"] if ip in str(lead.get("value"))
        for ev in lead.get("source_refs") or []
    }
    ep_sources = {
        ev.get("source") for ep in payload["endpoints"] if ep.get("value") == ip
        for ev in ep.get("evidences") or []
    }
    assert lead_sources == {"runtime-pcap"}, f"lead 面未原子恢复：{lead_sources}"
    assert ep_sources == {"runtime-pcap"}, (
        f"★endpoint 面未原子恢复：{ep_sources}——两个消费面对同一事实给出相反结论，"
        "而闭环排序读的是 endpoint 面"
    )
    assert any(lead.get("is_runtime_contact") is True
               for lead in payload["leads"] if ip in str(lead.get("value")))
    endpoint = next(ep for ep in payload["endpoints"] if ep.get("value") == ip)
    runtime = endpoint["enrichment"]["runtime"]
    assert runtime["target_attributed"] is True
    inventory = payload["meta"][runtime_inventory.INVENTORY_META_KEY]
    assert inventory["target_attributed"] == 1
    assert payload["meta"][runtime_inventory.TARGET_ATTRIBUTED_SET_KEYS["pcap"]] == [ip]
    carrier = f"tcp/{ip}:30110"
    assert payload["meta"]["capture_signals"]["pcap_app_attribution"][carrier][
        "is_target_app"
    ] is True
    typed_endpoint = next(
        ep for ep in report_from_dict(payload).endpoints if ep.value == ip
    )
    layer = _runtime_layer(typed_endpoint)
    assert layer["status"] == "complete"
    layer_evidence = layer["evidence"]
    assert isinstance(layer_evidence, dict)
    assert layer_evidence["target_attributed"] is True
    for field in ("out_bytes", "in_bytes", "connection_count"):
        assert runtime[field] == next(
            ep for ep in first["endpoints"] if ep.get("value") == ip
        )["enrichment"]["runtime"][field]
    assert payload["meta"]["runtime_pcap_merges"] == first["meta"]["runtime_pcap_merges"]


def test_explicit_denial_replaces_target_on_every_face(tmp_path: Path) -> None:
    """同一 PCAP 的 TARGET→DENIED 必须原子替换所有消费面且不重复计流量。

    ★与上一条成对：上一条锁"升档到得了每个面"，本条锁"降档撤得掉每个面"。
      此前 `_restamp_runtime_endpoint_evidence` 只动 evidences、绝不碰 enrichment，
      于是反转归因后 `runtime.target_attributed` 留着旧 True；inventory 的目标集
      只增不减，显式 DENIED 也撤不掉——闭环照旧把该 IP 当已确认目标通信。
    """
    ip = "100.64.9.50"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")
    summary = _one_flow_summary(ip)

    pcap_ingest.merge_into_report_json(str(path), summary, _attr(ip, is_target=True))
    first = json.loads(path.read_text(encoding="utf-8"))
    pcap_ingest.merge_into_report_json(str(path), summary, _attr(ip, is_target=False))
    payload = json.loads(path.read_text(encoding="utf-8"))

    lead = next(item for item in payload["leads"] if ip in str(item.get("value")))
    endpoint = next(item for item in payload["endpoints"] if item.get("value") == ip)
    runtime = endpoint["enrichment"]["runtime"]
    assert {ev["source"] for ev in lead["source_refs"]} == {"runtime-derived"}
    assert {ev["source"] for ev in endpoint["evidences"]} == {"runtime-derived"}
    assert lead["is_runtime_contact"] is False
    assert runtime["target_attributed"] is False
    inventory = payload["meta"][runtime_inventory.INVENTORY_META_KEY]
    assert inventory["target_attributed"] == 0
    assert payload["meta"][runtime_inventory.TARGET_ATTRIBUTED_SET_KEYS["pcap"]] == []
    carrier = f"tcp/{ip}:30110"
    assert payload["meta"]["capture_signals"]["pcap_app_attribution"][carrier][
        "is_target_app"
    ] is False
    typed_endpoint = next(
        ep for ep in report_from_dict(payload).endpoints if ep.value == ip
    )
    layer = _runtime_layer(typed_endpoint)
    assert layer["status"] != "complete"
    layer_evidence = layer["evidence"]
    assert isinstance(layer_evidence, dict)
    assert layer_evidence["target_attributed"] is False
    first_runtime = next(
        ep for ep in first["endpoints"] if ep.get("value") == ip
    )["enrichment"]["runtime"]
    for field in ("out_bytes", "in_bytes", "connection_count"):
        assert runtime[field] == first_runtime[field]
    assert payload["meta"]["runtime_pcap_merges"] == first["meta"]["runtime_pcap_merges"]


def test_reversing_one_fingerprint_preserves_another_target(tmp_path: Path) -> None:
    """同 IP 多次抓包各自记账；反转 F1 不得擦掉 F2 的 TARGET。

    ★这是 fingerprint 记账要防的核心事故：归因结论此前是全局一张表
      （`merged_attr.update(app_attr)`，carrier 级后写者胜），目标集与端点
      runtime 标志又只从"本次" fresh_eps 算——反转其中一次抓包的结论，
      另一次抓包已确证的 TARGET 会被连带擦掉或凭空复活。
    """
    ip = "100.64.9.51"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")
    first = _one_flow_summary(ip, 30110)
    second = _one_flow_summary(ip, 30111)

    pcap_ingest.merge_into_report_json(
        str(path), first, _attr(ip, is_target=True, port=30110)
    )
    pcap_ingest.merge_into_report_json(
        str(path), second, _attr(ip, is_target=True, port=30111)
    )
    pcap_ingest.merge_into_report_json(
        str(path), first, _attr(ip, is_target=False, port=30110)
    )
    payload = json.loads(path.read_text(encoding="utf-8"))

    endpoint = next(item for item in payload["endpoints"] if item.get("value") == ip)
    assert endpoint["enrichment"]["runtime"]["target_attributed"] is True
    assert payload["meta"][runtime_inventory.INVENTORY_META_KEY][
        "target_attributed"
    ] == 1
    signals = payload["meta"]["capture_signals"]["pcap_app_attribution"]
    assert signals[f"tcp/{ip}:30110"]["is_target_app"] is False
    assert signals[f"tcp/{ip}:30111"]["is_target_app"] is True
    ledger = payload["meta"]["runtime_pcap_attribution_ledger"]
    assert len(ledger["captures"]) == 2

    pcap_ingest.merge_into_report_json(
        str(path), second, _attr(ip, is_target=False, port=30111)
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    endpoint = next(item for item in payload["endpoints"] if item.get("value") == ip)
    assert endpoint["enrichment"]["runtime"]["target_attributed"] is False
    assert payload["meta"][runtime_inventory.INVENTORY_META_KEY][
        "target_attributed"
    ] == 0


def test_same_carrier_target_from_earlier_capture_survives_later_denial(
    tmp_path: Path,
) -> None:
    """同一 carrier 在两次抓包里结论相反：TARGET 优先，后来的 DENIED 不得整表覆写。

    ★这是投影语义与旧 ``merged_attr.update(app_attr)`` 的分水岭：F1 里目标持有过
      该 socket 就是"目标连过该端点"的既成事实，F2 时段别的进程持有它不构成翻案
      （账本里两个 fingerprint 的 verdict 都留着，可审计）。update() 是后写者胜，
      恰好把这条既成事实擦掉。
    """
    ip = "100.64.9.64"
    carrier = f"tcp/{ip}:30110"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")
    first = _one_flow_summary(ip, 30110)
    second = _one_flow_summary(ip, 30110)
    # 同 carrier、不同内容指纹：改字节数即可（fingerprint 含 out/in 字节）。
    second.flows[0].bytes_ = 1600
    second.flows[0].payload_bytes = 800
    assert pcap_ingest.summary_merge_fingerprint(
        first
    ) != pcap_ingest.summary_merge_fingerprint(second)

    pcap_ingest.merge_into_report_json(str(path), first, _attr(ip, is_target=True))
    pcap_ingest.merge_into_report_json(str(path), second, _attr(ip, is_target=False))
    payload = json.loads(path.read_text(encoding="utf-8"))

    endpoint = next(ep for ep in payload["endpoints"] if ep.get("value") == ip)
    assert endpoint["enrichment"]["runtime"]["target_attributed"] is True
    assert payload["meta"]["capture_signals"]["pcap_app_attribution"][carrier][
        "is_target_app"
    ] is True
    assert payload["meta"][runtime_inventory.TARGET_ATTRIBUTED_SET_KEYS["pcap"]] == [ip]
    captures = payload["meta"]["runtime_pcap_attribution_ledger"]["captures"]
    stored = sorted(
        capture["verdicts"][carrier]["is_target_app"]
        for capture in captures.values()
    )
    assert stored == [False, True], "两个 fingerprint 的相反结论都要留痕可审计"


def test_unrelated_nonempty_attribution_does_not_revive_denial(tmp_path: Path) -> None:
    """非空表缺当前 carrier 仍是 MISSING，不得把先前 DENIED 误读成 TARGET。"""
    ip = "100.64.9.52"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")
    summary = _one_flow_summary(ip)
    pcap_ingest.merge_into_report_json(
        str(path), summary, _attr(ip, is_target=False)
    )
    unrelated = _attr("203.0.113.99", is_target=True, port=443)
    pcap_ingest.merge_into_report_json(str(path), summary, unrelated)
    payload = json.loads(path.read_text(encoding="utf-8"))

    lead = next(item for item in payload["leads"] if ip in str(item.get("value")))
    endpoint = next(item for item in payload["endpoints"] if item.get("value") == ip)
    assert {e["source"] for e in lead["source_refs"]} == {"runtime-derived"}
    assert {e["source"] for e in endpoint["evidences"]} == {"runtime-derived"}
    assert endpoint["enrichment"]["runtime"]["target_attributed"] is False


def test_legacy_unscoped_attribution_is_quarantined_from_new_capture(
    tmp_path: Path,
) -> None:
    """旧报告无 fingerprint 的归因只作历史留痕，不得冒充当前 PCAP 证据。"""
    ip = "100.64.9.53"
    carrier = f"tcp/{ip}:30110"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {
            "capture_signals": {
                "pcap_app_attribution": {
                    carrier: {
                        "is_target_app": True,
                        "attribution": "legacy-confirmed",
                    }
                }
            }
        },
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(path), _one_flow_summary(ip), None)
    payload = json.loads(path.read_text(encoding="utf-8"))
    ledger = payload["meta"]["runtime_pcap_attribution_ledger"]
    assert "legacy:unscoped" not in ledger["captures"]
    assert ledger["legacy_unscoped"]["verdicts"][carrier]["is_target_app"] is True
    endpoint = next(ep for ep in payload["endpoints"] if ep.get("value") == ip)
    assert "target_attributed" not in endpoint["enrichment"]["runtime"]
    assert payload["meta"].get(
        runtime_inventory.TARGET_ATTRIBUTED_SET_KEYS["pcap"], []
    ) == []


def test_malformed_v1_ledger_is_sanitized_without_aborting_merge(
    tmp_path: Path,
) -> None:
    """历史 ledger 是不可信输入；坏键/坏对象不得令整个公开 merge 静默放弃。"""
    ip = "100.64.9.54"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {
            "runtime_pcap_attribution_ledger": {
                "version": 1,
                "captures": {
                    "valid": {
                        "carrier_ips": {}, "sni_carriers": {}, "verdicts": {},
                    },
                    "malformed": "not-a-capture",
                },
            }
        },
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")

    assert pcap_ingest.merge_into_report_json(
        str(path), _one_flow_summary(ip)
    ) >= 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    captures = payload["meta"]["runtime_pcap_attribution_ledger"]["captures"]
    assert "malformed" not in captures
    assert any(ep.get("value") == ip for ep in payload["endpoints"])


def test_ledger_persists_only_bounded_projection_fields(tmp_path: Path) -> None:
    """详细 socket 证据可留在既有 capture_signals，ledger 不得复制任意字段。"""
    ip = "100.64.9.55"
    carrier = f"tcp/{ip}:30110"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")
    detailed = {
        carrier: {
            "is_target_app": False,
            "attribution": "unattributed",
            "score": 0.25,
            "target_uid_among_candidates": True,
            "uid": 4242,
            "process_path": "/synthetic/private/path",
            "unexpected": {"nested": "payload"},
        }
    }

    pcap_ingest.merge_into_report_json(str(path), _one_flow_summary(ip), detailed)
    payload = json.loads(path.read_text(encoding="utf-8"))
    captures = payload["meta"]["runtime_pcap_attribution_ledger"]["captures"]
    verdict = next(iter(captures.values()))["verdicts"][carrier]
    assert set(verdict) == {
        "is_target_app", "attribution", "score", "target_uid_among_candidates",
    }
    assert payload["meta"]["capture_signals"]["pcap_app_attribution"][carrier][
        "uid"
    ] == 4242


def test_ambiguous_verdict_persists_denial_across_rounds(tmp_path: Path) -> None:
    """``is_target_app`` 非 True（含 ambiguous 的 ``None``）按 DENIED 口径降档，
    且该结论要经账本存续——下一轮无归因合并不得翻案。

    ★与 runtime_evidence 模块头的口径一致（在表内且不为 True 即 DENIED），
      这与旧私库分支"只认显式 bool"的口径**相反**；本条锁住不许回退。
    """
    ip = "100.64.9.56"
    carrier = f"tcp/{ip}:30110"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")
    summary = _one_flow_summary(ip)
    ambiguous = {carrier: {"is_target_app": None, "attribution": "ambiguous"}}

    pcap_ingest.merge_into_report_json(str(path), summary, ambiguous)
    pcap_ingest.merge_into_report_json(str(path), summary, None)
    payload = json.loads(path.read_text(encoding="utf-8"))

    endpoint = next(ep for ep in payload["endpoints"] if ep.get("value") == ip)
    assert {e["source"] for e in endpoint["evidences"]} == {"runtime-derived"}
    assert endpoint["enrichment"]["runtime"]["target_attributed"] is False
    captures = payload["meta"]["runtime_pcap_attribution_ledger"]["captures"]
    verdict = next(iter(captures.values()))["verdicts"][carrier]
    assert verdict["is_target_app"] is None, "ambiguous 原样存续，不得硬化成 False"


def test_unsupported_ledger_version_fails_closed_without_rewriting(
    tmp_path: Path,
) -> None:
    """未来 schema 不能被旧实现静默降级；拒绝本轮并保持原文件字节不变。"""
    path = tmp_path / "report.json"
    original = json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {
            "runtime_pcap_attribution_ledger": {
                "version": 99,
                "captures": {"future": {"opaque": "preserve"}},
            }
        },
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False, indent=2)
    path.write_text(original, encoding="utf-8")

    assert pcap_ingest.merge_into_report_json(
        str(path), _one_flow_summary("100.64.9.57")
    ) == 0
    assert path.read_text(encoding="utf-8") == original


def test_carrier_ip_is_canonical_and_rejects_malformed_values() -> None:
    assert pcap_ingest._carrier_ip("tcp/100.64.9.58:443") == "100.64.9.58"
    assert pcap_ingest._carrier_ip("tcp/2001:db8::58:443") == "2001:db8::58"
    assert pcap_ingest._carrier_ip("tcp/[2001:db8::58]:443") == "2001:db8::58"
    assert pcap_ingest._carrier_ip("not-a-carrier") == ""
    assert pcap_ingest._carrier_ip("tcp/999.999.999.999:443") == ""
    assert pcap_ingest._carrier_ip("tcp/2001:db8::58:not-a-port") == ""


def test_attribution_ledger_limit_rejects_new_history_without_forgetting(
    tmp_path: Path, monkeypatch,
) -> None:
    """达到资源上限后拒绝新 fingerprint；不截尾、不擦除已记历史。

    ★与 ``runtime_pcap_merges`` 名单"不截尾"同哲学：宁可漏、不可造——
      截掉最老的记账等于让那份抓包的归因结论"失忆"，再并一次就凭空翻案。
    """
    monkeypatch.setattr(pcap_ingest, "_MAX_ATTRIBUTION_LEDGER_FINGERPRINTS", 2)
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")
    ip = "100.64.9.59"
    first = _one_flow_summary(ip, 30110)
    second = _one_flow_summary(ip, 30111)
    third = _one_flow_summary(ip, 30112)
    assert pcap_ingest.merge_into_report_json(str(path), first) >= 0
    assert pcap_ingest.merge_into_report_json(str(path), second) >= 0
    before = path.read_bytes()

    assert pcap_ingest.merge_into_report_json(str(path), third) == 0
    assert path.read_bytes() == before
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert len(payload["meta"]["runtime_pcap_attribution_ledger"]["captures"]) == 2


def test_pcap_projection_order_is_independent_of_flow_order() -> None:
    """同一组观测只换输入顺序，不得制造报告 diff。"""
    one = _one_flow_summary("100.64.9.61", 30110)
    two = _one_flow_summary("100.64.9.60", 30111)
    forward = pcap_ingest.PcapSummary(flows=[*one.flows, *two.flows])
    reverse = pcap_ingest.PcapSummary(flows=list(reversed(forward.flows)))

    assert [
        (remote.ip, remote.port, remote.proto)
        for remote in pcap_ingest.remote_endpoints(forward)
    ] == [
        (remote.ip, remote.port, remote.proto)
        for remote in pcap_ingest.remote_endpoints(reverse)
    ]
    assert [
        (lead.category.value, lead.value)
        for lead in pcap_ingest.to_report_leads(forward)
    ] == [
        (lead.category.value, lead.value)
        for lead in pcap_ingest.to_report_leads(reverse)
    ]


def test_explicit_denial_overrides_same_ip_legacy_target_set(tmp_path: Path) -> None:
    """隔离留痕可保留，但同 IP 的当前明确 DENIED 必须从活动目标集移除。"""
    ip = "100.64.9.62"
    carrier = f"tcp/{ip}:30110"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {
            "capture_signals": {
                "pcap_app_attribution": {
                    carrier: {
                        "is_target_app": True,
                        "attribution": "legacy-confirmed",
                    }
                }
            },
            runtime_inventory.TARGET_ATTRIBUTED_SET_KEYS["pcap"]: [ip],
        },
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(
        str(path), _one_flow_summary(ip), _attr(ip, is_target=False)
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    meta = payload["meta"]
    assert meta[runtime_inventory.TARGET_ATTRIBUTED_SET_KEYS["pcap"]] == []
    assert meta[runtime_inventory.INVENTORY_META_KEY]["target_attributed"] == 0
    assert meta["capture_signals"]["pcap_app_attribution"][carrier][
        "is_target_app"
    ] is False
    assert meta["runtime_pcap_attribution_ledger"]["legacy_unscoped"][
        "verdicts"
    ][carrier]["is_target_app"] is True


def test_fingerprint_distinguishes_delimiter_bearing_sni_sets() -> None:
    """不可信 SNI 不能用逗号拼接成有歧义的幂等身份。"""
    assert pcap_ingest._fingerprint_sni_fragment({
        "api.example.test", "cdn.example.test",
    }) == "sni=api.example.test,cdn.example.test", "正常 SNI 必须兼容旧指纹"
    first = _one_flow_summary("100.64.9.63")
    second = _one_flow_summary("100.64.9.63")
    first.flows[0].sni = {"a,b", "c"}
    second.flows[0].sni = {"a", "b,c"}

    assert pcap_ingest.summary_merge_fingerprint(
        first
    ) != pcap_ingest.summary_merge_fingerprint(second)


def test_empty_attribution_table_is_not_missing_attribution(tmp_path: Path) -> None:
    """★ ``{}``（做了归因、无可归因远端）≠ ``None``（没做归因），两个出口都要认这条界线。

    纯 DNS 采集 + 有效 socket 快照即可产生 ``{}``（``socket_attr`` 对零远端返回空表）。
    此前 merge 侧用 ``if not app_attr`` / ``bool(app_attr)`` 把它塌成"没做归因"，
    而 ``to_ledger_dict`` 用 ``is not None`` 判为"已归因"——**同一条命令，
    台账写已归因、报告写未归因**。这与 #347 修的"两出口两结论"是同一类问题，
    只是那次修的是归因**结论**没贯穿，漏了归因**是否执行过**这一维。

    影响不止措辞：inventory 的 ``uid_attributed`` 是闭环门控的输入，
    把"问过、没有可归因远端"当成"没问过"会让动态结论被无谓封顶。
    """
    path = tmp_path / "report.json"
    summary = pcap_ingest.PcapSummary(dns_queries={"cfg.example.test"})  # 零 flow

    def _uid_attributed(app_attr) -> bool | None:
        path.write_text(json.dumps({
            "package_name": "com.example.synthetic", "meta": {},
            "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
        }, ensure_ascii=False), encoding="utf-8")
        pcap_ingest.merge_into_report_json(str(path), summary, app_attr)
        meta = json.loads(path.read_text(encoding="utf-8")).get("meta") or {}
        for value in meta.values():
            if isinstance(value, dict) and "uid_attributed" in value:
                return value["uid_attributed"]
        return None

    assert _uid_attributed(None) is False, "None = 没做归因"
    assert _uid_attributed({}) is True, "★{} = 做了归因、只是没有可归因的远端"

    # 两个出口必须一致——这才是本用例真正要钉住的不变量
    assert pcap_ingest.to_ledger_dict(summary, {})["uid_attributed"] is True
    assert pcap_ingest.to_ledger_dict(summary, None)["uid_attributed"] is False


def test_empty_table_does_not_revive_downgraded_endpoint(tmp_path: Path) -> None:
    """★ ``{}`` 在 **run 级**算"已归因"，但**端点级**仍是缺信息，不得给已确证的否定翻案。

    这是两个层次的区别，极易混用同一个判据：
      - run 级（``uid_attributed`` / ``capture_signals``）：这一轮**执行过**归因吗？``{}`` = 执行过。
      - 端点级（继承墓碑）：**这个端点**本轮拿到结论了吗？空表 = 一个都没有 = 全是未归因。

    实证：修 run 级三态时若顺手把继承分支也改成 ``is None``，传 ``{}`` 会让上一轮已确证
    判否的端点重新升回 ``contact=True``——缺信息翻案，三态哲学最禁止的那件事，
    而当时没有任何测试抓得住它。本用例即为此而设。
    """
    ip = "100.64.9.25"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")

    # 第一轮：明确判否 → 降档
    pcap_ingest.merge_into_report_json(str(path), _one_flow_summary(ip), _attr(ip, is_target=False))
    # 第二轮：传 {}（做了归因，但该端点不在表内 = 未归因）
    pcap_ingest.merge_into_report_json(str(path), _one_flow_summary(ip), {})

    payload = json.loads(path.read_text(encoding="utf-8"))
    for lead in payload["leads"]:
        if ip in str(lead.get("value")):
            sources = {ev.get("source") for ev in lead.get("source_refs") or []}
            assert sources == {"runtime-derived"}, f"★空表让已降档端点复活：{sources}"
            assert lead.get("is_runtime_contact") is False
    for ep in payload["endpoints"]:
        if ep.get("value") == ip:
            assert {ev.get("source") for ev in ep.get("evidences") or []} == {"runtime-derived"}


def test_missing_attribution_does_not_revoke_earlier_downgrade(tmp_path: Path) -> None:
    """反向：后一次没做归因时，不得把已降档的证据升回 observed-contact。

    缺信息不给否定证据翻案——与 _endpoint_source 的三态同一条哲学。
    ★与上一条成对：明确证据可翻案、缺信息不可翻案，两条都要在。
    ★注意这里传的是 ``None``（没做归因）；``{}`` 的语义见
      :func:`test_empty_attribution_table_is_not_missing_attribution`。
    """
    ip = "100.64.9.23"
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "package_name": "com.example.synthetic", "meta": {},
        "leads": [], "endpoints": [], "findings": [], "analyzer_status": [],
    }, ensure_ascii=False), encoding="utf-8")

    pcap_ingest.merge_into_report_json(str(path), _one_flow_summary(ip), _attr(ip, is_target=False))
    pcap_ingest.merge_into_report_json(str(path), _one_flow_summary(ip), None)

    payload = json.loads(path.read_text(encoding="utf-8"))
    for lead in payload["leads"]:
        if ip in str(lead.get("value")):
            assert lead.get("is_runtime_contact") is False, "缺信息不得给否定证据翻案"
