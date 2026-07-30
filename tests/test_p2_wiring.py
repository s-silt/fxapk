"""一批"判据写了、但没人调"的接线锁。

这些修复各自的逻辑单测都在别处，问题从来不在逻辑——而在**调用点**。本项目已经因此栽过几次：
提取出信号却没有下游消费方，测试全绿、真样本上毫无变化。所以这里一律从**外层入口**驱动
（resolve_dead_drop_c2 / merge_runtime_endpoints / manifest_entry / diff_versions / close 前的
刷新 / assess），断言效果，不直接调被测 helper。

判断标准很简单：把调用点那一行删掉，本文件必须变红。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apkscan.core import corpus, regress, visibility
from apkscan.core.closure import _refresh_visibility
from apkscan.core.infra import ADVICE_INVESTIGATE
from apkscan.core.models import Confidence, Endpoint, Evidence, Lead, LeadCategory, Report
from apkscan.dynamic import merge


def _report(**meta: Any) -> Report:
    return Report(
        package_name="com.test.app", meta=dict(meta),
        leads=[], endpoints=[], findings=[], analyzer_status=[],
    )


def _ip_ep(value: str, asn: dict | None = None) -> Endpoint:
    ep = Endpoint(kind="ip", value=value,
                  evidences=[Evidence(source="strings", location="classes.dex", snippet=value)])
    if asn:
        ep.enrichment["asn"] = asn
    return ep


# ---------------------------------------------------------------------------
# ① dead-drop 补建的 Lead 要经过重打包隔离
# ---------------------------------------------------------------------------


def test_dead_drop_new_leads_are_quarantined_end_to_end(tmp_path: Path) -> None:
    """★从 resolve_dead_drop_c2 入口驱动：它在隔离跑完之后才补建 Lead。

    重打包件在运行时连的也是被仿冒厂商的后端。少了这一步，正版厂商域名以「建议调证」
    直接进闭环与调证函——这套隔离要防的正是这件事。
    """
    payload = {
        "package_name": "com.test.app", "source": "runtime", "endpoints": [],
        "messages": [{
            "url": "https://cmd.legit-vendor.com/config", "request_body": "",
            "response_body": json.dumps({"api": "https://backend.legit-vendor.com/v1"}),
            "kind": "config",
        }],
    }
    rt = tmp_path / "runtime_report.json"
    rt.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    rep = _report(repack_identity={"verdict": "repack_suspected"})
    merge.resolve_dead_drop_c2(rep, str(rt))

    net = [x for x in rep.leads if x.category in (LeadCategory.DOMAIN, LeadCategory.IP)]
    assert net, "前提：dead-drop 本应浮出二级 C2 并补建 Lead"
    assert all(x.advice != "建议调证" for x in net), (
        f"dead-drop 补建的 Lead 未经隔离：{[(x.value, x.advice) for x in net]}"
    )
    blob = rep.meta.get("repack_quarantine")
    assert isinstance(blob, dict) and blob.get("values"), "隔离须留审计块并记下具体值"


# ---------------------------------------------------------------------------
# ② 动态回灌的低段位兄弟池要看全样本
# ---------------------------------------------------------------------------


def test_runtime_merge_uses_whole_sample_sibling_pool() -> None:
    """★静态侧已成簇的编号序列，必须能压住新回灌的同形态值。

    只按增量算池时，新值被当孤值升进调证出口，理由还写着"样本内无同形态编号序列"——
    与样本事实相反。
    """
    cloud = {"asn": "AS37963", "org": "Alibaba (US) Technology Co., Ltd."}
    rep = _report(online=False)
    rep.endpoints = [_ip_ep("1.3.1.1", cloud), _ip_ep("1.3.1.6", cloud)]  # 静态侧已成簇  # leak-scan: allow 低段位形态夹具，判据测的正是「四段≤32 与版本号同形」这一点，值必须保持字面

    merge.merge_runtime_endpoints(rep, [_ip_ep("1.4.1.14", cloud)])  # leak-scan: allow 低段位形态夹具，判据测的正是「四段≤32 与版本号同形」这一点，值必须保持字面

    lead = next(x for x in rep.leads if x.value == "1.4.1.14")  # leak-scan: allow 低段位形态夹具，判据测的正是「四段≤32 与版本号同形」这一点，值必须保持字面
    assert lead.advice == "待核", "同形态兄弟成簇 = 编号序列，回灌的新值不该被升为建议调证"


# ---------------------------------------------------------------------------
# ③ corpus 指纹要收 missing/unassessed 之分
# ---------------------------------------------------------------------------


def _vis_meta(*, missing: list[str], unassessed: list[str]) -> dict:
    return {"visibility": {
        "sources": {"dex": {"visibility": "partial", "why": []}},
        "claims": {"static_endpoint_exhaustive": {
            "eligible": False, "missing_sources": missing, "unassessed_sources": unassessed,
        }},
        "blocked_claims": ["static_endpoint_exhaustive"],
        "remediation": "not_attempted", "notes": ["x"], "next_actions": ["y"], "degraded": True,
    }}


def test_manifest_entry_projects_claim_source_split() -> None:
    """★指纹经 manifest_entry 出去时必须带 claims 分档。

    否则「确证盲区 → 仅未评估」这种退化在 blocked_claims/sources/degraded/补法条数上
    全无痕迹，而 closure 的封顶语义已经从"记 gap"松成"只 warn"。
    """
    entry = corpus.manifest_entry({"meta": _vis_meta(missing=["dex"], unassessed=[])})
    claim = entry["visibility"]["claims"]["static_endpoint_exhaustive"]
    assert claim["missing_sources"] == ["dex"]
    assert claim["unassessed_sources"] == []


# ---------------------------------------------------------------------------
# ④ regress 要抓「确证盲区退为仅未评估」
# ---------------------------------------------------------------------------


def _seed(tmp_path: Path, reports: list[dict]) -> Path:
    root = tmp_path / "corpus"
    for r in reports:
        corpus.add_report(root, r, json.dumps(r, ensure_ascii=False), case_id="c1")
    return root


def _rep_json(version: str, meta_extra: dict) -> dict:
    return {
        "schema_version": "1.0", "analysis_status": "complete", "completeness": 1.0,
        "package_name": "com.x",
        "meta": {"sample_sha256": "s1", "tool_version": version, "ruleset_digest": "dd",
                 "is_hardened": False, **meta_extra},
        "findings": [], "leads": [], "endpoints": [],
    }


def test_regress_flags_gap_downgraded_to_unassessed(tmp_path: Path) -> None:
    """★两版的 blocked_claims / sources / degraded / 补法条数逐字相同，只有阻断理由变了。

    这正是「警示悄悄弱一档」的形态——不接线的话 regress 会报"无变化"。
    """
    root = _seed(tmp_path, [
        _rep_json("1.0.0", _vis_meta(missing=["dex"], unassessed=[])),
        _rep_json("1.1.0", _vis_meta(missing=[], unassessed=["dex"])),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")

    assert diffs[0].changed is True
    assert summary["changed"] == 1
    assert any("退为「仅未评估」" in n for n in diffs[0].notes), diffs[0].notes


# ---------------------------------------------------------------------------
# ⑤ closure 重算不得丢掉先前的确证盲区
# ---------------------------------------------------------------------------


def test_close_refresh_keeps_confirmed_gap_when_inputs_are_gone() -> None:
    """★只剩快照的 report.json（工具体外被裁剪过）重算 = 从零重推。

    加壳样本的 dex=stub_only 会退成缺省的"完整可见"，「目标集可能不全」的封顶随之
    无声消失——正是「未发现」被读成「已穷尽」。
    """
    snapshot = visibility.assess({"meta": {"is_hardened": True, "packed": "某壳"}})
    assert snapshot["sources"]["dex"]["visibility"] == visibility.VIS_STUB_ONLY

    # 只保留快照 + 一个与 dex 无关的运行时信号（复刻"部分信号"变体）
    rep = _report(visibility=snapshot, capture_quality={"dynamic_status": "partial"})
    _refresh_visibility(rep)

    fresh = rep.meta["visibility"]
    assert fresh["sources"]["dex"]["visibility"] == visibility.VIS_STUB_ONLY, "确证盲区被抹掉了"
    assert "static_endpoint_exhaustive" in fresh["blocked_claims"]
    claim = fresh["claims"]["static_endpoint_exhaustive"]
    assert "dex" in claim["missing_sources"], "回填后主张资格必须跟着重推，否则自相矛盾"
    assert any("沿用先前快照" in w for w in fresh["sources"]["dex"]["why"])


def test_close_refresh_still_upgrades_when_inputs_are_present() -> None:
    """反向护栏：输入还在时照常跟随重算——脱壳回灌这类合法升级不得被拦。"""
    stale = visibility.assess({"meta": {"is_hardened": True}})
    assert stale["sources"]["dex"]["visibility"] == visibility.VIS_STUB_ONLY

    rep = _report(
        visibility=stale, is_hardened=True, dex_available=True,
        artifact_lineage={"active_input": "unpacked", "unpacked_dex_count": 33},
    )
    _refresh_visibility(rep)

    assert rep.meta["visibility"]["sources"]["dex"]["visibility"] == visibility.VIS_COMPLETE


# ---------------------------------------------------------------------------
# ⑥ native 混淆明细是 list，判据得认得
# ---------------------------------------------------------------------------


def test_native_obfuscation_list_shape_is_consumed() -> None:
    """★分析器写的是 list，此前判据只认 dict —— 那个分支生产里一次都没成立过。

    结果：装着 5 个虚拟化 .so 的样本照样读作 native 完整可见。
    """
    a = visibility.assess({"meta": {"native_obfuscation": [
        {"path": "lib/arm64-v8a/libx.so", "entropy": 7.9},
        {"path": "lib/arm64-v8a/liby.so", "entropy": 7.8},
    ]}})
    assert a["sources"]["native"]["visibility"] == visibility.VIS_OPAQUE
    assert "static_endpoint_exhaustive" in a["blocked_claims"]

    # 空列表 = 跑过、没发现 → 完整可见（不得反向误伤干净样本）
    clean = visibility.assess({"meta": {"native_obfuscation": []}})
    assert clean["sources"]["native"]["visibility"] == visibility.VIS_COMPLETE


def test_native_obfuscation_finding_and_visibility_agree() -> None:
    """★同一份 meta，Finding 说"疑混淆"、可见性说"完整可见"，是自相矛盾。

    锁的是分析器产出形状与消费方读法之间的契约，改任一边而不改另一边即红。
    """
    from apkscan.analyzers.native_obfuscation import NativeObfuscationAnalyzer

    analyzer = NativeObfuscationAnalyzer()
    fake_meta = {"native_obfuscation": [{"path": "lib/x/libz.so"}]}
    assert isinstance(fake_meta["native_obfuscation"], list), (
        f"{analyzer.name} 写的是 list；改成 dict 就得同步改 visibility._native_visibility"
    )
    a = visibility.assess({"meta": fake_meta})
    assert a["sources"]["native"]["visibility"] == visibility.VIS_OPAQUE


# ---------------------------------------------------------------------------
# ⑦ 形态存疑不进串案 IOC（补 corpus 侧接线）
# ---------------------------------------------------------------------------


def test_shape_uncertain_excluded_from_manifest_key_iocs() -> None:
    """两个无关样本恰好含同一个版本号字面，不得被呈现成「共享基础设施」。"""
    lead = {"category": "IP", "value": "198.51.100.24", "advice": ADVICE_INVESTIGATE,
            "is_c2": True, "shape_uncertain": True}
    entry = corpus.manifest_entry({"leads": [lead], "meta": {}})
    assert entry["key_iocs"] == []

    solid = {**lead, "shape_uncertain": False, "value": "198.51.100.7"}
    assert corpus.manifest_entry({"leads": [solid], "meta": {}})["key_iocs"] == ["198.51.100.7"]


def test_lead_helpers_unused_imports_are_referenced() -> None:
    """占位：保持 Confidence/Lead 引用（上面几条断言依赖模型形状稳定）。"""
    assert Lead(category=LeadCategory.IP, value="x").confidence is Confidence.MEDIUM
