"""正版重打包件的端点隔离：不得进入任何调证出口。

守的是本项目最重的一类错误——**把无关方写成嫌疑方**。自研马甲包与正版重打包件的
接口/域名归属完全相反：后者属于被仿冒的正版厂商。实测发生过同型错误（正版钱包的
156 条接口被整体错归为团伙资产）。

本文件的断言一律落在**最终出口**（is_c2 / letters 套打 / closure 目标选择），
而不是只断言 advice 字段变了——只断中间字段的测试挡不住"字段改了但出口没关"。
"""

from __future__ import annotations

import pytest

from apkscan.analyzers.repack_identity import VERDICT_REPACK_SUSPECTED
from apkscan.core import pipeline
from apkscan.core.closure.targets import _select_targets_with_stats
from apkscan.core.leads import _VERDICT_REPACK_SUSPECTED, apply_repack_quarantine
from apkscan.core.models import (
    AnalysisConfig,
    Confidence,
    Endpoint,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.dynamic import merge
from apkscan.report import letters


def _lead(value: str, category: LeadCategory = LeadCategory.DOMAIN, *, advice: str = "建议调证") -> Lead:
    return Lead(
        category=category,
        value=value,
        subject="某注册商",
        where_to_request="域名注册商",
        evidence_to_obtain=["注册人实名"],
        confidence=Confidence.HIGH,
        advice=advice,
    )


def _repack_meta() -> dict:
    return {"repack_identity": {"verdict": VERDICT_REPACK_SUSPECTED}}


def test_verdict_literal_is_in_sync_with_analyzer() -> None:
    """core 层刻意不 import analyzers（避免分层倒置），故用本断言钉住两处字面量一致。

    改了任一边而没改另一边，隔离会静默失效——正版厂商资产照旧进调证出口。
    """
    assert _VERDICT_REPACK_SUSPECTED == VERDICT_REPACK_SUSPECTED


def test_quarantine_closes_every_downstream_gate() -> None:
    """★核心：隔离后，四个调证出口共用的闸门必须全部关闭。"""
    lead = _lead("api.legit-vendor.com")
    assert lead.is_c2 is True, "前提：未隔离时它本会被当作 C2/主控域名渲染进红标区块"
    assert letters._is_actionable(
        {"advice": lead.advice, "evidence_to_obtain": lead.evidence_to_obtain,
         "where_to_request": lead.where_to_request}
    ) is True, "前提：未隔离时它本会被套打成调证函草稿"

    quarantined = apply_repack_quarantine([lead], _repack_meta())

    assert quarantined == ["api.legit-vendor.com"]
    # 出口一：HTML「C2/主控域名（建议调证）」红标区块
    assert lead.is_c2 is False
    # 出口二：letters 调证函自动套打
    assert letters._is_actionable(
        {"advice": lead.advice, "evidence_to_obtain": lead.evidence_to_obtain,
         "where_to_request": lead.where_to_request}
    ) is False
    # 降档而非删除：仍在清单里、带理由，人工差分核实后可恢复
    assert lead.advice == "待核"
    assert lead.confidence is Confidence.LOW
    assert "正版" in lead.notes and "差分" in lead.notes


def test_quarantine_never_downgrades_to_skip() -> None:
    """绝不降到「无需调证」——那等于替人下了"与本案无关"的结论。

    重打包件里**可能**真被注入了 C2，只是无法只凭本包区分，需与官方包差分。
    """
    lead = _lead("maybe-injected.example")
    apply_repack_quarantine([lead], _repack_meta())
    assert lead.advice != "无需调证"


@pytest.mark.parametrize(
    "meta, why",
    [
        ({}, "无 repack_identity"),
        ({"repack_identity": {"verdict": "self_built"}}, "判为自研马甲包"),
        ({"repack_identity": {"verdict": "unknown"}}, "判不出来"),
    ],
)
def test_quarantine_only_fires_on_repack_verdict(meta: dict, why: str) -> None:
    """非重打包件一律不动——否则自研马甲包的真 C2 会被误隔离（漏报方向）。"""
    lead = _lead("real-c2.example")
    assert apply_repack_quarantine([lead], meta) == [], why
    assert lead.advice == "建议调证"
    assert lead.is_c2 is True


def test_quarantine_leaves_non_network_leads_alone() -> None:
    """只隔离 DOMAIN/IP：支付/SDK 等类别的归属逻辑与重打包无关。"""
    pay = _lead("某支付平台", LeadCategory.FOURTH_PARTY_PAYMENT)
    apply_repack_quarantine([pay], _repack_meta())
    assert pay.advice == "建议调证"


def test_quarantine_is_idempotent() -> None:
    """运行时回灌路径会二次调用；重复隔离不得叠加注记。"""
    lead = _lead("api.legit-vendor.com")
    apply_repack_quarantine([lead], _repack_meta())
    first = lead.notes
    assert apply_repack_quarantine([lead], _repack_meta()) == []
    assert lead.notes == first


def _report_with(leads: list[Lead], endpoints: list[Endpoint], meta: dict) -> Report:
    return Report(
        package_name="com.example.repacked",
        meta=dict(meta),
        leads=list(leads),
        endpoints=list(endpoints),
        findings=[],
        analyzer_status=[],
    )


def test_static_pipeline_stage_is_wired() -> None:
    """★接线：静态主路径必须真的调用隔离，而不是只把函数放在那里。

    退回 pipeline._stage_build_leads 里的那几行，本测试即红——
    只测 apply_repack_quarantine 本身的测试挡不住"函数写了但没人调"。
    """
    state = pipeline._PipelineState(
        ctx=None,  # type: ignore[arg-type]  # 本 stage 不碰 ctx
        config=AnalysisConfig(online=False),
        platform="android",
        capabilities=set(),
    )
    state.meta.update(_repack_meta())
    state.endpoints.append(Endpoint(kind="domain", value="api.legit-vendor.com"))

    pipeline._stage_build_leads(state)

    net = [x for x in state.leads if x.category in (LeadCategory.DOMAIN, LeadCategory.IP)]
    assert net, "前提：该端点本应产出一条网络 Lead"
    assert all(x.advice != "建议调证" for x in net), "静态路径未接线：厂商域名仍以「建议调证」入清单"
    assert all(x.is_c2 is False for x in net)
    audit = state.meta.get("repack_quarantine")
    assert isinstance(audit, dict) and audit.get("count", 0) >= 1, "隔离须留审计块，否则兜底门会误判为旧报告"


def test_runtime_merge_path_is_wired() -> None:
    """★接线：`capture --into` 的运行时回灌路径同样要隔离。

    重打包件在运行时连的也是正版厂商的后端；只修静态侧，动态新引入的域名照旧进调证出口。
    退回 merge._build_runtime_leads 里的那几行，本测试即红。
    """
    rep = _report_with([], [], _repack_meta())
    runtime_only = [Endpoint(kind="domain", value="rt.legit-vendor.com")]

    merge._build_runtime_leads(rep, runtime_only)

    net = [x for x in rep.leads if x.category in (LeadCategory.DOMAIN, LeadCategory.IP)]
    assert net, "前提：运行时端点本应产出网络 Lead"
    assert all(x.advice != "建议调证" for x in net), "运行时路径未接线"
    audit = rep.meta.get("repack_quarantine")
    assert isinstance(audit, dict) and audit.get("count", 0) >= 1


def test_closure_backstop_excludes_unquarantined_legacy_report() -> None:
    """★兜底门：旧版/手编 report.json 未经隔离时，其端点不得进闭环目标。

    退回 targets.py 的兜底分支，本测试即红（端点会被选入 closure 目标）。
    """
    ep = Endpoint(kind="domain", value="api.legit-vendor.com")
    rep = _report_with([_lead("api.legit-vendor.com")], [ep], _repack_meta())

    selected, stats = _select_targets_with_stats(rep, max_targets=6)

    assert selected == [], "被仿冒厂商的域名不该成为闭环归因目标"
    assert stats.get("repack_excluded") == 1, "排除不得静默——要能看出是隔离导致目标为空"


def test_closure_backstop_respects_manual_restore() -> None:
    """审计块存在 = 隔离跑过 = 残余的「建议调证」是人工差分核实后恢复的，应予尊重。

    否则人工确认属注入的真 C2 会被永久挡在闭环之外（漏报方向）。
    """
    ep = Endpoint(kind="domain", value="confirmed-injected.example")
    meta = {**_repack_meta(),
            "repack_quarantine": {"reason": VERDICT_REPACK_SUSPECTED, "count": 3, "values": []}}
    rep = _report_with([_lead("confirmed-injected.example")], [ep], meta)

    selected, stats = _select_targets_with_stats(rep, max_targets=6)

    assert [e.value for e in selected] == ["confirmed-injected.example"]
    assert "repack_excluded" not in stats
