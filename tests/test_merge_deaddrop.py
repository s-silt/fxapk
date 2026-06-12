"""apkscan.dynamic.merge.resolve_dead_drop_c2 的单测（Dead-Drop 二级 C2 浮出）。

二段式 dead-drop：app 先打伪装的「命令域名」，回包**明文 JSON 配置**里才带真实交易/后台域名
（rest.apizza.net→acedealex.xyz 模式）。本测聚焦回包关系分析的纯逻辑（真机抓包不可测）：
- 喂合成 messages（命令域名请求 + 回包带二级域名 evil-c2.com + 回包带 CDN 域名）。
- resolve_dead_drop_c2 把 evil-c2.com 浮出标 secondary（infra 判建议调证）、CDN 不升。
- 命令域名标与二级 C2 的关系。
- 坏/空 messages 不抛；**不改已有 Lead 的 advice 终判**（advice 仍由 infra 分级决定）。
- 二级 C2 若同时 is_runtime_seen（运行时实连）即高可信。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apkscan.core import infra
from apkscan.core.models import (
    Confidence,
    Endpoint,
    Evidence,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.dynamic import merge


# ---------------------------------------------------------------------------
# 合成帮助器
# ---------------------------------------------------------------------------


def _make_report(
    *,
    endpoints: list[Endpoint] | None = None,
    leads: list[Lead] | None = None,
    meta: dict[str, Any] | None = None,
) -> Report:
    return Report(
        package_name="com.test.app",
        meta=dict(meta or {}),
        leads=list(leads or []),
        endpoints=list(endpoints or []),
        findings=[],
        analyzer_status=[],
    )


def _write_runtime_report(tmp_path: Path, messages: list[Any]) -> str:
    payload = {
        "package_name": "com.test.app",
        "source": "runtime",
        "endpoints": [],
        "messages": messages,
    }
    p = tmp_path / "runtime_report.json"
    p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return str(p)


def _config_msg(url: str, resp_body: str, *, kind: str = "config") -> dict[str, Any]:
    return {"url": url, "request_body": "", "response_body": resp_body, "kind": kind}


# ---------------------------------------------------------------------------
# 核心：二级真实 C2 浮出 + 标 secondary
# ---------------------------------------------------------------------------


def test_dead_drop_surfaces_secondary_c2(tmp_path):
    """命令域名回包里的新域名（infra 判建议调证）→ 作为二级 C2 浮出，notes 标二级下发。"""
    rr = _write_runtime_report(
        tmp_path,
        [_config_msg("https://rest.apizza.net/api/webConfig",
                     '{"home":"https://acedealex.xyz/in","name":"ACE"}')],
    )
    report = _make_report()
    stats = merge.resolve_dead_drop_c2(report, rr)

    # 二级域名作为端点/线索浮出。
    values = {ep.value for ep in report.endpoints}
    assert "acedealex.xyz" in values
    lead = next(l for l in report.leads if l.value == "acedealex.xyz")
    assert lead.category == LeadCategory.DOMAIN
    # advice 仍由 infra 分级决定（疑似 App 自有 → 建议调证）。
    assert lead.advice == infra.ADVICE_INVESTIGATE
    # notes 标二级下发、经回包关系分析浮出、非直连命令域名。
    assert "二级下发" in lead.notes
    assert "回包关系分析" in lead.notes
    assert "命令域名" in lead.notes
    assert stats["secondary_c2"] == 1


def test_dead_drop_command_domain_noted_relationship(tmp_path):
    """命令域名（发起请求那个）保留并在 notes 标与二级 C2 的关系。"""
    rr = _write_runtime_report(
        tmp_path,
        [_config_msg("https://rest.apizza.net/api/webConfig",
                     '{"home":"https://acedealex.xyz/in"}')],
    )
    # 命令域名已有静态 Lead（apizza 疑似 App 自有 → 建议调证）。
    report = _make_report()
    merge.resolve_dead_drop_c2(report, rr)

    cmd_lead = next((l for l in report.leads if l.value == "rest.apizza.net"), None)
    assert cmd_lead is not None
    assert "命令域名" in cmd_lead.notes
    assert "acedealex.xyz" in cmd_lead.notes  # 标出与二级 C2 的关系


# ---------------------------------------------------------------------------
# infra 兜底：CDN/SDK/公共服务回调不升、不标 C2
# ---------------------------------------------------------------------------


def test_dead_drop_cdn_not_elevated(tmp_path):
    """回包里的新域名是 CDN（myqcloud，infra 判无需调证）→ 不升、不标二级 C2。"""
    rr = _write_runtime_report(
        tmp_path,
        [_config_msg("https://rest.apizza.net/api/webConfig",
                     '{"cdn":"https://res.myqcloud.com/a.png"}')],
    )
    report = _make_report()
    stats = merge.resolve_dead_drop_c2(report, rr)

    # CDN 不被当二级 C2 浮出。
    cdn_lead = next((l for l in report.leads if l.value == "res.myqcloud.com"), None)
    if cdn_lead is not None:
        # 即使作为端点并入也只走常规 infra 分级（无需调证），绝不标二级下发。
        assert cdn_lead.advice == infra.ADVICE_SKIP
        assert "二级下发" not in cdn_lead.notes
    assert stats["secondary_c2"] == 0


def test_dead_drop_mixed_cdn_and_c2(tmp_path):
    """同一回包既带 CDN 又带真二级 C2 → 仅 C2 浮出标 secondary，CDN 不升。"""
    rr = _write_runtime_report(
        tmp_path,
        [_config_msg("https://rest.apizza.net/api/webConfig",
                     '{"cdn":"https://res.myqcloud.com/a.png",'
                     '"backend":"https://evil-c2.shop/in"}')],
    )
    report = _make_report()
    stats = merge.resolve_dead_drop_c2(report, rr)

    c2 = next(l for l in report.leads if l.value == "evil-c2.shop")
    assert c2.advice == infra.ADVICE_INVESTIGATE
    assert "二级下发" in c2.notes
    # CDN 不标 secondary。
    cdn = next((l for l in report.leads if l.value == "res.myqcloud.com"), None)
    if cdn is not None:
        assert "二级下发" not in cdn.notes
    assert stats["secondary_c2"] == 1


# ---------------------------------------------------------------------------
# 只调优先级 + notes，不改 advice 终判（避免误杀/误升）
# ---------------------------------------------------------------------------


def test_dead_drop_does_not_change_existing_advice(tmp_path):
    """二级域名已有静态 Lead（advice 已被 infra 判定）→ dead-drop 不改其 advice，只加 notes。"""
    # 静态侧已把 evil-c2.shop 判为建议调证；构造一条 advice 被显式设成"待核"的 Lead，
    # 断言 dead-drop 绝不把它改成别的（advice 终判归 infra/静态，dead-drop 只调序+notes）。
    static_lead = Lead(
        category=LeadCategory.DOMAIN,
        value="evil-c2.shop",
        advice=infra.ADVICE_REVIEW,  # 故意非 INVESTIGATE
        notes="静态既有",
        source_refs=[Evidence(source="dex", location="classes.dex", snippet="evil-c2.shop")],
    )
    report = _make_report(leads=[static_lead])
    rr = _write_runtime_report(
        tmp_path,
        [_config_msg("https://rest.apizza.net/api/webConfig",
                     '{"backend":"https://evil-c2.shop/in"}')],
    )
    merge.resolve_dead_drop_c2(report, rr)

    lead = next(l for l in report.leads if l.value == "evil-c2.shop")
    # advice 不被 dead-drop 改写（仍是静态判的"待核"）。
    assert lead.advice == infra.ADVICE_REVIEW
    # 但 notes 补了二级下发关系。
    assert "二级下发" in lead.notes
    assert "静态既有" in lead.notes  # 旧 notes 保留


def test_dead_drop_secondary_c2_sorted_ahead(tmp_path):
    """二级 C2 调高排序：浮出的 secondary C2 Lead 排在普通线索之前（优先级）。"""
    other = Lead(category=LeadCategory.DOMAIN, value="aaa-other.cn",
                 advice=infra.ADVICE_INVESTIGATE, source_refs=[])
    report = _make_report(leads=[other])
    rr = _write_runtime_report(
        tmp_path,
        [_config_msg("https://rest.apizza.net/api/webConfig",
                     '{"backend":"https://evil-c2.shop/in"}')],
    )
    merge.resolve_dead_drop_c2(report, rr)

    idx = {l.value: i for i, l in enumerate(report.leads)}
    assert idx["evil-c2.shop"] < idx["aaa-other.cn"]  # 二级 C2 优先级更高、排在前


# ---------------------------------------------------------------------------
# 二级 C2 + 运行时实连 → 高可信
# ---------------------------------------------------------------------------


def test_dead_drop_secondary_runtime_seen_high_confidence(tmp_path):
    """二级 C2 同时被运行时实连（已有 runtime 端点）→ 高可信（is_runtime_seen=True）。"""
    runtime_seen = Endpoint(
        value="evil-c2.shop",
        kind="domain",
        evidences=[Evidence(source="runtime", location="flows.mitm", snippet="evil-c2.shop")],
    )
    report = _make_report(endpoints=[runtime_seen])
    rr = _write_runtime_report(
        tmp_path,
        [_config_msg("https://rest.apizza.net/api/webConfig",
                     '{"backend":"https://evil-c2.shop/in"}')],
    )
    merge.resolve_dead_drop_c2(report, rr)

    lead = next(l for l in report.leads if l.value == "evil-c2.shop")
    assert lead.confidence == Confidence.HIGH
    assert lead.is_runtime_seen is True  # source_refs 带 runtime


# ---------------------------------------------------------------------------
# 健壮性：坏/空 messages 不抛
# ---------------------------------------------------------------------------


def test_dead_drop_empty_messages_no_op(tmp_path):
    rr = _write_runtime_report(tmp_path, [])
    report = _make_report()
    stats = merge.resolve_dead_drop_c2(report, rr)
    assert stats["secondary_c2"] == 0
    assert report.leads == []


def test_dead_drop_missing_file_no_throw():
    report = _make_report()
    stats = merge.resolve_dead_drop_c2(report, "C:/nope/runtime_report.json")
    assert stats["secondary_c2"] == 0


def test_dead_drop_garbage_messages_no_throw(tmp_path):
    """messages 含非 dict / 缺字段 / 非 JSON 响应体 → 不抛、不浮出垃圾。"""
    rr = _write_runtime_report(
        tmp_path,
        ["not-a-dict", 123, {"no_body": True},
         _config_msg("https://x.cn/config", "not json at all <<<")],
    )
    report = _make_report()
    stats = merge.resolve_dead_drop_c2(report, rr)
    assert stats["secondary_c2"] == 0


def test_dead_drop_self_reference_not_surfaced(tmp_path):
    """回包只引用请求自身 host（无新域名）→ 不浮出二级 C2（不重复命令域名自己）。"""
    rr = _write_runtime_report(
        tmp_path,
        [_config_msg("https://api.biz.cn/config",
                     '{"self":"https://api.biz.cn/x","ok":1}')],
    )
    report = _make_report()
    stats = merge.resolve_dead_drop_c2(report, rr)
    assert stats["secondary_c2"] == 0


# ---------------------------------------------------------------------------
# 诚实标注：launch-only 抓不全（在 Lead.notes / 模块 docstring）
# ---------------------------------------------------------------------------


def test_dead_drop_notes_launch_only_caveat(tmp_path):
    """notes 必须诚实标注 launch-only 抓不全、需人工操作触发命令域名回包。"""
    rr = _write_runtime_report(
        tmp_path,
        [_config_msg("https://rest.apizza.net/api/webConfig",
                     '{"home":"https://acedealex.xyz/in"}')],
    )
    report = _make_report()
    merge.resolve_dead_drop_c2(report, rr)
    lead = next(l for l in report.leads if l.value == "acedealex.xyz")
    assert "人工操作" in lead.notes or "launch-only" in lead.notes
