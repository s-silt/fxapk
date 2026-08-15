"""锁住 ``Report`` 顶层与 ``Lead`` 的序列化键集合，并与 schema 版本号钉在一处。

★为什么单独测版本常量不够：那只能防住「改了版本号但忘了改文档」，防不住真正会伤人的那个
  方向——**加了字段却忘了 bump 版本**。消费方（AI / CI / 第三方工具）拿 ``schema_version``
  判断字段布局；键集合变了而版本没变，等于对外撒谎说布局没动。所以这里把**键集合**与
  **版本号**钉在同一处：动了任一边，测试都红，维护者被迫同时面对另一边。

★为什么写死字面而不是 ``== REPORT_SCHEMA_VERSION``：拿常量和它自己比恒真，锁不住任何东西。

★**覆盖边界（别把这里当成"整个 report.json 都锁住了"）**：

  - 冻结 ``Report`` 顶层、单条 ``Lead`` 与 ``Evidence``；``Endpoint`` / ``Finding`` 尚未锁。
    Evidence 自 1.2 起携带案件作用域，属于会直接改变 closure 资格的核心契约，故必须锁住。
  - 落盘的 ``report.json`` 顶层键**可能多于**这里的 12 个：``report_io.write_report`` 会把
    ``meta`` 里的扩展区键 update 进顶层。那是「载入—写回时原样保留未知顶层字段」的开放扩展
    区，不属于 fxapk 生成的规范字段，故不在本契约内。
"""

from __future__ import annotations

from apkscan.core.models import Evidence, Lead, LeadCategory, Report
from apkscan.report import json as report_json

# ★1.2 增加 Evidence.scope；再新增机器可见字段时，集合与版本断言必须一起更新。
_REPORT_KEYS_1_2 = {
    "analysis_status",
    "analyzer_status",
    "completeness",
    "critical_failures",
    "endpoints",
    "enricher_status",
    "findings",
    "leads",
    "meta",
    "package_name",
    "schema_version",
    "skipped_analyzers",
}

_LEAD_KEYS_1_2 = {
    "advice",
    "base_advice",
    "category",
    "confidence",
    "downgrades",
    "evidence_to_obtain",
    "is_c2",
    "is_runtime_contact",
    "is_runtime_seen",
    "legacy_effective_advice",
    "notes",
    "shape_uncertain",
    "sni_masquerade",
    "source_refs",
    "subject",
    "value",
    "where_to_request",
}

_EVIDENCE_KEYS_1_2 = {
    "evidence_id",
    "location",
    "observed_at",
    "scope",
    "snippet",
    "source",
}


def _empty_report(leads: list[Lead] | None = None) -> Report:
    return Report(
        package_name="com.example.app",
        meta={},
        leads=leads or [],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def test_report_top_level_keys_are_frozen_at_schema_1_2() -> None:
    payload = report_json.to_dict(_empty_report())

    assert set(payload) == _REPORT_KEYS_1_2, (
        "report.json 顶层字段集合变了。这是对外 schema：请同时把 REPORT_SCHEMA_VERSION "
        "bump 到 1.3、更新本测试的集合、并写进 CHANGELOG。"
    )


def test_lead_keys_are_frozen_at_schema_1_2() -> None:
    lead = Lead(category=LeadCategory.DOMAIN, value="a.example")
    payload = report_json.to_dict(_empty_report([lead]))

    assert set(payload["leads"][0]) == _LEAD_KEYS_1_2, (
        "Lead 序列化字段集合变了。请把 REPORT_SCHEMA_VERSION bump 到 1.3、"
        "更新本测试的集合、并写进 CHANGELOG。"
    )


def test_evidence_keys_are_frozen_at_schema_1_2() -> None:
    lead = Lead(
        category=LeadCategory.DOMAIN,
        value="a.example",
        source_refs=[Evidence(source="dex", location="classes.dex")],
    )
    payload = report_json.to_dict(_empty_report([lead]))

    assert set(payload["leads"][0]["source_refs"][0]) == _EVIDENCE_KEYS_1_2, (
        "Evidence 序列化字段集合变了。请把 REPORT_SCHEMA_VERSION bump 到 1.3、"
        "更新本测试的集合、并写进 CHANGELOG。"
    )


def test_schema_version_literal_matches_the_frozen_key_sets() -> None:
    # 写死字面：与上面两个集合成对。任何一边先动，这里就是提醒另一边也要动的锚点。
    payload = report_json.to_dict(_empty_report())

    assert payload["schema_version"] == "1.2"
