"""锁住 ``Report`` 顶层与 ``Lead`` 的序列化键集合，并与 schema 版本号钉在一处。

★为什么单独测版本常量不够：那只能防住「改了版本号但忘了改文档」，防不住真正会伤人的那个
  方向——**加了字段却忘了 bump 版本**。消费方（AI / CI / 第三方工具）拿 ``schema_version``
  判断字段布局；键集合变了而版本没变，等于对外撒谎说布局没动。所以这里把**键集合**与
  **版本号**钉在同一处：动了任一边，测试都红，维护者被迫同时面对另一边。

★为什么写死字面而不是 ``== REPORT_SCHEMA_VERSION``：拿常量和它自己比恒真，锁不住任何东西。

★**覆盖边界（别把这里当成"整个 report.json 都锁住了"）**：

  - 只冻结 ``Report`` 顶层与单条 ``Lead``。``Endpoint`` / ``Finding`` / ``Evidence`` **没锁**
    ——它们加字段而版本不变时这三条测试仍会全绿。这个边界是有意的：Lead 是本项目的核心产出
    单元，也是出口们（digest / letters / html / ioc）共同的消费对象；真要把政策定成「1.1 下
    任何结构化字段都不能新增」，就该把那三个类型一并锁上。
  - 落盘的 ``report.json`` 顶层键**可能多于**这里的 12 个：``report_io.write_report`` 会把
    ``meta`` 里的扩展区键 update 进顶层。那是「载入—写回时原样保留未知顶层字段」的开放扩展
    区，不属于 fxapk 生成的规范字段，故不在本契约内。
"""

from __future__ import annotations

from apkscan.core.models import Lead, LeadCategory, Report
from apkscan.report import json as report_json

# ★自 v1.5.0 起 1.1 随发布出门、成为在野报告依赖的契约：**不能再往 1.1 里加字段**。
#   下次新增机器可见字段时，这两个集合与下面的版本断言必须一起改，且版本要开 1.2。
_REPORT_KEYS_1_1 = {
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

_LEAD_KEYS_1_1 = {
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


def _empty_report(leads: list[Lead] | None = None) -> Report:
    return Report(
        package_name="com.example.app",
        meta={},
        leads=leads or [],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def test_report_top_level_keys_are_frozen_at_schema_1_1() -> None:
    payload = report_json.to_dict(_empty_report())

    assert set(payload) == _REPORT_KEYS_1_1, (
        "report.json 顶层字段集合变了。这是对外 schema：请同时把 REPORT_SCHEMA_VERSION "
        "bump 到 1.2（自 v1.5.0 起 1.1 随发布出门，不能再改）、更新本测试的集合、并写进 CHANGELOG。"
    )


def test_lead_keys_are_frozen_at_schema_1_1() -> None:
    lead = Lead(category=LeadCategory.DOMAIN, value="a.example")
    payload = report_json.to_dict(_empty_report([lead]))

    assert set(payload["leads"][0]) == _LEAD_KEYS_1_1, (
        "Lead 序列化字段集合变了。同上：bump 到 1.2、更新本测试、写 CHANGELOG。"
    )


def test_schema_version_literal_matches_the_frozen_key_sets() -> None:
    # 写死字面：与上面两个集合成对。任何一边先动，这里就是提醒另一边也要动的锚点。
    payload = report_json.to_dict(_empty_report())

    assert payload["schema_version"] == "1.1"
