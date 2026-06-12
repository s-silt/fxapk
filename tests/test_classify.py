"""classify_app 聚合分类器的契约测试。

直接 new 合成 Report（meta/leads/endpoints/findings 填信号）喂 classify_app，
断言：
1) 命中类型写入 meta["app_classification"]（type/score/signals/runner_up）；
2) ★ 分类必须伴随产出「针对性调证 Lead」（带 where_to_request + evidence_to_obtain），
   把"一摞域名/SDK"翻译成"该向谁调什么证据"——只打标签不产 Lead 视为不合格；
3) 证据不足显式标"未定"且不产硬判 Lead；
4) 多类竞争取高分 + runner_up 非空；
5) classify_app 绝不抛（喂坏 report 也不崩）。
"""

from __future__ import annotations

from apkscan.analyzers.classify import classify_app
from apkscan.core.models import (
    Endpoint,
    Evidence,
    Lead,
    LeadCategory,
    Report,
)


def _blank_report(**meta: object) -> Report:
    """构造一个最小空 Report，meta 用关键字填充。"""
    return Report(
        package_name="com.test.app",
        meta=dict(meta),
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def _classify_lead(report: Report) -> Lead | None:
    """取出 classify_app 追加的「涉诈类型研判」调证 Lead（按 notes/value 前缀识别）。"""
    for lead in report.leads:
        if lead.category == LeadCategory.CONFIG_KEY and "涉诈类型研判" in (lead.value or ""):
            return lead
    return None


# --------------------------------------------------------------------------
# 1) 贷款盘：通讯录 + 短信权限 + /loan 路径 + 放款文案
# --------------------------------------------------------------------------


def test_loan_classification_emits_investigation_lead() -> None:
    report = _blank_report(
        permissions=[
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
        ],
        dangerous_matched=["READ_CONTACTS", "READ_SMS"],
    )
    report.endpoints = [
        Endpoint(value="https://api.daikuan-x.com/loan/apply", kind="url"),
    ]
    report.leads = [
        Lead(category=LeadCategory.CONTACT, value="客服微信 daikuan88"),
    ]
    # 文案信号通过 finding 描述带入（不重新扫 dex）。
    from apkscan.core.models import Finding, Severity

    report.findings = [
        Finding(
            id="X1",
            title="放款额度页面",
            severity=Severity.INFO,
            category="text",
            description="立即放款，提升额度，下款秒到",
        )
    ]

    classify_app(report)

    cls = report.meta.get("app_classification")
    assert cls is not None
    assert cls["type"] == "贷款盘"
    assert cls["score"] > 0
    assert cls["signals"]  # 命中信号非空，可追溯

    lead = _classify_lead(report)
    assert lead is not None, "贷款盘必须产出针对性调证 Lead，而非只打标签"
    assert lead.where_to_request
    assert lead.evidence_to_obtain  # 非空：要调什么证据
    # 指向运营商 / 被害人范围
    assert "运营商" in lead.where_to_request or "平台" in lead.where_to_request
    joined = "".join(lead.evidence_to_obtain)
    assert "通讯录" in joined or "短信" in joined


# --------------------------------------------------------------------------
# 2) 杀猪盘：USDT/收款地址 + is_c2 入金接口 + 客服 IM
# --------------------------------------------------------------------------


def test_pig_butchering_classification_emits_investigation_lead() -> None:
    report = _blank_report(
        crypto_addresses=["TXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
        payment_keywords=["USDT 收款", "充值 recharge"],
    )
    # is_c2 入金接口：DOMAIN Lead + advice=建议调证 → is_c2 为 True
    report.leads = [
        Lead(
            category=LeadCategory.DOMAIN,
            value="gw.touzi-pay.com",
            advice="建议调证",
        ),
        Lead(category=LeadCategory.CONTACT, value="客服 Telegram @kefu888"),
    ]
    report.endpoints = [
        Endpoint(value="https://gw.touzi-pay.com/recharge", kind="url"),
        Endpoint(value="https://gw.touzi-pay.com/withdraw", kind="url"),
    ]

    classify_app(report)

    cls = report.meta.get("app_classification")
    assert cls is not None
    assert cls["type"] == "杀猪盘"

    lead = _classify_lead(report)
    assert lead is not None, "杀猪盘必须产出针对性调证 Lead"
    assert lead.where_to_request
    assert lead.evidence_to_obtain
    joined = "".join(lead.evidence_to_obtain)
    # 指向入金接口商户号 / 客服 IM / 收款地址
    assert "商户号" in joined or "收款" in joined or "IM" in joined


# --------------------------------------------------------------------------
# 3) 证据不足 → 未定，不产硬判 Lead
# --------------------------------------------------------------------------


def test_insufficient_signal_yields_undetermined_no_hard_lead() -> None:
    report = _blank_report(
        permissions=["android.permission.INTERNET"],
        sdks=["极光推送 JPush"],
    )

    classify_app(report)

    cls = report.meta.get("app_classification")
    assert cls is not None
    assert cls["type"] == "未定"

    # 不产生硬判 Lead（贷款盘/杀猪盘等指向具体类型的调证 Lead 不应出现）。
    for lead in report.leads:
        if lead.category == LeadCategory.CONFIG_KEY and "涉诈类型研判" in (lead.value or ""):
            # 若产出，只能是"未定·建议人工研判"，不得是某硬判类型。
            assert "未定" in lead.value


# --------------------------------------------------------------------------
# 4) 多类竞争 → 取高分 + runner_up 非空
# --------------------------------------------------------------------------


def test_competing_types_keeps_runner_up() -> None:
    report = _blank_report(
        # 赌博信号（强）：下注路径 + USDT
        crypto_addresses=["TXyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"],
        payment_keywords=["聚合支付", "USDT"],
        # 同时带一点贷款信号（弱）
        permissions=["android.permission.READ_CONTACTS"],
    )
    report.endpoints = [
        Endpoint(value="https://api.dubo-x.com/bet/place", kind="url"),
        Endpoint(value="https://api.dubo-x.com/game/lottery", kind="url"),
    ]
    report.leads = [
        Lead(category=LeadCategory.DOMAIN, value="api.dubo-x.com", advice="建议调证"),
    ]

    classify_app(report)

    cls = report.meta.get("app_classification")
    assert cls is not None
    assert cls["type"] == "赌博"
    assert cls["runner_up"], "多类竞争时 runner_up 必须非空"
    assert cls["runner_up"]["type"] != cls["type"]


# --------------------------------------------------------------------------
# 5) classify_app 绝不抛
# --------------------------------------------------------------------------


def test_classify_never_raises_on_broken_report() -> None:
    # meta 里塞非预期类型，endpoints/leads 是脏数据，也不能崩。
    report = _blank_report(
        permissions="not-a-list",  # 类型错
        sdks=123,
        crypto_addresses=None,
    )
    report.endpoints = [Endpoint(value="", kind="url")]
    report.leads = [Lead(category=LeadCategory.DOMAIN, value="")]

    # 不抛即通过。
    classify_app(report)
    # report 仍可用（至少 meta 是 dict）。
    assert isinstance(report.meta, dict)


def test_classify_handles_completely_bogus_object() -> None:
    class _Bogus:
        pass

    # 整个 report 是个不符合契约的对象，也只能吞掉异常不抛。
    classify_app(_Bogus())  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# 6) 不破坏既有 Lead：只追加，不改既有
# --------------------------------------------------------------------------


def test_classify_only_appends_does_not_mutate_existing_leads() -> None:
    existing = Lead(
        category=LeadCategory.DOMAIN,
        value="gw.touzi-pay.com",
        advice="建议调证",
        notes="原始备注",
        source_refs=[Evidence(source="dex", location="X", snippet="y")],
    )
    report = _blank_report(crypto_addresses=["TXzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"])
    report.leads = [existing]
    report.endpoints = [Endpoint(value="https://gw.touzi-pay.com/recharge", kind="url")]

    before_count = len(report.leads)
    before_notes = existing.notes

    classify_app(report)

    # 既有 Lead 对象未被改动。
    assert existing.notes == before_notes
    assert existing.advice == "建议调证"
    # 只新增（>= 原数量）。
    assert len(report.leads) >= before_count
