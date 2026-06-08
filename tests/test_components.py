"""components 分析器单测：用 FakeContext 喂合成组件，断言导出组件 Finding。

覆盖命中（各类型导出）与不命中（无导出）两类用例，含 provider HIGH、
研判提示标注、缺名/None 组件集的健壮性。不依赖 androguard / 网络。
"""

from __future__ import annotations

from apkscan.analyzers.components import ComponentsAnalyzer
from apkscan.core.models import (
    AnalyzerResult,
    Component,
    ComponentSet,
    Finding,
    Severity,
)
from tests.conftest import FakeContext


def _run(components: ComponentSet | None) -> AnalyzerResult:
    ctx = FakeContext(package_name="com.fraud.app", components=components)
    return ComponentsAnalyzer().analyze(ctx)


def _ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


def _by_id(findings: list[Finding], fid: str) -> list[Finding]:
    return [f for f in findings if f.id == fid]


# ---------------------------------------------------------------------------
# 命中：各类型导出组件 → Finding
# ---------------------------------------------------------------------------


def test_exported_activity_emits_medium_finding() -> None:
    comp = ComponentSet(
        activities=[
            Component(name="com.fraud.app.PayActivity", exported=True, kind="activity")
        ]
    )
    result = _run(comp)

    assert result.analyzer == "components"
    assert result.error is None
    hits = _by_id(result.findings, "COMPONENT-EXPORTED-ACTIVITY")
    assert len(hits) == 1
    f = hits[0]
    assert f.severity is Severity.MEDIUM
    assert f.category == "component"
    assert f.evidences and f.evidences[0].source == "manifest"
    assert "com.fraud.app.PayActivity" in f.evidences[0].location
    assert "com.fraud.app.PayActivity" in f.description


def test_exported_service_emits_medium_finding() -> None:
    comp = ComponentSet(
        services=[Component(name="com.fraud.app.RemoteService", exported=True, kind="service")]
    )
    result = _run(comp)
    hits = _by_id(result.findings, "COMPONENT-EXPORTED-SERVICE")
    assert len(hits) == 1
    assert hits[0].severity is Severity.MEDIUM
    assert hits[0].category == "component"


def test_exported_receiver_emits_medium_finding() -> None:
    comp = ComponentSet(
        receivers=[Component(name="com.fraud.app.SmsReceiver", exported=True, kind="receiver")]
    )
    result = _run(comp)
    hits = _by_id(result.findings, "COMPONENT-EXPORTED-RECEIVER")
    assert len(hits) == 1
    assert hits[0].severity is Severity.MEDIUM


def test_exported_provider_emits_high_finding() -> None:
    comp = ComponentSet(
        providers=[
            Component(name="com.fraud.app.LedgerProvider", exported=True, kind="provider")
        ]
    )
    result = _run(comp)
    hits = _by_id(result.findings, "COMPONENT-EXPORTED-PROVIDER")
    assert len(hits) == 1
    # ContentProvider 可读/可写数据 → HIGH。
    assert hits[0].severity is Severity.HIGH
    assert hits[0].category == "component"


def test_all_types_combined() -> None:
    comp = ComponentSet(
        activities=[Component(name="A", exported=True, kind="activity")],
        services=[Component(name="S", exported=True, kind="service")],
        receivers=[Component(name="R", exported=True, kind="receiver")],
        providers=[Component(name="P", exported=True, kind="provider")],
    )
    result = _run(comp)
    assert {
        "COMPONENT-EXPORTED-ACTIVITY",
        "COMPONENT-EXPORTED-SERVICE",
        "COMPONENT-EXPORTED-RECEIVER",
        "COMPONENT-EXPORTED-PROVIDER",
    } <= _ids(result.findings)
    assert result.meta["exported_total"] == 4


# ---------------------------------------------------------------------------
# 研判提示标注
# ---------------------------------------------------------------------------


def test_sms_receiver_name_annotated() -> None:
    comp = ComponentSet(
        receivers=[Component(name="com.x.SmsCodeReceiver", exported=True, kind="receiver")]
    )
    result = _run(comp)
    f = _by_id(result.findings, "COMPONENT-EXPORTED-RECEIVER")[0]
    assert "研判提示" in f.description
    assert "sms" in f.description


def test_writable_provider_name_annotated_high() -> None:
    comp = ComponentSet(
        providers=[
            Component(name="com.x.FileProvider", exported=True, kind="provider")
        ]
    )
    result = _run(comp)
    f = _by_id(result.findings, "COMPONENT-EXPORTED-PROVIDER")[0]
    assert f.severity is Severity.HIGH
    assert "研判提示" in f.description
    assert "fileprovider" in f.description.lower()


def test_payment_activity_name_annotated() -> None:
    comp = ComponentSet(
        activities=[Component(name="com.x.CashierPayActivity", exported=True, kind="activity")]
    )
    result = _run(comp)
    f = _by_id(result.findings, "COMPONENT-EXPORTED-ACTIVITY")[0]
    assert "研判提示" in f.description
    assert "payment" in f.description


# ---------------------------------------------------------------------------
# kind 字段缺失：靠分组类型推断
# ---------------------------------------------------------------------------


def test_kind_inferred_from_group_when_field_empty() -> None:
    # Component.kind 留空时，仍按所在分组（providers）判定为 provider → HIGH。
    comp = ComponentSet(
        providers=[Component(name="com.x.DataProvider", exported=True, kind="")]
    )
    result = _run(comp)
    hits = _by_id(result.findings, "COMPONENT-EXPORTED-PROVIDER")
    assert len(hits) == 1
    assert hits[0].severity is Severity.HIGH


# ---------------------------------------------------------------------------
# 不命中：无导出组件
# ---------------------------------------------------------------------------


def test_no_exported_components_no_findings() -> None:
    comp = ComponentSet(
        activities=[Component(name="com.x.MainActivity", exported=False, kind="activity")],
        services=[Component(name="com.x.SyncService", exported=False, kind="service")],
        providers=[Component(name="com.x.PrivateProvider", exported=False, kind="provider")],
    )
    result = _run(comp)
    assert result.error is None
    assert result.findings == []
    assert result.meta["exported_total"] == 0
    assert result.meta["component_totals"]["activity"] == 1
    assert result.meta["component_totals"]["provider"] == 1
    assert result.meta["exported_counts"]["provider"] == 0


def test_mixed_exported_and_private() -> None:
    comp = ComponentSet(
        activities=[
            Component(name="com.x.MainActivity", exported=False, kind="activity"),
            Component(name="com.x.OpenActivity", exported=True, kind="activity"),
        ]
    )
    result = _run(comp)
    hits = _by_id(result.findings, "COMPONENT-EXPORTED-ACTIVITY")
    assert len(hits) == 1
    assert "com.x.OpenActivity" in hits[0].evidences[0].location
    assert result.meta["component_totals"]["activity"] == 2
    assert result.meta["exported_counts"]["activity"] == 1


def test_empty_component_set_no_findings() -> None:
    result = _run(ComponentSet())
    assert result.error is None
    assert result.findings == []
    assert result.meta["exported_total"] == 0


def test_none_components_treated_as_empty() -> None:
    # ctx.components() 返回 None → 按空组件处理，不崩溃。
    result = _run(None)
    assert result.error is None
    assert result.findings == []
    assert result.meta["exported_total"] == 0


# ---------------------------------------------------------------------------
# 健壮性：缺名组件被跳过，其余仍处理
# ---------------------------------------------------------------------------


def test_component_without_name_skipped() -> None:
    comp = ComponentSet(
        activities=[
            Component(name="", exported=True, kind="activity"),
            Component(name="com.x.GoodActivity", exported=True, kind="activity"),
        ]
    )
    result = _run(comp)
    hits = _by_id(result.findings, "COMPONENT-EXPORTED-ACTIVITY")
    # 缺名组件被跳过，只剩有效的一条。
    assert len(hits) == 1
    assert "com.x.GoodActivity" in hits[0].evidences[0].location


def test_fixture_context_runs(fake_ctx: FakeContext) -> None:
    # conftest 的 fake_ctx：MainActivity exported=True、SyncService exported=False。
    result = ComponentsAnalyzer().analyze(fake_ctx)
    assert result.analyzer == "components"
    assert result.error is None
    hits = _by_id(result.findings, "COMPONENT-EXPORTED-ACTIVITY")
    assert len(hits) == 1
    assert "com.test.app.MainActivity" in hits[0].evidences[0].location
    # 未导出的 SyncService 不产 Finding。
    assert _by_id(result.findings, "COMPONENT-EXPORTED-SERVICE") == []
    assert result.meta["exported_total"] == 1
