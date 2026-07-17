"""阶段化执行 + 韧性（④，承接 pipeline 拆 stage）。

锁死：每个核心阶段经 _run_stage 执行 → stage_status 记 {name,status,error?}；阶段级异常被捕获、
不中断流水线（后续阶段照跑、仍产出报告），并反馈 analysis_status（analyze 崩→failed，其它→partial）。
计时只入日志、不入报告（保持串行==并行逐字节一致）。
"""

from __future__ import annotations

from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig

_EXPECTED_STAGES = [
    "analyze",
    "degradation_flags",
    "enrich",
    "attribution",
    "build_leads",
    "overseas_targets",
    "credibility",
    "network_attribution",
]


def _stub_discovery(monkeypatch, *, analyzers=None, enrichers=None) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: analyzers or [])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: enrichers or [])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())


def test_stage_status_recorded_in_order_happy_path(fake_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _stub_discovery(monkeypatch)
    report = pipeline.run(fake_ctx, AnalysisConfig(online=False))
    ss = report.meta["stage_status"]
    assert [s["name"] for s in ss] == _EXPECTED_STAGES  # 8 核心阶段，固定顺序
    assert all(s["status"] == "ran" for s in ss)
    assert all("error" not in s for s in ss)  # 无故障时不带 error 键
    assert report.analysis_status == "complete"


def test_stage_status_has_no_timing_deterministic(fake_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # 计时不入报告：stage_status 每项只含 name/status（+error），无 duration → 输出确定、可比对。
    _stub_discovery(monkeypatch)
    report = pipeline.run(fake_ctx, AnalysisConfig(online=False))
    for s in report.meta["stage_status"]:
        assert set(s.keys()) <= {"name", "status", "error"}


def test_stage_failure_captured_pipeline_continues(fake_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★韧性：某非 analyze 阶段崩 → 捕获记录、后续阶段照跑、run 不抛、analysis_status 至少 partial。
    _stub_discovery(monkeypatch)

    def _boom(_state: object) -> None:
        raise RuntimeError("enrich boom")

    monkeypatch.setattr(pipeline, "_stage_enrich", _boom)
    report = pipeline.run(fake_ctx, AnalysisConfig(online=True))  # 不抛异常

    ss = {s["name"]: s for s in report.meta["stage_status"]}
    assert ss["enrich"]["status"] == "error"
    assert "enrich boom" in ss["enrich"]["error"]
    assert ss["build_leads"]["status"] == "ran"  # 崩溃阶段之后的阶段仍执行
    assert ss["overseas_targets"]["status"] == "ran"
    assert ss["credibility"]["status"] == "ran"
    assert report.analysis_status == "partial"  # 阶段级故障反馈完整度


def test_analyze_stage_failure_marks_failed(fake_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # analyze 是核心阶段：崩溃 → analysis_status=failed（核心产出缺失），但仍返回 Report、不抛。
    _stub_discovery(monkeypatch)

    def _boom(_state: object) -> None:
        raise RuntimeError("analyze boom")

    monkeypatch.setattr(pipeline, "_stage_run_analyzers", _boom)
    report = pipeline.run(fake_ctx, AnalysisConfig(online=False))

    ss = {s["name"]: s for s in report.meta["stage_status"]}
    assert ss["analyze"]["status"] == "error"
    assert report.analysis_status == "failed"
    # ★codex 复审:analyze 崩时 analyzer_status 为空、_analysis_health 会算出误导性的 completeness=1.0，
    #   须校正为 0.0，与 failed 一致（否则报告出现 failed + 满完整度的矛盾）。
    assert report.completeness == 0.0


def test_apply_stage_failures_does_not_upgrade_failed() -> None:
    # 单元：已判 failed 的不因"其它阶段也崩"被上调；有 analyze 崩即 failed（优先级最高）。
    from apkscan.core.models import ANALYSIS_STATUS_FAILED

    state = pipeline._PipelineState(
        ctx=object(), config=AnalysisConfig(), platform="android", capabilities=set()
    )
    state.analysis_status = ANALYSIS_STATUS_FAILED  # 分析器侧已判 failed
    state.stage_status = [{"name": "enrich", "status": "error", "error": "x"}]  # 非 analyze 崩
    pipeline._apply_stage_failures(state)
    assert state.analysis_status == ANALYSIS_STATUS_FAILED  # 不被上调回 partial


def _boom(_state: object) -> None:
    raise RuntimeError("assemble boom")


def test_network_attribution_failure_is_additive_no_degrade(fake_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★codex 复审 P1-2：network_attribution 是纯被动附加视图（_ADDITIVE_STAGES）——其组装故障只记
    #   stage_status 供审计、**不反哺 analysis_status**，附加视图崩不该把整份报告降 partial。
    _stub_discovery(monkeypatch)
    baseline = pipeline.run(fake_ctx, AnalysisConfig(online=False))  # 未 patch 的干净基线

    monkeypatch.setattr(pipeline, "_stage_network_attribution", _boom)
    report = pipeline.run(fake_ctx, AnalysisConfig(online=False))

    ss = {s["name"]: s for s in report.meta["stage_status"]}
    assert ss["network_attribution"]["status"] == "error"  # error 审计痕迹保留
    assert "assemble boom" in ss["network_attribution"]["error"]
    assert report.analysis_status == "complete"  # 附加视图崩不降级
    assert report.completeness == baseline.completeness  # 分析器层完整度不受附加视图影响


def test_network_attribution_failure_does_not_touch_strict_exit(fake_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★codex 复审 P1-2：附加视图崩不得污染 --strict 退出码（analysis_status 仍 complete → 无错误退出码）。
    from apkscan.cli import _strict_exit_code

    _stub_discovery(monkeypatch)
    monkeypatch.setattr(pipeline, "_stage_network_attribution", _boom)
    report = pipeline.run(fake_ctx, AnalysisConfig(online=False))
    assert _strict_exit_code(report) is None


def test_additive_exemption_does_not_mask_real_stage_failure(fake_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★豁免只对 _ADDITIVE_STAGES：非附加阶段（enrich）崩仍照常降 partial，即便 network_attribution 同时崩。
    _stub_discovery(monkeypatch)

    def _boom_enrich(_state: object) -> None:
        raise RuntimeError("enrich boom")

    monkeypatch.setattr(pipeline, "_stage_enrich", _boom_enrich)
    monkeypatch.setattr(pipeline, "_stage_network_attribution", _boom)
    report = pipeline.run(fake_ctx, AnalysisConfig(online=True))
    assert report.analysis_status == "partial"  # enrich 崩（非附加）→ 仍降级，附加豁免不掩盖真故障


def test_apply_stage_failures_exempts_additive_stages() -> None:
    # 单元：stage_status 只有附加阶段 network_attribution error → analysis_status 不从 complete 降级。
    from apkscan.core.models import ANALYSIS_STATUS_COMPLETE

    state = pipeline._PipelineState(
        ctx=object(), config=AnalysisConfig(), platform="android", capabilities=set()
    )
    state.analysis_status = ANALYSIS_STATUS_COMPLETE
    state.stage_status = [{"name": "network_attribution", "status": "error", "error": "x"}]
    pipeline._apply_stage_failures(state)
    assert state.analysis_status == ANALYSIS_STATUS_COMPLETE  # 附加阶段崩不降级
