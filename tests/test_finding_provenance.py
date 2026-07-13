"""Finding 级溯源（1b-1）：analyzer 集中盖章 + confidence 置信度轴。

锁死：pipeline 聚合处给每条 finding 盖上产出它的分析器名（不覆盖已自标的）；Finding.confidence
默认 MEDIUM、启发式发现显式降 LOW；新字段正确序列化进 report.json。
"""

from __future__ import annotations

from apkscan.core import pipeline
from apkscan.core.models import AnalyzerResult, Confidence, Finding, Severity
from apkscan.report import json as report_json


def _finding(fid: str, analyzer: str = "") -> Finding:
    return Finding(
        id=fid, title="t", severity=Severity.LOW, category="c", description="d", analyzer=analyzer
    )


# --- analyzer 集中盖章 ------------------------------------------------------


def test_finding_analyzer_defaults_empty() -> None:
    assert _finding("X").analyzer == ""  # 构造时默认空，由 pipeline 聚合盖章


def test_aggregation_stamps_analyzer_name(monkeypatch, fake_ctx) -> None:  # type: ignore[no-untyped-def]
    from apkscan.core.registry import BaseAnalyzer

    class _A(BaseAnalyzer):
        name = "myzer"
        requires: list[str] = []

        def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
            return AnalyzerResult(analyzer=self.name, findings=[_finding("R1")])

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [_A()])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())
    from apkscan.core.models import AnalysisConfig

    report = pipeline.run(fake_ctx, AnalysisConfig(online=False))
    stamped = [f for f in report.findings if f.id == "R1"]
    assert stamped and stamped[0].analyzer == "myzer"  # 盖上分析器名


def test_aggregation_does_not_override_explicit_analyzer(monkeypatch, fake_ctx) -> None:  # type: ignore[no-untyped-def]
    from apkscan.core.models import AnalysisConfig
    from apkscan.core.registry import BaseAnalyzer

    class _A(BaseAnalyzer):
        name = "myzer"
        requires: list[str] = []

        def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
            # 分析器自标更细子来源 → 集中盖章不得覆盖。
            return AnalyzerResult(analyzer=self.name, findings=[_finding("R2", analyzer="myzer:sub")])

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [_A()])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())

    report = pipeline.run(fake_ctx, AnalysisConfig(online=False))
    got = [f for f in report.findings if f.id == "R2"]
    assert got and got[0].analyzer == "myzer:sub"  # 保留自标，不被覆盖


# --- confidence 轴 ----------------------------------------------------------


def test_finding_confidence_defaults_medium() -> None:
    assert _finding("X").confidence == Confidence.MEDIUM


def test_native_obfuscation_finding_is_low_confidence() -> None:
    # 启发式发现（熵/串密度）显式降 LOW，供消费方抑制噪声（packing name-only 在 test_packing 覆盖）。
    from apkscan.analyzers.native_obfuscation import NativeObfuscationAnalyzer

    nf = NativeObfuscationAnalyzer()._build_finding(
        [{"lib": "libx.so", "signals": ["高熵/低串"], "entropy": 7.9,
          "string_density": 0.01, "size": 999999}]
    )
    assert nf.id == "NATIVE-OBFUSCATION-SUSPECTED"
    assert nf.confidence == Confidence.LOW


# --- 序列化 ----------------------------------------------------------------


def test_provenance_fields_serialize() -> None:
    r_finding = _finding("S1", analyzer="myzer")
    r_finding.confidence = Confidence.HIGH
    from apkscan.core.models import Report

    rep = Report(
        package_name="x", meta={}, leads=[], endpoints=[], findings=[r_finding], analyzer_status=[]
    )
    d = report_json.to_dict(rep)
    f = d["findings"][0]
    assert f["analyzer"] == "myzer"
    assert f["confidence"] == "HIGH"  # Enum → .value
    assert f["kind"] == "inference"  # 主张类型默认 inference


# --- kind 主张类型轴 --------------------------------------------------------


def test_finding_kind_defaults_inference() -> None:
    # 静态规则 finding 默认 inference（规则推导）；运行时实测行为在 merge 侧标 observation。
    assert _finding("X").kind == "inference"


def test_finding_kinds_taxonomy() -> None:
    from apkscan.core.models import (
        FINDING_KIND_ANALYST_CONCLUSION,
        FINDING_KIND_INFERENCE,
        FINDING_KIND_OBSERVATION,
        FINDING_KINDS,
    )

    assert set(FINDING_KINDS) == {
        FINDING_KIND_OBSERVATION,
        FINDING_KIND_INFERENCE,
        FINDING_KIND_ANALYST_CONCLUSION,
    }
    assert FINDING_KIND_INFERENCE == "inference"
