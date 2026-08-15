"""合成样本检出回归网（战略 #1 地基）。

价值：这个工具的实际价值 = 从真实涉诈样本抠出多少可办案线索，而检出率由 ~4677 行规则 YAML 决定、
非 Python 引擎。此前只有"引擎正确"的组件测试，缺"对样本检出有效"的回归基线——改一条规则不知检出涨了还是回归了。

本网用**零 PII 合成样本**驱动**真实 pipeline**（真分析器 + 真规则），双重断言：
  · ``expected_categories ⊆ detected``——语义必守：改规则不得掉了该样本的核心线索类（回归即红）；
  · ``detected == baseline``——漂移可见：任何检出集变化（掉/增）都逼一次**有意的基线更新**，
    让规则改动在 diff/review 里显式可见、可回归。规则有意变更时更新 ``tests/synthetic/baseline.json``。

★这是地基（3 样本 / 3 类），不是全量夹具库——扩样本见 ``tests/synthetic/README.md``。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig
from tests.synthetic.samples import SAMPLES, SyntheticSample
from tests.synthetic.snapshot import build_context

_BASELINE = json.loads((Path(__file__).parent / "synthetic" / "baseline.json").read_text(encoding="utf-8"))


def _detected_categories(sample: SyntheticSample) -> list[str]:
    """跑真实 pipeline，返回该合成样本检出的 LeadCategory 值（排序、去重）。

    FakeContext 经 snapshot.build_context 构造（最小 manifest + DEX 填充到 stub 阈值之上）：
    修的是夹具缺陷——此前空 manifest 让每个样本都背着 critical_failures=['manifest']、串太少
    让每个样本都被误判 stub_only。8 个样本修复前后检出类别 0 变化（已实测），断言语义不变。
    """
    report = pipeline.run(build_context(sample), AnalysisConfig(online=False))
    return sorted({str(getattr(lead.category, "value", lead.category)) for lead in report.leads})


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s.name)
def test_expected_categories_still_detected(sample: SyntheticSample) -> None:
    """★语义回归：期望的 LeadCategory 必须仍被真实 pipeline 检出（改规则掉了核心检出即红）。"""
    detected = set(_detected_categories(sample))
    missing = sample.expected_categories - detected
    assert not missing, (
        f"合成样本 {sample.name!r} 掉了期望线索类 {sorted(missing)}（检出回归！）；"
        f"实际检出 {sorted(detected)}"
    )


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s.name)
def test_detection_matches_baseline(sample: SyntheticSample) -> None:
    """★漂移可见：检出集须与基线全等。规则有意变更→更新 tests/synthetic/baseline.json（让改动在 review 里显式）。"""
    detected = _detected_categories(sample)
    baseline = _BASELINE.get(sample.name)
    assert baseline is not None, f"样本 {sample.name!r} 无基线；新增样本后请重生成 baseline.json"
    assert detected == baseline, (
        f"合成样本 {sample.name!r} 检出漂移：基线 {baseline} → 实际 {detected}。"
        f"若为规则有意变更，更新 tests/synthetic/baseline.json；否则是检出回归。"
    )


def test_baseline_covers_all_samples() -> None:
    """基线与样本集一一对应（防新增样本忘记基线、或基线残留已删样本）。"""
    assert set(_BASELINE) == {s.name for s in SAMPLES}


def test_expected_categories_are_subset_of_baseline() -> None:
    """样本声明的 expected 必须在基线里（防 expected 写了个基线根本没检出的类，造成永假绿）。"""
    for s in SAMPLES:
        assert s.expected_categories.issubset(set(_BASELINE[s.name])), \
            f"{s.name}: expected {sorted(s.expected_categories)} 不在基线 {_BASELINE[s.name]} 内"
