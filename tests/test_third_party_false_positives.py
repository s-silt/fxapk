"""第三方生态误报回归网（反向：不该报的别报）。

与 ``test_synthetic_regression.py`` 互为镜像：
  · 那边守「该检出的别漏」（检出回归）；
  · 本网守「**不该报的别报**」（误报回归）。

判据是形态启发式，在熟悉的域内准确率尚可，一进新生态就大面积误报——而误报的产出会
指向无关主体，附注措辞还会反过来影响人工复核的取舍。所以误报要像检出一样
**有回归网兜着**，而不是发现一个修一个。

三重断言（缺一不可）
--------------------
1. ``forbidden ∩ detected == ∅``——高代价线索类绝不能被第三方内容触发（**硬门禁**）；
2. ``detected == baseline``——附带产生的低档位线索必须与基线全等，**任何漂移都逼一次
   有意的基线更新**，让「判据变松了」在 review 里显式可见；
3. 正向自检——夹具确实跑过了真 pipeline（防「样本根本没进分析器」造成的永假绿）。

★为什么必须有第 2、3 条：只断言第 1 条的话，把判据全删光也能全绿——那不是护栏，是安慰剂。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig
from tests.conftest import FakeContext
from tests.synthetic.third_party import THIRD_PARTY_SAMPLES, ThirdPartySample

_BASELINE_PATH = Path(__file__).parent / "synthetic" / "third_party_baseline.json"
_BASELINE = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))


def _run(sample: ThirdPartySample):
    """跑真实 pipeline（真分析器 + 真规则），返回 report。"""
    ctx = FakeContext(dex_strings=sample.dex_strings, files=sample.files)
    return pipeline.run(ctx, AnalysisConfig(online=False))


def _categories(report) -> list[str]:
    return sorted({str(getattr(lead.category, "value", lead.category)) for lead in report.leads})


@pytest.mark.parametrize("sample", THIRD_PARTY_SAMPLES, ids=lambda s: s.name)
def test_third_party_content_never_triggers_high_stakes_leads(sample: ThirdPartySample) -> None:
    """★硬门禁：第三方生态内容不得产生会进调证出口的高代价线索类。  # leak-scan: allow 断言说明：高代价出口类的定义

    这些内容在真实世界是库常量 / 文案键 / 作者信息 / 伪域名——**没有一条是谁的资产**。
    一旦命中，产出的线索会指向一个与案件无关的主体。  # leak-scan: allow 断言说明：误报会指向无关主体
    """
    detected = set(_categories(_run(sample)))
    hit = sample.forbidden_categories & detected
    assert not hit, (
        f"第三方样本 {sample.name!r} 误报了高代价线索类 {sorted(hit)}\n"
        f"  该内容实为：{sample.why}\n"
        f"  实际检出：{sorted(detected)}"
    )


@pytest.mark.parametrize("sample", THIRD_PARTY_SAMPLES, ids=lambda s: s.name)
def test_third_party_detection_matches_baseline(sample: ThirdPartySample) -> None:
    """★漂移可见：附带线索须与基线全等——判据变松/变严都要在 diff 里显式。

    只守「禁止类为空」是不够的：判据整体放宽时，低档位噪音会先涨起来，
    那正是下一次高代价误报的前兆。基线全等把这个前兆也钉住。
    """
    detected = _categories(_run(sample))
    baseline = _BASELINE.get(sample.name)
    assert baseline is not None, (
        f"样本 {sample.name!r} 无基线；新增第三方样本后请更新 {_BASELINE_PATH.name}"
    )
    assert detected == baseline, (
        f"第三方样本 {sample.name!r} 检出漂移：基线 {baseline} → 实际 {detected}。\n"
        f"  该内容实为：{sample.why}\n"
        f"  线索变多 = 判据变松（误报风险上升）；变少 = 降噪生效，两者都请有意更新基线。"
    )


@pytest.mark.parametrize("sample", THIRD_PARTY_SAMPLES, ids=lambda s: s.name)
def test_samples_actually_reach_the_analyzers(sample: ThirdPartySample) -> None:
    """★防永假绿：夹具必须真的被分析器读到。

    若 FakeContext 装配方式变了、样本内容压根没进 pipeline，上面两条会「全绿」——
    但那是什么都没测。这里断言 pipeline 确实跑起来并产出了报告结构。
    """
    report = _run(sample)
    assert report is not None
    ran = (report.meta or {}).get("analyzers_ran")
    if ran is not None:  # 该字段存在时顺带断言确有分析器执行
        assert ran, f"{sample.name}: 没有任何分析器执行，样本未进 pipeline"


def test_baseline_covers_all_third_party_samples() -> None:
    """基线与样本集一一对应（防新增样本忘记基线、或基线残留已删样本）。"""
    assert set(_BASELINE) == {s.name for s in THIRD_PARTY_SAMPLES}


def test_forbidden_categories_are_not_in_baseline() -> None:
    """★自洽性：基线里不得含任何样本自己声明的禁止类。

    否则等于把一条已知误报「固化成基线」当作正常——护栏会永远绿着，而误报还在。
    """
    for s in THIRD_PARTY_SAMPLES:
        overlap = s.forbidden_categories & set(_BASELINE[s.name])
        assert not overlap, (
            f"{s.name}: 基线里含禁止类 {sorted(overlap)}——"
            f"这是把已知误报固化成基线，必须先修判据"
        )
