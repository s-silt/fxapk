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

from pathlib import Path

import pytest

from apkscan.core import infra, pipeline
from apkscan.core.models import AnalysisConfig
from apkscan.core.regress import ADVICE_INVESTIGATE
from tests.conftest import FakeContext
from tests.synthetic.third_party import THIRD_PARTY_SAMPLES, ThirdPartySample
from tests.synthetic.third_party_baseline import BASELINE

_BASELINE_PATH = Path(__file__).parent / "synthetic" / "third_party_baseline.py"
_BASELINE = BASELINE


def _run(sample: ThirdPartySample):
    """跑真实 pipeline（真分析器 + 真规则），返回 report。"""
    ctx = FakeContext(dex_strings=sample.dex_strings, files=sample.files)
    return pipeline.run(ctx, AnalysisConfig(online=False))


def _categories(report) -> list[str]:
    return sorted({str(getattr(lead.category, "value", lead.category)) for lead in report.leads})


#: 档位 → 基线里用的稳定代号。基线存代号而非中文文案，是为了与措辞解耦：改一句文案
#: 不该让十份基线一起漂移。
_ADVICE_CODE = {ADVICE_INVESTIGATE: "investigate", "待核": "review", "无需调证": "skip"}  # leak-scan: allow 判据档位常量本身，映射表要照抄它们


def _signature(report) -> list[list[str]]:
    """值级签名：``[类别, 值, 档位代号]`` 的有序列表，**不去重**（条数也是签名的一部分）。

    ★基线从「类别集合」升到这里，补的是两个盲区：
      · **值集**——夹具本要防的那个具体串还在不在？判据某天不再提取它，夹具就空转了，
        而类集合看不出来（实证：go-truncated 那份夹具的伪域名早就不出现了，基线仍全绿）；
      · **条数**——同一类多冒出一条，是判据变松最早的征兆。
    """
    return sorted(
        [
            str(getattr(x.category, "value", x.category)),
            str(x.value),
            _ADVICE_CODE.get(str(x.advice or ""), str(x.advice or "")),
        ]
        for x in report.leads
    )


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
    """★漂移可见：附带线索须与基线**逐值**全等——判据变松/变严都要在 diff 里显式。

    只守「禁止类为空」是不够的：判据整体放宽时，低档位噪音会先涨起来，
    那正是下一次高代价误报的前兆。基线全等把这个前兆也钉住。

    基线记的是 ``[类别, 值, 档位]``，不是类别集合——后者对「值换了」「多了一条」
    「档位升了」三种漂移全盲，而那三种恰恰是判据变松的样子。
    """
    detected = _signature(_run(sample))
    baseline = _BASELINE.get(sample.name)
    assert baseline is not None, (
        f"样本 {sample.name!r} 无基线；新增第三方样本后请更新 {_BASELINE_PATH.name}"
    )
    expected = [list(row) for row in baseline]
    assert detected == expected, (
        f"第三方样本 {sample.name!r} 检出漂移：\n"
        f"  基线 {expected}\n  实际 {detected}\n"
        f"  该内容实为：{sample.why}\n"
        f"  线索变多 = 判据变松（误报风险上升）；变少 = 降噪生效，两者都请有意更新基线。"
    )


@pytest.mark.parametrize(
    "sample", [s for s in THIRD_PARTY_SAMPLES if s.must_not_appear],
    ids=lambda s: s.name,
)
def test_named_dead_values_never_show_up(sample: ThirdPartySample) -> None:
    """★点名死值：这些具体串一个都不该作为线索出现。

    补的是基线的另一个盲区——**夹具空转**。判据某天不再提取某种形态后，夹具还在、
    基线也还绿，但它已经什么都不防了，直到判据回退、误报重新出现才被发现。
    把「这份夹具到底在防什么」写成可执行断言，空转与生效就分得开了。

    ★变异验证：把域名正则的边界放宽（去掉左边界的非字母数字要求），本测试必红。
    """
    values = {str(x.value) for x in _run(sample).leads}
    hit = sample.must_not_appear & values
    assert not hit, (
        f"{sample.name}: 点名的死值又出现了 {sorted(hit)}\n"
        f"  该内容实为：{sample.why}\n"
        f"  这些串不是任何人的资产，出现在报告里就是纯噪音。"
    )


@pytest.mark.parametrize(
    "sample", [s for s in THIRD_PARTY_SAMPLES if s.must_not_be_actionable],
    ids=lambda s: s.name,
)
def test_framework_own_values_never_reach_the_actionable_tier(sample: ThirdPartySample) -> None:
    """★档位锁：框架自带的域名/地址不得落在"建议"档。

    基线只记「检出了哪些线索类」，对档位是盲的——一个域名从"无需"升成"建议"，
    类还是 DOMAIN，基线照样全绿，而那正是误报真正生效的形态。这条补上那个缺口。

    实测抓到过：同一个 Flutter 框架的域名里，只有 dart.dev 漏在名单外被升了档；
    Unity 的三个云服务端点与 RN 的文档站整族缺席。

    ★变异验证：把 infra 已知基础设施清单里对应的条目删掉，本测试必红。
    """
    report = _run(sample)
    by_value = {str(lead.value): lead for lead in report.leads}
    offenders = {
        v: by_value[v].advice
        for v in sample.must_not_be_actionable
        if v in by_value and by_value[v].advice == ADVICE_INVESTIGATE
    }
    assert not offenders, (
        f"{sample.name}: 框架自带的值被升到「{ADVICE_INVESTIGATE}」档 {offenders}\n"
        f"  该内容实为：{sample.why}\n"
        f"  这些值没有可查的主体，升档只会把无关的一方拉进来。"
    )
    # ★防空转：这些值必须真的出现在报告里，否则本条断言什么都没检查。
    missing = sample.must_not_be_actionable - set(by_value)
    assert not missing, (
        f"{sample.name}: 夹具里的 {sorted(missing)} 压根没被提取成线索，"
        f"本条档位断言等于空转——请先确认夹具形态仍能被提取"
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


#: ★往「已知基础设施」清单里加一条 = 给它下的一整棵子树发免检牌（本表按域边界后缀匹配）。
#: 平台厂商的域名下常常同时挂着两种东西：厂商自己的固定服务端点，以及**租户可控**的资源。
#: 后者的归属恰恰是最该核的——它是 App 作者能往里塞代码/配置的地方。
_TENANT_CONTROLLED = [
    ("u.expo.dev", "EAS Update 的 OTA 清单地址，JS bundle 与下发配置由 App 作者控制"),
    ("services.api.unity.com", "Unity Gaming Services，Cloud Code 是开发者自写的服务端脚本"),  # leak-scan: allow 阴性夹具：测的正是这个租户可控子域不该被整域免检，占位域名验不出边界
    ("cloud.unity3d.com", "Unity Cloud Build 承载用户构建产物"),  # leak-scan: allow 阴性夹具：测的正是这个租户可控子域不该被整域免检，占位域名验不出边界
]
#: 与之相对：厂商自己的固定端点/文档站，免检才对。
_VENDOR_FIXED = [
    "auction.unityads.unity3d.com", "config.uca.cloud.unity3d.com",  # leak-scan: allow 阴性夹具：Unity 引擎自带端点，测的正是它们该免检
    "cdp.cloud.unity3d.com", "docs.expo.dev", "reactnative.dev",  # leak-scan: allow 阴性夹具：Unity/Expo/RN 厂商固定端点与文档站
    "flutter.dev", "dart.dev", "pub.dev",
]


@pytest.mark.parametrize(("host", "why"), _TENANT_CONTROLLED, ids=lambda x: str(x)[:40])
def test_tenant_controlled_subdomains_are_not_waved_through(host: str, why: str) -> None:
    """★整域收编会把租户可控的子域一起免检——那是把最该查的东西判成不用查。

    本表的 SKIP 是判据链结论、不进抑制账本，``fxapk lead restore`` 也够不着；
    落进去就捞不回来，所以宁可窄。同表里对同类情形本就是这个做法（钉钉只列 mcs 子域）。

    ★变异验证：把 infra 清单里的文档站条目放宽成对应的裸域（去掉 docs. 前缀，或补回
    厂商的顶级域整条），本测试必红。
    """
    assert not infra.is_known_infra(host), f"{host} 被整域免检了——{why}"


@pytest.mark.parametrize("host", _VENDOR_FIXED)
def test_vendor_fixed_endpoints_stay_waved_through(host: str) -> None:
    """收窄不能收过头：厂商自己的固定端点与文档站仍要免检，否则每个包都稳定贡献噪音。"""
    assert infra.is_known_infra(host), f"{host} 该免检却没有——收窄收过头了"


def test_baseline_covers_all_third_party_samples() -> None:
    """基线与样本集一一对应（防新增样本忘记基线、或基线残留已删样本）。"""
    assert set(_BASELINE) == {s.name for s in THIRD_PARTY_SAMPLES}


def test_forbidden_categories_are_not_in_baseline() -> None:
    """★自洽性：基线里不得含任何样本自己声明的禁止类。

    否则等于把一条已知误报「固化成基线」当作正常——护栏会永远绿着，而误报还在。
    """
    for s in THIRD_PARTY_SAMPLES:
        baseline_cats = {str(row[0]) for row in _BASELINE[s.name]}
        overlap = s.forbidden_categories & baseline_cats
        assert not overlap, (
            f"{s.name}: 基线里含禁止类 {sorted(overlap)}——"
            f"这是把已知误报固化成基线，必须先修判据"
        )


def test_named_dead_values_are_not_in_baseline() -> None:
    """★同理：点名的死值也不能出现在基线里——那同样是把已知误报固化。"""
    for s in THIRD_PARTY_SAMPLES:
        if not s.must_not_appear:
            continue
        baseline_values = {str(row[1]) for row in _BASELINE[s.name]}
        overlap = s.must_not_appear & baseline_values
        assert not overlap, (
            f"{s.name}: 基线里含点名死值 {sorted(overlap)}——先修判据，别把它写进基线"
        )
