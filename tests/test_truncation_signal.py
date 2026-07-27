"""DEX 扫描截断必须成为**数据**，而不是只落一行日志。零真实数据。

截断是最隐蔽的可见性缺口：分析器"跑成功了"、状态全绿，只是没扫完，于是"未发现某接口"
完全可能只是它排在截断线之后。实测一个 100MB 样本上 11 个分析器同时截断，而此前只有
endpoints 把这个事实写进 meta——可见性层碰巧靠它感知到，一旦 endpoints 没截断而别的截断了
就彻底沉默。
"""
from __future__ import annotations

from apkscan.analyzers._common import DEX_TRUNCATED_META_KEY, collect_dex_strings
from apkscan.core import visibility
from apkscan.core.models import AnalyzerResult


class _Ctx:
    """只提供 dex_strings 的最小上下文。"""

    def __init__(self, n: int) -> None:
        self._n = n

    def dex_strings(self):
        return (f"s{i}" for i in range(self._n))


def test_truncation_lands_in_result_meta():
    """★截断要写进 result.meta —— 只打日志的话，digest / closure / AI 全都读不到。"""
    result = AnalyzerResult(analyzer="probe")
    ok, strings = collect_dex_strings(_Ctx(50), "probe", max_strings=10, result=result)
    assert ok and len(strings) == 10
    assert result.meta.get(DEX_TRUNCATED_META_KEY) is True


def test_no_truncation_leaves_meta_clean():
    result = AnalyzerResult(analyzer="probe")
    collect_dex_strings(_Ctx(5), "probe", max_strings=10, result=result)
    assert DEX_TRUNCATED_META_KEY not in result.meta


def test_result_optional_keeps_old_callers_working():
    """不传 result 时行为不变——便于逐个分析器渐进接入，不必一次改完全部调用点。"""
    ok, strings = collect_dex_strings(_Ctx(50), "probe", max_strings=10)
    assert ok and len(strings) == 10


def test_pipeline_merges_truncation_as_or_not_overwrite():
    """★多分析器合并时截断是**或运算**，不是覆盖。

    实测一个样本上 11 个分析器同时截断；若按普通 meta 合并，最后一个写 False 的会把前面的
    True 抹掉——"没扫全"这件事就此消失。顺带要记下是谁截断的，让人能定位哪块没扫完。
    """
    import inspect

    from apkscan.core import pipeline

    src = inspect.getsource(pipeline)
    assert "_DEX_TRUNCATED_KEY" in src
    assert "_DEX_TRUNCATED_BY_KEY" in src
    # 合并处必须跳过截断键的覆盖式赋值
    assert "continue" in src.split("_DEX_TRUNCATED_KEY:")[-1][:200], (
        "截断键没有被排除出覆盖式合并，后跑的分析器会把 True 抹成 False"
    )


def test_visibility_reads_truncation_from_any_analyzer():
    """可见性层读顶层聚合键，而非某个特定分析器的 —— 谁截断都算数，并说出是谁。"""
    a = visibility.assess({"meta": {
        "dex_strings_truncated": True,
        "dex_strings_truncated_by": ["contacts", "api_surface", "wallet_secret"],
    }})
    assert a["sources"]["dex"]["visibility"] == visibility.VIS_PARTIAL
    assert "static_endpoint_exhaustive" in a["blocked_claims"]
    why = " ".join(a["sources"]["dex"]["why"])
    assert "contacts" in why and "api_surface" in why, "没说清是谁截断的，无从定位哪块没扫完"
