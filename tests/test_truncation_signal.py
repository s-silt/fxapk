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


def test_pipeline_merges_truncation_as_or_not_overwrite(monkeypatch):
    """★多分析器合并时截断是**或运算**，不是覆盖，且要记下是谁截断的。

    实测一个样本上 11 个分析器同时截断；若按普通 meta 合并，最后一个写 False 的会把前面的
    True 抹掉——"没扫全"这件事就此消失。

    ★这条测试**曾经是假的**：原版用 ``inspect.getsource(pipeline)`` 断言源码里出现过
      ``continue`` 字符串。复审实测：把那个守卫改成 ``if False:``，``continue`` 仍在源码里，
      4362 条测试全绿——它查的是源码文本，不是行为。而同一文件下一条测试的 docstring 就写着
      「静态审计骗过我三次……唯一可信的是真跑一遍」，教训写下了，没有回头改这一条。

    现改为走 ``pipeline.run`` 真入口的行为断言，锁三件事（缺一件都等于「没扫全」丢了）：
      ① 先 True 后 False → 合并结果必须仍是 True；
      ② ``dex_strings_truncated_by`` 记下**是谁**截断的（人要能定位哪块没扫完）；
      ③ 这个事实一路传到 ``visibility``，把 dex 面判成 partial 且理由里带上分析器名。
    """
    from apkscan.core import pipeline, visibility
    from apkscan.core.meta_contract import META_KEY_REGISTRY, MetaKeyContract
    from apkscan.core.models import AnalysisConfig, AnalyzerResult
    from apkscan.core.registry import BaseAnalyzer

    class _Truncating(BaseAnalyzer):
        name = "probe_truncated"
        requires: list = []

        def analyze(self, ctx):  # noqa: ANN001
            r = AnalyzerResult(analyzer=self.name)
            r.meta[pipeline._DEX_TRUNCATED_KEY] = True
            return r

    class _NotTruncating(BaseAnalyzer):
        """后跑且明确写 False——正是会把前者抹掉的那种。"""

        name = "probe_complete"
        requires: list = []

        def analyze(self, ctx):  # noqa: ANN001
            r = AnalyzerResult(analyzer=self.name)
            r.meta[pipeline._DEX_TRUNCATED_KEY] = False
            return r

    # 顺序要紧：截断的先跑，不截断的后跑，才验得到「后者不得覆盖前者」
    from tests.conftest import FakeContext

    monkeypatch.setattr(
        pipeline, "discover_analyzers", lambda: [_Truncating(), _NotTruncating()]
    )
    contract = META_KEY_REGISTRY[pipeline._DEX_TRUNCATED_KEY]
    monkeypatch.setitem(
        META_KEY_REGISTRY,
        pipeline._DEX_TRUNCATED_KEY,
        MetaKeyContract(
            owners=contract.owners | {"probe_truncated", "probe_complete"},
            merge=contract.merge,
        ),
    )
    report = pipeline.run(FakeContext(), AnalysisConfig(online=False))

    # ① 或运算：后写的 False 不得抹掉前面的 True
    assert report.meta.get(pipeline._DEX_TRUNCATED_KEY) is True, (
        "后跑的分析器把截断标记抹成了 False——「没扫全」这件事就此消失"
    )
    # ② 记名：人要能定位是哪块没扫完
    by = report.meta.get(pipeline._DEX_TRUNCATED_BY_KEY)
    assert by == ["probe_truncated"], f"截断来源记错或没记：{by!r}"

    # ③ 接线：截断事实必须一路传到可见性判定，否则「未发现」会被当成「确实没有」
    dex_vis, why = visibility._dex_visibility(report.meta)
    assert dex_vis == visibility.VIS_PARTIAL, (
        f"截断了却把 DEX 面判成 {dex_vis}——「未发现某接口」会被误当作确实不存在"
    )
    assert any("probe_truncated" in w for w in why), f"可见性理由里没带上是谁截断的：{why}"


def test_every_dex_reading_analyzer_reports_truncation():
    """★全量实跑：凡是读 DEX 字符串的分析器，截断时都必须上报。

    这条是拿实跑当判据，因为静态审计骗过我三次：正则不认 `.get(`、AST 不认位置参数、
    改模块变量对**函数默认参数**无效（默认值在定义时就绑定了）。唯一可信的是——
    把上限压到 1 真跑一遍，看 meta 里有没有标记。

    新增分析器若读 DEX 却不上报，这条会红。
    """
    from apkscan.analyzers import _common
    from apkscan.core.registry import discover_analyzers

    analyzers = list(discover_analyzers())

    class _Ctx:
        package_name = "com.probe"
        platform = "android"
        apk_path = ""
        manifest_xml = None
        permissions: list = []
        components: list = []
        config = None
        dex_available = True

        def dex_strings(self):
            # 兼具路径形态与接口形态，让各类分析器都走到自己的提取分支
            return (f"/opt/work/e{i}/p/a.cc /api/v1/x{i}/get" for i in range(50))

        def list_files(self):
            return []

        def native_libs(self):
            return []

        def read_file(self, _path):
            return None

        def declared_size(self, _path):
            return None

        def certificates(self):
            return []

    # ★同时压两处：模块级常量（显式传 max_strings 的调用）与函数默认值（无参调用）。
    #   只改前者会漏掉走默认值的分析器——api_surface 就这样被漏判过一次。
    originals: list = []
    kwdefaults = _common.collect_dex_strings.__kwdefaults__
    if kwdefaults and "max_strings" in kwdefaults:
        originals.append((kwdefaults, "max_strings", kwdefaults["max_strings"]))
        kwdefaults["max_strings"] = 1
    import sys as _sys
    for mod in list(_sys.modules.values()):
        mod_name = getattr(mod, "__name__", "")
        if not mod_name.startswith("apkscan.analyzers"):
            continue
        for attr in ("_MAX_DEX_STRINGS", "_MAX_STRINGS"):
            if hasattr(mod, attr):
                originals.append((mod, attr, getattr(mod, attr)))
                setattr(mod, attr, 1)

    # ★"读没读 DEX"必须直接观测，不能靠 meta 里有没有某几个键去猜——猜法漏过突变验证：
    #   把 wallet_secret 的上报去掉后测试仍绿，因为它的 meta 里没有那几个键。
    #   改为在 ctx 上记录 dex_strings() 是否真被调用过。
    class _CountingCtx(_Ctx):
        def __init__(self) -> None:
            self.dex_read = False

        def dex_strings(self):
            self.dex_read = True
            return super().dex_strings()

    try:
        silent: list[str] = []
        for analyzer in analyzers:
            name = getattr(analyzer, "name", type(analyzer).__name__)
            ctx = _CountingCtx()
            try:
                res = analyzer.analyze(ctx)  # type: ignore[arg-type]
            except Exception:  # noqa: BLE001 — 本测试只关心截断上报，分析器自身异常另有测试覆盖
                continue
            meta = getattr(res, "meta", {}) or {}
            if ctx.dex_read and not meta.get(DEX_TRUNCATED_META_KEY):
                silent.append(name)
        assert not silent, (
            f"这些分析器读了 DEX 却在截断时不吭声：{silent}。"
            f"截断意味着'未发现'可能只是没扫到那一段——报告必须说出来"
        )
    finally:
        for holder, attr, value in originals:
            if isinstance(holder, dict):
                holder[attr] = value
            else:
                setattr(holder, attr, value)


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
