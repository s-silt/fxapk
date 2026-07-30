"""平台能力门控：``requires`` 除工具能力外还表达"我只适用于某平台"。

★为什么需要它：改这里之前，``requires`` 只表达"环境有没有某工具"，完全没有平台概念，
  而 ``capabilities.add("apk")`` 是**无条件**的——于是任何非 APK 输入（网页证据一类）进来时，
  30 个扫 dex/.so/assets 的 ``requires=["apk"]`` 分析器照样被判 eligible 然后空跑一趟：
  既白费时间，又让 ``completeness`` 显得很完整（分母里全算"跑过了"），掩盖"这批分析器
  对当前输入压根不适用"的事实。

门控走**现成的 skip 通路**（``analyzer_status`` 记 skipped + reason），不新造机制：
跨平台分析器被跳过这件事必须在报告里看得见，而不是静默消失。
"""

from __future__ import annotations

import logging

import pytest

from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig, AnalyzerResult
from apkscan.core.registry import (
    _KNOWN_CAPABILITIES,
    _PLATFORM_CAPABILITIES,
    BaseAnalyzer,
    _dedup_and_validate,
    platform_capabilities,
)

from tests.conftest import FakeContext


class _AndroidOnly(BaseAnalyzer):
    """代表既有那 30 个 requires=["apk"] 的分析器（扫 dex/.so/assets）。"""

    name = "android_only"
    requires = ["apk"]

    def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
        return AnalyzerResult(analyzer=self.name)


class _WebOnly(BaseAnalyzer):
    name = "web_only"
    requires = ["web"]

    def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
        return AnalyzerResult(analyzer=self.name)


class _PlatformAgnostic(BaseAnalyzer):
    """无 requires 的分析器（纯静态文本判据）必须两个平台都跑——门控不许波及它们。"""

    name = "agnostic"
    requires: list[str] = []

    def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
        return AnalyzerResult(analyzer=self.name)


def _run(monkeypatch: pytest.MonkeyPatch, platform: str) -> dict[str, dict]:
    """在给定平台上跑 pipeline，返回 ``{分析器名: status 记录}``。"""
    monkeypatch.setattr(
        pipeline,
        "discover_analyzers",
        lambda: [_AndroidOnly(), _WebOnly(), _PlatformAgnostic()],
    )
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    # 工具能力清空：本文件只测平台维度，避免本机装没装 jadx/adb 影响结果。
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())

    report = pipeline.run(FakeContext(platform=platform), AnalysisConfig(online=False))
    return {s["name"]: s for s in report.analyzer_status}


# ---------------------------------------------------------------------------
# 两个方向的跨平台跳过（本任务的核心断言）
# ---------------------------------------------------------------------------


def test_web_only_analyzer_is_skipped_on_android(monkeypatch: pytest.MonkeyPatch) -> None:
    """★web 专属分析器在 android 上下文里必须 skip，且理由点名缺的是 "web"。"""
    status = _run(monkeypatch, "android")
    assert status["web_only"]["status"] == "skipped"
    assert "web" in status["web_only"]["reason"]
    assert status["android_only"]["status"] == "ran"


def test_android_only_analyzer_is_skipped_on_web(monkeypatch: pytest.MonkeyPatch) -> None:
    """★android 专属（含既有全部 requires=["apk"]）在 web 上下文里必须 skip。

    这条正是改动的目的：``"apk"`` 从无条件注入改为挂在 android 平台下，既有 30 个
    ``requires=["apk"]`` 声明**一个都不用改**就自动获得正确的跨平台行为。
    """
    status = _run(monkeypatch, "web")
    assert status["android_only"]["status"] == "skipped"
    assert "apk" in status["android_only"]["reason"]
    assert status["web_only"]["status"] == "ran"


def test_platform_agnostic_analyzer_runs_on_both(monkeypatch: pytest.MonkeyPatch) -> None:
    """无 requires 的分析器不受平台门控影响（否则门控就成了全局熔断）。"""
    for platform in ("android", "web"):
        assert _run(monkeypatch, platform)["agnostic"]["status"] == "ran"


def test_skipped_cross_platform_analyzer_is_visible_in_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """跳过必须在报告里看得见：``skipped_analyzers`` 有名字、completeness 不把它算进分母。"""
    monkeypatch.setattr(
        pipeline, "discover_analyzers", lambda: [_AndroidOnly(), _WebOnly()]
    )
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())

    report = pipeline.run(FakeContext(platform="web"), AnalysisConfig(online=False))
    assert "android_only" in report.skipped_analyzers
    # 唯一 eligible 的 web_only 跑成功 → 完整（跳过的不进分母）。
    assert report.completeness == 1.0
    assert report.meta["platform"] == "web"


# ---------------------------------------------------------------------------
# platform_capabilities 本身
# ---------------------------------------------------------------------------


def test_android_platform_grants_apk_capability() -> None:
    assert platform_capabilities("android") == {"android", "apk"}


def test_web_platform_does_not_grant_apk_capability() -> None:
    caps = platform_capabilities("web")
    assert caps == {"web"}
    assert "apk" not in caps, "web 上下文拿到 apk 能力 → 扫 dex 的分析器会空跑"


def test_platform_name_is_normalized() -> None:
    """CLI / 手编 report 传进来的平台名大小写与空白不该导致能力全空。"""
    assert platform_capabilities("  Android  ") == {"android", "apk"}


def test_unknown_platform_grants_nothing_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    """未知平台不猜：返回空集 + 告警。平台专属分析器全 skip，但报告里逐个可见。"""
    with caplog.at_level(logging.WARNING):
        assert platform_capabilities("symbian") == set()
    assert any("未知平台" in r.message for r in caplog.records)


def test_blank_platform_is_treated_as_android() -> None:
    """★空/空白平台名按 android 处理，**不是**"未知平台"。

    改动前 ``capabilities.add("apk")`` 无条件执行，所以 platform 为空的上下文照样跑全部
    android 分析器。若这里返回空集，这次改动就会把既有 30 个 ``requires=["apk"]`` 分析器
    在**真实 APK** 上静默关掉——典型的"加门控顺手把主路径锁死"。
    """
    assert platform_capabilities("") == {"android", "apk"}
    assert platform_capabilities("   ") == {"android", "apk"}


def test_missing_platform_attribute_defaults_to_android(monkeypatch: pytest.MonkeyPatch) -> None:
    """★旧的/程序化构造的 ctx 可能压根没有 platform 属性，必须仍按 android 走。

    pipeline 侧读法是 ``getattr(ctx, "platform", "android")``（对标 ``dex_available`` 的既有
    做法）。这里用一个**不带该属性**的最小上下文替身直接验那条默认分支，而不是去删
    FakeContext 的类属性（改类会污染同进程内其它测试）。
    """
    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [_AndroidOnly()])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())

    ctx = FakeContext()
    monkeypatch.delattr(ctx, "platform", raising=True)  # 实例属性删掉 → getattr 命中默认值
    assert not hasattr(ctx, "platform"), "夹具没能造出缺 platform 的上下文，本测试失去意义"

    report = pipeline.run(ctx, AnalysisConfig(online=False))
    status = {s["name"]: s for s in report.analyzer_status}
    assert status["android_only"]["status"] == "ran"


# ---------------------------------------------------------------------------
# 与既有 requires 拼写校验的关系（不能因为加了平台名就放宽校验）
# ---------------------------------------------------------------------------


def test_platform_capability_names_are_known_to_requires_validation() -> None:
    """平台能力名必须在 _KNOWN_CAPABILITIES 里，否则 requires=["web"] 会被误报成拼写错。"""
    for caps in _PLATFORM_CAPABILITIES.values():
        assert caps <= _KNOWN_CAPABILITIES


def test_requires_typo_still_flagged_after_adding_platform_caps(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """★拼写校验不许被放宽：把 "web" 拼成 "wbe" 仍必须点名。

    未知能力名会让分析器**永久静默 skip** 且伪装成"环境缺工具"，是最难查的一类 bug。
    """

    class _TypoWeb(BaseAnalyzer):
        name = "typo_web"
        requires = ["wbe"]

        def analyze(self, ctx: object) -> AnalyzerResult:  # noqa: ARG002
            return AnalyzerResult(analyzer=self.name)

    with caplog.at_level(logging.ERROR):
        kept = _dedup_and_validate([_TypoWeb()], kind="分析器")
    assert len(kept) == 1  # 只告警不删
    assert any("未知能力名" in r.message and "wbe" in r.message for r in caplog.records)


def test_declared_platform_capabilities_accepted_by_validation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.ERROR):
        kept = _dedup_and_validate([_AndroidOnly(), _WebOnly()], kind="分析器")
    assert len(kept) == 2
    assert not any("未知能力名" in r.message for r in caplog.records)


def test_real_analyzers_declare_only_known_capabilities(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """全量真实分析器过一遍校验：改了能力词表后不许有任何一个变成"未知能力"。"""
    from apkscan.core.registry import discover_analyzers

    with caplog.at_level(logging.ERROR):
        analyzers = discover_analyzers()
    assert analyzers
    assert not any("未知能力名" in r.message for r in caplog.records)
