"""meta 注册表构建与运行期快照对账。"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from apkscan.core import meta_contract, pipeline, registry
from apkscan.core.models import AnalysisConfig


def test_pipeline_reserved_key_conflict_fails_registry_build(monkeypatch) -> None:
    """分析器不得声明 pipeline 派生键，冲突必须在构建注册表时失败。"""
    analyzer = SimpleNamespace(
        name="conflicting_analyzer",
        meta_keys=frozenset({"dex_strings_truncated_by"}),
    )
    monkeypatch.setattr(registry, "discover_analyzers", lambda: [analyzer])

    with pytest.raises(RuntimeError, match="pipeline 保留 meta 键"):
        meta_contract._build_registry()


@pytest.mark.parametrize(
    "bad_key",
    [pytest.param("", id="空串"), pytest.param(None, id="None"), pytest.param(1, id="非字符串")],
)
def test_malformed_declaration_fails_registry_build(monkeypatch, bad_key) -> None:  # type: ignore[no-untyped-def]
    """``meta_keys`` 里的非法键必须在构建时炸掉。

    ★这道防线原本没有任何测试：删掉 ``_build_registry`` 里那两行校验，全套测试照绿。
      空串键会让 ``allowed_meta_keys`` 平白多出一个 ``""``，非字符串键则会在
      后续与 ``result.meta.keys()`` 求差集时静默参与比较——两者都不会有人发现。
    """
    analyzer = SimpleNamespace(name="malformed_analyzer", meta_keys=frozenset({bad_key}))
    monkeypatch.setattr(registry, "discover_analyzers", lambda: [analyzer])

    with pytest.raises(RuntimeError, match="含非法键"):
        meta_contract._build_registry()


def test_runtime_discovery_reports_missing_registry_owners_without_raising() -> None:
    """单模块 import 失败是发现器的降级形态，必须可见但不得打死 stage。"""
    registered = {
        owner
        for contract in meta_contract.META_KEY_REGISTRY.values()
        for owner in contract.owners
        if owner != meta_contract.PIPELINE_OWNER
    }
    assert meta_contract.validate_registry_owners(registered) == frozenset()
    # 新发现名字本身不会清空 stage；它真写未注册 meta 时由聚合门标红。
    assert meta_contract.validate_registry_owners(registered | {"late_analyzer"}) == frozenset()
    missing = next(iter(registered))
    assert meta_contract.validate_registry_owners(registered - {missing}) == {missing}


def test_analyzer_stage_reconciles_runtime_discovery(monkeypatch) -> None:
    """对账必须接在每次运行的发现结果上，不能只留下一个无人调用的 helper。"""
    seen: list[set[str]] = []
    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [])
    def reconcile(names: set[str]) -> frozenset[str]:
        seen.append(names)
        return frozenset()
    monkeypatch.setattr(pipeline, "validate_registry_owners", reconcile)
    state = pipeline._PipelineState(
        ctx=SimpleNamespace(),
        config=AnalysisConfig(online=False),
        platform="android",
        capabilities=set(),
    )

    pipeline._stage_run_analyzers(state)

    assert seen == [set()]


def test_pipeline_true_entry_records_missing_analyzers_without_failing(monkeypatch) -> None:
    """对账守卫必须在 pipeline.run 真入口留痕，且不把 analyze 归零。"""
    from tests.conftest import FakeContext

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [])
    report = pipeline.run(FakeContext(), AnalysisConfig(online=False))

    expected = sorted({
        owner
        for contract in meta_contract.META_KEY_REGISTRY.values()
        for owner in contract.owners
        if owner != meta_contract.PIPELINE_OWNER
    })
    assert report.meta[meta_contract.MISSING_ANALYZERS_KEY] == expected
    assert report.analysis_status != "failed"


def test_pipeline_true_entry_rejects_unregistered_meta(monkeypatch) -> None:
    """未注册写入必须经 pipeline.run 真入口标红，不能只测 helper。"""
    from apkscan.core.models import AnalyzerResult
    from apkscan.core.registry import BaseAnalyzer
    from tests.conftest import FakeContext

    class LateAnalyzer(BaseAnalyzer):
        name = "late_analyzer"

        def analyze(self, ctx):  # noqa: ANN001
            return AnalyzerResult(analyzer=self.name, meta={"late_key": "value"})

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [LateAnalyzer()])
    report = pipeline.run(FakeContext(), AnalysisConfig(online=False))

    assert "late_key" not in report.meta
    assert report.analyzer_status == [{
        "name": "late_analyzer",
        "status": "error",
        "reason": "meta 契约违规：未登记键 ['late_key']",
    }]
