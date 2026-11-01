from __future__ import annotations

from apkscan.core import parallel, pipeline
from apkscan.core.apk import ApkContext
from apkscan.core.file_read import FileReadLedger
from apkscan.core.models import AnalysisConfig, AnalyzerResult
from apkscan.core.snapshot import SnapshotContext
from apkscan.core.visibility import (
    VIS_PARTIAL,
    _native_visibility,
    _resource_visibility,
    assess,
)


def test_cached_declared_limit_read_repeats_original_safe_gap(monkeypatch) -> None:
    class APK:
        calls = 0

        def get_file(self, _path: str) -> bytes:
            self.calls += 1
            raise AssertionError("declared-size denial must happen before reading")

    apk = APK()
    ctx = ApkContext(apk, [], AnalysisConfig(online=False))
    ctx._declared_sizes = {"assets/large.json": 5}
    monkeypatch.setattr("apkscan.core.apk._MAX_DECOMPRESSED_FILE_BYTES", 4)

    ctx.file_read_ledger.begin_scope()
    assert ctx.read_file("assets/large.json") is None
    first = ctx.file_read_ledger.end_scope("first")
    ctx.file_read_ledger.begin_scope()
    assert ctx.read_file("assets/large.json") is None
    second = ctx.file_read_ledger.end_scope("second")

    assert first == [{"path": "assets/large.json", "source": "first", "reason": "declared_limit"}]
    assert second == [{"path": "assets/large.json", "source": "second", "reason": "declared_limit"}]
    assert apk.calls == 0


def _failing_snapshot() -> SnapshotContext:
    path = "assets/failure.txt"

    class APK:
        def get_file(self, _path: str) -> bytes:
            raise OSError("private read failure detail")

    snapshot = SnapshotContext(
        package_name="com.test",
        manifest_xml="",
        platform="android",
        config=None,
        apk_path="synthetic.apk",
        extra_dex_paths=[],
        jadx_cache_root=None,
        jadx_baseline_index=None,
        permissions=[],
        components=None,
        dex_strings=(),
        file_list=[path],
        native_libs=[],
        certificates=[],
        files={},
        read_failures={path: "read_failure"},
    )
    snapshot._ensure_declared_sizes = lambda: {}
    snapshot._ensure_worker_apk = lambda: APK()
    return snapshot


def test_worker_lazy_read_failure_is_safe_and_matches_serial_scope(monkeypatch) -> None:
    path = "assets/failure.txt"

    class Analyzer:
        name = "coverage_probe"

        def analyze(self, ctx) -> AnalyzerResult:
            ctx.read_file(path)
            raise OSError("private read failure detail")

    analyzer = Analyzer()
    serial_ctx = _failing_snapshot()
    worker_ctx = _failing_snapshot()
    serial_row = parallel._analyze_serial(serial_ctx, [(analyzer.name, analyzer)])[0]
    monkeypatch.setitem(parallel._WORKER_STATE, "snapshot", worker_ctx)
    monkeypatch.setitem(parallel._WORKER_STATE, "analyzers", {analyzer.name: analyzer})
    worker_row = parallel._worker_analyze(analyzer.name)

    for row in (serial_row, worker_row):
        name, result, error = row
        assert name == analyzer.name
        assert isinstance(result, AnalyzerResult)
        assert result.input_gaps == [{
            "path": path, "source": analyzer.name, "reason": "read_failure"
        }]
        assert result.endpoints == result.leads == result.findings == []
        assert error == "OSError"
        assert "private read failure detail" not in str(result)
        assert "private read failure detail" not in error
    assert serial_row[1].input_gaps == worker_row[1].input_gaps
    assert worker_ctx.file_read_ledger.failure_reasons[path] == "read_failure"


def test_pipeline_folds_failed_analyzer_gaps_and_visibility_marks_partial(monkeypatch) -> None:
    gaps = [
        {"path": "res/config.json", "source": "resource_probe", "reason": "read_failure"},
        {"path": "lib/arm64/libsample.so", "source": "native_probe", "reason": "actual_decompression_limit"},
    ]

    class Analyzer:
        name = "coverage_probe"
        requires: list[str] = []

    analyzer = Analyzer()
    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [analyzer])
    monkeypatch.setattr(pipeline, "validate_registry_owners", lambda _names: frozenset())
    monkeypatch.setattr(
        pipeline,
        "_analyze_eligible",
        lambda _ctx, _eligible: (
            [("coverage_probe", AnalyzerResult("coverage_probe", input_gaps=gaps), "OSError")],
            {"coverage_probe": {"lane": "short", "execution": "analyzer_error"}},
        ),
    )
    state = pipeline._PipelineState(
        ctx=object(),
        config=AnalysisConfig(online=False),
        platform="android",
        capabilities=set(),
    )

    pipeline._stage_run_analyzers(state)

    assert state.meta["file_read_visibility"] == sorted(
        gaps, key=lambda item: (item["path"], item["source"], item["reason"])
    )
    visibility = assess({"meta": state.meta})
    assert visibility["sources"]["native"]["visibility"] == VIS_PARTIAL
    assert visibility["sources"]["resource"]["visibility"] == VIS_PARTIAL
    assert "file_read_visibility" in visibility["sources"]["native"]["inputs_seen"]
    assert "file_read_visibility" in visibility["sources"]["resource"]["inputs_seen"]


def test_ledger_scope_does_not_attribute_prior_analyzer_failure() -> None:
    ledger = FileReadLedger()
    ledger.begin_scope()
    ledger.request("res/a.json")
    ledger.record_failure("res/a.json", "read_failure")
    first = ledger.end_scope("first")

    ledger.begin_scope()
    ledger.request("res/b.json")
    second = ledger.end_scope("second")

    assert first == [{"path": "res/a.json", "source": "first", "reason": "read_failure"}]
    assert second == []


def test_visibility_reason_counts_distinct_failed_paths_not_ledger_rows() -> None:
    meta = {
        "file_read_visibility": [
            {"path": "lib/arm64/liba.so", "source": "native_a", "reason": "read_failure"},
            {"path": "lib/arm64/liba.so", "source": "native_b", "reason": "read_failure"},
            {"path": "lib/arm64/libb.so", "source": "native_a", "reason": "read_failure"},
            {"path": "assets/a.xml", "source": "resource_a", "reason": "read_failure"},
            {"path": "assets/a.xml", "source": "resource_b", "reason": "read_failure"},
            {"path": "assets/b.xml", "source": "resource_a", "reason": "read_failure"},
        ],
        "native_obfuscation": [],
    }

    native_state, native_why = _native_visibility(meta)
    resource_state, resource_why = _resource_visibility(meta)

    assert native_state == resource_state == VIS_PARTIAL
    assert native_why == ["2 个 native 文件读取失败（.so 内容未进入本次分析）"]
    assert resource_why == ["2 个资源文件读取失败，内容未进入本次分析"]
