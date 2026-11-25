from __future__ import annotations

import pickle

import pytest

from fxapk.core import apk, parallel, pipeline
from fxapk.core.apk import ApkContext
from fxapk.core.file_read import FileReadLedger
from fxapk.core.models import AnalysisConfig, AnalyzerResult
from fxapk.core.snapshot import SnapshotContext
from fxapk.core.visibility import (
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
    monkeypatch.setattr("fxapk.core.apk._MAX_DECOMPRESSED_FILE_BYTES", 4)

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


@pytest.mark.parametrize(("path", "visibility_source"), [
    ("assets/example.txt", "resource"),
    ("lib/arm64/libexample.so", "native"),
])
def test_snapshot_total_budget_retains_exact_partial_coverage_reason(
    monkeypatch: pytest.MonkeyPatch, path: str, visibility_source: str,
) -> None:
    opened: list[str] = []

    class APK:
        def get_file(self, member: str) -> bytes:
            opened.append(member)
            return b"ok"

    class Reader:
        name = "budget_probe"

        def analyze(self, ctx) -> AnalyzerResult:
            data = ctx.read_file(path)
            return AnalyzerResult(self.name, meta={"read": data is not None})

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
        declared_sizes={path: 2},
    )
    monkeypatch.setattr(SnapshotContext, "_ensure_worker_apk", lambda _self: APK())
    analyzer = Reader()
    eligible = [(analyzer.name, analyzer)]
    below = parallel._analyze_serial(snapshot, eligible)[0][1]
    assert below.meta["read"] is True
    assert below.input_gaps == []
    assert opened == [path]

    snapshot._lazy_other_extract_bytes = apk._OTHER_TOTAL_LIMIT_BYTES
    worker_context = pickle.loads(pickle.dumps(snapshot))
    serial = parallel._analyze_serial(snapshot, eligible)
    monkeypatch.setitem(parallel._WORKER_STATE, "snapshot", worker_context)
    monkeypatch.setitem(parallel._WORKER_STATE, "analyzers", dict(eligible))
    worker = parallel._worker_analyze(analyzer.name)
    assert serial == [worker]
    assert opened == [path]
    assert worker[1].meta["read"] is False
    meta: dict = {"resource_files_scanned": 1, "native_files_scanned": 1}
    pipeline._merge_file_read_gaps(meta, worker[1].input_gaps)
    assert meta["file_read_visibility"] == [{
        "path": path, "source": analyzer.name, "reason": "decompression_budget",
    }]
    assert assess({"meta": meta})["sources"][visibility_source]["visibility"] == VIS_PARTIAL


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


def test_merge_keeps_one_gap_and_only_allowlisted_worker_diagnostics() -> None:
    gap = {"path": "res/a.json", "source": "probe", "reason": "parser_worker_failed"}
    reports = [
        {**gap, "diagnostic": "worker_nonzero_exit"},
        {**gap, "diagnostic": "worker_tree_unverified"},
        {**gap, "diagnostic": "untrusted worker message"},
        {**gap, "path": "res/b.json", "diagnostic": ["not a valid type"]},
        {**gap, "path": "res/c.json", "reason": "parser_timeout", "diagnostic": "worker_nonzero_exit"},
    ]
    forward: dict = {}
    reverse: dict = {}
    for row in reports:
        pipeline._merge_file_read_gaps(forward, [row])
    for row in reversed(reports):
        pipeline._merge_file_read_gaps(reverse, [row])
    assert forward == reverse
    assert forward["file_read_visibility"] == [
        {**gap, "diagnostic": "multiple_worker_failures"},
        {**gap, "path": "res/b.json"},
        {**gap, "path": "res/c.json", "reason": "parser_timeout"},
    ]
