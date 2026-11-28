"""Deterministic offline regressions for parser worker IPC and decode accounting."""

from __future__ import annotations

import base64
import contextvars
import json
from typing import Any

import pytest

from fxapk.core import apk as apk_mod, parallel, parser_worker
from fxapk.core.models import AnalysisConfig, AnalyzerResult, ComponentSet
from fxapk.core.parser_limits import ParserLimits
from fxapk.core.snapshot import SnapshotContext, build_snapshot


def _limits() -> ParserLimits:
    return ParserLimits(timeout_sec=90, memory_bytes=2 * 1024**3)


class _BudgetReader:
    def __init__(
        self,
        files: dict[str, bytes],
        overhead: dict[str, int] | None = None,
    ) -> None:
        self.files = dict(files)
        self.overhead = dict(overhead or {})
        self.calls: list[str] = []

    def get_file(self, path: str) -> bytes:
        self.calls.append(path)
        data = self.files[path]
        # 与真实解码器一致：classes*.dex 走独立的 DEX 聚合计数器，不计入
        # 非 DEX 的 _other_extract_total_bytes 预算（见 apk._charge_other_total）。
        if apk_mod._is_dex_entry_name(path):
            return data
        prior = apk_mod._other_extract_total_bytes.get()
        if prior is not None:
            total = prior + len(data) + self.overhead.get(path, 0)
            if total > apk_mod._OTHER_TOTAL_LIMIT_BYTES:
                apk_mod._other_extract_total_bytes.set(apk_mod._OTHER_TOTAL_LIMIT_BYTES + 1)
                raise apk_mod.ZipEntryTooLargeError(
                    path,
                    apk_mod._OTHER_TOTAL_LIMIT_BYTES,
                    resource_budget=True,
                )
            apk_mod._other_extract_total_bytes.set(total)
        return data

    def get_files(self) -> list[str]:
        return list(self.files)


class _BudgetAnalyzer:
    def __init__(self, name: str, paths: list[str]) -> None:
        self.name = name
        self.paths = list(paths)

    def analyze(self, ctx: Any) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer=self.name,
            meta={"readable": [ctx.read_file(path) is not None for path in self.paths]},
        )


def _budget_bytes(rows: list[Any]) -> bytes:
    return json.dumps(
        [(name, result.meta, result.input_gaps, error) for name, result, error in rows],
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _make_apk_context(
    monkeypatch: pytest.MonkeyPatch,
    files: dict[str, bytes],
    overhead: dict[str, int] | None = None,
) -> apk_mod.ApkContext:
    reader: Any = _BudgetReader(files, overhead)
    ctx = apk_mod.ApkContext(
        reader,
        [],
        AnalysisConfig(online=False),
        apk_path="synthetic.apk",
        sample_sha256="a" * 64,
        parser_execution={"status": "completed_under_limits"},
    )
    ctx.__dict__.update(
        _pkg_decision=("com.test.synthetic", None),
        manifest_xml="",
        parser_limits=_limits().to_dict(),
        declared_sizes={path: len(data) for path, data in files.items()},
        hiddenapi_relaxation={},
    )
    monkeypatch.setattr(ctx, "permissions", lambda: [])
    monkeypatch.setattr(ctx, "components", ComponentSet)
    monkeypatch.setattr(ctx, "certificates", lambda: [])
    return ctx


def _make_snapshot(
    files: dict[str, bytes],
    *,
    cached: dict[str, bytes] | None = None,
    overhead: dict[str, int] | None = None,
    isolated: bool = False,
    declared_sizes: dict[str, int] | None = None,
) -> SnapshotContext:
    sizes = (
        dict(declared_sizes)
        if declared_sizes is not None
        else {path: len(data) for path, data in files.items()}
    )
    return SnapshotContext(
        package_name="com.test.synthetic",
        manifest_xml="",
        platform="android",
        config=AnalysisConfig(online=False),
        apk_path="synthetic.apk",
        extra_dex_paths=[],
        jadx_cache_root=None,
        jadx_baseline_index=None,
        permissions=[],
        components=ComponentSet(),
        dex_strings=(),
        file_list=list(files),
        native_libs=[],
        certificates=[],
        files=dict(cached or {}),
        sample_sha256="a" * 64,
        parser_limits=_limits().to_dict() if isolated else None,
        parser_execution={"status": "completed_under_limits"},
        declared_sizes=sizes,
        hiddenapi_relaxation={},
        prefetch_decode_overhead=dict(overhead or {}),
    )


def _install_isolated_worker_loopback(
    monkeypatch: pytest.MonkeyPatch,
    reader: _BudgetReader,
    *,
    digest: str = "a" * 64,
) -> list[dict[str, Any]]:
    requests_seen: list[dict[str, Any]] = []
    monkeypatch.setattr("fxapk.core.integrity.sha256_file", lambda _path: digest)
    monkeypatch.setattr(SnapshotContext, "_ensure_worker_apk", lambda _self: reader)

    def run_in_fresh_context(
        request: dict[str, Any],
        _limits_arg: ParserLimits,
    ) -> dict[str, Any]:
        requests_seen.append(dict(request))
        response = contextvars.Context().run(parser_worker._handle_request, dict(request))
        response["_run_receipt"] = {
            "ownership_complete": True,
            "termination_complete": True,
            "forced_tree_kill": False,
            "memory_limit_enforced": True,
        }
        return response

    monkeypatch.setattr(parser_worker, "_run_operation", run_in_fresh_context)
    return requests_seen


def test_prefetch_decode_overhead_round_trips_and_matches_direct_accounting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(apk_mod, "_OTHER_TOTAL_LIMIT_BYTES", 5)
    files = {"prefix.txt": b"ab", "body.bin": b"cd"}
    overhead = {"prefix.txt": 2}
    ctx = _make_apk_context(monkeypatch, files, overhead)
    snapshot = build_snapshot(ctx)
    assert snapshot._files == {"prefix.txt": b"ab"}
    assert snapshot._prefetch_decode_overhead == {"prefix.txt": 2}

    raw_payload = parser_worker._loads(
        json.dumps(parser_worker.snapshot_to_dict(snapshot))
    )
    assert raw_payload["prefetch_decode_overhead"] == {"prefix.txt": 2}
    restored = parser_worker.snapshot_from_dict(raw_payload)
    assert restored._prefetch_decode_overhead == {"prefix.txt": 2}

    with apk_mod._analyzer_file_read_scope():
        budget = apk_mod._ANALYZER_RESOURCE_BUDGET.get()
        assert budget is not None
        assert restored.read_file("prefix.txt") == b"ab"
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (2, 4, False)
        assert restored.read_file("prefix.txt") is None
        assert restored.file_read_ledger.failure_for("prefix.txt") == "decompression_budget"
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (2, 5, True)

    with apk_mod._analyzer_file_read_scope():
        budget = apk_mod._ANALYZER_RESOURCE_BUDGET.get()
        assert budget is not None
        assert restored.read_file("prefix.txt") == b"ab"
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (2, 4, False)

    _install_isolated_worker_loopback(monkeypatch, _BudgetReader(files, overhead))
    tasks = [
        ("twice", _BudgetAnalyzer("twice", ["prefix.txt", "prefix.txt"])),
        ("pair", _BudgetAnalyzer("pair", ["prefix.txt", "body.bin"])),
        ("once", _BudgetAnalyzer("once", ["prefix.txt"])),
    ]
    serial_ctx = _make_apk_context(monkeypatch, files, overhead)
    fresh_snapshot = build_snapshot(_make_apk_context(monkeypatch, files, overhead))
    fresh_restored = parser_worker.snapshot_from_dict(
        parser_worker._loads(json.dumps(parser_worker.snapshot_to_dict(fresh_snapshot)))
    )
    serial_rows = parallel._analyze_serial(serial_ctx, tasks)
    snapshot_rows = parallel._analyze_serial(fresh_snapshot, tasks)
    restored_rows = parallel._analyze_serial(fresh_restored, tasks)

    assert [row[1].meta["readable"] for row in restored_rows] == [
        [True, False],
        [True, False],
        [True],
    ]
    assert _budget_bytes(serial_rows) == _budget_bytes(snapshot_rows)
    assert _budget_bytes(serial_rows) == _budget_bytes(restored_rows)


def test_old_snapshot_payload_without_prefetch_overhead_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(apk_mod, "_OTHER_TOTAL_LIMIT_BYTES", 5)
    files = {"prefix.txt": b"ab"}
    snapshot = _make_snapshot(
        files,
        cached={"prefix.txt": b"ab"},
        overhead={"prefix.txt": 2},
        isolated=True,
    )
    payload = parser_worker._loads(json.dumps(parser_worker.snapshot_to_dict(snapshot)))
    payload.pop("prefetch_decode_overhead")

    legacy_restored = parser_worker.snapshot_from_dict(payload)
    assert legacy_restored._prefetch_decode_overhead == {}

    with apk_mod._analyzer_file_read_scope():
        budget = apk_mod._ANALYZER_RESOURCE_BUDGET.get()
        assert budget is not None
        assert legacy_restored.read_file("prefix.txt") == b"ab"
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (2, 2, False)
        assert legacy_restored.read_file("prefix.txt") == b"ab"
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (4, 4, False)
        assert legacy_restored.read_file("prefix.txt") is None
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (4, 5, True)


@pytest.mark.parametrize(
    "bad_overhead",
    [
        {"unknown.txt": 1},
        {"prefix.txt": -1},
        {"prefix.txt": True},
        {"prefix.txt": False},
        {"prefix.txt": 1.5},
        {"prefix.txt": "2"},
        {"prefix.txt": None},
        [],
        "invalid",
        1,
    ],
)
def test_snapshot_from_dict_strictly_validates_prefetch_decode_overhead(
    bad_overhead: Any,
) -> None:
    snapshot = _make_snapshot(
        {"prefix.txt": b"ab"},
        cached={"prefix.txt": b"ab"},
        overhead={"prefix.txt": 2},
        isolated=True,
    )
    payload = parser_worker.snapshot_to_dict(snapshot)
    payload["prefetch_decode_overhead"] = bad_overhead

    with pytest.raises(ValueError, match="parser_invalid_response:prefetch_decode_overhead"):
        parser_worker.snapshot_from_dict(payload)


def test_run_parser_read_old_payload_compatibility_and_strict_decode_bytes_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(apk_mod, "_OTHER_TOTAL_LIMIT_BYTES", 5)
    limits = _limits()
    files = {"body.bin": b"ab"}

    legacy_ok_response: dict[str, Any] = {
        "version": parser_worker.IPC_VERSION,
        "kind": "read_file",
        "data": base64.b64encode(b"ab").decode("ascii"),
        "failure_reason": None,
        "parser_limits": limits.to_dict(),
    }
    monkeypatch.setattr(
        parser_worker,
        "_run_operation",
        lambda *_a, **_kw: dict(legacy_ok_response),
    )
    isolated = _make_snapshot(files, isolated=True)
    with apk_mod._analyzer_file_read_scope():
        budget = apk_mod._ANALYZER_RESOURCE_BUDGET.get()
        assert budget is not None
        assert isolated.read_file("body.bin") == b"ab"
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (2, 2, False)
        assert isolated.read_file("body.bin") == b"ab"
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (4, 4, False)

    legacy_denied_response: dict[str, Any] = {
        "version": parser_worker.IPC_VERSION,
        "kind": "read_file",
        "data": None,
        "failure_reason": "decompression_budget",
        "parser_limits": limits.to_dict(),
    }
    monkeypatch.setattr(
        parser_worker,
        "_run_operation",
        lambda *_a, **_kw: dict(legacy_denied_response),
    )
    isolated_denied = _make_snapshot(files, isolated=True)
    with apk_mod._analyzer_file_read_scope():
        budget = apk_mod._ANALYZER_RESOURCE_BUDGET.get()
        assert budget is not None
        assert isolated_denied.read_file("body.bin") is None
        assert isolated_denied.file_read_ledger.failure_for("body.bin") == "decompression_budget"
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (0, 5, True)

    for bad_decode_bytes in (-1, True, False, 1.5, "2", None, [], {}):
        bad_response = dict(legacy_ok_response)
        bad_response["decode_bytes"] = bad_decode_bytes
        monkeypatch.setattr(
            parser_worker,
            "_run_operation",
            lambda *_a, _resp=bad_response, **_kw: dict(_resp),
        )
        candidate = _make_snapshot(files, isolated=True)
        with apk_mod._analyzer_file_read_scope():
            budget = apk_mod._ANALYZER_RESOURCE_BUDGET.get()
            assert budget is not None
            assert candidate.read_file("body.bin") is None
            assert (
                candidate.file_read_ledger.failure_for("body.bin")
                == "parser_invalid_response"
            )
            assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (0, 0, False)

    extra_field_response = dict(legacy_ok_response)
    extra_field_response["decode_bytes"] = 2
    extra_field_response["unexpected"] = 1
    monkeypatch.setattr(
        parser_worker,
        "_run_operation",
        lambda *_a, **_kw: dict(extra_field_response),
    )
    extra_candidate = _make_snapshot(files, isolated=True)
    with apk_mod._analyzer_file_read_scope():
        budget = apk_mod._ANALYZER_RESOURCE_BUDGET.get()
        assert budget is not None
        assert extra_candidate.read_file("body.bin") is None
        assert (
            extra_candidate.file_read_ledger.failure_for("body.bin")
            == "parser_invalid_response"
        )
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (0, 0, False)


def test_isolated_lazy_read_matches_direct_caller_logical_and_decode_accounting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(apk_mod, "_OTHER_TOTAL_LIMIT_BYTES", 5)
    files = {
        "prefix.bin": b"ab",
        "body.bin": b"cd",
        "tail.bin": b"e",
        "classes.dex": b"dexdata",
    }
    overhead = {"prefix.bin": 2, "tail.bin": 2}
    _install_isolated_worker_loopback(monkeypatch, _BudgetReader(files, overhead))

    direct_ctx = _make_apk_context(monkeypatch, files, overhead)
    legacy_ctx = _make_snapshot(files, isolated=False)
    isolated_ctx = _make_snapshot(files, isolated=True)

    for ctx in (direct_ctx, legacy_ctx, isolated_ctx):
        with apk_mod._analyzer_file_read_scope():
            budget = apk_mod._ANALYZER_RESOURCE_BUDGET.get()
            assert budget is not None
            assert ctx.read_file("prefix.bin") == b"ab"
            assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (2, 4, False)
            assert ctx.read_file("classes.dex") == b"dexdata"
            assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (2, 4, False)
            assert ctx.read_file("tail.bin") is None
            assert ctx.file_read_ledger.failure_for("tail.bin") == "decompression_budget"
            assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (2, 5, True)

    tasks = [
        ("repeat_ok", _BudgetAnalyzer("repeat_ok", ["body.bin", "body.bin"])),
        (
            "repeat_cap",
            _BudgetAnalyzer("repeat_cap", ["body.bin", "body.bin", "body.bin"]),
        ),
        ("overhead_cap", _BudgetAnalyzer("overhead_cap", ["prefix.bin", "body.bin"])),
        ("overhead_only_cap", _BudgetAnalyzer("overhead_only_cap", ["prefix.bin", "tail.bin"])),
        ("after_cap", _BudgetAnalyzer("after_cap", ["prefix.bin"])),
    ]
    serial_rows = parallel._analyze_serial(_make_apk_context(monkeypatch, files, overhead), tasks)
    legacy_rows = parallel._analyze_serial(_make_snapshot(files, isolated=False), tasks)
    isolated_rows = parallel._analyze_serial(_make_snapshot(files, isolated=True), tasks)

    assert [row[1].meta["readable"] for row in isolated_rows] == [
        [True, True],
        [True, True, False],
        [True, False],
        [True, False],
        [True],
    ]
    assert _budget_bytes(serial_rows) == _budget_bytes(legacy_rows)
    assert _budget_bytes(serial_rows) == _budget_bytes(isolated_rows)


def test_child_decompression_budget_denial_exhausts_caller_and_skips_next_child_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(apk_mod, "_OTHER_TOTAL_LIMIT_BYTES", 5)
    files = {
        "oversize.bin": b"abcdef",
        "small.bin": b"ab",
        "declared_big.bin": b"ab",
        "classes.dex": b"dexdata",
    }
    reader = _BudgetReader(files)
    requests_seen = _install_isolated_worker_loopback(monkeypatch, reader)
    declared_sizes = {
        "oversize.bin": 6,
        "small.bin": 2,
        "declared_big.bin": apk_mod._MAX_DECOMPRESSED_FILE_BYTES + 1,
        "classes.dex": 7,
    }
    isolated = _make_snapshot(files, isolated=True, declared_sizes=declared_sizes)

    with apk_mod._analyzer_file_read_scope():
        budget = apk_mod._ANALYZER_RESOURCE_BUDGET.get()
        assert budget is not None
        assert isolated.read_file("declared_big.bin") is None
        assert isolated.file_read_ledger.failure_for("declared_big.bin") == "declared_limit"
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (0, 0, False)
        assert len(requests_seen) == 1

        assert isolated.read_file("oversize.bin") is None
        assert isolated.file_read_ledger.failure_for("oversize.bin") == "decompression_budget"
        assert (budget.logical_bytes, budget.decode_bytes, budget.exhausted) == (0, 5, True)
        assert len(requests_seen) == 2

        assert isolated.read_file("small.bin") is None
        assert isolated.file_read_ledger.failure_for("small.bin") == "decompression_budget"
        assert len(requests_seen) == 2

        assert isolated.read_file("classes.dex") == b"dexdata"
        assert len(requests_seen) == 3

    standalone = _make_snapshot(files, isolated=True, declared_sizes=declared_sizes)
    assert standalone.read_file("small.bin") == b"ab"
    assert len(requests_seen) == 4
