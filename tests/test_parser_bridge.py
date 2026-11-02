from __future__ import annotations

import hashlib
import io
import pickle
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from apkscan.core import apk as apk_module, parallel, parser_worker
from apkscan.core.models import (
    AnalysisConfig,
    AnalyzerResult,
    CertInfo,
    Component,
    ComponentSet,
)
from apkscan.core.observations import DexStringRecord
from apkscan.core.parser_limits import ParserLimits
from apkscan.core.proctree import OwnedRun, run_owned
from apkscan.core.snapshot import SnapshotContext


def _limits() -> ParserLimits:
    return ParserLimits(timeout_sec=90, memory_bytes=2 * 1024**3)


def _set_limits(monkeypatch: pytest.MonkeyPatch) -> ParserLimits:
    monkeypatch.setenv("FXAPK_PARSER_TIMEOUT_SEC", "90")
    monkeypatch.setenv("FXAPK_PARSER_MEMORY_MB", "2048")
    monkeypatch.delenv("FXAPK_PARSER_OUTPUT_MB", raising=False)
    return _limits()


def test_unconfigured_loader_is_explicitly_not_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "FXAPK_PARSER_TIMEOUT_SEC",
        "FXAPK_PARSER_MEMORY_MB",
        "FXAPK_PARSER_OUTPUT_MB",
    ):
        monkeypatch.delenv(name, raising=False)
    context = SimpleNamespace(parser_execution={})
    monkeypatch.setattr(apk_module, "_load_apk_inprocess", lambda *_a, **_kw: context)

    result = apk_module.load_apk("synthetic.apk", AnalysisConfig(online=False))

    assert result is context
    assert result.parser_execution["status"] == "not_enforced"
    assert result.parser_execution["parser_isolation"] == "not_enforced"


def test_invalid_public_loader_configuration_does_not_fall_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FXAPK_PARSER_TIMEOUT_SEC", "10")
    monkeypatch.delenv("FXAPK_PARSER_MEMORY_MB", raising=False)
    monkeypatch.setattr(
        apk_module,
        "_load_apk_inprocess",
        lambda *_a, **_kw: pytest.fail("invalid policy fell back to in-process parsing"),
    )

    with pytest.raises(apk_module.ApkParseError) as raised:
        apk_module.load_apk("synthetic.apk", AnalysisConfig(online=False))

    assert raised.value.parser_receipt["reason"] == "parser_configuration_invalid"


def test_ipc_parser_rejects_nonfinite_and_duplicate_json_fields() -> None:
    with pytest.raises(ValueError, match="non-finite"):
        parser_worker._loads('{"value":NaN}')
    with pytest.raises(ValueError, match="duplicate"):
        parser_worker._loads('{"value":1,"value":2}')


def test_worker_reports_memory_exhaustion_only_for_memoryerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CapturedStdout:
        buffer = io.BytesIO()

    monkeypatch.setattr(parser_worker, "_read_request", lambda _path: {})

    def raise_memory_error(_request):
        raise MemoryError

    monkeypatch.setattr(parser_worker, "_handle_request", raise_memory_error)
    monkeypatch.setattr(parser_worker.sys, "stdout", CapturedStdout())

    assert parser_worker.main(["request.json"]) == 0
    response = parser_worker._loads(CapturedStdout.buffer.getvalue())
    assert response["reason"] == "parser_memory_limit"


def _make_apk(path: Path, **members: bytes) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            b'<?xml version="1.0"?><manifest package="com.test.synthetic"/>',
        )
        for name, data in members.items():
            archive.writestr(name, data)


def _snapshot(
    path: Path,
    limits: ParserLimits,
    *,
    digest: str | None = None,
    declared_sizes: dict[str, int] | None = None,
) -> SnapshotContext:
    return SnapshotContext(
        package_name="com.test.synthetic",
        manifest_xml="",
        platform="android",
        config=AnalysisConfig(online=False),
        apk_path=str(path),
        extra_dex_paths=[],
        jadx_cache_root=None,
        jadx_baseline_index=None,
        permissions=[],
        components=ComponentSet(),
        dex_strings=(),
        file_list=[],
        native_libs=[],
        certificates=[],
        files={},
        sample_sha256=digest or hashlib.sha256(path.read_bytes()).hexdigest(),
        parser_limits=limits.to_dict(),
        parser_execution={"status": "completed_under_limits"},
        declared_sizes=declared_sizes if declared_sizes is not None else {},
        hiddenapi_relaxation={},
    )


def test_snapshot_json_roundtrip_preserves_occurrence_and_context_ledgers() -> None:
    limits = _limits()
    component = Component("com.test.Main", True, "activity")
    certificate = CertInfo("subject", "issuer", "a" * 64, "before", "after", True, ["v2"])
    record = DexStringRecord(
        "https://example.test/api",
        provenance={"sample_sha256": "b" * 64, "source_kind": "main"},
        locator={"member_path": "classes.dex", "string_index": 9},
    )
    snapshot = SnapshotContext(
        package_name="com.test.synthetic",
        manifest_xml="<manifest/>",
        platform="android",
        config=AnalysisConfig(online=False, formats=["json"]),
        apk_path="synthetic.apk",
        extra_dex_paths=["extra.dex"],
        jadx_cache_root=None,
        jadx_baseline_index=None,
        permissions=["android.permission.INTERNET"],
        components=ComponentSet(activities=[component]),
        dex_strings=(record.value,),
        records=(record,),
        file_list=["assets/config.json"],
        native_libs=["lib/arm64-v8a/libsample.so"],
        certificates=[certificate],
        files={"assets/config.json": b'{"ok":true}'},
        read_failures={"assets/missing.txt": "parser_timeout"},
        main_dex_report={"requested": 1, "loaded": 0, "failed": 1},
        extra_dex_report={"requested": 1, "loaded": 1, "failed": 0},
        dex_decode_report={"truncated": True},
        parser_limits=limits.to_dict(),
        parser_execution={"status": "completed_under_limits"},
        declared_sizes={},
        hiddenapi_relaxation={},
    )

    decoded = parser_worker.snapshot_from_dict(parser_worker.snapshot_to_dict(snapshot))

    assert list(decoded.dex_string_records()) == [record]
    assert decoded.components() == ComponentSet(activities=[component])
    assert decoded.certificates() == [certificate]
    assert decoded.read_file("assets/config.json") == b'{"ok":true}'
    assert decoded.file_read_ledger.failure_for("assets/missing.txt") == "parser_timeout"
    assert decoded.parser_limits == limits.to_dict()
    assert decoded.parser_execution == {"status": "completed_under_limits"}
    assert decoded.main_dex_report == {"requested": 1, "loaded": 0, "failed": 1}
    assert decoded.extra_dex_report == {"requested": 1, "loaded": 1, "failed": 0}
    assert decoded.dex_decode_report == {"truncated": True}
    assert decoded.declared_sizes == {}
    assert decoded.hiddenapi_relaxation == {}


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="macOS parser memory enforcement is fail-closed",
)
def test_configured_loader_uses_real_child_and_parses_local_synthetic_apk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_limits(monkeypatch)
    apk_path = tmp_path / "synthetic.apk"
    _make_apk(apk_path, **{"assets/settings.json": b'{"mode":"offline"}'})

    def forbid_in_process(*_args, **_kwargs):
        pytest.fail("configured parser must not use the parent loader")

    monkeypatch.setattr(apk_module, "_load_apk_inprocess", forbid_in_process)
    context = apk_module.load_apk(str(apk_path), AnalysisConfig(online=False))

    assert isinstance(context, SnapshotContext)
    assert context.parser_execution["status"] == "completed_under_limits"
    assert context.parser_execution["parser_isolation"] == "enforced"
    assert context.parser_execution["memory_limit_enforced"] is True
    assert context.parser_limits == _limits().to_dict()
    assert context.hiddenapi_relaxation == {"applied": False, "unknown_flags": []}
    assert context.declared_size("assets/settings.json") == len(b'{"mode":"offline"}')
    assert context.read_file("assets/settings.json") == b'{"mode":"offline"}'


@pytest.mark.parametrize(
    ("run", "expected"),
    [
        (
            OwnedRun(None, "", "", True, True, True, False, ("timeout",)),
            "parser_timeout",
        ),
        (
            OwnedRun(None, "", "", False, True, True, False, ("output_limit",)),
            "parser_output_limit",
        ),
        (
            OwnedRun(
                None, "", "", False, False, True, False, ("memory_limit_unavailable",)
            ),
            "parser_memory_limit_unavailable",
        ),
        (
            OwnedRun(
                -9, "", "", False, True, True, False, (), memory_limit_enforced=True
            ),
            "parser_worker_failed",
        ),
        (
            OwnedRun(
                0, "not-json", "", False, True, True, False, (),
                memory_limit_enforced=True,
            ),
            "parser_invalid_response",
        ),
    ],
)
def test_configured_loader_errors_never_fall_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    run: OwnedRun,
    expected: str,
) -> None:
    _set_limits(monkeypatch)
    apk_path = tmp_path / "synthetic.apk"
    _make_apk(apk_path)
    monkeypatch.setattr("apkscan.core.proctree.run_owned", lambda *_a, **_kw: run)
    monkeypatch.setattr(
        apk_module,
        "_load_apk_inprocess",
        lambda *_a, **_kw: pytest.fail("configured failure fell back in process"),
    )

    with pytest.raises(apk_module.ApkParseError) as raised:
        apk_module.load_apk(str(apk_path), AnalysisConfig(online=False))

    assert raised.value.parser_receipt is not None
    assert raised.value.parser_receipt["reason"] == expected
    if expected == "parser_memory_limit_unavailable":
        assert raised.value.parser_receipt["parser_isolation"] == "not_enforced"


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="macOS parser memory enforcement is fail-closed",
)
def test_isolated_late_read_uses_child_policy_and_rejects_changed_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    limits = _limits()
    apk_path = tmp_path / "binary.apk"
    contents = b"\x7fELFsynthetic"
    _make_apk(apk_path, **{"lib/arm64-v8a/libsample.so": contents})
    declared_size = len(contents)
    context = _snapshot(
        apk_path,
        limits,
        declared_sizes={"lib/arm64-v8a/libsample.so": declared_size},
    )
    worker_copy = pickle.loads(pickle.dumps(context))
    assert worker_copy.declared_size("lib/arm64-v8a/libsample.so") == declared_size
    monkeypatch.setattr(
        "apkscan.core.snapshot.zipfile.ZipFile",
        lambda *_a, **_kw: pytest.fail(
            "isolated declared-size lookup reopened the ZIP in parent"
        ),
    )
    monkeypatch.setattr(
        context,
        "_ensure_worker_apk",
        lambda: pytest.fail("isolated lazy read reopened Androguard in parent"),
    )

    assert context.declared_size("lib/arm64-v8a/libsample.so") == declared_size
    assert context.read_file("lib/arm64-v8a/libsample.so") == contents

    changed = _snapshot(apk_path, limits)
    old_digest = changed.sample_sha256
    apk_path.write_bytes(b"changed APK input")
    assert hashlib.sha256(apk_path.read_bytes()).hexdigest() != old_digest
    assert changed.read_file("lib/arm64-v8a/libsample.so") is None
    assert changed.file_read_ledger.failure_for("lib/arm64-v8a/libsample.so") == (
        "parser_input_changed"
    )


def test_child_hiddenapi_snapshot_keeps_empty_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.conftest import FakeContext

    apk_path = tmp_path / "hiddenapi.apk"
    apk_path.write_bytes(b"synthetic APK input")
    digest = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    context = FakeContext(apk_path=str(apk_path))
    context.sample_sha256 = digest
    context.hiddenapi_flags_baseline = 37
    context._declared_sizes = {}
    seen: list[int | None] = []
    monkeypatch.setattr(apk_module, "_load_apk_inprocess", lambda *_a, **_kw: context)
    monkeypatch.setattr(
        apk_module,
        "hiddenapi_relax_report",
        lambda since=None: seen.append(since) or {},
    )
    response = parser_worker._handle_request({
        "version": parser_worker.IPC_VERSION,
        "operation": "load",
        "path": str(apk_path),
        "config": {
            "online": False,
            "out_dir": "out",
            "formats": ["html", "json"],
            "mode": "passive",
            "enrich_max_targets": 32,
            "enrich_static_ip_max_targets": 16,
            "enrichment_dry_run": False,
            "web_supplement": None,
            "web_supplement_request": None,
            "flutter": "auto",
            "flutter_toolchain": None,
            "flutter_timeout": 300,
        },
        "extra_dex": [],
        "jadx_cache_root": None,
        "jadx_baseline_index": None,
        "parser_limits": _limits().to_dict(),
    })
    decoded = parser_worker.snapshot_from_dict(response["snapshot"])

    assert seen == [37]
    assert decoded.hiddenapi_relaxation == {}


def test_initial_parser_load_rejects_input_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.conftest import FakeContext

    apk_path = tmp_path / "mutating.apk"
    apk_path.write_bytes(b"original APK input")
    digest = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    context = FakeContext(apk_path=str(apk_path))
    context.sample_sha256 = digest
    context.hiddenapi_flags_baseline = 0
    context._declared_sizes = {}

    def mutate_during_load(*_args, **_kwargs):
        apk_path.write_bytes(b"changed APK input")
        return context

    monkeypatch.setattr(apk_module, "_load_apk_inprocess", mutate_during_load)
    monkeypatch.setattr(apk_module, "hiddenapi_relax_report", lambda *_a: {})
    response = parser_worker._handle_request({
        "version": parser_worker.IPC_VERSION,
        "operation": "load",
        "path": str(apk_path),
        "config": {
            "online": False,
            "out_dir": "out",
            "formats": ["html", "json"],
            "mode": "passive",
            "enrich_max_targets": 32,
            "enrich_static_ip_max_targets": 16,
            "enrichment_dry_run": False,
            "web_supplement": None,
            "web_supplement_request": None,
            "flutter": "auto",
            "flutter_toolchain": None,
            "flutter_timeout": 300,
        },
        "extra_dex": [],
        "jadx_cache_root": None,
        "jadx_baseline_index": None,
        "parser_limits": _limits().to_dict(),
    })

    assert response["kind"] == "error"
    assert response["reason"] == "parser_input_changed"


def test_parser_read_rejects_data_with_failure_and_changed_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = _limits()
    base_response = {
        "version": parser_worker.IPC_VERSION,
        "kind": "read_file",
        "data": "Ynl0ZXM=",
        "failure_reason": "parser_worker_failed",
        "parser_limits": limits.to_dict(),
    }
    monkeypatch.setattr(parser_worker, "_run_operation", lambda *_a, **_kw: dict(base_response))

    data, reason = parser_worker.run_parser_read(
        apk_path="synthetic.apk",
        expected_sha256="a" * 64,
        file_path="assets/sample.bin",
        limits=limits,
        declared_sizes={},
    )

    assert data is None
    assert reason == "parser_invalid_response"

    changed_policy = dict(base_response)
    changed_policy["failure_reason"] = None
    changed_policy["parser_limits"] = ParserLimits(
        timeout_sec=91, memory_bytes=limits.memory_bytes
    ).to_dict()
    monkeypatch.setattr(
        parser_worker, "_run_operation", lambda *_a, **_kw: dict(changed_policy)
    )

    data, reason = parser_worker.run_parser_read(
        apk_path="synthetic.apk",
        expected_sha256="a" * 64,
        file_path="assets/sample.bin",
        limits=limits,
        declared_sizes={},
    )

    assert data is None
    assert reason == "parser_invalid_response"


def test_parser_load_rejects_snapshot_with_changed_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk_path = tmp_path / "policy.apk"
    apk_path.write_bytes(b"synthetic APK input")
    limits = _limits()
    snapshot = _snapshot(apk_path, limits)
    payload = parser_worker.snapshot_to_dict(snapshot)
    payload["parser_limits"] = ParserLimits(
        timeout_sec=91, memory_bytes=limits.memory_bytes
    ).to_dict()
    monkeypatch.setattr(
        parser_worker,
        "_run_operation",
        lambda *_a, **_kw: {
            "version": parser_worker.IPC_VERSION,
            "kind": "snapshot",
            "snapshot": payload,
            "_run_receipt": {
                "ownership_complete": True,
                "termination_complete": True,
                "forced_tree_kill": False,
                "memory_limit_enforced": True,
            },
        },
    )

    with pytest.raises(parser_worker.ParserBridgeError) as raised:
        parser_worker.run_parser_load(
            str(apk_path),
            AnalysisConfig(online=False),
            None,
            None,
            None,
            limits,
        )

    assert raised.value.receipt["reason"] == "parser_invalid_response"


def test_parser_execution_flows_through_pipeline_contract_and_digest() -> None:
    from apkscan.core import meta_contract, pipeline
    from apkscan.report.digest import build_digest

    receipt = {"status": "completed_under_limits", "policy": {"memory_bytes": 1}}
    state = pipeline._PipelineState(
        ctx=SimpleNamespace(parser_execution=receipt),
        config=AnalysisConfig(online=False),
        platform="android",
        capabilities=set(),
    )
    pipeline._stage_degradation_flags(state)
    contract = meta_contract.META_KEY_REGISTRY["parser_execution"]
    digest = build_digest({"meta": state.meta, "leads": []})

    assert state.meta["parser_execution"] == receipt
    assert meta_contract.PIPELINE_OWNER in contract.owners
    assert contract.category == "coverage"
    assert digest["parser_execution"] == receipt


def test_isolated_serial_and_pickled_worker_analysis_are_equivalent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if sys.platform == "darwin":
        pytest.skip("macOS parser memory enforcement is fail-closed")
    limits = _limits()
    apk_path = tmp_path / "parallel.apk"
    contents = b"synthetic-binary"
    _make_apk(apk_path, **{"assets/runtime.bin": contents})
    context = _snapshot(apk_path, limits)

    class Reader:
        name = "parser_reader"

        def analyze(self, ctx):
            data = ctx.read_file("assets/runtime.bin")
            return AnalyzerResult(
                analyzer=self.name,
                meta={"length": len(data) if data is not None else None},
            )

    analyzer = Reader()
    serial = parallel._analyze_serial(context, [(analyzer.name, analyzer)])
    worker_context = pickle.loads(pickle.dumps(context))
    monkeypatch.setitem(parallel._WORKER_STATE, "snapshot", worker_context)
    monkeypatch.setitem(parallel._WORKER_STATE, "analyzers", {analyzer.name: analyzer})
    worker = parallel._worker_analyze(analyzer.name)

    assert serial == [worker]
    assert worker[1].meta == {"length": len(contents)}


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="RLIMIT_AS allocation test is Linux-specific",
)
def test_run_owned_enforces_timeout_output_and_address_space() -> None:
    timeout_run = run_owned(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout=0.2,
        memory_bytes=1024**3,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
    )
    assert timeout_run.timed_out
    assert "timeout" in timeout_run.reason_codes

    output_run = run_owned(
        [sys.executable, "-c", "print('x' * 1000000)"],
        timeout=10,
        memory_bytes=1024**3,
        max_stdout_bytes=1024,
        max_stderr_bytes=4096,
    )
    assert "output_limit" in output_run.reason_codes

    allocation_run = run_owned(
        [
            sys.executable,
            "-c",
            (
                "try:\n"
                "    bytearray(512 * 1024 * 1024)\n"
                "except MemoryError:\n"
                "    print('allocation_blocked')\n"
                "else:\n"
                "    print('allocation_succeeded')\n"
            ),
        ],
        timeout=10,
        memory_bytes=256 * 1024 * 1024,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
    )
    assert allocation_run.memory_limit_enforced
    assert (
        allocation_run.returncode != 0
        or "allocation_blocked" in allocation_run.stdout
    )
    assert "allocation_succeeded" not in allocation_run.stdout


def test_cli_writes_parser_failure_sidecar_and_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apkscan import cli
    from apkscan.core.apk import ApkParseError

    apk_path = tmp_path / "blocked.apk"
    apk_path.write_bytes(b"synthetic")
    out_dir = tmp_path / "out"
    monkeypatch.setattr(cli, "_adb_owned_at_start", lambda: False)

    def fail_parse(*_args, **_kwargs):
        raise ApkParseError(
            "blocked",
            parser_receipt={
                "schema_version": 1,
                "status": "failed",
                "reason": "parser_timeout",
                "blocked_claims": ["parser_derived_observations"],
            },
        )

    monkeypatch.setattr(cli, "load_apk", fail_parse)

    result = CliRunner().invoke(
        cli.app,
        ["analyze", str(apk_path), "--offline", "--out", str(out_dir)],
    )

    sidecar = out_dir / "blocked.parser-failure.json"
    assert result.exit_code == 2
    assert str(sidecar) in result.output
    assert sidecar.is_file()
    assert not (out_dir / "report.json").exists()
    content = sidecar.read_text(encoding="utf-8")
    assert '"status": "failed"' in content
    assert '"reason": "parser_timeout"' in content
