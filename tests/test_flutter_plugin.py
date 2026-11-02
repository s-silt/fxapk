"""Synthetic Flutter contracts; no Docker, APK cases or external network required."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import importlib
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import zipfile

import pytest

from apkscan.core.integrity import evidence_id
from apkscan.core.models import AnalysisConfig
from apkscan.report.json import _to_jsonable


@pytest.fixture
def flutter(monkeypatch):
    pytest.importorskip("elftools")
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "plugins/fxapk-flutter/src"))
    return SimpleNamespace(**{name: importlib.import_module("fxapk_flutter." + name) for name in
                              ("runtime", "evidence", "index", "projection", "detect", "plugin")})


def elf_bytes() -> bytes:
    raw = bytearray(0x1100)
    raw[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0x100, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<I", raw, 0x100, 0x94000004)
    return bytes(raw)


def outputs(root: Path):
    asm = root / "raw/asm/synthetic.dart"
    asm.parent.mkdir(parents=True)
    asm.write_text('''// lib: , url: package:synthetic/main.dart
class UploadService extends Object {
  _ uploadContacts(/* No info */) async {
    // ** addr: 0x1000, size: 0x10
    //     0x1000: bl              #0x1010
    // 0x1004: r1 = "https://example.invalid/api"
    // 0x1008: r2 = "contacts"
    // 0x100c: blr x0
  }
  _ post(/* No info */) {
    // ** addr: 0x1010, size: 0x10
    // 0x1010: r0 = "ok"
  }
}
''', encoding="utf-8")
    for name in ("pp.txt", "objs.txt"):
        (root / "raw" / name).write_text("synthetic pool", encoding="utf-8")


@pytest.fixture
def prepared(flutter, tmp_path, monkeypatch):
    r, e = flutter.runtime, flutter.evidence
    compatibility = {"dart_version": "0.0.0", "snapshot": "1" * 32, "abi": "android_arm64",
                     "compressed_pointers": True, "snapshot_flags": ["synthetic"]}
    binary = tmp_path / "tool"
    binary.write_bytes(b"synthetic-not-executable")
    entry = {**compatibility, "binary": str(binary), "binary_sha256": e.digest(binary), "image_id": "sha256:" + "2" * 64,
             "blutter_revision": "synthetic"}
    config = tmp_path / "toolchain.json"
    cache = tmp_path / "cache"
    e.save(config, {"schema_version": "fxapk-flutter-toolchain/1", "entries": [entry], "cache_dir": str(cache)})
    apks = []
    for n in (1, 2):
        apk = tmp_path / f"sample{n}.apk"
        with zipfile.ZipFile(apk, "w") as z:
            for member in e.MEMBERS:
                z.writestr(member, elf_bytes())
            z.writestr("identity.txt", str(n))
        apks.append(apk)
    executions = []
    def execute(root, *_):
        executions.append(root)
        outputs(root)
    monkeypatch.setattr(r, "inspect_pair", lambda *_: compatibility)
    monkeypatch.setattr(r.shutil, "which", lambda _: "synthetic-docker")
    monkeypatch.setattr(r, "docker_check", lambda *_: None)
    monkeypatch.setattr(r, "execute", execute)
    return SimpleNamespace(apks=apks, config=config, cache=cache, executions=executions, compatibility=compatibility, entry=entry)


def test_real_address_translation_and_calls(flutter, prepared, tmp_path):
    out = tmp_path / "out"
    result = flutter.runtime.analyze(prepared.apks[0], out, prepared.config)
    assert result["coverage"]["functions"] == 2
    assert result["coverage"]["raw_call_mismatches"] == 0
    assert result["coverage"]["unresolved_indirect_calls"] == 1
    match = flutter.index.query(out, symbol="UploadService.uploadContacts")["matches"][0]
    assert match["calls"][0]["verified"] == 1
    assert match["calls"][0]["target"] == 0x1010
    assert match["strings"][1]["value"] == "contacts"
    assert flutter.index.query(out, text="contacts")["matches"][0]["function"] == 0x1000


def test_cache_rebinds_each_apk_and_detects_tampering(flutter, prepared, tmp_path):
    first = flutter.runtime.analyze(prepared.apks[0], tmp_path / "one", prepared.config)
    second = flutter.runtime.analyze(prepared.apks[1], tmp_path / "two", prepared.config)
    assert second["cache_hit"] and not first["cache_hit"]
    assert first["source"]["apk_sha256"] != second["source"]["apk_sha256"]
    assert first["cache_key"] == second["cache_key"]
    assert len(prepared.executions) == 1
    (prepared.cache / first["cache_key"] / "raw/pp.txt").write_text("changed")
    third = flutter.runtime.analyze(prepared.apks[0], tmp_path / "three", prepared.config)
    assert not third["cache_hit"] and third["cache_reason"] == "invalid_cache_recomputed"
    assert len(prepared.executions) == 2


def test_no_cache_actually_runs(flutter, prepared, tmp_path):
    flutter.runtime.analyze(prepared.apks[0], tmp_path / "one", prepared.config)
    result = flutter.runtime.analyze(prepared.apks[0], tmp_path / "two", prepared.config, use_cache=False)
    assert not result["cache_hit"] and len(prepared.executions) == 2


def test_attach_exact_apk_preserves_original_fields(flutter, prepared, tmp_path):
    root = tmp_path / "bundle"
    result = flutter.runtime.analyze(prepared.apks[0], root, prepared.config)
    report = tmp_path / "report.json"
    data = {"schema_version": "1.3", "meta": {"sample_sha256": result["source"]["apk_sha256"], "closure": {"status": "partial"}},
            "endpoints": [], "leads": [], "private_extension": {"keep": True}}
    flutter.evidence.save(report, data)
    before = report.read_bytes()
    flutter.projection.attach(root, report, tmp_path / "attached")
    updated = flutter.evidence.load(tmp_path / "attached/report.json")
    assert report.read_bytes() == before
    assert updated["private_extension"] == data["private_extension"]
    assert updated["meta"]["closure"] == data["meta"]["closure"]
    assert updated["endpoints"][0]["evidences"][0]["source"] == "derived-native"
    expected = {
        ev["location"]: ev
        for ep in flutter.projection.project(
            tmp_path / "attached/flutter" / result["cache_key"], "flutter/" + result["cache_key"]
        )["endpoints"]
        for ev in _to_jsonable(ep)["evidences"]
    }
    for evidence in updated["endpoints"][0]["evidences"]:
        assert evidence["source"] == "derived-native"
        assert evidence["reachability"] == "unknown"
        assert evidence["evidence_id"] == evidence_id(evidence["source"], evidence["location"])
        assert evidence["occurrence_id"] == expected[evidence["location"]]["occurrence_id"]
    assert updated["meta"]["flutter_analysis"]["runtime_observed"] is False
    data["meta"]["sample_sha256"] = "a" * 64
    flutter.evidence.save(report, data)
    with pytest.raises(flutter.evidence.FlutterError, match="report_apk_mismatch"):
        flutter.projection.attach(root, report, tmp_path / "wrong")
    assert not (tmp_path / "wrong").exists()


def test_raw_call_mismatch_not_verified(flutter, tmp_path):
    root = tmp_path / "bundle"
    (root / "input").mkdir(parents=True)
    (root / "input/libapp.so").write_bytes(elf_bytes().replace(struct.pack("<I", 0x94000004), struct.pack("<I", 0x94000008)))
    outputs(root)
    result = flutter.index.build(root)
    assert result["raw_call_mismatches"] == 1
    assert flutter.index.query(root, symbol="uploadContacts")["matches"][0]["calls"][0]["verified"] == 0


@pytest.mark.parametrize("field,value", [("snapshot", "x"), ("abi", "x"), ("compressed_pointers", False), ("snapshot_flags", [])])
def test_exact_compatibility_required(flutter, prepared, field, value):
    bad = {**prepared.compatibility, field: value}
    with pytest.raises(flutter.evidence.FlutterError, match="unsupported_snapshot"):
        flutter.runtime.select({"entries": [prepared.entry]}, bad)


def test_duplicate_toolchain_refused(flutter, prepared):
    with pytest.raises(flutter.evidence.FlutterError, match="ambiguous"):
        flutter.runtime.select({"entries": [prepared.entry, prepared.entry]}, prepared.compatibility)


def test_input_output_and_failure_boundaries(flutter, prepared, tmp_path, monkeypatch):
    out = tmp_path / "existing"
    out.mkdir()
    (out / "keep").write_text("keep")
    with pytest.raises(FileExistsError):
        flutter.runtime.analyze(prepared.apks[0], out, prepared.config)
    assert list(out.iterdir()) == [out / "keep"]
    monkeypatch.setattr(flutter.runtime, "execute", lambda *_: (_ for _ in ()).throw(flutter.evidence.FlutterError("analysis_timeout")))
    with pytest.raises(flutter.evidence.FlutterError, match="analysis_timeout"):
        flutter.runtime.analyze(prepared.apks[0], tmp_path / "timeout", prepared.config)
    assert flutter.evidence.load(tmp_path / "timeout/failure.json")["reason"] == "analysis_timeout"
    assert not (prepared.cache / "analysis.lock").exists()


@pytest.mark.parametrize("relative", ["../escape", "/absolute", "C:/outside", "a/../../escape", "a\\b"])
def test_path_escape_refused(flutter, tmp_path, relative):
    with pytest.raises(flutter.evidence.FlutterError):
        flutter.evidence.contained(tmp_path, relative)


def test_truncated_elf_and_missing_outputs(flutter, tmp_path):
    bad = tmp_path / "bad.so"
    bad.write_bytes(b"\x7fELF")
    with pytest.raises(flutter.evidence.FlutterError, match="invalid_flutter_elf"):
        flutter.detect.inspect_pair(bad, bad)
    with pytest.raises(flutter.evidence.FlutterError, match="required_output_missing"):
        flutter.index.build(tmp_path)


def test_bundle_tamper_rejected_before_query(flutter, prepared, tmp_path):
    root = tmp_path / "bundle"
    flutter.runtime.analyze(prepared.apks[0], root, prepared.config)
    (root / "raw/pp.txt").write_text("changed")
    with pytest.raises(flutter.evidence.FlutterError, match="bundle_incomplete_or_changed"):
        flutter.evidence.validate_bundle(root)


def test_stage_modes_and_missing_plugin(flutter, monkeypatch):
    from apkscan.core import flutter_analysis as stage
    from apkscan.core.pipeline import _PipelineState, _analysis_health
    state = _PipelineState(ctx=SimpleNamespace(apk_path="synthetic.apk"), config=AnalysisConfig(), platform="android", capabilities=set())
    state.meta["app_framework"] = {"identified": True, "name": "flutter", "own_code_libs": ["libapp.so"]}
    monkeypatch.setattr(stage, "discover_plugins", lambda: ([], []))
    stage.run_flutter_stage(state)
    assert state.meta["flutter_analysis"]["reason"] == "plugin_not_installed"
    assert _analysis_health(state.analyzer_status)[0] == "failed"
    state.config.flutter = "off"
    stage.run_flutter_stage(state)
    assert state.meta["flutter_analysis"]["reason"] == "disabled"


def test_stage_uses_plugin_and_preserves_static_provenance(flutter, prepared, tmp_path, monkeypatch):
    from apkscan.core import flutter_analysis as stage
    from apkscan.core.pipeline import _PipelineState
    cfg = AnalysisConfig(out_dir=str(tmp_path / "pipeline"), flutter="required", flutter_toolchain=str(prepared.config))
    state = _PipelineState(ctx=SimpleNamespace(apk_path=str(prepared.apks[0])), config=cfg, platform="android", capabilities=set())
    state.meta["app_framework"] = {"identified": True, "name": "flutter"}
    monkeypatch.setattr(stage, "discover_plugins", lambda: ([flutter.plugin.FlutterPlugin()], []))
    stage.run_flutter_stage(state)
    assert state.meta["flutter_analysis"]["status"] == "ok"
    assert asdict(state.endpoints[0])["evidences"][0]["reachability"] == "unknown"


def test_distribution_and_cli(flutter):
    import tomllib
    from typer.testing import CliRunner
    metadata = tomllib.loads((Path(__file__).parents[1] / "plugins/fxapk-flutter/pyproject.toml").read_text())
    assert metadata["project"]["entry-points"]["fxapk.plugins"]["flutter"] == "fxapk_flutter.plugin:plugin_factory"
    result = CliRunner().invoke(flutter.plugin.app, ["capabilities", "--toolchain", "missing-config.json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["reason"] == "toolchain_not_configured"


def test_abstract_class_static_method_index(flutter, tmp_path):
    root = tmp_path / "bundle"
    (root / "input").mkdir(parents=True)
    (root / "input/libapp.so").write_bytes(elf_bytes())
    outputs(root)
    asm = root / "raw/asm/synthetic.dart"
    asm.write_text(asm.read_text().replace("class UploadService", "abstract class MasterConfig")
                   .replace("_ uploadContacts(/* No info */)", "static Future<void> init()"))
    flutter.index.build(root)
    assert flutter.index.query(root, symbol="MasterConfig.init")["matches"][0]["address"] == 0x1000


def test_anonymous_closure_signature(flutter, tmp_path):
    root = tmp_path / "bundle"
    (root / "input").mkdir(parents=True)
    (root / "input/libapp.so").write_bytes(elf_bytes())
    outputs(root)
    asm = root / "raw/asm/synthetic.dart"
    asm.write_text(asm.read_text().replace("_ uploadContacts(/* No info */)", "(/* No info */)"))
    flutter.index.build(root)
    assert flutter.index.query(root, symbol="closure@1000")["matches"][0]["address"] == 0x1000


def test_timeout_removes_only_owned_container(flutter, tmp_path, monkeypatch):
    from apkscan.core.proctree import OwnedRun
    calls = []
    entry = {"binary": str(tmp_path / "tool"), "image_id": "sha256:" + "a" * 64}
    def run(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "run":
            return OwnedRun(None, "", "", True, True, True, True, ("timeout",))
        return OwnedRun(0, "", "", False, True, True, False, ())
    monkeypatch.setattr(flutter.runtime, "run_owned", run)
    with pytest.raises(flutter.evidence.FlutterError, match="analysis_timeout"):
        flutter.runtime.execute(tmp_path, entry, "docker", 1)
    run_args, cleanup = calls
    name = run_args[run_args.index("--name") + 1]
    assert cleanup == ["docker", "rm", "-f", name]
    assert run_args[run_args.index("--network") + 1] == "none"
    assert "--read-only" in run_args and "--pull" in run_args
    assert (tmp_path / "execution.json").is_file()


def test_missing_container_cleanup_is_not_success(flutter, tmp_path, monkeypatch):
    from apkscan.core.proctree import OwnedRun
    monkeypatch.setattr(flutter.runtime, "run_owned", lambda argv, **_: OwnedRun(
        0 if argv[1] == "run" else 1, "", "", False, True, True, False, ()))
    with pytest.raises(flutter.evidence.FlutterError, match="container_cleanup_failed"):
        flutter.runtime.execute(tmp_path, {"binary": str(tmp_path / "tool"), "image_id": "sha256:" + "a" * 64}, "docker", 1)


def test_digest_exposes_counts_not_raw_strings():
    from apkscan.report.digest import build_digest
    report = {"meta": {"flutter_analysis": {"status": "ok", "coverage": {"functions": 2, "source_namespaces": ["private"]},
                                              "compatibility": {"dart_version": "0.0.0"}}}, "leads": [], "endpoints": [], "findings": []}
    result = build_digest(report)["flutter_analysis"]
    assert result["functions"] == 2 and "private" not in str(result)


@pytest.mark.parametrize("encoded,decoded", [
    (r'"https://example.invalid/config\?app=demo"', "https://example.invalid/config?app=demo"),
    (r'"a\\?b"', "a\\?b"),
    (r'"a\'b"', "a'b"),
    ('"中文"', "中文"),
    (r'"a\nb"', "a\nb"),
])
def test_blutter_string_encoding(flutter, encoded, decoded):
    assert flutter.index.decode_string(encoded) == decoded


def test_unknown_string_escape_rejected(flutter):
    with pytest.raises(flutter.evidence.FlutterError, match="unsupported_string_escape"):
        flutter.index.decode_string(r'"\x00"')


@pytest.mark.parametrize("key,value", [("flutter", "bad"), ("flutter", []), ("flutter_timeout", True),
                                      ("flutter_timeout", 0), ("flutter_toolchain", 1)])
def test_parser_bridge_validates_flutter_config(key, value):
    from apkscan.core.parser_worker import _config_from_request
    config = asdict(AnalysisConfig())
    assert _config_from_request(config).flutter == "auto"
    config[key] = value
    with pytest.raises(ValueError, match="parser_invalid_request"):
        _config_from_request(config)


@pytest.mark.parametrize("bad_key", ["../../escaped", "/absolute", "x", None, 123])
def test_attach_rejects_unsafe_cache_key(flutter, prepared, tmp_path, bad_key):
    root = tmp_path / "bundle"
    flutter.runtime.analyze(prepared.apks[0], root, prepared.config)
    manifest = flutter.evidence.load(root / "manifest.json")
    manifest["cache_key"] = bad_key
    flutter.evidence.save(root / "manifest.json", manifest)
    report = tmp_path / "report.json"
    data = {"schema_version": "1.3",
            "meta": {"sample_sha256": manifest["source"]["apk_sha256"]},
            "endpoints": [], "leads": []}
    flutter.evidence.save(report, data)
    before = sorted(p.name for p in tmp_path.iterdir())
    out = tmp_path / "attached"
    with pytest.raises(flutter.evidence.FlutterError, match="invalid_cache_key"):
        flutter.projection.attach(root, report, out)
    assert not out.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_attach_reads_one_report_snapshot(flutter, prepared, tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    result = flutter.runtime.analyze(prepared.apks[0], root, prepared.config)
    report = tmp_path / "report.json"
    data = {"schema_version": "1.3",
            "meta": {"sample_sha256": result["source"]["apk_sha256"], "closure": {"status": "partial"}},
            "endpoints": [], "leads": [], "private_extension": {"keep": True}}
    flutter.evidence.save(report, data)
    before = report.read_bytes()
    replaced = {"schema_version": "1.3", "meta": {"sample_sha256": "a" * 64},
                "endpoints": [], "leads": [], "private_extension": {"keep": False}}
    real_read = flutter.projection.read

    def swap(path, *args, **kwargs):
        raw = real_read(path, *args, **kwargs)
        flutter.evidence.save(report, replaced)
        return raw

    monkeypatch.setattr(flutter.projection, "read", swap)
    attached = tmp_path / "attached"
    flutter.projection.attach(root, report, attached)
    assert (attached / "source-report.json").read_bytes() == before
    updated = flutter.evidence.load(attached / "report.json")
    assert updated["private_extension"] == {"keep": True}
    assert updated["meta"]["flutter_analysis"]["source_report"]["sha256"] == hashlib.sha256(before).hexdigest()
    assert report.read_bytes() != before
    assert json.loads(report.read_bytes())["meta"]["sample_sha256"] == "a" * 64


def _stub_pipeline(monkeypatch, plugin=None):
    from apkscan.core import flutter_analysis as stage
    from apkscan.core import pipeline

    def _analyzers(state):
        state.meta["app_framework"] = {"identified": True, "name": "flutter"}
        state.meta.setdefault("analyzer_receipts", {})
        state.analyzer_status.append({"name": "synthetic", "status": "ran"})

    monkeypatch.setattr(pipeline, "_stage_run_analyzers", _analyzers)
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    monkeypatch.setattr(stage, "discover_plugins", lambda: ([plugin] if plugin else [], []))


def _fake_plugin(calls):
    from apkscan.core.models import Endpoint, Evidence

    class _FakePlugin:
        name = "flutter"

        def run_static(self, request):
            calls.append(request)
            return {
                "metadata": {"schema_version": "fxapk-flutter/1", "status": "ok", "runtime_observed": False},
                "endpoints": [
                    Endpoint(
                        value="https://example.invalid/api", kind="url",
                        evidences=[Evidence(source="derived-native", location="synthetic",
                                            structure_status="parsed", reference_status="static_literal",
                                            reachability="unknown")],
                    )
                ],
            }

    return _FakePlugin()


def test_pipeline_flutter_stage_runs_plugin(fake_ctx, tmp_path, monkeypatch):
    from apkscan.core import pipeline
    from apkscan.core.models import evidence_source_is_direct, has_case_evidence

    calls = []
    _stub_pipeline(monkeypatch, _fake_plugin(calls))
    report = pipeline.run(fake_ctx, AnalysisConfig(online=False, flutter="required", out_dir=str(tmp_path)))
    assert report.meta["flutter_analysis"]["status"] == "ok"
    assert calls and calls[0]["apk"] == fake_ctx.apk_path
    candidate = next(e for e in report.endpoints if e.value == "https://example.invalid/api")
    assert evidence_source_is_direct(candidate.evidences[0].source) is False
    assert has_case_evidence(candidate.evidences) is False
    from apkscan.core.admission import evaluate_evidence
    assert evaluate_evidence(candidate.evidences[0], "closure_candidate").state == "review"
    assert evaluate_evidence(candidate.evidences[0], "passive_enrichment").state == "review"
    evidence = _to_jsonable(candidate)["evidences"][0]
    assert evidence["source"] == "derived-native" and evidence["reachability"] == "unknown"
    assert evidence["evidence_id"] == evidence_id("derived-native", "synthetic")


def test_pipeline_flutter_off_skips_plugin(fake_ctx, tmp_path, monkeypatch):
    from apkscan.core import pipeline

    calls = []
    _stub_pipeline(monkeypatch, _fake_plugin(calls))
    report = pipeline.run(fake_ctx, AnalysisConfig(online=False, flutter="off", out_dir=str(tmp_path)))
    assert calls == []
    assert report.meta["flutter_analysis"]["status"] == "skipped"
    assert report.meta["flutter_analysis"]["reason"] == "disabled"
    assert all(s["name"] != "flutter" for s in report.analyzer_status)
    assert all(e.value != "https://example.invalid/api" for e in report.endpoints)


def test_pipeline_flutter_missing_plugin_marks_partial(fake_ctx, tmp_path, monkeypatch):
    from apkscan.core import pipeline

    _stub_pipeline(monkeypatch)
    report = pipeline.run(fake_ctx, AnalysisConfig(online=False, flutter="auto", out_dir=str(tmp_path)))
    assert report.meta["flutter_analysis"]["status"] == "unavailable"
    assert report.meta["flutter_analysis"]["reason"] == "plugin_not_installed"
    statuses = {s["name"]: s["status"] for s in report.analyzer_status}
    assert statuses["synthetic"] == "ran" and statuses["flutter"] == "error"
    assert report.analysis_status == "partial"


def _stub_cli(monkeypatch, report):
    import apkscan.cli as cli
    import apkscan.core.pipeline as pipeline

    monkeypatch.setattr(cli, "_adb_owned_at_start", lambda: False)
    monkeypatch.setattr(cli.device, "has_device", lambda: False)
    monkeypatch.setattr(cli, "load_apk",
                        lambda *a, **k: SimpleNamespace(package_name="synthetic.test", extra_dex_report=None))
    monkeypatch.setattr(pipeline, "run", lambda ctx, config: report)


def test_cli_flutter_required_exit4_preserves_report(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from apkscan.cli import app
    from apkscan.core.models import Report

    report = Report(package_name="synthetic.test", meta={"flutter_analysis": {"status": "failed"}},
                    leads=[], endpoints=[], findings=[], analyzer_status=[], analysis_status="complete")
    _stub_cli(monkeypatch, report)
    apk = tmp_path / "synthetic.apk"
    apk.write_bytes(b"synthetic")
    out = tmp_path / "out-required"
    result = CliRunner().invoke(app, ["analyze", str(apk), "--offline", "--flutter", "required",
                                      "--fmt", "json", "--out", str(out)])
    assert result.exit_code == 4
    written = out / "synthetic.json"
    assert written.is_file()
    assert json.loads(written.read_bytes())["meta"]["flutter_analysis"]["status"] == "failed"


def test_cli_flutter_invalid_mode_exit2(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from apkscan.cli import app

    _stub_cli(monkeypatch, None)
    apk = tmp_path / "synthetic.apk"
    apk.write_bytes(b"synthetic")
    result = CliRunner().invoke(app, ["analyze", str(apk), "--offline", "--flutter", "bogus",
                                      "--out", str(tmp_path / "out-invalid")])
    assert result.exit_code == 2


def test_cli_flutter_auto_preserves_report_without_gate(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from apkscan.cli import app
    from apkscan.core.models import Report

    report = Report(package_name="synthetic.test", meta={"flutter_analysis": {"status": "failed"}},
                    leads=[], endpoints=[], findings=[], analyzer_status=[], analysis_status="complete")
    _stub_cli(monkeypatch, report)
    apk = tmp_path / "synthetic.apk"
    apk.write_bytes(b"synthetic")
    out = tmp_path / "out-auto"
    result = CliRunner().invoke(app, ["analyze", str(apk), "--offline", "--flutter", "auto",
                                    "--fmt", "json", "--out", str(out)])
    assert result.exit_code == 0
    assert json.loads((out / "synthetic.json").read_bytes())["meta"]["flutter_analysis"]["status"] == "failed"
