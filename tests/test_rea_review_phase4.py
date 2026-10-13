"""Confirmed follow-ups after phase 3. Synthetic fixtures only."""

from __future__ import annotations

import importlib
import json
import struct
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from apkscan.cli import app
from apkscan.core.models import Report
from apkscan.core.web_observation_plan import project_plan_for_digest
from apkscan.core.web_supplement import project_for_digest, summary_line
from apkscan.core.web_supplement_report import SupplementRefusal, supplement_report
from apkscan.dynamic import auto
from apkscan.report.digest import build_digest
from tests.test_rea_attach import _rea_bundle
from tests.test_rea_native import _elf, _report, _sha
from tests.test_rea_review_phase2 import _attach_report, _recover

PLUGIN_SRC = Path(__file__).parents[1] / "plugins" / "fxapk-rea" / "src"
_FLAGS = ("relation_verified", "runtime_observed", "closure_evaluated", "label")


@pytest.fixture
def native(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.syspath_prepend(str(PLUGIN_SRC))
    return importlib.import_module("fxapk_rea.native")


def _cdp(mode: str = "auto") -> dict[str, object]:
    return {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": mode,
        "source": "cdp",
        "endpoint": "http://127.0.0.1:9222",
        "target": "synthetic-target",
        "exact_origins": ["http://127.0.0.1:9"],
        "provider": "trace",
        "observation_ms": 50,
        "authorized": True,
    }


def _off_config(path: Path) -> None:
    path.write_text(
        json.dumps({
            "schema_version": "fxapk.web_supplement.v1",
            "mode": "off",
            "source": "bundle",
            "path": str(path.parent / "unused-material"),
        }),
        encoding="utf-8",
    )


def _forged_report(native, monkeypatch, tmp_path: Path, *, contradictory: bool) -> tuple[Path, bytes, str]:  # noqa: ANN001
    recovery, body = _recover(native, monkeypatch, tmp_path)
    attached = _attach_report(native, recovery, tmp_path, body)
    report = attached / "report.json"
    payload = json.loads(report.read_text(encoding="utf-8"))
    item = payload["meta"]["native_recovery"][0]
    item["analyst_note"] = "keep-me"
    if contradictory:
        item.update(
            relation_verified=True,
            runtime_observed=True,
            closure_evaluated=True,
            label="runtime_observation",
        )
    else:
        for key in ("relation_verified", "runtime_observed", "closure_evaluated", "label"):
            item.pop(key, None)
    report.write_text(json.dumps(payload), encoding="utf-8")
    return report, report.read_bytes(), item["content_digest"]


def test_r2_web_entrypoints_reject_contradictory_history_flags(native, monkeypatch, tmp_path: Path) -> None:  # noqa: ANN001
    report, original, _digest = _forged_report(native, monkeypatch, tmp_path, contradictory=True)
    config = tmp_path / "off.json"
    _off_config(config)
    bundle = tmp_path / "web-bundle"
    _rea_bundle(PLUGIN_SRC, bundle)
    attachment = importlib.import_module("fxapk_rea.attachment")
    with pytest.raises(attachment.AttachError) as attach_error:
        attachment.attach(bundle, report, tmp_path / "web-attach")
    assert str(attach_error.value) == "result_mismatch"
    assert not (tmp_path / "web-attach").exists()
    with pytest.raises(SupplementRefusal) as supplement_error:
        supplement_report(report, config, tmp_path / "supplement-off")
    assert supplement_error.value.reason == "result_mismatch"
    assert not (tmp_path / "supplement-off").exists()
    assert report.read_bytes() == original


def test_r2_web_entrypoints_reconstruct_only_absent_flags(native, monkeypatch, tmp_path: Path) -> None:  # noqa: ANN001
    report, original, digest = _forged_report(native, monkeypatch, tmp_path, contradictory=False)
    snapshot = next((report.parent / "input_report").glob("*/report.json"))
    snapshot_bytes = snapshot.read_bytes()
    config = tmp_path / "off.json"
    _off_config(config)
    bundle = tmp_path / "web-bundle"
    _rea_bundle(PLUGIN_SRC, bundle)
    attachment = importlib.import_module("fxapk_rea.attachment")
    attachment.attach(bundle, report, tmp_path / "web-attach")
    supplement_report(report, config, tmp_path / "supplement-off")
    assert report.read_bytes() == original
    for out in (tmp_path / "web-attach", tmp_path / "supplement-off"):
        written = json.loads((out / "report.json").read_text(encoding="utf-8"))
        item = written["meta"]["native_recovery"][0]
        assert item["relation_verified"] is False
        assert item["runtime_observed"] is False
        assert item["closure_evaluated"] is False
        assert item["label"] == "analyst_reconstruction"
        assert item["analyst_note"] == "keep-me"
        immutable = json.loads((out / "native_recovery" / digest / "result.json").read_text(encoding="utf-8"))
        assert immutable["relation_verified"] is False
        assert immutable["candidate"]["label"] == "analyst_reconstruction"
        shown = build_digest(written)
        assert shown["native_recovery"]["relation_verified"] is False
        assert shown["native_recovery"]["closure_evaluated"] is False
    copied_old = next((tmp_path / "web-attach" / "input_report").glob("*/report.json"))
    assert copied_old.read_bytes() == snapshot_bytes or copied_old.read_bytes() == original


def _rehash_result(recovery: Path, result: dict) -> None:
    encoded = (json.dumps(result, indent=2) + "\n").encode()
    (recovery / "result.json").write_bytes(encoded)
    manifest = json.loads((recovery / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"]["result.json"] = {"sha256": _sha(encoded), "size": len(encoded)}
    (recovery / "manifest.json").write_bytes((json.dumps(manifest, indent=2) + "\n").encode())


@pytest.mark.parametrize("mutation", ["recipe_sha256", "verified_offset", "candidate_label"])
def test_p2_result_projection_rejects_rehashed_mutations(native, monkeypatch, tmp_path: Path, mutation: str) -> None:  # noqa: ANN001
    """Receipt integrity only. These mutations are not a closure upgrade."""
    recovery, body = _recover(native, monkeypatch, tmp_path)
    before = (recovery / "result.json").read_bytes()
    result = json.loads(before)
    if mutation == "recipe_sha256":
        result["recipe_sha256"] = "0" * 64
    elif mutation == "verified_offset":
        result["verified_ranges"][0]["offset"] += 1
    else:
        result["candidate"]["label"] = "runtime_observation"
    _rehash_result(recovery, result)
    report = tmp_path / "input.json"
    report.write_text(json.dumps(_report(_sha(body))), encoding="utf-8")
    report_before = report.read_bytes()
    out = tmp_path / "attached"
    with pytest.raises(native.NativeError) as exc:
        native.attach(recovery, report, out)
    assert str(exc.value) == "result_mismatch"
    assert not out.exists()
    assert report.read_bytes() == report_before


def _deflated_member(archive: Path, member: str, payload: bytes, *, corrupt: str | None) -> None:
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr(member, payload)
    if corrupt is None:
        return
    blob = bytearray(archive.read_bytes())
    if corrupt == "deflate":
        name_len, extra_len = struct.unpack_from("<HH", blob, 26)
        offset = 30 + name_len + extra_len
        blob[offset] = (blob[offset] & 0xF8) | 7
    elif corrupt == "crc":
        blob[14] ^= 0xFF
        central = blob.find(b"PK\x01\x02")
        blob[central + 16] ^= 0xFF
    archive.write_bytes(blob)


def test_b3_cli_maps_bad_deflate_and_crc_and_keeps_valid(native, tmp_path: Path) -> None:  # noqa: ANN001
    del native
    cli = importlib.import_module("fxapk_rea.native_cli")
    member = "lib/x86_64/libsample.so"
    payload = _elf(62) + b"\0" * 64
    runner = CliRunner()
    for corrupt, expect in (("deflate", "invalid_zip"), ("crc", "invalid_zip"), (None, "ok")):
        archive = tmp_path / f"{corrupt or 'valid'}.apk"
        out = tmp_path / f"out-{corrupt or 'valid'}"
        _deflated_member(archive, member, payload, corrupt=corrupt)
        result = runner.invoke(cli.native_app, ["extract", str(archive), "--member", member, "--out", str(out)])
        if expect == "ok":
            assert result.exit_code == 0
            assert result.exception is None
            assert (out / "binary.bin").read_bytes() == payload
        else:
            assert result.exit_code == 1
            assert "invalid_zip" in result.stdout
            assert not isinstance(result.exception, zlib_error())
            assert not out.exists()


def zlib_error() -> type[BaseException]:
    import zlib

    return zlib.error


def test_d4_failed_summary_is_distinct_from_skipped() -> None:
    failed = project_for_digest({"status": "failed", "reason": "worker_not_stopped"})
    assert failed["status"] == "failed"
    assert failed["latest_reason"] == "worker_not_stopped"
    assert failed["summary_line"].startswith("网页补采失败：worker_not_stopped")
    assert "已跳过" not in failed["summary_line"]
    skipped = summary_line("skipped", "mode_off", 0)
    assert skipped.startswith("网页补采已跳过：mode_off")
    assert "失败" not in skipped


def _guard_processes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    def _refuse(command: object, *args: object, **kwargs: object) -> object:
        del args, kwargs
        text = " ".join(str(part) for part in command) if isinstance(command, (list, tuple)) else str(command)
        seen.append(text)
        lowered = text.lower()
        if any(token in lowered for token in ("adb", "frida", "chrome", "msedge", "chromium")):
            raise AssertionError(text)
        if "git" in lowered and "rev-parse" in lowered:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected subprocess: {text}")

    monkeypatch.setattr(subprocess, "run", _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)
    monkeypatch.setattr("apkscan.core.tools.adb_server_running", lambda: True)
    monkeypatch.setattr("apkscan.core.tools.kill_adb_server", lambda: None)
    return seen


def _synthetic_report() -> Report:
    return Report(
        package_name="app.synthetic",
        meta={
            "web_observation_plan": {
                "status": "selected",
                "reason": "ok",
                "source": "cdp",
                "provider": "trace",
                "mode": "auto",
                "platform": "android",
            },
        },
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def _invoke_analyze(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, dynamic: bool, device: bool, mode: str, pre_observer: bool) -> Path:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"synthetic-apk")
    config = tmp_path / "web.json"
    body = _cdp(mode)
    if mode == "off":
        body = {
            "schema_version": "fxapk.web_supplement.v1",
            "mode": "off",
            "source": "cdp",
            "endpoint": "http://127.0.0.1:9222",
            "target": "synthetic-target",
            "exact_origins": ["http://127.0.0.1:9"],
            "provider": "trace",
            "authorized": True,
        }
    config.write_text(json.dumps(body), encoding="utf-8")
    out = tmp_path / "reports"
    monkeypatch.setattr("apkscan.cli.load_apk", lambda *a, **k: SimpleNamespace(package_name="app.synthetic", extra_dex_report=None))
    monkeypatch.setattr("apkscan.core.pipeline.run", lambda *a, **k: _synthetic_report())
    monkeypatch.setattr("apkscan.cli.device.has_device", lambda: device)
    if dynamic and device:
        unpack = importlib.import_module("apkscan.dynamic.unpack")
        capture = importlib.import_module("apkscan.dynamic.capture")
        monkeypatch.setattr(unpack, "run", lambda *a, **k: {"status": "skipped"})
        if pre_observer:
            monkeypatch.setattr(capture, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("pre-observer")))
        else:
            monkeypatch.setattr(capture, "run", lambda *a, **k: {"status": "skipped"})
        monkeypatch.setattr(
            "apkscan.core.web_supplement_runtime.make_capture_observer",
            lambda *a, **k: object(),
        )
    args = ["analyze", str(apk), "--offline", "--fmt", "json", "--out", str(out), "--web-supplement", str(config)]
    if dynamic:
        args.append("--dynamic")
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    written = out / "sample.json"
    assert written.is_file()
    return written


@pytest.mark.parametrize(
    ("dynamic", "device", "deferral", "pre_observer"),
    [
        (False, False, "not_requested", False),
        (True, False, "device_unavailable", False),
        (True, True, "pre_observer_failure", True),
    ],
)
def test_d1_analyze_cli_records_cdp_deferred(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dynamic: bool, device: bool, deferral: str, pre_observer: bool,
) -> None:
    seen = _guard_processes(monkeypatch)
    written = _invoke_analyze(
        tmp_path, monkeypatch, dynamic=dynamic, device=device, mode="auto", pre_observer=pre_observer,
    )
    payload = json.loads(written.read_text(encoding="utf-8"))
    receipt = payload["meta"]["web_supplement_runtime"][-1]
    assert receipt["reason"] == "cdp_deferred"
    assert receipt["execution"] == "not_executed"
    assert receipt["deferral"] == deferral
    digest = build_digest(payload)
    handoff = digest["web_observation_plan"]["agent_handoff"]
    assert handoff["why"] == "cdp_deferred"
    assert "not_executed" in json.dumps(digest["web_observation_plan"])
    assert not any(token in item.lower() for item in seen for token in ("adb", "frida", "chrome", "msedge", "chromium"))


def test_d1_analyze_mode_off_has_no_cdp_deferred(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _guard_processes(monkeypatch)
    written = _invoke_analyze(tmp_path, monkeypatch, dynamic=True, device=True, mode="off", pre_observer=False)
    payload = json.loads(written.read_text(encoding="utf-8"))
    assert "cdp_deferred" not in json.dumps(payload.get("meta", {}).get("web_supplement_runtime", []))
    assert not any(token in item.lower() for item in seen for token in ("adb", "frida", "chrome", "msedge", "chromium"))


def _auto_static(*_args: object, **_kwargs: object) -> tuple[dict, Report, str, list[str], str]:
    return (
        {"name": "static", "status": "done", "detail": "mocked"},
        _synthetic_report(),
        "app.synthetic",
        [],
        "sample",
    )


def test_d1_auto_device_and_pre_observer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _guard_processes(monkeypatch)
    config = tmp_path / "web.json"
    config.write_text(json.dumps(_cdp()), encoding="utf-8")
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"synthetic-apk")
    monkeypatch.setattr(auto, "_run_doctor", lambda **_k: {"name": "doctor", "status": "skipped", "detail": ""})
    monkeypatch.setattr(auto, "_run_static", _auto_static)
    monkeypatch.setattr(auto, "_run_closure", lambda *a, **k: (
        {"name": "close", "status": "skipped", "detail": "not this batch"},
        {"status": "failed", "gaps": ["not run"]},
        [],
    ))
    monkeypatch.setattr(auto, "_run_unpack", lambda *a, **k: (
        {"name": "unpack", "status": "skipped", "detail": ""}, [], None,
    ))
    monkeypatch.setattr("apkscan.dynamic.auto.device.select_target_serial", lambda: None)
    unavailable = auto.run(
        str(apk), out_dir=str(tmp_path / "no-device"), online=False, auto_fix=False,
        three_rounds=False, formats=["json"], web_supplement=str(config),
    )
    assert unavailable["status"]
    no_device_report = json.loads((tmp_path / "no-device" / "sample.json").read_text(encoding="utf-8"))
    assert no_device_report["meta"]["web_supplement_runtime"][-1]["deferral"] == "device_unavailable"

    capture = importlib.import_module("apkscan.dynamic.capture")
    monkeypatch.setattr(capture, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("pre-observer")))
    monkeypatch.setattr("apkscan.core.web_supplement_runtime.make_capture_observer", lambda *a, **k: object())
    monkeypatch.setattr(auto, "_ensure_root_frida_server", lambda **_k: None)
    monkeypatch.setattr(auto, "_run_install_app", lambda *a, **k: {"name": "install", "status": "skipped", "detail": ""})
    monkeypatch.setattr("apkscan.dynamic.auto.device.select_target_serial", lambda: "serial-synthetic")
    failed = auto.run(
        str(apk), out_dir=str(tmp_path / "pre"), online=False, auto_fix=False,
        three_rounds=False, formats=["json"], web_supplement=str(config),
    )
    assert any("未预期异常" in step.get("detail", "") for step in failed["steps"])
    pre_report = json.loads((tmp_path / "pre" / "sample.json").read_text(encoding="utf-8"))
    receipt = pre_report["meta"]["web_supplement_runtime"][-1]
    assert receipt["reason"] == "cdp_deferred"
    assert receipt["execution"] == "not_executed"
    assert receipt["deferral"] == "pre_observer_failure"
    assert not any(token in item.lower() for item in seen for token in ("adb", "frida", "chrome", "msedge", "chromium"))


def test_d2_runtime_coverage_transports_and_latest_missing_does_not_borrow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(PLUGIN_SRC))
    from tests.test_rea_trace_extended import _call, _ctx, _envelope, _parsed, _request, _source

    trace = importlib.import_module("fxapk_rea.trace")
    evidence = importlib.import_module("fxapk_rea.evidence")
    supplement = importlib.import_module("fxapk_rea.supplement")
    from apkscan.core.web_observation_plan import build_plan
    from apkscan.core.web_supplement_runtime import apply_verified
    from apkscan.report.json import _to_jsonable

    raw = _envelope([
        _ctx(1, "u1", "FRAME-A", 1),
        _ctx(2, "u2", "FRAME-B", 2),
        _parsed("9", 2, 3),
        _request(
            "req", "FRAME-A", 4,
            {"callFrames": [], "parent": {"callFrames": [_call("9", 0, 0, "parent")]}},
            loader="LOAD-A",
        ),
    ], [_source("9", 3, 2, "function parent(){return 1}\n")])
    receipt, files = trace.project_trace(raw)
    assert receipt["coverage"]["status"] == "partial"
    bundle = tmp_path / "bundle"
    evidence.claim_output(bundle)
    trace._publish(bundle, raw, receipt, files)
    collected = supplement.run_supplement({"source": "bundle", "path": str(bundle)})
    assert collected["status"] == "ok"
    report = Report(
        package_name="com.example.synthetic",
        meta={"platform": "android", "web_observation_plan": build_plan(None, platform="android", meta={})},
        endpoints=[],
        leads=[],
        findings=[],
        analyzer_status=[],
    )
    runtime = apply_verified(
        report, collected["verified"],
        publish_dir=str(tmp_path / "out"), material_dir=str(bundle), live_cdp=False,
    )
    assert runtime["coverage"]["status"] == "partial"
    assert "click_attribution_unavailable" in runtime["coverage"]["gaps"]
    payload = _to_jsonable(report)
    canonical = payload["meta"]["web_supplement"]
    assert canonical["coverage"]["status"] == "partial"
    assert canonical["coverage"]["gaps"] == runtime["coverage"]["gaps"]
    digest = build_digest(payload)
    assert digest["web_supplement"]["coverage"]["status"] == "partial"
    assert digest["web_supplement"]["coverage"]["gaps"] == runtime["coverage"]["gaps"]

    older = {
        "status": "executed",
        "reason": "executed",
        "provider": "fxapk-cdp-trace",
        "coverage": {"status": "complete", "gaps": []},
    }
    latest = {"status": "executed", "reason": "executed", "provider": "fxapk-cdp-trace"}
    supplement_row = {
        "status": "executed",
        "reason": "executed",
        "provider": "fxapk-cdp-trace",
        "coverage": {"status": "complete", "gaps": []},
    }
    projected = project_plan_for_digest(
        {"status": "selected", "reason": "ok", "source": "cdp", "provider": "trace", "mode": "auto"},
        supplement_row,
        [older, latest],
    )
    handoff = projected["agent_handoff"]
    assert handoff.get("coverage_status") != "complete"
    assert older["coverage"]["status"] == "complete"
    assert supplement_row["coverage"]["status"] == "complete"
