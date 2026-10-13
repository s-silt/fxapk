"""Dynamic web-supplement window: real ready file, isolated rounds, no unauthorized CDP."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, cast

import pytest

from apkscan.core.models import (
    ADVICE_INVESTIGATE,
    ADVICE_REVIEW,
    DOWNGRADE_EVIDENCE_SCOPE,
    AnalysisConfig,
    Confidence,
    Endpoint,
    Evidence,
    EvidenceScope,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.core.web_supplement_runtime import (
    SOURCE,
    CaptureWindowObserver,
    apply_verified,
    make_capture_observer,
    static_web_arguments,
)
from apkscan.core.web_supplement import project_for_digest
from apkscan.dynamic.auto import _web_observer_factory, _window_callbacks
from apkscan.dynamic import capture as capture_module
from apkscan.dynamic.capture import overlap_web_observation


class _Proc:
    def __init__(self) -> None:
        self.pid = 4242
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 1

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.returncode is None:
            raise AssertionError("wait without a real exit")
        return self.returncode


class _Plugin:
    def __init__(self, proc: _Proc, out: Path, *, write_ready: bool, verified: dict[str, Any] | None) -> None:
        self.name = "rea"
        self.proc = proc
        self.out = out
        self.write_ready = write_ready
        self.verified = verified
        self.phases: list[str] = []

    def run_supplement(self, request: dict[str, Any]) -> dict[str, Any]:
        phase = str(request.get("phase") or "")
        self.phases.append(phase)
        if phase == "start":
            if request.get("authorized") is not True:
                raise AssertionError("unauthorized start")
            if self.write_ready:
                ready = self.out / "ready.json"
                ready.parent.mkdir(parents=True, exist_ok=True)
                ready.write_text(json.dumps({
                    "status": "ready", "debugger_enabled": True, "capture_id": "synthetic",
                }), encoding="utf-8")
            return {
                "status": "started", "pid": self.proc.pid,
                "ready_path": str(self.out / "ready.json"), "out_dir": str(self.out),
            }
        if phase == "poll":
            return {"running": self.proc.poll() is None}
        if phase == "stop":
            self.proc.terminate()
            return {"stopped": self.proc.poll() is not None, "returncode": self.proc.returncode}
        if phase == "collect":
            if self.verified is None:
                return {"status": "failed", "reason": "target_unavailable", "live_cdp": True}
            return {"status": "ok", "reason": "ok", "verified": self.verified, "live_cdp": True}
        raise AssertionError(phase)


def _report() -> Report:
    return Report(
        package_name="com.example.synthetic",
        meta={"_web_supplement_raws": []},
        leads=[],
        endpoints=[Endpoint(value="203.0.113.10", kind="ip", evidences=[
            Evidence(source="runtime-pcap", location="pcap"),
        ])],
        findings=[],
        analyzer_status=[],
    )


def _install(monkeypatch: pytest.MonkeyPatch, plugin: _Plugin | None) -> None:
    def load() -> tuple[_Plugin | None, str]:
        if plugin is None:
            return None, "plugin_unavailable"
        return plugin, ""

    monkeypatch.setattr("apkscan.core.web_supplement_runtime._load_plugin", load)


def _verified_runtime_bundle(tmp_path: Path) -> dict[str, Any]:
    """Build a verifiable bundle in tmp. No ignored out/ live directory."""
    from tests.test_web_supplement import _bundle

    root = tmp_path / "synthetic-bundle"
    root.mkdir()
    script = 'var API_BASE = "https://runtime-only.example.test/only-supplement";\n'
    bundle = _bundle(root, script)
    from fxapk_rea.supplement import run_supplement

    collected = run_supplement({"source": "bundle", "path": str(bundle)})
    assert collected["status"] == "ok"
    verified = collected["verified"]
    assert isinstance(verified, dict)
    return verified


def _request(tmp_path: Path) -> dict[str, Any]:
    return {
        "schema_version": "fxapk.web_supplement.v1",
        "source": "cdp",
        "endpoint": "http://127.0.0.1:9222",
        "target": "synthetic-target",
        "exact_origins": ["http://127.0.0.1:9"],
        "provider": "trace",
        "observation_ms": 50,
        "authorized": True,
        "out_dir": str(tmp_path / "round"),
    }


def test_static_live_config_is_deferred(tmp_path: Path) -> None:
    payload = {
        "schema_version": "fxapk.web_supplement.v1", "mode": "auto", "source": "cdp",
        "endpoint": "http://127.0.0.1:9222", "target": "synthetic-target",
        "exact_origins": ["http://127.0.0.1:9"], "provider": "trace",
        "observation_ms": 50, "authorized": True,
    }
    path = tmp_path / "live.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert static_web_arguments(str(path), None) == (None, None)
    assert static_web_arguments(None, {**payload, "mode": "off"})[1] is not None


def test_missing_plugin_keeps_ui(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(capture_module, "_READY_STARTUP_SEC", 0.03)
    _install(monkeypatch, None)
    calls: list[str] = []
    observer = CaptureWindowObserver(_request(tmp_path), publish_dir=str(tmp_path))
    result = overlap_web_observation(
        interaction=lambda **_kwargs: calls.append("ui"),
        web_observer=observer, deadline=None, window_seconds=0.05,
    )
    assert calls == ["ui"]
    assert result is not None
    assert result["status"] == "unavailable"
    assert result["reason"] == "plugin_unavailable"


def test_timeout_keeps_ui_and_does_not_invent_ready(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(capture_module, "_READY_STARTUP_SEC", 0.03)
    proc = _Proc()
    material = tmp_path / "cdp"
    plugin = _Plugin(proc, material, write_ready=False, verified=None)
    _install(monkeypatch, plugin)
    calls: list[str] = []
    observer = CaptureWindowObserver(_request(tmp_path), publish_dir=str(tmp_path))
    result = overlap_web_observation(
        interaction=lambda **_kwargs: calls.append("ui"),
        web_observer=observer, deadline=None, window_seconds=1.0,
    )
    assert calls == ["ui"]
    assert result is not None
    assert result["status"] == "failed"
    assert result["reason"] == "timeout"
    assert proc.terminated is True
    assert "start" in plugin.phases and "stop" in plugin.phases
    assert not (material / "ready.json").exists()


def test_ready_file_backfills_report_without_bytes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    verified = _verified_runtime_bundle(tmp_path)
    proc = _Proc()
    material = tmp_path / "round-a" / "web-supplement-cdp"
    plugin = _Plugin(proc, material, write_ready=True, verified=verified)
    _install(monkeypatch, plugin)
    report = _report()
    calls: list[str] = []
    observer = CaptureWindowObserver(
        {**_request(tmp_path), "out_dir": str(tmp_path / "round-a")},
        report=report, publish_dir=str(tmp_path / "publish"),
    )
    result = overlap_web_observation(
        interaction=lambda **_kwargs: calls.append("ui"),
        web_observer=observer, deadline=None, window_seconds=0.5,
    )
    assert calls == ["ui"]
    assert result is not None
    assert result["status"] == "executed"
    assert result["provenance"] == SOURCE
    encoded = json.dumps(result)
    assert "verified" not in result
    assert "b'" not in encoded
    assert result["raw_sha256"]
    assert any(ep.value == "runtime-only.example.test" for ep in report.endpoints)
    assert any(item.confidence.value == "LOW" for item in report.findings)
    again = CaptureWindowObserver(
        {**_request(tmp_path), "out_dir": str(tmp_path / "round-b")},
        report=report, publish_dir=str(tmp_path / "publish"),
    )
    _Plugin(proc, tmp_path / "round-b", write_ready=True, verified=verified)
    second_plugin = _Plugin(proc, tmp_path / "round-b", write_ready=True, verified=verified)
    _install(monkeypatch, second_plugin)
    second = overlap_web_observation(
        interaction=lambda **_kwargs: calls.append("ui"),
        web_observer=again, deadline=None, window_seconds=0.5,
    )
    assert second is not None
    assert second["reason"] == "duplicate_raw"
    assert [ep.value for ep in report.endpoints].count("runtime-only.example.test") == 1


def test_rounds_use_distinct_dirs_and_skip_unauthorized(tmp_path: Path) -> None:
    live = {
        "schema_version": "fxapk.web_supplement.v1", "mode": "auto", "source": "cdp",
        "endpoint": "http://127.0.0.1:9222", "target": "synthetic-target",
        "exact_origins": ["http://127.0.0.1:9"], "provider": "trace",
        "observation_ms": 50, "authorized": True,
    }
    factory = _web_observer_factory(str(tmp_path / "case"), None, live, report=_report())
    assert factory is not None
    observers = [factory(number, kind, tmp_path / f"round{number}-{kind}") for number, kind in (
        (1, "pcap"), (2, "probe"), (3, "targeted"),
    )]
    dirs = [getattr(item, "round_dir") for item in observers]
    assert None not in dirs
    assert len(set(dirs)) == 3
    denied = make_capture_observer(AnalysisConfig(
        out_dir=str(tmp_path), web_supplement_request={**live, "authorized": False},
    ))
    assert denied is not None
    assert denied.finish()["reason"] == "cdp_not_authorized"


def test_callbacks_keep_during_round_and_android_plugin() -> None:
    seen: list[str] = []

    def during_round(*_args: object, **_kwargs: object) -> str:
        seen.append("during")
        return "during"

    class Plugin:
        def run_round(self, _context: object) -> str:
            seen.append("plugin")
            return "plugin"

    bound = _window_callbacks(
        during_round, cast(Any, Plugin()), serial="synthetic", package_name="example.synthetic",
        sample_sha256=None,
    )
    assert bound is not None
    assert bound(1, "pcap", "single", Path("round"), deadline_monotonic=1.0) == "plugin"
    assert seen == ["during", "plugin"]


def test_six_second_window_shortens_60s_config_and_keeps_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    verified = _verified_runtime_bundle(tmp_path)
    recorded: dict[str, int] = {}

    class Bounded:
        name = "rea"

        def run_supplement(self, request: dict[str, Any]) -> dict[str, Any]:
            phase = str(request.get("phase") or "")
            if phase == "start":
                recorded["ms"] = int(request["observation_ms"])
                if recorded["ms"] >= 10_000:
                    raise AssertionError("60s observation was dispatched into a 6s window")
                out = tmp_path / "bounded"
                out.mkdir()
                (out / "ready.json").write_text(
                    json.dumps({"status": "ready", "debugger_enabled": True}), encoding="utf-8",
                )
                return {"status": "started", "pid": 1, "ready_path": str(out / "ready.json"), "out_dir": str(out)}
            if phase == "poll":
                return {"running": False}
            if phase == "stop":
                return {"stopped": True, "returncode": 0}
            if phase == "collect":
                return {"status": "ok", "verified": verified, "live_cdp": True}
            raise AssertionError(phase)

    _install(monkeypatch, Bounded())  # type: ignore[arg-type]
    report = _report()
    started = time.monotonic()
    result = overlap_web_observation(
        interaction=lambda **_kwargs: {"status": "complete"},
        web_observer=CaptureWindowObserver(
            {**_request(tmp_path), "observation_ms": 60_000, "out_dir": str(tmp_path / "window")},
            report=report, publish_dir=str(tmp_path / "publish"),
        ),
        deadline=started + 6,
        window_seconds=6,
    )
    elapsed = time.monotonic() - started
    assert recorded["ms"] < 6_000
    assert result is not None
    assert result["status"] == "executed"
    assert result["observation_ms"] == recorded["ms"]
    assert "observation_limit" in result
    assert elapsed < 8.5
    assert any(ep.value == "runtime-only.example.test" for ep in report.endpoints)
    digest = project_for_digest(report.meta["web_supplement"])
    assert digest["status"] == "executed"
    assert digest["raw_sha256"]
    assert "material_path" not in digest
    assert "artifact_sha256" not in digest
    assert all(
        evidence.scope.name == "BATCH_REFERENCE"
        for finding in report.findings for evidence in finding.evidences
    )


def _cdp_request(tmp_path: Path, origins: list[str]) -> dict[str, object]:
    return {
        "source": "cdp", "authorized": True, "endpoint": "http://127.0.0.1:9222",
        "target": "synthetic-target", "exact_origins": origins, "provider": "trace",
        "observation_ms": 50, "out_dir": str(tmp_path),
    }


def test_sync_cdp_keeps_every_origin_and_disables_actions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    pytest.importorskip("websockets")
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    seen: dict[str, object] = {}
    original = supplement._invoke_trace

    def fake_invoke(endpoint: str, target: str, origins: list[str], observation_ms: int, out: Path) -> None:
        seen["passed"] = (endpoint, target, origins, observation_ms)
        out.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(supplement, "_invoke_trace", fake_invoke)
    monkeypatch.setattr(supplement, "_verify_bundle", lambda _path: {"verified": True})
    first = "http://127.0.0.1:9"
    second = "http://127.0.0.1:10"
    result = supplement.run_supplement(_cdp_request(tmp_path, [first, second]))
    assert result["status"] == "ok"
    assert result["live_cdp"] is True
    passed = seen["passed"]
    assert isinstance(passed, tuple)
    assert passed[2] == [first, second]

    def fake_trace(*_args: object, **kwargs: object) -> None:
        seen["kwargs"] = kwargs

    monkeypatch.setattr("fxapk_rea.trace.run_trace", fake_trace)
    original("http://127.0.0.1:9222", "synthetic-target", [first, second], 50, tmp_path / "trace")
    kwargs = seen["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["related_targets"] is True
    assert kwargs["related_origin"] == [second]
    assert kwargs["pause_related_start"] is False
    assert kwargs["navigate"] is None
    assert kwargs["click_selector"] is None


def test_dynamic_collect_does_not_upgrade_unstarted_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    class Plugin:
        name = "rea"

        def run_supplement(self, request: dict[str, Any]) -> dict[str, Any]:
            phase = str(request.get("phase") or "")
            if phase == "start":
                return {
                    "status": "started", "pid": 1,
                    "ready_path": str(tmp_path / "missing-ready.json"),
                    "out_dir": str(tmp_path / "partial"),
                }
            if phase == "poll":
                return {"running": False}
            if phase == "stop":
                return {"stopped": True, "returncode": 1}
            if phase == "collect":
                return {
                    "status": "failed", "reason": "trace_oversize",
                    "live_cdp": True, "capture_started": False,
                }
            raise AssertionError(phase)

    _install(monkeypatch, Plugin())  # type: ignore[arg-type]
    report = _report()
    observer = CaptureWindowObserver(
        {**_request(tmp_path), "observation_ms": 0, "out_dir": str(tmp_path)},
        report=report, publish_dir=str(tmp_path / "publish"),
    )
    result = observer._stop_and_collect(Plugin(), 1, str(tmp_path / "partial"))
    assert result["status"] == "failed"
    assert result["reason"] == "trace_oversize"
    assert result["capture_started"] is False
    assert result["live_cdp"] is False
    assert "secret" not in json.dumps(result)


def test_sync_single_origin_does_not_enable_related_targets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    seen: dict[str, object] = {}

    def fake_trace(*_args: object, **kwargs: object) -> None:
        seen["kwargs"] = kwargs

    monkeypatch.setattr("fxapk_rea.trace.run_trace", fake_trace)
    supplement._invoke_trace("http://127.0.0.1:9222", "t", ["http://127.0.0.1:9"], 50, tmp_path / "one")
    kwargs = seen["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["related_targets"] is False
    assert kwargs["related_origin"] is None
    assert kwargs["pause_related_start"] is False


def test_too_many_origins_reject_without_trace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("trace called")

    monkeypatch.setattr(supplement, "_invoke_trace", denied)
    origins = [f"http://127.0.0.1:{port}" for port in range(9, 19)]
    result = supplement.run_supplement(_cdp_request(tmp_path, origins))
    assert result["status"] == "failed"
    assert result["reason"] == "config_rejected"
    assert result["live_cdp"] is False


def test_start_does_not_overwrite_request_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pytest.importorskip("websockets")
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("spawned")

    monkeypatch.setattr(supplement.subprocess, "Popen", denied)
    request = tmp_path / "web-supplement-cdp-request.json"
    request.write_text("owned-original", encoding="utf-8")
    result = supplement.run_supplement({**_cdp_request(tmp_path, ["http://127.0.0.1:9"]), "phase": "start"})
    assert result["reason"] == "publish_conflict"
    assert request.read_text(encoding="utf-8") == "owned-original"


def _spawned_creationflags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, platform: str, pid: int,
) -> int:
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    seen: dict[str, int] = {}

    class Proc:
        def __init__(self) -> None:
            self.pid = pid

        def poll(self) -> None:
            return None

    def fake_popen(*_args: object, **kwargs: object) -> Proc:
        flags = kwargs.get("creationflags", 0)
        seen["flags"] = flags if isinstance(flags, int) else 0
        return Proc()

    monkeypatch.setattr(supplement.sys, "platform", platform)
    monkeypatch.setattr(supplement.subprocess, "Popen", fake_popen)
    result = supplement.run_supplement({**_cdp_request(tmp_path, ["http://127.0.0.1:9"]), "phase": "start"})
    assert result["status"] == "started"
    supplement._LIVE.pop(pid, None)
    supplement._OWNED_REQUESTS.pop(pid, None)
    return seen["flags"]


def test_windows_spawn_passes_nonzero_hidden_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    pytest.importorskip("websockets")
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    hidden = 0x08000000
    group = 0x00000200
    monkeypatch.setattr(supplement.subprocess, "CREATE_NO_WINDOW", hidden, raising=False)
    monkeypatch.setattr(supplement.subprocess, "CREATE_NEW_PROCESS_GROUP", group, raising=False)
    flags = _spawned_creationflags(monkeypatch, tmp_path, platform="win32", pid=77)
    assert flags & hidden
    assert flags & group


def test_non_windows_spawn_passes_zero_creationflags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    pytest.importorskip("websockets")
    flags = _spawned_creationflags(monkeypatch, tmp_path, platform="linux", pid=79)
    assert flags == 0


def test_start_payload_keeps_every_origin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pytest.importorskip("websockets")
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    class Proc:
        pid = 78

        def poll(self) -> None:
            return None

    monkeypatch.setattr(supplement.subprocess, "Popen", lambda *_a, **_k: Proc())
    first = "http://127.0.0.1:9"
    second = "http://127.0.0.1:10"
    result = supplement.run_supplement({**_cdp_request(tmp_path, [first, second]), "phase": "start"})
    assert result["status"] == "started"
    payload = json.loads((tmp_path / "web-supplement-cdp-request.json").read_text(encoding="utf-8"))
    assert payload["exact_origins"] == [first, second]
    supplement._LIVE.pop(78, None)
    supplement._OWNED_REQUESTS.pop(78, None)


def test_start_reports_occupied_output_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pytest.importorskip("websockets")
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("spawned")

    monkeypatch.setattr(supplement.subprocess, "Popen", denied)
    occupied = tmp_path / "web-supplement-cdp"
    occupied.mkdir()
    marker = occupied / "marker.txt"
    marker.write_text("kept", encoding="utf-8")
    result = supplement.run_supplement({**_cdp_request(tmp_path, ["http://127.0.0.1:9"]), "phase": "start"})
    assert result["status"] == "failed"
    assert result["reason"] == "publish_conflict"
    assert marker.read_text(encoding="utf-8") == "kept"


def test_sync_reports_occupied_output_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pytest.importorskip("websockets")
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("trace called")

    monkeypatch.setattr(supplement, "_invoke_trace", denied)
    occupied = tmp_path / "web-supplement-cdp"
    occupied.mkdir()
    result = supplement.run_supplement(_cdp_request(tmp_path, ["http://127.0.0.1:9"]))
    assert result["status"] == "failed"
    assert result["reason"] == "publish_conflict"
    assert result["live_cdp"] is False


def test_start_does_not_overwrite_request_symlink(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pytest.importorskip("websockets")
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("spawned")

    monkeypatch.setattr(supplement.subprocess, "Popen", denied)
    published = {"called": False}

    def refuse_publish(path: Path, data: bytes) -> bool:
        del path, data
        published["called"] = True
        raise AssertionError("request publication ran")

    monkeypatch.setattr(supplement, "atomic_create_bytes", refuse_publish)
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("do-not-touch", encoding="utf-8")
    link = tmp_path / "web-supplement-cdp-request.json"
    real_link = False
    try:
        link.symlink_to(sentinel)
        real_link = True
    except OSError:
        original = Path.is_symlink

        def fake_is_symlink(self: Path) -> bool:
            return self == link or original(self)

        monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)
    result = supplement.run_supplement({**_cdp_request(tmp_path, ["http://127.0.0.1:9"]), "phase": "start"})
    assert result["status"] == "failed"
    assert result["reason"] == "publish_conflict"
    assert published["called"] is False
    assert sentinel.read_text(encoding="utf-8") == "do-not-touch"
    if real_link:
        assert link.is_symlink()
    else:
        assert not link.exists()


def test_worker_passes_every_origin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement_worker

    seen: dict[str, object] = {}

    def fake_invoke(endpoint: str, target: str, origins: list[str], observation_ms: int, out: Path) -> None:
        del endpoint, target, observation_ms, out
        seen["origins"] = origins

    monkeypatch.setattr("fxapk_rea.supplement._invoke_trace", fake_invoke)
    first = "http://127.0.0.1:9"
    second = "http://127.0.0.1:10"
    request = tmp_path / "request.json"
    request.write_text(json.dumps({
        "source": "cdp", "authorized": True, "endpoint": "http://127.0.0.1:9222",
        "target": "synthetic-target", "exact_origins": [first, second],
        "provider": "trace", "observation_ms": 50, "out_dir": str(tmp_path / "out"),
    }), encoding="utf-8")
    assert supplement_worker.main(["--request", str(request)]) == 0
    assert seen["origins"] == [first, second]


def test_apply_verified_keeps_high_lead_and_duplicate_raw(tmp_path: Path) -> None:
    verified = _verified_runtime_bundle(tmp_path)
    original = Lead(
        category=LeadCategory.DOMAIN,
        value="runtime-only.example.test",
        confidence=Confidence.HIGH,
        advice=ADVICE_INVESTIGATE,
        base_advice=ADVICE_INVESTIGATE,
        source_refs=[Evidence(
            source="dex", location="classes.dex", snippet="runtime-only.example.test",
            scope=EvidenceScope.CASE_EVIDENCE,
        )],
        downgrades={DOWNGRADE_EVIDENCE_SCOPE: "prior-case-downgrade"},
    )
    report = Report(
        package_name="com.example.synthetic", meta={}, leads=[original],
        endpoints=[], findings=[], analyzer_status=[],
    )
    first = apply_verified(
        report, verified, publish_dir=str(tmp_path / "publish"),
        material_dir=str(tmp_path / "material"), live_cdp=True,
    )
    assert first["status"] == "executed"
    same = [
        lead for lead in report.leads
        if lead.category is LeadCategory.DOMAIN and lead.value == "runtime-only.example.test"
    ]
    assert same == [original]
    assert original.confidence is Confidence.HIGH
    assert original.advice == ADVICE_INVESTIGATE
    assert original.base_advice == ADVICE_INVESTIGATE
    assert original.downgrades == {DOWNGRADE_EVIDENCE_SCOPE: "prior-case-downgrade"}
    assert original.source_refs[0].source == "dex"
    assert original.source_refs[0].scope is EvidenceScope.CASE_EVIDENCE
    configs = [lead for lead in report.leads if lead.category is LeadCategory.CONFIG_KEY]
    assert configs
    assert all(
        lead.base_advice == lead.advice == ADVICE_REVIEW and lead.confidence is Confidence.LOW
        for lead in configs
    )
    assert all(
        ev.scope is EvidenceScope.BATCH_REFERENCE for lead in configs for ev in lead.source_refs
    )
    assert [ep.value for ep in report.endpoints].count("runtime-only.example.test") == 1
    finding_count = len(report.findings)
    second = apply_verified(
        report, verified, publish_dir=str(tmp_path / "publish"),
        material_dir=str(tmp_path / "material"), live_cdp=True,
    )
    assert second["reason"] == "duplicate_raw"
    assert [
        lead for lead in report.leads
        if lead.category is LeadCategory.DOMAIN and lead.value == "runtime-only.example.test"
    ] == [original]
    assert original.confidence is Confidence.HIGH
    assert original.advice == ADVICE_INVESTIGATE
    assert original.base_advice == ADVICE_INVESTIGATE
    assert original.downgrades == {DOWNGRADE_EVIDENCE_SCOPE: "prior-case-downgrade"}
    assert [lead for lead in report.leads if lead.category is LeadCategory.CONFIG_KEY] == configs
    assert all(lead.base_advice == lead.advice == ADVICE_REVIEW for lead in configs)
    assert [ep.value for ep in report.endpoints].count("runtime-only.example.test") == 1
    assert len(report.findings) == finding_count


def test_digest_projection_drops_relation_text_and_targets() -> None:
    planted = "http://127.0.0.1:9/synthetic-target"
    digest = project_for_digest({
        "status": "executed",
        "reason": "executed",
        "provider": "trace",
        "parse_counts": {"endpoints": 1, "config_leads": 0, "relations": 2, "scripts": 0},
        "round_id": "single",
        "raw_sha256": ["a" * 64],
        "relations": [{"note": planted}],
        "summary_line": planted,
        "material_path": planted,
        "target": planted,
        "relative_paths": [planted],
    })
    assert planted not in json.dumps(digest)
    assert digest["parse_counts"]["relations"] == 2
    assert "material_path" not in digest
    assert "relations" not in digest


def test_supplement_start_does_not_spawn_when_unauthorized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("spawned")

    monkeypatch.setattr(supplement.subprocess, "Popen", denied)
    result = supplement.run_supplement({
        "phase": "start", "source": "cdp", "authorized": False,
        "endpoint": "http://127.0.0.1:9222", "target": "t",
        "exact_origins": ["http://127.0.0.1:9"], "provider": "trace", "observation_ms": 10,
    })
    assert result["reason"] == "cdp_not_authorized"
    assert result["live_cdp"] is False


def test_stop_does_not_claim_success_when_process_survives(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    class Stuck(_Proc):
        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            raise subprocess_timeout()

    import subprocess

    def subprocess_timeout() -> BaseException:
        return subprocess.TimeoutExpired(cmd="worker", timeout=2)

    proc = Stuck()
    proc.pid = 7
    supplement._LIVE[7] = proc  # type: ignore[assignment]
    stopped = supplement.run_supplement({"phase": "stop", "pid": 7})
    assert stopped["stopped"] is False
    assert proc.killed is True
    assert supplement._LIVE[7] is proc
    supplement._LIVE.pop(7, None)


def test_runtime_receipt_keeps_capture_started(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    verified = _verified_runtime_bundle(tmp_path)
    proc = _Proc()
    material = tmp_path / "round-c" / "web-supplement-cdp"
    plugin = _Plugin(proc, material, write_ready=True, verified=verified)
    _install(monkeypatch, plugin)
    report = _report()
    observer = CaptureWindowObserver(
        {**_request(tmp_path), "out_dir": str(tmp_path / "round-c")},
        report=report, publish_dir=str(tmp_path / "publish"),
    )
    result = overlap_web_observation(
        interaction=None, web_observer=observer, deadline=None, window_seconds=0.3,
    )
    assert result is not None
    assert result["status"] == "executed"
    rounds = report.meta["web_supplement_runtime"]
    assert rounds[-1]["capture_started"] is True
    assert report.meta["web_supplement"]["boundary"]["capture_started"] is True


def test_observer_branch_records_interaction_receipt(tmp_path: Path) -> None:
    class Observer:
        def start(self, deadline: float | None) -> None:
            del deadline

        def wait_ready(self, deadline: float | None) -> str:
            del deadline
            return "ready"

        def finish(self) -> dict[str, Any]:
            return {"status": "skipped", "reason": "not_live_cdp", "live_cdp": False}

    ui_observations: list[dict[str, Any]] = []
    playbook: list[str] = []
    warnings: list[str] = []
    overlap_web_observation(
        interaction=lambda **_kwargs: {"action": "tap", "selector": "#ok"},
        web_observer=Observer(),
        deadline=None,
        window_seconds=0.05,
        ui_observations=ui_observations,
        playbook=playbook,
        warnings=warnings,
        pass_tag="pcap",
    )
    assert [item["action"] for item in ui_observations] == ["tap"]
    assert ui_observations[0]["status"] == "complete"
    assert ui_observations[0]["round_id"] == "pcap"
    assert playbook == ["UI interaction completed: dict"]
