"""Routing and failure taxonomy. Synthetic inputs only. No browser or device."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import BinaryIO

import pytest

from apkscan.core.models import AnalysisConfig
from apkscan.core.web_observation_plan import build_agent_handoff, parse_config
from apkscan.core.web_supplement_runtime import make_capture_observer


def _body(**extra: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "cdp",
        "path": "",
        "endpoint": "http://127.0.0.1:9222",
        "target": "synthetic-target",
        "exact_origins": ["http://127.0.0.1:9"],
        "provider": "trace",
        "observation_ms": 50,
        "authorized": True,
    }
    payload.update(extra)
    return payload


def test_related_targets_bool_rejects_malformed_and_actions() -> None:
    parsed, reason = parse_config(_body(related_targets=True))
    assert reason == ""
    assert parsed is not None and parsed.related_targets is True
    absent, _ = parse_config(_body())
    assert absent is not None and absent.related_targets is False
    for value in ("false", 1, None, "true"):
        _request, rejected = parse_config(_body(related_targets=value))
        assert rejected == "invalid_type"
    for field in ("navigate", "click_selector", "pause_related_start"):
        _request, rejected = parse_config(_body(**{field: "https://evil.example/run"}))
        assert rejected == "unknown_field"
        assert "evil" not in rejected


def test_make_capture_observer_forwards_related_targets() -> None:
    observer = make_capture_observer(AnalysisConfig(
        out_dir="out",
        web_supplement_request=_body(related_targets=True),
    ))
    assert observer is not None
    assert observer._request["related_targets"] is True
    assert "navigate" not in observer._request
    legacy = make_capture_observer(AnalysisConfig(
        out_dir="out",
        web_supplement_request=_body(),
    ))
    assert legacy is not None
    assert legacy._request["related_targets"] is False


def test_plugin_transports_related_targets_and_keeps_legacy_origins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    pytest.importorskip("websockets")
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement, supplement_worker

    seen: dict[str, object] = {}

    def fake_trace(*_args: object, **kwargs: object) -> None:
        seen["kwargs"] = kwargs

    monkeypatch.setattr("fxapk_rea.trace.run_trace", fake_trace)
    supplement._invoke_trace(
        "http://127.0.0.1:9222", "synthetic-target", ["http://127.0.0.1:9"], 50,
        tmp_path / "legacy", related_targets=True,
    )
    kwargs = seen["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["related_targets"] is True
    assert kwargs["related_origin"] is None
    assert kwargs["navigate"] is None
    assert kwargs["pause_related_start"] is False

    class Proc:
        pid = 81

        def poll(self) -> None:
            return None

    monkeypatch.setattr(supplement.subprocess, "Popen", lambda *_a, **_k: Proc())
    started = supplement.run_supplement({
        **_body(related_targets=True), "phase": "start", "out_dir": str(tmp_path),
    })
    assert started["status"] == "started"
    payload = json.loads((tmp_path / "web-supplement-cdp-request.json").read_text(encoding="utf-8"))
    assert payload["related_targets"] is True
    assert "navigate" not in payload
    supplement._LIVE.pop(81, None)
    supplement._OWNED_REQUESTS.pop(81, None)

    request_path = tmp_path / "worker.json"
    request_path.write_text(json.dumps({
        "source": "cdp", "authorized": True, "provider": "trace",
        "endpoint": "http://127.0.0.1:9222", "target": "synthetic-target",
        "exact_origins": ["http://127.0.0.1:9"], "observation_ms": 50,
        "out_dir": str(tmp_path / "worker-out"), "related_targets": True,
    }), encoding="utf-8")
    assert supplement_worker.main(["--request", str(request_path)]) == 0
    worker_kwargs = seen["kwargs"]
    assert isinstance(worker_kwargs, dict)
    assert worker_kwargs["related_targets"] is True


def test_worker_rejects_bad_flag_before_import(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement_worker

    guard = ModuleType("fxapk_rea.supplement")

    def _invoke_trace(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("imported")

    guard._invoke_trace = _invoke_trace  # type: ignore[attr-defined]
    monkeypatch.setitem(__import__("sys").modules, "fxapk_rea.supplement", guard)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({
        "source": "cdp", "authorized": True, "provider": "trace",
        "endpoint": "http://127.0.0.1:9222", "target": "synthetic-target",
        "exact_origins": ["http://127.0.0.1:9"], "observation_ms": 50,
        "out_dir": str(tmp_path / "out"), "related_targets": "false",
        "navigate": "http://evil.example/",
    }), encoding="utf-8")
    assert supplement_worker.main(["--request", str(path)]) == 2


def _marker(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "fxapk-rea-bundle.json").write_text(json.dumps({
        "schema_version": "fxapk-rea-bundle-marker/1",
        "kind": "unverified_external_observation_bundle",
    }), encoding="utf-8")


def _ready(directory: Path) -> None:
    (directory / "ready.json").write_text(json.dumps({
        "status": "ready", "debugger_enabled": True,
    }), encoding="utf-8")


def test_sync_failure_keeps_stable_reason_and_start_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    pytest.importorskip("websockets")
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea.evidence import EvidenceError
    from fxapk_rea import supplement

    def before_start(*_args: object, **_kwargs: object) -> None:
        out = tmp_path / "web-supplement-cdp"
        _marker(out)
        (out / "failure.json").write_text(json.dumps({
            "status": "failed",
            "reason": "trace_deadline",
            "target": "http://evil.example/secret",
        }), encoding="utf-8")
        raise EvidenceError("trace_oversize")

    monkeypatch.setattr(supplement, "_invoke_trace", before_start)
    early = supplement.run_supplement(_body(out_dir=str(tmp_path)))
    assert early["status"] == "failed"
    assert early["reason"] == "trace_deadline"
    assert early["live_cdp"] is False
    assert early["capture_started"] is False
    assert "evil" not in json.dumps(early)

    def after_start(*_args: object, **_kwargs: object) -> None:
        out = tmp_path / "later" / "web-supplement-cdp"
        _marker(out)
        _ready(out)
        (out / "cdp-trace-original.json").write_text(json.dumps({
            "origin": "http://evil.example",
            "capture": {"stopped_reason": "source_unavailable"},
        }), encoding="utf-8")
        raise EvidenceError("trace_cleanup_failed")

    monkeypatch.setattr(supplement, "_invoke_trace", after_start)
    late = supplement.run_supplement(_body(out_dir=str(tmp_path / "later")))
    assert late["status"] == "failed"
    assert late["reason"] == "source_unavailable"
    assert late["capture_started"] is True
    assert late["live_cdp"] is True
    assert "evil" not in json.dumps(late)


def _cdp_bundle(directory: Path) -> None:
    path = Path(__file__).with_name("test_rea_attach.py")
    spec = importlib.util.spec_from_file_location("rea_attach_bundle_helper", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing trace bundle helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._cdp_bundle(path, directory)


def test_collect_verifies_saved_trace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    bundle = tmp_path / "recorded"
    _cdp_bundle(bundle)
    _ready(bundle)
    assert (bundle / "cdp-trace-original.json").is_file()
    assert not (bundle / "failure.json").exists()
    result = supplement.run_supplement({"phase": "collect", "out_dir": str(bundle)})
    assert result["status"] == "ok"
    assert result["reason"] == "ok"
    assert result["verified"]["schema"] == "fxapk-cdp-trace-observation/1"
    assert result["capture_started"] is True
    assert result["live_cdp"] is True

    partial = tmp_path / "partial-stop"
    _marker(partial)
    _ready(partial)
    (partial / "cdp-trace-original.json").write_text(json.dumps({
        "origin": "http://evil.example",
        "capture": {"stopped_reason": "trace_deadline", "detail": "secret-window"},
    }), encoding="utf-8")
    stopped = supplement.run_supplement({"phase": "collect", "out_dir": str(partial)})
    assert stopped["status"] == "failed"
    assert stopped["reason"] == "trace_deadline"
    assert stopped["capture_started"] is True
    assert "secret-window" not in json.dumps(stopped)
    assert "evil" not in json.dumps(stopped)

    unknown = tmp_path / "unknown-stop"
    _marker(unknown)
    _ready(unknown)
    (unknown / "cdp-trace-original.json").write_text(json.dumps({
        "capture": {"stopped_reason": "secret-not-a-stable-reason"},
    }), encoding="utf-8")
    hidden = supplement.run_supplement({"phase": "collect", "out_dir": str(unknown)})
    assert hidden["status"] == "failed"
    assert hidden["reason"] == "bundle_rejected"
    assert "secret-not-a-stable-reason" not in json.dumps(hidden)


def test_collect_keeps_stopped_reason_between_failure_and_trace_caps(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A post-start trace between 64KiB and the 256KiB raw cap keeps its stable stop."""
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    bundle = tmp_path / "wide-stop"
    _marker(bundle)
    _ready(bundle)
    body = {
        "origin": "http://evil.example",
        "padding": "x" * (70 * 1024),
        "capture": {"stopped_reason": "trace_deadline", "detail": "secret-window"},
    }
    raw = json.dumps(body).encode("utf-8")
    assert supplement._MAX_FAILURE_BYTES < len(raw) <= supplement._MAX_TRACE_ORIGINAL_BYTES
    (bundle / "cdp-trace-original.json").write_bytes(raw)
    stopped = supplement.run_supplement({"phase": "collect", "out_dir": str(bundle)})
    assert stopped["status"] == "failed"
    assert stopped["reason"] == "trace_deadline"
    assert stopped["capture_started"] is True
    assert stopped["live_cdp"] is True
    assert "secret-window" not in json.dumps(stopped)
    assert "evil" not in json.dumps(stopped)
    assert "xxxx" not in json.dumps(stopped)


def test_read_object_rejects_growth_after_small_stat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A file that grows after a small stat is rejected, and the read stays at limit+1."""
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    limit = 32
    target = tmp_path / "grown.json"
    target.write_bytes(b'{"reason":"trace_deadline"}' + b"x" * (limit + 64))
    assert target.stat().st_size > limit
    real_stat = target.stat()
    reads: list[int] = []

    class _Stale:
        st_mode = real_stat.st_mode
        st_size = 1

    class _Bounded:
        def __init__(self, raw: BinaryIO) -> None:
            self._raw = raw

        def read(self, n: int = -1) -> bytes:
            reads.append(n)
            return self._raw.read(n)

        def __enter__(self) -> _Bounded:
            return self

        def __exit__(self, *_exc: object) -> None:
            self._raw.close()

    monkeypatch.setattr(Path, "stat", lambda self, *args, **kwargs: _Stale())
    real_open = Path.open

    def _open(self: Path, mode: str = "r", *_args: object, **_kwargs: object) -> _Bounded:
        assert mode == "rb"
        return _Bounded(real_open(self, "rb"))

    def _refuse_decode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("decoded")

    monkeypatch.setattr(Path, "open", _open)
    monkeypatch.setattr(supplement.json, "loads", _refuse_decode)
    assert supplement._read_object(target, limit=limit) is None
    assert reads and max(reads) <= limit + 1


def test_collect_keeps_partial_failure_reason(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(Path("plugins/fxapk-rea/src")))
    from fxapk_rea import supplement

    bundle = tmp_path / "bundle"
    _marker(bundle)
    _ready(bundle)
    (bundle / "failure.json").write_text(
        json.dumps({"status": "failed", "reason": "trace_oversize"}), encoding="utf-8",
    )
    result = supplement.run_supplement({"phase": "collect", "out_dir": str(bundle)})
    assert result["status"] == "failed"
    assert result["reason"] == "trace_oversize"
    assert result["capture_started"] is True
    assert result["live_cdp"] is True


def test_run_plugin_forwards_related_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    from apkscan.core import web_supplement as supplement

    seen: dict[str, object] = {}

    class Plugin:
        name = "rea"

        def run_supplement(self, request: dict[str, object]) -> dict[str, str]:
            seen["request"] = request
            return {"status": "skipped", "reason": "cdp_not_authorized"}

    monkeypatch.setattr(supplement, "_plugin", lambda: (Plugin(), ""))
    request, reason = parse_config(_body(related_targets=True))
    assert reason == "" and request is not None
    supplement._run_plugin(request, "out")
    forwarded = seen["request"]
    assert isinstance(forwarded, dict)
    assert forwarded["related_targets"] is True
    assert "navigate" not in forwarded


def test_existing_report_template_and_malformed_status() -> None:
    handoff = build_agent_handoff({
        "status": "skipped",
        "reason": "material_missing",
        "source": "bundle",
        "mode": "auto",
        "platform": "android",
        "agent_handoff": {"next_actions": [{"argv": ["curl", "https://evil.example"]}]},
    })
    assert handoff["next_actions"][0]["argv"] == [
        "fxapk", "supplement-web", "<report.json>", "--web-supplement", "<config>",
        "--out", "<new-out-dir>",
    ]
    assert handoff["authorization"] is False
    assert "evil" not in json.dumps(handoff)
    first = build_agent_handoff({
        "status": "pending", "reason": "no_config", "platform": "android", "mode": "off",
        "agent_handoff": {"next_actions": [{"argv": ["fxapk", "supplement-web", "raw-report.json"]}]},
    })
    assert [item["argv"][1] for item in first["next_actions"]] == ["analyze", "supplement-web"]
    assert first["next_actions"][0]["code"] == "prepare_web_supplement"
    assert "首次分析" in first["next_actions"][0]["instruction"]
    assert first["next_actions"][1]["code"] == "supplement_existing_report"
    assert first["next_actions"][1]["argv"] == [
        "fxapk", "supplement-web", "<report.json>", "--web-supplement", "<config>",
        "--out", "<new-out-dir>",
    ]
    assert "已有报告" in first["next_actions"][1]["instruction"]
    assert "raw-report.json" not in json.dumps(first)
    assert first["authorization"] is False
    off = build_agent_handoff({"status": "skipped", "reason": "mode_off", "mode": "off"})
    assert off["next_actions"] == []
    idle = build_agent_handoff({"status": "not_applicable", "reason": "no_config"})
    assert idle["next_actions"] == []
    bad = build_agent_handoff({"status": ["failed"], "reason": "trace_oversize"})
    assert bad["why"] == "unknown"
    assert bad["next_actions"][0]["argv"] == []
    assert "supplement-web" not in json.dumps([off, idle, bad])
