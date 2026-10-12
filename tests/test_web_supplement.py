"""Automatic web supplement from the real pipeline and CLI. Synthetic inputs only."""

from __future__ import annotations

import importlib
import json
import socket
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan.core.models import (
    ADVICE_INVESTIGATE,
    ADVICE_REVIEW,
    OBSERVED_CONTACT_SOURCES,
    AnalysisConfig,
    Confidence,
    Endpoint,
    Evidence,
    Lead,
    LeadCategory,
)
from apkscan.core.web_supplement import (
    SOURCE,
    clamp_web_only_leads,
    merge_candidates,
    project_for_digest,
)
from apkscan.core.webctx import WebContext
from apkscan.dynamic.capture import overlap_web_observation
from apkscan.dynamic.capture_sequence import run_rounds
from apkscan.report.digest import build_digest


MARKER = "MALICIOUS-FREE-TEXT-NOT-FOR-DIGEST"


def test_source_is_outside_runtime_and_observed_contact() -> None:
    assert not SOURCE.startswith("runtime")
    assert SOURCE not in OBSERVED_CONTACT_SOURCES


def test_pipeline_without_config_does_not_call_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"n": 0}

    def boom() -> tuple[list[object], list[dict[str, str]]]:
        called["n"] += 1
        return [], []

    monkeypatch.setattr("apkscan.core.web_supplement.discover_plugins", boom)
    from apkscan.core import pipeline

    ctx = WebContext(AnalysisConfig(online=False, out_dir="out"), files={"web/index.html": b"<html></html>"})
    report = pipeline.run(ctx, ctx.config)  # type: ignore[arg-type]
    assert called["n"] == 0
    assert report.meta["web_observation_plan"]["execute"] is False
    assert report.meta["web_supplement"]["parse_counts"]["endpoints"] == 0
    assert all(ev.source != SOURCE for ep in report.endpoints for ev in ep.evidences)


def _observation(script: str) -> dict:
    return {
        "ok": True,
        "data": {
            "operation": "inspect_web_page",
            "predicate_type": "rea.web-page-inspection",
            "provider": {"id": "rea-cdp-browser", "version": "2"},
            "parameters": {
                "target_id": "synthetic-target",
                "observation_ms": 1000,
                "allowed_origins": ["http://127.0.0.1:9"],
            },
            "normalized_result": {
                "target": {"target_id": "synthetic-target", "origin": "http://127.0.0.1:9", "url": "http://127.0.0.1:9/"},
                "capture_window": {
                    "started_at": "2026-10-11T12:00:00Z",
                    "ended_at": "2026-10-11T12:00:01Z",
                    "observation_ms": 1000,
                },
                "completeness": {"status": "policy_filtered", "conditions": ["attach_limited"], "dropped_events": {"total": 0}},
                "frames": [{"frame_id": "synthetic-frame", "parent_frame_id": None, "url": "http://127.0.0.1:9/", "origin": "http://127.0.0.1:9"}],
                "scripts": {"items": [{
                    "url": "http://127.0.0.1:9/app.js",
                    "frame_id": "synthetic-frame",
                    "origin": "http://127.0.0.1:9",
                    "source": {"included": True, "artifact": {
                        "text": script,
                        "sha256": __import__("hashlib").sha256(script.encode()).hexdigest(),
                        "bytes": len(script.encode()),
                        "media_type": "text/javascript",
                    }},
                }]},
                "network": {"requests": [{
                    "request_id": "1",
                    "url": "http://127.0.0.1:9/only-request",
                    "origin": "http://127.0.0.1:9",
                    "method": "GET",
                    "status": 200,
                    "initiator": {"type": "script", "url": "http://127.0.0.1:9/app.js", "line": 0, "column": 0},
                }]},
                "console": {"prior_activity_available": False, "events": [{"timestamp": None, "type": "log", "text": MARKER}]},
                "limitations": [MARKER],
            },
            "limitations": [MARKER],
        },
    }


def _bundle(tmp_path: Path, script: str) -> Path:
    importlib.import_module("apkscan.plugins.registry")
    src = Path(__file__).parents[1] / "plugins/fxapk-rea/src"
    import sys
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    evidence = importlib.import_module("fxapk_rea.evidence")
    raw = tmp_path / "source.json"
    raw.write_bytes((json.dumps(_observation(script)) + "\n").encode())
    out = tmp_path / "bundle"
    evidence.import_observation(raw, out)
    return out


def _install_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    src = Path(__file__).parents[1] / "plugins/fxapk-rea/src"
    monkeypatch.syspath_prepend(str(src))
    plugin = importlib.import_module("fxapk_rea.plugin")

    def discover() -> tuple[list[object], list[dict[str, str]]]:
        return [plugin.plugin_factory()], [{"name": "rea", "status": "ok", "reason": ""}]

    monkeypatch.setattr("apkscan.core.web_supplement.discover_plugins", discover)


def test_analyze_web_auto_adds_candidate_and_off_does_not(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_plugin(monkeypatch)
    script = 'var API_BASE = "http://127.0.0.1:9/only-supplement";\n'
    bundle = _bundle(tmp_path, script)
    evidence = tmp_path / "html"
    evidence.mkdir()
    (evidence / "index.html").write_text("<html><body>plain</body></html>", encoding="utf-8")
    config = tmp_path / "supplement.json"
    config.write_text(json.dumps({
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": str(bundle),
    }), encoding="utf-8")
    from apkscan import cli

    out = tmp_path / "out"
    result = CliRunner().invoke(cli.app, [
        "analyze-web", str(evidence), "--out", str(out), "--fmt", "json", "--offline",
        "--web-supplement", str(config),
    ])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "html.json").read_text(encoding="utf-8"))
    blob = json.dumps(report)
    assert "only-supplement" in blob
    assert "only-request" in blob
    assert MARKER not in blob
    assert report["meta"]["closure"].get("status", "partial") != "complete" if isinstance(report["meta"].get("closure"), dict) else True
    sources = [ev.get("source") for ep in report["endpoints"] for ev in ep.get("evidences") or []]
    assert SOURCE in sources
    assert not any(str(source).startswith("runtime") for source in sources if source == SOURCE)
    digest = build_digest(report)
    assert MARKER not in json.dumps(digest)
    assert "已自动补采解析" in digest["web_supplement"]["summary_line"]
    assert digest["web_supplement"]["closure_evaluated"] is False
    assert digest["web_supplement"]["status"] != "complete"

    off = tmp_path / "off.json"
    off.write_text(json.dumps({
        "schema_version": "fxapk.web_supplement.v1", "mode": "off", "source": "bundle", "path": str(bundle),
    }), encoding="utf-8")
    out2 = tmp_path / "out-off"
    result = CliRunner().invoke(cli.app, [
        "analyze-web", str(evidence), "--out", str(out2), "--fmt", "json", "--offline",
        "--web-supplement", str(off),
    ])
    assert result.exit_code == 0, result.output
    report2 = json.loads((out2 / "html.json").read_text(encoding="utf-8"))
    assert "only-supplement" not in json.dumps(report2["endpoints"])


def test_missing_plugin_keeps_main_flow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "apkscan.core.web_supplement.discover_plugins",
        lambda: ([], [{"name": "rea", "status": "unavailable", "reason": "plugin_unavailable"}]),
    )
    evidence = tmp_path / "html"
    evidence.mkdir()
    (evidence / "index.html").write_text("<html></html>", encoding="utf-8")
    config = tmp_path / "supplement.json"
    config.write_text(json.dumps({
        "schema_version": "fxapk.web_supplement.v1", "mode": "auto", "source": "bundle", "path": str(tmp_path / "missing"),
    }), encoding="utf-8")
    from apkscan.core import pipeline

    ctx = WebContext(
        AnalysisConfig(online=False, out_dir=str(tmp_path / "out"), web_supplement=str(config)),
        files={"web/index.html": (evidence / "index.html").read_bytes()},
    )
    report = pipeline.run(ctx, ctx.config)  # type: ignore[arg-type]
    assert report.meta["web_supplement"]["reason"] == "plugin_unavailable"
    assert report.analysis_status in {"complete", "partial"}


def test_tamper_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_plugin(monkeypatch)
    bundle = _bundle(tmp_path, 'var API_BASE = "http://127.0.0.1:9/only-supplement";\n')
    script = next((bundle / "scripts").glob("*.js"))
    script.write_bytes(script.read_bytes() + b"x")
    from apkscan.core import pipeline

    ctx = WebContext(
        AnalysisConfig(online=False, out_dir=str(tmp_path / "out"), web_supplement_request={
            "schema_version": "fxapk.web_supplement.v1", "mode": "auto", "source": "bundle", "path": str(bundle),
        }),
        files={"web/index.html": b"<html></html>"},
    )
    report = pipeline.run(ctx, ctx.config)  # type: ignore[arg-type]
    assert report.meta["web_supplement"]["status"] in {"skipped", "failed"}
    assert "only-supplement" not in json.dumps([ep.value for ep in report.endpoints])


def test_unauthorised_cdp_does_not_touch_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("cdp touched")

    monkeypatch.setattr(socket, "create_connection", denied)
    src = Path(__file__).parents[1] / "plugins/fxapk-rea/src"
    monkeypatch.syspath_prepend(str(src))
    supplement = importlib.import_module("fxapk_rea.supplement")
    result = supplement.run_supplement({
        "source": "cdp", "authorized": False, "endpoint": "http://127.0.0.1:9222",
        "target": "t", "exact_origins": ["http://127.0.0.1:9"], "provider": "trace",
    })
    assert result["reason"] == "cdp_not_authorized"
    assert result["live_cdp"] is False


def test_repeat_does_not_raise_trust_and_runtime_lead_stays() -> None:
    runtime = Evidence(source="runtime-pcap", location="pcap")
    endpoint = Endpoint(value="203.0.113.10", kind="ip", evidences=[runtime])
    from apkscan.core.leads import build_endpoint_leads

    original = build_endpoint_leads([endpoint], online=False)[0]
    web = Evidence(source=SOURCE, location="raw:aa|request")
    endpoint.evidences.append(web)
    mixed = build_endpoint_leads([endpoint], online=False)[0]
    clamp_web_only_leads([mixed])
    assert mixed.advice == original.advice
    assert mixed.confidence == original.confidence
    assert any(ev.source == "runtime-pcap" for ev in mixed.source_refs)
    only = Endpoint(value="203.0.113.11", kind="ip", evidences=[Evidence(source=SOURCE, location="raw:aa|x")])
    fresh = build_endpoint_leads([only], online=False)[0]
    clamp_web_only_leads([fresh])
    assert fresh.advice == ADVICE_REVIEW
    assert fresh.confidence == Confidence.LOW
    parsed = {"raw_sha": "ab" * 32, "endpoints": [only], "leads": [], "relations": 1, "scripts": 1}
    bucket: list[Endpoint] = []
    leads: list[Lead] = [Lead(category=LeadCategory.IP, value="203.0.113.11", advice=ADVICE_INVESTIGATE, confidence=Confidence.HIGH)]
    seen: set[str] = set()
    merge_candidates(bucket, leads, parsed, seen)
    merge_candidates(bucket, leads, parsed, seen)
    assert len(bucket) == 1
    assert leads[0].advice == ADVICE_INVESTIGATE
    assert leads[0].confidence == Confidence.HIGH


def test_digest_drops_free_text_and_cached_complete() -> None:
    projected = project_for_digest({
        "status": "complete",
        "reason": "executed",
        "note": MARKER,
        "parse_counts": {"endpoints": 2, "config_leads": 1, "relations": 1, "scripts": 1},
        "raw_sha256": ["ab" * 32],
    })
    assert projected["status"] != "complete"
    assert MARKER not in json.dumps(projected)
    assert "仍缺证据" in projected["summary_line"]


def test_same_window_ready_before_interaction_and_rounds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    events: list[str] = []

    class Observer:
        def start(self, deadline: float | None) -> None:
            events.append(f"start:{deadline}")
            self._deadline = deadline

        def wait_ready(self, deadline: float | None) -> str:
            events.append("ready")
            time.sleep(0.05)
            return "ready"

        def finish(self) -> dict[str, object]:
            events.append("finish")
            return {"status": "skipped", "reason": "not_live_cdp", "live_cdp": False}

    def interaction(*_args: object, **_kwargs: object) -> dict[str, str]:
        events.append("interaction")
        time.sleep(0.05)
        return {"status": "ok"}

    start = time.monotonic()
    overlap_web_observation(interaction=interaction, web_observer=Observer(), deadline=start + 0.35, window_seconds=0.35)
    elapsed = time.monotonic() - start
    assert events[:3] == ["start:" + events[0].split(":", 1)[1], "ready", "interaction"]
    assert events[-1] == "finish"
    assert elapsed < 0.55

    seen: list[int] = []

    def runner(*_args: object, **kwargs: object) -> dict[str, str]:
        seen.append(int(kwargs.get("duration") or 0))
        if kwargs.get("web_observer") is not None:
            overlap_web_observation(
                interaction=kwargs.get("interaction"),  # type: ignore[arg-type]
                web_observer=kwargs["web_observer"],
                deadline=time.monotonic() + 0.05,
                window_seconds=0.05,
            )
        return {"status": "skipped", "reason": "fake"}

    records = run_rounds(
        "com.example.app", report=None, unpacked=False, out_dir=str(tmp_path / "rounds"),
        duration=1, runner=runner, web_observer_factory=lambda number, _kind, _path: Observer() if number == 1 else None,
    )
    assert len(records) == 3
    assert seen == [1, 1]
    assert records[2]["status"] == "skipped"
    assert records[2]["reason"] == "unpacked_evidence_or_supported_targeted_hook_missing"


@pytest.mark.parametrize("status", [[], {}, None])
def test_untrusted_plan_status_does_not_crash(status: object) -> None:
    result = build_digest({
        "meta": {"web_observation_plan": {"status": status}},
        "leads": [],
        "endpoints": [],
    })
    assert result["web_observation_plan"]["status"] not in ("executed", "selected")


def test_not_applicable_plan_stays_not_applicable() -> None:
    result = build_digest({
        "meta": {"web_observation_plan": {
            "status": "not_applicable", "reason": "no_config", "execute": False,
        }},
        "leads": [],
        "endpoints": [],
    })
    assert result["web_observation_plan"]["status"] == "not_applicable"


def test_plan_execute_is_explicit_boolean_only() -> None:
    result = build_digest({
        "meta": {"web_observation_plan": {"status": "pending", "execute": "false"}},
        "leads": [],
        "endpoints": [],
    })
    assert result["web_observation_plan"]["execute"] is False
