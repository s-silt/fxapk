"""D1：采集身份不绑定到别的 APK，缺失事实不能当成这次覆盖。"""

from __future__ import annotations

import json
from pathlib import Path

from apkscan.core.models import Report
from apkscan.core.runtime_diagnostics import explain_coverage, observation_from_capture
from apkscan.dynamic import capture, merge
from apkscan.report.digest import build_digest
from tests.test_capture import _FakeProc, _set_capabilities, _stub_orchestration

_SAMPLE = "ab" * 32
_OTHER = "cd" * 32


def _report() -> Report:
    return Report(
        package_name="example.invalid",
        meta={"sample_sha256": _SAMPLE, "closure": {"status": "partial", "gaps": ["keep"]}},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def test_capture_passes_sample_hash_and_does_not_copy_window_into_run(
    monkeypatch, tmp_path: Path,
) -> None:
    _set_capabilities(monkeypatch, has_frida=False, frida_server_running=False, has_mitmproxy=False)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=_FakeProc())
    monkeypatch.setattr(capture, "_parse_flows", lambda _f: [])
    monkeypatch.setattr(capture, "_pull_shared_prefs_credentials", lambda *_a, **_k: None)
    monkeypatch.setattr(capture, "_pull_exported_databases", lambda *_a, **_k: None)
    monkeypatch.setattr(capture, "_capture_uid_socket_snapshot", lambda *_a, **_k: None)
    monkeypatch.setattr(capture, "_start_frida_session", lambda *_a, **_k: (None, None))
    monkeypatch.setattr(capture, "_start_frida_unpinning", lambda *_a, **_k: None)
    monkeypatch.setattr(capture, "_start_floor_pcap", lambda *_a, **_k: object())
    floor = tmp_path / "floor.pcap"
    floor.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 40)
    monkeypatch.setattr(capture, "_stop_floor_pcap", lambda _h, _op: floor)

    class EmptySampler:
        def __init__(self, *_a: object, **_k: object) -> None:
            return None

        def start(self) -> None:
            return None

        def stop(self) -> None:
            return None

    monkeypatch.setattr(capture, "_SocketSampler", EmptySampler)
    result = capture.run(
        "example.invalid",
        out_dir=str(tmp_path),
        mode="floor-only",
        duration=1,
        pass_tag="pass1",
        report=_report(),
    )
    assert result["status"] == capture.STATUS_DONE
    payload = json.loads((tmp_path / "runtime_report.json").read_text(encoding="utf-8"))
    observed = payload["process_observations"][0]
    assert observed["apk_sha256"] == _SAMPLE
    assert observed["window_id"] == "pass1"
    assert observed["run_id"] is None
    assert observed.get("start_token") in (None, "")
    bare = capture.run(
        "example.invalid",
        out_dir=str(tmp_path / "bare"),
        mode="floor-only",
        duration=1,
        pass_tag="pass1",
    )
    assert bare["status"] == capture.STATUS_DONE
    bare_obs = json.loads(
        (tmp_path / "bare" / "runtime_report.json").read_text(encoding="utf-8")
    )["process_observations"][0]
    assert bare_obs["apk_sha256"] is None
    assert bare_obs["run_id"] is None


def test_missing_apk_or_start_is_not_coverage() -> None:
    raw = observation_from_capture(
        pid=123,
        uid=None,
        hook_status="confirmed",
        retreated=False,
        runtime_variant="original-runtime",
        pass_tag="pass1",
    )
    item = explain_coverage([raw])["items"][0]
    assert item["class"] != "observed-event"
    assert item["event"] == "identity_unattributed"
    assert item["window_id"] == "pass1"
    assert item["run_id"] == "unknown"
    assert item["apk_sha256"] == "unknown"
    assert item["start_token"] == "unknown"
    isolated = explain_coverage([{
        "event": "capture_window",
        "pid": 20,
        "uid": 99001,
        "apk_sha256": _SAMPLE,
        "window_id": "w",
        "run_id": "run-1",
    }])["items"][0]
    assert isolated["event"] != "uid_isolated"
    assert isolated["class"] != "observed-event"


def test_merge_keeps_other_apk_but_not_as_this_sample_coverage(tmp_path: Path) -> None:
    report = _report()
    runtime = tmp_path / "runtime_report.json"
    runtime.write_text(json.dumps({
        "package_name": "example.invalid",
        "source": "runtime",
        "endpoints": [],
        "process_observations": [{
            "event": "capture_window",
            "pid": 123,
            "start_token": "a",
            "window_id": "w1",
            "run_id": "run1",
            "apk_sha256": _OTHER,
            "runtime_variant": "original-runtime",
            "observer_attached": True,
        }],
    }), encoding="utf-8")
    merge.merge_and_rerender(
        report, [], str(tmp_path), formats=["json", "html"], runtime_report_path=str(runtime),
    )
    assert report.endpoints == []
    assert report.findings == []
    assert report.meta["closure"] == {"status": "partial", "gaps": ["keep"]}
    items = report.meta["runtime_diagnostics"]["items"]
    dynamic = [item for item in items if item.get("apk_sha256") == _OTHER]
    assert len(dynamic) == 1
    assert dynamic[0]["class"] != "observed-event"
    assert dynamic[0]["event"] == "identity_mismatch"
    assert dynamic[0]["source_event"] == "capture_window"
    assert dynamic[0]["window_id"] == "w1"
    assert dynamic[0]["run_id"] == "run1"
    assert dynamic[0]["start_token"] == "a"
    assert dynamic[0]["source_report_sha256"]
    rendered = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    digest = build_digest(rendered)
    exported = [
        item for item in digest["runtime_diagnostics"]["items"] if item.get("apk_sha256") == _OTHER
    ]
    assert exported[0]["class"] != "observed-event"
    assert exported[0]["event"] == "identity_mismatch"
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "identity_mismatch" in html
    assert report.meta["runtime_diagnostics"]["frida_detection"] == "not_inferred"
    assert report.meta["runtime_diagnostics"]["endpoints_added"] == 0


def test_matching_apk_remains_observed_event(tmp_path: Path) -> None:
    report = _report()
    runtime = tmp_path / "runtime_report.json"
    runtime.write_text(json.dumps({
        "package_name": "example.invalid",
        "source": "runtime",
        "endpoints": [],
        "process_observations": [{
            "event": "capture_window",
            "pid": 123,
            "start_token": "a",
            "window_id": "w1",
            "run_id": "run1",
            "apk_sha256": _SAMPLE,
            "runtime_variant": "original-runtime",
            "observer_attached": True,
        }],
    }), encoding="utf-8")
    merge.merge_and_rerender(
        report, [], str(tmp_path), formats=["json"], runtime_report_path=str(runtime),
    )
    item = report.meta["runtime_diagnostics"]["items"][-1]
    assert item["class"] == "observed-event"
    assert item["event"] == "capture_window"
    assert item["apk_sha256"] == _SAMPLE
    assert item["source_report_sha256"]
