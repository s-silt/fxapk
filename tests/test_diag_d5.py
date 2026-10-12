"""D5：没请求 Frida 不能写成 observer_late。"""

from __future__ import annotations

from apkscan.core.runtime_diagnostics import explain_coverage, observation_from_capture

_SAMPLE = "ab" * 32


def test_floor_only_none_is_not_requested_and_not_late() -> None:
    raw = observation_from_capture(
        pid=None,
        uid=None,
        hook_status="none",
        retreated=False,
        runtime_variant="original-runtime",
        pass_tag="round1",
        apk_sha256=_SAMPLE,
    )
    explained = explain_coverage([raw])
    item = explained["items"][0]
    assert item["event"] == "not_requested"
    assert item["event"] != "observer_late"
    assert item["observer_requested"] is False
    assert explained["frida_detection"] == "not_inferred"
    assert "frida_detected" not in {row["event"] for row in explained["items"]}


def test_requested_but_unattached_is_not_late_without_time() -> None:
    raw = observation_from_capture(
        pid=7,
        uid=None,
        hook_status="unconfirmed",
        retreated=False,
        runtime_variant="original-runtime",
        pass_tag="round2",
        apk_sha256=_SAMPLE,
        run_id="run-1",
        start_token="start-1",
    )
    item = explain_coverage([raw])["items"][0]
    assert item["event"] == "observer_not_attached"
    assert item["class"] != "observed-event"
    assert item["observer_requested"] is True
    late = explain_coverage([{
        "event": "capture_window",
        "observer_attached": False,
        "observer_requested": True,
        "observer_late_evidence": True,
        "apk_sha256": _SAMPLE,
        "window_id": "late",
        "run_id": "run-1",
        "pid": 7,
        "start_token": "start-1",
    }])["items"][0]
    assert late["event"] == "observer_late"
    unknown = explain_coverage([{
        "event": "observer_late",
        "observer_attached": False,
        "window_id": "no-time",
        "apk_sha256": _SAMPLE,
    }])["items"][0]
    assert unknown["event"] != "observer_late"
