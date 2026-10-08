from __future__ import annotations

import json
from dataclasses import replace

import pytest

from apkscan.dynamic import capture
from tests.test_capture import _set_capabilities, _stub_orchestration


def _prepare(monkeypatch):
    _set_capabilities(monkeypatch)
    calls = _stub_orchestration(monkeypatch)
    monkeypatch.setattr(capture, "_parse_flows", lambda _path: [])
    monkeypatch.setattr(capture, "_pull_shared_prefs_credentials", lambda *args, **kwargs: None)
    monkeypatch.setattr(capture, "_pull_exported_databases", lambda *args, **kwargs: None)
    return calls


def test_expired_capture_budget_skips_ui_and_delivers_report(monkeypatch, tmp_path):
    calls = _prepare(monkeypatch)
    clock = {"now": 0.0}
    monkeypatch.setattr(capture, "_monotonic", lambda: clock["now"])

    def startup(_serial):
        clock["now"] = 11.0
        return True, ""

    monkeypatch.setattr(capture, "_check_frida_version_match", startup)
    interactions = []
    result = capture._capture(
        "com.example.synthetic", tmp_path, 60, "device-1",
        decision=replace(capture.decide_capture(None), total_budget_sec=10), mitm=False, floor=False, frida=False,
        interaction=lambda: interactions.append(True),
    )

    assert interactions == []
    assert calls["waited"] is False
    assert result["report_paths"] == [str(tmp_path / "runtime_report.json")]
    assert json.loads((tmp_path / "runtime_report.json").read_text(encoding="utf-8"))["budget_exceeded"] is True
    assert "frida" in calls["terminated"]


def test_socket_sampling_is_active_during_ui_interaction(monkeypatch, tmp_path):
    _prepare(monkeypatch)
    sampler = {"active": False}

    class Sampler:
        def __init__(self, *_args, **_kwargs):
            pass

        def start(self):
            sampler["active"] = True

        def stop(self):
            sampler["active"] = False
            return None

    monkeypatch.setattr(capture, "_SocketSampler", Sampler)
    active_during_ui = []
    capture._capture(
        "com.example.synthetic", tmp_path, 1, "device-1", mitm=False, floor=False, frida=False,
        interaction=lambda: active_during_ui.append(sampler["active"]),
    )

    assert active_during_ui == [True]
    assert sampler["active"] is False


@pytest.mark.parametrize("fallback", [False, True])
def test_cold_start_connections_are_sampled_before_frida_resume(monkeypatch, tmp_path, fallback):
    _prepare(monkeypatch)
    state = {"active": False}
    observed = []

    class Sampler:
        def __init__(self, *_args, **_kwargs):
            pass

        def start(self):
            state["active"] = True

        def stop(self):
            state["active"] = False
            return None

    def spawn(*_args, **_kwargs):
        if fallback:
            return None, None
        observed.append(state["active"])
        return object(), object()

    def subprocess_spawn(*_args, **_kwargs):
        observed.append(state["active"])
        return None

    monkeypatch.setattr(capture, "_SocketSampler", Sampler)
    monkeypatch.setattr(capture, "_start_frida_session", spawn)
    monkeypatch.setattr(capture, "_start_frida_unpinning", subprocess_spawn)
    monkeypatch.setattr(capture, "_frida_session_alive", lambda _session: True)
    monkeypatch.setattr(capture, "_teardown_frida_session", lambda *_args: None)
    capture._capture(
        "com.example.synthetic", tmp_path, 1, "device-1", mitm=False, floor=False, frida=True,
    )
    assert observed == [True]
    assert state["active"] is False


def test_ui_receives_absolute_capture_deadline(monkeypatch, tmp_path):
    _prepare(monkeypatch)
    clock = {"now": 100.0}
    monkeypatch.setattr(capture, "_monotonic", lambda: clock["now"])
    deadlines = []
    waits = []
    monkeypatch.setattr(capture, "_wait", waits.append)

    def interaction(*, deadline_monotonic):
        deadlines.append(deadline_monotonic)
        clock["now"] = 103.0
        return {"status": "complete"}

    result = capture._capture(
        "com.example.synthetic", tmp_path, 60, "device-1",
        decision=replace(capture.decide_capture(None), total_budget_sec=10), mitm=False, floor=False, frida=False,
        interaction=interaction,
    )

    assert deadlines == [110.0]
    assert waits == [7.0]
    assert result["ui_observations"][0]["status"] == "complete"


def test_sampler_start_cannot_spend_budget_then_start_ui(monkeypatch, tmp_path):
    _prepare(monkeypatch)
    clock = {"now": 0.0}
    monkeypatch.setattr(capture, "_monotonic", lambda: clock["now"])

    class Sampler:
        def __init__(self, *_args, **_kwargs):
            pass

        def start(self):
            clock["now"] = 11.0

        def stop(self):
            return None

    monkeypatch.setattr(capture, "_SocketSampler", Sampler)
    interactions = []
    capture._capture(
        "com.example.synthetic", tmp_path, 60, "device-1",
        decision=replace(capture.decide_capture(None), total_budget_sec=10), mitm=False, floor=False, frida=False,
        interaction=lambda: interactions.append(True),
    )

    assert interactions == []


def test_callback_typeerror_is_not_retried_and_sampler_is_cleaned(monkeypatch, tmp_path):
    calls = _prepare(monkeypatch)
    attempts = []

    def interaction():
        attempts.append(True)
        raise TypeError("synthetic callback error")

    capture._capture(
        "com.example.synthetic", tmp_path, 1, "device-1", mitm=False, floor=False, frida=False,
        interaction=interaction,
    )

    assert attempts == [True]
    assert "frida" in calls["terminated"]
