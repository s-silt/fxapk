"""Selector tests. No browser, device, or case material."""

from __future__ import annotations

import json

import pytest

from apkscan.core.web_observation_plan import (
    build_plan,
    load_config_bytes,
    parse_config,
)


def _body(**extra: str | bool | int | list[str]) -> dict[str, str | bool | int | list[str]]:
    payload: dict[str, str | bool | int | list[str]] = {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": "bundle",
    }
    payload.update(extra)
    return payload


def test_no_config_plan_does_not_execute() -> None:
    plan = build_plan(None, platform="android", meta={})
    assert plan["execute"] is False
    assert plan["status"] == "not_applicable"
    assert plan["gaps"] == []
    assert plan["reason"] == "no_config"
    assert plan["closure_evaluated"] is False
    web = build_plan(None, platform="web", meta={})
    assert web["status"] == "pending"
    assert web["platform"] == "web"
    assert web["execute"] is False
    assert web["reason"] == "no_config"
    assert web["mode"] == "off"
    assert web["agent_handoff"]["why"] == "needs_material"
    unknown = build_plan(None, platform="desktop", meta={"webview_signal_count": 1})
    assert unknown["platform"] == ""
    assert unknown["status"] == "pending"
    assert unknown["agent_handoff"]["why"] == "unknown"


def test_unknown_field_duplicate_and_limit_reject_without_echo() -> None:
    with pytest.raises(ValueError, match="duplicate_json_key"):
        load_config_bytes(b'{"schema_version":"fxapk.web_supplement.v1","mode":"auto","mode":"off"}')
    request, reason = parse_config(_body(api_url="https://secret.example/token"))
    assert request is None
    assert reason == "unknown_field"
    assert "secret" not in reason
    request, reason = parse_config(_body(observation_ms=60001))
    assert reason == "observation_ms_limit"


def test_bare_api_and_missing_signal_do_not_start() -> None:
    request, reason = parse_config({"schema_version": "fxapk.web_supplement.v1", "mode": "auto", "source": "bundle"})
    assert reason == ""
    plan = build_plan(request, platform="android", meta={"endpoints": ["https://api.example/v1"]})
    assert plan["execute"] is False
    assert plan["reason"] == "no_web_signal"


def test_explicit_material_and_authorized_cdp_select() -> None:
    material, _ = parse_config(_body())
    assert build_plan(material, platform="android", meta={})["execute"] is True
    denied, _ = parse_config(_body(
        source="cdp", path="", endpoint="http://127.0.0.1:9222", target="t",
        exact_origins=["http://127.0.0.1:9"], authorized=False,
    ))
    assert build_plan(denied, platform="android", meta={})["reason"] == "cdp_not_authorized"
    allowed, _ = parse_config(_body(
        source="cdp", path="", endpoint="http://127.0.0.1:9222", target="t",
        exact_origins=["http://127.0.0.1:9"], authorized=True, provider="trace",
        observation_ms=1000,
    ))
    assert build_plan(allowed, platform="android", meta={})["execute"] is True


def test_mode_off_stays_idle() -> None:
    request, _ = parse_config(_body(mode="off"))
    plan = build_plan(request, platform="web", meta={"webview_signals": ["x"]})
    assert plan["execute"] is False
    assert plan["reason"] == "mode_off"
    assert json.dumps(plan)
