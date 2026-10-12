"""Portable signaling regressions for D1-D5. Synthetic data only."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from apkscan.core.native_handoff import project_native_handoff
from apkscan.core.web_observation_plan import build_agent_handoff, build_plan
from apkscan.core.web_supplement import project_for_digest
from apkscan.core.web_supplement_preservation import project_attempts
from apkscan.core.web_supplement_runtime import route_stripped_cdp
from apkscan.report.digest import build_digest


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


def test_d1_runtime_receipt_outranks_missing_static_signal_and_mode_off() -> None:
    plan = build_plan(None, platform="android", meta={})
    for status, reason in (("executed", "executed"), ("failed", "trace_dependency_missing")):
        handoff = build_agent_handoff(plan, {
            "status": status, "reason": reason, "provider": "fxapk-cdp-trace",
        })
        assert handoff["why"] != "no_web_signal"
        assert handoff["relevant"] is True
    off = build_agent_handoff(
        {**_cdp("off"), "status": "skipped", "reason": "mode_off", "provider": "trace"},
        {"status": "failed", "reason": "worker_not_stopped", "provider": "fxapk-cdp-trace"},
    )
    assert off["why"] == "mode_off"
    assert off["next_actions"] == []


def test_d1_cli_route_records_not_executed_without_starting_dynamic(tmp_path: Path) -> None:
    path = tmp_path / "live.json"
    path.write_text(json.dumps(_cdp()), encoding="utf-8")
    cases = (
        (False, False, "not_requested"),
        (True, False, "device_unavailable"),
        (True, True, "pre_observer_failure"),
    )
    for dynamic, device, deferral in cases:
        report = SimpleNamespace(meta={})
        route_stripped_cdp(
            report, str(path), None, dynamic=dynamic, device=device, observer_started=False,
        )
        receipt = report.meta["web_supplement_runtime"][-1]
        assert receipt["reason"] == "cdp_deferred"
        assert receipt["execution"] == "not_executed"
        assert receipt["deferral"] == deferral
        assert receipt["capture_started"] is False


def test_d4_worker_not_stopped_stays_out_of_inspect_input() -> None:
    selected = {
        "status": "selected", "reason": "ok", "source": "cdp",
        "provider": "trace", "mode": "auto", "platform": "android",
    }
    outcome = {"status": "failed", "reason": "worker_not_stopped", "provider": "fxapk-cdp-trace"}
    handoff = build_agent_handoff(selected, outcome)
    projected = project_for_digest(outcome)
    assert handoff["why"] == "worker_not_stopped"
    assert handoff["why"] != "inspect_input"
    assert projected["latest_reason"] == "worker_not_stopped"


def test_d2_coverage_whitelist_and_latest_attempt_only() -> None:
    first = {
        "status": "executed", "reason": "executed", "provider": "fxapk-cdp-trace",
        "parse_counts": {"endpoints": 1, "config_leads": 0, "relations": 1, "scripts": 1},
        "coverage": {"status": "complete", "gaps": ["free text must drop", "loader_unknown"]},
        "raw_sha256": ["ab" * 32],
    }
    second = {
        "status": "executed", "reason": "executed", "provider": "fxapk-cdp-trace",
        "parse_counts": {"endpoints": 0, "config_leads": 0, "relations": 0, "scripts": 0},
        "coverage": {
            "status": "partial",
            "gaps": ["loader_unknown", "oopif_worker_unsupported", "related_target_uncovered", "not a code"],
        },
        "raw_sha256": ["cd" * 32],
    }
    record = project_attempts([first, second], round_id="single")
    assert record["status"] == "executed"
    assert record["coverage"]["status"] == "partial"
    assert record["coverage"]["gaps"] == [
        "loader_unknown", "oopif_worker_unsupported", "related_target_uncovered",
    ]
    projected = project_for_digest(record)
    assert projected["status"] == "executed"
    assert "loader_unknown" in json.dumps(projected["coverage"])
    handoff = build_agent_handoff(
        {"status": "executed", "reason": "executed", "source": "bundle", "provider": "trace", "mode": "auto"},
        {"status": "executed", "reason": "executed", "coverage": record["coverage"]},
    )
    assert handoff["why"] == "review_candidates"
    assert "review_coverage_gaps" in handoff["evidence_checks"]
    assert handoff["closure_evaluated"] is False


def test_d3_relation_keeps_request_frame_and_unverified_script() -> None:
    from apkscan.core.web_supplement import _request_relations

    sha = "ef" * 32
    hop = {
        "url": "http://127.0.0.1:9/app",
        "frame_id": "FRAME-A",
        "loader_id": "LOAD-A",
        "observed_identity_bridge": False,
        "async_parent_present": True,
        "gaps": ["loader_unknown", "made-up"],
        "stack_groups": [{
            "kind": "async",
            "frames": [{
                "frame_id": "FRAME-A",
                "script_frame_id": "FRAME-B",
                "source_ref": {
                    "relative_path": f"scripts/{sha}.js",
                    "sha256": sha,
                    "original_ref": "cdp-trace-original.json#/sources/0",
                },
            }],
        }],
    }
    rows = _request_relations({"requests": [{"request_id": "req", "hops": [hop]}]}, sha, [])
    row = rows[0]
    assert row["frame_id"] == "FRAME-A"
    assert row["script_frame_id"] == "FRAME-B"
    assert row["loader_id"] == "LOAD-A"
    assert row["observed_identity_bridge"] is False
    assert row["async_parent_present"] is True
    assert row["script_sha256"] == sha
    assert row["gaps"] == ["loader_unknown"]
    assert row["app_attribution_verified"] is False


def test_d5_external_endpoint_and_bare_dex_do_not_close_native_gap() -> None:
    digest = "ab" * 32
    base = {
        "meta": {"native_lib_hashes": [{"name": "a.so", "sha256": digest, "size": 1}]},
        "findings": [{"id": "DEX-STRING-POOL-OPAQUE"}],
        "endpoints": [{
            "kind": "domain",
            "value": "sdk.example.test",
            "evidences": [{"source": "external-web-observation", "scope": "batch_reference"}],
        }],
        "leads": [],
    }
    handoff = project_native_handoff(base)
    assert handoff is not None
    assert handoff["stage"] == "capabilities"
    assert handoff["native_tool_status"] == "not_probed"
    assert "native_hash_endpoint_gap" in handoff["reasons"]
    assert "dex_string_pool_opaque" in handoff["reasons"]
    assert handoff["linux_ghidra_elf_live_run"] == "unverified"
    assert any("no Mach-O" in item for item in handoff["commands"])
    opaque_only = project_native_handoff({
        "meta": {},
        "findings": [{"id": "DEX-STRING-POOL-OPAQUE"}],
        "endpoints": [],
        "leads": [],
    })
    assert opaque_only is None
    shown = build_digest(base)
    assert shown["native_recovery"]["stage"] == "capabilities"
