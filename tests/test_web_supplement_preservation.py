"""Evidence preservation for external web observations. Synthetic values only."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from apkscan.core.models import (
    AnalysisConfig,
    Confidence,
    Endpoint,
    Evidence,
    EvidenceScope,
    Finding,
    Lead,
    LeadCategory,
    Report,
    Severity,
)
from apkscan.core import web_supplement as ws
from apkscan.core.web_supplement_preservation import commit_supplement, union_evidence
from apkscan.core.web_supplement_runtime import _remember_runtime
from apkscan.report.digest import build_digest


def _report() -> Report:
    return Report("com.example.synthetic", {}, [], [], [], [])


def _ev(location: str, timestamp: float | None = None, snippet: str = "", source: str = ws.SOURCE) -> Evidence:
    return Evidence(source, location, snippet, timestamp, EvidenceScope.BATCH_REFERENCE)


def _parsed(**kwargs: object) -> dict[str, object]:
    base: dict[str, object] = {
        "endpoints": [], "leads": [], "findings": [], "raw_sha": "a" * 64,
        "relations": 0, "scripts": 0, "relation_records": [], "copies": {}, "provider": "rea",
    }
    base.update(kwargs)
    return base


def test_same_config_unions_refs_without_grade_change() -> None:
    old = Lead(
        LeadCategory.CONFIG_KEY, "SYNTHETIC", source_refs=[_ev("a")],
        evidence_to_obtain=["first"], advice="待核", base_advice="建议调证",
        downgrades={"synthetic": "待核"}, confidence=Confidence.MEDIUM, notes="keep",
    )
    new = Lead(
        LeadCategory.CONFIG_KEY, "SYNTHETIC", source_refs=[_ev("b")],
        evidence_to_obtain=["second"], advice="建议调证", confidence=Confidence.HIGH, notes="drop",
    )
    parsed = _parsed(leads=[new])
    ws.merge_candidates([], [old], parsed, set())
    ws.merge_candidates([], [old], parsed, set())
    assert old is old
    assert [item.location for item in old.source_refs] == ["a", "b"]
    assert old.evidence_to_obtain == ["first", "second"]
    assert old.notes == "keep"
    assert (old.advice, old.base_advice, old.downgrades, old.confidence) == (
        "待核", "建议调证", {"synthetic": "待核"}, Confidence.MEDIUM,
    )


def test_evidence_identity_keeps_snippet_scope_and_time() -> None:
    endpoint = Endpoint("api.example.test", "domain", [_ev("same", 1, "one")])
    incoming = [
        Endpoint("api.example.test", "domain", [_ev("same", 2, "one")]),
        Endpoint("api.example.test", "domain", [
            Evidence(ws.SOURCE, "same", "two", 1, EvidenceScope.BATCH_REFERENCE),
            Evidence(ws.SOURCE, "same", "one", 1, EvidenceScope.LEGACY_UNSPECIFIED),
        ]),
    ]
    seen: set[str] = set()
    for index, item in enumerate(incoming):
        parsed = _parsed(raw_sha=("ab" * 32)[:63] + str(index), endpoints=[item])
        # distinct 64-hex hashes
        parsed["raw_sha"] = f"{index:064x}"
        ws.merge_candidates([endpoint], [], parsed, seen)
    assert {(item.snippet, item.scope, item.observed_at) for item in endpoint.evidences} == {
        ("one", EvidenceScope.BATCH_REFERENCE, 1),
        ("one", EvidenceScope.BATCH_REFERENCE, 2),
        ("two", EvidenceScope.BATCH_REFERENCE, 1),
        ("one", EvidenceScope.LEGACY_UNSPECIFIED, 1),
    }
    again = _parsed(raw_sha=f"{0:064x}", endpoints=[incoming[0]])
    ws.merge_candidates([endpoint], [], again, seen)
    assert len(endpoint.evidences) == 4


def test_existing_domain_lead_receives_external_ref() -> None:
    endpoint = Endpoint("api.example.test", "domain", [Evidence("dex", "first")])
    lead = Lead(LeadCategory.DOMAIN, endpoint.value, source_refs=list(endpoint.evidences), advice="建议调证")
    url = Endpoint("https://api.example.test/v", "url", [_ev("url-ref")])
    url_lead = Lead(LeadCategory.DOMAIN, url.value, source_refs=[_ev("url-old")], confidence=Confidence.HIGH)
    parsed = _parsed(endpoints=[Endpoint(endpoint.value, "domain", [_ev("second")]), url])
    ws.merge_candidates([endpoint, url], [lead, url_lead], parsed, set())
    assert {item.location for item in lead.source_refs} == {"first", "second", "url-ref"}
    assert {item.location for item in url_lead.source_refs} == {"url-old", "url-ref"}
    assert lead.advice == "建议调证"
    assert url_lead.confidence is Confidence.HIGH


def test_superseded_pcap_is_not_resurrected() -> None:
    endpoint = Endpoint("203.0.113.10", "ip", [
        Evidence("runtime-derived", "flow", "same", None, EvidenceScope.CASE_EVIDENCE),
    ])
    parsed = _parsed(endpoints=[Endpoint("203.0.113.10", "ip", [
        Evidence("runtime-pcap", "flow", "same", None, EvidenceScope.CASE_EVIDENCE),
    ])])
    ws.merge_candidates([endpoint], [], parsed, set())
    assert [item.source for item in endpoint.evidences] == ["runtime-derived"]
    other = Endpoint("203.0.113.10", "ip", [
        Evidence("runtime-pcap", "flow", "same", None, EvidenceScope.CASE_EVIDENCE),
    ])
    union_evidence(other.evidences, [
        Evidence("runtime-derived", "flow", "same", None, EvidenceScope.CASE_EVIDENCE),
    ])
    assert [item.source for item in other.evidences] == ["runtime-derived"]


def test_repeat_raw_and_distinct_raw_same_value() -> None:
    endpoint = Endpoint("api.example.test", "domain", [_ev("static")])
    seen: set[str] = set()
    first = _parsed(endpoints=[Endpoint(endpoint.value, "domain", [_ev("one")])])
    assert ws.merge_candidates([endpoint], [], first, seen)["duplicate"] == 0
    assert ws.merge_candidates([endpoint], [], first, seen)["duplicate"] == 1
    assert [item.location for item in endpoint.evidences] == ["static", "one"]
    second = _parsed(raw_sha="b" * 64, endpoints=[Endpoint(endpoint.value, "domain", [_ev("two")])])
    counts = ws.merge_candidates([endpoint], [], second, seen)
    assert counts["endpoints"] == 0
    assert counts["duplicate"] == 0
    assert [item.location for item in endpoint.evidences] == ["static", "one", "two"]


def test_bad_incoming_does_not_mark_raw_seen() -> None:
    class Bad:
        @property
        def value(self) -> str:
            raise RuntimeError("bad endpoint")

        evidences: list[Evidence] = []

    endpoint = Endpoint("api.example.test", "domain", [_ev("keep")])
    seen: set[str] = set()
    with pytest.raises(RuntimeError):
        ws.merge_candidates([endpoint], [], _parsed(endpoints=[Bad()]), seen)
    assert seen == set()
    assert [item.location for item in endpoint.evidences] == ["keep"]


def test_runtime_finding_collision_keeps_grade(monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory) -> None:
    from apkscan.core.web_supplement_runtime import apply_verified

    report = _report()
    old = Finding(
        "SYNTHETIC", "synthetic", Severity.INFO, "web", "synthetic",
        evidences=[_ev("first")], confidence=Confidence.MEDIUM,
    )
    report.findings = [old]
    parsed = _parsed(findings=[Finding(
        "SYNTHETIC", "new", Severity.INFO, "web", "synthetic", evidences=[_ev("second")],
        confidence=Confidence.LOW,
    )])
    monkeypatch.setattr(ws, "_parse_verified", lambda _: deepcopy(parsed))
    monkeypatch.setattr(ws, "_publish", lambda *args: "external_observations/" + "a" * 64)
    apply_verified(report, {}, publish_dir=str(tmp_path), material_dir=str(tmp_path), live_cdp=False)
    assert {item.location for item in old.evidences} == {"first", "second"}
    assert old.confidence is Confidence.MEDIUM
    blob = json.loads(json.dumps(report.meta))
    assert blob["web_supplement"]["status"] == "executed"
    assert blob["web_supplement"]["boundary"]["app_attribution_verified"] is False
    assert blob["web_supplement"]["boundary"]["closure_evaluated"] is False


def test_failed_parse_does_not_enter_seen(monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory) -> None:
    from apkscan.core.web_supplement_runtime import apply_verified

    def boom(_: object) -> dict[str, object]:
        raise RuntimeError("parse")

    report = _report()
    monkeypatch.setattr(ws, "_parse_verified", boom)
    result = apply_verified(report, {}, publish_dir=str(tmp_path), material_dir=str(tmp_path), live_cdp=False)
    assert result["status"] == "failed"
    assert report.meta.get("_web_supplement_raws", []) == []
    assert report.meta["web_supplement"]["latest_status"] == "failed"
    assert report.meta["web_supplement"]["raw_sha256"] == []


def test_static_then_runtime_then_failure_keeps_success() -> None:
    from apkscan.core.web_supplement_runtime import _publish_canonical

    raw_a, raw_b = "a" * 64, "b" * 64
    meta: dict[str, object] = {}
    commit_supplement(meta, ws._record(
        {"execute": True, "provider": "rea"},
        status="executed", reason="executed", raw_sha256=[raw_a],
        relative_paths=["external_observations/" + raw_a],
        relations=[{
            "source": ws.SOURCE, "url": "https://static.example.test/a",
            "original_ref": "/scripts/0", "script_sha256": raw_a,
            "relative_path": "external_observations/" + raw_a + "/scripts/a.js",
        }],
        parse_counts={"endpoints": 0, "config_leads": 0, "relations": 1, "scripts": 2},
    ))
    rounds = [{
        "status": "executed", "reason": "executed", "raw_sha256": raw_b,
        "published_path": "external_observations/" + raw_b,
        "parse_counts": {"scripts": 3, "relations": 1},
        "relation_records": [{
            "source": ws.SOURCE, "url": "https://runtime.example.test/b",
            "original_ref": "/requests/0", "script_sha256": raw_b,
            "relative_path": "external_observations/" + raw_b + "/scripts/b.js",
        }],
    }]
    _publish_canonical(meta, rounds, "round2")
    supplement = meta["web_supplement"]
    assert isinstance(supplement, dict)
    assert set(supplement["raw_sha256"]) == {raw_a, raw_b}
    assert supplement["parse_counts"]["scripts"] == 5
    assert supplement["parse_counts"]["relations"] == 2
    assert {item["url"] for item in supplement["relations"]} == {
        "https://static.example.test/a", "https://runtime.example.test/b",
    }
    rounds.append({"status": "failed", "reason": "parse_failed"})
    _publish_canonical(meta, rounds, "round3")
    supplement = meta["web_supplement"]
    assert isinstance(supplement, dict)
    assert set(supplement["raw_sha256"]) == {raw_a, raw_b}
    assert supplement["parse_counts"]["scripts"] == 5
    assert supplement["status"] == "executed"
    assert supplement["latest_status"] == "failed"
    assert supplement["boundary"]["closure_evaluated"] is False


def test_static_rerun_keeps_prior_success() -> None:
    raw_a = "c" * 64
    meta: dict[str, object] = {"_web_supplement_raws": [raw_a]}

    class State:
        def __init__(self) -> None:
            self.config = AnalysisConfig(online=False, out_dir="out")
            self.meta = meta
            self.endpoints = []
            self.leads = []
            self.findings = []
            self.platform = ""

    commit_supplement(meta, ws._record(
        {"execute": True, "provider": "rea"},
        status="executed", reason="executed", provider="rea", raw_sha256=[raw_a],
        relative_paths=["external_observations/" + raw_a],
        parse_counts={"endpoints": 1, "config_leads": 0, "relations": 0, "scripts": 1},
    ))
    ws.apply_static(State())
    supplement = meta["web_supplement"]
    assert isinstance(supplement, dict)
    assert supplement["raw_sha256"] == [raw_a]
    assert supplement["parse_counts"]["endpoints"] == 1
    assert supplement["status"] == "executed"
    assert supplement["latest_status"] != "executed"


def test_same_url_distinct_frames_keep_anchors() -> None:
    sha = "d" * 64
    other = "e" * 64
    receipt = {"requests": [
        {
            "url": "https://api.example.test/same",
            "request_id": "req-1",
            "session_id": "sess-1",
            "original_ref": "/requests/0",
            "stack_groups": [{"frames": [{
                "id": "frame-1",
                "original_ref": "/frames/0",
                "source_ref": {"relative_path": "scripts/one.js", "sha256": sha},
            }]}],
        },
        {
            "url": "https://api.example.test/same",
            "request_id": "req-2",
            "session_id": "sess-2",
            "original_ref": "/requests/1",
            "stack_groups": [{"frames": [{
                "id": "frame-2",
                "original_ref": "/frames/1",
                "source_ref": {"relative_path": "https://evil.example/steal.js", "sha256": other},
            }]}],
        },
    ]}
    endpoints: list[Endpoint] = []
    records = ws._request_relations(receipt, "f" * 64, endpoints)
    assert len(records) == 2
    assert {item["original_ref"] for item in records} == {"/frames/0", "/frames/1"}
    assert {item["request_id"] for item in records} == {"req-1", "req-2"}
    assert {item["session_id"] for item in records} == {"sess-1", "sess-2"}
    assert all(item["app_attribution_verified"] is False for item in records)
    assert all("://" not in item["relative_path"] for item in records)
    cleaned = ws._clean_relations(records)
    assert len(cleaned) == 2
    ws.merge_candidates(endpoints, [], _parsed(raw_sha="f" * 64, endpoints=list(endpoints)), set())
    same = [item for item in endpoints if item.value == "https://api.example.test/same"]
    assert same
    assert len(same[0].evidences) >= 2
    assert all(item.scope is EvidenceScope.BATCH_REFERENCE for item in same[0].evidences)


def _bundle_state(tmp_path: Path) -> SimpleNamespace:
    config = AnalysisConfig(online=False, out_dir=str(tmp_path), web_supplement_request={
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": "synthetic",
    })
    return SimpleNamespace(config=config, platform="web", meta={}, endpoints=[], leads=[], findings=[])


def test_static_plugin_failure_is_failed_not_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    state = _bundle_state(tmp_path)
    monkeypatch.setattr(ws, "_run_plugin", lambda *_args: {"status": "failed", "reason": "parse_failed"})
    ws.apply_static(state)
    assert state.meta["web_supplement"]["latest_status"] == "failed"
    assert ws.project_for_digest(state.meta["web_supplement"])["failure_count"] == 1


def test_canonical_and_digest_agree_after_old_success_then_failed_static(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    state = _bundle_state(tmp_path)
    commit_supplement(state.meta, ws._record(
        {"execute": True}, status="executed", reason="executed", raw_sha256=["a" * 64],
    ))
    monkeypatch.setattr(ws, "_run_plugin", lambda *_args: {"status": "failed", "reason": "parse_failed"})
    ws.apply_static(state)
    raw = state.meta["web_observation_plan"]["agent_handoff"]["why"]
    compact = build_digest({"leads": [], "endpoints": [], "meta": state.meta})["web_observation_plan"]["agent_handoff"]["why"]
    assert raw == compact == "review_failure"


@pytest.mark.parametrize(("raw_status", "expected"), [
    ("parse_failed", "failed"),
    ("mystery", "failed"),
    ("unavailable", "unavailable"),
    ("skipped", "skipped"),
])
def test_static_plugin_status_keeps_skip_and_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raw_status: str, expected: str,
) -> None:
    state = _bundle_state(tmp_path)
    monkeypatch.setattr(ws, "_run_plugin", lambda *_args: {"status": raw_status, "reason": raw_status})
    ws.apply_static(state)
    assert state.meta["web_supplement"]["latest_status"] == expected
    assert state.meta["web_observation_plan"]["execute"] is True


def test_canonical_and_digest_agree_after_runtime_failure() -> None:
    report = Report("com.example.synthetic", {}, [], [], [], [])
    report.meta["web_observation_plan"] = {
        "status": "selected", "reason": "ok", "source": "cdp", "mode": "auto", "provider": "trace",
    }
    _remember_runtime(report, {"status": "executed", "reason": "executed", "raw_sha256": "a" * 64}, "round-1")
    _remember_runtime(report, {"status": "failed", "reason": "parse_failed"}, "round-2")
    raw = report.meta["web_observation_plan"]["agent_handoff"]["why"]
    compact = build_digest({
        "leads": [], "endpoints": [], "meta": report.meta,
    })["web_observation_plan"]["agent_handoff"]["why"]
    assert raw == compact == "review_failure"


def _started(meta: dict) -> bool:
    boundary = meta["web_supplement"]["boundary"]
    digest = build_digest({"leads": [], "endpoints": [], "meta": meta})
    assert digest["web_supplement"]["capture_started"] is boundary["capture_started"]
    return boundary["capture_started"] is True


def test_capture_started_aggregates_strict_bools_not_live_cdp() -> None:
    true_top: dict = {}
    commit_supplement(true_top, {
        "status": "executed",
        "reason": "executed",
        "capture_started": True,
        "live_cdp": False,
    })
    assert _started(true_top) is True
    assert true_top["web_supplement"]["boundary"]["live_cdp"] is False

    false_overrides: dict = {}
    commit_supplement(false_overrides, {
        "status": "executed",
        "reason": "executed",
        "capture_started": False,
        "live_cdp": True,
        "boundary": {"capture_started": True, "live_cdp": True},
    })
    assert _started(false_overrides) is False

    from_boundary: dict = {}
    commit_supplement(from_boundary, {
        "status": "executed",
        "reason": "executed",
        "boundary": {"capture_started": True},
    })
    assert _started(from_boundary) is True

    string_value: dict = {}
    commit_supplement(string_value, {
        "status": "executed",
        "reason": "executed",
        "capture_started": "true",
        "boundary": {"capture_started": "true"},
    })
    assert _started(string_value) is False

    live_only: dict = {}
    commit_supplement(live_only, {
        "status": "executed",
        "reason": "executed",
        "live_cdp": True,
    })
    assert _started(live_only) is False
    assert live_only["web_supplement"]["boundary"]["live_cdp"] is True

    aggregated: dict = {}
    commit_supplement(aggregated, {
        "status": "executed",
        "reason": "executed",
        "capture_started": True,
        "raw_sha256": ["ab" * 32],
    })
    commit_supplement(aggregated, {
        "status": "failed",
        "reason": "parse_failed",
        "capture_started": False,
        "raw_sha256": ["cd" * 32],
    })
    assert _started(aggregated) is True

    report = Report("com.example.synthetic", {}, [], [], [], [])
    _remember_runtime(report, {
        "status": "executed",
        "reason": "executed",
        "capture_started": True,
        "live_cdp": False,
        "raw_sha256": "ef" * 32,
    }, "round-started")
    assert _started(report.meta) is True
    assert report.meta["web_supplement"]["boundary"]["live_cdp"] is False

    quiet = Report("com.example.synthetic", {}, [], [], [], [])
    _remember_runtime(quiet, {
        "status": "executed",
        "reason": "executed",
        "capture_started": False,
        "live_cdp": True,
        "raw_sha256": "11" * 32,
    }, "round-live")
    assert _started(quiet.meta) is False
    assert quiet.meta["web_supplement"]["boundary"]["live_cdp"] is True
