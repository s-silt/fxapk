"""合成夹具：阶段替换与去重不得丢掉更早阶段的证据。

不读案件、不联网、不碰设备。值全部是文档保留段或明显的合成标签。
"""

from __future__ import annotations

import json

from apkscan.core.models import (
    ANALYSIS_STATUS_COMPLETE,
    ANALYSIS_STATUS_PARTIAL,
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
from apkscan.core.pipeline import _dedup_endpoints, _dedup_leads
from apkscan.dynamic.auto import _adopt_unpacked_report
from apkscan.report import json as report_json


def _report(**kwargs: object) -> Report:
    base = dict(
        package_name="com.example.fixture",
        meta={},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    base.update(kwargs)
    return Report(**base)  # type: ignore[arg-type]


def _ev(source: str, location: str, *, observed_at: float | None = None, snippet: str = "fixture") -> Evidence:
    return Evidence(
        source=source,
        location=location,
        snippet=snippet,
        observed_at=observed_at,
        scope=EvidenceScope.CASE_EVIDENCE,
    )


def test_static_rea_survives_unpacked_replacement() -> None:
    """脱壳重分析不能把外部导入的 REA 去重键和独立网页观察丢掉。"""
    raws = ["a" * 64]
    observations = {"schema": "fixture", "count": 1, "gaps": ["identity_unverified"]}
    supplement = {"status": "executed", "raw_sha256": list(raws), "provider": "rea"}
    plan = {"schema": "fxapk.web_observation_plan/1", "execute": False, "reason": "fixture"}
    runtime_rounds = [{"round_id": "static", "raw_sha256": list(raws)}]
    original = _report(
        meta={
            "online": False,
            "mode": "passive",
            "is_hardened": True,
            "packed": "fixture-packer",
            "_web_supplement_raws": raws,
            "web_supplement": supplement,
            "web_observation_plan": plan,
            "web_observations": observations,
            "web_supplement_runtime": runtime_rounds,
        },
        analysis_status=ANALYSIS_STATUS_PARTIAL,
        critical_failures=["fixture-analyzer"],
        endpoints=[
            Endpoint(
                value="rea.example",
                kind="domain",
                evidences=[_ev("external-web-observation", "rea/bundle")],
            )
        ],
        leads=[
            Lead(
                category=LeadCategory.CONFIG_KEY,
                value="fixture-key=1",
                advice="待核",
                source_refs=[_ev("external-web-observation", "rea/bundle")],
                evidence_to_obtain=["配置原文"],
            )
        ],
    )
    unpacked = _report(
        meta={"is_hardened": False, "unpacked_dex_count": 2},
        analysis_status=ANALYSIS_STATUS_COMPLETE,
        endpoints=[Endpoint(value="hidden.example", kind="domain", evidences=[_ev("dex", "classes.dex")])],
    )
    raw_before = json.dumps(report_json.to_dict(original), ensure_ascii=False, sort_keys=True)

    adopted = _adopt_unpacked_report(original, unpacked, apk_path="fixture.apk")

    assert adopted is unpacked
    assert adopted.meta["is_hardened"] is False
    assert "packed" not in adopted.meta
    assert adopted.meta["online"] is False
    assert adopted.meta["mode"] == "passive"
    assert adopted.meta["_web_supplement_raws"] == raws
    assert adopted.meta["web_supplement"]["provider"] == "rea"
    assert adopted.meta["web_observations"]["count"] == 1
    assert adopted.meta["web_observation_plan"]["reason"] == "fixture"
    assert adopted.meta["web_supplement_runtime"][0]["round_id"] == "static"
    assert adopted.analysis_status == ANALYSIS_STATUS_COMPLETE
    assert adopted.critical_failures == []
    assert json.dumps(report_json.to_dict(original), ensure_ascii=False, sort_keys=True) == raw_before
    assert {ep.value for ep in adopted.endpoints} >= {"rea.example", "hidden.example"}
    carried = next(ep for ep in adopted.endpoints if ep.value == "rea.example")
    assert carried.enrichment["stage_preservation"]["carried_from"] == "superseded-static"
    assert any(lead.value == "fixture-key=1" for lead in adopted.leads)


def test_existing_grade_and_downgrade_stay() -> None:
    """更早阶段的更高档不得抬升脱壳报告上已经封存的档位。"""
    original = _report(
        leads=[
            Lead(
                category=LeadCategory.DOMAIN,
                value="api.example",
                advice="建议调证",
                base_advice="建议调证",
                confidence=Confidence.HIGH,
                evidence_to_obtain=["早期解析"],
                source_refs=[_ev("external-web-observation", "rea/api")],
            )
        ],
        endpoints=[
            Endpoint(
                value="api.example",
                kind="domain",
                evidences=[_ev("external-web-observation", "rea/api")],
                enrichment={"tier": "app"},
            )
        ],
    )
    sealed = Lead(
        category=LeadCategory.DOMAIN,
        value="api.example",
        advice="待核",
        base_advice="建议调证",
        downgrades={"repack_identity": "fixture"},
        confidence=Confidence.LOW,
        evidence_to_obtain=["脱壳后线索"],
        source_refs=[_ev("dex", "classes.dex")],
    )
    unpacked = _report(
        meta={"is_hardened": False},
        leads=[sealed],
        endpoints=[
            Endpoint(
                value="api.example",
                kind="domain",
                evidences=[_ev("dex", "classes.dex")],
                enrichment={"tier": "bulk-string"},
            )
        ],
    )

    adopted = _adopt_unpacked_report(original, unpacked, apk_path="fixture.apk")
    lead = next(item for item in adopted.leads if item.value == "api.example")

    assert lead is sealed
    assert lead.advice == "待核"
    assert lead.base_advice == "建议调证"
    assert lead.downgrades == {"repack_identity": "fixture"}
    assert lead.confidence is Confidence.LOW
    assert "早期解析" in lead.evidence_to_obtain
    assert "脱壳后线索" in lead.evidence_to_obtain
    assert {ev.location for ev in lead.source_refs} == {"rea/api", "classes.dex"}
    endpoint = adopted.endpoints[0]
    assert endpoint.enrichment["tier"] == "bulk-string"
    assert any(ev.location == "rea/api" for ev in endpoint.evidences)


def test_old_only_endpoint_and_lead_remain_marked() -> None:
    original = _report(
        endpoints=[Endpoint(value="203.0.113.10", kind="ip", evidences=[_ev("dex", "old.dex")])],
        leads=[
            Lead(
                category=LeadCategory.IP,
                value="203.0.113.10",
                advice="待核",
                base_advice="待核",
                notes="早期备注",
                source_refs=[_ev("dex", "old.dex")],
            )
        ],
    )
    unpacked = _report(meta={"is_hardened": False})

    adopted = _adopt_unpacked_report(original, unpacked, apk_path="fixture.apk")

    assert [ep.value for ep in adopted.endpoints] == ["203.0.113.10"]
    assert adopted.endpoints[0].enrichment["stage_preservation"]["carried_from"] == "superseded-static"
    lead = adopted.leads[0]
    assert lead.value == "203.0.113.10"
    assert lead.base_advice == "待核"
    assert "沿用较早阶段" in lead.notes
    assert "早期备注" in lead.notes
    original.endpoints[0].evidences.append(_ev("dex", "mutated-after"))
    assert all(ev.location != "mutated-after" for ev in adopted.endpoints[0].evidences)


def test_hardening_finding_archived_not_active_and_json_roundtrip() -> None:
    hardening = Finding(
        id="fixture-packer",
        title="fixture hardened",
        severity=Severity.HIGH,
        category="packing",
        description="packed fixture",
        analyzer="packing",
        evidences=[_ev("native", "libfixture.so")],
    )
    kept = Finding(
        id="fixture-config",
        title="fixture config",
        severity=Severity.LOW,
        category="config",
        description="still relevant",
        evidences=[_ev("resource", "res/fixture")],
    )
    original = _report(
        meta={"is_hardened": True, "packed": "fixture-packer"},
        findings=[hardening, kept],
        analysis_status=ANALYSIS_STATUS_PARTIAL,
        critical_failures=["fixture-analyzer"],
        analyzer_status=[{"name": "fixture-analyzer", "status": "error"}],
    )
    active_finding = Finding(
        id="fixture-config",
        title="fixture config",
        severity=Severity.INFO,
        category="config",
        description="unpacked",
        evidences=[_ev("dex", "classes.dex")],
    )
    unpacked = _report(
        meta={"is_hardened": False, "unpacked_dex_count": 1},
        findings=[active_finding],
        analysis_status=ANALYSIS_STATUS_COMPLETE,
    )

    adopted = _adopt_unpacked_report(original, unpacked, apk_path="fixture.apk")

    assert [item.id for item in adopted.findings] == ["fixture-config"]
    assert adopted.findings[0].severity is Severity.INFO
    assert {ev.location for ev in adopted.findings[0].evidences} >= {"classes.dex", "res/fixture"}
    history = adopted.meta["artifact_lineage"]["phase_history"]
    assert history[0]["phase_status"] == "superseded"
    archived = history[0]["report"]
    assert archived["meta"]["phase_status"] == "superseded"
    assert archived["analysis_status"] == ANALYSIS_STATUS_PARTIAL
    assert archived["critical_failures"] == ["fixture-analyzer"]
    assert archived["findings"][0]["id"] == "fixture-packer"
    assert adopted.analysis_status == ANALYSIS_STATUS_COMPLETE

    payload = json.loads(json.dumps(report_json.to_dict(adopted), ensure_ascii=False))
    assert payload["meta"]["artifact_lineage"]["phase_history"][0]["report"]["findings"][0]["id"] == (
        "fixture-packer"
    )
    assert payload["meta"]["is_hardened"] is False


def test_repeated_adoption_is_idempotent_and_not_nested() -> None:
    original = _report(
        meta={"_web_supplement_raws": ["b" * 64], "is_hardened": True},
        endpoints=[Endpoint(value="old.example", kind="domain")],
        findings=[
            Finding(
                id="fixture-packer",
                title="fixture hardened",
                severity=Severity.HIGH,
                category="packing",
                description="packed",
                analyzer="packing",
            )
        ],
    )
    unpacked = _report(meta={"is_hardened": False, "unpacked_dex_count": 1})
    first = _adopt_unpacked_report(original, unpacked, apk_path="fixture.apk")
    once = json.dumps(report_json.to_dict(first), sort_keys=True)
    second = _adopt_unpacked_report(original, first, apk_path="fixture.apk")
    twice = json.dumps(report_json.to_dict(second), sort_keys=True)
    assert once == twice

    newer = _report(meta={"is_hardened": False, "unpacked_dex_count": 4})
    third = _adopt_unpacked_report(second, newer, apk_path="fixture.apk")
    phases = third.meta["artifact_lineage"]["phase_history"]
    assert len(phases) == 2
    nested = phases[-1]["report"]["meta"].get("artifact_lineage") or {}
    assert "phase_history" not in nested
    blob = json.dumps(phases)
    assert blob.count("phase_history") == 0


def test_endpoint_timestamp_is_identity_and_runtime_is_not_spliced() -> None:
    early = Endpoint(
        value="203.0.113.20",
        kind="ip",
        evidences=[_ev("runtime-pcap", "floor.pcap", observed_at=1000.0)],
        enrichment={
            "tier": "library-file",
            "runtime": {"target_attributed": False, "has_payload": False},
            "vendor_note": "first",
        },
    )
    late = Endpoint(
        value="203.0.113.20",
        kind="ip",
        evidences=[_ev("runtime-pcap", "floor.pcap", observed_at=2000.0)],
        enrichment={
            "tier": "app",
            "runtime": {"target_attributed": True, "has_payload": True, "attribution": "other"},
            "vendor_note": "second",
            "mystery": "keep-in-history",
        },
    )

    merged = _dedup_endpoints([early, late])
    assert len(merged) == 1
    assert [ev.observed_at for ev in merged[0].evidences] == [1000.0, 2000.0]
    runtime = merged[0].enrichment["runtime"]
    assert runtime == {"target_attributed": False, "has_payload": False}
    assert "attribution" not in runtime
    assert merged[0].enrichment["vendor_note"] == "first"
    assert merged[0].enrichment["tier"] == "app"
    history = merged[0].enrichment["enrichment_history"]
    assert history[0]["source_stage"]
    assert history[0]["evidence_anchors"][0]["observed_at"] == 2000.0
    assert history[0]["diff"]["runtime"]["has_payload"] is True
    assert history[0]["diff"]["vendor_note"] == "second"
    assert "mystery" in history[0]["diff"]
    assert merged[0].enrichment.get("mystery") in (None, "keep-in-history")

    again = _dedup_endpoints(merged)
    refed = _dedup_endpoints(merged + [late])
    assert again[0].enrichment["enrichment_history"] == history
    assert refed[0].enrichment["enrichment_history"] == history


def test_lead_dedup_unions_evidence_without_rewriting_seals() -> None:
    first = Lead(
        category=LeadCategory.DOMAIN,
        value="Api.Example",
        advice="待核",
        base_advice="建议调证",
        downgrades={"repack_identity": "sealed"},
        legacy_effective_advice=None,
        subject="first-subject",
        where_to_request="first-desk",
        evidence_to_obtain=["日志A"],
        confidence=Confidence.LOW,
        notes="已有说明",
        source_refs=[_ev("dex", "a.dex", observed_at=1.0)],
    )
    second = Lead(
        category=LeadCategory.DOMAIN,
        value="api.example",
        advice="建议调证",
        base_advice="建议调证",
        subject="second-subject",
        where_to_request="second-desk",
        evidence_to_obtain=["日志A", "日志B"],
        confidence=Confidence.HIGH,
        notes="另一来源说明",
        source_refs=[
            _ev("dex", "a.dex", observed_at=1.0),
            _ev("dex", "a.dex", observed_at=2.0),
        ],
    )

    merged = _dedup_leads([first, second])
    assert len(merged) == 1
    lead = merged[0]
    assert lead is first
    assert lead.advice == "待核"
    assert lead.base_advice == "建议调证"
    assert lead.downgrades == {"repack_identity": "sealed"}
    assert lead.confidence is Confidence.LOW
    assert lead.subject == "first-subject"
    assert lead.evidence_to_obtain == ["日志A", "日志B"]
    assert [ev.observed_at for ev in lead.source_refs] == [1.0, 2.0]
    assert "建议调证" in lead.notes
    assert "second-subject" in lead.notes

    refed = _dedup_leads([lead, second])
    assert refed[0].notes == lead.notes
    assert refed[0].evidence_to_obtain == ["日志A", "日志B"]
    assert len(refed[0].source_refs) == 2


def test_dedup_keeps_every_distinct_evidence() -> None:
    rows = [Evidence("dex", f"synthetic:{i}", scope=EvidenceScope.CASE_EVIDENCE) for i in range(100)]
    merged = _dedup_endpoints([Endpoint("api.example.test", "domain", rows)])
    assert [ev.location for ev in merged[0].evidences] == [f"synthetic:{i}" for i in range(100)]


def test_skipped_web_receipt_keeps_prior_success_and_nonhardening_finding() -> None:
    from apkscan.core import web_supplement as ws

    original = _report(
        meta={"web_supplement": ws._record({"execute": True}, status="executed", raw_sha256=["a" * 64])},
        findings=[
            Finding(
                id="WEB-REQUEST-RECIPE",
                title="fixture web",
                severity=Severity.INFO,
                category="web",
                description="prior",
                evidences=[_ev("external-web-observation", "old")],
            )
        ],
    )
    unpacked = _report(
        meta={"web_supplement": ws._record({"execute": False}, status="skipped", reason="no_config")},
    )
    adopted = _adopt_unpacked_report(original, unpacked, apk_path="fixture.apk")
    assert "a" * 64 in adopted.meta["web_supplement"]["raw_sha256"]
    assert any(item.id == "WEB-REQUEST-RECIPE" for item in adopted.findings)
    assert original.meta["web_supplement"]["status"] == "executed"


def test_colliding_adoption_does_not_alias_prior_evidence_or_archive() -> None:
    from copy import deepcopy

    prior = _report(
        meta={"artifact_lineage": {"phase_history": [{"snapshot_sha256": "a" * 64, "report": {"meta": {}}}]}},
        endpoints=[Endpoint("api.example.test", "domain", [_ev("dex", "old", snippet="old")])],
        findings=[
            Finding(
                id="fixture-shared",
                title="fixture",
                severity=Severity.INFO,
                category="config",
                description="prior",
                evidences=[_ev("dex", "old-finding", snippet="old")],
            )
        ],
    )
    active = _report(
        endpoints=[Endpoint("api.example.test", "domain", [_ev("dex", "new", snippet="new")])],
        findings=[
            Finding(
                id="fixture-shared",
                title="fixture",
                severity=Severity.INFO,
                category="config",
                description="active",
                evidences=[_ev("dex", "new-finding", snippet="new")],
            )
        ],
    )
    before = deepcopy(prior)
    adopted = _adopt_unpacked_report(prior, active, apk_path="fixture.apk")
    next(ev for ev in adopted.endpoints[0].evidences if ev.location == "old").snippet = "later"
    next(ev for ev in adopted.findings[0].evidences if ev.location == "old-finding").snippet = "later"
    adopted.meta["artifact_lineage"]["phase_history"][0]["report"]["meta"]["tampered"] = True
    assert prior == before


def test_preaggregated_endpoint_keeps_conflict_history_and_anchors() -> None:
    def endpoint(name: str, location: str) -> Endpoint:
        return Endpoint(
            "api.example.test",
            "domain",
            [_ev("dex", location, snippet=name)],
            enrichment={"synthetic": {"observation": name}, "runtime": {"round_id": name}},
        )

    second = endpoint("stage-2", "loc-2")
    third = endpoint("stage-3", "loc-3")
    grouped = _dedup_endpoints([second, third])[0]
    grouped.enrichment["runtime"]["round_id"] = "mutated-alias"
    assert second.enrichment["runtime"]["round_id"] == "stage-2"
    assert third.enrichment["runtime"]["round_id"] == "stage-3"
    merged = _dedup_endpoints([endpoint("stage-1", "loc-1"), grouped])[0]
    serialized = json.dumps(merged.enrichment)
    assert all(name in serialized for name in ("stage-1", "stage-2", "stage-3"))
    assert merged.enrichment["runtime"] == {"round_id": "stage-1"}
    anchors = [
        item.get("location")
        for record in merged.enrichment["enrichment_history"]
        for item in record["evidence_anchors"]
    ]
    assert "loc-2" in anchors and "loc-3" in anchors
