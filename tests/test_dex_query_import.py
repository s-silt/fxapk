"""导入回执只追加静态观察，不升级运行时证据，也不把查询原文送进默认投影。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from apkscan.core.dex_query import (
    DexQueryLimits,
    import_receipt,
    project_dex_handoff,
    project_dex_query,
    query_apk,
)
from apkscan.core.jsonl import report_to_events
from tests.fixtures.dex_query.dexgen import build_dex, sample_classes, zip_bytes

_WORKER = [sys.executable, "tests/fixtures/dex_query/fake_worker.py"]
_TOKEN = "xref-token-example"
_DOMAIN = "api.example.invalid"
_IP = "192.0.2.10"


def _report(sample: str) -> dict[str, object]:
    return {
        "package_name": "example.invalid",
        "schema_version": "1.2",
        "extension_marker": {"keep": True},
        "endpoints": [],
        "findings": [],
        "analyzer_status": [],
        "meta": {
            "sample_sha256": sample,
            "package_name": "example.invalid",
            "jadx_index_status": "built",
            "closure": {"status": "partial", "gaps": ["origin-unknown"]},
            "custom_note": "keep-me",
        },
        "leads": [
            {
                "category": "DOMAIN",
                "value": _DOMAIN,
                "advice": "建议调证",
                "confidence": "HIGH",
                "is_runtime_seen": True,
                "is_runtime_contact": True,
                "notes": "dynamic-observed",
                "source_refs": [
                    {
                        "source": "runtime",
                        "location": "socket",
                        "snippet": "observed",
                        "scope": "case_evidence",
                    }
                ],
            }
        ],
    }


@pytest.mark.skipif(sys.platform == "darwin", reason="RLIMIT_AS not enforceable on macOS; dex worker memory limit unavailable")
def test_import_keeps_dynamic_evidence_and_hides_non_lead_query_text(tmp_path: Path) -> None:
    domain = build_dex(sample_classes(_DOMAIN))
    ip = build_dex(sample_classes(_IP))
    apk = tmp_path / "app.apk"
    apk.write_bytes(zip_bytes([
        ("classes.dex", domain.data),
        ("assets/payload.dex", ip.data),
    ]))
    receipt_path = tmp_path / "receipt.json"
    receipt = query_apk(
        apk,
        [_DOMAIN, _IP, _TOKEN],
        worker_argv=_WORKER,
        limits=DexQueryLimits(timeout_sec=20, memory_bytes=256 * 1024 * 1024),
        out=receipt_path,
    )
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(_report(receipt["apk_sha256"])), encoding="utf-8")
    out = tmp_path / "imported"
    result = import_receipt(receipt_path, report_path, out, apk=apk)
    assert result["status"] == "imported"
    assert result["closure_evaluated"] is False
    assert result["runtime_observed_upgraded"] is False
    again = import_receipt(receipt_path, report_path, out, apk=apk)
    assert again["status"] == "idempotent"

    merged = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert merged["extension_marker"] == {"keep": True}
    assert merged["meta"]["custom_note"] == "keep-me"
    assert merged["meta"]["closure"]["status"] == "partial"
    assert merged["meta"]["closure"]["gaps"] == ["origin-unknown"]
    leads = {item["value"]: item for item in merged["leads"]}
    domain_lead = leads[_DOMAIN]
    assert domain_lead["advice"] == "建议调证"
    assert domain_lead["is_runtime_seen"] is True
    assert domain_lead["is_runtime_contact"] is True
    assert domain_lead["source_refs"][0]["source"] == "runtime"
    static_refs = [item for item in domain_lead["source_refs"] if item["source"] == "static-dex-xref"]
    assert len(static_refs) == 2
    assert {item["scope"] for item in static_refs} == {"case_evidence"}
    assert len({item["location"] for item in static_refs}) == 2
    ip_lead = leads[_IP]
    assert ip_lead["advice"] == "待核"
    assert ip_lead["confidence"] == "LOW"
    assert ip_lead["is_runtime_seen"] is False
    assert ip_lead["is_runtime_contact"] is False
    assert ip_lead["source_refs"][0]["scope"] == "case_evidence"
    assert ip_lead["source_refs"][0]["source"] == "static-dex-xref"
    assert _TOKEN not in leads
    assert "relation_verified" not in json.dumps(merged)
    assert "runtime_observed" not in json.dumps(merged["meta"])

    digest = (out / "report.digest.json").read_text(encoding="utf-8")
    html = (out / "report.html").read_text(encoding="utf-8")
    events = "\n".join(json.dumps(item, ensure_ascii=False) for item in report_to_events(merged))
    for public in (digest, html, events):
        assert _TOKEN not in public
        assert "query_values" not in public
        assert "classes.dex" in public
        assert "assets/payload.dex" in public
        assert "fxapk jadx usage" in public
        assert "fxapk case close" not in public
    stored = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert _TOKEN in stored["query_values"]
    canonical_counts = [
        member["hit_count"]
        for item in merged["meta"]["dex_query"]["receipts"]
        for member in item["members"]
    ]
    assert sum(canonical_counts) > 0
    digest_doc = json.loads(digest)
    digest_counts = [
        member["hit_count"]
        for item in digest_doc["dex_query"]["receipts"]
        for member in item["members"]
    ]
    assert digest_counts == canonical_counts
    wrapped = project_dex_query({"dex_query": project_dex_query(merged["meta"])})
    assert wrapped is not None
    wrapped_counts = [
        member["hit_count"]
        for item in wrapped["receipts"]
        for member in item["members"]
    ]
    assert wrapped_counts == canonical_counts
    event_counts = [
        member["hit_count"]
        for event in report_to_events(merged)
        if isinstance(event.get("dex_query"), dict)
        for item in event["dex_query"]["receipts"]
        for member in item["members"]
    ]
    assert event_counts == canonical_counts
    assert sum(event_counts) > 0


@pytest.mark.parametrize("count", [True, False, -1, "2"])
def test_invalid_hit_count_projects_to_zero(count: object) -> None:
    projected = project_dex_query({"dex_query": {"receipts": [{"members": [{
        "name": "classes.dex",
        "hit_count": count,
    }]}]}})
    assert projected is not None
    assert projected["receipts"][0]["members"][0]["hit_count"] == 0


def test_raw_hits_override_stale_hit_count() -> None:
    projected = project_dex_query({"dex_query": {"receipts": [{"members": [
        {"name": "classes.dex", "hits": [{}, {}], "hit_count": 99},
        {"name": "assets/payload.dex", "hits": "stale", "hit_count": 4},
    ]}]}})
    assert projected is not None
    counts = [member["hit_count"] for member in projected["receipts"][0]["members"]]
    assert counts == [2, 0]


def test_mode_off_handoff_has_no_action() -> None:
    handoff = project_dex_handoff({"dex_query_plan": {"mode": "off"}, "dex_query": {"receipts": []}})
    assert handoff is not None
    assert handoff["actions"] == []
    assert handoff["auto_execute"] is False
    assert handoff["install"] is False
    assert handoff["capture"] is False
    assert handoff["close"] is False
