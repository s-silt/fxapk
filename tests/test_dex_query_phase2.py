"""DEX xref 导入必须带 evidence_id，Phase-2 才看得见；新来源要进阶段分类。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from apkscan.core.dex_query import DexQueryLimits, import_receipt, query_apk
from apkscan.core.integrity import evidence_id
from apkscan.core.models import Endpoint
from apkscan.core.phase2.evidence_map import PackageEvidenceIndex
from apkscan.core.phase2.inventory import (
    InventoryLimits,
    Phase1EvidenceInventory,
    ReviewCandidate,
    _collect_report_candidates,
    _stable_parent_id,
    candidate_id,
)
from tests.fixtures.dex_query.dexgen import build_dex, sample_classes, zip_bytes

_WORKER = [sys.executable, "tests/fixtures/dex_query/fake_worker.py"]
_DOMAIN = "api.example.invalid"
_IP = "192.0.2.10"
_LIMITS = DexQueryLimits(timeout_sec=20, memory_bytes=256 * 1024 * 1024)


def _report(sample: str) -> dict[str, object]:
    """与 test_dex_query_import._report 相同的已有 runtime lead，并带齐 evidence_id。"""
    return {
        "package_name": "example.invalid",
        "schema_version": "1.2",
        "endpoints": [],
        "findings": [],
        "analyzer_status": [],
        "meta": {
            "sample_sha256": sample,
            "package_name": "example.invalid",
            "closure": {"status": "partial", "gaps": ["origin-unknown"]},
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
                        "evidence_id": evidence_id("runtime", "socket"),
                    }
                ],
            }
        ],
    }


def _xref_refs(report: dict[str, object]) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    leads = report.get("leads")
    if not isinstance(leads, list):
        return found
    for lead in leads:
        if not isinstance(lead, dict):
            continue
        refs = lead.get("source_refs")
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if isinstance(ref, dict) and ref.get("source") == "static-dex-xref":
                found.append(ref)
    return found


def test_imported_dex_xref_is_visible_to_phase2(tmp_path: Path) -> None:
    domain = build_dex(sample_classes(_DOMAIN))
    ip = build_dex(sample_classes(_IP))
    apk = tmp_path / "app.apk"
    apk.write_bytes(zip_bytes([
        ("classes.dex", domain.data),
        ("assets/payload.dex", ip.data),
    ]))
    receipt_path = tmp_path / "receipt.json"
    receipt = query_apk(apk, [_DOMAIN, _IP], worker_argv=_WORKER, limits=_LIMITS, out=receipt_path)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(_report(receipt["apk_sha256"])), encoding="utf-8")
    out = tmp_path / "imported"
    result = import_receipt(receipt_path, report_path, out, apk=apk)
    assert result["status"] == "imported"

    merged = json.loads((out / "report.json").read_text(encoding="utf-8"))
    refs = _xref_refs(merged)
    assert refs
    for ref in refs:
        assert ref["scope"] == "case_evidence"
        assert ref["evidence_id"] == evidence_id(str(ref["source"]), str(ref["location"]))

    leads = {item["value"]: item for item in merged["leads"]}
    appended = leads[_DOMAIN]["source_refs"]
    assert appended[0]["source"] == "runtime"
    assert any(item["source"] == "static-dex-xref" and item["scope"] == "case_evidence" for item in appended)
    created = leads[_IP]["source_refs"]
    assert created
    assert all(item["source"] == "static-dex-xref" and item["scope"] == "case_evidence" for item in created)

    inv = Phase1EvidenceInventory(case_id="synthetic-phase2")
    _collect_report_candidates(
        inv, "p" * 64, "m" * 64, merged, "report.json", "pkg", InventoryLimits(),
    )
    assert inv.issues == []
    assert len(inv.candidates) >= len(refs)


def _review_candidate(
    collection: str,
    parent: dict[str, object],
    eid: str,
    scope: str,
) -> ReviewCandidate:
    identity = _stable_parent_id(collection, parent)
    assert identity is not None
    parent_id, display = identity
    return ReviewCandidate(
        candidate_id("pkg", collection, parent_id, eid, scope),
        "pkg",
        collection,
        parent_id,
        eid,
        scope,
        True,
        "m" * 64,
        "report.json",
        display_value=display,
    )


def test_evidence_map_classifies_dex_xref_and_external_web() -> None:
    static_source = "static-dex-xref"
    static_location = "classes.dex!Lexample/invalid/Q;->lookup()Ljava/lang/String;@code_units:0"
    static_id = evidence_id(static_source, static_location)
    web_source = "external-web-observation"
    web_location = "rea/bundle"
    web_id = evidence_id(web_source, web_location)
    host = "api.example.invalid"
    lead = {
        "category": "DOMAIN",
        "value": host,
        "source_refs": [{
            "source": static_source,
            "location": static_location,
            "snippet": "static",
            "scope": "case_evidence",
            "evidence_id": static_id,
        }],
    }
    endpoint = {
        "kind": "domain",
        "value": host,
        "evidences": [{
            "source": web_source,
            "location": web_location,
            "snippet": "web",
            "scope": "case_evidence",
            "evidence_id": web_id,
        }],
    }
    index = PackageEvidenceIndex(
        {"meta": {}, "leads": [lead], "endpoints": [endpoint]},
        [
            _review_candidate("leads", lead, static_id, "case_evidence"),
            _review_candidate("endpoints", endpoint, web_id, "case_evidence"),
        ],
    )
    resolved = index.resolve(Endpoint(value=host, kind="domain"))
    stages = {ref["collection"]: ref["stages"] for ref in resolved["candidate_refs"]}
    assert "static" in stages["leads"]
    assert "web" in stages["endpoints"]
