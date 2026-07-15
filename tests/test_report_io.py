from __future__ import annotations

import json

from apkscan.core.models import (
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    Lead,
    LeadCategory,
    Report,
    Severity,
)
from apkscan.core.report_io import load_report, write_report
from apkscan.report import json as report_json


def _report() -> Report:
    evidence = Evidence(source="runtime", location="pcap:flow-1", snippet="api.example.test")
    return Report(
        package_name="com.example.synthetic",
        meta={
            "package_name": "com.example.synthetic",
            "closure": {"schema_version": "1.0", "status": "partial"},
        },
        leads=[
            Lead(
                category=LeadCategory.DOMAIN,
                value="api.example.test",
                confidence=Confidence.HIGH,
                source_refs=[evidence],
                advice="建议调证",
            )
        ],
        endpoints=[
            Endpoint(
                value="api.example.test",
                kind="domain",
                evidences=[evidence],
                is_suspicious=True,
                enrichment={"dns": {"ok": True, "addresses": ["198.51.100.10"]}},
            )
        ],
        findings=[
            Finding(
                id="synthetic-finding",
                title="Synthetic finding",
                severity=Severity.INFO,
                category="test",
                description="Synthetic report round-trip coverage.",
                evidences=[evidence],
                analyzer="synthetic",
                confidence=Confidence.HIGH,
                kind="observation",
            )
        ],
        analyzer_status=[{"name": "manifest", "status": "error", "reason": "synthetic"}],
        enricher_status=[{"provider": "dns", "attempted": 1, "ok": 1, "failed": 0}],
        schema_version="1.0",
        analysis_status="partial",
        completeness=0.75,
        critical_failures=["manifest"],
        skipped_analyzers=["native"],
    )


def test_report_round_trip_preserves_health_and_closure(tmp_path):
    path = tmp_path / "report.json"
    report_json.dump(_report(), str(path))

    loaded = load_report(path)

    assert loaded.analysis_status == "partial"
    assert loaded.completeness == 0.75
    assert loaded.critical_failures == ["manifest"]
    assert loaded.skipped_analyzers == ["native"]
    assert loaded.enricher_status[0]["provider"] == "dns"
    assert loaded.meta["closure"]["status"] == "partial"
    assert loaded.leads[0].category is LeadCategory.DOMAIN
    assert loaded.findings[0].severity is Severity.INFO
    assert loaded.endpoints[0].evidences[0].observed_at is None


def test_write_report_atomically_preserves_unknown_top_level_extensions(tmp_path):
    path = tmp_path / "report.json"
    payload = report_json.to_dict(_report())
    payload["vendor_extension"] = {"version": 2, "enabled": True}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    loaded = load_report(path)
    written = write_report(loaded, path, render_existing_html=False)
    restored = json.loads(path.read_text(encoding="utf-8"))

    assert written == [str(path)]
    assert restored["vendor_extension"] == {"version": 2, "enabled": True}
    assert "_report_top_level_extensions" not in restored["meta"]
    assert not path.with_suffix(".json.tmp").exists()
