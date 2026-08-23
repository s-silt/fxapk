from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading

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
from apkscan.core.report_io import load_report, report_from_dict, write_report
from apkscan.report import json as report_json
from apkscan.report.digest import build_digest


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


def test_write_report_does_not_reuse_or_delete_preexisting_fixed_tmp(tmp_path):
    path = tmp_path / "report.json"
    fixed_tmp = path.with_suffix(".json.tmp")
    fixed_tmp.write_text("belongs-to-another-writer", encoding="utf-8")

    write_report(_report(), path, render_existing_html=False)

    assert json.loads(path.read_text(encoding="utf-8"))["package_name"] == (
        "com.example.synthetic"
    )
    assert fixed_tmp.read_text(encoding="utf-8") == "belongs-to-another-writer"


def test_concurrent_write_report_uses_independent_temps_and_keeps_complete_json(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "report.json"
    barrier = threading.Barrier(2)
    original_write_text = Path.write_text

    def synchronized_temp_write(self, data, *args, **kwargs):  # noqa: ANN001, ANN202
        written = original_write_text(self, data, *args, **kwargs)
        if self.name.endswith(".tmp"):
            barrier.wait(timeout=5)
        return written

    monkeypatch.setattr(Path, "write_text", synchronized_temp_write)
    first = _report()
    first.package_name = "com.example.first"
    second = _report()
    second.package_name = "com.example.second"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(write_report, first, path, render_existing_html=False),
            pool.submit(write_report, second, path, render_existing_html=False),
        ]
        written = [future.result(timeout=10) for future in futures]

    assert written == [[str(path)], [str(path)]]
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["package_name"] in {"com.example.first", "com.example.second"}


def test_write_report_canonicalizes_all_endpoint_source_status_trees(tmp_path):
    report = _report()
    report.meta["closure"] = {
        "targets": [
            {
                "value": "api.example.com",
                "source_status": {"fofa": "rate_limited"},
            }
        ]
    }
    report.endpoints.append(
        Endpoint(
            value="198.51.100.11",
            kind="ip",
            enrichment={"source_status": {"rdap": "no_record"}},
        )
    )
    report.endpoints[0].enrichment["source_status"] = {
        "rdap": "hit",
        "fofa": {"status": "failed", "error_type": "timeout", "attempts": 2},
    }
    report.endpoints[0].enrichment["resolved_ip_enrichment"] = {
        "198.51.100.10": {"source_status": {"shodan": "quota_insufficient"}}
    }
    path = tmp_path / "report.json"

    write_report(report, path, render_existing_html=False)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["endpoints"][0]["enrichment"]["source_status"] == {
        "fofa": {"status": "failed", "error_type": "timeout"},
        "rdap": {"status": "hit"},
    }
    assert payload["endpoints"][0]["enrichment"]["resolved_ip_enrichment"][
        "198.51.100.10"
    ]["source_status"] == {
        "shodan": {"status": "failed", "error_type": "quota_insufficient"}
    }
    assert payload["endpoints"][1]["enrichment"]["source_status"] == {
        "rdap": {"status": "no_record"}
    }
    assert payload["meta"]["closure"]["targets"][0]["source_status"] == {
        "fofa": {"status": "failed", "error_type": "rate_limited"}
    }


def test_load_report_canonicalizes_all_endpoint_source_status_trees(tmp_path):
    report = _report()
    payload = report_json.to_dict(report)
    payload["endpoints"][0]["enrichment"]["source_status"] = {"rdap": "hit"}
    payload["endpoints"][0]["enrichment"]["resolved_ip_enrichment"] = {
        "198.51.100.10": {"source_status": {"shodan": "quota_insufficient"}}
    }
    payload["meta"]["closure"] = {
        "targets": [
            {
                "value": "api.example.com",
                "source_status": {"fofa": "rate_limited"},
            }
        ]
    }
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )

    loaded = load_report(path)

    assert loaded.endpoints[0].enrichment["source_status"] == {
        "rdap": {"status": "hit"}
    }
    assert loaded.endpoints[0].enrichment["resolved_ip_enrichment"][
        "198.51.100.10"
    ]["source_status"] == {
        "shodan": {"status": "failed", "error_type": "quota_insufficient"}
    }
    assert loaded.meta["closure"]["targets"][0]["source_status"] == {
        "fofa": {"status": "failed", "error_type": "rate_limited"}
    }


def test_report_json_to_dict_never_emits_legacy_source_status_strings() -> None:
    report = _report()
    report.endpoints[0].enrichment["source_status"] = {"rdap": "hit"}
    report.meta["closure"] = {
        "targets": [
            {
                "value": "api.example.com",
                "source_status": {"fofa": "rate_limited"},
            }
        ]
    }

    payload = report_json.to_dict(report)

    assert payload["endpoints"][0]["enrichment"]["source_status"] == {
        "rdap": {"status": "hit"}
    }
    assert payload["meta"]["closure"]["targets"][0]["source_status"] == {
        "fofa": {"status": "failed", "error_type": "rate_limited"}
    }


# --- D1-c：未知 LeadCategory 三出口一致 --------------------------------------


def _unknown_category_payload() -> dict:
    """report.json **存盘形状**的最小夹具：含一条本版本不认识的 category="future_x" 线索。"""
    return {
        "package_name": "com.example.synthetic",
        "meta": {"package_name": "com.example.synthetic"},
        "leads": [
            {
                "category": "future_x",
                "value": "future-fixture",
                "confidence": "HIGH",
                "advice": "待核",
                "notes": "",
                "source_refs": [
                    {
                        "source": "dex",
                        "location": "X;->y",
                        "snippet": "future-fixture",
                        "scope": "case_evidence",
                    }
                ],
            }
        ],
        "endpoints": [],
        "findings": [],
        "analyzer_status": [],
        "enricher_status": [],
        "schema_version": "1.2",
        "analysis_status": "complete",
        "completeness": 1.0,
        "critical_failures": [],
        "skipped_analyzers": [],
    }


def test_unknown_category_preserved_and_roundtrips(tmp_path):
    """★D1-c：未知 category 不再被 typed loader 丢弃——归入 UNKNOWN + 保留原始串，
    write_report 往返后 JSON 里 category **仍是**原始串（不把别人的类别改掉）。"""
    report = report_from_dict(_unknown_category_payload())

    matches = [lead for lead in report.leads if lead.value == "future-fixture"]
    assert len(matches) == 1, "未知 category 的 Lead 被 typed loader 丢弃了"
    lead = matches[0]
    assert lead.category is LeadCategory.UNKNOWN
    assert lead.raw_category == "future_x"

    out = tmp_path / "report.json"
    write_report(report, out, render_existing_html=False)
    written = json.loads(out.read_text(encoding="utf-8"))
    cats = [
        item.get("category")
        for item in written["leads"]
        if item.get("value") == "future-fixture"
    ]
    assert cats == ["future_x"], f"往返后 category 应写回原始串，实得 {cats!r}"


def test_unknown_category_visible_in_digest(tmp_path):
    """★D1-c：typed load → write_report → digest 全链后，未知 category 的 Lead 仍在
    digest 出口可见，且 category 显式标注「（未识别类别）」。"""
    report = report_from_dict(_unknown_category_payload())
    out = tmp_path / "report.json"
    write_report(report, out, render_existing_html=False)
    written = json.loads(out.read_text(encoding="utf-8"))

    digest = build_digest(written)
    rows = [row for row in digest["leads"] if row.get("value") == "future-fixture"]
    assert rows, "未知 category 的 Lead 在 digest 出口消失了"
    assert rows[0]["category"] == "future_x（未识别类别）"
