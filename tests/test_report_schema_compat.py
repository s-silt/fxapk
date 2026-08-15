from __future__ import annotations

import json

import pytest

from apkscan.core.models import EvidenceScope
from apkscan.core.report_io import load_report
from apkscan.core.report_schema import (
    UnsupportedReportSchema,
    migrate_report_payload,
    report_schema_info,
)


def _legacy_payload(version: str | None = "1.1") -> dict:
    payload = {
        "package_name": "com.example.synthetic",
        "meta": {},
        "leads": [
            {
                "category": "DOMAIN",
                "value": "backend.example",
                "confidence": "MEDIUM",
                "source_refs": [{"source": "runtime-pcap", "location": "capture.pcap"}],
            }
        ],
        "endpoints": [
            {
                "value": "backend.example",
                "kind": "domain",
                "evidences": [{"source": "runtime-pcap", "location": "capture.pcap"}],
            }
        ],
        "findings": [],
        "analyzer_status": [],
    }
    if version is not None:
        payload["schema_version"] = version
    return payload


def test_missing_schema_is_legacy_not_current() -> None:
    info = report_schema_info(_legacy_payload(None))

    assert info.source_version == "1.0"
    assert info.needs_migration is True
    assert info.warnings


def test_legacy_report_migration_marks_missing_evidence_scope_unknown() -> None:
    migrated = migrate_report_payload(_legacy_payload("1.1"))

    assert migrated["schema_version"] == "1.2"
    assert migrated["endpoints"][0]["evidences"][0]["scope"] == "legacy_unspecified"
    assert migrated["leads"][0]["source_refs"][0]["scope"] == "legacy_unspecified"


def test_load_report_migrates_legacy_scope_without_trusting_it(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(_legacy_payload("1.1")), encoding="utf-8")

    report = load_report(path)

    assert report.schema_version == "1.2"
    assert report.endpoints[0].evidences[0].scope is EvidenceScope.LEGACY_UNSPECIFIED


def test_loaded_legacy_endpoint_cannot_retain_investigate_upgrade(tmp_path) -> None:  # noqa: ANN001
    payload = _legacy_payload("1.1")
    payload["leads"][0] |= {
        "advice": "建议调证",
        "base_advice": "建议调证",
        "downgrades": {},
    }
    path = tmp_path / "legacy-investigate.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    report = load_report(path)

    assert report.leads[0].advice == "待核"
    assert "evidence_scope" in report.leads[0].downgrades


def test_future_report_schema_is_rejected_before_typed_write_path(tmp_path) -> None:  # noqa: ANN001
    payload = _legacy_payload("9.0")
    path = tmp_path / "future.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(UnsupportedReportSchema, match="9.0"):
        load_report(path)

    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == "9.0"


def test_future_report_schema_is_rejected_by_raw_runtime_mutators(tmp_path) -> None:  # noqa: ANN001
    from apkscan.dynamic import pcap_ingest, probe_ingest

    path = tmp_path / "future.json"
    original = json.dumps(_legacy_payload("9.0"), ensure_ascii=False, indent=2).encode()

    for mutate in (
        lambda: pcap_ingest.merge_into_report_json(str(path), pcap_ingest.PcapSummary()),
        lambda: probe_ingest.merge_into_report_json(str(path), []),
    ):
        path.write_bytes(original)
        assert mutate() == 0
        assert path.read_bytes() == original


def test_future_report_schema_is_rejected_by_config_probe_raw_merge(tmp_path) -> None:  # noqa: ANN001
    from apkscan.cli import _merge_config_probe_into_report

    class Result:
        endpoints: tuple[object, ...] = ()
        outcomes: tuple[object, ...] = ()
        authorized = False

        @staticmethod
        def to_meta() -> dict:
            return {"status": "skipped"}

    path = tmp_path / "future.json"
    original = json.dumps(_legacy_payload("9.0"), ensure_ascii=False, indent=2).encode()
    path.write_bytes(original)

    with pytest.raises(UnsupportedReportSchema, match="9.0"):
        _merge_config_probe_into_report(str(path), Result())

    assert path.read_bytes() == original
