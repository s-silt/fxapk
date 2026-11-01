import base64
import hashlib
import json

import pytest

from apkscan.core.models import LeadCategory, Report
from apkscan.core.observations import evidence_identity
from apkscan.dynamic import merge


def _report() -> Report:
    return Report(
        package_name="com.example.synthetic",
        meta={},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def test_runtime_event_pointer_uses_original_index_and_exact_raw_bytes(tmp_path):
    event = {"source": "okhttp", "url": "https://example.test/api", "method": "GET",
             "headers": {}, "body": None,
             "provenance": {"artifact_sha256": "forged"}}
    raw = json.dumps({"credential_events": [None, event, event]}, indent=2).replace("\n", "\r\n").encode()
    path = tmp_path / "runtime_report.json"
    path.write_bytes(raw)
    report = _report()
    merge.merge_runtime_credentials(report, str(path))
    credential_leads = [
        lead for lead in report.leads if lead.category == LeadCategory.RUNTIME_CREDENTIAL
    ]
    assert len(credential_leads) == 1
    refs = credential_leads[0].source_refs
    assert [ref.locator["json_pointer"] for ref in refs] == ["/credential_events/1", "/credential_events/2"]
    assert len({evidence_identity(ref) for ref in refs}) == 2
    for ref in refs:
        assert ref.provenance["artifact_sha256"] == hashlib.sha256(raw).hexdigest()
        assert ref.provenance["target_app_attribution_verified"] is False
        assert ref.provenance["script_identity_status"] == "not_provided"
    assert all(len(endpoint.evidences) == 2 for endpoint in report.endpoints)


def test_cached_runtime_read_keeps_original_hash_when_file_changes(tmp_path):
    path = tmp_path / "runtime_report.json"
    raw = b'{"jsbridge_events":[{"event":"register","iface":"SyntheticBridge"}]}'
    path.write_bytes(raw)
    with merge._runtime_payload_cache():
        first = merge._load_events_field(str(path), "jsbridge_events")
        path.write_bytes(b"{}")
        second = merge._load_events_field(str(path), "jsbridge_events")
    from apkscan.dynamic.event_origin import evidence_coordinates
    assert evidence_coordinates(first[0]) == evidence_coordinates(second[0])
    assert evidence_coordinates(second[0])["provenance"]["artifact_sha256"] == hashlib.sha256(raw).hexdigest()
    assert merge._load_events_field(str(path), "jsbridge_events") == []


def test_aggregated_jsbridge_hint_retains_both_occurrences(tmp_path):
    event = {"event": "register", "iface": "SyntheticBridge"}
    path = tmp_path / "runtime_report.json"
    path.write_text(json.dumps({"jsbridge_events": [event, event]}), encoding="utf-8")
    report = _report()
    assert merge.merge_runtime_traces(report, str(path))["jsbridge_leads"] == 1
    assert [ref.locator["json_pointer"] for ref in report.leads[0].source_refs] == [
        "/jsbridge_events/0", "/jsbridge_events/1",
    ]


@pytest.mark.parametrize(("field", "event", "merger"), [
    ("crypto_events", {"plaintext_b64": base64.b64encode(b'{"webName":"SyntheticBrand"}').decode()}, merge.decrypt_runtime_messages),
    ("sqlcipher_events", {"event": "key_only", "db_path": "/synthetic/application.db", "key": "fixture",
                          "export_status": "not_attempted_non_interference"}, merge.merge_runtime_databases),
    ("clipboard_events", {"addresses": [{"value": "synthetic-address", "chain": "synthetic", "checksum_verified": False}]}, merge.merge_runtime_clipboard),
    ("remote_control_events", {"event": "gesture", "action": "dispatchGesture", "target_package": "com.example.synthetic", "host": "example.test"}, merge.merge_runtime_remote_control),
])
def test_bundled_event_normalization_and_aggregation_preserve_occurrences(tmp_path, field, event, merger):
    event = dict(event, ts=1700000000123)
    path = tmp_path / "runtime_report.json"
    raw = json.dumps({field: [event, event]}).encode()
    path.write_bytes(raw)
    report = _report()
    merger(report, str(path))
    refs = [ref for lead in report.leads for ref in lead.source_refs]
    refs.extend(ref for finding in report.findings for ref in finding.evidences)
    refs.extend(ref for endpoint in report.endpoints for ref in endpoint.evidences)
    assert refs
    assert {ref.locator["json_pointer"] for ref in refs} == {f"/{field}/0", f"/{field}/1"}
    assert all(ref.provenance["artifact_sha256"] == hashlib.sha256(raw).hexdigest() for ref in refs)
    assert all(ref.observed_at == 1700000000.123 for ref in refs)
    assert all(ref.provenance["completeness"] == "not_attested" for ref in refs)
    if field == "sqlcipher_events":
        assert all("未尝试导出" in ref.snippet for ref in refs)
        assert all(ref.provenance["capture_gaps"] == ["database_export_not_attempted_non_interference"] for ref in refs)


@pytest.mark.parametrize("raw", [b'{"credential_events":[],"credential_events":[]}', b'{"v":NaN}', b'{"v":1e999}', b'[]', b'{'])
def test_runtime_input_failure_is_not_a_successful_zero_findings_merge(tmp_path, raw):
    from apkscan.dynamic.runtime_input import RuntimeReadFailure

    path = tmp_path / "runtime_report.json"
    path.write_bytes(raw)
    assert isinstance(merge._read_runtime_payload(str(path)), RuntimeReadFailure)
    report = _report()
    merge.merge_and_rerender(report, None, str(tmp_path), formats=["json"])
    assert report.meta["runtime_report_input"]["status"] == "unavailable"
    assert {step["status"] for step in report.meta["runtime_merge_steps"].values()} == {"skipped"}
    assert report.meta["visibility"]["sources"]["runtime"]["visibility"] == "partial"


def test_runtime_input_budget_and_invalid_rows_are_reported(tmp_path, monkeypatch):
    from apkscan.dynamic import runtime_input

    path = tmp_path / "runtime_report.json"
    raw = b'{"credential_events":[null,{}]}'
    path.write_bytes(raw)
    receipt = runtime_input.input_receipt(merge._read_runtime_payload(str(path)))
    assert receipt["status"] == "partial"
    assert receipt["gaps"]["credential_events"]["count"] == 1
    monkeypatch.setattr(runtime_input, "REPORT_JSON_MAX_BYTES", len(raw) - 1)
    receipt = runtime_input.input_receipt(merge._read_runtime_payload(str(path)))
    assert receipt["reason"] == "runtime_report_size_limit"
