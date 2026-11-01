import hashlib
import json

import pytest
from typer.testing import CliRunner

from apkscan.core.observations import occurrence_id
from apkscan.core.models import Confidence
from apkscan.dynamic import probe_ingest


def test_raw_bytes_and_decoded_text_have_distinct_hashes_and_line_locations(tmp_path):
    raw = b"\xff\r\n[http][LEAD] https://backend.example.test/api\r\n"
    path = tmp_path / "probe.log"
    path.write_bytes(raw)
    leads = probe_ingest.load_probe_log(path)
    ref = leads[0].source_refs[0]
    assert ref.provenance["log_file_sha256"] == hashlib.sha256(raw).hexdigest()
    assert ref.provenance["log_text_sha256"] == hashlib.sha256(raw.decode("utf-8", "replace").encode()).hexdigest()
    assert ref.provenance["log_file_sha256"] != ref.provenance["log_text_sha256"]
    assert ref.locator == {"line": 2, "line_base": 1, "char_offset": 3,
                           "offset_unit": "decoded-text-codepoint"}
    assert ref.provenance["target_app_attribution_verified"] is False


def test_dedup_keeps_occurrences_without_mutating_inputs_or_upgrading_same_probe(tmp_path, monkeypatch):
    monkeypatch.setattr(probe_ingest, "_network_advice", lambda *args: ("", ""))
    line = "[http][LEAD] backend.example.test"
    leads = probe_ingest.parse_probe_log(line + "\n" + line)
    deduped = probe_ingest.dedup(leads)
    assert len(deduped) == 1
    assert len(deduped[0].source_refs) == 2
    assert len(leads[0].source_refs) == 1
    assert len({occurrence_id(ref) for ref in deduped[0].source_refs}) == 2
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"leads": [], "endpoints": []}), encoding="utf-8")
    probe_ingest.merge_into_report_json(str(path), [leads[0]])
    assert json.loads(path.read_text(encoding="utf-8"))["leads"][0]["confidence"] == Confidence.MEDIUM.value
    probe_ingest.merge_into_report_json(str(path), [leads[1]])
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["leads"][0]["confidence"] == Confidence.MEDIUM.value
    assert len(payload["leads"][0]["source_refs"]) == 2
    endpoint = next(ep for ep in payload["endpoints"] if ep["value"] == "backend.example.test")
    assert len(endpoint["evidences"]) == 2
    assert all(ref["occurrence_id"] for ref in endpoint["evidences"])


def test_budget_refuses_partial_log_instead_of_silently_dropping(monkeypatch, tmp_path):
    monkeypatch.setattr(probe_ingest, "MAX_PROBE_LEADS", 1)
    text = "[http][LEAD] one.example.test\n[http][LEAD] two.example.test"
    with pytest.raises(probe_ingest.ProbeLogLimitError, match="probe_log_record_limit"):
        probe_ingest.parse_probe_log(text)
    monkeypatch.setattr(probe_ingest, "MAX_PROBE_LOG_BYTES", 16)
    path = tmp_path / "probe.log"
    path.write_text(text)
    with pytest.raises(probe_ingest.ProbeLogLimitError, match="probe_log_input_limit"):
        probe_ingest.load_probe_log(path)


def test_cli_budget_failure_does_not_write_partial_ledger(monkeypatch, tmp_path):
    from apkscan.cli import app

    monkeypatch.setattr(probe_ingest, "MAX_PROBE_LOG_BYTES", 16)
    log = tmp_path / "probe.log"
    log.write_text("[http][LEAD] backend.example.test")
    ledger = tmp_path / "ledger.json"
    result = CliRunner().invoke(app, ["probe-leads", str(log), "--json", str(ledger)])
    assert result.exit_code == 2
    assert "probe_log_input_limit" in result.output
    assert not ledger.exists()
