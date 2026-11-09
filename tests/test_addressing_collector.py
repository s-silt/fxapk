import hashlib
import json
from pathlib import Path

from tests.test_addressing_runtime import CONTEXT, events


def test_observer_events_are_archived_with_host_scope_and_exact_links(tmp_path):
    from apkscan.dynamic.addressing_events import AddressingEventCollector, verify_event_record
    collector = AddressingEventCollector(tmp_path, {**CONTEXT, "script_sha256": "b" * 64})
    for event in events():
        collector.on_message({"type": "send", "payload": {**event, "type": "fxapk-addressing-event-v1",
                                                          "sample_sha256": "c" * 64}}, None)
    rows = collector.records()
    assert len(rows) == 2
    for row in rows:
        assert row["sample_sha256"] == CONTEXT["sample_sha256"]
        path = tmp_path / row["raw_record"]["stored_path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["raw_record"]["sha256"]
        assert verify_event_record(row, tmp_path)
    network = next(r for r in rows if r["kind"] == "network_argument")
    assert network["origin_event_id"] == "read-1" and network["origin_object_id"] == "obj-1"
    network["origin_event_id"] = "invented"
    assert not verify_event_record(network, tmp_path)
    path.write_bytes(b"changed")
    assert not verify_event_record(rows[-1], tmp_path)


def test_observer_missing_records_and_budget_exhaustion_fail_closed(tmp_path, monkeypatch):
    from apkscan.dynamic import addressing_events as ae
    assert not ae.verify_event_record(events()[0], tmp_path)
    monkeypatch.setattr(ae, "MAX_EVENTS", 1)
    collector = ae.AddressingEventCollector(tmp_path, CONTEXT)
    for event in events():
        collector.on_message({"type": "send", "payload": {**event, "type": "fxapk-addressing-event-v1"}}, None)
    assert collector.dropped == 1 and len(collector.records()) == 1
    assert "observer_event_budget_exceeded" in collector.records()[0]["capture_gaps"]
    assert not ae.verify_event_record(collector.records()[0], tmp_path)


def test_runtime_report_persists_explicit_event_channel(tmp_path):
    from apkscan.dynamic.capture import _write_runtime_report
    path = _write_runtime_report("test.example.app", tmp_path, [], addressing_events=events(), capture_context=CONTEXT)
    assert {r["event_id"] for r in json.loads(Path(path).read_text())["addressing_events"]} == {"read-1", "call-1"}
    assert json.loads(Path(path).read_text())["capture_context"]["sample_sha256"] == CONTEXT["sample_sha256"]


def test_process_scope_requires_observed_identity(monkeypatch):
    from apkscan.dynamic.capture import _addressing_context
    from apkscan.dynamic import recovery
    monkeypatch.setattr(recovery, "_identity", lambda *a: {"start_ticks": "12345"})
    scope = _addressing_context({"pid": 123, "package": "test.example.app"}, "test-device", modified=False)
    assert scope["process_start"] == "12345" and scope["target_attributed"] is True
    def fail(*a): raise ValueError("process_changed")
    monkeypatch.setattr(recovery, "_identity", fail)
    scope = _addressing_context({"pid": 123, "package": "test.example.app"}, "test-device", modified=True)
    assert scope["process_start"] is None and scope["target_attributed"] is False
    assert scope["runtime_variant"] == "modified-runtime"
