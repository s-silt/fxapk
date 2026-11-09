"""A bounded org.json -> Socket observer; no actual network or device access."""
import json
import hashlib
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).parents[1]


def run_observer(scenario):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js unavailable")
    source = ROOT / "apkscan/dynamic/frida_js/config_consumer_hook.js"
    assert source.is_file(), "consumer observer not implemented"
    result = subprocess.run([node, str(ROOT / "tests/fixtures/config_consumer_harness.js"), str(source), scenario],
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("scenario", ["direct", "different_string_object", "mutated_bytes", "changed_field",
    "repeated_read", "prefix_body", "socket_failure", "send_failure", "budget", "unsupported_bridge",
    "json_subclass", "socket_subclass", "transplanted_field", "nested_array", "android_factory", "android_factory_clone",
    "android_factory_shared"])
def test_observer_preserves_original_objects_and_requires_direct_origin(scenario):
    result = run_observer(scenario)
    links = [e for e in result["events"] if e.get("kind") == "network_argument"]
    if scenario in ("direct", "nested_array", "android_factory"):
        assert len(links) == 1
        field = next(e for e in result["events"] if e.get("kind") == "config_field_read")
        assert links[0]["origin_event_id"] == field["event_id"]
        assert links[0]["origin_object_id"] == field["object_id"]
        assert links[0]["peer_ip"] == "192.0.2.1" and links[0]["port"] == 443
        assert links[0]["sni"] is None and links[0]["sni_status"] == "not_applicable"
        assert field["field_path"] == ("$.items[0].host" if scenario == "nested_array" else "$.host")
        assert field["value"] == "api.example.test"
        assert field["sequence"] < links[0]["sequence"]
    else:
        assert not links
    assert result["original_calls_once"] and result["argument_identity_preserved"]
    assert result["return_and_exception_preserved"]


def test_config_consumer_is_opt_in_and_requires_body_observer():
    from apkscan.dynamic.capture import _build_injection_source
    from apkscan.dynamic.probe_coverage import new_probe_state
    assert "fxapk-config-consumer-v1" not in _build_injection_source(enable_tls_unpinning=False)
    with pytest.raises(ValueError, match="config_consumer_requires_config_body"):
        _build_injection_source(selected_hooks=("config_consumer",), enable_tls_unpinning=False)
    source = _build_injection_source(selected_hooks=("config_body", "config_consumer"), enable_tls_unpinning=False)
    assert "fxapk-config-consumer-v1" in source
    state = new_probe_state(package="test.example.app", requested_hooks=("config_body", "config_consumer"),
                            frida_requested=True, pass_tag="fixture", sample_sha256="a" * 64)
    assert "config_consumer" in state["families"]


def test_invalid_consumer_profile_fails_before_any_device_work(monkeypatch):
    from apkscan.dynamic import capture
    def unexpected(*args, **kwargs):
        pytest.fail("invalid profile reached capture setup")
    monkeypatch.setattr(capture, "decide_capture", unexpected)
    result = capture.run("test.example.app", selected_hooks=("config_consumer",))
    assert result["status"] == "error"
    assert "config_consumer_requires_config_body" in str(result)


def test_tcp_coordinates_distinguish_not_applicable_from_missing():
    from tests.test_addressing_runtime import events, review
    rows = events()
    rows[1].update(protocol="tcp", sni=None, sni_status="not_applicable", host_status="socket_argument",
                   peer_ip="192.0.2.1", network_api="java.net.Socket.<init>(java.lang.String,int)", socket_connected=True)
    assert review(rows)[0]["correlations"][0]["consumption"] == "verified"
    for change in ({"sni_status": "not_observed"}, {"peer_ip": None}, {"socket_connected": False}, {"network_api": "unknown"}):
        changed = [rows[0], {**rows[1], **change}]
        assert review(changed)[0]["correlations"][0]["consumption"] == "candidate"
    rows[1].update(protocol="https", sni="api.example.test", sni_status="inferred_from_url")
    assert review(rows)[0]["correlations"][0]["consumption"] == "candidate"


@pytest.mark.parametrize("protocol", ["http", "https"])
def test_http_coordinates_require_observed_host_and_applicable_sni(protocol):
    from tests.test_addressing_runtime import events, review
    rows = events()
    rows[1].update(protocol=protocol, host_status="observed", sni_status="observed")
    if protocol == "http":
        rows[1].update(sni=None, sni_status="not_applicable")
    assert review(rows)[0]["correlations"][0]["consumption"] == "verified"
    rows[1]["host_status"] = "inferred_from_url"
    assert review(rows)[0]["correlations"][0]["consumption"] == "candidate"
    rows[1]["host_status"] = "observed"
    rows[1]["sni_status"] = "not_observed"
    assert review(rows)[0]["correlations"][0]["consumption"] == "candidate"


def test_real_observer_script_to_archive_projection_and_digest(tmp_path):
    from apkscan.core.models import Endpoint, Report
    from apkscan.dynamic.addressing import project_addressing
    from apkscan.dynamic.addressing_events import AddressingEventCollector
    from apkscan.dynamic.config_artifacts import ConfigBodyCollector
    from apkscan.dynamic.event_origin import RuntimePayload
    from apkscan.report.digest import build_digest
    from tests.test_addressing_runtime import ART, BODY, CONTEXT, SAMPLE
    collector = AddressingEventCollector(tmp_path, CONTEXT)
    for event in run_observer("direct")["events"]:
        collector.on_message({"type": "send", "payload": event}, None)
    bodies = ConfigBodyCollector(tmp_path, CONTEXT)
    source_url = "https://cfg.example.test/config"
    bodies.on_message({"type": "send", "payload": {"type": "fxapk-config-body-v1", "source_url": source_url,
                       "body_complete": True, "declared_length": len(BODY)}}, BODY)
    payload = {"package_name": "test.example.app", "runtime_variant": "original-runtime",
               "addressing_events": collector.records(), "config_body_artifacts": bodies.records()}
    raw = json.dumps(payload).encode()
    path = tmp_path / "runtime_report.json"
    path.write_bytes(raw)
    namespace = "capture:" + hashlib.sha256(raw).hexdigest()
    endpoint = Endpoint(kind="domain", value="api.example.test")
    report = Report(package_name="test.example.app", meta={"sample_sha256": SAMPLE,
        "remote_config_artifacts": [{**ART, "source_url": source_url, "domains": [endpoint.value]}],
        "runtime_observations": [{"capture_ref": namespace, "value": endpoint.value, "eligible": True,
                                  "runtime": {"variant": "original-runtime", "target_attributed": True}}]},
                    leads=[], endpoints=[endpoint], findings=[], analyzer_status=[])
    bound = RuntimePayload(payload, raw, str(path))
    assert project_addressing(report, bound) == 1
    view = build_digest({"meta": report.meta})["control_chains"][0]["backends"][0]
    assert view["runtime_correlations"][0]["consumption"] == "verified"
    assert view["runtime_correlations"][0]["sni_status"] == "not_applicable"
    assert view["runtime_correlations"][0]["protocol"] == "tcp"
    assert endpoint.evidences == [] and report.leads == []
    # Altering just the normalized peer must fail the original-envelope check.
    next(e for e in payload["addressing_events"] if e["kind"] == "network_argument")["peer_ip"] = "198.51.100.1"
    project_addressing(report, bound)
    assert report.meta["control_chains"][0]["backends"][0]["runtime_correlations"][0]["consumption"] == "candidate"
