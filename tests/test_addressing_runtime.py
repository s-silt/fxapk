"""Runtime provenance is scoped evidence; equal values never establish consumption."""
import copy
import hashlib
from pathlib import Path

import pytest

from apkscan.config import runtime_chain

SAMPLE = "a" * 64
BODY = b'{"host":"api.example.test"}'
SHA = hashlib.sha256(BODY).hexdigest()
ART = {"sha256": SHA, "decoded": True, "material": {"complete": True}, "fields": [{"path": "$.host", "value": "api.example.test", "kind": "domain"}]}
CONTEXT = {"sample_sha256": SAMPLE, "capture_ref": "round-1", "runtime_variant": "original-runtime", "pid": 123, "process_start": "start-1", "target_attributed": True}


def events():
    return [
        {**CONTEXT, "event_id": "read-1", "kind": "config_field_read", "observed_at": "2026-11-09T00:00:01Z", "sequence": 1,
         "artifact_sha256": SHA, "field_path": "$.host", "value": "api.example.test", "source_binding": "direct_object_origin", "object_id": "obj-1"},
        {**CONTEXT, "event_id": "call-1", "kind": "network_argument", "observed_at": "2026-11-09T00:00:02Z", "sequence": 2,
         "value": "api.example.test", "protocol": "https", "port": 443, "host": "api.example.test", "sni": "api.example.test",
         "host_status": "observed", "sni_status": "observed",
         "origin_event_id": "read-1", "origin_object_id": "obj-1", "source_binding": "direct_object_origin"},
    ]


def review(rows, bodies=None, rounds=None):
    return runtime_chain.review_runtime([ART], rows, sample_sha256=SAMPLE,
                                      body_records=bodies or [{**CONTEXT, "sha256": SHA, "hash_scope": "full", "verified": True}], rounds=rounds or [])


def test_direct_event_chain_is_verified_and_inputs_are_unchanged():
    rows = events()
    before = copy.deepcopy(rows)
    result = review(rows)
    assert rows == before
    assert result[0]["correlations"][0]["consumption"] == "verified"
    assert result[0]["correlations"][0]["evidence_event_ids"] == ["call-1", "read-1"]


@pytest.mark.parametrize("change", ["same_value_only", "cross_round", "cross_sample", "cross_process", "cross_variant", "duplicate_event", "wrong_object", "reverse_time", "missing_port", "missing_attribution", "wrong_field", "prefix_body"])
def test_incomplete_or_conflicting_binding_never_verifies(change):
    rows = events()
    bodies = [{**CONTEXT, "sha256": SHA, "hash_scope": "full", "verified": True}]
    if change == "same_value_only":
        rows[1].pop("origin_event_id")
    elif change == "cross_round":
        rows[0]["capture_ref"] = "round-2"
    elif change == "cross_sample":
        rows[0]["sample_sha256"] = "b" * 64
    elif change == "cross_process":
        rows[0]["process_start"] = "other-start"
    elif change == "cross_variant":
        rows[0]["runtime_variant"] = "modified-runtime"
    elif change == "duplicate_event":
        rows.append(copy.deepcopy(rows[0]))
    elif change == "wrong_object":
        rows[1]["origin_object_id"] = "different-object"
    elif change == "reverse_time":
        rows[0]["sequence"] = 3
    elif change == "missing_port":
        rows[1].pop("port")
    elif change == "missing_attribution":
        rows[1]["target_attributed"] = False
    elif change == "wrong_field":
        rows[0]["field_path"] = "$.different"
    elif change == "prefix_body":
        bodies[0]["hash_scope"] = "prefix"
    result = review(rows, bodies)
    assert result[0]["correlations"]
    assert all(c["consumption"] == "candidate" and c["gaps"] for c in result[0]["correlations"])


def test_original_and_modified_rounds_remain_separate():
    original = events()
    modified = [{**r, "capture_ref": "round-2", "runtime_variant": "modified-runtime", "event_id": r["event_id"] + "-m"} for r in events()]
    modified[1]["origin_event_id"] += "-m"
    result = review(original + modified)
    assert {c["capture_ref"] for c in result[0]["correlations"]} == {"round-1", "round-2"}


def test_absence_requires_original_attributed_business_round():
    round_record = {**CONTEXT, "business_traffic_observed": True, "observed_values": ["other.example.test"]}
    result = review([], rounds=[round_record])
    assert result[0]["suspicions"] == [{"kind": "not_contacted_in_round", "capture_ref": "round-1"}]
    for changed in ({"runtime_variant": "modified-runtime"}, {"target_attributed": False}, {"business_traffic_observed": False}, {"sample_sha256": "b" * 64}):
        assert review([], rounds=[{**round_record, **changed}])[0]["suspicions"] == []


@pytest.mark.parametrize("complete,declared,scope", [(True, len(BODY), "full"), (True, 1, "prefix"), (False, len(BODY), "prefix"), (True, None, "prefix")])
def test_body_collector_archives_exact_bytes(tmp_path, complete, declared, scope):
    from apkscan.dynamic.config_artifacts import ConfigBodyCollector
    collector = ConfigBodyCollector(tmp_path, CONTEXT)
    payload = {"type": "fxapk-config-body-v1", "source_url": "https://cfg.example.test/config", "method": "GET", "observed_at": "2026-11-09T00:00:00Z",
               "response_headers": {"Content-Type": "application/json"}, "declared_length": declared, "body_complete": complete}
    collector.on_message({"type": "send", "payload": payload}, BODY)
    row = collector.records()[0]
    assert (tmp_path / row["stored_path"]).read_bytes() == BODY
    assert row["sha256"] == SHA and row["hash_scope"] == scope
    assert row["sample_sha256"] == SAMPLE and row["capture_ref"] == "round-1"
    assert row["comparability"] == ("comparable" if scope == "full" else "not_comparable")
    assert runtime_chain.compare_material(ART, row)["status"] == ("content_matches" if scope == "full" else "not_comparable")


def test_different_full_bodies_are_only_content_differs():
    result = runtime_chain.compare_material(ART, {"sha256": "b" * 64, "hash_scope": "full", "verified": True})
    assert result == {"status": "content_differs", "static_sha256": SHA, "runtime_sha256": "b" * 64}


def test_body_collector_does_not_trust_payload_context_or_exceed_budget(tmp_path, monkeypatch):
    from apkscan.dynamic import config_artifacts
    monkeypatch.setattr(config_artifacts, "MAX_BODY_BYTES", 4)
    collector = config_artifacts.ConfigBodyCollector(tmp_path, CONTEXT)
    collector.on_message({"type": "send", "payload": {"type": "fxapk-config-body-v1", "sample_sha256": "b" * 64}}, BODY)
    row = collector.records()[0]
    assert row["hash_scope"] == "prefix" and row["received_bytes"] == 4
    assert row["sample_sha256"] == SAMPLE
    assert row["comparability"] == "not_comparable"
    assert Path(tmp_path / row["stored_path"]).stat().st_size == 4


def test_body_observer_is_opt_in_and_report_retains_records(tmp_path):
    import json
    from apkscan.dynamic import capture
    source = capture._build_injection_source(selected_hooks=("config_body",), enable_tls_unpinning=False)
    assert "fxapk-config-body-v1" in source
    assert "fxapk-config-body-v1" not in capture._build_injection_source(enable_tls_unpinning=False)
    path = capture._write_runtime_report("test.example.app", tmp_path, [], config_body_artifacts=[{**CONTEXT, "sha256": SHA}])
    assert json.loads(Path(path).read_text(encoding="utf-8"))["config_body_artifacts"][0]["sha256"] == SHA


@pytest.mark.parametrize("key", ["event_id", "capture_ref", "origin_event_id"])
def test_malformed_event_identity_cannot_crash_or_verify(key):
    rows = events()
    rows[1][key] = []
    assert review(rows)[0]["correlations"][0]["consumption"] == "candidate"


def test_merge_rechecks_body_and_scopes_rounds_without_changing_evidence(tmp_path):
    import json
    from apkscan.core.models import Endpoint, Report
    from apkscan.dynamic import merge
    from apkscan.report.digest import build_digest
    body = tmp_path / "config_artifacts" / f"{SHA}.bin"
    body.parent.mkdir()
    body.write_bytes(BODY)
    record = {**CONTEXT, "sha256": SHA, "hash_scope": "full", "verified": True,
              "source_url": "https://cfg.example.test/config", "stored_path": f"config_artifacts/{SHA}.bin", "received_bytes": len(BODY), "declared_length": len(BODY)}
    from apkscan.dynamic.addressing_events import AddressingEventCollector
    collector = AddressingEventCollector(tmp_path, CONTEXT)
    for event in events():
        collector.on_message({"type": "send", "payload": {**event, "type": "fxapk-addressing-event-v1"}}, None)
    payload = {"package_name": "test.example.app", "runtime_variant": "original-runtime",
               "addressing_events": collector.records(), "config_body_artifacts": [record]}
    raw = json.dumps(payload).encode()
    path = tmp_path / "runtime_report.json"
    path.write_bytes(raw)
    capture_ref = "capture:" + hashlib.sha256(raw).hexdigest()
    ep = Endpoint(kind="domain", value="api.example.test")
    art = {**ART, "source_url": "https://cfg.example.test/config", "domains": [ep.value]}
    report = Report(package_name="test.example.app", meta={"sample_sha256": SAMPLE, "remote_config_artifacts": [art],
        "runtime_observations": [{"capture_ref": capture_ref, "value": ep.value, "eligible": True,
                                  "runtime": {"variant": "original-runtime", "target_attributed": True}}]},
                    leads=[], endpoints=[ep], findings=[], analyzer_status=[])
    assert merge.merge_config_addressing(report, str(path))["bindings"] == 1
    backend = report.meta["control_chains"][0]["backends"][0]
    assert backend["runtime_correlations"][0]["consumption"] == "verified"
    assert backend["runtime_correlations"][0]["capture_ref"] == capture_ref
    assert backend["material_comparisons"][0]["status"] == "content_matches"
    assert ep.evidences == [] and report.leads == []
    assert build_digest({"meta": report.meta})["control_chains"][0]["backends"][0]["runtime_correlations"][0]["consumption"] == "verified"
    event_path = tmp_path / payload["addressing_events"][0]["raw_record"]["stored_path"]
    original_event = event_path.read_bytes()
    event_path.write_bytes(b"changed")
    merge.merge_config_addressing(report, str(path))
    assert report.meta["control_chains"][0]["backends"][0]["runtime_correlations"][0]["consumption"] == "candidate"
    event_path.write_bytes(original_event)
    body.write_bytes(b"changed")
    merge.merge_config_addressing(report, str(path))
    backend = report.meta["control_chains"][0]["backends"][0]
    assert backend["runtime_correlations"][0]["consumption"] == "candidate"
    assert backend["material_comparisons"][0]["status"] == "not_comparable"

    # A body from another source round cannot repair this round's missing material.
    body.write_bytes(BODY)
    payload["config_body_artifacts"][0]["capture_ref"] = "round-2"
    path.write_text(json.dumps(payload), encoding="utf-8")
    from apkscan.dynamic.event_origin import RuntimePayload
    from apkscan.dynamic.addressing import project_addressing
    changed = path.read_bytes()
    report.meta["runtime_observations"][0]["capture_ref"] = "capture:" + hashlib.sha256(changed).hexdigest()
    project_addressing(report, RuntimePayload(payload, changed, str(path)))
    assert all(c["consumption"] == "candidate" for c in report.meta["control_chains"][0]["backends"][0]["runtime_correlations"])


def test_body_archive_rejects_ancestor_links(tmp_path):
    from apkscan.dynamic.config_artifacts import ConfigBodyCollector
    # The archive must inspect all path components; an output ancestor can redirect writes.
    import os
    link, outside = tmp_path / "link", tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    collector = ConfigBodyCollector(link / "nested", CONTEXT)
    collector.on_message({"type": "send", "payload": {"type": "fxapk-config-body-v1", "body_complete": True, "declared_length": len(BODY)}}, BODY)
    assert collector.records()[0]["verified"] is False
    assert not list(outside.rglob("*.bin"))


@pytest.mark.parametrize("name", ["objstore-config-hook.js", "coldstart-config-hook.js"])
def test_manual_probe_emits_binary_body_contract_without_second_read(name):
    import json
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js unavailable")
    source = (Path(__file__).parents[1] / "apkscan/dynamic/frida_probes" / name).read_text(encoding="utf-8")
    program = """
const vm = require('vm'), assert = require('assert');
const messages = [];
const context = {Java: {perform: () => {}}, console: {log: () => {}},
    setTimeout: () => {}, setInterval: () => {}, send: (meta, data) => messages.push({meta, data})};
vm.createContext(context); vm.runInContext(SOURCE, context);
const req = {url: () => 'https://cfg.example.test/config', method: () => 'GET'};
const resp = {body: () => ({contentLength: () => 3}), headers: () => ({size: () => 0})};
context._emitConfigBody(req, resp, [-1, 0, 1]);
assert.deepStrictEqual(Array.from(new Uint8Array(messages[0].data)), [255, 0, 1]);
assert.strictEqual(messages[0].meta.body_complete, true);
context._emitConfigBody(req, resp, null);
assert.strictEqual(messages[1].meta.body_complete, false);
for (let i=0; i<60; i++) context._emitConfigBody(req, resp, [1,2,3]);
assert.strictEqual(messages.length, 40);
""".replace("SOURCE", json.dumps(source))
    result = subprocess.run([node], input=program, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("change", ["body_attribution", "sample_hash", "network_coordinate"])
def test_runtime_proof_rejects_unqualified_body_and_malformed_coordinates(change):
    rows = events()
    bodies = [{**CONTEXT, "sha256": SHA, "hash_scope": "full", "verified": True}]
    sample = SAMPLE
    if change == "body_attribution":
        bodies[0]["target_attributed"] = False
    elif change == "network_coordinate":
        rows[1]["sni"] = ["api.example.test"]
    else:
        sample = "not-a-sha256"
        for row in rows + bodies:
            row["sample_sha256"] = sample
    result = runtime_chain.review_runtime([ART], rows, sample_sha256=sample, body_records=bodies, rounds=[])
    assert result[0]["correlations"][0]["consumption"] == "candidate"


def test_body_observer_preserves_original_result_exception_and_call_count():
    import json
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js unavailable")
    source = (Path(__file__).parents[1] / "apkscan/dynamic/frida_js/config_body_hook.js").read_text(encoding="utf-8")
    program = """
const vm = require('vm'), assert = require('assert');
let reads=0, responses=0, fail=false, messages=[];
const raw=[1,2,3], error=new Error('app error');
const body={contentLength:()=>3, equals:function(other){return this===other;}, $dispose:()=>{}};
body.$h=body;
const response={body:()=>body, request:()=>({url:()=> 'https://cfg.example.test/config',method:()=> 'GET'}),headers:()=>({size:()=>0})};
const bytes={call:()=>{reads++; if(fail) throw error; return raw;}};
const call={call:()=>{responses++; if(fail) throw error; return response;}};
const context={Java:{available:true,perform:fn=>fn(),retain:value=>value,vm:{getEnv:()=>({isSameObject:(a,b)=>a===b})},use:name=>{
    if(name==='okhttp3.ResponseBody') return {bytes:{overload:()=>bytes}};
    if(name==='okhttp3.RealCall') return {getResponseWithInterceptorChain:{overload:()=>call}};
    throw new Error('unavailable');}},send:(meta,data)=>messages.push({meta,data})};
vm.createContext(context); vm.runInContext(SOURCE,context);
assert.strictEqual(call.implementation(),response);
assert.strictEqual(reads,0);
assert.strictEqual(bytes.implementation.call(body),raw);
assert.strictEqual(reads,1); assert.strictEqual(responses,1);
assert.strictEqual(messages[0].meta.body_complete,false);
assert.strictEqual(messages[1].meta.body_complete,true);
fail=true;
assert.throws(()=>bytes.implementation.call(body), e=>e===error);
assert.throws(()=>call.implementation(), e=>e===error);
assert.strictEqual(reads,2); assert.strictEqual(responses,2);
assert.strictEqual(messages.length,2);
""".replace("SOURCE", json.dumps(source))
    result = subprocess.run([node], input=program, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name", ["objstore-config-hook.js", "coldstart-config-hook.js"])
def test_manual_probe_unreadable_body_retains_an_incomparable_observation(name):
    import json
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js unavailable")
    source = (Path(__file__).parents[1] / "apkscan/dynamic/frida_probes" / name).read_text(encoding="utf-8")
    program = """
const vm=require('vm'), assert=require('assert');
const method={}, callClass={execute:{overload:()=>method}}, messages=[];
const context={Java:{perform:fn=>fn(),use:name=>{
    if(name==='okhttp3.RealCall') return callClass;
    if(name==='okio.Buffer') return {};
    throw new Error('unavailable');}},console:{log:()=>{}},setTimeout:()=>{},setInterval:()=>{},
    send:(meta,data)=>messages.push({meta,data})};
context.global=context;vm.createContext(context);vm.runInContext(SOURCE,context);
context._isObjStore=()=>true;
const request={url:()=> 'https://cfg.example.test/config',method:()=> 'GET',body:()=>null,headers:()=>({size:()=>0})};
const response={code:()=>200,peekBody:()=>{throw new Error('stream unavailable');},body:()=>({contentLength:()=>-1}),headers:()=>({size:()=>0})};
let calls=0;
const value=method.implementation.call({execute:()=>{calls++;return response;},request:()=>request});
assert.strictEqual(value,response);assert.strictEqual(calls,1);
assert.strictEqual(messages.length,1);assert.strictEqual(messages[0].meta.type,'fxapk-config-body-v1');
assert.strictEqual(messages[0].meta.body_complete,false);assert.strictEqual(messages[0].data,undefined);
""".replace("SOURCE", json.dumps(source))
    result = subprocess.run([node], input=program, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
