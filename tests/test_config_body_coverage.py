"""Real-device regression reduced to offline, synthetic observer contracts."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from apkscan.dynamic import probe_coverage


def test_config_body_status_round_trip_without_changing_default_profile():
    args = dict(package="test.example.app", frida_requested=True,
                pass_tag="synthetic", sample_sha256="a" * 64)
    default = probe_coverage.new_probe_state(requested_hooks=None, **args)
    assert len(default["requested_hooks"]) == 7
    assert "config_body" not in default["families"]
    state = probe_coverage.new_probe_state(requested_hooks=("config_body",), **args)
    for status, hook in [("installed", None), ("triggered", "response"), ("truncated", "events")]:
        probe_coverage.record_status(state, {"type": "apkscan-probe-status", "family": "config_body",
                                            "status": status, **({"hook": hook} if hook else {})})
    receipt = probe_coverage.finalize_probe_state(state, observed_pid=123, observed_uid=10001)
    assert receipt["installed_hooks"] == ["config_body"]
    family = receipt["families"]["config_body"]
    assert family["trigger_status"] == "observed"
    assert family["triggered_hooks"] == ["response"]
    assert family["truncation_known"] is True


@pytest.mark.parametrize("variant,expected", [("kotlin", "installed"), ("legacy", "installed"),
                                               ("no_response", "partial"), ("no_body", "unsupported")])
def test_response_observer_compatibility_and_truthful_coverage(variant, expected):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js unavailable")
    scripts = Path(__file__).parents[1] / "apkscan/dynamic/frida_js"
    source = (scripts / "probe_coverage.js").read_text(encoding="utf-8") + "\n" + (
        scripts / "config_body_hook.js").read_text(encoding="utf-8")
    program = r'''
const vm=require('vm'), assert=require('assert'), messages=[];
let reads=0, responses=0, fail=false, observedBodies=0;
const error=new Error('original exception'), raw=[1,2,3];
const body={contentLength:()=>3,equals:()=>true,$dispose:()=>{}};
body.$h=body;
const response={body:()=>body,request:()=>({url:()=> 'https://cfg.example.test/config',method:()=> 'GET'}),headers:()=>({size:()=>0})};
const bytes={call:()=>{reads++;if(fail)throw error;return raw;}};
const method={call:()=>{responses++;if(fail)throw error;return response;}};
const context={__fxapkConfigConsumer:{observeBody:(meta,value)=>{assert.strictEqual(value,raw);observedBodies++;}},
Java:{available:true,perform:fn=>fn(),retain:x=>x,vm:{getEnv:()=>({isSameObject:(a,b)=>a===b})},use:name=>{
 if(name==='okhttp3.ResponseBody' && VARIANT!=='no_body')return {bytes:{overload:()=>bytes}};
 if(VARIANT==='legacy' && name==='okhttp3.RealCall')return {getResponseWithInterceptorChain:{overload:()=>method}};
 if(VARIANT==='kotlin' && name==='okhttp3.internal.connection.RealCall')return {'getResponseWithInterceptorChain$okhttp':{overload:()=>method}};
 throw new Error('API unavailable');
}},send:(meta,data)=>messages.push({meta,data})};
vm.createContext(context);vm.runInContext(SOURCE,context);
const statuses=()=>messages.filter(m=>m.meta.type==='apkscan-probe-status' && m.meta.family==='config_body');
assert(statuses().some(m=>m.meta.status===EXPECTED),JSON.stringify(statuses()));
if(EXPECTED==='installed'){
 assert.strictEqual(method.implementation(),response);assert.strictEqual(reads,0);
 const differentBody={equals:()=>true};differentBody.$h=differentBody;
 assert.strictEqual(bytes.implementation.call(differentBody),raw);
 assert.strictEqual(messages.filter(m=>m.meta.type==='fxapk-config-body-v1').length,1);
 assert.strictEqual(observedBodies,0);
 assert.strictEqual(bytes.implementation.call(body),raw);
 assert.strictEqual(reads,2);assert.strictEqual(responses,1);assert.strictEqual(observedBodies,1);
 const bodies=messages.filter(m=>m.meta.type==='fxapk-config-body-v1');
 assert.strictEqual(bodies.length,2);assert.strictEqual(bodies[0].meta.body_complete,false);
 assert.strictEqual(bodies[1].meta.body_complete,true);
 assert(statuses().some(m=>m.meta.status==='triggered' && m.meta.hook==='response'));
 assert(statuses().some(m=>m.meta.status==='triggered' && m.meta.hook==='body_bytes'));
 fail=true;assert.throws(()=>method.implementation(),e=>e===error);
 assert.throws(()=>bytes.implementation.call(body),e=>e===error);
 assert.strictEqual(reads,3);assert.strictEqual(responses,2);
}
'''.replace("VARIANT", json.dumps(variant)).replace("EXPECTED", json.dumps(expected)).replace("SOURCE", json.dumps(source))
    result = subprocess.run([node], input=program, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
