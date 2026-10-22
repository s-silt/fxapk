from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.fixture
def compat(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "plugins/fxapk-rea/src"))
    return importlib.import_module("fxapk_rea.rea_compat")


@pytest.mark.parametrize("version", ["6.4.0", "6.7.0"])
def test_pinned_repair_dry_run_idempotence_and_unknown_source(compat, tmp_path, monkeypatch, version):
    (tmp_path / "package.json").write_text(json.dumps({"name": "rea-agents", "version": version}))
    target = tmp_path / compat.RELATIVE
    target.parent.mkdir(parents=True)
    before = ("// fixture\n" + compat._OLD).encode()
    after = (compat._IMPORT + "// fixture\n" + compat._NEW).encode()
    suffix = "_670" if version == "6.7.0" else ""
    monkeypatch.setattr(compat, f"BEFORE{suffix}_SHA256", hashlib.sha256(before).hexdigest())
    monkeypatch.setattr(compat, f"AFTER{suffix}_SHA256", hashlib.sha256(after).hexdigest())
    target.write_bytes(before)
    assert compat.repair(tmp_path)["changed"]
    assert target.read_bytes() == before
    assert compat.repair(tmp_path, apply=True)["changed"]
    assert target.read_bytes() == after
    assert not compat.repair(tmp_path, apply=True)["changed"]
    launcher = tmp_path / "scripts/rea.mjs"
    assert compat.provenance(str(launcher))["status"] == "patched"
    target.write_bytes(b"local changes")
    with pytest.raises(ValueError, match="unrecognized"):
        compat.repair(tmp_path, apply=True)
    assert target.read_bytes() == b"local changes"
    assert compat.provenance(str(launcher))["status"] == "not_detected"


def test_missing_source_only_is_recoverable_javascript(compat, tmp_path):
    node = os.environ.get("FXAPK_NODE") or shutil.which("node")
    if not node:
        pytest.skip("Node required for REA JavaScript compatibility regression")
    script = r'''
import assert from 'node:assert/strict';
class CdpCommandRejection extends Error {
    constructor(command,code,reportedMessage){super(reportedMessage);Object.assign(this,{command,code,reportedMessage})}
}
const requiredScriptSource = value => {if(typeof value.scriptSource !== 'string')throw Error('malformed');return value.scriptSource};
const sourceResult = text => ({included:true,text});
const sourceExcluded = reason => ({included:false,reason});
async function captureScriptSource(script,state){const {context}=state;
''' + compat._NEW + r'''
}
const exclusions=[];
let failure=null;
let response={scriptSource:'valid source'};
const state={context:{connection:{send:async()=>{if(failure)throw failure;return response}}},events:{completeness:{exclude:(...args)=>exclusions.push(args)}}};
for(const message of ['No script for id: 5','Could not find script with given id']){
    failure=new CdpCommandRejection('Debugger.getScriptSource',-32000,message);
    assert.equal((await captureScriptSource({scriptId:'5'},state)).included,false);
}
assert.deepEqual(exclusions,[['script_sources','provider_unavailable',1],['script_sources','provider_unavailable',1]]);
failure=null;
assert.deepEqual(await captureScriptSource({scriptId:'6'},state),{included:true,text:'valid source'});
for(const error of [new Error('No script for id: 5'),new CdpCommandRejection('Debugger.getScriptSource',-32000,'Other protocol error'),new CdpCommandRejection('Debugger.getScriptSource',-32601,'No script for id: 5'),new CdpCommandRejection('Other.command',-32000,'No script for id: 5')]){
    failure=error;await assert.rejects(captureScriptSource({scriptId:'5'},state),e=>e===error);
}
failure=null;response={};await assert.rejects(captureScriptSource({scriptId:'5'},state),/malformed/);
assert.equal(exclusions.length,2);
'''
    target = tmp_path / "compat.mjs"
    target.write_text(script, encoding="utf-8")
    result = subprocess.run([node, str(target)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_trace_capture_and_import_share_hard_bound(compat):
    del compat
    from fxapk_rea import attachment, supplement, trace, trace_runtime
    from fxapk_rea.evidence import EvidenceError

    assert trace.MAX_RAW_BYTES == trace_runtime._MAX_ENVELOPE == 1024 * 1024
    assert attachment._MAX_TRACE == supplement._MAX_TRACE_ORIGINAL_BYTES == trace.MAX_RAW_BYTES
    with pytest.raises(EvidenceError, match="trace_oversize"):
        trace.project_trace(b" " * (trace.MAX_RAW_BYTES + 1))
    # A syntactically valid envelope beyond the old cap reaches schema validation;
    # it must not be silently truncated or rejected by the obsolete input limit.
    raw = json.dumps({"padding": "x" * (300 * 1024)}).encode()
    with pytest.raises(EvidenceError) as exc:
        trace.project_trace(raw)
    assert str(exc.value) != "trace_oversize"


@pytest.mark.parametrize("reason,expected", [("target_changed", 2), ("target_not_allowed", 1), ("protocol_error", 1)])
def test_navigation_retry_once_preserves_first_attempt(compat, tmp_path, monkeypatch, reason, expected):
    del compat
    from fxapk_rea import runtime

    calls = []
    raw = json.dumps({"data": {"code": "target_unavailable", "details": {"operation": "inspect_web_page", "reason": reason}}}).encode()

    def run(args, out, **kwargs):
        calls.append((args, out))
        out.mkdir(parents=True)
        (out / "stdout.bin").write_bytes(raw)
        return {"ok": False, "errors": [], "streams": {}, "process_tree": {"timed_out": False, "ownership_complete": True, "termination_complete": True}}

    monkeypatch.setattr(runtime, "run_bounded", run)
    monkeypatch.setattr(runtime.ReaRuntime, "command", lambda self: ["rea"])
    result = runtime.ReaRuntime().inspect("http://127.0.0.1:9999", "T", "https://example.test", tmp_path / "execution", observation_ms=1000)
    assert len(calls) == expected
    assert (tmp_path / "execution/stdout.bin").read_bytes() == raw
    if expected == 2:
        assert calls[0][0] == calls[1][0]
        assert calls[1][1] == tmp_path / "execution/after-navigation"
        assert result["navigation_retry"]["scope"] == "new_observation_window_after_navigation"
        assert result["ok"] is False  # no third attempt or false success
