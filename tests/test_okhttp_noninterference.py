"""Execute bundled JS against a synthetic Java bridge, never a device."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from apkscan.dynamic.cryptohook import normalize_credential_event
from apkscan.dynamic.cryptohook import normalize_sqlcipher_event


def test_okhttp_observer_never_consumes_request_body():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js required for synthetic Java bridge execution")
    hook = Path(__file__).parents[1] / "apkscan/dynamic/frida_js/okhttp_hook.js"
    harness = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const events = [], execute = {};
let bodyReads = 0, originals = 0, fail = false;
const sentinel = new Error('synthetic original failure');
const request = {
  url: () => ({toString: () => 'https://backend.example.test/'}),
  method: () => 'POST',
  headers: () => ({size: () => 0}),
  body: () => { bodyReads++; throw new Error('body must not be inspected'); }
};
const receiver = {
  request: () => request,
  execute: () => { originals++; if(fail) throw sentinel; return 'original-result'; }
};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), {
  Java: {perform: f => f(), use: name => {
    if (name === 'okhttp3.RealCall') return {execute};
    throw new Error('unsupported synthetic class');
  }},
  send: e => events.push(e), console: {log: () => {}}, Date
});
for (let i=0; i<1501; i++) {
  assert.equal(execute.implementation.call(receiver), 'original-result');
}
fail = true;
assert.throws(() => execute.implementation.call(receiver), e => e === sentinel);
assert.equal(originals, 1502);
assert.equal(bodyReads, 0);
const observations = events.filter(e => e.type === 'apkscan-credential');
assert.equal(observations.length, 1500);
for (const event of observations) {
  assert.equal(event.body, null);
  assert.equal(event.body_capture_status, 'not_read_non_interference');
}
process.stdout.write(JSON.stringify(observations[0]));
"""
    completed = subprocess.run(
        [node, "-e", harness, str(hook)], capture_output=True, text=True,
        timeout=10, check=True,
    )
    normalized = normalize_credential_event(json.loads(completed.stdout))
    assert normalized is not None
    assert normalized["body_capture_status"] == "not_read_non_interference"
    assert normalized["body"] == ""


def test_sqlcipher_observer_never_executes_sql_or_changes_original_return_and_error():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js required for synthetic Java bridge execution")
    hook = Path(__file__).parents[1] / "apkscan/dynamic/frida_js/sqlcipher_hook.js"
    harness = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const events = [], sentinel = new Error('synthetic open failure');
let sqlCalls = 0, originals = 0, fail = false;
const database = new Proxy({}, {
  get: (_target, property) => {
    sqlCalls++;
    throw new Error('database access forbidden: ' + String(property));
  },
  set: (_target, property) => {
    sqlCalls++;
    throw new Error('database write forbidden: ' + String(property));
  }
});
const javaClasses = [];
function open() { originals++; if (fail) throw sentinel; return database; }
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), {
  Java: {perform: f => f(), use: name => {
    javaClasses.push(name);
    if (name === 'net.sqlcipher.database.SQLiteDatabase') {
      return {openOrCreateDatabase: {overloads: [open]}};
    }
    throw new Error('unsupported synthetic class');
  }}, send: e => events.push(e), console: {log: () => {}}, Date
});
for (let i=0; i<201; i++) {
  assert.strictEqual(open.implementation('/synthetic/db-' + i + '.db', 'fixture-key'), database);
}
fail = true;
assert.throws(() => open.implementation('/synthetic/fail.db', 'fixture-key'), e => e === sentinel);
assert.equal(originals, 202);
assert.equal(sqlCalls, 0);
assert(!javaClasses.includes('java.io.File'));
const observations = events.filter(e => e.type === 'apkscan-sqlcipher');
assert.equal(observations.length, 200);
assert(observations.every(e => e.event === 'key_only' && e.plain_path === null &&
  e.export_status === 'not_attempted_non_interference'));
process.stdout.write(JSON.stringify(observations[0]));
"""
    completed = subprocess.run([node, "-e", harness, str(hook)], capture_output=True,
                               text=True, timeout=10, check=True)
    normalized = normalize_sqlcipher_event(json.loads(completed.stdout))
    assert normalized is not None
    assert normalized["export_status"] == "not_attempted_non_interference"
    assert normalized["plain_path"] == ""
