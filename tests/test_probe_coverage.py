from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from apkscan.core.models import Report
from apkscan.dynamic import capture, probe_coverage
from apkscan.dynamic.merge import merge_capture_quality


def _probe_state(*, frida_requested: bool = True) -> dict[str, Any]:
    return probe_coverage.new_probe_state(
        package="com.example.synthetic",
        requested_hooks=("crypto",),
        frida_requested=frida_requested,
        pass_tag="synthetic-pass",
        sample_sha256="a" * 64,
    )


@pytest.mark.parametrize("failure_point", ["load", "resume"])
def test_probe_receipts_remain_sticky_when_session_start_fails(
    monkeypatch: pytest.MonkeyPatch, failure_point: str
) -> None:
    captured: dict[str, Any] = {}

    class FakeScript:
        def __init__(self, source: str) -> None:
            captured["source"] = source
            self.handlers: list[Any] = []

        def on(self, _name: str, handler: Any) -> None:
            self.handlers.append(handler)

        def load(self) -> None:
            message = {
                "type": "send",
                "payload": {
                    "type": "apkscan-probe-status",
                    "family": "crypto",
                    "status": "installed",
                },
            }
            trigger = {
                "type": "send",
                "payload": {
                    "type": "apkscan-probe-status",
                    "family": "crypto",
                    "status": "triggered",
                    "hook": "cipher_init",
                },
            }
            for handler in self.handlers:
                handler(message, None)
                handler(trigger, None)
            if failure_point == "load":
                raise RuntimeError("synthetic load failure")

    class FakeSession:
        def create_script(self, source: str) -> FakeScript:
            return FakeScript(source)

        def detach(self) -> None:
            captured["detached"] = True

    class FakeDevice:
        def spawn(self, _argv: list[str]) -> int:
            return 4321

        def attach(self, _pid: int) -> FakeSession:
            return FakeSession()

        def resume(self, _pid: int) -> None:
            if failure_point == "resume":
                raise RuntimeError("synthetic resume failure")

        def kill(self, _pid: int) -> None:
            captured["killed"] = True

    monkeypatch.setitem(
        sys.modules,
        "frida",
        SimpleNamespace(get_usb_device=lambda timeout=None: FakeDevice()),
    )
    state = _probe_state()

    assert capture._start_frida_session(
        "com.example.synthetic",
        [],
        probe_state=state,
        selected_hooks=("crypto",),
        enable_tls_unpinning=False,
    ) == (None, None)

    assert state["script_sha256"] == hashlib.sha256(captured["source"].encode()).hexdigest()
    assert state["observed_pid"] == 4321
    coverage = probe_coverage.finalize_probe_state(state, observed_pid=4321, observed_uid=None)
    assert coverage["families"]["crypto"]["registration_status"] == "installed"
    assert coverage["families"]["crypto"]["trigger_status"] == "observed"
    assert coverage["families"]["crypto"]["triggered_hooks"] == ["cipher_init"]
    assert captured["killed"] is True
    assert captured["detached"] is True


def test_floor_only_probe_state_is_not_requested() -> None:
    coverage = probe_coverage.finalize_probe_state(
        _probe_state(frida_requested=False), observed_pid=None, observed_uid=None
    )

    assert coverage["frida_requested"] is False
    assert all(
        row["registration_status"] == "not_requested"
        for row in coverage["families"].values()
    )


def test_sink_cap_marker_is_retained_as_a_lower_bound_drop() -> None:
    state = _probe_state()
    probe_coverage.note_sink_drop(state, "crypto", [{"_capped": True}])
    coverage = probe_coverage.finalize_probe_state(
        state, observed_pid=None, observed_uid=None
    )

    assert coverage["families"]["crypto"]["dropped_observation"] is True
    assert coverage["families"]["crypto"]["dropped_count_lower_bound"] == 1


def test_java_bridge_readiness_does_not_confirm_missing_family_registration() -> None:
    state = _probe_state()
    probe_coverage.record_status(
        state,
        {"type": "apkscan-probe-status", "family": "java_bridge", "status": "ready"},
    )
    session = SimpleNamespace()

    assert capture._frida_hook_status(session, state) == "unconfirmed"

    probe_coverage.record_status(
        state,
        {"type": "apkscan-probe-status", "family": "crypto", "status": "installed"},
    )
    assert capture._frida_hook_status(session, state) == "confirmed"


def test_runtime_report_events_bind_capture_context_and_merge_coverage(tmp_path) -> None:
    context = {
        "script_sha256": "b" * 64,
        "package": "com.example.synthetic",
        "pid": 4321,
        "uid": None,
        "round": None,
        "pass_tag": "synthetic-pass",
        "sample_sha256": "a" * 64,
    }
    signals = {
        "probe_coverage": probe_coverage.finalize_probe_state(
            _probe_state(), observed_pid=4321, observed_uid=None
        )
    }
    bound_context = {
        **context,
        "script_sha256": "c" * 64,
        "pid": 8765,
    }
    report_path = capture._write_runtime_report(
        "com.example.synthetic",
        tmp_path,
        [],
        capture_signals=signals,
        crypto_events=[
            {"src": "cipher", "event": "init"},
            {"src": "cipher", "event": "doFinal", "capture_context": bound_context},
        ],
        credential_events=[
            {"body_capture_status": "not_read_non_interference"}
        ],
        sqlcipher_events=[
            {"export_status": "not_attempted_non_interference"}
        ],
        capture_context=context,
    )
    payload = json.loads((tmp_path / "runtime_report.json").read_text(encoding="utf-8"))
    event = payload["crypto_events"][0]
    bound_event = payload["crypto_events"][1]
    okhttp_event = payload["credential_events"][0]
    sqlcipher_event = payload["sqlcipher_events"][0]

    assert event["capture_context"] == {
        "script_sha256": None,
        "package": context["package"],
        "pid": None,
        "uid": None,
        "round": context["round"],
        "pass_tag": context["pass_tag"],
        "sample_sha256": context["sample_sha256"],
    }
    assert "process_binding_missing" in event["capture_gaps"]
    assert bound_event["capture_context"] == bound_context
    assert event["event_locator"]["json_pointer"] == "/crypto_events/0"
    assert event["event_provenance"] == {
        "completeness": "not_attested",
        "target_app_attribution_verified": False,
    }
    assert set(okhttp_event["capture_gaps"]) == {
        "process_binding_missing",
        "request_body_not_read_non_interference",
    }
    assert set(sqlcipher_event["capture_gaps"]) == {
        "process_binding_missing",
        "database_export_not_attempted_non_interference",
    }
    assert payload["capture_signals"]["probe_coverage"] == signals["probe_coverage"]

    report = Report(
        package_name="com.example.synthetic",
        meta={},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    merge_capture_quality(report, report_path)
    assert report.meta["capture_signals"]["probe_coverage"] == signals["probe_coverage"]


def test_shared_js_coverage_protocol_is_bounded_and_preserves_calls() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    bootstrap = json.dumps(probe_coverage.load_bootstrap())
    program = f"""
const assert = require('assert');
const vm = require('vm');
const bootstrap = {bootstrap};
function runtime(java) {{
  const messages = [];
  const context = {{ Java: java, send: value => messages.push(value) }};
  vm.createContext(context);
  vm.runInContext(bootstrap, context);
  return {{ coverage: context.__fxapkProbeCoverage, messages }};
}}

const installed = runtime({{ available: true, perform: callback => callback() }});
installed.coverage.perform('crypto', function () {{
  installed.coverage.attempted('crypto', 'cipher_init');
  installed.coverage.installed('crypto', 'cipher_init');
  let originalCalls = 0;
  function original(value) {{
    originalCalls += 1;
    if (value < 0) throw new Error('original throw');
    return value + 3;
  }}
  function observed(value) {{
    installed.coverage.trigger('crypto', 'cipher_init');
    return original.call(this, value);
  }}
  assert.strictEqual(observed(4), 7);
  assert.throws(() => observed(-1), /original throw/);
  assert.strictEqual(originalCalls, 2);
  installed.coverage.drop('crypto', 'events');
  installed.coverage.drop('crypto', 'events');
  installed.coverage.truncated('crypto', 'cipher_final');
  installed.coverage.truncated('crypto', 'cipher_final');
}});
const statuses = installed.messages.map(message => message.status);
assert.strictEqual(statuses.filter(status => status === 'installed').length, 1);
assert.strictEqual(statuses.filter(status => status === 'triggered').length, 1);
assert.strictEqual(statuses.filter(status => status === 'dropped').length, 1);
assert.strictEqual(statuses.filter(status => status === 'truncated').length, 1);
const dropped = installed.messages.find(message => message.status === 'dropped');
assert.strictEqual(dropped.dropped_count_lower_bound, 1);
assert.strictEqual(dropped.drop_count_semantics, 'lower_bound');
assert.strictEqual(
  installed.messages.find(message => message.status === 'truncated').event_completeness,
  'not_attested'
);

const unsupported = runtime({{ available: false, perform: callback => callback() }});
unsupported.coverage.perform('crypto', function () {{}});
assert(unsupported.messages.some(message => message.status === 'unsupported'));

const failed = runtime({{ available: true, perform: callback => callback() }});
failed.coverage.perform('jsbridge', function () {{
  failed.coverage.attempted('jsbridge', 'add_interface');
}});
assert(failed.messages.some(message => message.status === 'installation_failed'));

const partial = runtime({{ available: true, perform: callback => callback() }});
partial.coverage.perform('okhttp', function () {{
  partial.coverage.attempted('okhttp', 'execute');
  partial.coverage.installed('okhttp', 'execute');
  partial.coverage.attempted('okhttp', 'proceed');
}});
assert(partial.messages.some(message => message.status === 'partial'));
"""
    result = subprocess.run(
        [node, "-e", program],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_bundled_crypto_hook_registers_both_mac_init_overloads() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    hook_path = Path(__file__).parents[1] / "apkscan/dynamic/frida_js/crypto_hook.js"
    bootstrap = json.dumps(probe_coverage.load_bootstrap())
    hook_source = json.dumps(hook_path.read_text(encoding="utf-8"))
    program = f"""
const assert = require('assert');
const vm = require('vm');
const messages = [];
const originalCalls = [];
const originalFailure = new Error('synthetic Mac.init failure');
let shouldFail = false;
const keyOverload = {{}};
const specOverload = {{}};
const Mac = {{
  init: {{
    overload: (...types) => types.length === 1 ? keyOverload : specOverload
  }}
}};
const Java = {{
  available: true,
  perform: callback => callback(),
  use: name => {{
    if (name === 'javax.crypto.Mac') return Mac;
    throw new Error('unsupported synthetic class');
  }}
}};
const context = {{
  Java,
  send: message => messages.push(message),
  console: {{ log: () => {{}} }}
}};
vm.createContext(context);
vm.runInContext({bootstrap}, context);
vm.runInContext({hook_source}, context);
const receiver = {{
  getAlgorithm: () => 'HmacSHA256',
  init: function (...args) {{
    originalCalls.push(args);
    if (shouldFail) throw originalFailure;
    return args.length === 1 ? 'key-init-result' : 'key-spec-init-result';
  }}
}};
const key = {{ getEncoded: () => null }};
assert.equal(keyOverload.implementation.call(receiver, key), 'key-init-result');
assert.equal(specOverload.implementation.call(receiver, key, {{ name: 'spec' }}),
  'key-spec-init-result');
shouldFail = true;
assert.throws(
  () => keyOverload.implementation.call(receiver, key),
  error => error === originalFailure
);
assert.equal(originalCalls.length, 3);
const coverage = messages.filter(message =>
  message.type === 'apkscan-probe-status' && message.family === 'crypto'
);
assert(coverage.some(message => message.status === 'installed'));
assert(!coverage.some(message =>
  ['partial', 'installation_failed', 'registration_failed'].includes(message.status)
));
assert.equal(coverage.filter(message => message.status === 'api_unavailable').length > 0, true);
"""
    result = subprocess.run(
        [node, "-e", program],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
