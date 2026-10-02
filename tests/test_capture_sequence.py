"""Run fake acquisition only; never invoke a device, shell, proxy, or network."""
import json
from pathlib import Path

import pytest

from apkscan.core.models import Report
from apkscan.dynamic import auto, capture, cryptohook
from apkscan.dynamic.capture_sequence import run_rounds, targeted_hooks


def report():
    return Report(package_name="com.example.synthetic", meta={"crypto_recipe": {"synthetic": True}},
                  leads=[], endpoints=[], findings=[], analyzer_status=[])


def fake_runner(events):
    def run(package, **kwargs):
        events.append(kwargs)
        out = Path(kwargs["out"])
        out.mkdir(parents=True)
        file = out / "runtime_report.json"
        file.write_text(json.dumps({"endpoints": [], "runtime_variant": "original-runtime",
                                   "capture_signals": {}}))
        return {"status": "done", "reason": "", "report_paths": [str(file)]}
    return run


def test_three_round_order_profiles_and_artifact_binding(tmp_path):
    calls = []
    rows = run_rounds("com.example.synthetic", report=report(), unpacked=True,
                      out_dir=str(tmp_path), runner=fake_runner(calls))
    assert [c["mode"] for c in calls] == ["floor-only", "no-proxy", "both"]
    assert "selected_hooks" not in calls[0]
    assert calls[1]["selected_hooks"] == ("crypto", "jsbridge", "sensitive_api", "okhttp",
                                           "sqlcipher", "clipboard", "accessibility")
    assert calls[2]["selected_hooks"] == ("crypto",)
    assert len({r["runtime_report_path"] for r in rows}) == 3
    assert all(len(r["runtime_report_sha256"]) == 64 for r in rows)


def test_missing_unpack_does_not_fake_targeted_round(tmp_path):
    calls = []
    rows = run_rounds("com.example.synthetic", report=report(), unpacked=False,
                      out_dir=str(tmp_path), runner=fake_runner(calls))
    assert len(calls) == 2 and rows[-1]["status"] == "skipped"
    assert targeted_hooks(report(), unpacked=False) == ()


def test_existing_round_evidence_is_not_overwritten(tmp_path):
    (tmp_path / "round1-pcap").mkdir()
    calls = []
    rows = run_rounds("com.example.synthetic", report=report(), unpacked=True,
                      out_dir=str(tmp_path), runner=fake_runner(calls), duration=99999)
    assert rows[0]["reason"] == "round_output_exists_refuse_overwrite"
    assert len(calls) == 2
    assert all(r["duration_seconds"] == 1200 for r in rows)


def test_hook_profile_is_bundled_and_rejects_sample_code():
    source = capture._build_injection_source(selected_hooks=("crypto",))
    assert cryptohook.FRIDA_CRYPTO_HOOK_JS in source
    assert cryptohook.FRIDA_SQLCIPHER_HOOK_JS not in source
    assert cryptohook.FRIDA_ANTIDETECT_JS not in source
    with pytest.raises(ValueError):
        capture._build_injection_source(selected_hooks=("arbitrary-sample-script",))


@pytest.mark.parametrize("floor_failed", [False, True])
def test_auto_unpacks_then_runs_three_rounds_and_merges_each(tmp_path, monkeypatch, floor_failed):
    events = []
    rep = report()
    monkeypatch.setattr(auto.device, "select_target_serial", lambda: "synthetic-device")
    monkeypatch.setattr(auto, "_run_doctor", lambda **kw: auto._step("doctor", "done", ""))
    monkeypatch.setattr(auto, "_ensure_root_frida_server", lambda **kw: None)
    monkeypatch.setattr(auto, "_run_install_app", lambda *a, **kw: auto._step("install", "done", ""))
    monkeypatch.setattr(auto, "_run_static", lambda *a, **kw: (auto._step("static", "done", ""), rep, rep.package_name, [], "synthetic"))
    def unpack(*a, **kw):
        events.append("unpack")
        return auto._step("unpack", "done", ""), [], rep
    monkeypatch.setattr(auto, "_run_unpack", unpack)
    calls = []
    runner = fake_runner(calls)
    def capture_fake(*a, **kw):
        events.append(kw["mode"])
        if floor_failed and kw["mode"] == "floor-only":
            return {"status": "error", "reason": "synthetic floor failure"}
        return runner(*a, **kw)
    monkeypatch.setattr(capture, "run", capture_fake)
    def merge(*a, **kw):
        events.append("merge")
        return auto._step("merge", "done", ""), []
    monkeypatch.setattr(auto, "_run_merge", merge)
    monkeypatch.setattr(auto, "_run_closure", lambda *a, **kw: (auto._step("close", "done", ""), {"status": "partial"}, []))
    outcome = auto.run("synthetic.apk", out_dir=str(tmp_path), three_rounds=True, online=False, repackage=False)
    assert events == ["unpack", "floor-only", "no-proxy", "both"] + ["merge"] * (2 if floor_failed else 3)
    assert len(rep.meta["capture_rounds"]) == 3
    assert outcome["status"] == "partial"


def test_round_namespace_preserves_same_coordinate_from_different_captures(tmp_path, monkeypatch):
    from apkscan.core.models import Endpoint, Evidence
    from apkscan.dynamic import merge
    observed = []
    monkeypatch.setattr(merge, "load_runtime_endpoints",
        lambda path: [Endpoint(kind="domain", value="api.example.test",
                               evidences=[Evidence(source="runtime", location="flow:1")])])
    def collect(rep, endpoints, *a, **kw):
        observed.extend(endpoints[0].evidences)
        return {"merged": 1, "new_leads": 0, "report_paths": []}
    monkeypatch.setattr(merge, "merge_and_rerender", collect)
    for name in ("a" * 64, "b" * 64):
        auto._run_merge(report(), str(tmp_path / "runtime_report.json"), out_dir=str(tmp_path),
                        base="synthetic", formats=[], on_progress=None,
                        evidence_namespace="capture:" + name)
    assert len({ev.location for ev in observed}) == 2
    assert all(ev.source == "runtime" for ev in observed)


def test_two_rounds_can_complement_ciphertext_and_recipe_without_editing_raw(tmp_path):
    import hashlib
    from apkscan.dynamic.capture_sequence import complement_decryption
    from tests.test_merge import _c5b_encrypt_fixed_iv, _C5B_KEY
    key, iv = _C5B_KEY, "abcdefghijklmnop"
    plain = '{"url":"https://api.example.test/v1"}'
    cipher = _c5b_encrypt_fixed_iv(plain, key, iv)
    events = [{"src": "cipher", "event": "init", "transformation": "AES/CFB/PKCS5Padding",
               "key_hex": key.encode().hex(), "iv_hex": iv.encode().hex()}] * 2
    rep = report()
    rep.meta = {"capture_apk_identity": {"which": "original", "original": {"sha256": "a" * 64}}}
    rows = []
    originals = {}
    for number, (messages, crypto) in enumerate([
        ([{"url": "https://api.example.test/config",
           "response_body": json.dumps({"data": cipher, "timestamp": 1700000000000})}], []),
        ([], events),
    ]):
        path = tmp_path / f"round-{number}.json"
        raw = json.dumps({"package_name": rep.package_name, "runtime_variant": "original-runtime",
                          "messages": messages, "crypto_events": crypto}).encode()
        path.write_bytes(raw)
        originals[path] = raw
        rows.append({"runtime_report_path": str(path), "runtime_report_sha256": hashlib.sha256(raw).hexdigest(),
                     "sample_sha256": "a" * 64})
    result = complement_decryption(rep, rows)
    assert result["decrypted"] == 1 and result["originals_modified"] is False
    assert any(ep.value == "https://api.example.test/v1" for ep in rep.endpoints)
    assert all(path.read_bytes() == raw for path, raw in originals.items())
    rows[0]["sample_sha256"] = "b" * 64
    assert "round_sample_identity_mismatch" in complement_decryption(rep, rows)["gaps"]


def test_cross_round_decrypt_requires_original_sample_identity():
    from apkscan.dynamic.capture_sequence import complement_decryption
    rep = report()
    result = complement_decryption(rep, [])
    assert result["status"] == "not_attempted"
    assert result["gaps"] == ["original_sample_identity_unconfirmed"]


def test_targeted_selection_consumes_actual_static_metadata():
    rep = report()
    rep.meta = {"webview_signals": ["synthetic"], "repack_identity": {
        "stack": {"families": {"sqlcipher": ["libsqlcipher.so"]}}}}
    assert targeted_hooks(rep, unpacked=True) == ("jsbridge", "sqlcipher")


def test_general_probe_keeps_all_legacy_observers(tmp_path):
    calls = []
    run_rounds('com.example.synthetic', report=report(), unpacked=True,
               out_dir=str(tmp_path), runner=fake_runner(calls))
    profile = calls[1]['selected_hooks']
    assert set(profile) == {'crypto', 'jsbridge', 'sensitive_api', 'okhttp',
                            'sqlcipher', 'clipboard', 'accessibility'}
    assert capture._build_injection_source(selected_hooks=profile) == capture._build_injection_source()
