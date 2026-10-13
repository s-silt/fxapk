"""Synthetic native REA address recovery. No device, network, or live Ghidra."""

from __future__ import annotations

import hashlib
import importlib
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan.core.models import EvidenceScope

ROOT = Path(__file__).parents[1]
PLUGIN_SRC = ROOT / "plugins" / "fxapk-rea" / "src"
DOMAIN = b"api.native.example.test"
DOC_IP = "192.0.2.1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pe(*, machine: int = 0x8664, dll: bool = False, managed: bool = False) -> bytes:
    """Minimal native PE header. CLR directory size is explicit."""
    size_opt = 240
    blob = bytearray(0x80 + 24 + size_opt)
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x80)
    blob[0x80:0x84] = b"PE\0\0"
    chars = 0x2000 if dll else 0x0002
    struct.pack_into("<HHIIIHH", blob, 0x84, machine, 1, 0, 0, 0, size_opt, chars)
    magic = 0x20B if machine == 0x8664 else 0x10B
    struct.pack_into("<H", blob, 0x80 + 24, magic)
    num_off, dir_off = (108, 112) if magic == 0x20B else (92, 96)
    struct.pack_into("<I", blob, 0x80 + 24 + num_off, 16)
    struct.pack_into("<II", blob, 0x80 + 24 + dir_off + 14 * 8, 0, 16 if managed else 0)
    return bytes(blob)


def _elf(machine: int = 183) -> bytes:
    blob = bytearray(64)
    blob[0:4] = b"\x7fELF"
    blob[4] = 2
    blob[5] = 1
    struct.pack_into("<H", blob, 18, machine)
    return bytes(blob)


def _xor(data: bytes, key: int) -> bytes:
    return bytes(item ^ key for item in data)


@pytest.fixture
def native(monkeypatch):
    monkeypatch.syspath_prepend(str(PLUGIN_SRC))
    import fxapk_rea.plugin as plugin

    importlib.reload(plugin)
    module = importlib.import_module("fxapk_rea.native")
    reloaded = importlib.reload(module)
    # reload() keeps the native module dict and rebinds NativeError inside it.
    # native_cli captured the previous class and function at import time, so a
    # later except NativeError misses the exception the old function now raises.
    native_cli = importlib.import_module("fxapk_rea.native_cli")
    importlib.reload(native_cli)
    return reloaded


def _envelope(
    procedure: str,
    binary_sha: str,
    *,
    ok: bool = True,
    status: str | None = None,
    provider: str = "ghidra",
    command: str = "function",
    operation: str = "analyze_function",
) -> bytes:
    """Small canonical REA 6.4.0 function envelope. Not a copy of the live capture."""
    data: dict = {
        "subject": {"digest": {"sha256": binary_sha}, "format": "pe"},
        "provider": {"id": provider, "version": "12.1.4"},
        "operation": operation,
        "parameters": {"procedure": procedure},
        "raw_result": {
            "value": {
                "procedure": {"name": procedure, "address": "0x1000"},
                "pseudocode": "void fn() { /* decompiler limitation: not source */ }",
                "assembly": ["0x1000: NOP"],
                "limitations": ["Pseudocode is a decompiler observation."],
            }
        },
        "normalized_result": {"procedure": {"name": procedure}},
    }
    if status is not None:
        data["status"] = status
    payload = {"ok": ok, "data": data, "meta": {"command": command, "duration": "1ms"}}
    if not ok:
        payload["error"] = {"code": "execution_failure", "message": "failed"}
    return (json.dumps(payload) + "\n").encode()


def _install_engine(monkeypatch, native, stdout: bytes, *, ok: bool = True, calls: list | None = None):
    def fake(argv, out, *, timeout, max_stdout=8 * 1024 * 1024, **_kwargs):
        if calls is not None:
            calls.append(list(argv))
        out.mkdir(parents=True, exist_ok=False)
        (out / "stdout.bin").write_bytes(stdout)
        (out / "stderr.bin").write_bytes(b"")
        return {
            "ok": ok,
            "exit_code": 0 if ok else 1,
            "errors": [] if ok else ["exit"],
            "streams": {
                "stdout": {"truncated": False},
                "stderr": {"truncated": False},
            },
        }

    monkeypatch.setattr(native, "run_bounded", fake)


def _runtime_ok(monkeypatch, native):
    monkeypatch.setattr(
        native.ReaRuntime,
        "capabilities",
        lambda self: {
            "status": "ok",
            "reason": "",
            "rea_version": "6.4.0",
            "supported_rea_versions": ["6.4.0"],
        },
    )
    monkeypatch.setattr(native.ReaRuntime, "command", lambda self: ["node", "rea.mjs"])


def test_capabilities_backend_unavailable_and_elf_mismatch(native, monkeypatch, tmp_path):
    calls: list = []

    def explode(*_args, **_kwargs):
        calls.append("engine")
        raise AssertionError("engine")

    monkeypatch.setattr(native, "run_bounded", explode)
    monkeypatch.setattr(
        native.ReaRuntime,
        "capabilities",
        lambda self: {"status": "unavailable", "reason": "rea_missing", "rea_version": None},
    )
    monkeypatch.setattr(native.sys, "platform", "win32")
    from fxapk_rea import runtime as rea_runtime

    monkeypatch.setattr(rea_runtime.shutil, "which", lambda *_args, **_kwargs: None)
    info = native.capabilities(provider="ghidra")
    assert info["status"] == "unavailable"
    assert info["reason"] == "rea_missing"
    assert info["live_target_verified"] is False
    assert info["android_elf"] == "unsupported_on_this_host"
    elf = tmp_path / "libnative.so"
    elf.write_bytes(_elf())
    mismatched = native.capabilities(provider="ghidra", binary=elf)
    assert mismatched["status"] == "unsupported"
    assert mismatched["target"]["format"] == "elf"
    assert calls == []


def test_inspect_realistic_envelope_uses_copy_and_exact_argv(native, monkeypatch, tmp_path):
    calls: list = []
    _runtime_ok(monkeypatch, native)
    source = tmp_path / "sample.exe"
    body = _pe() + b"\x00" * 32
    source.write_bytes(body)
    _install_engine(monkeypatch, native, _envelope("decode_host", _sha(body)), calls=calls)
    out = tmp_path / "inspect"
    native.inspect(
        source,
        out,
        provider="ghidra",
        operation="function",
        query="decode_host",
        executable="rea.mjs",
        node="node",
    )
    argv = calls[0]
    assert argv[:2] == ["node", "rea.mjs"]
    assert "function" in argv
    assert "--provider" in argv and "ghidra" in argv
    assert "--format" in argv and "json" in argv
    assert "--full-output" in argv
    assert "npx" not in argv
    copied = out / "binary.bin"
    assert copied.read_bytes() == body
    assert argv[argv.index("function") + 1] == str(copied.resolve())
    assert _sha(source.read_bytes()) == _sha(body)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["envelope"]["ok"] is True
    assert manifest["envelope"]["endpoints_derived"] is False
    assert "api.native.example.test" not in json.dumps(manifest["envelope"])
    assert manifest["query"] == "decode_host"
    assert manifest["provider"] == "ghidra"


def test_inspect_rejects_failed_truncated_and_unresolved(native, monkeypatch, tmp_path):
    _runtime_ok(monkeypatch, native)
    source = tmp_path / "sample.exe"
    source.write_bytes(_pe())
    _install_engine(monkeypatch, native, _envelope("decode_host", _sha(source.read_bytes())), ok=False)
    with pytest.raises(native.NativeError, match="rea_execution_failed"):
        native.inspect(source, tmp_path / "bad-exit", provider="ghidra", operation="overview")
    assert not (tmp_path / "bad-exit" / "manifest.json").exists()

    def truncated(argv, out, *, timeout, max_stdout=1, **_kwargs):
        out.mkdir()
        (out / "stdout.bin").write_bytes(_envelope("decode_host", _sha(source.read_bytes())))
        (out / "stderr.bin").write_bytes(b"")
        return {
            "ok": False,
            "exit_code": 0,
            "errors": [],
            "streams": {"stdout": {"truncated": True}, "stderr": {"truncated": False}},
        }

    monkeypatch.setattr(native, "run_bounded", truncated)
    with pytest.raises(native.NativeError, match="rea_execution_failed"):
        native.inspect(source, tmp_path / "trunc", provider="ghidra", operation="overview")

    _install_engine(
        monkeypatch, native, _envelope("decode_host", _sha(source.read_bytes()), status="unresolved")
    )
    with pytest.raises(native.NativeError, match="envelope_not_complete"):
        native.inspect(source, tmp_path / "unresolved", provider="ghidra", operation="function", query="decode_host")


def _hidden_file() -> tuple[bytes, dict]:
    key = 0x5A
    encoded = _xor(DOMAIN, key)
    body = _pe() + b"\x11" * 8 + encoded
    offset = len(_pe()) + 8
    recipe = {
        "schema_version": "fxapk-native-recipe/1",
        "binary_sha256": _sha(body),
        "evidence_sha256": "",
        "anchor": {"operation": "function", "query": "decode_host"},
        "ranges": [
            {
                "id": "host",
                "offset": offset,
                "length": len(encoded),
                "expected_hex": encoded.hex(),
            }
        ],
        "steps": [
            {"op": "concat", "ids": ["host"]},
            {"op": "xor-byte", "key": key},
            {"op": "ascii-domain"},
        ],
    }
    return body, recipe


def _inspect_bundle(native, monkeypatch, tmp_path, body: bytes, procedure: str = "decode_host") -> Path:
    _runtime_ok(monkeypatch, native)
    _install_engine(monkeypatch, native, _envelope(procedure, _sha(body)))
    source = tmp_path / "sample.exe"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(body)
    out = tmp_path / "inspect"
    native.inspect(
        source,
        out,
        provider="ghidra",
        operation="function",
        query=procedure,
        executable="rea.mjs",
        node="node",
    )
    return out


def test_recover_xor_domain_and_encoded_documentation_ip(native, monkeypatch, tmp_path):
    body, recipe = _hidden_file()
    bundle = _inspect_bundle(native, monkeypatch, tmp_path, body)
    recipe["evidence_sha256"] = _sha((bundle / "execution" / "stdout.bin").read_bytes())
    recipe_path = tmp_path / "recipe.json"
    recipe_path.write_text(json.dumps(recipe), encoding="utf-8")
    out = tmp_path / "recover"
    summary = native.recover(bundle, recipe_path, out)
    assert summary["closure_evaluated"] is False
    assert summary["relation_verified"] is False
    assert DOMAIN.decode() not in json.dumps(summary)
    result = json.loads((out / "result.json").read_text(encoding="utf-8"))
    assert result["candidate"]["value"] == DOMAIN.decode()
    assert result["candidate"]["label"] == "analyst_reconstruction"
    assert result["candidate"]["confidence"] == "LOW"
    assert result["candidate"]["advice"] == "待核"
    assert result["candidate"]["relation_verified"] is False
    assert result["candidate"]["runtime_observed"] is False
    assert result["gaps"]

    ip_raw = bytes(int(part) for part in DOC_IP.split("."))
    encoded = _xor(ip_raw, 3)
    ip_body = _pe() + encoded
    ip_bundle = _inspect_bundle(native, monkeypatch, tmp_path / "ip", ip_body)
    ip_recipe = {
        "schema_version": "fxapk-native-recipe/1",
        "binary_sha256": _sha(ip_body),
        "evidence_sha256": _sha((ip_bundle / "execution" / "stdout.bin").read_bytes()),
        "anchor": {"operation": "function", "query": "decode_host"},
        "ranges": [{"id": "a", "offset": len(_pe()), "length": 4, "expected_hex": encoded.hex()}],
        "steps": [
            {"op": "concat", "ids": ["a"]},
            {"op": "xor-byte", "key": 3},
            {"op": "u32-ipv4", "endian": "big"},
        ],
    }
    ip_path = tmp_path / "ip.json"
    ip_path.write_text(json.dumps(ip_recipe), encoding="utf-8")
    native.recover(ip_bundle, ip_path, tmp_path / "ip-out")
    ip_result = json.loads((tmp_path / "ip-out" / "result.json").read_text(encoding="utf-8"))
    assert ip_result["candidate"]["value"] == DOC_IP
    assert ip_result["candidate"]["kind"] == "ip"


def test_recover_rejects_bad_recipe_and_random_bytes(native, monkeypatch, tmp_path):
    body, recipe = _hidden_file()
    bundle = _inspect_bundle(native, monkeypatch, tmp_path, body)
    good_evidence = _sha((bundle / "execution" / "stdout.bin").read_bytes())
    recipe["evidence_sha256"] = good_evidence

    def dump(name: str, payload: dict | None = None, raw: bytes | None = None) -> Path:
        path = tmp_path / name
        path.write_bytes(raw if raw is not None else json.dumps(payload).encode())
        return path

    wrong = dict(recipe)
    wrong["binary_sha256"] = "0" * 64
    with pytest.raises(native.NativeError, match="binary_sha256_mismatch"):
        native.recover(bundle, dump("wrong-hash.json", wrong), tmp_path / "o1")
    wrong_q = json.loads(json.dumps(recipe))
    wrong_q["anchor"]["query"] = "other"
    with pytest.raises(native.NativeError, match="function_dossier_mismatch"):
        native.recover(bundle, dump("wrong-query.json", wrong_q), tmp_path / "o2")
    wrong_b = json.loads(json.dumps(recipe))
    wrong_b["ranges"][0]["expected_hex"] = "00" * len(DOMAIN)
    with pytest.raises(native.NativeError, match="expected_bytes_mismatch"):
        native.recover(bundle, dump("wrong-bytes.json", wrong_b), tmp_path / "o3")
    bool_recipe = json.dumps(recipe).replace('"offset": ' + str(recipe["ranges"][0]["offset"]), '"offset": true', 1)
    with pytest.raises(native.NativeError, match="invalid_recipe"):
        native.recover(bundle, dump("bool.json", raw=bool_recipe.encode()), tmp_path / "o4")
    overflow = json.loads(json.dumps(recipe))
    overflow["ranges"][0]["offset"] = 2**31 - 1
    with pytest.raises(native.NativeError, match="range_out_of_bounds"):
        native.recover(bundle, dump("overflow.json", overflow), tmp_path / "o5")
    oob = json.loads(json.dumps(recipe))
    oob["ranges"][0]["offset"] = len(body) - 1
    oob["ranges"][0]["length"] = 4
    with pytest.raises(native.NativeError, match="range_out_of_bounds"):
        native.recover(bundle, dump("oob.json", oob), tmp_path / "o6")
    dup = json.dumps(recipe).replace('"schema_version"', '"schema_version"', 1)
    dup = "{" + '"schema_version": "fxapk-native-recipe/1", ' + dup[1:]
    with pytest.raises(native.NativeError, match="duplicate_json_key"):
        native.recover(bundle, dump("dup.json", raw=dup.encode()), tmp_path / "o7")
    with pytest.raises(native.NativeError, match="invalid_json"):
        native.recover(bundle, dump("nan.json", raw=b'{"schema_version": NaN}'), tmp_path / "o8")
    random_body = _pe() + bytes(range(32))
    random_bundle = _inspect_bundle(native, monkeypatch, tmp_path / "rand", random_body)
    random_recipe = {
        "schema_version": "fxapk-native-recipe/1",
        "binary_sha256": _sha(random_body),
        "evidence_sha256": _sha((random_bundle / "execution" / "stdout.bin").read_bytes()),
        "anchor": {"operation": "function", "query": "decode_host"},
        "ranges": [{"id": "a", "offset": len(_pe()), "length": 32, "expected_hex": bytes(range(32)).hex()}],
        "steps": [{"op": "concat", "ids": ["a"]}, {"op": "xor-byte", "key": 1}, {"op": "ascii-domain"}],
    }
    with pytest.raises(native.NativeError, match="invalid_hostname"):
        native.recover(random_bundle, dump("random.json", random_recipe), tmp_path / "random-out")
    assert not (tmp_path / "random-out").exists()
    assert not (tmp_path / "o1").exists()


def _report(binary_sha: str) -> dict:
    return {
        "meta": {
            "sample_sha256": "ab" * 32,
            "native_lib_hashes": [{"name": "libsynthetic.so", "sha256": binary_sha, "size": 1}],
            "closure": {"status": "partial", "gaps": ["keep"], "targets": [{"value": "old.example"}]},
            "custom_kept": {"nested": True},
        },
        "endpoints": [
            {
                "value": "old.example",
                "kind": "domain",
                "confidence": "HIGH",
                "enrichment": {"attribution": {"service_operator": "unknown"}},
                "evidences": [
                    {"source": "dex", "location": "strings", "snippet": "old.example", "scope": "case_evidence"}
                ],
            }
        ],
        "leads": [
            {
                "category": "DOMAIN",
                "value": "old.example",
                "confidence": "HIGH",
                "advice": "建议调证",
                "base_advice": "建议调证",
                "source_refs": [
                    {"source": "dex", "location": "strings", "snippet": "old.example", "scope": "case_evidence"}
                ],
            }
        ],
        "untouched": [1, 2, 3],
    }


def test_attach_preserves_report_and_is_idempotent(native, monkeypatch, tmp_path):
    body, recipe = _hidden_file()
    bundle = _inspect_bundle(native, monkeypatch, tmp_path, body)
    recipe["evidence_sha256"] = _sha((bundle / "execution" / "stdout.bin").read_bytes())
    recipe_path = tmp_path / "recipe.json"
    recipe_path.write_text(json.dumps(recipe), encoding="utf-8")
    recovery = tmp_path / "recovery"
    native.recover(bundle, recipe_path, recovery)
    report_path = tmp_path / "report.json"
    original = json.dumps(_report(_sha(body))).encode()
    report_path.write_bytes(original)
    side = tmp_path / "notes.txt"
    side.write_text("keep-at-source", encoding="utf-8")
    out = tmp_path / "attached"
    native.attach(recovery, report_path, out)
    assert report_path.read_bytes() == original
    published = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert published["untouched"] == [1, 2, 3]
    assert published["meta"]["custom_kept"] == {"nested": True}
    assert published["meta"]["closure"]["status"] == "partial"
    old = published["leads"][0]
    assert old["confidence"] == "HIGH"
    assert old["advice"] == "建议调证"
    assert published["endpoints"][0]["enrichment"]["attribution"]["service_operator"] == "unknown"
    new = next(lead for lead in published["leads"] if lead["value"] == DOMAIN.decode())
    assert new["confidence"] == "LOW"
    assert new["advice"] == "待核"
    assert new["source_refs"][0]["source"] == "derived-native"
    assert not new["source_refs"][0]["source"].startswith("runtime")
    history = published["meta"]["native_recovery"]
    assert len(history) == 1
    assert history[0]["relation_verified"] is False
    assert published["meta"]["native_recovery_input"]["source_report_absolute"]
    assert "nonnative_artifact_gap" not in published["meta"]["native_recovery_input"]
    snapshot = out / published["meta"]["native_recovery_input"]["relative_path"]
    assert snapshot.read_bytes() == original
    again = tmp_path / "attached-again"
    native.attach(recovery, out / "report.json", again)
    second = json.loads((again / "report.json").read_text(encoding="utf-8"))
    assert len(second["meta"]["native_recovery"]) == 1
    assert (again / "report.json").read_bytes() != b""
    first_snap = published["meta"]["native_recovery_input"]["relative_path"]
    assert (again / first_snap).read_bytes() == original
    with pytest.raises(native.NativeError, match="output_exists"):
        native.attach(recovery, report_path, out)


def test_attach_rejects_tamper_and_wrong_binding(native, monkeypatch, tmp_path):
    body, recipe = _hidden_file()
    bundle = _inspect_bundle(native, monkeypatch, tmp_path, body)
    recipe["evidence_sha256"] = _sha((bundle / "execution" / "stdout.bin").read_bytes())
    recipe_path = tmp_path / "recipe.json"
    recipe_path.write_text(json.dumps(recipe), encoding="utf-8")
    recovery = tmp_path / "recovery"
    native.recover(bundle, recipe_path, recovery)
    report = _report("cd" * 32)
    report_path = tmp_path / "wrong.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(native.NativeError, match="sample_binding_mismatch"):
        native.attach(recovery, report_path, tmp_path / "nope")
    assert not (tmp_path / "nope").exists()
    good = tmp_path / "good.json"
    good.write_text(json.dumps(_report(_sha(body))), encoding="utf-8")
    for name, edit in (
        ("stdout.bin", lambda root: _flip(root / "dossier" / "stdout.bin")),
        ("binary.bin", lambda root: _flip(root / "binary.bin")),
        ("recipe.json", lambda root: _flip(root / "recipe.json")),
        ("result.json", lambda root: _flip(root / "result.json")),
    ):
        copy = tmp_path / f"tamper-{name}"
        _copy_tree(recovery, copy)
        edit(copy)
        with pytest.raises(native.NativeError):
            native.attach(copy, good, tmp_path / f"out-{name}")
        assert not (tmp_path / f"out-{name}").exists()


def _flip(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[-2] ^= 0x01
    path.write_bytes(data)


def _copy_tree(src: Path, dst: Path) -> None:
    for item in src.rglob("*"):
        target = dst / item.relative_to(src)
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.read_bytes())


def test_cli_help_and_routes(native):
    plugin = importlib.import_module("fxapk_rea.plugin")
    runner = CliRunner()
    help_text = runner.invoke(plugin.rea_app, ["native", "--help"])
    assert help_text.exit_code == 0
    for name in ("capabilities", "inspect", "recover", "attach", "extract"):
        assert name in help_text.stdout
    web = runner.invoke(plugin.rea_app, ["--help"])
    assert "inspect" in web.stdout
    assert web.exit_code == 0


def test_digest_native_handoff_without_plugin_import():
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json,sys\n"
                "from apkscan.report.digest import build_digest\n"
                "report={'meta':{'native_lib_hashes':[{'name':'a.so','sha256':'ab'*32,'size':1}]},"
                "'findings':[{'id':'NATIVE-OBFUSCATION-SUSPECTED','severity':'MEDIUM'}],"
                "'endpoints':[],'leads':[]}\n"
                "digest=build_digest(report)\n"
                "print('fxapk_rea' in sys.modules)\n"
                "print(json.dumps(digest['native_recovery']))\n"
            ),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    lines = completed.stdout.splitlines()
    assert lines[0] == "False"
    handoff = json.loads(lines[1])
    assert handoff["native_tool_missing"] == "not_probed"
    assert handoff["native_tool_status"] == "not_probed"
    assert "native capabilities" in handoff["check_command"]
    assert handoff["stage"] == "capabilities"
    assert handoff["closure_evaluated"] is False
    assert any("rea native inspect" in item for item in handoff["commands"])
    assert handoff["web_only"] is False


def test_digest_shows_recovery_candidate(native, monkeypatch, tmp_path):
    from apkscan.report.digest import build_digest

    body, recipe = _hidden_file()
    bundle = _inspect_bundle(native, monkeypatch, tmp_path, body)
    recipe["evidence_sha256"] = _sha((bundle / "execution" / "stdout.bin").read_bytes())
    path = tmp_path / "recipe.json"
    path.write_text(json.dumps(recipe), encoding="utf-8")
    recovery = tmp_path / "recovery"
    native.recover(bundle, path, recovery)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(_report(_sha(body))), encoding="utf-8")
    out = tmp_path / "out"
    native.attach(recovery, report_path, out)
    published = json.loads((out / "report.json").read_text(encoding="utf-8"))
    digest = build_digest(published)
    assert digest["native_recovery"]["stage"] == "awaiting_review"
    assert any(lead.get("value") == DOMAIN.decode() and lead.get("advice") == "待核" for lead in digest["leads"])


def test_linux_elf_is_structural_only(native, monkeypatch, tmp_path):
    monkeypatch.setattr(native.sys, "platform", "linux")
    monkeypatch.setattr(native, "run_bounded", lambda *a, **k: (_ for _ in ()).throw(AssertionError("engine")))
    monkeypatch.setattr(
        native.ReaRuntime,
        "capabilities",
        lambda self: {"status": "unavailable", "reason": "rea_missing", "rea_version": None},
    )
    info = native.capabilities(provider="ghidra")
    assert info["android_elf"] == "ghidra_structural_only_live_unverified"
    assert info["linux_ghidra_elf_live_run"] == "unverified"
    elf = tmp_path / "libnative.so"
    elf.write_bytes(_elf())
    probed = native.capabilities(provider="ghidra", binary=elf)
    assert probed["status"] == "unavailable"
    assert probed["target"]["header_supported"] is True
    with pytest.raises(native.NativeError, match="provider_target_unclaimed"):
        native.inspect(elf, tmp_path / "ida", provider="ida", operation="overview")
    assert not (tmp_path / "ida").exists()


def test_dash_query_and_recipe_shape_reject_before_output(native, monkeypatch, tmp_path):
    calls: list = []
    body, recipe = _hidden_file()
    bundle = _inspect_bundle(native, monkeypatch, tmp_path, body)
    source = tmp_path / "sample.exe"

    def boom(*_a, **_k):
        calls.append("run")
        raise AssertionError("subprocess")

    monkeypatch.setattr(native, "run_bounded", boom)
    with pytest.raises(native.NativeError, match="invalid_query"):
        native.inspect(source, tmp_path / "dash", provider="ghidra", operation="function", query="-snapshot")
    assert calls == []
    assert not (tmp_path / "dash").exists()
    recipe["evidence_sha256"] = _sha((bundle / "execution" / "stdout.bin").read_bytes())
    bad = json.loads(json.dumps(recipe))
    bad["steps"][0] = ["concat"]
    path = tmp_path / "steps.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(native.NativeError, match="invalid_recipe"):
        native.recover(bundle, path, tmp_path / "bad-steps")
    assert not (tmp_path / "bad-steps").exists()
    extra = json.loads(json.dumps(recipe))
    extra["steps"][1]["note"] = "ignore-me"
    path.write_text(json.dumps(extra), encoding="utf-8")
    with pytest.raises(native.NativeError, match="invalid_recipe"):
        native.recover(bundle, path, tmp_path / "extra")
    huge = json.loads(json.dumps(recipe))
    huge["steps"][0]["ids"] = ["host"] * 40
    path.write_text(json.dumps(huge), encoding="utf-8")
    with pytest.raises(native.NativeError, match="invalid_recipe"):
        native.recover(bundle, path, tmp_path / "bomb")
    late = json.loads(json.dumps(recipe))
    late["steps"].append({"op": "xor-byte", "key": 1})
    path.write_text(json.dumps(late), encoding="utf-8")
    with pytest.raises(native.NativeError, match="invalid_recipe"):
        native.recover(bundle, path, tmp_path / "late")
    (tmp_path / "inf.json").write_text('{"schema_version": 1e999}', encoding="utf-8")
    with pytest.raises(native.NativeError, match="invalid_json"):
        native.recover(bundle, tmp_path / "inf.json", tmp_path / "inf")
    assert not (tmp_path / "inf").exists()


def test_extract_member_and_reject_duplicate(native, tmp_path):
    member = "lib/arm64-v8a/libsample.so"
    blob = _elf()
    apk = tmp_path / "sample.zip"
    import zipfile

    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr(member, blob)
    out = tmp_path / "extracted"
    summary = native.extract_native(apk, member, out)
    assert summary["engine_required"] is False
    assert summary["abi"] == "arm64-v8a"
    assert (out / "binary.bin").read_bytes() == blob
    dup = tmp_path / "dup.zip"
    with zipfile.ZipFile(dup, "w") as archive:
        archive.writestr(member, blob)
        archive.writestr(member, blob)
    with pytest.raises(native.NativeError, match="invalid_member"):
        native.extract_native(dup, member, tmp_path / "nope")
    assert not (tmp_path / "nope").exists()
    slip = tmp_path / "slip.zip"
    with zipfile.ZipFile(slip, "w") as archive:
        archive.writestr("../lib/arm64-v8a/libsample.so", blob)
    with pytest.raises(native.NativeError, match="invalid_member"):
        native.extract_native(slip, "../lib/arm64-v8a/libsample.so", tmp_path / "slip-out")


def _off_config(path: Path) -> Path:
    path.write_text(
        json.dumps({
            "schema_version": "fxapk.web_supplement.v1",
            "mode": "off",
            "source": "rea-json",
            "path": str(path.with_name("unused.json")),
        }),
        encoding="utf-8",
    )
    return path


def test_shared_snapshot_dag_is_not_a_cycle(tmp_path):
    from apkscan.core.web_supplement_report import supplement_report

    blob = json.dumps({"schema_version": "1.2", "meta": {}, "endpoints": [], "leads": []}).encode()
    digest = hashlib.sha256(blob).hexdigest()
    base = tmp_path / "case"
    prior = base / "input_report" / digest / "report.json"
    prior.parent.mkdir(parents=True)
    prior.write_bytes(blob)
    pointer = {
        "sha256": digest,
        "relative_path": f"input_report/{digest}/report.json",
        "byte_length": len(blob),
    }
    report = base / "report.json"
    report.write_bytes(json.dumps({
        "schema_version": "1.2",
        "meta": {"supplement_web_input": pointer, "native_recovery_input": dict(pointer)},
        "endpoints": [],
        "leads": [],
    }).encode())
    out = tmp_path / "out"
    supplement_report(report, _off_config(tmp_path / "off.json"), out)
    assert (out / "input_report" / digest / "report.json").read_bytes() == blob


def test_history_entry_hash_and_duplicate_refuse(native, monkeypatch, tmp_path):
    body, recipe = _hidden_file()
    bundle = _inspect_bundle(native, monkeypatch, tmp_path, body)
    recipe["evidence_sha256"] = _sha((bundle / "execution" / "stdout.bin").read_bytes())
    path = tmp_path / "recipe.json"
    path.write_text(json.dumps(recipe), encoding="utf-8")
    recovery = tmp_path / "recovery"
    native.recover(bundle, path, recovery)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(_report(_sha(body))), encoding="utf-8")
    first = tmp_path / "first"
    native.attach(recovery, report_path, first)
    published = json.loads((first / "report.json").read_text(encoding="utf-8"))
    published["meta"]["native_recovery"][0]["files"][0]["sha256"] = "ab" * 32
    swapped = tmp_path / "swapped"
    swapped.mkdir()
    (swapped / "report.json").write_text(json.dumps(published), encoding="utf-8")
    for item in (first / "native_recovery").rglob("*"):
        if item.is_file():
            target = swapped / item.relative_to(first)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.read_bytes())
    for item in (first / "input_report").rglob("*"):
        if item.is_file():
            target = swapped / item.relative_to(first)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.read_bytes())
    with pytest.raises(native.NativeError, match="history_snapshot_mismatch"):
        native.attach(recovery, swapped / "report.json", tmp_path / "no-swap")
    assert not (tmp_path / "no-swap").exists()
    published["meta"]["native_recovery"][0]["files"][0]["sha256"] = hashlib.sha256(
        (first / published["meta"]["native_recovery"][0]["files"][0]["path"]).read_bytes()
    ).hexdigest()
    published["meta"]["native_recovery"][0]["files"].append(
        dict(published["meta"]["native_recovery"][0]["files"][0])
    )
    (swapped / "report.json").write_text(json.dumps(published), encoding="utf-8")
    with pytest.raises(native.NativeError, match="history_snapshot_mismatch"):
        native.attach(recovery, swapped / "report.json", tmp_path / "no-dup")
    assert not (tmp_path / "no-dup").exists()


def test_incomplete_native_history_is_not_dropped(tmp_path):
    from apkscan.core.web_supplement_report import SupplementRefusal, supplement_report

    digest = "ab" * 32
    manifest = b"{}\n"
    relative = f"native_recovery/{digest}/manifest.json"
    base = tmp_path / "case"
    target = base / relative
    target.parent.mkdir(parents=True)
    target.write_bytes(manifest)
    report = base / "report.json"
    report.write_bytes(json.dumps({
        "schema_version": "1.2",
        "meta": {
            "native_recovery": [{
                "content_digest": digest,
                "files": [{
                    "path": relative,
                    "sha256": hashlib.sha256(manifest).hexdigest(),
                    "size": len(manifest),
                }],
            }],
        },
        "endpoints": [],
        "leads": [],
    }).encode())
    out = tmp_path / "out"
    with pytest.raises(SupplementRefusal):
        supplement_report(report, _off_config(tmp_path / "off.json"), out)
    assert not out.exists()


def test_extract_report_binds_apk_member_and_abi(native, tmp_path):
    import zipfile

    member = "lib/arm64-v8a/libsample.so"
    blob = _elf()
    apk = tmp_path / "sample.zip"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr(member, blob)
    apk_sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    report = tmp_path / "report.json"
    report.write_text(json.dumps({
        "meta": {
            "sample_sha256": apk_sha,
            "native_lib_hashes": [{
                "name": "libsample.so",
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
            }],
        },
    }), encoding="utf-8")
    summary = native.extract_native(apk, member, tmp_path / "ok", report)
    assert summary["member_sha256"] == hashlib.sha256(blob).hexdigest()
    other = tmp_path / "other.zip"
    with zipfile.ZipFile(other, "w") as archive:
        archive.writestr(member, blob)
        archive.writestr("extra.txt", b"different-apk")
    with pytest.raises(native.NativeError, match="sample_binding_mismatch"):
        native.extract_native(other, member, tmp_path / "cross", report)
    assert not (tmp_path / "cross").exists()
    conflict = "lib/x86_64/libsample.so"
    mixed = tmp_path / "mixed.zip"
    with zipfile.ZipFile(mixed, "w") as archive:
        archive.writestr(conflict, blob)
    mixed_sha = hashlib.sha256(mixed.read_bytes()).hexdigest()
    report.write_text(json.dumps({
        "meta": {
            "sample_sha256": mixed_sha,
            "native_lib_hashes": [{
                "name": "libsample.so",
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
            }],
        },
    }), encoding="utf-8")
    with pytest.raises(native.NativeError, match="abi_mismatch"):
        native.extract_native(mixed, conflict, tmp_path / "abi", report)
    assert not (tmp_path / "abi").exists()


@pytest.mark.parametrize(
    ("kind", "value"),
    [("domain", "pay.example.com"), ("ip", "192.0.2.73")],
)
def test_build_endpoint_leads_keeps_unverified_native_low(kind: str, value: str):
    from apkscan.core.leads import build_endpoint_leads
    from apkscan.core.models import Confidence, Endpoint, Evidence, EvidenceScope

    native_ev = Evidence(source="derived-native", location="native-recovery:synthetic", snippet=value)
    web_ev = Evidence(
        source="web",
        location="page.html",
        snippet=value,
        scope=EvidenceScope.BATCH_REFERENCE,
    )
    case_web = Evidence(source="web", location="case.html", snippet=value)
    external_ev = Evidence(
        source="external-web-observation",
        location="bundle",
        snippet=value,
        scope=EvidenceScope.BATCH_REFERENCE,
    )
    alone = build_endpoint_leads(
        [Endpoint(value=value, kind=kind, evidences=[native_ev])], online=False,
    )[0]
    assert alone.confidence is Confidence.LOW
    assert alone.advice == "待核"
    assert not alone.is_runtime_contact
    assert [ref.source for ref in alone.source_refs] == ["derived-native"]

    with_external = build_endpoint_leads(
        [Endpoint(value=value, kind=kind, evidences=[native_ev, external_ev])],
        online=False,
    )[0]
    assert with_external.confidence is Confidence.LOW
    assert with_external.advice == "待核"
    assert [ref.source for ref in with_external.source_refs] == [
        "derived-native", "external-web-observation",
    ]

    mixed = build_endpoint_leads(
        [Endpoint(value=value, kind=kind, evidences=[native_ev, web_ev, external_ev])],
        online=False,
    )[0]
    assert mixed.confidence is Confidence.LOW
    assert mixed.advice == "待核"
    assert [ref.source for ref in mixed.source_refs] == [
        "derived-native", "web", "external-web-observation",
    ]

    before = build_endpoint_leads(
        [Endpoint(value=value, kind=kind, evidences=[case_web])], online=False,
    )[0]
    after = build_endpoint_leads(
        [Endpoint(value=value, kind=kind, evidences=[native_ev, case_web])],
        online=False,
    )[0]
    assert before.confidence is Confidence.MEDIUM
    assert after.confidence is before.confidence
    assert after.advice == before.advice
    assert after.advice != "待核"


@pytest.mark.parametrize(
    ("kind", "value", "kept_advice"),
    [
        ("domain", "pay.example.com", "建议调证"),
        ("ip", "192.0.2.73", "无需调证"),
    ],
)
def test_build_endpoint_leads_keeps_independent_static_and_pcap(
    kind: str, value: str, kept_advice: str,
):
    from apkscan.core.leads import build_endpoint_leads
    from apkscan.core.models import Confidence, Endpoint, Evidence

    native_ev = Evidence(source="derived-native", location="native-recovery:synthetic", snippet=value)
    dex_ev = Evidence(source="dex", location="strings", snippet=value)
    pcap_ev = Evidence(source="runtime-pcap", location="floor.pcap", snippet=value)
    static_lead = build_endpoint_leads(
        [Endpoint(value=value, kind=kind, evidences=[dex_ev, native_ev])], online=False,
    )[0]
    assert static_lead.advice == kept_advice
    assert static_lead.confidence is Confidence.MEDIUM
    assert [ref.source for ref in static_lead.source_refs] == ["dex", "derived-native"]
    assert not static_lead.is_runtime_contact

    pcap_lead = build_endpoint_leads(
        [Endpoint(value=value, kind=kind, evidences=[pcap_ev, native_ev])], online=False,
    )[0]
    assert pcap_lead.advice == kept_advice
    assert pcap_lead.confidence is Confidence.MEDIUM
    assert pcap_lead.is_runtime_contact
    assert [ref.source for ref in pcap_lead.source_refs] == ["runtime-pcap", "derived-native"]


@pytest.mark.parametrize(
    ("kind", "value", "source", "scope"),
    [
        ("domain", "pay.example.com", "dex", EvidenceScope.BATCH_REFERENCE),
        ("domain", "pay.example.com", "runtime-pcap", EvidenceScope.BATCH_REFERENCE),
        ("ip", "192.0.2.73", "dex", EvidenceScope.LEGACY_UNSPECIFIED),
        ("ip", "192.0.2.73", "runtime-pcap", EvidenceScope.LEGACY_UNSPECIFIED),
    ],
)
def test_non_case_scope_cannot_corroborate_unverified_native(
    kind: str, value: str, source: str, scope: EvidenceScope,
):
    from apkscan.core.leads import build_endpoint_leads
    from apkscan.core.models import Confidence, Endpoint, Evidence

    native_ev = Evidence(source="derived-native", location="native-recovery:synthetic", snippet=value)
    other = Evidence(source=source, location="other-case", snippet=value, scope=scope)
    lead = build_endpoint_leads(
        [Endpoint(value=value, kind=kind, evidences=[native_ev, other])], online=False,
    )[0]
    assert lead.confidence is Confidence.LOW
    assert lead.advice == "待核"


@pytest.mark.parametrize("upstream_provider", ["ghidra", "other"])
def test_overview_workflow_keeps_exact_upstream_provider(native, upstream_provider):
    sha = "a" * 64
    identity = {"id": "rea-workflow", "version": "1"}
    data = {
        "subject": {"digest": {"sha256": sha}},
        "provider": identity,
        "operation": "binary_overview",
        "analysis_profile": {
            "provider": identity,
            "parameters": {
                "workflow_revision": 2,
                "upstream_analysis_profile": {
                    "provider": {"id": upstream_provider, "version": "12.1.4"},
                },
            },
        },
        "normalized_result": {"segments": [{"name": "synthetic"}]},
    }
    raw = json.dumps({"ok": True, "meta": {"command": "analyze"}, "data": data}).encode()
    if upstream_provider != "ghidra":
        with pytest.raises(native.NativeError, match="envelope_not_complete"):
            native._envelope(raw, binary_sha=sha, provider="ghidra", operation="overview", query=None)
    else:
        result = native._envelope(raw, binary_sha=sha, provider="ghidra", operation="overview", query=None)
        assert result["data"]["provider"]["id"] == "rea-workflow"
        assert native._native_provider_identity(result["data"], "overview")["version"] == "12.1.4"
