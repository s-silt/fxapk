"""REA/CDP bundle 离线挂接：验证在发布之前，报告只新增受限观察条目。"""

from __future__ import annotations

import hashlib
import importlib
import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan.core.rea_intake import (
    ReaDirectIntakeError,
    refuse_unverified_rea_direct_intake,
)
from apkscan.core.report_io import report_from_dict

_ORIGIN = "http://127.0.0.1:8080"
_PAGE = f"{_ORIGIN}/"
_SCRIPT_URL = f"{_ORIGIN}/app.js"
_TOKEN = "SECRET-SCRIPT-TOKEN-9f3a"
_SAMPLE = "ab" * 32


@pytest.fixture
def plugin_src(monkeypatch: pytest.MonkeyPatch) -> Path:
    src = Path(__file__).parents[1] / "plugins" / "fxapk-rea" / "src"
    monkeypatch.syspath_prepend(str(src))
    return src


def _attach_mod(plugin_src: Path):
    del plugin_src
    return importlib.import_module("fxapk_rea.attachment")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _artifact(text: str) -> dict[str, object]:
    raw = text.encode("utf-8")
    return {"text": text, "sha256": _sha(raw), "bytes": len(raw), "media_type": "text/javascript"}


def _rea_payload(text: str) -> dict[str, object]:
    return {
        "ok": True,
        "data": {
            "operation": "inspect_web_page",
            "predicate_type": "rea.web-page-inspection",
            "provider": {"id": "rea-cdp-browser", "version": "2"},
            "parameters": {
                "target_id": "synthetic-target",
                "observation_ms": 1000,
                "allowed_origins": [_ORIGIN],
            },
            "normalized_result": {
                "target": {"target_id": "synthetic-target", "origin": _ORIGIN, "url": _PAGE},
                "capture_window": {
                    "started_at": "2026-10-11T12:00:00Z",
                    "ended_at": "2026-10-11T12:00:01Z",
                    "observation_ms": 1000,
                },
                "completeness": {"status": "policy_filtered"},
                "frames": [
                    {
                        "frame_id": "frame-1",
                        "parent_frame_id": None,
                        "url": _PAGE,
                        "origin": _ORIGIN,
                    }
                ],
                "scripts": {
                    "items": [
                        {
                            "url": _SCRIPT_URL,
                            "frame_id": "frame-1",
                            "origin": _ORIGIN,
                            "source": {"included": True, "artifact": _artifact(text)},
                            "cdp_hash": "a" * 64,
                        }
                    ]
                },
                "network": {
                    "requests": [
                        {
                            "request_id": "1",
                            "url": f"{_ORIGIN}/api?q={_TOKEN}",
                            "origin": _ORIGIN,
                            "method": "GET",
                            "status": 200,
                            "initiator": {
                                "type": "script",
                                "url": _SCRIPT_URL,
                                "line": 0,
                                "column": 0,
                            },
                        }
                    ]
                },
                "console": {"events": []},
            },
        },
    }


def _rea_bundle(plugin_src: Path, directory: Path, text: str = f"const {_TOKEN} = 1;\n") -> str:
    del plugin_src
    evidence = importlib.import_module("fxapk_rea.evidence")
    source = directory.parent / (directory.name + "-source.json")
    raw = json.dumps(_rea_payload(text)).encode("utf-8")
    source.write_bytes(raw)
    evidence.import_observation(source, directory)
    (directory / "not-copied-decoy.txt").write_text(_TOKEN, encoding="utf-8")
    return _sha(raw)


def _cdp_bundle(plugin_src: Path, directory: Path, text: str | None = None) -> str:
    del plugin_src
    evidence = importlib.import_module("fxapk_rea.evidence")
    trace = importlib.import_module("fxapk_rea.trace")
    if text is None:
        text = f"function click(){{fetch('/api')}} /* {_TOKEN} */\n"
    body = {
        "schema_version": "fxapk-cdp-trace/1",
        "producer": "fxapk-cdp-trace",
        "target_id": "TARGET-1",
        "session_id": "SESSION-A",
        "origin": _ORIGIN,
        "capture": {
            "id": "00000000-0000-4000-8000-000000000001",
            "tool_version": "synthetic",
            "started_at": "2026-10-12T00:00:00Z",
        },
        "events": [
            {
                "method": "Runtime.executionContextCreated",
                "sessionId": "SESSION-A",
                "seq": 1,
                "params": {
                    "context": {
                        "id": 1,
                        "uniqueId": "unique-1",
                        "origin": _ORIGIN,
                        "auxData": {"frameId": "frame-1", "isDefault": True},
                    }
                },
            },
            {
                "method": "Debugger.scriptParsed",
                "sessionId": "SESSION-A",
                "seq": 2,
                "params": {
                    "scriptId": "7",
                    "url": _SCRIPT_URL,
                    "executionContextId": 1,
                    "startLine": 0,
                    "startColumn": 0,
                    "hash": "cdp-hash-not-bytes",
                },
            },
            {
                "method": "Network.requestWillBeSent",
                "sessionId": "SESSION-A",
                "seq": 3,
                "params": {
                    "requestId": "1",
                    "frameId": "frame-1",
                    "loaderId": "LOAD-1",
                    "timestamp": 0.003,
                    "documentURL": _PAGE,
                    "request": {"url": f"{_ORIGIN}/api?q={_TOKEN}", "method": "GET"},
                    "initiator": {
                        "type": "script",
                        "stack": {
                            "callFrames": [
                                {
                                    "functionName": "click",
                                    "scriptId": "7",
                                    "url": _SCRIPT_URL,
                                    "lineNumber": 0,
                                    "columnNumber": 0,
                                }
                            ]
                        },
                    },
                },
            },
        ],
        "sources": [
            {
                "scriptId": "7",
                "sessionId": "SESSION-A",
                "seq": 2,
                "contextId": 1,
                "sourceText": text,
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
            }
        ],
        "commands": [],
        "completeness": {"gaps": []},
    }
    raw = json.dumps(body).encode("utf-8")
    evidence.claim_output(directory)
    receipt, files = trace.project_trace(raw)
    trace._publish(directory, raw, receipt, files)
    (directory / "ready.json").write_text('{"status":"ready"}\n', encoding="utf-8")
    return _sha(raw)


def _case(path: Path, *, sha: str = _SAMPLE, closure: str = "partial") -> None:
    payload = {
        "schema_version": "1.2",
        "package_name": "example.app",
        "meta": {
            "sample_sha256": sha,
            "package_name": "example.app",
            "closure": {"status": closure, "gaps": ["keep-gap"], "targets": [{"id": "t1"}]},
            "custom_note": "keep-unknown-meta",
        },
        "leads": [
            {
                "category": "DOMAIN",
                "value": "keep.example",
                "advice": "待核",
                "notes": "same-note",
                "custom_lead_field": "keep-lead",
            }
        ],
        "endpoints": [{"value": "keep.example", "kind": "domain", "custom_ep": 1}],
        "findings": [],
        "analyzer_status": [],
        "mystery_top": {"token": "preserve-me"},
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _context(path: Path, **overrides: object) -> None:
    payload: dict[str, object] = {
        "schema_version": "fxapk-web-context/1",
        "sample_sha256": _SAMPLE,
        "target_id": "synthetic-target",
        "origin": _ORIGIN,
        "package_name": "example.app",
        "process_id": 42,
        "webview_target_id": "wv-1",
        "recorded_at": "2026-10-12T00:00:00Z",
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8")


def _without_observations(payload: dict) -> dict:
    cloned = json.loads(json.dumps(payload))
    meta = cloned.get("meta")
    if isinstance(meta, dict):
        meta.pop("web_observations", None)
    return cloned


def test_rea_attach_digest_html_and_typed_load_keep_report_bytes(
    plugin_src: Path, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"
    report = tmp_path / "case.json"
    out = tmp_path / "delivery"
    context = tmp_path / "context.json"
    raw_sha = _rea_bundle(plugin_src, bundle)
    _case(report, closure="complete")
    original = json.loads(report.read_text(encoding="utf-8"))
    _context(context)
    mod = _attach_mod(plugin_src)
    summary = mod.attach(bundle, report, out, context_record=context)
    assert summary["closure_evaluated"] is False
    assert summary["identity"] == "declared"
    published = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert _without_observations(published) == _without_observations(original)
    assert published["meta"]["closure"] == original["meta"]["closure"]
    assert published["leads"] == original["leads"]
    assert published["endpoints"] == original["endpoints"]
    entry = published["meta"]["web_observations"][0]
    assert entry["source_sha256"] == raw_sha
    assert entry["provider"] == "rea"
    assert entry["coverage_status"] == "partial"
    assert entry["bundle_integrity_checked"] is True
    assert entry["provenance_authenticated"] is False
    assert entry["target_app_attribution_verified"] is False
    assert entry["click_attribution_verified"] is False
    assert entry["closure_evaluated"] is False
    assert entry["identity"] == "declared"
    copied = out / "external_observations" / raw_sha
    assert (copied / "rea-original.json").read_bytes() == (
        bundle / "rea-original.json"
    ).read_bytes()
    assert (copied / "observation.json").is_file()
    assert (copied / "fxapk-rea-bundle.json").is_file()
    assert (copied / "context-record.json").read_bytes() == context.read_bytes()
    assert not (copied / "not-copied-decoy.txt").exists()
    manifest = json.loads((copied / "manifest.json").read_text(encoding="utf-8"))
    for row in manifest["files"]:
        blob = (copied / row["relative_path"]).read_bytes()
        assert hashlib.sha256(blob).hexdigest() == row["sha256"]
        assert len(blob) == row["size"]
    digest = json.loads((out / "report.digest.json").read_text(encoding="utf-8"))
    html = (out / "report.html").read_text(encoding="utf-8")
    assert _TOKEN not in (out / "report.json").read_text(encoding="utf-8")
    assert _TOKEN not in json.dumps(digest)
    assert _TOKEN not in html
    assert "example.app" not in json.dumps(digest["web_observations"])
    assert digest["web_observations"]["closure_evaluated"] is False
    assert "外部网页观察" in html
    assert 'href="http' not in html
    loaded = report_from_dict(published)
    assert published["meta"]["closure"]["status"] == "complete"
    assert loaded.leads[0].value == "keep.example"
    assert loaded.meta["web_observations"][0]["source_sha256"] == raw_sha
    assert loaded.meta["web_observations"][0]["closure_evaluated"] is False
    moved = tmp_path / "moved"
    shutil.move(out, moved)
    moved_manifest = json.loads(
        (moved / "external_observations" / raw_sha / "manifest.json").read_text(encoding="utf-8")
    )
    root = moved / "external_observations" / raw_sha
    for row in moved_manifest["files"]:
        blob = (root / row["relative_path"]).read_bytes()
        assert hashlib.sha256(blob).hexdigest() == row["sha256"]
    with pytest.raises(ReaDirectIntakeError):
        refuse_unverified_rea_direct_intake(root / "rea-original.json", root=moved)


def test_cdp_bundle_and_cli_register(plugin_src: Path, tmp_path: Path) -> None:
    bundle = tmp_path / "cdp"
    report = tmp_path / "case.json"
    out = tmp_path / "delivery"
    raw_sha = _cdp_bundle(plugin_src, bundle)
    _case(report)
    mod = _attach_mod(plugin_src)
    summary = mod.attach(bundle, report, out)
    assert summary["identity"] == "unknown"
    entry = json.loads((out / "report.json").read_text(encoding="utf-8"))["meta"][
        "web_observations"
    ][0]
    assert entry["provider"] == "fxapk-cdp-trace"
    assert entry["source_sha256"] == raw_sha
    assert (out / "external_observations" / raw_sha / "ready.json").is_file()
    assert (out / "external_observations" / raw_sha / "cdp-trace-original.json").is_file()
    app = importlib.import_module("typer").Typer(add_completion=False)

    @app.command("placeholder")
    def _placeholder() -> None:
        """Keep attach as a real subcommand, matching the multi-command rea app."""

    mod.register_attach(app)
    result = CliRunner().invoke(
        app,
        [
            "attach",
            "--bundle",
            str(bundle),
            "--report",
            str(report),
            "--out",
            str(tmp_path / "cli"),
        ],
    )
    assert result.exit_code == 0
    assert raw_sha in result.stdout
    assert _TOKEN not in result.stdout


@pytest.mark.parametrize(
    "mutate",
    ["source", "script", "receipt", "failure", "duplicate_key", "path", "oversize"],
)
def test_bad_bundle_is_refused_before_claim(plugin_src: Path, tmp_path: Path, mutate: str) -> None:
    bundle = tmp_path / "bundle"
    report = tmp_path / "case.json"
    out = tmp_path / "delivery"
    _rea_bundle(plugin_src, bundle)
    _case(report)
    if mutate == "source":
        target = bundle / "rea-original.json"
        target.write_bytes(target.read_bytes() + b" ")
    elif mutate == "script":
        script = next((bundle / "scripts").glob("*.js"))
        script.write_bytes(script.read_bytes() + b" ")
    elif mutate == "receipt":
        observation = json.loads((bundle / "observation.json").read_text(encoding="utf-8"))
        observation["requests"][0]["url"] = f"{_ORIGIN}/tampered"
        (bundle / "observation.json").write_text(json.dumps(observation), encoding="utf-8")
    elif mutate == "failure":
        (bundle / "failure.json").write_text('{"status":"failed"}\n', encoding="utf-8")
    elif mutate == "duplicate_key":
        (bundle / "observation.json").write_text(
            '{"schema_version":1,"schema_version":2}\n', encoding="utf-8"
        )
    elif mutate == "path":
        observation = json.loads((bundle / "observation.json").read_text(encoding="utf-8"))
        observation["artifacts"][0]["relative_path"] = "../escape.json"
        (bundle / "observation.json").write_text(json.dumps(observation), encoding="utf-8")
    else:
        raw = bundle / "rea-original.json"
        raw.write_bytes(b"{" + b" " * (16 * 1024 * 1024))
    mod = _attach_mod(plugin_src)
    with pytest.raises(mod.AttachError):
        mod.attach(bundle, report, out)
    assert not out.exists()


def test_existing_output_context_and_duplicate_attachment(plugin_src: Path, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    other = tmp_path / "other"
    report = tmp_path / "case.json"
    out = tmp_path / "delivery"
    again = tmp_path / "again"
    _rea_bundle(plugin_src, bundle)
    _rea_bundle(plugin_src, other, text=f"const {_TOKEN} = 2;\n")
    _case(report)
    mod = _attach_mod(plugin_src)
    mod.attach(bundle, report, out)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    with pytest.raises(mod.AttachError):
        mod.attach(bundle, report, occupied)
    assert not (occupied / "report.json").exists()
    context = tmp_path / "bad-context.json"
    _context(context, sample_sha256="cd" * 32)
    refused = tmp_path / "refused"
    with pytest.raises(mod.AttachError):
        mod.attach(bundle, report, refused, context_record=context)
    assert not refused.exists()
    extra = tmp_path / "extra-context.json"
    _context(extra, unexpected=True)
    with pytest.raises(mod.AttachError):
        mod.attach(other, report, tmp_path / "extra-out", context_record=extra)
    assert not (tmp_path / "extra-out").exists()
    with pytest.raises(mod.AttachError):
        mod.attach(bundle, out / "report.json", again)
    assert not again.exists()
    second = tmp_path / "second"
    mod.attach(other, out / "report.json", second)
    published = json.loads((second / "report.json").read_text(encoding="utf-8"))
    assert len(published["meta"]["web_observations"]) == 2
    assert _TOKEN not in (second / "report.json").read_text(encoding="utf-8")
    decoy_root = next((out / "external_observations").iterdir())
    (decoy_root / "local-only.txt").write_text(_TOKEN, encoding="utf-8")
    with pytest.raises(mod.AttachError):
        mod.attach(other, out / "report.json", tmp_path / "decoy-kept")
    assert not (tmp_path / "decoy-kept").exists()
    manifest = next((second / "external_observations").glob("*/manifest.json"))
    manifest.write_text(
        '{"schema_version":"fxapk-web-observation-manifest/1","files":[]}\n', encoding="utf-8"
    )
    broken = tmp_path / "broken"
    with pytest.raises(mod.AttachError):
        mod.attach(bundle, second / "report.json", broken)
    assert not broken.exists()


def _live_bundle() -> Path | None:
    matrix = Path(__file__).parents[1] / "out_rea_trace_20261012" / "live-matrix.json"
    if not matrix.is_file():
        return None
    rows = json.loads(matrix.read_text(encoding="utf-8"))
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return None
    run_dir = rows[0].get("run_dir")
    if not isinstance(run_dir, str):
        return None
    bundle = Path(run_dir) / "bundle"
    return bundle if (bundle / "observation.json").is_file() else None


def test_historical_live_bundle_attaches_without_promotion(
    plugin_src: Path, tmp_path: Path
) -> None:
    bundle = _live_bundle()
    if bundle is None:
        pytest.skip("historical live bundle is not on this machine")
    report = tmp_path / "case.json"
    out = tmp_path / "delivery"
    _case(report, sha="a" * 64)
    mod = _attach_mod(plugin_src)
    summary = mod.attach(bundle, report, out)
    assert summary["identity"] == "unknown"
    assert summary["provenance_authenticated"] is False
    assert summary["closure_evaluated"] is False
    published = json.loads((out / "report.json").read_text(encoding="utf-8"))
    entry = published["meta"]["web_observations"][0]
    assert entry["coverage_status"] == "partial"
    assert entry["provenance_authenticated"] is False
    assert entry["click_attribution_verified"] is False
    assert entry["target_app_attribution_verified"] is False
    assert entry["closure_evaluated"] is False
    copied = out / "external_observations" / entry["source_sha256"]
    assert (copied / "observation.json").read_bytes() == (bundle / "observation.json").read_bytes()
    record = json.loads((copied / "projection-record.json").read_text(encoding="utf-8"))
    assert record["certification_upgraded"] is False
    assert record["coverage_status"] == "partial"
    assert record["gap_reordered"] is True
    tampered = tmp_path / "tampered-bundle"
    shutil.copytree(bundle, tampered)
    observation = json.loads((tampered / "observation.json").read_text(encoding="utf-8"))
    observation["provenance_authenticated"] = True
    (tampered / "observation.json").write_text(json.dumps(observation), encoding="utf-8")
    with pytest.raises(mod.AttachError) as raised:
        mod.attach(tampered, report, tmp_path / "rejected")
    assert str(raised.value) == "saved_flag_rejected"
    assert not (tmp_path / "rejected").exists()


def test_moved_new_bundle_reattach_and_existing_tamper_rejected(
    plugin_src: Path, tmp_path: Path
) -> None:
    bundle = tmp_path / "cdp"
    other = tmp_path / "cdp-other"
    report = tmp_path / "case.json"
    out = tmp_path / "delivery"
    raw_sha = _cdp_bundle(plugin_src, bundle)
    _cdp_bundle(plugin_src, other, text=f"function click(){{fetch('/other')}} /* {_TOKEN} */\n")
    _case(report)
    context = tmp_path / "context.json"
    _context(context, target_id="TARGET-1")
    mod = _attach_mod(plugin_src)
    mod.attach(bundle, report, out, context_record=context)
    moved = tmp_path / "moved"
    shutil.move(out, moved)
    again = tmp_path / "again"
    mod.attach(other, moved / "report.json", again)
    rows = json.loads((again / "report.json").read_text(encoding="utf-8"))["meta"]["web_observations"]
    assert [row["source_sha256"] for row in rows][0] == raw_sha
    assert len(rows) == 2
    with pytest.raises(mod.AttachError):
        mod.attach(bundle, again / "report.json", tmp_path / "duplicate")
    assert not (tmp_path / "duplicate").exists()

    def refuse(mutate) -> None:
        destination = tmp_path / f"bad-{mutate}"
        if destination.exists():
            shutil.rmtree(destination)
        with pytest.raises(mod.AttachError):
            mod.attach(other, report_path, destination)
        assert not destination.exists()

    report_path = again / "report.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    original = json.loads(report_path.read_text(encoding="utf-8"))
    payload["meta"]["web_observations"][0]["request_count"] = 999
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    refuse("entry")
    report_path.write_text(json.dumps(original), encoding="utf-8")
    root = again / "external_observations" / raw_sha
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["sha256"] = "ab" * 32
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    refuse("manifest")
    manifest_path.write_bytes(
        (moved / "external_observations" / raw_sha / "manifest.json").read_bytes()
    )
    observation_path = root / "observation.json"
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    observation["click_attribution_verified"] = True
    observation_path.write_text(json.dumps(observation), encoding="utf-8")
    refuse("receipt")
    observation_path.write_bytes(
        (moved / "external_observations" / raw_sha / "observation.json").read_bytes()
    )
    script = next((root / "scripts").glob("*.js"))
    script.write_bytes(script.read_bytes() + b" ")
    refuse("script")
    script.write_bytes((moved / "external_observations" / raw_sha / "scripts" / script.name).read_bytes())
    context_path = root / "context-record.json"
    context_path.write_text(context_path.read_text(encoding="utf-8").replace(_SAMPLE, "cd" * 32), encoding="utf-8")
    refuse("context")


def test_linked_bundle_is_refused(plugin_src: Path, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    report = tmp_path / "case.json"
    out = tmp_path / "delivery"
    _rea_bundle(plugin_src, bundle)
    _case(report)
    outside = tmp_path / "outside.js"
    outside.write_text(_TOKEN, encoding="utf-8")
    script = next((bundle / "scripts").glob("*.js"))
    script.unlink()
    try:
        script.symlink_to(outside)
    except OSError:
        pytest.skip("symlink not permitted")
    mod = _attach_mod(plugin_src)
    with pytest.raises(mod.AttachError):
        mod.attach(bundle, report, out)
    assert not out.exists()


def test_attach_copies_dex_receipt_and_rejects_a_hash_mismatch(
    plugin_src: Path, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"
    report = tmp_path / "case.json"
    out = tmp_path / "delivery"
    _rea_bundle(plugin_src, bundle)
    _case(report)
    payload = json.loads(report.read_text(encoding="utf-8"))
    receipt = {"schema": "dex-query-receipt/1", "query_values": ["xref-token-example"]}
    blob = (json.dumps(receipt, sort_keys=True) + "\n").encode("utf-8")
    receipt_id = _sha(blob)
    (report.parent / "dex-query").mkdir()
    (report.parent / "dex-query" / f"{receipt_id}.json").write_bytes(blob)
    payload["meta"]["dex_query"] = {
        "receipts": [{"receipt_id": receipt_id, "sha256": receipt_id, "members": []}],
    }
    report.write_text(json.dumps(payload), encoding="utf-8")
    mod = _attach_mod(plugin_src)
    mod.attach(bundle, report, out)
    copied = (out / "dex-query" / f"{receipt_id}.json").read_bytes()
    assert copied == blob
    assert "xref-token-example" not in (out / "report.digest.json").read_text(encoding="utf-8")
    assert "xref-token-example" not in (out / "report.html").read_text(encoding="utf-8")

    bad = tmp_path / "bad-case.json"
    bad_payload = json.loads(report.read_text(encoding="utf-8"))
    bad_payload["meta"]["dex_query"]["receipts"][0]["sha256"] = "ab" * 32
    bad.write_text(json.dumps(bad_payload), encoding="utf-8")
    rejected = tmp_path / "rejected"
    with pytest.raises(mod.AttachError) as raised:
        mod.attach(bundle, bad, rejected)
    assert str(raised.value) == "dex_receipt_mismatch"
    assert not rejected.exists()
