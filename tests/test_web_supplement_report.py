"""CLI coverage for supplementing an existing canonical report."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from apkscan import cli
from tests.test_web_supplement import _bundle, _install_plugin

MARKER = "only-supplement"
RUNNER = CliRunner()


def _report(path: Path, **extra: Any) -> Path:
    payload: dict[str, Any] = {
        "schema_version": "1.2",
        "package_name": "app.example.test",
        "analysis_status": "complete",
        "meta": {
            "platform": "android",
            "closure": {"status": "partial", "gaps": ["kept-closure"]},
            "web_supplement_runtime": {"rounds": [{"round_id": "round-1", "keep": True}]},
            "web_supplement": {
                "status": "executed",
                "reason": "executed",
                "attempts": [{
                    "status": "executed",
                    "reason": "executed",
                    "history_token": "static-round",
                    "parse_counts": {
                        "endpoints": 0, "config_leads": 0, "relations": 0, "scripts": 0,
                    },
                    "raw_sha256": [],
                    "relative_paths": [],
                }],
            },
            "web_observation_plan": {"custom_plan_note": "keep-plan"},
        },
        "endpoints": [
            {
                "kind": "domain",
                "value": "old.example.test",
                "custom_endpoint": "keep-endpoint",
                "evidences": [
                    {
                        "source": "dex",
                        "location": "Old.java",
                        "snippet": "old.example.test",
                        "scope": "case_evidence",
                        "analyst_note": "keep-evidence",
                    },
                    {
                        "source": "dex",
                        "location": "Old.java",
                        "snippet": "old.example.test",
                        "scope": "case_evidence",
                        "analyst_note": "duplicate-evidence",
                    },
                ],
            },
            {
                "kind": "domain",
                "value": "old.example.test",
                "custom_endpoint": "duplicate-row",
                "evidences": [{
                    "source": "dex",
                    "location": "Other.java",
                    "snippet": "same-value",
                    "scope": "case_evidence",
                }],
            },
        ],
        "leads": [{
            "category": "DOMAIN",
            "value": "old.example.test",
            "advice": "建议调证",
            "base_advice": "建议调证",
            "confidence": "HIGH",
            "downgrades": {},
            "notes": "original-note",
            "case_note": "keep-lead",
            "source_refs": [{
                "source": "runtime-pcap",
                "location": "captures/floor.pcap",
                "snippet": "old.example.test",
                "scope": "case_evidence",
                "pcap_note": "not-copied",
            }],
        }],
        "findings": [{
            "id": "OLD-FINDING",
            "title": "old",
            "severity": "MEDIUM",
            "category": "static",
            "description": "kept",
            "confidence": "HIGH",
            "custom_finding": "keep-finding",
            "evidences": [],
        }],
        "outside_tool": {"kept": True},
    }
    payload.update(extra)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _config(path: Path, body: dict[str, Any]) -> Path:
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _invoke(report: Path, config: Path, out: Path) -> Any:
    return RUNNER.invoke(cli.app, [
        "supplement-web", str(report), "--web-supplement", str(config), "--out", str(out),
    ])


def _written(out: Path) -> dict[str, Any]:
    return json.loads((out / "report.json").read_text(encoding="utf-8"))


def test_cli_adds_candidate_and_keeps_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_plugin(monkeypatch)
    bundle = _bundle(tmp_path, f'var API_BASE = "http://127.0.0.1:9/{MARKER}";\n')
    report = _report(tmp_path / "in" / "report.json")
    before = report.read_bytes()
    config = _config(tmp_path / "supplement.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": str(bundle),
    })
    out = tmp_path / "out"
    result = _invoke(report, config, out)
    assert result.exit_code == 0, result.output
    assert MARKER not in result.output
    assert "建议调证" not in result.output
    assert report.read_bytes() == before
    written = _written(out)
    assert written["outside_tool"] == {"kept": True}
    assert written["meta"]["closure"] == {"status": "partial", "gaps": ["kept-closure"]}
    assert written["meta"]["web_supplement_runtime"]["rounds"][0]["keep"] is True
    assert written["meta"]["web_observation_plan"]["custom_plan_note"] == "keep-plan"
    attempts = written["meta"]["web_supplement"]["attempts"]
    assert any(item.get("history_token") == "static-round" for item in attempts)
    assert written["meta"]["web_supplement"]["latest_status"] == "executed"
    assert written["meta"]["web_supplement"]["boundary"]["live_cdp"] is False
    old_rows = [item for item in written["endpoints"] if item["value"] == "old.example.test"]
    assert [item["custom_endpoint"] for item in old_rows] == ["keep-endpoint", "duplicate-row"]
    assert old_rows[0]["evidences"][0]["analyst_note"] == "keep-evidence"
    assert old_rows[0]["evidences"][1]["analyst_note"] == "duplicate-evidence"
    lead = written["leads"][0]
    assert lead["advice"] == "建议调证"
    assert lead["base_advice"] == "建议调证"
    assert lead["confidence"] == "HIGH"
    assert lead["case_note"] == "keep-lead"
    assert lead["source_refs"][0]["pcap_note"] == "not-copied"
    assert lead["source_refs"][0]["location"] == "captures/floor.pcap"
    assert not (out / "captures" / "floor.pcap").exists()
    fresh = [item for item in written["endpoints"] if MARKER in item["value"]]
    assert fresh
    assert all(
        ev.get("scope") == "batch_reference" and ev.get("source") == "external-web-observation"
        for item in fresh for ev in item["evidences"]
    )
    new_leads = [item for item in written["leads"] if item is not lead and MARKER in json.dumps(item)]
    assert new_leads
    assert all(item["advice"] == "待核" and item["confidence"] == "LOW" for item in new_leads)
    assert written["findings"][0]["custom_finding"] == "keep-finding"
    snapshot = written["meta"]["supplement_web_input"]
    stored = (out / snapshot["relative_path"]).read_bytes()
    assert stored == before
    assert snapshot["sha256"] == hashlib.sha256(before).hexdigest()
    digest = json.loads((out / "report.digest.json").read_text(encoding="utf-8"))
    assert "web_supplement" in digest
    assert (out / "report.html").is_file()
    assert (out / "report.sha256").is_file()

    again = tmp_path / "again"
    second = _invoke(out / "report.json", config, again)
    assert second.exit_code == 0, second.output
    repeated = _written(again)
    assert repeated["meta"]["web_supplement"]["latest_reason"] == "duplicate_raw"
    assert sum(MARKER in item["value"] for item in repeated["endpoints"]) == len(fresh)
    assert any(
        item.get("history_token") == "static-round"
        for item in repeated["meta"]["web_supplement"]["attempts"]
    )


def test_off_skipped_no_plugin_and_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_plugin(monkeypatch)
    bundle = _bundle(tmp_path, f'var API_BASE = "http://127.0.0.1:9/{MARKER}";\n')
    report = _report(tmp_path / "in" / "report.json")
    off = _config(tmp_path / "off.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "off",
        "source": "bundle",
        "path": str(bundle),
    })
    off_out = tmp_path / "off-out"
    off_result = _invoke(report, off, off_out)
    assert off_result.exit_code == 3, off_result.output
    assert _written(off_out)["meta"]["web_supplement"]["latest_reason"] == "mode_off"
    assert MARKER not in json.dumps(_written(off_out)["endpoints"])

    monkeypatch.setattr(
        "apkscan.core.web_supplement.discover_plugins",
        lambda: ([], [{"name": "rea", "status": "unavailable", "reason": "plugin_unavailable"}]),
    )
    missing = _config(tmp_path / "missing.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": str(bundle),
    })
    missing_out = tmp_path / "missing-out"
    missing_result = _invoke(report, missing, missing_out)
    assert missing_result.exit_code == 1, missing_result.output
    assert _written(missing_out)["meta"]["web_supplement"]["latest_reason"] == "plugin_unavailable"

    _install_plugin(monkeypatch)
    script = next((bundle / "scripts").glob("*.js"))
    script.write_bytes(script.read_bytes() + b"x")
    failed = _config(tmp_path / "bad.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": str(bundle),
    })
    failed_out = tmp_path / "failed-out"
    failed_result = _invoke(report, failed, failed_out)
    assert failed_result.exit_code == 1, failed_result.output
    receipt = _written(failed_out)["meta"]["web_supplement"]
    assert receipt["latest_status"] == "failed"
    assert MARKER not in json.dumps(_written(failed_out)["endpoints"])


def test_old_observation_relocate_and_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_plugin(monkeypatch)
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("net")))
    work = tmp_path / "fresh"
    work.mkdir()
    bundle = _bundle(work, 'var API_BASE = "http://127.0.0.1:9/fresh";\n')
    import fxapk_rea.supplement as supplement

    verified = supplement.run_supplement({"source": "bundle", "path": str(bundle)})
    sha = verified["verified"]["raw_sha"]
    report = _report(tmp_path / "case" / "report.json")
    tree = tmp_path / "case" / "external_observations" / sha
    shutil.copytree(bundle, tree)
    payload = json.loads(report.read_text(encoding="utf-8"))
    relative = f"external_observations/{sha}/"
    payload["meta"]["web_observations"] = [{
        "schema_version": "fxapk-web-observation-attachment/1",
        "bundle_relative_path": relative,
        "source_sha256": sha,
    }]
    payload["meta"]["web_supplement"]["attempts"][0]["relative_paths"] = [relative]
    report.write_text(json.dumps(payload), encoding="utf-8")
    config = _config(tmp_path / "off.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "off",
        "source": "bundle",
        "path": str(bundle),
    })
    out = tmp_path / "relocated"
    result = _invoke(report, config, out)
    assert result.exit_code == 3, result.output
    copied = out / "external_observations" / sha / "fxapk-rea-bundle.json"
    assert copied.is_file()
    assert copied.read_bytes() == (tree / "fxapk-rea-bundle.json").read_bytes()

    missing = _report(tmp_path / "missing-case" / "report.json")
    missing_payload = json.loads(missing.read_text(encoding="utf-8"))
    missing_payload["meta"]["web_observations"] = [{
        "bundle_relative_path": "external_observations/" + ("ab" * 32) + "/",
    }]
    missing.write_text(json.dumps(missing_payload), encoding="utf-8")
    refused = _invoke(missing, config, tmp_path / "should-not")
    assert refused.exit_code == 2
    assert not (tmp_path / "should-not").exists()

    tampered = tmp_path / "tampered-case"
    shutil.copytree(tmp_path / "case", tampered)
    script = next((tampered / "external_observations" / sha / "scripts").glob("*.js"))
    script.write_bytes(script.read_bytes() + b"y")
    tamper_result = _invoke(tampered / "report.json", config, tmp_path / "tamper-out")
    assert tamper_result.exit_code == 2
    assert not (tmp_path / "tamper-out").exists()

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    conflict = _invoke(report, config, occupied)
    assert conflict.exit_code == 2

    nested = _invoke(report, config, tmp_path / "case" / "nested")
    assert nested.exit_code == 3, nested.output
    inside = tmp_path / "case" / "external_observations" / "nested-out"
    refused_inside = _invoke(report, config, inside)
    assert refused_inside.exit_code == 2
    assert not inside.exists()


def test_rea_json_and_mocked_live_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_plugin(monkeypatch)
    import tests.test_rea_plugin as rea_tests

    source = tmp_path / "rea.json"
    source.write_text(json.dumps(_observation_body(rea_tests.observation)), encoding="utf-8")
    report = _report(tmp_path / "in" / "report.json")
    config = _config(tmp_path / "rea.jsonc", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "rea-json",
        "path": str(source),
    })
    result = _invoke(report, config, tmp_path / "rea-out")
    assert result.exit_code == 0, result.output
    written = _written(tmp_path / "rea-out")
    assert written["meta"]["web_supplement"]["boundary"]["live_cdp"] is False
    assert any("127.0.0.1" in item.get("value", "") for item in written["endpoints"])

    calls: list[dict[str, Any]] = []

    class _Plugin:
        name = "rea"

        def run_supplement(self, request: dict[str, Any]) -> dict[str, Any]:
            calls.append(request)
            return {"status": "skipped", "reason": "cdp_not_authorized", "live_cdp": False}

    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("net")))
    monkeypatch.setattr(
        "apkscan.core.web_supplement.discover_plugins",
        lambda: ([_Plugin()], []),
    )
    live = _config(tmp_path / "live.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "cdp",
        "provider": "trace",
        "endpoint": "http://127.0.0.1:9222",
        "target": "synthetic-target",
        "exact_origins": ["http://127.0.0.1:9"],
        "observation_ms": 1000,
        "authorized": True,
    })
    live_result = _invoke(report, live, tmp_path / "live-out")
    assert live_result.exit_code == 3, live_result.output
    assert calls and calls[0]["source"] == "cdp"
    assert calls[0]["authorized"] is True
    assert "live_cdp=false" in live_result.output


def test_invalid_report_config_and_future_schema(tmp_path: Path) -> None:
    report = _report(tmp_path / "in" / "report.json")
    config = _config(tmp_path / "bad-config.json", {"schema_version": "nope"})
    assert _invoke(report, config, tmp_path / "out-config").exit_code == 2

    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["schema_version"] = "9.9"
    future = tmp_path / "future" / "report.json"
    future.parent.mkdir()
    future.write_text(json.dumps(payload), encoding="utf-8")
    good = _config(tmp_path / "good.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "off",
        "source": "bundle",
        "path": str(tmp_path / "unused"),
    })
    assert _invoke(future, good, tmp_path / "out-future").exit_code == 2

    broken = _report(tmp_path / "broken" / "report.json")
    body = json.loads(broken.read_text(encoding="utf-8"))
    body["leads"].append("not-a-row")
    broken.write_text(json.dumps(body), encoding="utf-8")
    broken_result = _invoke(broken, good, tmp_path / "out-broken")
    assert broken_result.exit_code == 2
    assert not (tmp_path / "out-broken").exists()
    assert "Traceback" not in broken_result.output


def test_sibling_output_allowed_material_and_source_refused(tmp_path: Path) -> None:
    report = _report(tmp_path / "case" / "original.json")
    config = _config(tmp_path / "off.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "off",
        "source": "rea-json",
        "path": str(tmp_path / "case" / "material.json"),
    })
    (tmp_path / "case" / "material.json").write_text("{}", encoding="utf-8")
    sibling = _invoke(report, config, tmp_path / "case" / "new")
    assert sibling.exit_code == 3, sibling.output
    same = _invoke(report, config, report)
    assert same.exit_code == 2
    nested_material = tmp_path / "case" / "material"
    nested_material.mkdir()
    config.write_text(json.dumps({
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "off",
        "source": "bundle",
        "path": str(nested_material),
    }), encoding="utf-8")
    refused = _invoke(report, config, nested_material / "out")
    assert refused.exit_code == 2
    assert not (nested_material / "out").exists()


def test_malformed_json_refused_before_plugin_or_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class _Plugin:
        name = "rea"

        def run_supplement(self, request: dict[str, Any]) -> dict[str, Any]:
            calls.append("called")
            return {"status": "failed", "reason": "should-not-run"}

    monkeypatch.setattr(
        "apkscan.core.web_supplement.discover_plugins",
        lambda: ([_Plugin()], []),
    )
    config = _config(tmp_path / "off.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": str(tmp_path / "missing-bundle"),
    })
    samples = {
        "duplicate": '{"schema_version":"1.2","package_name":"a","package_name":"b","meta":{}}\n',
        "nan": '{"schema_version":"1.2","package_name":"a","meta":{},"custom":NaN}\n',
        "exponent": '{"schema_version":"1.2","package_name":"a","meta":{},"custom":1e9999}\n',
        "deep": '{"schema_version":"1.2","package_name":"a","meta":%s}\n' % (
            '{"v":' * 33 + "0" + "}" * 33
        ),
    }
    for name, text in samples.items():
        source = tmp_path / f"{name}.json"
        source.write_text(text, encoding="utf-8")
        out = tmp_path / f"{name}-out"
        result = _invoke(source, config, out)
        assert result.exit_code == 2, name
        assert not out.exists(), name
        assert "Traceback" not in result.output
    assert calls == []


def test_repeat_snapshot_chain_and_byte_identical_publish(tmp_path: Path) -> None:
    report = _report(tmp_path / "case" / "original.json")
    config = _config(tmp_path / "off.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "off",
        "source": "rea-json",
        "path": str(tmp_path / "unused.json"),
    })
    (tmp_path / "unused.json").write_text("{}", encoding="utf-8")
    first = tmp_path / "first"
    assert _invoke(report, config, first).exit_code == 3
    before = _written(first)
    old = before["meta"]["supplement_web_input"]["relative_path"]
    second = tmp_path / "second"
    assert _invoke(first / "report.json", config, second).exit_code == 3
    assert (second / old).read_bytes() == (first / old).read_bytes()
    fresh = _written(second)["meta"]["supplement_web_input"]["relative_path"]
    assert (second / fresh).read_bytes() == (first / "report.json").read_bytes()
    assert before["leads"][0]["notes"] == "original-note"
    assert _written(second)["leads"][0]["case_note"] == "keep-lead"

    from apkscan.core.web_supplement_report import SupplementRefusal, _place_trees

    sha = "ab" * 32
    root = tmp_path / "publish"
    tree = root / "external_observations" / sha
    tree.mkdir(parents=True)
    (tree / "keep.txt").write_bytes(b"same")
    _place_trees(root, [(sha, {"keep.txt": b"same", "manifest.json": b"{}\n"})])
    assert (tree / "manifest.json").read_bytes() == b"{}\n"
    assert (tree / "keep.txt").read_bytes() == b"same"
    with pytest.raises(SupplementRefusal) as refused:
        _place_trees(root, [(sha, {"keep.txt": b"changed"})])
    assert refused.value.reason == "publish_conflict"
    assert (tree / "keep.txt").read_bytes() == b"same"


def _observation_body(factory: object) -> dict[str, Any]:
    wrapped = getattr(factory, "__wrapped__", factory)
    if not callable(wrapped):
        raise AssertionError("observation fixture is not callable")
    payload = wrapped()
    if not isinstance(payload, dict):
        raise AssertionError("observation fixture did not return an object")
    return payload


@pytest.mark.skipif(os.name != "nt", reason="directory junction requires Windows")
def test_junction_ancestor_refused(tmp_path: Path) -> None:
    import subprocess

    report = _report(tmp_path / "case" / "original.json")
    target = tmp_path / "outside"
    target.mkdir()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("keep-target", encoding="utf-8")
    link = tmp_path / "jump"
    owned = False
    try:
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
        )
        if created.returncode != 0:
            pytest.skip("directory junction is not available")
        owned = True
        config = _config(tmp_path / "off.json", {
            "schema_version": "fxapk.web_supplement.v1",
            "mode": "off",
            "source": "rea-json",
            "path": str(tmp_path / "unused.json"),
        })
        (tmp_path / "unused.json").write_text("{}", encoding="utf-8")
        result = _invoke(report, config, link / "new")
        assert result.exit_code == 2
        assert not (target / "new").exists()
        assert sentinel.read_text(encoding="utf-8") == "keep-target"
    finally:
        if owned:
            os.rmdir(link)


def test_attach_supplement_repeat_keeps_manifest_and_refuses_changed_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    from tests.test_rea_attach import _case, _rea_bundle

    _install_plugin(monkeypatch)
    bundle = tmp_path / "bundle"
    raw_sha = _rea_bundle(tmp_path, bundle)
    case = tmp_path / "case.json"
    _case(case)
    attached = tmp_path / "attached"
    importlib.import_module("fxapk_rea.attachment").attach(bundle, case, attached)
    tree = attached / "external_observations" / raw_sha
    original = (tree / "manifest.json").read_bytes()
    claimed = json.loads((attached / "report.json").read_text(encoding="utf-8"))
    assert claimed["meta"]["web_observations"][0]["manifest_sha256"] == hashlib.sha256(original).hexdigest()
    config = _config(tmp_path / "off.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "off",
        "source": "rea-json",
        "path": str(tmp_path / "unused.json"),
    })
    (tmp_path / "unused.json").write_text("{}", encoding="utf-8")
    first = tmp_path / "supplement-1"
    assert _invoke(attached / "report.json", config, first).exit_code == 3
    assert (first / "external_observations" / raw_sha / "manifest.json").read_bytes() == original
    second = tmp_path / "supplement-2"
    assert _invoke(first / "report.json", config, second).exit_code == 3
    assert (second / "external_observations" / raw_sha / "manifest.json").read_bytes() == original
    assert (tree / "manifest.json").read_bytes() == original

    tampered = tmp_path / "tampered-report"
    shutil.copytree(attached, tampered)
    payload = json.loads((tampered / "report.json").read_text(encoding="utf-8"))
    payload["meta"]["web_observations"][0]["manifest_sha256"] = "cd" * 32
    (tampered / "report.json").write_text(json.dumps(payload), encoding="utf-8")
    refused_out = tmp_path / "refused-out"
    refused = _invoke(tampered / "report.json", config, refused_out)
    assert refused.exit_code == 2
    assert not refused_out.exists()
    assert (tampered / "external_observations" / raw_sha / "manifest.json").read_bytes() == original


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_attach_preserves_parsed_trees_and_refuses_damaged_ones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    from tests.test_rea_attach import _rea_bundle

    _install_plugin(monkeypatch)
    attachment = importlib.import_module("fxapk_rea.attachment")
    bundle_a = tmp_path / "bundle-a"
    bundle_b = tmp_path / "bundle-b"
    sha_a = _rea_bundle(tmp_path, bundle_a, text="const ALPHA = 1;\n")
    sha_b = _rea_bundle(tmp_path, bundle_b, text="const BETA = 2;\n")
    assert sha_a != sha_b
    report = _report(tmp_path / "in" / "report.json")
    before = report.read_bytes()
    config_a = _config(tmp_path / "supplement-a.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": str(bundle_a),
    })
    parsed = tmp_path / "parsed"
    first = _invoke(report, config_a, parsed)
    assert first.exit_code == 0, first.output
    assert report.read_bytes() == before
    parsed_report = json.loads((parsed / "report.json").read_text(encoding="utf-8"))
    assert "web_observations" not in parsed_report["meta"]
    assert f"external_observations/{sha_a}/" in json.dumps(parsed_report)
    original = _tree_bytes(parsed / "external_observations" / sha_a)
    attached = tmp_path / "attached"
    attachment.attach(bundle_b, parsed / "report.json", attached)
    assert report.read_bytes() == before
    published = json.loads((attached / "report.json").read_text(encoding="utf-8"))
    assert f"external_observations/{sha_a}/" in json.dumps(published)
    assert [item["source_sha256"] for item in published["meta"]["web_observations"]] == [sha_b]
    copied = _tree_bytes(attached / "external_observations" / sha_a)
    assert copied == original
    config_b = _config(tmp_path / "supplement-b.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": str(bundle_b),
    })
    again = tmp_path / "again"
    second = _invoke(attached / "report.json", config_b, again)
    assert second.exit_code == 0, second.output
    assert "missing_observation" not in second.output
    assert report.read_bytes() == before

    def refuse(name: str, mutate) -> None:
        source = tmp_path / name / "src"
        shutil.copytree(parsed, source)
        mutate(source)
        destination = tmp_path / name / "out"
        with pytest.raises(attachment.AttachError):
            attachment.attach(bundle_b, source / "report.json", destination)
        assert not destination.exists()

    def tamper(source: Path) -> None:
        raw = source / "external_observations" / sha_a / "rea-original.json"
        raw.write_bytes(raw.read_bytes() + b" ")

    def missing(source: Path) -> None:
        shutil.rmtree(source / "external_observations" / sha_a)

    def link(source: Path) -> None:
        tree = source / "external_observations" / sha_a
        held = tmp_path / name_held
        if held.exists():
            shutil.rmtree(held)
        shutil.move(tree, held)
        try:
            tree.symlink_to(held, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation unavailable on this platform/permission")

    name_held = "held-a"
    refuse("tampered", tamper)
    refuse("missing", missing)
    refuse("symlink", link)


def test_same_parsed_and_attached_sha_is_copied_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    from tests.test_rea_attach import _case, _rea_bundle

    _install_plugin(monkeypatch)
    attachment = importlib.import_module("fxapk_rea.attachment")
    bundle_a = tmp_path / "bundle-a"
    bundle_b = tmp_path / "bundle-b"
    sha_a = _rea_bundle(tmp_path, bundle_a, text="const ALPHA = 1;\n")
    sha_b = _rea_bundle(tmp_path, bundle_b, text="const BETA = 2;\n")
    case = tmp_path / "case.json"
    _case(case)
    first = tmp_path / "first"
    attachment.attach(bundle_a, case, first)
    payload = json.loads((first / "report.json").read_text(encoding="utf-8"))
    payload["meta"]["parsed_ref"] = f"external_observations/{sha_a}/rea-original.json"
    (first / "report.json").write_text(json.dumps(payload), encoding="utf-8")
    second = tmp_path / "second"
    attachment.attach(bundle_b, first / "report.json", second)
    published = json.loads((second / "report.json").read_text(encoding="utf-8"))
    rows = [item["source_sha256"] for item in published["meta"]["web_observations"]]
    assert rows == [sha_a, sha_b]
    names = sorted(path.name for path in (second / "external_observations").iterdir())
    assert names == sorted([sha_a, sha_b])


def test_supplement_carries_dex_receipt_and_attach_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    from tests.test_rea_attach import _rea_bundle

    _install_plugin(monkeypatch)
    attachment = importlib.import_module("fxapk_rea.attachment")
    receipt = {"schema": "dex-query-receipt/1", "query_values": ["xref-token-example"]}
    blob = (json.dumps(receipt, sort_keys=True) + "\n").encode("utf-8")
    receipt_id = hashlib.sha256(blob).hexdigest()
    report = _report(tmp_path / "in" / "report.json")
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["dex_query"] = {
        "receipts": [{"receipt_id": receipt_id, "sha256": receipt_id, "members": []}],
    }
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (tmp_path / "in" / "dex-query").mkdir()
    (tmp_path / "in" / "dex-query" / f"{receipt_id}.json").write_bytes(blob)

    bundle = _bundle(tmp_path, f'var API_BASE = "http://127.0.0.1:9/{MARKER}";\n')
    config = _config(tmp_path / "supplement.json", {
        "schema_version": "fxapk.web_supplement.v1",
        "mode": "auto",
        "source": "bundle",
        "path": str(bundle),
    })
    supplemented = tmp_path / "supplemented"
    result = _invoke(report, config, supplemented)
    assert result.exit_code == 0, result.output
    assert (supplemented / "dex-query" / f"{receipt_id}.json").read_bytes() == blob

    bundle_b = tmp_path / "bundle-b"
    _rea_bundle(tmp_path, bundle_b, text="const B = 2;\n")
    final = tmp_path / "final"
    attachment.attach(bundle_b, supplemented / "report.json", final)
    assert (final / "dex-query" / f"{receipt_id}.json").read_bytes() == blob
