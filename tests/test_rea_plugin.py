"""Synthetic REA evidence contracts; no browser, npm or case data required."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from apkscan.plugins import registry


def test_optional_distribution_declares_entry_point():
    import tomllib

    path = Path(__file__).parents[1] / "plugins/fxapk-rea/pyproject.toml"
    assert path.is_file(), "Optional REA distribution is missing"
    metadata = tomllib.loads(path.read_text(encoding="utf-8"))
    assert (
        metadata["project"]["entry-points"]["fxapk.plugins"]["rea"]
        == "fxapk_rea.plugin:plugin_factory"
    )


@pytest.fixture
def rea(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "plugins/fxapk-rea/src"))
    if importlib.util.find_spec("fxapk_rea") is None:
        pytest.fail("Optional REA plugin has not been implemented")
    return importlib.import_module("fxapk_rea.plugin")


@pytest.fixture
def observation():
    source = 'document.querySelector("button").addEventListener("click", () => fetch("/api"));\n'
    return {
        "ok": True,
        "data": {
            "operation": "inspect_web_page",
            "predicate_type": "rea.web-page-inspection",
            "provider": {"id": "rea-cdp-browser", "version": "2"},
            "parameters": {
                "target_id": "synthetic-target",
                "observation_ms": 10000,
                "allowed_origins": ["http://127.0.0.1:8080"],
            },
            "normalized_result": {
                "target": {
                    "target_id": "synthetic-target",
                    "origin": "http://127.0.0.1:8080",
                    "url": "http://127.0.0.1:8080/",
                },
                "capture_window": {
                    "started_at": "2026-10-11T12:00:00Z",
                    "ended_at": "2026-10-11T12:00:10Z",
                    "observation_ms": 10000,
                },
                "completeness": {
                    "status": "policy_filtered",
                    "conditions": ["attach_limited"],
                    "dropped_events": {"total": 0},
                },
                "frames": [
                    {
                        "frame_id": "synthetic-frame",
                        "parent_frame_id": None,
                        "url": "http://127.0.0.1:8080/",
                        "origin": "http://127.0.0.1:8080",
                    }
                ],
                "scripts": {
                    "items": [
                        {
                            "url": "http://127.0.0.1:8080/app.js",
                            "frame_id": "synthetic-frame",
                            "origin": "http://127.0.0.1:8080",
                            "source": {
                                "included": True,
                                "artifact": {
                                    "text": source,
                                    "sha256": hashlib.sha256(source.encode()).hexdigest(),
                                    "bytes": len(source.encode()),
                                    "media_type": "text/javascript",
                                },
                            },
                        }
                    ]
                },
                "network": {
                    "requests": [
                        {
                            "request_id": "1",
                            "url": "http://127.0.0.1:8080/api",
                            "origin": "http://127.0.0.1:8080",
                            "method": "GET",
                            "status": 200,
                            "initiator": {
                                "type": "script",
                                "url": "http://127.0.0.1:8080/app.js",
                                "line": 0,
                                "column": 64,
                            },
                            "body_shapes": {
                                "status": "included",
                                "response": {"root_type": "object"},
                            },
                        }
                    ]
                },
                "console": {
                    "prior_activity_available": False,
                    "events": [
                        {"timestamp": 1791720001000, "type": "log"},
                        {"timestamp": 1791719999000, "type": "log"},
                        {"timestamp": None, "type": "log"},
                    ],
                },
                "limitations": ["Prior network activity unavailable"],
            },
            "limitations": ["Artifact identity unavailable"],
        },
    }


def invoke_import(rea, tmp_path, payload, *extra):
    path = tmp_path / "source.json"
    raw = (json.dumps(payload, ensure_ascii=False, indent=1) + "\n").encode()
    path.write_bytes(raw)
    out = tmp_path / "result"
    cli = CliRunner().invoke(rea.rea_app, ["import", str(path), "--out", str(out), *extra])
    return cli, out, raw


def test_import_exact_bytes_provenance_and_no_attribution_upgrade(rea, observation, tmp_path):
    result, out, raw = invoke_import(rea, tmp_path, observation)
    assert result.exit_code == 0, result.output
    receipt = json.loads((out / "observation.json").read_text())
    assert (out / "rea-original.json").read_bytes() == raw
    assert receipt["source"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["status"] == "ok"
    assert receipt["coverage"]["status"] == "partial"
    assert receipt["target_app_attribution_verified"] is False
    assert receipt["closure_evaluated"] is False
    assert receipt["tool_version"] is None
    request = receipt["requests"][0]
    assert request["observed_at"] is None
    assert request["raw_body_available"] is False
    assert request["source_ref"].endswith("#/data/normalized_result/network/requests/0")
    assert request["initiator"]["type"] == "script"
    assert request["initiator"]["line_zero_based"] == 0
    assert request["initiator"]["binding"] == "url_candidate_unverified"
    assert request["initiator"]["script_path"] is None
    assert request["initiator"]["candidate_script_path"]
    assert request["initiator"]["frame_identity_verified"] is False
    assert "initiator_frame_identity_unverified" in receipt["coverage"]["gaps"]
    assert receipt["scripts"][0]["cdp_hash_relation"] == "unverified"
    assert receipt["provenance_authenticated"] is False
    sources = [item for item in receipt["artifacts"] if item["kind"] == "script_source"]
    assert sources and all(item["representation"] == "rea_source_text_utf8" for item in sources)
    for artifact in receipt["artifacts"]:
        content = (out / artifact["relative_path"]).read_bytes()
        assert artifact["sha256"] == hashlib.sha256(content).hexdigest()
        assert artifact["size"] == len(content)
    assert "http://" not in result.output
    assert "document.querySelector" not in result.output


def test_console_history_and_unknown_time_are_not_current_events(rea, observation, tmp_path):
    result, out, _ = invoke_import(rea, tmp_path, observation)
    assert result.exit_code == 0
    receipt = json.loads((out / "observation.json").read_text())
    assert [e["window_membership"] for e in receipt["console_events"]] == [
        "inside",
        "outside",
        "unknown",
    ]
    assert "console_outside_window" in receipt["coverage"]["gaps"]
    assert "console_time_unknown" in receipt["coverage"]["gaps"]
    assert receipt["click_attribution_verified"] is False


@pytest.mark.parametrize("value", [10**400, True, "1791720001000"])
def test_invalid_console_time_never_crashes_or_becomes_inside(rea, observation, tmp_path, value):
    observation["data"]["normalized_result"]["console"]["events"] = [{"timestamp": value}]
    result, out, _ = invoke_import(rea, tmp_path, observation)
    assert result.exit_code == 0, result.output
    receipt = json.loads((out / "observation.json").read_text())
    assert receipt["console_events"][0]["window_membership"] == "unknown"


def test_inspect_requires_original_requested_target_binding(
    rea, observation, tmp_path, monkeypatch
):
    class FakeRuntime:
        def __init__(self, *args):
            pass

        def capabilities(self):
            return {"status": "ok", "rea_version": "6.4.0"}

        def inspect(self, endpoint, target, origin, out, **kwargs):
            out.mkdir()
            (out / "stdout.bin").write_text(json.dumps(observation))
            return {"ok": True}

    monkeypatch.setattr(rea, "ReaRuntime", FakeRuntime)
    out = tmp_path / "capture"
    result = CliRunner().invoke(
        rea.rea_app,
        [
            "inspect",
            "--endpoint",
            "http://127.0.0.1:9222",
            "--target",
            "different",
            "--origin",
            "http://127.0.0.1:8080",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 1
    assert not (out / "observation.json").exists()
    assert (
        json.loads((out / "failure.json").read_text())["reason"]
        == "requested_observation_binding_mismatch"
    )


def test_inspect_after_claim_failure_keeps_marker_without_success(rea, tmp_path, monkeypatch):
    class FailedRuntime:
        def __init__(self, *args):
            pass

        def capabilities(self):
            return {"status": "ok", "rea_version": "6.4.0"}

        def inspect(self, endpoint, target, origin, out, **kwargs):
            return {"ok": False, "reason": "synthetic_runtime_stop"}

    monkeypatch.setattr(rea, "ReaRuntime", FailedRuntime)
    out = tmp_path / "capture"
    result = CliRunner().invoke(
        rea.rea_app,
        [
            "inspect",
            "--endpoint",
            "http://127.0.0.1:9222",
            "--target",
            "synthetic-target",
            "--origin",
            "http://127.0.0.1:8080",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 1
    assert json.loads(result.stdout)["reason"] == "rea_execution_failed"
    failure = json.loads((out / "failure.json").read_text(encoding="utf-8"))
    assert failure["reason"] == "rea_execution_failed"
    assert (out / "fxapk-rea-bundle.json").is_file()
    assert not (out / "observation.json").exists()
    from apkscan.core.rea_intake import ReaDirectIntakeError, refuse_unverified_rea_directory

    with pytest.raises(ReaDirectIntakeError):
        refuse_unverified_rea_directory(out)


@pytest.mark.parametrize("failure_point", ["script", "receipt"])
def test_import_publication_failure_keeps_original_and_marker(
    rea, observation, tmp_path, monkeypatch, failure_point
):
    evidence = importlib.import_module("fxapk_rea.evidence")
    real = evidence.atomic_create_bytes

    def inject(path, data):
        if (failure_point == "script" and path.parent.name == "scripts") or (
            failure_point == "receipt" and path.name == "observation.json"
        ):
            return False
        return real(path, data)

    monkeypatch.setattr(evidence, "atomic_create_bytes", inject)
    result, out, raw = invoke_import(rea, tmp_path, observation)
    assert result.exit_code == 1
    reason = json.loads(result.stdout)["reason"]
    assert reason == (
        "artifact_exists_refuse_overwrite"
        if failure_point == "script"
        else "receipt_exists_refuse_overwrite"
    )
    assert (out / "rea-original.json").read_bytes() == raw
    assert (out / "fxapk-rea-bundle.json").is_file()
    assert not (out / "observation.json").exists()
    from apkscan.core.rea_intake import ReaDirectIntakeError, refuse_unverified_rea_directory

    with pytest.raises(ReaDirectIntakeError):
        refuse_unverified_rea_directory(out)


def test_inspect_existing_output_prevents_runtime_calls(rea, tmp_path, monkeypatch):
    monkeypatch.setattr(rea, "ReaRuntime", lambda *args: pytest.fail("existing output invoked REA"))
    result = CliRunner().invoke(
        rea.rea_app,
        [
            "inspect",
            "--endpoint",
            "http://127.0.0.1:9222",
            "--target",
            "synthetic",
            "--origin",
            "http://127.0.0.1:8080",
            "--out",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 1
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("source_hash", "script_hash_mismatch"),
        ("source_size", "script_size_mismatch"),
        ("window_order", "invalid_window_order"),
        ("window_timezone", "invalid_timestamp"),
        ("wrong_operation", "unsupported_operation"),
        ("wrong_provider", "unsupported_provider"),
        ("target_mismatch", "target_binding_mismatch"),
        ("origin_mismatch", "target_origin_mismatch"),
        ("outside_request", "request_origin_mismatch"),
        ("bad_line", "invalid_source_coordinate"),
        ("false_ok", "rea_operation_failed"),
    ],
)
def test_invalid_contract_fails_without_evidence_publication(
    rea, observation, tmp_path, change, reason
):
    p = copy.deepcopy(observation)
    n = p["data"]["normalized_result"]
    if change == "source_hash":
        n["scripts"]["items"][0]["source"]["artifact"]["sha256"] = "0" * 64
    elif change == "source_size":
        n["scripts"]["items"][0]["source"]["artifact"]["bytes"] = True
    elif change == "window_order":
        n["capture_window"]["ended_at"] = "2026-10-11T11:00:00Z"
    elif change == "window_timezone":
        n["capture_window"]["started_at"] = "2026-10-11T12:00:00"
    elif change == "wrong_operation":
        p["data"]["operation"] = "other"
    elif change == "wrong_provider":
        p["data"]["provider"]["id"] = "other"
    elif change == "target_mismatch":
        n["target"]["target_id"] = "other"
    elif change == "origin_mismatch":
        n["target"]["origin"] = "https://example.test"
    elif change == "outside_request":
        n["network"]["requests"][0]["url"] = "https://example.test/api"
    elif change == "bad_line":
        n["network"]["requests"][0]["initiator"]["line"] = True
    elif change == "false_ok":
        p["ok"] = False
    result, out, _ = invoke_import(rea, tmp_path, p)
    assert result.exit_code == 1
    assert json.loads(result.stdout)["reason"] == reason
    assert not out.exists()


def test_import_is_offline_and_checks_expected_hash(rea, observation, tmp_path, monkeypatch):
    monkeypatch.setattr(
        rea, "ReaRuntime", lambda *a, **k: pytest.fail("offline import invoked runtime")
    )
    result, out, _ = invoke_import(rea, tmp_path, observation, "--expected-sha256", "0" * 64)
    assert result.exit_code != 0
    assert not out.exists()


def test_existing_directory_refused_without_overwrite(rea, observation, tmp_path):
    out = tmp_path / "result"
    out.mkdir()
    (out / "keep").write_bytes(b"keep")
    result, _, _ = invoke_import(rea, tmp_path, observation)
    assert result.exit_code != 0
    assert list(out.iterdir()) == [out / "keep"]
    assert (out / "keep").read_bytes() == b"keep"


def test_invalid_unicode_metadata_fails_before_publication(rea, observation, tmp_path):
    observation["data"]["normalized_result"]["target"]["title"] = "\ud800"
    path = tmp_path / "source.json"
    path.write_text(json.dumps(observation, ensure_ascii=True), encoding="utf-8")
    out = tmp_path / "result"
    result = CliRunner().invoke(rea.rea_app, ["import", str(path), "--out", str(out)])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["reason"] == "invalid_json"
    assert not out.exists()


@pytest.mark.parametrize("duration", [-1, True, "10000", 10001, 60001])
def test_window_declared_duration_must_match_parameters(rea, observation, tmp_path, duration):
    observation["data"]["normalized_result"]["capture_window"]["observation_ms"] = duration
    result, out, _ = invoke_import(rea, tmp_path, observation)
    assert result.exit_code == 1
    assert not out.exists()


@pytest.mark.parametrize("raw", [b'{"ok":true,"ok":false}', b'{"value":NaN}', b"\xff", b"[" * 2000])
def test_malformed_input_is_bounded_structured_error(rea, tmp_path, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    result = CliRunner().invoke(rea.rea_app, ["import", str(path), "--out", str(tmp_path / "out")])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["status"] == "failed"
    assert "Traceback" not in result.output


def test_exact_plugin_entry_is_discoverable_and_has_no_round_hook(rea, monkeypatch):
    entry = SimpleNamespace(
        name="rea",
        value="fxapk_rea.plugin:plugin_factory",
        dist=SimpleNamespace(metadata={"Name": "fxapk-rea"}),
        load=lambda: rea.plugin_factory,
    )
    monkeypatch.setattr(registry, "_entry_points", lambda: [entry])
    plugins, statuses = registry.discover_plugins()
    assert statuses == [{"name": "rea", "status": "ok", "reason": ""}]
    assert len(plugins) == 1
    assert not hasattr(plugins[0], "run_round")


def test_capabilities_missing_tool_preserves_offline_import(rea, tmp_path):
    result = CliRunner().invoke(rea.rea_app, ["capabilities", "--rea", str(tmp_path / "missing")])
    assert result.exit_code == 1
    capability = json.loads(result.stdout)
    assert capability["capabilities"]["import"] == "available"
    assert capability["capabilities"]["inspect"] == "unavailable"
    assert capability["browser"] == "not_probed"


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://example.test:9222",
        "http://localhost:9222",
        "http://127.0.0.1:9222/path",
        "http://user@127.0.0.1:9222",
        "https://127.0.0.1:9222",
    ],
)
def test_inspect_rejects_unsafe_endpoint_before_runtime(rea, tmp_path, monkeypatch, endpoint):
    monkeypatch.setattr(
        rea, "ReaRuntime", lambda *a, **k: pytest.fail("invalid endpoint invoked runtime")
    )
    result = CliRunner().invoke(
        rea.rea_app,
        [
            "inspect",
            "--endpoint",
            endpoint,
            "--target",
            "synthetic",
            "--origin",
            "http://127.0.0.1:8080",
            "--out",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 1
    assert json.loads(result.stdout)["status"] == "failed"
