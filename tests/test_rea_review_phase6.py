"""Phase 6 reconciliation: history fallback, legacy frames, coverage, native gap, cleanup."""

from __future__ import annotations

import importlib
import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan.core.infra import _matched_infra
from apkscan.core.models import Endpoint, Evidence, Report
from apkscan.core.native_handoff import project_native_handoff, reconcile_native_history_item
from apkscan.core.web_observation_plan import build_agent_handoff, build_plan, clean_coverage
from apkscan.core.web_supplement import _record, project_for_digest
from apkscan.core.web_supplement_preservation import project_attempts
from apkscan.core.web_supplement_report import SupplementRefusal, _align_native_history_item
from apkscan.report.digest import build_digest
from apkscan.report.json import _to_jsonable
from tests.test_rea_trace_extended import _call, _ctx, _envelope, _parsed, _request, _source

@pytest.fixture
def plugin_src(monkeypatch: pytest.MonkeyPatch) -> Path:
    src = Path(__file__).parents[1] / "plugins" / "fxapk-rea" / "src"
    monkeypatch.syspath_prepend(str(src))
    return src


@pytest.fixture
def native(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "plugins" / "fxapk-rea" / "src"))
    plugin = importlib.import_module("fxapk_rea.plugin")
    importlib.reload(plugin)
    module = importlib.import_module("fxapk_rea.native")
    reloaded = importlib.reload(module)
    native_cli = importlib.import_module("fxapk_rea.native_cli")
    importlib.reload(native_cli)
    return reloaded


PRODUCER_GAPS = (
    "related_target_conflict",
    "related_target_unknown",
    "trace_cleanup_failed",
    "worker_top_frame_rejected",
    "source_unavailable",
)


def _digest() -> str:
    return "ab" * 32


def _canonical(item: dict) -> dict:
    return {
        "relation_verified": False,
        "runtime_observed": False,
        "closure_evaluated": False,
        "content_digest": item["content_digest"],
        "binary_sha256": item["binary_sha256"],
        "candidate": {
            "label": "analyst_reconstruction",
            "relation_verified": False,
            "runtime_observed": False,
            "closure_evaluated": False,
        },
    }


def test_history_fallback_rejects_result_and_candidate_conflicts() -> None:
    digest = _digest()
    binary = "cd" * 32
    item = {"content_digest": digest, "binary_sha256": binary}
    original = dict(item)
    contradictory = {
        "relation_verified": True,
        "label": "runtime_observation",
        "content_digest": digest,
        "binary_sha256": binary,
    }
    with pytest.raises(ValueError, match="result_mismatch"):
        reconcile_native_history_item(item, contradictory)
    assert item == original
    missing_candidate = dict(contradictory)
    with pytest.raises(ValueError, match="result_mismatch"):
        reconcile_native_history_item(item, missing_candidate)
    noncanonical = {
        "content_digest": digest,
        "binary_sha256": binary,
        "candidate": {"relation_verified": True, "note": "not-a-receipt"},
    }
    with pytest.raises(ValueError, match="result_mismatch"):
        reconcile_native_history_item(item, noncanonical)
    with pytest.raises(ValueError, match="result_mismatch"):
        reconcile_native_history_item(item, {**contradictory, "content_digest": "ef" * 32})
    with pytest.raises(ValueError, match="result_mismatch"):
        reconcile_native_history_item(item, {"binary_sha256": "11" * 32})
    assert item == original

    aligned = dict(item)
    reconcile_native_history_item(aligned, _canonical(aligned))
    assert aligned["relation_verified"] is False
    assert aligned["label"] == "analyst_reconstruction"

    opaque = {"content_digest": digest, "unrelated": "kept"}
    before = dict(opaque)
    reconcile_native_history_item(opaque, {"content_digest": digest})
    assert opaque == before

    files = [(f"native_recovery/{digest}/result.json", json.dumps(contradictory).encode())]
    with pytest.raises(SupplementRefusal, match="result_mismatch"):
        _align_native_history_item(item, files)
    assert item == original


def _plugin(plugin_src: Path):
    del plugin_src
    return importlib.import_module("fxapk_rea.trace"), importlib.import_module("fxapk_rea.attachment")


def _raw_cross_frame() -> bytes:
    return _envelope(
        [
            _ctx(1, "u1", "FRAME-A", 1),
            _ctx(2, "u2", "FRAME-B", 2),
            _parsed("9", 2, 3),
            _request(
                "req",
                "FRAME-A",
                4,
                {"callFrames": [], "parent": {"callFrames": [_call("9", 0, 0, "parent")]}},
                loader="LOAD-A",
            ),
        ],
        [_source("9", 3, 2, "function parent(){return 1}\n")],
    )


def _to_legacy(node: object) -> None:
    if isinstance(node, dict):
        if isinstance(node.get("script_frame_id"), str):
            node["frame_id"] = node.pop("script_frame_id")
        for value in node.values():
            _to_legacy(value)
    elif isinstance(node, list):
        for value in node:
            _to_legacy(value)


def _marker(bundle: Path) -> None:
    (bundle / "fxapk-rea-bundle.json").write_text(json.dumps({
        "schema_version": "fxapk-rea-bundle-marker/1",
        "kind": "unverified_external_observation_bundle",
    }), encoding="utf-8")


def _publish_legacy(plugin_src: Path, tmp_path: Path, raw: bytes, name: str) -> tuple[Path, bytes]:
    trace, _attachment = _plugin(plugin_src)
    fresh, files = trace.project_trace(raw)
    bundle = tmp_path / name
    from fxapk_rea.evidence import claim_output

    claim_output(bundle)
    body = trace._publish(bundle, raw, fresh, files)
    _to_legacy(body)
    encoded = (json.dumps(body, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    (bundle / "observation.json").write_bytes(encoded)
    _marker(bundle)
    return bundle, encoded


def test_legacy_cross_frame_attaches_and_forgeries_reject(plugin_src: Path, tmp_path: Path) -> None:
    trace, attachment = _plugin(plugin_src)
    raw = _raw_cross_frame()
    bundle, observation = _publish_legacy(plugin_src, tmp_path, raw, "legacy")
    fresh, _files = trace.project_trace(raw)
    from fxapk_rea.bundlecompat import assess

    compat = assess(json.loads(observation), fresh)
    assert compat.ok is True
    assert compat.legacy_frame_paths
    assert not any(path.endswith("script_frame_id") for path in compat.added_paths)
    report = tmp_path / "input.json"
    report.write_bytes(json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {},
        "endpoints": [],
        "leads": [],
        "findings": [],
        "analyzer_status": [],
    }).encode())
    attached = attachment.attach(bundle, report, tmp_path / "attached")
    copied = tmp_path / "attached" / "external_observations" / attached["source_sha256"]
    assert (copied / "observation.json").read_bytes() == observation
    record = json.loads((copied / "projection-record.json").read_text(encoding="utf-8"))
    assert record["certification_upgraded"] is False
    assert record["compatibility_gap"] == "legacy_script_frame_id"
    assert record["legacy_frame_paths"]
    published = json.loads((tmp_path / "attached" / "report.json").read_text(encoding="utf-8"))
    entry = published["meta"]["web_observations"][0]
    assert entry["provenance_authenticated"] is False
    assert entry["closure_evaluated"] is False

    nxt = json.loads(raw)
    nxt["capture"]["id"] = "00000000-0000-4000-8000-000000000002"
    again, _again_bytes = _publish_legacy(plugin_src, tmp_path, json.dumps(nxt).encode(), "current")
    attachment.attach(again, tmp_path / "attached" / "report.json", tmp_path / "reattached")
    from fxapk_rea.supplement import run_supplement

    collected = run_supplement({"source": "bundle", "path": str(bundle)})
    assert collected["status"] == "ok"
    receipt = collected["verified"]["receipt"]
    assert receipt["provenance_authenticated"] is False
    assert receipt["closure_evaluated"] is False

    same = json.loads(observation)
    forged_frame = json.loads(observation)
    forged_context = json.loads(observation)
    forged_script = json.loads(observation)
    forged_request = json.loads(observation)
    forged_hop = json.loads(observation)

    def frames(payload: dict) -> list[dict]:
        found: list[dict] = []

        def walk(node: object) -> None:
            if isinstance(node, dict):
                if "script_id" in node and "frame_id" in node:
                    found.append(node)
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(payload)
        return found

    assert frames(same)
    frames(forged_frame)[0]["frame_id"] = "FRAME-FORGED"
    frames(forged_context)[0]["context_id"] = "forged-context"
    frames(forged_script)[0]["script_id"] = "forged-script"
    forged_request["requests"][0]["request_id"] = "forged-request"
    forged_hop["requests"][0]["hops"][0]["frame_id"] = "FRAME-FORGED"
    for name, payload in (
        ("frame", forged_frame),
        ("context", forged_context),
        ("script", forged_script),
        ("request", forged_request),
        ("hop", forged_hop),
    ):
        assert assess(payload, fresh).ok is False, name
    positive = json.loads(json.dumps(fresh))
    _to_legacy(positive)
    for frame in frames(positive):
        if frame.get("frame_id") and "script_frame_id" not in frame:
            frame["script_frame_id"] = frame["frame_id"]
            break
    else:
        raise AssertionError("same-frame legacy fixture missing")
    legacy_same = json.loads(json.dumps(positive))
    _to_legacy(legacy_same)
    assert assess(legacy_same, positive).ok is True


def test_historical_manifest_accepts_only_derived_projection_files(
    plugin_src: Path, tmp_path: Path,
) -> None:
    """A report attached by the pre-migration projector has no projection files.

    Reattaching a different capture may add only those derived files in the new
    directory. A tampered stored entry still fails and writes nothing.
    """
    trace, attachment = _plugin(plugin_src)
    raw = _raw_cross_frame()
    fresh, files = trace.project_trace(raw)
    legacy = json.loads(json.dumps(fresh))
    _to_legacy(legacy)
    from fxapk_rea.evidence import claim_output

    bundle = tmp_path / "historical-bundle"
    claim_output(bundle)
    trace._publish(bundle, raw, legacy, files)
    _marker(bundle)
    observation = (bundle / "observation.json").read_bytes()
    report = tmp_path / "input.json"
    report.write_text(json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {},
        "endpoints": [],
        "leads": [],
        "findings": [],
        "analyzer_status": [],
    }), encoding="utf-8")
    from unittest.mock import patch

    original_project = attachment._project

    def legacy_project(schema: str, data: bytes) -> tuple:
        receipt, projected_files = original_project(schema, data)
        if schema == "fxapk-cdp-trace-observation/1":
            historical = json.loads(json.dumps(receipt))
            _to_legacy(historical)
            return historical, projected_files
        return receipt, projected_files

    with patch.object(attachment, "_project", side_effect=legacy_project):
        first = attachment.attach(bundle, report, tmp_path / "historical-attached")
    stored = tmp_path / "historical-attached" / "external_observations" / first["source_sha256"]
    assert (stored / "observation.json").read_bytes() == observation
    assert not (stored / "projection-record.json").is_file()
    nxt = json.loads(raw)
    nxt["capture"]["id"] = "00000000-0000-4000-8000-000000000099"
    current, _encoded = _publish_legacy(plugin_src, tmp_path, json.dumps(nxt).encode(), "current-bundle")
    second = attachment.attach(
        current, tmp_path / "historical-attached" / "report.json", tmp_path / "reattached",
    )
    carried = tmp_path / "reattached" / "external_observations" / first["source_sha256"]
    assert (carried / "observation.json").read_bytes() == observation
    assert (carried / "projection-record.json").is_file()
    record = json.loads((carried / "projection-record.json").read_text(encoding="utf-8"))
    assert record["certification_upgraded"] is False
    assert record["compatibility_gap"] == "legacy_script_frame_id"
    assert second["provenance_authenticated"] is False
    from fxapk_rea.supplement import run_supplement

    assert run_supplement({"source": "bundle", "path": str(bundle)})["status"] == "ok"
    tampered_report = tmp_path / "tampered-report.json"
    payload = json.loads((tmp_path / "historical-attached" / "report.json").read_text(encoding="utf-8"))
    payload["meta"]["web_observations"][0]["closure_evaluated"] = True
    tampered_report.write_text(json.dumps(payload), encoding="utf-8")
    rejected = tmp_path / "rejected"
    with pytest.raises(attachment.AttachError, match="existing_observation_unverified"):
        attachment.attach(current, tampered_report, rejected)
    assert not rejected.exists()
    assert (stored / "observation.json").read_bytes() == observation


def test_coverage_codes_survive_runtime_static_and_digest() -> None:
    junk = ["free text", "not_a_real_gap", *PRODUCER_GAPS]
    cleaned = clean_coverage({"status": "partial", "gaps": junk})
    assert cleaned["gaps"] == list(PRODUCER_GAPS)
    assert clean_coverage({"status": "unknown", "gaps": ["free text"]}) == {}
    older = {
        "status": "executed",
        "reason": "executed",
        "provider": "fxapk-cdp-trace",
        "coverage": {"status": "complete", "gaps": ["loader_unknown"]},
        "raw_sha256": ["a" * 64],
        "parse_counts": {"endpoints": 0, "config_leads": 0, "relations": 0, "scripts": 0},
    }
    newer = {
        "status": "executed",
        "reason": "executed",
        "provider": "fxapk-cdp-trace",
        "coverage": {"status": "partial", "gaps": [*PRODUCER_GAPS, "free text"]},
        "raw_sha256": ["b" * 64],
        "parse_counts": {"endpoints": 0, "config_leads": 0, "relations": 0, "scripts": 0},
    }
    runtime = project_attempts([older, newer], round_id="round-latest")
    assert runtime["coverage"] == {"status": "partial", "gaps": list(PRODUCER_GAPS)}
    static = _record(
        {"execute": True, "status": "executed", "reason": "executed"},
        coverage={"status": "partial", "gaps": [*PRODUCER_GAPS, "still free"]},
    )
    assert static["coverage"]["gaps"] == list(PRODUCER_GAPS)
    projected = project_for_digest(runtime)
    assert projected["coverage"]["gaps"] == list(PRODUCER_GAPS)
    digest = build_digest({"meta": {"web_supplement": runtime}, "leads": [], "findings": []})
    assert digest["web_supplement"]["coverage"]["gaps"] == list(PRODUCER_GAPS)


def test_trace_cleanup_is_environment_and_mode_off_stays_off() -> None:
    plan = build_plan(None, platform="android", meta={})
    handoff = build_agent_handoff(plan, {
        "status": "failed",
        "reason": "trace_cleanup_failed",
        "provider": "fxapk-cdp-trace",
    })
    assert handoff["why"] == "trace_cleanup_failed"
    assert handoff["next_actions"][0]["code"] == "clean_worker_environment"
    assert "修正输入" not in handoff["next_actions"][0]["instruction"]
    off = build_agent_handoff(
        {"status": "not_applicable", "reason": "mode_off", "mode": "off", "platform": "android"},
        {"status": "failed", "reason": "trace_cleanup_failed", "provider": "fxapk-cdp-trace"},
    )
    assert off["why"] == "mode_off"
    assert off["next_actions"] == []


def test_url_host_and_private_ip_do_not_cover_native_gap(monkeypatch) -> None:  # noqa: ANN001
    del monkeypatch
    sdk = Endpoint(
        value="https://sdk.example.test/config",
        kind="url",
        evidences=[Evidence(source="dex", location="classes.dex")],
    )
    loopback = Endpoint(
        value="http://127.0.0.1:8765/config",
        kind="url",
        evidences=[Evidence(source="dex", location="classes.dex")],
    )
    private_ip = Endpoint(
        value="192.0.2.1",
        kind="ip",
        evidences=[Evidence(source="dex", location="classes.dex")],
    )
    business = Endpoint(
        value="https://app.example.test/api",
        kind="url",
        evidences=[Evidence(source="dex", location="classes.dex")],
    )
    original = _matched_infra

    def matched(value: str) -> str | None:
        if value == "sdk.example.test":
            return "synthetic-sdk-rule"
        return original(value)

    from unittest.mock import patch

    from apkscan.core import infra

    with patch.object(infra, "_matched_infra", side_effect=matched):
        for endpoint in (sdk, loopback, private_ip):
            payload = _to_jsonable(Report(
                package_name="com.example.synthetic",
                endpoints=[endpoint],
                leads=[],
                findings=[],
                analyzer_status=[],
                meta={"native_lib_hashes": [{"sha256": "a" * 64}]},
            ))
            assert payload["endpoints"][0]["value"] == endpoint.value
            handoff = project_native_handoff(payload)
            assert handoff is not None
            assert "native_hash_endpoint_gap" in handoff["reasons"]
        covered = project_native_handoff(_to_jsonable(Report(
            package_name="com.example.synthetic",
            endpoints=[business],
            leads=[],
            findings=[],
            analyzer_status=[],
            meta={"native_lib_hashes": [{"sha256": "b" * 64}]},
        )))
        assert covered is None or "native_hash_endpoint_gap" not in covered["reasons"]


def test_native_cli_uses_reloaded_native_error(native, tmp_path: Path) -> None:  # noqa: ANN001
    cli = importlib.import_module("fxapk_rea.native_cli")
    assert cli.NativeError is native.NativeError
    assert cli.extract_native.__globals__["NativeError"] is native.NativeError
    member = "lib/x86_64/libsample.so"
    archive_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(member, b"synthetic-native-bytes")
    raw = bytearray(archive_path.read_bytes())
    raw[14] ^= 0xFF
    central = raw.find(b"PK\x01\x02")
    raw[central + 16] ^= 0xFF
    archive_path.write_bytes(raw)
    out = tmp_path / "extracted"
    result = CliRunner().invoke(cli.native_app, [
        "extract", str(archive_path), "--member", member, "--out", str(out),
    ])
    assert result.exit_code == 1
    assert not isinstance(result.exception, native.NativeError)
    assert json.loads(result.stdout) == {"status": "failed", "reason": "invalid_zip"}
    assert not out.exists()
