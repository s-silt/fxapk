import hashlib
import json

import pytest


def ref(path, value):
    data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
    path.write_bytes(data)
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}


def specimen(tmp_path):
    apk = ref(tmp_path / "sample.apk", b"synthetic-test-bytes")
    report = ref(tmp_path / "report.json", {"package_name": "test.example.app", "meta": {"sample_sha256": apk["sha256"]}, "endpoints": []})
    runtime = ref(tmp_path / "runtime_report.json", {"package_name": "test.example.app", "runtime_variant": "original-runtime",
        "capture_context": {"sample_sha256": apk["sha256"]}, "config_body_artifacts": [], "addressing_events": []})
    return {"case_id": "example", "apk": apk, "report": report, "runtime_reports": [runtime]}


def test_real_evaluation_keeps_unknowns_out_of_accuracy_denominator(tmp_path):
    from apkscan.config.evaluation import evaluate_real_suite
    case = specimen(tmp_path)
    result = evaluate_real_suite([case])
    assert result["real_case_count"] == 1 and result["independently_labeled_case_count"] == 0
    assert result["cases"][0]["label_status"] == "unknown"
    assert result["accuracy"] is None and result["ranking_or_advice_change_eligible"] is False
    assert "independent_real_case_labels_missing" in result["gaps"]
    assert result["cases"][0]["actual"]["original_consumption_verified"] is False


def test_real_evaluation_lists_all_six_missing_negative_categories(tmp_path):
    from apkscan.config.evaluation import evaluate_real_suite

    result = evaluate_real_suite([specimen(tmp_path)])
    expected = ["cdn_contact", "expired_resolution", "modified_runtime", "random_iv", "sdk_config_domain", "shared_ip"]
    assert result["negative_category_coverage"] == [{"category": name, "labeled_case_count": 0} for name in expected]
    assert all("independent_negative_category_missing:" + name in result["gaps"] for name in expected)


@pytest.mark.parametrize("categories", [["modified_runtime"], ["invented"], "modified_runtime", [{}]])
def test_real_negative_categories_require_explicit_valid_labels(tmp_path, categories):
    from apkscan.config.evaluation import evaluate_real_suite

    case = specimen(tmp_path)
    label = {"schema": "fxapk-addressing-label-1", "case_id": "example", "sample_sha256": case["apk"]["sha256"],
             "basis": "independent_review", "reviewer": "fixture-reviewer", "evidence_sha256": [case["runtime_reports"][0]["sha256"]],
             "negative_categories": categories,
             "expected": {"original_consumption_verified": False, "business_certificate_usable": False, "origin_confirmed": False}}
    case["independent_label"] = ref(tmp_path / "label.json", label)
    if categories == ["modified_runtime"]:
        result = evaluate_real_suite([case])
        counts = {r["category"]: r["labeled_case_count"] for r in result["negative_category_coverage"]}
        assert counts["modified_runtime"] == 1 and sum(counts.values()) == 1
    else:
        with pytest.raises(ValueError, match="invalid_independent_label"):
            evaluate_real_suite([case])


def test_evaluation_rehashes_sample_report_and_runtime_and_never_rewrites(tmp_path):
    from apkscan.config.evaluation import evaluate_real_suite
    case = specimen(tmp_path)
    before = {r["path"]: open(r["path"], "rb").read() for r in [case["apk"], case["report"], *case["runtime_reports"]]}
    evaluate_real_suite([case])
    assert all(open(p, "rb").read() == raw for p, raw in before.items())
    (tmp_path / "runtime_report.json").write_text("{}")
    with pytest.raises(ValueError, match="hash_mismatch"):
        evaluate_real_suite([case])


def test_independent_label_is_separate_bound_material_not_inferred_from_zero_events(tmp_path):
    from apkscan.config.evaluation import evaluate_real_suite
    case = specimen(tmp_path)
    label = {"schema": "fxapk-addressing-label-1", "case_id": "example", "sample_sha256": case["apk"]["sha256"],
             "basis": "independent_review", "reviewer": "fixture-reviewer", "evidence_sha256": [case["runtime_reports"][0]["sha256"]],
             "expected": {"original_consumption_verified": False, "business_certificate_usable": False, "origin_confirmed": False}}
    case["independent_label"] = ref(tmp_path / "label.json", label)
    result = evaluate_real_suite([case])
    assert result["independently_labeled_case_count"] == 1 and result["accuracy"] == 1
    assert result["ranking_or_advice_change_eligible"] is False
    label["sample_sha256"] = "b" * 64
    case["independent_label"] = ref(tmp_path / "label.json", label)
    with pytest.raises(ValueError, match="invalid_independent_label"):
        evaluate_real_suite([case])


def test_evaluation_cli_is_offline_and_does_not_overwrite(tmp_path, monkeypatch):
    import socket
    from typer.testing import CliRunner
    from apkscan.cli import app
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("evaluation network"))
    case = specimen(tmp_path)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema": "fxapk-addressing-evaluation-1", "cases": [case]}))
    output = tmp_path / "evaluation.json"
    result = CliRunner().invoke(app, ["addressing-evaluate", str(manifest), "--out", str(output)])
    assert result.exit_code == 0, result.output
    before = output.read_bytes()
    result = CliRunner().invoke(app, ["addressing-evaluate", str(manifest), "--out", str(output)])
    assert result.exit_code == 2 and output.read_bytes() == before


@pytest.mark.parametrize("variant", ["bound", "unbound_round", "wrong_identity", "stale_ledger"])
def test_evaluation_rebuilds_capture_scope_and_does_not_trust_old_ledger(tmp_path, variant):
    from apkscan.config.evaluation import evaluate_real_suite
    from apkscan.dynamic.addressing_events import AddressingEventCollector
    from apkscan.dynamic.config_artifacts import ConfigBodyCollector
    from tests.test_addressing_runtime import ART, BODY, CONTEXT, events
    case = specimen(tmp_path)
    sample = case["apk"]["sha256"]
    scope = {**CONTEXT, "sample_sha256": sample}
    collector = AddressingEventCollector(tmp_path, scope)
    for event in events():
        collector.on_message({"type": "send", "payload": {**event, "type": "fxapk-addressing-event-v1"}}, None)
    bodies = ConfigBodyCollector(tmp_path, scope)
    bodies.on_message({"type": "send", "payload": {"type": "fxapk-config-body-v1", "body_complete": True,
                       "declared_length": len(BODY)}}, BODY)
    endpoint = {"kind": "domain", "value": "api.example.test", "enrichment": {
        "runtime": {"variant": "original-runtime", "target_attributed": True}},
        "evidences": [{"source": "runtime-pcap", "location": "floor.pcap", "snippet": "fixture",
                       "scope": "case_evidence"}]}
    runtime = {"package_name": "test.example.app", "runtime_variant": "original-runtime", "capture_context": scope,
               "addressing_events": collector.records(), "config_body_artifacts": bodies.records(),
               "endpoints": [] if variant == "stale_ledger" else [endpoint]}
    runtime_ref = ref(tmp_path / "runtime_report.json", runtime)
    case["runtime_reports"] = [runtime_ref]
    sha = "b" * 64 if variant == "wrong_identity" else sample
    meta = {"sample_sha256": sample, "remote_config_artifacts": [{**ART, "source_url": "https://cfg.example.test/config", "domains": [endpoint["value"]]}],
            "capture_apk_identity": {"which": "original", "original": {"sha256": sha}},
            "capture_rounds": [{"sample_sha256": sha, "runtime_report_sha256": runtime_ref["sha256"]}]}
    if variant == "unbound_round":
        meta["capture_rounds"] = []
    if variant == "stale_ledger":
        meta["runtime_observations"] = [{"capture_ref": "capture:" + runtime_ref["sha256"], "kind": "domain",
            "value": endpoint["value"], "eligible": True, "runtime": endpoint["enrichment"]["runtime"]}]
    case["report"] = ref(tmp_path / "report.json", {"package_name": "test.example.app", "meta": meta,
                                                   "endpoints": [{"kind": "domain", "value": endpoint["value"]}]})
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    result = evaluate_real_suite([case])
    assert result["cases"][0]["actual"]["original_consumption_verified"] is (variant == "bound")
    assert result["accuracy"] is None
    assert all(p.read_bytes() == raw for p, raw in before.items())
