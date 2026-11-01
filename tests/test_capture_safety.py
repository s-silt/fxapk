import hashlib

from apkscan.dynamic.capture_safety import compare_rounds, round_safety


def test_capture_and_ui_complete_or_zero_traffic_do_not_prove_business_outcomes(tmp_path):
    row = {"status": "done", "output_dir": str(tmp_path)}
    health = round_safety(row, {"status": "done", "capture_signals": {"endpoint_total": 0},
        "ui_observations": [{"requested_package": "com.example.synthetic", "status": "complete",
                             "target_foreground_confirmed": True}]}, "com.example.synthetic")
    assert health["onboarding"] == health["network"] == "not_checked"
    assert health["zero_traffic_means_network_failure"] is False
    result = compare_rounds([dict(row, kind="pcap", round=1, capture_safety=health),
                             dict(row, kind="probe", round=2, capture_safety=health)])
    assert result["comparisons"][0]["status"] == "inconclusive"


def test_declared_matched_regression_is_only_a_signal_and_changed_evidence_invalidates(tmp_path):
    artifact = tmp_path / "observation.txt"
    artifact.write_bytes(b"synthetic activity observation")
    check = {
        "schema_version": "capture-safety-check/1", "onboarding": "passed", "network": "passed",
        "action_plan_sha256": "a" * 64, "initial_state_sha256": "b" * 64,
        "environment_sha256": "c" * 64,
        "evidence_refs": [{"path": artifact.name, "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}],
    }
    rows = []
    for index, kind in enumerate(("pcap", "probe"), 1):
        row = {"kind": kind, "round": index, "status": "done", "output_dir": str(tmp_path),
               "artifact_verified": True, "package_matches": True, "identity_which": "original",
               "original_sample_sha256": "d" * 64}
        result = {"ui_observations": [{"requested_package": "com.example.synthetic",
                  "target_foreground_confirmed": True, "safety_check": dict(check, network="failed" if index == 2 else "passed")}]}
        row["capture_safety"] = round_safety(row, result, "com.example.synthetic")
        rows.append(row)
    comparison = compare_rounds(rows)["comparisons"][0]
    assert comparison["status"] == "reported_regression"
    assert comparison["regressions"] == ["network"]
    assert comparison["causal_attribution"] == "not_established"
    rows[1]["capture_safety"]["conditions"]["initial_state_sha256"] = "e" * 64
    assert compare_rounds(rows)["comparisons"][0]["status"] == "inconclusive"
    rows[1]["capture_safety"]["conditions"]["initial_state_sha256"] = "b" * 64
    artifact.write_bytes(b"changed")
    assert compare_rounds(rows)["comparisons"][0]["status"] == "inconclusive"
