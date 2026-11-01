from apkscan.report.digest import build_digest


def test_capture_safety_digest_does_not_export_private_artifacts_or_prove_causality():
    digest = build_digest({"meta": {"capture_safety_comparison": {
        "non_interference_proven": True,
        "comparisons": [{"round": 2, "baseline_round": 1, "status": "reported_regression",
                         "regressions": ["network"], "gaps": [],
                         "causal_attribution": "proven", "path": "private.txt"}] * 14,
    }}})
    safety = digest["capture_safety"]
    assert safety["non_interference_proven"] is False
    assert safety["omitted_comparisons"] == 2
    assert safety["comparisons"][0]["status"] == "reported_regression"
    assert safety["comparisons"][0]["causal_attribution"] == "not_established"
    assert "private.txt" not in str(safety)


def test_request_digest_preserves_per_ip_roles_and_cannot_establish_operator():
    candidate = {"value": "192.0.2.10", "status": "partial", "layers": {
        "request_target": {"evidence": {
            "provider": "Synthetic Edge", "provider_role": "edge_delivery",
            "required_identifiers": ["event time window with timezone"],
            "evidence_fields": ["origin configuration"],
            "legal_request_channel_status": "verified",
        }}}, "source_context": {"internetdb": {
            "source_family": "shodan", "query_time": {"status": "unavailable"},
        }}}
    digest = build_digest({"meta": {"closure": {"status": "partial", "targets": [
        {"value": "example.test", "status": "partial", "resolved_ip_targets": [candidate]},
    ]}}})
    child = digest["closure"]["request_targets"][0]["resolved_ip_candidates"][0]
    assert child["provider_candidate"] == "Synthetic Edge"
    assert child["provider_role"] == "edge_delivery"
    assert child["service_operator"] == "unknown"
    assert child["legal_request_channel_status"] == "not_verified"
    assert child["evidence_to_obtain"] == ["origin configuration"]
    assert child["sources"][0]["same_family_counts_as_independent"] is False
