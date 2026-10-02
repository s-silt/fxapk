from apkscan.dynamic import pcap_ingest


def test_capture_file_and_bytes_budget_are_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(pcap_ingest, "MAX_CAPTURE_BYTES", 16)
    path = tmp_path / "synthetic.pcap"
    path.write_bytes(b"x" * 17)
    assert pcap_ingest.parse_pcap(str(path)).parse_status == "resource_limit"
    assert pcap_ingest.parse_pcap_bytes(path.read_bytes()).parse_status == "resource_limit"


def test_capture_readiness_needs_attribution_same_endpoint_and_identity():
    from apkscan.dynamic.capture_plan import decide_capture
    decision = decide_capture({"meta": {"capture_quality": {
        "target_attributed_count": 1, "business_candidate_count": 2,
        "bidirectional_business_count": 1, "bidirectional_target_count": 0}}})
    gaps = decision.evidence_readiness["gaps"]
    assert "same_target_bidirectional_payload_missing" in gaps
    assert "running_apk_identity_requires_confirmation" in gaps
    assert decision.evidence_readiness["operator_identity_verified"] is False


def test_capture_plan_does_not_guarantee_origin_or_nonempty_capture():
    from apkscan.dynamic.capture_plan import plan_capture
    text = "\n".join(plan_capture({}))
    assert "永远有结果" not in text and "已保证你不会" not in text
    assert "不能保证" in text and "不能直接认定源站" in text
