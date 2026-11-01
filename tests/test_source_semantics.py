from apkscan.core.closure.layers import _request_layer
from apkscan.core.source_catalog import source_lineage_summary
from apkscan.core.source_semantics import source_contexts


def test_same_publisher_is_not_independent_and_unknown_is_not_assumed():
    internetdb = source_lineage_summary("internetdb")
    shodan = source_lineage_summary("shodan")
    assert internetdb["source_family"] == shodan["source_family"] == "shodan"
    assert internetdb["same_family_counts_as_independent"] is False
    assert source_lineage_summary("unknown")["independence_status"] == "not_established"


def test_query_provider_and_incident_times_are_not_interchanged():
    context = source_contexts({
        "source_status": {"shodan": "hit", "internetdb": "failed"},
        "shodan": {"services": [{"timestamp": "2020-01-01T00:00:00Z"}]},
    }, {"shodan": {"started_at": "2026-01-01T00:00:00Z"}})
    shodan = context["shodan"]
    assert shodan["query_time"]["started_at"] == "2026-01-01T00:00:00Z"
    assert shodan["provider_time"]["fields"] == [{
        "json_pointer": "/services/0/timestamp", "value": "2020-01-01T00:00:00Z",
    }]
    assert shodan["incident_time_correlation"] == "not_established"
    assert context["internetdb"]["outcome"]["status"] == "failed"
    assert context["internetdb"]["query_time"]["status"] == "unavailable"


def test_time_projection_is_bounded_with_visible_gap():
    context = source_contexts({
        "source_status": {"shodan": "hit"},
        "shodan": {"records": [{"timestamp": str(i)} for i in range(1000)]},
    })["shodan"]["provider_time"]
    assert len(context["fields"]) <= 32
    assert context["projection_truncated"] is True
    assert context["historical_validity"] == "not_established"


def test_request_target_remains_candidate_and_requires_event_window():
    result = _request_layer({
        "status": "partial", "evidence": {"provider": "Synthetic Network"},
    }, {"required": False})
    assert result["status"] == "partial"
    evidence = result["evidence"]
    assert evidence["relationship_status"] == "candidate"
    assert "event time window with timezone" in evidence["required_identifiers"]
    assert evidence["establishes_business_ownership"] is False
    assert evidence["legal_request_channel_status"] == "not_verified"


def test_cdn_request_prioritizes_account_and_origin_not_operator():
    result = _request_layer({"status": "partial", "evidence": {}}, {
        "required": True, "status": "missing", "edge_provider": "Synthetic Edge",
    })
    assert result["status"] == "partial"
    evidence = result["evidence"]
    assert evidence["provider"] == "Synthetic Edge"
    assert evidence["provider_role"] == "edge_delivery"
    assert "origin configuration" in evidence["evidence_fields"]
    assert evidence["establishes_business_ownership"] is False
