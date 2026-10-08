"""Offline preparation never promotes infrastructure signals to identity proof."""
from copy import deepcopy
import json

import pytest

from apkscan.core.provider_review import build_provider_review_plan, source_family


def target():
    return {"value": "private-target-CANARY.invalid", "layers": {
        "resource_registration": {"status": "complete", "evidence": {"org": "PRIVATE COMPANY CANARY"}},
        "bgp_announcement": {"status": "complete", "evidence": {"asn_holder": "NETWORK CANARY"}},
        "hosting_delivery": {"status": "complete", "evidence": {"provider": "HOSTING CANARY"}},
    }, "origin": {"edge_provider": "EDGE CANARY"},
        "actual_service_operator": {"status": "complete", "evidence": {"name": "FORGED OPERATOR"}},
        "source_status": {"fofa": "hit", "fofa_profile": "hit", "fofa_host": "hit",
                          "shodan": "hit", "internetdb": "hit"}}


def test_default_projection_excludes_values_and_does_not_assert_verification():
    source = target()
    before = deepcopy(source)
    plan = build_provider_review_plan([source])
    blob = json.dumps(plan)
    assert "CANARY" not in blob and "FORGED" not in blob
    assert plan["network_requests"] == plan["automatic_retries"] == 0
    assert plan["formal_report_generated"] is False
    assert plan["operator_identity_asserted"] is False
    assert all(row["verified"] is False for row in plan["targets"][0]["roles"])
    assert source == before


def test_shared_api_families_are_not_counted_as_independent_sources():
    row = build_provider_review_plan([target()])["targets"][0]
    assert row["hit_source_count"] == 5
    assert row["known_hit_source_families"] == ["fofa", "shodan"]
    assert row["independence_verified"] is False
    assert source_family("unreviewed-adapter") == "unclassified"


def test_raw_is_explicit_and_keeps_roles_separate():
    row = build_provider_review_plan([target()], evidence_values="raw")["targets"][0]
    roles = {role["role"]: role for role in row["roles"]}
    assert roles["resource_holder"]["candidate_entities"] == ["PRIVATE COMPANY CANARY"]
    assert roles["origin_network"]["candidate_entities"] == ["NETWORK CANARY"]
    assert roles["hosting_provider"]["candidate_entities"] == ["HOSTING CANARY"]
    assert roles["edge_provider"]["candidate_entities"] == ["EDGE CANARY"]
    assert roles["service_operator"]["candidate_entities"] == []
    assert roles["service_operator"]["verification_status"] == "unresolved"


@pytest.mark.parametrize("status,action", [
    ("no_record", "retain_negative_lookup_seek_independent_evidence"),
    ("disabled", "confirm_credentials_and_product_scope_before_query"),
    ("skipped", "review_skip_reason_and_query_budget"),
    ("hit", "review_existing_evidence_and_observation_time"),
    ({"status": "failed", "error_type": "http_429"}, "resolve_access_or_quota_do_not_retry_automatically"),
])
def test_source_states_have_distinct_next_actions(status, action):
    source = target()
    source["source_status"] = {"ip_rdap": status}
    role = build_provider_review_plan([source])["targets"][0]["roles"][0]
    assert role["next_actions"][0]["action"] == action
    assert role["next_actions"][0]["automatic_query"] is False


def test_multiple_ip_providers_are_not_automatically_a_conflict():
    source = target()
    source["layers"]["hosting_delivery"]["evidence"] = {"per_ip": {
        "192.0.2.1": {"provider": "PROVIDER A"}, "192.0.2.2": {"provider": "PROVIDER B"}}}
    role = build_provider_review_plan([source])["targets"][0]["roles"][2]
    assert role["verification_status"] == "multiple_scoped_candidates"
    assert role["entity_count"] == 2
    assert "preserve_per_ip_entity_scope_do_not_majority_vote" in role["gaps"]


def test_empty_and_truncated_input_never_becomes_ready():
    assert build_provider_review_plan([])["status"] == "insufficient_input"
    plan = build_provider_review_plan([target()] * 3, max_targets=2)
    assert plan["truncated"] is True and plan["input_target_count"] == 3
    assert plan["selected_target_count"] == 2 and plan["status"] == "needs_review"


@pytest.mark.parametrize("limit", [0, -1, 201, True, 1.5])
def test_plan_budget_rejects_invalid_limits(limit):
    with pytest.raises(ValueError):
        build_provider_review_plan([], max_targets=limit)


def test_registration_prefers_organization_over_network_label():
    source = target()
    source["layers"]["resource_registration"]["evidence"]["netname"] = "NETWORK LABEL"
    role = build_provider_review_plan([source], evidence_values="raw")["targets"][0]["roles"][0]
    assert role["entity_count"] == 1
    assert role["candidate_entities"] == ["PRIVATE COMPANY CANARY"]


def test_cli_plan_binds_exact_input_and_does_not_overwrite(tmp_path):
    from typer.testing import CliRunner
    from apkscan.cli import app
    from apkscan.core.integrity import sha256_hex

    report = tmp_path / "input.json"
    content = b'{"schema_version":"1.0","meta":{},"leads":[],"endpoints":[]}'
    report.write_bytes(content)
    output = tmp_path / "plan.json"
    runner = CliRunner()
    result = runner.invoke(app, ["case", "provider-plan", str(report), "--out", str(output)])
    assert result.exit_code == 0, result.output
    plan = json.loads(output.read_bytes())
    assert plan["source_report_sha256"] == sha256_hex(content)
    assert plan["status"] == "insufficient_input"
    assert plan["formal_report_generated"] is False
    before = output.read_bytes()
    duplicate = runner.invoke(app, ["case", "provider-plan", str(report), "--out", str(output)])
    assert duplicate.exit_code == 2
    assert output.read_bytes() == before and report.read_bytes() == content


def test_report_loader_diagnostics_do_not_leak_case_values(caplog):
    from apkscan.core.report_io import report_from_dict

    report_from_dict({"schema_version": "1.0", "leads": [
        {"category": "SECRET CATEGORY CANARY", "value": "SECRET VALUE CANARY",
         "base_advice": "SECRET ADVICE CANARY"},
        {"category": "DOMAIN", "value": "SECRET VALUE CANARY",
         "base_advice": "建议调证", "legacy_effective_advice": "待核"},
    ]})
    assert caplog.records
    assert "CANARY" not in caplog.text


def test_malformed_layer_status_never_becomes_complete():
    source = target()
    source["layers"]["hosting_delivery"]["status"] = ["complete"]
    role = build_provider_review_plan([source])["targets"][0]["roles"][2]
    assert role["existing_layer_status"] == "unknown"
    assert role["verified"] is False


def test_source_worklist_deduplicates_roles_and_keeps_budget():
    from apkscan.core.provider_review import build_source_worklist
    plan = build_provider_review_plan([target()])
    work = build_source_worklist(plan, query_budget=1)
    assert work["proposed_query_count"] == 1 and work["deferred_query_count"] > 0
    rdap = [row for row in work["items"] if row["provider"] == "ip_rdap"]
    assert len(rdap) == 1
    assert set(rdap[0]["roles"]) == {"resource_holder", "hosting_provider"}
    assert all(row["automatic_query"] is False for row in work["items"])


def test_source_worklist_does_not_requery_hits_or_access_failures():
    source = target()
    source["source_status"]["ip_rdap"] = "hit"
    source["source_status"]["ripestat_bgp"] = {"status": "failed", "error_type": "http_403"}
    plan = build_provider_review_plan([source])
    tasks = {row["provider"]: row for row in plan["source_worklist"]["items"]}
    assert tasks["ip_rdap"]["action"] == "review_existing_evidence_and_observation_time"
    assert tasks["ripestat_bgp"]["action"] == "resolve_access_or_quota_do_not_retry_automatically"
    assert tasks["ripestat_bgp"]["state"] == "review_existing_outcome"


def test_pure_role_projection_and_standalone_plan_are_equivalent():
    from apkscan.core.provider_review import project_provider_review, build_source_worklist
    projected = project_provider_review([target()])
    assert "source_worklist" not in projected
    assert build_provider_review_plan([target()]) == {
        **projected, "source_worklist": build_source_worklist(projected)}


@pytest.mark.parametrize("provider,adapter", [
    ("ip_rdap", "IpRdapEnricher"),
    ("ripestat_bgp", "RipeStatBgpEnricher"),
    ("cymru", "CymruEnricher"),
    ("asn", "AsnEnricher"),
    ("censys", "CensysPassiveEnricher"),
])
@pytest.mark.parametrize("kind,value,requires_ip,expected_state", [
    ("domain", "example.invalid", True, "await_resolved_ip_evidence"),
    ("url", "https://example.invalid/api", True, "await_resolved_ip_evidence"),
    ("ip", "192.0.2.1", False, "proposed_within_budget"),
])
def test_worklist_prerequisites_match_current_ip_only_adapters(
        provider, adapter, kind, value, requires_ip, expected_state):
    # Check the current CLI adapter contract, not the broader provider product catalog.
    from apkscan.enrichers.asn import AsnEnricher
    from apkscan.enrichers.infrastructure import CymruEnricher
    from apkscan.enrichers.ip_rdap import IpRdapEnricher
    from apkscan.enrichers.multisource import CensysPassiveEnricher, RipeStatBgpEnricher

    adapters = {cls.__name__: cls for cls in (
        AsnEnricher, CymruEnricher, IpRdapEnricher, CensysPassiveEnricher, RipeStatBgpEnricher)}
    assert adapters[adapter].name == provider
    assert adapters[adapter].applies_to == ["ip"]
    source = {"kind": kind, "value": value, "source_status": {}}
    before = deepcopy(source)
    plan = build_provider_review_plan([source])
    rows = [row for row in plan["source_worklist"]["items"] if row["provider"] == provider]
    assert len(rows) == 1
    assert rows[0]["source_status"] == "not_queried"
    assert rows[0]["resolved_ip_prerequisite"] is requires_ip
    assert rows[0]["state"] == expected_state
    assert rows[0]["action"] == (
        "bind_observed_or_time_scoped_resolved_ip_before_source_query" if requires_ip else
        "check_access_disclosure_and_observation_window_before_query")
    assert rows[0]["automatic_query"] is False
    assert plan["network_requests"] == plan["source_worklist"]["network_requests"] == 0
    assert source == before


@pytest.mark.parametrize("provider", ["ip_rdap", "ripestat_bgp", "cymru", "asn", "censys"])
@pytest.mark.parametrize("kind,value,requires_ip", [
    ("domain", "example.invalid", True),
    ("url", "https://example.invalid/api", True),
    ("ip", "192.0.2.1", False),
])
@pytest.mark.parametrize("status,expected_status,action", [
    ("hit", "hit", "review_existing_evidence_and_observation_time"),
    ("no_record", "no_record", "retain_negative_lookup_seek_independent_evidence"),
    ("disabled", "disabled", "confirm_credentials_and_product_scope_before_query"),
    ("skipped", "skipped", "review_skip_reason_and_query_budget"),
    ("failed", "failed", "diagnose_failure_before_bounded_retry"),
    ({"status": "failed", "error_type": "http_429"}, "failed",
     "resolve_access_or_quota_do_not_retry_automatically"),
])
def test_ip_only_worklist_preserves_existing_outcomes(
        provider, kind, value, requires_ip, status, expected_status, action):
    source = {"kind": kind, "value": value, "source_status": {provider: status}}
    plan = build_provider_review_plan([source])
    rows = [row for row in plan["source_worklist"]["items"] if row["provider"] == provider]
    assert len(rows) == 1
    assert rows[0]["source_status"] == expected_status
    assert rows[0]["resolved_ip_prerequisite"] is requires_ip
    assert rows[0]["state"] == "review_existing_outcome"
    assert rows[0]["action"] == action
    assert rows[0]["automatic_query"] is False


@pytest.mark.parametrize("kind,budget,proposed,deferred,first_provider", [
    ("domain", 0, 0, 5, None),
    ("domain", 1, 1, 4, "shodan"),
    ("url", 0, 0, 5, None),
    ("url", 1, 1, 4, "shodan"),
    ("ip", 0, 0, 10, None),
    ("ip", 1, 1, 9, "ip_rdap"),
])
def test_worklist_budget_counts_only_ready_source_queries(
        kind, budget, proposed, deferred, first_provider):
    from apkscan.core.provider_review import build_source_worklist

    values = {"domain": "example.invalid", "url": "https://example.invalid/api", "ip": "192.0.2.1"}
    plan = build_provider_review_plan([{"kind": kind, "value": values[kind]}])
    work = build_source_worklist(plan, query_budget=budget)
    ready = [row["provider"] for row in work["items"] if row["state"] == "proposed_within_budget"]
    assert ready == ([first_provider] if first_provider else [])
    assert work["proposed_query_count"] == proposed
    assert work["deferred_query_count"] == deferred
    assert sum(row["state"] == "deferred_query_budget" for row in work["items"]) == deferred
    assert work["network_requests"] == 0


@pytest.mark.parametrize("kind,value", [
    ("domain", "example.invalid"),
    ("url", "https://example.invalid/api"),
])
def test_censys_prerequisite_keeps_shared_budget_for_ready_queries(kind, value):
    from apkscan.core.provider_review import build_source_worklist

    plan = build_provider_review_plan([
        {"kind": kind, "value": value}, {"kind": "ip", "value": "192.0.2.1"}])
    work = build_source_worklist(plan, query_budget=1)
    ready = [(row["target_ref"], row["provider"]) for row in work["items"]
             if row["state"] == "proposed_within_budget"]
    assert ready == [("target-0001", "shodan")]
    censys = [row for row in work["items"] if row["provider"] == "censys"]
    assert [row["state"] for row in censys] == [
        "await_resolved_ip_evidence", "deferred_query_budget"]
    assert [row["roles"] for row in censys] == [
        ["hosting_provider", "edge_provider"], ["hosting_provider", "edge_provider"]]
    assert work["proposed_query_count"] == 1
    assert work["deferred_query_count"] == 14


@pytest.mark.parametrize("kind_fields", [{}, {"kind": "unknown"}, {"kind": "unsupported"}])
@pytest.mark.parametrize("status,state,action", [
    (None, "await_resolved_ip_evidence",
     "bind_observed_or_time_scoped_resolved_ip_before_source_query"),
    ("hit", "review_existing_outcome", "review_existing_evidence_and_observation_time"),
    ("failed", "review_existing_outcome", "diagnose_failure_before_bounded_retry"),
    ({"status": "failed", "error_type": "http_429"}, "review_existing_outcome",
     "resolve_access_or_quota_do_not_retry_automatically"),
])
def test_censys_requires_explicit_ip_kind_without_changing_other_unknown_sources(
        kind_fields, status, state, action):
    source = {**kind_fields, "value": "synthetic.invalid",
              "source_status": {} if status is None else {"censys": status}}
    before = deepcopy(source)
    plan = build_provider_review_plan([source])
    items = plan["source_worklist"]["items"]
    censys = [row for row in items if row["provider"] == "censys"]
    assert len(censys) == 1
    assert censys[0]["target_kind"] == "unknown"
    assert censys[0]["resolved_ip_prerequisite"] is True
    assert censys[0]["state"] == state
    assert censys[0]["action"] == action
    assert censys[0]["automatic_query"] is False
    others = [row for row in items if row["provider"] != "censys"]
    assert len(others) == 9
    assert all(row["state"] == "proposed_within_budget" for row in others)
    assert all(row["resolved_ip_prerequisite"] is False for row in others)
    assert plan["source_worklist"]["proposed_query_count"] == 9
    assert plan["source_worklist"]["network_requests"] == 0
    assert source == before


@pytest.mark.parametrize("kind_fields", [{}, {"kind": "unknown"}, {"kind": "unsupported"}])
def test_unknown_censys_target_does_not_take_shared_budget_from_explicit_ip(kind_fields):
    from apkscan.core.provider_review import build_source_worklist

    source_status = {provider: "hit" for provider in (
        "ip_rdap", "ripestat_bgp", "cymru", "asn", "shodan", "quake", "dns_records", "dns", "certs")}
    plan = build_provider_review_plan([
        {**kind_fields, "value": "synthetic.invalid", "source_status": source_status},
        {"kind": "ip", "value": "192.0.2.1"},
    ])
    work = build_source_worklist(plan, query_budget=1)
    ready = [(row["target_ref"], row["provider"]) for row in work["items"]
             if row["state"] == "proposed_within_budget"]
    assert ready == [("target-0002", "ip_rdap")]
    censys = [row for row in work["items"] if row["provider"] == "censys"]
    assert [row["state"] for row in censys] == [
        "await_resolved_ip_evidence", "deferred_query_budget"]
    assert work["proposed_query_count"] == 1
    assert work["deferred_query_count"] == 9
