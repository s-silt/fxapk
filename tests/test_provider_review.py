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


def test_domain_worklist_does_not_spend_query_budget_on_ip_only_calls():
    plan=build_provider_review_plan([{'kind':'domain','value':'example.invalid','source_status':{}}])
    items=plan['source_worklist']['items']
    ip_only=[item for item in items if item['provider'] in {'ip_rdap','cymru','asn','ripestat_bgp','internetdb'}]
    assert ip_only
    assert all(item['state']=='await_resolved_ip_evidence' for item in ip_only)
    assert all(item['resolved_ip_prerequisite'] is True for item in ip_only)
