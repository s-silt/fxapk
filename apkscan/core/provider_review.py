"""Offline provider-role review plans, never provider identity verification.

This projection consumes the existing closure evidence layers. It does not
query a provider, modify a report, infer a service operator, or turn two API
views from the same data family into independent corroboration. Its output is
an intermediate review worklist, not a formal report or a closure verdict.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from apkscan.core.source_status import normalize_source_status_map
from apkscan.core.source_catalog import source_access_summary

SCHEMA_VERSION = "provider-review-plan/1.0"
MAX_TARGETS = 200
ROLES = ("resource_holder", "origin_network", "hosting_provider", "edge_provider",
         "service_operator")
SOURCE_FAMILIES = {
    "fofa": "fofa", "fofa_profile": "fofa", "fofa_host": "fofa",
    "shodan": "shodan", "internetdb": "shodan",
    "daydaymap": "daydaymap", "daydaymap_profile": "daydaymap",
    "rdap": "registration", "whois": "registration", "ip_rdap": "registration",
    "ripestat_bgp": "ripe_ris", "cymru": "cymru", "asn": "ip_api",
    "dns": "dns", "dns_records": "dns", "certs": "certificate_transparency",
    "censys": "censys", "quake": "quake", "hunter": "hunter", "zoomeye": "zoomeye",
    "icp": "icp_registration", "urlscan": "urlscan", "otx": "otx",
    "virustotal": "virustotal",
}
# These are candidate evidence sources, not interchangeable identity authorities.
_ROLE_SOURCES = {
    "resource_holder": ("ip_rdap",),
    "origin_network": ("ripestat_bgp", "cymru", "asn"),
    "hosting_provider": ("ip_rdap", "ripestat_bgp", "censys", "shodan", "quake"),
    "edge_provider": ("dns_records", "dns", "certs", "censys", "shodan"),
    "service_operator": (),  # Requires reviewed first-party/account-level evidence.
}
_ROLE_LAYER = {"resource_holder": "resource_registration", "origin_network": "bgp_announcement",
               "hosting_provider": "hosting_delivery"}
_ENTITY_FIELDS = {"resource_holder": ("org", "netname"),
                  "origin_network": ("asn_holder",), "hosting_provider": ("provider",)}


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def source_family(provider: str) -> str:
    """Unknown adapters never earn a claim of source independence."""
    return SOURCE_FAMILIES.get(provider, "unclassified")


def _entity_names(evidence: Mapping[str, Any], fields: tuple[str, ...]) -> list[str]:
    def first_name(item: Mapping[str, Any]) -> str | None:
        for field in fields:
            value = item.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    name = first_name(evidence)
    names = {name} if name else set()
    # A network label and an organization are not two competing entities.
    # Prefer the first available field within each scoped record.
    per_ip = evidence.get("per_ip")
    if isinstance(per_ip, Mapping):
        for item in per_ip.values():
            if isinstance(item, Mapping):
                name = first_name(item)
                if name:
                    names.add(name)

    return sorted(names)


def _source_action(status: Mapping[str, Any]) -> str:
    state = status.get("status")
    if state == "hit":
        return "review_existing_evidence_and_observation_time"
    if state == "no_record":
        return "retain_negative_lookup_seek_independent_evidence"
    if state == "disabled":
        return "confirm_credentials_and_product_scope_before_query"
    if state == "failed":
        error = status.get("error_type")
        if isinstance(error, str) and error in {"auth_failed", "authentication_failed", "permission_denied", "quota_insufficient", "rate_limited",
                     "http_401", "http_403", "http_429", "local_rate_limit"}:
            return "resolve_access_or_quota_do_not_retry_automatically"
        return "diagnose_failure_before_bounded_retry"
    if state == "skipped":
        return "review_skip_reason_and_query_budget"
    return "plan_authorized_lookup_with_budget"


def _role_review(role: str, target: Mapping[str, Any], sources: Mapping[str, Any],
                 raw: bool) -> dict[str, Any]:
    layer = _mapping(_mapping(target.get("layers")).get(_ROLE_LAYER.get(role, "")))
    evidence = _mapping(layer.get("evidence"))
    names = _entity_names(evidence, _ENTITY_FIELDS.get(role, ()))
    observed_status = layer.get("status")
    if role == "edge_provider":
        origin = _mapping(target.get("origin"))
        name = origin.get("edge_provider")
        names = [name.strip()] if isinstance(name, str) and name.strip() else []
        observed_status = "partial" if names else "unknown"
    if role == "service_operator":
        # Infrastructure/closure completeness is never operator identity proof.
        names = []
        observed_status = "unknown"
    state = ("multiple_scoped_candidates" if len(names) > 1 else
             "candidate_requires_review" if names else "unresolved")
    available = [(provider, _mapping(sources[provider]))
                 for provider in _ROLE_SOURCES[role] if provider in sources]
    gaps = []
    if not names:
        gaps.append("entity_not_established")
    if observed_status != "complete":
        gaps.append("role_evidence_incomplete")
    if len(names) > 1:
        gaps.append("preserve_per_ip_entity_scope_do_not_majority_vote")
    # Collection time and TTL do not prove when a service was observed.
    gaps.append("observation_time_and_case_time_alignment_require_review")
    if role == "service_operator":
        actions = [{"action": "obtain_authorized_first_party_operator_evidence",
                    "automatic_query": False}]
        gaps.append("asn_icp_shared_ip_and_family_links_are_not_operator_proof")
    elif available:
        actions = [{"provider": provider, "source_family": source_family(provider),
                    "status": status.get("status"), "action": _source_action(status),
                    "automatic_query": False} for provider, status in available]
    else:
        actions = [{"action": "plan_authorized_lookup_with_budget",
                    "candidate_sources": list(_ROLE_SOURCES[role]), "automatic_query": False}]
    return {"role": role, "verification_status": state,
            "existing_layer_status": observed_status if isinstance(observed_status, str) and observed_status in
            {"complete", "partial", "failed"} else "unknown",
            "entity_count": len(names), **({"candidate_entities": names} if raw else {}),
            "verified": False, "gaps": gaps, "next_actions": actions}


def project_provider_review(targets: Sequence[Mapping[str, Any]], *,
                               evidence_values: str = "omit",
                               max_targets: int = MAX_TARGETS) -> dict[str, Any]:
    """Prepare a bounded, deterministic worklist from assembled closure targets.

    Default output contains role/status codes and local aliases, no target or
    entity values. Raw output is private case material and must not be sent to
    third parties. Source families describe known common origins, not a proof
    that different listed services are actually independent.
    """
    if evidence_values not in {"omit", "raw"}:
        raise ValueError("evidence_values must be omit or raw")
    if isinstance(max_targets, bool) or not isinstance(max_targets, int) or not 1 <= max_targets <= MAX_TARGETS:
        raise ValueError(f"max_targets must be between 1 and {MAX_TARGETS}")
    if any(not isinstance(target, Mapping) for target in targets):
        raise ValueError("closure targets must be objects")
    rows = []
    for index, target in enumerate(targets[:max_targets], 1):
        sources = normalize_source_status_map(target.get("source_status"))
        hit_families = sorted({source_family(provider) for provider, status in sources.items()
                               if status.get("status") == "hit" and
                               source_family(provider) != "unclassified"})
        raw = evidence_values == "raw"
        rows.append({"target_ref": f"target-{index:04d}",
                     "target_kind": target.get("kind") if target.get("kind") in ("ip", "domain", "url") else "unknown",
                     **({"target_value": target.get("value")} if raw else {}),
                     "roles": [_role_review(role, target, sources, raw) for role in ROLES],
                     "hit_source_count": sum(s.get("status") == "hit" for s in sources.values()),
                     "known_hit_source_families": hit_families,
                     "independence_verified": False})
    result = {"schema_version": SCHEMA_VERSION, "kind": "pre_report_provider_review",
            "evidence_values": evidence_values, "input_target_count": len(targets),
            "selected_target_count": len(rows), "truncated": len(targets) > len(rows),
            "status": "needs_review" if rows else "insufficient_input",
            "network_requests": 0, "automatic_retries": 0,
            "formal_report_generated": False, "operator_identity_asserted": False,
            "targets": rows}
    return result


def build_provider_review_plan(targets: Sequence[Mapping[str, Any]], *,
                               evidence_values: str = "omit",
                               max_targets: int = MAX_TARGETS) -> dict[str, Any]:
    """Public standalone plan: role projection plus one budgeted worklist.

    Multi-package composition calls project_provider_review per package and
    builds the worklist only once, with a single case-wide query budget.
    """
    result = project_provider_review(targets, evidence_values=evidence_values, max_targets=max_targets)
    result["source_worklist"] = build_source_worklist(result)
    return result


def build_source_worklist(plan: Mapping[str, Any], *, query_budget: int = 32) -> dict[str, Any]:
    """Deduplicate role work per target/provider; propose, never execute I/O.

    A request-count budget is not a monetary quota. Existing hits are reviewed,
    negatives retained, and access failures require action rather than blind
    retries. Unknown observation times always remain a separate review task.
    """
    if isinstance(query_budget, bool) or not isinstance(query_budget, int) or not 0 <= query_budget <= 1000:
        raise ValueError("invalid_query_budget")
    targets = plan.get("targets")
    if not isinstance(targets, list):
        raise ValueError("invalid_provider_plan")
    rows = []
    proposed = 0
    for target in targets:
        if not isinstance(target, Mapping) or not isinstance(target.get("target_ref"), str):
            raise ValueError("invalid_provider_target")
        providers: dict[str, dict[str, Any]] = {}
        roles = target.get("roles")
        if not isinstance(roles, list):
            raise ValueError("invalid_provider_roles")
        for role in roles:
            if not isinstance(role, Mapping) or role.get("role") not in ROLES:
                raise ValueError("invalid_provider_role")
            name = str(role["role"])
            existing = {action.get("provider"): action for action in role.get("next_actions", [])
                        if isinstance(action, Mapping) and isinstance(action.get("provider"), str)}
            for provider in _ROLE_SOURCES[name]:
                row = providers.setdefault(provider, {"roles": [], "status": "not_queried"})
                row["roles"].append(name)
                if provider in existing:
                    status = existing[provider].get("status")
                    action = existing[provider].get("action")
                    # All role views of one source must be consistent.
                    if row["status"] not in ("not_queried", status):
                        raise ValueError("inconsistent_source_views")
                    row["status"], row["action"] = status, action
        for provider, row in providers.items():
            state = row["status"]
            needs_ip = (target.get("target_kind") in ("domain", "url")
                        and provider in {"ip_rdap", "cymru", "asn", "ripestat_bgp", "internetdb"})
            if state == "not_queried" and needs_ip:
                outcome = "await_resolved_ip_evidence"
                action = "bind_observed_or_time_scoped_resolved_ip_before_source_query"
            elif state == "not_queried":
                proposed += 1
                outcome = "proposed_within_budget" if proposed <= query_budget else "deferred_query_budget"
                action = "check_access_disclosure_and_observation_window_before_query"
            else:
                outcome = "review_existing_outcome"
                action = row.get("action", "review_source_status")
            rows.append({"target_ref": target["target_ref"], "provider": provider,
                         "target_kind": target.get("target_kind", "unknown"),
                         "resolved_ip_prerequisite": needs_ip,
                         "source_family": source_family(provider), "roles": row["roles"],
                         "source_status": state, "state": outcome, "action": action,
                         "source_access": source_access_summary(provider),
                         "automatic_query": False})
    return {"kind": "provider_source_worklist", "items": rows,
            "query_budget": query_budget, "proposed_query_count": min(proposed, query_budget),
            "deferred_query_count": max(0, proposed - query_budget),
            "network_requests": 0, "cost_budget_verified": False,
            "observation_time_review_required": True,
            "service_operator_requires_authorized_first_party_review": True}
