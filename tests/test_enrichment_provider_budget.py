"""Explicit endpoint-invocation budgets apply to both enrichment entry paths."""
import pytest
from apkscan.core.enrichment import enrich_selected_targets
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher


class SyntheticSource(BaseEnricher):
    name = "synthetic_source"
    applies_to = ["domain"]

    def __init__(self):
        self.calls = []

    def enrich(self, endpoint):
        self.calls.append(endpoint.value)
        return EnrichmentResult(provider=self.name, ok=True, data={"value": "synthetic"})


@pytest.mark.parametrize("close", [False, True])
@pytest.mark.parametrize("limit", [0, 2, 10])
def test_explicit_budget_is_enforced_before_any_source_invocation(close, limit):
    source = SyntheticSource()
    endpoints = [Endpoint(kind="domain", value=f"item-{i}.invalid") for i in range(5)]
    enrich_selected_targets(endpoints, [source], include_case_close=close,
                            provider_limits={source.name: limit})
    assert len(source.calls) == min(limit, 5)
    for ep in endpoints[limit:]:
        assert ep.enrichment["source_status"][source.name] == {
            "status": "skipped", "reason": "provider_budget_exhausted"}


@pytest.mark.parametrize("limit", [True, -1, 1.5, "3"])
def test_invalid_budget_never_falls_back_to_unlimited(limit):
    source = SyntheticSource()
    with pytest.raises(ValueError, match="invalid_provider_budget"):
        enrich_selected_targets([Endpoint(kind="domain", value="example.invalid")], [source],
                                include_case_close=True, provider_limits={source.name: limit})
    assert source.calls == []


def test_budget_is_shared_across_separate_target_calls():
    from apkscan.core.enrichment_budget import EnrichmentBudget
    budget = EnrichmentBudget(total=2)
    source = SyntheticSource()
    endpoints = [Endpoint(kind="domain", value=f"item-{i}.invalid") for i in range(5)]
    for ep in endpoints:
        enrich_selected_targets([ep], [source], include_case_close=True, budget=budget)
    assert len(source.calls) == 2
    assert budget.snapshot()["admitted"] == 2
    assert budget.snapshot()["denied_by_provider"] == {source.name: 3}
    assert budget.snapshot()["account_credit_budget_enforced"] is False


def test_budget_admission_is_thread_safe():
    from concurrent.futures import ThreadPoolExecutor
    from apkscan.core.enrichment_budget import EnrichmentBudget
    budget = EnrichmentBudget(total=37, providers={"synthetic": 23})
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: budget.admit("synthetic"), range(500)))
    assert sum(outcomes) == 23
    assert budget.snapshot()["admitted"] == 23


def test_zero_budget_case_close_records_skips_without_network():
    from apkscan.core.closure import ClosureConfig, close_report
    from tests.test_closure import _endpoint, _report
    source = SyntheticSource()
    ep = _endpoint("api.example.test", kind="domain", runtime=True, target=True, payload=True)
    report = _report(ep)
    result = close_report(report, ClosureConfig(max_source_calls=0), enrichers=[source])
    assert source.calls == []
    assert result["source_budget"]["admitted"] == 0
    assert result["source_budget"]["total_limit"] == 0
    assert len(result["targets"]) == 1
    assert result["source_budget"]["denied_by_provider"] == {source.name: 1}


def test_closure_budget_cannot_reset_for_resolved_ips(monkeypatch):
    from apkscan.core.closure import ClosureConfig, close_report, sources
    from tests.test_closure import _endpoint, _report, _FakeEnricher
    monkeypatch.setattr(sources, "_normalized_public_ip", lambda value: str(value).strip())
    domain = _endpoint("api.example.test", kind="domain", runtime=True, target=True, payload=True)
    dns = _FakeEnricher("dns", ["domain"], {"ips": ["198.51.100.10", "198.51.100.11"]})
    ip_source = _FakeEnricher("ip_rdap", ["ip"], {"netname": "SYNTHETIC"})
    result = close_report(_report(domain), ClosureConfig(max_source_calls=2, require_dynamic=False),
                          enrichers=[dns, ip_source])
    assert len(dns.calls) + len(ip_source.calls) == 2
    assert result["source_budget"]["admitted"] == 2
    assert result["source_budget"]["denied_by_provider"] == {"ip_rdap": 1}
    assert len(domain.enrichment["resolved_ip_enrichment"]) == 2
    assert domain.enrichment["resolved_ip_enrichment"]["198.51.100.11"]["source_status"]["ip_rdap"] == {
        "status": "skipped", "reason": "run_source_budget_exhausted"}
