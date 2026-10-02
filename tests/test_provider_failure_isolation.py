"""Malformed provider control fields must not abort independent sources."""
import pytest
from apkscan.core.enrichment import enrich_selected_targets
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher


class Source(BaseEnricher):
    applies_to = ["domain"]

    def __init__(self, name, data):
        self.name, self.data, self.calls = name, data, 0

    def enrich(self, endpoint):
        self.calls += 1
        return EnrichmentResult(provider=self.name, ok=True, data=self.data)


@pytest.mark.parametrize("marker", [["hit"], {"status": "hit"}, None, True, 1])
@pytest.mark.parametrize("close", [False, True])
def test_invalid_control_marker_isolated_from_other_sources(marker, close):
    bad = Source("malformed", {"_source_status": marker})
    good = Source("healthy", {"value": "synthetic"})
    endpoints = [Endpoint(kind="domain", value=f"sample-{i}.invalid") for i in range(3)]
    enrich_selected_targets(endpoints, [bad, good], include_case_close=close)
    assert good.calls == 3
    for ep in endpoints:
        assert ep.enrichment["source_status"]["malformed"] == {
            "status": "failed", "error_type": "invalid_source_status"}
        assert ep.enrichment["healthy"] == {"value": "synthetic"}


@pytest.mark.parametrize('close',[False,True])
def test_denied_refresh_does_not_reuse_old_hit_status(close):
    good=Source('healthy',{'value':'new'})
    ep=Endpoint(kind='domain',value='example.invalid',enrichment={
        'healthy':{'value':'old'},'source_status':{'healthy':{'status':'hit'}}})
    enrich_selected_targets([ep],[good],include_case_close=close,provider_limits={'healthy':0})
    assert good.calls==0
    assert ep.enrichment['source_status']['healthy']=={'status':'skipped','reason':'provider_budget_exhausted'}
    assert ep.enrichment['healthy']=={'value':'old'}  # Historical payload preserved, not a current hit.


def test_authentication_failure_worklist_requires_access_resolution():
    from apkscan.core.provider_review import _source_action
    assert _source_action({'status':'failed','error_type':'authentication_failed'}) == 'resolve_access_or_quota_do_not_retry_automatically'


@pytest.mark.parametrize('status',['skipped','disabled'])
def test_adapter_unexecuted_status_is_not_counted_as_failure(status):
    source=Source('synthetic',{'_source_status':status})
    ep=Endpoint(kind='domain',value='example.invalid')
    stats=enrich_selected_targets([ep],[source])
    assert stats[0]['failed']==0
    assert stats[0][status]==1
    assert ep.enrichment['source_status']['synthetic']['status']==status
