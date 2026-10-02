from copy import deepcopy
import pytest
from apkscan.core.models import Endpoint, EvidenceScope, Report
from apkscan.dynamic.capture_provenance import capture_scope, scoped_evidence, retain_observations, project_observations


def rep():
    return Report(package_name='com.example.synthetic', meta={}, endpoints=[], leads=[], findings=[], analyzer_status=[])


def observe(report, ref, runtime, *, verified=True, source='runtime-pcap'):
    with capture_scope(ref, verified=verified):
        ep = Endpoint(kind='domain', value='api.example.invalid',
                      evidences=[scoped_evidence(source=source, location='flow:1', scope=EvidenceScope.CASE_EVIDENCE)],
                      enrichment={'runtime':deepcopy(runtime)})
        retain_observations(report, [ep])
        if not report.endpoints:
            report.endpoints.append(ep)
        project_observations(report)


def test_projection_preserves_prior_denial_without_mixing_observations():
    r = rep()
    first = {'target_attributed':False, 'has_payload':True, 'edge_hosts':{'a':True,'b':False}}
    second = {'target_attributed':True, 'has_payload':False, 'edge_hosts':{'a':False,'b':True}}
    observe(r,'capture:a',first)
    observe(r,'capture:b',second)
    rt = r.endpoints[0].enrichment['runtime']
    assert rt['target_attributed'] is True and rt['has_payload'] is False
    assert rt['edge_hosts'] == second['edge_hosts']
    assert r.meta['runtime_observations'][0]['runtime'] == first
    before = deepcopy(r.meta)
    observe(r,'capture:b',second)
    assert r.meta == before


@pytest.mark.parametrize('source,verified', [('runtime-decrypted',True), ('runtime-pcap',False)])
def test_derived_or_unverified_cannot_borrow_other_contact(source,verified):
    r=rep()
    observe(r,'capture:a',{'target_attributed':False,'has_payload':False})
    observe(r,'capture:b',{'target_attributed':True,'has_payload':True},source=source,verified=verified)
    assert r.endpoints[0].enrichment['runtime']['target_attributed'] is False
    assert len(r.meta['runtime_observations']) == 2


def test_conflicting_same_capture_is_not_last_write_wins():
    r=rep()
    observe(r,'capture:a',{'target_attributed':False})
    observe(r,'capture:a',{'target_attributed':True})
    assert r.endpoints[0].enrichment['runtime']['target_attributed'] is None
    assert r.endpoints[0].enrichment['runtime_observation_conflicts'] == ['capture:a']


def test_context_is_reset_after_error():
    with pytest.raises(RuntimeError), capture_scope('capture:a'):
        assert scoped_evidence(source='runtime',location='x').location == 'capture:a::x'
        raise RuntimeError('synthetic')
    assert scoped_evidence(source='runtime',location='x').location == 'x'


def test_loader_preserves_observed_time():
    from apkscan.dynamic.merge import _evidences_from_jsonable
    raw=[{'source':'runtime-pcap','location':'frame:1','observed_at':1767225600.25}]
    assert _evidences_from_jsonable(raw, "synthetic")[0].observed_at == raw[0]['observed_at']


def test_real_decryption_keeps_both_capture_coordinates(tmp_path):
    import json
    from apkscan.dynamic import auto
    from tests.test_merge import _c5b_encrypt, _c5b_recipe_meta, _C5B_TS
    r=rep()
    r.meta['crypto_recipe']=_c5b_recipe_meta()
    envelope=json.dumps({'data':_c5b_encrypt('{"url":"https://api.example.test/v1"}'), 'timestamp':_C5B_TS})
    for n in (1,2):
        p=tmp_path/f'round{n}.json'
        p.write_text(json.dumps({'messages':[{'url':'https://config.example.test/config','response_body':envelope}],
                                 'endpoints':[], 'synthetic_round':n}))
        step,_=auto._run_merge(r,str(p),out_dir=str(tmp_path/f'out{n}'),base='synthetic',formats=['json'],
                               on_progress=None,evidence_namespace='capture:'+str(n)*64)
        assert step['status']=='done'
    ep=next(e for e in r.endpoints if e.value=='https://api.example.test/v1')
    locations={e.location for e in ep.evidences if e.source=='runtime-decrypted'}
    assert len(locations)==2
    assert all(x.startswith('capture:') for x in locations)


def test_unverified_identity_cannot_emit_attribution_contact_or_behavior():
    from apkscan.attribution.assemble import _bridge_endpoint, _runtime_contact_observed
    r=rep()
    observe(r,'capture:a',{'target_attributed':True,'has_payload':True,
                         'sni':['api.example.invalid'],'remote_endpoints':['192.0.2.10:443']},verified=False)
    ep=r.endpoints[0]
    assert not _runtime_contact_observed(ep)
    edges,_=_bridge_endpoint(ep)
    assert not [edge for edge in edges if edge.evidence_type in ('tls_sni','network_flow')]


@pytest.mark.parametrize('ledger', [[None], {}, [{'eligible':True}]])
def test_invalid_ledger_fails_before_merging(tmp_path, ledger):
    from apkscan.dynamic import auto
    r=rep()
    r.meta['runtime_observations']=ledger
    p=tmp_path/'runtime.json'
    p.write_text('{"endpoints":[]}')
    step,_=auto._run_merge(r,str(p),out_dir=str(tmp_path),base='synthetic',formats=['json'],
                           on_progress=None,evidence_namespace='capture:'+'a'*64)
    assert step['status']=='error'
    assert r.endpoints==[]


def test_closure_and_attribution_both_reject_unbound_selected_refs():
    from apkscan.core.closure.targets import _runtime_info
    from apkscan.attribution.assemble import _runtime_contact_observed
    r=rep()
    observe(r,'capture:a',{'target_attributed':True,'has_payload':True})
    ep=r.endpoints[0]
    ep.enrichment['runtime']['selected_evidence_refs']=['capture:a::missing']
    assert _runtime_contact_observed(ep) is False
    assert _runtime_info(ep).get('target_attributed') is not True


@pytest.mark.parametrize('kind',['credentials','jsbridge'])
def test_derived_lead_round_refs_are_complete_and_replay_idempotent(kind):
    from apkscan.dynamic import merge
    r=rep()
    for ref in ['capture:a','capture:b','capture:b']:
        with capture_scope(ref,verified=True):
            if kind=='credentials':
                merge._add_runtime_credential_leads(r,[{'source':'okhttp','url':'https://api.example.invalid/login','body':'SYNTHETIC'}])
            else:
                merge._add_runtime_jsbridge_leads(r,['SyntheticBridge'])
    assert len(r.leads)==1
    assert len(r.leads[0].source_refs)==2
    assert {e.location.split('::')[0] for e in r.leads[0].source_refs}=={'capture:a','capture:b'}
