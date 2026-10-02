"""Sequence evidence cannot be assembled by mixing different observations."""
from copy import deepcopy
import pytest
from apkscan.core.closure import evaluate_capture_quality


def row(n, **quality):
    return {'kind': 'pcap' if n == 1 else 'probe', 'status': 'done',
            'artifact_verified': True, 'merge_status': 'done',
            'runtime_report_sha256': str(n) * 64, 'identity_which': 'original',
            'sample_sha256':'a'*64, 'original_sample_sha256':'a'*64,
            'runtime_variant': 'original-runtime', 'package_matches': True,
            'quality_after_merge': quality}


def complete(n):
    return row(n, business_candidate_count=1, target_attributed_count=1,
               bidirectional_target_count=1)


@pytest.mark.parametrize('reverse', [False, True])
def test_later_empty_round_cannot_erase_earlier_proof_or_hide_gap(reverse):
    rows = [complete(1), row(2)]
    if reverse:
        rows.reverse()
    before = deepcopy(rows)
    result = evaluate_capture_quality({'sequence_rounds': rows})
    assert result['dynamic_status'] == 'partial'
    assert result['sequence_business_evidence_status'] == 'complete'
    assert len(result['proof_round_refs']) == len(result['incomplete_round_refs']) == 1
    assert rows == before
    assert evaluate_capture_quality(result)['dynamic_status'] == 'partial'


def test_different_rounds_never_supply_composite_bidirectional_proof():
    rows = [row(1, business_candidate_count=1, target_attributed_count=1),
            row(2, business_candidate_count=1, bidirectional_business_count=1)]
    result = evaluate_capture_quality({'sequence_rounds': rows})
    assert result['dynamic_status'] == 'partial'
    assert result['proof_round_refs'] == []
    assert result['bidirectional_target_count'] == 0


@pytest.mark.parametrize('field,value', [('identity_which', 'unknown'),
    ('runtime_variant', 'modified-runtime'), ('artifact_verified', False),
    ('package_matches', False), ('merge_status', 'error')])
def test_unsafe_round_cannot_supply_complete_proof(field, value):
    item = complete(1)
    item[field] = value
    result = evaluate_capture_quality({'sequence_rounds': [item]})
    assert result['dynamic_status'] != 'complete'
    assert result['proof_round_refs'] == []


def test_explained_inapplicable_targeting_does_not_create_failure():
    rows = [complete(1), complete(2), {'kind':'targeted', 'status':'skipped',
        'reason':'unpacked_evidence_or_supported_targeted_hook_missing'}]
    result = evaluate_capture_quality({'sequence_rounds':rows})
    assert result['dynamic_status'] == 'complete'
    assert result['not_applicable_round_refs'] == ['round-3']


def test_legacy_single_round_unchanged():
    assert evaluate_capture_quality(complete(1)['quality_after_merge'])['dynamic_status'] == 'complete'


@pytest.mark.parametrize('records',[[],{},[None]*4])
def test_invalid_ledger_returns_complete_failure_shape(records):
    result=evaluate_capture_quality({'sequence_rounds':records})
    assert result['dynamic_status']=='failed'
    assert result['target_attributed_count']==0
    assert result['bidirectional_target_count']==0
    assert 'runtime_variant' in result


def test_unexecuted_empty_sequence_does_not_invent_dynamic_material():
    from apkscan.core.closure.gates import _capture_meta
    from apkscan.core.models import Report
    report=Report(package_name='com.example.synthetic',meta={'capture_rounds':[]},endpoints=[],leads=[],findings=[],analyzer_status=[])
    assert _capture_meta(report)=={}


def test_healthy_floor_does_not_require_intentionally_absent_frida():
    from apkscan.dynamic.auto import _pass1_suggests_bypass
    payload={'endpoint_total':3,'capture_signals':{'hook_ready_status':'none'}}
    assert _pass1_suggests_bypass('done',payload,instrumentation_expected=False)[0] is False
    assert _pass1_suggests_bypass('done',payload)[0] is True  # Legacy instrumentation contract.


def test_actual_merge_to_closure_and_preparation_keeps_round_evidence(tmp_path):
    import hashlib
    import json
    from apkscan.core.models import Report
    from apkscan.core.closure.gates import _capture_meta
    from apkscan.core.phase2.preparation import _stage_observations
    from apkscan.dynamic.auto import _run_merge
    report=Report(package_name='com.example.synthetic',meta={
        'capture_apk_identity':{'which':'original','original':{'sha256':'a'*64}}},
        endpoints=[],leads=[],findings=[],analyzer_status=[])
    rows=[]
    for n, signals in [(1, complete(1)['quality_after_merge']), (2,{})]:
        p=tmp_path/f'capture{n}.json'
        p.write_text(json.dumps({'package_name':report.package_name,'runtime_variant':'original-runtime',
                                 'capture_signals':signals,'endpoints':[]}))
        digest=hashlib.sha256(p.read_bytes()).hexdigest()
        step,_=_run_merge(report,str(p),out_dir=str(tmp_path/f'out{n}'),base='synthetic',formats=['json'],
                          on_progress=None,evidence_namespace='capture:'+digest)
        record=row(n,**report.meta['capture_quality'])
        record.update(runtime_report_sha256=digest,merge_status=step['status'])
        rows.append(record)
    report.meta['capture_rounds']=rows
    quality=evaluate_capture_quality(_capture_meta(report))
    assert quality['dynamic_status']=='partial'
    assert quality['proof_round_refs']==['round-1']
    stage=_stage_observations({'meta':report.meta},report)
    assert stage['dynamic']['status']=='partial'
    assert stage['dynamic']['target_attributed_count']==1


def test_duplicate_artifact_does_not_count_as_two_completed_rounds():
    rows=[complete(1),complete(2)]
    rows[1]['runtime_report_sha256']=rows[0]['runtime_report_sha256']
    assert evaluate_capture_quality({'sequence_rounds':rows})['dynamic_status']=='partial'


@pytest.mark.parametrize('sample_hash',[None,'bad','b'*64])
def test_missing_or_mismatched_original_sample_binding_is_not_complete(sample_hash):
    item=complete(1)
    item['sample_sha256']=sample_hash
    assert evaluate_capture_quality({'sequence_rounds':[item]})['dynamic_status']!='complete'
