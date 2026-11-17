"""Pure result assembly contracts; never start orchestration or a device operation."""
from __future__ import annotations

from dataclasses import asdict
import json

import pytest

from fxapk.core.report_delivery import ReportDelivery
from fxapk.dynamic import auto


@pytest.mark.parametrize('status', ['done', 'skipped', 'degraded', 'error'])
@pytest.mark.parametrize('cancel', ['', 'synthetic_cancel'])
def test_step_and_run_projection_preserve_separate_axes(status, cancel):
    step = auto._step('synthetic', status, 'fixed reason')
    assert list(step) == ['name', 'status', 'detail']
    assert step == {'name': 'synthetic', 'status': status, 'detail': 'fixed reason'}
    closure = {'status': 'partial'}
    steps = [step]
    payload = auto._finish_run(
        status='partial', closure=closure, strict_case=True, steps=steps,
        report_paths=[], package_name='', out_dir='', delivery_sink=[], cancel_reason=cancel,
    )
    expected = dict(status='partial', closure=closure, strict_case=True, steps=steps,
                    report_paths=[], package_name='', out_dir='', report_delivery=None)
    if cancel:
        expected['cancel_reason'] = cancel
    assert json.dumps(payload, ensure_ascii=False) == json.dumps(expected, ensure_ascii=False)
    assert payload['steps'] is steps and payload['closure'] is closure


def test_delivery_failure_survives_later_success_without_changing_closure():
    failed = ReportDelivery(('json',), (), ('json',), ())
    successful = ReportDelivery(('json',), ('json',), (), ())
    payload = auto._finish_run(
        status='complete', closure={'status': 'complete'}, strict_case=False,
        steps=[], report_paths=[], package_name='', out_dir='', delivery_sink=[failed, successful],
    )
    assert payload['status'] == 'complete'
    assert payload['report_delivery'].blocks_success()
    assert asdict(payload['report_delivery']) == dict(
        requested=('json',), written=('json',), failed=('json',), skipped=())


@pytest.mark.parametrize('raw,expected', [
    ('done', 'done'), ('skipped', 'skipped'), ('error', 'error'),
    ('degraded', 'error'), ('dnoe', 'error'), ('', 'error'), (None, 'error'),
])
def test_legacy_fold_does_not_broaden_status_selection(raw, expected):
    step, paths = auto._fold_dynamic_step(
        'synthetic', {'status': raw, 'reason': 'fixed reason', 'report_paths': ['synthetic.json']})
    assert step == dict(name='synthetic', status=expected, detail='fixed reason')
    assert paths == ['synthetic.json']


def test_non_mapping_fold_keeps_existing_error_projection():
    step, paths = auto._fold_dynamic_step('synthetic', None)
    assert step == dict(name='synthetic', status='error', detail='返回值非预期格式')
    assert paths == []
