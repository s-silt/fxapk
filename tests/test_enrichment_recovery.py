"""Budgeted recovery against real adapters, without network or wall-clock waits."""
import json
from pathlib import Path

import pytest
import requests
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core import enrichment_recovery as recovery
from apkscan.core.batch_enrich import Target
from apkscan.enrichers.multisource import FofaPassiveEnricher, HunterPassiveEnricher


def response(status=200, *, payload=None, headers=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(payload if payload is not None else {
        'results': [['https://example.com', '198.51.100.1', 443]], 'size': 1,
    }).encode()
    result.headers.update(headers or {})
    result.url = 'https://synthetic.invalid/api'
    return result


class Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return next(self.responses)


@pytest.fixture
def clock(monkeypatch):
    now = [100.0]
    waits = []
    def sleep(seconds):
        waits.append(seconds)
        now[0] += seconds
    monkeypatch.setattr(recovery.time, 'monotonic', lambda: now[0])
    monkeypatch.setattr(recovery.time, 'sleep', sleep)
    monkeypatch.setenv('FXAPK_FOFA_KEY', 'synthetic')
    monkeypatch.setenv('FXAPK_FOFA_FIELD_PROFILE', 'basic')
    return waits


def execute(adapter, count=1, sink=None):
    return recovery.enrich_with_recovery(
        [Target(f'{i}.example.com', 'domain') for i in range(count)], [adapter],
        mode='passive', env={'FXAPK_FOFA_KEY': 'synthetic', 'FXAPK_HUNTER_KEY': 'synthetic'},
        completed={}, on_record=sink or (lambda r: None), retry_delay=3, provider_interval=2,
    )


def test_failed_attempt_persisted_before_recovery_and_next_target_is_paced(clock):
    http = Session([response(429), response(), response()])
    persisted = []
    records = execute(FofaPassiveEnricher(http), 2, lambda r: persisted.append((len(http.calls), r)))
    assert [x['source_status']['fofa']['status'] for x in records] == ['failed', 'hit', 'hit']
    assert [x[0] for x in persisted] == [1, 2, 3]
    assert clock == [3, 2]
    assert records[0]['receipts']['fofa']['http_status'] == 429
    assert records[1]['recovery']['retry'] is True


def test_second_failure_stops_provider_and_never_resets_recovery_budget(clock):
    http = Session([response(429), response(429)])
    rows = execute(FofaPassiveEnricher(http), 4)
    assert len(http.calls) == 2
    assert len(rows) == 5
    assert all(r['source_status']['fofa']['status'] == 'skipped' for r in rows[2:])


def test_later_limit_after_recovery_success_has_no_second_retry(clock):
    http = Session([response(429), response(), response(429)])
    rows = execute(FofaPassiveEnricher(http), 3)
    assert len(http.calls) == 3
    assert rows[-1]['source_status']['fofa']['status'] == 'skipped'


@pytest.mark.parametrize('status', [401, 402, 403])
def test_auth_permission_and_credit_errors_never_retried(clock, status):
    http = Session([response(status)])
    rows = execute(FofaPassiveEnricher(http), 2)
    assert len(http.calls) == 1
    assert not any(r['recovery'].get('retry') for r in rows)


@pytest.mark.parametrize('header,expected_calls', [('8', 2), ('120', 1)])
def test_retry_after_is_honored_or_deferred_not_truncated(clock, header, expected_calls):
    http = Session([response(429, headers={'Retry-After': header}), response()])
    execute(FofaPassiveEnricher(http), 2 if expected_calls == 1 else 1)
    assert len(http.calls) == expected_calls
    assert clock == ([8] if expected_calls == 2 else [])


def test_failed_persistence_aborts_before_sleep_or_second_request(clock):
    http = Session([response(429), response()])
    def fail(_):
        raise OSError('synthetic_disk_full')
    with pytest.raises(OSError):
        execute(FofaPassiveEnricher(http), sink=fail)
    assert len(http.calls) == 1 and clock == []


def test_hunter_retry_rechecks_free_balance_and_keeps_unknown_reservation(clock, monkeypatch, tmp_path):
    monkeypatch.setenv('FXAPK_HUNTER_KEY', 'synthetic')
    monkeypatch.setenv('FXAPK_HUNTER_CREDIT_MODE', 'provider_default')
    monkeypatch.setenv('FXAPK_HUNTER_QUOTA_DB', str(tmp_path / 'budget.sqlite3'))
    def account(remaining):
        return response(payload={'code': 200, 'data': {'rest_free_point': remaining,
            'day_free_point': 500, 'personal_info': {'phone': '10000000000'}}})
    http = Session([account(500), response(429), account(500), response(payload={
        'code': 200, 'data': {'arr': [], 'total': 0, 'consume_quota': 1}})])
    rows = execute(HunterPassiveEnricher(http))
    assert ['userInfo' in url for url, _ in http.calls] == [True, False, True, False]
    assert rows[0]['receipts']['hunter']['quota']['accounted_points'] == 10
    assert rows[1]['receipts']['hunter']['quota']['accounted_points'] == 11
    assert rows[1]['source_status']['hunter']['status'] == 'no_record'


def test_cli_dry_run_budgets_retry_without_calls(clock, monkeypatch, tmp_path: Path):
    http = Session([])
    monkeypatch.setattr('apkscan.core.registry.discover_enrichers', lambda: [FofaPassiveEnricher(http)])
    targets = tmp_path / 'targets.txt'
    targets.write_text('example.com\n')
    result = CliRunner().invoke(cli.app, ['enrich', 'batch', '-t', str(targets), '-o', str(tmp_path/'out'),
                                        '--recover-transient', '--providers', 'fofa', '--stage', 'api'])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data['estimated_requests'] == 2
    assert data['recovery_policy']['extra_request_budget'] == {'fofa': 1}
    assert http.calls == [] and clock == []


def test_completed_provider_does_not_gain_retry_budget():
    from apkscan.core.batch_enrich import BudgetLine
    assert recovery.recovery_budget([BudgetLine('fofa', 'already_done', 0)], [FofaPassiveEnricher()]) == {}


def test_cli_recovery_retains_failed_event_and_resume_makes_no_new_calls(clock, monkeypatch, tmp_path):
    http = Session([response(429), response()])
    monkeypatch.setattr('apkscan.core.registry.discover_enrichers', lambda: [FofaPassiveEnricher(http)])
    targets = tmp_path / 'targets.txt'
    targets.write_text('example.com\n')
    args = ['enrich', 'batch', '-t', str(targets), '-o', str(tmp_path/'out'),
            '--recover-transient', '--providers', 'fofa', '--stage', 'api', '--no-dry-run']
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data['processed'] == 1 and data['attempt_records'] == 2
    rows = [json.loads(line) for line in (tmp_path/'out/enrich.ndjson').read_text().splitlines()]
    assert [r['source_status']['fofa']['status'] for r in rows] == ['failed', 'hit']
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['will_process'] == 0
    assert len(http.calls) == 2



@pytest.fixture
def shodan_adapter(monkeypatch, tmp_path):
    from apkscan.enrichers import shodan

    monkeypatch.setenv("FXAPK_SHODAN_KEY", "synthetic")
    monkeypatch.setenv("FXAPK_HTTP_RATE_LIMITS", "")
    monkeypatch.setattr(shodan, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(shodan, "CACHE_FILE", tmp_path / "cache/shodan.json")
    return shodan, shodan.ShodanEnricher()


def execute_shodan(adapter, targets):
    return recovery.enrich_with_recovery(
        targets, [adapter], mode="passive", env={"FXAPK_SHODAN_KEY": "synthetic"},
        completed={}, on_record=lambda record: None, retry_delay=3, provider_interval=2,
    )


def test_shodan_recovery_dns_misses_keep_other_targets_and_one_extra_call(clock, monkeypatch, shodan_adapter):
    shodan, adapter = shodan_adapter
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        return response(payload={} if "/dns/resolve" in url else {
            "ip_str": "198.51.100.99", "ports": [443], "data": [],
        })

    monkeypatch.setattr(shodan._http, "capped_get", get)
    rows = execute_shodan(adapter, [Target("absent.example.test", "domain"),
        Target("also-absent.example.test", "domain"), Target("198.51.100.99", "ip")])
    assert [row["source_status"]["shodan"]["status"] for row in rows] == ["failed", "failed", "failed", "hit"]
    assert sum("/dns/resolve" in url for url in calls) == 3
    assert calls[-1].endswith("/shodan/host/198.51.100.99")
    assert sum(row["recovery"].get("retry", False) for row in rows) == 1
    assert adapter._blocked_error is None


@pytest.mark.parametrize("header,expected_calls", [("8", 2), ("120", 1)])
def test_shodan_recovery_honors_remote_cooldown(clock, monkeypatch, shodan_adapter, header, expected_calls):
    shodan, adapter = shodan_adapter
    http = Session([response(429, headers={"Retry-After": header}), response(payload={
        "ip_str": "198.51.100.99", "ports": [443], "data": [],
    })])
    monkeypatch.setattr(shodan._http, "capped_get", http.get)
    rows = execute_shodan(adapter, [Target("198.51.100.99", "ip")])
    assert rows[0]["receipts"]["shodan"]["retry_after_seconds"] == float(header)
    assert len(http.calls) == expected_calls
    assert clock == ([8] if expected_calls == 2 else [])


@pytest.mark.parametrize("error", [requests.ReadTimeout, TimeoutError])
def test_shodan_recovery_normalizes_timeout_and_uses_one_extra_call(clock, monkeypatch, shodan_adapter, error):
    shodan, adapter = shodan_adapter
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            raise error("synthetic timeout")
        return response(payload={"ip_str": "198.51.100.99", "ports": [443], "data": []})

    monkeypatch.setattr(shodan._http, "capped_get", get)
    rows = execute_shodan(adapter, [Target("198.51.100.99", "ip")])
    assert rows[0]["source_status"]["shodan"]["error_type"] == "timeout"
    assert rows[-1]["source_status"]["shodan"]["status"] == "hit"
    assert len(calls) == 2 and clock == [3]
