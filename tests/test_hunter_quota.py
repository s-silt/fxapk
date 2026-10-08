"""No live Hunter calls: exercise accounting, concurrency and fail-closed I/O."""
from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import json
import multiprocessing
import os
import sqlite3

import pytest
import requests
from typer.testing import CliRunner

from apkscan.cli import app
from apkscan.core import hunter_quota as quota
from apkscan.core.models import Endpoint
from apkscan.core.response_evidence import capture_responses, retain_response
from apkscan.enrichers.multisource import HunterPassiveEnricher, FofaPassiveEnricher
from apkscan.enrichers.multisource import _business_error


def account(remaining=500, phone="10000000000", limit=500):
    return {"code": 200, "data": {"rest_free_point": remaining, "day_free_point": limit,
            "rest_equity_point": 10000, "personal_info": {"phone": phone}}}


class Response:
    status_code = 200

    def __init__(self, body, url):
        self.body, self.url = body, url
        self.content = json.dumps(body).encode()

    def json(self):
        return self.body

    def raise_for_status(self):
        pass


class Session:
    def __init__(self, info=None, cost=10, error=None):
        self.info = account() if info is None else info
        self.cost, self.error, self.calls = cost, error, []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if url.endswith("userInfo"):
            response = Response(self.info, url)
        else:
            if self.error:
                raise self.error
            response = Response({"code": 200, "data": {"arr": [], "consume_quota": self.cost}}, url)
        retain_response(response)
        return response


@pytest.fixture(autouse=True)
def isolated_quota(tmp_path, monkeypatch):
    monkeypatch.setenv("FXAPK_HUNTER_QUOTA_DB", str(tmp_path / "quota.sqlite3"))
    monkeypatch.setenv("FXAPK_HUNTER_KEY", "SYNTHETIC_QUOTA_KEY")


def run(session=None):
    adapter = HunterPassiveEnricher(session=session or Session())
    result = adapter.enrich(Endpoint(kind="domain", value="quota.example.test"))
    return result, adapter.receipt


def used():
    with sqlite3.connect(quota.quota_path()) as db:
        return db.execute("SELECT sum(used) FROM budget").fetchone()[0]


def test_hunter_busy_message_is_rate_limited():
    error = _business_error({"code": 429, "message": "请求太多啦，稍后再试试"})
    assert error.category == "rate_limited"
    assert _business_error({"errmsg": "今日次数已用完"}).category == "quota_insufficient"


def test_fofa_basic_profile_preserves_canonical_column_positions(monkeypatch):
    monkeypatch.setenv("FXAPK_FOFA_FIELD_PROFILE", "basic")
    session = Session()
    adapter = FofaPassiveEnricher(session=session)
    endpoint = Endpoint(kind="ip", value="203.0.113.5")
    adapter._lookup(endpoint, "synthetic")
    assert session.calls[0][1]["params"]["fields"] == "host,ip,port"
    result = adapter._normalize({"results": [["203.0.113.5:443", "203.0.113.5", "443"]], "size": 1}, endpoint)
    assert result["records"][0][1:3] == ["203.0.113.5", "443"]
    assert result["records"][0][3:] == [None] * 8
    with pytest.raises(ValueError, match="field_count"):
        adapter._normalize({"results": [["bad"]]}, endpoint)


def test_fofoapi_documented_fields_map_to_canonical_columns(monkeypatch):
    monkeypatch.setenv("FXAPK_FOFA_URL", "https://fofoapi.com")  # leak-scan: allow public relay API hostname required for provider-specific protocol compatibility
    monkeypatch.setenv("FXAPK_FOFA_FIELD_PROFILE", "full")
    session = Session()
    adapter = FofaPassiveEnricher(session=session)
    endpoint = Endpoint(kind="ip", value="203.0.113.5")
    adapter._lookup(endpoint, "synthetic")
    assert session.calls[0][1]["params"]["fields"].endswith("location.country,location.region,location.city,asn,org")
    row = ["203.0.113.5:443", "203.0.113.5", "443", "https", "title", "server", "ZZ", "region", "city", "64500", "example"]
    result = adapter._normalize({"results": [row], "size": 1}, endpoint)
    assert result["records"][0][1:] == row[1:]


@pytest.mark.parametrize("total", [0, "0"])
def test_null_empty_search_is_no_record_and_charges_actual_cost(total):
    class EmptySession(Session):
        def get(self, url, **kwargs):
            response = super().get(url, **kwargs)
            if not url.endswith("userInfo"):
                response.body["data"].update(arr=None, total=total)
            return response

    result, _ = run(EmptySession(cost=1))
    assert result.data["_source_status"] == "no_record"
    assert used() == 1


@pytest.mark.parametrize("data", [
    {"arr": None}, {"arr": None, "total": 1},
    {"arr": None, "total": False}, {"total": 0},
    {"arr": [None], "total": 0}, {"arr": None, "total": 0.0},
])
def test_null_or_malformed_records_do_not_hide_missing_evidence(data):
    adapter = HunterPassiveEnricher(session=Session())
    with pytest.raises(ValueError):
        adapter._normalize({"code": 200, "data": data},
                           Endpoint(kind="domain", value="quota.example.test"))


def test_shared_daily_cap_across_instances_threads_and_rotated_key(monkeypatch):
    def query(_):
        return run()[0].data["_source_status"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        states = list(pool.map(query, range(60)))
    assert states.count("no_record") == 50
    assert states.count("skipped") == 10
    assert used() == 500
    monkeypatch.setenv("FXAPK_HUNTER_KEY", "ROTATED_SYNTHETIC_KEY")
    session = Session()
    result, receipt = run(session)
    assert result.data["_error_type"] == "hunter_daily_free_limit"
    assert receipt["search_attempted"] is False
    assert len(session.calls) == 1


def _reserve_in_process(path):
    os.environ["FXAPK_HUNTER_QUOTA_DB"] = path
    identity, remaining, limit = quota.account_balance(account())
    try:
        with quota.quota_store() as store:
            store.reserve(identity, remaining, limit, quota.local_day())
        return True
    except quota.HunterQuotaError as exc:
        assert exc.category == "hunter_daily_free_limit"
        return False


def test_process_reservations_survive_exit_and_serialize():
    identity, remaining, limit = quota.account_balance(account())
    with quota.quota_store() as store:
        for _ in range(48):
            store.reserve(identity, remaining, limit, quota.local_day())
    with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context("spawn")) as pool:
        allowed = list(pool.map(_reserve_in_process, [str(quota.quota_path())] * 8))
    assert sum(allowed) == 2
    assert used() == 500  # Unsettled reservations are never automatically released.


@pytest.mark.parametrize("remaining", [0, 1, 9])
def test_live_free_balance_blocks_paid_fallback(remaining):
    session = Session(account(remaining))
    result, receipt = run(session)
    assert result.data["_source_status"] == "skipped"
    assert len(session.calls) == 1 and receipt["search_attempted"] is False


def test_web_spending_is_included_and_exact_last_page_allowed():
    result, receipt = run(Session(account(10)))
    assert result.data["_source_status"] == "no_record"
    assert receipt["quota"]["accounted_points"] == 500
    assert run(Session(account(10)))[0].data["_source_status"] == "skipped"


@pytest.mark.parametrize("cost,expected", [("消耗积分：1", 1), (0, 0), (None, 10), (True, 10), (-1, 10), ("bad", 10)])
def test_actual_cost_or_conservative_reservation(cost, expected):
    run(Session(cost=cost))
    assert used() == expected


def test_timeout_keeps_reservation():
    result, receipt = run(Session(error=requests.Timeout()))
    assert result.data["_source_status"] == "failed"
    assert used() == 10
    assert receipt["quota"]["status"] == "reserved"
    assert result.data["_error_type"] != "hunter_quota_store_unavailable"


def test_changed_cost_contract_blocks_further_queries():
    run(Session(cost=11))
    session = Session()
    result, _ = run(session)
    assert result.data["_error_type"] == "hunter_cost_contract_changed"
    assert len(session.calls) == 1


@pytest.mark.parametrize("info", [account(-1), account(True), account(501), account(500, limit=-1),
                                 account(phone="masked***"), {"code": 200, "data": {}}, {}])
def test_unknown_account_or_balance_never_searches(info):
    session = Session(info)
    assert run(session)[0].data["_source_status"] == "failed"
    assert len(session.calls) == 1


def test_corrupt_or_unwritable_store_blocks_before_network(tmp_path, monkeypatch):
    quota.quota_path().write_bytes(b"not a database")
    session = Session()
    result, _ = run(session)
    assert result.data["_error_type"] == "hunter_quota_store_unavailable"
    assert not session.calls
    monkeypatch.setenv("FXAPK_HUNTER_QUOTA_DB", str(tmp_path))
    session = Session()
    assert run(session)[0].data["_source_status"] == "failed"
    assert not session.calls


def test_new_day_and_clock_rollback(monkeypatch):
    monkeypatch.setattr(quota, "local_day", lambda: "2026-09-24")
    run(Session(account(10)))
    monkeypatch.setattr(quota, "local_day", lambda: "2026-09-25")
    assert run()[0].data["_source_status"] == "no_record"
    monkeypatch.setattr(quota, "local_day", lambda: "2026-09-23")
    assert run()[0].data["_error_type"] == "hunter_quota_clock_rollback"


def test_account_body_and_credentials_not_retained(tmp_path):
    with capture_responses(tmp_path / "evidence") as artifacts:
        _, receipt = run()
    assert len(artifacts) == 1
    assert "10000000000" not in json.dumps(receipt)
    assert "SYNTHETIC_QUOTA_KEY" not in json.dumps(receipt)
    assert b"10000000000" not in quota.quota_path().read_bytes()
    assert b"SYNTHETIC_QUOTA_KEY" not in quota.quota_path().read_bytes()
    assert len(receipt["responses"]) == 2


def test_query_stays_within_free_history_and_no_redirects():
    session = Session()
    run(session)
    from datetime import datetime, timedelta
    params = session.calls[1][1]["params"]
    assert datetime.fromisoformat(params["end_time"]) - datetime.fromisoformat(params["start_time"]) == timedelta(days=29)
    assert params["page_size"] == 10
    assert all(call[1]["allow_redirects"] is False for call in session.calls)


def test_batch_dry_run_does_not_read_account_or_reserve(tmp_path, monkeypatch):
    session = Session()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [HunterPassiveEnricher(session=session)])
    targets = tmp_path / "targets.txt"
    targets.write_text("quota.example.test\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["enrich", "batch", "--targets", str(targets), "--out", str(tmp_path / "out"), "--providers", "hunter"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["estimated_requests"] == 2
    assert not session.calls and not quota.quota_path().exists()


def test_new_case_output_and_no_resume_cannot_reset_account(tmp_path, monkeypatch):
    session = Session(account(10))
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [HunterPassiveEnricher(session=session)])
    targets = tmp_path / "targets.txt"
    targets.write_text("quota.example.test\n", encoding="utf-8")
    for index in range(2):
        out = tmp_path / str(index)
        result = CliRunner().invoke(app, ["enrich", "batch", "--targets", str(targets), "--out", str(out),
            "--providers", "hunter", "--no-dry-run", "--no-resume", "--case-id", f"fixture-{index}"])
        assert result.exit_code == 0, result.output
        rows = [json.loads(line) for line in (out / "enrich.ndjson").read_text(encoding="utf-8").splitlines()]
        assert rows[0]["source_status"]["hunter"]["status"] == ("no_record" if index == 0 else "skipped")
    assert sum(url.endswith("/search") for url, _ in session.calls) == 1
    assert used() == 500
