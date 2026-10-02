"""HAR imports are offline evidence; no browser/target access or code execution."""
import base64
import json

from apkscan.analyzers.web_har import WebHarAnalyzer
from apkscan.core.models import AnalysisConfig
from apkscan.core.webctx import WebContext


def context(entries):
    return WebContext(AnalysisConfig(online=False), files={
        "web/synthetic.har": json.dumps({"log": {"version": "1.2", "entries": entries}}).encode()})


def entry(url="https://api.example.test/start", status=302, body=None):
    return {"startedDateTime": "2026-01-01T00:00:00Z",
            "request": {"url": url, "method": "GET"},
            "response": {"status": status, "redirectURL": "/next",
                         "content": {} if body is None else {"text": body}}}


def test_har_retains_request_response_redirect_and_body_endpoints():
    item = entry(body='<html><script>var api="https://body.example.test/v1";</script></html>')
    result = WebHarAnalyzer().analyze(context([item]))
    values = {ep.value for ep in result.endpoints}
    assert "https://api.example.test/start" in values
    assert "https://api.example.test/next" in values
    assert "https://body.example.test/v1" in values
    row = result.meta["web_har_records"][0]
    assert row["status"] == 302 and row["response_recorded"]
    assert row["body_state"] == "captured" and len(row["body_sha256"]) == 64
    assert row["target_app_attribution_verified"] is False
    assert all(ev.source == "web" for ep in result.endpoints for ev in ep.evidences)


def test_base64_body_and_failed_response_remain_distinct():
    item = entry(status=0)
    item["response"]["content"] = {
        "encoding": "base64", "text": base64.b64encode(b'https://body.example.test/v2').decode()}
    result = WebHarAnalyzer().analyze(context([item]))
    row = result.meta["web_har_records"][0]
    assert row["response_recorded"] is False
    assert "redirect_url" not in row
    assert result.meta["web_har_summary"]["gaps"]["response_not_recorded"] == 1
    assert any(ep.value == "https://body.example.test/v2" for ep in result.endpoints)


def test_har_missing_and_malformed_data_never_claims_complete():
    result = WebHarAnalyzer().analyze(WebContext(AnalysisConfig(online=False),
        files={"web/broken.har": b'{"log": {"entries": [NaN]}}'}))
    assert result.meta["web_har_summary"]["gaps"]["invalid_har_json"] == 1
    assert result.meta["web_har_summary"]["complete_export_verified"] is False
    assert not result.endpoints


def test_har_bounds_include_invalid_entries(monkeypatch):
    import apkscan.analyzers.web_har as module
    monkeypatch.setattr(module, "MAX_ENTRIES", 2)
    result = WebHarAnalyzer().analyze(context([None, None, entry()]))
    summary = result.meta["web_har_summary"]
    assert summary["examined_entries"] == 2 and summary["processed_entries"] == 0
    assert summary["gaps"]["entry_budget_exceeded"] == 1


def test_har_body_limit_is_explicit(monkeypatch):
    import apkscan.analyzers.web_har as module
    monkeypatch.setattr(module, "MAX_BODY_BYTES", 4)
    result = WebHarAnalyzer().analyze(context([entry(body="x" * 100)]))
    assert result.meta["web_har_records"][0]["body_state"] == "over_limit"
    assert result.meta["web_har_summary"]["gaps"]["body_budget_exceeded"] == 1


def test_truncated_har_coverage_survives_real_pipeline_contract(monkeypatch):
    from apkscan.core import pipeline
    import apkscan.analyzers.web_har as module
    monkeypatch.setattr(module,'MAX_BODY_BYTES',4)
    monkeypatch.setattr(pipeline,'discover_analyzers',lambda:[WebHarAnalyzer()])
    monkeypatch.setenv('FXAPK_NO_PARALLEL','1')
    result=pipeline.run(context([entry(body='SYNTHETIC BODY')]),AnalysisConfig(online=False))
    assert result.meta['web_har_items_truncated']==1
    assert result.analyzer_status[0]['status']=='ran'
