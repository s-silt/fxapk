from apkscan.analyzers.json_endpoints import JsonEndpointAnalyzer
from apkscan.core.models import AnalysisConfig
from apkscan.core.webctx import WebContext


def test_escaped_json_url_retains_decoding_coordinate():
    ctx = WebContext(AnalysisConfig(online=False), files={
        "web/config.json": br'{"api":{"url":"https:\/\/api.example.test\/v1"},"other":"https:\u002f\u002fsecond.example.test"}'})
    result = JsonEndpointAnalyzer().analyze(ctx)
    assert {ep.value for ep in result.endpoints} >= {
        "https://api.example.test/v1", "https://second.example.test"}
    assert any("#/api/url (JSON-decoded)" in ev.location for ep in result.endpoints for ev in ep.evidences)
    assert result.meta["json_endpoint_coverage"]["decoded_url_literals"] == 2


def test_json_noncode_and_invalid_data_are_not_executed():
    ctx = WebContext(AnalysisConfig(online=False), files={
        "web/config.json": br'{"api":"https:\/\/api.example.test", "bad": NaN}'})
    result = JsonEndpointAnalyzer().analyze(ctx)
    assert not result.endpoints
    assert result.meta["json_endpoint_coverage"]["invalid_json"] == 1


def test_json_declared_size_budget(monkeypatch):
    import apkscan.analyzers.json_endpoints as module
    monkeypatch.setattr(module, "MAX_BYTES", 8)
    ctx = WebContext(AnalysisConfig(online=False), files={
        "web/config.json": br'{"api":"https:\/\/api.example.test"}'})
    result = JsonEndpointAnalyzer().analyze(ctx)
    assert result.meta["json_endpoint_coverage"]["over_limit"] == 1
    assert not result.endpoints
