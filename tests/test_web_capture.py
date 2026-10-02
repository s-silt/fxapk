"""Controlled HTTP doubles; not a live target smoke test."""
from io import BytesIO

import pytest

from apkscan.core import web_capture
from apkscan.analyzers.web_har import WebHarAnalyzer
from apkscan.core.models import AnalysisConfig
from apkscan.core.webctx import WebContext
import json


class Raw(BytesIO):
    def read1(self, size, decode_content=True):
        return self.read(size)


class Response:
    def __init__(self, body=b"synthetic", status=200, headers=None):
        self.raw, self.status_code = Raw(body), status
        self.headers = headers or {}
        self.closed = False

    def close(self):
        self.closed = True


class Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []
        self.cookies = self
        self.closed = False

    def clear(self):
        pass

    def get(self, url, **kw):
        self.calls.append((url, kw))
        return next(self.responses)

    def close(self):
        self.closed = True


def setup(monkeypatch, responses):
    session = Session(responses)
    monkeypatch.setattr(web_capture, "_new_session", lambda: session)
    monkeypatch.setattr(web_capture, "_target_is_safe", lambda url: (True, ""))
    return session


def test_capture_requires_explicit_authorization(monkeypatch):
    monkeypatch.setattr(web_capture, "_new_session", lambda: pytest.fail("must not create a session"))
    result = web_capture.capture_http("https://example.test")
    assert result["_capture"]["status"] == "not_authorized"
    assert result["_capture"]["network_requests"] == 0


def test_redirect_chain_capture_and_har_import(monkeypatch):
    responses = [Response(status=302, headers={"Location": "/next"}),
                 Response(b'<html>https://api.example.test/v1</html>', headers={"Content-Type": "text/html"})]
    session = setup(monkeypatch, responses)
    result = web_capture.capture_http("https://example.test", authorized=True)
    assert result["_capture"]["status"] == "captured_http"
    assert len(result["log"]["entries"]) == 2
    assert all(kw["allow_redirects"] is False and "verify" not in kw for _, kw in session.calls)
    assert session.closed and all(response.closed for response in responses)
    parsed = WebHarAnalyzer().analyze(WebContext(AnalysisConfig(online=False), files={
        "web/capture.har": json.dumps(result).encode()}))
    assert any(ep.value == "https://api.example.test/v1" for ep in parsed.endpoints)


def test_cross_host_redirect_waits_for_explicit_scope(monkeypatch):
    session = setup(monkeypatch, [Response(status=302, headers={"Location": "https://other.example.test/"})])
    result = web_capture.capture_http("https://example.test", authorized=True)
    assert len(session.calls) == 1
    assert "redirect_host_not_authorized" in result["_capture"]["gaps"]


def test_dns_rejection_never_sends_http(monkeypatch):
    session = setup(monkeypatch, [])
    monkeypatch.setattr(web_capture, "_target_is_safe", lambda url: (False, "private"))
    result = web_capture.capture_http("https://example.test", authorized=True)
    assert not session.calls and result["_capture"]["network_requests"] == 0


def test_body_budget_and_partial_export_survive_import(monkeypatch):
    setup(monkeypatch, [Response(b"x" * 20)])
    result = web_capture.capture_http("https://example.test", authorized=True, max_bytes=5)
    assert result["_capture"]["status"] == "partial"
    assert result["log"]["entries"][0]["_body_truncated"] is True
    parsed = WebHarAnalyzer().analyze(WebContext(AnalysisConfig(online=False), files={
        "web/capture.har": json.dumps(result).encode()}))
    assert parsed.meta["web_har_content_truncated"] == 1


def test_underlying_pinned_transport_rejects_private_or_unknown():
    from apkscan.core.origin_check import _public_ip
    for value in ("127.0.0.1", "169.254.169.254", "not-an-ip"):
        with pytest.raises(ValueError):
            _public_ip(value)


def test_real_session_disables_environment_credentials():
    session = web_capture._new_session()
    try:
        assert session.trust_env is False
        assert session.connections == []
    finally:
        session.close()


def test_cli_capture_to_analysis_package_and_pre_report(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from apkscan.cli import app
    from apkscan.core import pipeline
    from apkscan.core.case_package import create_case_package
    from apkscan.core.phase2.preparation import prepare_case_materials
    evidence = tmp_path / "web"
    evidence.mkdir()
    package = tmp_path / "case" / "sample"
    setup(monkeypatch, [Response(b'<html><script>var api="https://api.example.test/v1";</script></html>',
                                headers={"Content-Type": "text/html"})])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())
    runner = CliRunner()
    captured = runner.invoke(app, ["capture-web", "https://example.test", "--authorized",
                                   "--out", str(evidence / "capture.har")])
    assert captured.exit_code == 0, captured.output
    analyzed = runner.invoke(app, ["analyze-web", str(evidence), "--offline",
                                   "--fmt", "json", "--out", str(package)])
    assert analyzed.exit_code == 0, analyzed.output
    reports = [p for p in package.glob("*.json") if p.name != "case-package.json"]
    assert len(reports) == 1
    payload = json.loads(reports[0].read_text(encoding="utf-8"))
    assert payload["meta"]["web_har_summary"]["processed_entries"] == 1
    assert any(ep["value"] == "api.example.test" for ep in payload["endpoints"])
    create_case_package(reports[0], package / "case-package.json", case_id="CASE-WEB-SYNTHETIC", producer="synthetic-web-test")
    materials = prepare_case_materials(tmp_path / "case")
    assert materials["state"] == "review_required"
    assert materials["packages"][0]["stage_observations"]["web"]["material_present"]
    assert not materials["formal_report_generated"]


def test_interrupted_body_preserves_received_prefix(monkeypatch):
    class InterruptedRaw:
        version = 11
        calls = 0
        def read1(self, size, decode_content=True):
            self.calls += 1
            if self.calls == 1:
                return b"prefix"
            raise TimeoutError("private error payload must not be retained")
    response = Response()
    response.raw = InterruptedRaw()
    setup(monkeypatch, [response])
    result = web_capture.capture_http("https://example.test", authorized=True)
    import base64
    row = result["log"]["entries"][0]
    assert base64.b64decode(row["response"]["content"]["text"]) == b"prefix"
    assert row["_body_truncated"] is True
    assert "private error payload" not in json.dumps(result)
    assert result["_capture"]["gaps"] == ["read_failed:TimeoutError"]
