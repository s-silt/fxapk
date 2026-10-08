"""Synthetic HAR body semantics retain provenance without changing evidence inventory."""
from __future__ import annotations

import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from apkscan.analyzers.web_evidence import (
    WebInlineConfigAnalyzer,
    WebRedirectChainAnalyzer,
    WebRequestRecipeAnalyzer,
)
from apkscan.analyzers.web_har import WebHarAnalyzer
from apkscan.core.models import AnalysisConfig
from apkscan.core.webctx import WebContext

BODY = (
    '<html><script>window.api="https://config.example.test/v1";'
    'location.assign("https://hop.example.test/landing");'
    'fetch("/x", {headers: atob("WC1TeW50aGV0aWMtSGVhZGVy")});'
    '</script></html>'
)
ANALYZERS = (WebInlineConfigAnalyzer, WebRedirectChainAnalyzer, WebRequestRecipeAnalyzer)


def make_context(*, body=BODY, encoding=None, truncated=False, content_encoding=None):
    content = {"text": body}
    if encoding:
        content["encoding"] = encoding
    item = {"startedDateTime": "2026-01-01T00:00:00Z",
            "request": {"url": "https://page.example.test/start", "method": "GET"},
            "response": {"status": 200, "content": content}}
    if truncated:
        item["_body_truncated"] = True
    if content_encoding:
        item["_body_content_encoding"] = content_encoding
    raw = json.dumps({"log": {"entries": [item]}}).encode()
    return WebContext(AnalysisConfig(online=False), files={"web/synthetic.har": raw})


@pytest.mark.parametrize("analyzer", ANALYZERS)
@pytest.mark.parametrize("encoding", [None, "base64"])
def test_har_only_body_is_visible_to_each_semantic_analyzer(analyzer, encoding):
    body = base64.b64encode(BODY.encode()).decode() if encoding else BODY
    ctx = make_context(body=body, encoding=encoding)
    result = analyzer().analyze(ctx)
    if analyzer is WebInlineConfigAnalyzer:
        assert result.meta.get("web_inline_config_count") == 1
        assert any(ep.value == "https://config.example.test/v1" for ep in result.endpoints)
    elif analyzer is WebRedirectChainAnalyzer:
        chains = result.meta.get("web_redirect_chain", [])
        assert len(chains) == 1
        assert chains[0]["hops"][0]["target"] == "https://hop.example.test/landing"
    else:
        recipes = result.meta.get("web_request_recipe", [])
        assert [r["decoded"] for r in recipes] == ["X-Synthetic-Header"]
    assert all(ev.source == "web" and ev.observed_at is None
               for ep in result.endpoints for ev in ep.evidences)
    assert ctx.list_files() == ["web/synthetic.har"]


def test_body_provenance_binds_source_entry_and_exact_decoded_bytes():
    ctx = make_context(truncated=True)
    row = WebHarAnalyzer().analyze(ctx).meta["web_har_records"][0]
    assert row.get("source_file") == "web/synthetic.har"
    assert row.get("source_sha256") == hashlib.sha256(ctx.read_file("web/synthetic.har")).hexdigest()
    assert row.get("body_location") == "web/synthetic.har#/log/entries/0/response/content.body.html"
    assert row["body_sha256"] == hashlib.sha256(BODY.encode()).hexdigest()
    assert row.get("body_truncated") is True
    assert row["body_state"] == "captured_truncated"
    for analyzer in ANALYZERS:
        result = analyzer().analyze(ctx)
        assert result.meta.get(analyzer.name + "_content_truncated") is True


@pytest.mark.parametrize("analyzer", ANALYZERS)
def test_body_budget_omission_is_visible_to_semantic_coverage(analyzer, monkeypatch):
    import apkscan.analyzers.web_har as har
    monkeypatch.setattr(har, "MAX_BODY_BYTES", 4)
    result = analyzer().analyze(make_context())
    assert result.meta.get(analyzer.name + "_content_truncated") is True
    assert not result.endpoints and not result.findings and not result.leads


def test_semantic_results_are_independent_of_har_analyzer_order_and_threads():
    ctx = make_context()
    raw = ctx.read_file("web/synthetic.har")
    serial = [analyzer().analyze(ctx) for analyzer in ANALYZERS]
    WebHarAnalyzer().analyze(ctx)
    with ThreadPoolExecutor(max_workers=3) as pool:
        concurrent = list(pool.map(lambda analyzer: analyzer().analyze(ctx), ANALYZERS))
    assert concurrent == serial
    assert ctx.list_files() == ["web/synthetic.har"]
    assert ctx.read_file("web/synthetic.har") == raw
    assert serial[0].meta.get("web_inline_config_count") == 1


@pytest.mark.parametrize("body,encoding,content_encoding", [
    ("%%%", "base64", None),
    (base64.b64encode(b"\x89PNG\r\n\x1a\n").decode(), "base64", None),
    (BODY, None, "gzip"),
])
def test_unusable_bodies_do_not_enter_semantic_analysis(body, encoding, content_encoding):
    ctx = make_context(body=body, encoding=encoding, content_encoding=content_encoding)
    for analyzer in ANALYZERS:
        result = analyzer().analyze(ctx)
        assert not result.endpoints and not result.findings and not result.leads


def test_public_body_inputs_are_immutable_and_do_not_change_fingerprint(monkeypatch):
    from dataclasses import FrozenInstanceError
    from apkscan.analyzers.web_har import decode_har_evidence
    from apkscan.core import integrity
    from apkscan.core.webctx import WebBodyInput

    monkeypatch.setattr(integrity, "_build_provenance", lambda: {})
    ctx = make_context(truncated=True)
    original = {path: ctx.read_file(path) for path in ctx.list_files()}
    before = integrity.web_evidence_fingerprint(original, tool_version="synthetic")
    har, bodies = decode_har_evidence(ctx)
    assert isinstance(bodies, tuple) and len(bodies) == 1
    body = bodies[0]
    assert isinstance(body, WebBodyInput)
    row = har.meta["web_har_records"][0]
    assert (body.location, body.entry_ref, body.source_file, body.source_sha256,
            body.body_sha256, body.body_truncated) == (
        row["body_location"], row["entry_ref"], row["source_file"], row["source_sha256"],
        row["body_sha256"], row["body_truncated"],
    )
    assert body.data == BODY.encode()
    with pytest.raises(FrozenInstanceError):
        body.location = "changed"
    after = integrity.web_evidence_fingerprint(
        {path: ctx.read_file(path) for path in ctx.list_files()}, tool_version="synthetic",
    )
    assert after["sha256"] == before["sha256"]
    assert after["files"] == before["files"]


def test_bom_normalization_keeps_decoded_body_and_analysis_hashes_distinct():
    from apkscan.analyzers.web_har import decode_har_evidence

    raw = BODY.encode("utf-16")
    ctx = make_context(body=base64.b64encode(raw).decode(), encoding="base64")
    har, bodies = decode_har_evidence(ctx)
    assert bodies[0].data == BODY.encode()
    row = har.meta["web_har_records"][0]
    assert row["body_sha256"] == hashlib.sha256(raw).hexdigest()
    assert row["body_text_sha256"] == hashlib.sha256(BODY.encode()).hexdigest()
    assert WebInlineConfigAnalyzer().analyze(ctx).meta["web_inline_config_count"] == 1


def test_explicit_javascript_mime_uses_existing_script_semantics():
    from apkscan.analyzers.web_har import decode_har_evidence

    ctx = make_context(body=BODY.removeprefix("<html><script>").removesuffix("</script></html>"))
    payload = json.loads(ctx.read_file("web/synthetic.har"))
    payload["log"]["entries"][0]["response"]["content"]["mimeType"] = "text/javascript; charset=utf-8"
    ctx = WebContext(ctx.config, files={"web/synthetic.har": json.dumps(payload).encode()})
    _, bodies = decode_har_evidence(ctx)
    assert bodies[0].location.endswith(".body.js")
    assert WebRedirectChainAnalyzer().analyze(ctx).meta["web_redirect_chain"]
    assert WebRequestRecipeAnalyzer().analyze(ctx).meta["web_request_recipe"]
    assert not WebInlineConfigAnalyzer().analyze(ctx).leads


def test_real_pipeline_keeps_semantic_signals_and_har_provenance(monkeypatch):
    from apkscan.core import pipeline

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [
        analyzer() for analyzer in (*ANALYZERS, WebHarAnalyzer)
    ])
    monkeypatch.setenv("FXAPK_NO_PARALLEL", "1")
    report = pipeline.run(make_context(truncated=True), AnalysisConfig(online=False))
    assert report.meta["web_inline_config_count"] == 1
    assert report.meta["web_redirect_chain"][0]["hops"][0]["target"] == "https://hop.example.test/landing"
    assert report.meta["web_request_recipe"][0]["decoded"] == "X-Synthetic-Header"
    assert report.meta["web_har_records"][0]["source_file"] == "web/synthetic.har"
    assert all(row["status"] == "ran" for row in report.analyzer_status)
    assert all(ev.source == "web" for ep in report.endpoints for ev in ep.evidences)
    assert all(report.meta[analyzer.name + "_content_truncated"] for analyzer in ANALYZERS)
