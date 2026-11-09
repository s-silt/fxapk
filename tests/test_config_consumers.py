"""A+ consumers are bounded same-method candidates, never dataflow proof."""
from __future__ import annotations

import copy

import pytest

from apkscan.config import string_graph

SHA = "a" * 64
FIELDS = [{"path": "$.api.hosts[0]", "value": "api.example.test", "kind": "domain"}]
ARTIFACTS = [{"sha256": SHA, "decoded": True, "fields": FIELDS}]


@pytest.mark.parametrize("sink", ["HttpUrl.parse(v)", "b.baseUrl(v)", "new Retrofit.Builder()", "c.newWebSocket(v,l)", "new Socket(v,443)", "c.connect(v)", "web.loadUrl(v)", "new URL(v)"])
def test_same_method_candidate_only(sink):
    sources = {"app/Config.java": f'class Config {{ void run() {{ String v = j.getString("hosts"); {sink}; }} }}'}
    before = copy.deepcopy(ARTIFACTS)
    result = string_graph.bind_config_consumers(ARTIFACTS, sources)
    assert ARTIFACTS == before
    assert result[0]["artifact_sha256"] == SHA
    assert result[0]["field_path"] == "$.api.hosts[0]"
    candidate = result[0]["candidates"][0]
    assert candidate["status"] == "consumer_candidate"
    assert candidate["binding"] == "heuristic_same_method"
    assert candidate["method"] == "run"
    assert candidate["key"] == "hosts"
    assert candidate["source_path"] == "app/Config.java"
    assert candidate["source_sha256"] and candidate["sinks"]
    assert result[0]["gaps"] == []


@pytest.mark.parametrize("body", [
    'void key(){j.getString("hosts");} void sink(){new URL(v);}',
    'void run(){ /* "hosts" */ new URL(v);}',
    'void run(){j.getString("hosts"); String example="new URL(v)";}',
    'void run(){j.getString("hosts"); /* new URL(v) */}',
    'void run(){j.getString("hosts"); new Task(){void inner(){new URL(v);}};}',
    'void run(){String v="hostsSuffix";new URL(v);}',
    'void run(){class Local {String key="hosts";} new URL(v);}',
    'void run(){new Task(){String key="hosts";}; new URL(v);}',
])
def test_no_cross_method_comment_or_string_sink(body):
    result = string_graph.bind_config_consumers(ARTIFACTS, {"app/Config.java": "class Config {" + body + "}"})
    assert result[0]["candidates"] == []


def test_absent_sources_have_explicit_gap():
    result = string_graph.bind_config_consumers(ARTIFACTS, None)
    assert result[0]["candidates"] == []
    assert result[0]["gaps"] == ["consumer_unbound_no_jadx"]


def test_quoted_jsonpath_key_and_deterministic_order():
    artifacts = [{"sha256": SHA, "decoded": True, "fields": [
        {"path": '$["api-key"][0]', "value": "api.example.test", "kind": "domain"},
        {"path": "$text[0]", "value": "backup.example.test", "kind": "domain"},
    ]}]
    sources = {name: 'class Config {void run(){j.getString("api-key");new URL(v);}}' for name in ("b.java", "a.java")}
    result = string_graph.bind_config_consumers(artifacts, sources)
    assert result == string_graph.bind_config_consumers(artifacts, dict(reversed(list(sources.items()))))
    structured = next(r for r in result if r["field_path"].startswith('$["'))
    assert [c["source_path"] for c in structured["candidates"]] == ["a.java", "b.java"]
    fallback = next(r for r in result if r["field_path"].startswith("$text"))
    assert fallback["candidates"] == []
    assert "consumer_unbound_field_path" in fallback["gaps"]


def test_budget_gap_is_not_a_negative_result(monkeypatch):
    monkeypatch.setattr(string_graph, "_MAX_TEXT_BYTES", 16)
    result = string_graph.bind_config_consumers(ARTIFACTS, {"a.java": 'class Config {void run(){j.getString("hosts");new URL(v);}}'})
    assert "consumer_scan_partial" in result[0]["gaps"]


def test_pipeline_uses_verified_snapshot_and_projection_survives_refresh(tmp_path):
    import json
    from types import SimpleNamespace
    from apkscan.core import pipeline
    from apkscan.core.jadx_sources import capture_sources
    from apkscan.core.models import AnalysisConfig, Endpoint
    from apkscan.config.chain import build_control_chains
    from apkscan.report.digest import build_digest

    cache, source = tmp_path / "cache", tmp_path / "source"
    (cache / SHA).mkdir(parents=True)
    (cache / SHA / "manifest.json").write_text("{}", encoding="utf-8")
    source.mkdir()
    (source / "Config.java").write_text('class C {void run(){j.getString("hosts");new URL(v);}}', encoding="utf-8")
    receipt = capture_sources(cache, SHA, source, coverage="complete")
    artifacts = [{**ARTIFACTS[0], "source_url": "https://cfg.example.test/config", "domains": ["api.example.test"]}]
    state = pipeline._PipelineState(ctx=SimpleNamespace(jadx_cache_root=str(cache)), config=AnalysisConfig(), platform="android", capabilities=set(),
                                    meta={"remote_config_artifacts": artifacts, "jadx_index_key": SHA, "jadx_query_sources": receipt},
                                    endpoints=[Endpoint(value="api.example.test", kind="domain")])
    before = json.dumps(artifacts, sort_keys=True)
    pipeline._stage_control_chain(state)
    assert json.dumps(artifacts, sort_keys=True) == before
    backend = state.meta["control_chains"][0]["backends"][0]
    assert backend["consumer_candidates"][0]["method"] == "run"
    assert backend["consumer_gaps"] == []
    assert build_control_chains(artifacts, None, state.endpoints) == state.meta["control_chains"]
    digest = build_digest({"meta": state.meta})["control_chains"][0]["backends"][0]
    assert digest["consumer_candidates"][0]["binding"] == "heuristic_same_method"
    # Corruption must clear old derived candidates rather than silently reuse them.
    (cache / receipt["locator"]).write_bytes(b"invalid")
    pipeline._stage_control_chain(state)
    backend = state.meta["control_chains"][0]["backends"][0]
    assert backend["consumer_candidates"] == []
    assert "consumer_source_invalid" in backend["consumer_gaps"]


def test_malformed_jsonpath_is_not_a_binding():
    arts = [{"sha256": SHA, "decoded": True, "fields": [{"path": '$["\\q"]', "value": "api.example.test"}]}]
    assert string_graph.bind_config_consumers(arts, None)[0]["candidates"] == []
