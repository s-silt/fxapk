from __future__ import annotations

import hashlib
import json

import pytest

from apkscan.analyzers.web_evidence import WebInlineConfigAnalyzer
from apkscan.analyzers.web_har import WebHarAnalyzer
from apkscan.core.admission import evaluate_evidence
from apkscan.core.models import AnalysisConfig, Evidence
from apkscan.core.observations import occurrence_id
from apkscan.core.web_handoff import SCHEMA, bind_evidence, bind_result, load_handoff
from apkscan.core.webctx import WebContext, load_web_evidence


def fixture(tmp_path, raw=b'<script>var api="https://api.example.test/v1";</script>'):
    root = tmp_path / "input"
    root.mkdir()
    (root / "page.body").write_bytes(raw)
    data = {
        "schema_version": SCHEMA,
        "files": [{"path": "page.body", "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
                   "source": {"archive_sha256": "a" * 64, "observation_sequence": 7},
                   "capture": {"complete": False, "request_association": "known",
                               "tls_verification": "ignored"}}],
        "coverage": {"status": "partial", "attachments": {"included_in_web_analysis": False}},
    }
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps(data))
    return root, path, data


def test_binding_uses_raw_hash_but_offsets_remain_in_decoded_representation(tmp_path):
    raw = '<script>var api="https://api.example.test/v1";</script>'.encode("utf-16")
    root, path, _ = fixture(tmp_path, raw)
    ctx = load_web_evidence(root, AnalysisConfig(online=False))
    load_handoff(path, ctx)
    result = WebInlineConfigAnalyzer().analyze(ctx)
    evidence = result.endpoints[0].evidences[0]
    bind_evidence(ctx, evidence)
    assert evidence.provenance["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert evidence.provenance["representation_changed"] is True
    assert evidence.provenance["capture_handoff"]["source"]["observation_sequence"] == 7
    assert evidence.locator == {"char_offset": 8, "offset_unit": "decoded-text-codepoint"}
    assert occurrence_id(evidence)
    assert {row["kind"] for row in evidence.suspicions} == {"capture_truncated", "capture_tls_unverified"}
    assert evaluate_evidence(evidence, "closure_candidate").state == "review"
    assert ctx.handoff_receipt["authenticity_verified"] is False


@pytest.mark.parametrize("change", [
    "hash", "size", "duplicate", "traversal", "unlisted", "capture", "tls", "pointer", "version",
])
def test_invalid_handoff_fails_closed(tmp_path, change):
    root, path, data = fixture(tmp_path)
    row = data["files"][0]
    if change == "hash":
        row["sha256"] = "b" * 64
    elif change == "size":
        row["size"] += 1
    elif change == "duplicate":
        data["files"].append(dict(row))
    elif change == "traversal":
        row["path"] = "../page.body"
    elif change == "unlisted":
        data["files"] = []
    elif change == "capture":
        row["capture"]["complete"] = 1
    elif change == "tls":
        row["capture"]["tls_verification"] = []
    elif change == "pointer":
        row["entries"] = [{"pointer": "/log/entries/0x", "source": {}, "capture": {}}]
    elif change == "version":
        data["schema_version"] = "unsupported"
    path.write_text(json.dumps(data))
    ctx = load_web_evidence(root, AnalysisConfig(online=False))
    with pytest.raises(ValueError):
        load_handoff(path, ctx)
    assert not ctx.handoff_receipt


def test_sidecar_inside_inputs_is_rejected(tmp_path):
    root, path, _ = fixture(tmp_path)
    inside = root / "handoff.json"
    inside.write_bytes(path.read_bytes())
    ctx = load_web_evidence(root, AnalysisConfig(online=False))
    with pytest.raises(ValueError, match="external"):
        load_handoff(inside, ctx)


def test_duplicate_json_keys_rejected(tmp_path):
    root, path, _ = fixture(tmp_path)
    path.write_text('{"files":[],"files":[]}')
    with pytest.raises(ValueError, match="duplicate"):
        load_handoff(path, load_web_evidence(root, AnalysisConfig(online=False)))


def test_repeated_inline_literals_keep_distinct_occurrences():
    text = b'<script>var api="https://api.example.test/v1";</script>' * 2
    ctx = WebContext(AnalysisConfig(online=False), {"web/page.html": text})
    result = WebInlineConfigAnalyzer().analyze(ctx)
    refs = result.endpoints[0].evidences
    assert len(refs) == 2
    assert len({occurrence_id(ref) for ref in refs}) == 2


def test_har_locators_are_json_pointers_not_runtime():
    entry = {"request": {"url": "https://entry.example.test/"},
             "response": {"status": 302, "redirectURL": "https://end.example.test/"}}
    raw = json.dumps({"log": {"entries": [entry, entry]}}).encode()
    ctx = WebContext(AnalysisConfig(online=False), {"web/observed.har": raw})
    result = WebHarAnalyzer().analyze(ctx)
    refs = [ref for ep in result.endpoints for ref in ep.evidences]
    assert refs and all(ref.locator.get("json_pointer") for ref in refs)
    assert all(ref.provenance["member_sha256"] == hashlib.sha256(raw).hexdigest() for ref in refs)
    assert all(ref.source == "web" for ref in refs)
    assert all(evaluate_evidence(ref, "corpus_relation").state == "review" for ref in refs)


def test_legacy_unlocated_reference_does_not_get_fabricated_coordinates(tmp_path):
    root, _, _ = fixture(tmp_path)
    ctx = load_web_evidence(root, AnalysisConfig(online=False))
    ref = Evidence(source="web", location=ctx.list_files()[0])
    bind_evidence(ctx, ref)
    assert ref.provenance["source_sha256"]
    assert occurrence_id(ref) is None


def test_truncated_har_body_is_not_a_complete_request_or_runtime_observation():
    entry = {"request": {"url": "https://entry.example.test/"}, "_body_truncated": True,
             "response": {"status": 200, "content": {
                 "text": '<script>var api="https://body.example.test/v1";</script>',
                 "mimeType": "text/html"}}}
    raw = json.dumps({"log": {"entries": [entry]}}).encode()
    ctx = WebContext(AnalysisConfig(online=False), {"web/capture.har": raw})
    for analyzer in (WebHarAnalyzer(), WebInlineConfigAnalyzer()):
        result = analyzer.analyze(ctx)
        bind_result(ctx, result)
        refs = [ref for ep in result.endpoints for ref in ep.evidences
                if "/response/content.body" in ref.location]
        assert refs
        for ref in refs:
            assert ref.provenance["member_sha256"] == hashlib.sha256(raw).hexdigest()
            assert ref.provenance["body_truncated"] is True
            assert ref.locator["offset_scope"] == "decoded-har-body"
            assert ref.locator["json_pointer"] == "/log/entries/0/response/content/text"
            assert {"kind": "capture_truncated"} in ref.suspicions
        requests = [ref for ep in result.endpoints for ref in ep.evidences if ref.location.endswith("/request/url")]
        assert all(not ref.suspicions for ref in requests)


def test_har_binding_does_not_borrow_another_entry_context(tmp_path):
    root = tmp_path / "input"
    root.mkdir()
    raw = json.dumps({"log": {"entries": [
        {"request": {"url": "https://shared.example.test/"}, "response": {}},
        {"request": {"url": "https://shared.example.test/"}, "response": {}},
    ]}}).encode()
    (root / "observed.har").write_bytes(raw)
    row = {"path": "observed.har", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
           "source": {}, "capture": {}, "entries": [
               {"pointer": f"/log/entries/{index}", "source": {"observation_sequences": [index + 1]},
                "capture": {"request_association": "known", "tls_verification": tls}}
               for index, tls in enumerate(("ignored", "verified"))]}
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps({"schema_version": SCHEMA, "files": [row], "coverage": {}}))
    ctx = load_web_evidence(root, AnalysisConfig(online=False))
    load_handoff(path, ctx)
    result = WebHarAnalyzer().analyze(ctx)
    bind_result(ctx, result)
    refs = [ref for ep in result.endpoints if ep.value == "https://shared.example.test/" for ref in ep.evidences]
    assert len(refs) == 2
    assert refs[0].suspicions == [{"kind": "capture_tls_unverified"}]
    assert not refs[1].suspicions
    assert refs[0].provenance["capture_handoff"]["entry"]["source"]["observation_sequences"] == [1]
    assert refs[1].provenance["capture_handoff"]["entry"]["source"]["observation_sequences"] == [2]


def test_unknown_request_and_rendered_dom_remain_review(tmp_path):
    root, path, data = fixture(tmp_path)
    data["files"][0]["capture"] = {"complete": True, "request_association": "unknown",
                                   "representation": "browser_rendered_dom", "tls_verification": "unknown"}
    path.write_text(json.dumps(data))
    ctx = load_web_evidence(root, AnalysisConfig(online=False))
    load_handoff(path, ctx)
    ref = WebInlineConfigAnalyzer().analyze(ctx).endpoints[0].evidences[0]
    bind_evidence(ctx, ref)
    assert {row["kind"] for row in ref.suspicions} == {
        "capture_request_association_unknown", "capture_rendered_dom",
    }
    assert evaluate_evidence(ref, "passive_enrichment").state == "review"
