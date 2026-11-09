"""Stage A counterexamples: synthetic, offline provenance, never contact evidence."""
from __future__ import annotations

import base64
import copy
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from apkscan.config import decode, fetch
from apkscan.config.chain import build_control_chains
from apkscan.core import config_probe_run as probe, pipeline
from apkscan.core.appcrypto import CryptoRecipe
from apkscan.report.digest import build_digest

URL = "https://cfg.example.test/config"
HOST = "api.example.test"
BLOB = b'{"api":{"hosts":["api.example.test"]},"other-key":"api.example.test"}'


def produce(monkeypatch, blob=BLOB, *, declared=None, encoding=None, archive=None):
    fetched = fetch.FetchResult(URL, True, blob, 200, None, declared, encoding)
    monkeypatch.setattr(pipeline, "fetch_config_object", lambda url: fetched)
    sink = []
    art = pipeline._fetch_decode_one(URL, None, sink, archive)
    return art, sink


def test_fields_paths_and_original_endpoint_set():
    result = decode.decode_config_blob(BLOB)
    assert result.domains == (HOST,) and result.ips == ()
    assert result.fields == [
        {"path": "$.api.hosts[0]", "value": HOST, "kind": "domain"},
        {"path": '$["other-key"]', "value": HOST, "kind": "domain"},
    ]
    assert {f["value"] for f in result.fields} == set(result.domains) | set(result.ips)


def test_fields_filter_leaf_only_extra_values(monkeypatch):
    original = decode._extract_endpoints

    def extract(text):
        domains, ips = original(text)
        return (domains + ("extra.example.test",), ips) if text == HOST else (domains, ips)

    monkeypatch.setattr(decode, "_extract_endpoints", extract)
    result = decode.decode_config_blob(BLOB)
    assert result.domains == (HOST,) and result.ips == ()
    assert {f["value"] for f in result.fields} == {HOST}


@pytest.mark.parametrize("blob,offset", [
    (b'prefix HTTPS://API.EXAMPLE.TEST/path', 7),
    (b'{"api.example.test":42}', 2),
])
def test_unstructured_or_key_only_fallback(monkeypatch, blob, offset):
    result = decode.decode_config_blob(blob)
    assert result.fields == [{"path": f"$text[{offset}]", "value": HOST, "kind": "domain"}]
    art, _ = produce(monkeypatch, blob)
    assert "field_path_unavailable" in art["gaps"]


@pytest.mark.parametrize("iv", ["md5", "MD5(KEY+TS)", "md5(key+ts)[:16]", "fixed", "same_as_key", "none", "other"])
@pytest.mark.parametrize("ts", [None, 0, "123"])
def test_transform_order_timestamp_and_no_secrets(monkeypatch, iv, ts):
    recipe = CryptoRecipe(key="synthetic-key", iv_value="synthetic-iv", iv_derive=iv)
    monkeypatch.setattr(decode, "decrypt_envelope", lambda *args: BLOB.decode())
    result = decode.decode_config_blob(b"opaque-envelope", recipe=recipe, timestamp=ts)
    assert result.decode_chain == ("aes", "json")
    assert [t["step"] for t in result.transforms] == list(result.decode_chain)
    aes = result.transforms[0]
    assert aes["recipe_ref"] == "meta.crypto_recipe"
    assert aes["recipe_shape"] == {k: getattr(recipe, k) for k in (
        "algo", "mode", "padding", "key_encoding", "iv_derive")}
    expected = {} if not iv.lower().startswith("md5") else {
        "timestamp": {"value": 0 if ts is None else ts,
                      "source": "default_not_observed" if ts is None else "caller_supplied"}}
    assert aes["inputs"] == expected
    assert "synthetic-key" not in json.dumps(result.transforms)
    assert "synthetic-iv" not in json.dumps(result.transforms)
    assert result.transforms[-1] == {"step": "json", "inputs": {}}
    monkeypatch.setattr(pipeline, "fetch_config_object", lambda url: fetch.FetchResult(url, True, b"opaque-envelope", 200, None))
    art = pipeline._fetch_decode_one(URL, recipe, [], None)
    assert ("recipe_input_defaulted" in art["gaps"]) == iv.lower().startswith("md5")


def test_failed_decode_retains_transform_prefix(monkeypatch):
    blob = base64.b64encode(bytes(range(256)))
    result = decode.decode_config_blob(blob)
    assert not result.decoded
    assert result.fields == []
    assert [t["step"] for t in result.transforms] == list(result.decode_chain) == ["base64"]
    art, sink = produce(monkeypatch, blob)
    assert art["fields"] == [] and sink == []
    assert art["gaps"] == ["not_archived", "undecoded"]


@pytest.mark.parametrize("declared,encoding,complete", [
    (None, None, "unknown"), (None, "identity", "unknown"),
    (len(BLOB), None, True), (len(BLOB), "identity", True),
    (1, None, False), (1, "identity", False), (1, "gzip", "unknown"),
    (len(BLOB), "deflate", "unknown"), (1, " Identity ", False),
    (len(BLOB), "", "unknown"),
])
def test_material_completeness(monkeypatch, declared, encoding, complete):
    art, _ = produce(monkeypatch, declared=declared, encoding=encoding)
    assert art["material"] == {"complete": complete, "received_bytes": len(BLOB), "declared_length": declared}
    assert ("material_incomplete" in art["gaps"]) == (complete is False)


def test_two_producers_same_shape_and_provenance(monkeypatch, tmp_path):
    art, sink = produce(monkeypatch, declared=len(BLOB), archive=tmp_path / "remote_config")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fetch, "fetch_config_object", pipeline.fetch_config_object)
    probe_sink = []
    outcome = probe._fetch_one({"url": URL}, None, Path("remote_config"), probe_sink)
    record = outcome.to_dict()
    for key in ("fields", "transforms", "material", "gaps"):
        assert record[key] == art[key]
    assert asdict(probe_sink[0]) == asdict(sink[0])
    evidence = sink[0].evidences[0]
    assert evidence.location == f"remote-config:{URL}"
    assert evidence.provenance == {"artifact_sha256": art["sha256"], "field_paths": ["$.api.hosts[0]", '$["other-key"]']}
    assert evidence.locator == {"stored_path": art["stored_path"]}
    from apkscan.cli import _merge_config_probe_into_report
    path = tmp_path / "report.json"
    path.write_text('{"schema_version":"1.3"}', encoding="utf-8")
    _merge_config_probe_into_report(str(path), probe.ProbeRunResult([outcome], probe_sink))
    assert json.loads(path.read_text(encoding="utf-8"))["meta"]["remote_config_artifacts"] == [art]


@pytest.mark.parametrize("stored", [None, "/absolute/config.bin", "C:/absolute/config.bin", "C:\\absolute\\config.bin"])
def test_unlocated_paths_do_not_gain_occurrence(monkeypatch, stored):
    from apkscan.core.observations import occurrence_id
    monkeypatch.setattr(probe, "archive_blob", lambda *args: stored)
    monkeypatch.setattr(fetch, "fetch_config_object", lambda url: fetch.FetchResult(url, True, BLOB, 200, None))
    sink = []
    probe._fetch_one({"url": URL}, None, None, sink)
    assert sink[0].evidences[0].provenance["artifact_sha256"]
    assert sink[0].evidences[0].locator == {}
    assert occurrence_id(sink[0].evidences[0]) is None


def test_admission_states_unchanged_and_report_roundtrip(monkeypatch, tmp_path):
    from apkscan.core.admission import PURPOSES, evaluate_usage
    from apkscan.core.report_io import report_from_dict
    from apkscan.report.json import _to_jsonable
    _, sink = produce(monkeypatch, archive=tmp_path / "remote_config")
    before = probe.config_endpoint(HOST, "domain", URL).evidences
    after = sink[0].evidences
    for purpose in sorted(PURPOSES):
        old, new = evaluate_usage(before, purpose), evaluate_usage(after, purpose)
        assert old["state"] == new["state"]
        if purpose == "corpus_relation":
            assert new["state"] == "review" and new["reason_codes"] == ["relation_support_unknown"]
        else:
            assert old["unlocated_allowed_count"] == 1 and new["unlocated_allowed_count"] == 0
            assert len(new["supporting_occurrence_ids"]) == 1
    assert all(getattr(after[0], k) == "unknown" for k in ("structure_status", "reference_status", "reachability"))
    serialized = _to_jsonable(sink[0])
    restored = report_from_dict({"schema_version": "1.3", "endpoints": [serialized]})
    assert _to_jsonable(restored.endpoints[0]) == serialized


def test_cli_appends_evidence_without_touching_existing_leads(tmp_path):
    from apkscan.cli import _merge_config_probe_into_report
    from apkscan.report.json import _to_jsonable
    path = tmp_path / "report.json"
    old = probe.config_endpoint(HOST, "domain", URL)
    leads = [{"category": "domain", "value": HOST, "notes": ["preserve"], "advice": "待核"}]
    path.write_text(json.dumps({"schema_version": "1.3", "endpoints": [_to_jsonable(old)], "leads": leads}), encoding="utf-8")
    x = probe.config_endpoint(HOST, "domain", URL, provenance={"artifact_sha256": "a" * 64, "field_paths": ["$.x"]})
    y1 = probe.config_endpoint("new.example.test", "domain", URL)
    y2 = probe.config_endpoint("new.example.test", "domain", URL + "2")
    result = probe.ProbeRunResult(endpoints=[x, y1, y2, x])
    assert _merge_config_probe_into_report(str(path), result) == (1, 1)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert len(payload["endpoints"]) == 2
    assert [len(e["evidences"]) for e in payload["endpoints"]] == [2, 2]
    assert payload["leads"][0] == leads[0]
    assert len(payload["leads"][1]["source_refs"]) == 2
    assert _merge_config_probe_into_report(str(path), result) == (0, 0)
    x.evidences[0].provenance = {"field_paths": ["$.x"], "artifact_sha256": "a" * 64}
    _merge_config_probe_into_report(str(path), result)
    assert len(json.loads(path.read_text(encoding="utf-8"))["endpoints"][0]["evidences"]) == 2
    x.evidences[0].provenance["artifact_sha256"] = "b" * 64
    _merge_config_probe_into_report(str(path), result)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert len(payload["endpoints"][0]["evidences"]) == 3
    assert payload["leads"][0] == leads[0] and len(payload["leads"]) == 2


def test_old_report_projection_only_adds_view_gaps():
    arts = [{"source_url": URL, "decoded": True, "domains": [HOST]}, {"source_url": URL + "2", "decoded": False, "error": "failed"}]
    before = copy.deepcopy(arts)
    chains = build_control_chains(arts, None, [])
    assert arts == before
    assert chains[0]["artifact_sha256"] is None
    assert chains[0]["material"] == {"complete": "unknown"}
    assert chains[0]["gaps"] == ["field_path_unavailable"]
    assert chains[0]["transforms"] == []
    assert chains[0]["backends"][0]["field_paths"] == []
    assert chains[1]["gaps"] == []
    assert probe.ProbeOutcome(URL, "hit").to_dict()["material"] == {"complete": "unknown"}


def test_two_artifacts_converge_and_digest_redaction(monkeypatch):
    a, ea = produce(monkeypatch)
    b, eb = produce(monkeypatch, BLOB + b" ")
    secret_url = "https://user:password@cfg.example.test/config?token=synthetic-secret#private"
    a["source_url"] = secret_url
    b["source_url"] = URL + "2"
    # Pipeline's existing dedup remains unchanged; distinct locations retain both.
    eb[0].evidences[0].location += "2"
    merged = pipeline._dedup_endpoints(ea + eb)
    assert len(merged) == 1 and len(merged[0].evidences) == 2
    chains = build_control_chains([a, b], None, merged)
    assert len(chains) == 2
    assert chains[0]["artifact_sha256"] != chains[1]["artifact_sha256"]
    for chain, art in zip(chains, [a, b], strict=True):
        assert chain["material"] == art["material"] and chain["gaps"] == art["gaps"]
        assert chain["transforms"] == art["transforms"]
        assert chain["backends"][0]["field_paths"] == ["$.api.hosts[0]", '$["other-key"]']
    report = {"meta": {"control_chains": chains}}
    safe = build_digest(report)["control_chains"]
    raw = build_digest(report, redact=False)["control_chains"]
    assert safe[0]["source_url"] == "https://cfg.example.test/config?***#***"
    assert "synthetic-secret" not in json.dumps(safe) and "password" not in json.dumps(safe)
    assert raw[0]["source_url"] == secret_url
    for projection in (safe, raw):
        assert projection[0]["artifact_sha256"] == a["sha256"]
        assert projection[0]["transforms"] == [{"step": "json"}]
        assert projection[0]["material"] == {"complete": "unknown"}
        assert projection[0]["gaps"] == ["not_archived"]
        assert "fields" not in projection[0]
        assert projection[0]["backends"][0]["field_paths"] == ["$.api.hosts[0]", '$["other-key"]']


def test_reserved_ip_fields_preserve_original_extraction(monkeypatch):
    monkeypatch.setattr(decode.textutil, "ip_is_private", lambda ip: False)
    monkeypatch.setattr(decode.textutil, "is_noise_bare_ip", lambda ip: False)
    blob = b'{"ip":["192.0.2.4","198.51.100.7"],"api":"api.example.test"}'
    result = decode.decode_config_blob(blob)
    assert result.ips == ("192.0.2.4", "198.51.100.7")
    assert {f["value"] for f in result.fields} == set(result.domains) | set(result.ips)
    assert [f for f in result.fields if f["kind"] == "ip"] == [
        {"path": "$.ip[0]", "value": "192.0.2.4", "kind": "ip"},
        {"path": "$.ip[1]", "value": "198.51.100.7", "kind": "ip"},
    ]


@pytest.mark.parametrize("declared,expected", [("69", 69), (None, None), ("invalid", None)])
def test_fetch_copies_response_metadata_without_changing_bytes(monkeypatch, declared, expected):
    from types import SimpleNamespace
    response = SimpleNamespace(status_code=200, headers={"Content-Length": declared, "Content-Encoding": "gzip"},
                               iter_content=lambda size: iter([BLOB]), close=lambda: None)
    monkeypatch.setattr(fetch, "_target_is_safe", lambda url: (True, ""))
    monkeypatch.setattr(fetch, "_build_guarded_session", lambda: SimpleNamespace(get=lambda *a, **k: response, close=lambda: None))
    fetched = fetch.fetch_config_object(URL)
    assert fetched.ok and fetched.raw == BLOB
    assert fetched.declared_length == expected and fetched.content_encoding == "gzip"


def test_download_failure_variant_and_probe_exception(monkeypatch):
    monkeypatch.setattr(pipeline, "fetch_config_object", lambda url: fetch.FetchResult(url, False, None, 400, "failed"))
    assert pipeline._fetch_decode_one(URL, None, [], None) == {"source_url": URL, "decoded": False, "error": "failed"}
    monkeypatch.setattr(fetch, "fetch_config_object", lambda url: fetch.FetchResult(url, True, BLOB, 200, None))
    def broken(*args, **kwargs):
        raise ValueError("synthetic decode error")
    monkeypatch.setattr(decode, "decode_config_blob", broken)
    outcome = probe._fetch_one({"url": URL}, None, None, [])
    assert outcome.status == "undecoded"
    assert outcome.to_dict()["gaps"] == ["not_archived", "undecoded"]
    assert outcome.material["complete"] == "unknown"
    assert probe.ProbeOutcome(URL, "planned").to_dict() == {"url": URL, "status": "planned"}
    assert probe.ProbeOutcome(URL, "failed", error="failed").to_dict() == {"url": URL, "status": "failed", "error": "failed"}


def _determinism_snapshot():
    """Real AES + gzip/base64/text, with both fetch entry points stubbed in the child."""
    import gzip
    import hashlib
    import socket
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    recipe = CryptoRecipe(key="0123456789abcdef", padding="None")
    iv = hashlib.md5((recipe.key + "0").encode()).hexdigest()[:16].encode()
    enc = Cipher(algorithms.AES(recipe.key.encode()), modes.CFB(iv)).encryptor()
    ciphertext = base64.b64encode(enc.update(BLOB) + enc.finalize())
    blobs = [BLOB, base64.b64encode(gzip.compress(BLOB, mtime=0)), b"api.example.test\nbackup.example.test", ciphertext]
    with pytest.MonkeyPatch.context() as patch:
        def forbidden(*args, **kwargs):
            raise AssertionError("network is forbidden")
        patch.setattr(socket, "getaddrinfo", forbidden)
        patch.setattr(socket.socket, "connect", forbidden)
        patch.setattr(socket.socket, "sendto", forbidden)
        endpoints, artifacts, decoded = [], [], []
        for i, blob in enumerate(blobs):
            url = URL + str(i)
            patch.setattr(pipeline, "fetch_config_object", lambda url, data=blob: fetch.FetchResult(url, True, data, 200, None, len(data)))
            decoded.append(asdict(decode.decode_config_blob(blob, recipe=recipe)))
            artifacts.append(pipeline._fetch_decode_one(url, recipe, endpoints, None))
        chains = build_control_chains(artifacts, asdict(recipe), pipeline._dedup_endpoints(endpoints))
        return {"decoded": decoded, "artifacts": artifacts, "chains": chains,
                "digest": build_digest({"meta": {"control_chains": chains}})["control_chains"]}


def test_cross_hash_seed_byte_identical():
    import os
    import subprocess
    import sys
    pytest.importorskip("cryptography")
    outputs = []
    for seed in ("1", "73", "999"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONIOENCODING": "utf-8"}
        result = subprocess.run([sys.executable, "-c", "import json; from tests.test_addressing_chain_stage_a import _determinism_snapshot; print(json.dumps(_determinism_snapshot(), ensure_ascii=False, sort_keys=False))"],
                                cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, check=True, timeout=30)
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1] == outputs[2]
    snapshot = json.loads(outputs[0])
    assert snapshot["decoded"][-1]["decode_chain"] == ["aes", "json"]
    assert "recipe_input_defaulted" in snapshot["artifacts"][-1]["gaps"]
    assert snapshot["artifacts"][0]["fields"]
