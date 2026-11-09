"""Bounded active checks: every network operation is replaced with a local stub."""
import hashlib
import json
from copy import deepcopy
from io import BytesIO

import pytest

from apkscan.core import probe_target as pt
from tests.test_probe_target import report


def plan(**kwargs):
    return pt.build_plan(report(), target="192.0.2.1", business_host="api.example.test",
                         allow=["192.0.2.1", "api.example.test"], **kwargs)


def test_full_plan_counts_operations_and_never_resolves(monkeypatch):
    monkeypatch.setattr(pt, "resolve_public", lambda *a, **k: pytest.fail("planning DNS"))
    p = plan(checks=["tls", "host-compare", "resource", "objstore-head"],
             url="https://api.example.test/public", resource_url="https://api.example.test/static.json",
             object_url="https://api.example.test/config.json")
    assert p["planned_requests"] == 6
    assert p["checks"] == sorted(p["checks"])
    assert p["follow_redirects"] is False
    with pytest.raises(ValueError, match="request_budget"):
        plan(checks=["tls", "host-compare"], url="https://api.example.test/public", max_requests=2)


@pytest.mark.parametrize("url", ["http://api.example.test/a", "https://user:pass@api.example.test/a",
    "https://api.example.test/a?token=secret", "https://api.example.test/a#b",
    "https://api.example.test:8443/a", "https://other.example.test/a", "https://api.example.test/a\r\nX:1"])
def test_unsafe_or_out_of_scope_url_is_rejected_offline(url):
    with pytest.raises(ValueError):
        plan(checks=["business"], url=url)


def test_http_does_not_redirect_and_archives_exact_response(monkeypatch):
    from apkscan.core import probe_checks as pc
    calls = []
    class Connection:
        peer_ip = "192.0.2.1"
        sock = None
        def __init__(self, request, address, **kwargs):
            assert address == "192.0.2.1" and request["host"] == "api.example.test"
        def request(self, method, path, headers): calls.append((method, path, headers))
        def getresponse(self):
            stream = BytesIO(b"moved")
            stream.status = 302
            stream.getheaders = lambda: [("Location", "https://other.example.test/"), ("Content-Length", "5")]
            stream.read1 = stream.read
            return stream
        def close(self): calls.append("closed")
    monkeypatch.setattr(pc, "PinnedConnection", Connection)
    monkeypatch.setattr(pc, "resolve_public", lambda *a, **k: ["192.0.2.1"])
    request = pc.http_request("business", "https://api.example.test/public", target="192.0.2.1")
    row = pc.observe_http(request, max_bytes=2048, timeout=2)
    assert row["outcome"] == "redirect_not_followed" and row["body_complete"] is True
    assert row["body_sha256"] == hashlib.sha256(b"moved").hexdigest()
    assert row["peer_ip"] == "192.0.2.1" and row["sni"] == "api.example.test"
    assert len(calls) == 2 and calls[-1] == "closed"
    assert "Authorization" not in calls[0][2] and "Cookie" not in calls[0][2]


def test_bos_request_id_is_retained_even_when_object_is_missing(monkeypatch):
    from apkscan.core import probe_checks as pc

    class Connection:
        peer_ip = "192.0.2.1"
        sock = None

        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            response = BytesIO(b'{"code":"NoSuchBucket"}')
            response.status = 404
            response.getheaders = lambda: [("X-Bce-Request-Id", "fixture-request"), ("Content-Length", "23")]
            response.read1 = response.read
            return response

        def close(self):
            pass

    monkeypatch.setattr(pc, "PinnedConnection", Connection)
    monkeypatch.setattr(pc, "resolve_public", lambda *a, **k: ["192.0.2.1"])
    row = pc.observe_http(pc.http_request("objstore-get", "https://api.example.test/config"), max_bytes=1024, timeout=2)
    assert row["object_metadata"] == {"x-bce-request-id": "fixture-request"}
    assert row["http_status"] == 404
    assert "bucket_exists" not in row and "business_certificate" not in row


def test_comparisons_need_complete_same_peer_and_single_variable():
    from apkscan.core.probe_checks import compare_http
    a = {"outcome": "observed", "body_complete": True, "http_status": 200,
         "body_sha256": "a" * 64, "peer_ip": "192.0.2.1", "sni": "api.example.test", "port": 443,
         "request_target": "/public", "method": "GET", "host_header": "api.example.test"}
    b = {**a, "body_sha256": "b" * 64, "host_header": "random.example.test"}
    assert compare_http("host-compare", [a, b])["outcome"] == "content_difference_observed"
    for change in ({"body_complete": False}, {"peer_ip": "192.0.2.2"}, {"request_target": "/other"}, {"sni": "other.example.test"}):
        assert compare_http("host-compare", [a, {**b, **change}])["outcome"] == "inconclusive"
    assert compare_http("resource", [a, {**a, "peer_ip": "192.0.2.2"}])["outcome"] == "resource_bytes_match"
    assert compare_http("resource", [{**a, "http_status": 404}, {**a, "http_status": 404}])["outcome"] == "inconclusive"


def test_multi_checks_share_budget_preserve_bodies_and_do_not_modify_report(tmp_path, monkeypatch):
    from apkscan.core import probe_checks as pc
    calls = []
    def observe(request, *, max_bytes, timeout):
        calls.append((request, max_bytes, timeout))
        body = b"business" if request["label"] == "business" else b"random"
        return {**request, "outcome": "observed", "observed_at": "2026-11-09T00:00:00Z",
                "peer_ip": "192.0.2.1", "body_complete": True, "http_status": 200,
                "body_sha256": hashlib.sha256(body).hexdigest(), "body_base64": __import__("base64").b64encode(body).decode(),
                "consumed_bytes": len(body)}
    monkeypatch.setattr(pc, "observe_http", observe)
    base = report()
    before = deepcopy(base)
    path = pt.run_plan(plan(checks=["host-compare"], url="https://api.example.test/public", max_bytes=1024),
                       tmp_path, base, authorized=True)
    assert base == before and len(calls) == 2
    assert calls[1][1] < calls[0][1] and calls[1][2] <= calls[0][2]
    saved = json.loads((path.parent / "report.json").read_text())
    row = saved["endpoints"][0]["enrichment"]["active_observation"][0]
    assert row["check"] == "host-compare" and row["outcome"] == "content_difference_observed"
    for request in row["requests"]:
        assert (path.parent / "bodies" / (request["body_sha256"] + ".body")).is_file()
    assert all(hashlib.sha256((path.parent / p).read_bytes()).hexdigest() == sha
               for p, sha in json.loads((path.parent / "SHA256.json").read_text()).items())
    assert all(e["source"] == "active-probe" for e in saved["endpoints"][0]["evidences"])


def test_follow_requires_explicit_verified_relation_and_allowlist(tmp_path, monkeypatch):
    from apkscan.core import probe_checks as pc
    body = b'{"next":"https://api.example.test/child.json"}'
    edge = {"source_url": "https://api.example.test/root.json", "source_sha256": hashlib.sha256(body).hexdigest(),
            "field_pointer": "/next", "target_url": "https://api.example.test/child.json"}
    calls = []
    def observe(request, **kwargs):
        calls.append(request["url"])
        raw = body if request["url"] == edge["source_url"] else b"{}"
        return {**request, "outcome": "observed", "observed_at": "2026-11-09T00:00:00Z", "peer_ip": "192.0.2.1",
                "http_status": 200, "body_complete": True, "body_sha256": hashlib.sha256(raw).hexdigest(),
                "body_base64": __import__("base64").b64encode(raw).decode(), "consumed_bytes": len(raw)}
    monkeypatch.setattr(pc, "observe_http", observe)
    p = plan(checks=["follow"], follow_edges=[edge], max_objects=2)
    path = pt.run_plan(p, tmp_path, report(), authorized=True)
    assert calls == [edge["source_url"], edge["target_url"]]
    assert json.loads(path.read_text())["outcome"] == "follow_observed"
    calls.clear()
    changed = {**edge, "source_sha256": "a" * 64}
    path = pt.run_plan(plan(checks=["follow"], follow_edges=[changed], max_objects=2), tmp_path, report(), authorized=True)
    assert calls == [edge["source_url"]]
    assert json.loads(path.read_text())["outcome"] == "inconclusive"
    with pytest.raises(ValueError):
        plan(checks=["follow"], follow_edges=[edge])
    with pytest.raises(ValueError):
        plan(checks=["follow"], follow_edges=[edge, {**edge, "source_url": edge["target_url"], "target_url": edge["source_url"]}], max_objects=2)


@pytest.mark.parametrize("check", ["tls-no-sni", "tls-random-sni"])
def test_comparison_sni_keeps_chain_validation_and_never_claims_business_identity(monkeypatch, check):
    from types import SimpleNamespace
    context = SimpleNamespace(minimum_version=None, check_hostname=True, verify_mode=pt.ssl.CERT_REQUIRED)
    class Sock:
        def getpeername(self): return "192.0.2.1", 443
        def settimeout(self, value): pass
        def close(self): pass
        def getpeercert(self, binary_form=False): return b"comparison-der" if binary_form else {"subjectAltName": [("DNS", "other.example.test")]}
    sock = Sock()
    def wrap(raw, *, server_hostname):
        assert context.verify_mode == pt.ssl.CERT_REQUIRED and context.check_hostname is False
        assert server_hostname is None if check == "tls-no-sni" else server_hostname.endswith(".example.test")
        return sock
    context.wrap_socket = wrap
    monkeypatch.setattr(pt.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(pt, "resolve_public", lambda *a, **k: ["192.0.2.1"])
    monkeypatch.setattr(pt, "connect_pinned", lambda *a, **k: sock)
    row, _ = pt.probe_tls({**plan(checks=[check]), "tls_check": check})
    assert row["outcome"] == "certificate_selection_observed" and row["tls_verified"] is False
    assert row["chain_verified"] is True and row["hostname_verified"] is False


def test_host_difference_signal_requires_bound_receipt_and_same_peer(tmp_path, monkeypatch):
    from apkscan.core import probe_checks as pc
    from apkscan.core.report_io import report_from_dict
    from apkscan.attribution.assemble import _ip_entity, _ip_signal_features
    from apkscan.attribution.roles import RoleSignal
    def observe(request, **kwargs):
        raw = request["label"].encode()
        return {**request, "outcome": "observed", "peer_ip": "192.0.2.1", "http_status": 200, "body_complete": True,
                "body_sha256": hashlib.sha256(raw).hexdigest(), "body_base64": __import__("base64").b64encode(raw).decode(), "consumed_bytes": len(raw)}
    monkeypatch.setattr(pc, "observe_http", observe)
    path = pt.run_plan(plan(checks=["host-compare"], url="https://api.example.test/public"), tmp_path, report(), authorized=True)
    ep = report_from_dict(json.loads((path.parent / "report.json").read_text())).endpoints[0]
    ip = _ip_entity(ep.value)
    def signals(entry=None): return {f.signal for f in _ip_signal_features(ip, entry or {}, endpoint=ep)}
    assert RoleSignal.CONTENT_DIFFERENCE in signals()
    assert RoleSignal.DIRECT_CONNECTION not in signals()
    assert RoleSignal.SHARED_TLS not in signals() and RoleSignal.MANY_SHARED_DOMAINS not in signals()
    assert RoleSignal.CONTENT_DIFFERENCE not in signals({"edge_provider": {"tier": "possible"}})
    ep.enrichment["active_observation"][0]["requests"][0]["peer_ip"] = "192.0.2.2"
    assert RoleSignal.CONTENT_DIFFERENCE not in signals()


def test_follow_rejects_ambiguous_json_duplicate_keys():
    from apkscan.core.probe_checks import relation_matches
    import base64
    raw = b'{"next":"https://other.example.test/x","next":"https://api.example.test/x"}'
    sha = hashlib.sha256(raw).hexdigest()
    edge = {"source_sha256": sha, "field_pointer": "/next", "target_url": "https://api.example.test/x"}
    row = {"outcome": "observed", "http_status": 200, "body_complete": True, "body_sha256": sha,
           "body_base64": base64.b64encode(raw).decode()}
    assert not relation_matches(edge, row)


def test_http_budget_and_allowlist_stop_later_connections(tmp_path, monkeypatch):
    from apkscan.core import probe_checks as pc
    calls = []
    def observe(request, **kwargs):
        calls.append(request)
        return {**request, "outcome": "failed", "consumed_bytes": 1}
    monkeypatch.setattr(pc, "observe_http", observe)
    p = plan(checks=["host-compare"], url="https://api.example.test/public", max_bytes=1)
    path = pt.run_plan(p, tmp_path, report(), authorized=True)
    assert len(calls) == 1
    assert json.loads(path.read_text())["requests"][1]["outcome"] == "skipped_budget_exhausted"
    calls.clear()
    p = pt.build_plan(report(), target="192.0.2.1", business_host="api.example.test", allow=[],
                      checks=["business"], url="https://api.example.test/public")
    path = pt.run_plan(p, tmp_path, report(), authorized=True)
    assert calls == [] and json.loads(path.read_text())["outcome"] == "skipped_not_allowed"
