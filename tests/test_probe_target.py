import base64
import hashlib
import json
from copy import deepcopy

import pytest
from typer.testing import CliRunner


def report():
    from apkscan.core.models import Endpoint, Report
    from apkscan.report.json import to_dict
    return to_dict(Report("test.example.app", {"sample_sha256": "a" * 64}, [],
                          [Endpoint("192.0.2.1", "ip"), Endpoint("api.example.test", "domain")], [], []))


def test_plan_default_zero_dns_and_no_writes(tmp_path, monkeypatch):
    from apkscan.cli import app
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("plan resolved"))
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()), encoding="utf-8")
    result = CliRunner().invoke(app, ["probe-target", str(path), "--target", "192.0.2.1", "--business-host", "api.example.test",
                                      "--allow", "192.0.2.1", "--out", str(tmp_path / "out")])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["status"] == "planned"
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("change", [{"checks": ["resource"]}, {"max_requests": 0}, {"max_requests": 7},
                                    {"max_bytes": 0}, {"window": 601}, {"business_host": "api.example.test/path"}])
def test_plan_rejects_unsupported_or_unbounded_requests(change):
    from apkscan.core.probe_target import build_plan
    args = {"target": "192.0.2.1", "business_host": "api.example.test", "allow": ["192.0.2.1"],
            "checks": ["tls"], "max_requests": 6, "max_bytes": 2 * 1024 * 1024, "window": 600}
    args.update(change)
    with pytest.raises(ValueError):
        build_plan(report(), **args)


def test_allowlist_is_required_before_any_dns(tmp_path, monkeypatch):
    from apkscan.core import probe_target as pt
    monkeypatch.setattr(pt, "probe_tls", lambda *a, **k: pytest.fail("unallowed target accessed"))
    plan = pt.build_plan(report(), target="192.0.2.1", business_host="api.example.test", allow=[])
    result = pt.run_plan(plan, tmp_path, report(), authorized=True)
    assert json.loads(result.read_text())["outcome"] == "skipped_not_allowed"


def test_tls_binding_and_archive_do_not_become_app_contact_or_origin(tmp_path, monkeypatch):
    from apkscan.core import probe_target as pt
    from apkscan.core.models import OBSERVED_CONTACT_SOURCES
    base = report()
    before = deepcopy(base)
    der = b"synthetic-certificate"
    monkeypatch.setattr(pt, "probe_tls", lambda *a, **k: ({"check": "tls", "outcome": "tls_binding_observed",
        "peer_ip": "192.0.2.1", "sni": "api.example.test", "host_header": None,
        "observed_at": "2026-11-09T00:00:00Z", "certificate_sha256": hashlib.sha256(der).hexdigest(),
        "san": ["api.example.test"], "tls_verified": True}, der))
    plan = pt.build_plan(base, target="192.0.2.1", business_host="api.example.test", allow=["192.0.2.1"])
    receipt = pt.run_plan(plan, tmp_path, base, authorized=True)
    saved = json.loads((receipt.parent / "report.json").read_text())
    assert base == before
    ep = saved["endpoints"][0]
    assert ep["enrichment"]["active_observation"][0]["certificate_ownership"]["status"] == "unknown"
    assert ep["evidences"][-1]["source"] == "active-probe"
    assert "active-probe" not in OBSERVED_CONTACT_SOURCES
    assert "origin" not in ep["enrichment"]
    assert "runtime" not in ep["enrichment"]
    manifest = json.loads((receipt.parent / "SHA256.json").read_text())
    assert all(hashlib.sha256((receipt.parent / path).read_bytes()).hexdigest() == sha for path, sha in manifest.items())


def test_certificate_ownership_requires_signature_bound_to_der_and_host(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from apkscan.core.probe_target import verify_certificate_ownership
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    claim = {"schema": "fxapk-certificate-ownership-1", "certificate_sha256": "a" * 64,
             "business_host": "api.example.test", "cdn_managed": False, "basis": "provider_record"}
    signed = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()
    attestation = json.dumps({"claim": claim, "signature": base64.b64encode(key.sign(signed)).decode()}).encode()
    result = verify_certificate_ownership(attestation, public, "a" * 64, "api.example.test")
    assert result["status"] == "verified" and result["material_sha256"] == hashlib.sha256(attestation).hexdigest()
    assert verify_certificate_ownership(attestation, public, "b" * 64, "api.example.test")["status"] == "unknown"
    changed = json.loads(attestation)
    changed["claim"]["business_host"] = "other.example.test"
    assert verify_certificate_ownership(json.dumps(changed).encode(), public, "a" * 64, "other.example.test")["status"] == "unknown"


def test_active_receipt_only_licenses_certificate_signal_with_independent_material(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from apkscan.core import probe_target as pt
    from apkscan.core.report_io import report_from_dict
    from apkscan.core.closure.layers import assemble_target_closure
    from apkscan.attribution.assemble import _ip_signal_features, _ip_entity
    from apkscan.attribution.roles import RoleSignal
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    der = b"synthetic certificate"
    sha = hashlib.sha256(der).hexdigest()
    claim = {"schema": "fxapk-certificate-ownership-1", "certificate_sha256": sha, "business_host": "api.example.test", "cdn_managed": False, "basis": "provider_record"}
    material = json.dumps({"claim": claim, "signature": base64.b64encode(key.sign(json.dumps(claim, sort_keys=True, separators=(",", ":")).encode())).decode()}).encode()
    monkeypatch.setattr(pt, "probe_tls", lambda *a, **k: ({"check": "tls", "outcome": "tls_binding_observed", "peer_ip": "192.0.2.1",
        "sni": "api.example.test", "host_header": None, "observed_at": "2026-11-09T00:00:00Z", "certificate_sha256": sha, "tls_verified": True}, der))
    base = report()
    baseline = assemble_target_closure(report_from_dict(base).endpoints[0])
    base["meta"]["closure"] = {"status": "partial", "targets": [deepcopy(baseline)]}
    plan = pt.build_plan(base, target="192.0.2.1", business_host="api.example.test", allow=["192.0.2.1"])
    path = pt.run_plan(plan, tmp_path, base, authorized=True, ownership_material=material, ownership_key=public)
    ep = report_from_dict(json.loads((path.parent / "report.json").read_text())).endpoints[0]
    published = json.loads((path.parent / "report.json").read_text())
    assert published["meta"]["network_attribution"]["phase"] == "probe-target"
    assert published["meta"]["closure"]["targets"][0]["layers"]["request_target"]["evidence"]["active_evidence"]
    assert published["meta"]["closure"]["status"] == "partial"
    ip = _ip_entity(ep.value)
    assert ip is not None
    def signals(entry=None):
        return {f.signal for f in _ip_signal_features(ip, entry or {}, endpoint=ep)}
    assert RoleSignal.BUSINESS_CERTIFICATE in signals()
    assert RoleSignal.DIRECT_CONNECTION not in signals()
    assert RoleSignal.BUSINESS_CERTIFICATE not in signals({"edge_provider": {"tier": "possible"}})
    projected = assemble_target_closure(ep)
    assert projected["layers"]["request_target"]["evidence"]["active_evidence"]
    assert {k: v["status"] for k, v in projected["layers"].items()} == {k: v["status"] for k, v in baseline["layers"].items()}
    assert projected["origin"] == baseline["origin"]
    ep.enrichment["active_observation"][0]["certificate_ownership"] = {"status": "verified"}
    assert RoleSignal.BUSINESS_CERTIFICATE not in signals()


def test_execute_is_explicit_and_report_binding_cannot_change(tmp_path, monkeypatch):
    from apkscan.core import probe_target as pt
    monkeypatch.setattr(pt, "probe_tls", lambda *a, **k: pytest.fail("must not execute"))
    base = report()
    plan = pt.build_plan(base, target="192.0.2.1", business_host="api.example.test", allow=["192.0.2.1"])
    with pytest.raises(ValueError):
        pt.run_plan(plan, tmp_path, base)
    changed = deepcopy(base)
    changed["meta"]["sample_sha256"] = "b" * 64
    with pytest.raises(ValueError):
        pt.run_plan(plan, tmp_path, changed, authorized=True)


def test_cli_accepts_documented_budget_units(tmp_path):
    from apkscan.cli import app
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()), encoding="utf-8")
    result = CliRunner().invoke(app, ["probe-target", str(path), "--target", "192.0.2.1", "--business-host", "api.example.test",
                                    "--max-bytes", "2MiB", "--window", "10m"])
    assert result.exit_code == 0, result.output
    planned = json.loads(result.stdout)
    assert planned["window"] == 600 and planned["max_bytes"] == 2 * 1024 * 1024


@pytest.mark.parametrize("failure", [None, "tls_rejected", "oversized", "san_mismatch"])
def test_tls_probe_preserves_sni_verification_and_limits_material(monkeypatch, failure):
    from types import SimpleNamespace
    from apkscan.core import probe_target as pt
    closed = []
    class Sock:
        def getpeername(self): return ("192.0.2.1", 443)
        def settimeout(self, value): assert 0 < value <= 15
        def close(self): closed.append(True)
        def getpeercert(self, binary_form=False):
            if binary_form:
                return b"synthetic-der"
            return {"subjectAltName": [("DNS", "other.example.test" if failure == "san_mismatch" else "api.example.test")]}
    sock = Sock()
    context = SimpleNamespace(minimum_version=None)
    def wrap(raw, *, server_hostname):
        assert raw is sock and server_hostname == "api.example.test"
        assert context.minimum_version == pt.ssl.TLSVersion.TLSv1_2
        if failure == "tls_rejected":
            raise pt.ssl.SSLError("rejected")
        return sock
    context.wrap_socket = wrap
    monkeypatch.setattr(pt, "resolve_public", lambda *a, **k: ["192.0.2.1"])
    monkeypatch.setattr(pt, "connect_pinned", lambda *a, **k: sock)
    monkeypatch.setattr(pt.ssl, "create_default_context", lambda: context)
    plan = pt.build_plan(report(), target="192.0.2.1", business_host="api.example.test", allow=["192.0.2.1"], max_bytes=1 if failure == "oversized" else 1024)
    result, der = pt.probe_tls(plan)
    assert closed == [True]
    if failure in ("tls_rejected", "oversized"):
        assert result["outcome"] == "failed" and der == b""
    elif failure == "san_mismatch":
        assert result["outcome"] == "san_binding_unverified"
    else:
        assert result["outcome"] == "tls_binding_observed" and result["peer_ip"] == "192.0.2.1"
        assert result["certificate_sha256"] == hashlib.sha256(der).hexdigest()


def test_future_report_schema_is_not_written():
    from apkscan.core import probe_target as pt
    base = report()
    base["schema_version"] = "999.0"
    with pytest.raises(ValueError):
        pt.build_plan(base, target="192.0.2.1", business_host="api.example.test", allow=[])


def test_followup_projection_preserves_each_active_receipt_and_certificate(tmp_path, monkeypatch):
    from apkscan.core import probe_target as pt
    base = report()
    result = None
    for index in (1, 2):
        der = f"synthetic-certificate-{index}".encode()
        sha = hashlib.sha256(der).hexdigest()
        monkeypatch.setattr(pt, "probe_tls", lambda *a, **k: ({"check": "tls", "outcome": "tls_binding_observed",
            "peer_ip": "192.0.2.1", "sni": "api.example.test", "host_header": None,
            "observed_at": f"2026-11-09T00:00:0{index}Z", "tls_verified": True, "certificate_sha256": sha}, der))
        plan = pt.build_plan(base, target="192.0.2.1", business_host="api.example.test", allow=["192.0.2.1"])
        result = pt.run_plan(plan, tmp_path, base, authorized=True)
        base = json.loads((result.parent / "report.json").read_text())
    assert result is not None
    evidence = base["endpoints"][0]["evidences"]
    assert len({e["locator"]["stored_path"] for e in evidence}) == 2
    for row in evidence:
        data = (result.parent / row["locator"]["stored_path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == row["provenance"]["artifact_sha256"]
        assert (result.parent / "certificates" / (row["provenance"]["certificate_sha256"] + ".der")).is_file()
    base["endpoints"][0]["enrichment"]["active_observation"][0]["outcome"] = "tampered"
    monkeypatch.setattr(pt, "probe_tls", lambda *a, **k: pytest.fail("invalid prior material must fail before network"))
    plan = pt.build_plan(base, target="192.0.2.1", business_host="api.example.test", allow=["192.0.2.1"])
    with pytest.raises(ValueError, match="prior_active_receipt_hash_mismatch"):
        pt.run_plan(plan, tmp_path, base, authorized=True)
