import base64
import hashlib
import json

import pytest


def statement(**change):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    claim = {"schema": "fxapk-tls-bindings-1", "basis": "provider_record", "peer_ip": "192.0.2.1",
             "valid_from": "2026-11-09T00:00:00Z", "valid_until": "2026-11-09T01:00:00Z",
             "bindings": [{"domain": domain, "certificate_sha256": hashlib.sha256(b"der").hexdigest()}
                          for domain in ("a.example.test", "b.example.test", "c.example.test")]}
    claim.update(change)
    signed = key.sign(json.dumps(claim, sort_keys=True, separators=(",", ":")).encode())
    return json.dumps({"claim": claim, "signature": base64.b64encode(signed).decode()}).encode(), public


@pytest.mark.parametrize("change", [{}, {"peer_ip": "192.0.2.2"}, {"valid_until": "2026-11-08T00:00:00Z"},
    {"basis": "san_names"}, {"bindings": [{"domain": "a.example.test", "certificate_sha256": "a" * 64}]}])
def test_independent_bindings_must_match_peer_der_and_observation_window(change):
    from apkscan.core.tls_bindings import verify_tls_bindings, bound_tls_domains
    material, key = statement(**change)
    sha = hashlib.sha256(b"der").hexdigest()
    checked = verify_tls_bindings(material, key, "192.0.2.1", sha, "2026-11-09T00:30:00Z")
    assert (checked["status"] == "verified") is (not change)
    domains = bound_tls_domains(checked, "192.0.2.1", sha, "2026-11-09T00:30:00Z")
    assert bool(domains) is (not change)
    if not change:
        assert domains == ["a.example.test", "b.example.test", "c.example.test"]
        checked["domains"].append("tampered.example.test")
        assert bound_tls_domains(checked, "192.0.2.1", sha, "2026-11-09T00:30:00Z") == []


def test_cert_selection_difference_alone_never_means_shared_tenants(tmp_path, monkeypatch):
    from apkscan.core import probe_target as pt
    from apkscan.core.report_io import report_from_dict
    from apkscan.attribution.assemble import _ip_entity, _ip_signal_features
    from apkscan.attribution.roles import RoleSignal
    from tests.test_probe_target import report
    monkeypatch.setattr(pt, "probe_tls", lambda *a, **k: ({"check": "tls-no-sni", "outcome": "certificate_selection_observed",
        "observed_at": "2026-11-09T00:30:00Z", "peer_ip": "192.0.2.1", "sni": None, "chain_verified": True,
        "certificate_sha256": hashlib.sha256(b"der").hexdigest(), "tls_verified": False}, b"der"))
    material, key = statement()
    for supplied in (False, True):
        p = pt.build_plan(report(), target="192.0.2.1", business_host="a.example.test", allow=["192.0.2.1"], checks=["tls-no-sni"])
        path = pt.run_plan(p, tmp_path, report(), authorized=True,
                           binding_material=material if supplied else b"", binding_key=key if supplied else b"")
        ep = report_from_dict(json.loads((path.parent / "report.json").read_text())).endpoints[0]
        signals = {f.signal for f in _ip_signal_features(_ip_entity(ep.value), {}, endpoint=ep)}
        assert (RoleSignal.SHARED_TLS in signals) is supplied
        assert (RoleSignal.MANY_SHARED_DOMAINS in signals) is supplied
        assert RoleSignal.DIRECT_CONNECTION not in signals and RoleSignal.BUSINESS_CERTIFICATE not in signals
