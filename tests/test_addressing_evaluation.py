"""Independent synthetic positives/negatives; not a real-case effectiveness claim."""
from copy import deepcopy
import base64
import hashlib
import json

import pytest

from tests.test_addressing_runtime import ART, CONTEXT, SAMPLE, SHA, events


def case(name):
    item = {"case_id": name, "sample_sha256": SAMPLE, "artifacts": [deepcopy(ART)], "events": events(),
            "body_records": [{**CONTEXT, "sha256": SHA, "hash_scope": "full", "verified": True}], "rounds": [],
            "expected": {"original_consumption_verified": True, "business_certificate_usable": True,
                         "origin_confirmed": False}}
    independent, edge = True, None
    if name == "sdk_domain_in_configuration":
        item["events"] = []
        item["expected"]["original_consumption_verified"] = False
    elif name == "contacted_cdn_edge":
        edge = "confirmed"
        item["expected"]["business_certificate_usable"] = False
    elif name == "shared_ip_multiple_tenants":
        independent = False
        item["expected"]["business_certificate_usable"] = False
    elif name == "expired_historical_resolution":
        item["events"][1]["capture_ref"] = "other-round"
        item["expected"]["original_consumption_verified"] = False
    elif name == "modified_runtime":
        for row in item["events"] + item["body_records"]:
            row["runtime_variant"] = "modified-runtime"
        item["expected"]["original_consumption_verified"] = False
    elif name == "random_iv_body_hash_change":
        item["body_records"][0]["sha256"] = "b" * 64
        item["expected"]["original_consumption_verified"] = False
    item["endpoint"] = certificate_endpoint(independent, edge)
    return item


def certificate_endpoint(independent, edge):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from apkscan.core.certificate_ownership import verify_certificate_ownership
    from apkscan.core.models import Endpoint, Evidence, EvidenceScope
    from apkscan.report.json import _to_jsonable
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    claim = {"schema": "fxapk-certificate-ownership-1", "certificate_sha256": SHA,
             "business_host": "api.example.test", "cdn_managed": False, "basis": "provider_record"}
    material = json.dumps({"claim": claim, "signature": base64.b64encode(key.sign(json.dumps(claim, sort_keys=True, separators=(",", ":")).encode())).decode()}).encode()
    ownership = verify_certificate_ownership(material, public, SHA, "api.example.test") if independent else {"status": "unknown"}
    row = {"check": "tls", "outcome": "tls_binding_observed", "peer_ip": "192.0.2.1", "sni": "api.example.test",
           "certificate_sha256": SHA, "tls_verified": True, "certificate_ownership": ownership}
    receipt_sha = hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
    row["observation_sha256"] = receipt_sha
    return _to_jsonable(Endpoint("192.0.2.1", "ip", evidences=[Evidence(source="active-probe", location=f"probe-target:{receipt_sha}",
        scope=EvidenceScope.CASE_EVIDENCE, provenance={"artifact_sha256": receipt_sha})], enrichment={
        "active_observation": [row], "attribution": {"ips": [{"ip": "192.0.2.1", "edge_provider": {"tier": edge} if edge else {}}]}}))


@pytest.mark.parametrize("name", ["positive", "sdk_domain_in_configuration", "contacted_cdn_edge", "shared_ip_multiple_tenants",
                                 "expired_historical_resolution", "modified_runtime", "random_iv_body_hash_change"])
def test_independent_evaluation_dimensions(name):
    from apkscan.config.evaluation import evaluate_synthetic_suite
    result = evaluate_synthetic_suite([case(name)])
    assert result["cases"][0]["matches_expected"] is True
    assert result["real_case_count"] == 0
    assert result["ranking_or_advice_change_eligible"] is False


def test_evaluation_detects_wrong_labels_and_is_permutation_invariant():
    from apkscan.config.evaluation import evaluate_synthetic_suite
    rows = [case("positive"), case("contacted_cdn_edge")]
    rows[0]["expected"]["origin_confirmed"] = True
    result = evaluate_synthetic_suite(rows)
    assert result == evaluate_synthetic_suite(list(reversed(rows)))
    assert result["mismatch_count"] == 1
