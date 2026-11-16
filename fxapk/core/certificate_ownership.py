"""Verify an explicit provider statement against a caller-selected trust anchor.

The caller must independently obtain the provider public key. A valid signature
authenticates the statement under that key; it does not establish an origin host.
No issuer-name or missing-CDN heuristic is an ownership proof.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


def verify_certificate_ownership(material: bytes, public_key: bytes, sha: str, host: str) -> dict[str, Any]:
    unknown = {"status": "unknown", "gap": "independent_certificate_ownership_unverified"}
    if not material or not public_key or len(material) > 65536 or len(public_key) > 8192:
        return unknown
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        envelope = json.loads(material)
        claim = envelope["claim"]
        if (claim.get("schema") != "fxapk-certificate-ownership-1" or claim.get("basis") != "provider_record"
                or claim.get("certificate_sha256") != sha or claim.get("business_host") != host
                or claim.get("cdn_managed") is not False):
            return unknown
        key = load_pem_public_key(public_key)
        if not isinstance(key, Ed25519PublicKey):
            return unknown
        key.verify(base64.b64decode(envelope["signature"], validate=True),
                   json.dumps(claim, sort_keys=True, separators=(",", ":")).encode())
        return {"status": "verified", "material_sha256": hashlib.sha256(material).hexdigest(),
                "trust_anchor_sha256": hashlib.sha256(public_key).hexdigest(),
                "certificate_sha256": sha, "business_host": host, "basis": "signed_provider_statement",
                "material_base64": base64.b64encode(material).decode(), "trust_anchor_pem": public_key.decode("ascii")}
    except Exception:  # malformed, missing crypto support, wrong key/signature: no ownership signal
        return unknown


def ownership_is_bound(value: Any, sha: str, host: str) -> bool:
    if not isinstance(value, dict) or value.get("status") != "verified":
        return False
    try:
        material = base64.b64decode(value.get("material_base64", ""), validate=True)
        key = value.get("trust_anchor_pem", "").encode("ascii")
        checked = verify_certificate_ownership(material, key, sha, host)
        return checked.get("status") == "verified" and all(checked.get(k) == value.get(k) for k in (
            "material_sha256", "trust_anchor_sha256", "certificate_sha256", "business_host"))
    except (ValueError, TypeError, AttributeError):
        return False
