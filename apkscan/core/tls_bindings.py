"""Verify independent, time-bounded same-IP domain bindings under a supplied key.

The trust anchor must be obtained independently. Neither SANs nor certificate
selection differences establish these bindings or identify tenants/operators.
"""
from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import ipaddress
import json
import re
from typing import Any


def verify_tls_bindings(material: bytes, public_key: bytes, peer: str, sha: str, observed_at: str) -> dict[str, Any]:
    unknown = {"status": "unknown", "gap": "independent_tls_bindings_unverified"}
    if not material or not public_key or len(material) > 65536 or len(public_key) > 8192:
        return unknown
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from apkscan.core.probe_target import _host

        envelope = json.loads(material)
        claim = envelope["claim"]
        if (claim.get("schema") != "fxapk-tls-bindings-1" or claim.get("basis") != "provider_record"
                or claim.get("peer_ip") != str(ipaddress.ip_address(peer))):
            return unknown
        start, end, observed = [datetime.fromisoformat(v.replace("Z", "+00:00"))
                                for v in (claim["valid_from"], claim["valid_until"], observed_at)]
        if any(t.tzinfo is None for t in (start, end, observed)) or not start <= observed <= end:
            return unknown
        bindings = claim["bindings"]
        if not isinstance(bindings, list) or not 2 <= len(bindings) <= 100:
            return unknown
        domains = []
        for binding in bindings:
            domain = _host(binding["domain"], domain=True)
            if domain != binding["domain"] or not re.fullmatch(r"[0-9a-f]{64}", binding["certificate_sha256"]):
                return unknown
            domains.append(domain)
        if len(set(domains)) != len(domains) or not any(b["certificate_sha256"] == sha for b in bindings):
            return unknown
        key = load_pem_public_key(public_key)
        if not isinstance(key, Ed25519PublicKey):
            return unknown
        key.verify(base64.b64decode(envelope["signature"], validate=True), json.dumps(claim, sort_keys=True, separators=(",", ":")).encode())
        return {"status": "verified", "domains": sorted(domains), "peer_ip": peer, "certificate_sha256": sha,
                "observed_at": observed_at, "material_sha256": hashlib.sha256(material).hexdigest(),
                "trust_anchor_sha256": hashlib.sha256(public_key).hexdigest(),
                "material_base64": base64.b64encode(material).decode(), "trust_anchor_pem": public_key.decode("ascii")}
    except Exception:  # malformed, missing crypto, or unverifiable: no shared-domain signal
        return unknown


def bound_tls_domains(value: Any, peer: str, sha: str, observed_at: str) -> list[str]:
    if not isinstance(value, dict) or value.get("status") != "verified":
        return []
    try:
        if len(value.get("material_base64", "")) > 90000:
            return []
        checked = verify_tls_bindings(base64.b64decode(value["material_base64"], validate=True),
                                      value["trust_anchor_pem"].encode("ascii"), peer, sha, observed_at)
        return checked["domains"] if checked == value and checked["status"] == "verified" else []
    except (ValueError, TypeError, KeyError, AttributeError):
        return []
