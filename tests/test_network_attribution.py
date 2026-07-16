"""PR9 network_attribution: bridge, conservative signal compiler, determinism,
passive discipline, and the anti-over-inference acceptance negatives."""

from __future__ import annotations

import json
import subprocess
import sys

from apkscan.attribution.assemble import _parse_asn, build_network_attribution
from apkscan.core.models import Endpoint, Evidence


def _ep(value, kind, enrichment=None, evidences=None):
    return Endpoint(value=value, kind=kind, evidences=evidences or [], enrichment=enrichment or {})


def _build(*endpoints, phase="analyze"):
    return build_network_attribution(list(endpoints), artifact_id="sha-test", phase=phase)


def _all_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _all_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _all_keys(item)


def _roles(blob, ip):
    for ep in blob["endpoints"]:
        for ipv in ep["ips"]:
            if ipv["ip"] == ip:
                return {r["role"]: r for r in ipv["roles"]}
    return {}


def _edges(blob):
    return {
        (e["relation"], e["source"]["value"], e["target"]["value"]) for e in blob["graph"]["edges"]
    }


# --------------------------------------------------------------------------- #
# ASN parsing
# --------------------------------------------------------------------------- #
def test_parse_asn_strict() -> None:
    assert _parse_asn(13335) == 13335
    assert _parse_asn("AS13335") == 13335
    assert _parse_asn("AS13335 Cloudflare, Inc.") == 13335
    assert _parse_asn("13335") == 13335
    assert _parse_asn(True) is None
    assert _parse_asn(0) is None
    assert _parse_asn("ASN-bad") is None
    assert _parse_asn("Cloudflare 13335") is None  # never extract digits from the middle


# --------------------------------------------------------------------------- #
# Bridge: facts -> evidence -> graph edges
# --------------------------------------------------------------------------- #
def test_dns_facts_become_resolves_to_and_alias_edges() -> None:
    ep = _ep("a.example.com", "domain", {
        "dns": {"ips": ["1.2.3.4"], "hosting": [{"ip": "5.6.7.8", "asn": "AS4134"}], "cname": ["cdn.b.net"]},
    })
    blob = _build(ep)
    edges = _edges(blob)
    assert ("resolves_to", "a.example.com", "1.2.3.4") in edges
    assert ("resolves_to", "a.example.com", "5.6.7.8") in edges  # hosting ip union
    assert ("alias_of", "a.example.com", "cdn.b.net") in edges
    assert ("in_asn", "5.6.7.8", "AS4134") in edges


def test_certs_and_shodan_hostnames_become_related_hostname_never_certificate() -> None:
    ep = _ep("a.example.com", "domain", {
        "certs": {"related_hostnames": ["alt.example.com"]},
        "shodan": {"hostnames": ["scan.example.com"]},
    })
    blob = _build(ep)
    edges = _edges(blob)
    assert ("intel_related", "a.example.com", "alt.example.com") in edges
    assert ("intel_related", "a.example.com", "scan.example.com") in edges
    # crt.sh carries no leaf-cert sha256 -> never a CERTIFICATE node / certifies edge
    assert not any(n["type"] == "CERTIFICATE" for n in blob["graph"]["nodes"])


def test_bridged_evidence_confidence_is_constant_and_timestamp_none() -> None:
    ep = _ep("a.example.com", "domain", {"dns": {"ips": ["1.2.3.4"]}})
    blob = _build(ep)
    resolved = [e for e in blob["evidence"] if e["type"] == "resolved_ip"]
    assert resolved and all(e["confidence"] == 0.8 and e["timestamp"] is None for e in resolved)


# --------------------------------------------------------------------------- #
# Conservative signal compiler
# --------------------------------------------------------------------------- #
def _cn_ip_endpoint():
    return _ep("203.0.113.9", "ip", {
        "asn": {"asn": "AS4134 China Telecom", "country": "CN"},
        "attribution": {"ips": [{"ip": "203.0.113.9", "country": "CN",
                                 "origin_network": {"asn": 4134, "category": "telecom"},
                                 "hosting_provider": {"category": "idc"}, "edge_provider": {"tier": None}}]},
    }, evidences=[Evidence(source="runtime", location="pcap")])


def test_domestic_and_direct_connection_from_facts() -> None:
    blob = _build(_cn_ip_endpoint())
    relay = _roles(blob, "203.0.113.9").get("domestic_relay_candidate")
    assert relay is not None
    assert "domestic_network" in relay["matched_signals"]
    assert "direct_connection" in relay["matched_signals"]  # ip endpoint + runtime observed


def test_public_cdn_reuses_the_wired_edge_tier() -> None:
    ep = _ep("cdn.example.com", "domain", {
        "dns": {"ips": ["104.16.0.1"]},
        "attribution": {"ips": [{"ip": "104.16.0.1", "country": "US",
                                 "origin_network": {"asn": 13335, "category": "cdn"},
                                 "hosting_provider": {"category": "cdn"},
                                 "edge_provider": {"name": "Cloudflare", "tier": "confirmed"}}]},
    })
    blob = _build(ep)
    roles = _roles(blob, "104.16.0.1")
    # public_cdn present as a role signal (context/blocker), and it BLOCKS relay/origin
    assert roles["domestic_relay_candidate"]["eligible"] is False
    assert "public_cdn" in roles["domestic_relay_candidate"]["negative_signals"]


def test_domain_icp_does_not_make_resolved_ips_domestic() -> None:
    # over-inference guard: an ICP filing is a domain fact; a US CDN edge IP the
    # domain resolves to must NOT inherit domestic_network.
    ep = _ep("pay.example.com", "domain", {
        "icp": {"unit": "示例公司"},
        "dns": {"ips": ["104.16.0.1"]},
        "attribution": {"ips": [{"ip": "104.16.0.1", "country": "US",
                                 "origin_network": {"asn": 13335, "category": "cdn"},
                                 "hosting_provider": {"category": "cdn"},
                                 "edge_provider": {"tier": "confirmed"}}]},
    })
    blob = _build(ep)
    for role in _roles(blob, "104.16.0.1").values():
        assert "domestic_network" not in role["matched_signals"]


def test_no_behavioral_signal_is_synthesized_statically() -> None:
    blob = _build(_cn_ip_endpoint())
    forbidden = {"redirect", "cookie_challenge", "content_difference", "shared_tls",
                 "subsequent_overseas_connection", "historical_dns", "stable_ip", "many_shared_domains"}
    for role in _roles(blob, "203.0.113.9").values():
        assert not (set(role["matched_signals"]) & forbidden)


# --------------------------------------------------------------------------- #
# Anti-over-inference acceptance
# --------------------------------------------------------------------------- #
def test_no_static_report_yields_an_eligible_role() -> None:
    # the load-bearing invariant: behavioral signals are never static-derivable, so
    # cloaking/edge/relay/origin can never be eligible from a static-only report.
    blob = _build(_cn_ip_endpoint(), _ep("x.example.com", "domain", {
        "dns": {"ips": ["104.16.0.1"]},
        "attribution": {"ips": [{"ip": "104.16.0.1", "country": "US",
                                 "origin_network": {"asn": 13335, "category": "cdn"},
                                 "hosting_provider": {"category": "cdn"}, "edge_provider": {"tier": "confirmed"}}]}}))
    for ep in blob["endpoints"]:
        for ipv in ep["ips"]:
            assert all(not r["eligible"] for r in ipv["roles"])
    assert blob["graph"]["nodes"]  # graph still assembled


def test_same_asn_alone_makes_no_cross_edge() -> None:
    e1 = _ep("1.1.1.1", "ip", {"asn": {"asn": 4837}, "attribution": {"ips": [{"ip": "1.1.1.1", "origin_network": {"asn": 4837}}]}})
    e2 = _ep("2.2.2.2", "ip", {"asn": {"asn": 4837}, "attribution": {"ips": [{"ip": "2.2.2.2", "origin_network": {"asn": 4837}}]}})
    blob = _build(e1, e2)
    edges = _edges(blob)
    assert ("in_asn", "1.1.1.1", "AS4837") in edges
    assert ("in_asn", "2.2.2.2", "AS4837") in edges
    assert all(t == "AS4837" for rel, s, t in edges if rel == "in_asn")  # only the shared AS, no stray in_asn
    assert not any(s in ("1.1.1.1", "2.2.2.2") and t in ("1.1.1.1", "2.2.2.2") for _, s, t in edges)


def test_no_operator_or_actor_key_anywhere() -> None:
    blob = _build(_cn_ip_endpoint())
    keys = set(_all_keys(blob))
    assert keys & {"operator", "actor", "owner", "service_operator"} == set()
    assert "disclaimer" in blob  # the explicit "resource fact, not an operator claim" note


# --------------------------------------------------------------------------- #
# Shape, determinism, empty, failure isolation
# --------------------------------------------------------------------------- #
def test_output_shape_and_json_round_trip() -> None:
    blob = _build(_cn_ip_endpoint())
    assert set(blob) == {"version", "phase", "artifact_id", "disclaimer", "graph", "evidence", "endpoints", "skipped"}
    assert blob["version"] == 1 and blob["phase"] == "analyze"
    assert json.loads(json.dumps(blob)) == blob


def test_determinism_under_endpoint_shuffle() -> None:
    # Two domains sharing one hosting IP+ASN (the routine anti-red-front / shared-CDN
    # case) collide on a fact-only evidence id, so this exercises the dedup path — the
    # only order-sensitive one. Permuting endpoint order must still yield a byte-identical
    # blob: the deduped evidence keeps a canonical (lexicographically-smallest) raw_reference.
    a = _ep("a.example.com", "domain", {"dns": {"hosting": [{"ip": "5.6.7.8", "asn": "AS4134"}]}})
    b = _ep("b.example.com", "domain", {"dns": {"hosting": [{"ip": "5.6.7.8", "asn": "AS4134"}]}})
    first = json.dumps(build_network_attribution([a, b], artifact_id="s", phase="analyze"), sort_keys=True)
    second = json.dumps(build_network_attribution([b, a], artifact_id="s", phase="analyze"), sort_keys=True)
    assert first == second
    # the shared asn fact is deduped to exactly one evidence, keyed to the smallest ref.
    blob = build_network_attribution([b, a], artifact_id="s", phase="analyze")
    asn_ev = [e for e in blob["evidence"] if e["type"] == "asn"]
    assert len(asn_ev) == 1
    assert asn_ev[0]["raw_reference"] == "endpoints[a.example.com].enrichment.dns.hosting"


def test_none_when_no_bridgeable_endpoint() -> None:
    assert _build(_ep("https://x/y", "url", {})) is None
    assert _build() is None


def test_one_malformed_endpoint_is_skipped_not_crashing() -> None:
    good = _ep("a.example.com", "domain", {"dns": {"ips": ["1.2.3.4"]}})
    # an unhashable category value raises inside the signal compiler (`... in frozenset`),
    # so this drives the per-endpoint skip-and-record path — not the silent _as_list
    # coercion, which a plain non-list `ips` would hit without ever entering the except.
    bad = _ep("b.example.com", "domain",
              {"attribution": {"ips": [{"ip": "9.9.9.9", "hosting_provider": {"category": ["cloud"]}}]}})
    blob = _build(good, bad)
    assert blob is not None
    assert any(ep["endpoint"] == "a.example.com" for ep in blob["endpoints"])  # good survives
    assert blob["skipped"] == [{"endpoint": "b.example.com", "error": "TypeError"}]  # bad recorded, not crashed


# --------------------------------------------------------------------------- #
# Passive discipline
# --------------------------------------------------------------------------- #
def test_assemble_imports_no_network_or_enricher_stack() -> None:
    # socket is stdlib and ubiquitously pre-loaded, so it is not a proxy for "does
    # network" (the socket tripwire test covers that); the HTTP / enricher / intel
    # stack is what must stay unimported.
    code = (
        "import apkscan.attribution.assemble, sys;"
        "bad=[m for m in sys.modules if m == 'requests' or m == 'apkscan.core.enrichment'"
        " or m.startswith('apkscan.enrichers') or m.startswith('apkscan.intel')];"
        "print(sorted(bad))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "[]", out


def test_digest_surfaces_a_compact_network_attribution_block() -> None:
    from apkscan.report.digest import build_digest

    blob = _build(_cn_ip_endpoint())
    report = {"package_name": "com.x", "meta": {"network_attribution": blob}, "leads": []}
    digest = build_digest(report)
    assert set(digest["network_attribution"]) == {"counts", "role_candidates"}
    assert digest["network_attribution"]["counts"]["nodes"] >= 1
    assert digest["network_attribution"]["role_candidates"] == []  # static -> none eligible
    assert digest["summary"]["attributed_role_candidates"] == 0


def test_digest_degrades_on_malformed_network_attribution() -> None:
    from apkscan.report.digest import build_digest

    digest = build_digest({"meta": {"network_attribution": "not-a-dict"}, "leads": []})
    assert "network_attribution" not in digest  # None -> key omitted, never raises
    assert digest["summary"]["attributed_role_candidates"] == 0

    # a non-numeric score on an eligible role (only reachable from a hand-edited /
    # version-skewed report.json) must degrade in the sort key, never raise.
    malformed = {"meta": {"network_attribution": {"endpoints": [
        {"endpoint": "x", "ips": [{"ip": "1.1.1.1", "roles": [
            {"role": "edge_candidate", "eligible": True, "score": "high"}]}]}]}}, "leads": []}
    digest = build_digest(malformed)
    assert digest["network_attribution"]["counts"]["eligible"] == 1
    assert digest["summary"]["attributed_role_candidates"] == 1
    assert [c["role"] for c in digest["network_attribution"]["role_candidates"]] == ["edge_candidate"]


def test_assembly_touches_no_network() -> None:
    import socket

    real = socket.socket

    def _boom(*_a, **_k):
        raise AssertionError("network at assembly time")

    socket.socket = _boom  # type: ignore[assignment]
    try:
        build_network_attribution([_cn_ip_endpoint()], artifact_id="s", phase="analyze")
    finally:
        socket.socket = real  # type: ignore[assignment]
