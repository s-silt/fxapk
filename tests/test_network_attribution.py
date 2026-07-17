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


def _matched_signals(blob, ip):
    return {s for r in _roles(blob, ip).values() for s in r["matched_signals"]}


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
    cand = digest["network_attribution"]["role_candidates"][0]
    assert cand["role"] == "edge_candidate"
    assert cand["kind"] is None  # ★codex P2-4：endpoint 无 kind → kind 降级为 None（defensive .get），不抛


def test_digest_role_candidates_have_exact_keys_including_kind() -> None:
    """★codex 复审 P2-4：role_candidates 每项键集须 == 设计 schema {endpoint,kind,ip,role,score,confidence}，
    kind（domain/ip）如实透传，排序按 role_rank——此前实现漏 kind，与 spec 漂移且无测试锁定。"""
    from apkscan.report.digest import _ROLE_RANK, build_digest

    blob = {"endpoints": [
        {"endpoint": "c2.fraud-gw.cn", "kind": "domain", "ips": [
            {"ip": "1.2.3.4", "roles": [
                {"role": "origin_candidate", "eligible": True, "score": 0.9, "confidence": "high"}]}]},
        {"endpoint": "5.6.7.8", "kind": "ip", "ips": [
            {"ip": "5.6.7.8", "roles": [
                {"role": "edge_candidate", "eligible": True, "score": 0.5, "confidence": "medium"}]}]},
    ]}
    cands = build_digest({"meta": {"network_attribution": blob}, "leads": []})["network_attribution"]["role_candidates"]
    assert len(cands) == 2
    for c in cands:
        assert set(c) == {"endpoint", "kind", "ip", "role", "score", "confidence"}  # exact key set
    by_ep = {c["endpoint"]: c for c in cands}
    assert by_ep["c2.fraud-gw.cn"]["kind"] == "domain"  # domain 端点 kind 透传
    assert by_ep["5.6.7.8"]["kind"] == "ip"             # ip 端点 kind 透传
    ranks = [_ROLE_RANK.get(str(c["role"]), 99) for c in cands]
    assert ranks == sorted(ranks)  # 排序仍按 role_rank 优先


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


# --------------------------------------------------------------------------- #
# Runtime bridge: dynamic ground-truth edges (tls_sni served_at, network_flow)
# --------------------------------------------------------------------------- #
def _runtime_dom(value="api.example.com", ips=("203.0.113.7:443",), sni=None):
    return _ep(value, "domain", {"runtime": {"sni": list(sni or [value]), "remote_endpoints": list(ips)}})


def _runtime_ip(value="203.0.113.7", source="runtime-pcap", enrichment=None):
    return _ep(value, "ip", enrichment or {}, evidences=[Evidence(source=source, location="pcap")])


def test_runtime_domain_becomes_tls_sni_served_at_plus_apk_contacted() -> None:
    blob = _build(_runtime_dom(ips=["203.0.113.7:443"]))
    edges = _edges(blob)
    assert ("served_at", "api.example.com", "203.0.113.7") in edges  # DOMAIN -> IP, not resolves_to
    assert ("contacted", "sha-test", "api.example.com") in edges  # APK -> DOMAIN (artifact_id source)
    assert not any(rel == "resolves_to" for rel, _s, _t in edges)  # runtime SNI is served_at, not DNS


def test_runtime_ip_becomes_network_flow_apk_contacted_and_mints_apk_node() -> None:
    blob = _build(_runtime_ip("203.0.113.7"))
    edges = _edges(blob)
    assert ("contacted", "sha-test", "203.0.113.7") in edges  # APK -> IP
    assert ("APK", "sha-test") in {(n["type"], n["value"]) for n in blob["graph"]["nodes"]}


def test_tls_sni_requires_the_domain_to_be_an_observed_sni() -> None:
    # a hand-edited report pairing a domain with unrelated remotes: the domain is NOT
    # among the observed SNI names, so no DOMAIN -> IP edge is licensed. A dns fact
    # keeps the endpoint bridged (blob non-None) to prove it is processed yet emits
    # a resolves_to edge only, never a served_at from the mismatched runtime pairing.
    ep = _ep("api.example.com", "domain", {
        "dns": {"ips": ["1.2.3.4"]},
        "runtime": {"sni": ["other.com"], "remote_endpoints": ["9.9.9.9:443"]}})
    blob = _build(ep)
    assert not any(e["type"] == "tls_sni" for e in blob["evidence"])
    assert not any(rel == "served_at" for rel, _s, _t in _edges(blob))
    assert ("resolves_to", "api.example.com", "1.2.3.4") in _edges(blob)  # still bridged


def test_runtime_remote_endpoint_ipv6_port_is_stripped_on_last_colon() -> None:
    blob = _build(_runtime_dom(ips=["2001:db8::1:443"]))
    assert ("served_at", "api.example.com", "2001:db8::1") in _edges(blob)


def test_tls_sni_dedups_one_ip_seen_on_multiple_ports() -> None:
    blob = _build(_runtime_dom(ips=["203.0.113.7:443", "203.0.113.7:8443"]))
    tls = [e for e in blob["evidence"] if e["type"] == "tls_sni"]
    assert len(tls) == 1 and tls[0]["value"] == "203.0.113.7"


def test_network_flow_fires_for_mitm_only_ip_without_runtime_dict() -> None:
    # mitm-only run: an ip endpoint with a source="runtime" evidence but NO structured
    # enrichment["runtime"] — the contact is still observed, so network_flow fires.
    blob = _build(_runtime_ip("198.51.100.5", source="runtime", enrichment={}))
    assert ("contacted", "sha-test", "198.51.100.5") in _edges(blob)


def test_ip_endpoint_sni_list_makes_no_domain_ip_edge() -> None:
    # runtime["sni"] on an IP endpoint may list co-hosted third-party names; the bridge
    # must NOT pair them to the IP (tls_sni is emitted only from the domain-endpoint side).
    ep = _ep("203.0.113.7", "ip",
             {"runtime": {"sni": ["a.com", "b.com"], "remote_endpoints": ["203.0.113.7:443"]}},
             evidences=[Evidence(source="runtime-pcap", location="pcap")])
    blob = _build(ep)
    assert not any(e["type"] == "tls_sni" for e in blob["evidence"])
    assert not any(rel == "served_at" for rel, _s, _t in _edges(blob))


def test_static_ip_without_runtime_yields_no_network_flow() -> None:
    blob = _build(_ep("9.9.9.9", "ip", {"asn": {"asn": 4134}}))  # no runtime evidence
    assert not any(e["type"] == "network_flow" for e in (blob["evidence"] if blob else []))


def test_no_apk_node_without_a_runtime_contacted_edge() -> None:
    # a purely static (DNS) report has no APK->* contacted edge, so no APK node is minted.
    blob = _build(_ep("a.example.com", "domain", {"dns": {"ips": ["1.2.3.4"]}}))
    assert not any(n["type"] == "APK" for n in blob["graph"]["nodes"])


def test_runtime_edge_confidence_is_constant_0_95() -> None:
    blob = _build(_runtime_dom(ips=["203.0.113.7:443"]), _runtime_ip("203.0.113.7"))
    types = {e["type"] for e in blob["evidence"]}
    assert {"tls_sni", "network_flow"} <= types  # both actually emitted, so the loop is not vacuous
    for e in blob["evidence"]:
        if e["type"] in ("tls_sni", "network_flow"):
            assert e["confidence"] == 0.95
            assert e["timestamp"] is None  # determinism contract


def test_runtime_bridge_deterministic_under_shuffle() -> None:
    a, b = _runtime_dom("api.example.com", ips=["203.0.113.7:443"]), _runtime_ip("203.0.113.7")
    first = json.dumps(build_network_attribution([a, b], artifact_id="s", phase="analyze"), sort_keys=True)
    second = json.dumps(build_network_attribution([b, a], artifact_id="s", phase="analyze"), sort_keys=True)
    assert first == second


def test_only_peer_observing_runtime_sources_license_network_flow() -> None:
    # network_flow needs a source that observed the actual PEER IP. A value derived from a
    # Host/:authority header (runtime-tshark) or a decrypted request/body (*-decrypted) is
    # attacker-controllable (e.g. a spoofed IP-literal Host), so it mints no contacted edge.
    for bad_source in ("runtime-decrypted", "runtime-tls-decrypted", "runtime-tshark", "runtime-probe"):
        ep = _runtime_ip("203.0.113.99", source=bad_source, enrichment={})
        assert _build(ep) is None, bad_source  # no observed-contact edge, nothing else to bridge
    # control: the peer-observing sources still fire
    for good_source in ("runtime", "runtime-pcap"):
        blob = _build(_runtime_ip("203.0.113.99", source=good_source))
        assert any(e["type"] == "network_flow" for e in blob["evidence"]), good_source


def test_direct_connection_signal_also_gated_by_peer_observation() -> None:
    # the peer-observed predicate gates BOTH the network_flow edge AND the PR9
    # direct_connection RoleSignal — a Host/content-derived source must license neither,
    # only a peer-observing source (runtime / runtime-pcap) does. (pins the signal path.)
    def ip_ep(source):
        return _ep("203.0.113.9", "ip", {
            "attribution": {"ips": [{"ip": "203.0.113.9", "country": "CN",
                                     "origin_network": {"asn": 4134, "category": "telecom"}}]}},
            evidences=[Evidence(source=source, location="x")])
    for bad in ("runtime-decrypted", "runtime-tls-decrypted", "runtime-tshark"):
        assert "direct_connection" not in _matched_signals(_build(ip_ep(bad)), "203.0.113.9"), bad
    for good in ("runtime", "runtime-pcap"):
        assert "direct_connection" in _matched_signals(_build(ip_ep(good)), "203.0.113.9"), good


def test_known_intercept_ip_is_never_served_at_nor_contacted() -> None:
    # a domestically-blocked fraud domain's SNI genuinely reaches the anti-fraud intercept
    # page (183.192.65.101) — but that node is not the domain's serving IP, so no served_at.
    dom = _runtime_dom("fraud.example.com", ips=["183.192.65.101:443"])
    assert _build(dom) is None  # the intercept remote is the only fact; nothing survives
    # even a (hand-edited) intercept ip endpoint mints no APK->IP contacted edge
    intercept_ip = _runtime_ip("183.192.65.101")
    assert _build(intercept_ip) is None


def test_tls_sni_guard_normalizes_case_and_trailing_dot() -> None:
    # the wire SNI is stored raw (mixed case / trailing dot), the endpoint value may differ
    # in case — the guard must normalize both, so the served_at edge is still emitted.
    ep = _ep("API.Example.com", "domain",
             {"runtime": {"sni": ["api.example.com."], "remote_endpoints": ["203.0.113.7:443"]}})
    assert ("served_at", "api.example.com", "203.0.113.7") in _edges(_build(ep))


def test_static_dns_and_runtime_tls_coexist_as_parallel_edges() -> None:
    # the routine real-capture shape: a domain both resolves (DNS) and is TLS-observed at
    # the same IP — both a resolves_to and a served_at edge, with distinct evidence entries.
    ep = _ep("api.example.com", "domain", {
        "dns": {"ips": ["203.0.113.7"]},
        "runtime": {"sni": ["api.example.com"], "remote_endpoints": ["203.0.113.7:443"]}})
    blob = _build(ep)
    edges = _edges(blob)
    assert ("resolves_to", "api.example.com", "203.0.113.7") in edges
    assert ("served_at", "api.example.com", "203.0.113.7") in edges
    assert {"resolved_ip", "tls_sni"} <= {e["type"] for e in blob["evidence"]}


def test_malformed_remote_endpoints_are_skipped_not_crashing() -> None:
    # non-strings, empties, port-less / bracketed / garbage entries must be skipped (never
    # raise — a raise would drop the WHOLE endpoint incl. its valid edges).
    ep = _ep("api.example.com", "domain", {"runtime": {"sni": ["api.example.com"], "remote_endpoints": [
        443, None, {"ip": "x"}, "", ":", "garbage:443", "1.2.3.4:99999", "[2001:db8::1]:443",
        "203.0.113.7:443"]}})
    blob = _build(ep)
    served = {t for rel, _s, t in _edges(blob) if rel == "served_at"}
    assert served == {"203.0.113.7"}  # only the one well-formed entry survives
    assert blob["skipped"] == []  # skipped-per-endpoint list stays empty (no raise)


def test_mitm_only_domain_yields_no_contacted_edge_intended_asymmetry() -> None:
    # network_flow is intentionally ip-only: a runtime-observed DOMAIN without a structured
    # runtime pairing has no IP to contact, so it mints nothing (asymmetric with the ip case).
    dom = _ep("api.example.com", "domain", {}, evidences=[Evidence(source="runtime", location="runtime")])
    assert _build(dom) is None  # domain-only mitm observation bridges nothing
    # the identically-observed ip endpoint DOES mint an APK->IP contacted edge
    ip_edges = _edges(_build(_runtime_ip("203.0.113.7", source="runtime")))
    assert ("contacted", "sha-test", "203.0.113.7") in ip_edges
