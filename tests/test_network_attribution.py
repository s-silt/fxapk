"""PR9 network_attribution: bridge, conservative signal compiler, determinism,
passive discipline, and the anti-over-inference acceptance negatives."""

from __future__ import annotations

import json
import subprocess
import sys

from apkscan.attribution.assemble import _parse_asn, build_network_attribution
from apkscan.core.models import Endpoint, Evidence
from apkscan.dynamic.merge import load_runtime_endpoints


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
                 "subsequent_overseas_connection", "historical_dns", "stable_ip", "many_shared_domains",
                 "business_api", "login_endpoint"}
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


# --------------------------------------------------------------------------- #
# P0: SUBSEQUENT_OVERSEAS_CONNECTION → domestic_relay_candidate 端到端资格
# （运行时行为信号，保留"静态/被动不产 eligible"不变量：只在有真运行时时序时成立）
# --------------------------------------------------------------------------- #
def _rt_ip(value, country, ts, *, tier=None, hosting_cat=None):
    origin_cat = "telecom" if country == "CN" else "cloud"
    return _ep(value, "ip", {
        "attribution": {"ips": [{"ip": value, "country": country,
                                 "origin_network": {"asn": 4134, "category": origin_cat},
                                 "hosting_provider": {"category": hosting_cat},
                                 "edge_provider": {"tier": tier}}]},
        "runtime": {"first_contact_ts": ts},
    }, evidences=[Evidence(source="runtime", location="pcap")])


def test_domestic_relay_eligible_from_subsequent_overseas_runtime() -> None:
    # 境内 IP 被接触(t=100) → 随后接触境外 IP(t=200) = DIRECT+DOMESTIC+SUBSEQUENT_OVERSEAS → eligible。
    blob = _build(_rt_ip("203.0.113.9", "CN", 100.0), _rt_ip("198.51.100.7", "US", 200.0))
    r = _roles(blob, "203.0.113.9")["domestic_relay_candidate"]
    assert r["eligible"] is True
    assert set(r["matched_signals"]) >= {"direct_connection", "domestic_network", "subsequent_overseas_connection"}
    # 证据可回溯：角色带证据 id，且 SUBSEQUENT_OVERSEAS 的 raw_reference（运行时时序对比）在报告图谱里可查。
    assert r["evidence"]
    assert "first_contact_ts" in json.dumps(blob)


def test_domestic_relay_not_eligible_without_later_overseas() -> None:
    # 境外接触在**前**(t=100 < 境内 t=200) → 非 subsequent → 不 eligible。
    early = _build(_rt_ip("203.0.113.9", "CN", 200.0), _rt_ip("198.51.100.7", "US", 100.0))
    assert _roles(early, "203.0.113.9")["domestic_relay_candidate"]["eligible"] is False
    # 根本没有境外端点 → 不 eligible（保留"无真信号不成立"）。
    solo = _build(_rt_ip("203.0.113.9", "CN", 100.0))
    r = _roles(solo, "203.0.113.9")["domestic_relay_candidate"]
    assert r["eligible"] is False and "subsequent_overseas_connection" not in r["matched_signals"]


def test_domestic_relay_blocked_by_public_cdn_even_with_subsequent_overseas() -> None:
    # 境内 IP 命中 confirmed edge → PUBLIC_CDN blocker：即便有 SUBSEQUENT_OVERSEAS 也被阻断。
    blob = _build(_rt_ip("203.0.113.9", "CN", 100.0, tier="confirmed"), _rt_ip("198.51.100.7", "US", 200.0))
    r = _roles(blob, "203.0.113.9")["domestic_relay_candidate"]
    assert r["eligible"] is False and "public_cdn" in r["negative_signals"]


# --------------------------------------------------------------------------- #
# P0 复审修复回归（Fable 对抗式复审 CONFIRMED 项）
# --------------------------------------------------------------------------- #
def _blob_json(eps):
    return json.dumps(build_network_attribution(list(eps), artifact_id="s", phase="analyze"), sort_keys=True)


def _ip_ep(value, entry_country, ts, *, asn_country=None, source="runtime", tier=None):
    enr = {
        "attribution": {"ips": [{"ip": value, "country": entry_country,
                                 "origin_network": {"asn": 4134, "category": "telecom"},
                                 "hosting_provider": {"category": None}, "edge_provider": {"tier": tier}}]},
        "runtime": {"first_contact_ts": ts},
    }
    if asn_country is not None:
        enr["asn"] = {"country": asn_country}
    return _ep(value, "ip", enr, evidences=[Evidence(source=source, location="x")])


def test_no_subsequent_from_country_conflict_entry_vs_asn() -> None:
    # ★口径互斥：entry country=US/HK 但 asn.country=CN（电信出海段）——两侧都算境内-capable，不得进境外池自我授信。
    e1 = _ip_ep("203.0.113.9", "US", 100.0, asn_country="CN")
    e2 = _ip_ep("198.51.100.7", "HK", 200.0, asn_country="CN")
    r = _roles(_build(e1, e2), "203.0.113.9")["domestic_relay_candidate"]
    assert r["eligible"] is False and "subsequent_overseas_connection" not in r["matched_signals"]


def test_intercept_node_never_relay_candidate_even_with_subsequent_overseas() -> None:
    # ★已知反诈拦截节点不产运行时行为信号（与 _bridge_endpoint 排除一致；办案约定：拦截节点勿入线索）。
    r = _roles(_build(_rt_ip("183.192.65.101", "CN", 100.0), _rt_ip("198.51.100.7", "US", 200.0)),
               "183.192.65.101")["domestic_relay_candidate"]
    assert r["eligible"] is False
    assert not ({"direct_connection", "subsequent_overseas_connection"} & set(r["matched_signals"]))


def test_nan_inf_first_contact_ts_rejected_and_order_stable() -> None:
    dom, ok = _rt_ip("203.0.113.9", "CN", 100.0), _rt_ip("198.51.100.7", "US", 200.0)
    nan = _rt_ip("198.51.100.8", "US", float("nan"))
    assert _blob_json([dom, nan, ok]) == _blob_json([dom, ok, nan])  # NaN 不引入顺序敏感
    assert _roles(build_network_attribution([dom, nan, ok], artifact_id="s", phase="analyze"),
                  "203.0.113.9")["domestic_relay_candidate"]["eligible"] is True  # 有效端点(200>100)仍成立
    # +inf 垃圾值不铸信号
    assert _roles(_build(_rt_ip("203.0.113.9", "CN", 100.0), _rt_ip("198.51.100.7", "US", float("inf"))),
                  "203.0.113.9")["domestic_relay_candidate"]["eligible"] is False


def test_tie_timestamp_not_subsequent_strict_gt() -> None:
    # 同时刻 co-occurrence ≠ subsequent（严格 >）。
    r = _roles(_build(_rt_ip("203.0.113.9", "CN", 100.0), _rt_ip("198.51.100.7", "US", 100.0)),
               "203.0.113.9")["domestic_relay_candidate"]
    assert r["eligible"] is False and "subsequent_overseas_connection" not in r["matched_signals"]


def test_subsequent_overseas_permutation_deterministic() -> None:
    eps = [_rt_ip("203.0.113.9", "CN", 100.0), _rt_ip("198.51.100.7", "US", 200.0), _rt_ip("198.51.100.8", "US", 150.0)]
    assert _blob_json(eps) == _blob_json(list(reversed(eps)))


def test_ts_dict_without_runtime_evidence_licenses_nothing() -> None:
    # 境内带 ts 字典但无 runtime 证据（合并/手编） + 真运行时境外 → 不产 subsequent。
    r1 = _roles(_build(_ip_ep("203.0.113.9", "CN", 100.0, source="static"), _rt_ip("198.51.100.7", "US", 200.0)),
                "203.0.113.9")["domestic_relay_candidate"]
    assert r1["eligible"] is False and "subsequent_overseas_connection" not in r1["matched_signals"]
    # 境外带 ts 字典但无 runtime 证据 → 不入境外池。
    r2 = _roles(_build(_rt_ip("203.0.113.9", "CN", 100.0), _ip_ep("198.51.100.7", "US", 200.0, source="static")),
                "203.0.113.9")["domestic_relay_candidate"]
    assert r2["eligible"] is False and "subsequent_overseas_connection" not in r2["matched_signals"]


def test_truthy_nonstring_country_not_treated_overseas() -> None:
    # 坏 country（True/dict/list）不得当境外把境内 IP 授信成 eligible。
    bad = _ep("198.51.100.7", "ip", {
        "attribution": {"ips": [{"ip": "198.51.100.7", "country": True,
                                 "origin_network": {"asn": 64500, "category": "cloud"},
                                 "hosting_provider": {"category": None}, "edge_provider": {"tier": None}}]},
        "runtime": {"first_contact_ts": 200.0},
    }, evidences=[Evidence(source="runtime", location="pcap")])
    r = _roles(_build(_rt_ip("203.0.113.9", "CN", 100.0), bad), "203.0.113.9")["domestic_relay_candidate"]
    assert r["eligible"] is False and "subsequent_overseas_connection" not in r["matched_signals"]


# --------------------------------------------------------------------------- #
# P0-2: BUSINESS_API + LOGIN_ENDPOINT → origin_candidate（运行时请求路径，守不变量）
# --------------------------------------------------------------------------- #
def _biz_ip(value, *, biz=True, login=True, source="runtime", tier=None):
    rt = {}
    if biz:
        rt["business_api_paths"] = ["/api/user/order"]
    if login:
        rt["login_paths"] = ["/api/user/login"]
    return _ep(value, "ip", {
        "attribution": {"ips": [{"ip": value, "country": "US",
                                 "origin_network": {"asn": 64500, "category": "cloud"},
                                 "hosting_provider": {"category": None}, "edge_provider": {"tier": tier}}]},
        "runtime": rt,
    }, evidences=[Evidence(source=source, location="x")])


def test_origin_candidate_eligible_from_runtime_business_and_login_paths() -> None:
    r = _roles(_build(_biz_ip("1.2.3.4")), "1.2.3.4")["origin_candidate"]
    assert r["eligible"] is True
    assert {"business_api", "login_endpoint"} <= set(r["matched_signals"])
    assert r["evidence"]  # 证据可回溯


def test_origin_candidate_not_eligible_business_api_alone() -> None:
    # BUSINESS_API 单独不足（origin 须 BUSINESS_API + 一之 LOGIN/STABLE_IP/HISTORICAL_DNS/BUSINESS_CERT）。
    r = _roles(_build(_biz_ip("1.2.3.4", login=False)), "1.2.3.4")["origin_candidate"]
    assert r["eligible"] is False and "login_endpoint" not in r["matched_signals"]


def test_origin_candidate_blocked_by_public_cdn() -> None:
    r = _roles(_build(_biz_ip("1.2.3.4", tier="confirmed")), "1.2.3.4")["origin_candidate"]
    assert r["eligible"] is False and "public_cdn" in r["negative_signals"]


def test_origin_candidate_needs_runtime_evidence_not_just_path_dict() -> None:
    # ★守不变量：手注 business/login path 字典但无 runtime 证据（合并/手编）→ 不产信号、不 eligible。
    roles = _roles(_build(_biz_ip("1.2.3.4", source="static")), "1.2.3.4")
    all_sig = {s for role in roles.values() for s in role["matched_signals"]}
    assert not ({"business_api", "login_endpoint"} & all_sig)
    r = roles.get("origin_candidate")
    assert r is None or r["eligible"] is False


def test_intercept_node_never_origin_candidate() -> None:
    # 反诈拦截节点即便被观测业务/登录路径也不产运行时信号（与 _bridge_endpoint 排除一致）。
    ep = _ep("183.192.65.101", "ip", {
        "attribution": {"ips": [{"ip": "183.192.65.101", "country": "CN",
                                 "origin_network": {"asn": 4134, "category": "telecom"},
                                 "hosting_provider": {"category": None}, "edge_provider": {"tier": None}}]},
        "runtime": {"business_api_paths": ["/api/x"], "login_paths": ["/login"]},
    }, evidences=[Evidence(source="runtime", location="x")])
    roles = _roles(_build(ep), "183.192.65.101")
    all_sig = {s for role in roles.values() for s in role["matched_signals"]}
    assert not ({"business_api", "login_endpoint", "direct_connection"} & all_sig)
    r = roles.get("origin_candidate")
    assert r is None or r["eligible"] is False


def test_origin_candidate_not_eligible_when_edge_fingerprinted() -> None:
    # ★复审 P1：IP 带 edge 指纹（possible/clustered=像前置/防红共享前端）→ 不产 origin 信号、不 eligible
    #   （补 PUBLIC_CDN blocker 只认 confirmed/probable 的负证据缺口）。
    for tier in ("possible", "clustered"):
        roles = _roles(_build(_biz_ip("1.2.3.4", tier=tier)), "1.2.3.4")
        all_sig = {s for role in roles.values() for s in role["matched_signals"]}
        assert not ({"business_api", "login_endpoint"} & all_sig), tier
        r = roles.get("origin_candidate")
        assert r is None or r["eligible"] is False


def test_origin_candidate_single_login_path_not_eligible() -> None:
    # ★复审 P2：单条 /api/user/login 同为业务+登录路径 → 不授 BUSINESS_API（第二要件须来自不同事实）→ 不 eligible。
    ep = _ep("1.2.3.4", "ip", {
        "attribution": {"ips": [{"ip": "1.2.3.4", "country": "US",
                                 "origin_network": {"asn": 64500, "category": "cloud"},
                                 "hosting_provider": {"category": None}, "edge_provider": {"tier": None}}]},
        "runtime": {"business_api_paths": ["/api/user/login"], "login_paths": ["/api/user/login"]},
    }, evidences=[Evidence(source="runtime", location="x")])
    roles = _roles(_build(ep), "1.2.3.4")
    all_sig = {s for role in roles.values() for s in role["matched_signals"]}
    assert "business_api" not in all_sig  # 无独立业务路径
    r = roles.get("origin_candidate")
    assert r is None or r["eligible"] is False


# --------------------------------------------------------------------------- #
# P0-3: REDIRECT + COOKIE_CHALLENGE → edge_candidate / cloaking_edge_node（运行时响应行为）
# --------------------------------------------------------------------------- #
def _edge_ip(value, *, host_signals=None, source="runtime", tier=None, country="US"):
    # host_signals: {host: (redirect, cookie)}; 默认一个 host 同时重定向+挑战（cloaking 行为）。
    if host_signals is None:
        host_signals = {"pay.x.com": (True, True)}
    edge_hosts = {h: {"r": bool(r), "c": bool(c)} for h, (r, c) in host_signals.items()}
    return _ep(value, "ip", {
        "attribution": {"ips": [{"ip": value, "country": country,
                                 "origin_network": {"asn": 64500, "category": "cloud"},
                                 "hosting_provider": {"category": None}, "edge_provider": {"tier": tier}}]},
        "runtime": {"edge_hosts": edge_hosts},
    }, evidences=[Evidence(source=source, location="x")])


def test_edge_candidate_eligible_from_runtime_redirect_and_cookie() -> None:
    r = _roles(_build(_edge_ip("5.5.5.5")), "5.5.5.5")["edge_candidate"]
    assert r["eligible"] is True
    assert {"redirect", "cookie_challenge"} <= set(r["matched_signals"])
    assert r["evidence"]


def test_cloaking_edge_node_eligible_from_redirect_and_cookie() -> None:
    r = _roles(_build(_edge_ip("5.5.5.5")), "5.5.5.5")["cloaking_edge_node"]
    assert r["eligible"] is True  # 同 host 的 COOKIE_CHALLENGE + REDIRECT = ≥2 强行为信号


def test_edge_and_cloaking_not_eligible_single_signal() -> None:
    # 某 host 仅重定向（无挑战）→ 无 host 双命中 → 不产信号 → 不 eligible。
    roles = _roles(_build(_edge_ip("5.5.5.5", host_signals={"pay.x.com": (True, False)})), "5.5.5.5")
    for role in ("edge_candidate", "cloaking_edge_node"):
        r = roles.get(role)
        assert r is None or r["eligible"] is False, role


def test_edge_cross_tenant_shared_edge_not_eligible() -> None:
    # ★复审 P1：共享边缘上不同 host（不同租户）各出一个信号，不得凑成 cloaking——须同一 host 双命中。
    roles = _roles(_build(_edge_ip("5.5.5.5", host_signals={"a.com": (True, False), "b.com": (False, True)})), "5.5.5.5")
    all_sig = {s for role in roles.values() for s in role["matched_signals"]}
    assert not ({"redirect", "cookie_challenge"} & all_sig)
    for role in ("edge_candidate", "cloaking_edge_node"):
        r = roles.get(role)
        assert r is None or r["eligible"] is False, role


def test_redirect_does_not_leak_into_domestic_relay() -> None:
    # ★复审 P1：REDIRECT 不满足 relay 的过渡要件（须 SUBSEQUENT_OVERSEAS）——境内 IP 有跨host重定向不等于中继。
    roles = _roles(_build(_edge_ip("203.0.113.9", country="CN")), "203.0.113.9")
    r = roles.get("domestic_relay_candidate")
    assert r is None or r["eligible"] is False


# --------------------------------------------------------------------------- #
# P0-3 加固：手编 / 回灌的 runtime_report.json 无真实 observed-contact 证据，经
# load_runtime_endpoints 重建后不得凭"两只布尔"过运行时行为角色（信任边界回归）。
# --------------------------------------------------------------------------- #
def _write_runtime_report(tmp_path, endpoint: dict) -> str:
    path = tmp_path / "runtime_report.json"
    path.write_text(
        json.dumps({"package_name": "com.test.app", "source": "runtime", "endpoints": [endpoint]},
                   ensure_ascii=False),
        encoding="utf-8",
    )
    return str(path)


def _cloaking_ip_payload(evidences) -> dict:
    # 一个 IP 端点：带 cloaking 触发所需的 enrichment（同 host redirect+cookie=两只布尔就过 cloaking 档）
    # 与 attribution 事实，evidences 由参数决定（无 / 非 runtime* / 真 runtime）。
    ep: dict = {
        "value": "5.5.5.5",
        "kind": "ip",
        "enrichment": {
            "attribution": {"ips": [{"ip": "5.5.5.5", "country": "US",
                                     "origin_network": {"asn": 64500, "category": "cloud"},
                                     "hosting_provider": {"category": None},
                                     "edge_provider": {"tier": None}}]},
            "runtime": {"edge_hosts": {"pay.x.com": {"r": True, "c": True}}},
        },
    }
    if evidences is not None:
        ep["evidences"] = evidences
    return ep


def test_handinjected_runtime_report_without_contact_evidence_licenses_no_role(tmp_path) -> None:
    # ★信任边界：runtime_report.json 里一个只有 enrichment.runtime 标志、**无 evidences** 的 IP 端点，
    #   经 load_runtime_endpoints 合成的证据被钉成 runtime-derived（非 observed-contact），故
    #   build_network_attribution 不产运行时行为信号、cloaking/edge 角色不 eligible。无修复即失败：
    #   旧逻辑合成 source="runtime" 会命中 observed-contact allowlist、两只布尔直接过 cloaking 档。
    eps = load_runtime_endpoints(_write_runtime_report(tmp_path, _cloaking_ip_payload(evidences=None)))
    assert eps and all(ev.source == "runtime-derived" for ev in eps[0].evidences)
    roles = _roles(_build(*eps), "5.5.5.5")
    all_sig = {s for role in roles.values() for s in role["matched_signals"]}
    assert not ({"redirect", "cookie_challenge"} & all_sig)
    for role in ("edge_candidate", "cloaking_edge_node"):
        r = roles.get(role)
        assert r is None or r["eligible"] is False, role


def test_handinjected_runtime_report_with_static_evidence_licenses_no_role(tmp_path) -> None:
    # 同上，但 evidences 显式写了非 runtime* 来源（source=static，手编/写串）→ 也钉 runtime-derived → 不授信。
    static_ev = [{"source": "static", "location": "x", "snippet": "s"}]
    eps = load_runtime_endpoints(_write_runtime_report(tmp_path, _cloaking_ip_payload(evidences=static_ev)))
    assert eps and all(ev.source == "runtime-derived" for ev in eps[0].evidences)
    roles = _roles(_build(*eps), "5.5.5.5")
    all_sig = {s for role in roles.values() for s in role["matched_signals"]}
    assert not ({"redirect", "cookie_challenge"} & all_sig)
    for role in ("edge_candidate", "cloaking_edge_node"):
        r = roles.get(role)
        assert r is None or r["eligible"] is False, role


def test_genuine_capture_runtime_evidence_still_licenses_cloaking(tmp_path) -> None:
    # 控制组 / 无回归：真 capture 产物本就带 source="runtime"（observed-contact），reload 后保持 "runtime"，
    #   cloaking 仍如常 eligible——证明上面两条不是因整条路径失灵才通过。
    real_ev = [{"source": "runtime", "location": "flows.mitm", "snippet": "5.5.5.5:443"}]
    eps = load_runtime_endpoints(_write_runtime_report(tmp_path, _cloaking_ip_payload(evidences=real_ev)))
    assert eps and eps[0].evidences[0].source == "runtime"
    r = _roles(_build(*eps), "5.5.5.5")["cloaking_edge_node"]
    assert r["eligible"] is True


def test_edge_signals_need_runtime_evidence_not_just_flags() -> None:
    # ★守不变量：手注 edge_hosts 但无 runtime 证据 → 不产信号。
    roles = _roles(_build(_edge_ip("5.5.5.5", source="static")), "5.5.5.5")
    all_sig = {s for role in roles.values() for s in role["matched_signals"]}
    assert not ({"redirect", "cookie_challenge"} & all_sig)


def test_intercept_node_never_edge_signals() -> None:
    # 规范写法与 IPv4-mapped IPv6 写法都须被拦（复审 P2：::ffff: 绕过）。
    for value in ("183.192.65.101", "::ffff:183.192.65.101"):
        ep = _ep(value, "ip", {
            "attribution": {"ips": [{"ip": value, "country": "CN",
                                     "origin_network": {"asn": 4134, "category": "telecom"},
                                     "hosting_provider": {"category": None}, "edge_provider": {"tier": None}}]},
            "runtime": {"edge_hosts": {"h": {"r": True, "c": True}}},
        }, evidences=[Evidence(source="runtime", location="x")])
        all_sig = {s for role in _roles(_build(ep), value).values() for s in role["matched_signals"]}
        assert not ({"redirect", "cookie_challenge", "direct_connection"} & all_sig), value
